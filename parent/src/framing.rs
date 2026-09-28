use prost::Message;
use std::io::{Read, Write};

use crate::error::{ParentError, Result};

const MAX_MESSAGE_SIZE: u32 = 4 * 1024 * 1024; // 4 MB

/// Read a length-prefixed protobuf message from a stream.
/// Wire format: [4-byte LE u32 length][protobuf bytes].
pub fn read_message<M: Message + Default>(stream: &mut impl Read) -> Result<M> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);

    if len == 0 {
        return Err(ParentError::Framing("zero-length message".into()));
    }
    if len > MAX_MESSAGE_SIZE {
        return Err(ParentError::Framing(format!(
            "message too large: {} bytes (max {})",
            len, MAX_MESSAGE_SIZE
        )));
    }

    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf)?;

    let msg = M::decode(&buf[..])?;
    Ok(msg)
}

/// Write a length-prefixed protobuf message to a stream.
/// Wire format: [4-byte LE u32 length][protobuf bytes].
pub fn write_message<M: Message>(stream: &mut impl Write, msg: &M) -> Result<()> {
    let buf = msg.encode_to_vec();
    let len = buf.len() as u32;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(&buf)?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave_proto::{
        enclave_request, EnclaveRequest, ErrorResponse, GetPublicKeyRequest,
    };
    use std::io::Cursor;

    fn sample() -> EnclaveRequest {
        EnclaveRequest {
            request: Some(enclave_request::Request::GetPublicKey(
                GetPublicKeyRequest {},
            )),
        }
    }

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    fn is_eof(err: &ParentError) -> bool {
        matches!(err, ParentError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof)
    }

    #[test]
    fn write_then_read_roundtrips_and_prefixes_the_le_length() {
        let mut buf = Vec::new();
        write_message(&mut buf, &sample()).unwrap();
        let body_len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(body_len, buf.len() - 4);
        assert_eq!(&buf[4..], sample().encode_to_vec().as_slice());
        let back: EnclaveRequest = read_message(&mut Cursor::new(buf)).unwrap();
        assert_eq!(back, sample());
    }

    #[test]
    fn consecutive_frames_read_back_in_order_then_eof() {
        let a = ErrorResponse {
            code: 1,
            message: "a".into(),
        };
        let b = ErrorResponse {
            code: 2,
            message: "b".into(),
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &a).unwrap();
        write_message(&mut buf, &b).unwrap();
        let mut cur = Cursor::new(buf);
        assert_eq!(read_message::<ErrorResponse>(&mut cur).unwrap(), a);
        assert_eq!(read_message::<ErrorResponse>(&mut cur).unwrap(), b);
        let err = read_message::<ErrorResponse>(&mut cur).unwrap_err();
        assert!(is_eof(&err), "{err}");
    }

    #[test]
    fn zero_length_frame_is_rejected() {
        let err = read_message::<EnclaveRequest>(&mut Cursor::new(0u32.to_le_bytes())).unwrap_err();
        match err {
            ParentError::Framing(m) => assert_eq!(m, "zero-length message"),
            other => panic!("unexpected {other}"),
        }
    }

    #[test]
    fn oversized_frame_is_rejected_before_the_body_is_read() {
        // Only the header is present: a reader that tried to read the body
        // would hit EOF rather than the size check.
        let err =
            read_message::<EnclaveRequest>(&mut Cursor::new((MAX_MESSAGE_SIZE + 1).to_le_bytes()))
                .unwrap_err();
        match err {
            ParentError::Framing(m) => assert_eq!(
                m,
                format!(
                    "message too large: {} bytes (max {})",
                    MAX_MESSAGE_SIZE + 1,
                    MAX_MESSAGE_SIZE
                )
            ),
            other => panic!("unexpected {other}"),
        }
        let err =
            read_message::<EnclaveRequest>(&mut Cursor::new(u32::MAX.to_le_bytes())).unwrap_err();
        assert!(matches!(err, ParentError::Framing(_)), "{err}");
    }

    #[test]
    fn frame_at_exactly_the_cap_is_accepted() {
        // tag (1 byte) + varint length (4 bytes) + payload = 4 MiB exactly.
        let msg = ErrorResponse {
            code: 0,
            message: "x".repeat(MAX_MESSAGE_SIZE as usize - 5),
        };
        let body = msg.encode_to_vec();
        assert_eq!(body.len(), MAX_MESSAGE_SIZE as usize);
        let back: ErrorResponse = read_message(&mut Cursor::new(framed(&body))).unwrap();
        assert_eq!(back.message.len(), msg.message.len());
    }

    #[test]
    fn truncated_header_and_truncated_body_are_io_errors() {
        let err = read_message::<EnclaveRequest>(&mut Cursor::new([1u8, 0])).unwrap_err();
        assert!(is_eof(&err), "{err}");

        let mut buf = 10u32.to_le_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 3]);
        let err = read_message::<EnclaveRequest>(&mut Cursor::new(buf)).unwrap_err();
        assert!(is_eof(&err), "{err}");
    }

    #[test]
    fn malformed_protobuf_body_is_a_decode_error() {
        let err = read_message::<EnclaveRequest>(&mut Cursor::new(framed(&[0xff; 4]))).unwrap_err();
        assert!(matches!(err, ParentError::ProtobufDecode(_)), "{err}");
        assert!(err.to_string().starts_with("protobuf decode error: "));
    }

    #[test]
    fn unknown_fields_are_skipped_on_decode() {
        let body = ErrorResponse {
            code: 7,
            message: "m".into(),
        }
        .encode_to_vec();
        let back: GetPublicKeyRequest = read_message(&mut Cursor::new(framed(&body))).unwrap();
        assert_eq!(back, GetPublicKeyRequest {});
    }

    struct FailingWriter;
    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("sink closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_failure_surfaces_as_io_error() {
        let err = write_message(&mut FailingWriter, &sample()).unwrap_err();
        assert!(matches!(err, ParentError::Io(_)), "{err}");
        assert!(err.to_string().contains("sink closed"), "{err}");
    }
}
