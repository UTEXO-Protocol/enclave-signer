use prost::Message;
use std::io::{Read, Write};

use crate::error::{EnclaveError, Result};

const MAX_MESSAGE_SIZE: u32 = 4 * 1024 * 1024; // 4 MB

/// Read a length-prefixed protobuf message from a stream.
/// Wire format: [4-byte LE u32 length][protobuf bytes].
pub fn read_message<M: Message + Default>(stream: &mut impl Read) -> Result<M> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);

    if len == 0 {
        return Err(EnclaveError::Framing("zero-length message".into()));
    }
    if len > MAX_MESSAGE_SIZE {
        return Err(EnclaveError::Framing(format!(
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
    use std::io::Cursor;

    use crate::proto::{enclave_request, EnclaveRequest, GetPublicKeyRequest};

    #[test]
    fn roundtrip() {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::GetPublicKey(
                GetPublicKeyRequest {},
            )),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &req).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: EnclaveRequest = read_message(&mut cursor).unwrap();

        assert_eq!(req, decoded);
    }

    #[test]
    fn reject_zero_length() {
        let buf = vec![0u8; 4]; // length = 0
        let mut cursor = Cursor::new(buf);
        let result: Result<EnclaveRequest> = read_message(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn reject_oversized() {
        let len: u32 = MAX_MESSAGE_SIZE + 1;
        let buf = len.to_le_bytes().to_vec();
        let mut cursor = Cursor::new(buf);
        let result: Result<EnclaveRequest> = read_message(&mut cursor);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use std::io::Cursor;

    use crate::proto::{enclave_request, EnclaveRequest, GetPublicKeyRequest, SignCcdRequest};

    fn request() -> EnclaveRequest {
        EnclaveRequest {
            request: Some(enclave_request::Request::SignCcd(SignCcdRequest {
                hash: vec![0xAB; 32],
            })),
        }
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn wire_layout_is_le_length_then_protobuf() {
        let req = request();
        let mut buf = Vec::new();
        write_message(&mut buf, &req).unwrap();
        let body = req.encode_to_vec();
        assert_eq!(&buf[..4], &(body.len() as u32).to_le_bytes());
        assert_eq!(&buf[4..], &body[..]);
    }

    #[test]
    fn two_messages_back_to_back_are_read_in_order() {
        let a = request();
        let b = EnclaveRequest {
            request: Some(enclave_request::Request::GetPublicKey(
                GetPublicKeyRequest {},
            )),
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &a).unwrap();
        write_message(&mut buf, &b).unwrap();
        let mut cursor = Cursor::new(buf);
        let got_a: EnclaveRequest = read_message(&mut cursor).unwrap();
        let got_b: EnclaveRequest = read_message(&mut cursor).unwrap();
        assert_eq!(got_a, a);
        assert_eq!(got_b, b);
        // Nothing left: a third read hits EOF on the length prefix.
        let third: Result<EnclaveRequest> = read_message(&mut cursor);
        assert!(
            matches!(third, Err(EnclaveError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof)
        );
    }

    #[test]
    fn empty_stream_is_an_unexpected_eof() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let r: Result<EnclaveRequest> = read_message(&mut cursor);
        assert!(
            matches!(r, Err(EnclaveError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof)
        );
    }

    #[test]
    fn truncated_length_prefix_is_an_unexpected_eof() {
        for n in 1..4 {
            let mut cursor = Cursor::new(vec![0x10u8; n]);
            let r: Result<EnclaveRequest> = read_message(&mut cursor);
            assert!(
                matches!(r, Err(EnclaveError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof),
                "{n}-byte prefix: {r:?}"
            );
        }
    }

    #[test]
    fn body_shorter_than_declared_length_is_an_unexpected_eof() {
        let body = request().encode_to_vec();
        let mut buf = ((body.len() + 1) as u32).to_le_bytes().to_vec();
        buf.extend_from_slice(&body);
        let mut cursor = Cursor::new(buf);
        let r: Result<EnclaveRequest> = read_message(&mut cursor);
        assert!(
            matches!(r, Err(EnclaveError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof)
        );
    }

    #[test]
    fn garbage_body_is_a_protobuf_decode_error() {
        // 0xff is an invalid tag/varint start for this message.
        let mut cursor = Cursor::new(frame(&[0xff, 0xff, 0xff, 0xff]));
        let r: Result<EnclaveRequest> = read_message(&mut cursor);
        assert!(matches!(r, Err(EnclaveError::ProtobufDecode(_))), "{r:?}");
    }

    #[test]
    fn declared_length_is_authoritative_and_extra_bytes_stay_in_the_stream() {
        // A body longer than the declared length is read up to the length;
        // the rest is left for the next read (which then fails as garbage).
        let body = request().encode_to_vec();
        let mut buf = frame(&body);
        buf.extend_from_slice(&[0xAA, 0xBB]);
        let mut cursor = Cursor::new(buf);
        let got: EnclaveRequest = read_message(&mut cursor).unwrap();
        assert_eq!(got, request());
        assert_eq!(cursor.position() as usize, 4 + body.len());
    }

    #[test]
    fn zero_length_error_is_a_framing_error_with_text() {
        let mut cursor = Cursor::new(vec![0u8; 4]);
        match read_message::<EnclaveRequest>(&mut cursor) {
            Err(EnclaveError::Framing(msg)) => assert_eq!(msg, "zero-length message"),
            other => panic!("expected Framing, got {other:?}"),
        }
    }

    #[test]
    fn oversized_error_names_both_sizes_and_reads_nothing_more() {
        let len = MAX_MESSAGE_SIZE + 1;
        let mut buf = len.to_le_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 16]);
        let mut cursor = Cursor::new(buf);
        match read_message::<EnclaveRequest>(&mut cursor) {
            Err(EnclaveError::Framing(msg)) => {
                assert!(msg.contains(&len.to_string()), "{msg}");
                assert!(msg.contains(&MAX_MESSAGE_SIZE.to_string()), "{msg}");
            }
            other => panic!("expected Framing, got {other:?}"),
        }
        // The body was never touched: only the 4-byte prefix was consumed.
        assert_eq!(cursor.position(), 4);
    }

    #[test]
    fn u32_max_length_is_rejected_before_allocation() {
        let mut cursor = Cursor::new(u32::MAX.to_le_bytes().to_vec());
        assert!(matches!(
            read_message::<EnclaveRequest>(&mut cursor),
            Err(EnclaveError::Framing(_))
        ));
    }

    #[test]
    fn exactly_max_size_is_accepted_when_the_body_decodes() {
        // A SignCcd request padded to exactly MAX_MESSAGE_SIZE bytes via its
        // `hash` field: the framing layer accepts the boundary, and the
        // message decodes (the handler, not the framing, rejects the length).
        let encode = |hash_len: usize| EnclaveRequest {
            request: Some(enclave_request::Request::SignCcd(SignCcdRequest {
                hash: vec![0x01; hash_len],
            })),
        };
        // Tag + length-varint overhead is constant once the hash length sits
        // in the same varint width as the target, so probe it at 3 MiB.
        let probe = 3 * 1024 * 1024;
        let overhead = encode(probe).encode_to_vec().len() - probe;
        let hash_len = MAX_MESSAGE_SIZE as usize - overhead;
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::SignCcd(SignCcdRequest {
                hash: vec![0x01; hash_len],
            })),
        };
        let body = req.encode_to_vec();
        assert_eq!(
            body.len(),
            MAX_MESSAGE_SIZE as usize,
            "sanity: exact boundary"
        );
        let mut cursor = Cursor::new(frame(&body));
        let got: EnclaveRequest = read_message(&mut cursor).unwrap();
        assert_eq!(got, req);
    }

    #[test]
    fn write_propagates_writer_errors() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("nope"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let r = write_message(&mut Broken, &request());
        assert!(matches!(r, Err(EnclaveError::Io(_))));
    }

    #[test]
    fn write_propagates_flush_errors() {
        struct NoFlush(Vec<u8>);
        impl Write for NoFlush {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("flush failed"))
            }
        }
        let mut w = NoFlush(Vec::new());
        let r = write_message(&mut w, &request());
        assert!(
            matches!(r, Err(EnclaveError::Io(ref e)) if e.to_string().contains("flush failed"))
        );
        // Bytes were handed to the writer before flush failed.
        assert!(!w.0.is_empty());
    }

    #[test]
    fn empty_request_encodes_to_a_one_byte_frame_header_only() {
        // `EnclaveRequest { request: None }` is zero protobuf bytes, so
        // writing it yields a zero-length frame that the reader refuses.
        let req = EnclaveRequest { request: None };
        let mut buf = Vec::new();
        write_message(&mut buf, &req).unwrap();
        assert_eq!(buf, vec![0, 0, 0, 0]);
        let mut cursor = Cursor::new(buf);
        assert!(matches!(
            read_message::<EnclaveRequest>(&mut cursor),
            Err(EnclaveError::Framing(_))
        ));
    }
}
