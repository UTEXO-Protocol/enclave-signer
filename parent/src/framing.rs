use prost::Message;
use std::io::{Read, Write};

use crate::error::{ParentError, Result};

/// Maximum size of one framed message. Equal to the enclave constant
/// (`enclave/src/framing.rs`). The gRPC server accepts requests up to the same
/// size, so a request that the enclave can read is not refused before it.
pub const MAX_MESSAGE_SIZE: u32 = 24 * 1024 * 1024; // 24 MiB

/// Read a length-prefixed protobuf message from a stream.
/// Wire format: `[4-byte LE u32 length][protobuf bytes]`.
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
/// Wire format: `[4-byte LE u32 length][protobuf bytes]`.
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
        enclave_request::Request, sign_request::SourceNetwork, EnclaveRequest, RgbSource,
        SignRequest,
    };
    use std::io::Cursor;

    /// A request with a consignment larger than the old 4 MiB frame limit.
    fn large_request(consignment_bytes: usize) -> EnclaveRequest {
        EnclaveRequest {
            request: Some(Request::Sign(SignRequest {
                source_network: Some(SourceNetwork::RgbSource(RgbSource {
                    consignment: vec![0x5a; consignment_bytes],
                    ..Default::default()
                })),
                ..Default::default()
            })),
        }
    }

    #[test]
    fn reads_a_frame_larger_than_the_old_4_mib_limit() {
        let request = large_request(8 * 1024 * 1024);
        let mut buf = Vec::new();
        write_message(&mut buf, &request).unwrap();
        assert!(buf.len() > 4 * 1024 * 1024);
        let decoded: EnclaveRequest = read_message(&mut Cursor::new(buf)).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn rejects_a_frame_above_the_limit() {
        let len = MAX_MESSAGE_SIZE + 1;
        let result: Result<EnclaveRequest> =
            read_message(&mut Cursor::new(len.to_le_bytes().to_vec()));
        assert!(result.is_err());
    }
}
