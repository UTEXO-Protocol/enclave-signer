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

    // F03-AF-22: test truncated and invalid protobuf frames.

    /// Reject a body shorter than its length header.
    #[test]
    fn reject_truncated_body() {
        let mut buf = 32u32.to_le_bytes().to_vec(); // claim 32 body bytes...
        buf.extend_from_slice(&[0u8; 8]); // ...but supply only 8
        let mut cursor = Cursor::new(buf);
        let result: Result<EnclaveRequest> = read_message(&mut cursor);
        assert!(result.is_err());
    }

    /// Return a decode error for invalid protobuf data.
    #[test]
    fn reject_garbage_body() {
        // 0xFF bytes are an invalid protobuf field/wire-type stream for this msg.
        let body = vec![0xFFu8; 24];
        let mut buf = (body.len() as u32).to_le_bytes().to_vec();
        buf.extend_from_slice(&body);
        let mut cursor = Cursor::new(buf);
        let result: Result<EnclaveRequest> = read_message(&mut cursor);
        assert!(result.is_err());
    }

    /// Handle each fixed test frame without a panic.
    /// Inputs stay below the 4 MiB frame limit.
    #[test]
    fn framed_garbage_corpus_never_panics() {
        let mut state = 0xD1B5_4A32_D192_ED03u64;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        };
        for len in [1usize, 2, 5, 13, 64, 255, 1024] {
            let body: Vec<u8> = (0..len).map(|_| next()).collect();
            let mut buf = (len as u32).to_le_bytes().to_vec();
            buf.extend_from_slice(&body);
            let mut cursor = Cursor::new(buf);
            let _res: Result<EnclaveRequest> = read_message(&mut cursor);
        }
    }
}
