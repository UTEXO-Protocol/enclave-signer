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
