use prost::bytes::Buf;
use prost::encoding::{decode_key, decode_varint, skip_field, DecodeContext, WireType};
use prost::Message;
use std::io::{Read, Write};

use crate::error::{EnclaveError, Result};
use crate::proto::EnclaveRequest;

/// Maximum size of one framed message in the image. The operator can change
/// it ([`crate::limits`]). A request is one message, so it holds
/// the consignment, the Merkle proofs and the calldata.
///
/// Sized for the default request limits in [`crate::config`]: a consignment
/// of [`crate::config::DEFAULT_MAX_CONSIGNMENT_BYTES`], proof bytes of
/// [`crate::config::DEFAULT_MAX_TOTAL_PROOF_BYTES`], and protobuf overhead
/// for [`crate::config::DEFAULT_MAX_MERKLE_PROOFS`] proof entries. The parent
/// has the same constant.
pub const MAX_MESSAGE_SIZE: u32 = 24 * 1024 * 1024; // 24 MiB

/// Maximum protobuf field occurrences in one request in the image. The
/// operator can change it ([`crate::limits`]). The shape check counts
/// them on the wire before the decode. A decoded element costs far more
/// memory than its wire form. A field occurrence can be 2 bytes on the wire
/// and about 80 bytes in memory. A `MerkleProofEntry` with one empty path
/// element is 4 bytes and two occurrences. So a 24 MiB frame of them decodes
/// into more than 1 GiB. The largest real request at the image limits is a
/// burn with [`crate::config::DEFAULT_MAX_MERKLE_PROOFS`] proofs of 13 path
/// elements each. A test shows that it passes the shape check. The memory
/// model (`memory.rs`) budgets `WIRE_ELEMENT_BYTES` for each element.
/// A packed repeated scalar would be one occurrence for many values. The
/// request proto has none, and a test refuses one until the model covers it.
pub const MAX_WIRE_ELEMENTS: usize = 1 << 19;

/// Read a length-prefixed frame from a stream and return its bytes.
/// Wire format: [4-byte LE u32 length][protobuf bytes].
fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);

    if len == 0 {
        return Err(EnclaveError::Framing("zero-length message".into()));
    }
    let max = crate::limits::get().max_message_bytes;
    if u64::from(len) > max {
        return Err(EnclaveError::Framing(format!(
            "message too large: {len} bytes (max {max})"
        )));
    }

    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read a length-prefixed protobuf message from a stream. For requests from
/// the parent use [`read_request`], which checks the wire shape first.
pub fn read_message<M: Message + Default>(stream: &mut impl Read) -> Result<M> {
    let buf = read_frame(stream)?;
    let msg = M::decode(&buf[..])?;
    Ok(msg)
}

/// Read one request frame, check its wire shape and decode it. The shape
/// check runs before the decode allocates anything for the elements.
pub fn read_request(stream: &mut impl Read) -> Result<EnclaveRequest> {
    let buf = read_frame(stream)?;
    check_request_shape(&buf)?;
    let msg = EnclaveRequest::decode(&buf[..])?;
    Ok(msg)
}

/// The request messages that hold other messages or repeated fields. The
/// walk recurses only along these paths. It skips a `bytes` field such as the
/// consignment and never reads it as protobuf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Schema {
    /// `EnclaveRequest`: field 3 is `sign`, field 11 is `submit_headers`.
    Request,
    /// `SignRequest`: field 3 is `rgb_source`.
    Sign,
    /// `RgbSource`: field 6 is the repeated `merkle_proofs`.
    RgbSource,
    /// `MerkleProofEntry`: field 4 is the repeated `merkle_path`.
    MerkleProofEntry,
    /// `SubmitHeadersRequest`: field 1 is the repeated `headers`.
    SubmitHeaders,
    /// A message with no repeated fields and no nested messages, or a
    /// scalar, string or bytes field. Not entered.
    Leaf,
}

impl Schema {
    fn child(self, tag: u32) -> Schema {
        match (self, tag) {
            (Schema::Request, 3) => Schema::Sign,
            (Schema::Request, 11) => Schema::SubmitHeaders,
            (Schema::Sign, 3) => Schema::RgbSource,
            (Schema::RgbSource, 6) => Schema::MerkleProofEntry,
            _ => Schema::Leaf,
        }
    }
}

/// Counts the field occurrences of a request frame and refuses more than
/// `max_wire_elements`, the limit in force. Every occurrence counts, at every
/// depth the schema knows. The shape check or the decode refuses a frame that
/// is not valid protobuf.
pub fn check_request_shape(frame: &[u8]) -> Result<()> {
    count_request_elements(frame).map(|_| ())
}

/// The field occurrences of a request frame, or the refusal of
/// [`check_request_shape`]. The memory tests use the count.
pub(crate) fn count_request_elements(frame: &[u8]) -> Result<usize> {
    let max = crate::limits::get().max_wire_elements as usize;
    let mut left = max;
    walk(frame, Schema::Request, &mut left)?;
    Ok(max - left)
}

fn shape_error(e: prost::DecodeError) -> EnclaveError {
    EnclaveError::Framing(format!("request shape: {e}"))
}

fn walk(mut buf: &[u8], schema: Schema, left: &mut usize) -> Result<()> {
    while buf.has_remaining() {
        let (tag, wire_type) = decode_key(&mut buf).map_err(shape_error)?;
        *left = left.checked_sub(1).ok_or_else(|| {
            EnclaveError::Framing(format!(
                "request has more than {} elements",
                crate::limits::get().max_wire_elements
            ))
        })?;
        let child = schema.child(tag);
        if child == Schema::Leaf || wire_type != WireType::LengthDelimited {
            // A scalar, string or bytes field, a message the walk does not
            // enter, or a message field sent with another wire type. The
            // decode refuses the last one.
            skip_field(wire_type, tag, &mut buf, DecodeContext::default()).map_err(shape_error)?;
            continue;
        }
        let len = decode_varint(&mut buf).map_err(shape_error)?;
        let len = usize::try_from(len)
            .ok()
            .filter(|len| *len <= buf.remaining())
            .ok_or_else(|| {
                EnclaveError::Framing("request shape: nested message truncated".into())
            })?;
        walk(&buf[..len], child, left)?;
        buf.advance(len);
    }
    Ok(())
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
mod tests;
