use prost::bytes::Buf;
use prost::encoding::{decode_key, decode_varint, skip_field, DecodeContext, WireType};
use prost::Message;
use std::io::{Read, Write};

use crate::error::{EnclaveError, Result};
use crate::proto::EnclaveRequest;

/// Maximum size of one framed message. A request is one message, so it holds
/// the consignment, the Merkle proofs and the calldata.
///
/// Sized for the default request caps in [`crate::config`]: 12 MiB consignment,
/// 8 MiB proof bytes, and protobuf overhead for 16_384 proof entries. The
/// parent has the same constant.
pub const MAX_MESSAGE_SIZE: u32 = 24 * 1024 * 1024; // 24 MiB

/// Maximum protobuf field occurrences in one request. The shape check counts
/// them on the wire before the decode. A decoded element costs far more
/// memory than its wire form. An empty `MerkleProofEntry` is 4 bytes on the
/// wire and about 80 bytes in memory. A 24 MiB frame of them decoded into
/// more than 1 GiB. The largest real request is a burn with 16 384 proofs of
/// 13 path elements each. It has about 280 000 occurrences. The memory model
/// (`memory.rs`) budgets `WIRE_ELEMENT_BYTES` for each element.
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
    if len > MAX_MESSAGE_SIZE {
        return Err(EnclaveError::Framing(format!(
            "message too large: {} bytes (max {})",
            len, MAX_MESSAGE_SIZE
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
/// [`MAX_WIRE_ELEMENTS`]. Every occurrence counts, at every depth the schema
/// knows. The shape check or the decode refuses a frame that is not valid
/// protobuf.
pub fn check_request_shape(frame: &[u8]) -> Result<()> {
    let mut left = MAX_WIRE_ELEMENTS;
    walk(frame, Schema::Request, &mut left)
}

fn shape_error(e: prost::DecodeError) -> EnclaveError {
    EnclaveError::Framing(format!("request shape: {e}"))
}

fn walk(mut buf: &[u8], schema: Schema, left: &mut usize) -> Result<()> {
    while buf.has_remaining() {
        let (tag, wire_type) = decode_key(&mut buf).map_err(shape_error)?;
        *left = left.checked_sub(1).ok_or_else(|| {
            EnclaveError::Framing(format!(
                "request has more than {MAX_WIRE_ELEMENTS} elements"
            ))
        })?;
        match (schema.child(tag), wire_type) {
            (Schema::Leaf, _) => {
                skip_field(wire_type, tag, &mut buf, DecodeContext::default())
                    .map_err(shape_error)?;
            }
            (child, WireType::LengthDelimited) => {
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
            (_, _) => {
                // A nested message sent with another wire type: not a message.
                // The decode refuses it.
                skip_field(wire_type, tag, &mut buf, DecodeContext::default())
                    .map_err(shape_error)?;
            }
        }
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

    /// The request memory model (`memory.rs`): reading a frame of the largest
    /// size uses a small multiple of its bytes.
    #[test]
    fn a_frame_size_request_is_read_within_the_request_memory_factor() {
        use crate::memory::peak;
        use crate::proto::SignRawDigestRequest;

        let (wire, decoded, peak) = peak::measure(
            || {
                let req = EnclaveRequest {
                    request: Some(enclave_request::Request::SignRawDigest(
                        SignRawDigestRequest {
                            digest: Vec::new(),
                            unsigned_tx: vec![0xc0; MAX_MESSAGE_SIZE as usize - 64],
                        },
                    )),
                };
                let mut wire = Vec::new();
                write_message(&mut wire, &req).unwrap();
                wire
            },
            |wire| read_request(&mut Cursor::new(wire)).unwrap(),
        );
        assert!(wire.len() <= MAX_MESSAGE_SIZE as usize + 4);
        assert!(matches!(
            decoded.request,
            Some(enclave_request::Request::SignRawDigest(_))
        ));
        peak::assert_within_request_bound("read_request of a bytes frame", wire.len(), peak);
    }

    /// Protobuf wire helpers for shape tests: a varint and a length-delimited
    /// field.
    fn varint(mut v: u64, out: &mut Vec<u8>) {
        while v >= 0x80 {
            out.push((v as u8) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }
    fn len_field(field: u32, payload: &[u8], out: &mut Vec<u8>) {
        varint(u64::from(field) << 3 | 2, out);
        varint(payload.len() as u64, out);
        out.extend_from_slice(payload);
    }

    /// A `Sign` request whose RGB source has `n` Merkle proof entries with one
    /// empty path element each: 4 wire bytes per entry.
    fn sign_frame_with_empty_proof_entries(n: usize) -> Vec<u8> {
        let mut proofs = Vec::with_capacity(n * 4);
        for _ in 0..n {
            proofs.extend_from_slice(&[0x32, 0x02, 0x22, 0x00]);
        }
        let mut sign = Vec::new();
        len_field(3, &proofs, &mut sign); // SignRequest.rgb_source
        let mut request = Vec::new();
        len_field(3, &sign, &mut request); // EnclaveRequest.sign
        let mut wire = (request.len() as u32).to_le_bytes().to_vec();
        wire.extend_from_slice(&request);
        wire
    }

    /// The request memory model (`memory.rs`): the shape check refuses a frame
    /// of repeated empty entries before the decode. Without the check, the
    /// frame decoded into 45 times its size.
    #[test]
    fn a_frame_of_empty_proof_entries_is_refused_within_the_request_memory_factor() {
        use crate::memory::peak;

        let (wire, result, peak) = peak::measure(
            || sign_frame_with_empty_proof_entries((MAX_MESSAGE_SIZE as usize - 64) / 4),
            |wire| read_request(&mut Cursor::new(wire)).map(|_| ()),
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("more than"), "got: {err}");
        peak::assert_within_request_bound("read_request of empty proof entries", wire.len(), peak);
    }

    /// The element cap is exact. A `Sign` frame with `n` empty entries has
    /// 2 + 2n occurrences: `sign`, `rgb_source`, one for each entry and one
    /// for its path element. The frame at the cap is the most a request can
    /// expand, and it stays within the request bound.
    #[test]
    fn the_wire_element_cap_is_exact() {
        use crate::memory::peak;

        let (at_cap, decoded, peak) = peak::measure(
            || sign_frame_with_empty_proof_entries((MAX_WIRE_ELEMENTS - 2) / 2),
            |wire| read_request(&mut Cursor::new(wire)).unwrap(),
        );
        peak::assert_within_request_bound("read_request at the element cap", at_cap.len(), peak);
        let Some(enclave_request::Request::Sign(sign)) = decoded.request else {
            panic!("not a Sign request");
        };
        let Some(crate::proto::sign_request::SourceNetwork::RgbSource(source)) =
            sign.source_network
        else {
            panic!("not an RGB source");
        };
        assert_eq!(source.merkle_proofs.len(), (MAX_WIRE_ELEMENTS - 2) / 2);

        let over = sign_frame_with_empty_proof_entries((MAX_WIRE_ELEMENTS - 2) / 2 + 1);
        let err = read_request(&mut Cursor::new(&over))
            .unwrap_err()
            .to_string();
        assert!(err.contains("more than"), "got: {err}");
    }

    /// The largest real burn request passes the shape check: the proof cap
    /// of entries, each with a full mainnet path, and a consignment that the
    /// walk skips as bytes.
    #[test]
    fn the_largest_burn_request_passes_the_shape_check() {
        use crate::config::DEFAULT_MAX_MERKLE_PROOFS;
        use crate::proto::sign_request::SourceNetwork;
        use crate::proto::{MerkleProofEntry, RgbSource, SignRequest};

        let entry = MerkleProofEntry {
            txid: vec![0x11; 32],
            block_height: 900_000,
            tx_position: 4_000,
            merkle_path: vec![vec![0x5a; 32]; 13],
        };
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::Sign(SignRequest {
                amount: 1,
                source_network: Some(SourceNetwork::RgbSource(RgbSource {
                    consignment_valid: true,
                    asset_id: "rgb:test".into(),
                    // Bytes that look like protobuf keys. The walk skips them
                    // without counting them.
                    consignment: vec![0x32; 12 * 1024 * 1024],
                    consignment_hash: vec![0x22; 32],
                    merkle_proofs: vec![entry; DEFAULT_MAX_MERKLE_PROOFS],
                    commission: 0,
                })),
                destination_network: None,
            })),
        };
        let mut wire = Vec::new();
        write_message(&mut wire, &req).unwrap();
        assert!(
            wire.len() <= MAX_MESSAGE_SIZE as usize + 4,
            "{} bytes",
            wire.len()
        );
        let decoded = read_request(&mut Cursor::new(&wire)).unwrap();
        assert_eq!(decoded, req);
    }

    /// Handle each fixed test frame without a panic.
    /// Inputs stay below the frame limit.
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
