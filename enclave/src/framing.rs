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
/// memory than its wire form. A field occurrence can be 2 bytes on the wire
/// and about 80 bytes in memory. A `MerkleProofEntry` with one empty path
/// element is 4 bytes and two occurrences. So a 24 MiB frame of them decoded
/// into more than 1 GiB. The largest real request is a burn with 16 384
/// proofs of 13 path elements each. It has about 280 000 occurrences. The
/// memory model (`memory.rs`) budgets `WIRE_ELEMENT_BYTES` for each element.
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
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
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

    /// A message field sent with another wire type. The walk skips it, and
    /// the decode refuses it.
    #[test]
    fn a_message_field_with_another_wire_type_is_refused_by_the_decode() {
        // `EnclaveRequest.sign` (field 3) as a varint, then as a group.
        for body in [vec![0x18, 0x05], vec![0x1b, 0x1c]] {
            check_request_shape(&body).unwrap();
            let mut wire = (body.len() as u32).to_le_bytes().to_vec();
            wire.extend_from_slice(&body);
            let err = read_request(&mut Cursor::new(&wire)).unwrap_err();
            assert!(matches!(err, EnclaveError::ProtobufDecode(_)), "{err}");
        }
        // An end-group key with no open group: the shape check refuses it.
        let err = check_request_shape(&[0x1c]).unwrap_err();
        assert!(matches!(err, EnclaveError::Framing(_)), "{err}");
    }

    /// The proto the enclave decodes, verbatim from upstream
    /// (`enclave-proto/README.md`).
    const ENCLAVE_PROTO: &str = include_str!("../../enclave-proto/proto/enclave.proto");

    /// A field of a proto message.
    struct ProtoField {
        name: String,
        type_name: String,
        tag: u32,
        repeated: bool,
    }

    /// The proto3 scalar types. Every other field type must be a message or
    /// an enum of the same file.
    const PROTO_SCALARS: [&str; 15] = [
        "double", "float", "int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32",
        "fixed64", "sfixed32", "sfixed64", "bool", "string", "bytes",
    ];

    /// The scalar types that proto3 packs: one key for all values.
    fn is_packable_scalar(type_name: &str) -> bool {
        PROTO_SCALARS.contains(&type_name) && !["string", "bytes"].contains(&type_name)
    }

    /// Parses the messages of a proto3 file with no imports and no nested
    /// definitions. It accepts `syntax`, `package` and `option` lines,
    /// `message`, `oneof` and `enum` blocks, field lines with a bare type
    /// name, `reserved` lines and `//` comments. It panics on any other
    /// construct, so a new construct fails the test instead of hiding a
    /// field.
    fn parse_proto_messages(proto: &str) -> BTreeMap<String, Vec<ProtoField>> {
        let mut messages: BTreeMap<String, Vec<ProtoField>> = BTreeMap::new();
        let mut enums: BTreeSet<String> = BTreeSet::new();
        let mut current: Option<String> = None;
        let mut in_oneof = false;
        let mut in_enum = false;
        let block_name = |rest: &str, raw: &str| -> (String, bool) {
            match rest.strip_suffix("{}") {
                Some(name) => (name.trim().to_string(), true),
                None => {
                    let name = rest
                        .strip_suffix('{')
                        .unwrap_or_else(|| panic!("block line: {raw:?}"));
                    (name.trim().to_string(), false)
                }
            }
        };
        for raw in proto.lines() {
            let line = raw.split("//").next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            if in_enum {
                in_enum = line != "}";
                continue;
            }
            if let Some(rest) = line.strip_prefix("message ") {
                assert!(current.is_none(), "nested message: {raw:?}");
                let (name, empty) = block_name(rest, raw);
                let fresh = messages.insert(name.clone(), Vec::new()).is_none();
                assert!(fresh, "duplicate message {name}");
                if !empty {
                    current = Some(name);
                }
                continue;
            }
            if let Some(rest) = line.strip_prefix("enum ") {
                let (name, empty) = block_name(rest, raw);
                assert!(enums.insert(name.clone()), "duplicate enum {name}");
                in_enum = !empty;
                continue;
            }
            if line.starts_with("oneof ") {
                in_oneof = true;
                continue;
            }
            if line == "}" {
                if in_oneof {
                    in_oneof = false;
                } else {
                    assert!(current.take().is_some(), "stray brace: {raw:?}");
                }
                continue;
            }
            if ["syntax ", "package ", "option ", "reserved "]
                .iter()
                .any(|prefix| line.starts_with(prefix))
            {
                continue;
            }
            let message = current
                .as_deref()
                .unwrap_or_else(|| panic!("field outside a message: {raw:?}"));
            // `[repeated|optional] type name = tag [options];`
            let decl = line
                .strip_suffix(';')
                .unwrap_or_else(|| panic!("unknown line: {raw:?}"));
            let decl = decl.split('[').next().unwrap_or_default().trim();
            let mut words = decl.split_whitespace();
            let mut word = words.next().unwrap_or_default();
            let repeated = word == "repeated";
            if repeated || word == "optional" {
                word = words.next().unwrap_or_default();
            }
            assert!(
                !word.starts_with("map<"),
                "map field, count it as repeated: {raw:?}"
            );
            let type_name = word.to_string();
            let name = words.next().unwrap_or_default().to_string();
            assert_eq!(words.next(), Some("="), "unknown line: {raw:?}");
            let tag = words
                .next()
                .and_then(|tag| tag.parse().ok())
                .unwrap_or_else(|| panic!("tag: {raw:?}"));
            assert!(words.next().is_none(), "unknown line: {raw:?}");
            messages.get_mut(message).unwrap().push(ProtoField {
                name,
                type_name,
                tag,
                repeated,
            });
        }
        assert!(current.is_none() && !in_oneof && !in_enum, "unclosed block");
        // A qualified or imported type name would pass as a scalar below.
        for (message, fields) in &messages {
            for field in fields {
                let known = PROTO_SCALARS.contains(&field.type_name.as_str())
                    || messages.contains_key(&field.type_name)
                    || enums.contains(&field.type_name);
                assert!(
                    known,
                    "{message}.{}: unknown type {:?}; use a bare message, enum or scalar name",
                    field.name, field.type_name
                );
            }
        }
        messages
    }

    /// The proto message each schema variant walks.
    fn schema_message(schema: Schema) -> Option<&'static str> {
        match schema {
            Schema::Request => Some("EnclaveRequest"),
            Schema::Sign => Some("SignRequest"),
            Schema::RgbSource => Some("RgbSource"),
            Schema::MerkleProofEntry => Some("MerkleProofEntry"),
            Schema::SubmitHeaders => Some("SubmitHeadersRequest"),
            Schema::Leaf => None,
        }
    }

    const WALKED: [Schema; 5] = [
        Schema::Request,
        Schema::Sign,
        Schema::RgbSource,
        Schema::MerkleProofEntry,
        Schema::SubmitHeaders,
    ];

    fn schema_of(message: &str) -> Schema {
        WALKED
            .into_iter()
            .find(|schema| schema_message(*schema) == Some(message))
            .unwrap_or(Schema::Leaf)
    }

    /// True when `message`, or a message it holds at any depth, has a
    /// repeated field.
    fn holds_repeated_fields(
        message: &str,
        messages: &BTreeMap<String, Vec<ProtoField>>,
        depth: usize,
    ) -> bool {
        assert!(depth < 16, "message cycle at {message}");
        messages[message].iter().any(|field| {
            field.repeated
                || (messages.contains_key(&field.type_name)
                    && holds_repeated_fields(&field.type_name, messages, depth + 1))
        })
    }

    /// The schema walk matches the proto. From `EnclaveRequest`, every message
    /// field that holds a repeated field at any depth leads to the schema the
    /// walk enters, and every other message field is a leaf. A new repeated
    /// field in a message the walk does not enter fails this test until
    /// `Schema::child` names its path. Without that, the decode could again
    /// expand a small frame into many elements.
    #[test]
    fn the_shape_walk_knows_every_repeated_field_of_the_proto() {
        let messages = parse_proto_messages(ENCLAVE_PROTO);
        assert!(messages.len() > 30, "{} messages parsed", messages.len());

        let mut repeated = 0;
        let mut todo = vec!["EnclaveRequest"];
        let mut seen = BTreeSet::new();
        while let Some(name) = todo.pop() {
            if !seen.insert(name) {
                continue;
            }
            let schema = schema_of(name);
            for field in &messages[name] {
                repeated += usize::from(field.repeated);
                let at = format!(
                    "{name}.{} (tag {}, {})",
                    field.name, field.tag, field.type_name
                );
                let child = schema.child(field.tag);
                if !messages.contains_key(&field.type_name) {
                    // A scalar, enum, string or bytes field: the walk skips it.
                    assert_eq!(child, Schema::Leaf, "{at} is not a message");
                    assert!(
                        !(field.repeated && is_packable_scalar(&field.type_name)),
                        "{at} is a packed repeated scalar: one occurrence for many values. \
                         Extend the request memory model before adding it."
                    );
                    continue;
                }
                todo.push(&field.type_name);
                if holds_repeated_fields(&field.type_name, &messages, 0) {
                    assert_ne!(
                        schema,
                        Schema::Leaf,
                        "{at} holds repeated fields, but the walk does not enter {name}: \
                         add a Schema variant for it"
                    );
                    assert_eq!(
                        schema_message(child),
                        Some(field.type_name.as_str()),
                        "{at} holds repeated fields, and Schema::child gives {child:?}: \
                         add the path to Schema::child"
                    );
                } else {
                    assert_eq!(
                        child,
                        Schema::Leaf,
                        "{at} holds no repeated field, so Schema::child need not enter it"
                    );
                }
            }
        }
        assert!(
            repeated >= 3,
            "{repeated} repeated fields reachable from EnclaveRequest"
        );
        for schema in WALKED {
            let name = schema_message(schema).unwrap();
            assert!(
                seen.contains(name),
                "{schema:?} ({name}) is not reachable from EnclaveRequest"
            );
            assert!(
                holds_repeated_fields(name, &messages, 0),
                "{schema:?} ({name}) holds no repeated field, so the walk need not enter it"
            );
        }
    }

    /// Bytes that look like protobuf keys and lengths. Drawn at random, they
    /// make nested messages, groups, truncated varints and lengths past the
    /// frame.
    const KEY_LIKE_BYTES: [u8; 12] = [
        0x18, 0x1a, 0x1b, 0x1c, 0x32, 0x22, 0x5a, 0x00, 0x01, 0x02, 0x7f, 0xff,
    ];

    /// Handle each fixed test frame without a panic, through the plain read
    /// and through the shape check. Inputs stay below the frame limit.
    #[test]
    fn framed_garbage_corpus_never_panics() {
        let mut state = 0xD1B5_4A32_D192_ED03u64;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        };
        let frame = |body: &[u8]| {
            let mut buf = (body.len() as u32).to_le_bytes().to_vec();
            buf.extend_from_slice(body);
            buf
        };
        for len in [1usize, 2, 5, 13, 64, 255, 1024, 4096, 65536] {
            let body: Vec<u8> = (0..len).map(|_| next()).collect();
            let _res: Result<EnclaveRequest> = read_message(&mut Cursor::new(frame(&body)));
            let _res = read_request(&mut Cursor::new(frame(&body)));
            let keys: Vec<u8> = body
                .iter()
                .map(|b| KEY_LIKE_BYTES[usize::from(*b) % KEY_LIKE_BYTES.len()])
                .collect();
            let _res = read_request(&mut Cursor::new(frame(&keys)));
        }
    }
}
