//! Request shape check before the protobuf decode.
//!
//! A decoded protobuf element costs far more memory than its wire form. An
//! empty `MerkleProofEntry` is 2 bytes on the wire and a 56-byte struct after
//! the decode, and its list can double while it grows. So a 24 MiB `Sign`
//! request of them took 1.5 GiB of heap in the parent, and the parent serves
//! several requests at once. [`ShapeLayer`] reads the whole request body first.
//! It counts the field occurrences on the wire, at every depth that the
//! schema knows, and refuses more than [`MAX_WIRE_ELEMENTS`]. Only then does
//! tonic decode the message.
//!
//! The walk enters only the message fields that hold a repeated field, as
//! [`Schema::child`] lists them. It skips a `bytes` field such as the
//! consignment and never reads it as protobuf. When a request message of
//! `federated-signer-proto` gets a new repeated field inside a nested
//! message, add that path to [`Schema::child`].

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use http_body_util::BodyExt;
use prost::encoding::{decode_key, decode_varint, skip_field, DecodeContext, WireType};
use tonic::{body::Body, server::NamedService, Status};
use tower::{Layer, Service};

use crate::framing::MAX_MESSAGE_SIZE;
use crate::grpc_proto::parent_service_server::ParentServiceServer;
use crate::grpc_server::ParentAdapterService;

/// Maximum protobuf field occurrences in one request, the same limit as the
/// enclave. The largest real request is a burn with 16 384 proofs of 13 path
/// elements each. It has about 280 000 occurrences.
pub const MAX_WIRE_ELEMENTS: usize = 1 << 19;

/// The gRPC prefix of each message: a compression flag and a 4-byte length.
const GRPC_PREFIX: usize = 5;

/// The request messages that hold a repeated field, or a message with one.
/// The walk recurses only along these paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Schema {
    /// `parent.SignRequest`: field 2 is `source`.
    Sign,
    /// `parent.SourceProof`: field 11 is `rgb`.
    SourceProof,
    /// `parent.RgbSource`: field 5 is the repeated `merkle_proofs`.
    RgbSource,
    /// `parent.MerkleProofEntry`: field 4 is the repeated `merkle_path`. Its
    /// elements are bytes, so the walk counts them and enters none.
    MerkleProofEntry,
    /// A message with no repeated message field, or a scalar, string or bytes
    /// field. Not entered. `SubmitHeadersRequest` is a leaf too: the walk
    /// counts each of its `headers` at the top level.
    Leaf,
}

impl Schema {
    fn for_method(method: &str) -> Schema {
        match method {
            "Sign" => Schema::Sign,
            _ => Schema::Leaf,
        }
    }

    fn child(self, tag: u32) -> Schema {
        match (self, tag) {
            (Schema::Sign, 2) => Schema::SourceProof,
            (Schema::SourceProof, 11) => Schema::RgbSource,
            (Schema::RgbSource, 5) => Schema::MerkleProofEntry,
            _ => Schema::Leaf,
        }
    }
}

/// The field occurrences of the protobuf message of a request to `method`,
/// or the refusal. `method` is the RPC name, for example `Sign`.
pub fn count_request_elements(method: &str, message: &[u8]) -> Result<usize, Status> {
    let mut left = MAX_WIRE_ELEMENTS;
    walk(message, Schema::for_method(method), &mut left)?;
    Ok(MAX_WIRE_ELEMENTS - left)
}

fn shape_error(e: prost::DecodeError) -> Status {
    Status::invalid_argument(format!("request shape: {e}"))
}

fn walk(mut buf: &[u8], schema: Schema, left: &mut usize) -> Result<(), Status> {
    while buf.has_remaining() {
        let (tag, wire_type) = decode_key(&mut buf).map_err(shape_error)?;
        *left = left.checked_sub(1).ok_or_else(|| {
            Status::invalid_argument(format!(
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
            .ok_or_else(|| Status::invalid_argument("request shape: nested message truncated"))?;
        walk(&buf[..len], child, left)?;
        buf.advance(len);
    }
    Ok(())
}

/// Reads the whole body of each request and checks its shape before tonic
/// decodes it. Add it inside the concurrency limit, so that the bodies it
/// holds count against that limit.
#[derive(Clone, Copy, Debug, Default)]
pub struct ShapeLayer;

impl<S> Layer<S> for ShapeLayer {
    type Service = ShapeService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        ShapeService { inner }
    }
}

#[derive(Clone)]
pub struct ShapeService<S> {
    inner: S,
}

impl<S> Service<http::Request<Body>> for ShapeService<S>
where
    S: Service<http::Request<Body>, Response = http::Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = http::Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        // Call the instance that `poll_ready` made ready, and keep a clone.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let bytes = match checked_body(parts.uri.path(), body).await {
                Ok(bytes) => bytes,
                Err(status) => return Ok(status.into_http()),
            };
            let req = http::Request::from_parts(parts, Body::new(http_body_util::Full::new(bytes)));
            inner.call(req).await
        })
    }
}

/// Reads at most one gRPC message of at most [`MAX_MESSAGE_SIZE`] bytes and
/// checks its shape. Returns the body to pass on.
async fn checked_body(path: &str, body: Body) -> Result<Bytes, Status> {
    let prefix = format!(
        "/{}/",
        <ParentServiceServer<ParentAdapterService> as NamedService>::NAME
    );
    let method = path.strip_prefix(&prefix).unwrap_or_default();
    let limit = MAX_MESSAGE_SIZE as usize + GRPC_PREFIX;
    let bytes = http_body_util::Limited::new(body, limit)
        .collect()
        .await
        .map_err(|_| {
            Status::resource_exhausted(format!(
                "request body is larger than {limit} bytes or cannot be read"
            ))
        })?
        .to_bytes();
    if bytes.len() < GRPC_PREFIX {
        return Err(Status::invalid_argument("request has no gRPC message"));
    }
    if bytes[0] != 0 {
        return Err(Status::unimplemented(
            "compressed requests are not accepted",
        ));
    }
    let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    if bytes.len() != GRPC_PREFIX + len {
        return Err(Status::invalid_argument(
            "request must hold exactly one gRPC message",
        ));
    }
    count_request_elements(method, &bytes[GRPC_PREFIX..])?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc_proto::{
        source_proof, MerkleProofEntry, RgbSource, SignRequest, SourceProof, SubmitHeadersRequest,
    };
    use prost::Message;

    fn proof(path: usize) -> MerkleProofEntry {
        MerkleProofEntry {
            txid: vec![0x11; 32],
            block_height: 900_000,
            tx_position: 7,
            merkle_path: vec![vec![0x22; 32]; path],
        }
    }

    fn rgb_sign(proofs: Vec<MerkleProofEntry>) -> SignRequest {
        SignRequest {
            common: Some(Default::default()),
            source: Some(SourceProof {
                chain: Some(source_proof::Chain::Rgb(RgbSource {
                    consignment: vec![0x33; 1024],
                    merkle_proofs: proofs,
                    ..Default::default()
                })),
                ..Default::default()
            }),
            data: None,
        }
    }

    /// The largest real request passes: 16 384 proofs of 13 path elements.
    /// The count is exact, so the walk enters every path that holds them.
    #[test]
    fn the_largest_real_request_passes_with_an_exact_count() {
        let req = rgb_sign(vec![proof(13); 16_384]);
        let count = count_request_elements("Sign", &req.encode_to_vec()).unwrap();
        // The count: common and source, then rgb, then the consignment and
        // each proof. Each proof adds its txid, height, position and 13 path
        // elements.
        assert_eq!(count, 2 + 1 + 1 + 16_384 + 16_384 * 16);
    }

    /// Empty proof entries are 2 bytes each on the wire. One more than the
    /// limit is refused.
    #[test]
    fn one_element_over_the_limit_is_refused() {
        let at_limit = MAX_WIRE_ELEMENTS - 4;
        for (entries, ok) in [(at_limit, true), (at_limit + 1, false)] {
            let req = rgb_sign(vec![MerkleProofEntry::default(); entries]);
            let result = count_request_elements("Sign", &req.encode_to_vec());
            assert_eq!(result.is_ok(), ok, "{entries} entries: {result:?}");
            if let Err(status) = result {
                assert!(
                    status.message().contains("more than 524288 elements"),
                    "{status}"
                );
            }
        }
    }

    /// prost merges a message field that occurs twice, so the proofs of both
    /// sources add up. The walk counts both.
    #[test]
    fn the_proofs_of_a_repeated_source_add_up() {
        let mut bytes = rgb_sign(vec![proof(1); 10]).encode_to_vec();
        let source = SourceProof {
            chain: Some(source_proof::Chain::Rgb(RgbSource {
                merkle_proofs: vec![proof(1); 10],
                ..Default::default()
            })),
            ..Default::default()
        };
        bytes.push(0x12);
        prost::encoding::encode_varint(source.encoded_len() as u64, &mut bytes);
        source.encode(&mut bytes).unwrap();
        let once = count_request_elements("Sign", &rgb_sign(vec![proof(1); 10]).encode_to_vec());
        let twice = count_request_elements("Sign", &bytes).unwrap();
        assert_eq!(twice, once.unwrap() + 1 + 1 + 10 + 10 * 4);
        let decoded = SignRequest::decode(bytes.as_slice()).unwrap();
        let Some(source_proof::Chain::Rgb(rgb)) = decoded.source.unwrap().chain else {
            panic!("no RGB source");
        };
        assert_eq!(rgb.merkle_proofs.len(), 20);
    }

    /// Each header of `SubmitHeaders` counts at the top level.
    #[test]
    fn each_header_counts() {
        let req = SubmitHeadersRequest {
            headers: vec![vec![0u8; 80]; 500],
            start_height: 900_000,
        };
        assert_eq!(
            count_request_elements("SubmitHeaders", &req.encode_to_vec()).unwrap(),
            500 + 1
        );
    }

    /// A nested message longer than the bytes that hold it is refused.
    #[test]
    fn a_truncated_nested_message_is_refused() {
        let bytes = [0x12, 0x05, 0x5a, 0x00];
        let err = count_request_elements("Sign", &bytes).unwrap_err();
        assert!(err.message().contains("truncated"), "{err}");
    }

    /// The walk enters no field of a method that it does not know. So a field
    /// there that is not a valid message does not refuse the request.
    #[test]
    fn other_methods_count_only_the_top_level() {
        let bytes = [0x12, 0x02, 0xff, 0xff];
        assert_eq!(count_request_elements("Clone", &bytes).unwrap(), 1);
    }
}
