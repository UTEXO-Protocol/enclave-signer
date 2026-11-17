//! Request shape check before the protobuf decode.
//!
//! A decoded protobuf element costs far more memory than its wire form. An
//! empty `MerkleProofEntry` is 2 bytes on the wire and a 56-byte struct after
//! the decode, and its list can double while it grows. So a 24 MiB `Sign`
//! request of them needs 1.5 GiB of heap to decode, and the parent serves
//! several requests at once. [`ShapeLayer`] reads the whole request body first.
//! It counts the field occurrences on the wire, at every depth that the
//! schema knows, and refuses more than [`MAX_WIRE_ELEMENTS`]. Only then does
//! tonic decode the message.
//!
//! The layer also limits the `Sign` requests at once. Only `Sign` can carry
//! a large body, so each `Sign` request holds a permit until it ends. The
//! permit also stays with each blocking enclave exchange that the request
//! starts (see [`SIGN_PERMIT`]), so a cancelled or timed-out call does not
//! free its permit while its exchange still holds the decoded request. A
//! `Sign` request above the permits gets `UNAVAILABLE` at once. Every other
//! request needs no permit, and its body can have at most
//! [`MAX_OTHER_MESSAGE_SIZE`] bytes. So a health probe, such as the
//! `PublicKey` call of the signer node, still gets an answer while `Sign`
//! requests run. When its probe fails, the signer node reports the parent as
//! unreachable. After a probe that gets `UNAVAILABLE`, it also opens a new
//! connection, and that cancels each request on the old connection.
//!
//! The walk enters only the message fields that hold a repeated field, as
//! [`Schema::child`] lists them. It skips a `bytes` field such as the
//! consignment and never reads it as protobuf. When a request message of
//! `federated-signer-proto` gets a new repeated field inside a nested
//! message, add that path to [`Schema::child`].

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use http_body_util::BodyExt;
use prost::encoding::{decode_key, decode_varint, skip_field, DecodeContext, WireType};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::{body::Body, server::NamedService, Status};
use tower::{Layer, Service};

use crate::framing::MAX_MESSAGE_SIZE;
use crate::grpc_proto::parent_service_server::ParentServiceServer;
use crate::grpc_server::ParentAdapterService;

/// Maximum protobuf field occurrences in one request, the same limit as the
/// enclave. The largest real request is a burn with 16 384 proofs of 13 path
/// elements each. It has about 280 000 occurrences.
pub const MAX_WIRE_ELEMENTS: usize = 1 << 19;

/// The most bytes of the message of any request but `Sign`. The largest one
/// in use is `Clone`, which carries an attestation document. The enclave has
/// its own size limit for that document.
pub const MAX_OTHER_MESSAGE_SIZE: usize = 256 * 1024;

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

tokio::task_local! {
    /// The `Sign` permit of the request that runs in this task. A blocking
    /// exchange clones it, see [`current_sign_permit`].
    static SIGN_PERMIT: Arc<OwnedSemaphorePermit>;
}

/// The permit of the current `Sign` request, or `None` outside one. The
/// caller moves it into the blocking worker, so the permit lasts until the
/// worker ends, even when the waiting RPC future is gone.
pub(crate) fn current_sign_permit() -> Option<Arc<OwnedSemaphorePermit>> {
    SIGN_PERMIT.try_with(Arc::clone).ok()
}

/// Reads the whole body of each request and checks its shape before tonic
/// decodes it. Each `Sign` request also holds one of `max_sign` permits until
/// it ends, and a `Sign` request above them gets `UNAVAILABLE` before its
/// body is read. Add the layer inside the global concurrency limit, so that
/// the bodies it holds count against that limit.
#[derive(Clone, Debug)]
pub struct ShapeLayer {
    sign_permits: Arc<Semaphore>,
    max_sign: usize,
}

impl ShapeLayer {
    pub fn new(max_sign: usize) -> Self {
        Self {
            sign_permits: Arc::new(Semaphore::new(max_sign)),
            max_sign,
        }
    }
}

impl<S> Layer<S> for ShapeLayer {
    type Service = ShapeService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        ShapeService {
            inner,
            sign_permits: self.sign_permits.clone(),
            max_sign: self.max_sign,
        }
    }
}

#[derive(Clone)]
pub struct ShapeService<S> {
    inner: S,
    sign_permits: Arc<Semaphore>,
    max_sign: usize,
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
        let method = method_of(req.uri().path()).to_owned();
        let permit = if method == "Sign" {
            match self.sign_permits.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    let status = Status::unavailable(format!(
                        "the parent serves at most {} Sign requests at once",
                        self.max_sign
                    ));
                    return Box::pin(async move { Ok(status.into_http()) });
                }
            }
        } else {
            None
        };
        // Call the instance that `poll_ready` made ready, and keep a clone.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let permit = permit.map(Arc::new);
            let (parts, body) = req.into_parts();
            let bytes = match checked_body(&method, body).await {
                Ok(bytes) => bytes,
                Err(status) => return Ok(status.into_http()),
            };
            let req = http::Request::from_parts(parts, Body::new(http_body_util::Full::new(bytes)));
            match permit {
                Some(permit) => SIGN_PERMIT.scope(permit, inner.call(req)).await,
                None => inner.call(req).await,
            }
        })
    }
}

/// The RPC name in a request path, for example `Sign`, or "" for a path of
/// another service.
fn method_of(path: &str) -> &str {
    let service = <ParentServiceServer<ParentAdapterService> as NamedService>::NAME;
    path.strip_prefix('/')
        .and_then(|rest| rest.strip_prefix(service))
        .and_then(|rest| rest.strip_prefix('/'))
        .unwrap_or_default()
}

/// Reads at most one gRPC message and checks its shape. The message of
/// `Sign` can have [`MAX_MESSAGE_SIZE`] bytes, and the message of any other
/// method [`MAX_OTHER_MESSAGE_SIZE`]. Returns the body to pass on.
async fn checked_body(method: &str, body: Body) -> Result<Bytes, Status> {
    let message = if method == "Sign" {
        MAX_MESSAGE_SIZE as usize
    } else {
        MAX_OTHER_MESSAGE_SIZE
    };
    let limit = message + GRPC_PREFIX;
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
        sign_request, source_proof, EnrichedRgbPayload, MerkleProofEntry, RgbSource, SignRequest,
        SourceProof, SubmitHeadersRequest,
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

    /// A request with a value at the reserved `parent_fascia` number: the walk and the decode skip it.
    #[test]
    fn a_reserved_rgb_field_is_skipped() {
        let payload = EnrichedRgbPayload {
            psbt_bytes: vec![0xFF; 32],
            rgb_asset_id: "rgb:asset".into(),
            fascia: vec![0x05; 6],
        };
        let mut rgb = payload.encode_to_vec();
        prost::encoding::bytes::encode(10, &vec![0x04; 8], &mut rgb);
        let mut bytes = Vec::new();
        prost::encoding::bytes::encode(4, &rgb, &mut bytes);
        count_request_elements("Sign", &bytes).unwrap();
        let decoded = SignRequest::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded.data, Some(sign_request::Data::RgbData(payload)));
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

    /// Holds the permit of its request in a worker thread, as an enclave
    /// exchange does, and then never answers.
    #[derive(Clone)]
    struct HoldingService {
        release: Arc<std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>>,
        started: Arc<tokio::sync::Notify>,
    }

    impl Service<http::Request<Body>> for HoldingService {
        type Response = http::Response<Body>;
        type Error = std::convert::Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: http::Request<Body>) -> Self::Future {
            let release = self.release.lock().unwrap().take().unwrap();
            let started = self.started.clone();
            // As in a tonic handler, the work runs when the future is polled,
            // inside the permit scope.
            Box::pin(async move {
                let permit = current_sign_permit().expect("a Sign request has a permit");
                std::thread::spawn(move || {
                    let _permit = permit;
                    let _ = release.recv();
                });
                started.notify_one();
                std::future::pending().await
            })
        }
    }

    fn sign_http_request() -> http::Request<Body> {
        let service = <ParentServiceServer<ParentAdapterService> as NamedService>::NAME;
        http::Request::builder()
            .uri(format!("/{service}/Sign"))
            .body(Body::new(http_body_util::Full::new(Bytes::from_static(&[
                0, 0, 0, 0, 0,
            ]))))
            .unwrap()
    }

    /// A cancelled Sign call does not free its permit while its worker holds
    /// the request. The permit comes back when the worker ends.
    #[tokio::test]
    async fn a_cancelled_sign_keeps_its_permit_until_the_worker_ends() {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let started = Arc::new(tokio::sync::Notify::new());
        let layer = ShapeLayer::new(1);
        let mut svc = layer.layer(HoldingService {
            release: Arc::new(std::sync::Mutex::new(Some(wait))),
            started: started.clone(),
        });
        let call = svc.call(sign_http_request());
        let task = tokio::spawn(call);
        started.notified().await;
        task.abort();
        let _ = task.await;

        let refused = svc.call(sign_http_request()).await.unwrap();
        assert_eq!(
            refused.headers().get("grpc-status").unwrap(),
            &(tonic::Code::Unavailable as i32).to_string()
        );

        release.send(()).unwrap();
        for _ in 0..100 {
            if layer.sign_permits.available_permits() == 1 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("the permit was not released after the worker ended");
    }
}
