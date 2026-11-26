//! Request shape check before the protobuf decode.
//!
//! The decode of a repeated field can take far more memory than its wire
//! form: each element is a value in a list that can double while it grows,
//! and the parent serves several requests at once. [`ShapeLayer`] reads the
//! whole request body first. It counts the field occurrences on the wire and
//! refuses more than [`MAX_WIRE_ELEMENTS`]. Only then does tonic decode the
//! message.
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
//! The walk counts the top-level fields of a request message and reads no
//! field as protobuf. No request message of `federated-signer-proto` holds a
//! repeated field inside a nested message. When one does, the walk must enter
//! that message.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use http_body_util::BodyExt;
use prost::encoding::{decode_key, skip_field, DecodeContext};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::{body::Body, server::NamedService, Status};
use tower::{Layer, Service};

use crate::framing::MAX_MESSAGE_SIZE;
use crate::grpc_proto::parent_service_server::ParentServiceServer;
use crate::grpc_server::ParentAdapterService;

/// Maximum protobuf field occurrences in one request, the same limit as the
/// enclave.
pub const MAX_WIRE_ELEMENTS: usize = 1 << 19;

/// The most bytes of the message of any request but `Sign`. The largest one
/// in use is `Clone`, which carries an attestation document. The enclave has
/// its own size limit for that document.
pub const MAX_OTHER_MESSAGE_SIZE: usize = 256 * 1024;

/// The gRPC prefix of each message: a compression flag and a 4-byte length.
const GRPC_PREFIX: usize = 5;

/// The field occurrences of the protobuf message of a request, or the
/// refusal. Only the top level counts.
pub fn count_request_elements(message: &[u8]) -> Result<usize, Status> {
    let mut buf = message;
    let mut count = 0;
    while buf.has_remaining() {
        let (tag, wire_type) = decode_key(&mut buf).map_err(shape_error)?;
        count += 1;
        if count > MAX_WIRE_ELEMENTS {
            return Err(Status::invalid_argument(format!(
                "request has more than {MAX_WIRE_ELEMENTS} elements"
            )));
        }
        skip_field(wire_type, tag, &mut buf, DecodeContext::default()).map_err(shape_error)?;
    }
    Ok(count)
}

fn shape_error(e: prost::DecodeError) -> Status {
    Status::invalid_argument(format!("request shape: {e}"))
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
    count_request_elements(&bytes[GRPC_PREFIX..])?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc_proto::{
        sign_request, source_proof, EnrichedRgbPayload, RgbSource, SignRequest, SourceProof,
        SubmitHeadersRequest,
    };
    use prost::Message;

    /// A burn counts its top-level fields only: `common` and `source`.
    #[test]
    fn a_burn_counts_its_top_level_fields() {
        let req = SignRequest {
            common: Some(Default::default()),
            source: Some(SourceProof {
                chain: Some(source_proof::Chain::Rgb(RgbSource {
                    consignment: vec![0x33; 1024],
                    ..Default::default()
                })),
                ..Default::default()
            }),
            data: None,
        };
        assert_eq!(count_request_elements(&req.encode_to_vec()).unwrap(), 2);
    }

    /// Empty `common` fields are 2 bytes each on the wire, and the decode
    /// merges them. One more than the limit is refused.
    #[test]
    fn one_element_over_the_limit_is_refused() {
        for (fields, ok) in [(MAX_WIRE_ELEMENTS, true), (MAX_WIRE_ELEMENTS + 1, false)] {
            let body = [0x0a, 0x00].repeat(fields);
            let result = count_request_elements(&body);
            assert_eq!(result.is_ok(), ok, "{fields} fields: {result:?}");
            if let Err(status) = result {
                assert!(
                    status.message().contains("more than 524288 elements"),
                    "{status}"
                );
            }
        }
    }

    /// A request with proofs at the reserved `merkle_proofs` number of
    /// `RgbSource`: the walk and the decode skip them.
    #[test]
    fn proofs_at_the_reserved_number_are_skipped() {
        let mut rgb = RgbSource {
            consignment: vec![0x33; 64],
            ..Default::default()
        }
        .encode_to_vec();
        // One proof: a txid and a path element.
        let proof = vec![0x0a, 0x02, 0x11, 0x11, 0x22, 0x02, 0x22, 0x22];
        prost::encoding::bytes::encode(5, &proof, &mut rgb);
        let mut source = Vec::new();
        prost::encoding::bytes::encode(11, &rgb, &mut source);
        let mut bytes = Vec::new();
        prost::encoding::bytes::encode(2, &source, &mut bytes);
        assert_eq!(count_request_elements(&bytes).unwrap(), 1);
        let decoded = SignRequest::decode(bytes.as_slice()).unwrap();
        let Some(source_proof::Chain::Rgb(rgb)) = decoded.source.unwrap().chain else {
            panic!("no RGB source");
        };
        assert_eq!(rgb.consignment, vec![0x33; 64]);
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
        count_request_elements(&bytes).unwrap();
        let decoded = SignRequest::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded.data, Some(sign_request::Data::RgbData(payload)));
    }

    /// Each header of `SubmitHeaders` counts.
    #[test]
    fn each_header_counts() {
        let req = SubmitHeadersRequest {
            headers: vec![vec![0u8; 80]; 500],
            start_height: 900_000,
        };
        assert_eq!(
            count_request_elements(&req.encode_to_vec()).unwrap(),
            500 + 1
        );
    }

    /// A field longer than the bytes that hold it is refused.
    #[test]
    fn a_truncated_field_is_refused() {
        let bytes = [0x12, 0x05, 0x5a, 0x00];
        let err = count_request_elements(&bytes).unwrap_err();
        assert!(err.message().contains("request shape"), "{err}");
    }

    /// The walk reads no field as protobuf, so a field that is not a valid
    /// message does not refuse the request. The decode refuses it.
    #[test]
    fn the_walk_counts_only_the_top_level() {
        let bytes = [0x12, 0x02, 0xff, 0xff];
        assert_eq!(count_request_elements(&bytes).unwrap(), 1);
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
