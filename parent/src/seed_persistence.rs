//! Optional seed storage bridge for AWS credentials and opaque KMS ciphertext.
//! The enclave chooses the flow, performs recipient-attested KMS calls and signs.
//! This is a separate, bounded JSON protocol, not the parent protobuf framing.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use aws_config::{retry::RetryConfig, timeout::TimeoutConfig, BehaviorVersion};
use aws_sdk_s3::{
    config::{ProvideCredentials, Region, SharedCredentialsProvider},
    error::{ProvideErrorMetadata, SdkError},
    primitives::ByteStream,
    Client,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{timeout, timeout_at, Instant},
};
use zeroize::Zeroizing;

use crate::config::Config;

const MAX_FRAME: usize = 65536;
const MAX_CIPHERTEXT: usize = 6144;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(7);
const MAX_CONNECTIONS: usize = 16;
const CONNECTIONS_PER_CID: usize = 4;
const OPERATIONS_PER_CID: usize = 2;
const OPERATION_RATE: f64 = 4.0;
const OPERATION_BURST: f64 = 8.0;

/// Fixed public diagnostics only: never wrap an SDK error or request content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("configuration_error")]
    Configuration,
    #[error("access_denied")]
    AccessDenied,
    #[error("aws_unavailable")]
    AwsUnavailable,
    #[error("invalid_ciphertext")]
    InvalidCiphertext,
    #[error("broker_busy")]
    Busy,
    #[error("operation_timeout")]
    OperationTimeout,
    #[error("request_timeout")]
    RequestTimeout,
    #[error("invalid_frame")]
    InvalidFrame,
    #[error("invalid_request")]
    InvalidRequest,
    #[error("seed_id_not_allowed")]
    SeedIdNotAllowed,
    #[error("response_too_large")]
    ResponseTooLarge,
    #[error("internal_error")]
    Internal,
}

struct Settings {
    seed_id: String,
    bucket: String,
    key: String,
    region: String,
    cids: Vec<u32>,
    tcp: Option<SocketAddr>,
}

impl Settings {
    fn read(parent: &Config, get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, Error> {
        if !CONFIG_KEYS.iter().any(|key| get(key).is_some()) {
            return Ok(None);
        }
        let required = |name| {
            get(name)
                .filter(|v| !v.is_empty() && v.trim() == v)
                .ok_or(Error::Configuration)
        };
        let seed_id = required("KMS_SEED_ID")?;
        let bucket = required("KMS_S3_BUCKET")?;
        let key = required("KMS_S3_KEY")?;
        let region = required("AWS_REGION")?;
        if seed_id.len() > 256 || bucket.len() > 255 || key.len() > 1024 || region.len() > 64 {
            return Err(Error::Configuration);
        }
        let tcp = get("KMS_BROKER_TCP")
            .map(|value| {
                let addr: SocketAddr = value.parse().map_err(|_| Error::Configuration)?;
                if parent.use_vsock
                    || addr.ip() != std::net::Ipv4Addr::LOCALHOST
                    || addr.port() == 0
                {
                    return Err(Error::Configuration);
                }
                Ok(addr)
            })
            .transpose()?;
        if tcp.is_none() && !parent.use_vsock {
            return Err(Error::Configuration);
        }
        let cids = if let Some(raw) = get("KMS_ALLOWED_CIDS") {
            if raw.len() > 4096 {
                return Err(Error::Configuration);
            }
            let mut cids = Vec::new();
            for value in raw.split(',') {
                let value = value.trim();
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Error::Configuration);
                }
                let cid: u32 = value.parse().map_err(|_| Error::Configuration)?;
                if cid <= 3 || cid == u32::MAX || cids.contains(&cid) {
                    return Err(Error::Configuration);
                }
                cids.push(cid);
            }
            if cids.len() > 64 {
                return Err(Error::Configuration);
            }
            cids
        } else {
            if parent.enclave_vsock_cid <= 3 || parent.enclave_vsock_cid == u32::MAX {
                return Err(Error::Configuration);
            }
            vec![parent.enclave_vsock_cid]
        };
        if get("KMS_BROKER_PORT").is_some_and(|port| port != "8004") {
            return Err(Error::Configuration);
        }
        Ok(Some(Self {
            seed_id,
            bucket,
            key,
            region,
            cids,
            tcp,
        }))
    }
}

const CONFIG_KEYS: [&str; 5] = [
    "KMS_SEED_ID",
    "KMS_S3_BUCKET",
    "KMS_S3_KEY",
    "KMS_ALLOWED_CIDS",
    "KMS_BROKER_TCP",
];

/// Shared activation predicate for configuration and safe startup logging.
pub fn configured() -> bool {
    CONFIG_KEYS
        .iter()
        .any(|name| std::env::var_os(name).is_some())
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
enum Request {
    Credentials {},
    Load { seed_id: String },
    Create { seed_id: String, ciphertext: String },
}

fn decode_ciphertext(text: &str) -> Result<Vec<u8>, Error> {
    if text.len() > MAX_CIPHERTEXT.div_ceil(3) * 4 {
        return Err(Error::InvalidCiphertext);
    }
    let blob = STANDARD
        .decode(text)
        .map_err(|_| Error::InvalidCiphertext)?;
    if blob.is_empty() || blob.len() > MAX_CIPHERTEXT || STANDARD.encode(&blob) != text {
        return Err(Error::InvalidCiphertext);
    }
    Ok(blob)
}

fn aws_code(code: Option<&str>) -> Error {
    match code {
        Some(
            "AccessDenied"
            | "AccessDeniedException"
            | "UnauthorizedOperation"
            | "InvalidAccessKeyId"
            | "InvalidClientTokenId"
            | "SignatureDoesNotMatch",
        ) => Error::AccessDenied,
        Some(
            "NoSuchBucket"
            | "PermanentRedirect"
            | "AuthorizationHeaderMalformed"
            | "IllegalLocationConstraintException"
            | "InvalidRegion",
        ) => Error::Configuration,
        _ => Error::AwsUnavailable,
    }
}

fn credential_error(error: &aws_credential_types::provider::error::CredentialsError) -> Error {
    use aws_credential_types::provider::error::CredentialsError;
    match error {
        CredentialsError::CredentialsNotLoaded(_) | CredentialsError::InvalidConfiguration(_) => {
            Error::Configuration
        }
        _ => Error::AwsUnavailable,
    }
}

fn sdk_error<E: ProvideErrorMetadata + std::error::Error + 'static>(error: &SdkError<E>) -> Error {
    // Identity-provider failures can be nested inside dispatch errors. Inspect
    // types only, never format provider diagnostics or signed request details.
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        if let Some(credentials) =
            cause.downcast_ref::<aws_credential_types::provider::error::CredentialsError>()
        {
            return credential_error(credentials);
        }
        source = cause.source();
    }
    if matches!(error, SdkError::ConstructionFailure(_)) {
        Error::Configuration
    } else {
        aws_code(error.as_service_error().and_then(|e| e.code()))
    }
}

fn service_error_is<E: ProvideErrorMetadata>(
    error: &SdkError<E>,
    status: u16,
    codes: &[&str],
) -> bool {
    error
        .raw_response()
        .is_some_and(|r| r.status().as_u16() == status)
        && error
            .as_service_error()
            .and_then(|e| e.code())
            .is_some_and(|code| codes.contains(&code))
}

struct Peer {
    connections: Arc<Semaphore>,
    operations: Arc<Semaphore>,
    tokens: Mutex<(f64, Instant)>,
}

impl Peer {
    fn new() -> Self {
        Self {
            connections: Arc::new(Semaphore::new(CONNECTIONS_PER_CID)),
            operations: Arc::new(Semaphore::new(OPERATIONS_PER_CID)),
            tokens: Mutex::new((OPERATION_BURST, Instant::now())),
        }
    }
    fn take_token(&self, now: Instant) -> Result<(), Error> {
        let mut bucket = self.tokens.lock().map_err(|_| Error::Internal)?;
        bucket.0 = OPERATION_BURST
            .min(bucket.0 + now.saturating_duration_since(bucket.1).as_secs_f64() * OPERATION_RATE);
        bucket.1 = now;
        if bucket.0 < 1.0 {
            return Err(Error::Busy);
        }
        bucket.0 -= 1.0;
        Ok(())
    }
}

fn acquire(
    global: &Arc<Semaphore>,
    peer: &Arc<Semaphore>,
) -> Result<(OwnedSemaphorePermit, OwnedSemaphorePermit), Error> {
    let global = global
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::Busy)?;
    let peer = peer.clone().try_acquire_owned().map_err(|_| Error::Busy)?;
    Ok((global, peer))
}

struct Broker {
    settings: Settings,
    s3: Client,
    credentials: SharedCredentialsProvider,
    connections: Arc<Semaphore>,
    operations: Arc<Semaphore>,
    peers: HashMap<u32, Arc<Peer>>,
}

impl Broker {
    fn new(settings: Settings, s3: Client, credentials: SharedCredentialsProvider) -> Self {
        let peers = if settings.tcp.is_some() {
            vec![0]
        } else {
            settings.cids.clone()
        }
        .into_iter()
        .map(|cid| (cid, Arc::new(Peer::new())))
        .collect();
        Self {
            settings,
            s3,
            credentials,
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            operations: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            peers,
        }
    }

    async fn load(&self) -> Result<Option<Vec<u8>>, Error> {
        let output = match self
            .s3
            .get_object()
            .bucket(&self.settings.bucket)
            .key(&self.settings.key)
            .send()
            .await
        {
            Ok(output) => output,
            Err(error) if service_error_is(&error, 404, &["NoSuchKey", "NotFound", "404"]) => {
                return Ok(None)
            }
            Err(error) => return Err(sdk_error(&error)),
        };
        let length = output.content_length;
        if length.is_some_and(|size| size <= 0 || size > MAX_CIPHERTEXT as i64) {
            return Err(Error::InvalidCiphertext);
        }
        // The SDK operation timeout ends at the headers. The caller's absolute
        // timeout also covers this capped streaming read, including a trickle.
        let mut blob = Vec::new();
        output
            .body
            .into_async_read()
            .take((MAX_CIPHERTEXT + 1) as u64)
            .read_to_end(&mut blob)
            .await
            .map_err(|_| Error::AwsUnavailable)?;
        if blob.is_empty()
            || blob.len() > MAX_CIPHERTEXT
            || length.is_some_and(|size| size != blob.len() as i64)
        {
            return Err(Error::InvalidCiphertext);
        }
        Ok(Some(blob))
    }

    async fn create(&self, blob: Vec<u8>) -> Result<Vec<u8>, Error> {
        match self
            .s3
            .put_object()
            .bucket(&self.settings.bucket)
            .key(&self.settings.key)
            .body(ByteStream::from(blob))
            .content_type("application/octet-stream")
            .if_none_match("*")
            .send()
            .await
        {
            Ok(_) => {}
            Err(error)
                if service_error_is(&error, 412, &["PreconditionFailed"])
                    || service_error_is(&error, 409, &["ConditionalRequestConflict"]) => {}
            Err(error) => return Err(sdk_error(&error)),
        }
        // Even a successful creator returns a GET of the committed winner.
        // A timed-out PUT can commit remotely; the next initialization loads it.
        self.load().await?.ok_or(Error::AwsUnavailable)
    }

    fn validate(&self, request: &Request) -> Result<(), Error> {
        match request {
            Request::Credentials {} => Ok(()),
            Request::Load { seed_id } | Request::Create { seed_id, .. }
                if seed_id != &self.settings.seed_id =>
            {
                Err(Error::SeedIdNotAllowed)
            }
            Request::Create { ciphertext, .. } => decode_ciphertext(ciphertext).map(|_| ()),
            _ => Ok(()),
        }
    }

    async fn dispatch(&self, request: Request) -> Result<Zeroizing<Vec<u8>>, Error> {
        #[derive(Serialize)]
        struct Credentials<'a> {
            access_key_id: &'a str,
            secret_access_key: &'a str,
            session_token: &'a str,
        }
        #[derive(Serialize)]
        struct Ciphertext {
            ciphertext: Option<String>,
        }
        match request {
            Request::Credentials {} => {
                // Admission grants the FULL role. Use a dedicated least-privilege
                // role; CID reuse is not attestation. KMS verifies the recipient.
                let credentials = self
                    .credentials
                    .provide_credentials()
                    .await
                    .map_err(|error| credential_error(&error))?;
                if credentials.access_key_id().is_empty()
                    || credentials.secret_access_key().is_empty()
                {
                    return Err(Error::Configuration);
                }
                json(&Credentials {
                    access_key_id: credentials.access_key_id(),
                    secret_access_key: credentials.secret_access_key(),
                    session_token: credentials.session_token().unwrap_or(""),
                })
            }
            Request::Load { .. } => json(&Ciphertext {
                ciphertext: self.load().await?.map(|blob| STANDARD.encode(blob)),
            }),
            Request::Create { ciphertext, .. } => json(&Ciphertext {
                ciphertext: Some(
                    STANDARD.encode(self.create(decode_ciphertext(&ciphertext)?).await?),
                ),
            }),
        }
    }

    async fn response(
        &self,
        request: Request,
        peer: &Peer,
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate(&request)?;
        let _permits = acquire(&self.operations, &peer.operations)?;
        peer.take_token(Instant::now())?;
        // Cancellation drops the entire async SDK/body future; there is no
        // detached blocking worker that can accumulate after repeated timeouts.
        timeout_at(
            deadline.min(Instant::now() + OPERATION_TIMEOUT),
            self.dispatch(request),
        )
        .await
        .map_err(|_| Error::OperationTimeout)?
    }

    async fn handle(&self, mut stream: Box<dyn Stream>, peer: Arc<Peer>, deadline: Instant) {
        let result = match read_request(&mut stream, deadline).await {
            Ok(request) => self.response(request, &peer, deadline).await,
            Err(error) => Err(error),
        };
        let payload = result.unwrap_or_else(|error| {
            tracing::warn!(code = %error, "seed persistence request failed");
            Zeroizing::new(format!("{{\"error\":\"{error}\"}}").into_bytes())
        });
        let _ = timeout_at(
            deadline.min(Instant::now() + Duration::from_secs(2)),
            async {
                stream
                    .write_all(&(payload.len() as u32).to_be_bytes())
                    .await?;
                stream.write_all(&payload).await?;
                stream.shutdown().await
            },
        )
        .await;
    }
}

fn json(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>, Error> {
    // Fixed storage avoids reallocations leaving credential fragments behind.
    // Cursor refuses overflow before any oversized response is allocated.
    let mut bytes = Zeroizing::new(vec![0; MAX_FRAME]);
    let length = {
        let mut cursor = std::io::Cursor::new(bytes.as_mut_slice());
        serde_json::to_writer(&mut cursor, value).map_err(|error| {
            if error.is_io() {
                Error::ResponseTooLarge
            } else {
                Error::Internal
            }
        })?;
        cursor.position() as usize
    };
    bytes.truncate(length);
    Ok(bytes)
}

async fn read_request(
    stream: &mut (impl AsyncRead + Unpin + ?Sized),
    deadline: Instant,
) -> Result<Request, Error> {
    timeout_at(deadline, async {
        let length = stream.read_u32().await.map_err(|_| Error::InvalidFrame)? as usize;
        if length == 0 || length > MAX_FRAME {
            return Err(Error::InvalidFrame);
        }
        let mut bytes = vec![0; length];
        stream
            .read_exact(&mut bytes)
            .await
            .map_err(|_| Error::InvalidFrame)?;
        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidRequest)
    })
    .await
    .map_err(|_| Error::RequestTimeout)?
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

enum Listener {
    Tcp(TcpListener),
    #[cfg(target_os = "linux")]
    Vsock(tokio_vsock::VsockListener),
}

impl Listener {
    async fn bind(settings: &Settings) -> Result<Self, Error> {
        if let Some(address) = settings.tcp {
            return TcpListener::bind(address)
                .await
                .map(Self::Tcp)
                .map_err(|_| Error::Configuration);
        }
        #[cfg(target_os = "linux")]
        {
            tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(3, 8004))
                .map(Self::Vsock)
                .map_err(|_| Error::Configuration)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::Configuration)
        }
    }
    async fn accept(&self) -> std::io::Result<(Box<dyn Stream>, u32)> {
        match self {
            Self::Tcp(listener) => {
                let (stream, address) = listener.accept().await?;
                // All loopback callers share one quota; TCP is development only.
                Ok((
                    Box::new(stream),
                    if address.ip() == std::net::Ipv4Addr::LOCALHOST {
                        0
                    } else {
                        u32::MAX
                    },
                ))
            }
            #[cfg(target_os = "linux")]
            Self::Vsock(listener) => {
                let (stream, address) = listener.accept().await?;
                Ok((Box::new(stream), address.cid()))
            }
        }
    }
}

async fn serve(listener: Listener, broker: Arc<Broker>) {
    loop {
        let (stream, cid) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(_) => {
                tracing::warn!("seed persistence accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Some(peer) = broker.peers.get(&cid).cloned() else {
            continue;
        };
        let Ok(permits) = acquire(&broker.connections, &peer.connections) else {
            continue;
        };
        let broker = broker.clone();
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        tokio::spawn(async move {
            let _permits = permits;
            broker.handle(stream, peer, deadline).await;
        });
    }
}

/// Bind before starting gRPC, so a partial persistence configuration fails startup.
/// With no seed storage environment variables this performs no AWS work.
pub async fn start(parent: &Config) -> Result<Option<JoinHandle<()>>, Error> {
    if !configured() {
        return Ok(None);
    }
    let settings =
        Settings::read(parent, |name| std::env::var(name).ok())?.ok_or(Error::Configuration)?;
    let listener = Listener::bind(&settings).await?;
    let shared = timeout(
        OPERATION_TIMEOUT,
        aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(settings.region.clone()))
            .retry_config(RetryConfig::standard().with_max_attempts(1))
            .timeout_config(
                TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(1))
                    .read_timeout(Duration::from_secs(2))
                    .operation_timeout(OPERATION_TIMEOUT)
                    .build(),
            )
            .load(),
    )
    .await
    .map_err(|_| Error::OperationTimeout)?;
    let credentials = shared.credentials_provider().ok_or(Error::Configuration)?;
    let s3_config = aws_sdk_s3::config::Builder::from(&shared)
        .force_path_style(settings.tcp.is_some())
        .build();
    let broker = Arc::new(Broker::new(
        settings,
        Client::from_conf(s3_config),
        credentials,
    ));
    tracing::info!("seed persistence bridge ready");
    Ok(Some(tokio::spawn(serve(listener, broker))))
}

#[cfg(test)]
mod tests;
