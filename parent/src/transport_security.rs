//! Host gRPC perimeter. TLS authenticates the peer; leaf SHA-256 pins grant
//! explicit RPC roles before protobuf handlers or enclave I/O are invoked.
use anyhow::{bail, Context as _, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tonic::{
    body::Body,
    transport::{
        server::{TcpConnectInfo, TlsConnectInfo},
        Certificate, ClientTlsConfig, Endpoint, Identity, ServerTlsConfig,
    },
    Status,
};
use tower::{Layer, Service};

#[derive(Clone, Copy, Debug)]
enum Role {
    CloneOperator,
    Listener,
    Observer,
}

pub struct ServerSecurity {
    pub tls: Option<ServerTlsConfig>,
    pub access: AccessLayer,
    pub max_connections: usize,
}

fn value(key: &str) -> Result<Option<String>> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Ok(Some(v)),
        Ok(_) => bail!("{key} must not be empty"),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(e).with_context(|| key.to_string()),
    }
}
fn read(path: &str) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading TLS file {path}"))
}

impl ServerSecurity {
    pub fn from_env(bind: std::net::IpAddr) -> Result<Self> {
        // Other workspace dependencies may also enable aws-lc. Select ring
        // explicitly so feature unification cannot make rustls panic at startup.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let max_connections = value("GRPC_MAX_CONNECTIONS")?
            .unwrap_or_else(|| "64".into())
            .parse::<usize>()
            .context("invalid GRPC_MAX_CONNECTIONS")?;
        if !(1..=4096).contains(&max_connections) {
            bail!("GRPC_MAX_CONNECTIONS must be 1..4096");
        }
        let cert = value("GRPC_TLS_CERT_FILE")?;
        let key = value("GRPC_TLS_KEY_FILE")?;
        let ca = value("GRPC_TLS_CLIENT_CA_FILE")?;
        let acl = value("GRPC_TLS_ACL_FILE")?;
        let insecure = value("GRPC_ALLOW_INSECURE_LOOPBACK")?;
        if insecure.is_some() && insecure.as_deref() != Some("true") {
            bail!("GRPC_ALLOW_INSECURE_LOOPBACK must be true or absent");
        }
        if insecure.is_some() {
            if !bind.is_loopback()
                || cert.is_some()
                || key.is_some()
                || ca.is_some()
                || acl.is_some()
            {
                bail!("insecure mode requires loopback bind and no TLS settings");
            }
            return Ok(Self {
                tls: None,
                access: AccessLayer::insecure_loopback(),
                max_connections,
            });
        }
        let (Some(cert), Some(key), Some(ca), Some(acl)) = (cert, key, ca, acl) else {
            bail!("mTLS requires GRPC_TLS_CERT_FILE, GRPC_TLS_KEY_FILE, GRPC_TLS_CLIENT_CA_FILE and GRPC_TLS_ACL_FILE");
        };
        let limit = value("GRPC_CLONE_MAX_PER_MINUTE")?
            .unwrap_or_else(|| "30".into())
            .parse::<u32>()
            .context("invalid GRPC_CLONE_MAX_PER_MINUTE")?;
        if !(1..=10000).contains(&limit) {
            bail!("GRPC_CLONE_MAX_PER_MINUTE must be 1..10000");
        }
        let access = AccessLayer::from_acl(
            &std::fs::read_to_string(acl)?,
            limit,
            Duration::from_secs(60),
        )?;
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(read(&cert)?, read(&key)?))
            .client_ca_root(Certificate::from_pem(read(&ca)?))
            .client_auth_optional(false)
            .timeout(Duration::from_secs(5));
        Ok(Self {
            tls: Some(tls),
            access,
            max_connections,
        })
    }
}

/// Shared Rust client settings used by clone and attest-verify. Only explicit
/// HTTP loopback is allowed without TLS; partial settings never downgrade.
pub fn client_endpoint(url: &str) -> Result<Endpoint> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let endpoint = Endpoint::from_shared(url.to_owned())?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(60));
    let ca = value("PARENT_TLS_CA_FILE")?;
    let cert = value("PARENT_TLS_CERT_FILE")?;
    let key = value("PARENT_TLS_KEY_FILE")?;
    let name = value("PARENT_TLS_SERVER_NAME")?;
    if endpoint.uri().scheme_str() == Some("http") {
        let host = endpoint.uri().host().unwrap_or("").trim_matches(['[', ']']);
        let local = host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
        if !local || ca.is_some() || cert.is_some() || key.is_some() || name.is_some() {
            bail!("plaintext is allowed only for explicit loopback IP without TLS settings");
        }
        return Ok(endpoint);
    }
    if endpoint.uri().scheme_str() != Some("https") {
        bail!("Parent endpoint requires https");
    }
    let (Some(ca), Some(cert), Some(key)) = (ca, cert, key) else {
        bail!("https Parent requires PARENT_TLS_CA_FILE, PARENT_TLS_CERT_FILE and PARENT_TLS_KEY_FILE");
    };
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(read(&ca)?))
        .identity(Identity::from_pem(read(&cert)?, read(&key)?));
    if let Some(name) = name {
        tls = tls.domain_name(name);
    }
    Ok(endpoint.tls_config(tls)?)
}

struct Window {
    start: Instant,
    used: u32,
}
struct Policy {
    roles: HashMap<[u8; 32], Role>,
    limit: u32,
    period: Duration,
    window: Mutex<Window>,
}
#[derive(Clone)]
pub struct AccessLayer {
    policy: Option<Arc<Policy>>,
}
impl AccessLayer {
    fn insecure_loopback() -> Self {
        Self { policy: None }
    }
    pub fn from_acl(acl: &str, limit: u32, period: Duration) -> Result<Self> {
        if limit == 0 || period.is_zero() {
            bail!("invalid Clone budget");
        }
        let mut roles = HashMap::new();
        for (i, line) in acl.lines().enumerate() {
            let line = line.split('#').next().unwrap().trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<_> = line.split_whitespace().collect();
            if parts.len() != 2 {
                bail!("ACL line {}: expected leaf_sha256 role", i + 1);
            }
            let pin: [u8; 32] = hex::decode(parts[0])?
                .try_into()
                .map_err(|_| anyhow::anyhow!("ACL fingerprint must be 32 bytes"))?;
            let role = match parts[1] {
                "clone-operator" => Role::CloneOperator,
                "listener" => Role::Listener,
                "observer" => Role::Observer,
                _ => bail!("unknown ACL role on line {}", i + 1),
            };
            if roles.insert(pin, role).is_some() {
                bail!("duplicate ACL fingerprint");
            }
            if roles.len() > 512 {
                bail!("ACL exceeds 512 identities");
            }
        }
        if roles.is_empty() {
            bail!("empty ACL");
        }
        Ok(Self {
            policy: Some(Arc::new(Policy {
                roles,
                limit,
                period,
                window: Mutex::new(Window {
                    start: Instant::now(),
                    used: 0,
                }),
            })),
        })
    }
    fn authorize(&self, req: &http::Request<Body>) -> Result<(), Status> {
        let Some(policy) = &self.policy else {
            return Ok(());
        };
        let certs = req
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .and_then(|info| info.peer_certs())
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
        let leaf = certs
            .first()
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
        let pin: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
        let role = policy
            .roles
            .get(&pin)
            .ok_or_else(|| Status::permission_denied("client not authorized"))?;
        use tonic::server::NamedService;
        let service = <crate::grpc_proto::parent_service_server::ParentServiceServer<
            crate::grpc_server::ParentAdapterService,
        > as NamedService>::NAME;
        let prefix = format!("/{service}/");
        let method = req
            .uri()
            .path()
            .strip_prefix(&prefix)
            .ok_or_else(|| Status::permission_denied("RPC not authorized"))?;
        let read = matches!(
            method,
            "PublicKey" | "AttestedPublicKey" | "GetLastSavedBlock"
        );
        let allowed = read
            || match role {
                Role::CloneOperator => method == "Clone",
                Role::Listener => matches!(method, "Sign" | "SubmitHeaders"),
                Role::Observer => false,
            };
        if !allowed {
            return Err(Status::permission_denied("RPC not authorized"));
        }
        if method == "Clone" {
            let mut window = policy
                .window
                .lock()
                .map_err(|_| Status::unavailable("clone budget unavailable"))?;
            if window.start.elapsed() >= policy.period {
                *window = Window {
                    start: Instant::now(),
                    used: 0,
                };
            }
            if window.used >= policy.limit {
                return Err(Status::resource_exhausted("clone rate limit"));
            }
            window.used += 1;
        }
        Ok(())
    }
}
impl<S> Layer<S> for AccessLayer {
    type Service = AccessService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        AccessService {
            inner,
            access: self.clone(),
        }
    }
}
#[derive(Clone)]
pub struct AccessService<S> {
    inner: S,
    access: AccessLayer,
}
impl<S> Service<http::Request<Body>> for AccessService<S>
where
    S: Service<http::Request<Body>, Response = http::Response<Body>> + Send + 'static,
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
        if let Err(status) = self.access.authorize(&req) {
            return Box::pin(async move { Ok(status.into_http()) });
        }
        Box::pin(self.inner.call(req))
    }
}

/// Caps sockets for their entire lifetime, including unfinished TLS handshakes.
/// HTTP/2 request concurrency alone does not bound tonic's TLS accept tasks.
pub struct LimitedIncoming {
    listener: tokio::net::TcpListener,
    permits: Arc<tokio::sync::Semaphore>,
}
impl LimitedIncoming {
    pub async fn bind(addr: std::net::SocketAddr, limit: usize) -> std::io::Result<Self> {
        if limit == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "zero connection limit",
            ));
        }
        Ok(Self {
            listener: tokio::net::TcpListener::bind(addr).await?,
            permits: Arc::new(tokio::sync::Semaphore::new(limit)),
        })
    }
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }
}
impl tokio_stream::Stream for LimitedIncoming {
    type Item = std::io::Result<LimitedSocket>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.listener.poll_accept(cx) {
            Poll::Ready(Ok((stream, _))) => match self.permits.clone().try_acquire_owned() {
                Ok(permit) => Poll::Ready(Some(Ok(LimitedSocket {
                    stream,
                    _permit: permit,
                }))),
                Err(_) => {
                    // Drop excess sockets without spawning work or logging per attempt.
                    drop(stream);
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            },
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}
pub struct LimitedSocket {
    stream: tokio::net::TcpStream,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl tonic::transport::server::Connected for LimitedSocket {
    type ConnectInfo = TcpConnectInfo;
    fn connect_info(&self) -> Self::ConnectInfo {
        self.stream.connect_info()
    }
}
impl tokio::io::AsyncRead for LimitedSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for LimitedSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
