//! Typed, destination-pinned Esplora egress for the RGB consignment resolver.
//!
//! Replaces the generic loopback→vsock forwarder for the Esplora path. The
//! forwarder is a process-wide egress primitive: any code inside the enclave
//! that can open a loopback socket could tunnel arbitrary host-bound traffic
//! through it. This client instead:
//!   * dials a **boot-pinned** destination — production dials the parent vsock
//!     directly (CID 3, no loopback port at all); dev/tests use a fixed TCP
//!     host:port;
//!   * exposes **only** the four GETs the resolver and the fee-rate check
//!     issue (`/block-height/0`, `/tx/{txid}/raw`, `/tx/{txid}/status`,
//!     `/fee-estimates`). There is no arbitrary-path method, so no other
//!     host-bound traffic can be composed;
//!   * bounds every call with a connect/read timeout, **no retries**, and a
//!     response-size cap, so a stalled or 429/5xx-spamming host can neither
//!     amplify one fetch nor pin a signing worker. esplora-client's default
//!     6-retry backoff is what this replaces.
//!
//! TRUST BOUNDARY: responses are still HOST-RELAYED and UNTRUSTED. This client
//! bounds *what* is fetched and *how long* it may take; it never makes the
//! bytes trustworthy. Authorisation comes from SPV proof checking and rgbstd
//! consignment validation, never from these responses. The resolver logic below
//! mirrors rgb-ops' `EsploraClient` / `AnyResolver` exactly so the RGB
//! validation semantics are unchanged.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::num::NonZeroU32;
use std::str::FromStr;
use std::time::Duration;

use bitcoin::consensus::encode::deserialize as consensus_deserialize;
use bitcoin::{BlockHash, Transaction, Txid};
use rgbstd::indexers::esplora_blocking::esplora_client::TxStatus;
use rgbstd::rgbcore::validation::{ResolveWitness, WitnessResolverError, WitnessStatus};
use rgbstd::rgbcore::vm::{WitnessOrd, WitnessPos};
use rgbstd::rgbcore::ChainNet;

use crate::conn::{DeadlineStream, SocketTimeout};
use crate::error::{EnclaveError, Result};

/// Parent instance CID in Nitro enclaves is always 3.
#[cfg(all(feature = "vsock", target_os = "linux"))]
const PARENT_CID: u32 = 3;

/// Upper bound on a single Esplora response (headers + body). Witness txs and
/// fee maps are a few KB; this ceiling only bounds a host that streams forever
/// without ever closing (the read timeout bounds a host that stalls silently).
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// A boot-pinned Esplora destination. The host still relays the bytes; pinning
/// only removes the caller's ability to choose *where* the egress goes.
#[derive(Debug, Clone)]
pub enum EsploraDest {
    /// Parent vsock (CID 3) at the given port. Production: no loopback port.
    #[cfg(all(feature = "vsock", target_os = "linux"))]
    Vsock { port: u32 },
    /// Direct TCP host:port. Dev / tests (and the local stub servers).
    Tcp { host: String, port: u16 },
}

impl EsploraDest {
    /// Parse a `http://host:port` URL into a pinned TCP destination (dev/tests).
    /// Only `http` is accepted: the host controls this relay so TLS to it buys
    /// nothing, and the payload is verified regardless.
    pub fn tcp_from_url(url: &str) -> Result<Self> {
        let rest = url.strip_prefix("http://").ok_or_else(|| {
            EnclaveError::Internal(format!("ESPLORA_URL must be http://host:port, got {url:?}"))
        })?;
        let rest = rest.trim_end_matches('/');
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => {
                let port = p.parse::<u16>().map_err(|_| {
                    EnclaveError::Internal(format!("ESPLORA_URL has a non-numeric port: {url:?}"))
                })?;
                (h.to_string(), port)
            }
            None => (rest.to_string(), 80),
        };
        if host.is_empty() {
            return Err(EnclaveError::Internal(format!(
                "ESPLORA_URL has no host: {url:?}"
            )));
        }
        Ok(EsploraDest::Tcp { host, port })
    }
}

/// A pinned transport: a TCP socket (dev/tests) or a vsock socket (production).
/// Both expose std-style timeout setters, so a [`DeadlineStream`] can bound
/// every read/write by an absolute per-call deadline.
enum EsploraStream {
    Tcp(TcpStream),
    #[cfg(all(feature = "vsock", target_os = "linux"))]
    Vsock(vsock::VsockStream),
}

impl Read for EsploraStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            EsploraStream::Tcp(s) => s.read(buf),
            #[cfg(all(feature = "vsock", target_os = "linux"))]
            EsploraStream::Vsock(s) => s.read(buf),
        }
    }
}

impl Write for EsploraStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            EsploraStream::Tcp(s) => s.write(buf),
            #[cfg(all(feature = "vsock", target_os = "linux"))]
            EsploraStream::Vsock(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            EsploraStream::Tcp(s) => s.flush(),
            #[cfg(all(feature = "vsock", target_os = "linux"))]
            EsploraStream::Vsock(s) => s.flush(),
        }
    }
}

impl SocketTimeout for EsploraStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        match self {
            EsploraStream::Tcp(s) => s.set_read_timeout(dur),
            #[cfg(all(feature = "vsock", target_os = "linux"))]
            EsploraStream::Vsock(s) => s.set_read_timeout(dur),
        }
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        match self {
            EsploraStream::Tcp(s) => s.set_write_timeout(dur),
            #[cfg(all(feature = "vsock", target_os = "linux"))]
            EsploraStream::Vsock(s) => s.set_write_timeout(dur),
        }
    }
}

/// How a response body is delimited, decided from the response headers.
enum BodyFraming {
    /// `Content-Length: N` — read exactly N body bytes, then stop (do not wait
    /// for the peer to close).
    Length(usize),
    /// `Transfer-Encoding: chunked` — read to EOF, then de-chunk.
    Chunked,
    /// Neither header — read to EOF (relies on `Connection: close`).
    Eof,
}

/// A typed Esplora client with a pinned destination and per-call limits.
#[derive(Debug, Clone)]
pub struct TypedEsploraClient {
    dest: EsploraDest,
    timeout: Duration,
    max_response_bytes: usize,
}

impl TypedEsploraClient {
    pub fn new(dest: EsploraDest, timeout: Duration) -> Self {
        Self {
            dest,
            timeout,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }

    /// Shrink the timeout so the stalled-host test doesn't wait the production
    /// budget. Test-only.
    #[cfg(test)]
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Open a fresh pinned connection wrapped in a [`DeadlineStream`], so every
    /// read/write is bounded by one absolute `self.timeout` budget — a
    /// slow-trickle host that keeps a per-read timeout re-arming cannot pin a
    /// worker. Both the TCP and vsock connects are themselves time-bounded.
    fn connect(&self) -> Result<DeadlineStream<EsploraStream>> {
        let stream = match &self.dest {
            #[cfg(all(feature = "vsock", target_os = "linux"))]
            EsploraDest::Vsock { port } => EsploraStream::Vsock(self.vsock_connect(*port)?),
            EsploraDest::Tcp { host, port } => {
                let addr = (host.as_str(), *port)
                    .to_socket_addrs()
                    .map_err(|e| {
                        EnclaveError::CrossCheck(format!(
                            "esplora TCP resolve {host}:{port} failed: {e}"
                        ))
                    })?
                    .next()
                    .ok_or_else(|| {
                        EnclaveError::CrossCheck(format!(
                            "esplora TCP resolve {host}:{port} yielded no address"
                        ))
                    })?;
                let stream = TcpStream::connect_timeout(&addr, self.timeout).map_err(|e| {
                    EnclaveError::CrossCheck(format!("esplora TCP connect {addr} failed: {e}"))
                })?;
                EsploraStream::Tcp(stream)
            }
        };
        Ok(DeadlineStream::new(stream, self.timeout, self.timeout))
    }

    /// `vsock::VsockStream::connect_with_cid_port` is a blocking connect with no
    /// timeout, so a host that keeps the connection pending would park a signing
    /// worker before any read timeout could apply. Run it on a watchdog thread
    /// and abandon it if it outlasts the budget (matching the TCP arm's
    /// `connect_timeout` guarantee).
    #[cfg(all(feature = "vsock", target_os = "linux"))]
    fn vsock_connect(&self, port: u32) -> Result<vsock::VsockStream> {
        use std::sync::mpsc;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(vsock::VsockStream::connect_with_cid_port(PARENT_CID, port));
        });
        match rx.recv_timeout(self.timeout) {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(EnclaveError::CrossCheck(format!(
                "esplora vsock connect to CID {PARENT_CID}:{port} failed: {e}"
            ))),
            Err(_) => Err(EnclaveError::CrossCheck(format!(
                "esplora vsock connect to CID {PARENT_CID}:{port} timed out"
            ))),
        }
    }

    /// Issue a fixed `GET path` and return the response body, or `None` on 404.
    ///
    /// Parses the response framing: `Content-Length` (stop at the declared
    /// length, without waiting for the peer to close), `Transfer-Encoding:
    /// chunked` (read to EOF then de-chunk), else read to EOF. `path` is only
    /// ever one of the four fixed strings the typed methods below pass — this is
    /// not public, so no arbitrary path can be requested.
    fn get(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let mut stream = self.connect()?;
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: esplora\r\nUser-Agent: utexo-enclave\r\n\
             Accept: */*\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(req.as_bytes())
            .and_then(|_| stream.flush())
            .map_err(|e| {
                EnclaveError::CrossCheck(format!("esplora write failed for {path}: {e}"))
            })?;

        // Read at least through the end of the headers (the first CRLFCRLF).
        let mut raw = Vec::new();
        let mut buf = [0u8; 8192];
        let header_end = loop {
            if let Some(pos) = find_subsequence(&raw, b"\r\n\r\n") {
                break pos;
            }
            let n = self.read_into(&mut stream, &mut buf, path)?;
            if n == 0 {
                return Err(EnclaveError::CrossCheck(format!(
                    "esplora response for {path} closed before headers completed"
                )));
            }
            self.push_capped(&mut raw, &buf[..n], path)?;
        };

        let head = &raw[..header_end];
        let code = parse_status_code(head).ok_or_else(|| {
            EnclaveError::CrossCheck(format!("esplora response for {path} had no status code"))
        })?;
        let framing = parse_body_framing(head);
        let mut body = raw[header_end + 4..].to_vec();

        match framing {
            BodyFraming::Length(len) => {
                while body.len() < len {
                    let n = self.read_into(&mut stream, &mut buf, path)?;
                    if n == 0 {
                        break;
                    }
                    self.push_capped(&mut body, &buf[..n], path)?;
                }
                if body.len() < len {
                    return Err(EnclaveError::CrossCheck(format!(
                        "esplora response for {path} truncated: {} of {len} body bytes",
                        body.len()
                    )));
                }
                body.truncate(len);
            }
            BodyFraming::Chunked | BodyFraming::Eof => {
                loop {
                    let n = self.read_into(&mut stream, &mut buf, path)?;
                    if n == 0 {
                        break;
                    }
                    self.push_capped(&mut body, &buf[..n], path)?;
                }
                if matches!(framing, BodyFraming::Chunked) {
                    body = dechunk(&body).map_err(|e| {
                        EnclaveError::CrossCheck(format!(
                            "esplora response for {path} has a malformed chunked body: {e}"
                        ))
                    })?;
                }
            }
        }

        match code {
            200 => Ok(Some(body)),
            404 => Ok(None),
            other => Err(EnclaveError::CrossCheck(format!(
                "esplora {path} returned HTTP {other}"
            ))),
        }
    }

    fn read_into(
        &self,
        stream: &mut DeadlineStream<EsploraStream>,
        buf: &mut [u8],
        path: &str,
    ) -> Result<usize> {
        stream
            .read(buf)
            .map_err(|e| EnclaveError::CrossCheck(format!("esplora read failed for {path}: {e}")))
    }

    fn push_capped(&self, dst: &mut Vec<u8>, src: &[u8], path: &str) -> Result<()> {
        if dst.len() + src.len() > self.max_response_bytes {
            return Err(EnclaveError::CrossCheck(format!(
                "esplora response for {path} exceeds {} bytes",
                self.max_response_bytes
            )));
        }
        dst.extend_from_slice(src);
        Ok(())
    }

    /// `GET /block-height/0` → the genesis block hash (chain-identity check).
    pub fn genesis_block_hash(&self) -> Result<BlockHash> {
        let body = self.get("/block-height/0")?.ok_or_else(|| {
            EnclaveError::CrossCheck("esplora /block-height/0 returned 404".into())
        })?;
        let s = String::from_utf8_lossy(&body);
        BlockHash::from_str(s.trim()).map_err(|e| {
            EnclaveError::CrossCheck(format!(
                "esplora /block-height/0 is not a block hash: {e} (got {:?})",
                s.trim()
            ))
        })
    }

    /// `GET /tx/{txid}/raw` → the raw transaction, or `None` if unknown (404).
    pub fn get_tx(&self, txid: &Txid) -> Result<Option<Transaction>> {
        let Some(body) = self.get(&format!("/tx/{txid}/raw"))? else {
            return Ok(None);
        };
        let tx = consensus_deserialize::<Transaction>(&body).map_err(|e| {
            EnclaveError::CrossCheck(format!(
                "esplora /tx/{txid}/raw is not a valid transaction: {e}"
            ))
        })?;
        Ok(Some(tx))
    }

    /// `GET /tx/{txid}/status` → confirmation status.
    pub fn get_tx_status(&self, txid: &Txid) -> Result<TxStatus> {
        let body = self.get(&format!("/tx/{txid}/status"))?.ok_or_else(|| {
            EnclaveError::CrossCheck(format!("esplora /tx/{txid}/status returned 404"))
        })?;
        serde_json::from_slice::<TxStatus>(&body).map_err(|e| {
            EnclaveError::CrossCheck(format!("esplora /tx/{txid}/status is not valid JSON: {e}"))
        })
    }

    /// `GET /fee-estimates` → confirmation-target → sat/vB map.
    pub fn get_fee_estimates(&self) -> Result<HashMap<u16, f64>> {
        let body = self.get("/fee-estimates")?.ok_or_else(|| {
            EnclaveError::CrossCheck("esplora /fee-estimates returned 404".into())
        })?;
        serde_json::from_slice::<HashMap<u16, f64>>(&body).map_err(|e| {
            EnclaveError::CrossCheck(format!("esplora /fee-estimates is not valid JSON: {e}"))
        })
    }
}

/// A `ResolveWitness` that answers consignment-bundled txs as tentative
/// (mirroring rgb-ops' `AnyResolver::add_consignment_txes`) and delegates any
/// other witness to the pinned typed client. Built per `validate()` call and
/// owned privately by the RGB validator.
pub struct ConsignmentResolver<'a> {
    client: &'a TypedEsploraClient,
    consignment_txes: HashMap<Txid, Transaction>,
}

impl<'a> ConsignmentResolver<'a> {
    /// Build a resolver whose bundled witness txs come from `consignment_txes`
    /// (the map the caller extracts from the transfer's bundles, exactly as
    /// `AnyResolver::add_consignment_txes` does).
    pub fn new(
        client: &'a TypedEsploraClient,
        consignment_txes: HashMap<Txid, Transaction>,
    ) -> Self {
        Self {
            client,
            consignment_txes,
        }
    }
}

impl ResolveWitness for ConsignmentResolver<'_> {
    fn resolve_witness(
        &self,
        witness_id: Txid,
    ) -> std::result::Result<WitnessStatus, WitnessResolverError> {
        if let Some(tx) = self.consignment_txes.get(&witness_id) {
            return Ok(WitnessStatus::Resolved(tx.clone(), WitnessOrd::Tentative));
        }
        let Some(tx) = self
            .client
            .get_tx(&witness_id)
            .map_err(|e| WitnessResolverError::ResolverIssue(Some(witness_id), e.to_string()))?
        else {
            return Ok(WitnessStatus::Unresolved);
        };
        let status = self
            .client
            .get_tx_status(&witness_id)
            .map_err(|e| WitnessResolverError::ResolverIssue(Some(witness_id), e.to_string()))?;
        let ord = match status.block_height.zip(status.block_time) {
            Some((h, t)) => {
                let height = NonZeroU32::new(h).ok_or(WitnessResolverError::InvalidResolverData)?;
                WitnessOrd::Mined(
                    WitnessPos::bitcoin(height, t as i64)
                        .ok_or(WitnessResolverError::InvalidResolverData)?,
                )
            }
            None => WitnessOrd::Tentative,
        };
        Ok(WitnessStatus::Resolved(tx, ord))
    }

    fn check_chain_net(
        &self,
        chain_net: ChainNet,
    ) -> std::result::Result<(), WitnessResolverError> {
        let block_hash = self
            .client
            .genesis_block_hash()
            .map_err(|e| WitnessResolverError::ResolverIssue(None, e.to_string()))?;
        let chain_hash = bitcoin::constants::ChainHash::from_genesis_block_hash(block_hash);
        if chain_net.chain_hash() != chain_hash {
            return Err(WitnessResolverError::WrongChainNet);
        }
        Ok(())
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parse the numeric status code from the response's first line
/// (`HTTP/1.1 <code> <reason>`).
fn parse_status_code(head: &[u8]) -> Option<u16> {
    let line = head.split(|&b| b == b'\n').next().unwrap_or(&[]);
    String::from_utf8_lossy(line)
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
}

/// Decide how the body is delimited from the response headers. Per RFC 7230,
/// `Transfer-Encoding: chunked` takes precedence over `Content-Length`.
fn parse_body_framing(head: &[u8]) -> BodyFraming {
    let text = String::from_utf8_lossy(head);
    let mut content_length = None;
    let mut chunked = false;
    for line in text.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            if name == "content-length" {
                content_length = value.parse::<usize>().ok();
            } else if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }
    if chunked {
        BodyFraming::Chunked
    } else if let Some(len) = content_length {
        BodyFraming::Length(len)
    } else {
        BodyFraming::Eof
    }
}

/// Decode an HTTP/1.1 chunked transfer-encoded body. Each chunk is a hex size
/// line (optionally with `;ext`), the data, and a trailing CRLF; a zero-size
/// chunk terminates. Esplora sends no trailers.
fn dechunk(data: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut rest = data;
    loop {
        let crlf = find_subsequence(rest, b"\r\n").ok_or("missing chunk-size CRLF")?;
        let size_line =
            std::str::from_utf8(&rest[..crlf]).map_err(|_| "non-utf8 chunk size".to_string())?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("bad chunk size {size_hex:?}"))?;
        rest = &rest[crlf + 2..];
        if size == 0 {
            break;
        }
        // Checked arithmetic: a hostile chunk-size (e.g. `ffffffffffffffff`
        // parses to usize::MAX) must not overflow `size + 2` and slip past the
        // bound check into an out-of-range slice — which would abort the whole
        // enclave under `panic = "abort"`.
        let advance = size.checked_add(2).ok_or("chunk size overflows usize")?;
        if rest.len() < advance {
            return Err("truncated chunk data".to_string());
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[advance..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[test]
    fn tcp_from_url_parses_host_port() {
        match EsploraDest::tcp_from_url("http://127.0.0.1:3443").unwrap() {
            EsploraDest::Tcp { host, port } => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 3443);
            }
            #[allow(unreachable_patterns)]
            _ => panic!("expected Tcp"),
        }
        assert!(EsploraDest::tcp_from_url("https://x:1").is_err());
        assert!(EsploraDest::tcp_from_url("http://host:notaport").is_err());
    }

    /// Record every request line and answer each fixed path with a canned body.
    fn spawn_recording_stub(seen: Arc<Mutex<Vec<String>>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let first = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                seen.lock().unwrap().push(first.clone());
                let body = if first.contains("/fee-estimates") {
                    r#"{"6":12.0}"#.to_string()
                } else if first.contains("/block-height/0") {
                    // Mainnet genesis block hash.
                    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f".to_string()
                } else {
                    String::new()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn typed_client_issues_only_the_allowlisted_paths() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let url = spawn_recording_stub(seen.clone());
        let client = TypedEsploraClient::new(
            EsploraDest::tcp_from_url(&url).unwrap(),
            Duration::from_secs(5),
        );

        assert!(client.genesis_block_hash().is_ok());
        assert!(client.get_fee_estimates().is_ok());

        let lines = seen.lock().unwrap().clone();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            let path = line.split_whitespace().nth(1).unwrap_or("");
            assert!(
                path == "/block-height/0" || path == "/fee-estimates",
                "unexpected egress path: {line:?}"
            );
        }
    }

    #[test]
    fn get_maps_404_to_none() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Some(Ok(mut s)) = listener.incoming().next() {
                let mut b = [0u8; 512];
                let _ = s.read(&mut b);
                let _ = s.write_all(
                    b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                );
            }
        });
        let client = TypedEsploraClient::new(
            EsploraDest::tcp_from_url(&format!("http://{addr}")).unwrap(),
            Duration::from_secs(5),
        );
        let txid =
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        assert!(client.get_tx(&txid).unwrap().is_none());
    }

    #[test]
    fn get_errors_on_5xx() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Some(Ok(mut s)) = listener.incoming().next() {
                let mut b = [0u8; 512];
                let _ = s.read(&mut b);
                let _ = s.write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                );
            }
        });
        let client = TypedEsploraClient::new(
            EsploraDest::tcp_from_url(&format!("http://{addr}")).unwrap(),
            Duration::from_secs(5),
        );
        assert!(client.get_fee_estimates().is_err());
    }

    #[test]
    fn decodes_chunked_response() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Some(Ok(mut s)) = listener.incoming().next() {
                let mut b = [0u8; 512];
                let _ = s.read(&mut b);
                // `{"6":12.0}` is 10 bytes (hex `a`): one chunk + the zero terminator.
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nconnection: close\r\n\r\na\r\n{\"6\":12.0}\r\n0\r\n\r\n",
                );
            }
        });
        let client = TypedEsploraClient::new(
            EsploraDest::tcp_from_url(&format!("http://{addr}")).unwrap(),
            Duration::from_secs(5),
        );
        let fees = client.get_fee_estimates().unwrap();
        assert_eq!(fees.get(&6), Some(&12.0));
    }

    #[test]
    fn stops_reading_at_content_length() {
        // Body is exactly Content-Length bytes; trailing bytes on the connection
        // (a kept-alive / pipelining relay that ignores `Connection: close`) must
        // be dropped — proving we frame by Content-Length, not read-to-EOF. If
        // the garbage were included the JSON decode would fail.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Some(Ok(mut s)) = listener.incoming().next() {
                let mut b = [0u8; 512];
                let _ = s.read(&mut b);
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n{\"6\":12.0}!!!TRAILING-GARBAGE!!!",
                );
            }
        });
        let client = TypedEsploraClient::new(
            EsploraDest::tcp_from_url(&format!("http://{addr}")).unwrap(),
            Duration::from_secs(5),
        );
        let fees = client.get_fee_estimates().unwrap();
        assert_eq!(fees.get(&6), Some(&12.0));
    }

    #[test]
    fn dechunk_reassembles_and_rejects_malformed() {
        assert_eq!(
            dechunk(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n").unwrap(),
            b"Wikipedia"
        );
        assert!(dechunk(b"zz\r\nxx\r\n0\r\n\r\n").is_err());
        assert!(dechunk(b"9\r\ntooshort\r\n0\r\n\r\n").is_err());
        // A hostile chunk-size that overflows usize must error, never panic
        // (would abort the enclave under panic = "abort").
        assert!(dechunk(b"ffffffffffffffff\r\nx\r\n0\r\n\r\n").is_err());
    }
}
