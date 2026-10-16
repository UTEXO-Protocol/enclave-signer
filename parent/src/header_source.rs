//! Bitcoin headers from one Electrum server.
//!
//! A [`Session`] is one connection under one deadline and one byte cap. A sync
//! step opens one session for all its calls, and the parent checks every reply
//! field before it uses it.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context};
use bitcoin::block::Header;
use bitcoin::consensus::deserialize;
use electrum_client::raw_client::RawClient;
use electrum_client::{ElectrumApi, Param};
use rustls::pki_types::ServerName;

/// Limit for one session: name lookup, connect, TLS handshake and every read
/// and write.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(15);
/// Maximum headers per call.
pub const MAX_HEADERS: u32 = 2016;
/// Maximum bytes per call. 2,016 headers in hex are about 323 KB.
const MAX_READ_BYTES: usize = 1 << 20;

pub struct ElectrumSource {
    host: String,
    port: u16,
    tls: Option<(Arc<rustls::ClientConfig>, ServerName<'static>)>,
    timeout: Duration,
}

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

impl ElectrumSource {
    /// Parse `ssl://host:port`, or `tcp://ip:port` to a loopback IP. No I/O.
    pub fn new(url: &str) -> anyhow::Result<Self> {
        let (ssl, rest) = if let Some(rest) = url.strip_prefix("ssl://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("tcp://") {
            (false, rest)
        } else {
            bail!("Electrum URL must start with ssl:// or tcp://");
        };
        let (host, port) = rest.rsplit_once(':').context("Electrum URL has no port")?;
        let port: u16 = port.parse().context("Electrum URL has a bad port")?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        ensure!(
            !host.is_empty() && port != 0,
            "Electrum URL has no host or port"
        );
        let tls = if ssl {
            let name = ServerName::try_from(host.to_string())
                .context("Electrum URL has a bad host name")?;
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
            Some((Arc::new(config), name))
        } else {
            let ip: IpAddr = host
                .parse()
                .context("tcp:// is allowed only to a loopback IP")?;
            ensure!(ip.is_loopback(), "tcp:// is allowed only to a loopback IP");
            None
        };
        Ok(Self {
            host: host.to_string(),
            port,
            tls,
            timeout: CALL_TIMEOUT,
        })
    }

    /// Open one connection. Every call on it shares one deadline.
    pub fn connect(&self) -> anyhow::Result<Session> {
        let deadline = Instant::now() + self.timeout;
        let mut last = None;
        let mut tcp = None;
        for addr in resolve(&self.host, self.port, deadline)? {
            match TcpStream::connect_timeout(&addr, time_left(deadline)?) {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        let stream = DeadlineStream {
            tcp: match (tcp, last) {
                (Some(s), _) => s,
                (None, Some(e)) => return Err(e).context("cannot connect to the source"),
                (None, None) => bail!("source host resolves to no address"),
            },
            deadline,
            budget: MAX_READ_BYTES,
        };
        let stream: Box<dyn Stream> = match &self.tls {
            None => Box::new(stream),
            Some((config, name)) => {
                let conn = rustls::ClientConnection::new(config.clone(), name.clone())?;
                let mut tls = rustls::StreamOwned::new(conn, stream);
                while tls.conn.is_handshaking() {
                    tls.conn
                        .complete_io(&mut tls.sock)
                        .context("TLS handshake with the source failed")?;
                }
                Box::new(tls)
            }
        };
        Ok(Session {
            client: RawClient::from(stream),
        })
    }

    /// Height and header of the source tip, on a connection of its own.
    pub fn tip(&self) -> anyhow::Result<(u32, Header)> {
        self.connect()?.tip()
    }

    /// Up to `count` headers from height `from`, on a connection of its own.
    pub fn headers(&self, from: u32, count: u32) -> anyhow::Result<Vec<Header>> {
        self.connect()?.headers(from, count)
    }
}

/// One connection to the source.
pub struct Session {
    client: RawClient<Box<dyn Stream>>,
}

impl Session {
    /// Height and header of the source tip.
    pub fn tip(&self) -> anyhow::Result<(u32, Header)> {
        let reply = self.client.raw_call("blockchain.headers.subscribe", [])?;
        let height = reply["height"]
            .as_u64()
            .and_then(|h| u32::try_from(h).ok())
            .context("source tip height is not a u32")?;
        let header = reply["hex"].as_str().context("source tip has no header")?;
        let raw = hex::decode(header).context("source tip header hex is bad")?;
        ensure!(raw.len() == 80, "source tip header is not 80 bytes");
        let header = deserialize(&raw).context("source tip header does not parse")?;
        Ok((height, header))
    }

    /// Up to `count` headers from height `from`. Fewer when the source ends.
    pub fn headers(&self, from: u32, count: u32) -> anyhow::Result<Vec<Header>> {
        ensure!(
            (1..=MAX_HEADERS).contains(&count),
            "bad header count {count}"
        );
        let mut out: Vec<Header> = Vec::with_capacity(count as usize);
        while out.len() < count as usize {
            let remaining = count - out.len() as u32;
            let start = from
                .checked_add(out.len() as u32)
                .context("header height overflows")?;
            let reply = self.client.raw_call(
                "blockchain.block.headers",
                [Param::U32(start), Param::U32(remaining)],
            )?;
            let n = reply["count"]
                .as_u64()
                .context("source reply has no count")?;
            let raw = hex::decode(reply["hex"].as_str().context("source reply has no hex")?)
                .context("source reply hex is bad")?;
            ensure!(
                raw.len() % 80 == 0 && (raw.len() / 80) as u64 == n,
                "source reply count {n} does not match {} bytes",
                raw.len()
            );
            ensure!(
                n <= u64::from(remaining),
                "source sent more headers than asked"
            );
            if n == 0 {
                break;
            }
            for chunk in raw.chunks_exact(80) {
                out.push(deserialize(chunk).context("source header does not parse")?);
            }
        }
        Ok(out)
    }
}

/// Resolve `host` before `deadline`. The lookup runs on its own thread
/// because the resolver has no deadline. A hung lookup must not hold the
/// caller past the session limit.
fn resolve(host: &str, port: u16, deadline: Instant) -> anyhow::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let (tx, rx) = mpsc::channel();
    let host = host.to_string();
    std::thread::spawn(move || {
        let _ = tx.send((host.as_str(), port).to_socket_addrs().map(Vec::from_iter));
    });
    match rx.recv_timeout(time_left(deadline)?) {
        Ok(addrs) => addrs.context("cannot resolve the source host"),
        Err(_) => bail!("resolving the source host timed out"),
    }
}

fn time_left(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "source call timed out"))
}

/// A TCP stream with one deadline for the whole call and a cap on bytes read.
struct DeadlineStream {
    tcp: TcpStream,
    deadline: Instant,
    budget: usize,
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.budget == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source reply is too large",
            ));
        }
        self.tcp.set_read_timeout(Some(time_left(self.deadline)?))?;
        let cap = buf.len().min(self.budget);
        let n = self.tcp.read(&mut buf[..cap])?;
        self.budget -= n;
        Ok(n)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tcp
            .set_write_timeout(Some(time_left(self.deadline)?))?;
        self.tcp.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    #[test]
    fn url_rules() {
        assert!(ElectrumSource::new("ssl://electrum.example.com:50002").is_ok());
        assert!(ElectrumSource::new("tcp://127.0.0.1:50001").is_ok());
        assert!(ElectrumSource::new("tcp://[::1]:50001").is_ok());
        for bad in [
            "tcp://10.0.0.5:50001",
            "tcp://localhost:50001",
            "tcp://electrum.example.com:50001",
            "http://127.0.0.1:50001",
            "ssl://electrum.example.com",
            "ssl://electrum.example.com:0",
            "ssl://electrum.example.com:x",
            "ssl://:50002",
        ] {
            assert!(ElectrumSource::new(bad).is_err(), "{bad} must be refused");
        }
    }

    /// Serve one connection. Each request line gets the next scripted reply,
    /// with `{id}` replaced by the request id. `None` sends nothing more.
    fn serve(replies: Vec<Option<Vec<u8>>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("tcp://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            for reply in replies {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let id = serde_json::from_str::<serde_json::Value>(&line).unwrap()["id"].clone();
                let Some(reply) = reply else {
                    std::thread::sleep(Duration::from_secs(30));
                    return;
                };
                let reply = String::from_utf8(reply)
                    .unwrap()
                    .replace("{id}", &id.to_string());
                let _ = writer.write_all(reply.as_bytes());
            }
            std::thread::sleep(Duration::from_secs(30));
        });
        url
    }

    fn result(body: &str) -> Option<Vec<u8>> {
        Some(format!("{{\"jsonrpc\":\"2.0\",\"id\":{{id}},\"result\":{body}}}\n").into_bytes())
    }

    fn source(url: &str) -> ElectrumSource {
        ElectrumSource {
            timeout: Duration::from_secs(2),
            ..ElectrumSource::new(url).unwrap()
        }
    }

    #[test]
    fn good_replies_parse() {
        let h = "00".repeat(80);
        let url = serve(vec![result(&format!("{{\"height\":7,\"hex\":\"{h}\"}}"))]);
        assert_eq!(source(&url).tip().unwrap().0, 7);

        let url = serve(vec![
            result(&format!(
                "{{\"count\":2,\"hex\":\"{}\",\"max\":2016}}",
                h.repeat(2)
            )),
            result(&format!("{{\"count\":1,\"hex\":\"{h}\",\"max\":2016}}")),
        ]);
        assert_eq!(source(&url).headers(5, 3).unwrap().len(), 3);

        // An empty reply ends the read early.
        let url = serve(vec![result("{\"count\":0,\"hex\":\"\",\"max\":2016}")]);
        assert!(source(&url).headers(5, 3).unwrap().is_empty());
    }

    #[test]
    fn malformed_replies_are_errors() {
        let h = "00".repeat(80);
        for body in [
            "{\"count\":1,\"hex\":\"\"}".to_string(),
            format!("{{\"count\":2,\"hex\":\"{h}\"}}"),
            format!("{{\"count\":1,\"hex\":\"{h}00\"}}"),
            format!("{{\"count\":1,\"hex\":\"{}\"}}", "zz".repeat(80)),
            format!("{{\"count\":4,\"hex\":\"{}\"}}", h.repeat(4)),
            "{\"count\":\"1\",\"hex\":7}".to_string(),
            "[]".to_string(),
        ] {
            let url = serve(vec![result(&body)]);
            assert!(source(&url).headers(5, 3).is_err(), "{body}");
        }
        for body in [
            format!("{{\"height\":4294967296,\"hex\":\"{h}\"}}"),
            format!("{{\"height\":-1,\"hex\":\"{h}\"}}"),
            "{\"height\":7,\"hex\":\"00\"}".to_string(),
            "null".to_string(),
        ] {
            let url = serve(vec![result(&body)]);
            assert!(source(&url).tip().is_err(), "{body}");
        }
        let url = serve(vec![Some(b"not json\n".to_vec())]);
        assert!(source(&url).tip().is_err());
        assert!(source("tcp://127.0.0.1:1").headers(5, 0).is_err());
        assert!(source("tcp://127.0.0.1:1")
            .headers(5, MAX_HEADERS + 1)
            .is_err());
    }

    #[test]
    fn oversized_reply_is_an_error() {
        let mut line = vec![b'a'; MAX_READ_BYTES + 1];
        line.push(b'\n');
        let url = serve(vec![Some(line)]);
        let start = Instant::now();
        assert!(source(&url).tip().is_err());
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn silent_source_is_bounded() {
        let url = serve(vec![None]);
        let start = Instant::now();
        assert!(source(&url).tip().is_err());
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn slow_drip_source_is_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("tcp://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for _ in 0..30 {
                if stream.write_all(b" ").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        });
        let start = Instant::now();
        assert!(source(&url).tip().is_err());
        assert!(start.elapsed() < Duration::from_secs(3));
    }
}
