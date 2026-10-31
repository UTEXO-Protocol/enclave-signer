//! TCP-to-vsock forwarder from the enclave to external services (for example
//! Electrum). It listens on loopback TCP and sends each connection over vsock to
//! the parent, where `vsock-proxy` relays it to the real endpoint.
//!
//! Trust boundary: the host controls this path. It can drop, delay, reorder or
//! forge bytes. The enclave verifies all data from it (SPV, rgb-lib validation,
//! in-enclave TLS) and never trusts it as input.
//!
//! The listener is loopback only, but it is a generic egress path: any code in
//! the enclave process can use it. A forwarder for a TLS endpoint therefore
//! sends on only a connection that starts with a TLS handshake record
//! ([`crate::egress`]).

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};

use vsock::VsockStream;

/// Parent instance CID in Nitro enclaves is always 3.
const PARENT_CID: u32 = 3;

/// Start a background thread that forwards each connection on `listener` to
/// the parent (vsock CID 3), port `vsock_port`. With `require_tls`, a
/// connection that does not start with a TLS handshake record is closed
/// before the vsock is opened. Untrusted path: see the module docs.
///
/// Errors are logged and never stop the enclave.
pub fn spawn(listener: TcpListener, vsock_port: u32, require_tls: bool) {
    let local_port = listener.local_addr().map_or(0, |a| a.port());
    tracing::info!(
        local_port,
        vsock_port,
        require_tls,
        parent_cid = PARENT_CID,
        "vsock forwarder started: 127.0.0.1:{} -> vsock CID {}:{}",
        local_port,
        PARENT_CID,
        vsock_port
    );

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                // Own thread per connection: the TLS check reads from the
                // client, so a slow client must not stop the accept loop.
                Ok(tcp) => {
                    std::thread::spawn(move || forward(tcp, vsock_port, require_tls));
                }
                Err(e) => tracing::warn!("forwarder: TCP accept error: {e}"),
            }
        }
    });
}

/// Forward one connection. See [`spawn`].
fn forward(mut tcp: TcpStream, vsock_port: u32, require_tls: bool) {
    let first_bytes = if require_tls {
        match crate::egress::read_tls_record_header(&mut tcp) {
            Ok(header) => Some(header),
            Err(e) => {
                tracing::warn!(vsock_port, "forwarder: connection refused: {e}");
                return;
            }
        }
    } else {
        None
    };

    tracing::debug!(
        "forwarder: new connection, opening vsock to CID {}:{}",
        PARENT_CID,
        vsock_port
    );

    let mut vsock = match VsockStream::connect_with_cid_port(PARENT_CID, vsock_port) {
        Ok(s) => {
            tracing::debug!(
                "forwarder: vsock connected to CID {}:{}",
                PARENT_CID,
                vsock_port
            );
            s
        }
        Err(e) => {
            tracing::error!(
                "forwarder: vsock connect to CID {}:{} failed: {e} \
                 (is vsock-proxy running on the host?)",
                PARENT_CID,
                vsock_port
            );
            return;
        }
    };

    // The bytes the TLS check read go first.
    if let Some(header) = first_bytes {
        if let Err(e) = vsock.write_all(&header) {
            tracing::debug!("forwarder: tcp->vsock error: {e}");
            return;
        }
    }

    // Bidirectional copy: two threads per connection.
    let mut tcp_r = tcp;
    let mut vsock_w = match vsock.try_clone() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("forwarder: vsock clone failed: {e}");
            return;
        }
    };
    let mut vsock_r = vsock;
    let mut tcp_w = match tcp_r.try_clone() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("forwarder: TCP clone failed: {e}");
            return;
        }
    };

    std::thread::spawn(move || match copy_half(&mut tcp_r, &mut vsock_w) {
        Ok(bytes) => tracing::debug!("forwarder: tcp->vsock closed ({bytes} bytes)"),
        Err(e) => tracing::debug!("forwarder: tcp->vsock error: {e}"),
    });
    std::thread::spawn(move || match copy_half(&mut vsock_r, &mut tcp_w) {
        Ok(bytes) => tracing::debug!("forwarder: vsock->tcp closed ({bytes} bytes)"),
        Err(e) => tracing::debug!("forwarder: vsock->tcp error: {e}"),
    });
}

/// Socket shutdown applies to every cloned descriptor. Dropping just one copy
/// does not send EOF while the other relay direction still owns its clone.
trait ShutdownStream {
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;
}

impl ShutdownStream for TcpStream {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        TcpStream::shutdown(self, how)
    }
}

impl ShutdownStream for VsockStream {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        VsockStream::shutdown(self, how)
    }
}

/// Relay one direction. A clean EOF closes only the destination's write half:
/// the peer can still finish its response through the reverse copy. A failed
/// copy tears down both sockets, waking the reverse copy instead of leaving a
/// thread and an upstream connection blocked indefinitely.
fn copy_half<R: Read + ShutdownStream, W: Write + ShutdownStream>(
    source: &mut R,
    destination: &mut W,
) -> io::Result<u64> {
    let result = io::copy(source, destination).and_then(|bytes| {
        destination.shutdown(Shutdown::Write)?;
        Ok(bytes)
    });
    if result.is_err() {
        let _ = source.shutdown(Shutdown::Both);
        let _ = destination.shutdown(Shutdown::Both);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(2);

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let b = listener.accept().unwrap().0;
        for stream in [&a, &b] {
            stream.set_read_timeout(Some(TIMEOUT)).unwrap();
            stream.set_write_timeout(Some(TIMEOUT)).unwrap();
        }
        (a, b)
    }

    fn relay(mut left: TcpStream, mut right: TcpStream) -> mpsc::Receiver<io::Result<u64>> {
        let mut left_reply = left.try_clone().unwrap();
        let mut right_reply = right.try_clone().unwrap();
        let (done, receive) = mpsc::channel();
        let done_reply = done.clone();
        std::thread::spawn(move || {
            let _ = done.send(copy_half(&mut left, &mut right));
        });
        std::thread::spawn(move || {
            let _ = done_reply.send(copy_half(&mut right_reply, &mut left_reply));
        });
        receive
    }

    #[test]
    fn client_eof_reaches_upstream_without_discarding_the_reply() {
        let (mut client, left) = pair();
        let (right, mut upstream) = pair();
        let done = relay(left, right);

        client.write_all(b"request").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut request = Vec::new();
        // Before the fix, this timed out: the reverse relay held a clone of
        // the upstream socket open after the request copy had finished.
        upstream.read_to_end(&mut request).unwrap();
        assert_eq!(request, b"request");
        upstream.write_all(b"reply after request EOF").unwrap();
        upstream.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"reply after request EOF");
        for _ in 0..2 {
            done.recv_timeout(TIMEOUT).unwrap().unwrap();
        }
    }

    #[test]
    fn upstream_eof_reaches_client_without_discarding_the_remaining_request() {
        let (mut client, left) = pair();
        let (right, mut upstream) = pair();
        let done = relay(left, right);

        upstream.write_all(b"early response").unwrap();
        upstream.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"early response");
        client.write_all(b"request after response EOF").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut request = Vec::new();
        upstream.read_to_end(&mut request).unwrap();
        assert_eq!(request, b"request after response EOF");
        for _ in 0..2 {
            done.recv_timeout(TIMEOUT).unwrap().unwrap();
        }
    }

    struct FailedReader(TcpStream);

    impl Read for FailedReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::ConnectionReset, "test reset"))
        }
    }

    impl ShutdownStream for FailedReader {
        fn shutdown(&self, how: Shutdown) -> io::Result<()> {
            self.0.shutdown(how)
        }
    }

    #[test]
    fn copy_error_closes_both_sockets_and_wakes_the_reverse_copy() {
        let (mut client, left) = pair();
        let (mut right, mut upstream) = pair();
        let mut left_reply = left.try_clone().unwrap();
        let mut right_reply = right.try_clone().unwrap();
        let (done, receive) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(copy_half(&mut right_reply, &mut left_reply));
        });
        let error = copy_half(&mut FailedReader(left), &mut right).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
        assert_eq!(upstream.read(&mut [0]).unwrap(), 0);
        // A canceled reverse copy may observe EOF or NotConnected, depending
        // on the OS. It must terminate instead of retaining either socket.
        if let Err(error) = receive.recv_timeout(TIMEOUT).unwrap() {
            assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        }
    }
}
