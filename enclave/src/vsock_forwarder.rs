//! TCP-to-vsock forwarder from the enclave to external services (for example
//! Electrum). It listens on loopback TCP and sends each connection over vsock to
//! the parent, where `vsock-proxy` relays it to the real endpoint.
//!
//! Trust boundary: the host controls this path. It can drop, delay, reorder or
//! forge bytes. The enclave verifies all data from it (SPV, rgbstd validation,
//! in-enclave TLS) and never trusts it as input.
//!
//! The listener is loopback only, but it is a generic egress path: any code in
//! the enclave process can use it. A forwarder for a TLS endpoint therefore
//! sends on only a connection that starts with a TLS handshake record
//! ([`crate::egress`]).

use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};

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

    std::thread::spawn(move || match io::copy(&mut tcp_r, &mut vsock_w) {
        Ok(bytes) => tracing::debug!("forwarder: tcp->vsock closed ({bytes} bytes)"),
        Err(e) => tracing::debug!("forwarder: tcp->vsock error: {e}"),
    });
    std::thread::spawn(move || match io::copy(&mut vsock_r, &mut tcp_w) {
        Ok(bytes) => tracing::debug!("forwarder: vsock->tcp closed ({bytes} bytes)"),
        Err(e) => tracing::debug!("forwarder: vsock->tcp error: {e}"),
    });
}
