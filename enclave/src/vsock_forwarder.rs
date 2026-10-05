//! TCP-to-vsock forwarder from the enclave to external services (for example
//! Esplora). It listens on loopback TCP and sends each connection over vsock to
//! the parent, where `vsock-proxy` relays it to the real endpoint.
//!
//! Trust boundary: the host controls this path. It can drop, delay, reorder or
//! forge bytes. The enclave verifies all data from it (SPV, rgbstd validation,
//! in-enclave TLS) and never trusts it as input.
//!
//! The listener is loopback only, but it is a generic egress path: any code in
//! the enclave process can use it.

use std::io;
use std::net::TcpListener;

use vsock::VsockStream;

/// Parent instance CID in Nitro enclaves is always 3.
const PARENT_CID: u32 = 3;

/// Start a background thread that forwards each connection on `listener` to
/// the parent (vsock CID 3), port `vsock_port`. Untrusted path: see the module
/// docs.
///
/// Errors are logged and never stop the enclave.
pub fn spawn(listener: TcpListener, vsock_port: u32) {
    let local_port = listener.local_addr().map_or(0, |a| a.port());
    tracing::info!(
        local_port,
        vsock_port,
        parent_cid = PARENT_CID,
        "vsock forwarder started: 127.0.0.1:{} -> vsock CID {}:{}",
        local_port,
        PARENT_CID,
        vsock_port
    );

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let tcp = match stream {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("forwarder: TCP accept error: {e}");
                    continue;
                }
            };

            tracing::debug!(
                "forwarder: new connection, opening vsock to CID {}:{}",
                PARENT_CID,
                vsock_port
            );

            let vsock = match VsockStream::connect_with_cid_port(PARENT_CID, vsock_port) {
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
                    continue;
                }
            };

            // Bidirectional copy: two threads per connection.
            let mut tcp_r = tcp;
            let mut vsock_w = match vsock.try_clone() {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("forwarder: vsock clone failed: {e}");
                    continue;
                }
            };
            let mut vsock_r = vsock;
            let mut tcp_w = match tcp_r.try_clone() {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("forwarder: TCP clone failed: {e}");
                    continue;
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
    });
}
