//! TCP-to-vsock forwarder for reaching external services (e.g., Esplora) from
//! inside a Nitro enclave. Listens on localhost TCP and forwards each connection
//! to the parent instance via vsock, where `vsock-proxy` relays to the real endpoint.

use std::io;
use std::net::TcpListener;

use vsock::VsockStream;

/// Parent instance CID in Nitro enclaves is always 3.
const PARENT_CID: u32 = 3;

/// Start a background forwarder thread that bridges `127.0.0.1:{local_port}`
/// to vsock CID 3 (parent instance), port `vsock_port`.
///
/// The forwarder is fire-and-forget — it logs errors but never crashes the enclave.
pub fn start_forwarder(local_port: u16, vsock_port: u32) -> io::Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{local_port}"))?;
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
                Ok(bytes) => tracing::debug!("forwarder: tcp→vsock closed ({bytes} bytes)"),
                Err(e) => tracing::debug!("forwarder: tcp→vsock error: {e}"),
            });
            std::thread::spawn(move || match io::copy(&mut vsock_r, &mut tcp_w) {
                Ok(bytes) => tracing::debug!("forwarder: vsock→tcp closed ({bytes} bytes)"),
                Err(e) => tracing::debug!("forwarder: vsock→tcp error: {e}"),
            });
        }
    });

    Ok(())
}
