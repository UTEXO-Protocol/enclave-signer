//! TCP-to-vsock forwarder for reaching external services from inside a Nitro
//! enclave. Listens on localhost TCP and forwards each connection to the parent
//! instance via vsock, where `vsock-proxy` relays to the real endpoint.
//!
//! TRUST BOUNDARY: everything reachable through this forwarder is
//! HOST-CONTROLLED and UNTRUSTED. The host runs the `vsock-proxy` on the far
//! end and can drop, delay, reorder, or forge any bytes it returns. Data
//! fetched over it is EVIDENCE TO BE VERIFIED - by the in-enclave Helios light
//! client for EVM data - never trusted input. The listener binds only to
//! loopback (`127.0.0.1`, not externally reachable), but it is a GENERIC egress
//! primitive: any code inside the enclave process that can open a loopback
//! socket can tunnel host-bound traffic through it.
//!
//! The Esplora path no longer uses this forwarder: the RGB validator owns a
//! typed, destination-pinned Esplora client that dials the parent vsock
//! directly and exposes only the specific calls the resolver makes, so no
//! Esplora traffic can be tunneled through a generic port. This forwarder now
//! serves the EVM-RPC and Helios execution/consensus paths only.

use std::io;
use std::net::TcpListener;

use vsock::VsockStream;

/// Parent instance CID in Nitro enclaves is always 3.
const PARENT_CID: u32 = 3;

/// Start a background forwarder thread that bridges `127.0.0.1:{local_port}`
/// to vsock CID 3 (parent instance), port `vsock_port`.
///
/// See the module-level TRUST BOUNDARY note: this is an untrusted,
/// host-controlled egress path. Anything fetched through it must be verified
/// in-enclave (Helios light client for EVM data), never trusted as input.
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
