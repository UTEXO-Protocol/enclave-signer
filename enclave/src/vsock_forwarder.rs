//! Loopback TCP-to-vsock transport for the custody broker, Bitcoin indexer,
//! EVM RPC, and optional Helios RPC connections. The parent relays these
//! connections to their endpoints. The official KMS helper's authenticated TLS
//! connection uses direct vsock and does not pass through this module.
//!
//! Trust boundary: everything reachable
//! through this forwarder is host-controlled and untrusted. The host runs the
//! `vsock-proxy` on the far end and can drop, delay, reorder, or forge any
//! bytes. This transport does not authenticate those bytes: callers retain
//! their protocol-specific checks (e.g. SDK-authenticated KMS ciphertext,
//! expected identity pins, SPV and rgbstd validation).
//!
//! RGB-swap builds bound each listener to four workers, four copy threads and
//! eight queued connections. Connect and bidirectional I/O share the deadline
//! captured at accept: eight seconds for custody, five minutes for other egress
//! with a sixty-second idle bound. The pre-existing non-swap implementation is
//! kept separate so mint-burn and other flows retain their transport behavior.
//!
//! The listener binds to loopback only, but it is a generic egress primitive:
//! any code in the enclave process can tunnel host-bound traffic through it.
//! Hardening would replace it with a typed Esplora client private to the
//! RGB resolver path.

#[cfg(all(feature = "vsock", target_os = "linux"))]
use std::io;
#[cfg(all(feature = "vsock", target_os = "linux", not(feature = "rgb-swap")))]
use std::net::TcpListener;
#[cfg(all(feature = "vsock", target_os = "linux", not(feature = "rgb-swap")))]
use vsock::VsockStream;

#[cfg(feature = "rgb-swap")]
mod bounded;

/// Parent instance CID in Nitro enclaves is always 3.
#[cfg(all(feature = "vsock", target_os = "linux"))]
const PARENT_CID: u32 = 3;

/// RGB-swap egress uses bounded admission and connection lifetimes. Existing
/// non-swap transports retain their behavior below.
#[cfg(all(feature = "vsock", feature = "rgb-swap", target_os = "linux"))]
pub fn start_forwarder(local_port: u16, vsock_port: u32) -> io::Result<()> {
    bounded::start(local_port, vsock_port, bounded::EGRESS_LIMITS)
}

/// The custody relay uses the same eight-second aggregate bound as its client.
#[cfg(all(feature = "vsock", feature = "rgb-swap", target_os = "linux"))]
pub fn start_broker_forwarder(local_port: u16, vsock_port: u32) -> io::Result<()> {
    bounded::start(local_port, vsock_port, bounded::BROKER_LIMITS)
}

/// Start a background forwarder thread that bridges `127.0.0.1:{local_port}`
/// to vsock CID 3 (parent instance), port `vsock_port`.
///
/// See the module-level TRUST BOUNDARY note: this is an untrusted,
/// host-controlled egress path. Anything fetched through it must be verified
/// (SPV + rgbstd validation), never trusted as input.
///
/// The forwarder is fire-and-forget - it logs errors but never crashes the enclave.
#[cfg(all(feature = "vsock", target_os = "linux", not(feature = "rgb-swap")))]
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
                Ok(bytes) => tracing::debug!("forwarder: tcp->vsock closed ({bytes} bytes)"),
                Err(e) => tracing::debug!("forwarder: tcp->vsock error: {e}"),
            });
            std::thread::spawn(move || match io::copy(&mut vsock_r, &mut tcp_w) {
                Ok(bytes) => tracing::debug!("forwarder: vsock->tcp closed ({bytes} bytes)"),
                Err(e) => tracing::debug!("forwarder: vsock->tcp error: {e}"),
            });
        }
    });

    Ok(())
}
