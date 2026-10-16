//! The TLS rule for the loopback forwarders.
//!
//! A Nitro enclave has no network interface. Each outbound connection goes
//! through a loopback forwarder ([`crate::vsock_forwarder`]) to the host. The
//! host can read and change each plaintext byte on that path.
//!
//! A forwarder for a TLS endpoint (`ssl://` or `https://` indexer, EVM RPC,
//! KMS) accepts only a connection that starts with a TLS handshake record.
//! Thus no client in the enclave can send plaintext to such an endpoint, not
//! even after an HTTPS -> HTTP redirect. Some HTTP clients (`minreq` in
//! `esplora-client`, `reqwest` in the EVM RPC client) follow such redirects,
//! and the enclave cannot turn that off through their APIs. A redirect to a
//! port with no forwarder, or to another host, has no route out.

use std::io::{self, Read};
use std::net::TcpStream;
use std::time::Duration;

/// Time a client has to send the first three bytes. A TLS client sends its
/// ClientHello at once.
const FIRST_BYTES_TIMEOUT: Duration = Duration::from_secs(10);

/// True for the header of a TLS handshake record: content type 22, protocol
/// major version 3. A ClientHello record uses minor version 1 to 3, and TLS
/// 1.3 also writes 1 or 3 here. Plaintext HTTP starts with an ASCII method
/// name, and plaintext Electrum with `{`.
pub fn is_tls_handshake(header: &[u8; 3]) -> bool {
    header[0] == 0x16 && header[1] == 0x03 && (0x01..=0x04).contains(&header[2])
}

/// Reads the first three bytes of a client connection and returns them if
/// they start a TLS handshake record. The caller must send them on before
/// the rest of the stream.
///
/// Errors: a timeout, a short read, or a non-TLS start (`InvalidData`). The
/// caller then closes the connection, and no byte reaches the host.
pub fn read_tls_record_header(stream: &mut TcpStream) -> io::Result<[u8; 3]> {
    stream.set_read_timeout(Some(FIRST_BYTES_TIMEOUT))?;
    let mut header = [0u8; 3];
    stream.read_exact(&mut header)?;
    stream.set_read_timeout(None)?;
    if !is_tls_handshake(&header) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "connection to a TLS endpoint starts with {header:02x?}, not a TLS handshake \
                 record - refusing to send plaintext to the host"
            ),
        ));
    }
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// A gated listener: the result of the gate for each connection goes to
    /// the returned channel.
    fn gate() -> (std::net::SocketAddr, mpsc::Receiver<io::Result<[u8; 3]>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let _ = tx.send(read_tls_record_header(&mut stream));
            }
        });
        (addr, rx)
    }

    fn send(addr: std::net::SocketAddr, bytes: &[u8]) {
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(bytes).unwrap();
    }

    #[test]
    fn accepts_a_tls_client_hello() {
        let (addr, rx) = gate();
        // Record header of a real ClientHello: handshake, TLS 1.0 record
        // version (as TLS 1.2 and 1.3 clients write it), then the length.
        send(addr, &[0x16, 0x03, 0x01, 0x02, 0x00, 0x01]);
        assert_eq!(rx.recv().unwrap().unwrap(), [0x16, 0x03, 0x01]);
    }

    #[test]
    fn refuses_plaintext_http() {
        let (addr, rx) = gate();
        send(
            addr,
            b"GET /tx/00/raw HTTP/1.1\r\nHost: esplora.test\r\n\r\n",
        );
        let err = rx.recv().unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    }

    #[test]
    fn refuses_plaintext_electrum() {
        let (addr, rx) = gate();
        send(addr, br#"{"jsonrpc":"2.0","method":"server.version"}"#);
        assert!(rx.recv().unwrap().is_err());
    }

    #[test]
    fn the_header_check_is_exact() {
        assert!(is_tls_handshake(&[0x16, 0x03, 0x03]));
        assert!(!is_tls_handshake(&[0x17, 0x03, 0x03])); // application data
        assert!(!is_tls_handshake(&[0x16, 0x02, 0x00])); // SSL 2
        assert!(!is_tls_handshake(&[0x16, 0x03, 0x00])); // SSL 3
        assert!(!is_tls_handshake(b"GET"));
        assert!(!is_tls_handshake(b"POS"));
    }

    /// The downgrade from the review of #300: `esplora-client` follows an
    /// HTTPS -> HTTP redirect, and its next request is plaintext. Here the
    /// client sends that plaintext request to a gated forwarder port. The
    /// gate refuses it before any byte goes on, and the client gets an error,
    /// not an answer.
    #[cfg(feature = "rgb-validation")]
    #[test]
    fn a_downgraded_esplora_request_does_not_leave_the_enclave() {
        use rgbstd::indexers::esplora_blocking::esplora_client;

        let (addr, rx) = gate();
        let client = esplora_client::Builder::new(&format!("http://{addr}"))
            .timeout(5)
            .build_blocking();
        let txid: bitcoin::Txid =
            "8c2a99d569e9d3cfb5abe1697cdb73d170835672db9c161d684cb01d50c6b9e6"
                .parse()
                .unwrap();
        assert!(client.get_tx(&txid).is_err(), "the client got no answer");
        let gated = rx.recv().unwrap();
        assert_eq!(
            gated.unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "the gate saw the plaintext request and refused it"
        );
    }
}
