//! Connection-level resource limits for the request socket (audit M-03 / #83).
//!
//! The enclave reads a single length-prefixed request, replies, and closes
//! (see `framing` + `server::handle_connection`). Without deadlines a peer that
//! sends a length prefix and then withholds (or trickles) the body parks the
//! handler indefinitely; combined with serial accept handling that stalls every
//! other client. [`DeadlineStream`] bounds a single request end-to-end.
//!
//! Two bounds, both enforced by shrinking the kernel socket timeout
//! (`SO_RCVTIMEO` / `SO_SNDTIMEO`) before each syscall:
//!   * idle gap: no single read/write may block longer than [`IO_IDLE_TIMEOUT`]
//!     (kills "send prefix, then withhold the body"); and
//!   * total deadline: the whole request must complete within
//!     [`TOTAL_REQUEST_TIMEOUT`] (kills a slow trickle that stays just under the
//!     idle timeout, which a fixed per-read timeout alone cannot bound).
//!
//! The accept layer (`main::serve`) also caps in-flight work: a small worker
//! pool ([`WORKER_THREADS`]) fed by a bounded queue ([`MAX_QUEUED_CONNECTIONS`])
//! so one slow-but-bounded request can't starve the rest.
//!
//! Sole ingress is the parent over vsock (already treated as untrusted, and
//! able to withhold traffic or kill the enclave outright), so this is
//! availability defense-in-depth on a stateless single-request signer. The
//! limits are compile-time constants (PCR-attested), not env-tunable.

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

/// Max time a single read or write syscall on the request socket may block.
pub const IO_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Max wall-clock for one request, end-to-end (read + dispatch-adjacent I/O +
/// write). A trickle that stays under [`IO_IDLE_TIMEOUT`] per read is still
/// bounded by this.
pub const TOTAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Number of connection-handling worker threads. The sole ingress is the
/// single parent peer, so a small pool is ample; it exists so one slow request
/// can't block the others.
pub const WORKER_THREADS: usize = 4;

/// Bounded backlog of accepted-but-unhandled connections. When full, new
/// connections are dropped (closed) rather than queued unboundedly.
pub const MAX_QUEUED_CONNECTIONS: usize = 16;

/// Sockets we accept requests on. Both `std::net::TcpStream` (dev / tests) and
/// `vsock::VsockStream` (production) expose std-style timeout setters; this
/// trait lets [`DeadlineStream`] arm whichever it wraps.
pub trait SocketTimeout {
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
}

impl SocketTimeout for std::net::TcpStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        std::net::TcpStream::set_read_timeout(self, dur)
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        std::net::TcpStream::set_write_timeout(self, dur)
    }
}

// Production socket. vsock is Linux-only; mirrors the TcpStream impl exactly
// (the vsock crate's VsockStream provides the same std-style setters). Not
// compiled (or testable) off Linux.
#[cfg(all(feature = "vsock", target_os = "linux"))]
impl SocketTimeout for vsock::VsockStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        vsock::VsockStream::set_read_timeout(self, dur)
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        vsock::VsockStream::set_write_timeout(self, dur)
    }
}

/// Wraps a socket with an absolute per-request deadline. Before each read/write
/// it arms the kernel timeout to `min(idle, time-left)`; once the deadline has
/// passed, every op fails `TimedOut` without touching the socket. Implements
/// `Read + Write`, so `framing::{read_message, write_message}` use it unchanged.
pub struct DeadlineStream<S> {
    inner: S,
    deadline: Instant,
    idle: Duration,
}

impl<S: SocketTimeout> DeadlineStream<S> {
    /// Start the deadline clock now. `total` is the whole-request budget;
    /// `idle` caps any single syscall.
    pub fn new(inner: S, total: Duration, idle: Duration) -> Self {
        Self {
            inner,
            deadline: Instant::now() + total,
            idle,
        }
    }

    /// Time left until the deadline, or `None` (with a ready-made error) if the
    /// budget is exhausted. The armed value is clamped to `idle`.
    fn arm(&self) -> io::Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request deadline exceeded",
            ));
        }
        Ok(remaining.min(self.idle))
    }
}

impl<S: Read + SocketTimeout> Read for DeadlineStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let budget = self.arm()?;
        self.inner.set_read_timeout(Some(budget))?;
        self.inner.read(buf)
    }
}

impl<S: Write + SocketTimeout> Write for DeadlineStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let budget = self.arm()?;
        self.inner.set_write_timeout(Some(budget))?;
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// In-memory stand-in: Read/Write over a cursor, no-op timeout setters.
    struct MockSock {
        rx: Cursor<Vec<u8>>,
        tx: Vec<u8>,
    }
    impl MockSock {
        fn with_read(data: Vec<u8>) -> Self {
            Self {
                rx: Cursor::new(data),
                tx: Vec::new(),
            }
        }
    }
    impl Read for MockSock {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.rx.read(buf)
        }
    }
    impl Write for MockSock {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.tx.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl SocketTimeout for MockSock {
        fn set_read_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        fn set_write_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn reads_pass_through_before_deadline() {
        let mut s = DeadlineStream::new(
            MockSock::with_read(vec![1, 2, 3, 4]),
            Duration::from_secs(60),
            IO_IDLE_TIMEOUT,
        );
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3, 4]);
    }

    #[test]
    fn writes_pass_through_before_deadline() {
        let mut s = DeadlineStream::new(
            MockSock::with_read(vec![]),
            Duration::from_secs(60),
            IO_IDLE_TIMEOUT,
        );
        assert_eq!(s.write(&[9, 9, 9]).unwrap(), 3);
        assert_eq!(s.inner.tx, vec![9, 9, 9]);
    }

    #[test]
    fn read_after_deadline_is_timed_out() {
        // Zero total budget => deadline is already (about) now: the next op
        // sees no time left and fails without reading. No sleeping needed.
        let mut s = DeadlineStream::new(
            MockSock::with_read(vec![1, 2, 3]),
            Duration::ZERO,
            IO_IDLE_TIMEOUT,
        );
        let mut buf = [0u8; 1];
        let err = s.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn write_after_deadline_is_timed_out() {
        let mut s =
            DeadlineStream::new(MockSock::with_read(vec![]), Duration::ZERO, IO_IDLE_TIMEOUT);
        let err = s.write(&[1]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}
