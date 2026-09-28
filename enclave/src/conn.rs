//! Connection-level resource limits for the request socket.
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
//! Sole ingress is the parent over vsock, already untrusted and able to kill
//! the enclave outright, so this is availability defense in depth. The limits
//! are compile-time constants (PCR-attested), not env-tunable.

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

// Production socket. vsock is Linux-only and mirrors the TcpStream impl.
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

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use std::cell::Cell;
    use std::io::Cursor;

    /// Records the last timeout armed on it, so the clamp logic is observable.
    struct RecordingSock {
        rx: Cursor<Vec<u8>>,
        tx: Vec<u8>,
        last_read_timeout: Cell<Option<Duration>>,
        last_write_timeout: Cell<Option<Duration>>,
        fail_set_timeout: bool,
        flushes: Cell<usize>,
    }
    impl RecordingSock {
        fn new(data: Vec<u8>) -> Self {
            Self {
                rx: Cursor::new(data),
                tx: Vec::new(),
                last_read_timeout: Cell::new(None),
                last_write_timeout: Cell::new(None),
                fail_set_timeout: false,
                flushes: Cell::new(0),
            }
        }
    }
    impl Read for RecordingSock {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.rx.read(buf)
        }
    }
    impl Write for RecordingSock {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.tx.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes.set(self.flushes.get() + 1);
            Ok(())
        }
    }
    impl SocketTimeout for RecordingSock {
        fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
            if self.fail_set_timeout {
                return Err(io::Error::other("setsockopt failed"));
            }
            self.last_read_timeout.set(dur);
            Ok(())
        }
        fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
            if self.fail_set_timeout {
                return Err(io::Error::other("setsockopt failed"));
            }
            self.last_write_timeout.set(dur);
            Ok(())
        }
    }

    #[test]
    fn constants_are_the_documented_bounds() {
        assert_eq!(IO_IDLE_TIMEOUT, Duration::from_secs(10));
        assert_eq!(TOTAL_REQUEST_TIMEOUT, Duration::from_secs(30));
        assert!(IO_IDLE_TIMEOUT < TOTAL_REQUEST_TIMEOUT);
        assert_eq!(WORKER_THREADS, 4);
        assert_eq!(MAX_QUEUED_CONNECTIONS, 16);
    }

    #[test]
    fn read_arms_the_idle_timeout_when_plenty_of_budget_remains() {
        let mut s = DeadlineStream::new(
            RecordingSock::new(vec![1, 2, 3]),
            Duration::from_secs(3600),
            Duration::from_millis(250),
        );
        let mut buf = [0u8; 3];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3]);
        assert_eq!(
            s.inner.last_read_timeout.get(),
            Some(Duration::from_millis(250)),
            "budget is clamped to the idle timeout"
        );
        assert_eq!(s.inner.last_write_timeout.get(), None);
    }

    #[test]
    fn read_arms_the_remaining_budget_when_it_is_below_idle() {
        // Total budget smaller than idle: the armed timeout is the remainder,
        // which is at most the total.
        let total = Duration::from_millis(50);
        let mut s =
            DeadlineStream::new(RecordingSock::new(vec![1]), total, Duration::from_secs(10));
        let mut buf = [0u8; 1];
        s.read_exact(&mut buf).unwrap();
        let armed = s.inner.last_read_timeout.get().expect("timeout armed");
        assert!(
            armed <= total,
            "armed {armed:?} must not exceed total {total:?}"
        );
        assert!(!armed.is_zero());
    }

    #[test]
    fn write_arms_the_write_timeout_and_flush_passes_through() {
        let mut s = DeadlineStream::new(
            RecordingSock::new(vec![]),
            Duration::from_secs(3600),
            Duration::from_millis(250),
        );
        s.write_all(&[7, 8]).unwrap();
        s.flush().unwrap();
        assert_eq!(s.inner.tx, vec![7, 8]);
        assert_eq!(
            s.inner.last_write_timeout.get(),
            Some(Duration::from_millis(250))
        );
        assert_eq!(s.inner.last_read_timeout.get(), None);
        assert_eq!(s.inner.flushes.get(), 1);
    }

    #[test]
    fn flush_is_not_gated_by_the_deadline() {
        // Flushing after the deadline still reaches the socket: the data was
        // already accepted, only new reads/writes are refused.
        let mut s =
            DeadlineStream::new(RecordingSock::new(vec![]), Duration::ZERO, IO_IDLE_TIMEOUT);
        assert!(s.flush().is_ok());
        assert_eq!(s.inner.flushes.get(), 1);
    }

    #[test]
    fn setsockopt_failure_surfaces_as_the_io_error() {
        let mut sock = RecordingSock::new(vec![1, 2]);
        sock.fail_set_timeout = true;
        let mut s = DeadlineStream::new(sock, Duration::from_secs(60), IO_IDLE_TIMEOUT);
        let mut buf = [0u8; 1];
        let err = s.read(&mut buf).unwrap_err();
        assert!(err.to_string().contains("setsockopt failed"));
        let err = s.write(&[1]).unwrap_err();
        assert!(err.to_string().contains("setsockopt failed"));
        // Nothing was read or written past the failed arm.
        assert_eq!(s.inner.rx.position(), 0);
        assert!(s.inner.tx.is_empty());
    }

    #[test]
    fn expired_deadline_does_not_touch_the_socket() {
        let mut s = DeadlineStream::new(
            RecordingSock::new(vec![1, 2, 3]),
            Duration::ZERO,
            IO_IDLE_TIMEOUT,
        );
        let mut buf = [0u8; 3];
        assert_eq!(
            s.read(&mut buf).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(s.write(&[9]).unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(s.inner.last_read_timeout.get(), None, "no timeout armed");
        assert_eq!(s.inner.last_write_timeout.get(), None);
        assert_eq!(s.inner.rx.position(), 0);
        assert!(s.inner.tx.is_empty());
        // Every subsequent op keeps failing the same way.
        assert_eq!(
            s.read(&mut buf).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn eof_from_the_inner_socket_passes_through_as_zero_bytes() {
        let mut s = DeadlineStream::new(
            RecordingSock::new(vec![]),
            Duration::from_secs(60),
            IO_IDLE_TIMEOUT,
        );
        let mut buf = [0u8; 4];
        assert_eq!(s.read(&mut buf).unwrap(), 0);
        let err = s.read_exact(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn framing_reads_a_message_through_the_deadline_stream() {
        use crate::proto::{enclave_request, EnclaveRequest, GetPublicKeyRequest};
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::GetPublicKey(
                GetPublicKeyRequest {},
            )),
        };
        let mut wire = Vec::new();
        crate::framing::write_message(&mut wire, &req).unwrap();
        let mut s = DeadlineStream::new(
            RecordingSock::new(wire),
            TOTAL_REQUEST_TIMEOUT,
            IO_IDLE_TIMEOUT,
        );
        let got: EnclaveRequest = crate::framing::read_message(&mut s).unwrap();
        assert_eq!(got, req);
        crate::framing::write_message(&mut s, &req).unwrap();
        assert_eq!(s.inner.tx, req.encode_to_vec_framed());
    }

    trait FramedEncode {
        fn encode_to_vec_framed(&self) -> Vec<u8>;
    }
    impl<M: prost::Message> FramedEncode for M {
        fn encode_to_vec_framed(&self) -> Vec<u8> {
            let body = self.encode_to_vec();
            let mut out = (body.len() as u32).to_le_bytes().to_vec();
            out.extend_from_slice(&body);
            out
        }
    }

    #[test]
    fn tcp_stream_impl_forwards_to_the_std_setters() {
        // Real socket pair on loopback: arming must succeed and round-trip.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        // The kernel rounds SO_RCVTIMEO / SO_SNDTIMEO up to its tick, so
        // compare with a tolerance rather than exactly.
        let close = |got: Option<Duration>, want: Duration| {
            let got = got.expect("timeout armed");
            assert!(
                got >= want && got < want + Duration::from_millis(50),
                "{got:?} vs {want:?}"
            );
        };
        SocketTimeout::set_read_timeout(&client, Some(Duration::from_millis(100))).unwrap();
        close(client.read_timeout().unwrap(), Duration::from_millis(100));
        SocketTimeout::set_write_timeout(&client, Some(Duration::from_millis(200))).unwrap();
        close(client.write_timeout().unwrap(), Duration::from_millis(200));
        SocketTimeout::set_read_timeout(&client, None).unwrap();
        assert_eq!(client.read_timeout().unwrap(), None);

        // Through the wrapper, a withheld body times out on the kernel clock
        // rather than blocking forever.
        let mut s = DeadlineStream::new(client, Duration::from_secs(5), Duration::from_millis(20));
        let mut buf = [0u8; 1];
        let err = s.read(&mut buf).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "{err:?}"
        );
        drop(server);
    }
}
