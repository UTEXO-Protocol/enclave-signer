//! Resource limits for the request socket.
//!
//! The enclave reads one length-prefixed request, replies and closes. Without
//! deadlines, a peer that holds back the body blocks a worker for ever.
//! [`DeadlineStream`] sets two bounds through `SO_RCVTIMEO` / `SO_SNDTIMEO`:
//!   * idle gap: one read or write blocks at most [`IO_IDLE_TIMEOUT`];
//!   * total deadline: the request completes in [`TOTAL_REQUEST_TIMEOUT`].
//!     This stops a slow trickle that stays below the idle timeout.
//!
//! `main::serve` also caps work: [`WORKER_THREADS`] workers and a bounded queue
//! of [`MAX_QUEUED_CONNECTIONS`].
//!
//! The only ingress is the untrusted parent, which can stop the enclave anyway.
//! These limits are availability defense in depth. They are compile-time
//! constants (PCR-attested), not env settings.

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

/// Max time a single read or write syscall on the request socket may block.
pub const IO_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Max wall-clock time for one request, from accept to the last write.
pub const TOTAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Connection worker threads. The only peer is the parent, so a small pool is
/// sufficient. One slow request does not block the others.
pub const WORKER_THREADS: usize = 4;

/// Max accepted connections that wait for a worker. When full, new
/// connections are closed.
pub const MAX_QUEUED_CONNECTIONS: usize = 16;

/// Request socket timeouts, for `TcpStream` (dev, tests) and `VsockStream`
/// (production).
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

#[cfg(all(feature = "vsock", target_os = "linux"))]
impl SocketTimeout for vsock::VsockStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        vsock::VsockStream::set_read_timeout(self, dur)
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        vsock::VsockStream::set_write_timeout(self, dur)
    }
}

/// A socket with an absolute per-request deadline. Before each read or write,
/// it sets the kernel timeout to `min(idle, time left)`. After the deadline,
/// every operation fails with `TimedOut` and does not touch the socket.
pub struct DeadlineStream<S> {
    inner: S,
    deadline: Instant,
    idle: Duration,
}

impl<S: SocketTimeout> DeadlineStream<S> {
    /// Start the deadline now. `total` is the request budget. `idle` caps one
    /// syscall.
    pub fn new(inner: S, total: Duration, idle: Duration) -> Self {
        Self::with_deadline(inner, Instant::now() + total, idle)
    }

    /// Use an existing deadline.
    pub fn with_deadline(inner: S, deadline: Instant, idle: Duration) -> Self {
        Self {
            inner,
            deadline,
            idle,
        }
    }

    /// Time left, capped at `idle`. `TimedOut` error when no time is left.
    fn arm(&self) -> io::Result<Duration> {
        Ok(remaining_until(self.deadline)?.min(self.idle))
    }
}

/// Time left until `deadline`, or `TimedOut`. Used by sockets and custody calls.
pub(crate) fn remaining_until(deadline: Instant) -> io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "request deadline exceeded",
        ));
    }
    Ok(remaining)
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
        // Zero budget: the deadline is now, so the read fails at once.
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
