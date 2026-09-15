//! Bounded RGB-swap egress. Each listener owns four workers, at most four
//! additional copy threads, and eight queued sockets. Connect runs in a worker;
//! queueing, connect, and both copy directions share the admission deadline.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::conn::{remaining_until, DeadlineStream, SocketTimeout};

#[derive(Clone, Copy)]
pub(super) struct Limits {
    workers: usize,
    queue: usize,
    connect: Duration,
    idle: Duration,
    total: Duration,
}

pub(super) const EGRESS_LIMITS: Limits = Limits {
    workers: 4,
    queue: 8,
    connect: Duration::from_secs(2),
    idle: Duration::from_secs(60),
    total: Duration::from_secs(300),
};
pub(super) const BROKER_LIMITS: Limits = Limits {
    idle: Duration::from_secs(8),
    total: Duration::from_secs(8),
    ..EGRESS_LIMITS
};
const THREAD_STACK: usize = 256 * 1024;

fn connections(listener: TcpListener) -> impl Iterator<Item = io::Result<TcpStream>> + Send {
    std::iter::from_fn(move || Some(listener.accept().map(|(stream, _)| stream)))
}

#[cfg(all(feature = "vsock", target_os = "linux"))]
pub(super) fn start(local_port: u16, vsock_port: u32, limits: Limits) -> io::Result<()> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, local_port))?;
    spawn(connections(listener), limits, move |deadline| {
        connect_vsock(vsock_port, deadline)
    })?;
    tracing::info!(
        local_port,
        vsock_port,
        "bounded swap vsock forwarder started"
    );
    Ok(())
}

/// The finite-iterator form also lets loopback tests join every worker and
/// verify overload/expiry cleanup without leaving background listeners behind.
fn spawn<S, C, I>(incoming: I, limits: Limits, connect: C) -> io::Result<JoinHandle<()>>
where
    S: RelaySocket + 'static,
    C: Fn(Instant) -> io::Result<S> + Send + Sync + 'static,
    I: Iterator<Item = io::Result<TcpStream>> + Send + 'static,
{
    let (send, receive) = mpsc::sync_channel::<(TcpStream, Instant)>(limits.queue);
    let receive = Arc::new(Mutex::new(receive));
    let connect = Arc::new(connect);
    let mut workers = Vec::with_capacity(limits.workers);
    for index in 0..limits.workers {
        let receive = Arc::clone(&receive);
        let connect = Arc::clone(&connect);
        workers.push(
            thread::Builder::new()
                .name(format!("swap-egress-{index}"))
                .stack_size(THREAD_STACK)
                .spawn(move || loop {
                    // Hold the receiver lock only to dequeue, never across I/O.
                    let accepted = match receive.lock() {
                        Ok(queue) => queue.recv(),
                        Err(_) => return,
                    };
                    let Ok((tcp, deadline)) = accepted else {
                        return;
                    };
                    if remaining_until(deadline).is_err() {
                        continue;
                    }
                    let result = connect(deadline.min(Instant::now() + limits.connect))
                        .and_then(|peer| relay(tcp, peer, deadline, limits.idle));
                    if let Err(error) = result {
                        tracing::debug!(%error, "swap forwarder connection closed");
                    }
                })?,
        );
    }
    thread::Builder::new()
        .name("swap-egress-accept".into())
        .stack_size(THREAD_STACK)
        .spawn(move || {
            for accepted in incoming {
                let tcp = match accepted {
                    Ok(tcp) => tcp,
                    Err(error) => {
                        tracing::warn!(%error, "swap forwarder accept failed");
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                };
                // Admission never waits on a connect, worker, or full queue.
                // Dropping a rejected socket closes it immediately.
                match send.try_send((tcp, Instant::now() + limits.total)) {
                    Ok(()) => {}
                    Err(mpsc::TrySendError::Full(_)) => {
                        tracing::debug!("swap forwarder admission limit reached");
                    }
                    Err(mpsc::TrySendError::Disconnected(_)) => break,
                }
            }
            drop(send);
            for worker in workers {
                let _ = worker.join();
            }
        })
}

/// Share a socket between one reader and one writer without duplicated FDs.
trait RelaySocket: SocketTimeout + Send + Sync {
    fn receive(&self, bytes: &mut [u8]) -> io::Result<usize>;
    fn send(&self, bytes: &[u8]) -> io::Result<usize>;
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;
}

macro_rules! relay_socket {
    ($socket:ty) => {
        impl RelaySocket for $socket {
            fn receive(&self, bytes: &mut [u8]) -> io::Result<usize> {
                (&mut &*self).read(bytes)
            }
            fn send(&self, bytes: &[u8]) -> io::Result<usize> {
                (&mut &*self).write(bytes)
            }
            fn shutdown(&self, how: Shutdown) -> io::Result<()> {
                <$socket>::shutdown(self, how)
            }
        }
    };
}
relay_socket!(TcpStream);
#[cfg(all(feature = "vsock", target_os = "linux"))]
relay_socket!(vsock::VsockStream);

struct SocketRef<'a, S>(&'a S);
impl<S: RelaySocket> Read for SocketRef<'_, S> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.0.receive(bytes)
    }
}
impl<S: RelaySocket> Write for SocketRef<'_, S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.send(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl<S: RelaySocket> SocketTimeout for SocketRef<'_, S> {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(timeout)
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(timeout)
    }
}

fn copy_direction<S: RelaySocket, D: RelaySocket>(
    source: &S,
    destination: &D,
    deadline: Instant,
    idle: Duration,
) -> io::Result<u64> {
    let result = io::copy(
        &mut DeadlineStream::with_deadline(SocketRef(source), deadline, idle),
        &mut DeadlineStream::with_deadline(SocketRef(destination), deadline, idle),
    );
    if result.is_ok() {
        // EOF in one direction must be visible to the peer while its response
        // can still travel in the other direction.
        if let Err(error) = destination.shutdown(Shutdown::Write) {
            let _ = source.shutdown(Shutdown::Both);
            let _ = destination.shutdown(Shutdown::Both);
            return Err(error);
        }
    } else {
        // An error or deadline cancels the other copy immediately. No detached
        // read can keep a socket/worker alive after its partner fails.
        let _ = source.shutdown(Shutdown::Both);
        let _ = destination.shutdown(Shutdown::Both);
    }
    result
}

fn relay<S: RelaySocket>(
    tcp: TcpStream,
    peer: S,
    deadline: Instant,
    idle: Duration,
) -> io::Result<()> {
    let result = thread::scope(|scope| {
        let outgoing = thread::Builder::new()
            .name("swap-egress-copy".into())
            .stack_size(THREAD_STACK)
            .spawn_scoped(scope, || copy_direction(&tcp, &peer, deadline, idle))?;
        let incoming = copy_direction(&peer, &tcp, deadline, idle);
        let outgoing = outgoing
            .join()
            .map_err(|_| io::Error::other("forwarder copy failed"))?;
        incoming.and(outgoing).map(|_| ())
    });
    let _ = tcp.shutdown(Shutdown::Both);
    let _ = peer.shutdown(Shutdown::Both);
    result
}

#[cfg(all(feature = "vsock", target_os = "linux"))]
fn connect_vsock(port: u32, deadline: Instant) -> io::Result<vsock::VsockStream> {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, VsockAddr};
    use std::os::fd::{AsFd, AsRawFd};
    let socket = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )?;
    remaining_until(deadline)?;
    match connect(socket.as_raw_fd(), &VsockAddr::new(super::PARENT_CID, port)) {
        Ok(()) => {}
        Err(nix::errno::Errno::EINPROGRESS) => loop {
            let millis = remaining_until(deadline)?
                .as_millis()
                .clamp(1, i32::MAX as u128);
            let timeout = PollTimeout::try_from(millis).map_err(io::Error::other)?;
            let mut fds = [PollFd::new(socket.as_fd(), PollFlags::POLLOUT)];
            let ready = match poll(&mut fds, timeout) {
                Ok(ready) => ready,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(error) => return Err(error.into()),
            };
            if ready == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "vsock connect timed out",
                ));
            }
            let error =
                nix::sys::socket::getsockopt(&socket, nix::sys::socket::sockopt::SocketError)?;
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
            if !fds[0]
                .revents()
                .is_some_and(|events| events.contains(PollFlags::POLLOUT))
            {
                return Err(io::Error::other("vsock connect did not complete"));
            }
            break;
        },
        Err(error) => return Err(error.into()),
    }
    remaining_until(deadline)?;
    let stream = vsock::VsockStream::from(socket);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        (client, listener.accept().unwrap().0)
    }

    #[test]
    fn half_close_delivers_request_eof_then_complete_response() {
        let (mut client, local) = pair();
        let (remote, mut service) = pair();
        let worker = thread::spawn(move || {
            relay(
                local,
                remote,
                Instant::now() + Duration::from_secs(2),
                Duration::from_secs(1),
            )
        });
        let responder = thread::spawn(move || {
            let mut request = Vec::new();
            service.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"request");
            service.write_all(b"complete response").unwrap();
            service.shutdown(Shutdown::Write).unwrap();
        });
        client.write_all(b"request").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"complete response");
        responder.join().unwrap();
        let result = worker.join().unwrap();
        // macOS can reject SO_RCVTIMEO after the complete bidirectional FIN
        // exchange above. Production Linux must report successful clean EOF.
        #[cfg(target_os = "macos")]
        if let Err(error) = result {
            assert_eq!(error.raw_os_error(), Some(22));
        }
        #[cfg(not(target_os = "macos"))]
        result.unwrap();
    }

    #[test]
    fn stalled_peer_expires_and_closes_both_directions() {
        let (mut client, local) = pair();
        let (remote, mut service) = pair();
        let started = Instant::now();
        let worker = thread::spawn(move || {
            relay(
                local,
                remote,
                started + Duration::from_secs(2),
                Duration::from_millis(60),
            )
        });
        let result = worker.join().unwrap();
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
        assert_eq!(service.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn ongoing_bidirectional_trickle_cannot_extend_total_deadline() {
        let (mut client, local) = pair();
        let (remote, mut service) = pair();
        let started = Instant::now();
        let worker = thread::spawn(move || {
            relay(
                local,
                remote,
                started + Duration::from_millis(160),
                Duration::from_millis(100),
            )
        });
        let responder = thread::spawn(move || {
            let mut byte = [0];
            while service.read_exact(&mut byte).is_ok() {
                if service.write_all(&byte).is_err() {
                    break;
                }
            }
        });
        let mut exchanges = 0;
        while client.write_all(b"x").is_ok() && client.read_exact(&mut [0]).is_ok() {
            exchanges += 1;
            thread::sleep(Duration::from_millis(20));
        }
        assert!(worker.join().unwrap().is_err());
        responder.join().unwrap();
        assert!(exchanges >= 2);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn deadline_cancels_a_backpressured_writer_and_its_active_partner() {
        let (mut client, local) = pair();
        let (remote, mut service) = pair();
        let started = Instant::now();
        let worker = thread::spawn(move || {
            relay(
                local,
                remote,
                started + Duration::from_millis(180),
                Duration::from_secs(1),
            )
        });
        let mut producer = client.try_clone().unwrap();
        let writer = thread::spawn(move || {
            // The service never reads, so one direction eventually blocks on
            // full socket buffers. Its opposite direction remains active.
            while producer.write_all(&[0x55; 32 * 1024]).is_ok() {}
        });
        let responder = thread::spawn(move || {
            while service.write_all(b"x").is_ok() {
                thread::sleep(Duration::from_millis(10));
            }
        });
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut received = Vec::new();
        let _ = client.read_to_end(&mut received); // shutdown may send RST with unread request data
        assert!(!received.is_empty());
        assert!(worker.join().unwrap().is_err());
        writer.join().unwrap();
        responder.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    #[cfg(all(feature = "vsock", target_os = "linux"))]
    fn occupied_broker_port_returns_error_before_starting_workers() {
        let occupied = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let error = start(occupied.local_addr().unwrap().port(), 8004, BROKER_LIMITS).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn blocked_connects_do_not_block_accept_and_overload_is_closed() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let (started, starts) = mpsc::channel();
        let limits = Limits {
            workers: 2,
            queue: 1,
            connect: Duration::from_secs(2),
            total: Duration::from_secs(2),
            ..BROKER_LIMITS
        };
        let worker_active = Arc::clone(&active);
        let worker_max = Arc::clone(&maximum);
        let worker_release = Arc::clone(&release);
        let acceptor = spawn(
            connections(listener).take(4),
            limits,
            move |deadline| -> io::Result<TcpStream> {
                let count = worker_active.fetch_add(1, Ordering::SeqCst) + 1;
                worker_max.fetch_max(count, Ordering::SeqCst);
                started.send(()).unwrap();
                let (lock, ready) = &*worker_release;
                let released = lock.lock().unwrap();
                let _ = ready
                    .wait_timeout_while(released, remaining_until(deadline)?, |released| !*released)
                    .unwrap();
                worker_active.fetch_sub(1, Ordering::SeqCst);
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "test peer unavailable",
                ))
            },
        )
        .unwrap();
        let mut clients = Vec::new();
        for _ in 0..2 {
            clients.push(TcpStream::connect(address).unwrap());
            starts.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        clients.push(TcpStream::connect(address).unwrap()); // one bounded queue slot
        let mut rejected = TcpStream::connect(address).unwrap();
        rejected
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        assert_eq!(rejected.read(&mut [0]).unwrap(), 0);
        assert_eq!(active.load(Ordering::SeqCst), 2);
        let (lock, ready) = &*release;
        *lock.lock().unwrap() = true;
        ready.notify_all();
        acceptor.join().unwrap();
        assert_eq!(maximum.load(Ordering::SeqCst), 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        for mut client in clients {
            assert_eq!(client.read(&mut [0]).unwrap(), 0);
        }
    }

    #[test]
    fn error_in_one_direction_wakes_the_other_copy() {
        struct FailedPeer;
        impl SocketTimeout for FailedPeer {
            fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
                Ok(())
            }
            fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
                Ok(())
            }
        }
        impl RelaySocket for FailedPeer {
            fn receive(&self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "test peer reset",
                ))
            }
            fn send(&self, bytes: &[u8]) -> io::Result<usize> {
                Ok(bytes.len())
            }
            fn shutdown(&self, _: Shutdown) -> io::Result<()> {
                Ok(())
            }
        }
        let (mut client, local) = pair();
        let started = Instant::now();
        assert!(relay(
            local,
            FailedPeer,
            started + Duration::from_secs(2),
            Duration::from_secs(2)
        )
        .is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn custody_forwarder_budget_fits_the_custody_request() {
        assert!(BROKER_LIMITS.total < crate::swap_persistence::RECOVERY_TIMEOUT);
        assert!(BROKER_LIMITS.connect < BROKER_LIMITS.total);
        assert_eq!(BROKER_LIMITS.workers, EGRESS_LIMITS.workers);
        assert!(EGRESS_LIMITS.idle <= EGRESS_LIMITS.total);
    }
}
