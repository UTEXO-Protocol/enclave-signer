//! The connection loop: read one framed request, dispatch it, write one
//! framed response, close. One request per connection, by design.

use std::io::{Read, Write};

use super::context::ServerContext;
use super::dispatch::dispatch;
use crate::error::Result;
use crate::framing;
use crate::proto::EnclaveRequest;

/// Handle a single connection: read one request, dispatch, write one response, close.
pub fn handle_connection(stream: impl Read + Write, ctx: &ServerContext) {
    if let Err(e) = process_connection(stream, ctx) {
        tracing::error!("connection error: {}", e);
    }
}

fn process_connection(mut stream: impl Read + Write, ctx: &ServerContext) -> Result<()> {
    tracing::debug!("reading request");
    let request: EnclaveRequest = framing::read_message(&mut stream)?;

    let (response, reservation) = dispatch(request, ctx);

    framing::write_message(&mut stream, &response)?;
    tracing::debug!("response written");

    // Commit the replay key only after the write succeeds. A failed write drops
    // the reservation and rolls the key back.
    if let Some(reservation) = reservation {
        reservation.commit();
    }
    Ok(())
}

/// A connection that aged out in the queue is not dispatched. Its first
/// read fails.
#[cfg(all(test, feature = "spv"))]
mod expired_pickup {
    use std::io::{self, Cursor, Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::process_connection;
    use crate::config::BridgeConfig;
    use crate::conn::{DeadlineStream, SocketTimeout, IO_IDLE_TIMEOUT};
    use crate::framing;
    use crate::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
    use crate::proto::enclave_request::Request;
    use crate::proto::*;
    use crate::server::ServerContext;
    use crate::state::EnclaveState;

    /// Counts every read and write that reaches the socket.
    struct CountingSock {
        request: Cursor<Vec<u8>>,
        io_calls: Arc<AtomicUsize>,
    }

    impl Read for CountingSock {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.io_calls.fetch_add(1, Ordering::SeqCst);
            self.request.read(buf)
        }
    }

    impl Write for CountingSock {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.io_calls.fetch_add(1, Ordering::SeqCst);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl SocketTimeout for CountingSock {
        fn set_read_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        fn set_write_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_connection_whose_budget_ran_out_is_not_dispatched() {
        let mut request = Vec::new();
        framing::write_message(
            &mut request,
            &EnclaveRequest {
                request: Some(Request::Health(HealthRequest {})),
            },
        )
        .expect("frame request");

        let io_calls = Arc::new(AtomicUsize::new(0));
        let stream = DeadlineStream::new(
            CountingSock {
                request: Cursor::new(request),
                io_calls: Arc::clone(&io_calls),
            },
            Duration::from_millis(20),
            IO_IDLE_TIMEOUT,
        );

        // The wait a busy worker pool imposes.
        std::thread::sleep(Duration::from_millis(200));

        let ctx = ServerContext::new(
            EnclaveState::new(bitcoin::Network::Bitcoin),
            BridgeConfig::default(),
            std::sync::Mutex::new(HeaderChain::new(
                Network::Regtest,
                checkpoint_for(Network::Regtest),
            )),
        );

        assert!(process_connection(stream, &ctx).is_err());
        assert_eq!(io_calls.load(Ordering::SeqCst), 0);
    }
}
