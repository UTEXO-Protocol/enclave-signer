use super::*;
use crate::enclave_proto::{sign_request::SourceNetwork, RgbSource};
use std::net::{SocketAddr, TcpListener};
use std::thread;
use tonic::Code;

#[test]
fn finality_wire_code_survives_changed_diagnostic_wording() {
    for diagnostic in [
        "FundsIn receipt block 100 is above RPC safe block 99 - refusing to sign",
        "The finality head has not reached the deposit yet",
    ] {
        let status = ParentAdapterService::enclave_error_to_status(&enclave_proto::ErrorResponse {
            code: 8,
            message: diagnostic.into(),
        });
        assert_eq!(status.code(), Code::FailedPrecondition);
        assert!(status
            .message()
            .starts_with("evm event pending finality: 1 signer node(s)"));
        assert!(status.message().contains(diagnostic));
    }
}

#[test]
fn validation_errors_do_not_become_finality_waits() {
    // Even a familiar diagnostic is not retryable without wire code 8.
    for diagnostic in [
        "cross-check failed: BridgeFundsIn amount mismatch",
        "FundsIn receipt block 100 is above RPC safe block 99 - refusing to sign",
    ] {
        let status = ParentAdapterService::enclave_error_to_status(&enclave_proto::ErrorResponse {
            code: 3,
            message: diagnostic.into(),
        });
        assert_eq!(status.code(), Code::FailedPrecondition);
        assert_eq!(status.message(), diagnostic);
    }
}

#[test]
fn evm_destination_forwards_burn_destination() {
    let payload = grpc_proto::EnrichedEvmPayload {
        burn_destination: Some(grpc_proto::BurnDestination {
            version: 1,
            destination_chain_id: 137,
            dst_eid: 30109,
            recipient: vec![0x42; 20],
        }),
        ..Default::default()
    };
    let dest =
        ParentAdapterService::enclave_destination_network(sign_request::Data::EvmData(payload));
    let enclave_proto::sign_request::DestinationNetwork::EvmDestination(evm) = dest else {
        panic!("expected an EVM destination");
    };
    assert_eq!(
        evm.burn_destination,
        Some(enclave_proto::BurnDestination {
            version: 1,
            destination_chain_id: 137,
            dst_eid: 30109,
            recipient: vec![0x42; 20],
        })
    );
}

const BUDGET: Duration = Duration::from_millis(300);
const SLACK: Duration = Duration::from_secs(1);

fn health() -> EnclaveRequest {
    EnclaveRequest {
        request: Some(enclave_request::Request::Health(Default::default())),
    }
}

fn tcp(addr: SocketAddr) -> EnclaveTarget {
    EnclaveTarget::Tcp(addr.to_string())
}

/// Run `exchange` with `BUDGET` and check that it stops at the deadline.
fn assert_stops_at_deadline(target: EnclaveTarget, req: EnclaveRequest) {
    let start = Instant::now();
    let err = exchange(&target, &req, start + BUDGET, None).unwrap_err();
    assert_eq!(err.code(), Code::DeadlineExceeded, "{err:?}");
    assert!(start.elapsed() < BUDGET + SLACK, "{:?}", start.elapsed());
}

#[test]
fn queued_request_after_deadline_does_not_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = tcp(listener.local_addr().unwrap());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    rt.block_on(async {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let blocker = tokio::task::spawn_blocking(move || wait.recv());
        let err = send_within(target, health(), Duration::from_millis(50), None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::DeadlineExceeded);
        release.send(()).unwrap();
        blocker.await.unwrap().unwrap();
        // The pool runs tasks in order, so the late worker is done.
        tokio::task::spawn_blocking(|| ()).await.unwrap();
    });
    listener.set_nonblocking(true).unwrap();
    let err = listener.accept().unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
}

#[cfg(target_os = "linux")]
#[test]
fn connect_stops_at_deadline() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    listener.bind(&addr.into()).unwrap();
    listener.listen(0).unwrap();
    let addr = listener.local_addr().unwrap();
    // Fill the accept queue. Linux then drops new SYNs.
    let mut fillers = Vec::new();
    loop {
        let filler = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        if filler
            .connect_timeout(&addr, Duration::from_millis(100))
            .is_err()
        {
            break;
        }
        fillers.push(filler);
        assert!(fillers.len() < 16, "accept queue does not fill");
    }
    assert_stops_at_deadline(tcp(addr.as_socket().unwrap()), health());
}

#[test]
fn slow_write_stops_at_deadline() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    listener.set_recv_buffer_size(4096).unwrap();
    listener.bind(&addr.into()).unwrap();
    listener.listen(1).unwrap();
    let addr = listener.local_addr().unwrap().as_socket().unwrap();
    thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        let start = Instant::now();
        let mut buf = [0u8; 1024];
        while start.elapsed() < Duration::from_secs(5) {
            if !matches!(peer.read(&mut buf), Ok(n) if n > 0) {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });
    let req = EnclaveRequest {
        request: Some(enclave_request::Request::Sign(enclave_proto::SignRequest {
            source_network: Some(SourceNetwork::RgbSource(RgbSource {
                consignment: vec![0x5a; 8 * 1024 * 1024],
                ..Default::default()
            })),
            ..Default::default()
        })),
    };
    assert_stops_at_deadline(tcp(addr), req);
}

#[test]
fn slow_read_stops_at_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        let _: EnclaveRequest = framing::read_message(&mut peer).unwrap();
        peer.write_all(&1000u32.to_le_bytes()).unwrap();
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) && peer.write_all(&[0]).is_ok() {
            thread::sleep(Duration::from_millis(20));
        }
    });
    assert_stops_at_deadline(tcp(addr), health());
}

/// A socket failure that is not a timeout is `Unavailable`, which the
/// node retries: the enclave read the request and closed the connection.
#[test]
fn a_closed_connection_is_unavailable() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        let _: EnclaveRequest = framing::read_message(&mut peer).unwrap();
    });
    let err = exchange(&tcp(addr), &health(), Instant::now() + BUDGET, None).unwrap_err();
    assert_eq!(err.code(), Code::Unavailable, "{err:?}");
}

/// The enclave must give up before the parent. The parent starts from the
/// deadline of the image.
#[test]
fn the_parent_starts_from_the_deadline_of_the_image() {
    let image = utexo_bridge_enclave::limits::Limits::DEFAULTS.total_request_timeout_secs;
    assert_eq!(IMAGE_DEADLINE_SECS, image);
    let service = ParentAdapterService::new(EnclaveTarget::Tcp("127.0.0.1:1".into()));
    assert!(service.enclave_wait() > Duration::from_secs(image));
}

/// One enclave answer with `limits`, then each connection fails.
fn answer_limits(listener: TcpListener, deadline: u64) {
    thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        let _: EnclaveRequest = framing::read_message(&mut peer).unwrap();
        let current = enclave_proto::Limits {
            total_request_timeout_secs: deadline,
            ..Default::default()
        };
        let response = EnclaveResponse {
            response: Some(enclave_response::Response::Limits(
                enclave_proto::LimitsResponse {
                    current: Some(current),
                    image: None,
                },
            )),
        };
        framing::write_message(&mut peer, &response).unwrap();
    });
}

/// The operator changes the deadline with the CLI, so the wait must follow
/// the enclave, at any value. A failed read must not lower the wait.
#[tokio::test]
async fn the_wait_follows_the_deadline_in_force() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let service = ParentAdapterService::new(tcp(listener.local_addr().unwrap()));
    answer_limits(listener, 3_600);

    service.read_enclave_limits().await;
    assert_eq!(service.enclave_wait(), Duration::from_secs(3_610));
    let limits = service.limits_in_force().unwrap();
    assert_eq!(limits.total_request_timeout_secs, 3_600);

    service.read_enclave_limits().await;
    assert_eq!(service.enclave_wait(), Duration::from_secs(3_610));
    assert_eq!(service.limits_in_force(), Some(limits));
}

/// The parent's own timeout must outlast its wait for the enclave.
#[test]
fn a_request_timeout_at_or_below_the_enclave_wait_is_reported() {
    let wait = Duration::from_secs(100);
    assert!(timeout_conflict(Duration::from_secs(101), wait).is_none());
    let problem = timeout_conflict(Duration::from_secs(100), wait).unwrap();
    assert!(
        problem.contains("GRPC_REQUEST_TIMEOUT_SECS is 100 s"),
        "{problem}"
    );
    assert!(timeout_conflict(Duration::from_secs(60), wait).is_some());
}

/// A kept reply must outlive the replay window of the enclave.
#[test]
fn a_reply_ttl_below_the_enclave_replay_window_is_reported() {
    let enclave = Duration::from_secs(3_600);
    assert!(reply_ttl_conflict(Duration::from_secs(3_600), enclave).is_none());
    let problem = reply_ttl_conflict(Duration::from_secs(600), enclave).unwrap();
    assert!(
        problem.contains("SIGNED_RESPONSE_TTL_SECS is 600 s"),
        "{problem}"
    );
}

/// The default reply store outlives the replay window of the image.
#[test]
fn the_default_reply_ttl_covers_the_image_replay_window() {
    let image = utexo_bridge_enclave::limits::Limits::DEFAULTS.mint_replay_ttl_secs;
    assert!(crate::signed_responses::DEFAULT_TTL >= Duration::from_secs(image));
}

#[test]
fn handler_timeout_must_outlast_the_enclave_wait() {
    let wait = IMAGE_DEADLINE_SECS + ENCLAVE_WAIT_MARGIN_SECS;
    assert!(!handler_timeout_covers_enclave_wait(
        wait,
        IMAGE_DEADLINE_SECS
    ));
    assert!(handler_timeout_covers_enclave_wait(
        wait + 1,
        IMAGE_DEADLINE_SECS
    ));
    assert!(!handler_timeout_covers_enclave_wait(120, 111));
    assert!(!handler_timeout_covers_enclave_wait(120, u64::MAX));
}

#[test]
fn the_default_handler_timeout_is_valid_for_the_image_deadline() {
    assert!(image_handler_timeout_is_valid(
        crate::config::DEFAULT_GRPC_REQUEST_TIMEOUT_SECS
    ));
    assert!(!image_handler_timeout_is_valid(1));
}
