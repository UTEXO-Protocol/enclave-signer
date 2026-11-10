//! `SetLimits` and `GetLimits` over the full wire path: TCP framing -> `dispatch`
//! -> the process limits. The limits are one value for each process, so this
//! file has one test.

use utexo_bridge_enclave::framing::MAX_MESSAGE_SIZE;
use utexo_bridge_enclave::limits::Limits;
use utexo_bridge_enclave::proto::enclave_request::Request as EReq;
use utexo_bridge_enclave::proto::enclave_response::Response as ERes;
use utexo_bridge_enclave::proto::{
    EnclaveRequest, GetLimitsRequest, Limits as WireLimits, LimitsResponse, SetLimitsRequest,
};

mod common;
use common::{send_request, start_test_server};

fn send(port: u16, request: EReq) -> ERes {
    send_request(
        port,
        &EnclaveRequest {
            request: Some(request),
        },
    )
    .response
    .expect("a response")
}

fn get(port: u16) -> LimitsResponse {
    match send(port, EReq::GetLimits(GetLimitsRequest {})) {
        ERes::Limits(limits) => limits,
        other => panic!("unexpected response: {other:?}"),
    }
}

fn set(port: u16, values: WireLimits, reset: bool) -> ERes {
    send(
        port,
        EReq::SetLimits(SetLimitsRequest {
            values: Some(values),
            reset,
        }),
    )
}

fn current(limits: &LimitsResponse) -> Limits {
    Limits::from(limits.current.as_ref().expect("current"))
}

fn image(limits: &LimitsResponse) -> Limits {
    Limits::from(limits.image.as_ref().expect("image"))
}

#[test]
fn the_operator_changes_and_resets_the_limits_of_a_running_enclave() {
    let port = start_test_server();

    let start = get(port);
    assert_eq!(current(&start), image(&start));
    assert_eq!(
        current(&start).max_message_bytes,
        u64::from(MAX_MESSAGE_SIZE)
    );

    // A refused change keeps the values. 68 s of rgb-lib is over three quarters
    // of the image value of `total_request_timeout_secs`.
    let refused = set(
        port,
        WireLimits {
            max_rgb_lib_ms: 68_000,
            ..Default::default()
        },
        false,
    );
    match refused {
        ERes::Error(e) => assert!(e.message.contains("three quarters"), "{}", e.message),
        other => panic!("unexpected response: {other:?}"),
    }
    assert_eq!(current(&get(port)), current(&start));

    // With a later deadline it passes, and the next request sees it.
    let changed = set(
        port,
        WireLimits {
            max_rgb_lib_ms: 68_000,
            total_request_timeout_secs: 100,
            mint_replay_ttl_secs: 7_200,
            ..Default::default()
        },
        false,
    );
    assert!(matches!(changed, ERes::Limits(_)), "{changed:?}");
    let seen = current(&get(port));
    assert_eq!(seen.max_rgb_lib_ms, 68_000);
    assert_eq!(seen.total_request_timeout_secs, 100);
    assert_eq!(seen.mint_replay_ttl_secs, 7_200);

    // The frame limit reaches the frame reader: a frame over it is refused, so
    // the connection ends without a response.
    let small = set(
        port,
        WireLimits {
            max_message_bytes: 1024 * 1024,
            ..Default::default()
        },
        false,
    );
    assert!(matches!(small, ERes::Limits(_)), "{small:?}");
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    use std::io::{Read, Write};
    stream
        .write_all(&(2u32 * 1024 * 1024).to_le_bytes())
        .unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).unwrap();
    assert!(reply.is_empty(), "a frame over the limit gets no response");

    // A reset restores the image, and the enclave answers as before.
    let reset = set(port, WireLimits::default(), true);
    assert!(matches!(reset, ERes::Limits(_)), "{reset:?}");
    assert_eq!(current(&get(port)), image(&start));
}
