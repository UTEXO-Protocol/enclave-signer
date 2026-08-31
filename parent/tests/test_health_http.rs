//! Integration tests for `GET /health` - the full path a deploy poll takes:
//! HTTP/1.1 -> axum router -> wire protocol -> enclave -> status code.
//!
//! The contract deploy relies on is narrow: `200` means ready, and every other
//! outcome - not ready, enclave down, enclave error, garbled reply - is `503`.
//! A `5xx` the poller had to special-case would turn a slow restart into a
//! failed deploy, so each of those paths is pinned here.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use utexo_bridge_parent::enclave_proto::{
    enclave_request, enclave_response, EnclaveRequest, EnclaveResponse, ErrorResponse,
    HealthResponse,
};
use utexo_bridge_parent::framing;
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};
use utexo_bridge_parent::health;

fn ready_response(ready: bool) -> HealthResponse {
    HealthResponse {
        ready,
        key_loaded: ready,
        spv_synced: ready,
        phase: if ready { "active" } else { "initial" }.into(),
        spv_tip_height: 900_000,
        spv_tip_time: 1_700_000_000,
        spv_tip_age_secs: if ready { 30 } else { 99_999 },
        spv_max_tip_age_secs: 7200,
    }
}

fn start_mock_enclave(reply: Option<enclave_response::Response>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let req: EnclaveRequest = match framing::read_message(&mut stream) {
                Ok(r) => r,
                Err(_) => continue,
            };
            assert!(matches!(
                req.request,
                Some(enclave_request::Request::Health(_))
            ));
            let resp = EnclaveResponse {
                response: reply.clone(),
            };
            let _ = framing::write_message(&mut stream, &resp);
        }
    });

    port
}

/// Serve the health router on a random port and return it.
async fn start_health_server(enclave_port: u16) -> u16 {
    let service = ParentAdapterService::new(
        EnclaveTarget::Tcp(format!("127.0.0.1:{enclave_port}")),
        HashSet::new(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, health::router(service))
            .await
            .unwrap();
    });
    port
}

/// Mock enclave plus a health server pointed at it.
async fn serve_with(reply: Option<enclave_response::Response>) -> u16 {
    start_health_server(start_mock_enclave(reply)).await
}

/// Minimal HTTP/1.1 GET. Hand-rolled rather than pulling in an HTTP client: one
/// request, one connection, no keep-alive. Returns (status_code, body).
///
/// It blocks, which is why every test here runs on a multi-thread runtime - on
/// the default current-thread flavor it would starve the spawned server task
/// and hang instead of failing.
fn get(port: u16, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();

    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status line in response: {raw}"));
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ready_enclave_returns_200() {
    let port = serve_with(Some(enclave_response::Response::Health(ready_response(
        true,
    ))))
    .await;

    let (status, body) = get(port, "/health");
    assert_eq!(status, 200);
    assert!(body.contains("\"ready\":true"), "body: {body}");
    // Diagnostics ride along so a stuck deploy is debuggable from the poll log.
    assert!(body.contains("\"spv_tip_height\":900000"), "body: {body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn starting_enclave_returns_503() {
    let port = serve_with(Some(enclave_response::Response::Health(ready_response(
        false,
    ))))
    .await;

    let (status, body) = get(port, "/health");
    assert_eq!(status, 503);
    assert!(body.contains("\"ready\":false"), "body: {body}");
    assert!(body.contains("\"phase\":\"initial\""), "body: {body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreachable_enclave_returns_503() {
    // Bind then drop, so the port is almost certainly free and refuses.
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);

    let port = start_health_server(dead_port).await;

    let (status, body) = get(port, "/health");
    assert_eq!(status, 503, "a down enclave must not surface as 5xx");
    assert!(body.contains("\"ready\":false"), "body: {body}");
    assert!(body.contains("error"), "body: {body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enclave_error_returns_503() {
    let port = serve_with(Some(enclave_response::Response::Error(ErrorResponse {
        code: 3,
        message: "key not initialized".into(),
    })))
    .await;

    let (status, body) = get(port, "/health");
    assert_eq!(status, 503);
    assert!(body.contains("key not initialized"), "body: {body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enclave_without_health_support_returns_503() {
    // `None` is what an enclave built before `Health` existed sends back:
    // prost drops the unknown request field, so no oneof variant is set.
    let port = serve_with(None).await;

    let (status, body) = get(port, "/health");
    assert_eq!(status, 503, "an older enclave must read as not-ready");
    assert!(body.contains("\"ready\":false"), "body: {body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_path_is_404() {
    let port = serve_with(Some(enclave_response::Response::Health(ready_response(
        true,
    ))))
    .await;

    // The probe server serves exactly one route; nothing else is on it.
    let (status, _) = get(port, "/metrics");
    assert_eq!(status, 404);
}
