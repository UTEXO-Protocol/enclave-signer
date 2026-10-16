//! Integration tests for `GET /health`, on the full deploy poll path:
//! HTTP/1.1 -> axum router -> wire protocol -> enclave -> status code.
//!
//! Contract: `200` means ready. Every other result (not ready, enclave down,
//! enclave error, bad reply) is `503`. Any other `5xx` can turn a slow restart
//! into a failed deploy, so these tests cover each path.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use utexo_bridge_parent::enclave_proto::{
    enclave_request, enclave_response, EnclaveRequest, EnclaveResponse, ErrorResponse,
    HealthResponse,
};
use utexo_bridge_parent::framing;
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};
use utexo_bridge_parent::header_sync::{SyncState, SyncStatus};
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
        endpoints_set: ready,
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
    start_health_server_with(enclave_port, SyncStatus::default()).await
}

async fn start_health_server_with(enclave_port: u16, sync: SyncStatus) -> u16 {
    let service =
        ParentAdapterService::new(EnclaveTarget::Tcp(format!("127.0.0.1:{enclave_port}")));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (_, rx) = tokio::sync::watch::channel(sync);
        axum::serve(listener, health::router(service, rx))
            .await
            .unwrap();
    });
    port
}

/// Mock enclave plus a health server pointed at it.
async fn serve_with(reply: Option<enclave_response::Response>) -> u16 {
    start_health_server(start_mock_enclave(reply)).await
}

/// Minimal HTTP/1.1 GET: one request, one connection, no keep-alive.
/// Returns (status_code, body).
///
/// It blocks, so every test uses a multi-thread runtime. On a current-thread
/// runtime it starves the server task and hangs.
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
    // The body has diagnostics, so the poll log helps debug a stuck deploy.
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
    // Bind then drop, so the port is almost certainly free and refuses connections.
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
    // An enclave without `Health` drops the unknown request field and sends
    // no oneof variant (`None`).
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

    // The probe server has only one route.
    let (status, _) = get(port, "/metrics");
    assert_eq!(status, 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn header_sync_is_reported_and_code_follows_ready() {
    let stalled = SyncStatus {
        state: SyncState::Stalled,
        source_tip: Some(900_010),
        enclave_tip: Some(900_000),
        lag_blocks: Some(10),
        tip_age_secs: Some(30),
        last_ok_unix: Some(1_790_000_000),
        last_error: Some("source down".into()),
    };
    let expected = r#""header_sync":{"enclave_tip":900000,"lag_blocks":10,"last_error":"source down","last_ok_unix":1790000000,"source_tip":900010,"state":"stalled","tip_age_secs":30}"#;

    // A stalled sync does not change the code: it follows `ready`.
    for (ready, code) in [(true, 200), (false, 503)] {
        let enclave = start_mock_enclave(Some(enclave_response::Response::Health(ready_response(
            ready,
        ))));
        let port = start_health_server_with(enclave, stalled.clone()).await;
        let (status, body) = get(port, "/health");
        assert_eq!(status, code);
        assert!(body.contains(expected), "body: {body}");
    }

    // The object is also present when the enclave cannot answer.
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);
    let port = start_health_server_with(dead_port, stalled).await;
    let (status, body) = get(port, "/health");
    assert_eq!(status, 503);
    assert!(body.contains(expected), "body: {body}");
}
