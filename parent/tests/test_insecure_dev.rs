//! `insecure-dev` build: plaintext gRPC on any bind, no client auth.
#![cfg(feature = "insecure-dev")]
use std::time::Duration;
use tonic::transport::Endpoint;
use utexo_bridge_parent::{
    grpc_proto::parent_service_client::ParentServiceClient, signer::*,
    transport_security::client_endpoint,
};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn parent(settings: &[(&str, &str)]) -> std::process::Command {
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_utexo-bridge-parent"));
    c.env_clear().env("GRPC_HOST", "0.0.0.0");
    for (k, v) in settings {
        c.env(k, v);
    }
    c
}

#[test]
fn rejects_tls_settings() {
    let output = parent(&[("GRPC_TLS_CERT_FILE", "/missing")])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("takes no TLS settings"));
}

#[test]
fn client_allows_plaintext_to_any_host() {
    client_endpoint("http://10.0.0.1:50051").unwrap();
    client_endpoint("http://parent.dev:50051").unwrap();
}

#[tokio::test]
async fn serves_plaintext_on_wildcard_bind() {
    let port = free_port().to_string();
    let health = free_port().to_string();
    // No enclave listens here, so a call that passes the perimeter fails
    // with an enclave error, not an auth error.
    let enclave = format!("127.0.0.1:{}", free_port());
    let mut child = parent(&[
        ("GRPC_PORT", &port),
        ("HEALTH_PORT", &health),
        ("ENCLAVE_ADDR", &enclave),
    ])
    .stderr(std::process::Stdio::null())
    .spawn()
    .unwrap();

    let endpoint = Endpoint::from_shared(format!("http://127.0.0.1:{port}")).unwrap();
    let mut status = None;
    for _ in 0..100 {
        if let Ok(channel) = endpoint.connect().await {
            status = Some(
                ParentServiceClient::new(channel)
                    .public_key(PublicKeyRequest::default())
                    .await
                    .unwrap_err(),
            );
            break;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = child.kill();
    child.wait().unwrap();
    let status = status.expect("parent did not start");
    assert!(
        !matches!(
            status.code(),
            tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
        ),
        "{status}"
    );
}
