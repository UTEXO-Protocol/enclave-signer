//! Real TLS, the generated Parent router and a counting enclave transport.
//! These tests do not prove deployed VPC rules or a real NSM clone.
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tonic::{
    transport::{Certificate, Endpoint, Server, ServerTlsConfig},
    Code,
};
use utexo_bridge_parent::{
    enclave_proto::{enclave_response, EnclaveRequest, EnclaveResponse, ErrorResponse},
    framing,
    grpc_proto::{
        parent_service_client::ParentServiceClient, parent_service_server::ParentServiceServer, *,
    },
    grpc_server::{EnclaveTarget, ParentAdapterService},
    signer::*,
    transport_security::{AccessLayer, LimitedIncoming},
};

#[path = "support/pki.rs"]
mod pki;
use pki::Pki;

async fn counting_enclave() -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = backend.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let backend_task = tokio::spawn(async move {
        loop {
            let (stream, _) = backend.accept().await.unwrap();
            let count = count.clone();
            tokio::task::spawn_blocking(move || {
                let mut stream = stream.into_std().unwrap();
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let _: EnclaveRequest = framing::read_message(&mut stream).unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                // This marker shows that the Parent handler reached the enclave.
                let reply = EnclaveResponse {
                    response: Some(enclave_response::Response::Error(ErrorResponse {
                        code: 3,
                        message: "counting enclave".into(),
                    })),
                };
                framing::write_message(&mut stream, &reply).unwrap();
            });
        }
    });
    (target, calls, backend_task)
}

async fn server(
    pki: &Pki,
    operator: &str,
    limit: u32,
    attest_limit: u32,
    period: Duration,
    conn_limit: usize,
) -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let (target, calls, backend_task) = counting_enclave().await;
    let incoming = LimitedIncoming::bind("127.0.0.1:0".parse().unwrap(), conn_limit)
        .await
        .unwrap();
    let addr = incoming.local_addr().unwrap();
    let tls = ServerTlsConfig::new()
        .identity(pki.identity("server"))
        .client_ca_root(Certificate::from_pem(pki.read("ca.pem")))
        .client_auth_optional(false)
        .timeout(Duration::from_millis(300));
    let access = AccessLayer::from_acl(&pki.acl(operator), limit, attest_limit, period).unwrap();
    let task = tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .layer(access)
            .layer(tower::limit::GlobalConcurrencyLimitLayer::new(4))
            .load_shed(true)
            .concurrency_limit_per_connection(2)
            .max_concurrent_streams(Some(2))
            .timeout(Duration::from_secs(2))
            .add_service(ParentServiceServer::new(ParentAdapterService::new(
                EnclaveTarget::Tcp(target.to_string()),
            )))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    (addr, calls, task, backend_task)
}
fn reached<T: std::fmt::Debug>(r: Result<T, tonic::Status>) {
    let e = r.unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition, "{e}");
    assert_eq!(e.message(), "counting enclave");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mtls_roles_rate_budget_and_revocation() {
    let pki = Pki::new();
    let (addr, calls, task, backend) =
        server(&pki, "operator", 2, 100, Duration::from_millis(800), 32).await;
    for role in ["operator", "listener", "observer"] {
        let mut c = ParentServiceClient::new(
            pki.endpoint(addr, Some(role), "parent.test", "ca.pem")
                .connect()
                .await
                .unwrap(),
        );
        let before = calls.load(Ordering::SeqCst);
        reached(c.public_key(PublicKeyRequest::default()).await);
        reached(
            c.get_last_saved_block(GetLastSavedBlockRequest::default())
                .await,
        );
        reached(
            c.attested_public_key(AttestedPublicKeyRequest { nonce: vec![1; 32] })
                .await,
        );
        assert_eq!(calls.load(Ordering::SeqCst), before + 3);
        assert_eq!(
            c.initialize(InitializeRequest::default())
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
        if role != "operator" {
            assert_eq!(
                ParentServiceClient::clone(&mut c, CloneRequest::default())
                    .await
                    .unwrap_err()
                    .code(),
                Code::PermissionDenied
            );
        }
        if role != "listener" {
            assert_eq!(
                c.sign(utexo_bridge_parent::grpc_proto::SignRequest::default())
                    .await
                    .unwrap_err()
                    .code(),
                Code::PermissionDenied
            );
        } else {
            // A schema error shows the request passed auth, with no signature.
            assert_eq!(
                c.sign(utexo_bridge_parent::grpc_proto::SignRequest::default())
                    .await
                    .unwrap_err()
                    .code(),
                Code::InvalidArgument
            );
        }
        // No role can submit headers. The request does not reach the enclave.
        let before = calls.load(Ordering::SeqCst);
        assert_eq!(
            c.submit_headers(SubmitHeadersRequest::default())
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
        assert_eq!(calls.load(Ordering::SeqCst), before);
    }
    // Unknown method names must not inherit a role's read permission.
    let channel = pki
        .endpoint(addr, Some("operator"), "parent.test", "ca.pem")
        .connect()
        .await
        .unwrap();
    let mut raw = tonic::client::Grpc::new(channel);
    raw.ready().await.unwrap();
    use tonic::server::NamedService;
    let path = format!(
        "/{}/Unknown",
        <ParentServiceServer<ParentAdapterService> as NamedService>::NAME
    );
    let response: Result<tonic::Response<PublicKeyResponse>, _> = raw
        .unary(
            tonic::Request::new(PublicKeyRequest::default()),
            path.parse().unwrap(),
            tonic_prost::ProstCodec::default(),
        )
        .await;
    assert_eq!(response.unwrap_err().code(), Code::PermissionDenied);

    let mut unknown = ParentServiceClient::new(
        pki.endpoint(addr, Some("unknown"), "parent.test", "ca.pem")
            .connect()
            .await
            .unwrap(),
    );
    let before = calls.load(Ordering::SeqCst);
    for _ in 0..100 {
        assert_eq!(
            ParentServiceClient::clone(&mut unknown, CloneRequest::default())
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), before);
    let mut op = ParentServiceClient::new(
        pki.endpoint(addr, Some("operator"), "parent.test", "ca.pem")
            .connect()
            .await
            .unwrap(),
    );
    reached(ParentServiceClient::clone(&mut op, CloneRequest::default()).await);
    reached(ParentServiceClient::clone(&mut op, CloneRequest::default()).await);
    let mut second = ParentServiceClient::new(
        pki.endpoint(addr, Some("operator"), "parent.test", "ca.pem")
            .connect()
            .await
            .unwrap(),
    );
    assert_eq!(
        ParentServiceClient::clone(&mut second, CloneRequest::default())
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(calls.load(Ordering::SeqCst), before + 2);
    tokio::time::sleep(Duration::from_millis(850)).await;
    reached(ParentServiceClient::clone(&mut second, CloneRequest::default()).await);
    task.abort();
    backend.abort();
    // Restart with a new pin. The old certificate still chains to the CA but
    // loses access.
    let (addr, _, task, backend) =
        server(&pki, "rotated", 2, 100, Duration::from_secs(60), 4).await;
    let mut old = ParentServiceClient::new(
        pki.endpoint(addr, Some("operator"), "parent.test", "ca.pem")
            .connect()
            .await
            .unwrap(),
    );
    assert_eq!(
        old.public_key(PublicKeyRequest::default())
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    let mut new = ParentServiceClient::new(
        pki.endpoint(addr, Some("rotated"), "parent.test", "ca.pem")
            .connect()
            .await
            .unwrap(),
    );
    reached(new.public_key(PublicKeyRequest::default()).await);
    task.abort();
    backend.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_tls_never_reaches_enclave_and_socket_cap_recovers() {
    let pki = Pki::new();
    let (addr, calls, task, backend) =
        server(&pki, "operator", 2, 100, Duration::from_secs(60), 4).await;
    for (who, name, ca) in [
        (None, "parent.test", "ca.pem"),
        (Some("foreign"), "parent.test", "ca.pem"),
        (Some("expired"), "parent.test", "ca.pem"),
        (Some("operator"), "wrong.test", "ca.pem"),
        (Some("operator"), "parent.test", "foreign-ca.pem"),
    ] {
        if let Ok(channel) = pki.endpoint(addr, who, name, ca).connect().await {
            assert!(ParentServiceClient::new(channel)
                .public_key(PublicKeyRequest::default())
                .await
                .is_err());
        }
    }
    let plain = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(1));
    if let Ok(channel) = plain.connect().await {
        assert!(ParentServiceClient::new(channel)
            .public_key(PublicKeyRequest::default())
            .await
            .is_err());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    // Fill all socket permits with unfinished TLS handshakes.
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(tokio::net::TcpStream::connect(addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(40)).await;
    if let Ok(channel) = pki
        .endpoint(addr, Some("operator"), "parent.test", "ca.pem")
        .connect()
        .await
    {
        assert!(ParentServiceClient::new(channel)
            .public_key(PublicKeyRequest::default())
            .await
            .is_err());
    }
    tokio::time::sleep(Duration::from_millis(350)).await;
    let mut client = ParentServiceClient::new(
        pki.endpoint(addr, Some("operator"), "parent.test", "ca.pem")
            .connect()
            .await
            .unwrap(),
    );
    reached(client.public_key(PublicKeyRequest::default()).await);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(held);
    task.abort();
    backend.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attested_public_key_rate_budget() {
    let pki = Pki::new();
    let (addr, calls, task, backend) =
        server(&pki, "operator", 2, 2, Duration::from_secs(60), 32).await;
    let client = |role| {
        let endpoint = pki.endpoint(addr, Some(role), "parent.test", "ca.pem");
        async move { ParentServiceClient::new(endpoint.connect().await.unwrap()) }
    };
    let attest = || AttestedPublicKeyRequest { nonce: vec![1; 32] };
    let mut observer = client("observer").await;
    let mut listener = client("listener").await;
    let mut operator = client("operator").await;
    reached(observer.attested_public_key(attest()).await);
    reached(observer.attested_public_key(attest()).await);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    // The budget is shared by all clients. A refused call does not reach the enclave.
    assert_eq!(
        listener
            .attested_public_key(attest())
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    // Other reads and Clone use other budgets.
    reached(listener.public_key(PublicKeyRequest::default()).await);
    reached(ParentServiceClient::clone(&mut operator, CloneRequest::default()).await);
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    task.abort();
    backend.abort();
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn budgets_come_from_env() {
    let pki = Pki::new();
    std::fs::write(pki.0.join("clients.acl"), pki.acl("operator")).unwrap();
    let (enclave, _, backend) = counting_enclave().await;
    for (settings, clones, attests) in [
        (
            vec![
                ("GRPC_CLONE_MAX_PER_MINUTE", "3"),
                ("GRPC_ATTEST_MAX_PER_MINUTE", "2"),
            ],
            3,
            2,
        ),
        (vec![("GRPC_CLONE_MAX_PER_MINUTE", "1")], 1, 6),
    ] {
        let port = free_port();
        let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_utexo-bridge-parent"));
        c.env_clear()
            .env("GRPC_HOST", "127.0.0.1")
            .env("GRPC_PORT", port.to_string())
            .env("HEALTH_PORT", free_port().to_string())
            .env("ENCLAVE_ADDR", enclave.to_string())
            .env("GRPC_TLS_CERT_FILE", pki.0.join("server.pem"))
            .env("GRPC_TLS_KEY_FILE", pki.0.join("server.key"))
            .env("GRPC_TLS_CLIENT_CA_FILE", pki.0.join("ca.pem"))
            .env("GRPC_TLS_ACL_FILE", pki.0.join("clients.acl"))
            .envs(settings)
            .kill_on_drop(true)
            .stderr(std::process::Stdio::null());
        let mut parent = c.spawn().unwrap();
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let mut channel = None;
        for _ in 0..100 {
            if let Ok(ch) = pki
                .endpoint(addr, Some("operator"), "parent.test", "ca.pem")
                .connect()
                .await
            {
                channel = Some(ch);
                break;
            }
            assert!(parent.try_wait().unwrap().is_none(), "parent exited");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let mut c = ParentServiceClient::new(channel.expect("parent did not start"));
        for _ in 0..attests {
            reached(
                c.attested_public_key(AttestedPublicKeyRequest { nonce: vec![1; 32] })
                    .await,
            );
        }
        assert_eq!(
            c.attested_public_key(AttestedPublicKeyRequest { nonce: vec![1; 32] })
                .await
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
        for _ in 0..clones {
            reached(ParentServiceClient::clone(&mut c, CloneRequest::default()).await);
        }
        assert_eq!(
            ParentServiceClient::clone(&mut c, CloneRequest::default())
                .await
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
    }
    backend.abort();
}

#[test]
fn bad_acl_and_missing_server_config_fail_closed() {
    for acl in [
        "".to_string(),
        "00 observer".into(),
        format!("{} administrator", "00".repeat(32)),
        format!("{0} observer\n{0} listener", "00".repeat(32)),
    ] {
        assert!(AccessLayer::from_acl(&acl, 1, 1, Duration::from_secs(60)).is_err());
    }
    let acl = format!("{} observer", "00".repeat(32));
    assert!(AccessLayer::from_acl(&acl, 1, 1, Duration::from_secs(60)).is_ok());
    assert!(AccessLayer::from_acl(&acl, 0, 1, Duration::from_secs(60)).is_err());
    assert!(AccessLayer::from_acl(&acl, 1, 0, Duration::from_secs(60)).is_err());
    for key in ["GRPC_CLONE_MAX_PER_MINUTE", "GRPC_ATTEST_MAX_PER_MINUTE"] {
        for bad in ["0", "10001", "x", ""] {
            let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_utexo-bridge-parent"));
            c.env_clear().env("GRPC_HOST", "10.0.0.1").env(key, bad);
            for file in [
                "GRPC_TLS_CERT_FILE",
                "GRPC_TLS_KEY_FILE",
                "GRPC_TLS_CLIENT_CA_FILE",
                "GRPC_TLS_ACL_FILE",
            ] {
                c.env(file, "/missing");
            }
            let output = c.output().unwrap();
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(key),
                "{key}={bad}"
            );
        }
    }
    for settings in [
        vec![],
        vec![("GRPC_TLS_CERT_FILE", "/missing")],
        vec![("GRPC_ALLOW_INSECURE_LOOPBACK", "true")],
    ] {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_utexo-bridge-parent"));
        c.env_clear().env("GRPC_HOST", "10.0.0.1");
        for (k, v) in settings {
            c.env(k, v);
        }
        let output = c.output().unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("mTLS requires")
                || String::from_utf8_lossy(&output.stderr).contains("insecure mode requires")
        );
    }
}

#[tokio::test]
async fn cli_rejects_transport_configuration_before_enclave_io() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = listener.local_addr().unwrap().to_string();
    for (url, partial) in [
        ("http://10.0.0.1:50051", false),
        ("http://localhost:50051", false),
        ("https://parent.test:50051", false),
        ("http://127.0.0.1:50051", true),
        ("ftp://parent.test:50051", false),
    ] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_utexo-bridge-parent-cli"));
        command
            .env_clear()
            .env("UTEXO_CLONING_SECRET", "0123456789abcdef0123456789abcdef")
            .args([
                "--addr",
                &local,
                "clone",
                "--donor-grpc",
                url,
                "--donor-evm",
                "0x1111111111111111111111111111111111111111",
            ]);
        if partial {
            command.env("PARENT_TLS_CA_FILE", "/missing");
        }
        let output = command.output().unwrap();
        assert!(!output.status.success(), "accepted {url}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("CLONE_RESULT_V1=preflight_error"));
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err(),
        "bad transport settings initiated enclave work"
    );
}
