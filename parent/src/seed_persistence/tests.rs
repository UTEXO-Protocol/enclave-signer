use super::*;
use aws_sdk_s3::config::{Credentials, RequestChecksumCalculation};
use std::sync::atomic::{AtomicUsize, Ordering};

fn parent() -> Config {
    Config {
        grpc_host: "127.0.0.1".into(),
        grpc_port: 5000,
        health_host: "127.0.0.1".into(),
        health_port: 5001,
        enclave_addr: "127.0.0.1:5001".into(),
        enclave_vsock_cid: 16,
        enclave_vsock_port: 5000,
        use_vsock: true,
        evm_network_ids: Default::default(),
    }
}

fn environment() -> HashMap<String, String> {
    [
        ("KMS_SEED_ID", "seed-1"),
        ("KMS_S3_BUCKET", "seed-bucket"),
        ("KMS_S3_KEY", "signers/seed"),
        ("AWS_REGION", "eu-west-1"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect()
}

fn settings() -> Settings {
    Settings::read(&parent(), |key| environment().get(key).cloned())
        .unwrap()
        .unwrap()
}

#[test]
fn no_seed_configuration_does_not_enable_aws() {
    assert!(Settings::read(&parent(), |_| None).unwrap().is_none());
    assert!(Settings::read(&parent(), |key| (key == "AWS_REGION")
        .then(|| "eu-west-1".into()))
    .unwrap()
    .is_none());
}

#[test]
fn partial_or_invalid_configuration_is_rejected() {
    for name in ["KMS_SEED_ID", "KMS_S3_BUCKET", "KMS_S3_KEY", "AWS_REGION"] {
        let mut env = environment();
        env.remove(name);
        assert!(
            Settings::read(&parent(), |key| env.get(key).cloned()).is_err(),
            "{name}"
        );
    }
    for (key, value) in [
        ("KMS_SEED_ID", " "),
        ("KMS_SEED_ID", " trailing "),
        ("KMS_ALLOWED_CIDS", ""),
        ("KMS_ALLOWED_CIDS", "3"),
        ("KMS_ALLOWED_CIDS", "4294967295"),
        ("KMS_ALLOWED_CIDS", "16,"),
        ("KMS_ALLOWED_CIDS", "16,16"),
        ("KMS_ALLOWED_CIDS", "+16"),
        ("KMS_ALLOWED_CIDS", "-16"),
        ("KMS_BROKER_PORT", "8005"),
        ("KMS_BROKER_TCP", "0.0.0.0:3446"),
        ("KMS_BROKER_TCP", "[::1]:3446"),
        ("KMS_BROKER_TCP", "127.0.0.1:0"),
    ] {
        let mut env = environment();
        env.insert(key.into(), value.into());
        assert!(
            Settings::read(&parent(), |key| env.get(key).cloned()).is_err(),
            "{key}: {value}"
        );
    }
    let mut env = environment();
    env.insert(
        "KMS_ALLOWED_CIDS".into(),
        (4..69).map(|v| v.to_string()).collect::<Vec<_>>().join(","),
    );
    assert!(Settings::read(&parent(), |key| env.get(key).cloned()).is_err());
    env = environment();
    env.insert("KMS_SEED_ID".into(), "x".repeat(257));
    assert!(Settings::read(&parent(), |key| env.get(key).cloned()).is_err());
}

#[test]
fn default_cid_allowlist_and_explicit_dev_transport() {
    assert_eq!(settings().cids, [16]);
    let mut env = environment();
    env.insert("KMS_ALLOWED_CIDS".into(), "16, 17".into());
    assert_eq!(
        Settings::read(&parent(), |key| env.get(key).cloned())
            .unwrap()
            .unwrap()
            .cids,
        [16, 17]
    );
    env.insert("KMS_BROKER_TCP".into(), "127.0.0.1:3446".into());
    let mut development = parent();
    development.use_vsock = false;
    assert!(Settings::read(&development, |key| env.get(key).cloned())
        .unwrap()
        .unwrap()
        .tcp
        .is_some());
    let mut production = parent();
    production.use_vsock = true;
    assert!(Settings::read(&production, |key| env.get(key).cloned()).is_err());
}

#[test]
fn json_rejects_duplicates_unknown_fields_and_wrong_shapes() {
    for text in [
        r#"{"op":"credentials","op":"credentials"}"#,
        r#"{"op":"load","seed_id":"a","seed_id":"b"}"#,
        r#"{"op":"credentials","seed_id":null}"#,
        r#"{"op":"credentials","extra":0}"#,
        r#"{"op":"load","seed_id":"a","extra":0}"#,
        r#"{"op":"create","seed_id":"a","ciphertext":"AQ==","ciphertext":"Ag=="}"#,
        r#"{"op":"delete","seed_id":"a"}"#,
        r#"{"op":"load"}"#,
        r#"{"op":"load","seed_id":1}"#,
        r#"[]"#,
        r#"null"#,
        r#"{"op":"credentials"} {}"#,
    ] {
        assert!(serde_json::from_str::<Request>(text).is_err(), "{text}");
    }
    for text in [
        r#"{"op":"credentials"}"#,
        r#"{"op":"load","seed_id":"a"}"#,
        r#"{"op":"create","seed_id":"a","ciphertext":"AQ=="}"#,
    ] {
        assert!(serde_json::from_str::<Request>(text).is_ok());
    }
}

#[test]
fn ciphertext_is_nonempty_bounded_and_canonical() {
    for size in [1, 2, 3, MAX_CIPHERTEXT] {
        let blob = vec![137; size];
        assert_eq!(decode_ciphertext(&STANDARD.encode(&blob)).unwrap(), blob);
    }
    for text in ["", "AQ", "AR==", "AQ===", "AQ==\n", "_-==", "é==="] {
        assert_eq!(decode_ciphertext(text), Err(Error::InvalidCiphertext));
    }
    assert_eq!(
        decode_ciphertext(&STANDARD.encode(vec![1; MAX_CIPHERTEXT + 1])),
        Err(Error::InvalidCiphertext)
    );
}

#[test]
fn response_encoding_is_bounded_even_with_json_escaping() {
    assert_eq!(
        json(&"\0".repeat(MAX_FRAME)).unwrap_err(),
        Error::ResponseTooLarge
    );
    let payload = json(&"small").unwrap();
    assert_eq!(&*payload, b"\"small\"");
    assert_eq!(payload.capacity(), MAX_FRAME);
}

#[derive(Debug)]
struct MissingCredentials;
impl ProvideCredentials for MissingCredentials {
    fn provide_credentials<'a>(
        &'a self,
    ) -> aws_credential_types::provider::future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        aws_credential_types::provider::future::ProvideCredentials::new(async {
            Err(
                aws_credential_types::provider::error::CredentialsError::not_loaded(
                    "DO_NOT_EXPOSE_PROVIDER_DETAIL",
                ),
            )
        })
    }
}

#[tokio::test]
async fn missing_credentials_remain_configuration_errors_for_both_wire_operations() {
    let mut broker = broker("http://127.0.0.1:1");
    broker.credentials = SharedCredentialsProvider::new(MissingCredentials);
    broker.s3 = Client::from_conf(
        broker
            .s3
            .config()
            .to_builder()
            .credentials_provider(broker.credentials.clone())
            .build(),
    );
    assert!(matches!(
        broker.dispatch(Request::Credentials {}).await,
        Err(Error::Configuration)
    ));
    assert_eq!(broker.load().await, Err(Error::Configuration));
}

#[tokio::test]
async fn frame_is_big_endian_bounded_and_exact() {
    let payload = br#"{"op":"credentials"}"#;
    let mut framed = (payload.len() as u32).to_be_bytes().to_vec();
    framed.extend(payload);
    assert!(matches!(
        read_request(&mut framed.as_slice(), Instant::now() + REQUEST_TIMEOUT).await,
        Ok(Request::Credentials {})
    ));
    for frame in [
        vec![0, 0],
        vec![0, 0, 0, 0],
        (MAX_FRAME as u32 + 1).to_be_bytes().to_vec(),
        vec![0, 0, 0, 5, b'{'],
    ] {
        assert!(matches!(
            read_request(&mut frame.as_slice(), Instant::now() + REQUEST_TIMEOUT).await,
            Err(Error::InvalidFrame)
        ));
    }
    let frame = [0, 0, 0, 1, 0xff];
    assert!(matches!(
        read_request(&mut frame.as_slice(), Instant::now() + REQUEST_TIMEOUT).await,
        Err(Error::InvalidRequest)
    ));
}

#[tokio::test]
async fn deadline_covers_partial_prefix_and_partial_body() {
    for initial in [vec![0], vec![0, 0, 0, 20, b'{']] {
        let (mut reader, mut writer) = tokio::io::duplex(64);
        writer.write_all(&initial).await.unwrap();
        let before = Instant::now();
        assert!(matches!(
            read_request(&mut reader, before + Duration::from_millis(25)).await,
            Err(Error::RequestTimeout)
        ));
        assert!(before.elapsed() < Duration::from_secs(1));
    }
}

#[test]
fn admission_preserves_other_peers_and_releases_failed_acquisition() {
    let global = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let peer = Peer::new();
    let held: Vec<_> = (0..CONNECTIONS_PER_CID)
        .map(|_| acquire(&global, &peer.connections).unwrap())
        .collect();
    assert!(matches!(
        acquire(&global, &peer.connections),
        Err(Error::Busy)
    ));
    assert_eq!(
        global.available_permits(),
        MAX_CONNECTIONS - CONNECTIONS_PER_CID
    );
    assert!(acquire(&global, &Peer::new().connections).is_ok());
    drop(held);
    assert_eq!(global.available_permits(), MAX_CONNECTIONS);
    let held: Vec<_> = (0..MAX_CONNECTIONS)
        .map(|_| acquire(&global, &Peer::new().connections).unwrap())
        .collect();
    assert!(matches!(
        acquire(&global, &Peer::new().connections),
        Err(Error::Busy)
    ));
    drop(held);
    assert_eq!(global.available_permits(), MAX_CONNECTIONS);
}

#[test]
fn rate_limit_has_bounded_burst_refill_and_peer_isolation() {
    let peer = Peer::new();
    let now = Instant::now();
    for _ in 0..8 {
        peer.take_token(now).unwrap();
    }
    assert_eq!(peer.take_token(now), Err(Error::Busy));
    Peer::new().take_token(now).unwrap();
    peer.take_token(now + Duration::from_millis(250)).unwrap();
    assert_eq!(
        peer.take_token(now + Duration::from_millis(250)),
        Err(Error::Busy)
    );
    for _ in 0..8 {
        peer.take_token(now + Duration::from_secs(100)).unwrap();
    }
    assert_eq!(
        peer.take_token(now + Duration::from_secs(100)),
        Err(Error::Busy)
    );
}

fn broker(endpoint: &str) -> Broker {
    let credentials = SharedCredentialsProvider::new(Credentials::new(
        "test-access",
        "test-secret",
        None,
        None,
        "test",
    ));
    let client = Client::from_conf(
        aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("eu-west-1"))
            .credentials_provider(credentials.clone())
            .endpoint_url(endpoint)
            .force_path_style(true)
            .retry_config(RetryConfig::standard().with_max_attempts(1))
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .build(),
    );
    Broker::new(settings(), client, credentials)
}

struct Reply {
    status: u16,
    body: Vec<u8>,
    delay: Duration,
}
impl Reply {
    fn blob(body: &[u8]) -> Self {
        Self {
            status: 200,
            body: body.to_vec(),
            delay: Duration::ZERO,
        }
    }
    fn error(status: u16, code: &str) -> Self {
        Self {status,body:format!("<Error><Code>{code}</Code><Message>DO_NOT_EXPOSE_PROVIDER_DETAIL</Message></Error>").into_bytes(),delay:Duration::ZERO}
    }
}

// A real local HTTP endpoint exercises official SDK signing, S3 response
// parsing, conditional headers and streaming. It never contacts AWS.
async fn endpoint(replies: Vec<Reply>) -> (String, Arc<Mutex<Vec<String>>>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    let handle = tokio::spawn(async move {
        for reply in replies {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                headers.push(stream.read_u8().await.unwrap());
                assert!(headers.len() < 16384);
            }
            let headers = String::from_utf8(headers).unwrap();
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|v| v.trim().parse().ok())
                })
                .unwrap_or(0);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await.unwrap();
            recorded.lock().unwrap().push(headers);
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 {} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        reply.status,
                        reply.body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            tokio::time::sleep(reply.delay).await;
            let _ = stream.write_all(&reply.body).await;
        }
    });
    (address, requests, handle)
}

#[tokio::test]
async fn credentials_wire_shape_and_empty_optional_session_token() {
    let broker = broker("http://127.0.0.1:1");
    let bytes = broker.dispatch(Request::Credentials {}).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        value,
        serde_json::json!({"access_key_id":"test-access","secret_access_key":"test-secret","session_token":""})
    );
}

#[tokio::test]
async fn invalid_requests_do_not_consume_aws_capacity_or_tokens() {
    let broker = broker("http://127.0.0.1:1");
    let peer = Peer::new();
    assert!(matches!(
        broker
            .response(
                Request::Load {
                    seed_id: "other".into()
                },
                &peer,
                Instant::now() + REQUEST_TIMEOUT
            )
            .await,
        Err(Error::SeedIdNotAllowed)
    ));
    assert!(matches!(
        broker
            .response(
                Request::Create {
                    seed_id: "seed-1".into(),
                    ciphertext: "invalid".into()
                },
                &peer,
                Instant::now() + REQUEST_TIMEOUT
            )
            .await,
        Err(Error::InvalidCiphertext)
    ));
    assert_eq!(peer.tokens.lock().unwrap().0, 8.0);
    assert_eq!(broker.operations.available_permits(), 16);
}

#[tokio::test]
async fn explicit_missing_object_is_distinct_from_denial_and_missing_bucket() {
    for (status, code, expected) in [
        (404, "NoSuchKey", Ok(None)),
        (404, "NotFound", Ok(None)),
        (404, "NoSuchBucket", Err(Error::Configuration)),
        (404, "AccessDenied", Err(Error::AccessDenied)),
        (403, "NoSuchKey", Err(Error::AwsUnavailable)),
        (403, "AccessDenied", Err(Error::AccessDenied)),
        (500, "InternalError", Err(Error::AwsUnavailable)),
    ] {
        let (url, requests, server) = endpoint(vec![Reply::error(status, code)]).await;
        assert_eq!(broker(&url).load().await, expected, "{status}/{code}");
        timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn successful_load_uses_only_configured_object_and_caps_ciphertext() {
    for (blob, expected) in [
        (vec![8; MAX_CIPHERTEXT], Ok(Some(vec![8; MAX_CIPHERTEXT]))),
        (vec![], Err(Error::InvalidCiphertext)),
        (vec![8; MAX_CIPHERTEXT + 1], Err(Error::InvalidCiphertext)),
    ] {
        let (url, requests, server) = endpoint(vec![Reply::blob(&blob)]).await;
        assert_eq!(broker(&url).load().await, expected);
        timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert!(requests.lock().unwrap()[0]
            .starts_with("GET /seed-bucket/signers/seed?x-id=GetObject "));
    }
}

#[tokio::test]
async fn create_always_loads_committed_winner_and_never_overwrites() {
    for first in [
        Reply::blob(&[]),
        Reply::error(409, "ConditionalRequestConflict"),
        Reply::error(412, "PreconditionFailed"),
    ] {
        let (url, requests, server) = endpoint(vec![first, Reply::blob(b"winner")]).await;
        assert_eq!(
            broker(&url).create(b"proposal".to_vec()).await.unwrap(),
            b"winner"
        );
        timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("PUT /seed-bucket/signers/seed?x-id=PutObject "));
        assert!(requests[0]
            .to_ascii_lowercase()
            .contains("\r\nif-none-match: *\r\n"));
        assert!(requests[1].starts_with("GET /seed-bucket/signers/seed?x-id=GetObject "));
    }
}

#[tokio::test]
async fn failed_create_has_no_retry_and_missing_winner_is_never_success() {
    let (url, requests, server) = endpoint(vec![Reply::error(500, "InternalError")]).await;
    assert_eq!(
        broker(&url).create(vec![1]).await,
        Err(Error::AwsUnavailable)
    );
    timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(requests.lock().unwrap().len(), 1);
    let (url, requests, server) =
        endpoint(vec![Reply::blob(&[]), Reply::error(404, "NoSuchKey")]).await;
    assert_eq!(
        broker(&url).create(vec![1]).await,
        Err(Error::AwsUnavailable)
    );
    timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn response_deadline_includes_sdk_body_and_releases_cancelled_operation() {
    let mut reply = Reply::blob(b"ciphertext");
    reply.delay = Duration::from_secs(5);
    let (url, requests, server) = endpoint(vec![reply]).await;
    let broker = broker(&url);
    let peer = Peer::new();
    let now = Instant::now();
    assert!(matches!(
        broker
            .response(
                Request::Load {
                    seed_id: "seed-1".into()
                },
                &peer,
                now + Duration::from_millis(100)
            )
            .await,
        Err(Error::OperationTimeout)
    ));
    assert!(now.elapsed() < Duration::from_secs(1));
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert_eq!(broker.operations.available_permits(), 16);
    assert_eq!(peer.operations.available_permits(), 2);
    server.abort();
}

#[derive(Debug)]
struct PendingCredentials {
    active: Arc<AtomicUsize>,
}
impl ProvideCredentials for PendingCredentials {
    fn provide_credentials<'a>(
        &'a self,
    ) -> aws_credential_types::provider::future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        aws_credential_types::provider::future::ProvideCredentials::new(async {
            struct Active(Arc<AtomicUsize>);
            impl Drop for Active {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            self.active.fetch_add(1, Ordering::SeqCst);
            let _active = Active(self.active.clone());
            std::future::pending().await
        })
    }
}

#[tokio::test]
async fn stalled_credentials_are_bounded_per_peer_and_cancelled_before_permit_release() {
    let mut broker = broker("http://127.0.0.1:1");
    let active = Arc::new(AtomicUsize::new(0));
    broker.credentials = SharedCredentialsProvider::new(PendingCredentials {
        active: active.clone(),
    });
    let broker = Arc::new(broker);
    let peer = Arc::new(Peer::new());
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut workers = Vec::new();
    for _ in 0..2 {
        let broker = broker.clone();
        let peer = peer.clone();
        workers.push(tokio::spawn(async move {
            broker
                .response(Request::Credentials {}, &peer, deadline)
                .await
        }));
    }
    timeout(Duration::from_secs(1), async {
        while active.load(Ordering::SeqCst) != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("credential requests started");
    assert!(matches!(
        broker
            .response(Request::Credentials {}, &peer, deadline)
            .await,
        Err(Error::Busy)
    ));
    let other = Peer::new();
    assert!(matches!(
        broker
            .response(
                Request::Credentials {},
                &other,
                Instant::now() + Duration::from_millis(10)
            )
            .await,
        Err(Error::OperationTimeout)
    ));
    assert_eq!(active.load(Ordering::SeqCst), 2);
    for worker in workers {
        assert!(matches!(
            worker.await.unwrap(),
            Err(Error::OperationTimeout)
        ));
    }
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(broker.operations.available_permits(), 16);
}

#[tokio::test]
async fn live_tcp_protocol_and_admission_use_the_same_broker() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut broker = broker("http://127.0.0.1:1");
    broker.peers = HashMap::from([(0, Arc::new(Peer::new()))]);
    let server = tokio::spawn(serve(Listener::Tcp(listener), Arc::new(broker)));
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = br#"{"op":"credentials"}"#;
    stream.write_u32(request.len() as u32).await.unwrap();
    stream.write_all(request).await.unwrap();
    let length = stream.read_u32().await.unwrap();
    let mut response = vec![0; length as usize];
    stream.read_exact(&mut response).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(value["access_key_id"], "test-access");
    assert_eq!(
        stream.read_u8().await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    server.abort();
}
