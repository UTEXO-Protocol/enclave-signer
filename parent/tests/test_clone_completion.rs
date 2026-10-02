//! F03-IT-03: real enclave state/crypto/handlers, with response faults AFTER
//! SetClone commits Active. NSM is mocked; clone processing is not.
#![cfg(not(feature = "vsock"))]

#[path = "../src/bin/cli/clone_completion.rs"]
mod clone_completion;

use std::io::{self, Cursor, Read, Write};
use std::net::TcpListener;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use clone_completion::{complete, Outcome};
use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
use utexo_bridge_enclave::{
    config::BridgeConfig,
    server::{handle_connection, ServerContext},
    state::EnclaveState,
};
use utexo_bridge_parent::{
    client::EnclaveClient, enclave_proto::*, framing, grpc_proto::AttestedPublicKeyResponse,
};

#[path = "support/pki.rs"]
mod pki;

const SECRET: &str = "0123456789abcdef0123456789abcdef";

#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    Write,
    Drop,
    Decode,
    Stall,
    KeysStall,
    KeysError,
    KeysMismatch,
    DropKeysStall,
    BothStall,
    Reject,
    Pending,
}

struct HandlerStream {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    fail_write: bool,
}
impl Read for HandlerStream {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.input.read(b)
    }
}
impl Write for HandlerStream {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.fail_write {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected response write loss",
            ));
        }
        self.output.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Enclave {
    addr: String,
    client: EnclaveClient,
    ctx: Arc<ServerContext>,
    sets: Arc<AtomicUsize>,
    reads: Arc<AtomicUsize>,
}

fn start(donor: bool, fault: Fault) -> Enclave {
    let state = EnclaveState::new(bitcoin::Network::Bitcoin);
    if donor {
        state.initialize_from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        state.set_donor_cloning_secret(SECRET.into()).unwrap();
    }
    let ctx = Arc::new(ServerContext::new(
        state,
        BridgeConfig::from_env(),
        std::sync::Mutex::new(HeaderChain::new(
            Network::Regtest,
            checkpoint_for(Network::Regtest),
        )),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let client = EnclaveClient::new(&addr);
    let sets = Arc::new(AtomicUsize::new(0));
    let reads = Arc::new(AtomicUsize::new(0));
    let (context, set_count, read_count) = (ctx.clone(), sets.clone(), reads.clone());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let (ctx, sets, reads) = (context.clone(), set_count.clone(), read_count.clone());
            std::thread::spawn(move || {
                let mut stream = stream.unwrap();
                let mut request: EnclaveRequest = framing::read_message(&mut stream).unwrap();
                let is_set = matches!(request.request, Some(enclave_request::Request::SetClone(_)));
                let is_keys = matches!(
                    request.request,
                    Some(enclave_request::Request::GetPublicKey(_))
                );
                if is_set {
                    sets.fetch_add(1, Ordering::SeqCst);
                    if matches!(fault, Fault::Pending) {
                        // Never dispatch; emulate a request stalled before commit.
                        std::thread::sleep(Duration::from_secs(3));
                        return;
                    }
                    if matches!(fault, Fault::Reject) {
                        if let Some(enclave_request::Request::SetClone(r)) = &mut request.request {
                            r.encrypted_seed.clear();
                        }
                    }
                }
                if is_keys {
                    reads.fetch_add(1, Ordering::SeqCst);
                }
                let mut input = Vec::new();
                framing::write_message(&mut input, &request).unwrap();
                let mut io = HandlerStream {
                    input: Cursor::new(input),
                    output: vec![],
                    fail_write: is_set && matches!(fault, Fault::Write),
                };
                handle_connection(&mut io, &ctx);
                if is_set && !matches!(fault, Fault::Reject) {
                    // This assertion happens before ALL response-loss injection.
                    assert!(
                        ctx.state.get_keys().is_ok(),
                        "SetClone must really commit Active"
                    );
                }
                if is_set {
                    match fault {
                        Fault::Write | Fault::Drop | Fault::DropKeysStall => return,
                        Fault::Decode => {
                            stream.write_all(&[1, 0, 0, 0, 0xff]).unwrap();
                            return;
                        }
                        Fault::Stall | Fault::BothStall => {
                            std::thread::sleep(Duration::from_secs(3));
                            return;
                        }
                        _ => {}
                    }
                }
                if is_keys {
                    match fault {
                        Fault::KeysMismatch => {
                            let mut response: EnclaveResponse =
                                framing::read_message(&mut Cursor::new(io.output)).unwrap();
                            let Some(enclave_response::Response::PublicKeys(keys)) =
                                &mut response.response
                            else {
                                panic!("expected keys");
                            };
                            keys.evm_address[0] ^= 1;
                            framing::write_message(&mut stream, &response).unwrap();
                            return;
                        }
                        Fault::KeysStall | Fault::DropKeysStall | Fault::BothStall => {
                            std::thread::sleep(Duration::from_secs(3));
                            return;
                        }
                        Fault::KeysError => {
                            let error = EnclaveResponse {
                                response: Some(enclave_response::Response::Error(ErrorResponse {
                                    code: 1,
                                    message: "internal error: injected".into(),
                                })),
                            };
                            framing::write_message(&mut stream, &error).unwrap();
                            return;
                        }
                        _ => {}
                    }
                }
                let _ = stream.write_all(&io.output);
            });
        }
    });
    Enclave {
        addr,
        client,
        ctx,
        sets,
        reads,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_exit_codes_and_versioned_markers_follow_real_completion() {
    run_cli_completion(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_cli_exit_codes_and_versioned_markers_follow_real_completion() {
    run_cli_completion(true).await;
}

async fn run_cli_completion(secure: bool) {
    use std::process::{Command, Stdio};
    use utexo_bridge_parent::grpc_proto::parent_service_server::ParentServiceServer;
    use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};

    let donor = start(true, Fault::None);
    let evm = hex::encode(donor.client.get_public_keys().unwrap().evm_address);
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let grpc_addr = socket.local_addr().unwrap();
    drop(socket);
    let service =
        ParentAdapterService::new(EnclaveTarget::Tcp(donor.addr.clone()), Default::default());
    let pki = pki::Pki::new();
    let mut builder = tonic::transport::Server::builder();
    // Exercise production mTLS/auth with the actual CLI and actual enclave clone handlers.
    let access = if secure {
        builder = builder
            .tls_config(
                tonic::transport::ServerTlsConfig::new()
                    .identity(pki.identity("server"))
                    .client_ca_root(tonic::transport::Certificate::from_pem(pki.read("ca.pem"))),
            )
            .unwrap();
        Some(
            utexo_bridge_parent::transport_security::AccessLayer::from_acl(
                &pki.acl("operator"),
                30,
                Duration::from_secs(60),
            )
            .unwrap(),
        )
    } else {
        None
    };
    let server = tokio::spawn(async move {
        builder
            .layer(tower::util::option_layer(access))
            .add_service(ParentServiceServer::new(service))
            .serve(grpc_addr)
            .await
            .unwrap();
    });
    for attempt in 0..100 {
        if std::net::TcpStream::connect(grpc_addr).is_ok() {
            break;
        }
        assert!(attempt < 99, "gRPC server did not start");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    for (fault, marker, exit) in [
        (Fault::None, "success", 0),
        (Fault::Write, "recovered_success", 0),
        (Fault::Drop, "recovered_success", 0),
        (Fault::Decode, "recovered_success", 0),
        (Fault::Stall, "recovered_success", 0),
        (Fault::KeysMismatch, "identity_mismatch", 1),
        (Fault::Reject, "not_initialized", 1),
        (Fault::KeysStall, "unknown", 1),
        (Fault::DropKeysStall, "unknown", 1),
        (Fault::BothStall, "unknown", 1),
        (Fault::Pending, "unknown", 1),
    ] {
        let requester = start(false, fault);
        let mut command = Command::new(env!("CARGO_BIN_EXE_utexo-bridge-parent-cli"));
        for key in [
            "PARENT_TLS_CA_FILE",
            "PARENT_TLS_CERT_FILE",
            "PARENT_TLS_KEY_FILE",
            "PARENT_TLS_SERVER_NAME",
        ] {
            command.env_remove(key);
        }
        if secure {
            command
                .env("PARENT_TLS_CA_FILE", pki.0.join("ca.pem"))
                .env("PARENT_TLS_CERT_FILE", pki.0.join("operator.pem"))
                .env("PARENT_TLS_KEY_FILE", pki.0.join("operator.key"))
                .env("PARENT_TLS_SERVER_NAME", "parent.test");
        }
        let mut child = command
            .args([
                "--addr",
                &requester.addr,
                "clone",
                "--donor-grpc",
                &format!("{}://{grpc_addr}", if secure { "https" } else { "http" }),
                "--donor-evm",
                &evm,
            ])
            .env("UTEXO_CLONING_SECRET", SECRET)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let started = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if started.elapsed() > Duration::from_secs(5) {
                child.kill().unwrap();
                panic!("CLI hung with {fault:?}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "CLI completion exceeded two seconds: {fault:?}"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(exit),
            "{fault:?}: {stdout}\n{stderr}"
        );
        let markers: Vec<_> = stdout
            .lines()
            .filter(|l| l.starts_with("CLONE_RESULT_V1="))
            .collect();
        assert_eq!(
            markers,
            vec![format!("CLONE_RESULT_V1={marker}")],
            "{stderr}"
        );
        assert!(!stdout.contains(SECRET) && !stderr.contains(SECRET));
        assert_eq!(requester.sets.load(Ordering::SeqCst), 1);
        assert_eq!(requester.reads.load(Ordering::SeqCst), 1);
    }
    server.abort();
}

fn prepare(donor: &Enclave, requester: &Enclave) -> (SetCloneRequest, AttestedPublicKeyResponse) {
    let keys = donor.client.get_public_keys().unwrap();
    let init = requester
        .client
        .initiate_cloning(SECRET, keys.evm_address.clone())
        .unwrap();
    let response = donor
        .client
        .send_request(&EnclaveRequest {
            request: Some(enclave_request::Request::GetClone(GetCloneRequest {
                requester_attestation: init.requester_attestation,
                encryption_pubkey: init.encryption_pubkey,
                cluster_public_key: keys.evm_address.clone(),
                cloning_digest: init.cloning_digest,
            })),
        })
        .unwrap();
    let Some(enclave_response::Response::GetClone(clone)) = response.response else {
        panic!("donor rejected: {response:?}")
    };
    let bundle = AttestedPublicKeyResponse {
        evm_address: keys.evm_address,
        evm_uncompressed_pub: keys.evm_uncompressed_pub,
        btc_compressed_pub: keys.btc_compressed_pub,
        btc_xpub: keys.btc_xpub,
        master_fingerprint: keys.master_fingerprint,
        account_xpub_vanilla: keys.account_xpub_vanilla,
        account_xpub_colored: keys.account_xpub_colored,
        chain_id: keys.chain_id,
        bridge_contract: keys.bridge_contract,
        rgb_asset_id: keys.rgb_asset_id,
        evm_gas_tx_uncompressed_pub: keys.evm_gas_tx_uncompressed_pub,
        evm_gas_tx_address: keys.evm_gas_tx_address,
        ccd_ed25519_pub: keys.ccd_ed25519_pub,
        ..Default::default()
    };
    (
        SetCloneRequest {
            encrypted_seed: clone.encrypted_seed,
            donor_pubkey: clone.donor_pubkey,
            donor_attestation: clone.donor_attestation,
        },
        bundle,
    )
}

#[test]
fn real_commit_response_loss_recovers_without_retry_within_two_seconds() {
    for fault in [
        Fault::None,
        Fault::Write,
        Fault::Drop,
        Fault::Decode,
        Fault::Stall,
    ] {
        let donor = start(true, Fault::None);
        let requester = start(false, fault);
        let (request, bundle) = prepare(&donor, &requester);
        let started = Instant::now();
        let result = complete(&requester.client, request, &bundle.evm_address, &bundle);
        assert!(started.elapsed() < Duration::from_secs(2), "{fault:?}");
        assert_eq!(
            result.outcome,
            if matches!(fault, Fault::None) {
                Outcome::Success
            } else {
                Outcome::RecoveredSuccess
            },
            "{fault:?}: {}",
            result.detail
        );
        assert!(result.outcome.is_success());
        assert!(requester.ctx.state.get_keys().is_ok());
        assert_eq!(
            result.keys.unwrap(),
            donor.client.get_public_keys().unwrap()
        );
        assert_eq!(requester.sets.load(Ordering::SeqCst), 1);
        assert_eq!(requester.reads.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn no_keys_is_a_snapshot_and_transport_errors_are_unknown() {
    for (fault, outcome) in [
        (Fault::Reject, Outcome::NotInitialized),
        (Fault::KeysStall, Outcome::Unknown),
        (Fault::KeysError, Outcome::Unknown),
        (Fault::DropKeysStall, Outcome::Unknown),
        (Fault::BothStall, Outcome::Unknown),
        (Fault::Pending, Outcome::Unknown),
    ] {
        let donor = start(true, Fault::None);
        let requester = start(false, fault);
        let (request, bundle) = prepare(&donor, &requester);
        let started = Instant::now();
        let result = complete(&requester.client, request, &bundle.evm_address, &bundle);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(result.outcome, outcome, "{fault:?}: {}", result.detail);
        assert!(!result.outcome.is_success());
        assert_eq!(requester.sets.load(Ordering::SeqCst), 1);
        assert_eq!(requester.reads.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn recovered_success_requires_every_identity_and_config_field() {
    let donor = start(true, Fault::None);
    for index in 0..13 {
        let requester = start(false, Fault::Drop);
        let (request, mut bundle) = prepare(&donor, &requester);
        let expected_evm = bundle.evm_address.clone();
        match index {
            0 => bundle.evm_address[0] ^= 1,
            1 => bundle.evm_uncompressed_pub[0] ^= 1,
            2 => bundle.btc_compressed_pub[0] ^= 1,
            3 => bundle.btc_xpub.push('x'),
            4 => bundle.master_fingerprint[0] ^= 1,
            5 => bundle.account_xpub_vanilla.push('x'),
            6 => bundle.account_xpub_colored.push('x'),
            7 => bundle.chain_id ^= 1,
            8 => bundle.bridge_contract.push(1),
            9 => bundle.rgb_asset_id.push('x'),
            10 => bundle.evm_gas_tx_uncompressed_pub.push(1),
            11 => bundle.evm_gas_tx_address.push(1),
            12 => bundle.ccd_ed25519_pub.push(1),
            _ => unreachable!(),
        }
        let result = complete(&requester.client, request, &expected_evm, &bundle);
        assert_eq!(result.outcome, Outcome::IdentityMismatch, "field {index}");
        assert_eq!(result.outcome.as_str(), "identity_mismatch");
        assert_eq!(requester.sets.load(Ordering::SeqCst), 1);
    }
}
