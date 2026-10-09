//! End-to-end test for the `attest-verify` flow.
//!
//! Starts the real enclave server and the real parent gRPC server in-process.
//! Then runs the `attest-verify` library function against them. It covers all
//! CLI behavior except argument parsing and output formatting.
//!
//! The bundle tests run the built binaries and `deploy/verify-identity.sh`.

use std::net::TcpListener;
use std::sync::Arc;

use tonic::transport::Server;

use attestation_verify::EvmDataSource;
use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
use utexo_bridge_enclave::policy::BuildContext;
use utexo_bridge_enclave::server::{self as enclave_server, ServerContext};
use utexo_bridge_enclave::state::EnclaveState;
use utexo_bridge_parent::attest_verify::{verify_attested_pubkey, ExpectedPolicy, VerifyMode};
use utexo_bridge_parent::client::EnclaveClient;
use utexo_bridge_parent::enclave_proto::SetEndpointsRequest;
use utexo_bridge_parent::error::ParentError;
use utexo_bridge_parent::grpc_proto::parent_service_server::ParentServiceServer;
use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Start a real enclave TCP server on a random port and return the port.
/// Keys come from the BIP-39 test mnemonic, so the EVM address is stable.
fn start_real_enclave() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let state = EnclaveState::new(bitcoin::Network::Bitcoin);
    state
        .initialize_from_mnemonic(TEST_MNEMONIC)
        .expect("seed import");

    let header_chain = std::sync::Mutex::new(HeaderChain::new(
        Network::Regtest,
        checkpoint_for(Network::Regtest),
    ));
    let ctx = Arc::new(ServerContext::new(
        state,
        BridgeConfig::from_env(),
        header_chain,
    ));

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => enclave_server::handle_connection(s, &ctx),
                Err(_) => continue,
            }
        }
    });

    port
}

async fn start_real_parent_grpc(enclave_port: u16) -> u16 {
    let grpc_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let grpc_addr = grpc_listener.local_addr().unwrap();
    let grpc_port = grpc_addr.port();
    drop(grpc_listener);

    let service =
        ParentAdapterService::new(EnclaveTarget::Tcp(format!("127.0.0.1:{enclave_port}")));

    tokio::spawn(async move {
        Server::builder()
            .add_service(ParentServiceServer::new(service))
            .serve(grpc_addr)
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    grpc_port
}

#[tokio::test]
async fn e2e_attest_verify_succeeds_against_live_stack() {
    let enclave_port = start_real_enclave();
    let grpc_port = start_real_parent_grpc(enclave_port).await;

    let result = verify_attested_pubkey(
        &format!("http://127.0.0.1:{grpc_port}"),
        attestation_verify::ExpectedPcrs::zero(),
        VerifyMode::Mock,
        // The in-process enclave is a mock build, so its posture is Development.
        ExpectedPolicy::Development,
    )
    .await
    .expect("end-to-end verification succeeds");

    // Check the structure only. The test does not hardcode key bytes.
    assert_eq!(result.response.evm_address.len(), 20);
    assert_eq!(result.response.evm_uncompressed_pub.len(), 64);
    assert_eq!(result.response.btc_compressed_pub.len(), 33);
    assert_eq!(result.response.master_fingerprint.len(), 4);
    assert!(result.response.btc_xpub.starts_with("xpub"));
    assert!(!result.response.account_xpub_vanilla.is_empty());
    assert!(!result.response.account_xpub_colored.is_empty());

    // The verified `public_key` (NSM-bound) MUST equal the wire EVM pubkey.
    assert_eq!(
        result.verified.enclave_pubkey,
        result.response.evm_uncompressed_pub
    );

    // verify_attested_pubkey checked this commitment against `user_data`.
    assert_ne!(result.bundle_commitment, [0u8; 32]);

    // The document returns the fresh 32-byte nonce.
    assert_eq!(result.verified.nonce.len(), 32);
}

#[tokio::test]
async fn e2e_attest_verify_fails_on_pcr_mismatch() {
    let enclave_port = start_real_enclave();
    let grpc_port = start_real_parent_grpc(enclave_port).await;

    // Mock enclaves report all-zero PCRs. Non-zero expected PCRs simulate
    // wrong or old operator PCRs.
    let wrong_pcrs = attestation_verify::ExpectedPcrs::new([0xAA; 48], [0u8; 48], [0u8; 48]);

    let err = verify_attested_pubkey(
        &format!("http://127.0.0.1:{grpc_port}"),
        wrong_pcrs,
        VerifyMode::Mock,
        ExpectedPolicy::Development,
    )
    .await
    .expect_err("PCR0 mismatch must fail verification");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("PCR0") || msg.contains("PCR mismatch"),
        "expected PCR mismatch error, got: {msg}"
    );
}

#[tokio::test]
async fn e2e_attest_verify_fails_on_real_path_against_mock_enclave() {
    // The mock enclave makes a raw-CBOR doc, not COSE_Sign1. The real path
    // must reject it, so --mock and the real path cannot replace each other.
    let enclave_port = start_real_enclave();
    let grpc_port = start_real_parent_grpc(enclave_port).await;

    let err = verify_attested_pubkey(
        &format!("http://127.0.0.1:{grpc_port}"),
        attestation_verify::ExpectedPcrs::zero(),
        VerifyMode::Real, // Real path against a mock doc.
        ExpectedPolicy::Development,
    )
    .await
    .expect_err("real verifier must reject a mock document");

    let msg = format!("{err:#}");
    // The mock doc is not a 4-element COSE array, so parsing fails first.
    assert!(
        msg.contains("COSE") || msg.contains("CBOR") || msg.contains("attestation verify failed"),
        "expected COSE/CBOR parse failure, got: {msg}"
    );
}

#[tokio::test]
async fn e2e_attest_verify_fails_on_unreachable_endpoint() {
    let err = verify_attested_pubkey(
        "http://127.0.0.1:1", // nothing listening here
        attestation_verify::ExpectedPcrs::zero(),
        VerifyMode::Mock,
        ExpectedPolicy::Development,
    )
    .await
    .expect_err("connection to dead port must fail");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("connecting")
            || msg.contains("connect")
            || msg.contains("Connection")
            || msg.contains("transport"),
        "expected connection error, got: {msg}"
    );
}

#[tokio::test]
async fn e2e_attest_verify_fails_on_policy_mismatch() {
    // The in-process mock enclave attests the `Development` posture. A
    // verifier that expects production must reject the committed policy.
    let enclave_port = start_real_enclave();
    let grpc_port = start_real_parent_grpc(enclave_port).await;

    let err = verify_attested_pubkey(
        &format!("http://127.0.0.1:{grpc_port}"),
        attestation_verify::ExpectedPcrs::zero(),
        VerifyMode::Mock,
        ExpectedPolicy::Production {
            allow_vanilla_psbt: false,
            signer_role: attestation_verify::SignerRole::Mint,
            evm_source: EvmDataSource::RawRpc,
            electrum_host: "electrum.test".into(),
            evm_rpc_tls: None,
            expected_chain_id: None,
            expected_bridge_contract: None,
            expected_rgb_asset_id: None,
            funds_in_contract: [0x11; 20],
            token_contract: [0x22; 20],
            gas_tx_allowed_to: [0u8; 20],
            gas_tx_max_gas_limit: 0,
            gas_tx_max_fee_per_gas: 0,
            gas_tx_max_value_wei: 0,
            gas_tx_allowed_selectors: Vec::new(),
            kms: None,
        },
    )
    .await
    .expect_err("expecting a production policy against a dev enclave must fail");

    let msg = format!("{err:#}");
    assert!(
        msg.contains("user_data") || msg.contains("security posture") || msg.contains("policy"),
        "expected a policy/user_data mismatch error, got: {msg}"
    );
}

/// The parent sets the endpoints once, after launch. Before that, the
/// enclave attests nothing and opens no chain connection.
#[tokio::test]
async fn e2e_endpoints_are_set_once_at_launch() {
    // Fake Electrum. Nothing must connect to it.
    let electrum = TcpListener::bind("127.0.0.1:0").unwrap();
    electrum.set_nonblocking(true).unwrap();
    let electrum_port = electrum.local_addr().unwrap().port();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let enclave_port = listener.local_addr().unwrap().port();
    let state = EnclaveState::new(bitcoin::Network::Bitcoin);
    state
        .initialize_from_mnemonic(TEST_MNEMONIC)
        .expect("seed import");
    let ctx = Arc::new(ServerContext::awaiting_launch(
        state,
        BridgeConfig::from_env(),
        std::sync::Mutex::new(HeaderChain::new(
            Network::Regtest,
            checkpoint_for(Network::Regtest),
        )),
        BuildContext::current(),
    ));
    let served = ctx.clone();
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            enclave_server::handle_connection(s, &served);
        }
    });
    let grpc = format!(
        "http://127.0.0.1:{}",
        start_real_parent_grpc(enclave_port).await
    );
    let verify = || {
        verify_attested_pubkey(
            &grpc,
            attestation_verify::ExpectedPcrs::zero(),
            VerifyMode::Mock,
            ExpectedPolicy::Development,
        )
    };
    let client = EnclaveClient::new(&format!("127.0.0.1:{enclave_port}"));
    let set = |host: &str| SetEndpointsRequest {
        electrum_url: format!("tcp://{host}:{electrum_port}"),
        ..Default::default()
    };

    assert!(verify().await.is_err(), "attested before the set");
    assert!(!client.health().unwrap().endpoints_set);

    client.set_endpoints(set("localhost")).unwrap();
    assert!(client.health().unwrap().endpoints_set);
    verify().await.expect("attests after the set");

    let err = client.set_endpoints(set("other.test")).unwrap_err();
    assert!(
        matches!(&err, ParentError::EnclaveError { message, .. } if message.contains("already set")),
        "{err:?}"
    );
    assert_eq!(ctx.launch().unwrap().endpoints.electrum_host, "localhost");
    assert!(electrum.accept().is_err(), "a chain connection opened");
}

/// A fresh directory under the cargo target directory.
fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "{name}-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(program: &str, args: &[&str]) -> std::process::Output {
    std::process::Command::new(program)
        .args(args)
        .output()
        .unwrap()
}

/// The `OK` output without the lines that change with the nonce.
fn key_lines(out: &std::process::Output) -> Vec<String> {
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("OK\n"), "{stdout}");
    stdout
        .lines()
        .filter(|l| !l.contains("Nonce echoed") && !l.contains("Attestation timestamp"))
        .map(String::from)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn exported_bundle_round_trips_through_the_binaries() {
    let cli = env!("CARGO_BIN_EXE_utexo-bridge-parent-cli");
    let verify = env!("CARGO_BIN_EXE_attest-verify");
    let enclave = format!("127.0.0.1:{}", start_real_enclave());
    let dir = scratch("bundle");
    let bundle = dir.join("attestation.json");
    let bundle = bundle.to_str().unwrap();

    let out = run(
        cli,
        &[
            "--addr",
            &enclave,
            "export-attestation",
            "--mock",
            "--out",
            bundle,
        ],
    );
    assert!(out.status.success(), "{out:?}");

    // No parent runs yet, so the check is offline.
    let offline = run(verify, &["--from-file", bundle, "--mock"]);
    assert!(offline.status.success(), "{offline:?}");

    let grpc_port = start_real_parent_grpc(enclave[10..].parse().unwrap()).await;
    let endpoint = format!("http://127.0.0.1:{grpc_port}");
    let live = run(verify, &["--endpoint", &endpoint, "--mock"]);
    assert!(live.status.success(), "{live:?}");
    assert_eq!(key_lines(&offline), key_lines(&live));

    let pcrs = dir.join("PCR.json");
    let pcr = "aa".repeat(48);
    std::fs::write(
        &pcrs,
        format!(r#"{{"PCR0":"{pcr}","PCR1":"{pcr}","PCR2":"{pcr}"}}"#),
    )
    .unwrap();
    let refused = dir.join("refused.json");
    let refused = refused.to_str().unwrap();
    for extra in [
        ["--pcr-file", pcrs.to_str().unwrap()],
        [
            "--expect-evm-address",
            "0x0000000000000000000000000000000000000001",
        ],
    ] {
        let mut args = vec![
            "--addr",
            &enclave,
            "export-attestation",
            "--mock",
            "--out",
            refused,
        ];
        args.extend(extra);
        let out = run(cli, &args);
        assert_eq!(out.status.code(), Some(1), "{out:?}");
        assert!(String::from_utf8_lossy(&out.stderr).starts_with("FAIL: "));
        assert!(!std::path::Path::new(refused).exists());
    }

    let both = run(
        verify,
        &["--from-file", bundle, "--endpoint", &endpoint, "--mock"],
    );
    assert_eq!(both.status.code(), Some(2), "{both:?}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn verify_identity_writes_a_bundle_per_enclave_and_gates_on_the_attested_address() {
    let dir = scratch("verify-identity");
    let (p16, p18) = (start_real_enclave(), start_real_enclave());
    // The real CLI, with the TCP enclaves for the vsock CIDs. The mock
    // enclaves attest zero PCRs and the Development policy, so the wrapper
    // swaps the release flags for --mock.
    let wrapper = dir.join("utexo-bridge-parent-cli");
    std::fs::write(
        &wrapper,
        format!(
            r#"#!/usr/bin/env bash
args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --addr) case "$2" in vsock://16:*) args+=(--addr 127.0.0.1:{p16});; vsock://18:*) args+=(--addr 127.0.0.1:{p18});; esac; shift 2;;
    --pcr-file|--image-env|--signer-role) shift 2;;
    export-attestation) args+=(export-attestation --mock); shift;;
    *) args+=("$1"); shift;;
  esac
done
exec {} "${{args[@]}}"
"#,
            env!("CARGO_BIN_EXE_utexo-bridge-parent-cli")
        ),
    )
    .unwrap();
    let bin = dir.join("bin");
    std::fs::create_dir(&bin).unwrap();
    std::fs::write(
        bin.join("nitro-cli"),
        "#!/bin/sh\necho '[{\"EnclaveCID\":16,\"State\":\"RUNNING\"},{\"EnclaveCID\":18,\"State\":\"RUNNING\"}]'\n",
    )
    .unwrap();
    for f in [&wrapper, &bin.join("nitro-cli")] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let env_file = dir.join("enclave.env");
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let gate = |env: &str, expected_evm: &str| {
        std::fs::write(&env_file, env).unwrap();
        let out = std::process::Command::new("bash")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../deploy/verify-identity.sh"
            ))
            .env_clear()
            .env("PATH", &path)
            .env("CLUSTER_DIR", &dir)
            .env("CIDS", "16 18")
            .env("ENCLAVE_ENV", &env_file)
            .env("EXPECTED_EVM", expected_evm)
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };
    let burn = "PCR_FILE=PCR.json\nIMAGE_ENV=IMAGE-ENV.json\nSIGNER_ROLE=burn\n";
    let bundle = |cid: u16| dir.join(format!("attestation-{cid}.json"));

    let (code, log) = gate(burn, "");
    assert_eq!(code, Some(0), "{log}");
    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(bundle(16)).unwrap()).unwrap();
    let evm = json["public_keys"]["evm_address"]
        .as_str()
        .unwrap()
        .to_string();

    let (code, log) = gate(burn, &format!("16={evm} 18={evm}"));
    assert_eq!(code, Some(0), "{log}");
    for cid in [16, 18] {
        assert!(
            log.contains(&format!("CID {cid} attested EVM {evm} == registered")),
            "{log}"
        );
        let out = run(
            env!("CARGO_BIN_EXE_attest-verify"),
            &["--from-file", bundle(cid).to_str().unwrap(), "--mock"],
        );
        assert!(out.status.success(), "{out:?}");
    }

    let other = "0x0000000000000000000000000000000000000001";
    let (code, log) = gate(burn, &format!("16={evm} 18={other}"));
    assert_eq!(code, Some(1), "{log}");
    assert!(
        log.contains("CID 18 attested export failed: FAIL: evm_address mismatch"),
        "{log}"
    );
    assert!(bundle(16).exists() && !bundle(18).exists());

    let (code, log) = gate("IMAGE_ENV=IMAGE-ENV.json\nSIGNER_ROLE=burn\n", "");
    assert_eq!(code, Some(2), "{log}");

    std::fs::remove_file(bundle(16)).unwrap();
    let (code, log) = gate("SIGNER_ROLE=mint\n", &format!("16={evm} 18={evm}"));
    assert_eq!(code, Some(0), "{log}");
    assert!(!bundle(16).exists() && !bundle(18).exists());
    std::fs::remove_dir_all(dir).unwrap();
}
