//! Wire-level negative and positive coverage of the request dispatcher.
//!
//! Everything here goes through TCP framing -> `dispatch` -> response, the
//! same path the parent drives over vsock. The suite covers what the
//! per-RPC suites leave out: malformed frames, the empty request, the error
//! code mapping on the wire, the arms a single-network build refuses, the
//! `InitializeKey` refusal paths, and field-width validation on the cloning
//! handlers before any attestation is involved.
//!
//! Tests gated on `mock-attestation` additionally drive the requester side
//! of a clone against a donor simulated in-process, which reaches the
//! `SetClone` rejections (`NotReady`, `PubkeyMismatch`, `IdentityMismatch`)
//! the two-server suite in `test_clone.rs` does not.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;

use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::framing;
use utexo_bridge_enclave::proto::enclave_request::Request as Req;
use utexo_bridge_enclave::proto::enclave_response::Response as Resp;
use utexo_bridge_enclave::proto::sign_request::{DestinationNetwork, SourceNetwork};
use utexo_bridge_enclave::proto::*;

const CODE_GENERIC: u32 = 1;
const CODE_NOT_READY: u32 = 2;
#[allow(dead_code)]
const CODE_VALIDATION_FAILED: u32 = 3;

fn send(port: u16, req: Req) -> EnclaveResponse {
    common::send_request(port, &EnclaveRequest { request: Some(req) })
}

/// Write raw bytes on a fresh connection and try to read a framed response.
fn send_raw(port: u16, bytes: &[u8]) -> Result<EnclaveResponse, String> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    stream.write_all(bytes).unwrap();
    stream.flush().unwrap();
    // Half-close so a server that is still waiting for more body bytes sees
    // EOF instead of parking the test.
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    framing::read_message::<EnclaveResponse>(&mut stream).map_err(|e| e.to_string())
}

fn expect_error(resp: EnclaveResponse) -> ErrorResponse {
    match resp.response {
        Some(Resp::Error(e)) => e,
        other => panic!("expected an error response, got {other:?}"),
    }
}

fn init_from_entropy(port: u16) -> InitializeKeyResponse {
    match send(
        port,
        Req::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
            cloning_secret: String::new(),
        }),
    )
    .response
    {
        Some(Resp::InitializeKey(r)) => r,
        other => panic!("InitializeKey failed: {other:?}"),
    }
}

fn get_public_keys(port: u16) -> EnclaveResponse {
    send(port, Req::GetPublicKey(GetPublicKeyRequest {}))
}

fn assert_not_initialized(port: u16) {
    let err = expect_error(get_public_keys(port));
    assert_eq!(err.code, CODE_GENERIC);
    assert!(
        err.message.contains("key not initialized"),
        "{}",
        err.message
    );
}

fn pinned_config() -> BridgeConfig {
    BridgeConfig {
        chain_id: 1,
        bridge_contract: [0xAA; 20],
        rgb_asset_id: "rgb:test".into(),
        ..Default::default()
    }
}

// ---- framing on the socket -------------------------------------------------

#[test]
fn zero_length_frame_closes_the_connection_without_a_response() {
    let port = common::start_test_server();
    let err = send_raw(port, &[0, 0, 0, 0]).unwrap_err();
    assert!(err.contains("io error"), "{err}");
    // The server is still alive afterwards.
    assert_not_initialized(port);
}

#[test]
fn oversized_length_prefix_closes_the_connection_without_a_response() {
    let port = common::start_test_server();
    let len: u32 = 4 * 1024 * 1024 + 1;
    let err = send_raw(port, &len.to_le_bytes()).unwrap_err();
    assert!(err.contains("io error"), "{err}");
    assert_not_initialized(port);
}

#[test]
fn truncated_body_closes_the_connection_without_a_response() {
    let port = common::start_test_server();
    // Declares 100 bytes, sends 3, then half-closes.
    let mut bytes = 100u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[1, 2, 3]);
    let err = send_raw(port, &bytes).unwrap_err();
    assert!(err.contains("io error"), "{err}");
    assert_not_initialized(port);
}

#[test]
fn undecodable_body_closes_the_connection_without_a_response() {
    let port = common::start_test_server();
    let mut bytes = 4u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
    let err = send_raw(port, &bytes).unwrap_err();
    assert!(err.contains("io error"), "{err}");
    assert_not_initialized(port);
}

#[test]
fn a_well_formed_frame_gets_exactly_one_response_then_eof() {
    let port = common::start_test_server();
    let body = EnclaveRequest {
        request: Some(Req::GetPublicKey(GetPublicKeyRequest {})),
    };
    let mut wire = Vec::new();
    framing::write_message(&mut wire, &body).unwrap();
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    stream.write_all(&wire).unwrap();
    let resp: EnclaveResponse = framing::read_message(&mut stream).unwrap();
    assert!(matches!(resp.response, Some(Resp::Error(_))));
    // One request per connection: the server closes after replying.
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).unwrap();
    assert!(
        rest.is_empty(),
        "no second frame expected, got {} bytes",
        rest.len()
    );
}

// ---- dispatch: empty / unknown request ----------------------------------

#[test]
fn a_request_with_no_variant_set_is_reported_as_empty() {
    let port = common::start_test_server();
    // Field 4 is unassigned in the `request` oneof (tags 1-3, 5-15), so a
    // length-delimited field 4 decodes as "no variant". Same for tag 99.
    for body in [vec![0x22u8, 0x00], vec![0x9a, 0x06, 0x00]] {
        let mut wire = (body.len() as u32).to_le_bytes().to_vec();
        wire.extend_from_slice(&body);
        let err = expect_error(send_raw(port, &wire).unwrap());
        assert_eq!(err.code, CODE_GENERIC);
        assert_eq!(err.message, "empty request");
    }
}

// ---- error code mapping on the wire ------------------------------------------

#[test]
fn invalid_requests_carry_the_generic_code() {
    let port = common::start_test_server();
    let err = expect_error(send(
        port,
        Req::SignRawMessage(SignRawMessageRequest { message: vec![1] }),
    ));
    assert_eq!(err.code, CODE_GENERIC);
    assert!(err.message.contains("removed"), "{}", err.message);
}

#[test]
fn not_ready_carries_code_2() {
    let port = common::start_test_server();
    let err = expect_error(send(
        port,
        Req::ProxyFederation(ProxyFederationRequest {
            message_hash: vec![0; 32],
        }),
    ));
    assert_eq!(err.code, CODE_NOT_READY);
}

#[cfg(not(feature = "dev-mode"))]
#[test]
fn cross_check_failures_carry_code_3() {
    let port = common::start_test_server();
    // The gas-tx allowlist refuses an opaque digest before any key is needed.
    let err = expect_error(send(
        port,
        Req::SignRawDigest(SignRawDigestRequest {
            digest: vec![0xAB; 32],
            unsigned_tx: vec![],
        }),
    ));
    assert_eq!(err.code, CODE_VALIDATION_FAILED);
    assert!(err.message.contains("unsigned_tx"), "{}", err.message);
}

#[cfg(not(feature = "dev-mode"))]
#[test]
fn gas_tx_signing_fails_closed_when_nothing_is_pinned_even_after_init() {
    let port = common::start_test_server();
    init_from_entropy(port);
    // A syntactically plausible preimage still fails: the chain id is unpinned.
    let err = expect_error(send(
        port,
        Req::SignRawDigest(SignRawDigestRequest {
            digest: vec![],
            unsigned_tx: vec![0x02, 0xc0],
        }),
    ));
    assert_eq!(err.code, CODE_VALIDATION_FAILED);
}

// ---- Sign: request shape --------------------------------------------------------

#[test]
fn sign_without_a_source_network_is_invalid() {
    let port = common::start_test_server();
    let err = expect_error(send(
        port,
        Req::Sign(SignRequest {
            amount: 1,
            source_network: None,
            destination_network: Some(
                DestinationNetwork::EvmDestination(EvmDestination::default()),
            ),
        }),
    ));
    assert_eq!(err.code, CODE_GENERIC);
    assert!(err.message.contains("no source_network"), "{}", err.message);
}

#[test]
fn sign_without_a_destination_network_is_invalid() {
    let port = common::start_test_server();
    let err = expect_error(send(
        port,
        Req::Sign(SignRequest {
            amount: 1,
            source_network: Some(SourceNetwork::EvmSource(EvmSource {
                tx_hash: vec![0; 32],
                ..Default::default()
            })),
            destination_network: None,
        }),
    ));
    assert_eq!(err.code, CODE_GENERIC);
    assert!(
        err.message.contains("no destination_network"),
        "{}",
        err.message
    );
}

#[test]
fn sign_with_both_sides_missing_reports_the_source_first() {
    let port = common::start_test_server();
    let err = expect_error(send(
        port,
        Req::Sign(SignRequest {
            amount: 1,
            source_network: None,
            destination_network: None,
        }),
    ));
    assert!(err.message.contains("no source_network"), "{}", err.message);
}

#[cfg(not(feature = "dev-mode"))]
#[test]
fn sign_with_a_short_evm_tx_hash_is_a_cross_check_failure() {
    let port = common::start_test_server();
    let err = expect_error(send(
        port,
        Req::Sign(SignRequest {
            amount: 1,
            source_network: Some(SourceNetwork::EvmSource(EvmSource {
                tx_hash: vec![0; 31],
                ..Default::default()
            })),
            destination_network: Some(
                DestinationNetwork::EvmDestination(EvmDestination::default()),
            ),
        }),
    ));
    assert_eq!(err.code, CODE_VALIDATION_FAILED);
    assert!(err.message.contains("evm_tx_hash"), "{}", err.message);
}

// ---- single-network builds refuse the other network's RPCs ------------------

#[cfg(not(feature = "ccd"))]
#[test]
fn sign_ccd_is_refused_on_a_build_without_ccd() {
    let port = common::start_test_server();
    init_from_entropy(port);
    let err = expect_error(send(
        port,
        Req::SignCcd(SignCcdRequest {
            hash: vec![0xAB; 32],
        }),
    ));
    assert_eq!(err.code, CODE_GENERIC);
    assert!(err.message.contains("ccd"), "{}", err.message);
}

#[cfg(not(feature = "ccd"))]
#[test]
fn a_ccd_source_is_refused_on_a_build_without_ccd() {
    let port = common::start_test_server();
    let err = expect_error(send(
        port,
        Req::Sign(SignRequest {
            amount: 1,
            source_network: Some(SourceNetwork::CcdSource(CcdSource {
                tx_hash: vec![0xCC; 32],
                commission: 0,
            })),
            destination_network: Some(
                DestinationNetwork::EvmDestination(EvmDestination::default()),
            ),
        }),
    ));
    assert_eq!(err.code, CODE_GENERIC);
    assert!(err.message.contains("not supported"), "{}", err.message);
}

#[cfg(feature = "ccd")]
#[test]
fn sign_ccd_before_init_is_key_not_initialized() {
    let port = common::start_test_server();
    let err = expect_error(send(
        port,
        Req::SignCcd(SignCcdRequest {
            hash: vec![0xAB; 32],
        }),
    ));
    assert_eq!(err.code, CODE_GENERIC);
    assert!(
        err.message.contains("key not initialized"),
        "{}",
        err.message
    );
}

#[cfg(feature = "ccd")]
#[test]
fn sign_ccd_checks_the_hash_width_before_the_key_state() {
    // Uninitialised AND a bad width: the width error is reported, so a
    // caller learns about the malformed request first.
    let port = common::start_test_server();
    let err = expect_error(send(
        port,
        Req::SignCcd(SignCcdRequest {
            hash: vec![0xAB; 33],
        }),
    ));
    assert!(err.message.contains("32 bytes"), "{}", err.message);
}

#[cfg(feature = "ccd")]
#[test]
fn sign_ccd_signature_verifies_under_the_returned_key() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let port = common::start_test_server();
    let init = init_from_entropy(port);
    let hash = [0x77u8; 32];
    let (sig, pk) = match send(
        port,
        Req::SignCcd(SignCcdRequest {
            hash: hash.to_vec(),
        }),
    )
    .response
    {
        Some(Resp::CcdSignature(r)) => (r.signature, r.public_key),
        other => panic!("expected CcdSignature, got {other:?}"),
    };
    assert_eq!(pk, init.ccd_ed25519_pub, "signs under the initialised key");
    let vk = VerifyingKey::from_bytes(&pk.try_into().unwrap()).unwrap();
    let sig = Signature::from_bytes(&sig.try_into().unwrap());
    assert!(vk.verify(&hash, &sig).is_ok());
    assert!(vk.verify(&[0x78u8; 32], &sig).is_err());
}

#[cfg(not(feature = "spv"))]
#[test]
fn header_sync_rpcs_are_refused_on_a_build_without_spv() {
    let port = common::start_test_server();
    let err = expect_error(send(
        port,
        Req::SubmitHeaders(SubmitHeadersRequest {
            headers: vec![vec![0; 80]],
            start_height: 1,
        }),
    ));
    assert_eq!(err.code, CODE_GENERIC);
    assert!(err.message.contains("rgb"), "{}", err.message);
    let err = expect_error(send(
        port,
        Req::GetLastSavedBlock(GetLastSavedBlockRequest {}),
    ));
    assert_eq!(err.code, CODE_GENERIC);
    assert!(err.message.contains("rgb"), "{}", err.message);
}

#[cfg(feature = "spv")]
#[test]
fn garbage_header_bytes_are_a_validation_failure_on_the_wire() {
    let port = common::start_test_server();
    let err = expect_error(send(
        port,
        Req::SubmitHeaders(SubmitHeadersRequest {
            headers: vec![vec![0xff; 10]],
            start_height: 1,
        }),
    ));
    assert_eq!(err.code, CODE_VALIDATION_FAILED);
    assert!(err.message.contains("spv"), "{}", err.message);
}

// ---- InitializeKey ----------------------------------------------------------------

#[cfg(not(feature = "allow-seed-import"))]
#[test]
fn seed_and_mnemonic_import_are_refused_without_the_dev_feature() {
    let port = common::start_test_server();
    let err = expect_error(send(
        port,
        Req::InitializeKey(InitializeKeyRequest {
            seed: vec![7u8; 64],
            mnemonic: String::new(),
            cloning_secret: String::new(),
        }),
    ));
    assert_eq!(err.code, CODE_GENERIC);
    assert!(
        err.message.contains("seed import not allowed"),
        "{}",
        err.message
    );
    let err = expect_error(send(
        port,
        Req::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
            cloning_secret: String::new(),
        }),
    ));
    assert!(
        err.message.contains("mnemonic import not allowed"),
        "{}",
        err.message
    );
    // Nothing was installed: the entropy path still works afterwards.
    assert_not_initialized(port);
    init_from_entropy(port);
}

#[cfg(feature = "allow-seed-import")]
#[test]
fn seed_import_of_the_wrong_width_is_rejected_and_the_enclave_stays_initial() {
    let port = common::start_test_server();
    for len in [1usize, 32, 63, 65] {
        let err = expect_error(send(
            port,
            Req::InitializeKey(InitializeKeyRequest {
                seed: vec![7u8; len],
                mnemonic: String::new(),
                cloning_secret: String::new(),
            }),
        ));
        assert_eq!(err.code, CODE_GENERIC);
        assert!(err.message.contains("64 bytes"), "{len}: {}", err.message);
        assert!(
            err.message.contains(&format!("got {len}")),
            "{}",
            err.message
        );
    }
    assert_not_initialized(port);
    // A correct seed then succeeds.
    let resp = send(
        port,
        Req::InitializeKey(InitializeKeyRequest {
            seed: vec![7u8; 64],
            mnemonic: String::new(),
            cloning_secret: String::new(),
        }),
    );
    assert!(matches!(resp.response, Some(Resp::InitializeKey(_))));
}

#[cfg(feature = "allow-seed-import")]
#[test]
fn invalid_mnemonic_is_rejected_and_the_enclave_stays_initial() {
    let port = common::start_test_server();
    let err = expect_error(send(
        port,
        Req::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: "this is not a bip39 phrase and must be refused".into(),
            cloning_secret: String::new(),
        }),
    ));
    assert_eq!(err.code, CODE_GENERIC);
    assert!(err.message.contains("invalid mnemonic"), "{}", err.message);
    assert_not_initialized(port);
    init_from_entropy(port);
}

#[cfg(feature = "allow-seed-import")]
#[test]
fn mnemonic_wins_over_seed_when_both_are_supplied() {
    // The dispatcher routes on `mnemonic` first, so a request carrying both
    // installs the mnemonic's wallet, not the seed's.
    use utexo_bridge_enclave::keys::KeyManager;
    let port = common::start_test_server();
    let mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let resp = match send(
        port,
        Req::InitializeKey(InitializeKeyRequest {
            seed: vec![7u8; 64],
            mnemonic: mnemonic.into(),
            cloning_secret: String::new(),
        }),
    )
    .response
    {
        Some(Resp::InitializeKey(r)) => r,
        other => panic!("expected InitializeKey, got {other:?}"),
    };
    let from_mnemonic = KeyManager::from_mnemonic(mnemonic, bitcoin::Network::Bitcoin).unwrap();
    let from_seed = KeyManager::from_seed([7u8; 64], bitcoin::Network::Bitcoin).unwrap();
    assert_eq!(resp.evm_address, from_mnemonic.evm_address().to_vec());
    assert_ne!(resp.evm_address, from_seed.evm_address().to_vec());
}

#[test]
fn initialize_and_get_public_key_agree_and_carry_the_pinned_config() {
    let port = common::start_test_server_with_config(|_| {}, pinned_config());
    let init = init_from_entropy(port);
    let keys = match get_public_keys(port).response {
        Some(Resp::PublicKeys(k)) => k,
        other => panic!("expected PublicKeys, got {other:?}"),
    };
    assert_eq!(init.evm_address, keys.evm_address);
    assert_eq!(init.evm_uncompressed_pub, keys.evm_uncompressed_pub);
    assert_eq!(init.evm_gas_tx_address, keys.evm_gas_tx_address);
    assert_eq!(
        init.evm_gas_tx_uncompressed_pub,
        keys.evm_gas_tx_uncompressed_pub
    );
    assert_eq!(init.btc_compressed_pub, keys.btc_compressed_pub);
    assert_eq!(init.btc_xpub, keys.btc_xpub);
    assert_eq!(init.master_fingerprint, keys.master_fingerprint);
    assert_eq!(init.account_xpub_vanilla, keys.account_xpub_vanilla);
    assert_eq!(init.account_xpub_colored, keys.account_xpub_colored);
    assert_eq!(init.ccd_ed25519_pub, keys.ccd_ed25519_pub);
    for (chain_id, contract, asset) in [
        (init.chain_id, &init.bridge_contract, &init.rgb_asset_id),
        (keys.chain_id, &keys.bridge_contract, &keys.rgb_asset_id),
    ] {
        assert_eq!(chain_id, 1);
        assert_eq!(contract, &vec![0xAA; 20]);
        assert_eq!(asset, "rgb:test");
    }
    // Widths on the wire.
    assert_eq!(keys.evm_address.len(), 20);
    assert_eq!(keys.evm_uncompressed_pub.len(), 64);
    assert_eq!(keys.btc_compressed_pub.len(), 33);
    assert_eq!(keys.master_fingerprint.len(), 4);
    assert_eq!(keys.ccd_ed25519_pub.len(), 32);
}

#[test]
fn unconfigured_server_reports_empty_pins() {
    let port = common::start_test_server_with_config(|_| {}, BridgeConfig::default());
    let init = init_from_entropy(port);
    assert_eq!(init.chain_id, 0);
    assert_eq!(init.bridge_contract, vec![0u8; 20]);
    assert_eq!(init.rgb_asset_id, "");
}

#[test]
fn a_cloning_secret_on_init_configures_the_donor_role() {
    // Observable through GetClone: with the secret unset the donor-secret
    // check would fail NotReady, but the request below fails earlier on the
    // cluster key, so instead check via the state hook in the harness.
    let port = common::start_test_server_with(|state| {
        assert!(state.with_donor_cloning_secret(|_| Ok(())).is_err());
    });
    let resp = send(
        port,
        Req::InitializeKey(InitializeKeyRequest {
            seed: vec![],
            mnemonic: String::new(),
            cloning_secret: "operator-secret".into(),
        }),
    );
    assert!(matches!(resp.response, Some(Resp::InitializeKey(_))));
}

// ---- cloning handlers: field validation before any attestation -------------

#[test]
fn initiate_cloning_rejects_an_empty_secret() {
    let port = common::start_test_server();
    let err = expect_error(send(
        port,
        Req::InitiateCloning(InitiateCloningRequest {
            cloning_secret: String::new(),
            cluster_public_key: vec![0x11; 20],
        }),
    ));
    assert_eq!(err.code, CODE_GENERIC);
    assert!(
        err.message.contains("cloning_secret is required"),
        "{}",
        err.message
    );
    assert_not_initialized(port);
    // The phase is still Initial, so a normal init still works.
    init_from_entropy(port);
}

#[test]
fn initiate_cloning_rejects_a_cluster_key_of_the_wrong_width() {
    let port = common::start_test_server();
    for len in [0usize, 19, 21, 32] {
        let err = expect_error(send(
            port,
            Req::InitiateCloning(InitiateCloningRequest {
                cloning_secret: "s".into(),
                cluster_public_key: vec![0x11; len],
            }),
        ));
        assert_eq!(err.code, CODE_GENERIC);
        assert!(err.message.contains("20 bytes"), "{len}: {}", err.message);
        assert!(
            err.message.contains(&format!("got {len}")),
            "{}",
            err.message
        );
    }
    assert_not_initialized(port);
}

#[test]
fn get_clone_rejects_malformed_field_widths_before_touching_state() {
    let port = common::start_test_server();
    let good = GetCloneRequest {
        cluster_public_key: vec![0x11; 20],
        cloning_digest: vec![0x22; 32],
        encryption_pubkey: vec![0x33; 32],
        requester_attestation: vec![],
    };
    let cases = [
        (
            GetCloneRequest {
                cluster_public_key: vec![0x11; 19],
                ..good.clone()
            },
            "cluster_public_key must be 20 bytes, got 19",
        ),
        (
            GetCloneRequest {
                encryption_pubkey: vec![0x33; 33],
                ..good.clone()
            },
            "encryption_pubkey must be 32 bytes, got 33",
        ),
        (
            GetCloneRequest {
                cloning_digest: vec![],
                ..good.clone()
            },
            "cloning_digest must be 32 bytes, got 0",
        ),
    ];
    for (req, needle) in cases {
        let err = expect_error(send(port, Req::GetClone(req)));
        assert_eq!(err.code, CODE_GENERIC);
        assert!(err.message.contains(needle), "{}", err.message);
    }
    // Well-formed but the donor has no keys yet.
    let err = expect_error(send(port, Req::GetClone(good)));
    assert!(
        err.message.contains("key not initialized"),
        "{}",
        err.message
    );
}

#[test]
fn get_clone_addressed_to_another_enclave_is_refused_before_attestation() {
    let port = common::start_test_server();
    let init = init_from_entropy(port);
    let mut wrong = init.evm_address.clone();
    wrong[0] ^= 0xff;
    let err = expect_error(send(
        port,
        Req::GetClone(GetCloneRequest {
            cluster_public_key: wrong,
            cloning_digest: vec![0x22; 32],
            encryption_pubkey: vec![0x33; 32],
            requester_attestation: vec![],
        }),
    ));
    assert_eq!(err.code, CODE_GENERIC);
    assert!(
        err.message
            .contains("does not match this enclave's address"),
        "{}",
        err.message
    );
}

#[test]
fn set_clone_rejects_a_donor_pubkey_of_the_wrong_width() {
    let port = common::start_test_server();
    for len in [0usize, 31, 33] {
        let err = expect_error(send(
            port,
            Req::SetClone(SetCloneRequest {
                encrypted_seed: vec![0; 80],
                donor_pubkey: vec![0x44; len],
                donor_attestation: vec![],
            }),
        ));
        assert_eq!(err.code, CODE_GENERIC);
        assert!(
            err.message.contains("donor_pubkey must be 32 bytes"),
            "{}",
            err.message
        );
    }
    assert_not_initialized(port);
}

#[test]
fn set_clone_with_an_undecodable_attestation_is_rejected() {
    let port = common::start_test_server();
    let err = expect_error(send(
        port,
        Req::SetClone(SetCloneRequest {
            encrypted_seed: vec![0; 80],
            donor_pubkey: vec![0x44; 32],
            donor_attestation: vec![0xff; 8],
        }),
    ));
    assert_eq!(err.code, CODE_GENERIC);
    assert_not_initialized(port);
}

// ---- cloning: requester side against an in-process donor (mock attestation) --

#[cfg(feature = "mock-attestation")]
mod mock_clone {
    use super::*;
    use attestation_verify::build_mock_document;
    use utexo_bridge_enclave::cloning;
    use utexo_bridge_enclave::keys::KeyManager;

    const SEED: [u8; 64] = [0x5c; 64];

    fn seed_address() -> Vec<u8> {
        KeyManager::from_seed(SEED, bitcoin::Network::Bitcoin)
            .unwrap()
            .evm_address()
            .to_vec()
    }

    /// Requester enters Cloning for `cluster_pk` and returns its X25519 pubkey.
    fn initiate(port: u16, cluster_pk: Vec<u8>) -> [u8; 32] {
        match send(
            port,
            Req::InitiateCloning(InitiateCloningRequest {
                cloning_secret: "s".into(),
                cluster_public_key: cluster_pk,
            }),
        )
        .response
        {
            Some(Resp::InitiateCloning(r)) => {
                assert_eq!(r.cloning_digest.len(), 32);
                assert!(!r.requester_attestation.is_empty());
                r.encryption_pubkey.try_into().unwrap()
            }
            other => panic!("expected InitiateCloning, got {other:?}"),
        }
    }

    /// Simulated donor: seal `seed` to the requester and attest the donor key.
    fn donor_seal(requester_pk: &[u8; 32], seed: &[u8; 64]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let (ciphertext, donor_pub) = cloning::encrypt_seed_for_peer(requester_pk, seed).unwrap();
        let doc = build_mock_document(&[0x99; 32], Some(&donor_pub), None).unwrap();
        (ciphertext, donor_pub.to_vec(), doc)
    }

    #[test]
    fn requester_completes_a_clone_from_a_local_donor_and_takes_its_identity() {
        let port = common::start_test_server();
        let requester_pk = initiate(port, seed_address());
        assert_not_initialized(port);
        let (ciphertext, donor_pub, doc) = donor_seal(&requester_pk, &SEED);
        let resp = send(
            port,
            Req::SetClone(SetCloneRequest {
                encrypted_seed: ciphertext,
                donor_pubkey: donor_pub,
                donor_attestation: doc,
            }),
        );
        assert!(matches!(resp.response, Some(Resp::SetClone(_))), "{resp:?}");
        let keys = match get_public_keys(port).response {
            Some(Resp::PublicKeys(k)) => k,
            other => panic!("expected PublicKeys, got {other:?}"),
        };
        assert_eq!(keys.evm_address, seed_address());
    }

    #[test]
    fn a_second_initiate_while_cloning_is_already_initialized() {
        let port = common::start_test_server();
        initiate(port, seed_address());
        let err = expect_error(send(
            port,
            Req::InitiateCloning(InitiateCloningRequest {
                cloning_secret: "s".into(),
                cluster_public_key: seed_address(),
            }),
        ));
        assert!(
            err.message.contains("already initialized"),
            "{}",
            err.message
        );
    }

    #[test]
    fn initiate_after_active_is_already_initialized() {
        let port = common::start_test_server();
        let init = init_from_entropy(port);
        let err = expect_error(send(
            port,
            Req::InitiateCloning(InitiateCloningRequest {
                cloning_secret: "s".into(),
                cluster_public_key: init.evm_address.clone(),
            }),
        ));
        assert!(
            err.message.contains("already initialized"),
            "{}",
            err.message
        );
        // Still Active with the same identity.
        match get_public_keys(port).response {
            Some(Resp::PublicKeys(k)) => assert_eq!(k.evm_address, init.evm_address),
            other => panic!("expected PublicKeys, got {other:?}"),
        }
    }

    #[test]
    fn set_clone_outside_the_cloning_phase_is_not_ready() {
        // Initial phase.
        let port = common::start_test_server();
        let session = cloning::CloneSession::new();
        let (ciphertext, donor_pub, doc) = donor_seal(&session.public_key(), &SEED);
        let err = expect_error(send(
            port,
            Req::SetClone(SetCloneRequest {
                encrypted_seed: ciphertext.clone(),
                donor_pubkey: donor_pub.clone(),
                donor_attestation: doc.clone(),
            }),
        ));
        assert_eq!(err.code, CODE_NOT_READY);
        assert!(err.message.contains("initial"), "{}", err.message);
        // Active phase.
        init_from_entropy(port);
        let err = expect_error(send(
            port,
            Req::SetClone(SetCloneRequest {
                encrypted_seed: ciphertext,
                donor_pubkey: donor_pub,
                donor_attestation: doc,
            }),
        ));
        assert_eq!(err.code, CODE_NOT_READY);
        assert!(err.message.contains("active"), "{}", err.message);
    }

    #[test]
    fn set_clone_rejects_a_donor_pubkey_not_bound_in_the_attestation() {
        let port = common::start_test_server();
        let requester_pk = initiate(port, seed_address());
        let (ciphertext, donor_pub, _) = donor_seal(&requester_pk, &SEED);
        // Attestation binds a different key than the wire carries.
        let doc = build_mock_document(&[0x98; 32], Some(&[0x77; 32]), None).unwrap();
        let err = expect_error(send(
            port,
            Req::SetClone(SetCloneRequest {
                encrypted_seed: ciphertext,
                donor_pubkey: donor_pub,
                donor_attestation: doc,
            }),
        ));
        assert!(err.message.contains("pubkey mismatch"), "{}", err.message);
        assert_not_initialized(port);
    }

    #[test]
    fn set_clone_rejects_an_attestation_with_no_public_key() {
        let port = common::start_test_server();
        let requester_pk = initiate(port, seed_address());
        let (ciphertext, donor_pub, _) = donor_seal(&requester_pk, &SEED);
        let doc = build_mock_document(&[0x98; 32], None, None).unwrap();
        let err = expect_error(send(
            port,
            Req::SetClone(SetCloneRequest {
                encrypted_seed: ciphertext,
                donor_pubkey: donor_pub,
                donor_attestation: doc,
            }),
        ));
        assert!(
            err.message.contains("missing public key"),
            "{}",
            err.message
        );
    }

    #[test]
    fn set_clone_with_a_seed_of_the_wrong_identity_keeps_the_cloning_phase() {
        let port = common::start_test_server();
        // Requester expects the address of SEED but the donor seals another.
        let requester_pk = initiate(port, seed_address());
        let (ciphertext, donor_pub, doc) = donor_seal(&requester_pk, &[0x5d; 64]);
        let err = expect_error(send(
            port,
            Req::SetClone(SetCloneRequest {
                encrypted_seed: ciphertext,
                donor_pubkey: donor_pub,
                donor_attestation: doc,
            }),
        ));
        assert!(err.message.contains("identity mismatch"), "{}", err.message);
        // Still Cloning: init is refused, keys are absent, and a correct
        // SetClone afterwards succeeds.
        let err = expect_error(send(
            port,
            Req::InitializeKey(InitializeKeyRequest {
                seed: vec![],
                mnemonic: String::new(),
                cloning_secret: String::new(),
            }),
        ));
        assert!(
            err.message.contains("already initialized"),
            "{}",
            err.message
        );
        assert_not_initialized(port);
        let (ciphertext, donor_pub, doc) = donor_seal(&requester_pk, &SEED);
        let resp = send(
            port,
            Req::SetClone(SetCloneRequest {
                encrypted_seed: ciphertext,
                donor_pubkey: donor_pub,
                donor_attestation: doc,
            }),
        );
        assert!(matches!(resp.response, Some(Resp::SetClone(_))), "{resp:?}");
    }

    #[test]
    fn set_clone_with_a_ciphertext_for_another_requester_is_rejected() {
        let port = common::start_test_server();
        initiate(port, seed_address());
        // Sealed to a different X25519 key: the AEAD tag fails.
        let stranger = cloning::CloneSession::new();
        let (ciphertext, donor_pub, doc) = donor_seal(&stranger.public_key(), &SEED);
        let err = expect_error(send(
            port,
            Req::SetClone(SetCloneRequest {
                encrypted_seed: ciphertext,
                donor_pubkey: donor_pub,
                donor_attestation: doc,
            }),
        ));
        assert!(err.message.contains("clone failed"), "{}", err.message);
        assert_not_initialized(port);
    }

    #[test]
    fn a_completed_clone_refuses_to_be_cloned_over() {
        let port = common::start_test_server();
        let requester_pk = initiate(port, seed_address());
        let (ciphertext, donor_pub, doc) = donor_seal(&requester_pk, &SEED);
        let resp = send(
            port,
            Req::SetClone(SetCloneRequest {
                encrypted_seed: ciphertext.clone(),
                donor_pubkey: donor_pub.clone(),
                donor_attestation: doc.clone(),
            }),
        );
        assert!(matches!(resp.response, Some(Resp::SetClone(_))));
        // Replaying the same SetClone: the phase is Active now.
        let err = expect_error(send(
            port,
            Req::SetClone(SetCloneRequest {
                encrypted_seed: ciphertext,
                donor_pubkey: donor_pub,
                donor_attestation: doc,
            }),
        ));
        assert_eq!(err.code, CODE_NOT_READY);
    }

    // ---- donor side: digest and secret checks ------------------------------------

    /// A donor whose cloning secret arrives the production way: in the
    /// `InitializeKey` request, not through the test harness.
    fn donor_with_secret(secret: &str) -> (u16, Vec<u8>) {
        let port = common::start_test_server();
        match send(
            port,
            Req::InitializeKey(InitializeKeyRequest {
                seed: vec![],
                mnemonic: String::new(),
                cloning_secret: secret.into(),
            }),
        )
        .response
        {
            Some(Resp::InitializeKey(r)) => (port, r.evm_address),
            other => panic!("InitializeKey failed: {other:?}"),
        }
    }

    fn requester_doc(pubkey: &[u8; 32], user_data: Option<&[u8]>) -> Vec<u8> {
        build_mock_document(&[0x11; 32], Some(pubkey), user_data).unwrap()
    }

    #[test]
    fn get_clone_seals_the_seed_when_every_binding_holds() {
        let (port, address) = donor_with_secret("operator");
        let requester = cloning::CloneSession::new();
        let pk = requester.public_key();
        let digest = cloning::make_cloning_digest("operator", &pk);
        let resp = match send(
            port,
            Req::GetClone(GetCloneRequest {
                cluster_public_key: address,
                cloning_digest: digest.to_vec(),
                encryption_pubkey: pk.to_vec(),
                requester_attestation: requester_doc(&pk, Some(&digest)),
            }),
        )
        .response
        {
            Some(Resp::GetClone(r)) => r,
            other => panic!("expected GetClone, got {other:?}"),
        };
        assert_eq!(resp.donor_pubkey.len(), 32);
        assert_eq!(resp.encrypted_seed.len(), 64 + 16);
        let donor_pub: [u8; 32] = resp.donor_pubkey.clone().try_into().unwrap();
        let seed = requester
            .decrypt_seed_from_peer(&donor_pub, &resp.encrypted_seed)
            .unwrap();
        // The unsealed seed derives the donor's own identity.
        let km = KeyManager::from_seed(*seed, bitcoin::Network::Bitcoin).unwrap();
        let donor_keys = match get_public_keys(port).response {
            Some(Resp::PublicKeys(k)) => k,
            other => panic!("expected PublicKeys, got {other:?}"),
        };
        assert_eq!(km.evm_address().to_vec(), donor_keys.evm_address);
        // The donor's attestation binds the donor pubkey it just used.
        let verified = attestation_verify::verify_mock_attestation(
            &resp.donor_attestation,
            &attestation_verify::ExpectedPcrs::zero(),
            None,
        )
        .unwrap();
        assert_eq!(verified.enclave_pubkey, resp.donor_pubkey);
    }

    #[test]
    fn get_clone_without_a_donor_secret_is_not_ready() {
        let port = common::start_test_server();
        let address = init_from_entropy(port).evm_address;
        let pk = [0x33; 32];
        let digest = cloning::make_cloning_digest("whatever", &pk);
        let err = expect_error(send(
            port,
            Req::GetClone(GetCloneRequest {
                cluster_public_key: address,
                cloning_digest: digest.to_vec(),
                encryption_pubkey: pk.to_vec(),
                requester_attestation: requester_doc(&pk, Some(&digest)),
            }),
        ));
        assert_eq!(err.code, CODE_NOT_READY);
        assert!(
            err.message.contains("donor cloning secret"),
            "{}",
            err.message
        );
    }

    #[test]
    fn get_clone_rejects_an_attestation_without_user_data() {
        let (port, address) = donor_with_secret("operator");
        let pk = [0x33; 32];
        let digest = cloning::make_cloning_digest("operator", &pk);
        let err = expect_error(send(
            port,
            Req::GetClone(GetCloneRequest {
                cluster_public_key: address,
                cloning_digest: digest.to_vec(),
                encryption_pubkey: pk.to_vec(),
                requester_attestation: requester_doc(&pk, None),
            }),
        ));
        assert!(err.message.contains("missing user_data"), "{}", err.message);
    }

    #[test]
    fn get_clone_rejects_a_wire_digest_the_attestation_does_not_carry() {
        let (port, address) = donor_with_secret("operator");
        let pk = [0x33; 32];
        let digest = cloning::make_cloning_digest("operator", &pk);
        let err = expect_error(send(
            port,
            Req::GetClone(GetCloneRequest {
                cluster_public_key: address,
                cloning_digest: digest.to_vec(),
                encryption_pubkey: pk.to_vec(),
                requester_attestation: requester_doc(&pk, Some(&[0xEE; 32])),
            }),
        ));
        assert!(err.message.contains("digest mismatch"), "{}", err.message);
    }

    #[test]
    fn get_clone_rejects_an_attestation_with_wrong_pcrs() {
        let (port, address) = donor_with_secret("operator");
        let pk = [0x33; 32];
        let digest = cloning::make_cloning_digest("operator", &pk);
        let foreign = attestation_verify::ExpectedPcrs::new([1u8; 48], [0u8; 48], [0u8; 48]);
        let doc = attestation_verify::build_mock_document_with_pcrs(
            &[0x11; 32],
            Some(&pk),
            Some(&digest),
            &foreign,
        )
        .unwrap();
        let err = expect_error(send(
            port,
            Req::GetClone(GetCloneRequest {
                cluster_public_key: address,
                cloning_digest: digest.to_vec(),
                encryption_pubkey: pk.to_vec(),
                requester_attestation: doc,
            }),
        ));
        assert!(err.message.contains("PCR mismatch"), "{}", err.message);
        assert!(err.message.contains("PCR0"), "{}", err.message);
    }

    #[test]
    fn get_clone_replays_are_rejected_and_the_first_reply_is_not_reusable() {
        let (port, address) = donor_with_secret("operator");
        let requester = cloning::CloneSession::new();
        let pk = requester.public_key();
        let digest = cloning::make_cloning_digest("operator", &pk);
        let req = GetCloneRequest {
            cluster_public_key: address,
            cloning_digest: digest.to_vec(),
            encryption_pubkey: pk.to_vec(),
            requester_attestation: requester_doc(&pk, Some(&digest)),
        };
        assert!(matches!(
            send(port, Req::GetClone(req.clone())).response,
            Some(Resp::GetClone(_))
        ));
        let err = expect_error(send(port, Req::GetClone(req)));
        assert!(err.message.contains("nonce replay"), "{}", err.message);
    }
}
