//! Coverage for the host-side `EnclaveClient`: every request it can build,
//! every way the enclave can answer, and every transport failure.
//!
//! The client speaks TCP here, which a vsock build refuses by design.
#![cfg(not(all(feature = "vsock", target_os = "linux")))]

mod common;

use std::sync::Arc;

use common::{
    dead_port, error_response, msg, response, start_enclave, start_enclave_replying, Reply,
};
use utexo_bridge_parent::client::{EnclaveClient, SignEvmRequest, SignPsbtRequest};
use utexo_bridge_parent::enclave_proto::{
    enclave_request, enclave_response, EvmSignatureResponse, GetLastSavedBlockResponse,
    InitializeKeyResponse, InitiateCloningResponse, LzReleaseParams, MerkleProofEntry,
    PublicKeysResponse, SetCloneResponse, SignedPsbtResponse, SubmitHeadersResponse,
};
use utexo_bridge_parent::error::ParentError;

fn client(port: u16) -> EnclaveClient {
    EnclaveClient::new(&format!("127.0.0.1:{port}"))
}

fn keys() -> PublicKeysResponse {
    PublicKeysResponse {
        evm_address: vec![0xAA; 20],
        btc_compressed_pub: vec![0xBB; 33],
        btc_xpub: "xpub".into(),
        master_fingerprint: vec![0xDD; 4],
        account_xpub_vanilla: "v".into(),
        account_xpub_colored: "c".into(),
        evm_uncompressed_pub: vec![0xEE; 64],
        chain_id: 1,
        bridge_contract: vec![0x01; 20],
        rgb_asset_id: "rgb:x".into(),
        evm_gas_tx_uncompressed_pub: vec![0xFF; 64],
        evm_gas_tx_address: vec![0xFA; 20],
        ccd_ed25519_pub: vec![0x99; 32],
    }
}

fn init_keys() -> InitializeKeyResponse {
    InitializeKeyResponse {
        evm_address: vec![0xAA; 20],
        btc_compressed_pub: vec![0xBB; 33],
        btc_xpub: "xpub".into(),
        master_fingerprint: vec![0xDD; 4],
        account_xpub_vanilla: "v".into(),
        account_xpub_colored: "c".into(),
        evm_uncompressed_pub: vec![0xEE; 64],
        chain_id: 1,
        bridge_contract: vec![0x01; 20],
        rgb_asset_id: "rgb:x".into(),
        evm_gas_tx_uncompressed_pub: vec![0xFF; 64],
        evm_gas_tx_address: vec![0xFA; 20],
        ccd_ed25519_pub: vec![0x99; 32],
    }
}

fn sign_evm_req() -> SignEvmRequest {
    SignEvmRequest {
        call_data: vec![0xAB; 4],
        nonce: 1,
        deadline: 2,
        consignment_valid: true,
        rgb_amount: 100,
        rgb_asset_id: "rgb:asset".into(),
        chain_id: 3,
        proxy_contract: vec![0x04; 20],
        calldata_amount: 95,
        calldata_commission: 5,
        consignment: vec![0xC0; 3],
        consignment_hash: vec![0xC1; 32],
        merkle_proofs: vec![MerkleProofEntry {
            txid: vec![0x1D; 32],
            block_height: 200,
            tx_position: 3,
            merkle_path: vec![vec![0x2A; 32]],
        }],
        lz_release: Some(LzReleaseParams {
            dst_eid: 30101,
            min_amount_ld: 90,
            recipient: vec![0x13; 32],
        }),
    }
}

fn sign_psbt_req() -> SignPsbtRequest {
    SignPsbtRequest {
        evm_tx_hash: vec![0xAA; 32],
        evm_funds_in_operation_id: vec![0x33; 32],
        operation_idx: 9,
        evm_event_valid: true,
        evm_event_finalized: false,
        evm_token: vec![0x11; 20],
        evm_amount: 100,
        evm_recipient: b"utxob:seal".to_vec(),
        evm_commission: 5,
        psbt_bytes: vec![0x70; 8],
        psbt_output_amount: 95,
        rgb_asset_id: "rgb:asset".into(),
        consignment: vec![0xC0; 3],
        consignment_hash: vec![0xC1; 32],
    }
}

type Call = Box<dyn Fn(&EnclaveClient) -> Result<(), ParentError>>;

/// Every client entry point, so the error-path tests can sweep them all.
fn all_calls() -> Vec<(&'static str, Call)> {
    vec![
        (
            "initialize_keys",
            Box::new(|c| c.initialize_keys(None).map(|_| ())),
        ),
        (
            "initialize_keys_with_secret",
            Box::new(|c| c.initialize_keys_with_secret(None, None).map(|_| ())),
        ),
        (
            "initialize_keys_mnemonic",
            Box::new(|c| c.initialize_keys_mnemonic("w").map(|_| ())),
        ),
        (
            "initiate_cloning",
            Box::new(|c| c.initiate_cloning("s", vec![0; 20]).map(|_| ())),
        ),
        (
            "set_clone",
            Box::new(|c| c.set_clone(vec![1], vec![2], vec![3])),
        ),
        (
            "get_public_keys",
            Box::new(|c| c.get_public_keys().map(|_| ())),
        ),
        (
            "sign_evm",
            Box::new(|c| c.sign_evm(sign_evm_req()).map(|_| ())),
        ),
        (
            "sign_psbt",
            Box::new(|c| c.sign_psbt(sign_psbt_req()).map(|_| ())),
        ),
        (
            "get_last_saved_block",
            Box::new(|c| c.get_last_saved_block().map(|_| ())),
        ),
        (
            "submit_headers",
            Box::new(|c| c.submit_headers(1, vec![vec![0; 80]]).map(|_| ())),
        ),
    ]
}

#[test]
fn connection_refused_is_a_connection_error() {
    let c = client(dead_port());
    for (name, call) in all_calls() {
        let err = call(&c).expect_err(name);
        assert!(matches!(err, ParentError::Connection(_)), "{name}: {err}");
    }
}

#[test]
fn unparseable_address_is_a_connection_error_naming_resolution() {
    let c = EnclaveClient::new("");
    let err = c.get_public_keys().unwrap_err();
    match err {
        ParentError::Connection(m) => assert!(m.starts_with("resolve "), "{m}"),
        other => panic!("unexpected {other}"),
    }
}

#[cfg(not(all(feature = "vsock", target_os = "linux")))]
#[test]
fn vsock_address_is_refused_when_vsock_is_not_compiled_in() {
    let c = EnclaveClient::new("vsock://16:5000");
    let err = c.get_public_keys().unwrap_err();
    match err {
        ParentError::Connection(m) => {
            assert!(m.contains("vsock://16:5000"), "{m}");
            assert!(m.contains("built without vsock support"), "{m}");
        }
        other => panic!("unexpected {other}"),
    }
}

#[test]
fn hangup_without_a_reply_is_an_io_error() {
    let (port, _rx) = start_enclave(Arc::new(|_| Reply::Hangup));
    let err = client(port).get_public_keys().unwrap_err();
    assert!(matches!(err, ParentError::Io(_)), "{err}");
}

#[test]
fn zero_length_reply_frame_is_a_framing_error() {
    let (port, _rx) = start_enclave(Arc::new(|_| Reply::Raw(vec![0, 0, 0, 0])));
    let err = client(port).get_public_keys().unwrap_err();
    assert!(matches!(err, ParentError::Framing(_)), "{err}");
}

#[test]
fn malformed_reply_body_is_a_decode_error() {
    let (port, _rx) = start_enclave(Arc::new(|_| {
        Reply::Raw(vec![4, 0, 0, 0, 0xff, 0xff, 0xff, 0xff])
    }));
    let err = client(port).get_public_keys().unwrap_err();
    assert!(matches!(err, ParentError::ProtobufDecode(_)), "{err}");
}

#[test]
fn enclave_error_response_maps_to_enclave_error_for_every_call() {
    let (port, _rx) = start_enclave_replying(error_response(3, "nope"));
    let c = client(port);
    for (name, call) in all_calls() {
        match call(&c).expect_err(name) {
            ParentError::EnclaveError { code, message } => {
                assert_eq!((code, message.as_str()), (3, "nope"), "{name}");
            }
            other => panic!("{name}: unexpected {other}"),
        }
    }
}

#[test]
fn unexpected_response_variant_is_a_connection_error_for_every_call() {
    // A CCD signature is the answer to none of the client's requests.
    let (port, _rx) = start_enclave_replying(response(enclave_response::Response::CcdSignature(
        Default::default(),
    )));
    let c = client(port);
    for (name, call) in all_calls() {
        match call(&c).expect_err(name) {
            ParentError::Connection(m) => {
                assert!(
                    m.starts_with("unexpected response variant: "),
                    "{name}: {m}"
                )
            }
            other => panic!("{name}: unexpected {other}"),
        }
    }
}

#[test]
fn empty_response_cannot_even_be_framed() {
    // An `EnclaveResponse` with no variant encodes to zero bytes, which the
    // wire format refuses outright.
    let (port, _rx) = start_enclave_replying(Default::default());
    let err = client(port).get_last_saved_block().unwrap_err();
    match err {
        ParentError::Framing(m) => assert_eq!(m, "zero-length message"),
        other => panic!("unexpected {other}"),
    }
}

#[test]
fn initialize_variants_populate_exactly_one_field() {
    let (port, rx) = start_enclave_replying(response(enclave_response::Response::InitializeKey(
        init_keys(),
    )));
    let c = client(port);

    let r = c.initialize_keys(Some(vec![0x5E; 64])).unwrap();
    assert_eq!(r.btc_compressed_pub, vec![0xBB; 33]);
    match rx.recv().unwrap().request {
        Some(enclave_request::Request::InitializeKey(k)) => {
            assert_eq!(k.seed, vec![0x5E; 64]);
            assert!(k.mnemonic.is_empty());
            assert!(k.cloning_secret.is_empty());
        }
        other => panic!("unexpected {other:?}"),
    }

    c.initialize_keys(None).unwrap();
    match rx.recv().unwrap().request {
        Some(enclave_request::Request::InitializeKey(k)) => {
            assert!(k.seed.is_empty() && k.mnemonic.is_empty() && k.cloning_secret.is_empty());
        }
        other => panic!("unexpected {other:?}"),
    }

    c.initialize_keys_with_secret(Some(vec![1; 64]), Some("hunter2".into()))
        .unwrap();
    match rx.recv().unwrap().request {
        Some(enclave_request::Request::InitializeKey(k)) => {
            assert_eq!(k.seed, vec![1; 64]);
            assert!(k.mnemonic.is_empty());
            assert_eq!(k.cloning_secret, "hunter2");
        }
        other => panic!("unexpected {other:?}"),
    }

    c.initialize_keys_mnemonic("abandon abandon about").unwrap();
    match rx.recv().unwrap().request {
        Some(enclave_request::Request::InitializeKey(k)) => {
            assert!(k.seed.is_empty());
            assert_eq!(k.mnemonic, "abandon abandon about");
            assert!(k.cloning_secret.is_empty());
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn cloning_calls_forward_their_arguments() {
    let (port, rx) = start_enclave(Arc::new(|req| match req.request {
        Some(enclave_request::Request::InitiateCloning(_)) => msg(response(
            enclave_response::Response::InitiateCloning(InitiateCloningResponse {
                requester_attestation: vec![0xA7; 5],
                encryption_pubkey: vec![0xE1; 32],
                cloning_digest: vec![0xD1; 32],
            }),
        )),
        Some(enclave_request::Request::SetClone(_)) => msg(response(
            enclave_response::Response::SetClone(SetCloneResponse {}),
        )),
        _ => msg(error_response(1, "unexpected")),
    }));
    let c = client(port);

    let r = c.initiate_cloning("secret", vec![0xC1; 20]).unwrap();
    assert_eq!(r.encryption_pubkey, vec![0xE1; 32]);
    assert_eq!(r.cloning_digest, vec![0xD1; 32]);
    assert_eq!(r.requester_attestation, vec![0xA7; 5]);
    match rx.recv().unwrap().request {
        Some(enclave_request::Request::InitiateCloning(i)) => {
            assert_eq!(i.cloning_secret, "secret");
            assert_eq!(i.cluster_public_key, vec![0xC1; 20]);
        }
        other => panic!("unexpected {other:?}"),
    }

    c.set_clone(vec![1, 1], vec![2, 2], vec![3, 3]).unwrap();
    match rx.recv().unwrap().request {
        Some(enclave_request::Request::SetClone(s)) => {
            assert_eq!(s.encrypted_seed, vec![1, 1]);
            assert_eq!(s.donor_pubkey, vec![2, 2]);
            assert_eq!(s.donor_attestation, vec![3, 3]);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn get_public_keys_returns_the_bundle_verbatim() {
    let (port, rx) =
        start_enclave_replying(response(enclave_response::Response::PublicKeys(keys())));
    let r = client(port).get_public_keys().unwrap();
    assert_eq!(r, keys());
    assert!(matches!(
        rx.recv().unwrap().request,
        Some(enclave_request::Request::GetPublicKey(_))
    ));
}

#[test]
fn sign_evm_builds_an_rgb_to_evm_request_without_ancestors() {
    let (port, rx) = start_enclave_replying(response(enclave_response::Response::EvmSignature(
        EvmSignatureResponse {
            signature: vec![0xCC; 65],
            call_data: vec![0xE0; 9],
        },
    )));
    let r = client(port).sign_evm(sign_evm_req()).unwrap();
    assert_eq!(r.signature, vec![0xCC; 65]);
    assert_eq!(r.call_data, vec![0xE0; 9]);

    let sent = match rx.recv().unwrap().request {
        Some(enclave_request::Request::Sign(s)) => s,
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(sent.amount, 100);
    match sent.source_network.unwrap() {
        utexo_bridge_parent::enclave_proto::sign_request::SourceNetwork::RgbSource(s) => {
            assert!(s.consignment_valid);
            assert_eq!(s.asset_id, "rgb:asset");
            assert_eq!(s.consignment, vec![0xC0; 3]);
            assert_eq!(s.consignment_hash, vec![0xC1; 32]);
            // The CLI has no separate source commission: the calldata one is used.
            assert_eq!(s.commission, 5);
            assert_eq!(s.merkle_proofs.len(), 1);
            assert_eq!(s.merkle_proofs[0].block_height, 200);
            assert!(
                s.mint_ancestors.is_empty(),
                "the CLI cannot resolve ancestors"
            );
        }
        other => panic!("unexpected {other:?}"),
    }
    match sent.destination_network.unwrap() {
        utexo_bridge_parent::enclave_proto::sign_request::DestinationNetwork::EvmDestination(d) => {
            assert_eq!(d.call_data, vec![0xAB; 4]);
            assert_eq!(d.nonce, 1);
            assert_eq!(d.deadline, 2);
            assert_eq!(d.chain_id, 3);
            assert_eq!(d.proxy_contract, vec![0x04; 20]);
            assert_eq!(d.calldata_amount, 95);
            assert_eq!(d.calldata_commission, 5);
            let lr = d.lz_release.expect("lz release forwarded");
            assert_eq!((lr.dst_eid, lr.min_amount_ld), (30101, 90));
            assert_eq!(lr.recipient, vec![0x13; 32]);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn sign_psbt_builds_an_evm_to_rgb_request_without_ancestors() {
    let (port, rx) = start_enclave_replying(response(enclave_response::Response::SignedPsbt(
        SignedPsbtResponse {
            signed_psbt: vec![0xDD; 10],
            inputs_signed: 2,
        },
    )));
    let r = client(port).sign_psbt(sign_psbt_req()).unwrap();
    assert_eq!(r.signed_psbt, vec![0xDD; 10]);
    assert_eq!(r.inputs_signed, 2);

    let sent = match rx.recv().unwrap().request {
        Some(enclave_request::Request::Sign(s)) => s,
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(sent.amount, 100);
    match sent.source_network.unwrap() {
        utexo_bridge_parent::enclave_proto::sign_request::SourceNetwork::EvmSource(s) => {
            assert_eq!(s.tx_hash, vec![0xAA; 32]);
            assert!(s.event_valid);
            assert!(!s.event_finalized);
            assert_eq!(s.token, vec![0x11; 20]);
            assert_eq!(s.recipient, b"utxob:seal".to_vec());
            assert_eq!(s.commission, 5);
            assert_eq!(s.funds_in_operation_id, vec![0x33; 32]);
        }
        other => panic!("unexpected {other:?}"),
    }
    match sent.destination_network.unwrap() {
        utexo_bridge_parent::enclave_proto::sign_request::DestinationNetwork::RgbDestination(d) => {
            assert_eq!(d.operation_idx, 9);
            assert_eq!(d.psbt_bytes, vec![0x70; 8]);
            assert_eq!(d.psbt_output_amount, 95);
            assert_eq!(d.asset_id, "rgb:asset");
            assert_eq!(d.consignment, vec![0xC0; 3]);
            assert_eq!(d.consignment_hash, vec![0xC1; 32]);
            assert!(d.mint_ancestors.is_empty());
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn header_chain_calls_forward_and_return_verbatim() {
    let (port, rx) = start_enclave(Arc::new(|req| match req.request {
        Some(enclave_request::Request::GetLastSavedBlock(_)) => msg(response(
            enclave_response::Response::GetLastSavedBlock(GetLastSavedBlockResponse {
                block_height: 215_000,
                block_hash: vec![0x11; 32],
            }),
        )),
        Some(enclave_request::Request::SubmitHeaders(s)) => msg(response(
            enclave_response::Response::SubmitHeaders(SubmitHeadersResponse {
                last_block_height: s.start_height + s.headers.len() as u32 - 1,
                last_block_hash: vec![0x22; 32],
                headers_accepted: s.headers.len() as u32,
            }),
        )),
        _ => msg(error_response(1, "unexpected")),
    }));
    let c = client(port);

    let r = c.get_last_saved_block().unwrap();
    assert_eq!((r.block_height, r.block_hash), (215_000, vec![0x11; 32]));
    rx.recv().unwrap();

    let r = c
        .submit_headers(215_001, vec![vec![0xAB; 80], vec![0xCD; 80]])
        .unwrap();
    assert_eq!(r.last_block_height, 215_002);
    assert_eq!(r.headers_accepted, 2);
    match rx.recv().unwrap().request {
        Some(enclave_request::Request::SubmitHeaders(s)) => {
            assert_eq!(s.start_height, 215_001);
            assert_eq!(s.headers, vec![vec![0xAB; 80], vec![0xCD; 80]]);
        }
        other => panic!("unexpected {other:?}"),
    }
}
