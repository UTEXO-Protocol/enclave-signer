//! A mint signer never releases and a burn signer never mints. Each image
//! refuses the other direction's requests before any key or network work, so
//! these run against an uninitialized enclave.
#![cfg(any(feature = "mint-signer", feature = "burn-signer"))]

mod common;

use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::sign_request::{DestinationNetwork, SourceNetwork};
use utexo_bridge_enclave::proto::*;

/// The role refusal message for `req`, or a panic naming what came back.
fn refusal(req: Request) -> String {
    let port = common::start_test_server();
    let resp = common::send_request(port, &EnclaveRequest { request: Some(req) });
    match resp.response {
        Some(Response::Error(e)) => e.message,
        other => panic!("expected a role refusal, got {other:?}"),
    }
}

/// EVM lock -> RGB mint PSBT.
fn mint_request() -> Request {
    Request::Sign(SignRequest {
        amount: 1_000,
        source_network: Some(SourceNetwork::EvmSource(EvmSource::default())),
        destination_network: Some(DestinationNetwork::RgbDestination(RgbDestination::default())),
    })
}

/// RGB burn -> EVM `fundsOut` release.
fn release_request() -> Request {
    Request::Sign(SignRequest {
        amount: 1_000,
        source_network: Some(SourceNetwork::RgbSource(RgbSource::default())),
        destination_network: Some(DestinationNetwork::EvmDestination(EvmDestination::default())),
    })
}

#[cfg(feature = "mint-signer")]
mod mint_signer {
    use super::*;

    #[test]
    fn refuses_a_funds_out_release() {
        let msg = refusal(release_request());
        assert!(msg.contains("mint signer"), "{msg}");
        assert!(msg.contains("RGB -> EVM"), "{msg}");
    }

    #[test]
    fn refuses_an_evm_gas_tx() {
        let msg = refusal(Request::SignRawDigest(SignRawDigestRequest::default()));
        assert!(msg.contains("mint signer"), "{msg}");
        assert!(msg.contains("gas"), "{msg}");
    }

    /// The refusal is about direction: a mint request is not refused as
    /// the wrong role (it fails later, on the uninitialized key).
    #[test]
    fn does_not_refuse_a_mint_as_the_wrong_role() {
        let msg = refusal(mint_request());
        assert!(!msg.contains("mint signer"), "{msg}");
    }
}

#[cfg(feature = "burn-signer")]
mod burn_signer {
    use super::*;

    #[test]
    fn refuses_a_mint_psbt() {
        let msg = refusal(mint_request());
        assert!(msg.contains("burn signer"), "{msg}");
        assert!(msg.contains("EVM -> RGB"), "{msg}");
    }

    #[test]
    fn refuses_a_plain_btc_psbt() {
        let msg = refusal(Request::SignBtc(SignBtcRequest::default()));
        assert!(msg.contains("burn signer"), "{msg}");
        assert!(msg.contains("plain-BTC"), "{msg}");
    }

    /// The refusal is about direction: a release is not refused as the
    /// wrong role (it fails later, in validation).
    #[test]
    fn does_not_refuse_a_release_as_the_wrong_role() {
        let msg = refusal(release_request());
        assert!(!msg.contains("burn signer"), "{msg}");
    }
}
