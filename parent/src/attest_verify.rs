//! Library half of the `attest-verify` CLI.
//!
//! Calls the parent's `AttestedPublicKey` gRPC, verifies the returned
//! attestation document end-to-end, and returns the verified bundle. The
//! binary in `bin/attest_verify.rs` is a thin wrapper that parses CLI
//! flags, calls [`verify_attested_pubkey`], and formats output.
//!
//! Exposed here so integration tests can drive the same code paths used
//! by the binary against an in-process parent + enclave stack.

use anyhow::{bail, Context, Result};
use attestation_verify::{AttestationMode, AttestedPolicy, BtcDataSource, EvmDataSource};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::grpc_proto::parent_service_client::ParentServiceClient;
use crate::grpc_proto::{AttestedPublicKeyRequest, AttestedPublicKeyResponse};

/// Whether to verify the document via the COSE/cert-chain real path or
/// the raw-CBOR mock path. Real production use MUST always pass `Real`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyMode {
    Real,
    Mock,
}

/// The security posture the caller expects the attested enclave to have.
/// The enclave commits its resolved posture into `user_data`, and the
/// verifier reconstructs the expected posture here and requires a match, so a
/// downgraded enclave is rejected.
///
/// The chain/contract/asset pins ride the wire response (which the public-key
/// bundle already binds), so stating them is optional. When the operator DOES
/// declare them via `expected_chain_id` / `expected_bridge_contract` /
/// `expected_rgb_asset_id`, the verifier checks the (authenticated) wire value
/// equals the declared one and fails otherwise — without them the reference CLI
/// authenticates whatever the enclave reports but cannot tell an operator's
/// intended deployment apart from a valid attestation of the WRONG chain,
/// contract or RGB asset (F02-AF-04). The gas-tx rule is never on the wire and
/// must always be declared here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpectedPolicy {
    /// Expect a production bridge enclave with these posture flags.
    Production {
        allow_vanilla_psbt: bool,
        evm_source: EvmDataSource,
        /// The Helios weak-subjectivity checkpoint the operator expects the
        /// enclave to have pinned. `Some` (required) when `evm_source` is
        /// [`EvmDataSource::HeliosVerified`]; folded into the reconstructed
        /// commitment so an enclave that trust-rooted on a different checkpoint
        /// fails verification.
        evm_checkpoint: Option<[u8; 32]>,
        /// Operator's intended EVM chain id. `Some` => the wire `chain_id` must
        /// equal it or verification fails; `None` => trust the wire value (legacy
        /// behaviour). Lets onboarding pin the deployment's chain via the CLI.
        expected_chain_id: Option<u64>,
        /// Operator's intended bridge/MultisigProxy contract (20 bytes). `Some`
        /// => the wire `bridge_contract` must equal it or verification fails.
        expected_bridge_contract: Option<[u8; 20]>,
        /// Operator's intended RGB asset id. `Some` => the wire `rgb_asset_id`
        /// must equal it or verification fails. An empty string pins "no RGB
        /// asset" (pure-EVM / pure-CCD builds).
        expected_rgb_asset_id: Option<String>,
        /// Expected gas-tx (`SignRawDigest`) rule the enclave committed.
        /// An all-zero destination, zero caps, and empty selectors mean
        /// the operator did not pin the gas path, which the enclave attests as
        /// such and fails closed on per request.
        gas_tx_allowed_to: [u8; 20],
        gas_tx_max_gas_limit: u64,
        gas_tx_max_fee_per_gas: u128,
        gas_tx_max_value_wei: u128,
        gas_tx_allowed_selectors: Vec<[u8; 4]>,
    },
    /// Expect a dev/mock enclave (e.g. behind `--mock`). Never for production.
    Development,
}

/// Successful verification result. The presence of this value is the
/// proof that the bridge's signing pubkey was produced inside a TEE
/// matching the supplied PCRs.
#[derive(Debug, Clone)]
pub struct AttestedPubkeyResult {
    pub response: AttestedPublicKeyResponse,
    pub verified: attestation_verify::VerifiedAttestation,
    pub bundle_commitment: [u8; 32],
    pub nonce_sent: [u8; 32],
}

/// Build the canonical key bundle that the verifier hashes to check
/// `user_data`. Field order and encoding MUST match the enclave's
/// `canonical_pubkey_bundle` in `enclave/src/server.rs`.
pub fn canonical_bundle(resp: &AttestedPublicKeyResponse) -> Vec<u8> {
    let chain_id_bytes = resp.chain_id.to_be_bytes();
    let parts: [&[u8]; 13] = [
        &resp.evm_address,
        &resp.btc_compressed_pub,
        resp.btc_xpub.as_bytes(),
        &resp.master_fingerprint,
        resp.account_xpub_vanilla.as_bytes(),
        resp.account_xpub_colored.as_bytes(),
        &resp.evm_uncompressed_pub,
        &chain_id_bytes,
        &resp.bridge_contract,
        resp.rgb_asset_id.as_bytes(),
        &resp.evm_gas_tx_uncompressed_pub,
        &resp.evm_gas_tx_address,
        &resp.ccd_ed25519_pub,
    ];
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&(p.len() as u32).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// Run the full attestation flow: connect to `endpoint`, send a fresh
/// nonce, verify the returned doc against `expected_pcrs`, and re-check
/// the embedded pubkey + commitment against the wire bundle.
///
/// Returns `Ok(_)` only if every check passes. Errors describe the
/// specific failure (gRPC connect, RPC error, parse error, signature
/// failure, PCR mismatch, nonce mismatch, pubkey mismatch, commitment
/// mismatch).
pub async fn verify_attested_pubkey(
    endpoint: &str,
    expected_pcrs: attestation_verify::ExpectedPcrs,
    mode: VerifyMode,
    expected_policy: ExpectedPolicy,
) -> Result<AttestedPubkeyResult> {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);

    let mut client = ParentServiceClient::connect(endpoint.to_string())
        .await
        .with_context(|| format!("connecting to {endpoint}"))?;

    let response = client
        .attested_public_key(AttestedPublicKeyRequest {
            nonce: nonce.to_vec(),
        })
        .await
        .context("AttestedPublicKey RPC failed")?
        .into_inner();

    let verified = match mode {
        VerifyMode::Real => attestation_verify::verify_attestation(
            &response.attestation_doc,
            &expected_pcrs,
            Some(&nonce),
        )
        .context("attestation verify failed")?,
        VerifyMode::Mock => attestation_verify::verify_mock_attestation(
            &response.attestation_doc,
            &expected_pcrs,
            Some(&nonce),
        )
        .context("mock attestation verify failed")?,
    };

    if verified.enclave_pubkey != response.evm_uncompressed_pub {
        bail!(
            "attestation `public_key` ({} bytes) does not match wire evm_uncompressed_pub ({} bytes)",
            verified.enclave_pubkey.len(),
            response.evm_uncompressed_pub.len()
        );
    }

    // The enclave commits to sha256(pubkey_bundle || policy_commitment).
    // Reconstruct the expected policy - pins from the wire response,
    // posture flags from `expected_policy` - and require the whole commitment to
    // match. A mismatch means the attested posture is not the expected one.
    let attested_policy = expected_attested_policy(&expected_policy, &response)?;
    let mut preimage = canonical_bundle(&response);
    preimage.extend_from_slice(&attested_policy.to_bytes());
    let bundle_commitment: [u8; 32] = Sha256::digest(&preimage).into();
    let user_data = verified
        .user_data
        .as_deref()
        .context("attestation has no user_data field")?;
    if user_data != bundle_commitment {
        bail!(
            "attestation `user_data` ({}) does not match sha256(canonical_bundle || policy) ({}) \
             for the expected policy {expected_policy:?} - the enclave's attested public keys or \
             security posture differ from what was expected",
            hex::encode(user_data),
            hex::encode(bundle_commitment),
        );
    }

    Ok(AttestedPubkeyResult {
        response,
        verified,
        bundle_commitment,
        nonce_sent: nonce,
    })
}

/// Build the [`AttestedPolicy`] the verifier expects the enclave to have
/// committed, combining the operator-declared posture ([`ExpectedPolicy`]) with
/// the pins from the wire response (which the pubkey bundle already binds). MUST
/// produce the same bytes the enclave's `SecurityPolicy::commitment_bytes` does.
fn expected_attested_policy(
    expected: &ExpectedPolicy,
    resp: &AttestedPublicKeyResponse,
) -> Result<AttestedPolicy> {
    match expected {
        ExpectedPolicy::Development => Ok(AttestedPolicy::Development),
        ExpectedPolicy::Production {
            allow_vanilla_psbt,
            evm_source,
            evm_checkpoint,
            expected_chain_id,
            expected_bridge_contract,
            expected_rgb_asset_id,
            gas_tx_allowed_to,
            gas_tx_max_gas_limit,
            gas_tx_max_fee_per_gas,
            gas_tx_max_value_wei,
            gas_tx_allowed_selectors,
        } => {
            let bridge_contract: [u8; 20] = resp
                .bridge_contract
                .as_slice()
                .try_into()
                .with_context(|| {
                    format!(
                        "wire bridge_contract is {} bytes, expected 20 (is this really a \
                         production bridge enclave?)",
                        resp.bridge_contract.len()
                    )
                })?;

            // Compare the operator's declared deployment pins against the
            // authenticated wire values BEFORE folding them into the expected
            // commitment. Without this, the reference CLI would happily accept a
            // valid attestation of the wrong chain / contract / asset because it
            // reconstructs the expected policy from the very values it is meant
            // to be checking (F02-AF-04).
            if let Some(want) = expected_chain_id {
                if *want != resp.chain_id {
                    bail!(
                        "chain_id mismatch: enclave attests {} but --expect-chain-id is {want}",
                        resp.chain_id
                    );
                }
            }
            if let Some(want) = expected_bridge_contract {
                if want != &bridge_contract {
                    bail!(
                        "bridge_contract mismatch: enclave attests 0x{} but \
                         --expect-bridge-contract is 0x{}",
                        hex::encode(bridge_contract),
                        hex::encode(want),
                    );
                }
            }
            if let Some(want) = expected_rgb_asset_id {
                if want != &resp.rgb_asset_id {
                    bail!(
                        "rgb_asset_id mismatch: enclave attests {:?} but --expect-rgb-asset-id is {want:?}",
                        resp.rgb_asset_id
                    );
                }
            }

            Ok(AttestedPolicy::Production {
                allow_vanilla_psbt: *allow_vanilla_psbt,
                // A real-verified production enclave always uses real (NSM)
                // attestation; SPV is the only Bitcoin anchor source.
                attestation: AttestationMode::Real,
                evm_source: *evm_source,
                btc_source: BtcDataSource::SpvVerified,
                chain_id: resp.chain_id,
                bridge_contract,
                rgb_asset_id: resp.rgb_asset_id.clone(),
                evm_checkpoint: *evm_checkpoint,
                // Gas-tx rule: declared by the operator, not on the
                // wire. `to_bytes` canonicalises the selector set, so the caller
                // need not pre-sort it.
                gas_tx_allowed_to: *gas_tx_allowed_to,
                gas_tx_max_gas_limit: *gas_tx_max_gas_limit,
                gas_tx_max_fee_per_gas: *gas_tx_max_fee_per_gas,
                gas_tx_max_value_wei: *gas_tx_max_value_wei,
                gas_tx_allowed_selectors: gas_tx_allowed_selectors.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A production expectation with the three deployment pins set to `pins`
    /// (chain_id, bridge_contract, rgb_asset_id) and everything else neutral.
    fn expect_prod(
        chain_id: Option<u64>,
        bridge_contract: Option<[u8; 20]>,
        rgb_asset_id: Option<String>,
    ) -> ExpectedPolicy {
        ExpectedPolicy::Production {
            allow_vanilla_psbt: false,
            evm_source: EvmDataSource::RawRpc,
            evm_checkpoint: None,
            expected_chain_id: chain_id,
            expected_bridge_contract: bridge_contract,
            expected_rgb_asset_id: rgb_asset_id,
            gas_tx_allowed_to: [0u8; 20],
            gas_tx_max_gas_limit: 0,
            gas_tx_max_fee_per_gas: 0,
            gas_tx_max_value_wei: 0,
            gas_tx_allowed_selectors: Vec::new(),
        }
    }

    /// A wire response pinned to chain 42161, contract 0x11.., asset "rgb:abc".
    fn wire() -> AttestedPublicKeyResponse {
        AttestedPublicKeyResponse {
            chain_id: 42161,
            bridge_contract: vec![0x11u8; 20],
            rgb_asset_id: "rgb:abc".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn unset_pins_trust_the_wire() {
        // Legacy behaviour: no operator pins => accept whatever the enclave
        // attests (still authenticated, just not compared).
        let got = expected_attested_policy(&expect_prod(None, None, None), &wire())
            .expect("unset pins must not reject");
        match got {
            AttestedPolicy::Production {
                chain_id,
                rgb_asset_id,
                ..
            } => {
                assert_eq!(chain_id, 42161);
                assert_eq!(rgb_asset_id, "rgb:abc");
            }
            AttestedPolicy::Development => panic!("expected production policy"),
        }
    }

    #[test]
    fn matching_pins_are_accepted() {
        let exp = expect_prod(Some(42161), Some([0x11u8; 20]), Some("rgb:abc".into()));
        assert!(expected_attested_policy(&exp, &wire()).is_ok());
    }

    #[test]
    fn wrong_chain_id_is_rejected() {
        let exp = expect_prod(Some(1), None, None);
        let err = expected_attested_policy(&exp, &wire()).expect_err("wrong chain must fail");
        assert!(format!("{err:#}").contains("chain_id mismatch"));
    }

    #[test]
    fn wrong_bridge_contract_is_rejected() {
        let exp = expect_prod(None, Some([0x22u8; 20]), None);
        let err = expected_attested_policy(&exp, &wire()).expect_err("wrong contract must fail");
        assert!(format!("{err:#}").contains("bridge_contract mismatch"));
    }

    #[test]
    fn wrong_rgb_asset_is_rejected() {
        let exp = expect_prod(None, None, Some("rgb:other".into()));
        let err = expected_attested_policy(&exp, &wire()).expect_err("wrong asset must fail");
        assert!(format!("{err:#}").contains("rgb_asset_id mismatch"));
    }

    #[test]
    fn empty_asset_pin_matches_empty_wire() {
        // A pure-EVM / pure-CCD build ships no RGB asset; pinning "" must match.
        let mut w = wire();
        w.rgb_asset_id = String::new();
        let exp = expect_prod(None, None, Some(String::new()));
        assert!(expected_attested_policy(&exp, &w).is_ok());
    }
}
