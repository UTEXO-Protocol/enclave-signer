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
/// Chain/contract/asset pins come from the wire response, which the public-key
/// bundle already binds, so a production expectation states only the posture
/// flags plus the gas-tx rule - the latter is not on the wire and must be
/// declared here.
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

    fn resp() -> AttestedPublicKeyResponse {
        AttestedPublicKeyResponse {
            evm_address: vec![0x01; 20],
            evm_uncompressed_pub: vec![0x02; 64],
            btc_compressed_pub: vec![0x03; 33],
            btc_xpub: "xpub".into(),
            master_fingerprint: vec![0x04; 4],
            account_xpub_vanilla: "tpubV".into(),
            account_xpub_colored: "tpubC".into(),
            attestation_doc: vec![0xAA; 10],
            chain_id: 0x0102_0304_0506_0708,
            bridge_contract: vec![0x05; 20],
            rgb_asset_id: "rgb:asset".into(),
            evm_gas_tx_uncompressed_pub: vec![0x06; 64],
            evm_gas_tx_address: vec![0x07; 20],
            ccd_ed25519_pub: vec![0x08; 32],
        }
    }

    fn production() -> ExpectedPolicy {
        ExpectedPolicy::Production {
            allow_vanilla_psbt: true,
            evm_source: EvmDataSource::HeliosVerified,
            evm_checkpoint: Some([0x42; 32]),
            gas_tx_allowed_to: [0x11; 20],
            gas_tx_max_gas_limit: 21_000,
            gas_tx_max_fee_per_gas: 5,
            gas_tx_max_value_wei: 6,
            gas_tx_allowed_selectors: vec![[9, 9, 9, 9], [1, 1, 1, 1]],
        }
    }

    /// Split a bundle back into its `[len u32 BE][bytes]` parts.
    fn parts(bundle: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < bundle.len() {
            let len = u32::from_be_bytes(bundle[i..i + 4].try_into().unwrap()) as usize;
            i += 4;
            out.push(bundle[i..i + len].to_vec());
            i += len;
        }
        out
    }

    #[test]
    fn canonical_bundle_is_thirteen_length_prefixed_parts_in_wire_order() {
        let r = resp();
        let p = parts(&canonical_bundle(&r));
        assert_eq!(p.len(), 13);
        assert_eq!(p[0], r.evm_address);
        assert_eq!(p[1], r.btc_compressed_pub);
        assert_eq!(p[2], r.btc_xpub.as_bytes());
        assert_eq!(p[3], r.master_fingerprint);
        assert_eq!(p[4], r.account_xpub_vanilla.as_bytes());
        assert_eq!(p[5], r.account_xpub_colored.as_bytes());
        assert_eq!(p[6], r.evm_uncompressed_pub);
        assert_eq!(p[7], 0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(p[8], r.bridge_contract);
        assert_eq!(p[9], r.rgb_asset_id.as_bytes());
        assert_eq!(p[10], r.evm_gas_tx_uncompressed_pub);
        assert_eq!(p[11], r.evm_gas_tx_address);
        assert_eq!(p[12], r.ccd_ed25519_pub);

        // The attestation document carries the commitment; it is not part of
        // what is committed.
        let mut other = r.clone();
        other.attestation_doc = vec![0xBB; 3];
        assert_eq!(canonical_bundle(&other), canonical_bundle(&r));
    }

    #[test]
    fn canonical_bundle_length_prefixes_defeat_boundary_shifts() {
        // "ab" + "c" and "a" + "bc" collide under plain concatenation.
        let mut a = resp();
        a.account_xpub_vanilla = "ab".into();
        a.account_xpub_colored = "c".into();
        let mut b = resp();
        b.account_xpub_vanilla = "a".into();
        b.account_xpub_colored = "bc".into();
        assert_ne!(canonical_bundle(&a), canonical_bundle(&b));

        // An empty part still occupies its 4-byte zero prefix.
        let mut e = resp();
        e.rgb_asset_id = String::new();
        let p = parts(&canonical_bundle(&e));
        assert_eq!(p.len(), 13);
        assert!(p[9].is_empty());
    }

    #[test]
    fn every_committed_field_changes_the_bundle() {
        let base = canonical_bundle(&resp());
        type Mutation = fn(&mut AttestedPublicKeyResponse);
        let mutations: Vec<(&str, Mutation)> = vec![
            ("evm_address", |r| r.evm_address[0] ^= 1),
            ("btc_compressed_pub", |r| r.btc_compressed_pub[0] ^= 1),
            ("btc_xpub", |r| r.btc_xpub.push('!')),
            ("master_fingerprint", |r| r.master_fingerprint[0] ^= 1),
            ("account_xpub_vanilla", |r| r.account_xpub_vanilla.push('!')),
            ("account_xpub_colored", |r| r.account_xpub_colored.push('!')),
            ("evm_uncompressed_pub", |r| r.evm_uncompressed_pub[0] ^= 1),
            ("chain_id", |r| r.chain_id ^= 1),
            ("bridge_contract", |r| r.bridge_contract[0] ^= 1),
            ("rgb_asset_id", |r| r.rgb_asset_id.push('!')),
            ("evm_gas_tx_uncompressed_pub", |r| {
                r.evm_gas_tx_uncompressed_pub[0] ^= 1
            }),
            ("evm_gas_tx_address", |r| r.evm_gas_tx_address[0] ^= 1),
            ("ccd_ed25519_pub", |r| r.ccd_ed25519_pub[0] ^= 1),
        ];
        for (name, mutate) in mutations {
            let mut r = resp();
            mutate(&mut r);
            assert_ne!(canonical_bundle(&r), base, "{name} must be committed");
        }
    }

    #[test]
    fn development_expectation_ignores_the_wire_pins() {
        let mut r = resp();
        r.bridge_contract = Vec::new();
        assert_eq!(
            expected_attested_policy(&ExpectedPolicy::Development, &r).unwrap(),
            AttestedPolicy::Development
        );
    }

    #[test]
    fn production_expectation_takes_pins_from_the_wire_and_posture_from_the_caller() {
        let r = resp();
        match expected_attested_policy(&production(), &r).unwrap() {
            AttestedPolicy::Production {
                allow_vanilla_psbt,
                attestation,
                evm_source,
                btc_source,
                chain_id,
                bridge_contract,
                rgb_asset_id,
                evm_checkpoint,
                gas_tx_allowed_to,
                gas_tx_max_gas_limit,
                gas_tx_max_fee_per_gas,
                gas_tx_max_value_wei,
                gas_tx_allowed_selectors,
            } => {
                assert!(allow_vanilla_psbt);
                assert_eq!(attestation, AttestationMode::Real);
                assert_eq!(evm_source, EvmDataSource::HeliosVerified);
                assert_eq!(btc_source, BtcDataSource::SpvVerified);
                assert_eq!(chain_id, r.chain_id);
                assert_eq!(bridge_contract, [0x05; 20]);
                assert_eq!(rgb_asset_id, "rgb:asset");
                assert_eq!(evm_checkpoint, Some([0x42; 32]));
                assert_eq!(gas_tx_allowed_to, [0x11; 20]);
                assert_eq!(gas_tx_max_gas_limit, 21_000);
                assert_eq!(gas_tx_max_fee_per_gas, 5);
                assert_eq!(gas_tx_max_value_wei, 6);
                // Forwarded as declared; `to_bytes` canonicalises the set.
                assert_eq!(gas_tx_allowed_selectors, vec![[9, 9, 9, 9], [1, 1, 1, 1]]);
            }
            AttestedPolicy::Development => panic!("expected a production policy"),
        }
    }

    #[test]
    fn production_expectation_rejects_a_bridge_contract_that_is_not_20_bytes() {
        for len in [0usize, 19, 21, 32] {
            let mut r = resp();
            r.bridge_contract = vec![0x05; len];
            let err = expected_attested_policy(&production(), &r).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains(&format!("wire bridge_contract is {len} bytes, expected 20")),
                "{msg}"
            );
        }
    }

    #[test]
    fn selector_order_does_not_change_the_committed_policy() {
        let r = resp();
        let a = expected_attested_policy(&production(), &r).unwrap();
        let swapped = match production() {
            ExpectedPolicy::Production {
                allow_vanilla_psbt,
                evm_source,
                evm_checkpoint,
                gas_tx_allowed_to,
                gas_tx_max_gas_limit,
                gas_tx_max_fee_per_gas,
                gas_tx_max_value_wei,
                gas_tx_allowed_selectors,
            } => ExpectedPolicy::Production {
                allow_vanilla_psbt,
                evm_source,
                evm_checkpoint,
                gas_tx_allowed_to,
                gas_tx_max_gas_limit,
                gas_tx_max_fee_per_gas,
                gas_tx_max_value_wei,
                gas_tx_allowed_selectors: gas_tx_allowed_selectors.into_iter().rev().collect(),
            },
            ExpectedPolicy::Development => unreachable!(),
        };
        let b = expected_attested_policy(&swapped, &r).unwrap();
        assert_ne!(a, b, "the declared order is kept on the value");
        assert_eq!(a.to_bytes(), b.to_bytes(), "but not in the commitment");
    }

    #[test]
    fn a_different_posture_commits_to_different_bytes() {
        let r = resp();
        let helios = expected_attested_policy(&production(), &r).unwrap();
        let raw = ExpectedPolicy::Production {
            allow_vanilla_psbt: false,
            evm_source: EvmDataSource::RawRpc,
            evm_checkpoint: None,
            gas_tx_allowed_to: [0u8; 20],
            gas_tx_max_gas_limit: 0,
            gas_tx_max_fee_per_gas: 0,
            gas_tx_max_value_wei: 0,
            gas_tx_allowed_selectors: Vec::new(),
        };
        let raw = expected_attested_policy(&raw, &r).unwrap();
        assert_ne!(helios.to_bytes(), raw.to_bytes());
        assert_ne!(raw.to_bytes(), AttestedPolicy::Development.to_bytes());
    }

    #[test]
    fn expectation_types_compare_and_clone() {
        assert_eq!(VerifyMode::Real, VerifyMode::Real);
        assert_ne!(VerifyMode::Real, VerifyMode::Mock);
        let p = production();
        assert_eq!(p.clone(), p);
        assert_ne!(p, ExpectedPolicy::Development);
        assert!(format!("{p:?}").contains("Production"));
    }
}
