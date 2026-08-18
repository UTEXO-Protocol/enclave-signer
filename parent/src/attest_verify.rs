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

/// The security posture the caller expects the attested enclave to have (audit
/// C-01). The enclave commits its resolved posture into `user_data`, and the
/// verifier reconstructs the expected posture here and requires a match, so a
/// downgraded enclave is rejected.
///
/// Chain/contract/asset pins come from the wire response, which the public-key
/// bundle already binds, so a production expectation states only the posture
/// flags plus the gas-tx rule - the latter is not on the wire and must be
/// declared here (audit C-02).
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
        /// fails verification (audit M-06).
        evm_checkpoint: Option<[u8; 32]>,
        /// Expected gas-tx (`SignRawDigest`) rule the enclave committed (audit
        /// C-02). An all-zero destination, zero caps, and empty selectors mean
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

    // The enclave commits to sha256(pubkey_bundle || policy_commitment) (audit
    // C-01). Reconstruct the expected policy - pins from the wire response,
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
             for the expected policy {expected_policy:?} — the enclave's attested public keys or \
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
                // Gas-tx rule (audit C-02): declared by the operator, not on the
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
