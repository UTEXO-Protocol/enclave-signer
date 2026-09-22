//! Key lifecycle requests: `InitializeKey`, `GetPublicKey`, and the attested
//! variant.
//!
//! [`canonical_pubkey_bundle`] is the enclave half of a two-sided contract:
//! the parent's `attest_verify.rs::canonical_bundle` must hash the same bytes
//! in the same order, or every attestation check fails.

use super::context::ServerContext;
use crate::config::BridgeConfig;
use crate::error::{EnclaveError, Result};
use crate::proto::enclave_response::Response;
use crate::proto::*;

pub(super) fn handle_initialize(
    ctx: &ServerContext,
    req: InitializeKeyRequest,
    _deadline: std::time::Instant,
) -> Result<EnclaveResponse> {
    let state = &ctx.state;
    #[cfg(feature = "kms-persistence")]
    if !req.cloning_secret.is_empty() {
        return Err(EnclaveError::InvalidRequest(
            "cloning_secret is not supported with KMS persistence".into(),
        ));
    }
    if !req.mnemonic.is_empty() {
        // Testing path: import from BIP-39 mnemonic phrase
        #[cfg(feature = "allow-seed-import")]
        {
            state.initialize_from_mnemonic(&req.mnemonic)?;
            tracing::info!("key initialized from imported mnemonic");
        }
        #[cfg(not(feature = "allow-seed-import"))]
        {
            return Err(EnclaveError::InvalidRequest(
                "mnemonic import not allowed without allow-seed-import feature".into(),
            ));
        }
    } else if req.seed.is_empty() {
        #[cfg(feature = "kms-persistence")]
        {
            let deadline = _deadline
                .checked_sub(crate::seed_persistence::RESPONSE_RESERVE)
                .ok_or_else(|| {
                    EnclaveError::InvalidRequest("initialization request deadline exceeded".into())
                })?;
            state.initialize_from_persistence_until(deadline)?;
            tracing::info!("keys initialized from KMS persistence");
        }
        #[cfg(not(feature = "kms-persistence"))]
        {
            // Production path for mint/burn and CCD: generate from OS entropy
            let mut entropy = [0u8; 32];
            getrandom::fill(&mut entropy)
                .map_err(|e| EnclaveError::Internal(format!("entropy generation failed: {}", e)))?;
            let _mnemonic = state.initialize_from_entropy(&mut entropy)?;
            tracing::info!("key initialized from new mnemonic");
        }
    } else {
        // Testing path: import raw seed
        #[cfg(feature = "allow-seed-import")]
        {
            let seed: [u8; 64] = req.seed.try_into().map_err(|v: Vec<u8>| {
                EnclaveError::InvalidRequest(format!(
                    "seed must be exactly 64 bytes, got {}",
                    v.len()
                ))
            })?;
            state.initialize_from_seed(seed)?;
            tracing::info!("key initialized from imported seed");
        }
        #[cfg(not(feature = "allow-seed-import"))]
        {
            return Err(EnclaveError::InvalidRequest(
                "seed import not allowed without allow-seed-import feature".into(),
            ));
        }
    }

    // Donor-side cloning secret, delivered at runtime via the init message
    // (never baked into the EIF, so it stays out of the PCRs). Only required
    // for enclaves that will serve `GetClone`. Idempotent; empty = disabled.
    if !req.cloning_secret.is_empty() {
        state.set_donor_cloning_secret(req.cloning_secret)?;
        tracing::info!("donor cloning secret configured from init request");
    }

    let keys = state.get_keys()?;
    tracing::info!(
        evm_address = %hex::encode(keys.evm_address),
        evm_gas_tx_address = %hex::encode(keys.evm_gas_tx_address),
        btc_compressed_pub = %hex::encode(keys.btc_compressed_pubkey),
        ccd_ed25519_pub = %hex::encode(keys.ccd_ed25519_pub),
        master_fingerprint = %hex::encode(keys.master_fingerprint),
        account_xpub_vanilla = %keys.account_xpub_vanilla,
        account_xpub_colored = %keys.account_xpub_colored,
        "keys initialized"
    );
    Ok(EnclaveResponse {
        response: Some(Response::InitializeKey(InitializeKeyResponse {
            evm_address: keys.evm_address.to_vec(),
            btc_compressed_pub: keys.btc_compressed_pubkey.to_vec(),
            btc_xpub: keys.btc_xpub,
            master_fingerprint: keys.master_fingerprint.to_vec(),
            account_xpub_vanilla: keys.account_xpub_vanilla,
            account_xpub_colored: keys.account_xpub_colored,
            evm_uncompressed_pub: keys.evm_uncompressed_pub.to_vec(),
            chain_id: ctx.bridge_config.chain_id,
            bridge_contract: ctx.bridge_config.bridge_contract.to_vec(),
            rgb_asset_id: ctx.bridge_config.rgb_asset_id.clone(),
            evm_gas_tx_uncompressed_pub: keys.evm_gas_tx_uncompressed_pub.to_vec(),
            evm_gas_tx_address: keys.evm_gas_tx_address.to_vec(),
            ccd_ed25519_pub: keys.ccd_ed25519_pub.to_vec(),
        })),
    })
}

pub(super) fn handle_get_public_key(
    ctx: &ServerContext,
    _req: GetPublicKeyRequest,
) -> Result<EnclaveResponse> {
    let keys = ctx.state.get_keys()?;
    tracing::debug!(
        evm_address = %hex::encode(keys.evm_address),
        evm_gas_tx_address = %hex::encode(keys.evm_gas_tx_address),
        "returning public keys"
    );
    Ok(EnclaveResponse {
        response: Some(Response::PublicKeys(build_public_keys_response(
            keys,
            &ctx.bridge_config,
        ))),
    })
}

/// Single place that assembles a `PublicKeysResponse`, keeping the field order
/// matching `canonical_pubkey_bundle`. A new field must be added to the bundle
/// and to the verifier mirror in
/// `parent/src/attest_verify.rs::canonical_bundle`.
pub(super) fn build_public_keys_response(
    keys: crate::keys::KeyInfo,
    cfg: &BridgeConfig,
) -> PublicKeysResponse {
    PublicKeysResponse {
        evm_address: keys.evm_address.to_vec(),
        btc_compressed_pub: keys.btc_compressed_pubkey.to_vec(),
        btc_xpub: keys.btc_xpub,
        master_fingerprint: keys.master_fingerprint.to_vec(),
        account_xpub_vanilla: keys.account_xpub_vanilla,
        account_xpub_colored: keys.account_xpub_colored,
        evm_uncompressed_pub: keys.evm_uncompressed_pub.to_vec(),
        chain_id: cfg.chain_id,
        bridge_contract: cfg.bridge_contract.to_vec(),
        rgb_asset_id: cfg.rgb_asset_id.clone(),
        evm_gas_tx_uncompressed_pub: keys.evm_gas_tx_uncompressed_pub.to_vec(),
        evm_gas_tx_address: keys.evm_gas_tx_address.to_vec(),
        ccd_ed25519_pub: keys.ccd_ed25519_pub.to_vec(),
    }
}

/// Build the canonical bundle that the verifier hashes to check `user_data`.
///
/// Length-prefixed (u32 BE) concatenation of every field in
/// PublicKeysResponse, in proto field order. Strings are encoded as their
/// UTF-8 bytes; `chain_id` as 8-byte big-endian (its length prefix is the
/// constant 8). Order and field set MUST match the verifier - see
/// `docs/pubkey-attestation.md` and `parent/src/attest_verify.rs::canonical_bundle`.
fn canonical_pubkey_bundle(keys: &PublicKeysResponse) -> Vec<u8> {
    let chain_id_bytes = keys.chain_id.to_be_bytes();
    let parts: [&[u8]; 13] = [
        &keys.evm_address,
        &keys.btc_compressed_pub,
        keys.btc_xpub.as_bytes(),
        &keys.master_fingerprint,
        keys.account_xpub_vanilla.as_bytes(),
        keys.account_xpub_colored.as_bytes(),
        &keys.evm_uncompressed_pub,
        &chain_id_bytes,
        &keys.bridge_contract,
        keys.rgb_asset_id.as_bytes(),
        &keys.evm_gas_tx_uncompressed_pub,
        &keys.evm_gas_tx_address,
        &keys.ccd_ed25519_pub,
    ];
    let total: usize = parts.iter().map(|p| 4 + p.len()).sum();
    let mut out = Vec::with_capacity(total);
    for p in parts {
        out.extend_from_slice(&(p.len() as u32).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// Bind the v1 identity and policy to this encrypted clone response.
/// NSM signs the version and commitment in user_data.
/// The transcript contains only public values.
pub(super) fn clone_commitment(
    bundle: &PublicKeysResponse,
    policy: &[u8],
    requester: &[u8; 32],
    donor: &[u8; 32],
    ciphertext: &[u8],
) -> [u8; 36] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"utexo/clone-response/v1\0");
    hash.update(Sha256::digest(canonical_pubkey_bundle(bundle)));
    hash.update(Sha256::digest(policy));
    hash.update(requester);
    hash.update(donor);
    hash.update(Sha256::digest(ciphertext));
    let mut out = [0u8; 36];
    out[..4].copy_from_slice(&1u32.to_be_bytes());
    out[4..].copy_from_slice(&hash.finalize());
    out
}

pub(super) fn verify_clone_commitment(actual: Option<&[u8]>, expected: &[u8; 36]) -> Result<()> {
    if actual != Some(expected.as_slice()) {
        return Err(EnclaveError::Attestation(
            "clone response version/identity/policy/transcript mismatch".into(),
        ));
    }
    Ok(())
}

pub(super) fn handle_get_attested_public_key(
    ctx: &ServerContext,
    req: GetAttestedPublicKeyRequest,
) -> Result<EnclaveResponse> {
    use sha2::{Digest, Sha256};

    let nonce: [u8; 32] = req.nonce.as_slice().try_into().map_err(|_| {
        EnclaveError::InvalidRequest(format!("nonce must be 32 bytes, got {}", req.nonce.len()))
    })?;

    // This endpoint attests over a caller-supplied nonce, so it can
    // mint attestations for arbitrary nonces. Safe for replay accounting: the
    // cloning handlers record a nonce only after a fully-authenticated
    // handshake, so an oracle-minted nonce cannot exhaust the guard.
    let keys = ctx.state.get_keys()?;
    let public_keys = build_public_keys_response(keys, &ctx.bridge_config);

    // The attestation `user_data` commits to BOTH the public-key bundle and the
    // enclave's resolved security policy, so a verifier checks the
    // whole posture as one value: sha256(pubkey_bundle || policy_commitment).
    // The verifier mirror is `parent/src/attest_verify.rs::verify_attested_pubkey`.
    let mut preimage = canonical_pubkey_bundle(&public_keys);
    preimage.extend_from_slice(&ctx.policy.commitment_bytes());
    let commitment: [u8; 32] = Sha256::digest(&preimage).into();

    let attestation_doc = crate::attestation::get_attestation(
        &nonce,
        Some(&public_keys.evm_uncompressed_pub),
        Some(&commitment),
    )?;

    tracing::info!(
        evm_address = %hex::encode(&public_keys.evm_address),
        commitment = %hex::encode(commitment),
        attestation_bytes = attestation_doc.len(),
        "returning attested public keys"
    );

    Ok(EnclaveResponse {
        response: Some(Response::GetAttestedPublicKey(
            GetAttestedPublicKeyResponse {
                public_keys: Some(public_keys),
                attestation_doc,
            },
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_commitment_requires_the_signed_identity_transcript() {
        let expected = [0x5a; 36];
        assert!(verify_clone_commitment(Some(&expected), &expected).is_ok());
        assert!(verify_clone_commitment(None, &expected).is_err());

        let mut altered = expected;
        altered[35] ^= 1;
        assert!(verify_clone_commitment(Some(&altered), &expected).is_err());
    }
}
