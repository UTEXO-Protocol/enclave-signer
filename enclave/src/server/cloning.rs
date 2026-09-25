//! The cloning handshake: move a seed from a running donor enclave into a
//! fresh requester enclave without it ever leaving a TEE.
//!
//! See proto/enclave.proto for the full protocol description.

use super::context::ServerContext;
use super::keys::{build_public_keys_response, clone_commitment, verify_clone_commitment};
use crate::attestation;
use crate::cloning::{self, CloneSession};
use crate::error::{EnclaveError, Result};
use crate::proto::enclave_response::Response;
use crate::proto::*;
use crate::state::{CloningSession, EnclaveState};

fn fresh_nonce() -> Result<[u8; 32]> {
    let mut n = [0u8; 32];
    getrandom::fill(&mut n)
        .map_err(|e| EnclaveError::Internal(format!("entropy generation failed: {}", e)))?;
    Ok(n)
}

/// Requester side. Transitions `Initial -> Cloning`. Generates an
/// ephemeral X25519 keypair, binds it into an NSM attestation together
/// with the HMAC digest of (cloning_secret, pubkey, donor address), and
/// returns the three fields the parent needs to relay to the donor.
pub(super) fn handle_initiate_cloning(
    state: &EnclaveState,
    req: InitiateCloningRequest,
) -> Result<EnclaveResponse> {
    // Reject weak cloning secrets before use. (F03-AF-26)
    cloning::validate_cloning_secret(&req.cloning_secret)?;
    let cluster_public_key: [u8; 20] =
        req.cluster_public_key.as_slice().try_into().map_err(|_| {
            EnclaveError::InvalidRequest(format!(
                "cluster_public_key must be 20 bytes, got {}",
                req.cluster_public_key.len()
            ))
        })?;

    let session = CloneSession::new();
    let encryption_pubkey = session.public_key();

    let nonce = fresh_nonce()?;
    // Bind the digest to the intended donor EVM address. (F03-AF-07)
    let cloning_digest =
        cloning::make_cloning_digest(&req.cloning_secret, &encryption_pubkey, &cluster_public_key);

    // Bind both the X25519 pubkey and the digest into the NSM signature:
    // the parent cannot rewrite either without invalidating the attestation.
    let attestation =
        attestation::get_attestation(&nonce, Some(&encryption_pubkey), Some(&cloning_digest))?;

    state.enter_cloning(CloningSession::new(session, cluster_public_key))?;

    tracing::info!(
        cluster_pk = %hex::encode(cluster_public_key),
        "InitiateCloning: entered Cloning phase"
    );

    Ok(EnclaveResponse {
        response: Some(Response::InitiateCloning(InitiateCloningResponse {
            requester_attestation: attestation,
            encryption_pubkey: encryption_pubkey.to_vec(),
            cloning_digest: cloning_digest.to_vec(),
        })),
    })
}

/// Donor side. Stays in `Phase::Active`. Verifies the requester's
/// attestation, matches PCRs, records the nonce against replay, checks
/// pubkey + digest binding, verifies the digest against the configured
/// donor-side cloning secret, and only then seals the seed.
pub(super) fn handle_get_clone(
    ctx: &ServerContext,
    req: GetCloneRequest,
) -> Result<EnclaveResponse> {
    let state = &ctx.state;
    let req_cluster_pk: [u8; 20] = req.cluster_public_key.as_slice().try_into().map_err(|_| {
        EnclaveError::InvalidRequest(format!(
            "cluster_public_key must be 20 bytes, got {}",
            req.cluster_public_key.len()
        ))
    })?;
    let req_encryption_pk: [u8; 32] =
        req.encryption_pubkey.as_slice().try_into().map_err(|_| {
            EnclaveError::InvalidRequest(format!(
                "encryption_pubkey must be 32 bytes, got {}",
                req.encryption_pubkey.len()
            ))
        })?;
    let req_digest: [u8; 32] = req.cloning_digest.as_slice().try_into().map_err(|_| {
        EnclaveError::InvalidRequest(format!(
            "cloning_digest must be 32 bytes, got {}",
            req.cloning_digest.len()
        ))
    })?;

    // 1. Donor identity check: the request must address *this* enclave's
    //    public key. Prevents the parent from fanning one request out to
    //    unintended donors.
    let our_evm = state.evm_address()?;
    if req_cluster_pk != our_evm {
        return Err(EnclaveError::Clone(format!(
            "cluster_public_key {} does not match this enclave's address {}",
            hex::encode(req_cluster_pk),
            hex::encode(our_evm)
        )));
    }

    // 2. Check the HMAC against the requester key and donor address. (F03-AF-07)
    // Reject unauthorized requests before costly attestation checks. (F03-AF-20)
    // Steps 4 and 5 bind these values to the signed document.
    state.with_donor_cloning_secret(|secret| {
        if !cloning::verify_cloning_digest(secret, &req_encryption_pk, &req_cluster_pk, &req_digest)
        {
            return Err(EnclaveError::DigestMismatch);
        }
        Ok(())
    })?;

    // 3. Verify the requester attestation chain + PCRs. `None` for the
    //    expected nonce: we have not seen the requester's nonce before,
    //    so freshness is enforced by the replay guard once the binding and
    //    authenticity checks below have passed.
    let expected_pcrs = attestation::get_own_pcrs()?;
    let verified =
        attestation::verify_peer_attestation(&req.requester_attestation, &expected_pcrs, None)?;

    // 4. Pubkey binding: the attestation's `public_key` field must equal
    //    the one the parent put on the wire. Otherwise the parent could
    //    have swapped it for a key it controls.
    if verified.enclave_pubkey.as_slice() != req_encryption_pk {
        return Err(EnclaveError::PubkeyMismatch);
    }

    // 5. Digest binding: the attestation's `user_data` must equal the
    //    digest on the wire - NSM-signed, so parent-proof.
    let user_data = verified.user_data.as_deref().ok_or_else(|| {
        EnclaveError::Attestation("requester attestation missing user_data (cloning digest)".into())
    })?;
    if user_data != req_digest {
        return Err(EnclaveError::DigestMismatch);
    }

    // 5b. Reserve an export slot after authentication. (F03-AF-10)
    // Use an atomic reservation to enforce the cap across workers.
    // A later error releases the slot.
    // A zero cap disables the limit.
    let export_reservation = state.reserve_export_quota()?;

    // 6. Reserve the verified nonce after authentication. (F03-AF-02 / F03-AF-04)
    // Commit it after encryption and donor attestation succeed.
    // An error releases the nonce so the requester can retry.
    let nonce_array: [u8; 32] = verified
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| EnclaveError::Attestation("attestation nonce has wrong length".into()))?;
    let reservation = state.replay_guard.reserve(nonce_array)?;

    // 7. Seal the seed under a fresh donor ephemeral keypair.
    let (encrypted_seed, donor_pubkey) =
        state.with_seed(|seed| cloning::encrypt_seed_for_peer(&req_encryption_pk, seed))?;

    // 8. Donor's own attestation. Fresh nonce, binds the donor pubkey we
    //    just produced so the requester can be sure this response is
    //    not an old one replayed by the parent. `user_data` commits to the
    //    donor's full identity, policy and this transcript. (F03-AF-08)
    let donor_nonce = fresh_nonce()?;
    let bundle = build_public_keys_response(state.get_keys()?, &ctx.bridge_config);
    let commitment = clone_commitment(
        &bundle,
        &ctx.policy.commitment_bytes(),
        &req_encryption_pk,
        &donor_pubkey,
        &encrypted_seed,
    );
    let donor_attestation =
        attestation::get_attestation(&donor_nonce, Some(&donor_pubkey), Some(&commitment))?;

    // Seal + donor attestation succeeded: keep the nonce recorded.
    reservation.commit();

    // Record the successful export. (F03-AF-10)
    // The hard quota already applies through the reserved slot.
    let export_count = export_reservation.commit(&req_encryption_pk);
    tracing::info!(
        cluster_pk = %hex::encode(our_evm),
        seed_export_count = export_count,
        "GetClone: sealed seed for requester"
    );

    Ok(EnclaveResponse {
        response: Some(Response::GetClone(GetCloneResponse {
            encrypted_seed,
            donor_pubkey: donor_pubkey.to_vec(),
            donor_attestation,
        })),
    })
}

/// Requester side. Transitions `Cloning -> Active`. Verifies the donor's
/// attestation, unseals the ciphertext, and commits the derived keys
/// only if the EVM target and signed full identity/policy/transcript match.
pub(super) fn handle_set_clone(
    ctx: &ServerContext,
    req: SetCloneRequest,
) -> Result<EnclaveResponse> {
    let state = &ctx.state;
    let donor_pubkey: [u8; 32] = req.donor_pubkey.as_slice().try_into().map_err(|_| {
        EnclaveError::InvalidRequest(format!(
            "donor_pubkey must be 32 bytes, got {}",
            req.donor_pubkey.len()
        ))
    })?;

    // 1. Verify donor attestation chain + PCRs (no nonce match - freshness
    //    is enforced by the replay guard once the binding and seed/identity
    //    checks below have passed).
    let expected_pcrs = attestation::get_own_pcrs()?;
    let verified =
        attestation::verify_peer_attestation(&req.donor_attestation, &expected_pcrs, None)?;

    // 2. Pubkey binding: the donor's pubkey on the wire must equal the
    //    one inside their signed attestation.
    if verified.enclave_pubkey.as_slice() != donor_pubkey {
        return Err(EnclaveError::PubkeyMismatch);
    }

    // 3. Validate and reserve the donor nonce before changing state. (F03-AF-03)
    // An error releases the reservation.
    let nonce_array: [u8; 32] = verified
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| EnclaveError::Attestation("attestation nonce has wrong length".into()))?;
    let reservation = state.replay_guard.reserve(nonce_array)?;

    // 4. Check the decrypted identity and policy before setting Active.
    // Hold the state lock for the complete operation.
    // On error, keep Cloning and release the nonce for a retry.
    let network = state.network();
    let mut cluster_public_key = [0u8; 20];
    state.complete_cloning(|session| {
        let seed = session
            .session
            .decrypt_seed_from_peer(&donor_pubkey, &req.encrypted_seed)?;
        let km = crate::keys::KeyManager::from_seed(*seed, network)?;
        if km.evm_address() != &session.cluster_public_key {
            return Err(EnclaveError::IdentityMismatch);
        }
        let bundle = build_public_keys_response(EnclaveState::key_info(&km), &ctx.bridge_config);
        let expected = clone_commitment(
            &bundle,
            &ctx.policy.commitment_bytes(),
            &session.session.public_key(),
            &donor_pubkey,
            &req.encrypted_seed,
        );
        verify_clone_commitment(verified.user_data.as_deref(), &expected)?;
        cluster_public_key = session.cluster_public_key;
        Ok(km)
    })?;

    // Transition committed: keep the donor nonce recorded.
    reservation.commit();

    tracing::info!(
        cluster_pk = %hex::encode(cluster_public_key),
        "SetClone: cloned, transitioned to Active"
    );

    Ok(EnclaveResponse {
        response: Some(Response::SetClone(SetCloneResponse {})),
    })
}
