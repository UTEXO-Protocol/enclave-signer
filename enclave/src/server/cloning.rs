//! The cloning handshake. It moves a seed from a running donor enclave to a
//! new requester enclave. The seed does not leave a TEE.
//!
//! See `enclave-proto/proto/enclave.proto` for the full protocol.

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

/// Requester side: `Initial -> Cloning`.
/// Makes an ephemeral X25519 keypair. An NSM attestation binds it with the
/// HMAC digest of (cloning_secret, pubkey, donor address).
/// Returns the three fields that the parent relays to the donor.
pub(super) fn handle_initiate_cloning(
    state: &EnclaveState,
    req: InitiateCloningRequest,
) -> Result<EnclaveResponse> {
    // Refuse weak cloning secrets before use. (F03-AF-26)
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

    // The NSM signature binds the X25519 pubkey and the digest.
    // The parent cannot change either without breaking the attestation.
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

/// Donor side: stays in `Phase::Active`.
/// Checks the donor identity and the HMAC digest against the donor cloning
/// secret. Then verifies the requester attestation, PCRs, pubkey and digest
/// binding. Then reserves the export slot and the nonce. Only then it seals
/// the seed.
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

    // 1. The request must address this enclave. This stops the parent from
    //    sending one request to unintended donors.
    let our_evm = state.evm_address()?;
    if req_cluster_pk != our_evm {
        return Err(EnclaveError::InvalidRequest(format!(
            "cluster_public_key {} does not match this enclave's address {}",
            hex::encode(req_cluster_pk),
            hex::encode(our_evm)
        )));
    }

    // 2. Check the HMAC against the requester key and donor address. (F03-AF-07)
    //    Refuse unauthorized requests before costly attestation checks. (F03-AF-20)
    //    Steps 4 and 5 bind these values to the signed document.
    state.with_donor_cloning_secret(|secret| {
        if !cloning::verify_cloning_digest(secret, &req_encryption_pk, &req_cluster_pk, &req_digest)
        {
            return Err(EnclaveError::DigestMismatch);
        }
        Ok(())
    })?;

    // 3. Verify the requester attestation chain and PCRs. The expected nonce
    //    is `None` because the donor does not know it. The replay guard
    //    enforces freshness after the binding checks pass.
    // A local NSM fault is internal, not a refused peer.
    let expected_pcrs =
        attestation::get_own_pcrs().map_err(|e| EnclaveError::Internal(e.to_string()))?;
    let verified =
        attestation::verify_peer_attestation(&req.requester_attestation, &expected_pcrs, None)?;

    // 4. The attested `public_key` must equal the wire key. If not, the
    //    parent could replace it with a key that it controls.
    if verified.enclave_pubkey.as_slice() != req_encryption_pk {
        return Err(EnclaveError::PubkeyMismatch);
    }

    // 5. The attested `user_data` must equal the wire digest. NSM signs it,
    //    so the parent cannot change it.
    let user_data = verified.user_data.as_deref().ok_or_else(|| {
        EnclaveError::Attestation("requester attestation missing user_data (cloning digest)".into())
    })?;
    if user_data != req_digest {
        return Err(EnclaveError::DigestMismatch);
    }

    // 5b. Reserve an export slot after authentication. (F03-AF-10)
    //     The atomic reservation enforces the cap across workers.
    //     A later error releases the slot.
    let export_reservation = state.reserve_export_quota()?;

    // 6. Reserve the verified nonce after authentication. (F03-AF-02 / F03-AF-04)
    //    Commit it after encryption and donor attestation succeed.
    //    An error releases the nonce, so the requester can retry.
    let nonce_array: [u8; 32] = verified
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| EnclaveError::Attestation("attestation nonce has wrong length".into()))?;
    let reservation = state.replay_guard.reserve(nonce_array)?;

    // 7. Seal the seed with a new donor ephemeral keypair.
    let (encrypted_seed, donor_pubkey) =
        state.with_seed(|seed| cloning::encrypt_seed_for_peer(&req_encryption_pk, seed))?;

    // 8. Donor attestation with a new nonce. It binds the new donor pubkey,
    //    so the parent cannot replay an old response. `user_data` commits to
    //    the donor identity, policy and this transcript. (F03-AF-08)
    let donor_nonce = fresh_nonce()?;
    let bundle = build_public_keys_response(state.get_keys()?, &ctx.bridge_config);
    let commitment = clone_commitment(
        &bundle,
        &ctx.launch()?.policy.commitment_bytes(),
        &req_encryption_pk,
        &donor_pubkey,
        &encrypted_seed,
    );
    let donor_attestation =
        attestation::get_attestation(&donor_nonce, Some(&donor_pubkey), Some(&commitment))
            .map_err(|e| EnclaveError::Internal(e.to_string()))?;

    reservation.commit();

    // Record the successful export. (F03-AF-10)
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

/// Requester side: `Cloning -> Active`.
/// Verifies the donor attestation and unseals the ciphertext. Commits the
/// derived keys only if the EVM target and the signed identity, policy and
/// transcript match.
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

    // 1. Verify the donor attestation chain and PCRs. No nonce match: the
    //    replay guard enforces freshness.
    let expected_pcrs = attestation::get_own_pcrs()?;
    let verified =
        attestation::verify_peer_attestation(&req.donor_attestation, &expected_pcrs, None)?;

    // 2. The wire donor pubkey must equal the attested pubkey.
    if verified.enclave_pubkey.as_slice() != donor_pubkey {
        return Err(EnclaveError::PubkeyMismatch);
    }

    // 3. Reserve the donor nonce before the state changes. (F03-AF-03)
    //    An error releases the reservation.
    let nonce_array: [u8; 32] = verified
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| EnclaveError::Attestation("attestation nonce has wrong length".into()))?;
    let reservation = state.replay_guard.reserve(nonce_array)?;

    // 4. Check the decrypted identity and policy before Active.
    //    The state lock is held for the full operation.
    //    On error, the phase stays Cloning and the nonce is released.
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
            &ctx.launch()?.policy.commitment_bytes(),
            &session.session.public_key(),
            &donor_pubkey,
            &req.encrypted_seed,
        );
        verify_clone_commitment(verified.user_data.as_deref(), &expected)?;
        cluster_public_key = session.cluster_public_key;
        Ok(km)
    })?;

    reservation.commit();

    tracing::info!(
        cluster_pk = %hex::encode(cluster_public_key),
        "SetClone: cloned, transitioned to Active"
    );

    Ok(EnclaveResponse {
        response: Some(Response::SetClone(SetCloneResponse {})),
    })
}
