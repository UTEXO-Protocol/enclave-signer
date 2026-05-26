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
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::grpc_proto::enclave_service_client::EnclaveServiceClient;
use crate::grpc_proto::{AttestedPublicKeyRequest, AttestedPublicKeyResponse};

/// Whether to verify the document via the COSE/cert-chain real path or
/// the raw-CBOR mock path. Real production use MUST always pass `Real`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyMode {
    Real,
    Mock,
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
    let parts: [&[u8]; 10] = [
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
) -> Result<AttestedPubkeyResult> {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);

    let mut client = EnclaveServiceClient::connect(endpoint.to_string())
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

    let bundle = canonical_bundle(&response);
    let bundle_commitment: [u8; 32] = Sha256::digest(&bundle).into();
    let user_data = verified
        .user_data
        .as_deref()
        .context("attestation has no user_data field")?;
    if user_data != bundle_commitment {
        bail!(
            "attestation `user_data` ({}) does not match sha256(canonical_bundle) ({})",
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
