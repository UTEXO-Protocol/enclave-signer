//! Library part of the `attest-verify` CLI.
//!
//! Calls the parent `AttestedPublicKey` RPC, verifies the attestation
//! document end-to-end, and returns the verified bundle. The binary in
//! `bin/attest_verify.rs` parses flags, calls [`verify_attested_pubkey`] and
//! formats the output. Integration tests use this module against an
//! in-process parent and enclave.
//!
//! An [`AttestationBundle`] stores one verified answer, so anyone can run
//! the same checks later without network access ([`verify_bundle`]).

use anyhow::{bail, Context, Result};
use attestation_verify::{
    AttestationMode, AttestedPolicy, BtcDataSource, EvmDataSource, EvmRpcTlsPin, ExpectedPcrs,
    KmsPin, SignerRole, VerifiedAttestation,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::enclave_proto::GetAttestedPublicKeyResponse;
use crate::grpc_proto::parent_service_client::ParentServiceClient;
use crate::grpc_proto::{AttestedPublicKeyRequest, AttestedPublicKeyResponse};
use crate::launch_check;

/// Verify through the real COSE and cert-chain path, or the raw-CBOR mock
/// path. Production MUST use `Real`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyMode {
    Real,
    Mock,
}

/// The security posture the caller expects from the attested enclave.
///
/// The enclave commits its posture into `user_data`. The verifier builds the
/// expected posture and requires an exact match, so a downgraded enclave fails.
///
/// Chain, contract and asset values come from the wire response, which the
/// public-key bundle binds. This type gives only the posture flags and rules
/// that are not on the wire. The optional chain, contract and asset pins
/// (F02-AF-04) also compare the wire values with the operator deployment.
/// Without a pin, the value is authenticated but not compared.
///
/// One value is built per run, so the variant size difference does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpectedPolicy {
    /// Expect a production bridge enclave with these posture flags.
    Production {
        allow_vanilla_psbt: bool,
        /// Expected image: mint, burn or combined signer. A role mismatch
        /// fails verification.
        signer_role: SignerRole,
        evm_source: EvmDataSource,
        /// The Electrum host the operator set at launch.
        electrum_host: String,
        /// Expected EVM RPC TLS host and CA hash. Required when `evm_source`
        /// is [`EvmDataSource::PinnedTlsRpc`].
        evm_rpc_tls: Option<EvmRpcTlsPin>,
        /// Expected EVM chain ID. `None` accepts the authenticated value.
        expected_chain_id: Option<u64>,
        /// Expected 20-byte bridge or MultisigProxy address. `Some` requires
        /// an exact match.
        expected_bridge_contract: Option<[u8; 20]>,
        /// Expected RGB asset ID. `Some` requires an exact match. An empty
        /// string requires no RGB asset.
        expected_rgb_asset_id: Option<String>,
        funds_in_contract: [u8; 20],
        /// Expected ERC-20 that the Bridge releases (`TOKEN_CONTRACT`). It is
        /// an input to the `burnId` preimage. It is not on the wire, so the
        /// operator declares it.
        token_contract: [u8; 20],
        evm_min_confirmations: u64,
        /// Expected gas-tx (`SignRawDigest`) rule. An all-zero destination,
        /// zero caps and no selectors mean "not pinned". The enclave then
        /// rejects every gas-tx request.
        gas_tx_allowed_to: [u8; 20],
        gas_tx_max_gas_limit: u64,
        gas_tx_max_fee_per_gas: u128,
        gas_tx_max_value_wei: u128,
        gas_tx_allowed_selectors: Vec<[u8; 4]>,
        /// KMS key, region, seed ID and address set at launch. `None` expects
        /// no KMS pin.
        kms: Option<KmsPin>,
    },
    /// Expect a dev or mock enclave (for example with `--mock`). Not for
    /// production.
    Development,
}

/// Successful verification result. This value proves that the bridge signing
/// key comes from a TEE with the supplied PCRs.
#[derive(Debug, Clone)]
pub struct AttestedPubkeyResult {
    pub response: AttestedPublicKeyResponse,
    pub verified: attestation_verify::VerifiedAttestation,
    pub bundle_commitment: [u8; 32],
    pub nonce_sent: [u8; 32],
    /// The policy the enclave attests, decoded from the response.
    pub policy: AttestedPolicy,
}

/// Build the canonical key bundle that the verifier hashes to check
/// `user_data`. Field order and encoding MUST match
/// `canonical_pubkey_bundle` in `enclave/src/server/keys.rs`.
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

/// Run the full attestation flow. Connect to `endpoint`, send a fresh nonce,
/// verify the document against `expected_pcrs`, and check the public key and
/// commitment against the wire bundle.
///
/// Returns `Ok(_)` only if every check passes. The error names the failed
/// check.
pub async fn verify_attested_pubkey(
    endpoint: &str,
    expected_pcrs: attestation_verify::ExpectedPcrs,
    mode: VerifyMode,
    expected_policy: ExpectedPolicy,
) -> Result<AttestedPubkeyResult> {
    let mut nonce = [0u8; 32];
    rand::fill(&mut nonce);

    let channel = crate::transport_security::client_endpoint(endpoint)?
        .connect()
        .await
        .with_context(|| format!("connecting to {endpoint}"))?;
    let mut client = ParentServiceClient::new(channel);

    let response = client
        .attested_public_key(AttestedPublicKeyRequest {
            nonce: nonce.to_vec(),
        })
        .await
        .context("AttestedPublicKey RPC failed")?
        .into_inner();

    verify_attested_response(response, nonce, &expected_pcrs, mode, &expected_policy)
}

/// The checks of [`verify_attested_pubkey`] after the RPC: document, public
/// key and policy commitment. Tests call it without a server.
pub fn verify_attested_response(
    response: AttestedPublicKeyResponse,
    nonce: [u8; 32],
    expected_pcrs: &attestation_verify::ExpectedPcrs,
    mode: VerifyMode,
    expected_policy: &ExpectedPolicy,
) -> Result<AttestedPubkeyResult> {
    let result = verify_keyed(response, nonce, |doc| {
        verify_now(doc, expected_pcrs, &nonce, mode)
    })?;
    check_expected_policy(&result, expected_policy)?;
    Ok(result)
}

/// Verify the document now, with the PCRs and the nonce.
fn verify_now(
    doc: &[u8],
    pcrs: &ExpectedPcrs,
    nonce: &[u8; 32],
    mode: VerifyMode,
) -> Result<VerifiedAttestation> {
    match mode {
        VerifyMode::Real => attestation_verify::verify_attestation(doc, pcrs, Some(nonce))
            .context("attestation verify failed"),
        VerifyMode::Mock => attestation_verify::verify_mock_attestation(doc, pcrs, Some(nonce))
            .context("mock attestation verify failed"),
    }
}

/// Verify the document with `verify_doc`, then check that it binds the
/// public key and the commitment of the key bundle and the policy bytes.
/// Decode the policy. The caller compares it with what it expects.
fn verify_keyed(
    response: AttestedPublicKeyResponse,
    nonce: [u8; 32],
    verify_doc: impl FnOnce(&[u8]) -> Result<VerifiedAttestation>,
) -> Result<AttestedPubkeyResult> {
    let verified = verify_doc(&response.attestation_doc)?;

    if verified.enclave_pubkey != response.evm_uncompressed_pub {
        bail!(
            "attestation `public_key` ({} bytes) does not match wire evm_uncompressed_pub ({} bytes)",
            verified.enclave_pubkey.len(),
            response.evm_uncompressed_pub.len()
        );
    }

    // The enclave commits to sha256(pubkey_bundle || policy_commitment).
    // 1. Authenticate the policy bytes of the response against user_data.
    let mut preimage = canonical_bundle(&response);
    preimage.extend_from_slice(&response.attested_policy);
    let bundle_commitment: [u8; 32] = Sha256::digest(&preimage).into();
    let user_data = verified
        .user_data
        .as_deref()
        .context("attestation has no user_data field")?;
    if user_data != bundle_commitment {
        bail!(
            "attestation `user_data` ({}) does not match sha256(canonical_bundle || policy) ({}): \
             the policy bytes do not match the attestation",
            hex::encode(user_data),
            hex::encode(bundle_commitment),
        );
    }
    // 2. Decode them.
    let policy = AttestedPolicy::from_bytes(&response.attested_policy)?;

    Ok(AttestedPubkeyResult {
        response,
        verified,
        bundle_commitment,
        nonce_sent: nonce,
        policy,
    })
}

/// Compare the attested policy with the expected policy: pins from the wire
/// response, posture flags from `expected_policy`. The bytes are canonical.
fn check_expected_policy(
    result: &AttestedPubkeyResult,
    expected_policy: &ExpectedPolicy,
) -> Result<()> {
    let expected =
        expected_attested_policy(expected_policy, &result.response, &result.verified.pcrs)?;
    if result.response.attested_policy != expected.to_bytes() {
        bail!(
            "the attested policy {:?} does not match the expected policy {expected:?}: \
             the enclave's security posture differs from what was expected",
            result.policy
        );
    }
    Ok(())
}

/// The parent RPC answer for an enclave answer. An enclave without keys
/// attests its policy only, which proves no key.
pub fn attested_response(r: GetAttestedPublicKeyResponse) -> Result<AttestedPublicKeyResponse> {
    let pk = r
        .public_keys
        .context("the enclave has no key; run init or clone first")?;
    Ok(AttestedPublicKeyResponse {
        evm_address: pk.evm_address,
        evm_uncompressed_pub: pk.evm_uncompressed_pub,
        btc_compressed_pub: pk.btc_compressed_pub,
        btc_xpub: pk.btc_xpub,
        master_fingerprint: pk.master_fingerprint,
        account_xpub_vanilla: pk.account_xpub_vanilla,
        account_xpub_colored: pk.account_xpub_colored,
        attestation_doc: r.attestation_doc,
        chain_id: pk.chain_id,
        bridge_contract: pk.bridge_contract,
        rgb_asset_id: pk.rgb_asset_id,
        evm_gas_tx_uncompressed_pub: pk.evm_gas_tx_uncompressed_pub,
        evm_gas_tx_address: pk.evm_gas_tx_address,
        ccd_ed25519_pub: pk.ccd_ed25519_pub,
        attested_policy: r.attested_policy,
    })
}

/// The `format` value of an [`AttestationBundle`].
pub const BUNDLE_FORMAT: &str = "utexo-signer-attestation/1";

/// One verified attested answer, stored for offline verification.
/// Bytes are 0x-hex, except the document, which is base64.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationBundle {
    pub format: String,
    /// The 32-byte nonce that the document carries.
    pub nonce: String,
    pub attestation_doc: String,
    pub public_keys: BundleKeys,
    /// The policy bytes that `user_data` commits.
    pub attested_policy: String,
    /// The decoded policy as (field, value) pairs, for the reader.
    /// [`verify_bundle`] requires it to equal the decoded policy bytes.
    pub policy: Vec<(String, String)>,
}

/// The public-key bundle, in the order of [`canonical_bundle`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleKeys {
    pub evm_address: String,
    pub btc_compressed_pub: String,
    pub btc_xpub: String,
    pub master_fingerprint: String,
    pub account_xpub_vanilla: String,
    pub account_xpub_colored: String,
    pub evm_uncompressed_pub: String,
    pub chain_id: u64,
    pub bridge_contract: String,
    pub rgb_asset_id: String,
    pub evm_gas_tx_uncompressed_pub: String,
    pub evm_gas_tx_address: String,
    pub ccd_ed25519_pub: String,
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn from_hex0x(field: &str, value: &str) -> Result<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .with_context(|| format!("bundle field {field} is not hex"))
}

impl AttestationBundle {
    fn new(result: &AttestedPubkeyResult) -> Self {
        let r = &result.response;
        Self {
            format: BUNDLE_FORMAT.into(),
            nonce: hex0x(&result.nonce_sent),
            attestation_doc: BASE64.encode(&r.attestation_doc),
            public_keys: BundleKeys {
                evm_address: hex0x(&r.evm_address),
                btc_compressed_pub: hex0x(&r.btc_compressed_pub),
                btc_xpub: r.btc_xpub.clone(),
                master_fingerprint: hex0x(&r.master_fingerprint),
                account_xpub_vanilla: r.account_xpub_vanilla.clone(),
                account_xpub_colored: r.account_xpub_colored.clone(),
                evm_uncompressed_pub: hex0x(&r.evm_uncompressed_pub),
                chain_id: r.chain_id,
                bridge_contract: hex0x(&r.bridge_contract),
                rgb_asset_id: r.rgb_asset_id.clone(),
                evm_gas_tx_uncompressed_pub: hex0x(&r.evm_gas_tx_uncompressed_pub),
                evm_gas_tx_address: hex0x(&r.evm_gas_tx_address),
                ccd_ed25519_pub: hex0x(&r.ccd_ed25519_pub),
            },
            attested_policy: hex0x(&r.attested_policy),
            policy: launch_check::fields(&result.policy)
                .into_iter()
                .map(|(field, value)| (field.into(), value))
                .collect(),
        }
    }

    /// The nonce and the parent RPC answer that the bundle stores.
    fn response(&self) -> Result<([u8; 32], AttestedPublicKeyResponse)> {
        if self.format != BUNDLE_FORMAT {
            bail!("bundle format {:?} is not {BUNDLE_FORMAT:?}", self.format);
        }
        let nonce = from_hex0x("nonce", &self.nonce)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bundle field nonce is not 32 bytes"))?;
        let k = &self.public_keys;
        let response = AttestedPublicKeyResponse {
            evm_address: from_hex0x("evm_address", &k.evm_address)?,
            evm_uncompressed_pub: from_hex0x("evm_uncompressed_pub", &k.evm_uncompressed_pub)?,
            btc_compressed_pub: from_hex0x("btc_compressed_pub", &k.btc_compressed_pub)?,
            btc_xpub: k.btc_xpub.clone(),
            master_fingerprint: from_hex0x("master_fingerprint", &k.master_fingerprint)?,
            account_xpub_vanilla: k.account_xpub_vanilla.clone(),
            account_xpub_colored: k.account_xpub_colored.clone(),
            attestation_doc: BASE64
                .decode(&self.attestation_doc)
                .context("bundle field attestation_doc is not base64")?,
            chain_id: k.chain_id,
            bridge_contract: from_hex0x("bridge_contract", &k.bridge_contract)?,
            rgb_asset_id: k.rgb_asset_id.clone(),
            evm_gas_tx_uncompressed_pub: from_hex0x(
                "evm_gas_tx_uncompressed_pub",
                &k.evm_gas_tx_uncompressed_pub,
            )?,
            evm_gas_tx_address: from_hex0x("evm_gas_tx_address", &k.evm_gas_tx_address)?,
            ccd_ed25519_pub: from_hex0x("ccd_ed25519_pub", &k.ccd_ed25519_pub)?,
            attested_policy: from_hex0x("attested_policy", &self.attested_policy)?,
        };
        Ok((nonce, response))
    }
}

/// Verify a fresh keyed enclave answer for `nonce` as `verify-launch` and
/// `attest-verify` do, and return it as a bundle. `expected` is the launch
/// policy of the deploy. `expect_evm` is the registered EVM address.
pub fn export_bundle(
    response: GetAttestedPublicKeyResponse,
    nonce: [u8; 32],
    pcrs: &ExpectedPcrs,
    mode: VerifyMode,
    expected: &AttestedPolicy,
    expect_evm: Option<[u8; 20]>,
) -> Result<AttestationBundle> {
    let result = verify_keyed(attested_response(response)?, nonce, |doc| {
        verify_now(doc, pcrs, &nonce, mode)
    })?;
    let expected = launch_check::with_document_pcr3(expected, &result.verified.pcrs)?;
    launch_check::compare_policy(&expected, &result.response.attested_policy)?;
    if let Some(want) = expect_evm {
        if result.response.evm_address != want {
            bail!(
                "evm_address mismatch: expected {}, attested {}",
                hex0x(&want),
                hex0x(&result.response.evm_address)
            );
        }
    }
    Ok(AttestationBundle::new(&result))
}

/// Run every check of [`verify_attested_response`] on a bundle, offline.
/// The nonce is the bundle nonce. A real document is checked at its own
/// timestamp, because its certificates expire within hours.
pub fn verify_bundle(
    json: &str,
    pcrs: &ExpectedPcrs,
    mode: VerifyMode,
    expected_policy: &ExpectedPolicy,
) -> Result<AttestedPubkeyResult> {
    verify_bundle_with(json, expected_policy, |doc, nonce| match mode {
        VerifyMode::Real => {
            attestation_verify::verify_attestation_at_document_time(doc, pcrs, nonce)
                .context("attestation verify failed")
        }
        VerifyMode::Mock => attestation_verify::verify_mock_attestation(doc, pcrs, Some(nonce))
            .context("mock attestation verify failed"),
    })
}

fn verify_bundle_with(
    json: &str,
    expected_policy: &ExpectedPolicy,
    verify_doc: impl FnOnce(&[u8], &[u8; 32]) -> Result<VerifiedAttestation>,
) -> Result<AttestedPubkeyResult> {
    let bundle: AttestationBundle =
        serde_json::from_str(json).context("the file is not an attestation bundle")?;
    let (nonce, response) = bundle.response()?;
    let result = verify_keyed(response, nonce, |doc| verify_doc(doc, &nonce))?;
    check_expected_policy(&result, expected_policy)?;
    let attested = launch_check::fields(&result.policy);
    for (i, (field, value)) in attested.iter().enumerate() {
        match bundle.policy.get(i) {
            Some((f, v)) if f == field && v == value => {}
            other => {
                bail!("policy field {field} mismatch: bundle says {other:?}, attested {value:?}")
            }
        }
    }
    if bundle.policy.len() != attested.len() {
        bail!("policy has fields the attestation does not have");
    }
    Ok(result)
}

/// The clone-peer PCR3 that an enclave of `role` must attest. A cloning role
/// binds its clone peers to its own PCR3, the parent IAM role. The NSM signs
/// the document PCRs, so the expected value is the document's PCR3. It must be
/// set: an all-zero PCR3 means the instance has no IAM role. A role that does
/// not clone attests none.
pub(crate) fn clone_peer_pcr3(
    role: SignerRole,
    doc_pcrs: &std::collections::HashMap<u32, Vec<u8>>,
) -> Result<Option<[u8; 48]>> {
    if !role.clones() {
        return Ok(None);
    }
    let pcr3: [u8; 48] = doc_pcrs
        .get(&3)
        .context("the attestation document has no PCR3")?
        .as_slice()
        .try_into()
        .context("the document PCR3 is not 48 bytes")?;
    if pcr3.iter().all(|&b| b == 0) {
        bail!(
            "the document PCR3 is all zero: the parent instance has no IAM role, \
             so the enclave cannot bind clone peers"
        );
    }
    Ok(Some(pcr3))
}

/// Build the expected [`AttestedPolicy`] from the operator posture
/// ([`ExpectedPolicy`]), the wire values (bound by the key bundle) and the
/// verified document PCRs. The bytes MUST equal the enclave
/// `SecurityPolicy::commitment_bytes`.
fn expected_attested_policy(
    expected: &ExpectedPolicy,
    resp: &AttestedPublicKeyResponse,
    doc_pcrs: &std::collections::HashMap<u32, Vec<u8>>,
) -> Result<AttestedPolicy> {
    match expected {
        ExpectedPolicy::Development => Ok(AttestedPolicy::Development),
        ExpectedPolicy::Production {
            allow_vanilla_psbt,
            signer_role,
            evm_source,
            electrum_host,
            evm_rpc_tls,
            expected_chain_id,
            expected_bridge_contract,
            expected_rgb_asset_id,
            funds_in_contract,
            token_contract,
            evm_min_confirmations,
            gas_tx_allowed_to,
            gas_tx_max_gas_limit,
            gas_tx_max_fee_per_gas,
            gas_tx_max_value_wei,
            gas_tx_allowed_selectors,
            kms,
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

            // Check operator pins before building the expected commitment. (F02-AF-04)
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

            let clone_peer_pcr3 = clone_peer_pcr3(*signer_role, doc_pcrs)?;

            Ok(AttestedPolicy::Production {
                allow_vanilla_psbt: *allow_vanilla_psbt,
                signer_role: *signer_role,
                // A production enclave always uses real (NSM) attestation.
                // SPV is the only Bitcoin anchor source.
                attestation: AttestationMode::Real,
                evm_source: *evm_source,
                btc_source: BtcDataSource::SpvVerified,
                chain_id: resp.chain_id,
                bridge_contract,
                rgb_asset_id: resp.rgb_asset_id.clone(),
                funds_in_contract: *funds_in_contract,
                evm_min_confirmations: *evm_min_confirmations,
                electrum_host: electrum_host.clone(),
                evm_rpc_tls: evm_rpc_tls.clone(),
                // The operator declares the gas-tx rule. `to_bytes` sorts the
                // selector set, so the caller does not need to sort it.
                gas_tx_allowed_to: *gas_tx_allowed_to,
                gas_tx_max_gas_limit: *gas_tx_max_gas_limit,
                gas_tx_max_fee_per_gas: *gas_tx_max_fee_per_gas,
                gas_tx_max_value_wei: *gas_tx_max_value_wei,
                gas_tx_allowed_selectors: gas_tx_allowed_selectors.clone(),
                token_contract: *token_contract,
                kms: kms.clone(),
                clone_peer_pcr3,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A production expectation with the given chain_id, bridge_contract and
    /// rgb_asset_id pins. All other fields are neutral.
    fn expect_prod(
        chain_id: Option<u64>,
        bridge_contract: Option<[u8; 20]>,
        rgb_asset_id: Option<String>,
    ) -> ExpectedPolicy {
        ExpectedPolicy::Production {
            allow_vanilla_psbt: false,
            evm_source: EvmDataSource::RawRpc,
            signer_role: SignerRole::Combined,
            electrum_host: "electrum.test".into(),
            evm_rpc_tls: None,
            funds_in_contract: [0x11; 20],
            token_contract: [0x22; 20],
            evm_min_confirmations: 12,
            expected_chain_id: chain_id,
            expected_bridge_contract: bridge_contract,
            expected_rgb_asset_id: rgb_asset_id,
            gas_tx_allowed_to: [0u8; 20],
            gas_tx_max_gas_limit: 0,
            gas_tx_max_fee_per_gas: 0,
            gas_tx_max_value_wei: 0,
            gas_tx_allowed_selectors: Vec::new(),
            kms: None,
        }
    }

    fn production(signer_role: SignerRole) -> ExpectedPolicy {
        ExpectedPolicy::Production {
            allow_vanilla_psbt: false,
            signer_role,
            evm_source: EvmDataSource::PinnedTlsRpc,
            electrum_host: "electrum.test".into(),
            evm_rpc_tls: Some(EvmRpcTlsPin {
                host: "rpc.test".into(),
                ca_sha256: [0x33; 32],
            }),
            funds_in_contract: [0x11; 20],
            token_contract: [0x22; 20],
            evm_min_confirmations: 12,
            expected_chain_id: None,
            expected_bridge_contract: None,
            expected_rgb_asset_id: None,
            gas_tx_allowed_to: [0u8; 20],
            gas_tx_max_gas_limit: 0,
            gas_tx_max_fee_per_gas: 0,
            gas_tx_max_value_wei: 0,
            gas_tx_allowed_selectors: Vec::new(),
            kms: None,
        }
    }

    /// The PCRs of a mock document: zero PCR0/1/2 and the mock PCR3.
    fn mock_pcrs() -> std::collections::HashMap<u32, Vec<u8>> {
        let mut pcrs: std::collections::HashMap<u32, Vec<u8>> =
            (0..3).map(|i| (i, vec![0u8; 48])).collect();
        pcrs.insert(3, attestation_verify::MOCK_PCR3.to_vec());
        pcrs
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
        // Without operator pins, authenticate values without comparing them.
        let got = expected_attested_policy(&expect_prod(None, None, None), &wire(), &mock_pcrs())
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
        assert!(expected_attested_policy(&exp, &wire(), &mock_pcrs()).is_ok());
    }

    #[test]
    fn wrong_chain_id_is_rejected() {
        let exp = expect_prod(Some(1), None, None);
        let err = expected_attested_policy(&exp, &wire(), &mock_pcrs())
            .expect_err("wrong chain must fail");
        assert!(format!("{err:#}").contains("chain_id mismatch"));
    }

    #[test]
    fn wrong_bridge_contract_is_rejected() {
        let exp = expect_prod(None, Some([0x22u8; 20]), None);
        let err = expected_attested_policy(&exp, &wire(), &mock_pcrs())
            .expect_err("wrong contract must fail");
        assert!(format!("{err:#}").contains("bridge_contract mismatch"));
    }

    #[test]
    fn wrong_rgb_asset_is_rejected() {
        let exp = expect_prod(None, None, Some("rgb:other".into()));
        let err = expected_attested_policy(&exp, &wire(), &mock_pcrs())
            .expect_err("wrong asset must fail");
        assert!(format!("{err:#}").contains("rgb_asset_id mismatch"));
    }

    #[test]
    fn empty_asset_pin_matches_empty_wire() {
        // A build with no RGB asset (EVM or CCD only) must match a "" pin.
        let mut w = wire();
        w.rgb_asset_id = String::new();
        let exp = expect_prod(None, None, Some(String::new()));
        assert!(expected_attested_policy(&exp, &w, &mock_pcrs()).is_ok());
    }

    /// A response whose mock document commits to a production policy with
    /// `attested_role`.
    fn attested_response(attested_role: SignerRole, nonce: &[u8; 32]) -> AttestedPublicKeyResponse {
        attested_by(&production(attested_role), nonce)
    }

    /// A response whose mock document commits to `attested`.
    fn attested_by(attested: &ExpectedPolicy, nonce: &[u8; 32]) -> AttestedPublicKeyResponse {
        let pubkey = vec![0x04; 65];
        let mut resp = AttestedPublicKeyResponse {
            evm_address: vec![0x0E; 20],
            evm_uncompressed_pub: pubkey.clone(),
            chain_id: 1,
            bridge_contract: vec![0xAA; 20],
            rgb_asset_id: "rgb:asset".into(),
            ..Default::default()
        };
        resp.attested_policy = expected_attested_policy(attested, &resp, &mock_pcrs())
            .unwrap()
            .to_bytes();
        let mut preimage = canonical_bundle(&resp);
        preimage.extend_from_slice(&resp.attested_policy);
        let user_data: [u8; 32] = Sha256::digest(&preimage).into();
        resp.attestation_doc =
            attestation_verify::build_mock_document(nonce, Some(&pubkey), Some(&user_data))
                .unwrap();
        resp
    }

    fn verify(attested: SignerRole, expected: SignerRole) -> Result<AttestedPubkeyResult> {
        let nonce = [0x42; 32];
        verify_attested_response(
            attested_response(attested, &nonce),
            nonce,
            &attestation_verify::ExpectedPcrs::zero(),
            VerifyMode::Mock,
            &production(expected),
        )
    }

    #[test]
    fn matching_signer_role_verifies() {
        verify(SignerRole::Mint, SignerRole::Mint).unwrap();
        verify(SignerRole::Burn, SignerRole::Burn).unwrap();
    }

    /// Everything but the role matches, so the role alone fails the check.
    #[test]
    fn wrong_signer_role_alone_fails() {
        for (attested, expected) in [
            (SignerRole::Burn, SignerRole::Mint),
            (SignerRole::Mint, SignerRole::Burn),
            (SignerRole::Combined, SignerRole::Mint),
        ] {
            let err = verify(attested, expected).unwrap_err();
            assert!(
                format!("{err:#}").contains("expected policy"),
                "attested {attested:?}, expected {expected:?}: {err:#}"
            );
        }
    }

    #[test]
    fn wrong_evm_rpc_tls_pin_fails() {
        let nonce = [0x42; 32];
        for (host, ca_sha256) in [("other.test", [0x33; 32]), ("rpc.test", [0x44; 32])] {
            let mut expected = production(SignerRole::Mint);
            if let ExpectedPolicy::Production { evm_rpc_tls, .. } = &mut expected {
                *evm_rpc_tls = Some(EvmRpcTlsPin {
                    host: host.into(),
                    ca_sha256,
                });
            }
            let err = verify_attested_response(
                attested_response(SignerRole::Mint, &nonce),
                nonce,
                &attestation_verify::ExpectedPcrs::zero(),
                VerifyMode::Mock,
                &expected,
            )
            .unwrap_err();
            assert!(format!("{err:#}").contains("expected policy"), "{err:#}");
        }
    }

    fn with_kms(kms: Option<KmsPin>) -> ExpectedPolicy {
        let mut p = production(SignerRole::Mint);
        if let ExpectedPolicy::Production { kms: k, .. } = &mut p {
            *k = kms;
        }
        p
    }

    fn a_kms_pin() -> KmsPin {
        KmsPin {
            key_arn: "arn:aws:kms:eu-west-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef"
                .into(),
            region: "eu-west-1".into(),
            seed_id: "seed-1".into(),
            expected_evm_address: Some([0x42; 20]),
        }
    }

    fn verify_policy(
        resp: AttestedPublicKeyResponse,
        expected: &ExpectedPolicy,
    ) -> Result<AttestedPubkeyResult> {
        verify_attested_response(
            resp,
            [0x42; 32],
            &attestation_verify::ExpectedPcrs::zero(),
            VerifyMode::Mock,
            expected,
        )
    }

    #[test]
    fn tampered_policy_bytes_fail() {
        let expected = with_kms(Some(a_kms_pin()));
        let good = attested_by(&expected, &[0x42; 32]);
        let mut flipped = good.clone();
        let last = flipped.attested_policy.len() - 1;
        flipped.attested_policy[last] ^= 1;
        let mut swapped = good.clone();
        swapped.attested_policy = attested_by(&with_kms(None), &[0x42; 32]).attested_policy;
        for resp in [flipped, swapped] {
            let err = verify_policy(resp, &expected).unwrap_err();
            assert!(
                format!("{err:#}").contains("do not match the attestation"),
                "{err:#}"
            );
        }
        verify_policy(good, &expected).unwrap();
    }

    #[test]
    fn wrong_kms_pin_fails() {
        let resp = attested_by(&with_kms(Some(a_kms_pin())), &[0x42; 32]);
        let edits: [fn(&mut KmsPin); 4] = [
            |k| k.key_arn = k.key_arn.replace("mrk-0", "mrk-1"),
            |k| k.region = "eu-west-2".into(),
            |k| k.seed_id = "seed-2".into(),
            |k| k.expected_evm_address = None,
        ];
        for edit in edits {
            let mut pin = a_kms_pin();
            edit(&mut pin);
            let err = verify_policy(resp.clone(), &with_kms(Some(pin))).unwrap_err();
            assert!(
                format!("{err:#}").contains("does not match the expected policy"),
                "{err:#}"
            );
        }
        let err = verify_policy(resp.clone(), &with_kms(None)).unwrap_err();
        assert!(
            format!("{err:#}").contains("does not match the expected policy"),
            "{err:#}"
        );
        let ok = verify_policy(resp, &with_kms(Some(a_kms_pin()))).unwrap();
        assert!(
            matches!(ok.policy, AttestedPolicy::Production { kms: Some(k), .. } if k == a_kms_pin())
        );
    }

    /// A burn expectation with chain and contract pins.
    fn burn_pinned(chain_id: Option<u64>, bridge_contract: Option<[u8; 20]>) -> ExpectedPolicy {
        let mut p = production(SignerRole::Burn);
        if let ExpectedPolicy::Production {
            expected_chain_id,
            expected_bridge_contract,
            ..
        } = &mut p
        {
            *expected_chain_id = chain_id;
            *expected_bridge_contract = bridge_contract;
        }
        p
    }

    #[test]
    fn a_tampered_bundle_fails_with_the_field_named() {
        let nonce = [0x42; 32];
        let good = {
            let resp = attested_by(&production(SignerRole::Burn), &nonce);
            let result = verify_policy(resp, &production(SignerRole::Burn)).unwrap();
            assert_eq!(result.nonce_sent, nonce);
            serde_json::to_value(AttestationBundle::new(&result)).unwrap()
        };
        let zero = ExpectedPcrs::zero();
        let pcr0 = ExpectedPcrs::new([1; 48], [0; 48], [0; 48]);
        let verify =
            |bundle: &serde_json::Value, pcrs: &ExpectedPcrs, expected: &ExpectedPolicy| {
                verify_bundle(&bundle.to_string(), pcrs, VerifyMode::Mock, expected)
            };
        let ok = verify(&good, &zero, &burn_pinned(Some(1), Some([0xAA; 20]))).unwrap();
        assert_eq!(ok.response.evm_uncompressed_pub, vec![0x04; 65]);

        /// Change the last hex digit.
        fn flip(v: &mut serde_json::Value) {
            let s = v.as_str().unwrap();
            let last = if s.ends_with('0') { '1' } else { '0' };
            *v = format!("{}{last}", &s[..s.len() - 1]).into();
        }
        type Edit = fn(&mut serde_json::Value);
        let rows: [(Edit, &ExpectedPcrs, ExpectedPolicy, &str); 7] = [
            (
                |b| flip(&mut b["public_keys"]["evm_uncompressed_pub"]),
                &zero,
                production(SignerRole::Burn),
                "public_key",
            ),
            (
                |b| flip(&mut b["nonce"]),
                &zero,
                production(SignerRole::Burn),
                "nonce mismatch",
            ),
            (
                |b| flip(&mut b["attested_policy"]),
                &zero,
                production(SignerRole::Burn),
                "user_data",
            ),
            (
                |b| {
                    let row = b["policy"]
                        .as_array_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|r| r[0] == "chain_id")
                        .unwrap();
                    row[1] = "42161".into();
                },
                &zero,
                production(SignerRole::Burn),
                "policy field chain_id mismatch",
            ),
            (|_| {}, &pcr0, production(SignerRole::Burn), "PCR0"),
            (
                |_| {},
                &zero,
                burn_pinned(None, Some([0xBB; 20])),
                "bridge_contract mismatch",
            ),
            (
                |_| {},
                &zero,
                burn_pinned(Some(42161), None),
                "chain_id mismatch",
            ),
        ];
        for (edit, pcrs, expected, message) in rows {
            let mut bundle = good.clone();
            edit(&mut bundle);
            let err = verify(&bundle, pcrs, &expected).unwrap_err();
            assert!(format!("{err:#}").contains(message), "{message}: {err:#}");
        }
    }

    #[test]
    fn a_real_format_expired_bundle_verifies_offline() {
        use attestation_verify::test_util::{signed_document, verify_at_document_time_with_root};
        let nonce = [0x42; 32];
        let pcrs = ExpectedPcrs::new([1; 48], [2; 48], [3; 48]);
        let mut resp = attested_by(&production(SignerRole::Burn), &nonce);
        let mock: VerifiedAttestation = attestation_verify::verify_mock_attestation(
            &resp.attestation_doc,
            &ExpectedPcrs::zero(),
            None,
        )
        .unwrap();
        // 2020-01-01T12:00:00Z. The leaf certificate expired on 2020-01-02.
        let (doc, root) = signed_document(
            &pcrs,
            &nonce,
            Some(&resp.evm_uncompressed_pub),
            &mock.user_data.unwrap(),
            1_577_880_000_000,
            Some((2020, 1, 1)),
        );
        resp.attestation_doc = doc;
        let verify_doc = |doc: &[u8], nonce: &[u8; 32]| {
            verify_at_document_time_with_root(doc, &pcrs, nonce, &root)
                .context("attestation verify failed")
        };
        let result = verify_keyed(resp, nonce, |doc| verify_doc(doc, &nonce)).unwrap();
        let mut bundle = AttestationBundle::new(&result);
        let expected = production(SignerRole::Burn);
        verify_bundle_with(
            &serde_json::to_string(&bundle).unwrap(),
            &expected,
            verify_doc,
        )
        .unwrap();

        // The signature is the last element, so the last byte is in it.
        let mut doc = BASE64.decode(&bundle.attestation_doc).unwrap();
        *doc.last_mut().unwrap() ^= 1;
        bundle.attestation_doc = BASE64.encode(doc);
        let err = verify_bundle_with(
            &serde_json::to_string(&bundle).unwrap(),
            &expected,
            verify_doc,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("COSE signature"), "{err:#}");
    }

    /// The enclave answer that `resp` maps from.
    fn enclave_answer(resp: AttestedPublicKeyResponse) -> GetAttestedPublicKeyResponse {
        GetAttestedPublicKeyResponse {
            public_keys: Some(crate::enclave_proto::PublicKeysResponse {
                evm_address: resp.evm_address,
                evm_uncompressed_pub: resp.evm_uncompressed_pub,
                chain_id: resp.chain_id,
                bridge_contract: resp.bridge_contract,
                rgb_asset_id: resp.rgb_asset_id,
                ..Default::default()
            }),
            attestation_doc: resp.attestation_doc,
            attested_policy: resp.attested_policy,
        }
    }

    #[test]
    fn export_refuses_what_does_not_verify() {
        let nonce = [0x42; 32];
        let resp = attested_by(&production(SignerRole::Burn), &nonce);
        let burn =
            expected_attested_policy(&production(SignerRole::Burn), &resp, &mock_pcrs()).unwrap();
        let combined =
            expected_attested_policy(&production(SignerRole::Combined), &resp, &mock_pcrs())
                .unwrap();
        let zero = ExpectedPcrs::zero();
        let export = |answer, pcrs: &ExpectedPcrs, expected: &AttestedPolicy, evm| {
            export_bundle(answer, nonce, pcrs, VerifyMode::Mock, expected, evm)
        };

        let bundle = export(enclave_answer(resp.clone()), &zero, &burn, Some([0x0E; 20])).unwrap();
        let json = serde_json::to_string(&bundle).unwrap();
        verify_bundle(
            &json,
            &zero,
            VerifyMode::Mock,
            &production(SignerRole::Burn),
        )
        .unwrap();

        let no_key = GetAttestedPublicKeyResponse {
            public_keys: None,
            ..enclave_answer(resp.clone())
        };
        let other_pcrs = ExpectedPcrs::new([1; 48], [0; 48], [0; 48]);
        let cases = [
            (no_key, &zero, &burn, None, "no key"),
            (
                enclave_answer(resp.clone()),
                &zero,
                &combined,
                None,
                "signer_role mismatch",
            ),
            (
                enclave_answer(resp.clone()),
                &other_pcrs,
                &burn,
                None,
                "PCR0",
            ),
            (
                enclave_answer(resp.clone()),
                &zero,
                &burn,
                Some([1; 20]),
                "evm_address mismatch",
            ),
        ];
        for (answer, pcrs, expected, evm, message) in cases {
            let err = export(answer, pcrs, expected, evm).unwrap_err();
            assert!(format!("{err:#}").contains(message), "{message}: {err:#}");
        }
    }

    /// Issue #270: a cloning role commits the document PCR3 (the parent IAM
    /// role). The mint signer commits none.
    #[test]
    fn a_cloning_role_commits_the_document_pcr3() {
        for (role, want) in [
            (SignerRole::Burn, Some(attestation_verify::MOCK_PCR3)),
            (SignerRole::Combined, Some(attestation_verify::MOCK_PCR3)),
            (SignerRole::Mint, None),
        ] {
            let got = expected_attested_policy(&production(role), &wire(), &mock_pcrs()).unwrap();
            let AttestedPolicy::Production {
                clone_peer_pcr3, ..
            } = got
            else {
                panic!("expected Production");
            };
            assert_eq!(clone_peer_pcr3, want, "{role:?}");
        }
    }

    /// A cloning role on an instance with no IAM role (all-zero or missing
    /// PCR3) fails verification.
    #[test]
    fn a_cloning_role_without_an_iam_role_fails() {
        let mut zero = mock_pcrs();
        zero.insert(3, vec![0u8; 48]);
        let err =
            expected_attested_policy(&production(SignerRole::Burn), &wire(), &zero).unwrap_err();
        assert!(err.to_string().contains("no IAM role"), "{err}");

        let mut missing = mock_pcrs();
        missing.remove(&3);
        assert!(
            expected_attested_policy(&production(SignerRole::Burn), &wire(), &missing).is_err()
        );

        // The mint signer does not clone, so it needs no PCR3.
        assert!(expected_attested_policy(&production(SignerRole::Mint), &wire(), &zero).is_ok());
    }

    /// The committed PCR3 must be the document's PCR3: a policy that names
    /// another role does not verify.
    #[test]
    fn a_committed_pcr3_that_is_not_the_document_pcr3_fails() {
        let nonce = [0x42; 32];
        let attested = production(SignerRole::Burn);
        let pubkey = vec![0x04; 65];
        let mut resp = AttestedPublicKeyResponse {
            evm_uncompressed_pub: pubkey.clone(),
            chain_id: 1,
            bridge_contract: vec![0xAA; 20],
            rgb_asset_id: "rgb:asset".into(),
            ..Default::default()
        };
        let mut other_role = mock_pcrs();
        other_role.insert(3, vec![0x44; 48]);
        resp.attested_policy = expected_attested_policy(&attested, &resp, &other_role)
            .unwrap()
            .to_bytes();
        let mut preimage = canonical_bundle(&resp);
        preimage.extend_from_slice(&resp.attested_policy);
        let user_data: [u8; 32] = Sha256::digest(&preimage).into();
        resp.attestation_doc =
            attestation_verify::build_mock_document(&nonce, Some(&pubkey), Some(&user_data))
                .unwrap();
        let err = verify_attested_response(
            resp,
            nonce,
            &attestation_verify::ExpectedPcrs::zero(),
            VerifyMode::Mock,
            &attested,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the expected policy"),
            "{err}"
        );
    }
}
