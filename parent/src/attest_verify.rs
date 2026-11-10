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
    AttestationMode, AttestedPolicy, BitcoinNetwork, BtcDataSource, EvmDataSource, EvmFinalityTag,
    EvmRpcTlsPin, ExpectedPcrs, KmsPin, SignerRole, VerifiedAttestation,
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
/// path. Production MUST use `Real`. Mock refuses a Production expectation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerifyMode {
    Real,
    Mock,
}

impl VerifyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyMode::Real => "real",
            VerifyMode::Mock => "mock",
        }
    }
}

/// Fail for Mock mode with a Production expectation.
pub(crate) fn refuse_mock_production(mode: VerifyMode, production: bool) -> Result<()> {
    if mode == VerifyMode::Mock && production {
        bail!("mock mode refuses a Production expectation: a mock document proves no enclave");
    }
    Ok(())
}

/// The security posture the caller expects from the attested enclave.
///
/// The enclave commits its posture into `user_data`. The verifier builds the
/// expected posture and requires an exact match, so a downgraded enclave fails.
///
/// Chain, contract and asset values come from the wire response, which the
/// public-key bundle binds. This type gives only the posture flags and rules
/// that are not on the wire. The optional chain, contract and asset pins
/// also compare the wire values with the operator deployment.
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
        /// Expected Bitcoin network. It is not on the wire, so the operator
        /// declares it.
        bitcoin_network: BitcoinNetwork,
        /// Expected 20-byte bridge or MultisigProxy address. `Some` requires
        /// an exact match.
        expected_bridge_contract: Option<[u8; 20]>,
        /// Expected RGB asset ID. `Some` requires an exact match. An empty
        /// string requires no RGB asset.
        expected_rgb_asset_id: Option<String>,
        funds_in_contract: [u8; 20],
        /// Required EVM RPC head tag; never inferred from the enclave response.
        evm_finality_tag: EvmFinalityTag,
        /// Expected ERC-20 that the Bridge releases (`TOKEN_CONTRACT`). It is
        /// an input to the `burnId` preimage. It is not on the wire, so the
        /// operator declares it.
        token_contract: [u8; 20],
        /// Expected Bitcoin witness depth (`SPV_MIN_CONFIRMATIONS`).
        spv_min_confirmations: u32,
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

/// A passed verification. `mode` tells how the document was checked. Only
/// `Real` with independently approved PCRs and expected policy binds the key
/// bundle and policy to measured code; it does not prove the key's original
/// generation or exclusive custody. Public fields also allow direct
/// construction, so this type alone is not proof of verification.
#[derive(Debug, Clone)]
pub struct AttestedPubkeyResult {
    pub mode: VerifyMode,
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
    let parts: [&[u8]; 10] = [
        &resp.evm_address,
        &resp.master_fingerprint,
        resp.account_xpub_vanilla.as_bytes(),
        resp.account_xpub_colored.as_bytes(),
        &resp.evm_uncompressed_pub,
        &chain_id_bytes,
        &resp.bridge_contract,
        resp.rgb_asset_id.as_bytes(),
        &resp.evm_gas_tx_uncompressed_pub,
        &resp.evm_gas_tx_address,
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
    refuse_mock_production(
        mode,
        matches!(expected_policy, ExpectedPolicy::Production { .. }),
    )?;
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
    verify_attested_response_with(response, nonce, mode, expected_policy, |doc| {
        verify_now(doc, expected_pcrs, &nonce, mode)
    })
}

fn verify_attested_response_with(
    response: AttestedPublicKeyResponse,
    nonce: [u8; 32],
    mode: VerifyMode,
    expected_policy: &ExpectedPolicy,
    verify_doc: impl FnOnce(&[u8]) -> Result<VerifiedAttestation>,
) -> Result<AttestedPubkeyResult> {
    refuse_mock_production(
        mode,
        matches!(expected_policy, ExpectedPolicy::Production { .. }),
    )?;
    let result = verify_keyed(response, nonce, mode, verify_doc)?;
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
    mode: VerifyMode,
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
        mode,
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
        master_fingerprint: pk.master_fingerprint,
        account_xpub_vanilla: pk.account_xpub_vanilla,
        account_xpub_colored: pk.account_xpub_colored,
        attestation_doc: r.attestation_doc,
        chain_id: pk.chain_id,
        bridge_contract: pk.bridge_contract,
        rgb_asset_id: pk.rgb_asset_id,
        evm_gas_tx_uncompressed_pub: pk.evm_gas_tx_uncompressed_pub,
        evm_gas_tx_address: pk.evm_gas_tx_address,
        attested_policy: r.attested_policy,
    })
}

/// The `format` value of an [`AttestationBundle`].
pub const BUNDLE_FORMAT: &str = "utexo-signer-attestation/3";

/// One verified attested answer, stored for offline verification.
/// Bytes are 0x-hex, except the document, which is base64.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationBundle {
    pub format: String,
    /// The mode that verified the bundle. The document does not sign it.
    /// [`verify_bundle`] requires it to equal the mode of the check.
    pub verification_mode: VerifyMode,
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
    pub master_fingerprint: String,
    pub account_xpub_vanilla: String,
    pub account_xpub_colored: String,
    pub evm_uncompressed_pub: String,
    pub chain_id: u64,
    pub bridge_contract: String,
    pub rgb_asset_id: String,
    pub evm_gas_tx_uncompressed_pub: String,
    pub evm_gas_tx_address: String,
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn from_hex0x(field: &str, value: &str) -> Result<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .with_context(|| format!("bundle field {field} is not hex"))
}

impl BundleKeys {
    fn new(r: &AttestedPublicKeyResponse) -> Self {
        Self {
            evm_address: hex0x(&r.evm_address),
            master_fingerprint: hex0x(&r.master_fingerprint),
            account_xpub_vanilla: r.account_xpub_vanilla.clone(),
            account_xpub_colored: r.account_xpub_colored.clone(),
            evm_uncompressed_pub: hex0x(&r.evm_uncompressed_pub),
            chain_id: r.chain_id,
            bridge_contract: hex0x(&r.bridge_contract),
            rgb_asset_id: r.rgb_asset_id.clone(),
            evm_gas_tx_uncompressed_pub: hex0x(&r.evm_gas_tx_uncompressed_pub),
            evm_gas_tx_address: hex0x(&r.evm_gas_tx_address),
        }
    }

    /// Each key as (name, value), in field order.
    fn fields(&self) -> [(&'static str, String); 10] {
        let Self {
            evm_address,
            master_fingerprint,
            account_xpub_vanilla,
            account_xpub_colored,
            evm_uncompressed_pub,
            chain_id,
            bridge_contract,
            rgb_asset_id,
            evm_gas_tx_uncompressed_pub,
            evm_gas_tx_address,
        } = self;
        [
            ("evm_address", evm_address.clone()),
            ("master_fingerprint", master_fingerprint.clone()),
            ("account_xpub_vanilla", account_xpub_vanilla.clone()),
            ("account_xpub_colored", account_xpub_colored.clone()),
            ("evm_uncompressed_pub", evm_uncompressed_pub.clone()),
            ("chain_id", chain_id.to_string()),
            ("bridge_contract", bridge_contract.clone()),
            ("rgb_asset_id", rgb_asset_id.clone()),
            (
                "evm_gas_tx_uncompressed_pub",
                evm_gas_tx_uncompressed_pub.clone(),
            ),
            ("evm_gas_tx_address", evm_gas_tx_address.clone()),
        ]
    }
}

/// The `attest-verify` output on success: `OK`, then one `name: value` line
/// per verified field. The names are the paths of the exported bundle. Control
/// characters in a value are escaped, so each field is one line.
pub fn verified_report(result: &AttestedPubkeyResult) -> String {
    let v = &result.verified;
    let pcr = |i| hex0x(v.pcrs.get(&i).map_or(&[][..], Vec::as_slice));
    let keys = BundleKeys::new(&result.response).fields();
    let policy = launch_check::fields(&result.policy);
    let lines = [("mode".to_string(), format!("{:?}", result.mode))]
        .into_iter()
        .chain(keys.map(|(name, value)| (format!("public_keys.{name}"), value)))
        .chain([
            ("bundle_commitment".into(), hex0x(&result.bundle_commitment)),
            ("pcr0".into(), pcr(0)),
            ("pcr1".into(), pcr(1)),
            ("pcr2".into(), pcr(2)),
            ("timestamp_ms".into(), v.timestamp.to_string()),
            ("nonce".into(), hex0x(&result.nonce_sent)),
        ])
        .chain(
            policy
                .into_iter()
                .map(|(name, value)| (format!("policy.{name}"), value)),
        );
    let mut out = String::from("OK\n");
    for (name, value) in lines {
        out += &format!("  {name}: {}\n", value.escape_debug());
    }
    out
}

impl AttestationBundle {
    fn new(result: &AttestedPubkeyResult) -> Self {
        let r = &result.response;
        Self {
            format: BUNDLE_FORMAT.into(),
            verification_mode: result.mode,
            nonce: hex0x(&result.nonce_sent),
            attestation_doc: BASE64.encode(&r.attestation_doc),
            public_keys: BundleKeys::new(r),
            attested_policy: hex0x(&r.attested_policy),
            policy: launch_check::fields(&result.policy)
                .into_iter()
                .map(|(field, value)| (field.into(), value))
                .collect(),
        }
    }

    /// The nonce and the parent RPC answer that the bundle stores.
    fn response(&self) -> Result<([u8; 32], AttestedPublicKeyResponse)> {
        let nonce = from_hex0x("nonce", &self.nonce)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bundle field nonce is not 32 bytes"))?;
        let k = &self.public_keys;
        let response = AttestedPublicKeyResponse {
            evm_address: from_hex0x("evm_address", &k.evm_address)?,
            evm_uncompressed_pub: from_hex0x("evm_uncompressed_pub", &k.evm_uncompressed_pub)?,
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
    export_bundle_with(response, nonce, mode, expected, expect_evm, |doc| {
        verify_now(doc, pcrs, &nonce, mode)
    })
}

fn export_bundle_with(
    response: GetAttestedPublicKeyResponse,
    nonce: [u8; 32],
    mode: VerifyMode,
    expected: &AttestedPolicy,
    expect_evm: Option<[u8; 20]>,
    verify_doc: impl FnOnce(&[u8]) -> Result<VerifiedAttestation>,
) -> Result<AttestationBundle> {
    refuse_mock_production(mode, matches!(expected, AttestedPolicy::Production { .. }))?;
    let result = verify_keyed(attested_response(response)?, nonce, mode, verify_doc)?;
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
    verify_bundle_with(json, mode, expected_policy, |doc, nonce| match mode {
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
    mode: VerifyMode,
    expected_policy: &ExpectedPolicy,
    verify_doc: impl FnOnce(&[u8], &[u8; 32]) -> Result<VerifiedAttestation>,
) -> Result<AttestedPubkeyResult> {
    refuse_mock_production(
        mode,
        matches!(expected_policy, ExpectedPolicy::Production { .. }),
    )?;
    // Read the format first, so another bundle format fails with a clear message.
    #[derive(Deserialize)]
    struct Format {
        format: String,
    }
    let Format { format } =
        serde_json::from_str(json).context("the file is not an attestation bundle")?;
    if format != BUNDLE_FORMAT {
        bail!("bundle format {format:?} is not supported; export the bundle again");
    }
    let bundle: AttestationBundle =
        serde_json::from_str(json).context("the file is not an attestation bundle")?;
    if bundle.verification_mode != mode {
        bail!(
            "bundle verification_mode {} does not match the {} mode of this check",
            bundle.verification_mode.as_str(),
            mode.as_str()
        );
    }
    let (nonce, response) = bundle.response()?;
    let result = verify_keyed(response, nonce, mode, |doc| verify_doc(doc, &nonce))?;
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
            bitcoin_network,
            expected_bridge_contract,
            expected_rgb_asset_id,
            funds_in_contract,
            evm_finality_tag,
            token_contract,
            spv_min_confirmations,
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

            // Check operator pins before building the expected commitment.
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
                bitcoin_network: *bitcoin_network,
                bridge_contract,
                rgb_asset_id: resp.rgb_asset_id.clone(),
                funds_in_contract: *funds_in_contract,
                evm_finality_tag: *evm_finality_tag,
                spv_min_confirmations: *spv_min_confirmations,
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
mod tests;
