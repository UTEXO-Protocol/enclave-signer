//! Verify the launch policy against the measured image and deploy inputs.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};
use attestation_verify::{
    policy_commitment, AttestationMode, AttestedPolicy, BtcDataSource, EvmDataSource, EvmRpcTlsPin,
    ExpectedPcrs, KmsPin, SignerRole,
};
use sha2::{Digest, Sha256};

use crate::attest_verify::VerifyMode;
use crate::enclave_proto::{GetAttestedPublicKeyResponse, SetEndpointsRequest};

/// The policy that a production enclave of `role` must attest after
/// `endpoints` is set. `image_env` is the `Config.Env` JSON list of the
/// measured image.
pub fn expected_policy(
    role: SignerRole,
    image_env: &str,
    endpoints: &SetEndpointsRequest,
) -> Result<AttestedPolicy> {
    let entries: Vec<String> =
        serde_json::from_str(image_env).context("IMAGE-ENV.json is not a list of strings")?;
    let env: HashMap<&str, &str> = entries.iter().filter_map(|e| e.split_once('=')).collect();
    let required = |key: &str| {
        env.get(key)
            .copied()
            .with_context(|| format!("IMAGE-ENV.json has no {key}"))
    };
    let optional = |key: &str| env.get(key).copied().filter(|v| !v.is_empty());
    // An unset optional number is 0, as in the enclave.
    fn number<T: std::str::FromStr + Default>(key: &str, value: Option<&str>) -> Result<T> {
        value.map_or(Ok(T::default()), |v| {
            v.parse()
                .map_err(|_| anyhow!("{key} {v:?} is not a number"))
        })
    }
    let signs_gas_tx = role != SignerRole::Mint;
    let gas = |key: &str| optional(key).filter(|_| signs_gas_tx);

    let url = endpoints
        .electrum_url
        .strip_suffix('/')
        .unwrap_or(&endpoints.electrum_url);
    let electrum_host = url
        .strip_prefix("ssl://")
        .or_else(|| url.strip_prefix("tcp://"))
        .and_then(|rest| rest.rsplit_once(':'))
        .map(|(host, _)| host.to_ascii_lowercase())
        .with_context(|| format!("electrum_url {url:?} is not ssl:// or tcp://host:port"))?;
    let evm_rpc_tls = (!endpoints.evm_rpc_ca_der.is_empty()).then(|| EvmRpcTlsPin {
        host: endpoints.evm_rpc_host.to_ascii_lowercase(),
        ca_sha256: Sha256::digest(&endpoints.evm_rpc_ca_der).into(),
    });
    let kms_values = [
        &endpoints.kms_key_arn,
        &endpoints.kms_region,
        &endpoints.kms_seed_id,
        &endpoints.kms_expected_evm_address,
    ];
    let kms = if kms_values.iter().all(|v| v.is_empty()) {
        None
    } else {
        let address = &endpoints.kms_expected_evm_address;
        Some(KmsPin {
            key_arn: endpoints.kms_key_arn.clone(),
            region: endpoints.kms_region.clone(),
            seed_id: endpoints.kms_seed_id.clone(),
            expected_evm_address: (!address.is_empty())
                .then(|| address20("KMS_EXPECTED_EVM_ADDRESS", address))
                .transpose()?,
        })
    };

    Ok(AttestedPolicy::Production {
        allow_vanilla_psbt: role != SignerRole::Burn
            && number::<u64>("BTC_MAX_TOTAL_SATS", optional("BTC_MAX_TOTAL_SATS"))? != 0,
        signer_role: role,
        attestation: AttestationMode::Real,
        evm_source: EvmDataSource::PinnedTlsRpc,
        btc_source: BtcDataSource::SpvVerified,
        chain_id: number("EVM_CHAIN_ID", Some(required("EVM_CHAIN_ID")?))?,
        bridge_contract: address20(
            "EVM_PROXY_CONTRACT_ADDRESS",
            required("EVM_PROXY_CONTRACT_ADDRESS")?,
        )?,
        rgb_asset_id: required("RGB_ASSET_ID")?.to_string(),
        funds_in_contract: address20("FUNDS_IN_CONTRACT", required("FUNDS_IN_CONTRACT")?)?,
        evm_min_confirmations: number(
            "EVM_MIN_CONFIRMATIONS",
            Some(required("EVM_MIN_CONFIRMATIONS")?),
        )?,
        electrum_host,
        evm_rpc_tls,
        gas_tx_allowed_to: gas("GAS_TX_ALLOWED_TO")
            .map_or(Ok([0; 20]), |v| address20("GAS_TX_ALLOWED_TO", v))?,
        gas_tx_max_gas_limit: number("GAS_TX_MAX_GAS_LIMIT", gas("GAS_TX_MAX_GAS_LIMIT"))?,
        gas_tx_max_fee_per_gas: number("GAS_TX_MAX_FEE_PER_GAS", gas("GAS_TX_MAX_FEE_PER_GAS"))?,
        gas_tx_max_value_wei: number("GAS_TX_MAX_VALUE_WEI", gas("GAS_TX_MAX_VALUE_WEI"))?,
        gas_tx_allowed_selectors: gas("GAS_TX_ALLOWED_SELECTORS")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                hex::decode(s.strip_prefix("0x").unwrap_or(s))
                    .ok()
                    .and_then(|b| <[u8; 4]>::try_from(b).ok())
                    .with_context(|| format!("GAS_TX_ALLOWED_SELECTORS entry {s:?} is not 4 bytes"))
            })
            .collect::<Result<_>>()?,
        token_contract: address20("TOKEN_CONTRACT", required("TOKEN_CONTRACT")?)?,
        kms,
    })
}

fn address20(key: &str, value: &str) -> Result<[u8; 20]> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .ok()
        .and_then(|b| b.try_into().ok())
        .with_context(|| format!("{key} {value:?} is not a 20-byte hex address"))
}

/// Verify a policy-only attestation for `nonce` and compare its policy with
/// `expected`, field by field. The error names the first field that differs.
pub fn check_launch(
    response: GetAttestedPublicKeyResponse,
    nonce: [u8; 32],
    pcrs: &ExpectedPcrs,
    expected: &AttestedPolicy,
    mode: VerifyMode,
) -> Result<AttestedPolicy> {
    if response.public_keys.is_some() {
        bail!("the enclave already has keys; the launch check needs a fresh enclave");
    }
    let verified = match mode {
        VerifyMode::Real => {
            attestation_verify::verify_policy_attestation(&response.attestation_doc, pcrs, &nonce)
        }
        VerifyMode::Mock => attestation_verify::verify_mock_policy_attestation(
            &response.attestation_doc,
            pcrs,
            &nonce,
        ),
    }
    .context("attestation verification failed")?;
    if verified.user_data.as_deref()
        != Some(policy_commitment(&response.attested_policy).as_slice())
    {
        bail!("attestation user_data does not commit the returned policy bytes");
    }
    let attested = AttestedPolicy::from_bytes(&response.attested_policy)?;
    for ((field, want), (_, got)) in fields(expected).into_iter().zip(fields(&attested)) {
        if want != got {
            bail!("{field} mismatch: expected {want}, attested {got}");
        }
    }
    if expected.to_bytes() != response.attested_policy {
        bail!("attested policy bytes differ from the expected policy");
    }
    Ok(attested)
}

/// Each field of `policy` as (name, value), in wire order. An option gives a
/// present/absent entry before its subfields.
pub fn fields(policy: &AttestedPolicy) -> Vec<(&'static str, String)> {
    let AttestedPolicy::Production {
        allow_vanilla_psbt,
        signer_role,
        attestation,
        evm_source,
        btc_source,
        chain_id,
        bridge_contract,
        rgb_asset_id,
        funds_in_contract,
        evm_min_confirmations,
        electrum_host,
        evm_rpc_tls,
        gas_tx_allowed_to,
        gas_tx_max_gas_limit,
        gas_tx_max_fee_per_gas,
        gas_tx_max_value_wei,
        gas_tx_allowed_selectors,
        token_contract,
        kms,
    } = policy
    else {
        return vec![("policy", "Development".into())];
    };
    let hex = |b: &[u8]| format!("0x{}", hex::encode(b));
    let presence = |present: bool| if present { "present" } else { "absent" }.to_string();
    let mut selectors = gas_tx_allowed_selectors.clone();
    selectors.sort_unstable();
    selectors.dedup();
    let mut out = vec![
        ("policy", "Production".into()),
        ("allow_vanilla_psbt", allow_vanilla_psbt.to_string()),
        ("signer_role", format!("{signer_role:?}")),
        ("attestation", format!("{attestation:?}")),
        ("evm_source", format!("{evm_source:?}")),
        ("btc_source", format!("{btc_source:?}")),
        ("chain_id", chain_id.to_string()),
        ("bridge_contract", hex(bridge_contract)),
        ("rgb_asset_id", rgb_asset_id.clone()),
        ("funds_in_contract", hex(funds_in_contract)),
        ("evm_min_confirmations", evm_min_confirmations.to_string()),
        ("electrum_host", electrum_host.clone()),
        ("evm_rpc_tls", presence(evm_rpc_tls.is_some())),
    ];
    if let Some(pin) = evm_rpc_tls {
        out.push(("evm_rpc_tls.host", pin.host.clone()));
        out.push(("evm_rpc_tls.ca_sha256", hex(&pin.ca_sha256)));
    }
    out.extend([
        ("gas_tx_allowed_to", hex(gas_tx_allowed_to)),
        ("gas_tx_max_gas_limit", gas_tx_max_gas_limit.to_string()),
        ("gas_tx_max_fee_per_gas", gas_tx_max_fee_per_gas.to_string()),
        ("gas_tx_max_value_wei", gas_tx_max_value_wei.to_string()),
        (
            "gas_tx_allowed_selectors",
            selectors
                .iter()
                .map(|s| hex(s))
                .collect::<Vec<_>>()
                .join(","),
        ),
        ("token_contract", hex(token_contract)),
        ("kms", presence(kms.is_some())),
    ]);
    if let Some(pin) = kms {
        out.extend([
            ("kms.key_arn", pin.key_arn.clone()),
            ("kms.region", pin.region.clone()),
            ("kms.seed_id", pin.seed_id.clone()),
            (
                "kms.expected_evm_address",
                pin.expected_evm_address.map_or("none".into(), |a| hex(&a)),
            ),
        ]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PCRS: ExpectedPcrs = ExpectedPcrs {
        pcr0: [1; 48],
        pcr1: [2; 48],
        pcr2: [3; 48],
    };
    const NONCE: [u8; 32] = [7; 32];
    const ARN: &str = "arn:aws:kms:eu-west-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef";

    fn image_env() -> String {
        serde_json::json!([
            "PATH=/usr/bin",
            "EVM_CHAIN_ID=42161",
            "EVM_PROXY_CONTRACT_ADDRESS=0xC985c12bbCECe96A13A72A62FD75d8aB9381ef5A",
            "RGB_ASSET_ID=rgb:asset",
            "FUNDS_IN_CONTRACT=0x6711f1a319B37847fa0234181C34D883774c4951",
            "TOKEN_CONTRACT=0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
            "EVM_MIN_CONFIRMATIONS=12",
            "GAS_TX_ALLOWED_TO=0x6711f1a319B37847fa0234181C34D883774c4951",
            "GAS_TX_MAX_GAS_LIMIT=300000",
            "GAS_TX_MAX_FEE_PER_GAS=1000",
            "GAS_TX_MAX_VALUE_WEI=5",
            "GAS_TX_ALLOWED_SELECTORS=0xdeadbeef,0x01020304",
            "BTC_MAX_TOTAL_SATS=1000000",
        ])
        .to_string()
    }

    fn endpoints() -> SetEndpointsRequest {
        SetEndpointsRequest {
            electrum_url: "ssl://electrum.example:50002".into(),
            evm_rpc_host: "rpc.example".into(),
            evm_rpc_ca_der: vec![0xca; 40],
            evm_rpc_tls_port: 443,
            kms_key_arn: ARN.into(),
            kms_region: "eu-west-1".into(),
            kms_seed_id: "seed-1".into(),
            kms_expected_evm_address: format!("0x{}", "ab".repeat(20)),
        }
    }

    fn expected() -> AttestedPolicy {
        expected_policy(SignerRole::Combined, &image_env(), &endpoints()).unwrap()
    }

    /// The policy-only answer of an enclave that attests `policy`.
    fn response(policy: &[u8]) -> GetAttestedPublicKeyResponse {
        let commitment = policy_commitment(policy);
        GetAttestedPublicKeyResponse {
            public_keys: None,
            attestation_doc: attestation_verify::build_mock_document_with_pcrs(
                &NONCE,
                None,
                Some(&commitment),
                &PCRS,
            )
            .unwrap(),
            attested_policy: policy.to_vec(),
        }
    }

    fn check(response: GetAttestedPublicKeyResponse) -> Result<AttestedPolicy> {
        check_launch(response, NONCE, &PCRS, &expected(), VerifyMode::Mock)
    }

    /// The enclave attests `expected()` with one edit. The check must fail
    /// with `message`.
    fn assert_mismatch(edit: impl FnOnce(&mut AttestedPolicy), message: &str) {
        let mut attested = expected();
        edit(&mut attested);
        let err = check(response(&attested.to_bytes())).unwrap_err();
        assert_eq!(err.to_string(), message);
    }

    macro_rules! set {
        ($field:ident, $value:expr) => {
            |p: &mut AttestedPolicy| match p {
                AttestedPolicy::Production { $field, .. } => *$field = $value,
                AttestedPolicy::Development => unreachable!(),
            }
        };
    }

    fn tls(edit: impl FnOnce(&mut EvmRpcTlsPin)) -> impl FnOnce(&mut AttestedPolicy) {
        |p| match p {
            AttestedPolicy::Production {
                evm_rpc_tls: Some(pin),
                ..
            } => edit(pin),
            _ => unreachable!(),
        }
    }

    fn kms(edit: impl FnOnce(&mut KmsPin)) -> impl FnOnce(&mut AttestedPolicy) {
        |p| match p {
            AttestedPolicy::Production { kms: Some(pin), .. } => edit(pin),
            _ => unreachable!(),
        }
    }

    #[test]
    fn a_matching_enclave_passes() {
        let attested = check(response(&expected().to_bytes())).unwrap();
        assert_eq!(attested.to_bytes(), expected().to_bytes());
    }

    #[test]
    fn allow_vanilla_psbt_mismatch_aborts() {
        assert_mismatch(
            set!(allow_vanilla_psbt, false),
            "allow_vanilla_psbt mismatch: expected true, attested false",
        );
    }

    #[test]
    fn signer_role_mismatch_aborts() {
        assert_mismatch(
            set!(signer_role, SignerRole::Mint),
            "signer_role mismatch: expected Combined, attested Mint",
        );
    }

    #[test]
    fn attestation_mismatch_aborts() {
        assert_mismatch(
            set!(attestation, AttestationMode::Mock),
            "attestation mismatch: expected Real, attested Mock",
        );
    }

    #[test]
    fn evm_source_mismatch_aborts() {
        assert_mismatch(
            set!(evm_source, EvmDataSource::RawRpc),
            "evm_source mismatch: expected PinnedTlsRpc, attested RawRpc",
        );
    }

    #[test]
    fn an_unknown_btc_source_aborts_at_decode() {
        // SpvVerified is the only value. Byte 6 is btc_source.
        let mut bytes = expected().to_bytes();
        assert_eq!(bytes[6], BtcDataSource::SpvVerified as u8);
        bytes[6] = 2;
        let err = check(response(&bytes)).unwrap_err();
        assert!(err.to_string().contains("unknown BTC data source"), "{err}");
    }

    #[test]
    fn chain_id_mismatch_aborts() {
        assert_mismatch(
            set!(chain_id, 1),
            "chain_id mismatch: expected 42161, attested 1",
        );
    }

    #[test]
    fn bridge_contract_mismatch_aborts() {
        assert_mismatch(
            set!(bridge_contract, [0x11; 20]),
            &format!(
                "bridge_contract mismatch: expected 0xc985c12bbcece96a13a72a62fd75d8ab9381ef5a, \
                 attested 0x{}",
                "11".repeat(20)
            ),
        );
    }

    #[test]
    fn rgb_asset_id_mismatch_aborts() {
        assert_mismatch(
            set!(rgb_asset_id, "rgb:other".into()),
            "rgb_asset_id mismatch: expected rgb:asset, attested rgb:other",
        );
    }

    #[test]
    fn funds_in_contract_mismatch_aborts() {
        assert_mismatch(
            set!(funds_in_contract, [0x22; 20]),
            &format!(
                "funds_in_contract mismatch: expected 0x6711f1a319b37847fa0234181c34d883774c4951, \
                 attested 0x{}",
                "22".repeat(20)
            ),
        );
    }

    #[test]
    fn evm_min_confirmations_mismatch_aborts() {
        assert_mismatch(
            set!(evm_min_confirmations, 1),
            "evm_min_confirmations mismatch: expected 12, attested 1",
        );
    }

    #[test]
    fn electrum_host_mismatch_aborts() {
        assert_mismatch(
            set!(electrum_host, "evil.example".into()),
            "electrum_host mismatch: expected electrum.example, attested evil.example",
        );
    }

    #[test]
    fn evm_rpc_tls_host_mismatch_aborts() {
        assert_mismatch(
            tls(|pin| pin.host = "evil.example".into()),
            "evm_rpc_tls.host mismatch: expected rpc.example, attested evil.example",
        );
    }

    #[test]
    fn evm_rpc_tls_ca_sha256_mismatch_aborts() {
        assert_mismatch(
            tls(|pin| pin.ca_sha256 = [0x33; 32]),
            &format!(
                "evm_rpc_tls.ca_sha256 mismatch: expected 0x{}, attested 0x{}",
                hex::encode(Sha256::digest([0xca; 40])),
                "33".repeat(32)
            ),
        );
    }

    #[test]
    fn evm_rpc_tls_absent_aborts() {
        assert_mismatch(
            set!(evm_rpc_tls, None),
            "evm_rpc_tls mismatch: expected present, attested absent",
        );
    }

    #[test]
    fn gas_tx_allowed_to_mismatch_aborts() {
        assert_mismatch(
            set!(gas_tx_allowed_to, [0; 20]),
            &format!(
                "gas_tx_allowed_to mismatch: expected 0x6711f1a319b37847fa0234181c34d883774c4951, \
                 attested 0x{}",
                "00".repeat(20)
            ),
        );
    }

    #[test]
    fn gas_tx_max_gas_limit_mismatch_aborts() {
        assert_mismatch(
            set!(gas_tx_max_gas_limit, 1),
            "gas_tx_max_gas_limit mismatch: expected 300000, attested 1",
        );
    }

    #[test]
    fn gas_tx_max_fee_per_gas_mismatch_aborts() {
        assert_mismatch(
            set!(gas_tx_max_fee_per_gas, 1),
            "gas_tx_max_fee_per_gas mismatch: expected 1000, attested 1",
        );
    }

    #[test]
    fn gas_tx_max_value_wei_mismatch_aborts() {
        assert_mismatch(
            set!(gas_tx_max_value_wei, 6),
            "gas_tx_max_value_wei mismatch: expected 5, attested 6",
        );
    }

    #[test]
    fn gas_tx_allowed_selectors_mismatch_aborts() {
        assert_mismatch(
            set!(gas_tx_allowed_selectors, vec![[0xde, 0xad, 0xbe, 0xef]]),
            "gas_tx_allowed_selectors mismatch: expected 0x01020304,0xdeadbeef, \
             attested 0xdeadbeef",
        );
    }

    #[test]
    fn token_contract_mismatch_aborts() {
        assert_mismatch(
            set!(token_contract, [0x44; 20]),
            &format!(
                "token_contract mismatch: expected 0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9, \
                 attested 0x{}",
                "44".repeat(20)
            ),
        );
    }

    #[test]
    fn kms_key_arn_mismatch_aborts() {
        assert_mismatch(
            kms(|pin| pin.key_arn = "arn:other".into()),
            &format!("kms.key_arn mismatch: expected {ARN}, attested arn:other"),
        );
    }

    #[test]
    fn kms_region_mismatch_aborts() {
        assert_mismatch(
            kms(|pin| pin.region = "us-east-1".into()),
            "kms.region mismatch: expected eu-west-1, attested us-east-1",
        );
    }

    #[test]
    fn kms_seed_id_mismatch_aborts() {
        assert_mismatch(
            kms(|pin| pin.seed_id = "seed-2".into()),
            "kms.seed_id mismatch: expected seed-1, attested seed-2",
        );
    }

    #[test]
    fn kms_expected_evm_address_mismatch_aborts() {
        assert_mismatch(
            kms(|pin| pin.expected_evm_address = None),
            &format!(
                "kms.expected_evm_address mismatch: expected 0x{}, attested none",
                "ab".repeat(20)
            ),
        );
    }

    #[test]
    fn kms_absent_aborts() {
        assert_mismatch(
            set!(kms, None),
            "kms mismatch: expected present, attested absent",
        );
    }

    #[test]
    fn a_development_policy_aborts() {
        let err = check(response(&AttestedPolicy::Development.to_bytes())).unwrap_err();
        assert_eq!(
            err.to_string(),
            "policy mismatch: expected Production, attested Development"
        );
    }

    #[test]
    fn a_wrong_pcr_aborts() {
        let other = ExpectedPcrs::new([1; 48], [2; 48], [9; 48]);
        let err = check_launch(
            response(&expected().to_bytes()),
            NONCE,
            &other,
            &expected(),
            VerifyMode::Mock,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("PCR mismatch: PCR2"), "{err:#}");
    }

    #[test]
    fn a_wrong_nonce_aborts() {
        let err = check_launch(
            response(&expected().to_bytes()),
            [8; 32],
            &PCRS,
            &expected(),
            VerifyMode::Mock,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("nonce mismatch"), "{err:#}");
    }

    #[test]
    fn a_missing_nonce_aborts() {
        // The mock builder always sets a nonce. Drop it from the CBOR map.
        let mut r = response(&expected().to_bytes());
        let mut doc: ciborium::Value = ciborium::from_reader(r.attestation_doc.as_slice()).unwrap();
        doc.as_map_mut()
            .unwrap()
            .retain(|(k, _)| k.as_text() != Some("nonce"));
        r.attestation_doc.clear();
        ciborium::into_writer(&doc, &mut r.attestation_doc).unwrap();
        let err = check(r).unwrap_err();
        assert!(format!("{err:#}").contains("missing nonce"), "{err:#}");
    }

    #[test]
    fn changed_policy_bytes_fail_the_commitment() {
        let mut r = response(&expected().to_bytes());
        let mut other = expected();
        set!(chain_id, 1)(&mut other);
        r.attested_policy = other.to_bytes();
        let err = check(r).unwrap_err();
        assert!(err.to_string().contains("does not commit"), "{err}");
    }

    #[test]
    fn a_keyed_answer_aborts() {
        let mut r = response(&expected().to_bytes());
        r.public_keys = Some(Default::default());
        let err = check(r).unwrap_err();
        assert!(err.to_string().contains("already has keys"), "{err}");
    }

    #[test]
    fn a_keyed_document_aborts() {
        let mut r = response(&expected().to_bytes());
        let commitment = policy_commitment(&r.attested_policy);
        r.attestation_doc = attestation_verify::build_mock_document_with_pcrs(
            &NONCE,
            Some(&[4; 65]),
            Some(&commitment),
            &PCRS,
        )
        .unwrap();
        let err = check(r).unwrap_err();
        assert!(format!("{err:#}").contains("has a public key"), "{err:#}");
    }

    #[test]
    fn a_malformed_document_aborts_in_real_mode() {
        let err = check_launch(
            response(&expected().to_bytes()),
            NONCE,
            &PCRS,
            &expected(),
            VerifyMode::Real,
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").starts_with("attestation verification failed"),
            "{err:#}"
        );
    }

    #[test]
    fn mixed_case_hosts_match_the_lowercased_attestation() {
        let mut upper = endpoints();
        upper.electrum_url = "ssl://Electrum.Example:50002/".into();
        upper.evm_rpc_host = "RPC.Example".into();
        let policy = expected_policy(SignerRole::Combined, &image_env(), &upper).unwrap();
        assert_eq!(policy, expected());
    }

    #[test]
    fn a_missing_required_image_env_key_is_an_error() {
        let env = image_env().replace("\"TOKEN_CONTRACT=", "\"OTHER=");
        let err = expected_policy(SignerRole::Combined, &env, &endpoints()).unwrap_err();
        assert_eq!(err.to_string(), "IMAGE-ENV.json has no TOKEN_CONTRACT");
    }

    #[test]
    fn mint_masks_the_gas_fields_and_burn_masks_vanilla() {
        let AttestedPolicy::Production {
            gas_tx_allowed_to,
            gas_tx_max_gas_limit,
            gas_tx_max_fee_per_gas,
            gas_tx_max_value_wei,
            gas_tx_allowed_selectors,
            allow_vanilla_psbt,
            ..
        } = expected_policy(SignerRole::Mint, &image_env(), &endpoints()).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(gas_tx_allowed_to, [0; 20]);
        assert_eq!(
            (
                gas_tx_max_gas_limit,
                gas_tx_max_fee_per_gas,
                gas_tx_max_value_wei
            ),
            (0, 0, 0)
        );
        assert!(gas_tx_allowed_selectors.is_empty());
        assert!(allow_vanilla_psbt);

        let AttestedPolicy::Production {
            allow_vanilla_psbt,
            gas_tx_max_gas_limit,
            ..
        } = expected_policy(SignerRole::Burn, &image_env(), &endpoints()).unwrap()
        else {
            unreachable!()
        };
        assert!(!allow_vanilla_psbt);
        assert_eq!(gas_tx_max_gas_limit, 300_000);
    }
}
