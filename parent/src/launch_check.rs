//! Verify the launch policy against the measured image and deploy inputs.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};
use attestation_verify::{
    policy_commitment, AttestationMode, AttestedPolicy, BitcoinNetwork, BtcDataSource,
    EvmDataSource, EvmFinalityTag, EvmRpcTlsPin, ExpectedPcrs, KmsPin, SignerRole,
    VerifiedAttestation,
};
use sha2::{Digest, Sha256};

use crate::attest_verify::{refuse_mock_production, VerifyMode};
use crate::enclave_proto::{GetAttestedPublicKeyResponse, SetEndpointsRequest};

/// The policy that a production enclave of `role` must attest after
/// `endpoints` is set. `image_env` is the `Config.Env` JSON list of the
/// measured image. The deploy inputs do not give the clone-peer PCR3, so it is
/// unset here; [`with_document_pcr3`] sets it from the verified document.
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
    // Match the enclave: only an absent tag defaults; empty/invalid values refuse.
    let evm_finality_tag =
        env.get("EVM_FINALITY_TAG")
            .map_or(Ok(EvmFinalityTag::default()), |value| {
                value
                    .parse()
                    .map_err(|e: String| anyhow!("EVM_FINALITY_TAG: {e}"))
            })?;
    // A production enclave refuses `latest` at boot.
    if evm_finality_tag == EvmFinalityTag::Latest {
        bail!("EVM_FINALITY_TAG=latest is not a production policy; use safe or finalized");
    }
    let signs_gas_tx = role != SignerRole::Mint;
    let gas = |key: &str| optional(key).filter(|_| signs_gas_tx);

    let electrum_host = indexer_host(&endpoints.electrum_url)?;
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
        // Unset is mainnet, as in the enclave.
        bitcoin_network: {
            let name = optional("BITCOIN_NETWORK").unwrap_or("bitcoin");
            BitcoinNetwork::from_env_str(name)
                .with_context(|| format!("BITCOIN_NETWORK {name:?} is not a known network"))?
        },
        bridge_contract: address20(
            "EVM_PROXY_CONTRACT_ADDRESS",
            required("EVM_PROXY_CONTRACT_ADDRESS")?,
        )?,
        rgb_asset_id: required("RGB_ASSET_ID")?.to_string(),
        funds_in_contract: address20("FUNDS_IN_CONTRACT", required("FUNDS_IN_CONTRACT")?)?,
        evm_finality_tag,
        spv_min_confirmations: number(
            "SPV_MIN_CONFIRMATIONS",
            Some(required("SPV_MIN_CONFIRMATIONS")?),
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
        clone_peer_pcr3: None,
    })
}

/// The lowercased host of an indexer URL, as the enclave attests it:
/// `ssl://` or `tcp://host:port` (Electrum), `https://` or `http://host[:port]`
/// (Esplora). The enclave checks the scheme and port rules itself.
fn indexer_host(url: &str) -> Result<String> {
    let url = url.strip_suffix('/').unwrap_or(url);
    let (rest, port_optional) = if let Some(rest) = url
        .strip_prefix("ssl://")
        .or_else(|| url.strip_prefix("tcp://"))
    {
        (rest, false)
    } else if let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    {
        (rest, true)
    } else {
        bail!("electrum_url {url:?} is not ssl://, tcp://, https:// or http://");
    };
    let host = match rest.rsplit_once(':') {
        Some((host, _)) => host,
        None if port_optional => rest,
        None => bail!("electrum_url {url:?} has no port"),
    };
    Ok(host.to_ascii_lowercase())
}

/// `expected` with the clone-peer PCR3 taken from the verified document PCRs,
/// as [`crate::attest_verify`] does. A cloning role needs a non-zero PCR3.
pub fn with_document_pcr3(
    expected: &AttestedPolicy,
    doc_pcrs: &HashMap<u32, Vec<u8>>,
) -> Result<AttestedPolicy> {
    let mut policy = expected.clone();
    if let AttestedPolicy::Production {
        signer_role,
        clone_peer_pcr3,
        ..
    } = &mut policy
    {
        *clone_peer_pcr3 = crate::attest_verify::clone_peer_pcr3(*signer_role, doc_pcrs)?;
    }
    Ok(policy)
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
    check_launch_with(response, mode, expected, |doc| {
        Ok(match mode {
            VerifyMode::Real => attestation_verify::verify_policy_attestation(doc, pcrs, &nonce),
            VerifyMode::Mock => {
                attestation_verify::verify_mock_policy_attestation(doc, pcrs, &nonce)
            }
        }?)
    })
}

fn check_launch_with(
    response: GetAttestedPublicKeyResponse,
    mode: VerifyMode,
    expected: &AttestedPolicy,
    verify_doc: impl FnOnce(&[u8]) -> Result<VerifiedAttestation>,
) -> Result<AttestedPolicy> {
    refuse_mock_production(mode, matches!(expected, AttestedPolicy::Production { .. }))?;
    if response.public_keys.is_some() {
        bail!("the enclave already has keys; the launch check needs a fresh enclave");
    }
    let verified =
        verify_doc(&response.attestation_doc).context("attestation verification failed")?;
    if verified.user_data.as_deref()
        != Some(policy_commitment(&response.attested_policy).as_slice())
    {
        bail!("attestation user_data does not commit the returned policy bytes");
    }
    let expected = with_document_pcr3(expected, &verified.pcrs)?;
    compare_policy(&expected, &response.attested_policy)
}

/// Decode `attested` and compare it with `expected`, field by field. The
/// error names the first field that differs.
pub fn compare_policy(expected: &AttestedPolicy, attested: &[u8]) -> Result<AttestedPolicy> {
    let decoded = AttestedPolicy::from_bytes(attested)?;
    for ((field, want), (_, got)) in fields(expected).into_iter().zip(fields(&decoded)) {
        if want != got {
            bail!("{field} mismatch: expected {want}, attested {got}");
        }
    }
    if expected.to_bytes() != attested {
        bail!("attested policy bytes differ from the expected policy");
    }
    Ok(decoded)
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
        bitcoin_network,
        bridge_contract,
        rgb_asset_id,
        funds_in_contract,
        evm_finality_tag,
        spv_min_confirmations,
        electrum_host,
        evm_rpc_tls,
        gas_tx_allowed_to,
        gas_tx_max_gas_limit,
        gas_tx_max_fee_per_gas,
        gas_tx_max_value_wei,
        gas_tx_allowed_selectors,
        token_contract,
        kms,
        clone_peer_pcr3,
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
        ("bitcoin_network", format!("{bitcoin_network:?}")),
        ("bridge_contract", hex(bridge_contract)),
        ("rgb_asset_id", rgb_asset_id.clone()),
        ("funds_in_contract", hex(funds_in_contract)),
        ("evm_finality_tag", evm_finality_tag.to_string()),
        ("spv_min_confirmations", spv_min_confirmations.to_string()),
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
    out.push(("clone_peer_pcr3", presence(clone_peer_pcr3.is_some())));
    if let Some(pcr3) = clone_peer_pcr3 {
        out.push(("clone_peer_pcr3.value", hex(pcr3)));
    }
    out
}

#[cfg(test)]
mod tests;
