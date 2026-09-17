//! Independent v1 wire encoder and single-field negative cases. Shared by the
//! mock handler regression test and the separately built Nitro test peer.
use sha2::{Digest, Sha256};
use utexo_bridge_enclave::policy::{AttestationMode, AttestedPolicy, EvmDataSource};
use utexo_bridge_enclave::proto::PublicKeysResponse;

pub fn commitment(
    k: &PublicKeysResponse,
    policy: &[u8],
    requester: &[u8],
    donor: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let chain = k.chain_id.to_be_bytes();
    let fields: [&[u8]; 13] = [
        &k.evm_address,
        &k.btc_compressed_pub,
        k.btc_xpub.as_bytes(),
        &k.master_fingerprint,
        k.account_xpub_vanilla.as_bytes(),
        k.account_xpub_colored.as_bytes(),
        &k.evm_uncompressed_pub,
        &chain,
        &k.bridge_contract,
        k.rgb_asset_id.as_bytes(),
        &k.evm_gas_tx_uncompressed_pub,
        &k.evm_gas_tx_address,
        &k.ccd_ed25519_pub,
    ];
    let mut bundle = Vec::new();
    for field in fields {
        bundle.extend_from_slice(&(field.len() as u32).to_be_bytes());
        bundle.extend_from_slice(field);
    }
    let mut h = Sha256::new();
    h.update(b"utexo/clone-response/v1\0");
    h.update(Sha256::digest(bundle));
    h.update(Sha256::digest(policy));
    h.update(requester);
    h.update(donor);
    h.update(Sha256::digest(ciphertext));
    let mut result = 1u32.to_be_bytes().to_vec();
    result.extend_from_slice(&h.finalize());
    result
}

pub fn bundle_cases(keys: &PublicKeysResponse) -> Vec<(&'static str, PublicKeysResponse)> {
    let mut cases = Vec::new();
    macro_rules! bytes {
        ($field:ident) => {{
            let mut k = keys.clone();
            k.$field[0] ^= 1;
            cases.push((stringify!($field), k));
        }};
    }
    macro_rules! string {
        ($field:ident) => {{
            let mut k = keys.clone();
            k.$field.push('x');
            cases.push((stringify!($field), k));
        }};
    }
    bytes!(evm_address);
    bytes!(btc_compressed_pub);
    string!(btc_xpub);
    bytes!(master_fingerprint);
    string!(account_xpub_vanilla);
    string!(account_xpub_colored);
    bytes!(evm_uncompressed_pub);
    let mut k = keys.clone();
    k.chain_id ^= 1;
    cases.push(("chain_id", k));
    bytes!(bridge_contract);
    string!(rgb_asset_id);
    bytes!(evm_gas_tx_uncompressed_pub);
    bytes!(evm_gas_tx_address);
    bytes!(ccd_ed25519_pub);
    cases
}

pub fn policy_cases(policy: &AttestedPolicy) -> Vec<(&'static str, Vec<u8>)> {
    let mut cases = vec![("variant", AttestedPolicy::Development.to_bytes())];
    macro_rules! alter {
        ($field:ident, $value:expr) => {{
            let mut p = policy.clone();
            let AttestedPolicy::Production { $field, .. } = &mut p else {
                panic!("test requires a production-shaped policy");
            };
            *$field = $value;
            assert_ne!(p.to_bytes(), policy.to_bytes(), stringify!($field));
            cases.push((stringify!($field), p.to_bytes()));
        }};
    }
    alter!(allow_vanilla_psbt, !*allow_vanilla_psbt);
    alter!(attestation, AttestationMode::Mock);
    alter!(evm_source, EvmDataSource::Disabled);
    // The current Rust enum has only SpvVerified. A peer using another policy
    // vocabulary can nevertheless sign a byte encoding with a different source.
    let mut btc_source = policy.to_bytes();
    assert_eq!(&btc_source[..2], &[2, 1]);
    btc_source[5] = 0;
    cases.push(("btc_source", btc_source));
    alter!(chain_id, *chain_id ^ 1);
    alter!(bridge_contract, {
        let mut x = *bridge_contract;
        x[0] ^= 1;
        x
    });
    alter!(rgb_asset_id, format!("{rgb_asset_id}x"));
    alter!(evm_checkpoint, Some([0x91; 32]));
    alter!(gas_tx_allowed_to, {
        let mut x = *gas_tx_allowed_to;
        x[0] ^= 1;
        x
    });
    alter!(gas_tx_max_gas_limit, *gas_tx_max_gas_limit ^ 1);
    alter!(gas_tx_max_fee_per_gas, *gas_tx_max_fee_per_gas ^ 1);
    alter!(gas_tx_max_value_wei, *gas_tx_max_value_wei ^ 1);
    alter!(gas_tx_allowed_selectors, {
        let mut x = gas_tx_allowed_selectors.clone();
        x.push([0x91; 4]);
        x
    });
    cases
}
