use bitcoin::hashes::Hash;

use super::*;
use crate::state::EnclaveState;

#[test]
fn initialize_from_mnemonic_then_double_init_fails() {
    let state = EnclaveState::new(Network::Bitcoin);
    state
        .initialize_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
    let result =
        state.initialize_from_mnemonic("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
    assert!(result.is_err());
}

#[test]
fn bip86_testnet_derivation_matches_known_mnemonic() {
    // Known vector from a multisig setup.
    let km = KeyManager::from_mnemonic(
        "rail item marble one share venture artist brisk useful upset bus amused",
        Network::Testnet,
    )
    .unwrap();

    assert_eq!(hex::encode(km.master_fingerprint().to_bytes()), "82fb42e4");
    assert_eq!(
        km.account_xpub_vanilla().to_string(),
        "tpubDDCUjHgx7hFxgc9Zn4tGWyiBsxeGNXfA1oGBMykU7W5LNESKAxtVafP55gqfapRPM5f1wgUG7c9hqvzh548C8g5JTZSxCTCS2nxoBHPWGaH"
    );
    assert_eq!(
        km.account_xpub_colored().to_string(),
        "tpubDDgKC4Kea1GDCQBdR7i2SBycbDhydEHqqDguZZze7A6rLGqRD5YAYD29JAHydzGAmkcoHHdkjazd54zBEr4KPWQftyN3LiyGxGKw7CM38HR"
    );
}

#[test]
fn bip86_second_known_mnemonic() {
    // Second cosigner of the same multisig setup.
    let km = KeyManager::from_mnemonic(
        "season pave name banana aspect inject book roast clown young hill unhappy",
        Network::Testnet,
    )
    .unwrap();

    assert_eq!(hex::encode(km.master_fingerprint().to_bytes()), "9f249100");
    assert_eq!(
        km.account_xpub_colored().to_string(),
        "tpubDCSLyZybm4TSDo3aeCK5Ke2iPQQFJ6vrKAuyEa4v5F1Xnoi5UtbEeMBCQ1RtwvEH43NKnzSp63aNQUrkB6sQL6FSW2wqZVWupAy1hV3fcFw"
    );
}

#[test]
fn bip86_colored_xpub_coin_type_follows_the_network() {
    // Coin type is 827166 on mainnet and 827167 on other networks.
    let mnemonic = "rail item marble one share venture artist brisk useful upset bus amused";

    let km = KeyManager::from_mnemonic(mnemonic, Network::Bitcoin).unwrap();
    assert_eq!(
        km.account_xpub_colored().to_string(),
        "xpub6BpTsEaSGEwRS6ucdm4tQWenBnx6VniKR5S3wwu3e1hKLA3tAQUySodkH4bMTS4KaTgYpPzuJEQSSuosaD5yrvWQcTwy2LQLDYDo7zr3aBU"
    );

    for network in [
        Network::Testnet,
        Network::Testnet4,
        Network::Signet,
        Network::Regtest,
    ] {
        let km = KeyManager::from_mnemonic(mnemonic, network).unwrap();
        assert_eq!(
            km.account_xpub_colored().to_string(),
            "tpubDDgKC4Kea1GDCQBdR7i2SBycbDhydEHqqDguZZze7A6rLGqRD5YAYD29JAHydzGAmkcoHHdkjazd54zBEr4KPWQftyN3LiyGxGKw7CM38HR",
            "{network:?}"
        );
    }
}

#[test]
fn resolve_account_and_child_path_works() {
    let km = KeyManager::from_seed([42u8; 64], Network::Testnet).unwrap();

    // m/86'/1'/0'/0/7 -> Vanilla, [0, 7]
    let path = DerivationPath::from_str("m/86'/1'/0'/0/7").unwrap();
    let (account, child) = km.resolve_account_and_child_path(&path).unwrap();
    assert!(matches!(account, AccountType::Vanilla));
    assert_eq!(child.len(), 2);

    // m/86'/827167'/0'/0/3 -> Colored, [0, 3]
    let path = DerivationPath::from_str("m/86'/827167'/0'/0/3").unwrap();
    let (account, child) = km.resolve_account_and_child_path(&path).unwrap();
    assert!(matches!(account, AccountType::Colored));
    assert_eq!(child.len(), 2);

    // m/84'/0'/0'/0/0 -> None (wrong purpose)
    let path = DerivationPath::from_str("m/84'/0'/0'/0/0").unwrap();
    assert!(km.resolve_account_and_child_path(&path).is_none());

    // Only the 5-step BIP-86 shape resolves.
    for short_or_long in ["m/86'/1'/0'", "m/86'/1'/0'/0", "m/86'/1'/0'/0/7/0"] {
        let path = DerivationPath::from_str(short_or_long).unwrap();
        assert!(
            km.resolve_account_and_child_path(&path).is_none(),
            "{short_or_long}"
        );
    }
}

/// RGB coin type is network-scoped: 827166 on mainnet, 827167 elsewhere.
#[test]
fn colored_coin_type_follows_the_network() {
    let km_main = KeyManager::from_seed([42u8; 64], Network::Bitcoin).unwrap();
    let km_test = KeyManager::from_seed([42u8; 64], Network::Testnet).unwrap();

    let mainnet_rgb = DerivationPath::from_str("m/86'/827166'/0'/0/3").unwrap();
    let testnet_rgb = DerivationPath::from_str("m/86'/827167'/0'/0/3").unwrap();

    let (account, child) = km_main
        .resolve_account_and_child_path(&mainnet_rgb)
        .unwrap();
    assert!(matches!(account, AccountType::Colored));
    assert_eq!(child.len(), 2);
    assert!(km_main
        .resolve_account_and_child_path(&testnet_rgb)
        .is_none());

    let (account, _) = km_test
        .resolve_account_and_child_path(&testnet_rgb)
        .unwrap();
    assert!(matches!(account, AccountType::Colored));
    assert!(km_test
        .resolve_account_and_child_path(&mainnet_rgb)
        .is_none());
}

#[test]
fn seed_preserved_for_cloning() {
    let original_seed = [99u8; 64];
    let km = KeyManager::from_seed(original_seed, Network::Bitcoin).unwrap();
    assert_eq!(km.expose_seed(), &original_seed);
}

#[test]
fn test_sign_evm_recoverable() {
    use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};

    let seed = [0x42u8; 64];
    let km = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();
    let hash = [0xABu8; 32];
    let sig_bytes = km.sign_evm(&hash).unwrap();

    let signature = K256Signature::from_slice(&sig_bytes[..64]).unwrap();
    let recovery_id = RecoveryId::from_byte(sig_bytes[64]).unwrap();
    let recovered_key = VerifyingKey::recover_from_prehash(&hash, &signature, recovery_id).unwrap();

    let pubkey_bytes = recovered_key.to_sec1_point(false);
    let pubkey_hash = Keccak256::digest(&pubkey_bytes.as_bytes()[1..]);
    let recovered_address: [u8; 20] = pubkey_hash[12..].try_into().unwrap();

    assert_eq!(&recovered_address, km.evm_address());
}

/// A PSBT over the size limit is refused before the parse, for every account
/// scope, with the cross-check error the validation paths give.
#[test]
fn a_psbt_over_the_size_limit_is_refused_before_signing() {
    let mut entropy = [0u8; 32];
    getrandom::fill(&mut entropy).unwrap();
    let (km, _mnemonic) = KeyManager::generate(&mut entropy, Network::Bitcoin).unwrap();

    let bytes = vec![0x70; crate::config::MAX_PSBT_BYTES + 1];
    for scope in [None, Some(AccountType::Vanilla), Some(AccountType::Colored)] {
        let err = km.sign_psbt_scoped(&bytes, scope).unwrap_err();
        assert!(
            matches!(err, EnclaveError::CrossCheck(ref m) if m.contains("the limit is")),
            "{scope:?}: {err}"
        );
    }
}

/// A BIP-86 key-path taproot PSBT. The key is at m/86'/1'/0'/0/0 (vanilla
/// testnet).
fn build_test_taproot_psbt(km: &KeyManager) -> Vec<u8> {
    use bitcoin::bip32::ChildNumber;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
    };

    let secp = Secp256k1::new();

    let our_secret = km
        .derive_btc_child(
            AccountType::Vanilla,
            &[
                ChildNumber::Normal { index: 0 },
                ChildNumber::Normal { index: 0 },
            ],
        )
        .unwrap();
    let our_keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &our_secret);
    let (our_xonly, _parity) = XOnlyPublicKey::from_keypair(&our_keypair);
    let script_pubkey = ScriptBuf::new_p2tr(&secp, our_xonly, None);

    let unsigned_tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0xAA; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: script_pubkey.clone(),
        }],
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();

    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey,
    });
    psbt.inputs[0].tap_internal_key = Some(our_xonly);

    let our_fingerprint = *km.master_fingerprint();
    let our_derivation = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(86).unwrap(),
        ChildNumber::from_hardened_idx(1).unwrap(), // testnet
        ChildNumber::from_hardened_idx(0).unwrap(),
        ChildNumber::Normal { index: 0 },
        ChildNumber::Normal { index: 0 },
    ]);
    psbt.inputs[0]
        .tap_key_origins
        .insert(our_xonly, (vec![], (our_fingerprint, our_derivation)));

    psbt.serialize()
}

#[test]
fn test_sign_taproot_psbt_one_input() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let psbt_bytes = build_test_taproot_psbt(&km);

    let (signed_bytes, count) = km.sign_psbt(&psbt_bytes).unwrap();
    assert_eq!(count, 1);

    let signed_psbt = Psbt::deserialize(&signed_bytes).unwrap();
    assert!(signed_psbt.inputs[0].tap_key_sig.is_some());
}

#[test]
fn test_sign_taproot_psbt_skip_already_signed() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let psbt_bytes = build_test_taproot_psbt(&km);

    let (signed_bytes, count1) = km.sign_psbt(&psbt_bytes).unwrap();
    assert_eq!(count1, 1);

    // A signed input is skipped.
    let (_, count2) = km.sign_psbt(&signed_bytes).unwrap();
    assert_eq!(count2, 0);
}

#[test]
fn test_sign_taproot_psbt_schnorr_signature_valid() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let psbt_bytes = build_test_taproot_psbt(&km);

    let (signed_bytes, _) = km.sign_psbt(&psbt_bytes).unwrap();
    let signed_psbt = Psbt::deserialize(&signed_bytes).unwrap();

    let tap_sig = signed_psbt.inputs[0].tap_key_sig.unwrap();
    let witness_utxo = signed_psbt.inputs[0].witness_utxo.clone().unwrap();
    let output_key =
        bitcoin::XOnlyPublicKey::from_slice(&witness_utxo.script_pubkey.as_bytes()[2..34]).unwrap();

    let secp = Secp256k1::verification_only();
    let prevouts = vec![witness_utxo];
    let unsigned_tx = signed_psbt.unsigned_tx.clone();
    let mut cache = bitcoin::sighash::SighashCache::new(&unsigned_tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            bitcoin::sighash::TapSighashType::Default,
        )
        .unwrap();

    let msg = bitcoin::secp256k1::Message::from_digest(*sighash.as_byte_array());
    assert!(secp
        .verify_schnorr(&tap_sig.signature, &msg, &output_key)
        .is_ok());
}

#[test]
fn wallet_child_path_is_a_scanned_keychain_then_a_normal_index() {
    let normal = |i| ChildNumber::from_normal_idx(i).unwrap();
    let hardened = |i| ChildNumber::from_hardened_idx(i).unwrap();
    for account in [AccountType::Colored, AccountType::Vanilla] {
        assert!(is_wallet_child_path(account, &[normal(0), normal(7)]));
        assert!(is_wallet_child_path(
            account,
            &[normal(0), normal((1 << 31) - 1)]
        ));
        for refused in [
            vec![],
            vec![normal(0)],
            vec![normal(2), normal(7)],
            vec![hardened(0), normal(7)],
            vec![normal(0), hardened(7)],
            vec![normal(0), normal(7), normal(0)],
            vec![hardened(9), hardened(13)],
        ] {
            assert!(
                !is_wallet_child_path(account, &refused),
                "{account:?} {refused:?}"
            );
        }
    }
    // rgb-lib's vanilla keychain is configurable; the colored one is not.
    assert!(is_wallet_child_path(
        AccountType::Vanilla,
        &[normal(1), normal(7)]
    ));
    assert!(!is_wallet_child_path(
        AccountType::Colored,
        &[normal(1), normal(7)]
    ));
}
