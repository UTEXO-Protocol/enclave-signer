use bitcoin::hashes::Hash;

use super::*;
use crate::state::EnclaveState;

#[test]
fn deterministic_derivation() {
    let seed = [42u8; 64];
    let km1 = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();
    let km2 = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();

    assert_eq!(km1.evm_address(), km2.evm_address());
    assert_eq!(km1.btc_compressed_pubkey(), km2.btc_compressed_pubkey());
    assert_eq!(km1.btc_xpub().to_string(), km2.btc_xpub().to_string());
}

#[test]
fn from_mnemonic_deterministic() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let km1 = KeyManager::from_mnemonic(mnemonic, Network::Bitcoin).unwrap();
    let km2 = KeyManager::from_mnemonic(mnemonic, Network::Bitcoin).unwrap();

    assert_eq!(km1.evm_address(), km2.evm_address());
    assert_eq!(km1.btc_compressed_pubkey(), km2.btc_compressed_pubkey());
    assert_eq!(km1.btc_xpub().to_string(), km2.btc_xpub().to_string());
}

#[test]
fn from_mnemonic_matches_seed_derivation() {
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
    let seed = mnemonic.to_seed("");

    let km_mnemonic = KeyManager::from_mnemonic(mnemonic_str, Network::Bitcoin).unwrap();
    let km_seed = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();

    assert_eq!(km_mnemonic.evm_address(), km_seed.evm_address());
    assert_eq!(
        km_mnemonic.btc_compressed_pubkey(),
        km_seed.btc_compressed_pubkey()
    );
}

#[test]
fn from_mnemonic_invalid() {
    let result = KeyManager::from_mnemonic("not a valid mnemonic", Network::Bitcoin);
    assert!(result.is_err());
}

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
    // Known test vector from colleague's multisig setup
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
    // Second cosigner from the same multisig setup
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
fn bip86_vanilla_and_colored_xpubs_differ() {
    let km = KeyManager::from_seed([42u8; 64], Network::Testnet).unwrap();
    assert_ne!(
        km.account_xpub_vanilla().to_string(),
        km.account_xpub_colored().to_string()
    );
}

#[test]
fn bip86_mainnet_vs_testnet_vanilla_differ() {
    let seed = [42u8; 64];
    let km_main = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();
    let km_test = KeyManager::from_seed(seed, Network::Testnet).unwrap();

    // Same master fingerprint (derived from same seed)
    assert_eq!(km_main.master_fingerprint(), km_test.master_fingerprint());
    // Different vanilla xpubs (different coin type + different network prefix)
    assert_ne!(
        km_main.account_xpub_vanilla().to_string(),
        km_test.account_xpub_vanilla().to_string()
    );
    // Mainnet xpubs start with "xpub", testnet with "tpub"
    assert!(km_main
        .account_xpub_vanilla()
        .to_string()
        .starts_with("xpub"));
    assert!(km_test
        .account_xpub_vanilla()
        .to_string()
        .starts_with("tpub"));
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
fn derive_btc_child_deterministic() {
    let km = KeyManager::from_seed([42u8; 64], Network::Testnet).unwrap();
    let child1 = km
        .derive_btc_child(
            AccountType::Vanilla,
            &[
                ChildNumber::Normal { index: 0 },
                ChildNumber::Normal { index: 0 },
            ],
        )
        .unwrap();
    let child2 = km
        .derive_btc_child(
            AccountType::Vanilla,
            &[
                ChildNumber::Normal { index: 0 },
                ChildNumber::Normal { index: 0 },
            ],
        )
        .unwrap();
    assert_eq!(child1.secret_bytes(), child2.secret_bytes());
}

#[test]
fn generate_different_keys() {
    let mut entropy1 = [1u8; 32];
    let mut entropy2 = [2u8; 32];
    let (km1, _) = KeyManager::generate(&mut entropy1, Network::Bitcoin).unwrap();
    let (km2, _) = KeyManager::generate(&mut entropy2, Network::Bitcoin).unwrap();

    assert_ne!(km1.evm_address(), km2.evm_address());
}

#[test]
fn key_formats() {
    let seed = [42u8; 64];
    let km = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();

    assert_eq!(km.evm_address().len(), 20);
    assert_eq!(km.btc_compressed_pubkey().len(), 33);
    assert!(
        km.btc_compressed_pubkey()[0] == 0x02 || km.btc_compressed_pubkey()[0] == 0x03,
        "compressed pubkey must start with 0x02 or 0x03"
    );
    assert!(
        km.btc_xpub().to_string().starts_with("xpub"),
        "xpub must start with 'xpub'"
    );
}

#[test]
fn seed_preserved_for_cloning() {
    let original_seed = [99u8; 64];
    let km = KeyManager::from_seed(original_seed, Network::Bitcoin).unwrap();
    assert_eq!(km.expose_seed(), &original_seed);
}

#[test]
fn double_initialization_error() {
    let state = EnclaveState::new(Network::Bitcoin);
    let mut entropy1 = [1u8; 32];
    let mut entropy2 = [2u8; 32];

    state.initialize_from_entropy(&mut entropy1).unwrap();
    let result = state.initialize_from_entropy(&mut entropy2);
    assert!(result.is_err());
}

#[test]
fn get_keys_before_init_error() {
    let state = EnclaveState::new(Network::Bitcoin);
    let result = state.get_keys();
    assert!(result.is_err());
}

#[test]
fn test_sign_evm_produces_65_bytes() {
    let seed = [0x42u8; 64];
    let km = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();
    let hash = [0xABu8; 32];
    let sig = km.sign_evm(&hash).unwrap();
    assert_eq!(sig.len(), 65);
    assert!(sig[64] <= 1);
}

#[test]
fn test_sign_evm_deterministic() {
    let seed = [0x42u8; 64];
    let km = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();
    let hash = [0xABu8; 32];
    let sig1 = km.sign_evm(&hash).unwrap();
    let sig2 = km.sign_evm(&hash).unwrap();
    assert_eq!(sig1, sig2); // k256 uses RFC 6979 deterministic nonces
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

    let pubkey_bytes = recovered_key.to_encoded_point(false);
    let pubkey_hash = Keccak256::digest(&pubkey_bytes.as_bytes()[1..]);
    let recovered_address: [u8; 20] = pubkey_hash[12..].try_into().unwrap();

    assert_eq!(&recovered_address, km.evm_address());
}

#[test]
fn test_concordium_pubkey_deterministic() {
    let seed = [0x42u8; 64];
    let km1 = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();
    let km2 = KeyManager::from_seed(seed, Network::Bitcoin).unwrap();
    assert_eq!(km1.ccd_ed25519_pub(), km2.ccd_ed25519_pub());
    assert_eq!(km1.ccd_ed25519_pub().len(), 32);
}

#[test]
fn test_concordium_different_seeds_differ() {
    let a = KeyManager::from_seed([0x42u8; 64], Network::Bitcoin).unwrap();
    let b = KeyManager::from_seed([0x99u8; 64], Network::Bitcoin).unwrap();
    assert_ne!(a.ccd_ed25519_pub(), b.ccd_ed25519_pub());
}

#[test]
fn test_sign_ccd_produces_valid_signature() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let km = KeyManager::from_seed([0x42u8; 64], Network::Bitcoin).unwrap();
    let hash = [0xABu8; 32];
    let (sig_bytes, public_key) = km.sign_ccd(&hash).unwrap();
    assert_eq!(sig_bytes.len(), 64);

    // The reported key must be the one that signed: the consumer maps the
    // signature onto an account key index by it.
    assert_eq!(&public_key, km.ccd_ed25519_pub());

    let vk = VerifyingKey::from_bytes(&public_key).unwrap();
    let sig = Signature::from_bytes(&sig_bytes);
    assert!(vk.verify(&hash, &sig).is_ok());
}

#[test]
fn test_sign_ccd_deterministic() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Bitcoin).unwrap();
    let hash = [0xABu8; 32];
    // Ed25519 (RFC 8032) is deterministic.
    assert_eq!(km.sign_ccd(&hash).unwrap(), km.sign_ccd(&hash).unwrap());
}

/// The legacy segwit v0 P2WSH signer is gone: a 2-of-3 P2WSH input whose
/// witness script names our legacy key, committed correctly, is not signed.
#[test]
fn p2wsh_input_naming_our_legacy_key_is_never_signed() {
    use bitcoin::blockdata::opcodes::all::OP_CHECKMULTISIG;
    use bitcoin::blockdata::script::Builder as ScriptBuilder;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid};

    let km = KeyManager::from_seed([0x42u8; 64], Network::Bitcoin).unwrap();
    let secp = Secp256k1::new();
    let ours = bitcoin::PublicKey::from_slice(km.btc_compressed_pubkey()).unwrap();
    let other =
        |b: u8| bitcoin::PublicKey::new(SecretKey::from_slice(&[b; 32]).unwrap().public_key(&secp));
    let mut pubkeys = [ours, other(0x02), other(0x03)];
    pubkeys.sort_by_key(|k| k.to_bytes());
    let witness_script = ScriptBuilder::new()
        .push_int(2)
        .push_key(&pubkeys[0])
        .push_key(&pubkeys[1])
        .push_key(&pubkeys[2])
        .push_int(3)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();

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
            script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                [0xBB; 20],
            )),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::hash(witness_script.as_bytes())),
    });
    psbt.inputs[0].witness_script = Some(witness_script);

    let (signed_bytes, count) = km.sign_psbt(&psbt.serialize()).unwrap();
    assert_eq!(count, 0);
    let signed = Psbt::deserialize(&signed_bytes).unwrap();
    assert!(signed.inputs[0].partial_sigs.is_empty());
}

#[test]
fn test_sign_psbt_invalid_bytes() {
    let mut entropy = [0u8; 32];
    getrandom::fill(&mut entropy).unwrap();
    let (km, _mnemonic) = KeyManager::generate(&mut entropy, Network::Bitcoin).unwrap();

    let result = km.sign_psbt(&[0xFF, 0xFF, 0xFF]);
    assert!(result.is_err());
}

/// Build a BIP-86 key-path taproot PSBT for testing.
/// The signer's key is derived at m/86'/1'/0'/0/0 (vanilla testnet).
fn build_test_taproot_psbt(km: &KeyManager) -> Vec<u8> {
    use bitcoin::bip32::ChildNumber;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
    };

    let secp = Secp256k1::new();

    // Our key: derive child at m/86'/1'/0'/0/0
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

    // Sign the already-signed PSBT again - should skip
    let (_, count2) = km.sign_psbt(&signed_bytes).unwrap();
    assert_eq!(count2, 0);
}

#[test]
fn test_sign_taproot_psbt_no_matching_fingerprint() {
    // Key with a different seed -> different fingerprint -> should not sign
    let km_signer = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let km_other = KeyManager::from_seed([0x99u8; 64], Network::Testnet).unwrap();

    let psbt_bytes = build_test_taproot_psbt(&km_signer);

    // km_other's fingerprint won't match the tap_key_origins
    let (_, count) = km_other.sign_psbt(&psbt_bytes).unwrap();
    assert_eq!(count, 0);
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
