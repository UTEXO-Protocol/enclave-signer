use super::*;
use bitcoin::bip32::{ChildNumber, DerivationPath};
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Builder as ScriptBuilder;
use bitcoin::secp256k1::SecretKey;
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder};
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid};

/// NUMS internal key used for unspendable key-path.
const NUMS_INTERNAL: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

fn xonly_from_byte(b: u8) -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[b; 32]).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    XOnlyPublicKey::from_keypair(&kp).0
}

fn our_xonly(km: &KeyManager) -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    let sk = km
        .derive_btc_child(
            AccountType::Vanilla,
            &[
                ChildNumber::Normal { index: 0 },
                ChildNumber::Normal { index: 0 },
            ],
        )
        .unwrap();
    XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &sk)).0
}

fn our_full_path() -> DerivationPath {
    DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(86).unwrap(),
        ChildNumber::from_hardened_idx(1).unwrap(), // testnet
        ChildNumber::from_hardened_idx(0).unwrap(),
        ChildNumber::Normal { index: 0 },
        ChildNumber::Normal { index: 0 },
    ])
}

fn multi_a_2_of_3(keys: &[XOnlyPublicKey; 3]) -> ScriptBuf {
    let mut sorted = *keys;
    sorted.sort();
    ScriptBuilder::new()
        .push_x_only_key(&sorted[0])
        .push_opcode(OP_CHECKSIG)
        .push_x_only_key(&sorted[1])
        .push_opcode(OP_CHECKSIGADD)
        .push_x_only_key(&sorted[2])
        .push_opcode(OP_CHECKSIGADD)
        .push_int(2)
        .push_opcode(OP_NUMEQUAL)
        .into_script()
}

/// Build a taproot P2TR PSBT for testing.
/// Returns: (psbt, output_internal_key, leaf_script, leaf_hash, control_block).
fn build_legit_taproot_psbt(
    km: &KeyManager,
    account: AccountType,
) -> (Psbt, XOnlyPublicKey, ScriptBuf, TapLeafHash, ControlBlock) {
    let secp = Secp256k1::new();
    let child_path = [
        ChildNumber::Normal { index: 0 },
        ChildNumber::Normal { index: 0 },
    ];
    let secret = km.derive_btc_child(account, &child_path).unwrap();
    let our = XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &secret)).0;
    let coin_type = match account {
        AccountType::Vanilla => 1,
        AccountType::Colored => 827167,
    };
    let full_path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(86).unwrap(),
        ChildNumber::from_hardened_idx(coin_type).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
        child_path[0],
        child_path[1],
    ]);
    let other1 = xonly_from_byte(0xA1);
    let other2 = xonly_from_byte(0xA2);
    let leaf_script = multi_a_2_of_3(&[our, other1, other2]);
    let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);

    let internal_key = XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
    let builder = TaprootBuilder::new()
        .add_leaf(0, leaf_script.clone())
        .unwrap();
    let spend_info = builder.finalize(&secp, internal_key).unwrap();
    let script_pubkey = ScriptBuf::new_p2tr(&secp, internal_key, spend_info.merkle_root());
    let control_block = spend_info
        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
        .unwrap();

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
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey,
    });
    psbt.inputs[0].tap_internal_key = Some(internal_key);
    psbt.inputs[0].tap_scripts.insert(
        control_block.clone(),
        (leaf_script.clone(), LeafVersion::TapScript),
    );
    psbt.inputs[0].tap_key_origins.insert(
        our,
        (vec![leaf_hash], (*km.master_fingerprint(), full_path)),
    );

    (psbt, internal_key, leaf_script, leaf_hash, control_block)
}

#[test]
fn scoped_taproot_signing_honors_requested_sighash() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    for requested in [
        Some(TapSighashType::All),
        Some(TapSighashType::Default),
        None,
    ] {
        let (mut psbt, _, _, leaf_hash, _) = build_legit_taproot_psbt(&km, AccountType::Colored);
        psbt.inputs[0].sighash_type = requested.map(Into::into);
        let (bytes, count) = km
            .sign_psbt_scoped(&psbt.serialize(), Some(AccountType::Colored))
            .unwrap();
        assert_eq!(count, 1);

        let signed = Psbt::deserialize(&bytes).unwrap();
        let input = &signed.inputs[0];
        assert_eq!(input.sighash_type, psbt.inputs[0].sighash_type);

        let ((pubkey, _), signature) = input.tap_script_sigs.iter().next().unwrap();
        let expected = requested.unwrap_or(TapSighashType::Default);
        assert_eq!(signature.sighash_type, expected);
        assert_eq!(
            signature.to_vec().len(),
            if expected == TapSighashType::All {
                65
            } else {
                64
            }
        );

        let prevouts = [input.witness_utxo.clone().unwrap()];
        let hash = SighashCache::new(&signed.unsigned_tx)
            .taproot_script_spend_signature_hash(0, &Prevouts::All(&prevouts), leaf_hash, expected)
            .unwrap();
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature.signature,
                &Message::from_digest(hash.to_byte_array()),
                pubkey,
            )
            .unwrap();
    }
}

#[test]
fn scoped_taproot_signing_rejects_unsupported_sighash() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    for raw in [0x02, 0x03, 0x81, 0x82, 0x83, 0xff, 0x101] {
        let (mut psbt, _, _, _, _) = build_legit_taproot_psbt(&km, AccountType::Colored);
        psbt.inputs[0].sighash_type = Some(bitcoin::psbt::PsbtSighashType::from_u32(raw));
        let err = km
            .sign_psbt_scoped(&psbt.serialize(), Some(AccountType::Colored))
            .unwrap_err();
        assert!(matches!(err, EnclaveError::Signing(_)), "{err}");
    }
}

#[test]
fn emits_one_job_for_legit_multi_a_leaf() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (psbt, _, _, leaf_hash, _) = build_legit_taproot_psbt(&km, AccountType::Vanilla);
    let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].leaf_hash, Some(leaf_hash));
    assert_eq!(jobs[0].xonly_pubkey, our_xonly(&km));
}

/// `tap_scripts` advertises a leaf that does NOT actually sit under
/// `script_pubkey`'s output key. Control block fails to verify.
#[test]
fn skips_when_control_block_does_not_verify() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let secp = Secp256k1::new();

    // Build the legit PSBT (anchored output key).
    let (mut psbt, _, _, _, _) = build_legit_taproot_psbt(&km, AccountType::Vanilla);

    // Build an UNRELATED tree whose control_block we'll splice in.
    let our = our_xonly(&km);
    let unrelated_leaf = multi_a_2_of_3(&[our, xonly_from_byte(0xB1), xonly_from_byte(0xB2)]);
    let unrelated_internal = xonly_from_byte(0xC0);
    let unrelated_builder = TaprootBuilder::new()
        .add_leaf(0, unrelated_leaf.clone())
        .unwrap();
    let unrelated_info = unrelated_builder
        .finalize(&secp, unrelated_internal)
        .unwrap();
    let bad_control = unrelated_info
        .control_block(&(unrelated_leaf.clone(), LeafVersion::TapScript))
        .unwrap();

    psbt.inputs[0].tap_scripts.clear();
    psbt.inputs[0].tap_scripts.insert(
        bad_control,
        (unrelated_leaf.clone(), LeafVersion::TapScript),
    );
    // Update tap_key_origins to claim the unrelated leaf's hash.
    let bad_leaf_hash = TapLeafHash::from_script(&unrelated_leaf, LeafVersion::TapScript);
    psbt.inputs[0].tap_key_origins.insert(
        our,
        (
            vec![bad_leaf_hash],
            (*km.master_fingerprint(), our_full_path()),
        ),
    );

    let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
    assert!(jobs.is_empty());
}

#[test]
fn skips_when_origins_fingerprint_wrong() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (mut psbt, _, _, leaf_hash, _) = build_legit_taproot_psbt(&km, AccountType::Vanilla);
    let our = our_xonly(&km);
    psbt.inputs[0].tap_key_origins.insert(
        our,
        (
            vec![leaf_hash],
            (Fingerprint::from([0xDE, 0xAD, 0xBE, 0xEF]), our_full_path()),
        ),
    );
    let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
    assert!(jobs.is_empty());
}

/// `tap_key_origins` claims OUR fingerprint at a real BIP-86 path, but
/// keys it with someone else's xonly. Without the cryptographic anchor
/// (derived xonly == claimed xonly) the signer would sign for a key it
/// doesn't own.
#[test]
fn skips_when_origins_path_derives_to_different_xonly() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (mut psbt, _, _, leaf_hash, _) = build_legit_taproot_psbt(&km, AccountType::Vanilla);
    // Replace origins with a foreign xonly under our fingerprint+path.
    let foreign = xonly_from_byte(0xEE);
    psbt.inputs[0].tap_key_origins.clear();
    psbt.inputs[0].tap_key_origins.insert(
        foreign,
        (vec![leaf_hash], (*km.master_fingerprint(), our_full_path())),
    );
    // Note: leaf script does not push `foreign`, so even pubkey-in-leaf
    // catches this. Switch the leaf to one that DOES push `foreign` to
    // exercise the derivation-mismatch branch specifically.
    let secp = Secp256k1::new();
    let foreign_leaf = multi_a_2_of_3(&[foreign, xonly_from_byte(0xB1), xonly_from_byte(0xB2)]);
    let foreign_leaf_hash = TapLeafHash::from_script(&foreign_leaf, LeafVersion::TapScript);
    let internal = XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
    let info = TaprootBuilder::new()
        .add_leaf(0, foreign_leaf.clone())
        .unwrap()
        .finalize(&secp, internal)
        .unwrap();
    let cb = info
        .control_block(&(foreign_leaf.clone(), LeafVersion::TapScript))
        .unwrap();
    psbt.inputs[0].tap_scripts.clear();
    psbt.inputs[0]
        .tap_scripts
        .insert(cb, (foreign_leaf.clone(), LeafVersion::TapScript));
    psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey =
        ScriptBuf::new_p2tr_tweaked(info.output_key());
    psbt.inputs[0].tap_key_origins.clear();
    psbt.inputs[0].tap_key_origins.insert(
        foreign,
        (
            vec![foreign_leaf_hash],
            (*km.master_fingerprint(), our_full_path()),
        ),
    );

    let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
    assert!(jobs.is_empty());
}

/// `tap_key_origins` claims our key under our fingerprint, but the verified
/// leaf doesn't push our xonly key.
#[test]
fn skips_when_xonly_in_origins_not_pushed_in_committed_leaf() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let secp = Secp256k1::new();

    // Build a leaf that does NOT contain our xonly.
    let leaf = multi_a_2_of_3(&[
        xonly_from_byte(0xB1),
        xonly_from_byte(0xB2),
        xonly_from_byte(0xB3),
    ]);
    let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
    let internal = XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
    let info = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .unwrap()
        .finalize(&secp, internal)
        .unwrap();
    let cb = info
        .control_block(&(leaf.clone(), LeafVersion::TapScript))
        .unwrap();

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
        output: vec![],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
    });
    psbt.inputs[0]
        .tap_scripts
        .insert(cb, (leaf, LeafVersion::TapScript));
    // Lying entry: claims our key participates in this leaf.
    let our = our_xonly(&km);
    psbt.inputs[0].tap_key_origins.insert(
        our,
        (vec![leaf_hash], (*km.master_fingerprint(), our_full_path())),
    );

    let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
    assert!(jobs.is_empty());
}

#[test]
fn skips_when_already_signed_for_leaf() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (mut psbt, _, _, leaf_hash, _) = build_legit_taproot_psbt(&km, AccountType::Vanilla);
    let our = our_xonly(&km);
    // Insert any tap_script_sig under (our, leaf_hash); content doesn't matter.
    let secp = Secp256k1::new();
    let dummy_kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x77; 32]).unwrap());
    let msg = Message::from_digest([0u8; 32]);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &dummy_kp);
    psbt.inputs[0].tap_script_sigs.insert(
        (our, leaf_hash),
        taproot::Signature {
            signature: sig,
            sighash_type: TapSighashType::Default,
        },
    );
    let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
    assert!(jobs.is_empty());
    // The entry suppresses re-signing without revoking custody: the leaf
    // is still ours, whatever that entry turns out to contain.
    let leaves = find_controlled_taproot_leaves(&psbt, km.master_fingerprint(), &km);
    assert_eq!(leaves.len(), 1);
    assert_eq!(leaves[0].input_index, 0);
    assert_eq!(leaves[0].xonly_pubkey, our);
    assert_eq!(leaves[0].leaf_hash, Some(leaf_hash));
}

/// Another signer's *valid* contribution to the same leaf is not ours: it
/// neither consumes our job nor stands in for our custody.
#[test]
fn another_signers_entry_does_not_consume_our_job() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (mut psbt, _, _, leaf_hash, _) = build_legit_taproot_psbt(&km, AccountType::Vanilla);
    let our = our_xonly(&km);
    let secp = Secp256k1::new();
    // 0xA1 is a real co-signer of this leaf (see build_legit_taproot_psbt).
    let foreign_kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0xA1; 32]).unwrap());
    let foreign = XOnlyPublicKey::from_keypair(&foreign_kp).0;

    let prevouts = [psbt.inputs[0].witness_utxo.clone().unwrap()];
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .unwrap();
    let msg = Message::from_digest(*sighash.as_byte_array());
    let foreign_sig = secp.sign_schnorr_no_aux_rand(&msg, &foreign_kp);
    secp.verify_schnorr(&foreign_sig, &msg, &foreign).unwrap();
    psbt.inputs[0].tap_script_sigs.insert(
        (foreign, leaf_hash),
        taproot::Signature {
            signature: foreign_sig,
            sighash_type: TapSighashType::Default,
        },
    );

    for found in [
        find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km),
        find_controlled_taproot_leaves(&psbt, km.master_fingerprint(), &km),
    ] {
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].xonly_pubkey, our);
        assert_eq!(found[0].leaf_hash, Some(leaf_hash));
    }
}

#[test]
fn skips_when_path_outside_bip86_accounts() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (mut psbt, _, _, leaf_hash, _) = build_legit_taproot_psbt(&km, AccountType::Vanilla);
    let our = our_xonly(&km);
    // Replace path with m/44'/0'/...
    let bad_path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(44).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
    ]);
    psbt.inputs[0].tap_key_origins.clear();
    psbt.inputs[0]
        .tap_key_origins
        .insert(our, (vec![leaf_hash], (*km.master_fingerprint(), bad_path)));
    let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
    assert!(jobs.is_empty());
}

#[test]
fn skips_when_witness_utxo_missing() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (mut psbt, _, _, _, _) = build_legit_taproot_psbt(&km, AccountType::Vanilla);
    psbt.inputs[0].witness_utxo = None;
    let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
    assert!(jobs.is_empty());
}

#[test]
fn skips_when_witness_utxo_not_p2tr() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (mut psbt, _, _, _, _) = build_legit_taproot_psbt(&km, AccountType::Vanilla);
    psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey =
        ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0xCC; 20]));
    let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
    assert!(jobs.is_empty());
}

// === Account-scoped signing (plain-BTC path guard) ===

fn our_xonly_colored(km: &KeyManager) -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    let sk = km
        .derive_btc_child(
            AccountType::Colored,
            &[
                ChildNumber::Normal { index: 0 },
                ChildNumber::Normal { index: 0 },
            ],
        )
        .unwrap();
    XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &sk)).0
}

fn our_colored_full_path() -> DerivationPath {
    DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(86).unwrap(),
        ChildNumber::from_hardened_idx(827167).unwrap(), // RGB coin type -> Colored
        ChildNumber::from_hardened_idx(0).unwrap(),
        ChildNumber::Normal { index: 0 },
        ChildNumber::Normal { index: 0 },
    ])
}

/// Like [`build_legit_taproot_psbt`] but the leaf + tap_key_origins use the
/// COLORED (RGB) account key/path, so the resolved job is `AccountType::Colored`.
fn build_colored_taproot_psbt(km: &KeyManager) -> Psbt {
    let secp = Secp256k1::new();
    let our = our_xonly_colored(km);
    let leaf_script = multi_a_2_of_3(&[our, xonly_from_byte(0xA1), xonly_from_byte(0xA2)]);
    let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);

    let internal_key = XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, leaf_script.clone())
        .unwrap()
        .finalize(&secp, internal_key)
        .unwrap();
    let script_pubkey = ScriptBuf::new_p2tr(&secp, internal_key, spend_info.merkle_root());
    let control_block = spend_info
        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
        .unwrap();

    let unsigned_tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0xBB; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey,
    });
    psbt.inputs[0].tap_internal_key = Some(internal_key);
    psbt.inputs[0]
        .tap_scripts
        .insert(control_block, (leaf_script, LeafVersion::TapScript));
    psbt.inputs[0].tap_key_origins.insert(
        our,
        (
            vec![leaf_hash],
            (*km.master_fingerprint(), our_colored_full_path()),
        ),
    );
    psbt
}

#[test]
fn scoped_vanilla_signs_a_vanilla_input() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (psbt, _, _, _, _) = build_legit_taproot_psbt(&km, AccountType::Vanilla);
    let bytes = psbt.serialize();
    let (_, signed) = km
        .sign_psbt_scoped(&bytes, Some(AccountType::Vanilla))
        .unwrap();
    assert_eq!(
        signed, 1,
        "vanilla-scoped signing must sign a vanilla input"
    );
}

#[test]
fn scoped_vanilla_refuses_a_colored_input() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let bytes = build_colored_taproot_psbt(&km).serialize();

    // Unscoped: the colored input IS signable (sanity check the fixture).
    let (_, unscoped) = km.sign_psbt_scoped(&bytes, None).unwrap();
    assert_eq!(unscoped, 1, "fixture: colored input should sign unscoped");

    // Vanilla-scoped: the colored (RGB-allocated) input must NOT be signed.
    let (_, scoped) = km
        .sign_psbt_scoped(&bytes, Some(AccountType::Vanilla))
        .unwrap();
    assert_eq!(
        scoped, 0,
        "plain-BTC (vanilla-scoped) signing must refuse a colored input"
    );
}

/// Key-path P2TR PSBT spending our `account` key at /0/0, tweaked with `merkle_root`.
fn build_key_path_psbt(
    km: &KeyManager,
    account: AccountType,
    merkle_root: Option<TapNodeHash>,
) -> (Psbt, XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let (internal, path) = match account {
        AccountType::Vanilla => (our_xonly(km), our_full_path()),
        AccountType::Colored => (our_xonly_colored(km), our_colored_full_path()),
    };
    let (output_key, _) = internal.tap_tweak(&secp, merkle_root);
    let unsigned_tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0xCC; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(output_key),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(output_key),
    });
    psbt.inputs[0].tap_internal_key = Some(internal);
    psbt.inputs[0].tap_merkle_root = merkle_root;
    psbt.inputs[0]
        .tap_key_origins
        .insert(internal, (vec![], (*km.master_fingerprint(), path)));
    (psbt, output_key.to_x_only_public_key())
}

fn key_spend_sighash(psbt: &Psbt) -> Message {
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().unwrap())
        .collect();
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
        .unwrap();
    Message::from_digest(*sighash.as_byte_array())
}

#[test]
fn emits_a_key_path_job_for_a_bip86_input() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (psbt, _) = build_key_path_psbt(&km, AccountType::Vanilla, None);

    let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);

    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].leaf_hash, None);
    assert_eq!(jobs[0].merkle_root, None);
    assert_eq!(jobs[0].xonly_pubkey, our_xonly(&km));
    assert_eq!(jobs[0].account_type, AccountType::Vanilla);
}

#[test]
fn key_path_job_resolves_the_colored_account() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (psbt, _) = build_key_path_psbt(&km, AccountType::Colored, None);

    let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);

    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].account_type, AccountType::Colored);
}

#[test]
fn key_path_signature_verifies_against_the_output_key() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (mut psbt, output_key) = build_key_path_psbt(&km, AccountType::Vanilla, None);
    let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);

    let signed = sign_taproot_inputs(&mut psbt, &km, &jobs).unwrap();

    assert_eq!(signed, 1);
    let sig = psbt.inputs[0].tap_key_sig.expect("key-path signature set");
    assert_eq!(sig.sighash_type, TapSighashType::Default);
    assert!(psbt.inputs[0].tap_script_sigs.is_empty());
    Secp256k1::new()
        .verify_schnorr(&sig.signature, &key_spend_sighash(&psbt), &output_key)
        .expect("signature must verify against the on-chain output key");
}

#[test]
fn key_path_with_a_merkle_root_signs_with_the_same_tweak() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let root = TapNodeHash::from_byte_array([0x77; 32]);
    let (mut psbt, output_key) = build_key_path_psbt(&km, AccountType::Vanilla, Some(root));
    let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].merkle_root, Some(root));

    sign_taproot_inputs(&mut psbt, &km, &jobs).unwrap();

    let sig = psbt.inputs[0].tap_key_sig.unwrap();
    Secp256k1::new()
        .verify_schnorr(&sig.signature, &key_spend_sighash(&psbt), &output_key)
        .expect("tweaked signature must verify");
}

#[test]
fn skips_key_path_when_the_output_key_is_not_the_tweaked_internal_key() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (mut psbt, _) = build_key_path_psbt(&km, AccountType::Vanilla, None);
    // The PSBT claims our internal key, but the coin is locked to someone else.
    let secp = Secp256k1::new();
    let (foreign, _) = xonly_from_byte(0xA1).tap_tweak(&secp, None);
    psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey =
        ScriptBuf::new_p2tr_tweaked(foreign);

    assert!(find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km).is_empty());
}

#[test]
fn skips_key_path_when_the_merkle_root_claim_does_not_match_the_output() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (mut psbt, _) = build_key_path_psbt(&km, AccountType::Vanilla, None);
    psbt.inputs[0].tap_merkle_root = Some(TapNodeHash::from_byte_array([0x77; 32]));

    assert!(find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km).is_empty());
}

#[test]
fn skips_key_path_when_origins_claim_another_fingerprint() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (mut psbt, _) = build_key_path_psbt(&km, AccountType::Vanilla, None);
    let internal = psbt.inputs[0].tap_internal_key.unwrap();
    psbt.inputs[0].tap_key_origins.insert(
        internal,
        (
            vec![],
            (Fingerprint::from([0xDE, 0xAD, 0xBE, 0xEF]), our_full_path()),
        ),
    );

    assert!(find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km).is_empty());
}

#[test]
fn skips_key_path_when_the_claimed_path_derives_another_key() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (mut psbt, _) = build_key_path_psbt(&km, AccountType::Vanilla, None);
    let internal = psbt.inputs[0].tap_internal_key.unwrap();
    let other_path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(86).unwrap(),
        ChildNumber::from_hardened_idx(1).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
        ChildNumber::Normal { index: 0 },
        ChildNumber::Normal { index: 1 },
    ]);
    psbt.inputs[0]
        .tap_key_origins
        .insert(internal, (vec![], (*km.master_fingerprint(), other_path)));

    assert!(find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km).is_empty());
}

#[test]
fn skips_key_path_when_already_signed() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (mut psbt, _) = build_key_path_psbt(&km, AccountType::Vanilla, None);
    let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);
    sign_taproot_inputs(&mut psbt, &km, &jobs).unwrap();

    assert!(find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km).is_empty());
    // Our key-path signature does not revoke custody.
    let controlled = find_controlled_taproot_leaves(&psbt, km.master_fingerprint(), &km);
    assert_eq!(controlled.len(), 1);
    assert_eq!(controlled[0].leaf_hash, None);
}

#[test]
fn script_path_input_without_our_internal_key_emits_no_key_path_job() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (psbt, _, _, _, _) = build_legit_taproot_psbt(&km, AccountType::Vanilla);

    let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);

    assert_eq!(jobs.len(), 1);
    assert!(jobs[0].leaf_hash.is_some());
}

#[test]
fn key_path_signing_honors_requested_sighash() {
    let km = KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap();
    let (mut psbt, output_key) = build_key_path_psbt(&km, AccountType::Vanilla, None);
    psbt.inputs[0].sighash_type = Some(TapSighashType::All.into());
    let jobs = find_taproot_sign_jobs(&psbt, km.master_fingerprint(), &km);

    sign_taproot_inputs(&mut psbt, &km, &jobs).unwrap();

    let sig = psbt.inputs[0].tap_key_sig.unwrap();
    assert_eq!(sig.sighash_type, TapSighashType::All);
    let prevouts = [psbt.inputs[0].witness_utxo.clone().unwrap()];
    let hash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::All)
        .unwrap();
    Secp256k1::new()
        .verify_schnorr(
            &sig.signature,
            &Message::from_digest(*hash.as_byte_array()),
            &output_key,
        )
        .unwrap();
}
