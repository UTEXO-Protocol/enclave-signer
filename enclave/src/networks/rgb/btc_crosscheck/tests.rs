use super::*;
use bitcoin::bip32::{ChildNumber, DerivationPath};
use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL};
use bitcoin::blockdata::script::Builder as ScriptBuilder;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, WPubkeyHash,
    Witness, XOnlyPublicKey,
};

use crate::keys::AccountType;
use crate::networks::rgb::psbt_validation::MAX_FEE_CAP_CROSSOVER_VB;

fn km() -> KeyManager {
    KeyManager::from_seed([0x42u8; 64], Network::Testnet).unwrap()
}

fn foreign_xonly(b: u8) -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[b; 32]).unwrap();
    XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &sk)).0
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

/// Our BIP-86 key-path address at m/86'/1'/0'/0/0, with the key and origin
/// that make an input controlled.
struct OurAddress {
    spk: ScriptBuf,
    xonly: XOnlyPublicKey,
    path: DerivationPath,
}

fn our_address(keys: &KeyManager) -> OurAddress {
    let secp = Secp256k1::new();
    let child = [
        ChildNumber::Normal { index: 0 },
        ChildNumber::Normal { index: 0 },
    ];
    let sk = keys.derive_btc_child(AccountType::Vanilla, &child).unwrap();
    let xonly = XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &sk)).0;
    OurAddress {
        spk: ScriptBuf::new_p2tr(&secp, xonly, None),
        xonly,
        path: DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(86).unwrap(),
            ChildNumber::from_hardened_idx(1).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            child[0],
            child[1],
        ]),
    }
}

/// A taproot address with a foreign key.
fn foreign_address() -> ScriptBuf {
    ScriptBuf::new_p2tr(&Secp256k1::new(), foreign_xonly(0xB1), None)
}

/// Plain-BTC PSBT that spends `inputs` (sats each) from our address and pays
/// `outputs`. Inputs have full key-path metadata, so rule (A) accepts any
/// output back to that address.
fn psbt_from_our_address(
    keys: &KeyManager,
    inputs: &[u64],
    outputs: &[(ScriptBuf, u64)],
) -> Vec<u8> {
    psbt_inner(keys, inputs, outputs, true)
}

/// Like [`psbt_from_our_address`], but without witness_utxo.
fn psbt_without_witness_utxo(
    keys: &KeyManager,
    inputs: &[u64],
    outputs: &[(ScriptBuf, u64)],
) -> Vec<u8> {
    psbt_inner(keys, inputs, outputs, false)
}

fn psbt_inner(
    keys: &KeyManager,
    inputs: &[u64],
    outputs: &[(ScriptBuf, u64)],
    set_witness_utxo: bool,
) -> Vec<u8> {
    let ours = our_address(keys);
    let unsigned_tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: (0..inputs.len().max(1))
            .map(|i| TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                        [i as u8; 32],
                    )),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs
            .iter()
            .map(|(spk, sat)| TxOut {
                value: Amount::from_sat(*sat),
                script_pubkey: spk.clone(),
            })
            .collect(),
    };
    let mut p = Psbt::from_unsigned_tx(unsigned_tx).expect("from_unsigned_tx");
    for (i, sat) in inputs.iter().enumerate() {
        if set_witness_utxo {
            p.inputs[i].witness_utxo = Some(TxOut {
                value: Amount::from_sat(*sat),
                script_pubkey: ours.spk.clone(),
            });
        }
        p.inputs[i].tap_internal_key = Some(ours.xonly);
        p.inputs[i].tap_key_origins.insert(
            ours.xonly,
            (vec![], (*keys.master_fingerprint(), ours.path.clone())),
        );
    }
    p.serialize()
}

fn cfg_with_cap(cap: u64) -> BridgeConfig {
    BridgeConfig {
        btc_max_total_sats: cap,
        // Sized for `create_utxo` allocation dust (1000 sats x 5).
        btc_max_unowned_sats: 5_000,
        ..Default::default()
    }
}

/// Budget config for the send-RGB sats gate.
fn rgb_cfg(budget: u64) -> BridgeConfig {
    BridgeConfig {
        rgb_max_unowned_sats: budget,
        ..Default::default()
    }
}

// --- send-RGB unowned-output budget (BTC value-diversion PoC) ---

/// **The attack.** The PSBT spends two 5_000_000-sat bridge UTXOs. The RGB
/// legs are correct (recipient dust, change dust on a self-owned vout). The
/// rest goes to an attacker output with no RGB assignment, so no
/// asset-unit bind sees it. Only the budget catches it.
#[test]
fn rgb_sats_gate_rejects_a_treasury_sweep() {
    let keys = km();
    let ours = our_address(&keys);
    let psbt_bytes = psbt_from_our_address(
        &keys,
        &[5_000_000, 5_000_000],
        &[
            (foreign_address(), 546),       // recipient witness dust
            (ours.spk.clone(), 546),        // bridge change, self-owned
            (foreign_address(), 9_997_908), // the sweep
        ],
    );
    let psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes).unwrap();
    let err = validate_rgb_psbt_sats(&psbt, &rgb_cfg(5_000), &keys).unwrap_err();
    assert!(
        err.to_string().contains("cannot prove it controls"),
        "got: {err}"
    );
}

/// The correct shape signs: recipient dust is in the budget and the bridge
/// change pays back to an input script (rule (A)).
#[test]
fn rgb_sats_gate_accepts_recipient_dust_with_self_owned_change() {
    let keys = km();
    let ours = our_address(&keys);
    let psbt_bytes = psbt_from_our_address(
        &keys,
        &[5_000_000],
        &[(foreign_address(), 1_500), (ours.spk.clone(), 4_998_000)],
    );
    let psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes).unwrap();
    assert!(validate_rgb_psbt_sats(&psbt, &rgb_cfg(5_000), &keys).is_ok());
}

/// The budget counts the sum of unowned outputs, so a sweep split across
/// many outputs still fails.
#[test]
fn rgb_sats_gate_sums_unowned_outputs() {
    let keys = km();
    let outputs: Vec<_> = (0..6).map(|_| (foreign_address(), 1_000)).collect();
    let psbt_bytes = psbt_from_our_address(&keys, &[5_000_000], &outputs);
    let psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes).unwrap();
    // 6 x 1_000 = 6_000 > 5_000, but each output is under it.
    let err = validate_rgb_psbt_sats(&psbt, &rgb_cfg(5_000), &keys).unwrap_err();
    assert!(err.to_string().contains("6000 sats"), "got: {err}");
}

/// No rule (B): a taproot tree that names one of our keys is NOT proof of
/// control. The rest of the tree and its internal key are foreign. The output
/// counts against the budget.
#[test]
fn rgb_sats_gate_does_not_trust_a_leaf_mentioning_our_key() {
    use bitcoin::psbt::Psbt;
    let keys = km();
    let ours = our_address(&keys);

    // A foreign script with one leaf: our key and two attacker keys.
    let secp = Secp256k1::new();
    let leaf = multi_a_2_of_3(&[ours.xonly, foreign_xonly(0xC1), foreign_xonly(0xC2)]);
    let internal = foreign_xonly(0xC3);
    let info = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .unwrap()
        .finalize(&secp, internal)
        .unwrap();
    let spk = ScriptBuf::new_p2tr(&secp, internal, info.merkle_root());

    let psbt_bytes = psbt_from_our_address(&keys, &[5_000_000], &[(spk, 4_999_000)]);
    let mut psbt = Psbt::deserialize(&psbt_bytes).unwrap();
    // Full BIP-371 output metadata for the leaf.
    psbt.outputs[0].tap_internal_key = Some(internal);
    psbt.outputs[0].tap_tree = Some(
        TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    psbt.outputs[0].tap_key_origins.insert(
        ours.xonly,
        (
            vec![TapLeafHash::from_script(&leaf, LeafVersion::TapScript)],
            (*keys.master_fingerprint(), ours.path.clone()),
        ),
    );

    let err = validate_rgb_psbt_sats(&psbt, &rgb_cfg(5_000), &keys).unwrap_err();
    assert!(
        err.to_string().contains("cannot prove it controls"),
        "a leaf naming our key must not count as control; got: {err}"
    );
}

#[test]
fn rejects_empty_psbt() {
    let keys = km();
    let req = SignBtcRequest { psbt_bytes: vec![] };
    let err = validate_btc_request(&req, &cfg_with_cap(100_000), &keys).unwrap_err();
    assert!(err.to_string().contains("psbt_bytes is empty"));
}

// --- witness_utxo required (to bound the value spent) ---

#[test]
fn rejects_missing_witness_utxo() {
    let keys = km();
    let ours = our_address(&keys);
    let req = SignBtcRequest {
        psbt_bytes: psbt_without_witness_utxo(&keys, &[50_000], &[(ours.spk, 40_000)]),
    };
    let err = validate_btc_request(&req, &cfg_with_cap(100_000), &keys).unwrap_err();
    assert!(
        err.to_string().contains("missing witness_utxo"),
        "got: {err}"
    );
}

// --- Output self-ownership and value-spent cap ---

#[test]
fn accepts_self_paying_output_under_cap() {
    let keys = km();
    let ours = our_address(&keys);
    let req = SignBtcRequest {
        psbt_bytes: psbt_from_our_address(&keys, &[60_000], &[(ours.spk, 50_000)]),
    };
    assert!(validate_btc_request(&req, &cfg_with_cap(100_000), &keys).is_ok());
}

#[test]
fn accepts_input_value_at_exact_cap() {
    let keys = km();
    let ours = our_address(&keys);
    let req = SignBtcRequest {
        // input value 100_000 == cap; output pays back to us.
        psbt_bytes: psbt_from_our_address(&keys, &[100_000], &[(ours.spk, 99_000)]),
    };
    assert!(validate_btc_request(&req, &cfg_with_cap(100_000), &keys).is_ok());
}

#[test]
fn rejects_output_the_enclave_does_not_control() {
    let keys = km();
    let req = SignBtcRequest {
        psbt_bytes: psbt_from_our_address(&keys, &[50_000], &[(foreign_address(), 10_000)]),
    };
    let err = validate_btc_request(&req, &cfg_with_cap(100_000), &keys).unwrap_err();
    assert!(err.to_string().contains("same custody"), "got: {err}");
}

#[test]
fn rejects_one_foreign_output_among_self_paying_ones() {
    let keys = km();
    let ours = our_address(&keys);
    let req = SignBtcRequest {
        psbt_bytes: psbt_from_our_address(
            &keys,
            &[50_000],
            &[(ours.spk, 10_000), (foreign_address(), 10_000)],
        ),
    };
    let err = validate_btc_request(&req, &cfg_with_cap(100_000), &keys).unwrap_err();
    assert!(
        err.to_string().contains("10000 sats"),
        "only the foreign output counts against the budget; got: {err}"
    );
}

/// A non-taproot output is never proven ours. The enclave co-controls taproot
/// scripts only, and BIP-371 metadata cannot describe a P2WPKH.
#[test]
fn rejects_non_taproot_output() {
    let keys = km();
    let p2wpkh = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0xCC; 20]));
    let req = SignBtcRequest {
        psbt_bytes: psbt_from_our_address(&keys, &[50_000], &[(p2wpkh, 10_000)]),
    };
    assert!(validate_btc_request(&req, &cfg_with_cap(100_000), &keys).is_err());
}

#[test]
fn rejects_empty_output_set() {
    let keys = km();
    let req = SignBtcRequest {
        psbt_bytes: psbt_from_our_address(&keys, &[50_000], &[]),
    };
    let err = validate_btc_request(&req, &cfg_with_cap(100_000), &keys).unwrap_err();
    assert!(err.to_string().contains("no outputs"), "got: {err}");
}

#[test]
fn rejects_input_value_over_cap() {
    let keys = km();
    let ours = our_address(&keys);
    let req = SignBtcRequest {
        // input value 100_001 > cap. The fee is normal, so the cap fails,
        // not the fee policy.
        psbt_bytes: psbt_from_our_address(&keys, &[100_001], &[(ours.spk, 95_000)]),
    };
    let err = validate_btc_request(&req, &cfg_with_cap(100_000), &keys).unwrap_err();
    assert!(err.to_string().contains("exceeds pinned cap"), "got: {err}");
}

#[test]
fn rejects_summed_input_value_over_cap() {
    let keys = km();
    let ours = our_address(&keys);
    let req = SignBtcRequest {
        // two inputs: 70_000 + 50_000 = 120_000 > cap.
        psbt_bytes: psbt_from_our_address(&keys, &[70_000, 50_000], &[(ours.spk, 100_000)]),
    };
    let err = validate_btc_request(&req, &cfg_with_cap(100_000), &keys).unwrap_err();
    assert!(err.to_string().contains("exceeds pinned cap"), "got: {err}");
}

/// The unowned budget applies even when the value cap allows the spend.
#[test]
fn foreign_output_over_budget_is_rejected_whatever_the_value_cap_says() {
    let keys = km();
    let req = SignBtcRequest {
        psbt_bytes: psbt_from_our_address(&keys, &[100_000], &[(foreign_address(), 90_000)]),
    };
    // In `btc_max_total_sats`, but far over the unowned budget.
    let err = validate_btc_request(&req, &cfg_with_cap(1_000_000), &keys).unwrap_err();
    assert!(err.to_string().contains("same custody"), "got: {err}");
}

/// Five 1000-sat colored allocations funded from vanilla inputs fit the
/// budget. The vanilla change goes back to the spent script (address reuse).
#[test]
fn create_utxo_allocation_dust_fits_the_budget() {
    let keys = km();
    let ours = our_address(&keys);
    let mut outputs: Vec<_> = (0..5).map(|_| (foreign_address(), 1_000)).collect();
    outputs.push((ours.spk.clone(), 40_000));
    let req = SignBtcRequest {
        psbt_bytes: psbt_from_our_address(&keys, &[50_000], &outputs),
    };
    assert!(validate_btc_request(&req, &cfg_with_cap(100_000), &keys).is_ok());
}

/// With the cap unset, a production build fails closed. Default and test
/// builds use the dev path, after the other checks pass.
#[test]
fn unpinned_cap_behaviour_matches_build_profile() {
    let keys = km();
    let ours = our_address(&keys);
    let req = SignBtcRequest {
        // 200 sat pays for approx 111 signed vB at the 1 sat/vB floor.
        psbt_bytes: psbt_from_our_address(&keys, &[1_000], &[(ours.spk, 800)]),
    };
    let result = validate_btc_request(&req, &BridgeConfig::default(), &keys);
    #[cfg(all(feature = "rgb-validation", not(test)))]
    assert!(result.is_err());
    // Unit tests are always cfg(test), so the dev fallback returns Ok.
    #[cfg(not(all(feature = "rgb-validation", not(test))))]
    assert!(result.is_ok());
}

// --- pinned fee policy on the plain-BTC path (#248) ---

/// **The attack.** A compromised host spends a custody UTXO back to custody.
/// All outputs are self-owned and the value cap passes, but approx 98% of the
/// input goes to miners. Repeated per UTXO, this drains the mint wallet.
#[test]
fn rejects_a_fee_that_burns_most_of_the_input() {
    let keys = km();
    let ours = our_address(&keys);
    let req = SignBtcRequest {
        // #248: 60_676 sat in, 1_000 sat out, 59_676 sat fee.
        psbt_bytes: psbt_from_our_address(&keys, &[60_676], &[(ours.spk, 1_000)]),
    };
    let err = validate_btc_request(&req, &cfg_with_cap(100_000), &keys).unwrap_err();
    assert!(
        err.to_string().contains("plain-BTC PSBT fee rate too high"),
        "got: {err}"
    );
}

#[test]
fn rejects_an_excessive_fee_spread_over_two_inputs() {
    let keys = km();
    let ours = our_address(&keys);
    let req = SignBtcRequest {
        // Each input is small, but together 59_000 sat over approx 135 vB.
        psbt_bytes: psbt_from_our_address(&keys, &[30_000, 30_000], &[(ours.spk, 1_000)]),
    };
    let err = validate_btc_request(&req, &cfg_with_cap(100_000), &keys).unwrap_err();
    assert!(err.to_string().contains("fee rate too high"), "got: {err}");
}

#[test]
fn rejects_a_fee_over_the_pinned_absolute_maximum() {
    let keys = km();
    let ours = our_address(&keys);
    // Many self-owned outputs, so the absolute cap fails, not the rate.
    let outputs: Vec<_> = (0..30).map(|_| (ours.spk.clone(), 1_000)).collect();
    let req = SignBtcRequest {
        psbt_bytes: psbt_from_our_address(&keys, &[1_000_000], &outputs),
    };
    let err = validate_btc_request(&req, &cfg_with_cap(10_000_000), &keys).unwrap_err();
    assert!(err.to_string().contains("fee too high"), "got: {err}");
}

/// The fee floor needs the signed size, so every input must be classifiable.
/// A second P2TR input with no key-path metadata is not ours. Ownership does
/// not need it, because the output pays back to input 0's script. The request
/// still fails with a size error.
#[test]
fn rejects_an_input_whose_signed_size_cannot_be_estimated() {
    let keys = km();
    let ours = our_address(&keys);
    // Input 0 alone proves the 90_000-sat output (an input exempts outputs up
    // to its value). 20_000 sat over approx 125 unsigned vB is under the rate
    // cap, so only the size estimate can fail.
    let mut psbt = Psbt::deserialize(&psbt_from_our_address(
        &keys,
        &[100_000, 10_000],
        &[(ours.spk.clone(), 90_000)],
    ))
    .unwrap();
    let input = &mut psbt.inputs[1];
    input.witness_utxo.as_mut().unwrap().script_pubkey = foreign_address();
    input.tap_internal_key = None;
    input.tap_key_origins.clear();
    let req = SignBtcRequest {
        psbt_bytes: psbt.serialize(),
    };
    let err = validate_btc_request(&req, &cfg_with_cap(1_000_000), &keys).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("cannot estimate signed PSBT size"),
        "got: {msg}"
    );
    assert!(msg.contains("input 1"), "got: {msg}");
}

/// Above the crossover size, the absolute cap refuses a rate that the rate
/// cap accepts. The error must name the crossover, not a rate problem.
#[test]
fn absolute_cap_error_names_the_size_crossover() {
    let keys = km();
    let ours = our_address(&keys);
    // One input and 12 outputs: approx 584 unsigned vB x 180 sat/vB = 105_120.
    let outputs: Vec<_> = (0..12).map(|_| (ours.spk.clone(), 1_000)).collect();
    let fee = 105_120;
    let req = SignBtcRequest {
        psbt_bytes: psbt_from_our_address(&keys, &[12_000 + fee], &outputs),
    };
    let err = validate_btc_request(&req, &cfg_with_cap(10_000_000), &keys).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("fee too high"), "got: {msg}");
    assert!(
        msg.contains(&format!("above {} vB", MAX_FEE_CAP_CROSSOVER_VB)),
        "got: {msg}"
    );
}

#[test]
fn rejects_a_fee_below_the_signed_size_floor() {
    let keys = km();
    let ours = our_address(&keys);
    let req = SignBtcRequest {
        // 50 sat cannot pay for approx 111 signed vB at 1 sat/vB.
        psbt_bytes: psbt_from_our_address(&keys, &[10_000], &[(ours.spk, 9_950)]),
    };
    let err = validate_btc_request(&req, &cfg_with_cap(100_000), &keys).unwrap_err();
    assert!(err.to_string().contains("fee rate too low"), "got: {err}");
}

/// A normal `create_utxos` batch signs: one input, five allocations and
/// change, approx 50 sat/vB.
#[test]
fn accepts_a_create_utxos_batch_at_a_normal_fee_rate() {
    let keys = km();
    let ours = our_address(&keys);
    let mut outputs: Vec<_> = (0..5).map(|_| (foreign_address(), 1_000)).collect();
    // Approx 310 unsigned vB x 50 sat/vB = 15_500 sat fee.
    outputs.push((ours.spk.clone(), 100_000 - 5_000 - 15_500));
    let req = SignBtcRequest {
        psbt_bytes: psbt_from_our_address(&keys, &[100_000], &outputs),
    };
    validate_btc_request(&req, &cfg_with_cap(100_000), &keys).expect("create_utxos fee");
}

/// The fee policy needs no config. With the value cap unset, the dev fallback
/// must not accept an excessive fee in any build profile.
#[test]
fn fee_policy_holds_without_a_pinned_value_cap() {
    let keys = km();
    let ours = our_address(&keys);
    let req = SignBtcRequest {
        psbt_bytes: psbt_from_our_address(&keys, &[60_676], &[(ours.spk, 1_000)]),
    };
    let err = validate_btc_request(&req, &BridgeConfig::default(), &keys).unwrap_err();
    assert!(err.to_string().contains("fee rate too high"), "got: {err}");
}
