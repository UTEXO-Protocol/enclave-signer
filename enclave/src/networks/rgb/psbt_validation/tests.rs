use super::*;
#[cfg(feature = "rgb-validation")]
use bitcoin::{hashes::Hash, OutPoint, Sequence, TxIn, Txid, Witness};
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};

/// Minimal BIP-174-valid PSBT: one dummy input, one dummy output, no
/// signatures.
#[cfg(feature = "rgb-validation")]
fn minimal_valid_psbt_bytes() -> Vec<u8> {
    let unsigned_tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                    [0u8; 32],
                )),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    Psbt::from_unsigned_tx(unsigned_tx)
        .expect("from_unsigned_tx")
        .serialize()
}

// PSBT shape allowlist tests

#[test]
fn rejects_empty_psbt_bytes() {
    let err = validate_psbt_bytes(&[]).unwrap_err();
    assert!(err.to_string().contains("psbt_bytes is empty"));
}

// PSBT shape allowlist rejection tests

#[test]
fn rejects_garbage_psbt_bytes() {
    // Not empty, but not a BIP-174 PSBT.
    let err = validate_psbt_bytes(&[0xFF; 100]).unwrap_err();
    assert!(
        err.to_string().contains("not a valid PSBT"),
        "expected PSBT parse rejection, got: {err}"
    );
}

#[test]
fn rejects_psbt_with_no_inputs() {
    // BIP-174 can serialize a PSBT with zero inputs. Validation must reject
    // it, because there is nothing to sign.
    let unsigned_tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("from_unsigned_tx");
    let err = validate_psbt_bytes(&psbt.serialize()).unwrap_err();
    assert!(
        err.to_string().contains("no inputs"),
        "expected no-inputs rejection, got: {err}"
    );
}

// Operation-dedup key - `psbt_operation_key`

#[test]
fn op_key_varies_with_every_field() {
    let base = psbt_operation_key(1, &[0x11; 20], &[0xAA; 32], &[0x07; 32], "rgb:asset");
    assert_ne!(
        base,
        psbt_operation_key(2, &[0x11; 20], &[0xAA; 32], &[0x07; 32], "rgb:asset"),
        "chain_id must change the key"
    );
    assert_ne!(
        base,
        psbt_operation_key(1, &[0x22; 20], &[0xAA; 32], &[0x07; 32], "rgb:asset"),
        "bridge_contract must change the key"
    );
    assert_ne!(
        base,
        psbt_operation_key(1, &[0x11; 20], &[0xBB; 32], &[0x07; 32], "rgb:asset"),
        "evm_tx_hash must change the key"
    );
    assert_ne!(
        base,
        psbt_operation_key(1, &[0x11; 20], &[0xAA; 32], &[0x08; 32], "rgb:asset"),
        "funds_in_operation_id must change the key"
    );
    assert_ne!(
        base,
        psbt_operation_key(1, &[0x11; 20], &[0xAA; 32], &[0x07; 32], "rgb:other"),
        "rgb_asset_id must change the key"
    );
}

#[test]
fn op_key_length_prefix_blocks_concatenation_collision() {
    // Both variable-length field boundaries must be framed. Without the
    // prefixes, every case hashes the same bytes, "ABXC".
    let cases: [(&[u8], &[u8], &str); 3] =
        [(b"AB", b"X", "C"), (b"A", b"BX", "C"), (b"AB", b"", "XC")];
    let keys: Vec<_> = cases
        .iter()
        .map(|(tx, operation, asset)| {
            assert_eq!([*tx, *operation, asset.as_bytes()].concat(), b"ABXC");
            psbt_operation_key(1, &[0x11; 20], tx, operation, asset)
        })
        .collect();
    for (i, key) in keys.iter().enumerate() {
        for other in &keys[i + 1..] {
            assert_ne!(key, other, "field boundaries must change the operation key");
        }
    }
}

// Operation dedup end-to-end: `psbt_operation_key` and the soft replay guard,
// as the EVM->RGB path uses them.
mod operation_dedup {
    use crate::error::EnclaveError;
    use crate::networks::rgb::psbt_validation::psbt_operation_key;
    use crate::state::NonceReplayGuard;
    use std::time::Duration;

    // An EVM->RGB operation key, as at the server call site: pinned
    // chain/contract, request tx hash, on-chain `funds_in_operation_id`, and
    // RGB asset id.
    fn op_key(tx: &[u8], funds_in_operation_id: &[u8]) -> [u8; 32] {
        psbt_operation_key(1, &[0x11; 20], tx, funds_in_operation_id, "rgb:asset")
    }

    fn guard() -> NonceReplayGuard {
        NonceReplayGuard::with_capacity(1000, Duration::from_secs(24 * 60 * 60))
    }

    #[test]
    fn same_operation_is_rejected_within_one_instance() {
        // While the record is live, the same op is refused a second time
        // (honest retry or simple replay).
        let g = guard();
        let k = op_key(&[0xAA; 32], &[0x07; 32]);
        g.reserve(k)
            .expect("first signing reserves the op")
            .commit();
        assert!(
            matches!(g.reserve(k), Err(EnclaveError::NonceReplay)),
            "the same operation must be refused as a replay"
        );
    }
}

// Fee policy - `check_psbt_fee`
#[cfg(feature = "rgb-validation")]
mod fee_policy {
    use super::*;

    /// One native P2WPKH input (`witness_utxo` of `input_sats`) and one output
    /// of `output_sats`, so `Psbt::fee()` = input - output.
    fn psbt_with_fee(input_sats: u64, output_sats: u64) -> Psbt {
        let script_pubkey =
            ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x22; 20]));
        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                        [0x11; 32],
                    )),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_sats),
                script_pubkey: script_pubkey.clone(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("from_unsigned_tx");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(input_sats),
            script_pubkey,
        });
        psbt
    }

    fn disclose_taproot_leaf(
        input: &mut bitcoin::psbt::Input,
        leaf: ScriptBuf,
    ) -> bitcoin::taproot::ControlBlock {
        use bitcoin::secp256k1::Secp256k1;
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        let info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&Secp256k1::new(), input.tap_internal_key.unwrap())
            .unwrap();
        let control = info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap();
        input.tap_merkle_root = info.merkle_root();
        input.witness_utxo.as_mut().unwrap().script_pubkey =
            ScriptBuf::new_p2tr_tweaked(info.output_key());
        input
            .tap_scripts
            .insert(control.clone(), (leaf, LeafVersion::TapScript));
        control
    }

    #[test]
    fn owned_key_path_floor_ignores_disclosed_leaves() {
        use crate::keys::AccountType;
        use crate::networks::rgb::btc_ownership::tests as fx;
        use bitcoin::opcodes::all::{OP_CHECKSIG, OP_RETURN};
        use bitcoin::script::Builder;
        use bitcoin::sighash::TapSighashType;

        let keys = fx::km();
        for opcode in [OP_RETURN, OP_CHECKSIG] {
            for requested in [TapSighashType::Default, TapSighashType::All] {
                let mut psbt = psbt_with_fee(100_000, 100_000);
                fx::anchor_input(&mut psbt, 0, &keys, AccountType::Colored, 0, 0, 100_000);
                let internal = psbt.inputs[0].tap_internal_key.unwrap();
                let leaf = if opcode == OP_CHECKSIG {
                    Builder::new().push_x_only_key(&internal)
                } else {
                    Builder::new()
                }
                .push_opcode(opcode)
                .into_script();
                disclose_taproot_leaf(&mut psbt.inputs[0], leaf);
                psbt.inputs[0].sighash_type = Some(requested.into());
                let key_paths = fee_key_path_inputs_scoped(&psbt, &keys, AccountType::Colored);
                assert_eq!(key_paths, vec![0]);

                let mut tx = psbt.unsigned_tx.clone();
                let signature_len = if requested == TapSighashType::Default {
                    64
                } else {
                    65
                };
                tx.input[0].witness = Witness::from_slice(&[vec![0; signature_len]]);
                let minimum = tx.vsize() as u64;
                psbt.unsigned_tx.output[0].value = Amount::from_sat(100_000 - minimum);
                check_psbt_fee(&psbt, &key_paths, "send-RGB").unwrap();

                let (bytes, count) = keys
                    .sign_psbt_scoped(&psbt.serialize(), Some(AccountType::Colored))
                    .unwrap();
                assert_eq!(count, 1);
                let signed = Psbt::deserialize(&bytes).unwrap();
                let signature = fx::verify_own_signature(&signed, 0).unwrap();
                assert_eq!(signature.sighash_type, requested);
                tx = signed.unsigned_tx.clone();
                tx.input[0].witness = Witness::from_slice(&[signature.to_vec()]);
                assert_eq!(tx.vsize() as u64, minimum);
                // Merging a signature must not change the planned spend path.
                assert_eq!(
                    fee_key_path_inputs_scoped(&signed, &keys, AccountType::Colored),
                    key_paths
                );
                check_psbt_fee(&signed, &key_paths, "send-RGB").unwrap();

                psbt.unsigned_tx.output[0].value += Amount::from_sat(1);
                let err = check_psbt_fee(&psbt, &key_paths, "send-RGB").unwrap_err();
                assert!(err.to_string().contains("fee rate too low"), "{err}");
            }
        }
    }

    #[test]
    fn foreign_script_path_with_complete_metadata_keeps_its_full_fee_floor() {
        use crate::keys::AccountType;
        use crate::networks::rgb::btc_ownership::tests as fx;
        use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL, OP_RETURN};
        use bitcoin::script::Builder;

        let keys = fx::km();
        let mut psbt = fx::psbt_with_n(2, &[(fx::foreign_address(0xB1), 200_000)]);
        fx::anchor_input(&mut psbt, 0, &keys, AccountType::Colored, 0, 0, 100_000);
        disclose_taproot_leaf(
            &mut psbt.inputs[0],
            Builder::new().push_opcode(OP_RETURN).into_script(),
        );
        // BIP-341 NUMS internal key: the second input must use its script path.
        let nums = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
            .parse::<bitcoin::XOnlyPublicKey>()
            .unwrap();
        let forged_origin = psbt.inputs[0]
            .tap_key_origins
            .values()
            .next()
            .unwrap()
            .clone();
        let auxiliary = &mut psbt.inputs[1];
        auxiliary.witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new(),
        });
        auxiliary.tap_internal_key = Some(nums);
        auxiliary.tap_key_origins.insert(nums, forged_origin);
        let leaf = Builder::new()
            .push_x_only_key(&fx::foreign_xonly(7))
            .push_opcode(OP_CHECKSIG)
            .push_x_only_key(&fx::foreign_xonly(8))
            .push_opcode(OP_CHECKSIGADD)
            .push_x_only_key(&fx::foreign_xonly(9))
            .push_opcode(OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(OP_NUMEQUAL)
            .into_script();
        let control = disclose_taproot_leaf(auxiliary, leaf.clone());
        let key_paths = fee_key_path_inputs_scoped(&psbt, &keys, AccountType::Colored);
        assert_eq!(
            key_paths,
            vec![0],
            "forged origins cannot establish key ownership"
        );

        let mut tx = psbt.unsigned_tx.clone();
        tx.input[0].witness = Witness::from_slice(&[vec![0; 64]]);
        // Placeholder signatures for size, with the cosigner sighash bytes.
        tx.input[1].witness = Witness::from_slice(&[
            vec![0; 65],
            vec![0; 65],
            vec![],
            leaf.into_bytes(),
            control.serialize(),
        ]);
        let minimum = tx.vsize() as u64;
        psbt.unsigned_tx.output[0].value = Amount::from_sat(200_000 - minimum);
        check_psbt_fee(&psbt, &key_paths, "send-RGB").unwrap();

        tx.input[1].witness = Witness::from_slice(&[vec![0; 64]]);
        let key_path_only_fee = tx.vsize() as u64;
        assert!(key_path_only_fee < minimum);
        for fee in [key_path_only_fee, minimum - 1] {
            psbt.unsigned_tx.output[0].value = Amount::from_sat(200_000 - fee);
            let err = check_psbt_fee(&psbt, &key_paths, "send-RGB").unwrap_err();
            assert!(err.to_string().contains("fee rate too low"), "{err}");
        }
    }

    fn signed_vsize(psbt: &Psbt) -> u64 {
        let mut tx = psbt.unsigned_tx.clone();
        for input in &mut tx.input {
            // Placeholders for size: max ECDSA signature and compressed key.
            input.witness = Witness::from_slice(&[vec![0; 73], vec![0; 33]]);
        }
        tx.vsize() as u64
    }

    #[test]
    fn accepts_exactly_one_sat_per_estimated_signed_vbyte() {
        let fee = signed_vsize(&psbt_with_fee(100_000, 100_000));
        let psbt = psbt_with_fee(100_000, 100_000 - fee);
        assert_eq!(psbt.fee().unwrap().to_sat(), signed_vsize(&psbt));
        check_psbt_fee(&psbt, &[], "send-RGB").expect("1 sat/vB over the signed size passes");
    }

    #[test]
    fn rejects_fees_below_signed_size_minimum() {
        let psbt = psbt_with_fee(100_000, 100_000);
        let unsigned_vsize = psbt.unsigned_tx.vsize() as u64;
        let minimum = signed_vsize(&psbt);
        assert!(minimum > unsigned_vsize);
        for fee in [
            0,
            1, // One satoshi total, not per vbyte.
            minimum - 1,
            unsigned_vsize, // Does not pay for the witness.
        ] {
            let psbt = psbt_with_fee(100_000, 100_000 - fee);
            assert_eq!(psbt.fee().unwrap().to_sat(), fee);
            let err = check_psbt_fee(&psbt, &[], "send-RGB").unwrap_err();
            assert!(
                err.to_string().contains("fee rate too low"),
                "fee {fee} sat: {err}"
            );
        }
    }

    #[test]
    fn taproot_key_path_floor_counts_plain_and_rgb_inputs() {
        use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
        use bitcoin::sighash::TapSighashType;
        use bitcoin::taproot::TapNodeHash;

        let secp = Secp256k1::new();
        for requested in [
            None,
            Some(TapSighashType::Default),
            Some(TapSighashType::All),
        ] {
            let mut psbt = psbt_with_fee(100_000, 200_000);
            let mut second_input = psbt.unsigned_tx.input[0].clone();
            second_input.previous_output.vout = 1;
            psbt.unsigned_tx.input.push(second_input);
            psbt.inputs.push(Default::default());
            for (index, root) in [None, Some(TapNodeHash::from_byte_array([0x77; 32]))]
                .into_iter()
                .enumerate()
            {
                let secret = SecretKey::from_slice(&[index as u8 + 1; 32]).unwrap();
                let key = XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &secret)).0;
                let input = &mut psbt.inputs[index];
                input.witness_utxo = Some(TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: ScriptBuf::new_p2tr(&secp, key, root),
                });
                input.tap_internal_key = Some(key);
                input.tap_merkle_root = root;
                input.sighash_type = requested.map(Into::into);
            }

            let mut signed = psbt.unsigned_tx.clone();
            let signature_len = if requested == Some(TapSighashType::All) {
                65
            } else {
                64
            };
            for input in &mut signed.input {
                // A key-path witness has only the signature, not the Tapret tree.
                input.witness = Witness::from_slice(&[vec![0; signature_len]]);
            }
            let minimum = signed.vsize() as u64;
            assert!(minimum > psbt.unsigned_tx.vsize() as u64);
            psbt.unsigned_tx.output[0].value = Amount::from_sat(200_000 - minimum);
            assert_eq!(psbt.fee().unwrap().to_sat(), minimum);
            check_psbt_fee(&psbt, &[], "send-RGB").expect("key-path inputs funded at 1 sat/vB");
            psbt.unsigned_tx.output[0].value += Amount::from_sat(1);
            let err = check_psbt_fee(&psbt, &[], "send-RGB").unwrap_err();
            assert!(err.to_string().contains("fee rate too low"), "{err}");
        }
    }

    #[test]
    fn taproot_multisig_floor_counts_script_control_block_and_cosigners() {
        use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL};
        use bitcoin::script::Builder;
        use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
        use bitcoin::taproot::{LeafVersion, TaprootBuilder};

        let secp = Secp256k1::new();
        let keys: Vec<_> = (1..=3)
            .map(|byte| {
                let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
                XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &secret)).0
            })
            .collect();
        let script = Builder::new()
            .push_x_only_key(&keys[0])
            .push_opcode(OP_CHECKSIG)
            .push_x_only_key(&keys[1])
            .push_opcode(OP_CHECKSIGADD)
            .push_x_only_key(&keys[2])
            .push_opcode(OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(OP_NUMEQUAL)
            .into_script();
        let info = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .unwrap()
            .finalize(&secp, keys[0])
            .unwrap();
        let control = info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .unwrap();
        let mut psbt = psbt_with_fee(100_000, 100_000);
        psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey =
            ScriptBuf::new_p2tr_tweaked(info.output_key());
        psbt.inputs[0]
            .tap_scripts
            .insert(control.clone(), (script.clone(), LeafVersion::TapScript));

        let mut tx = psbt.unsigned_tx.clone();
        tx.input[0].witness = Witness::from_slice(&[
            vec![0; 65],
            vec![0; 65],
            vec![],
            script.into_bytes(),
            control.serialize(),
        ]);
        let minimum = tx.vsize() as u64;
        assert!(minimum > psbt.unsigned_tx.vsize() as u64);
        psbt.unsigned_tx.output[0].value = Amount::from_sat(100_000 - minimum);
        check_psbt_fee(&psbt, &[], "send-RGB").expect("funded 2-of-3 Taproot witness");
        psbt.unsigned_tx.output[0].value += Amount::from_sat(1);
        let err = check_psbt_fee(&psbt, &[], "send-RGB").unwrap_err();
        assert!(err.to_string().contains("fee rate too low"), "{err}");
    }

    #[test]
    fn rejects_unknown_spend_shape_instead_of_using_unsigned_size() {
        let mut psbt = psbt_with_fee(100_000, 99_000);
        psbt.inputs[0].witness_utxo.as_mut().unwrap().script_pubkey = ScriptBuf::new();
        let err = check_psbt_fee(&psbt, &[], "send-RGB").unwrap_err();
        assert!(
            err.to_string().contains("cannot estimate signed PSBT size"),
            "{err}"
        );
    }

    /// `psbt_with_fee` plus `extra` zero-value P2WPKH outputs. A large tx hits
    /// the absolute cap before the rate cap.
    fn wide_psbt_with_fee(input_sats: u64, output_sats: u64, extra: usize) -> Psbt {
        let mut psbt = psbt_with_fee(input_sats, output_sats);
        for _ in 0..extra {
            psbt.unsigned_tx.output.push(TxOut {
                value: Amount::ZERO,
                script_pubkey: psbt.unsigned_tx.output[0].script_pubkey.clone(),
            });
            psbt.outputs.push(Default::default());
        }
        psbt
    }

    #[test]
    fn accepts_fee_rate_at_pinned_cap() {
        // rate == MAX_FEE_RATE_SAT_VB over the unsigned size passes. Only a
        // higher rate fails.
        let vsize = psbt_with_fee(100_000, 100_000).unsigned_tx.vsize() as u64;
        let fee_at_cap = MAX_FEE_RATE_SAT_VB * vsize;
        assert!(
            fee_at_cap <= MAX_FEE_SATS,
            "fixture must exercise the rate cap"
        );
        let psbt = psbt_with_fee(100_000, 100_000 - fee_at_cap);
        check_psbt_fee(&psbt, &[], "send-RGB").expect("rate exactly at the pinned cap");
    }

    #[test]
    fn rejects_fee_rate_above_pinned_cap() {
        // One sat over the cap. Nothing else is wrong, so the error must be
        // the fee-rate one.
        let vsize = psbt_with_fee(100_000, 100_000).unsigned_tx.vsize() as u64;
        let fee_over_cap = MAX_FEE_RATE_SAT_VB * vsize + 1;
        let psbt = psbt_with_fee(100_000, 100_000 - fee_over_cap);
        let err = check_psbt_fee(&psbt, &[], "send-RGB").unwrap_err();
        assert!(
            err.to_string().contains("fee rate too high"),
            "expected fee-rate rejection, got: {err}"
        );
    }

    #[test]
    fn absolute_cap_binds_whatever_the_size() {
        // Wide enough that MAX_FEE_SATS is under the rate cap, so the
        // absolute cap decides.
        let extra = 20;
        let vsize = wide_psbt_with_fee(1_000_000, 1_000_000, extra)
            .unsigned_tx
            .vsize() as u64;
        assert!(
            MAX_FEE_RATE_SAT_VB * vsize > MAX_FEE_SATS,
            "fixture must let the absolute cap bind first"
        );

        let at_cap = wide_psbt_with_fee(1_000_000, 1_000_000 - MAX_FEE_SATS, extra);
        check_psbt_fee(&at_cap, &[], "send-RGB").expect("fee exactly at the absolute cap");

        let over_cap = wide_psbt_with_fee(1_000_000, 1_000_000 - MAX_FEE_SATS - 1, extra);
        let err = check_psbt_fee(&over_cap, &[], "send-RGB").unwrap_err();
        assert!(err.to_string().contains("fee too high"), "{err}");
    }

    #[test]
    fn rejects_a_fee_that_burns_most_of_the_input() {
        // #248: 60_676 sat in, 1_000 sat back to custody, approx 98% to
        // miners. Under the absolute cap, far over the rate cap.
        let psbt = psbt_with_fee(60_676, 1_000);
        let err = check_psbt_fee(&psbt, &[], "plain-BTC").unwrap_err();
        assert!(
            err.to_string().contains("plain-BTC PSBT fee rate too high"),
            "{err}"
        );
    }

    #[test]
    fn inflated_witness_cannot_weaken_the_upper_fee_limit() {
        // The rate cap uses the unsigned size, so a padded host witness does
        // not lower the rate.
        let vsize = psbt_with_fee(100_000, 100_000).unsigned_tx.vsize() as u64;
        let mut psbt = psbt_with_fee(100_000, 100_000 - (MAX_FEE_RATE_SAT_VB * vsize + 1));
        psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[vec![0; 1_000]]));
        let err = check_psbt_fee(&psbt, &[], "send-RGB").unwrap_err();
        assert!(err.to_string().contains("fee rate too high"), "{err}");
    }

    #[test]
    fn rejects_psbt_without_utxo_data() {
        // No witness_utxo/non_witness_utxo: no fee value, so fail closed.
        let psbt = Psbt::deserialize(&minimal_valid_psbt_bytes()).unwrap();
        let err = check_psbt_fee(&psbt, &[], "send-RGB").unwrap_err();
        assert!(
            err.to_string().contains("cannot compute PSBT fee"),
            "expected uncomputable-fee rejection, got: {err}"
        );
    }
}
