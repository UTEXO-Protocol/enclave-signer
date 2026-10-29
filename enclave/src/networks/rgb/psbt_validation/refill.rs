//! The PSBT rules of a rights refill (`SignRightsRefill`): one `mintRight` in,
//! 2..=255 rights out to the enclave's own Colored outputs, no units moved.
//! The rules read the committed transition from the PSBT, with no
//! consignment. The rule ids (G1, RR*) are those of `docs/mint-flow.md`
//! section 8.

use std::collections::BTreeSet;

use bitcoin::psbt::Psbt;
use rgbstd::{Opout, Transition, TypedAssigns};

use super::super::btc_ownership;
use super::super::psbt_commit::{single_right_input, witness_vout, Committed};
use super::super::signing::taproot::find_controlled_taproot_inputs;
use super::super::validation::{output_seal, OutputSeal};
use super::{assert_keeps_all_sats, assert_only_colored_inputs, fee_key_path_inputs_of};
use crate::error::{EnclaveError, Result};
use crate::keys::{AccountType, KeyManager};

/// Most fee inputs a refill may spend beside its right. Each one can destroy
/// the state it carries, so with [`MIN_REFILL_RIGHTS`] the count cannot drop.
pub const MAX_REFILL_FEE_INPUTS: usize = 1;

/// Fewest rights a refill makes: one right closed plus one destroyed on a
/// hostile fee input.
pub const MIN_REFILL_RIGHTS: usize = 2;

/// Our own cap: rgb-lib has no limit since ae85958. RR9, RR12 and RR13 carry
/// the security.
pub const MAX_REFILL_RIGHTS: usize = 255;

/// The gate (G1, RR10, RR12, RR13): PSBT and keys only, so it runs before the
/// rate limit and the RGB checks.
pub fn refill_gate(psbt: &Psbt, keys: &KeyManager) -> Result<()> {
    assert_refill_input_count(psbt)?;
    let colored = refill_colored_inputs(psbt, keys)?;
    assert_keeps_all_sats(psbt, keys, "rights-refill")?;
    super::check_psbt_fee(psbt, &colored, "rights-refill")
}

/// G1: the right's seal and at most [`MAX_REFILL_FEE_INPUTS`] fee inputs.
fn assert_refill_input_count(psbt: &Psbt) -> Result<()> {
    let inputs = psbt.unsigned_tx.input.len();
    if inputs > 1 + MAX_REFILL_FEE_INPUTS {
        return Err(EnclaveError::CrossCheck(format!(
            "rights-refill PSBT spends {inputs} inputs - a refill spends its right and at most \
             {MAX_REFILL_FEE_INPUTS} fee input"
        )));
    }
    Ok(())
}

/// RR10: every input is a Colored key-path input of this enclave, so RR12 and
/// RR13 see all the value. Returns those inputs.
fn refill_colored_inputs(psbt: &Psbt, keys: &KeyManager) -> Result<Vec<usize>> {
    let jobs = find_controlled_taproot_inputs(psbt, keys.master_fingerprint(), keys);
    let colored = fee_key_path_inputs_of(&jobs, AccountType::Colored);
    assert_only_colored_inputs(psbt, &colored, "rights-refill")?;
    Ok(colored)
}

/// RR6-RR8: one propagate that closes one right and makes rights only, on its
/// own tx. Returns the closed right (for RR11) and the new rights' vouts (RR9).
pub fn refill_rights(committed: &Committed) -> Result<(Opout, Vec<u32>)> {
    let transition = &committed.transition;
    assert_propagate(transition)?;
    let right = single_right_input(transition, "a rights refill")?;
    assert_rights_only(transition)?;
    let seals: Vec<OutputSeal> = transition
        .assignments
        .get(&schemata::OS_MINT)
        .map(|typed| typed.seals().map(output_seal).collect())
        .unwrap_or_default();
    Ok((right, assert_refill_rights(&seals)?))
}

/// RR6: rights move only by propagate; a transfer, a burn or a mint is not a refill.
fn assert_propagate(transition: &Transition) -> Result<()> {
    if transition.transition_type != schemata::TS_PROPAGATE {
        return Err(EnclaveError::CrossCheck(format!(
            "rights refill requires a propagate transition (transition_type = {}, want {})",
            transition.transition_type,
            schemata::TS_PROPAGATE
        )));
    }
    Ok(())
}

/// RR7: rights out, no units, no link, no globals or metadata.
fn assert_rights_only(transition: &Transition) -> Result<()> {
    let types: Vec<_> = transition.assignments.keys().collect();
    let empty = transition.globals.is_empty() && transition.metadata.is_empty();
    if types != [&schemata::OS_MINT] || !empty {
        return Err(EnclaveError::CrossCheck(format!(
            "rights refill assigns types {types:?} with {} global(s) and {} metadata - a refill \
             moves rights only",
            transition.globals.len(),
            transition.metadata.len()
        )));
    }
    // Consensus refuses a right with state, so the spent right would be lost.
    let Some(TypedAssigns::Declarative(_)) = transition.assignments.get(&schemata::OS_MINT) else {
        return Err(EnclaveError::CrossCheck(
            "rights refill makes mintRights that carry state - a right carries none".into(),
        ));
    };
    Ok(())
}

/// RR8: [`MIN_REFILL_RIGHTS`]..=[`MAX_REFILL_RIGHTS`] rights, each revealed on
/// its own output of the signed tx. Returns their vouts.
pub fn assert_refill_rights(rights: &[OutputSeal]) -> Result<Vec<u32>> {
    if !(MIN_REFILL_RIGHTS..=MAX_REFILL_RIGHTS).contains(&rights.len()) {
        return Err(EnclaveError::CrossCheck(format!(
            "rights refill makes {} right(s) - a refill makes {MIN_REFILL_RIGHTS} to \
             {MAX_REFILL_RIGHTS}",
            rights.len()
        )));
    }
    let mut vouts = BTreeSet::new();
    for seal in rights {
        let vout = witness_vout(seal, "a refill right")?;
        // One right per UTXO, so a later mint closes all a UTXO holds.
        if !vouts.insert(vout) {
            return Err(EnclaveError::CrossCheck(format!(
                "rights refill puts two rights on vout {vout} - one right per output"
            )));
        }
    }
    Ok(vouts.into_iter().collect())
}

/// RR9: each new right is on a rule C output of the Colored account. Rule C
/// accepts only child path `[0, i]`, the keychain rgb-lib scans. Else the host
/// could take the right, or park it where the wallet cannot find it.
pub fn assert_refill_rights_owned(psbt: &Psbt, vouts: &[u32], keys: &KeyManager) -> Result<()> {
    for &vout in vouts {
        let index = vout as usize;
        if !btc_ownership::output_is_self_derived(psbt, index, keys, Some(AccountType::Colored)) {
            return Err(EnclaveError::CrossCheck(format!(
                "rights refill puts a right on vout {vout}, which is not a Colored key-path \
                 output of this enclave at child path [0, i] - refusing to give a right away"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
