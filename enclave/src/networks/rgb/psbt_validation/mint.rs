//! The mint rules (`Sign`, EVM -> RGB): the rules on the committed transition,
//! read from rgb-lib's inspection of the fascia (what the VM's `sas` and `plc`
//! enforce, and the shape of the mint), and the sats rule of its PSBT. The
//! rule ids (M1-M8) are those of `docs/mint-flow.md` section 5.

use std::collections::HashSet;

use amplify::ByteArray;
use bitcoin::psbt::Psbt;
use rgb_lib::no_wallet::{RgbOutputInfo, RgbTransitionInfo, TransitionGlobal, TransitionMetadata};
use rgb_lib::Assignment;

use super::super::btc_ownership;
use super::super::flow;
use super::super::psbt_commit::{assert_single_right_input, witness_vout, Committed};
use super::super::validation::lock_id;
use super::assert_keeps_all_sats;
use crate::error::{EnclaveError, Result};
use crate::keys::KeyManager;

/// Inputs a mint spends (F7).
pub const MINT_INPUTS: usize = 1;

// The limits of the image, for the tests. `Limits` holds them and says why.
#[cfg(test)]
pub const MINT_MAX_INPUTS: usize = crate::limits::Limits::DEFAULTS.mint_max_inputs as usize;
#[cfg(test)]
pub const MINT_MAX_OUTPUTS: usize = crate::limits::Limits::DEFAULTS.mint_max_outputs as usize;

/// M0: the mint tx has a bounded number of inputs and outputs. Cheap, so it
/// runs before any fascia is decoded.
pub fn assert_mint_shape(psbt: &Psbt) -> Result<()> {
    let tx = &psbt.unsigned_tx;
    let limits = crate::limits::get();
    if tx.input.len() as u64 > limits.mint_max_inputs {
        return Err(EnclaveError::CrossCheck(format!(
            "mint PSBT has {} inputs, at most {}",
            tx.input.len(),
            limits.mint_max_inputs
        )));
    }
    if tx.output.len() as u64 > limits.mint_max_outputs {
        return Err(EnclaveError::CrossCheck(format!(
            "mint PSBT has {} outputs, at most {}",
            tx.output.len(),
            limits.mint_max_outputs
        )));
    }
    Ok(())
}

/// What a mint commits to: the deposit it needs and its recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintFacts {
    pub opid: [u8; 32],
    /// `LockId(opid, txid)` of the PSBT's tx: the id its `FundsIn` lock must name.
    /// F2 fixes that txid, so any other tx of this mint names another lock.
    pub lock_id: [u8; 32],
    /// `issuedSupply`, equal to the units of its one asset leg.
    pub issued: u64,
    /// `beforeBlock`: its EVM lock must be in an earlier block.
    pub before_block: u64,
    /// The seal of its one asset leg.
    pub recipient: MintRecipient,
}

/// Where a mint puts its units (M7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintRecipient {
    /// The `utxob:` seal of a blinded invoice.
    Blinded(String),
    /// A witness invoice: an output of the mint tx itself.
    Witness { vout: u32 },
}

/// M6: binds the mint to the request's verified EVM deposit, or refuses.
pub type MintBinder<'a> = &'a dyn Fn(&MintFacts) -> Result<()>;

/// M8 with the enclave keys and the pinned witness amount, or refuses.
pub type MintSatsCheck<'a> = &'a dyn Fn(&Psbt, &MintRecipient) -> Result<()>;

/// M1-M5 and M7: a `mint` that consumes one right and issues exactly its
/// `issuedSupply` to one recipient seal, nothing else.
pub fn mint_facts(committed: &Committed) -> Result<MintFacts> {
    let transition = &committed.transition;
    assert_mint_type(transition)?;
    assert_single_right_input(&transition.inputs, "a mint")?;
    assert_asset_assignments_only(transition)?;
    let (issued, before_block) = mint_globals(transition)?;
    let (units, recipient) = one_asset_leg(transition, committed.txid)?;
    if units != issued {
        return Err(EnclaveError::CrossCheck(format!(
            "mint pays {units} units but declares issuedSupply {issued}"
        )));
    }
    Ok(MintFacts {
        opid: committed.opid.to_byte_array(),
        lock_id: lock_id(committed.opid, committed.txid),
        issued,
        before_block,
        recipient,
    })
}

/// M5: the minted units are the net deposit, no more and no less.
pub fn assert_mints_net_deposit(mint: &MintFacts, amount: u64, commission: u64) -> Result<()> {
    flow::assert_group_amount(mint.issued, amount, commission)
}

/// M8: a blinded mint keeps every sat. A witness mint pays exactly
/// `witness_sat` to its seal's output and keeps every other sat.
pub fn assert_mint_sats(
    psbt: &Psbt,
    keys: &KeyManager,
    recipient: &MintRecipient,
    witness_sat: u64,
) -> Result<()> {
    let MintRecipient::Witness { vout } = recipient else {
        return assert_keeps_all_sats(psbt, keys, "mint");
    };
    assert_witness_output(psbt, keys, *vout, witness_sat)?;
    // No rule A exemption, as for a blinded mint: the witness output counts in
    // full, so every other output must be ours by rule C or carry 0 sat.
    match btc_ownership::unowned_output_sats(psbt, &HashSet::new(), keys) {
        Some(sats) if sats == witness_sat => Ok(()),
        Some(sats) => Err(EnclaveError::CrossCheck(format!(
            "mint PSBT pays {sats} sat to outputs this enclave does not derive - a witness mint \
             pays {witness_sat} sat to its recipient's output and keeps every other sat"
        ))),
        None => Err(EnclaveError::CrossCheck(
            "mint PSBT output total overflows u64".into(),
        )),
    }
}

/// M8 on a witness mint's seal: an output of the tx, not the OP_RETURN, not
/// ours by rule A or C, and worth exactly `witness_sat`.
fn assert_witness_output(
    psbt: &Psbt,
    keys: &KeyManager,
    vout: u32,
    witness_sat: u64,
) -> Result<()> {
    let outputs = &psbt.unsigned_tx.output;
    let Some(txout) = outputs.get(vout as usize) else {
        return Err(EnclaveError::CrossCheck(format!(
            "mint pays its units to vout {vout}, but its tx has {} outputs",
            outputs.len()
        )));
    };
    if txout.script_pubkey.is_op_return() {
        return Err(EnclaveError::CrossCheck(format!(
            "mint pays its units to vout {vout}, the OP_RETURN - a witness recipient is a \
             spendable output"
        )));
    }
    let index = vout as usize;
    let our_inputs = btc_ownership::self_controlled_input_scripts_scoped(psbt, keys, None);
    if btc_ownership::output_is_self_derived(psbt, index, keys, None)
        || btc_ownership::output_is_self_owned(psbt, index, &our_inputs)
    {
        return Err(EnclaveError::CrossCheck(format!(
            "mint pays its units to vout {vout}, an output of this enclave - a witness mint \
             pays the depositor's output"
        )));
    }
    let sats = txout.value.to_sat();
    if sats != witness_sat {
        return Err(EnclaveError::CrossCheck(format!(
            "mint pays {sats} sat to its recipient's vout {vout} - a witness mint pays exactly \
             MINT_WITNESS_SAT ({witness_sat} sat)"
        )));
    }
    Ok(())
}

/// M1.
fn assert_mint_type(transition: &RgbTransitionInfo) -> Result<()> {
    if !flow::is_signing_transition(transition.r#type) {
        return Err(EnclaveError::CrossCheck(format!(
            "mint-RGB PSBT commits a {:?} transition, not a mint",
            transition.r#type
        )));
    }
    Ok(())
}

/// M3: asset units only, so no `mintRight` passed on and no link. A right
/// passed on could go to a seal the host holds, and would put this mint in a
/// later mint's history.
fn assert_asset_assignments_only(transition: &RgbTransitionInfo) -> Result<()> {
    let others: Vec<_> = transition
        .outputs
        .iter()
        .map(|o| &o.assignment)
        .filter(|a| !matches!(a, Assignment::Fungible(_)))
        .collect();
    if !others.is_empty() {
        return Err(EnclaveError::CrossCheck(format!(
            "mint assigns {others:?} - a mint assigns asset units only, and the mint signer \
             signs only a mint that consumes its right"
        )));
    }
    Ok(())
}

/// M4: exactly `issuedSupply` (> 0) and `beforeBlock`, the values the VM's
/// `sas` and `plc` read. Nothing else rides along. rgb-lib decoded each, so a
/// malformed value never reaches here.
fn mint_globals(transition: &RgbTransitionInfo) -> Result<(u64, u64)> {
    let (&[TransitionGlobal::IssuedSupply(issued)], &[TransitionMetadata::BeforeBlock(before)]) = (
        transition.globals.as_slice(),
        transition.metadata.as_slice(),
    ) else {
        return Err(EnclaveError::CrossCheck(format!(
            "mint carries globals {:?} and metadata {:?} - a mint carries issuedSupply and \
             beforeBlock only",
            transition.globals, transition.metadata
        )));
    };
    if issued == 0 {
        return Err(EnclaveError::CrossCheck(
            "mint issuedSupply is 0 - no deposit backs an empty mint".into(),
        ));
    }
    Ok((issued, before))
}

/// M7: one asset leg, on the depositor's blinded seal or on a witness seal of
/// this tx. Returns its units and recipient. rgb-lib mints to one recipient.
fn one_asset_leg(
    transition: &RgbTransitionInfo,
    txid: bitcoin::Txid,
) -> Result<(u64, MintRecipient)> {
    let [leg] = transition.outputs.as_slice() else {
        return Err(EnclaveError::CrossCheck(format!(
            "mint pays {} asset legs - exactly one, to the depositor's seal",
            transition.outputs.len()
        )));
    };
    let Assignment::Fungible(units) = &leg.assignment else {
        return Err(EnclaveError::CrossCheck(format!(
            "mint pays {:?} - a mint pays asset units",
            leg.assignment
        )));
    };
    Ok((*units, mint_recipient(leg, txid)?))
}

/// M7: where the one leg pays. A blinded seal is the depositor's invoice; a
/// revealed one must be an output of the mint tx itself. The OpId commits that
/// vout, not its script: M8 checks the output.
fn mint_recipient(leg: &RgbOutputInfo, txid: bitcoin::Txid) -> Result<MintRecipient> {
    if leg.is_concealed {
        let seal = leg.recipient_id.clone().ok_or_else(|| {
            EnclaveError::CrossCheck(
                "mint pays a blinded seal that names no recipient id - refusing to sign a leg \
                 the enclave cannot read"
                    .into(),
            )
        })?;
        return Ok(MintRecipient::Blinded(seal));
    }
    Ok(MintRecipient::Witness {
        vout: witness_vout(leg, txid, "the mint's asset leg")?,
    })
}

#[cfg(test)]
mod tests;
