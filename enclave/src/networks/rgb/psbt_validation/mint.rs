//! The mint rules (`Sign`, EVM -> RGB) on the committed transition: what the
//! VM's `sas` and `pma` and the former consignment binds enforced, read from
//! the fascia, and the sats rule of its PSBT. The rule ids (M1-M8) are those of
//! `docs/mint-flow.md` section 5.

use std::collections::HashSet;

use amplify::{ByteArray, Wrapper};
use bitcoin::psbt::Psbt;
use rgbstd::{BuilderSeal, Opout, Transition};

use super::super::btc_ownership;
use super::super::flow;
use super::super::psbt_commit::{single_right_input, witness_vout, Committed};
use super::super::validation::{output_seal, single_global};
use super::assert_keeps_all_sats;
use crate::error::{EnclaveError, Result};
use crate::keys::KeyManager;

/// Inputs a mint spends: its right alone, whose UTXO's sats pay the fee.
pub const MINT_INPUTS: usize = 1;

/// What a mint commits to: the right it consumes and the deposit it needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintFacts {
    pub right: Opout,
    pub opid: [u8; 32],
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

impl MintRecipient {
    /// The seals S6.2 compares with a legacy deposit's invoice. A witness mint
    /// has none, so a legacy blinded invoice refuses it.
    pub fn blinded_seals(&self) -> Vec<String> {
        match self {
            Self::Blinded(seal) => vec![seal.clone()],
            Self::Witness { .. } => Vec::new(),
        }
    }
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
    let right = single_right_input(transition, "a mint")?;
    assert_asset_assignments_only(transition)?;
    let (issued, before_block) = mint_globals(transition)?;
    let (units, recipient) = one_asset_leg(transition)?;
    if units != issued {
        return Err(EnclaveError::CrossCheck(format!(
            "mint pays {units} units but declares issuedSupply {issued}"
        )));
    }
    Ok(MintFacts {
        right,
        opid: committed.opid.to_byte_array(),
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
fn assert_mint_type(transition: &Transition) -> Result<()> {
    let ty = transition.transition_type;
    if !flow::is_signing_transition(ty.to_inner()) {
        return Err(EnclaveError::CrossCheck(format!(
            "mint-RGB PSBT commits transition type {ty}, not a mint ({})",
            schemata::TS_MINT
        )));
    }
    Ok(())
}

/// M3: no `mintRight` passed on and no link. A right passed on could go to a
/// seal the host holds, and would put this mint in a later mint's history.
fn assert_asset_assignments_only(transition: &Transition) -> Result<()> {
    if let Some(rights) = transition.assignments.get(&schemata::OS_MINT) {
        return Err(EnclaveError::CrossCheck(format!(
            "mint passes {} mintRight output(s) on - the mint signer signs only a mint that \
             consumes its right",
            rights.len_u16()
        )));
    }
    let types: Vec<_> = transition.assignments.keys().collect();
    if types != [&schemata::OS_ASSET] {
        return Err(EnclaveError::CrossCheck(format!(
            "mint assigns types {types:?} - a mint assigns asset units only"
        )));
    }
    Ok(())
}

/// M4: exactly `issuedSupply` (> 0) and `beforeBlock`, each 8 LE bytes, the
/// bytes the VM's `sas` and `pma` read. Nothing else rides along.
fn mint_globals(transition: &Transition) -> Result<(u64, u64)> {
    let globals: Vec<_> = transition.globals.keys().collect();
    let metadata: Vec<_> = transition.metadata.keys().collect();
    if globals != [&schemata::GS_ISSUED_SUPPLY] || metadata != [&schemata::MS_BEFORE_BLOCK] {
        return Err(EnclaveError::CrossCheck(format!(
            "mint carries globals {globals:?} and metadata {metadata:?} - a mint carries \
             issuedSupply and beforeBlock only"
        )));
    }
    let issued = single_global::<8>(
        &transition.globals,
        schemata::GS_ISSUED_SUPPLY,
        "issuedSupply",
    )?
    .map(u64::from_le_bytes)
    .unwrap_or_default();
    if issued == 0 {
        return Err(EnclaveError::CrossCheck(
            "mint issuedSupply is 0 - no deposit backs an empty mint".into(),
        ));
    }
    Ok((issued, before_block(transition)?))
}

fn before_block(transition: &Transition) -> Result<u64> {
    let value = transition
        .metadata
        .get(&schemata::MS_BEFORE_BLOCK)
        .map(|value| value.as_slice())
        .unwrap_or_default();
    let bytes: [u8; 8] = value.try_into().map_err(|_| {
        EnclaveError::CrossCheck(format!(
            "mint beforeBlock is {} bytes, expected 8",
            value.len()
        ))
    })?;
    Ok(u64::from_le_bytes(bytes))
}

/// M7: one asset leg, on the depositor's blinded seal or on a witness seal of
/// this tx. Returns its units and recipient. rgb-lib mints to one recipient.
fn one_asset_leg(transition: &Transition) -> Result<(u64, MintRecipient)> {
    let legs = transition
        .assignments
        .get(&schemata::OS_ASSET)
        .map(|typed| typed.as_fungible())
        .unwrap_or_default();
    let [leg] = legs else {
        return Err(EnclaveError::CrossCheck(format!(
            "mint pays {} asset legs - exactly one, to the depositor's seal",
            legs.len()
        )));
    };
    let recipient = match &leg.seal {
        BuilderSeal::Concealed(seal) => MintRecipient::Blinded(seal.to_string()),
        // The OpId commits this vout, not its script: M8 checks the output.
        BuilderSeal::Revealed(_) => MintRecipient::Witness {
            vout: witness_vout(&output_seal(&leg.seal), "the mint's asset leg")?,
        },
    };
    Ok((leg.state.as_u64(), recipient))
}

#[cfg(test)]
mod tests;
