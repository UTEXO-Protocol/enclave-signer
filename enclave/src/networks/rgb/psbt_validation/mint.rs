//! The mint rules (`Sign`, EVM -> RGB) on the committed transition: what the
//! VM's `sas` and `pma` and the former consignment binds enforced, read from
//! the PSBT. The rule ids (M1-M8) are those of `docs/mint-flow.md` section 5.

use amplify::{ByteArray, Wrapper};
use rgbstd::{BuilderSeal, Opout, Transition};

use super::super::flow;
use super::super::psbt_commit::{single_right_input, Committed};
use super::super::validation::single_global;
use crate::error::{EnclaveError, Result};

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
    /// The `utxob:` seal of its one asset leg.
    pub recipient_seal: String,
}

/// M6: binds the mint to the request's verified EVM deposit, or refuses.
pub type MintBinder<'a> = &'a dyn Fn(&MintFacts) -> Result<()>;

/// M1-M5 and M7: a `mint` that consumes one right and issues exactly its
/// `issuedSupply` to one blinded seal, nothing else.
pub fn mint_facts(committed: &Committed) -> Result<MintFacts> {
    let transition = &committed.transition;
    assert_mint_type(transition)?;
    let right = single_right_input(transition, "a mint")?;
    assert_asset_assignments_only(transition)?;
    let (issued, before_block) = mint_globals(transition)?;
    let (units, recipient_seal) = one_blinded_leg(transition)?;
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
        recipient_seal,
    })
}

/// M5: the minted units are the net deposit, no more and no less.
pub fn assert_mints_net_deposit(mint: &MintFacts, amount: u64, commission: u64) -> Result<()> {
    flow::assert_group_amount(mint.issued, amount, commission)
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

/// M7: one asset leg on a blinded seal, the depositor's. Returns its units
/// and seal. rgb-lib mints to one recipient.
fn one_blinded_leg(transition: &Transition) -> Result<(u64, String)> {
    let legs = transition
        .assignments
        .get(&schemata::OS_ASSET)
        .map(|typed| typed.as_fungible())
        .unwrap_or_default();
    let [leg] = legs else {
        return Err(EnclaveError::CrossCheck(format!(
            "mint pays {} asset legs - exactly one, to the depositor's blinded seal",
            legs.len()
        )));
    };
    let BuilderSeal::Concealed(seal) = &leg.seal else {
        return Err(EnclaveError::CrossCheck(
            "mint pays its units to a revealed seal - the deposit authorizes a blinded seal \
             only"
                .into(),
        ));
    };
    Ok((leg.state.as_u64(), seal.to_string()))
}

#[cfg(test)]
mod tests;
