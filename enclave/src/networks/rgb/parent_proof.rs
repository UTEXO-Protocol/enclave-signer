//! The parent proof (PP1-PP7): the rgb-lib fascia of the tx that made the right
//! a mint or a refill spends. It pins that right's UTXO, so every signature for
//! one transition spends the same outpoint and a replay conflicts with the
//! first. The rule ids are those of `docs/mint-flow.md` section 5, Stage 5.

use bitcoin::psbt::Psbt;
use bitcoin::OutPoint;
use rgbstd::txout::TxoSeal;
use rgbstd::{BuilderSeal, ContractId, GraphSeal, Opout};

use super::psbt_commit::{
    committed_transition, parse_fascia, single_right_input, witness_vout, Committed,
};
use super::validation::output_seal;
use crate::error::{EnclaveError, Result};

/// PP1-PP7: the index of the one input of `psbt` that spends the UTXO of the
/// right `input` names, as `parent_fascia` proves that UTXO.
pub fn right_input(
    psbt: &Psbt,
    parent_fascia: &[u8],
    input: Opout,
    pin: ContractId,
) -> Result<usize> {
    // PP1, then PP2: the fascia carries the parent's unsigned tx, which the core binds.
    let parent = parse_fascia(parent_fascia, "parent_fascia")?;
    let made = committed_transition(&parent.seal_witness().tx, &parent, pin)?;
    let vout = right_vout(&made, input)?;
    spending_input(psbt, OutPoint::new(made.txid, vout))
}

/// PP3-PP6: the parent is a propagate that made `input` alone on an output of
/// its own tx. Returns that vout.
fn right_vout(made: &Committed, input: Opout) -> Result<u32> {
    if input.op != made.opid || input.ty != schemata::OS_MINT {
        return Err(EnclaveError::CrossCheck(format!(
            "parent_fascia commits transition {}, which did not make the mintRight {input} the \
             request spends",
            made.opid
        )));
    }
    // A propagate parent keeps every mint out of a mint's history (mint-flow 11).
    if made.transition.transition_type != schemata::TS_PROPAGATE {
        return Err(EnclaveError::CrossCheck(format!(
            "the spent right was made by transition type {}, not a propagate - a mint or genesis \
             parent is refused",
            made.transition.transition_type
        )));
    }
    single_right_input(&made.transition, "the parent propagate")?;
    let seal = made
        .transition
        .assignments
        .get(&input.ty)
        .and_then(|typed| typed.seal_at(input.no))
        .ok_or_else(|| {
            EnclaveError::CrossCheck(format!("parent transition has no mintRight {}", input.no))
        })?;
    let vout = witness_vout(&output_seal(seal), "the spent right")?;
    assert_alone_on(made, input, OutPoint::new(made.txid, vout))?;
    Ok(vout)
}

/// PP6: no other revealed assignment of the parent sits on the right's UTXO.
/// Spending it would destroy that state too.
fn assert_alone_on(made: &Committed, input: Opout, right: OutPoint) -> Result<()> {
    for (ty, typed) in made.transition.assignments.iter() {
        for (no, seal) in typed.seals().enumerate() {
            let other = (*ty, no) != (input.ty, usize::from(input.no));
            if other && seal_outpoint(seal, made.txid) == Some(right) {
                return Err(EnclaveError::CrossCheck(format!(
                    "the parent puts assignment {ty}/{no} on the spent right's UTXO {right} too - \
                     refusing to destroy it"
                )));
            }
        }
    }
    Ok(())
}

/// The outpoint of a revealed seal; a witness seal is on `witness`.
fn seal_outpoint(seal: &BuilderSeal<GraphSeal>, witness: bitcoin::Txid) -> Option<OutPoint> {
    match seal {
        BuilderSeal::Revealed(seal) => Some(OutPoint::new(
            seal.txid().unwrap_or(witness),
            seal.vout().into_u32(),
        )),
        BuilderSeal::Concealed(_) => None,
    }
}

/// PP7: exactly one input spends the right's UTXO. Else the transition is
/// invalid and the tx destroys what its inputs hold.
fn spending_input(psbt: &Psbt, right: OutPoint) -> Result<usize> {
    let spending: Vec<usize> = (0..psbt.unsigned_tx.input.len())
        .filter(|&i| psbt.unsigned_tx.input[i].previous_output == right)
        .collect();
    match spending.as_slice() {
        [i] => Ok(*i),
        _ => Err(EnclaveError::CrossCheck(format!(
            "the PSBT does not spend {right}, the UTXO of the right its transition closes - \
             refusing to sign a tx that would destroy the state on its inputs"
        ))),
    }
}

#[cfg(test)]
mod tests;
