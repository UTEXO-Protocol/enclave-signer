//! Mint/burn flow rules. The bridge owns the mint right of the contract. A
//! deposit mints with a BFA `mint`. A withdrawal destroys units with a BFA
//! `burn`.
//!
//! See [`super`] for the reason for a separate file and the shared item names.

use crate::error::{EnclaveError, Result};
use crate::networks::rgb::validation::{is_mint_transition, TransitionSummary};

/// Flow name for rejection messages. It lets an operator tell "wrong shape"
/// from "wrong enclave".
pub const FLOW_NAME: &str = "mint/burn";

/// Returns true if a deposit PSBT can finalize this transition type.
///
/// The signing shape of this flow is the mint shape. Thus it calls
/// [`is_mint_transition`], so that no second list can drift from it.
pub fn is_signing_transition(transition_type: u16) -> bool {
    is_mint_transition(transition_type)
}

/// Checks the last transition of the consignment before the PSBT bind.
#[cfg(evm_to_rgb)]
pub fn assert_signing_transition(last: &TransitionSummary) -> Result<()> {
    if !is_signing_transition(last.transition_type) {
        return Err(EnclaveError::CrossCheck(format!(
            "mint-RGB PSBT requires a mint transition (last transition_type = {}, want {}) - \
             this enclave is built for the {FLOW_NAME} flow",
            last.transition_type,
            schemata::TS_MINT
        )));
    }
    Ok(())
}

/// The signed tx must commit exactly one transition: the mint.
///
/// A sibling of another type would move value under a rule the enclave did
/// not apply to it. A second mint would let one mint's units absorb another's
/// shortfall in the group amount bind: an unbacked over-mint.
#[cfg(evm_to_rgb)]
pub fn assert_committed_group(committed: &[&TransitionSummary]) -> Result<()> {
    let [mint] = committed else {
        return Err(EnclaveError::CrossCheck(format!(
            "mint-RGB PSBT commits {} transitions - the {FLOW_NAME} flow signs exactly one mint",
            committed.len()
        )));
    };
    assert_signing_transition(mint)
}

/// Total amount bind over the committed group.
///
/// This is exact equality, not the send/receive lower bound. A mint has no
/// prior allocation to return as change, so the credit must cover every
/// minted unit. A surplus is an over-mint: supply with no deposit.
#[cfg(evm_to_rgb)]
pub fn assert_group_amount(
    committed_asset_output: u64,
    source_amount: u64,
    source_commission: u64,
) -> Result<()> {
    let net_credited = source_amount.saturating_sub(source_commission);
    if committed_asset_output != net_credited {
        return Err(EnclaveError::CrossCheck(format!(
            "mint-RGB amount mismatch: consignment asset_output_amount \
             ({committed_asset_output}) != net credited (source_amount {source_amount} - \
             source_commission {source_commission} = {net_credited})"
        )));
    }
    Ok(())
}

/// Returns the asset amount that a withdrawal (`fundsOut`) consignment
/// destroys, after a check of the transition type.
///
/// The amount is the burn's `burnedAsset` global, never its outputs: a burn
/// may return change. A burn without the global destroys no asset units, so
/// it cannot back a release.
#[cfg(rgb_to_evm)]
pub fn funds_out_source_amount(last: &TransitionSummary) -> Result<u64> {
    if rgbstd::TransitionType::with(last.transition_type) != schemata::TS_BURN {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut requires a burn transition (last transition_type = {}, want {}) - \
             this enclave is built for the {FLOW_NAME} flow",
            last.transition_type,
            schemata::TS_BURN
        )));
    }
    last.burned_asset_amount.ok_or_else(|| {
        EnclaveError::CrossCheck(
            "burn transition carries no burnedAsset global - it destroys no asset units".into(),
        )
    })
}

/// Binds the EVM release amount to the amount that the consignment proves.
///
/// This is exact equality. `fundsOut.amount` is gross: the contract takes the
/// commission on-chain. A release below the burn strands units. A release
/// above it is unbacked.
#[cfg(rgb_to_evm)]
pub fn assert_funds_out_amount(source_amount: u64, calldata_amount: u64) -> Result<()> {
    if source_amount != calldata_amount {
        return Err(EnclaveError::CrossCheck(format!(
            "fundsOut amount mismatch: consignment proves {source_amount} asset units were \
             burned, calldata amount is {calldata_amount} - the {FLOW_NAME} flow requires \
             exact equality"
        )));
    }
    Ok(())
}
