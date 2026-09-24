//! PSBT input-signing mechanics, split by script type.
//!
//! - `psbt.rs`: segwit (P2WPKH / P2WSH) input inspection. Decides whether an
//!   input is ours to co-sign and returns the validated witness script.
//! - `taproot.rs`: taproot key-path and script-path signing, with the sighash
//!   and prevout handling that goes with it.
//!
//! These are the low-level signers. What is *allowed* to be signed is decided
//! earlier, in [`super::psbt_validation`] and [`super::btc_crosscheck`].

pub mod psbt;
pub mod taproot;
