//! PSBT input-signing mechanics.
//!
//! - `taproot.rs`: BIP-86 key-path taproot signing, with the sighash and
//!   prevout handling that goes with it. Script-path and segwit v0 inputs are
//!   never signed.
//!
//! These are the low-level signers. What is *allowed* to be signed is decided
//! earlier, in [`super::psbt_validation`] and [`super::btc_crosscheck`].

pub mod taproot;
