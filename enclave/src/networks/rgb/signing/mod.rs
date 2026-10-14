//! PSBT input-signing mechanics.
//!
//! - `taproot.rs`: Taproot key-path signing with BIP-86 keys, plus sighash and
//!   prevout handling. Script-path and segwit v0 inputs are never signed.
//!
//! These are low-level signers. [`super::psbt_validation`] and
//! [`super::btc_crosscheck`] decide what is *allowed* to be signed.

pub mod taproot;
