//! The RGB/BTC half of the bridge.
//!
//! Wiring only. Every check lives in a submodule:
//!
//! - `route.rs`: the entry points `networks::route` dispatches to.
//! - `validation.rs`: consignment parsing, rgbstd validation, asset binding,
//!   and the `RgbValidator` indexer client.
//! - `psbt_validation.rs`: binds a PSBT to a validated RGB transition.
//! - `btc_crosscheck.rs`: the plain-BTC (`SignBtc`) authorization gate.
//! - `btc_ownership.rs`: proves an output or input script is one we control.
//! - `spv/`: the in-enclave Bitcoin header chain and Merkle verifier.
//! - `spv_crosscheck.rs`: anchors consignment witness txs in that chain.
//! - `signing/`: the low-level segwit and taproot input signers.
//! - `flow/`: the per-flow rules (send/receive vs mint/burn).
//! - `invoice.rs`: the send-RGB recipient bind.

// The PSBT-side checks (`SignBtc`, the mint PSBT bind, the recipient invoice)
// belong to the EVM -> RGB direction only.
#[cfg(evm_to_rgb)]
pub mod btc_crosscheck;
#[cfg(evm_to_rgb)]
pub mod btc_ownership;
#[cfg(feature = "rgb-validation")]
pub mod flow;
// The invoice bind reads a verified BridgeFundsIn log, so it only exists
// where the enclave can fetch one (`evm-rpc` implies `rgb-validation`).
#[cfg(all(feature = "evm-rpc", evm_to_rgb))]
pub mod invoice;
#[cfg(evm_to_rgb)]
pub mod psbt_validation;
mod route;
pub mod signing;
pub mod spv;
#[cfg(feature = "rgb-validation")]
pub mod spv_crosscheck;
#[cfg(feature = "rgb-validation")]
pub mod validation;

#[cfg(evm_to_rgb)]
pub use route::validate_destination;
#[cfg(all(feature = "rgb-validation", evm_to_rgb))]
pub use route::validate_destination_anchor;
#[cfg(rgb_to_evm)]
pub use route::validate_source;
