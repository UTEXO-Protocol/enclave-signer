//! Direction cfgs for the RGB <-> EVM bridge.
//!
//! `evm_to_rgb` compiles the deposit path (EVM lock -> RGB PSBT), `rgb_to_evm`
//! the release path (RGB burn -> EVM `fundsOut`). Both are on unless a
//! single-direction feature removes the other one:
//!
//!   * `mint-signer` - EVM -> RGB only
//!   * `burn-signer` - RGB -> EVM only
//!
//! Aliases instead of `not(feature = ...)` at every call site, so a gate reads
//! as the direction it guards.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(evm_to_rgb)");
    println!("cargo::rustc-check-cfg=cfg(rgb_to_evm)");
    let mint_only = std::env::var_os("CARGO_FEATURE_MINT_SIGNER").is_some();
    let burn_only = std::env::var_os("CARGO_FEATURE_BURN_SIGNER").is_some();
    if !burn_only {
        println!("cargo::rustc-cfg=evm_to_rgb");
    }
    if !mint_only {
        println!("cargo::rustc-cfg=rgb_to_evm");
    }
}
