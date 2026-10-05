#![deny(unsafe_code)]

// Release guards for two dev-only features:
//
//   * `allow-seed-import` - the parent can install a chosen seed, which
//     defeats in-enclave key custody.
//   * `mock-attestation`  - zero-PCR attestation documents pass, so a forged
//     enclave passes verification.
//
// A release build (`debug_assertions` off) with either one fails to compile.
// `not(test)` exempts `cargo test --release`. Dev images build in debug.
macro_rules! dev_feature_release_guard {
    ($feature:literal, $msg:literal) => {
        #[cfg(all(feature = $feature, not(debug_assertions), not(test)))]
        compile_error!($msg);
    };
}

dev_feature_release_guard!(
    "allow-seed-import",
    "`allow-seed-import` must not be enabled in a release build (debug_assertions off): \
     it lets the parent install a chosen seed. Build dev images in debug mode."
);
dev_feature_release_guard!(
    "mock-attestation",
    "`mock-attestation` must not be enabled in a release build (debug_assertions off): \
     it accepts zero-PCR attestation documents."
);

// Without `spv`, the host-controlled indexer tells if witness txs are mined.
// A malicious host can then get a `fundsOut` signed against a fake anchor.
// `spv` checks every witness tx against the enclave's own header chain.
// Unsafe in every profile, so this guard is not release-gated (M-01).
#[cfg(all(feature = "rgb-validation", not(feature = "spv")))]
compile_error!(
    "rgb-validation requires spv: without spv, consignment anchoring trusts only \
     the host-controlled indexer - build with `--features spv` (which \
     pulls in rgb-validation)"
);

// With these guards, `rgb`, `spv` and `rgb-validation` act as one switch.
// Code gates the RGB stack on `rgb-validation` only.

// Exactly one RGB flow. Each flow is its own enclave image with its own PCR0.
// The modules in `networks/rgb/flow/` export the same item names. These guards
// give a clear message instead of many name-resolution errors.
#[cfg(all(feature = "rgb-swap", feature = "rgb-mint-burn"))]
compile_error!(
    "rgb-swap and rgb-mint-burn are mutually exclusive: the send/receive and mint/burn flows \
     ship as separate enclave instances. Build one image per flow - the default feature set \
     carries `rgb-swap`, so a mint/burn image needs `--no-default-features --features \
     vsock,rgb,mint-signer` (or `burn-signer`)"
);
#[cfg(all(
    feature = "rgb-validation",
    not(feature = "rgb-swap"),
    not(feature = "rgb-mint-burn")
))]
compile_error!(
    "rgb-validation requires a flow: enable exactly one of `rgb-swap` (send/receive) or \
     `rgb-mint-burn`. Without one the enclave has no rule for which RGB transition types it \
     may sign, and refusing to build is safer than defaulting to either"
);

// Exactly one mint/burn signer role: each role is its own image with its own
// seed. `build.rs` derives the direction cfgs from the same two features.
#[cfg(all(feature = "mint-signer", feature = "burn-signer"))]
compile_error!(
    "mint-signer and burn-signer are mutually exclusive: the mint (EVM -> RGB) and burn \
     (RGB -> EVM) signers ship as separate enclave images with separate seeds. Build one \
     image per role"
);
#[cfg(all(
    feature = "rgb-mint-burn",
    not(feature = "mint-signer"),
    not(feature = "burn-signer")
))]
compile_error!(
    "a mint/burn build requires a signer role: enable exactly one of `mint-signer` \
     (EVM -> RGB) or `burn-signer` (RGB -> EVM), e.g. `--no-default-features --features \
     vsock,rgb,mint-signer`"
);

// The attested role reads the features. The gates read the `build.rs` cfgs.
// A cfg set from outside (for example RUSTFLAGS) must not make them disagree.
#[cfg(all(feature = "mint-signer", rgb_to_evm))]
compile_error!(
    "mint-signer with the `rgb_to_evm` cfg set: the image would attest Mint but compile the \
     release path. Do not set direction cfgs by hand; `build.rs` derives them"
);
#[cfg(all(feature = "burn-signer", evm_to_rgb))]
compile_error!(
    "burn-signer with the `evm_to_rgb` cfg set: the image would attest Burn but compile the \
     mint path. Do not set direction cfgs by hand; `build.rs` derives them"
);

// Only the mint signer has a persistent seed.
#[cfg(all(feature = "kms-persistence", not(feature = "mint-signer")))]
compile_error!(
    "kms-persistence requires mint-signer; seed persistence is available only to the RGB mint signer"
);

pub mod attestation;
// Boot sequence for `main.rs`. In the library so clippy and tests cover it.
pub mod bootstrap;
pub mod cloning;
// Keeps CLOCK_REALTIME on the hypervisor PTP clock. Linux-only (`nix::time`).
#[cfg(target_os = "linux")]
pub mod clocksync;
pub mod config;
pub mod conn;
pub mod error;
pub mod framing;
pub mod keys;
#[cfg(feature = "kms-persistence")]
pub mod kms;
pub mod networks;
pub mod policy;
#[cfg(feature = "kms-persistence")]
pub mod seed_persistence;
pub mod server;
pub mod state;
#[cfg(test)]
mod test_support;

#[cfg(all(feature = "vsock", target_os = "linux"))]
pub mod vsock_forwarder;

// Only the `enclave` proto package is vendored into the TEE build.
pub use enclave_proto as proto;
