#![deny(unsafe_code)]

// Release guards for two dev-only features:
//
//   * `allow-seed-import` - the parent can install a chosen seed, which
//     defeats in-enclave key custody.
//   * `mock-attestation`  - zero-PCR attestation documents pass, so a forged
//     enclave passes verification.
//
// A release build (`debug_assertions` off) with either one fails to compile.
// `not(test)` exempts the unit-test compilation only. Integration tests also
// compile the library without `cfg(test)`. Dev images build in debug mode.
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

// Builds without SPV require real attestation and an explicit signer role.
#[cfg(all(
    feature = "rgb-validation",
    not(feature = "spv"),
    any(
        feature = "allow-seed-import",
        feature = "mock-attestation",
        feature = "allow-debug-pcrs"
    )
))]
compile_error!("rgb-validation without spv requires real attestation; seed import and mock/debug attestation features are forbidden");
#[cfg(all(
    feature = "rgb-validation",
    not(feature = "spv"),
    not(any(feature = "mint-signer", feature = "burn-signer"))
))]
compile_error!("rgb-validation without spv requires mint-signer or burn-signer");

// Exactly one mint/burn signer role: each role is its own image with its own
// seed. `build.rs` derives the direction cfgs from the same two features.
#[cfg(all(feature = "mint-signer", feature = "burn-signer"))]
compile_error!(
    "mint-signer and burn-signer are mutually exclusive: the mint (EVM -> RGB) and burn \
     (RGB -> EVM) signers ship as separate enclave images with separate seeds. Build one \
     image per role"
);
#[cfg(all(
    feature = "rgb-validation",
    not(feature = "mint-signer"),
    not(feature = "burn-signer")
))]
compile_error!(
    "an RGB build requires a signer role: enable exactly one of `mint-signer` \
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
// The TLS rule of the loopback forwarders. Plain std, so tests run on all
// targets.
pub mod egress;
pub mod error;
pub mod framing;
pub mod keys;
#[cfg(feature = "kms-persistence")]
pub mod kms;
// The request memory model and its boot check.
pub mod limits;
pub mod memory;
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
