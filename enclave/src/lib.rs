#![deny(unsafe_code)]

// Release guards (dev-mode). Three dev-only
// features are catastrophic if accidentally enabled in a shipped build:
//
//   * `allow-seed-import` - the parent can install a chosen seed on a fresh
//     enclave, defeating the in-enclave key custody.
//   * `mock-attestation`  - zero-PCR attestation documents are accepted, so
//     a forged "enclave" passes verification.
//   * `dev-mode`          - every signing cross-check is skipped.
//
// A release build (`debug_assertions` off) must never carry any of them, so
// each trips a `compile_error!`. `not(test)` exempts `cargo test --release`,
// which legitimately exercises the dev paths; local dev images build in debug.
//
// `dev_feature_release_guard!` keeps the three checks in one place.
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
dev_feature_release_guard!(
    "dev-mode",
    "`dev-mode` must not be enabled in a release build (debug_assertions off): \
     it skips all signing cross-checks."
);

// `rgb-validation` asks a resolver whether a consignment's witness txs are
// mined. Without `spv` that resolver is the host-controlled Esplora endpoint,
// so a malicious host could claim a fabricated witness tx is confirmed and the
// enclave would sign a `fundsOut` against a non-existent anchor. `spv` re-anchors every witness tx against the enclave's own header
// chain. Unsafe in every profile, so this is not release-gated.
#[cfg(all(feature = "rgb-validation", not(feature = "spv")))]
compile_error!(
    "rgb-validation requires spv: without spv, consignment anchoring trusts only \
     the host-controlled Esplora resolver - build with `--features spv` (which \
     pulls in rgb-validation)"
);

pub mod attestation;
pub mod cloning;
pub mod config;
pub mod conn;
pub mod error;
pub mod framing;
pub mod keys;
pub mod networks;
pub mod policy;
pub mod server;
pub mod state;

#[cfg(all(feature = "vsock", target_os = "linux"))]
pub mod vsock_forwarder;

// Only the `enclave` package is vendored into the TEE build. The parent
// adapter still exposes the other proto packages (see parent/src/lib.rs).
pub use enclave_proto as proto;
