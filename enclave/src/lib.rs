#![deny(unsafe_code)]

// Release guards (audit TEE-IK-01 / TEE-CL-02 + dev-mode). Three dev-only
// features are catastrophic if accidentally enabled in a shipped build:
//
//   * `allow-seed-import` — the parent can install a chosen seed on a fresh
//     enclave, defeating the in-enclave key custody.
//   * `mock-attestation`  — zero-PCR attestation documents are accepted, so
//     a forged "enclave" passes verification.
//   * `dev-mode`          — every signing cross-check is skipped.
//
// A release build (`debug_assertions` off) must never carry any of them, so
// each trips a `compile_error!` instead of producing a binary. A misconfigured
// Dockerfile or CI matrix fails loudly at build time rather than shipping a
// trust-defeating enclave. `not(test)` exempts `cargo test --release`, which
// legitimately exercises the dev paths; local dev images build in debug
// (`build/Dockerfile.enclave-dev`), which keeps `debug_assertions` on.
//
// `dev_feature_release_guard!` keeps the three checks in one place so the
// pattern can't drift between features.
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

// `rgb-validation` validates a consignment by asking a resolver whether its
// witness txs are mined. Without `spv` that resolver is the host-controlled
// Esplora endpoint, so a malicious host can answer "mined at sufficient depth"
// for a fabricated witness tx and the enclave would sign a `fundsOut` release
// against a non-existent Bitcoin anchor (audit M-01 / #61). `spv` re-anchors
// every witness tx against the enclave's own PoW-verified header chain, so a
// build that can validate consignments MUST also carry SPV. Unlike the
// dev-feature guards above, this combination is unsafe in every profile — so it
// is not release-gated and must never compile.
#[cfg(all(feature = "rgb-validation", not(feature = "spv")))]
compile_error!(
    "rgb-validation requires spv: without spv, consignment anchoring trusts only \
     the host-controlled Esplora resolver — build with `--features spv` (which \
     pulls in rgb-validation)"
);

pub mod attestation;
pub mod cloning;
pub mod config;
pub mod conn;
pub mod error;
pub mod framing;
pub mod keys;
pub mod server;
pub mod signing;
pub mod spv;
pub mod state;
pub mod validation;
#[cfg(all(feature = "vsock", target_os = "linux"))]
pub mod vsock_forwarder;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/utexo_bridge.enclave.rs"));
}

pub mod enriched {
    include!(concat!(env!("OUT_DIR"), "/tricorn.enriched.rs"));
}
