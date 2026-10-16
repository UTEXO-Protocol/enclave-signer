//! Enclave wire protocol types.
//!
//! A vendored slice of `UTEXO-Protocol/federated-signer-proto` containing only
//! what runs inside the TEE: the `enclave` package. See README.md for
//! provenance and the re-sync procedure.
//!
//! `enclave.rs` is committed verbatim from upstream's generated output and must
//! not be hand-edited. This file is the only local addition - upstream exposes
//! the same code as `federated_signer_proto::enclave`, and here it sits at the
//! crate root.

include!("enclave.rs");
