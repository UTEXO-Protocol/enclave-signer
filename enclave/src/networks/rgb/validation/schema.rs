//! The trusted strict type-system a consignment is pinned against.
//!
//! Sourced from the schema id, never from the consignment: a consignment that
//! carries its own type system could otherwise redefine what its own bytes
//! mean.

use crate::error::EnclaveError;
use crate::error::Result;

/// Resolve the trusted strict type-system to pin a consignment against, keyed
/// on its `schema_id` and sourced from the canonical `rgb-schemas` crate.
///
/// `ValidationConfig.trusted_typesystem` must never come
/// from the consignment under validation. Feeding `transfer.types` back in
/// makes rgbstd compare the consignment's types against themselves, so the
/// control always passes and a malicious consignment can ship its own type
/// definitions for the schema's `SemId`s.
///
/// BFA is the only schema accepted; every other schema id is rejected
/// fail-closed. The exact asset is pinned separately via `contract_id` ->
/// `RGB_ASSET_ID`. Schema ids are compared by canonical string form so the
/// comparison survives `rgb-schemas` resolving a different `rgb-consensus`
/// build than the validator.
pub(super) fn trusted_typesystem_for_schema(
    schema_id: rgbstd::SchemaId,
) -> Result<rgbstd::TypeSystem> {
    if schema_id != schemata::BFA_SCHEMA_ID {
        return Err(EnclaveError::CrossCheck(format!(
            "consignment uses RGB schema {schema_id}, but this enclave validates only the \
             bridged fungible asset (BFA) schema - refusing to validate"
        )));
    }
    Ok(BFA_TYPES.clone())
}

/// The canonical BFA type system, built once.
///
/// `BridgedFungibleAsset::types()` rebuilds the standard type libraries and
/// re-assembles three AluVM scripts on every call. It is a constant, so the
/// enclave pays for it once instead of on every consignment.
pub(super) static BFA_TYPES: std::sync::LazyLock<rgbstd::TypeSystem> =
    std::sync::LazyLock::new(|| {
        use rgbstd::contract::IssuerWrapper;
        schemata::BridgedFungibleAsset::types()
    });
