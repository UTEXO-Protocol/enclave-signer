//! The trusted strict type system that a consignment is pinned to.
//!
//! It comes from the schema id, never from the consignment. A consignment
//! with its own type system can redefine the meaning of its own bytes.

use crate::error::EnclaveError;
use crate::error::Result;

/// Returns the trusted strict type system for `schema_id`, from the canonical
/// `rgb-schemas` crate.
///
/// `ValidationConfig.trusted_typesystem` must never come from the consignment.
/// If `transfer.types` is used, rgbstd compares the consignment types with
/// themselves. The check then always passes, and a malicious consignment can
/// supply its own type definitions for the schema `SemId`s.
///
/// BFA is the only accepted schema. All other schema ids fail closed. The
/// exact asset is pinned separately (`contract_id` -> `RGB_ASSET_ID`).
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
/// three AluVM scripts on each call. The result is constant, so build it once.
pub(super) static BFA_TYPES: std::sync::LazyLock<rgbstd::TypeSystem> =
    std::sync::LazyLock::new(|| {
        use rgbstd::contract::IssuerWrapper;
        schemata::BridgedFungibleAsset::types()
    });
