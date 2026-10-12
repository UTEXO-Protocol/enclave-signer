//! The schema rules a consignment is validated under, and the genesis gate.
//!
//! The rules come from the `rgb-schemas` crate, never from the consignment.
//! A V1 consignment carries no schema, types or scripts, so nothing in it can
//! redefine the meaning of its bytes.

use std::sync::LazyLock;

use rgbstd::contract::IssuerWrapper;
use rgbstd::validation::SchemaRules;
use rgbstd::Genesis;
use schemata::BridgedFungibleAsset;

use crate::error::{EnclaveError, Result};

/// The BFA rules, built once. Boot forces them, so an inconsistent built-in
/// schema stops the launch, not a request.
pub(crate) static BFA_RULES: LazyLock<SchemaRules> =
    LazyLock::new(BridgedFungibleAsset::schema_rules);

/// BFA is the only accepted schema. The exact asset is pinned separately
/// (`contract_id` -> `RGB_ASSET_ID`).
///
/// A genesis with a reject list is refused: the enclave does not read the
/// list, so it would release burns of outputs the issuer froze.
pub(super) fn assert_bfa_genesis(genesis: &Genesis) -> Result<()> {
    if genesis.schema_id != schemata::BFA_SCHEMA_ID {
        return Err(EnclaveError::CrossCheck(format!(
            "consignment uses RGB schema {}, but this enclave validates only the bridged \
             fungible asset (BFA) schema - refusing to validate",
            genesis.schema_id
        )));
    }
    if genesis.globals.contains_key(&schemata::GS_REJECT_LIST) {
        return Err(EnclaveError::CrossCheck(
            "BFA genesis declares a reject list, which this enclave does not enforce - refusing \
             to validate"
                .into(),
        ));
    }
    Ok(())
}
