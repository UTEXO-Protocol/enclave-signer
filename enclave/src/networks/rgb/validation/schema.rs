//! The genesis gate, and the reject list the genesis names.
//!
//! rgb-lib validates under the BFA rules of the `rgb-schemas` crate, never
//! under rules from the consignment. A V1 consignment carries no schema, types
//! or scripts, so nothing in it can redefine the meaning of its bytes.

use rgbstd::Genesis;

use super::reject_list::RejectListContract;
use crate::error::{EnclaveError, Result};

/// BFA is the only accepted schema. The exact asset is pinned separately
/// (`contract_id` -> `RGB_ASSET_ID`).
pub(super) fn assert_bfa_genesis(genesis: &Genesis) -> Result<()> {
    if genesis.schema_id != schemata::BFA_SCHEMA_ID {
        return Err(EnclaveError::CrossCheck(format!(
            "consignment uses RGB schema {}, but this enclave validates only the bridged \
             fungible asset (BFA) schema - refusing to validate",
            genesis.schema_id
        )));
    }
    Ok(())
}

/// Strict encoding of `RejectListLocation::Evm`: tag 1, the chain id as a
/// little-endian `u64`, the 20-byte address.
const EVM_LOCATION_LEN: usize = 1 + 8 + 20;
const EVM_LOCATION_TAG: u8 = 1;

/// The reject list the genesis names, if any. Only an EVM contract is read: a
/// URL list is refused, since its host would be untrusted.
pub(super) fn reject_list(genesis: &Genesis) -> Result<Option<RejectListContract>> {
    let Some(values) = genesis.globals.get(&schemata::GS_REJECT_LIST) else {
        return Ok(None);
    };
    let [value] = values.as_slice() else {
        return Err(EnclaveError::CrossCheck(format!(
            "BFA genesis carries {} reject lists, expected one",
            values.len()
        )));
    };
    let bytes = value.as_slice();
    if bytes.len() != EVM_LOCATION_LEN || bytes[0] != EVM_LOCATION_TAG {
        return Err(EnclaveError::CrossCheck(
            "BFA genesis names a reject list that is not an EVM contract - this enclave reads \
             only an EVM reject list, refusing to validate"
                .into(),
        ));
    }
    let mut chain_id = [0u8; 8];
    chain_id.copy_from_slice(&bytes[1..9]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&bytes[9..]);
    Ok(Some(RejectListContract {
        chain_id: u64::from_le_bytes(chain_id),
        address,
    }))
}
