//! The reject list the genesis names.
//!
//! rgb-lib validates under the BFA rules that its own pinned `rgb-schemas`
//! compiles, never under rules from the consignment. A V1 consignment carries
//! no schema, types or scripts, so nothing in it can redefine the meaning of
//! its bytes.
//!
//! The schema needs no check of its own. A `ContractId` is the genesis
//! commitment, which commits `schema_id` and merklizes every global, so the
//! `RGB_ASSET_ID` pin that [`super::consensus`] enforces admits exactly one
//! genesis, under exactly one schema. The same holds for the reject-list
//! location read below: the pin fixes it, so a location this enclave cannot
//! read is an operator error, not caller-chosen data.

use rgb_lib::Genesis;
use rgbstd::GlobalStateType;

/// Where the issuer publishes the asset's reject list, if anywhere. A
/// `ContractId` is the genesis commitment, so the `RGB_ASSET_ID` pin fixes
/// this location: nothing an operator or the parent sets can point the
/// enclave at another list. `tests` keeps the id equal to the pinned
/// `rgb-schemas`.
const GS_REJECT_LIST: GlobalStateType = GlobalStateType::with(3010);

use super::reject_list::RejectListContract;
use crate::error::{EnclaveError, Result};

/// Strict encoding of `RejectListLocation::Evm`: tag 1, the chain id as a
/// little-endian `u64`, the 20-byte address.
const EVM_LOCATION_LEN: usize = 1 + 8 + 20;
const EVM_LOCATION_TAG: u8 = 1;

/// The reject list the genesis names, if any. Only an EVM contract is read: a
/// URL list is refused, since its host would be untrusted.
pub(super) fn reject_list(genesis: &Genesis) -> Result<Option<RejectListContract>> {
    let Some(values) = genesis.globals.get(&GS_REJECT_LIST) else {
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
