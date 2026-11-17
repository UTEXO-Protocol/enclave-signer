//! The BFA schema's identifiers, as the enclave reads them.
//!
//! RGB carries no field names: a transition names its type, its globals and
//! its assignments by number, and those numbers mean something only under one
//! schema. The ids below are the pinned BFA schema's, held here so that
//! signing does not depend on `rgb-schemas` at runtime.
//!
//! `tests` keeps every id equal to the pinned `rgb-schemas`, which is a
//! dev-dependency for that comparison. A schema revision renumbers nothing by
//! itself, but it changes [`BFA_SCHEMA_ID`], and the pinned `RGB_ASSET_ID`
//! then names a contract of the old schema: the test fails until the ids and
//! the asset are updated together.

use rgbstd::{GlobalStateType, MetaType, TransitionType};

use rgb_lib::{AssignmentType, SchemaId};

/// The schema the pinned asset is issued on. A contract id is the genesis
/// commitment, which commits `schema_id`, so `RGB_ASSET_ID` fixes this: the
/// enclave needs no runtime comparison, only this pin on the ids below.
pub const BFA_SCHEMA_ID: SchemaId = SchemaId::from_array([
    0xdc, 0x8d, 0x31, 0x65, 0x51, 0x10, 0x9d, 0x0c, 0x58, 0x56, 0x4e, 0xef, 0x0e, 0x78, 0x79, 0xb8,
    0xdb, 0x50, 0xc9, 0x47, 0xec, 0x99, 0x38, 0x70, 0xe9, 0xd5, 0xfd, 0x9f, 0xe1, 0xaf, 0x6f, 0x9a,
]);

/// Units a mint issues (M4).
pub const GS_ISSUED_SUPPLY: GlobalStateType = GlobalStateType::with(2010);
/// Units a burn destroys. It sets the EVM release amount.
pub const GS_BURNED_ASSET: GlobalStateType = GlobalStateType::with(2015);
/// A burn's 32-byte destination: a V0 address or a V1 record hash.
pub const GS_BURN_REASON: GlobalStateType = GlobalStateType::with(3009);
/// Where the issuer publishes the asset's reject list, if anywhere.
pub const GS_REJECT_LIST: GlobalStateType = GlobalStateType::with(3010);

/// The EVM block a mint's lock must be included before (M4).
pub const MS_BEFORE_BLOCK: MetaType = MetaType::with(1003);

/// Fungible asset units.
pub const OS_ASSET: AssignmentType = AssignmentType::with(4000);
/// A mint right. Only the bridge holds these.
pub const OS_MINT: AssignmentType = AssignmentType::with(4013);

pub const TS_INFLATION: TransitionType = TransitionType::with(8000);
pub const TS_BURN: TransitionType = TransitionType::with(8010);
pub const TS_LINK: TransitionType = TransitionType::with(8012);
pub const TS_MINT: TransitionType = TransitionType::with(8013);
pub const TS_PROPAGATE: TransitionType = TransitionType::with(8014);
pub const TS_TRANSFER_INFLATION: TransitionType = TransitionType::with(8015);
pub const TS_TRANSFER_LINK: TransitionType = TransitionType::with(8016);
pub const TS_TRANSFER: TransitionType = TransitionType::with(10000);

#[cfg(test)]
mod tests {
    use super::*;

    /// Every id must still be the pinned schema's. `rgb-schemas` is a
    /// dev-dependency for exactly this comparison: a pin bump that renumbers
    /// anything fails here instead of changing what the enclave enforces.
    #[test]
    fn the_ids_are_the_pinned_schemas() {
        assert_eq!(BFA_SCHEMA_ID, schemata::BFA_SCHEMA_ID);
        assert_eq!(GS_ISSUED_SUPPLY, schemata::GS_ISSUED_SUPPLY);
        assert_eq!(GS_BURNED_ASSET, schemata::GS_BURNED_ASSET);
        assert_eq!(GS_BURN_REASON, schemata::GS_BURN_REASON);
        assert_eq!(GS_REJECT_LIST, schemata::GS_REJECT_LIST);
        assert_eq!(MS_BEFORE_BLOCK, schemata::MS_BEFORE_BLOCK);
        assert_eq!(OS_ASSET, schemata::OS_ASSET);
        assert_eq!(OS_MINT, schemata::OS_MINT);
        assert_eq!(TS_INFLATION, schemata::TS_INFLATION);
        assert_eq!(TS_BURN, schemata::TS_BURN);
        assert_eq!(TS_LINK, schemata::TS_LINK);
        assert_eq!(TS_MINT, schemata::TS_MINT);
        assert_eq!(TS_PROPAGATE, schemata::TS_PROPAGATE);
        assert_eq!(TS_TRANSFER_INFLATION, schemata::TS_TRANSFER_INFLATION);
        assert_eq!(TS_TRANSFER_LINK, schemata::TS_TRANSFER_LINK);
        assert_eq!(TS_TRANSFER, schemata::TS_TRANSFER);
    }
}
