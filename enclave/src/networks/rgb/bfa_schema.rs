//! The BFA schema's numeric identifiers, as vectors for the tests.
//!
//! No signing path reads a number from here. rgb-lib reports a transition
//! type, an assignment type, a global and a metadata entry already typed, so
//! the enclave compares typed values. A consignment carries the schema id its
//! genesis commits, so rgb-lib types its transitions under the schema it
//! compiles and refuses what that schema does not define; a fascia carries no
//! schema, so there a type is only checked to be one rgb-lib knows. The one
//! id production needs, the reject-list global, lives with its single reader
//! in [`super::validation`].
//!
//! These ids stay because the tests need them: the fixtures build operations
//! by number, the summary oracles read globals by number without borrowing
//! production code, and [`tests`] pins every id and every type name to the
//! compiled `rgb-schemas`. A pin bump that renumbers anything, or that maps a
//! type to another name, fails here instead of changing what the enclave
//! enforces.

use rgb_lib::{AssignmentType, SchemaId, TypeOfTransition};
use rgbstd::{GlobalStateType, MetaType};

/// The schema the pinned asset is issued on. A contract id is the genesis
/// commitment, which commits `schema_id`, so `RGB_ASSET_ID` fixes it.
pub const BFA_SCHEMA_ID: SchemaId = SchemaId::from_array([
    0xdc, 0x8d, 0x31, 0x65, 0x51, 0x10, 0x9d, 0x0c, 0x58, 0x56, 0x4e, 0xef, 0x0e, 0x78, 0x79, 0xb8,
    0xdb, 0x50, 0xc9, 0x47, 0xec, 0x99, 0x38, 0x70, 0xe9, 0xd5, 0xfd, 0x9f, 0xe1, 0xaf, 0x6f, 0x9a,
]);

/// Units a mint issues.
pub const GS_ISSUED_SUPPLY: GlobalStateType = GlobalStateType::with(2010);
/// Units a burn destroys. It sets the EVM release amount.
pub const GS_BURNED_ASSET: GlobalStateType = GlobalStateType::with(2015);
/// A burn's 32-byte destination: a V0 address or a V1 record hash.
pub const GS_BURN_REASON: GlobalStateType = GlobalStateType::with(3009);

/// The EVM block a mint's lock must be included before.
pub const MS_BEFORE_BLOCK: MetaType = MetaType::with(1003);

/// Fungible asset units.
pub const OS_ASSET: AssignmentType = AssignmentType::with(4000);
/// A mint right. Only the bridge holds these.
pub const OS_MINT: AssignmentType = AssignmentType::with(4013);

pub const TS_INFLATION: u16 = 8000;
pub const TS_BURN: u16 = 8010;
pub const TS_LINK: u16 = 8012;
pub const TS_MINT: u16 = 8013;
pub const TS_PROPAGATE: u16 = 8014;
pub const TS_TRANSFER_INFLATION: u16 = 8015;
pub const TS_TRANSFER_LINK: u16 = 8016;
pub const TS_TRANSFER: u16 = 10000;

/// The type name rgb-lib reports for a BFA transition id. The tests read a
/// consignment's types by number and compare with what production reads, so
/// this table must not come from rgb-lib's own conversion.
pub fn type_of(transition_type: u16) -> TypeOfTransition {
    match transition_type {
        TS_INFLATION => TypeOfTransition::Inflate,
        TS_BURN => TypeOfTransition::Burn,
        TS_LINK => TypeOfTransition::Link,
        TS_MINT => TypeOfTransition::Mint,
        TS_PROPAGATE => TypeOfTransition::Propagate,
        TS_TRANSFER_INFLATION => TypeOfTransition::TransferInflation,
        TS_TRANSFER_LINK => TypeOfTransition::TransferLink,
        TS_TRANSFER => TypeOfTransition::Transfer,
        other => panic!("{other} is no BFA transition type"),
    }
}

#[cfg(test)]
mod tests {
    use amplify::Wrapper;

    use super::*;

    /// Every id must still be the pinned schema's. `rgb-schemas` is a
    /// dev-dependency for exactly this comparison, and it builds the schema
    /// rules, which panic on an inconsistent definition.
    #[test]
    fn the_ids_are_the_pinned_schemas() {
        assert_eq!(BFA_SCHEMA_ID, schemata::BFA_SCHEMA_ID);
        assert_eq!(GS_ISSUED_SUPPLY, schemata::GS_ISSUED_SUPPLY);
        assert_eq!(GS_BURNED_ASSET, schemata::GS_BURNED_ASSET);
        assert_eq!(GS_BURN_REASON, schemata::GS_BURN_REASON);
        assert_eq!(MS_BEFORE_BLOCK, schemata::MS_BEFORE_BLOCK);
        assert_eq!(OS_ASSET, schemata::OS_ASSET);
        assert_eq!(OS_MINT, schemata::OS_MINT);
        assert_eq!(TS_INFLATION, schemata::TS_INFLATION.to_inner());
        assert_eq!(TS_BURN, schemata::TS_BURN.to_inner());
        assert_eq!(TS_LINK, schemata::TS_LINK.to_inner());
        assert_eq!(TS_MINT, schemata::TS_MINT.to_inner());
        assert_eq!(TS_PROPAGATE, schemata::TS_PROPAGATE.to_inner());
        assert_eq!(
            TS_TRANSFER_INFLATION,
            schemata::TS_TRANSFER_INFLATION.to_inner()
        );
        assert_eq!(TS_TRANSFER_LINK, schemata::TS_TRANSFER_LINK.to_inner());
        assert_eq!(TS_TRANSFER, schemata::TS_TRANSFER.to_inner());
    }

    /// rgb-lib must name each id the same type this table does: production
    /// compares the names, so a renaming upstream would silently reclassify
    /// a transition.
    #[test]
    fn rgb_lib_names_each_transition_type_the_same() {
        for ty in [
            TS_INFLATION,
            TS_BURN,
            TS_LINK,
            TS_MINT,
            TS_PROPAGATE,
            TS_TRANSFER_INFLATION,
            TS_TRANSFER_LINK,
            TS_TRANSFER,
        ] {
            let theirs = TypeOfTransition::try_from(rgbstd::TransitionType::with(ty))
                .expect("a BFA transition type rgb-lib knows");
            assert_eq!(type_of(ty), theirs, "{ty}");
        }
    }
}
