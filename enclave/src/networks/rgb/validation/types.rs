//! Plain data extracted from a validated consignment.
//!
//! All of it passed rgbstd validation. The rest of the enclave reads these
//! shapes and does not parse RGB again.

use super::bfa::VerifiedLock;
use super::reject_list::RejectScope;

/// Data extracted from a successfully validated RGB consignment.
#[derive(Debug, Clone, Default)]
pub struct ValidatedConsignment {
    /// RGB contract identifier (for example "rgb:2TGhRyP3-..."). Unique per
    /// asset. RGB 0.11 derives it from the genesis operation.
    pub contract_id: String,
    /// Bitcoin network of the consignment, in rgbstd prefix form: `"bc"`,
    /// `"tb3"`, `"tb4"`, `"sb"`, `"sbc"` or `"bcrt"`.
    /// Used to reject cross-network replay (for example regtest on mainnet).
    pub chain_net: String,
    /// Bitcoin txids that anchor each transition bundle, in **display
    /// (big-endian) byte order**, as `MerkleProofEntry.txid` on the wire.
    /// Deduplicated and sorted, so set comparisons are stable.
    pub witness_txids: Vec<[u8; 32]>,
    /// The settling transition: the last burn of the last witness, or its last
    /// transition. `None` only for a transfer with no bundles, which rgbstd
    /// rejects.
    pub last_transition: Option<TransitionSummary>,
    /// Bitcoin txid of the witness tx that anchors the last transition, for
    /// all transition types (burn included).
    ///
    /// In the send-RGB direction, the PSBT is that witness tx. The PSBT
    /// cross-check binds `psbt.unsigned_tx.compute_txid()` to it after the
    /// flow transition-type check. The RGB->EVM `fundsOut` source-block bind
    /// uses it for all types, so it works for transfer and burn.
    ///
    /// A `bitcoin::Txid`, not display-order bytes, to prevent byte-order
    /// errors. `None` only for a consignment with no bundles.
    pub last_witness_txid: Option<bitcoin::Txid>,
    /// Input prevouts of that witness tx. A V1 bundle always carries the full
    /// tx. The PSBT cross-check uses them as a redundant per-input canary.
    pub last_transfer_witness_prevouts: Vec<bitcoin::OutPoint>,
    /// The outpoints whose seals the last bundle's transitions close. A
    /// PSBT may spend no other colored output: that would destroy the RGB
    /// state on it.
    pub last_closed_seals: Vec<bitcoin::OutPoint>,
    /// Every transition of the last bundle is in the consignment. A hidden
    /// one still counts in the bundle id, so a signature would commit to
    /// state moves the enclave never saw.
    pub last_bundle_fully_disclosed: bool,
    /// The `mintRight` (`OS_MINT`) outputs of the settling transition. A mint
    /// must have none: it consumes its right.
    pub last_mint_rights: Vec<OutputSeal>,
    /// Authoritative OpId (32-byte commitment hash) of the **last**
    /// transition, read from the rgbstd-**validated** `Transfer`
    /// (`KnownTransition.opid` of the same bundle as `last_witness_txid`),
    /// NOT from the flat rgb-lib inspection.
    ///
    /// The `fundsOut` bind of `sourceBurnTxId` reads it, so the burn that a
    /// release names is the burn that consensus validated. `Some` when the
    /// settling transition is the type this flow signs on a deposit, or a burn.
    /// `None` for a consignment with no bundles or another transition type.
    /// Validation refuses a consignment where this OpId and the flat parser's
    /// `last_transition.op_id` differ.
    pub last_transfer_op_id: Option<[u8; 32]>,
    /// Witness txids that are **not mined**, in **display (big-endian) byte
    /// order**, as [`Self::witness_txids`].
    ///
    /// Empty on the burn path. On the mint path, at most the mint tx being
    /// signed: consensus refuses every other unmined witness.
    pub non_mined_witness_txids: Vec<[u8; 32]>,
    /// Every transition in the consignment, grouped by the witness tx that
    /// commits it.
    ///
    /// One Bitcoin tx commits a bundle, which can hold many transitions. A
    /// bind of only [`Self::last_transition`] lets an attacker put a large
    /// transfer earlier in the bundle. Thus the send-RGB PSBT cross-check
    /// binds the full group with [`Self::transitions_committed_by`].
    pub transitions_by_witness: Vec<(bitcoin::Txid, Vec<TransitionSummary>)>,
    /// The locks every mint anchor of the consignment was confirmed against.
    /// A `fundsOut` must cite exactly these deposits in `settlementData`.
    pub mint_locks: Vec<VerifiedLock>,
    /// What the reject-list check walks. `None` for an asset without a list.
    pub reject_scope: Option<RejectScope>,
}

impl ValidatedConsignment {
    /// Each transition that the witness tx `txid` commits.
    ///
    /// Empty if the consignment commits nothing to that tx. Callers must treat
    /// empty as a rejection, not as "nothing to check".
    pub fn transitions_committed_by(&self, txid: bitcoin::Txid) -> Vec<&TransitionSummary> {
        self.transitions_by_witness
            .iter()
            .filter(|(witness_txid, _)| *witness_txid == txid)
            .flat_map(|(_, transitions)| transitions.iter())
            .collect()
    }
}

/// Flat summary of one RGB state transition, read by rgb-lib's inspection.
/// Local types keep rgb-lib out of the public API.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransitionSummary {
    /// Operation id: 64-char lowercase hex of the 32-byte RGB OpId, from
    /// rgb-lib. It must be hex, not baid64:
    /// `validation::bfa::decode_opid` decodes it to 32 bytes.
    pub op_id: String,
    /// BFA transition-type id. Compare with `schemata::TS_TRANSFER`,
    /// `TS_BURN` or `TS_MINT` to classify the EVM action.
    pub transition_type: u16,
    /// Sum of all fungible amounts in the output assignments. For a Transfer,
    /// this is recipient plus change. For a Burn, it is its change only: the
    /// destroyed amount is in [`Self::burned_asset_amount`].
    pub total_output_amount: u64,
    /// Sum of the fungible amounts on `OS_ASSET` output assignments only.
    /// BFA has no other fungible type, so this equals
    /// [`Self::total_output_amount`]. For a mint, it is the minted value.
    pub asset_output_amount: u64,
    /// Fungible output assignments, each with a destination seal and an
    /// amount. The declarative mint right is not here.
    pub outputs: Vec<TransitionOutput>,
    /// Asset units that this burn destroys, from its `burnedAsset`
    /// (`GS_BURNED_ASSET`) global. Consensus refuses zero. `None` for a
    /// non-burn, or a burn without the global.
    pub burned_asset_amount: Option<u64>,
    /// The burn's `burnReason` (`GS_BURN_REASON`) global: 32 bytes. A V0
    /// left-padded EVM address or a V1 destination record hash, see
    /// `networks::evm::burn_destination`. `None` for a non-burn, or a burn
    /// without the global.
    pub burn_reason: Option<[u8; 32]>,
}

/// One fungible output assignment on a state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionOutput {
    /// BFA assignment type. Only `OS_ASSET` entries carry asset units. The
    /// per-output recipient bind filters on it, as `asset_output_amount` does.
    pub assignment_type: u16,
    /// Amount in the smallest unit of the asset.
    pub amount: u64,
    /// Destination seal: a revealed `txid:vout` or a hidden commitment.
    pub seal: OutputSeal,
}

/// The seal of an output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputSeal {
    /// Concrete `txid:vout`. `txid` is `None` if the seal points to the
    /// witness tx of its bundle. Then use the bundle witness txid.
    Revealed {
        /// Display-order bytes, as in `witness_txids`.
        txid: Option<[u8; 32]>,
        vout: u32,
    },
    /// Hidden (blinded) seal (`utxob:...` SHA-256 commitment string).
    Confidential { secret_seal: String },
}
