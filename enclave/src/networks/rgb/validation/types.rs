//! Plain data extracted from a validated consignment.
//!
//! All of it passed rgb-lib validation. The rest of the enclave reads these
//! shapes and does not parse RGB again.

use super::bfa::VerifiedLock;

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
    /// No PSBT check reads it: the mint signer runs no consensus and reads its
    /// tx from the PSBT and the fascia (`rgb::route`). The RGB->EVM `fundsOut`
    /// source-block bind reads it. It is set for all types, so the bind works
    /// for transfer and burn.
    ///
    /// A `bitcoin::Txid`, not display-order bytes, to prevent byte-order
    /// errors. `None` only for a consignment with no bundles.
    pub last_witness_txid: Option<bitcoin::Txid>,
    /// Input prevouts of that witness tx. A V1 bundle always carries the full
    /// tx. Only tests read this field.
    pub last_transfer_witness_prevouts: Vec<bitcoin::OutPoint>,
    /// The outpoints whose seals the last bundle's transitions close. Only
    /// tests read this field, but reading these seals refuses a transition
    /// input with no revealed seal.
    pub last_closed_seals: Vec<bitcoin::OutPoint>,
    /// Every transition of the last bundle is in the consignment. A hidden
    /// one still counts in the bundle id, so a signature would commit to
    /// state moves the enclave never saw. Only tests read this field.
    pub last_bundle_fully_disclosed: bool,
    /// The `mintRight` (`OS_MINT`) outputs of the settling transition. Only
    /// tests read this field. The mint signer checks the fascia instead (M3).
    pub last_mint_rights: Vec<OutputSeal>,
    /// Authoritative OpId (32-byte commitment hash) of the **last**
    /// transition, read from the rgbstd-**validated** `Transfer`
    /// (`KnownTransition.opid` of the same bundle as `last_witness_txid`),
    /// NOT from the flat summary.
    ///
    /// The `fundsOut` bind of `sourceBurnTxId` reads it, so the burn that a
    /// release names is the burn that consensus validated. `Some` for a
    /// settling transition of any type: the flow check refuses one that is not a burn.
    /// `None` only for a consignment with no bundles.
    /// Validation refuses a consignment where this OpId and the flat summary's
    /// `last_transition.op_id` differ.
    pub last_transfer_op_id: Option<[u8; 32]>,
    /// Witness txids that are **not mined**, in **display (big-endian) byte
    /// order**, as [`Self::witness_txids`].
    ///
    /// Empty after a passing validation: consensus refuses every unmined
    /// witness. `fundsOut` checks that again before it signs.
    pub non_mined_witness_txids: Vec<[u8; 32]>,
    /// Every transition in the consignment, grouped by the witness tx that
    /// commits it.
    ///
    /// One Bitcoin tx commits a bundle, which can hold many transitions. The
    /// burn path reads [`Self::last_transition`], and the mint signer reads
    /// the fascia. Only tests read this field.
    pub transitions_by_witness: Vec<(bitcoin::Txid, Vec<TransitionSummary>)>,
    /// The locks every mint anchor of the consignment was confirmed against.
    /// A `fundsOut` must cite exactly these deposits in `settlementData`.
    pub mint_locks: Vec<VerifiedLock>,
}

#[cfg(test)]
impl ValidatedConsignment {
    /// Each transition that the witness tx `txid` commits.
    ///
    /// Empty if the consignment commits nothing to that tx. Only tests call
    /// this.
    pub fn transitions_committed_by(&self, txid: bitcoin::Txid) -> Vec<&TransitionSummary> {
        self.transitions_by_witness
            .iter()
            .filter(|(witness_txid, _)| *witness_txid == txid)
            .flat_map(|(_, transitions)| transitions.iter())
            .collect()
    }
}

/// Flat summary of one RGB state transition, read by rgb-lib's inspection
/// (`rgb_lib::no_wallet::RgbTransitionInfo`). Local types keep it out of the public API.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransitionSummary {
    /// Operation id: 64-char lowercase hex of the 32-byte RGB OpId, from
    /// rgb-lib. It must be hex, not baid64:
    /// `validation::bfa::decode_opid` decodes it to 32 bytes.
    pub op_id: String,
    /// BFA transition-type id. Compare with `schemata::TS_TRANSFER`,
    /// `TS_BURN` or `TS_MINT` to classify the EVM action.
    pub transition_type: u16,
    /// Sum of the fungible amounts on `OS_ASSET` output assignments, the one
    /// fungible type of BFA. For a Transfer, this is recipient plus change.
    /// For a mint, it is the minted value. For a Burn, it is 0: the schema
    /// gives it no outputs, and the destroyed amount is in
    /// [`Self::burned_asset_amount`].
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
