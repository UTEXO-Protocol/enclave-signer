//! Plain data extracted from a validated consignment.
//!
//! All of it passed rgbstd validation. The rest of the enclave reads these
//! shapes and does not parse RGB again.

/// Data extracted from a successfully validated RGB consignment.
#[derive(Debug, Clone)]
pub struct ValidatedConsignment {
    /// RGB contract identifier (for example "rgb:2TGhRyP3-..."). Unique per
    /// asset. RGB 0.11 derives it from the genesis operation.
    pub contract_id: String,
    /// Bitcoin network of the consignment, in rgbstd prefix form: `"bc"`,
    /// `"bc:testnet3"`/`"tb"`, `"bc:signet"`/`"sb"`, or `"bc:regtest"`.
    /// Used to reject cross-network replay (for example regtest on mainnet).
    pub chain_net: String,
    /// Bitcoin txids that anchor each transition bundle, in **display
    /// (big-endian) byte order**, as `MerkleProofEntry.txid` on the wire.
    /// Deduplicated and sorted, so set comparisons are stable.
    pub witness_txids: Vec<[u8; 32]>,
    /// Each state-transition `op_id` in the consignment, in witness order
    /// (bundle k before bundle k+1). Spec section 6 requires a cross-check of
    /// each mint OpId committed to EVM state.
    pub all_op_ids: Vec<String>,
    /// The `op_id`s of each BFA `TS_BRIDGE` (mint) transition, in witness
    /// order. This is the subset of [`Self::all_op_ids`] that matches EVM lock
    /// records (`fundsIn`).
    ///
    /// The EVM side does not use it. The `fundsOut` citation comes from
    /// deposit receipts, and `RgbSettlementModule.beforeFundsOut` enforces it
    /// on-chain.
    pub mint_op_ids: Vec<String>,
    /// The last state transition: the state change that the EVM action
    /// commits to. `None` only for a transfer with no bundles, which rgbstd
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
    /// Input prevouts of that witness tx, if the consignment embeds the full
    /// tx (`PubWitness::Tx`). The PSBT cross-check uses them as a redundant
    /// per-input canary. `None` for `PubWitness::Txid`, where the txid bind
    /// alone anchors each input.
    pub last_transfer_witness_prevouts: Option<Vec<bitcoin::OutPoint>>,
    /// Authoritative OpId (32-byte commitment hash) of the **last**
    /// transition, read from the rgbstd-**validated** `Transfer`
    /// (`KnownTransition.opid` of the same bundle as `last_witness_txid`),
    /// NOT from the flat `rgb_consignment` parser.
    ///
    /// The `fundsOut` bind of `sourceBurnTxId` reads it, so the burn that a
    /// release names is the burn that consensus validated. `Some` when the
    /// last transition is the type this flow signs on a deposit, or a burn.
    /// `None` for a consignment with no bundles or another transition type.
    /// Validation refuses a consignment where this OpId and the flat parser's
    /// `last_transition.op_id` differ.
    pub last_transfer_op_id: Option<[u8; 32]>,
    /// Witness txids that are **not mined**, in **display (big-endian) byte
    /// order**, as [`Self::witness_txids`].
    ///
    /// Always empty at present. rgb-ops sets each consignment tx to
    /// `WitnessOrd::Tentative` at any depth, so `validate_consignment` does
    /// not fill it. RGB->EVM confirmation comes from the SPV depth check.
    /// The empty set keeps `evm::crosscheck::assert_witnesses_confirmed` as a
    /// structural guard.
    pub non_mined_witness_txids: Vec<[u8; 32]>,
    /// Every transition in the consignment, grouped by the witness tx that
    /// commits it.
    ///
    /// One Bitcoin tx commits a bundle, which can hold many transitions. A
    /// bind of only [`Self::last_transition`] lets an attacker put a large
    /// transfer earlier in the bundle. Thus the send-RGB PSBT cross-check
    /// binds the full group with [`Self::transitions_committed_by`].
    pub transitions_by_witness: Vec<(bitcoin::Txid, Vec<TransitionSummary>)>,
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

/// Flat summary of one RGB state transition. Mirrors
/// `rgb_consignment::TransitionInfo` in local types, so the parser dependency
/// stays out of the public API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionSummary {
    /// Operation id: 64-char lowercase hex of the 32-byte RGB OpId, from the
    /// parser. It must be hex, not baid64:
    /// `validation::bfa::decode_opid` decodes it to 32 bytes.
    pub op_id: String,
    /// BFA transition-type id. Compare with [`bfa::TS_TRANSFER`],
    /// [`bfa::TS_BURN`] or [`bfa::TS_BRIDGE`] to classify the EVM action.
    pub transition_type: u16,
    /// Sum of all fungible amounts in the output assignments. For a Transfer,
    /// this is recipient plus change. For a Burn, it is **zero**: a burn has no
    /// output assignments, and the amount is in [`Self::burned_asset_amount`].
    pub total_output_amount: u64,
    /// Sum of the fungible amounts on `OS_ASSET` output assignments only.
    /// Only these carry asset units. For a Transfer, this equals
    /// [`Self::total_output_amount`]. For a Bridge (mint), it is the minted
    /// value, **without** the declarative `OS_BRIDGE` output (the mint right).
    pub asset_output_amount: u64,
    /// Output assignments, each with a destination seal and an amount.
    /// Empty for a Burn.
    pub outputs: Vec<TransitionOutput>,
    /// Asset units that this transition destroys, from the BFA
    /// `MS_BURNED_ASSET` metadata. The schema allows `Some(0)`, but the EVM
    /// cross-check requires a positive value to sign an unlock.
    ///
    /// `None` for a non-burn, or for a malformed burn (rgbstd rejects it).
    pub burned_asset_amount: Option<u64>,
    /// EVM-side recipient of the burn proceeds, from the BFA
    /// `MS_BURN_RECIPIENT` metadata: exactly 32 bytes, as the schema requires.
    /// `None` for a non-burn.
    pub burn_recipient: Option<Vec<u8>>,
}

/// One fungible output assignment on a state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionOutput {
    /// BFA assignment type ([`bfa::OS_ASSET`] or [`bfa::OS_BRIDGE`]).
    /// Only `OS_ASSET` entries carry asset units. The per-output recipient
    /// bind must filter on it, as `asset_output_amount` does.
    pub assignment_type: u16,
    /// Amount in the smallest unit of the asset.
    pub amount: u64,
    /// Destination seal: a revealed `txid:vout` or a hidden commitment.
    pub seal: OutputSeal,
}

/// The seal of a fungible output. Mirrors `rgb_consignment::SealInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputSeal {
    /// Concrete `txid:vout`. `txid` is `None` if the seal points to the
    /// witness tx of its bundle. Then use the bundle witness txid.
    Revealed {
        /// Display-order bytes, as in `witness_txids`.
        txid: Option<[u8; 32]>,
        vout: u32,
    },
    /// Hidden recipient seal (`utxob:...` SHA-256 commitment string).
    Confidential { secret_seal: String },
}
