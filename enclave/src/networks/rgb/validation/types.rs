//! What a validated consignment is reduced to.
//!
//! Plain data. Everything here has already passed rgbstd validation, so the
//! rest of the enclave reads these shapes instead of re-parsing RGB.

/// Data extracted from a successfully validated RGB consignment.
#[derive(Debug, Clone)]
pub struct ValidatedConsignment {
    /// RGB contract identifier (e.g., "rgb:2TGhRyP3-..."). Globally unique
    /// per asset; derived from the genesis operation in RGB 0.11.
    pub contract_id: String,
    /// Bitcoin network the consignment is anchored to, in rgbstd's prefix
    /// form: `"bc"`, `"bc:testnet3"`/`"tb"`, `"bc:signet"`/`"sb"`, or `"bc:regtest"`.
    /// Used to reject cross-network replay (e.g. a regtest consignment
    /// presented to a mainnet enclave).
    pub chain_net: String,
    /// Bitcoin txids that anchor each transition bundle in the consignment,
    /// in **display (big-endian) byte order** - same encoding as
    /// `MerkleProofEntry.txid` on the wire. Deduplicated and sorted so
    /// equality checks against the listener's set are stable.
    pub witness_txids: Vec<[u8; 32]>,
    /// Every state-transition `op_id` in the consignment, in witness order
    /// (bundle k's transitions before bundle k+1's). Spec section 6 requires
    /// every mint OpId committed to EVM state to be cross-checked across RGB
    /// validations.
    pub all_op_ids: Vec<String>,
    /// The `op_id`s of every BFA `TS_BRIDGE` (mint) transition in the
    /// consignment, in witness order - the subset of [`Self::all_op_ids`]
    /// that corresponds to EVM lock records (`fundsIn`).
    ///
    /// Not currently consumed by the EVM side: on the route-agnostic Bridge
    /// the `fundsOut` citation comes from deposit receipts and is enforced
    /// on-chain by `RgbSettlementModule.beforeFundsOut`. Kept as the RGB half
    /// of that correspondence.
    pub mint_op_ids: Vec<String>,
    /// The most recent state transition: the state change the EVM action this
    /// consignment authorises commits to. `None` only for malformed transfers
    /// with no transition bundles, which rgbstd rejects upstream.
    pub last_transition: Option<TransitionSummary>,
    /// Bitcoin txid of the witness transaction anchoring the last transition,
    /// whatever its transition type (burn included).
    ///
    /// Two consumers. In the send-RGB direction the PSBT being signed IS that
    /// witness tx, and the PSBT cross-check binds
    /// `psbt.unsigned_tx.compute_txid()` to this after gating on the last
    /// transition being a Transfer or Bridge. The RGB->EVM `fundsOut`
    /// source-block bind uses it ungated, so it works for transfer and burn
    /// alike.
    ///
    /// A `bitcoin::Txid` rather than display-order bytes, to avoid the txid
    /// byte-order footgun. `None` only for a consignment with no bundles.
    pub last_witness_txid: Option<bitcoin::Txid>,
    /// Bitcoin input prevouts of that witness transaction, when the
    /// consignment embeds the full tx (`PubWitness::Tx`). Used by the PSBT
    /// cross-check as a redundant per-input canary over the txid bind. `None`
    /// for `PubWitness::Txid`, where the txid bind alone anchors every input.
    pub last_transfer_witness_prevouts: Option<Vec<bitcoin::OutPoint>>,
    /// Authoritative OpId (32-byte commitment hash) of the consignment's
    /// **last** transition, read from the rgbstd-**validated** `Transfer`
    /// (`KnownTransition.opid` of the same last bundle as
    /// `last_witness_txid`), NOT from the flat `rgb_consignment`
    /// parser. This is the value `validate()` authenticated and anchored on
    /// chain.
    ///
    /// No longer feeds the EVM `fundsOut` `burnId`: the new
    /// Bridge derives that itself and reverts `InvalidBurnId` otherwise. `None`
    /// for a consignment with no bundles or a non-Transfer last transition.
    pub last_transfer_op_id: Option<[u8; 32]>,
    /// Witness txids that rgbstd `validate()` classified as **not mined**
    /// (`WitnessOrd::Tentative` / `Ignored`), in **display (big-endian) byte
    /// order** - same encoding as [`Self::witness_txids`]. `validate()` already
    /// hard-rejects `Archived`/unresolvable witnesses, so only these softer
    /// not-yet-confirmed states reach here, and only because this set is built
    /// from the rgbstd status that was previously discarded.
    ///
    /// A non-empty set is **expected** for the send-RGB (EVM-lock -> RGB-send)
    /// PSBT path: that witness tx is freshly composed and unbroadcast, so it is
    /// legitimately `Tentative`. It is an **anomaly** for the RGB->EVM
    /// `fundsOut` direction, where the witness is already confirmed on-chain
    /// and SPV-verified - the SignEvm path rejects any non-mined witness as
    /// defense-in-depth atop the SPV depth check (see
    /// `evm::validation::assert_witnesses_confirmed`).
    pub non_mined_witness_txids: Vec<[u8; 32]>,
    /// Every transition in the consignment, grouped by the witness tx that
    /// commits it.
    ///
    /// A single Bitcoin transaction commits a bundle, which may hold several
    /// transitions. Binding only [`Self::last_transition`] would let an
    /// attacker park a large transfer earlier in the bundle, so the send-RGB
    /// PSBT cross-check binds the whole group via
    /// [`Self::transitions_committed_by`].
    pub transitions_by_witness: Vec<(bitcoin::Txid, Vec<TransitionSummary>)>,
}

impl ValidatedConsignment {
    /// Every transition committed by witness transaction `txid`.
    ///
    /// Empty when the consignment commits nothing to that transaction - which
    /// callers must treat as a rejection, not as "nothing to check".
    pub fn transitions_committed_by(&self, txid: bitcoin::Txid) -> Vec<&TransitionSummary> {
        self.transitions_by_witness
            .iter()
            .filter(|(witness_txid, _)| *witness_txid == txid)
            .flat_map(|(_, transitions)| transitions.iter())
            .collect()
    }
}

/// Flat summary of one RGB state transition. Mirrors
/// `rgb_consignment::TransitionInfo` but in types we own, so the parser dep
/// doesn't leak into our public surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionSummary {
    /// Operation id: 64-char lowercase hex of the 32-byte RGB OpId, as the
    /// parser yields it. The hex form is load-bearing, not baid64 -
    /// `evm::crosscheck::decode_op_id_to_bytes32` decodes it to 32 bytes.
    pub op_id: String,
    /// BFA-schema transition-type id; compare against [`bfa::TS_TRANSFER`]
    /// / [`bfa::TS_BURN`] / [`bfa::TS_BRIDGE`] to classify the EVM
    /// action this consignment authorises.
    pub transition_type: u16,
    /// Sum of all fungible amounts across all output assignments of this
    /// transition. For a Transfer this is the total of recipient + change
    /// outputs; for a Burn this is **zero** because burns have no output
    /// assignments - the destroyed amount lives in [`Self::burned_asset_amount`].
    pub total_output_amount: u64,
    /// Sum of the fungible amounts on `OS_ASSET`-typed output assignments
    /// only - the allocations that actually carry asset units. For a
    /// Transfer this equals [`Self::total_output_amount`] (transfers move
    /// only `OS_ASSET`); for a Bridge (mint) it is the freshly minted
    /// value, **excluding** the declarative `OS_BRIDGE` output, which carries
    /// the mint right and no asset units.
    pub asset_output_amount: u64,
    /// Concrete output assignments, each tagged with a destination seal
    /// and an amount. Empty for Burn transitions.
    pub outputs: Vec<TransitionOutput>,
    /// Asset units destroyed by this transition, from the BFA
    /// `MS_BURNED_ASSET` metadata field. `Some(0)` is schema-legal, but the
    /// EVM cross-check layer requires it strictly positive to sign an unlock.
    ///
    /// `None` when the transition is not a burn, or when a burn transition is
    /// malformed (which rgbstd validation should already have rejected).
    pub burned_asset_amount: Option<u64>,
    /// Where the burn's proceeds are owed on the EVM side, from the BFA
    /// `MS_BURN_RECIPIENT` metadata field: exactly 32 bytes, as the schema
    /// requires. `None` for a non-burn.
    pub burn_recipient: Option<Vec<u8>>,
}

/// One fungible output assignment on a state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionOutput {
    /// BFA assignment type ([`bfa::OS_ASSET`] or [`bfa::OS_BRIDGE`]).
    /// Load-bearing: only `OS_ASSET` entries carry asset units, so the
    /// per-output recipient bind must filter on this just as
    /// `asset_output_amount` does.
    pub assignment_type: u16,
    /// Amount in the asset's smallest unit.
    pub amount: u64,
    /// Destination seal - either a revealed `txid:vout` or a hidden
    /// commitment.
    pub seal: OutputSeal,
}

/// Where a fungible output lives. Mirrors `rgb_consignment::SealInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputSeal {
    /// Concrete `txid:vout`. `txid` is `None` when the seal points at the
    /// witness tx of its containing bundle - resolve by combining with
    /// the bundle's witness txid in display order.
    Revealed {
        /// Display-order bytes - matches `witness_txids` encoding.
        txid: Option<[u8; 32]>,
        vout: u32,
    },
    /// Hidden recipient seal (`utxob:...` SHA-256 commitment string).
    Confidential { secret_seal: String },
}
