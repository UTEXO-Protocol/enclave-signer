//! SPV cross-check: verify the consignment's witness Bitcoin transactions
//! are included in the in-enclave header chain with sufficient confirmations.
//!
//! Before signing an EVM unlock this gate demands:
//!
//! 1. **Coverage**: every witness txid extracted from the consignment is
//!    backed by a `MerkleProofEntry` from the listener - and there are no
//!    extra unrelated proofs. Set equality, both directions.
//! 2. **Cross-network**: the consignment's `chain_net` matches the network
//!    the enclave is compiled for. Catches "regtest consignment replayed
//!    against mainnet enclave".
//! 3. **Inclusion**: every Merkle proof reconstructs to the `merkle_root`
//!    committed in the header at `block_height` we have stored.
//! 4. **Confirmation depth**: every witness tx (not just the burn) must be
//!    at least `SPV_MIN_CONFIRMATIONS` deep - bridge spec section 11 explicitly
//!    forbids relying only on the most recent anchoring transaction.
//!
//! Byte order: `MerkleProofEntry.txid` and `.merkle_path` arrive in display
//! (big-endian) order, while `spv::merkle` works in internal (little-endian)
//! order. Conversion happens once per hash, at the `verify_one_proof`
//! boundary. Coverage checking stays in display order on both sides.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::hashes::Hash;
use rgbstd::ChainNet;

use crate::error::{EnclaveError, Result};
use crate::networks::rgb::spv::{verify_merkle_proof, HeaderChain, MerkleError, Network};
use crate::proto::MerkleProofEntry;

use super::validation::ValidatedConsignment;

/// Confirmation depth required before the enclave will sign. Compile-time, not
/// env-driven: a host-set value of 0 would bypass SPV while attestation still
/// passed.
pub const SPV_MIN_CONFIRMATIONS: u32 = 6;

/// Maximum age of the chain tip's `time`, in seconds. An older tip means the
/// enclave refuses to sign: defense against a listener feeding real-but-old
/// headers that never reach the real chain head.
///
/// 2 hours is generous - the listener pushes every ~30s, and even mainnet's
/// 10-minute target leaves legitimate gaps well short of it.
pub const SPV_MAX_TIP_AGE_SECS: u64 = 2 * 60 * 60;

/// Bitcoin consensus allows a block `time` up to ~2 hours ahead of
/// network-adjusted time. That grace is accepted; beyond it a header with
/// `time = far_future` would defeat the staleness check.
pub const SPV_MAX_TIP_FUTURE_SECS: u64 = 2 * 60 * 60;

/// Maximum sibling hashes in a single Merkle path. Depth d authenticates up to
/// 2^d transactions, and a 4 MB block holds well under 2^17, so 32 never
/// false-rejects a real proof while bounding the hashing a hostile listener can
/// demand. Checked in `validate_spv_proofs` before any hashing runs (audit
/// I-06 / #90). Compile-time and PCR-attested, not host-tunable.
pub const MAX_MERKLE_PATH_DEPTH: usize = 32;

/// Validate the RGB source's Bitcoin anchoring before signing.
///
/// The caller passes the already-validated consignment and the listener's
/// Merkle proofs; this checks chain freshness, network binding, inclusion, and
/// confirmation depth.
pub fn validate_source_chain(
    chain: &HeaderChain,
    validated_consignment: Option<&ValidatedConsignment>,
    merkle_proofs: &[MerkleProofEntry],
    now: SystemTime,
) -> Result<()> {
    let validated = validated_consignment.ok_or_else(|| {
        EnclaveError::Spv(
            "spv: RGB source requires a non-empty validated consignment, \
             but the request had no consignment bytes (or the validator \
             is not configured)"
                .into(),
        )
    })?;

    assert_chain_not_stale(
        chain,
        now,
        Duration::from_secs(SPV_MAX_TIP_AGE_SECS),
        Duration::from_secs(SPV_MAX_TIP_FUTURE_SECS),
    )?;
    assert_chain_net(&validated.chain_net, chain.network())?;
    validate_spv_proofs(
        chain,
        &validated.witness_txids,
        merkle_proofs,
        SPV_MIN_CONFIRMATIONS,
    )?;

    tracing::info!(
        proofs_count = merkle_proofs.len(),
        "SPV verification passed"
    );

    Ok(())
}

/// Verify a complete set of SPV proofs against the chain.
///
/// `expected_txids` is the witness-txid set extracted from the validated
/// RGB consignment, in **display byte order** (matches the wire format of
/// `MerkleProofEntry.txid`). `proofs` are exactly the entries the listener
/// supplied on the wire.
pub fn validate_spv_proofs(
    chain: &HeaderChain,
    expected_txids: &[[u8; 32]],
    proofs: &[MerkleProofEntry],
    min_confirmations: u32,
) -> Result<()> {
    // 1. Coverage: build sets in display order, compare both ways.
    let expected_set: BTreeSet<[u8; 32]> = expected_txids.iter().copied().collect();
    let mut proof_set: BTreeSet<[u8; 32]> = BTreeSet::new();

    for (i, proof) in proofs.iter().enumerate() {
        let txid: [u8; 32] = proof.txid.as_slice().try_into().map_err(|_| {
            EnclaveError::Spv(format!(
                "merkle_proofs[{i}].txid must be 32 bytes, got {}",
                proof.txid.len()
            ))
        })?;
        // Bound per-proof hashing before it starts: a path deeper than any
        // real block is a bug or a work-amplification attempt (audit I-06 /
        // #90).
        if proof.merkle_path.len() > MAX_MERKLE_PATH_DEPTH {
            return Err(EnclaveError::Spv(format!(
                "merkle_proofs[{i}].merkle_path too deep: {} siblings (max {})",
                proof.merkle_path.len(),
                MAX_MERKLE_PATH_DEPTH
            )));
        }
        if !proof_set.insert(txid) {
            return Err(EnclaveError::Spv(format!(
                "duplicate merkle proof for txid {}",
                hex::encode(txid)
            )));
        }
        if !expected_set.contains(&txid) {
            return Err(EnclaveError::Spv(format!(
                "merkle proof for txid {} does not match any consignment witness txid",
                hex::encode(txid)
            )));
        }
    }

    if proof_set.len() != expected_set.len() {
        // expected_set  strictly contains  proof_set (we already rejected anything in
        // proof_set  minus  expected_set above). Find what's missing for a
        // useful error.
        let missing: Vec<String> = expected_set
            .difference(&proof_set)
            .map(hex::encode)
            .collect();
        return Err(EnclaveError::Spv(format!(
            "missing merkle proofs for {} witness txid(s): {}",
            missing.len(),
            missing.join(", ")
        )));
    }

    // 2. Per-proof: header lookup, confirmation depth, Merkle inclusion.
    let tip = chain.tip_height();
    for (i, proof) in proofs.iter().enumerate() {
        verify_one_proof(chain, tip, min_confirmations, i, proof)?;
    }

    Ok(())
}

/// Refuse to sign if the chain tip is too old, or anomalously in the future,
/// against wall clock. `now` is injected for testability; production passes
/// `SystemTime::now()`.
///
/// Threat model: a listener serving real-but-old headers from the checkpoint
/// forward produces a chain that validates perfectly while the tip stays stuck
/// in the past, making an old block look well confirmed.
pub fn assert_chain_not_stale(
    chain: &HeaderChain,
    now: SystemTime,
    max_age: Duration,
    max_future: Duration,
) -> Result<()> {
    let now_unix = now
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EnclaveError::Internal(format!("system clock is before UNIX_EPOCH: {e}")))?
        .as_secs();
    let tip_time = u64::from(chain.tip_time());

    // Future-bound: a tip claiming to be far ahead of now is anomalous.
    // Bitcoin's consensus rule allows ~2h of future skew per block; we
    // reject anything beyond.
    if let Some(future_skew) = tip_time.checked_sub(now_unix) {
        if future_skew > max_future.as_secs() {
            return Err(EnclaveError::Spv(format!(
                "spv: chain tip is {future_skew}s in the future (now = {now_unix}, \
                 tip_time = {tip_time}, max future skew = {}s)",
                max_future.as_secs()
            )));
        }
        // Else: in-bounds future skew, OK.
        return Ok(());
    }

    // Past-bound: tip is in the past (the normal case). Check it isn't
    // too far back.
    let age = now_unix.saturating_sub(tip_time);
    if age > max_age.as_secs() {
        return Err(EnclaveError::Spv(format!(
            "spv: chain tip is too stale (now = {now_unix}, tip_time = {tip_time}, \
             age = {age}s, max age = {}s) — listener may be frozen or hostile",
            max_age.as_secs()
        )));
    }

    Ok(())
}

/// Cross-network replay defense: assert the consignment's `chain_net`
/// prefix (e.g. `"sb"` for signet) is the one this enclave is compiled for.
///
/// The expected value is derived from [`ChainNet::prefix()`] - the same
/// rgb-core code that produces the consignment-side string in
/// `validation::rgb` (`transfer.genesis.chain_net.prefix()`) - so the two
/// sides cannot drift apart on notation.
///
/// rgbstd's full validation also enforces this when `rgb-validation` is on,
/// but we re-assert at the SPV layer so a future configuration change that
/// loosens rgbstd validation (e.g. accepting an unresolved consignment for
/// some niche flow) can never accidentally let a wrong-network consignment
/// reach the signing path.
pub fn assert_chain_net(consignment_chain_net: &str, enclave_network: Network) -> Result<()> {
    let chain_net = expected_chain_net(enclave_network);
    let expected = chain_net.prefix();
    if consignment_chain_net != expected {
        return Err(EnclaveError::Spv(format!(
            "consignment chain_net {consignment_chain_net:?} does not match \
             enclave network {enclave_network:?} (expected {expected:?})"
        )));
    }
    Ok(())
}

/// The rgb-core [`ChainNet`] this enclave accepts consignments for.
///
/// Mirrors the `bitcoin_network` -> `ChainNet` mapping in
/// `validation::rgb::RgbValidator::new`. Plain `BitcoinSignet` also covers
/// our custom signet: the challenge script differs, but the rgb-core chain
/// identity (and thus the consignment prefix) is the same `"sb"`.
fn expected_chain_net(network: Network) -> ChainNet {
    match network {
        Network::Mainnet => ChainNet::BitcoinMainnet,
        Network::Signet => ChainNet::BitcoinSignet,
        Network::Testnet3 => ChainNet::BitcoinTestnet3,
        Network::Regtest => ChainNet::BitcoinRegtest,
    }
}

fn verify_one_proof(
    chain: &HeaderChain,
    tip: u32,
    min_confirmations: u32,
    index: usize,
    proof: &MerkleProofEntry,
) -> Result<()> {
    // Header lookup. `header_at` returns None for heights at-or-below
    // checkpoint (we don't store the checkpoint header itself) and for
    // heights beyond the tip - both are rejection cases here.
    let header = chain.header_at(proof.block_height).ok_or_else(|| {
        EnclaveError::Spv(format!(
            "merkle_proofs[{index}]: no header at height {} (chain tip = {})",
            proof.block_height, tip
        ))
    })?;

    // Confirmation depth, with checked arithmetic. A hostile listener can
    // send `block_height = u32::MAX`, which without the check would
    // underflow on `tip - block_height`.
    let confs = tip
        .checked_sub(proof.block_height)
        .and_then(|d| d.checked_add(1))
        .ok_or_else(|| {
            EnclaveError::Spv(format!(
                "merkle_proofs[{index}]: block_height {} is beyond chain tip {}",
                proof.block_height, tip
            ))
        })?;
    if confs < min_confirmations {
        return Err(EnclaveError::Spv(format!(
            "merkle_proofs[{index}]: insufficient confirmations for block_height {} \
             ({confs} < {min_confirmations})",
            proof.block_height
        )));
    }

    // Reverse display-order bytes to internal-order for the Merkle verifier.
    let mut txid_internal: [u8; 32] = proof.txid.as_slice().try_into().map_err(|_| {
        EnclaveError::Spv(format!(
            "merkle_proofs[{index}].txid must be 32 bytes (already validated above; defensive)"
        ))
    })?;
    txid_internal.reverse();

    let mut path_internal: Vec<[u8; 32]> = Vec::with_capacity(proof.merkle_path.len());
    for (j, sib) in proof.merkle_path.iter().enumerate() {
        let mut s: [u8; 32] = sib.as_slice().try_into().map_err(|_| {
            EnclaveError::Spv(format!(
                "merkle_proofs[{index}].merkle_path[{j}] must be 32 bytes, got {}",
                sib.len()
            ))
        })?;
        s.reverse();
        path_internal.push(s);
    }

    // header.merkle_root is a TxMerkleNode wrapping sha256d::Hash -
    // its as_byte_array() is internal order, matching what verify_merkle_proof
    // wants.
    let merkle_root_internal: [u8; 32] = header.merkle_root.to_byte_array();

    verify_merkle_proof(
        &txid_internal,
        proof.tx_position,
        &path_internal,
        &merkle_root_internal,
    )
    .map_err(|e| match e {
        MerkleError::RootMismatch { computed, expected } => {
            // Display-order hex for human readability - these are end-user
            // diagnostic hashes, not bytes used in further computation.
            let mut c = computed;
            c.reverse();
            let mut x = expected;
            x.reverse();
            EnclaveError::Spv(format!(
                "merkle_proofs[{index}]: proof for txid {} failed: \
                 computed root {} != header root {} at block_height {}",
                hex::encode(proof.txid.as_slice()),
                hex::encode(c),
                hex::encode(x),
                proof.block_height,
            ))
        }
        MerkleError::BadSiblingLength { index: j, len } => EnclaveError::Spv(format!(
            "merkle_proofs[{index}].merkle_path[{j}] has wrong length {len}"
        )),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networks::rgb::spv::checkpoint::Checkpoint;
    use crate::networks::rgb::spv::HeaderChain;
    use crate::proto::MerkleProofEntry;
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::{sha256d, Hash};

    /// Builds a regtest synthetic chain rooted at a zero checkpoint. We use
    /// regtest so PoW is skipped - these tests focus on the SPV crosscheck
    /// logic, not header validation (PR 2 covers that).
    fn regtest_chain_with(headers: Vec<Header>) -> HeaderChain {
        let mut chain = HeaderChain::new(
            Network::Regtest,
            Checkpoint {
                height: 0,
                hash: [0u8; 32],
                bits: 0x207fffff,
                time: 1_700_000_000,
                is_real: false,
            },
        );
        let raw_headers: Vec<Vec<u8>> = headers.iter().map(serialize).collect();
        chain.submit_headers(1, &raw_headers).unwrap();
        chain
    }

    /// Build N synthetic regtest headers chaining from a zero prev_blockhash.
    /// Each header has a deterministic, distinct merkle_root so we can test
    /// proofs against a known root.
    fn synth_headers(count: u32) -> Vec<Header> {
        let mut prev = bitcoin::BlockHash::from_byte_array([0u8; 32]);
        let mut out = Vec::new();
        for i in 0..count {
            let mut root_bytes = [0u8; 32];
            root_bytes[0] = i as u8;
            root_bytes[1] = 0xAB;
            let header = Header {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array(root_bytes),
                time: 1_700_000_001 + i,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: i,
            };
            prev = header.block_hash();
            out.push(header);
        }
        out
    }

    /// For a single-tx block, the Merkle root IS the txid (in internal
    /// order). To make a working "happy path" proof we use this fact.
    /// Returns (display-order txid, MerkleProofEntry).
    fn single_tx_proof(header: &Header, block_height: u32) -> ([u8; 32], MerkleProofEntry) {
        // header.merkle_root is internal-order. The txid that produces it
        // (single-tx block, empty path) is the same bytes. Display-order
        // is the reverse.
        let internal: [u8; 32] = header.merkle_root.to_byte_array();
        let mut display = internal;
        display.reverse();
        let entry = MerkleProofEntry {
            txid: display.to_vec(),
            block_height,
            tx_position: 0,
            merkle_path: vec![],
        };
        (display, entry)
    }

    fn dsha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(left);
        buf[32..].copy_from_slice(right);
        sha256d::Hash::hash(&buf).to_byte_array()
    }

    /// Bundle of test fixtures for a 2-tx block - used by both happy and
    /// rejection paths. Factored into a struct to keep clippy happy with
    /// the `type_complexity` lint (which would otherwise fire on a 5-tuple
    /// return).
    struct TwoTxBlock {
        header: Header,
        txid0_display: [u8; 32],
        txid1_display: [u8; 32],
        path_for_tx0: Vec<Vec<u8>>,
        path_for_tx1: Vec<Vec<u8>>,
    }

    /// Set up a 2-tx block: leaf0 + leaf1 -> root. Header points at root.
    fn build_two_tx_block(
        leaf0_internal: [u8; 32],
        leaf1_internal: [u8; 32],
        prev_blockhash: bitcoin::BlockHash,
        time: u32,
    ) -> TwoTxBlock {
        let root_internal = dsha256_pair(&leaf0_internal, &leaf1_internal);
        let header = Header {
            version: Version::ONE,
            prev_blockhash,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array(root_internal),
            time,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        };
        let mut txid0_display = leaf0_internal;
        txid0_display.reverse();
        let mut txid1_display = leaf1_internal;
        txid1_display.reverse();
        let mut sib1_display = leaf1_internal;
        sib1_display.reverse();
        let mut sib0_display = leaf0_internal;
        sib0_display.reverse();
        TwoTxBlock {
            header,
            txid0_display,
            txid1_display,
            path_for_tx0: vec![sib1_display.to_vec()],
            path_for_tx1: vec![sib0_display.to_vec()],
        }
    }

    /// Helper: build a chain of `confirmations` headers where the header at
    /// height 1 has the merkle commitment we care about; subsequent headers
    /// are throwaway (they just bury the target block deep enough).
    fn chain_burying(target_header: Header, depth_above: u32) -> HeaderChain {
        let base_time = target_header.time;
        let mut headers = vec![target_header];
        let mut prev = headers[0].block_hash();
        for i in 0..depth_above {
            let h = Header {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: base_time + 1 + i,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            };
            prev = h.block_hash();
            headers.push(h);
        }
        regtest_chain_with(headers)
    }

    #[test]
    fn happy_path_single_tx_block_with_six_confirmations() {
        // 1 target block + 5 burying = 6 confirmations.
        let target = synth_headers(1).into_iter().next().unwrap();
        let chain = chain_burying(target, 5);
        let (txid_display, proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);

        validate_spv_proofs(&chain, &[txid_display], &[proof], SPV_MIN_CONFIRMATIONS).unwrap();
    }

    /// Regression for #130: an anchor far below `tip - HEADER_WINDOW` (~2122)
    /// still verifies. The old sliding window pruned the anchor's header, so
    /// SPV rejected every RGB consignment whose oldest witness was older than
    /// ~a day on 30s-block signet ("no header at height H (chain tip = T)").
    /// With full retention from the checkpoint the header resolves and the
    /// proof passes.
    #[test]
    fn deep_anchor_below_old_window_still_verifies() {
        let target = synth_headers(1).into_iter().next().unwrap();
        // Derive the proof from the target before it is moved into the chain.
        let (txid_display, proof) = single_tx_proof(&target, 1);
        // Bury the target deep enough that the OLD sliding window would have
        // pruned its header: prune_front advanced the base to
        // floor_2016(tip - 2122), dropping the anchor at height 1 once that
        // base >= 1 (tip >= 4138). 4200 buries it comfortably past that point,
        // so this test genuinely fails on the pruning code and guards against
        // its reintroduction.
        let chain = chain_burying(target, 4200);
        let tip = chain.tip_height();
        let old_window = 100 + 2016 + 6; // former HEADER_WINDOW
        let old_pruned_base = (tip.saturating_sub(old_window) / 2016) * 2016;
        assert!(
            old_pruned_base >= 1,
            "precondition: the old window would have pruned the anchor at height 1 \
             (tip={tip}, old_pruned_base={old_pruned_base})"
        );

        validate_spv_proofs(&chain, &[txid_display], &[proof], SPV_MIN_CONFIRMATIONS).unwrap();
    }

    #[test]
    fn rejects_insufficient_confirmations() {
        // Only 3 confirmations < 6.
        let target = synth_headers(1).into_iter().next().unwrap();
        let chain = chain_burying(target, 2);
        let (txid_display, proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);

        let err = validate_spv_proofs(&chain, &[txid_display], &[proof], SPV_MIN_CONFIRMATIONS)
            .unwrap_err();
        assert!(
            err.to_string().contains("insufficient confirmations"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_block_height_beyond_tip() {
        let target = synth_headers(1).into_iter().next().unwrap();
        let chain = chain_burying(target, 5);
        let (txid_display, mut proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);
        proof.block_height = chain.tip_height() + 100;

        let err = validate_spv_proofs(&chain, &[txid_display], &[proof], SPV_MIN_CONFIRMATIONS)
            .unwrap_err();
        // Either "no header at height" (because we don't store > tip) or
        // "beyond chain tip" (the explicit underflow catch). Both are
        // acceptable rejections.
        let msg = err.to_string();
        assert!(
            msg.contains("no header") || msg.contains("beyond"),
            "got: {msg}"
        );
    }

    #[test]
    fn rejects_block_height_at_checkpoint_or_below() {
        let target = synth_headers(1).into_iter().next().unwrap();
        let chain = chain_burying(target, 5);
        let (txid_display, mut proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);
        proof.block_height = 0; // checkpoint height — we don't store its header

        let err = validate_spv_proofs(&chain, &[txid_display], &[proof], SPV_MIN_CONFIRMATIONS)
            .unwrap_err();
        assert!(
            err.to_string().contains("no header at height"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_extra_proof_for_unknown_txid() {
        // We expect ONE txid, listener supplies that one PLUS a second
        // unrelated proof. That extra proof must cause rejection - the
        // contract is set equality.
        let target = synth_headers(1).into_iter().next().unwrap();
        let chain = chain_burying(target, 5);
        let (txid_display, proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);

        let bogus_txid = [0xCC; 32];
        let bogus_proof = MerkleProofEntry {
            txid: bogus_txid.to_vec(),
            block_height: 1,
            tx_position: 0,
            merkle_path: vec![],
        };

        let err = validate_spv_proofs(
            &chain,
            &[txid_display],
            &[proof, bogus_proof],
            SPV_MIN_CONFIRMATIONS,
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not match any"), "got: {err}");
    }

    #[test]
    fn rejects_missing_proof_for_expected_txid() {
        let target = synth_headers(1).into_iter().next().unwrap();
        let chain = chain_burying(target, 5);
        let (txid_display, _proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);

        // Expected has TWO txids; listener provides ZERO proofs.
        let extra_txid = [0xEE; 32];
        let err = validate_spv_proofs(
            &chain,
            &[txid_display, extra_txid],
            &[],
            SPV_MIN_CONFIRMATIONS,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("missing merkle proofs"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_duplicate_proof() {
        let target = synth_headers(1).into_iter().next().unwrap();
        let chain = chain_burying(target, 5);
        let (txid_display, proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);

        let err = validate_spv_proofs(
            &chain,
            &[txid_display],
            &[proof.clone(), proof],
            SPV_MIN_CONFIRMATIONS,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("duplicate merkle proof"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_bad_merkle_path() {
        // Build a 2-tx block, supply the right proof shape but with a
        // wrong sibling - root reconstruction should mismatch.
        let leaf0 = [0x10u8; 32];
        let leaf1 = [0x20u8; 32];
        let prev = bitcoin::BlockHash::from_byte_array([0u8; 32]);
        let block = build_two_tx_block(leaf0, leaf1, prev, 1_700_000_001);

        let chain = chain_burying(block.header, 5);

        // Supply a path with the WRONG sibling (all zeros instead of leaf1).
        let proof = MerkleProofEntry {
            txid: block.txid0_display.to_vec(),
            block_height: 1,
            tx_position: 0,
            merkle_path: vec![vec![0u8; 32]],
        };

        let err = validate_spv_proofs(
            &chain,
            &[block.txid0_display],
            &[proof],
            SPV_MIN_CONFIRMATIONS,
        )
        .unwrap_err();
        assert!(err.to_string().contains("computed root"), "got: {err}");
    }

    #[test]
    fn happy_path_two_tx_block() {
        let leaf0 = [0x10u8; 32];
        let leaf1 = [0x20u8; 32];
        let prev = bitcoin::BlockHash::from_byte_array([0u8; 32]);
        let block = build_two_tx_block(leaf0, leaf1, prev, 1_700_000_001);

        let chain = chain_burying(block.header, 5);

        let proof0 = MerkleProofEntry {
            txid: block.txid0_display.to_vec(),
            block_height: 1,
            tx_position: 0,
            merkle_path: block.path_for_tx0,
        };
        let proof1 = MerkleProofEntry {
            txid: block.txid1_display.to_vec(),
            block_height: 1,
            tx_position: 1,
            merkle_path: block.path_for_tx1,
        };

        validate_spv_proofs(
            &chain,
            &[block.txid0_display, block.txid1_display],
            &[proof0, proof1],
            SPV_MIN_CONFIRMATIONS,
        )
        .unwrap();
    }

    #[test]
    fn rejects_short_txid_in_proof() {
        let target = synth_headers(1).into_iter().next().unwrap();
        let chain = chain_burying(target, 5);
        let bad_proof = MerkleProofEntry {
            txid: vec![0u8; 16], // not 32 bytes
            block_height: 1,
            tx_position: 0,
            merkle_path: vec![],
        };

        let err = validate_spv_proofs(&chain, &[[0u8; 32]], &[bad_proof], SPV_MIN_CONFIRMATIONS)
            .unwrap_err();
        assert!(err.to_string().contains("must be 32 bytes"), "got: {err}");
    }

    #[test]
    fn rejects_short_merkle_path_entry() {
        let target = synth_headers(1).into_iter().next().unwrap();
        let chain = chain_burying(target, 5);
        let (txid_display, _proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);

        let bad_proof = MerkleProofEntry {
            txid: txid_display.to_vec(),
            block_height: 1,
            tx_position: 0,
            merkle_path: vec![vec![0u8; 16]], // not 32 bytes
        };

        let err = validate_spv_proofs(&chain, &[txid_display], &[bad_proof], SPV_MIN_CONFIRMATIONS)
            .unwrap_err();
        assert!(err.to_string().contains("must be 32 bytes"), "got: {err}");
    }

    #[test]
    fn rejects_overdeep_merkle_path() {
        // A path deeper than any real block could produce is rejected before
        // any Merkle hashing runs (audit I-06 / #90). Siblings are well-formed
        // 32-byte hashes so the only failing predicate is the depth cap.
        let target = synth_headers(1).into_iter().next().unwrap();
        let chain = chain_burying(target, 5);
        let (txid_display, _proof) = single_tx_proof(chain.header_at(1).unwrap(), 1);

        let bad_proof = MerkleProofEntry {
            txid: txid_display.to_vec(),
            block_height: 1,
            tx_position: 0,
            merkle_path: vec![vec![0u8; 32]; MAX_MERKLE_PATH_DEPTH + 1],
        };

        let err = validate_spv_proofs(&chain, &[txid_display], &[bad_proof], SPV_MIN_CONFIRMATIONS)
            .unwrap_err();
        assert!(err.to_string().contains("too deep"), "got: {err}");
    }

    #[test]
    fn assert_chain_net_accepts_matching_pair() {
        // Literal prefixes on purpose (not derived from `ChainNet::prefix()`):
        // if an rgb-core upgrade ever changes the notation, this test must
        // fail loudly instead of the contract silently shifting.
        assert_chain_net("bc", Network::Mainnet).unwrap();
        assert_chain_net("sb", Network::Signet).unwrap();
        assert_chain_net("tb3", Network::Testnet3).unwrap();
        assert_chain_net("bcrt", Network::Regtest).unwrap();
    }

    #[test]
    fn assert_chain_net_rejects_mismatch() {
        let err = assert_chain_net("bcrt", Network::Mainnet).unwrap_err();
        assert!(err.to_string().contains("does not match"), "got: {err}");

        let err = assert_chain_net("bc", Network::Signet).unwrap_err();
        assert!(err.to_string().contains("does not match"), "got: {err}");

        // Regression: "bc:signet"-style notation is not what consignments
        // carry (`genesis.chain_net.prefix()` yields `"sb"`); it used to be
        // hardcoded as the expected value and blocked every signet sign.
        let err = assert_chain_net("bc:signet", Network::Signet).unwrap_err();
        assert!(err.to_string().contains("does not match"), "got: {err}");
    }

    #[test]
    fn empty_expected_and_empty_proofs_is_ok() {
        // A consignment with no witness bundles (degenerate) and no proofs
        // is trivially OK - there's nothing to verify. Useful sanity check
        // that we don't iterate an empty set into a panic.
        let target = synth_headers(1).into_iter().next().unwrap();
        let chain = chain_burying(target, 5);
        validate_spv_proofs(&chain, &[], &[], SPV_MIN_CONFIRMATIONS).unwrap();
    }

    // ===== Staleness tests =====
    //
    // These hand `assert_chain_not_stale` an explicit `now` so the test
    // doesn't depend on wall clock. Synthetic headers in this file have
    // `time = 1_700_000_001 + i`, so we anchor `now` relative to that.

    /// Build a chain whose tip header has the given `time` (Unix seconds).
    fn chain_with_tip_time(tip_time: u32) -> HeaderChain {
        let header = Header {
            version: Version::ONE,
            prev_blockhash: bitcoin::BlockHash::from_byte_array([0u8; 32]),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: tip_time,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        };
        regtest_chain_with(vec![header])
    }

    fn unix(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn staleness_fresh_tip_passes() {
        let chain = chain_with_tip_time(1_700_000_000);
        // Now = tip + 30 minutes. Well within 2h.
        assert_chain_not_stale(
            &chain,
            unix(1_700_000_000 + 30 * 60),
            Duration::from_secs(SPV_MAX_TIP_AGE_SECS),
            Duration::from_secs(SPV_MAX_TIP_FUTURE_SECS),
        )
        .unwrap();
    }

    #[test]
    fn staleness_tip_at_exact_max_age_passes() {
        let chain = chain_with_tip_time(1_700_000_000);
        // Now = tip + exactly max_age. Boundary is inclusive (age == max_age
        // is allowed; only age > max_age rejects).
        assert_chain_not_stale(
            &chain,
            unix(1_700_000_000 + SPV_MAX_TIP_AGE_SECS),
            Duration::from_secs(SPV_MAX_TIP_AGE_SECS),
            Duration::from_secs(SPV_MAX_TIP_FUTURE_SECS),
        )
        .unwrap();
    }

    #[test]
    fn staleness_old_tip_rejects() {
        let chain = chain_with_tip_time(1_700_000_000);
        // Now = tip + 3 hours. Past the 2-hour bound.
        let err = assert_chain_not_stale(
            &chain,
            unix(1_700_000_000 + 3 * 60 * 60),
            Duration::from_secs(SPV_MAX_TIP_AGE_SECS),
            Duration::from_secs(SPV_MAX_TIP_FUTURE_SECS),
        )
        .unwrap_err();
        assert!(err.to_string().contains("too stale"), "got: {err}");
    }

    #[test]
    fn staleness_far_future_tip_rejects() {
        let chain = chain_with_tip_time(1_700_000_000 + 4 * 60 * 60);
        // Tip is 4h ahead of now; we allow up to 2h future skew.
        let err = assert_chain_not_stale(
            &chain,
            unix(1_700_000_000),
            Duration::from_secs(SPV_MAX_TIP_AGE_SECS),
            Duration::from_secs(SPV_MAX_TIP_FUTURE_SECS),
        )
        .unwrap_err();
        assert!(err.to_string().contains("in the future"), "got: {err}");
    }

    #[test]
    fn staleness_near_future_tip_passes() {
        let chain = chain_with_tip_time(1_700_000_000 + 30 * 60);
        // Tip 30 min in the future of now - within the consensus 2h grace.
        assert_chain_not_stale(
            &chain,
            unix(1_700_000_000),
            Duration::from_secs(SPV_MAX_TIP_AGE_SECS),
            Duration::from_secs(SPV_MAX_TIP_FUTURE_SECS),
        )
        .unwrap();
    }

    #[test]
    fn staleness_uses_checkpoint_time_when_no_headers() {
        // No headers pushed. Chain falls back to checkpoint.time, which in
        // this test setup is 1_700_000_000. Now = +1h -> fresh; now = +3h
        // -> stale. Same logic as a populated chain - checkpoint is just a
        // header we don't store the body of.
        let chain = HeaderChain::new(
            Network::Regtest,
            crate::networks::rgb::spv::checkpoint::Checkpoint {
                height: 0,
                hash: [0u8; 32],
                bits: 0x207fffff,
                time: 1_700_000_000,
                is_real: false,
            },
        );
        assert_chain_not_stale(
            &chain,
            unix(1_700_000_000 + 60 * 60),
            Duration::from_secs(SPV_MAX_TIP_AGE_SECS),
            Duration::from_secs(SPV_MAX_TIP_FUTURE_SECS),
        )
        .unwrap();

        let err = assert_chain_not_stale(
            &chain,
            unix(1_700_000_000 + 3 * 60 * 60),
            Duration::from_secs(SPV_MAX_TIP_AGE_SECS),
            Duration::from_secs(SPV_MAX_TIP_FUTURE_SECS),
        )
        .unwrap_err();
        assert!(err.to_string().contains("too stale"), "got: {err}");
    }

    #[test]
    fn staleness_thresholds_are_what_we_documented() {
        // Defensive: if anyone tightens these constants without
        // understanding why, the test catches it. 2h on each side is
        // deliberately generous; lowering is a security tradeoff that
        // should be a conscious decision, not an incidental edit.
        assert_eq!(SPV_MAX_TIP_AGE_SECS, 2 * 60 * 60);
        assert_eq!(SPV_MAX_TIP_FUTURE_SECS, 2 * 60 * 60);
    }
}
