//! SPV cross-check: the witness Bitcoin transactions of the consignment must
//! be in the in-enclave header chain with enough confirmations.
//!
//! Before it signs an EVM unlock, this gate requires:
//!
//! 1. **Coverage**: each witness txid of the consignment has a
//!    `MerkleProofEntry` in the request, and no extra proofs exist (set
//!    equality, both directions).
//! 2. **Cross-network**: the consignment `chain_net` matches the compiled
//!    network. This stops a regtest consignment on a mainnet enclave.
//! 3. **Inclusion**: each Merkle proof gives the `merkle_root` of our stored
//!    header at `block_height`.
//! 4. **Confirmation depth**: every witness tx (not only the burn) is at least
//!    `SPV_MIN_CONFIRMATIONS` deep. Bridge spec section 11 forbids trust in
//!    only the most recent anchoring transaction.
//!
//! Byte order: `MerkleProofEntry.txid` and `.merkle_path` are in display
//! (big-endian) order. `spv::merkle` uses internal (little-endian) order.
//! `verify_one_proof` converts each hash once. The coverage check uses display
//! order on both sides.

#[cfg(rgb_to_evm)]
use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(rgb_to_evm)]
use bitcoin::hashes::Hash;
#[cfg(rgb_to_evm)]
use rgbstd::ChainNet;

use crate::error::{EnclaveError, Result};
use crate::networks::rgb::spv::HeaderChain;
#[cfg(rgb_to_evm)]
use crate::networks::rgb::spv::{verify_merkle_proof, MerkleError, Network};
#[cfg(rgb_to_evm)]
use crate::proto::MerkleProofEntry;

#[cfg(rgb_to_evm)]
use super::validation::ValidatedConsignment;

/// Confirmation depth required before the enclave signs. Compile-time, not an
/// env var: a host value of 0 would bypass SPV and attestation would still pass.
pub const SPV_MIN_CONFIRMATIONS: u32 = 6;

/// Maximum age of the chain tip `time`, in seconds. With an older tip the
/// enclave does not sign. This stops a host that sends real but old headers
/// and never reaches the real chain head.
///
/// 2 hours is a wide margin. The parent syncs every 10s by default, and mainnet
/// blocks come approx every 10 minutes.
pub const SPV_MAX_TIP_AGE_SECS: u64 = 2 * 60 * 60;

/// Bitcoin consensus allows a block `time` up to approx 2 hours ahead of
/// network-adjusted time. The check accepts that. A larger skew fails, because
/// `time = far_future` would defeat the staleness check.
pub const SPV_MAX_TIP_FUTURE_SECS: u64 = 2 * 60 * 60;

/// Maximum sibling hashes in one Merkle path. Depth d covers up to 2^d
/// transactions, and a 4 MB block holds far fewer than 2^17. Thus 32 never
/// rejects a real proof and bounds the hashing a hostile host can cause.
/// `validate_spv_proofs` checks it before any hashing. Compile-time and in
/// PCR0, so the host cannot change it.
#[cfg(rgb_to_evm)]
pub const MAX_MERKLE_PATH_DEPTH: usize = 32;

/// Validates the Bitcoin anchoring of the RGB source before signing.
///
/// Takes the validated consignment and the request Merkle proofs. Checks chain
/// freshness, network binding, inclusion, and confirmation depth.
#[cfg(rgb_to_evm)]
pub fn validate_source_chain(
    chain: &HeaderChain,
    validated_consignment: Option<&ValidatedConsignment>,
    merkle_proofs: &[MerkleProofEntry],
    now: SystemTime,
    pins: &ChainPins,
) -> Result<()> {
    let validated = validated_consignment.ok_or_else(|| {
        EnclaveError::Spv(
            "spv: RGB source requires a non-empty validated consignment, \
             but the request had no consignment bytes (or the validator \
             is not configured)"
                .into(),
        )
    })?;

    assert_chain_fresh(chain, now)?;
    assert_chain_net(&validated.chain_net, chain.network())?;
    validate_spv_proofs(
        chain,
        &validated.witness_txids,
        merkle_proofs,
        SPV_MIN_CONFIRMATIONS,
    )?;

    // Pin every block this check used, under the caller's lock guard. The guard
    // ends at return, so `ChainPins::assert_unchanged` checks the blocks again
    // at signing time (F05-NEW-AF-08).
    for proof in merkle_proofs {
        pins.pin(chain, proof.block_height)?;
    }

    tracing::info!(
        proofs_count = merkle_proofs.len(),
        pinned_blocks = pins.len(),
        "SPV verification passed"
    );

    Ok(())
}

/// Verifies a full set of SPV proofs against the chain.
///
/// `expected_txids` is the witness-txid set of the validated RGB consignment,
/// in **display byte order** (the wire format of `MerkleProofEntry.txid`).
/// `proofs` are the entries from the request.
#[cfg(rgb_to_evm)]
pub fn validate_spv_proofs(
    chain: &HeaderChain,
    expected_txids: &[[u8; 32]],
    proofs: &[MerkleProofEntry],
    min_confirmations: u32,
) -> Result<()> {
    // 1. Coverage: sets in display order, compared both ways.
    let expected_set: BTreeSet<[u8; 32]> = expected_txids.iter().copied().collect();
    let mut proof_set: BTreeSet<[u8; 32]> = BTreeSet::new();

    for (i, proof) in proofs.iter().enumerate() {
        let txid: [u8; 32] = proof.txid.as_slice().try_into().map_err(|_| {
            EnclaveError::Spv(format!(
                "merkle_proofs[{i}].txid must be 32 bytes, got {}",
                proof.txid.len()
            ))
        })?;
        // Bound per-proof hashing before it starts. A path deeper than any
        // real block is a bug or a work-amplification attack.
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
        // proof_set is a strict subset of expected_set (extras failed above).
        // List the missing txids in the error.
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

/// Chain-freshness part of the signing precondition, with this module's
/// bounds. Signing calls it before the proof checks. The readiness probe calls
/// it too, so the two cannot drift apart.
pub fn assert_chain_fresh(chain: &HeaderChain, now: SystemTime) -> Result<()> {
    assert_chain_not_stale(
        chain,
        now,
        Duration::from_secs(SPV_MAX_TIP_AGE_SECS),
        Duration::from_secs(SPV_MAX_TIP_FUTURE_SECS),
    )
}

/// Full signing precondition on the chain only: fresh, and at least
/// [`SPV_MIN_CONFIRMATIONS`] blocks past the checkpoint.
///
/// `validate_spv_proofs` rejects shallower proofs. A chain one block past the
/// checkpoint is fresh but cannot confirm anything. A freshness-only probe
/// would then report ready while every signing request fails.
pub fn assert_chain_ready(chain: &HeaderChain, now: SystemTime) -> Result<()> {
    assert_chain_fresh(chain, now)?;

    let depth = chain.len() as u32;
    if depth < SPV_MIN_CONFIRMATIONS {
        return Err(EnclaveError::Spv(format!(
            "spv: chain is only {depth} block(s) past the checkpoint, need \
             {SPV_MIN_CONFIRMATIONS} before a proof can reach the required \
             confirmation depth"
        )));
    }

    Ok(())
}

/// Fails if the chain tip is too old, or too far in the future, against the
/// wall clock. `now` is a parameter for tests. Production passes
/// `SystemTime::now()`.
///
/// Threat model: a host that sends real but old headers makes a valid chain
/// with an old tip. An old block then looks well confirmed.
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

    // Future bound: Bitcoin consensus allows approx 2h of future skew per
    // block. Reject more than `max_future`.
    if let Some(future_skew) = tip_time.checked_sub(now_unix) {
        if future_skew > max_future.as_secs() {
            return Err(EnclaveError::Spv(format!(
                "spv: chain tip is {future_skew}s in the future (now = {now_unix}, \
                 tip_time = {tip_time}, max future skew = {}s)",
                max_future.as_secs()
            )));
        }
        return Ok(());
    }

    // Past bound: the normal case.
    let age = now_unix.saturating_sub(tip_time);
    if age > max_age.as_secs() {
        return Err(EnclaveError::Spv(format!(
            "spv: chain tip is too stale (now = {now_unix}, tip_time = {tip_time}, \
             age = {age}s, max age = {}s) - listener may be frozen or hostile",
            max_age.as_secs()
        )));
    }

    Ok(())
}

/// Cross-network replay defense: the consignment `chain_net` prefix (for
/// example `"sb"` for signet) must match the compiled network.
///
/// The expected value comes from [`ChainNet::prefix()`], the same rgb-core
/// code that makes the consignment string in `validation::rgb`
/// (`transfer.genesis.chain_net.prefix()`). Thus the two sides use the same
/// notation.
///
/// rgbstd validation also checks this when `rgb-validation` is on. This SPV
/// check stays, so a later change that loosens rgbstd validation cannot let a
/// wrong-network consignment reach signing.
#[cfg(rgb_to_evm)]
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
/// Same `bitcoin_network` -> `ChainNet` mapping as
/// `validation::rgb::RgbValidator::new`. `BitcoinSignet` also covers our custom
/// signet: the challenge script is different, but the rgb-core chain identity
/// (and the consignment prefix `"sb"`) is the same.
#[cfg(rgb_to_evm)]
fn expected_chain_net(network: Network) -> ChainNet {
    match network {
        Network::Mainnet => ChainNet::BitcoinMainnet,
        Network::Signet => ChainNet::BitcoinSignet,
        Network::Testnet3 => ChainNet::BitcoinTestnet3,
        Network::Regtest => ChainNet::BitcoinRegtest,
    }
}

#[cfg(rgb_to_evm)]
fn verify_one_proof(
    chain: &HeaderChain,
    tip: u32,
    min_confirmations: u32,
    index: usize,
    proof: &MerkleProofEntry,
) -> Result<()> {
    // `header_at` returns None at or below the checkpoint and above the tip.
    // Both cases fail.
    let header = chain.header_at(proof.block_height).ok_or_else(|| {
        EnclaveError::Spv(format!(
            "merkle_proofs[{index}]: no header at height {} (chain tip = {})",
            proof.block_height, tip
        ))
    })?;

    // Checked arithmetic: a hostile host can send `block_height = u32::MAX`,
    // which would underflow `tip - block_height`.
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

    // Display order -> internal order for the Merkle verifier.
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

    // TxMerkleNode bytes are in internal order, as verify_merkle_proof needs.
    let merkle_root_internal: [u8; 32] = header.merkle_root.to_byte_array();

    verify_merkle_proof(
        &txid_internal,
        proof.tx_position,
        &path_internal,
        &merkle_root_internal,
    )
    .map_err(|e| match e {
        MerkleError::RootMismatch { computed, expected } => {
            // Display-order hex, for readable diagnostics only.
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

/// The blocks the SPV checks used, checked again before the key is used.
///
/// Each check releases the header-chain lock when it returns. Another worker
/// can then accept a reorg before signing (F05-NEW-AF-08).
///
/// A check records every block it used here. `assert_unchanged` reads those
/// heights again and fails if a hash changed. An extension does not touch a
/// pinned height, so signing continues.
#[derive(Debug, Default)]
pub struct ChainPins {
    pinned: std::sync::Mutex<std::collections::BTreeMap<u32, [u8; 32]>>,
}

impl ChainPins {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the chain hash at `height`. Call it under the check's own lock
    /// guard, so the pin and the check see one chain.
    ///
    /// A second pin with a different hash means two checks read two chains.
    /// That is the race this guards, so it fails closed.
    #[cfg(rgb_to_evm)]
    pub fn pin(&self, chain: &HeaderChain, height: u32) -> Result<()> {
        let hash = chain.hash_at(height).ok_or_else(|| {
            EnclaveError::Spv(format!(
                "chain pin: enclave holds no header at height {height} (chain tip = {}) \
                 - cannot pin a block the checks relied on",
                chain.tip_height()
            ))
        })?;

        let mut pinned = self.lock()?;
        if let Some(previous) = pinned.insert(height, hash) {
            if previous != hash {
                return Err(EnclaveError::Spv(format!(
                    "chain pin: height {height} was pinned as {} but now reads {} \
                     - the header chain changed between two validation checks, refusing to sign",
                    hex::encode(previous),
                    hex::encode(hash)
                )));
            }
        }
        Ok(())
    }

    /// Check every pinned block against `chain`. Call it under a fresh lock,
    /// just before the signing key is used.
    pub fn assert_unchanged(&self, chain: &HeaderChain) -> Result<()> {
        let pinned = self.lock()?;

        for (&height, &expected) in pinned.iter() {
            match chain.hash_at(height) {
                Some(current) if current == expected => {}
                Some(current) => {
                    return Err(EnclaveError::Spv(format!(
                        "chain reorg after validation: height {height} was {} when checked but is \
                         now {} (chain tip = {}) - refusing to sign against a replaced block",
                        hex::encode(expected),
                        hex::encode(current),
                        chain.tip_height()
                    )));
                }
                None => {
                    return Err(EnclaveError::Spv(format!(
                        "chain reorg after validation: height {height} was {} when checked but the \
                         enclave now holds no header there (chain tip = {}) - refusing to sign",
                        hex::encode(expected),
                        chain.tip_height()
                    )));
                }
            }
        }

        tracing::debug!(
            pinned_blocks = pinned.len(),
            tip_height = chain.tip_height(),
            "chain pins re-checked at key use"
        );
        Ok(())
    }

    /// Count of pinned blocks. For logs and tests.
    pub fn len(&self) -> usize {
        self.lock().map(|p| p.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Fail on a poisoned lock. A panic left the pin set in an unknown state.
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, std::collections::BTreeMap<u32, [u8; 32]>>> {
        self.pinned
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("chain pin set lock poisoned: {e}")))
    }
}

// SPV proof and chain-pin checks run on the RGB -> EVM path only.
#[cfg(all(test, rgb_to_evm))]
mod tests;

/// F05-NEW-AF-08: the pin set checked before key use.
#[cfg(all(test, rgb_to_evm))]
mod chain_pin_tests {
    use super::*;
    use crate::networks::rgb::spv::checkpoint::Checkpoint;
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;

    fn empty_chain() -> HeaderChain {
        HeaderChain::new(
            Network::Regtest,
            Checkpoint {
                height: 0,
                hash: [0u8; 32],
                bits: 0x207fffff,
                time: 1_700_000_000,
                is_real: false,
                chain_work: None,
            },
        )
    }

    fn header_at(prev: bitcoin::BlockHash, height: u32, nonce: u32) -> Header {
        Header {
            version: Version::ONE,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0xAB; 32]),
            time: 1_700_000_000 + height,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce,
        }
    }

    /// Submit `count` headers from `start`, chained from the block before.
    fn submit(chain: &mut HeaderChain, start: u32, count: u32, nonce: u32) {
        let mut prev = if start == 1 {
            bitcoin::BlockHash::from_byte_array([0u8; 32])
        } else {
            bitcoin::BlockHash::from_byte_array(
                chain.hash_at(start - 1).expect("predecessor present"),
            )
        };
        let mut raw = Vec::new();
        for height in start..start + count {
            let h = header_at(prev, height, nonce);
            prev = h.block_hash();
            raw.push(serialize(&h));
        }
        chain.submit_headers(start, &raw).unwrap();
    }

    fn chain_of(count: u32) -> HeaderChain {
        let mut chain = empty_chain();
        submit(&mut chain, 1, count, 0);
        chain
    }

    #[test]
    fn empty_pin_set_passes() {
        let chain = chain_of(5);
        ChainPins::new().assert_unchanged(&chain).unwrap();
        assert!(ChainPins::new().is_empty());
    }

    #[test]
    fn pinning_a_height_the_enclave_has_no_header_for_fails() {
        let chain = chain_of(5);
        let err = ChainPins::new().pin(&chain, 99).unwrap_err();
        assert!(err.to_string().contains("cannot pin"), "got: {err}");
    }

    #[test]
    fn extension_leaves_pinned_blocks_alone() {
        let mut chain = chain_of(5);
        let pins = ChainPins::new();
        pins.pin(&chain, 3).unwrap();

        submit(&mut chain, 6, 4, 0);

        pins.assert_unchanged(&chain).unwrap();
        assert_eq!(pins.len(), 1);
    }

    #[test]
    fn reorg_replacing_a_pinned_block_fails() {
        let mut chain = chain_of(5);
        let pins = ChainPins::new();
        pins.pin(&chain, 3).unwrap();

        // Longer chain from height 3. The normal accept rule takes it.
        submit(&mut chain, 3, 6, 42);

        let err = pins.assert_unchanged(&chain).unwrap_err();
        assert!(
            err.to_string().contains("chain reorg after validation"),
            "got: {err}"
        );
    }

    #[test]
    fn reorg_below_a_pinned_block_that_shortens_the_chain_fails() {
        let chain = chain_of(20);
        let pins = ChainPins::new();
        pins.pin(&chain, 18).unwrap();

        // The work rule forbids a stronger chain that ends below height 18.
        // So test the other loss case: no header at 18 at all.
        let mut short = empty_chain();
        submit(&mut short, 1, 5, 0);
        let err = pins.assert_unchanged(&short).unwrap_err();
        assert!(err.to_string().contains("no header there"), "got: {err}");
    }

    #[test]
    fn two_checks_reading_two_different_chains_fail_closed() {
        let chain_a = chain_of(5);
        let mut chain_b = empty_chain();
        submit(&mut chain_b, 1, 5, 42);

        let pins = ChainPins::new();
        pins.pin(&chain_a, 3).unwrap();
        let err = pins.pin(&chain_b, 3).unwrap_err();
        assert!(err.to_string().contains("was pinned as"), "got: {err}");
    }
}
