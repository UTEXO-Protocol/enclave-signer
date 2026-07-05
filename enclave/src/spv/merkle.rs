//! Bitcoin Merkle inclusion proof verification.
//!
//! Reconstructs a block's Merkle root from a single transaction id, its
//! position in the block, and the sibling hashes along its path. The result
//! is compared against the Merkle root committed in a validated block header.
//!
//! Wire format note: Bitcoin merkle nodes are computed in *internal* (little-
//! endian) byte order, but block explorers (Esplora included) typically
//! display txids and sibling hashes in *display* (big-endian) byte order.
//! The verifier here operates strictly on internal-order bytes — callers are
//! responsible for reversing display-order hex strings before passing them in.
//!
//! Bitcoin's classic Merkle tree has a known degenerate property: when a
//! level has an odd number of nodes, the last node is duplicated. This is
//! handled implicitly here because the proof-walk shape encodes the choice
//! at each step (sibling-on-the-right vs sibling-on-the-left), which the
//! prover already accounts for. We do not synthesise the duplication
//! ourselves; we trust the supplied path. The position index is what tells
//! us whether each sibling is on the left or the right.

use bitcoin::hashes::{sha256d, Hash};

/// 32-byte hash in Bitcoin internal byte order.
pub type Sha256d = [u8; 32];

/// Result of a Merkle inclusion check. Distinguishes "math is wrong" from
/// "you fed me garbage" so callers can produce useful errors.
#[derive(Debug, PartialEq, Eq)]
pub enum MerkleError {
    /// A sibling hash in the path was the wrong length.
    BadSiblingLength { index: usize, len: usize },
    /// Reconstructed root did not match the header's committed root.
    RootMismatch {
        computed: Sha256d,
        expected: Sha256d,
    },
    /// `position` carries more significant bits than the supplied `path`
    /// has levels, i.e. the index does not fit a tree of this depth. Left
    /// unchecked, the surplus high bits are silently ignored, so distinct
    /// positions (`p`, `p + 2^path.len()`, ...) reconstruct the *same* root
    /// and validate interchangeably -- the position is not authenticated by
    /// the proof. Bitcoin Core's `CPartialMerkleTree` enforces the same
    /// "all index bits consumed" invariant.
    PositionOutOfRange { position: u32, path_len: usize },
}

/// Verify that `txid` (in internal byte order) is included in a block whose
/// `merkle_root` (also internal order) we already trust, given its `position`
/// in the block's tx list and the `path` of sibling hashes from leaf to root.
///
/// Returns `Ok(())` on inclusion, an error otherwise.
///
/// `path` may be empty — that's the legitimate case where the block contains
/// exactly one transaction (the coinbase) and the txid *is* the merkle root.
pub fn verify_merkle_proof(
    txid: &Sha256d,
    position: u32,
    path: &[Sha256d],
    merkle_root: &Sha256d,
) -> Result<(), MerkleError> {
    let mut current = *txid;
    let mut idx = position;

    for (i, sibling) in path.iter().enumerate() {
        if sibling.len() != 32 {
            // unreachable given the [u8; 32] type, but kept defensively for
            // the day we accept Vec<Vec<u8>> at the boundary
            return Err(MerkleError::BadSiblingLength {
                index: i,
                len: sibling.len(),
            });
        }

        // Bottom bit of the position determines which side `current` is on:
        //   bit == 0 -> we are the LEFT child, sibling is on the right.
        //   bit == 1 -> we are the RIGHT child, sibling is on the left.
        let mut buf = [0u8; 64];
        if idx & 1 == 0 {
            buf[..32].copy_from_slice(&current);
            buf[32..].copy_from_slice(sibling);
        } else {
            buf[..32].copy_from_slice(sibling);
            buf[32..].copy_from_slice(&current);
        }

        current = sha256d::Hash::hash(&buf).to_byte_array();
        idx >>= 1;
    }

    // Every bit of `position` must have been consumed by a path level. A
    // non-zero residue means the caller supplied an index that cannot exist
    // in a tree of `path.len()` levels; without this guard the surplus bits
    // are ignored and the same root reconstructs for several positions,
    // leaving `tx_position` unauthenticated (Bitcoin Core applies the
    // identical check in `CPartialMerkleTree::ExtractMatches`).
    if idx != 0 {
        return Err(MerkleError::PositionOutOfRange {
            position,
            path_len: path.len(),
        });
    }

    if &current == merkle_root {
        Ok(())
    } else {
        Err(MerkleError::RootMismatch {
            computed: current,
            expected: *merkle_root,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{sha256d, Hash};

    /// Helper: double-SHA256 of two concatenated 32-byte hashes.
    fn dsha256_pair(left: &Sha256d, right: &Sha256d) -> Sha256d {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(left);
        buf[32..].copy_from_slice(right);
        sha256d::Hash::hash(&buf).to_byte_array()
    }

    #[test]
    fn empty_path_means_txid_equals_root() {
        // Single-tx block: the txid IS the merkle root.
        let txid: Sha256d = [0x42; 32];
        let root = txid;
        assert!(verify_merkle_proof(&txid, 0, &[], &root).is_ok());
    }

    #[test]
    fn empty_path_rejects_when_txid_neq_root() {
        let txid: Sha256d = [0x42; 32];
        let root: Sha256d = [0x43; 32];
        assert!(matches!(
            verify_merkle_proof(&txid, 0, &[], &root),
            Err(MerkleError::RootMismatch { .. })
        ));
    }

    #[test]
    fn two_tx_block_left_position() {
        // 2-tx block: root = sha256d(tx0 || tx1).
        let tx0: Sha256d = [0x11; 32];
        let tx1: Sha256d = [0x22; 32];
        let root = dsha256_pair(&tx0, &tx1);

        // Proof for tx0 (position 0): path = [tx1].
        assert!(verify_merkle_proof(&tx0, 0, &[tx1], &root).is_ok());
    }

    #[test]
    fn two_tx_block_right_position() {
        let tx0: Sha256d = [0x11; 32];
        let tx1: Sha256d = [0x22; 32];
        let root = dsha256_pair(&tx0, &tx1);

        // Proof for tx1 (position 1): path = [tx0].
        assert!(verify_merkle_proof(&tx1, 1, &[tx0], &root).is_ok());
    }

    #[test]
    fn four_tx_block_each_position() {
        // 4-tx block: standard balanced merkle tree.
        //          root
        //         /    \
        //       n01    n23
        //       / \    / \
        //      t0 t1  t2 t3
        let t0: Sha256d = [0x10; 32];
        let t1: Sha256d = [0x20; 32];
        let t2: Sha256d = [0x30; 32];
        let t3: Sha256d = [0x40; 32];
        let n01 = dsha256_pair(&t0, &t1);
        let n23 = dsha256_pair(&t2, &t3);
        let root = dsha256_pair(&n01, &n23);

        // Proof for t0: position 0, path = [t1, n23]
        assert!(verify_merkle_proof(&t0, 0, &[t1, n23], &root).is_ok());
        // Proof for t1: position 1, path = [t0, n23]
        assert!(verify_merkle_proof(&t1, 1, &[t0, n23], &root).is_ok());
        // Proof for t2: position 2, path = [t3, n01]
        assert!(verify_merkle_proof(&t2, 2, &[t3, n01], &root).is_ok());
        // Proof for t3: position 3, path = [t2, n01]
        assert!(verify_merkle_proof(&t3, 3, &[t2, n01], &root).is_ok());
    }

    #[test]
    fn rejects_wrong_position_in_balanced_tree() {
        let t0: Sha256d = [0x10; 32];
        let t1: Sha256d = [0x20; 32];
        let t2: Sha256d = [0x30; 32];
        let t3: Sha256d = [0x40; 32];
        let n01 = dsha256_pair(&t0, &t1);
        let n23 = dsha256_pair(&t2, &t3);
        let root = dsha256_pair(&n01, &n23);

        // Right path for t0 but claim it's at position 1 — should hash with
        // t1 on the wrong side and miss the root.
        assert!(matches!(
            verify_merkle_proof(&t0, 1, &[t1, n23], &root),
            Err(MerkleError::RootMismatch { .. })
        ));
    }

    #[test]
    fn rejects_position_high_bits_above_depth_two_tx_block() {
        // 2-tx block: root = sha256d(tx0 || tx1). The honest proof for tx0 is
        // (position 0, path [tx1]). Positions that differ only in bits above
        // the single path level (2, 4, 6, ...) reconstruct the identical root
        // because the surplus bits are never consulted during the walk. The
        // verifier must reject them so `tx_position` is authenticated.
        let tx0: Sha256d = [0x11; 32];
        let tx1: Sha256d = [0x22; 32];
        let root = dsha256_pair(&tx0, &tx1);

        // Honest proof still passes.
        assert!(verify_merkle_proof(&tx0, 0, &[tx1], &root).is_ok());

        // Forged positions sharing the low bits but with a high bit set.
        for forged in [2u32, 4, 6, 0x8000_0000] {
            assert!(
                matches!(
                    verify_merkle_proof(&tx0, forged, &[tx1], &root),
                    Err(MerkleError::PositionOutOfRange { position, path_len: 1 })
                        if position == forged
                ),
                "position {forged} should be rejected as out of range",
            );
        }
    }

    #[test]
    fn rejects_position_high_bits_above_depth_four_tx_block() {
        // 4-tx block, depth 2. tx2 sits at position 2 with path [t3, n01].
        // Position 6 (= 2 | 0b100) shares the two low bits but sets a third,
        // non-existent level bit; it used to validate identically to 2.
        let t0: Sha256d = [0x10; 32];
        let t1: Sha256d = [0x20; 32];
        let t2: Sha256d = [0x30; 32];
        let t3: Sha256d = [0x40; 32];
        let n01 = dsha256_pair(&t0, &t1);
        let n23 = dsha256_pair(&t2, &t3);
        let root = dsha256_pair(&n01, &n23);

        assert!(verify_merkle_proof(&t2, 2, &[t3, n01], &root).is_ok());
        assert!(matches!(
            verify_merkle_proof(&t2, 6, &[t3, n01], &root),
            Err(MerkleError::PositionOutOfRange { position: 6, path_len: 2 })
        ));
    }

    #[test]
    fn empty_path_rejects_nonzero_position() {
        // Single-tx block: the only valid position is 0. A non-zero index with
        // no path levels can never be legitimate.
        let txid: Sha256d = [0x42; 32];
        let root = txid;
        assert!(verify_merkle_proof(&txid, 0, &[], &root).is_ok());
        assert!(matches!(
            verify_merkle_proof(&txid, 1, &[], &root),
            Err(MerkleError::PositionOutOfRange { position: 1, path_len: 0 })
        ));
    }

    #[test]
    fn three_tx_block_with_odd_leaf_duplication() {
        // Bitcoin's "duplicate the last hash on odd levels" rule:
        //          root
        //         /    \
        //       n01    n22
        //       / \    / \
        //      t0 t1  t2 t2   <-- t2 duplicated
        let t0: Sha256d = [0x10; 32];
        let t1: Sha256d = [0x20; 32];
        let t2: Sha256d = [0x30; 32];
        let n01 = dsha256_pair(&t0, &t1);
        let n22 = dsha256_pair(&t2, &t2);
        let root = dsha256_pair(&n01, &n22);

        // Proof for t2 in the 3-tx block: position 2, sibling at level 0 is
        // t2 itself (the duplicated copy), level 1 sibling is n01.
        // The prover IS responsible for emitting t2 as the level-0 sibling —
        // this is Esplora's behaviour and matches Bitcoin Core.
        assert!(verify_merkle_proof(&t2, 2, &[t2, n01], &root).is_ok());
    }
}
