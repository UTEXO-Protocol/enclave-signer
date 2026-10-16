//! Bitcoin Merkle inclusion proof verification.
//!
//! Rebuilds a block's Merkle root from one txid, its position in the block,
//! and the sibling hashes on its path. Then compares it with the Merkle root
//! of a validated block header.
//!
//! Byte order: all inputs are in internal (little-endian) order. Explorers
//! such as Esplora show display (big-endian) order. Callers must reverse
//! display-order hex before the call.
//!
//! Bitcoin duplicates the last node on odd levels. The prover puts that
//! duplicate in the path, so this verifier does not make it.

use bitcoin::hashes::{sha256d, Hash};

/// 32-byte hash in Bitcoin internal byte order.
pub type Sha256d = [u8; 32];

/// Merkle inclusion check error. Bad input and a root mismatch are separate
/// variants, so callers can give clear errors.
#[derive(Debug, PartialEq, Eq)]
pub enum MerkleError {
    /// A sibling hash in the path was the wrong length.
    BadSiblingLength { index: usize, len: usize },
    /// Reconstructed root did not match the header's committed root.
    RootMismatch {
        computed: Sha256d,
        expected: Sha256d,
    },
}

/// Verifies that `txid` is in a block with the trusted `merkle_root`. All
/// hashes are in internal byte order. `position` is the tx index in the block.
/// `path` holds the sibling hashes from leaf to root.
///
/// An empty `path` is valid: a block with only the coinbase has txid ==
/// merkle root.
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
            // Unreachable with [u8; 32]. Kept for a future Vec<Vec<u8>> input.
            return Err(MerkleError::BadSiblingLength {
                index: i,
                len: sibling.len(),
            });
        }

        // Low bit of the position: 0 -> `current` is the left child,
        // 1 -> `current` is the right child.
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

    /// Double-SHA256 of two concatenated 32-byte hashes.
    fn dsha256_pair(left: &Sha256d, right: &Sha256d) -> Sha256d {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(left);
        buf[32..].copy_from_slice(right);
        sha256d::Hash::hash(&buf).to_byte_array()
    }

    #[test]
    fn empty_path_means_txid_equals_root() {
        // Single-tx block: the txid is the merkle root.
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

        // Correct path for t0 at the wrong position: t1 goes on the wrong side.
        assert!(matches!(
            verify_merkle_proof(&t0, 1, &[t1, n23], &root),
            Err(MerkleError::RootMismatch { .. })
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

        // Proof for t2: the level-0 sibling is the t2 duplicate, the level-1
        // sibling is n01. Esplora and Bitcoin Core emit the same path.
        assert!(verify_merkle_proof(&t2, 2, &[t2, n01], &root).is_ok());
    }
}
