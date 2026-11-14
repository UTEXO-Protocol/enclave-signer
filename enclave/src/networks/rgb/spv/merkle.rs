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
//!
//! The path length is not bound to the block's tree depth: a proof carries
//! no coinbase proof or transaction count. Two refusals cover that. The
//! position must be consumed by the path, one bit per sibling. And no node
//! hashed on the path may be a 64-byte transaction, because its txid is the
//! hash of its two halves (CVE-2017-12842). `MAX_MERKLE_PATH_DEPTH` bounds
//! the hashing a prover can cause.

use bitcoin::hashes::{sha256d, Hash};

/// 32-byte hash in Bitcoin internal byte order.
pub type Sha256d = [u8; 32];

/// Maximum sibling hashes in one Merkle path. Depth d covers up to 2^d
/// transactions, and a 4 MB block holds far fewer than 2^17, so 32 never
/// refuses a real proof and bounds the hashing a hostile prover can cause.
/// `spv_crosscheck::proof_txid` checks it before hashing request proofs on the
/// burn path. Compile-time and in PCR0, so the host cannot change it.
pub const MAX_MERKLE_PATH_DEPTH: usize = 32;

/// Merkle inclusion check error. Bad input and a root mismatch are separate
/// variants, so callers can give clear errors.
#[derive(Debug, PartialEq, Eq)]
pub enum MerkleError {
    /// Reconstructed root did not match the header's committed root.
    RootMismatch {
        computed: Sha256d,
        expected: Sha256d,
    },
    /// `position` has a set bit at or above `depth`. A path of `depth`
    /// siblings reaches only the leaves 0 to 2^depth - 1.
    PositionOutOfRange { position: u32, depth: usize },
    /// The 64 bytes hashed at path `level` are a transaction, not two hashes
    /// (see the module doc).
    TransactionShapedNode { level: usize },
}

/// Bitcoin's MAX_MONEY in satoshis. Consensus refuses an output above it.
const MAX_MONEY_SATS: u64 = 21_000_000 * 100_000_000;

/// True when `node` is the legacy serialization of a one-input, one-output
/// transaction with a value in the money range. That is every 64-byte
/// transaction: the fixed fields take 60 bytes, so the scriptSig (s bytes)
/// and the scriptPubKey (p bytes) share the other 4. Two inputs or two
/// outputs do not fit, and consensus refuses zero inputs or zero outputs.
/// Offsets: input count [4], s [41], output count [46+s], value [47+s,55+s),
/// p [55+s].
fn is_64_byte_transaction(node: &[u8; 64]) -> bool {
    if node[4] != 1 {
        return false;
    }
    let s = usize::from(node[41]);
    if s > 4 || node[46 + s] != 1 {
        return false;
    }
    let mut value = [0u8; 8];
    value.copy_from_slice(&node[47 + s..55 + s]);
    u64::from_le_bytes(value) <= MAX_MONEY_SATS && usize::from(node[55 + s]) == 4 - s
}

/// Verifies that `txid` is in a block with the trusted `merkle_root`. All
/// hashes are in internal byte order. `position` is the tx index in the block.
/// `path` holds the sibling hashes from leaf to root.
///
/// An empty `path` is valid: a block with only the coinbase has txid ==
/// merkle root.
///
/// Refuses a `position` that the path cannot reach, and a node that is a
/// 64-byte transaction (see the module doc).
pub fn verify_merkle_proof(
    txid: &Sha256d,
    position: u32,
    path: &[Sha256d],
    merkle_root: &Sha256d,
) -> Result<(), MerkleError> {
    let mut current = *txid;
    let mut idx = position;

    for (i, sibling) in path.iter().enumerate() {
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

        // A node is two hashes. Refuse one that is also a transaction.
        if is_64_byte_transaction(&buf) {
            return Err(MerkleError::TransactionShapedNode { level: i });
        }

        current = sha256d::Hash::hash(&buf).to_byte_array();
        idx >>= 1;
    }

    // Each sibling consumes one position bit. A bit left over is a position
    // that a path of this length cannot reach.
    if idx != 0 {
        return Err(MerkleError::PositionOutOfRange {
            position,
            depth: path.len(),
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
mod tests;
