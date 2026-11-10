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

// ===== Position binding and 64-byte transaction nodes =====

/// A legacy transaction with one input (scriptSig of `s` bytes) and one
/// output (scriptPubKey of `4 - s` bytes) serializes to 64 bytes:
/// 4 + 1 + 41 + s + 1 + 9 + (4 - s) + 4. Built with rust-bitcoin, not by hand.
fn transaction_of_64_bytes(s: usize, value: u64) -> bitcoin::Transaction {
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, TxIn,
        TxOut, Txid, Witness,
    };
    bitcoin::Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x5C; 32]),
                vout: 7,
            },
            script_sig: ScriptBuf::from_bytes(vec![0x51; s]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a; 4 - s]),
        }],
    }
}

/// Reference for the node-shape predicate: rust-bitcoin decodes all 64
/// bytes as a legacy transaction with one input, one output and a value of
/// at most MAX_MONEY, and encodes it back to the same 64 bytes.
fn rust_bitcoin_decodes_a_64_byte_one_in_one_out_tx(bytes: &[u8; 64]) -> bool {
    match bitcoin::consensus::deserialize::<bitcoin::Transaction>(bytes) {
        Ok(tx) => {
            tx.input.len() == 1
                && tx.output.len() == 1
                && tx.input[0].witness.is_empty()
                && tx.output[0].value <= bitcoin::Amount::MAX_MONEY
                && bitcoin::consensus::serialize(&tx) == bytes.as_slice()
        }
        Err(_) => false,
    }
}

/// xorshift64, for reproducible test inputs.
struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn fill(&mut self, out: &mut [u8; 64]) {
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes());
        }
    }
}

/// Every scriptSig length s in 0..=4 (scriptPubKey 4 - s) gives a 64-byte
/// tx; the predicate holds exactly when the value is in the money range.
#[test]
fn node_shape_predicate_holds_for_every_64_byte_transaction() {
    for s in 0..=4 {
        for value in [
            0,
            1,
            1_000,
            MAX_MONEY_SATS - 1,
            MAX_MONEY_SATS,
            MAX_MONEY_SATS + 1,
            i64::MAX as u64,
            u64::MAX,
        ] {
            let tx = transaction_of_64_bytes(s, value);
            let bytes: [u8; 64] = bitcoin::consensus::serialize(&tx)
                .try_into()
                .expect("64 bytes");
            let in_range = value <= MAX_MONEY_SATS;
            assert_eq!(is_64_byte_transaction(&bytes), in_range, "s={s} v={value}");
            assert_eq!(
                rust_bitcoin_decodes_a_64_byte_one_in_one_out_tx(&bytes),
                in_range,
                "s={s} v={value}"
            );
        }
    }
}

/// The predicate equals the rust-bitcoin reference on: every single-byte
/// change of a valid 64-byte tx (each s), structured candidates near the
/// shape, and plain random 64-byte strings (what a hash pair looks like).
#[test]
fn node_shape_predicate_matches_rust_bitcoin_decoding() {
    let mut shaped = 0u64;
    let mut check = |bytes: &[u8; 64]| {
        let got = is_64_byte_transaction(bytes);
        assert_eq!(
            got,
            rust_bitcoin_decodes_a_64_byte_one_in_one_out_tx(bytes),
            "disagree on {}",
            hex::encode(bytes)
        );
        shaped += u64::from(got);
    };

    for s in 0..=4 {
        let base: [u8; 64] = bitcoin::consensus::serialize(&transaction_of_64_bytes(s, 1_000))
            .try_into()
            .unwrap();
        for i in 0..64 {
            for v in 0..=255u8 {
                let mut m = base;
                m[i] = v;
                check(&m);
            }
        }
    }

    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    for _ in 0..200_000 {
        let mut m = [0u8; 64];
        rng.fill(&mut m);
        let r = rng.next();
        if r & 1 == 0 {
            m[4] = 1;
        }
        if (r >> 1) & 3 != 0 {
            m[41] = ((r >> 3) % 7) as u8;
        }
        let s = usize::from(m[41]);
        if s <= 4 {
            if (r >> 6) & 1 == 0 {
                m[46 + s] = 1;
            }
            if (r >> 7) & 1 == 0 {
                let v = rng.next() % (MAX_MONEY_SATS + 2);
                m[47 + s..55 + s].copy_from_slice(&v.to_le_bytes());
            }
            if (r >> 8) & 1 == 0 {
                m[55 + s] = (4 - s) as u8;
            }
        }
        check(&m);
    }

    for _ in 0..100_000 {
        let mut m = [0u8; 64];
        rng.fill(&mut m);
        check(&m);
    }

    assert!(shaped > 5_000, "too few positives exercised: {shaped}");
}

/// A 64-byte X mined at position 0 of a four-transaction block: each half
/// of X, proven as a leaf, is refused at level 0. The honest proofs of the
/// same block pass.
#[test]
fn refuses_a_half_of_a_64_byte_transaction_as_a_leaf() {
    for s in 0..=4 {
        let tx = transaction_of_64_bytes(s, 1_000);
        let x = bitcoin::consensus::serialize(&tx);
        let a: Sha256d = x[..32].try_into().unwrap();
        let b: Sha256d = x[32..].try_into().unwrap();
        let txid_x = tx.compute_txid().to_byte_array();
        assert_eq!(txid_x, dsha256_pair(&a, &b), "txid(X) = sha256d(a || b)");
        let t1: Sha256d = [0x11; 32];
        let t2: Sha256d = [0x22; 32];
        let t3: Sha256d = [0x33; 32];
        let n01 = dsha256_pair(&txid_x, &t1);
        let n23 = dsha256_pair(&t2, &t3);
        let root = dsha256_pair(&n01, &n23);

        assert_eq!(verify_merkle_proof(&txid_x, 0, &[t1, n23], &root), Ok(()));
        assert_eq!(verify_merkle_proof(&t1, 1, &[txid_x, n23], &root), Ok(()));
        assert_eq!(verify_merkle_proof(&t2, 2, &[t3, n01], &root), Ok(()));
        assert_eq!(verify_merkle_proof(&t3, 3, &[t2, n01], &root), Ok(()));

        assert_eq!(
            verify_merkle_proof(&a, 0, &[b, t1, n23], &root),
            Err(MerkleError::TransactionShapedNode { level: 0 }),
            "s={s}"
        );
        assert_eq!(
            verify_merkle_proof(&b, 1, &[a, t1, n23], &root),
            Err(MerkleError::TransactionShapedNode { level: 0 }),
            "s={s}"
        );
    }
}

/// A node that is not a transaction is accepted at any depth: without a
/// SHA-256d collision, no block can present such a node as a txid. Binding
/// the tree depth itself needs a coinbase proof, which the request does
/// not carry.
#[test]
fn a_node_that_is_not_a_transaction_is_accepted_at_any_depth() {
    let a: Sha256d = [0xA1; 32];
    let b: Sha256d = [0xB2; 32];
    assert!(!is_64_byte_transaction(&{
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&a);
        buf[32..].copy_from_slice(&b);
        buf
    }));
    let node = dsha256_pair(&a, &b);
    let t1: Sha256d = [0x11; 32];
    let t2: Sha256d = [0x22; 32];
    let t3: Sha256d = [0x33; 32];
    let n01 = dsha256_pair(&node, &t1);
    let n23 = dsha256_pair(&t2, &t3);
    let root = dsha256_pair(&n01, &n23);
    assert_eq!(verify_merkle_proof(&node, 0, &[t1, n23], &root), Ok(()));
    assert_eq!(verify_merkle_proof(&a, 0, &[b, t1, n23], &root), Ok(()));
    assert_eq!(verify_merkle_proof(&b, 1, &[a, t1, n23], &root), Ok(()));
}

#[test]
fn refuses_position_bits_above_the_path() {
    let a: Sha256d = [0x0A; 32];
    let b: Sha256d = [0x0B; 32];
    let root = dsha256_pair(&a, &b);
    assert_eq!(verify_merkle_proof(&a, 0, &[b], &root), Ok(()));
    assert_eq!(verify_merkle_proof(&b, 1, &[a], &root), Ok(()));
    for pos in [2u32, 4, 6, 1000, 0xFFFF_FFF0] {
        assert_eq!(
            verify_merkle_proof(&a, pos, &[b], &root),
            Err(MerkleError::PositionOutOfRange {
                position: pos,
                depth: 1
            })
        );
    }
    for pos in [3u32, 5, 0xFFFF_FFFF] {
        assert_eq!(
            verify_merkle_proof(&b, pos, &[a], &root),
            Err(MerkleError::PositionOutOfRange {
                position: pos,
                depth: 1
            })
        );
    }
    // Empty path: only position 0. A 32-sibling path reaches every u32.
    assert_eq!(
        verify_merkle_proof(&a, 1, &[], &a),
        Err(MerkleError::PositionOutOfRange {
            position: 1,
            depth: 0
        })
    );
    assert!(matches!(
        verify_merkle_proof(&a, u32::MAX, &[b; 32], &root),
        Err(MerkleError::RootMismatch { .. })
    ));
}

/// Siblings from leaf to root for the tx at `pos`, with Bitcoin's
/// duplicate-last rule on odd levels.
fn merkle_branch(txids: &[Sha256d], mut pos: usize) -> Vec<Sha256d> {
    let mut level = txids.to_vec();
    let mut path = Vec::new();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        path.push(level[pos ^ 1]);
        level = level
            .chunks(2)
            .map(|p| dsha256_pair(&p[0], &p[1]))
            .collect();
        pos >>= 1;
    }
    path
}

/// Every tx of every block in a local Bitcoin Core `blk*.dat` file
/// verifies with its honest proof. `MERKLE_BLK_FILE` is the file,
/// `MERKLE_BLK_XOR` the hex `xor.dat` key (empty for none).
#[test]
#[ignore = "needs MERKLE_BLK_FILE, a local blk*.dat file"]
fn real_block_file_honest_proofs_pass() {
    let path = std::env::var("MERKLE_BLK_FILE").expect("MERKLE_BLK_FILE");
    let key = hex::decode(std::env::var("MERKLE_BLK_XOR").unwrap_or_default()).unwrap();
    let mut data = std::fs::read(&path).unwrap();
    if !key.is_empty() {
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= key[i % key.len()];
        }
    }
    // Records are [magic][size][block]. The unused tail of the file is
    // preallocated zeros on disk, so it does not repeat the first magic.
    let magic: [u8; 4] = data[..4].try_into().unwrap();
    let (mut off, mut blocks) = (0usize, 0usize);
    while off + 8 <= data.len() && data[off..off + 4] == magic {
        let size = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
        let block: bitcoin::Block =
            bitcoin::consensus::deserialize(&data[off + 8..off + 8 + size]).unwrap();
        off += 8 + size;
        let txids: Vec<Sha256d> = block
            .txdata
            .iter()
            .map(|tx| tx.compute_txid().to_byte_array())
            .collect();
        let root = block.header.merkle_root.to_byte_array();
        for (pos, txid) in txids.iter().enumerate() {
            let branch = merkle_branch(&txids, pos);
            assert_eq!(
                verify_merkle_proof(txid, pos as u32, &branch, &root),
                Ok(()),
                "block {} tx {pos}",
                block.block_hash()
            );
        }
        blocks += 1;
    }
    assert!(blocks > 0);
}
