use super::*;
use crate::networks::rgb::spv::checkpoint::Checkpoint;
use crate::test_support::ANY_HEADER_CLOCK;
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

/// Regtest's maximum target: the chain checks no proof of work there.
const REGTEST_BITS: u32 = 0x207fffff;
/// Mainnet's genesis target. A header with these bits carries about 2^31
/// times the work of a regtest header, and regtest does not check PoW.
const HEAVY_BITS: u32 = 0x1d00ffff;

fn header_at(prev: bitcoin::BlockHash, height: u32, nonce: u32, bits: u32) -> Header {
    Header {
        version: Version::ONE,
        prev_blockhash: prev,
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0xAB; 32]),
        time: 1_700_000_000 + height,
        bits: bitcoin::CompactTarget::from_consensus(bits),
        nonce,
    }
}

/// Submit `count` headers of `bits` from `start`, chained from the block
/// before.
fn submit_with_bits(chain: &mut HeaderChain, start: u32, count: u32, nonce: u32, bits: u32) {
    let mut prev = if start == 1 {
        bitcoin::BlockHash::from_byte_array([0u8; 32])
    } else {
        bitcoin::BlockHash::from_byte_array(chain.hash_at(start - 1).expect("predecessor present"))
    };
    let mut raw = Vec::new();
    for height in start..start + count {
        let h = header_at(prev, height, nonce, bits);
        prev = h.block_hash();
        raw.push(serialize(&h));
    }
    chain.submit_headers(start, &raw, ANY_HEADER_CLOCK).unwrap();
}

/// Submit `count` regtest headers from `start`.
fn submit(chain: &mut HeaderChain, start: u32, count: u32, nonce: u32) {
    submit_with_bits(chain, start, count, nonce, REGTEST_BITS);
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
    assert!(ChainPins::new().none_pinned().unwrap());
}

#[test]
fn pinning_a_height_the_enclave_has_no_header_for_fails() {
    let chain = chain_of(5);
    let err = ChainPins::new().pin(&chain, 99, 1).unwrap_err();
    assert!(err.to_string().contains("cannot pin"), "got: {err}");
}

#[test]
fn extension_leaves_pinned_blocks_alone() {
    let mut chain = chain_of(5);
    let pins = ChainPins::new();
    // Height 3 is 3 deep, and the check required 3.
    pins.pin(&chain, 3, 3).unwrap();

    submit(&mut chain, 6, 4, 0);

    pins.assert_unchanged(&chain).unwrap();
    assert_eq!(pins.pinned_count(), 1);
}

#[test]
fn reorg_replacing_a_pinned_block_fails() {
    let mut chain = chain_of(5);
    let pins = ChainPins::new();
    pins.pin(&chain, 3, 1).unwrap();

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
    let mut chain = chain_of(20);
    let pins = ChainPins::new();
    pins.pin(&chain, 18, 1).unwrap();

    // One heavy block from height 10 out-works the eleven regtest blocks
    // it displaces. The chain then ends below height 18.
    submit_with_bits(&mut chain, 10, 1, 7, HEAVY_BITS);
    assert_eq!(chain.tip_height(), 10);
    let err = pins.assert_unchanged(&chain).unwrap_err();
    assert!(err.to_string().contains("no header there"), "got: {err}");
}

/// A replacement chain of fewer, heavier blocks keeps the pinned block
/// and leaves it shallower than the check required. The hash check alone
/// passes it. The depth check refuses it.
#[test]
fn reorg_that_leaves_a_pinned_block_shallower_fails() {
    let mut chain = chain_of(10);
    let pins = ChainPins::new();
    // Height 3 is 8 deep, and the check required 6.
    pins.pin(&chain, 3, 6).unwrap();
    let pinned_hash = chain.hash_at(3).unwrap();

    // Two heavy blocks from height 4 out-work the seven regtest blocks
    // they displace.
    submit_with_bits(&mut chain, 4, 2, 7, HEAVY_BITS);
    assert_eq!(chain.tip_height(), 5);
    assert_eq!(
        chain.hash_at(3),
        Some(pinned_hash),
        "the pinned block stays"
    );
    assert_eq!(chain.confirmations(3, 6), 3);

    let err = pins.assert_unchanged(&chain).unwrap_err();
    assert!(
        err.to_string().contains("fewer confirmations"),
        "got: {err}"
    );
}

/// Two checks that pin one height keep the larger required depth.
#[test]
fn a_second_pin_of_a_height_keeps_the_larger_depth() {
    let chain = chain_of(10);
    let pins = ChainPins::new();
    pins.pin(&chain, 3, 1).unwrap();
    pins.pin(&chain, 3, 4).unwrap();
    pins.pin(&chain, 3, 2).unwrap();
    assert_eq!(pins.pinned_count(), 1);
    pins.assert_unchanged(&chain).unwrap();

    // The same blocks, five of them: height 3 is 3 deep, one short of 4.
    let short = chain_of(5);
    assert_eq!(short.hash_at(3), chain.hash_at(3));
    let err = pins.assert_unchanged(&short).unwrap_err();
    assert!(
        err.to_string().contains("fewer confirmations"),
        "got: {err}"
    );
}

#[test]
fn two_checks_reading_two_different_chains_fail_closed() {
    let chain_a = chain_of(5);
    let mut chain_b = empty_chain();
    submit(&mut chain_b, 1, 5, 42);

    let pins = ChainPins::new();
    pins.pin(&chain_a, 3, 1).unwrap();
    let err = pins.pin(&chain_b, 3, 1).unwrap_err();
    assert!(err.to_string().contains("was pinned as"), "got: {err}");
}

#[test]
fn a_poisoned_pin_set_is_not_read_as_empty() {
    let pins = std::sync::Arc::new(ChainPins::new());
    let p = pins.clone();
    let _ = std::thread::spawn(move || {
        let _guard = p.pinned.lock().unwrap();
        panic!("poison the pin set");
    })
    .join();
    assert!(pins.none_pinned().is_err());
}
