use std::cell::RefCell;
use std::num::NonZeroU32;

use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash as _;
use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
use rgb_lib::{ChainNet, ResolveWitness};

use super::{BuriedHeaders, HeadersOnlyResolver};
use crate::error::Result;

fn header(nonce: u32) -> Header {
    Header {
        version: Version::ONE,
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: 0,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce,
    }
}

/// A header source that answers each read with the next header of a list, as
/// a chain does when a reorg replaces a block between two reads.
struct Reorging(RefCell<Vec<Header>>);

impl BuriedHeaders for Reorging {
    fn buried_header(&self, _: u32) -> Result<Header> {
        Ok(self.0.borrow_mut().remove(0))
    }

    fn safe_height(&self) -> Option<NonZeroU32> {
        None
    }
}

/// rgb-lib checks a proof against the header it is served. A second header at
/// the same height would leave the first proof tied to a block nothing checks
/// again, so the validation refuses it.
#[test]
fn a_second_different_header_at_a_height_is_refused() {
    let height = NonZeroU32::new(7).unwrap();
    let (first, second) = (header(1), header(2));
    let headers = Reorging(RefCell::new(vec![first, second]));
    let resolver = HeadersOnlyResolver::new(ChainNet::BitcoinRegtest, &headers);

    assert_eq!(resolver.get_block_header(height).unwrap(), first);
    assert!(resolver.get_block_header(height).is_err());

    let failure = resolver.take_failure().expect("the refusal").to_string();
    assert!(failure.contains("changed during validation"), "{failure}");
    assert_eq!(
        resolver.served_hash(7),
        Some(first.block_hash().to_byte_array()),
        "the header the first proof was checked against stays recorded"
    );
}

#[test]
fn the_same_header_twice_at_a_height_is_served() {
    let height = NonZeroU32::new(7).unwrap();
    let headers = Reorging(RefCell::new(vec![header(1), header(1)]));
    let resolver = HeadersOnlyResolver::new(ChainNet::BitcoinRegtest, &headers);

    assert_eq!(resolver.get_block_header(height).unwrap(), header(1));
    assert_eq!(resolver.get_block_header(height).unwrap(), header(1));
    assert!(resolver.take_failure().is_none());
}
