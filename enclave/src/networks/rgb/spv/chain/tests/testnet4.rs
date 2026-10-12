use super::*;
use crate::networks::rgb::spv::checkpoint::checkpoint_for;

const MIN_BITS: u32 = 0x1d00ffff;
const HARD_BITS: u32 = 0x1c0ffff0;

fn header(time: u32, bits: u32) -> Header {
    Header {
        version: bitcoin::block::Version::from_consensus(4),
        prev_blockhash: bitcoin::BlockHash::all_zeros(),
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time,
        bits: bitcoin::CompactTarget::from_consensus(bits),
        nonce: 0,
    }
}

fn chain() -> HeaderChain {
    HeaderChain::new(Network::Testnet4, checkpoint_for(Network::Testnet4))
}

/// Operator check against a captured Electrum chain. The file is concatenated
/// 80-byte headers INCLUDING genesis; it is read locally, never from the network.
#[test]
#[ignore = "set TESTNET4_HEADERS_FILE to captured binary headers including genesis"]
fn testnet4_captured_chain_validates_from_genesis() {
    let file = std::env::var("TESTNET4_HEADERS_FILE").expect("TESTNET4_HEADERS_FILE");
    let bytes = std::fs::read(file).unwrap();
    assert!(bytes.len() > 80);
    assert_eq!(bytes.len() % 80, 0);
    let raws: Vec<_> = bytes.chunks_exact(80).map(|h| h.to_vec()).collect();
    let genesis: Header = deserialize(&raws[0]).unwrap();
    let mut c = chain();
    assert_eq!(genesis.block_hash().to_byte_array(), c.tip_hash());
    for batch in raws[1..].chunks(2016) {
        c.submit_headers(c.tip_height() + 1, batch).unwrap();
    }
    assert_eq!(c.tip_height() as usize, raws.len() - 1);
    eprintln!(
        "validated testnet4 through {} ({})",
        c.tip_height(),
        bitcoin::BlockHash::from_byte_array(c.tip_hash())
    );
}

fn staged(headers: Vec<Header>) -> Vec<(Header, BlockHash)> {
    headers
        .into_iter()
        .map(|h| (h, h.block_hash().to_byte_array()))
        .collect()
}

#[test]
fn testnet4_real_headers_validate_in_one_or_several_batches() {
    // Public headers, heights 0..15, fetched from the mempool.space testnet4
    // Esplora API. Genesis is independently pinned by the bitcoin crate.
    let raws: Vec<_> = include_str!("../../../../../../tests/fixtures/testnet4-headers-0-15.hex")
        .lines()
        .map(|line| hex::decode(line).unwrap())
        .collect();
    let genesis: Header = deserialize(&raws[0]).unwrap();
    let mut one = chain();
    assert_eq!(genesis.block_hash().to_byte_array(), one.tip_hash());
    one.submit_headers(1, &raws[1..]).unwrap();
    let mut split = chain();
    split.submit_headers(1, &raws[1..8]).unwrap();
    split.submit_headers(8, &raws[8..]).unwrap();
    assert_eq!(one.tip_height(), 15);
    assert_eq!(one.tip_hash(), split.tip_hash());
    assert_eq!(
        bitcoin::BlockHash::from_byte_array(one.tip_hash()).to_string(),
        "000000003e7c0e3da706bdcab098605def88733947cec926b49ded611244f975"
    );

    let mut broken = raws[1..].to_vec();
    let mut bad: Header = deserialize(&broken[3]).unwrap();
    loop {
        bad.nonce = bad.nonce.wrapping_add(1);
        if bad.validate_pow(bad.target()).is_err() {
            break;
        }
    }
    broken[3] = serialize(&bad);
    let mut atomic = chain();
    assert!(matches!(
        atomic.submit_headers(1, &broken),
        Err(SpvError::PowFailed { height: 4 })
    ));
    assert_eq!(atomic.tip_height(), 0);
}

#[test]
fn testnet4_min_difficulty_is_strictly_after_twenty_minutes() {
    let c = chain();
    let t = c.base_time;
    let s = staged(vec![header(t + 600, HARD_BITS)]);
    assert_eq!(
        c.testnet4_bits(&header(t + 1800, MIN_BITS), 2, 1, &s)
            .unwrap(),
        HARD_BITS
    );
    assert_eq!(
        c.testnet4_bits(&header(t + 1801, MIN_BITS), 2, 1, &s)
            .unwrap(),
        MIN_BITS
    );
}

#[test]
fn testnet4_timely_block_walks_back_over_min_difficulty_blocks() {
    let c = chain();
    let t = c.base_time;
    let s = staged(vec![
        header(t + 600, HARD_BITS),
        header(t + 1801, MIN_BITS),
        header(t + 3002, MIN_BITS),
    ]);
    assert_eq!(
        c.testnet4_bits(&header(t + 3602, MIN_BITS), 4, 1, &s)
            .unwrap(),
        HARD_BITS
    );
    let s = staged(vec![header(t + 1201, MIN_BITS)]);
    assert_eq!(
        c.testnet4_bits(&header(t + 1202, MIN_BITS), 2, 1, &s)
            .unwrap(),
        MIN_BITS
    );
}

#[test]
fn testnet4_retarget_uses_first_target_and_has_no_min_difficulty_exception() {
    let mut c = chain();
    // Context-only difficulty test, no synthetic PoW is accepted into a chain.
    c.base_bits = HARD_BITS;
    let t = c.base_time;
    let mut h: Vec<_> = (1..2016).map(|i| header(t + i, HARD_BITS)).collect();
    h.last_mut().unwrap().time = t + 1_209_600;
    h.last_mut().unwrap().bits = bitcoin::CompactTarget::from_consensus(MIN_BITS);
    let s = staged(h);
    for offset in [1, 1201] {
        assert_eq!(
            c.testnet4_bits(&header(t + 1_209_600 + offset, MIN_BITS), 2016, 1, &s)
                .unwrap(),
            HARD_BITS
        );
    }
    // BIP-94 permits exactly 600 seconds of backward time at a boundary.
    assert!(c
        .testnet4_bits(&header(t + 1_209_000, HARD_BITS), 2016, 1, &s)
        .is_ok());
    assert!(matches!(
        c.testnet4_bits(&header(t + 1_208_999, HARD_BITS), 2016, 1, &s),
        Err(SpvError::Timestamp {
            reason: "BIP-94 timewarp at retarget boundary",
            ..
        })
    ));
}

#[test]
fn testnet4_rejects_median_time_and_far_future() {
    let c = chain();
    let t = c.base_time;
    let s = staged((1..12).map(|i| header(t + i, MIN_BITS)).collect());
    assert!(matches!(
        c.testnet4_bits(&header(t + 6, MIN_BITS), 12, 1, &s),
        Err(SpvError::Timestamp {
            reason: "not greater than median time past",
            ..
        })
    ));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    assert!(matches!(
        c.testnet4_bits(&header(now + 7300, MIN_BITS), 12, 1, &s),
        Err(SpvError::Timestamp {
            reason: "more than two hours in the future",
            ..
        })
    ));
}

#[test]
fn testnet4_reorg_context_uses_staged_branch_and_never_displaced_tail() {
    let mut c = chain();
    let t = c.base_time;
    c.headers = vec![header(t + 600, MIN_BITS), header(t + 1801, MIN_BITS)];
    let s = staged(vec![header(t + 600, HARD_BITS), header(t + 1801, MIN_BITS)]);
    assert_eq!(
        c.testnet4_bits(&header(t + 1900, MIN_BITS), 3, 1, &s)
            .unwrap(),
        HARD_BITS
    );
    // A missing staged entry must not fall back to the displaced committed one.
    assert!(matches!(
        c.candidate_bits_time(2, 1, &s[..1]),
        Err(SpvError::HeaderNotFound(2))
    ));
}
