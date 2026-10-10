use super::*;
use sha3::{Digest, Keccak256};

/// Shared cross-language vectors, made with go-ethereum `accounts/abi`.
const VECTORS: &str = include_str!("../../../../../docs/burn-destination-vectors.json");

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).unwrap()
}

/// `(meta, record)` for a V1 burn.
fn v1(chain: u64, eid: u32, recipient: &[u8]) -> ([u8; 32], BurnDestinationRecord) {
    let rec = BurnDestinationRecord::v1(chain, eid, recipient);
    (rec.hash_v1(), rec)
}

fn padded(recipient: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - recipient.len()..].copy_from_slice(recipient);
    out
}

#[test]
fn vectors_match() {
    let doc: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let type_v1 = UtexoBurnDestinationV1::eip712_encode_type();
    let typehash = Keccak256::digest(type_v1.as_bytes()).to_vec();
    assert_eq!(doc["typeV1"].as_str().unwrap(), type_v1);
    assert_eq!(unhex(doc["typehashV1"].as_str().unwrap()), typehash);

    let vectors = doc["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        assert_eq!(
            v["version"].as_u64().unwrap(),
            u64::from(VERSION_V1),
            "{name}"
        );
        let rec = BurnDestinationRecord::v1(
            v["destinationChainId"].as_u64().unwrap(),
            u32::try_from(v["dstEid"].as_u64().unwrap()).unwrap(),
            &unhex(v["recipient"].as_str().unwrap()),
        );
        let mut encoded = typehash.clone();
        encoded.extend_from_slice(&rec.to_sol_v1().eip712_encode_data());
        assert_eq!(encoded, unhex(v["encoded"].as_str().unwrap()), "{name}");
        let hash = unhex(v["hash"].as_str().unwrap());
        assert_eq!(rec.hash_v1().to_vec(), hash, "{name}");
        // The vector also resolves end to end.
        assert!(resolve(&hash, Some(&rec)).is_ok(), "{name}");
    }
}

#[test]
fn v0_resolves_without_record() {
    let meta = padded(&[0xab; 20]);
    assert_eq!(
        resolve(&meta, None).unwrap(),
        BurnTarget {
            destination_chain_id: None,
            dst_eid: None,
            recipient: meta,
        }
    );
}

#[test]
fn v0_with_record_fails() {
    let meta = padded(&[0xab; 20]);
    let rec = BurnDestinationRecord::v1(1, 30101, &[0xab; 20]);
    assert!(resolve(&meta, Some(&rec)).is_err());
}

#[test]
fn v1_lz_resolves() {
    let (meta, rec) = v1(1, 30101, &[0x22; 20]);
    assert_eq!(
        resolve(&meta, Some(&rec)).unwrap(),
        BurnTarget {
            destination_chain_id: Some(1),
            dst_eid: Some(30101),
            recipient: padded(&[0x22; 20]),
        }
    );
}

#[test]
fn v1_direct_resolves() {
    let (meta, rec) = v1(42161, 0, &[0x22; 20]);
    assert_eq!(resolve(&meta, Some(&rec)).unwrap().dst_eid, None);
}

#[test]
fn v1_without_record_fails() {
    let (meta, _) = v1(1, 30101, &[0x22; 20]);
    assert!(resolve(&meta, None).is_err());
}

#[test]
fn v1_hash_mismatch_fails() {
    let (meta, _) = v1(1, 30101, &[0x22; 20]);
    // Each field change gives another hash.
    for rec in [
        BurnDestinationRecord::v1(2, 30101, &[0x22; 20]),
        BurnDestinationRecord::v1(1, 30102, &[0x22; 20]),
        BurnDestinationRecord::v1(1, 30101, &[0x23; 20]),
    ] {
        assert!(resolve(&meta, Some(&rec)).is_err());
    }
}

#[test]
fn unknown_version_fails() {
    let (meta, mut rec) = v1(1, 30101, &[0x22; 20]);
    for version in [0, 2] {
        rec.version = version;
        assert!(resolve(&meta, Some(&rec)).is_err());
    }
}

#[test]
fn v1_field_limits() {
    for (chain, eid, recipient) in [
        // Zero chain id.
        (0, 30101, vec![0x22; 20]),
        // Empty recipient.
        (1, 30101, vec![]),
        // Recipient over one word.
        (1, 30101, vec![0x22; 33]),
        // Direct route needs an EVM address.
        (1, 0, vec![0x22; 32]),
    ] {
        let (meta, rec) = v1(chain, eid, &recipient);
        assert!(resolve(&meta, Some(&rec)).is_err(), "{chain} {eid}");
    }
}

#[test]
fn bad_meta_length_fails() {
    assert!(resolve(&[0u8; 31], None).is_err());
}
