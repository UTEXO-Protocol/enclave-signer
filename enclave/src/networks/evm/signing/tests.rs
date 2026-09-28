use super::*;
use crate::networks::evm::validation::decode_funds_out_params;
use hex::decode;

fn reference_params() -> FundsOutParams {
    decode_funds_out_params(&reference_call_data()).expect("reference calldata must decode")
}

#[test]
fn test_abi_encode_u256() {
    let encoded = abi_encode_u256(42);
    assert_eq!(encoded[31], 42);
    assert!(encoded[..31].iter().all(|&b| b == 0));
}

#[test]
fn test_abi_encode_u256_large() {
    let encoded = abi_encode_u256(u64::MAX);
    assert_eq!(&encoded[24..], &u64::MAX.to_be_bytes());
    assert!(encoded[..24].iter().all(|&b| b == 0));
}

#[test]
fn test_abi_encode_address() {
    let addr = [0xAA; 20];
    let encoded = abi_encode_address(&addr);
    assert!(encoded[..12].iter().all(|&b| b == 0));
    assert_eq!(&encoded[12..], &[0xAA; 20]);
}

#[test]
fn test_domain_separator_deterministic() {
    let domain = Eip712Domain {
        name: "MultisigProxy".to_string(),
        version: "1".to_string(),
        chain_id: 1,
        verifying_contract: [0u8; 20],
    };
    let hash1 = domain.separator_hash();
    let hash2 = domain.separator_hash();
    assert_eq!(hash1, hash2);
    assert_ne!(hash1, [0u8; HASH_LEN]);
}

/// Reference calldata over the fields listed in
/// [`test_digest_matches_reference_vector`]: the pre-#152 Foundry vector with
/// `sourceBurnTxId = 0xdd..dd` appended (one more head word, so every dynamic
/// tail offset moved up by 0x20).
fn reference_call_data() -> Vec<u8> {
    decode(concat!(
        "340276aa",
        "0000000000000000000000000000000000000000000000000000000000000020",
        "000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        "00000000000000000000000000000000000000000000000000000000000f4240",
        "00000000000000000000000000000000000000000000000000000000075bcd15",
        "0000000000000000000000000000000000000000000000000000000000000060",
        "0000000000000000000000000000000000000000000000000000000000007a69",
        "0000000000000000000000000000000000000000000000000000000000000120",
        "0000000000000000000000000000000000000000000000000000000000000160",
        "0000000000000000000000000000000000000000000000000000000000000200",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "0000000000000000000000000000000000000000000000000000000000000011",
        "7267623a6c6f63616c6e65742d74657374000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0000000000000000000000000000000000000000000000000000000000000065",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "000000000000000000000000000000000000000000000000000000000000006b",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "00000000000000000000000000000000000000000000000000000000000000c0",
        "0000000000000000000000000000000000000000000000000000000000000040",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "00000000000000000000000000000000000000000000000000000000000003e7",
    ))
    .unwrap()
}

fn arbitrum_domain() -> Eip712Domain {
    Eip712Domain {
        name: "MultisigProxy".to_string(),
        version: "1".to_string(),
        chain_id: 42161, // Arbitrum One
        verifying_contract: {
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&decode("eAB44D217C5Af0Cc2A46ba296b5e0eBa5B4362d0").unwrap());
            addr
        },
    }
}

/// The type string uses line continuations, so one stray space silently
/// changes the type hash and every signature with it. Pin it.
#[test]
fn test_tee_funds_out_typehash_matches_contract() {
    let type_hash: [u8; HASH_LEN] =
        Keccak256::digest(TEE_FUNDS_OUT_TYPE_HASH_STR.as_bytes()).into();
    assert_eq!(
        hex::encode(type_hash),
        "7b1c067721d3d07e40255c970c458626d43b425ca4bb0449b42baa0766cdae45"
    );
    // The pre-#152 string (no `sourceBurnTxId`) must be gone: the proxy no
    // longer verifies that struct.
    assert_ne!(
        hex::encode(type_hash),
        "e84f4b6ff956c2d754ac4310166ee6df5e488aa5a36cd65cf367cf80aff7c608"
    );
}

#[test]
fn test_tee_lz_funds_out_typehash_matches_contract() {
    let type_hash: [u8; HASH_LEN] =
        Keccak256::digest(TEE_LZ_FUNDS_OUT_TYPE_HASH_STR.as_bytes()).into();
    assert_eq!(
        hex::encode(type_hash),
        "5b65e176d2ff704611f5ee5f0709dee77247e909ddf326ff947b248ee80cdf9e"
    );
}

#[test]
fn test_funds_out_digest_deterministic() {
    let domain = arbitrum_domain();
    let params = reference_params();
    let digest1 = funds_out_digest(&domain, &params, 0, 1_700_000_000).unwrap();
    let digest2 = funds_out_digest(&domain, &params, 0, 1_700_000_000).unwrap();
    assert_eq!(digest1, digest2);
    assert_ne!(digest1, [0u8; HASH_LEN]);
}

#[test]
fn test_different_nonce_different_digest() {
    let domain = arbitrum_domain();
    let params = reference_params();
    let d1 = funds_out_digest(&domain, &params, 0, 1_700_000_000).unwrap();
    let d2 = funds_out_digest(&domain, &params, 1, 1_700_000_000).unwrap();
    assert_ne!(d1, d2);
}

/// Short and non-`fundsOut` calldata are rejected at the decode, which now
/// happens before signing rather than inside it.
#[test]
fn test_undecodable_call_data_rejected() {
    assert!(decode_funds_out_params(&[0xAA, 0xBB]).is_err());
    let erc20_transfer = decode(
        "a9059cbb000000000000000000000000abcdefabcdefabcdefabcdefabcdefabcdefabcd\
         0000000000000000000000000000000000000000000000000000000000000064",
    )
    .unwrap();
    assert!(decode_funds_out_params(&erc20_transfer).is_err());
}

/// Cross-implementation vector: Solidity, Go and this module must agree
/// byte-for-byte, or the chain recovers a garbage signer and reports it only
/// as "not a registered enclave signer".
///
/// Fields: recipient 0xf39F...2266, amount 1_000_000, burnId 123_456_789,
/// sourceChainId 96, destinationChainId 31337, sourceAddress
/// "rgb:localnet-test", proof = abi.encode(101, 0xaa..., 107, 0xbb...),
/// settlementData = abi.encode([0xcc...], [999]), sourceBurnTxId 0xdd..dd,
/// nonce 3, deadline 1_700_000_000, on the Arbitrum One domain.
///
/// The pinned digest was produced by alloy's own EIP-712 encoder over the
/// `TeeFundsOut` struct (an independent implementation of the hand-rolled
/// encoding here), and [`test_digest_matches_alloy_eip712`] re-derives it at
/// test time. The pre-#152 Foundry vector for the same fields was
/// `fed59f73...3de5`; re-pin from Foundry once the contracts repo publishes a
/// post-#152 vector.
#[test]
fn test_digest_matches_reference_vector() {
    let digest =
        funds_out_digest(&arbitrum_domain(), &reference_params(), 3, 1_700_000_000).unwrap();
    assert_eq!(
        hex::encode(digest),
        "8535655116c6f440c2f63e7cc8141e4ffd1cab3876164a2962ee127dcb57389f"
    );
}

/// The hand-rolled struct hash against alloy's `SolStruct` EIP-712 encoding
/// of the same `TeeFundsOut` type string: two encoders, one digest.
#[test]
fn test_digest_matches_alloy_eip712() {
    use alloy_primitives::{Address, U256};
    use alloy_sol_types::{sol, SolStruct};

    sol! {
        struct TeeFundsOut {
            address recipient;
            uint256 amount;
            uint256 burnId;
            uint256 sourceChainId;
            uint256 destinationChainId;
            string sourceAddress;
            bytes proof;
            bytes settlementData;
            bytes32 sourceBurnTxId;
            uint256 nonce;
            uint256 deadline;
        }
    }
    // The `sol!` type string must be the one the module hashes.
    assert_eq!(
        TeeFundsOut::eip712_encode_type(),
        TEE_FUNDS_OUT_TYPE_HASH_STR
    );

    let domain = arbitrum_domain();
    let p = reference_params();
    let typed = TeeFundsOut {
        recipient: p.recipient,
        amount: p.amount,
        burnId: p.burnId,
        sourceChainId: p.sourceChainId,
        destinationChainId: p.destinationChainId,
        sourceAddress: p.sourceAddress.clone(),
        proof: p.proof.clone(),
        settlementData: p.settlementData.clone(),
        sourceBurnTxId: p.sourceBurnTxId,
        nonce: U256::from(3u64),
        deadline: U256::from(1_700_000_000u64),
    };
    let alloy_domain = alloy_sol_types::Eip712Domain::new(
        Some(domain.name.clone().into()),
        Some(domain.version.clone().into()),
        Some(U256::from(domain.chain_id)),
        Some(Address::from(domain.verifying_contract)),
        None,
    );
    assert_eq!(
        funds_out_digest(&domain, &p, 3, 1_700_000_000).unwrap(),
        typed.eip712_signing_hash(&alloy_domain).0
    );
}

#[test]
fn test_different_chain_id_different_domain() {
    let d1 = Eip712Domain {
        name: "MultisigProxy".to_string(),
        version: "1".to_string(),
        chain_id: 1,
        verifying_contract: [0u8; 20],
    };
    let d2 = Eip712Domain {
        name: "MultisigProxy".to_string(),
        version: "1".to_string(),
        chain_id: 137,
        verifying_contract: [0u8; 20],
    };
    assert_ne!(d1.separator_hash(), d2.separator_hash());
}

#[test]
fn test_domain_separator_matches_deployed_contract() {
    let domain = Eip712Domain {
        name: "MultisigProxy".to_string(),
        version: "1".to_string(),
        chain_id: 42161,
        verifying_contract: {
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&decode("eAB44D217C5Af0Cc2A46ba296b5e0eBa5B4362d0").unwrap());
            addr
        },
    };
    let on_chain =
        decode("8da42c1b5850d914ac94e640f4edd2030e2330b104f8448fdf3c6639cb0542ff").unwrap();
    assert_eq!(domain.separator_hash(), on_chain.as_slice());
}

// --- LZ digest tests ---

fn lz_test_domain() -> Eip712Domain {
    Eip712Domain {
        name: "MultisigProxy".to_string(),
        version: "1".to_string(),
        chain_id: 42161,
        verifying_contract: [0u8; 20],
    }
}

/// Pack `lzFundsOut` calldata using the same ABI as the node's
/// `packIMultisigProxyLzFundsOut` test helper - individual params, no
/// struct wrapper.
fn lz_test_calldata() -> Vec<u8> {
    use crate::networks::evm::validation::lzFundsOutCall;
    use alloy_primitives::{Bytes, FixedBytes, U256};
    use alloy_sol_types::SolCall;

    let mut recipient = [0u8; 32];
    recipient[31] = 0x05;

    lzFundsOutCall {
        amount: U256::from(1u64),
        burnId: U256::from(3u64),
        sourceChainId: U256::from(84u64),
        destinationChainId: U256::from(1u64),
        sourceAddress: "addr".to_string(),
        proof: Bytes::new(),
        settlementData: Bytes::new(),
        dstEid: 30101u32,
        recipient: FixedBytes(recipient),
        minAmountLD: U256::from(1u64),
        extraOptions: Bytes::new(),
        sourceBurnTxId: FixedBytes([0x5b; 32]),
    }
    .abi_encode()
}

fn lz_test_release() -> crate::proto::LzReleaseParams {
    let mut recipient = vec![0u8; 32];
    recipient[31] = 0x05;
    crate::proto::LzReleaseParams {
        dst_eid: 30101,
        min_amount_ld: 1,
        recipient,
    }
}

#[test]
fn test_lz_funds_out_digest_deterministic() {
    let domain = lz_test_domain();
    let call_data = lz_test_calldata();
    let lz_release = lz_test_release();

    let d1 = lz_funds_out_digest(&domain, &call_data, &lz_release, 7, 999_999).unwrap();
    let d2 = lz_funds_out_digest(&domain, &call_data, &lz_release, 7, 999_999).unwrap();
    assert_eq!(d1, d2);
    assert_ne!(d1, [0u8; HASH_LEN]);
}

#[test]
fn test_lz_different_nonce_different_digest() {
    let domain = lz_test_domain();
    let call_data = lz_test_calldata();
    let lz_release = lz_test_release();

    let d1 = lz_funds_out_digest(&domain, &call_data, &lz_release, 0, 999_999).unwrap();
    let d2 = lz_funds_out_digest(&domain, &call_data, &lz_release, 1, 999_999).unwrap();
    assert_ne!(d1, d2);
}

#[test]
fn test_lz_different_dst_eid_different_digest() {
    let domain = lz_test_domain();
    let call_data = lz_test_calldata();
    let lz1 = lz_test_release();
    let mut lz2 = lz_test_release();
    lz2.dst_eid = 40161; // Sepolia

    // Rebuild calldata with different dstEid for lz2.
    use crate::networks::evm::validation::lzFundsOutCall;
    use alloy_primitives::{Bytes, FixedBytes, U256};
    use alloy_sol_types::SolCall;
    let mut recipient = [0u8; 32];
    recipient[31] = 0x05;
    let call_data2 = lzFundsOutCall {
        amount: U256::from(1u64),
        burnId: U256::from(3u64),
        sourceChainId: U256::from(84u64),
        destinationChainId: U256::from(1u64),
        sourceAddress: "addr".to_string(),
        proof: Bytes::new(),
        settlementData: Bytes::new(),
        dstEid: 40161u32,
        recipient: FixedBytes(recipient),
        minAmountLD: U256::from(1u64),
        extraOptions: Bytes::new(),
        sourceBurnTxId: FixedBytes([0x5b; 32]),
    }
    .abi_encode();

    let d1 = lz_funds_out_digest(&domain, &call_data, &lz1, 0, 999_999).unwrap();
    let d2 = lz_funds_out_digest(&domain, &call_data2, &lz2, 0, 999_999).unwrap();
    assert_ne!(d1, d2);
}

#[test]
fn test_lz_rejects_dst_eid_mismatch() {
    let domain = lz_test_domain();
    let call_data = lz_test_calldata();
    let mut lz_release = lz_test_release();
    lz_release.dst_eid = 99999; // wrong

    assert!(lz_funds_out_digest(&domain, &call_data, &lz_release, 0, 999_999).is_err());
}

#[test]
fn test_lz_rejects_recipient_mismatch() {
    let domain = lz_test_domain();
    let call_data = lz_test_calldata();
    let mut lz_release = lz_test_release();
    lz_release.recipient = vec![0xAB; 32]; // wrong

    assert!(lz_funds_out_digest(&domain, &call_data, &lz_release, 0, 999_999).is_err());
}
