use super::*;
use crate::networks::evm::validation::decode_funds_out_params;
use hex::decode;

fn reference_params() -> FundsOutParams {
    decode_funds_out_params(&reference_call_data()).expect("reference calldata must decode")
}

/// Reference calldata for the fields in
/// [`test_digest_matches_reference_vector`], with `sourceBurnTxId = 0xdd..dd`.
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

/// The type string uses line continuations. One stray space changes the type
/// hash and each signature. Pin it.
#[test]
fn test_tee_funds_out_typehash_matches_contract() {
    let type_hash: [u8; HASH_LEN] =
        Keccak256::digest(TEE_FUNDS_OUT_TYPE_HASH_STR.as_bytes()).into();
    assert_eq!(
        hex::encode(type_hash),
        "7b1c067721d3d07e40255c970c458626d43b425ca4bb0449b42baa0766cdae45"
    );
    // The string without `sourceBurnTxId` must not match: the proxy does not
    // verify that struct.
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

/// Fixed digest mathematics for fields outside the current RGB admission rules.
///
/// Fields: recipient 0xf39F...2266, amount 1_000_000, burnId 123_456_789,
/// sourceChainId 96, destinationChainId 31337, sourceAddress
/// "rgb:localnet-test", proof = abi.encode(101, 0xaa..., 107, 0xbb...),
/// settlementData = abi.encode([0xcc...], [999]), sourceBurnTxId 0xdd..dd,
/// nonce 3, deadline 1_700_000_000, on the Arbitrum One domain.
///
/// The independent Alloy encoder in [`test_digest_matches_alloy_eip712`]
/// reproduces these bytes. This does not execute Solidity or an admitted Burn.
#[test]
fn test_digest_matches_reference_vector() {
    let digest =
        funds_out_digest(&arbitrum_domain(), &reference_params(), 3, 1_700_000_000).unwrap();
    assert_eq!(
        hex::encode(digest),
        "8535655116c6f440c2f63e7cc8141e4ffd1cab3876164a2962ee127dcb57389f"
    );
}

/// Compares the hand-written struct hash with the alloy `SolStruct` EIP-712
/// encoding of the same `TeeFundsOut` type: two encoders, one digest.
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
        hex::encode(alloy_domain.separator()),
        "8da42c1b5850d914ac94e640f4edd2030e2330b104f8448fdf3c6639cb0542ff"
    );
    assert_eq!(
        hex::encode(typed.eip712_signing_hash(&alloy_domain)),
        "8535655116c6f440c2f63e7cc8141e4ffd1cab3876164a2962ee127dcb57389f"
    );
    assert_eq!(
        funds_out_digest(&domain, &p, 3, 1_700_000_000).unwrap(),
        typed.eip712_signing_hash(&alloy_domain).0
    );
}

#[test]
fn test_domain_separator_matches_reference_vector() {
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
    let expected =
        decode("8da42c1b5850d914ac94e640f4edd2030e2330b104f8448fdf3c6639cb0542ff").unwrap();
    assert_eq!(domain.separator_hash(), expected.as_slice());
}

#[test]
#[cfg(feature = "rgb-validation")]
fn shared_json_calculation_vectors() {
    use crate::config::BridgeConfig;
    use crate::networks::evm::crosscheck::validate_funds_out_settlement;
    use crate::networks::evm::events::derived_lock;
    use crate::networks::evm::validation::{expected_burn_id, ReleaseIdentity};
    use crate::networks::rgb::validation::lock_id;
    use alloy_primitives::U256;
    use bitcoin::hashes::Hash as _;
    use serde_json::Value;

    fn bytes(value: &Value) -> Vec<u8> {
        decode(value.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
    }
    fn word(value: &Value) -> [u8; 32] {
        bytes(value).try_into().unwrap()
    }
    fn uint(value: &Value) -> U256 {
        U256::from_str_radix(value.as_str().unwrap(), 10).unwrap()
    }

    let vectors: Value =
        serde_json::from_str(include_str!("../../../../../docs/burn-shared-vectors.json")).unwrap();
    assert_eq!(vectors["rgbNetwork"].as_str(), Some("827166"));
    let fields = &vectors["domain"];
    let cfg = BridgeConfig {
        chain_id: uint(&fields["chainId"]).try_into().unwrap(),
        funds_in_contract: bytes(&vectors["bridge"]).try_into().unwrap(),
        token_contract: bytes(&vectors["token"]).try_into().unwrap(),
        ..Default::default()
    };
    let domain = build_evm_domain(&EvmDestination {
        chain_id: cfg.chain_id,
        proxy_contract: bytes(&fields["verifyingContract"]),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(domain.name, fields["name"].as_str().unwrap());
    assert_eq!(domain.version, fields["version"].as_str().unwrap());
    assert_eq!(domain.separator_hash(), word(&fields["separator"]));
    let mints = vectors["mints"].as_array().unwrap();
    assert_eq!(mints.len(), 2);
    let locks: Vec<_> = mints
        .iter()
        .map(|mint| {
            let witness = bitcoin::Txid::from_byte_array(word(&mint["witnessTxidInternal"]));
            assert_eq!(
                format!("0x{witness}"),
                mint["witnessTxidDisplay"].as_str().unwrap()
            );
            let lock = lock_id(rgbstd::OpId::from(word(&mint["opId"])), witness);
            assert_eq!(lock, word(&mint["lockId"]));
            let verified =
                derived_lock(&cfg, lock, uint(&mint["amount"]).try_into().unwrap()).unwrap();
            assert_eq!(verified.operation_id, word(&mint["depositId"]));
            verified
        })
        .collect();
    let releases = vectors["releases"].as_array().unwrap();
    assert_eq!(releases.len(), 2);
    let burn_id = U256::from_be_bytes(word(&vectors["burn"]["id"]));
    for (case, name) in releases.iter().zip(["direct", "layerzero"]) {
        assert_eq!(case["name"].as_str(), Some(name));
        assert_eq!(case["route"].as_str(), Some(name));
        let expected_bytes = &case["expected"];
        let expected = ReleaseIdentity {
            burn_id: uint(&case["burnId"]),
            amount: uint(&case["amount"]),
            source_chain_id: uint(&case["sourceChainId"]),
            source_address: case["sourceAddress"].as_str().unwrap().into(),
            settlement_data: bytes(&case["settlementData"]),
            source_burn_tx_id: word(&case["sourceBurnTxId"]),
            recipient: U256::from_be_slice(&bytes(&case["recipient"])).to_be_bytes(),
            destination_chain_id: uint(&case["destinationChainId"]),
            dst_eid: case["dstEid"].as_str().map(|s| s.parse().unwrap()),
            proof: bytes(&case["proof"]),
        };
        let calldata = bytes(&expected_bytes["calldata"]);
        let nonce = uint(&case["nonce"]).try_into().unwrap();
        let deadline = uint(&case["deadline"]).try_into().unwrap();
        let (actual, digest, type_string) = match name {
            "direct" => {
                let params = decode_funds_out_params(&calldata).unwrap();
                (
                    ReleaseIdentity::from_funds_out(&params),
                    funds_out_digest(&domain, &params, nonce, deadline).unwrap(),
                    TEE_FUNDS_OUT_TYPE_HASH_STR,
                )
            }
            "layerzero" => {
                let params = decode_lz_funds_out_params(&calldata).unwrap();
                assert_eq!(params.extraOptions.to_vec(), bytes(&case["extraOptions"]));
                let lz = LzReleaseParams {
                    dst_eid: uint(&case["dstEid"]).try_into().unwrap(),
                    recipient: bytes(&case["recipient"]),
                    min_amount_ld: uint(&case["minAmountLD"]).try_into().unwrap(),
                };
                (
                    ReleaseIdentity::from_lz_funds_out(&params),
                    lz_funds_out_digest(&domain, &calldata, &lz, nonce, deadline).unwrap(),
                    TEE_LZ_FUNDS_OUT_TYPE_HASH_STR,
                )
            }
            _ => unreachable!(),
        };
        assert_eq!(actual, expected, "{name}");
        assert_eq!(actual.source_chain_id, U256::from(827166));
        assert!(actual.source_address.is_empty());
        assert_eq!(digest, word(&expected_bytes["digest"]));
        assert_eq!(
            Keccak256::digest(type_string).as_slice(),
            word(&expected_bytes["typeHash"])
        );
        assert_eq!(
            eip712_digest(&domain, &word(&expected_bytes["structHash"])),
            digest
        );
        assert_eq!(expected_burn_id(&cfg, &actual), burn_id);
        assert_eq!(actual.burn_id, burn_id);
        assert_eq!(
            actual.settlement_data,
            bytes(&vectors["settlement"]["encoded"])
        );
        assert_eq!(actual.proof, bytes(&vectors["proof"]["encoded"]));
        validate_funds_out_settlement(&actual, &locks).unwrap();
    }
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

/// The inner LZ intent uses individual ABI parameters rather than a tuple.
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

/// The independent Alloy EIP-712 encoder checks field order, dynamic-field
/// hashes, and every signed value against the handwritten production encoder.
/// These synthetic fields test hash mathematics, not complete Burn admission.
#[test]
fn test_lz_digest_matches_independent_encoder_for_every_field() {
    use crate::networks::evm::validation::lzFundsOutCall;
    use alloy_primitives::{Address, U256};
    use alloy_sol_types::{sol, SolCall, SolStruct};

    sol! {
        struct TeeLzFundsOut {
            uint256 amount;
            uint256 burnId;
            uint256 sourceChainId;
            uint256 destinationChainId;
            string sourceAddress;
            bytes proof;
            bytes settlementData;
            uint32 dstEid;
            bytes32 recipient;
            uint256 minAmountLD;
            bytes extraOptions;
            bytes32 sourceBurnTxId;
            uint256 nonce;
            uint256 deadline;
        }
    }
    let domain = arbitrum_domain();
    let alloy_domain = alloy_sol_types::Eip712Domain::new(
        Some("MultisigProxy".into()),
        Some("1".into()),
        Some(U256::from(42161)),
        Some(Address::from(domain.verifying_contract)),
        None,
    );
    let mut baseline = None;
    // Case zero is the positive control. Each other case changes exactly one
    // signed field, including the fields not present in the proto cross-check.
    for field in 0..=14 {
        let mut typed = TeeLzFundsOut {
            amount: U256::from(1000),
            burnId: U256::from(123),
            sourceChainId: U256::from(827166),
            destinationChainId: U256::from(137),
            sourceAddress: "rgb:fixture".into(),
            proof: vec![1, 2, 3].into(),
            settlementData: vec![4, 5, 6].into(),
            dstEid: 30109,
            recipient: [0x22; 32].into(),
            minAmountLD: U256::from(900),
            extraOptions: vec![0, 3, 1, 0, 1].into(),
            sourceBurnTxId: [0x55; 32].into(),
            nonce: U256::from(7),
            deadline: U256::from(1_700_000_000u64),
        };
        match field {
            0 => {}
            1 => typed.amount += U256::from(1),
            2 => typed.burnId += U256::from(1),
            3 => typed.sourceChainId += U256::from(1),
            4 => typed.destinationChainId += U256::from(1),
            5 => typed.sourceAddress.push('x'),
            6 => typed.proof = vec![1, 2, 4].into(),
            7 => typed.settlementData = vec![4, 5, 7].into(),
            8 => typed.dstEid += 1,
            9 => typed.recipient.0[0] ^= 1,
            10 => typed.minAmountLD += U256::from(1),
            11 => typed.extraOptions = vec![0, 3, 1, 0, 2].into(),
            12 => typed.sourceBurnTxId.0[0] ^= 1,
            13 => typed.nonce += U256::from(1),
            14 => typed.deadline += U256::from(1),
            _ => unreachable!(),
        }
        let call = lzFundsOutCall {
            amount: typed.amount,
            burnId: typed.burnId,
            sourceChainId: typed.sourceChainId,
            destinationChainId: typed.destinationChainId,
            sourceAddress: typed.sourceAddress.clone(),
            proof: typed.proof.clone(),
            settlementData: typed.settlementData.clone(),
            dstEid: typed.dstEid,
            recipient: typed.recipient,
            minAmountLD: typed.minAmountLD,
            extraOptions: typed.extraOptions.clone(),
            sourceBurnTxId: typed.sourceBurnTxId,
        };
        let release = LzReleaseParams {
            dst_eid: typed.dstEid,
            recipient: typed.recipient.to_vec(),
            min_amount_ld: typed.minAmountLD.try_into().unwrap(),
        };
        let digest = lz_funds_out_digest(
            &domain,
            &call.abi_encode(),
            &release,
            typed.nonce.try_into().unwrap(),
            typed.deadline.try_into().unwrap(),
        )
        .unwrap();
        assert_eq!(
            digest,
            typed.eip712_signing_hash(&alloy_domain).0,
            "field {field}"
        );
        if let Some(original) = baseline {
            assert_ne!(digest, original, "field {field} must be signed");
        } else {
            baseline = Some(digest);
        }
    }
}

#[test]
fn test_lz_rejects_min_amount_mismatch_and_overflow() {
    use crate::networks::evm::validation::lzFundsOutCall;
    use alloy_primitives::U256;
    use alloy_sol_types::SolCall;
    let domain = lz_test_domain();
    let release = lz_test_release();
    let mut call = lzFundsOutCall::abi_decode_validate(&lz_test_calldata()).unwrap();
    lz_funds_out_digest(&domain, &call.abi_encode(), &release, 7, 999_999).unwrap();
    call.minAmountLD = U256::from(release.min_amount_ld + 1);
    let err = lz_funds_out_digest(&domain, &call.abi_encode(), &release, 7, 999_999).unwrap_err();
    assert!(
        err.to_string().contains("lz_release.min_amount_ld"),
        "{err}"
    );
    call.minAmountLD = U256::from(u64::MAX) + U256::from(1);
    let err = lz_funds_out_digest(&domain, &call.abi_encode(), &release, 7, 999_999).unwrap_err();
    assert!(
        err.to_string().contains("minAmountLD exceeds u64 range"),
        "{err}"
    );
}
