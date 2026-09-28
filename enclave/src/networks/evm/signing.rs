use sha3::{Digest, Keccak256};

use crate::error::{EnclaveError, Result};
use crate::networks::evm::validation::{decode_lz_funds_out_params, FundsOutParams};
use crate::networks::evm::{ADDRESS_LEN, HASH_LEN};
use crate::proto::{EvmDestination, LzReleaseParams};

const DOMAIN_TYPE_HASH_STR: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// EIP-712 type string for `MultisigProxy.fundsOutCall` (MultisigProxy.sol:143-144),
/// replacing the generic `BridgeOperation(bytes4,bytes,uint256,uint256)`: the proxy
/// no longer takes opaque calldata, so the digest commits to the release fields.
///
/// Signing the old struct recovers a different address, which surfaces on-chain
/// only as an unregistered-signer rejection. There is no interop window.
const TEE_FUNDS_OUT_TYPE_HASH_STR: &str = "TeeFundsOut(address recipient,uint256 amount,\
     uint256 burnId,uint256 sourceChainId,uint256 destinationChainId,string sourceAddress,\
     bytes proof,bytes settlementData,uint256 nonce,uint256 deadline)";

/// EIP-712 domain separator components.
/// Must match the deployed MultisigProxy contract exactly.
pub struct Eip712Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: [u8; ADDRESS_LEN],
}

impl Eip712Domain {
    /// Compute the domain separator hash per EIP-712.
    pub fn separator_hash(&self) -> [u8; HASH_LEN] {
        let type_hash = Keccak256::digest(DOMAIN_TYPE_HASH_STR.as_bytes());
        let name_hash = Keccak256::digest(self.name.as_bytes());
        let version_hash = Keccak256::digest(self.version.as_bytes());

        let mut buf = Vec::with_capacity(HASH_LEN * 5);
        buf.extend_from_slice(&type_hash);
        buf.extend_from_slice(&name_hash);
        buf.extend_from_slice(&version_hash);
        buf.extend_from_slice(&abi_encode_u256(self.chain_id));
        buf.extend_from_slice(&abi_encode_address(&self.verifying_contract));

        Keccak256::digest(&buf).into()
    }
}

/// Build EIP-712 domain from enriched request fields.
/// In dev-mode, falls back to defaults if fields are missing.
pub fn build_evm_domain(req: &EvmDestination) -> Result<Eip712Domain> {
    let chain_id = if req.chain_id > 0 {
        req.chain_id
    } else {
        #[cfg(feature = "dev-mode")]
        {
            1
        }
        #[cfg(not(feature = "dev-mode"))]
        {
            return Err(EnclaveError::CrossCheck("chain_id must be > 0".into()));
        }
    };

    let verifying_contract: [u8; ADDRESS_LEN] = if req.proxy_contract.len() == ADDRESS_LEN {
        req.proxy_contract.as_slice().try_into().map_err(|_| {
            EnclaveError::CrossCheck("proxy_contract must be {ADDRESS_LEN} bytes".into())
        })?
    } else {
        #[cfg(feature = "dev-mode")]
        {
            [0u8; ADDRESS_LEN]
        }
        #[cfg(not(feature = "dev-mode"))]
        {
            return Err(EnclaveError::CrossCheck(format!(
                "proxy_contract must be {ADDRESS_LEN} bytes, got {}",
                req.proxy_contract.len()
            )));
        }
    };

    Ok(Eip712Domain {
        name: "MultisigProxy".to_string(),
        version: "1".to_string(),
        chain_id,
        verifying_contract,
    })
}

/// Build the EIP-712 digest that `MultisigProxy.fundsOutCall` verifies, from a
/// `fundsOut(FundsOutParams)` calldata blob.
///
/// Mirrors `MultisigProxy._fundsOutStructHash` (MultisigProxy.sol:293-315): ten
/// words, `string`/`bytes` pre-hashed. Domain separator unchanged.
///
/// Decoded rather than hashed whole, so the enclave commits to the individual
/// values the transactor will submit.
///
/// Fallible, not `assert!`: with `panic = "abort"` a short
/// calldata would take the enclave down, and dev-mode skips the validation layer.
pub fn funds_out_digest(
    domain: &Eip712Domain,
    params: &FundsOutParams,
    nonce: u64,
    deadline: u64,
) -> Result<[u8; HASH_LEN]> {
    let struct_hash = {
        let type_hash = Keccak256::digest(TEE_FUNDS_OUT_TYPE_HASH_STR.as_bytes());

        let mut buf = Vec::with_capacity(HASH_LEN * 11);
        buf.extend_from_slice(&type_hash);
        buf.extend_from_slice(&abi_encode_address(&params.recipient.into_array()));
        // Full-width uint256s - never narrowed to the cross-checks' u64.
        buf.extend_from_slice(&params.amount.to_be_bytes::<HASH_LEN>());
        buf.extend_from_slice(&params.burnId.to_be_bytes::<HASH_LEN>());
        buf.extend_from_slice(&params.sourceChainId.to_be_bytes::<HASH_LEN>());
        buf.extend_from_slice(&params.destinationChainId.to_be_bytes::<HASH_LEN>());
        // Dynamic fields enter the struct hash pre-hashed, per EIP-712.
        buf.extend_from_slice(&Keccak256::digest(params.sourceAddress.as_bytes()));
        buf.extend_from_slice(&Keccak256::digest(&params.proof));
        buf.extend_from_slice(&Keccak256::digest(&params.settlementData));
        buf.extend_from_slice(&abi_encode_u256(nonce));
        buf.extend_from_slice(&abi_encode_u256(deadline));

        let hash: [u8; HASH_LEN] = Keccak256::digest(&buf).into();
        hash
    };

    Ok(eip712_digest(domain, &struct_hash))
}

/// EIP-712 type string for `MultisigProxy.lzFundsOutCall` (MultisigProxy.sol:147).
/// Thirteen fields: the seven shared with `TeeFundsOut` plus four LZ-specific ones.
const TEE_LZ_FUNDS_OUT_TYPE_HASH_STR: &str = "TeeLzFundsOut(uint256 amount,uint256 burnId,\
     uint256 sourceChainId,uint256 destinationChainId,string sourceAddress,\
     bytes proof,bytes settlementData,uint32 dstEid,bytes32 recipient,\
     uint256 minAmountLD,bytes extraOptions,uint256 nonce,uint256 deadline)";

/// Build the EIP-712 digest that `MultisigProxy.lzFundsOutCall` verifies.
///
/// Mirrors `MultisigProxy._lzFundsOutStructHash` (MultisigProxy.sol:388-413):
/// thirteen words - dynamic fields pre-hashed, `dstEid` (uint32) padded to
/// 32 bytes. The `lz_release` proto fields are crosschecked against the decoded
/// calldata before the digest is built.
pub fn lz_funds_out_digest(
    domain: &Eip712Domain,
    call_data: &[u8],
    lz_release: &LzReleaseParams,
    nonce: u64,
    deadline: u64,
) -> Result<[u8; HASH_LEN]> {
    if call_data.len() < 4 {
        return Err(EnclaveError::CrossCheck(format!(
            "lzFundsOut call_data must be at least 4 bytes, got {}",
            call_data.len()
        )));
    }
    let params = decode_lz_funds_out_params(call_data)?;

    // Crosscheck LZ-specific fields from proto against decoded calldata.
    if lz_release.dst_eid != params.dstEid {
        return Err(EnclaveError::CrossCheck(format!(
            "lz_release.dst_eid {} != calldata dstEid {}",
            lz_release.dst_eid, params.dstEid
        )));
    }
    let recipient_bytes: [u8; 32] = params.recipient.0;
    if lz_release.recipient != recipient_bytes {
        return Err(EnclaveError::CrossCheck(
            "lz_release.recipient does not match calldata recipient".into(),
        ));
    }
    let min_amount_ld: u64 = params
        .minAmountLD
        .try_into()
        .map_err(|_| EnclaveError::CrossCheck("lzFundsOut minAmountLD exceeds u64 range".into()))?;
    if lz_release.min_amount_ld != min_amount_ld {
        return Err(EnclaveError::CrossCheck(format!(
            "lz_release.min_amount_ld {} != calldata minAmountLD {}",
            lz_release.min_amount_ld, min_amount_ld
        )));
    }

    let struct_hash = {
        let type_hash = Keccak256::digest(TEE_LZ_FUNDS_OUT_TYPE_HASH_STR.as_bytes());

        let mut buf = Vec::with_capacity(HASH_LEN * 14);
        buf.extend_from_slice(&type_hash);
        buf.extend_from_slice(&params.amount.to_be_bytes::<HASH_LEN>());
        buf.extend_from_slice(&params.burnId.to_be_bytes::<HASH_LEN>());
        buf.extend_from_slice(&params.sourceChainId.to_be_bytes::<HASH_LEN>());
        buf.extend_from_slice(&params.destinationChainId.to_be_bytes::<HASH_LEN>());
        buf.extend_from_slice(&Keccak256::digest(params.sourceAddress.as_bytes()));
        buf.extend_from_slice(&Keccak256::digest(&params.proof));
        buf.extend_from_slice(&Keccak256::digest(&params.settlementData));
        // uint32 dstEid: right-aligned in a 32-byte word (same as Solidity uint32 ABI-encoding).
        buf.extend_from_slice(&abi_encode_u32(params.dstEid));
        // bytes32 recipient: already 32 bytes, used as-is.
        buf.extend_from_slice(&recipient_bytes);
        buf.extend_from_slice(&params.minAmountLD.to_be_bytes::<HASH_LEN>());
        buf.extend_from_slice(&Keccak256::digest(&params.extraOptions));
        buf.extend_from_slice(&abi_encode_u256(nonce));
        buf.extend_from_slice(&abi_encode_u256(deadline));

        let hash: [u8; HASH_LEN] = Keccak256::digest(&buf).into();
        hash
    };

    Ok(eip712_digest(domain, &struct_hash))
}

/// Wrap a struct hash into the final EIP-712 digest: `keccak256(0x1901 ||
/// domainSeparator || structHash)`.
fn eip712_digest(domain: &Eip712Domain, struct_hash: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let domain_separator = domain.separator_hash();

    let mut buf = Vec::with_capacity(2 + HASH_LEN + HASH_LEN);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(&domain_separator);
    buf.extend_from_slice(struct_hash);

    Keccak256::digest(&buf).into()
}

/// ABI-encode a u64 as a uint256 (HASH_LEN bytes, big-endian, right-aligned).
fn abi_encode_u256(val: u64) -> [u8; HASH_LEN] {
    let mut buf = [0u8; HASH_LEN];
    buf[24..].copy_from_slice(&val.to_be_bytes());
    buf
}

/// ABI-encode a u32 as a uint32 (HASH_LEN bytes, big-endian, right-aligned).
/// Matches Solidity's abi.encode(uint32) padding.
fn abi_encode_u32(val: u32) -> [u8; HASH_LEN] {
    let mut buf = [0u8; HASH_LEN];
    buf[28..].copy_from_slice(&val.to_be_bytes());
    buf
}

/// ABI-encode an address (20 bytes, left-padded to HASH_LEN bytes).
fn abi_encode_address(addr: &[u8; ADDRESS_LEN]) -> [u8; HASH_LEN] {
    let mut buf = [0u8; HASH_LEN];
    buf[12..].copy_from_slice(addr);
    buf
}

#[cfg(test)]
mod tests {
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

    /// Reference calldata from `cast calldata`, over the fields listed in
    /// [`test_digest_matches_foundry_vector`].
    fn reference_call_data() -> Vec<u8> {
        decode(concat!(
            "dc771390",
            "0000000000000000000000000000000000000000000000000000000000000020",
            "000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "00000000000000000000000000000000000000000000000000000000000f4240",
            "00000000000000000000000000000000000000000000000000000000075bcd15",
            "0000000000000000000000000000000000000000000000000000000000000060",
            "0000000000000000000000000000000000000000000000000000000000007a69",
            "0000000000000000000000000000000000000000000000000000000000000100",
            "0000000000000000000000000000000000000000000000000000000000000140",
            "00000000000000000000000000000000000000000000000000000000000001e0",
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
            "e84f4b6ff956c2d754ac4310166ee6df5e488aa5a36cd65cf367cf80aff7c608"
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
    /// as "not a registered enclave signer". Calldata and digest come from
    /// Foundry, not from this module's own helpers.
    ///
    /// Fields: recipient 0xf39F...2266, amount 1_000_000, burnId 123_456_789,
    /// sourceChainId 96, destinationChainId 31337, sourceAddress
    /// "rgb:localnet-test", proof = abi.encode(101, 0xaa..., 107, 0xbb...),
    /// settlementData = abi.encode([0xcc...], [999]), nonce 3,
    /// deadline 1_700_000_000, on the Arbitrum One domain.
    #[test]
    fn test_digest_matches_foundry_vector() {
        let digest =
            funds_out_digest(&arbitrum_domain(), &reference_params(), 3, 1_700_000_000).unwrap();
        assert_eq!(
            hex::encode(digest),
            "fed59f73692c4af5ef0bcec16b76fdc50c0a5fc15a32b38264043b8a1c283de5"
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
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use crate::networks::evm::validation::{decode_funds_out_params, lzFundsOutCall};
    use alloy_primitives::{Bytes, FixedBytes, U256};
    use alloy_sol_types::SolCall;

    fn destination(chain_id: u64, proxy_len: usize) -> EvmDestination {
        EvmDestination {
            call_data: vec![],
            nonce: 1,
            deadline: 1,
            chain_id,
            proxy_contract: vec![0xAB; proxy_len],
            calldata_amount: 0,
            calldata_commission: 0,
            lz_release: None,
        }
    }

    #[test]
    fn build_evm_domain_fills_the_pinned_name_and_version() {
        let d = build_evm_domain(&destination(42161, ADDRESS_LEN)).unwrap();
        assert_eq!(d.name, "MultisigProxy");
        assert_eq!(d.version, "1");
        assert_eq!(d.chain_id, 42161);
        assert_eq!(d.verifying_contract, [0xAB; ADDRESS_LEN]);
    }

    #[cfg(not(feature = "dev-mode"))]
    #[test]
    fn build_evm_domain_rejects_zero_chain_id() {
        let err = build_evm_domain(&destination(0, ADDRESS_LEN))
            .err()
            .expect("zero chain id must fail");
        assert!(matches!(err, EnclaveError::CrossCheck(_)), "{err}");
        assert!(err.to_string().contains("chain_id"), "{err}");
    }

    #[cfg(not(feature = "dev-mode"))]
    #[test]
    fn build_evm_domain_rejects_proxy_of_the_wrong_width() {
        for len in [0usize, 19, 21, 32] {
            let err = build_evm_domain(&destination(1, len))
                .err()
                .expect("bad proxy width must fail");
            assert!(matches!(err, EnclaveError::CrossCheck(_)), "{len}: {err}");
            assert!(
                err.to_string().contains(&format!("got {len}")),
                "{len}: {err}"
            );
        }
    }

    #[cfg(feature = "dev-mode")]
    #[test]
    fn build_evm_domain_falls_back_in_dev_mode() {
        let d = build_evm_domain(&destination(0, 0)).unwrap();
        assert_eq!(d.chain_id, 1);
        assert_eq!(d.verifying_contract, [0u8; ADDRESS_LEN]);
    }

    #[test]
    fn domain_separator_changes_with_every_field() {
        let base = Eip712Domain {
            name: "MultisigProxy".into(),
            version: "1".into(),
            chain_id: 1,
            verifying_contract: [1u8; ADDRESS_LEN],
        };
        let variants = [
            Eip712Domain {
                name: "Other".into(),
                ..dup(&base)
            },
            Eip712Domain {
                version: "2".into(),
                ..dup(&base)
            },
            Eip712Domain {
                chain_id: 2,
                ..dup(&base)
            },
            Eip712Domain {
                verifying_contract: [2u8; ADDRESS_LEN],
                ..dup(&base)
            },
        ];
        for v in &variants {
            assert_ne!(v.separator_hash(), base.separator_hash());
        }
    }

    fn dup(d: &Eip712Domain) -> Eip712Domain {
        Eip712Domain {
            name: d.name.clone(),
            version: d.version.clone(),
            chain_id: d.chain_id,
            verifying_contract: d.verifying_contract,
        }
    }

    #[test]
    fn abi_encode_u32_is_right_aligned() {
        let e = abi_encode_u32(0x0102_0304);
        assert!(e[..28].iter().all(|&b| b == 0));
        assert_eq!(&e[28..], &[1, 2, 3, 4]);
        assert_eq!(abi_encode_u32(0), [0u8; HASH_LEN]);
        assert_eq!(&abi_encode_u32(u32::MAX)[28..], &[0xff; 4]);
    }

    #[test]
    fn eip712_digest_is_keccak_of_1901_domain_struct() {
        let domain = Eip712Domain {
            name: "MultisigProxy".into(),
            version: "1".into(),
            chain_id: 5,
            verifying_contract: [9u8; ADDRESS_LEN],
        };
        let struct_hash = [0x5a; HASH_LEN];
        let mut pre = vec![0x19, 0x01];
        pre.extend_from_slice(&domain.separator_hash());
        pre.extend_from_slice(&struct_hash);
        let expected: [u8; HASH_LEN] = Keccak256::digest(&pre).into();
        assert_eq!(eip712_digest(&domain, &struct_hash), expected);
    }

    fn pools_calldata() -> Vec<u8> {
        use crate::networks::evm::validation::{fundsOutCall, FundsOutParams};
        fundsOutCall {
            params: FundsOutParams {
                recipient: alloy_primitives::Address::from([0x22; ADDRESS_LEN]),
                amount: U256::from(1_000u64),
                burnId: U256::from(7u64),
                sourceChainId: U256::from(1u64),
                destinationChainId: U256::from(1u64),
                sourceAddress: "src".into(),
                proof: Bytes::from(vec![1, 2]),
                settlementData: Bytes::from(vec![3]),
            },
        }
        .abi_encode()
    }

    #[test]
    fn funds_out_digest_binds_deadline_domain_and_every_param() {
        let domain = build_evm_domain(&destination(1, ADDRESS_LEN)).unwrap();
        let params = decode_funds_out_params(&pools_calldata()).unwrap();
        let base = funds_out_digest(&domain, &params, 1, 100).unwrap();
        assert_ne!(base, funds_out_digest(&domain, &params, 1, 101).unwrap());
        let other_domain = build_evm_domain(&destination(2, ADDRESS_LEN)).unwrap();
        assert_ne!(
            base,
            funds_out_digest(&other_domain, &params, 1, 100).unwrap()
        );
        let mut p = decode_funds_out_params(&pools_calldata()).unwrap();
        p.settlementData = Bytes::from(vec![4]);
        assert_ne!(base, funds_out_digest(&domain, &p, 1, 100).unwrap());
        let mut p = decode_funds_out_params(&pools_calldata()).unwrap();
        p.sourceAddress = "other".into();
        assert_ne!(base, funds_out_digest(&domain, &p, 1, 100).unwrap());
        let mut p = decode_funds_out_params(&pools_calldata()).unwrap();
        p.burnId = U256::from(8u64);
        assert_ne!(base, funds_out_digest(&domain, &p, 1, 100).unwrap());
    }

    fn lz_domain() -> Eip712Domain {
        Eip712Domain {
            name: "MultisigProxy".into(),
            version: "1".into(),
            chain_id: 42161,
            verifying_contract: [0u8; ADDRESS_LEN],
        }
    }

    fn lz_call(min_amount_ld: U256) -> lzFundsOutCall {
        let mut recipient = [0u8; 32];
        recipient[31] = 0x05;
        lzFundsOutCall {
            amount: U256::from(1u64),
            burnId: U256::from(3u64),
            sourceChainId: U256::from(84u64),
            destinationChainId: U256::from(1u64),
            sourceAddress: "addr".into(),
            proof: Bytes::new(),
            settlementData: Bytes::new(),
            dstEid: 30101,
            recipient: FixedBytes(recipient),
            minAmountLD: min_amount_ld,
            extraOptions: Bytes::new(),
        }
    }

    fn lz_release(min_amount_ld: u64) -> LzReleaseParams {
        let mut recipient = vec![0u8; 32];
        recipient[31] = 0x05;
        LzReleaseParams {
            dst_eid: 30101,
            min_amount_ld,
            recipient,
        }
    }

    #[test]
    fn lz_digest_rejects_calldata_shorter_than_a_selector() {
        for len in [0usize, 1, 3] {
            let err = lz_funds_out_digest(&lz_domain(), &vec![0u8; len], &lz_release(1), 1, 1)
                .unwrap_err();
            assert!(matches!(err, EnclaveError::CrossCheck(_)), "{len}: {err}");
            assert!(err.to_string().contains("at least 4 bytes"), "{len}: {err}");
        }
    }

    #[test]
    fn lz_digest_rejects_undecodable_and_non_canonical_calldata() {
        let selector_only = lz_call(U256::from(1u64)).abi_encode()[..4].to_vec();
        let err =
            lz_funds_out_digest(&lz_domain(), &selector_only, &lz_release(1), 1, 1).unwrap_err();
        assert!(
            err.to_string().contains("invalid lzFundsOut calldata"),
            "{err}"
        );

        let mut trailing = lz_call(U256::from(1u64)).abi_encode();
        trailing.push(0);
        let err = lz_funds_out_digest(&lz_domain(), &trailing, &lz_release(1), 1, 1).unwrap_err();
        assert!(err.to_string().contains("non-canonical"), "{err}");

        // The pools selector is not an lzFundsOut call.
        let err =
            lz_funds_out_digest(&lz_domain(), &pools_calldata(), &lz_release(1), 1, 1).unwrap_err();
        assert!(matches!(err, EnclaveError::CrossCheck(_)), "{err}");
    }

    #[test]
    fn lz_digest_rejects_min_amount_mismatch_and_u64_overflow() {
        let call = lz_call(U256::from(1u64)).abi_encode();
        let err = lz_funds_out_digest(&lz_domain(), &call, &lz_release(2), 1, 1).unwrap_err();
        assert!(err.to_string().contains("min_amount_ld"), "{err}");

        let wide = lz_call(U256::from(u64::MAX) + U256::from(1u64)).abi_encode();
        let err =
            lz_funds_out_digest(&lz_domain(), &wide, &lz_release(u64::MAX), 1, 1).unwrap_err();
        assert!(err.to_string().contains("exceeds u64"), "{err}");

        // Exactly u64::MAX fits.
        let max = lz_call(U256::from(u64::MAX)).abi_encode();
        assert!(lz_funds_out_digest(&lz_domain(), &max, &lz_release(u64::MAX), 1, 1).is_ok());
    }

    #[test]
    fn lz_digest_binds_deadline_and_recipient_and_domain() {
        let call = lz_call(U256::from(1u64)).abi_encode();
        let base = lz_funds_out_digest(&lz_domain(), &call, &lz_release(1), 1, 10).unwrap();
        assert_ne!(
            base,
            lz_funds_out_digest(&lz_domain(), &call, &lz_release(1), 1, 11).unwrap()
        );
        let other_domain = Eip712Domain {
            chain_id: 1,
            ..lz_domain()
        };
        assert_ne!(
            base,
            lz_funds_out_digest(&other_domain, &call, &lz_release(1), 1, 10).unwrap()
        );
        let mut other_recipient = lz_call(U256::from(1u64));
        other_recipient.recipient = FixedBytes([0x06; 32]);
        let mut release = lz_release(1);
        release.recipient = vec![0x06; 32];
        assert_ne!(
            base,
            lz_funds_out_digest(&lz_domain(), &other_recipient.abi_encode(), &release, 1, 10)
                .unwrap()
        );
    }

    #[test]
    fn lz_digest_rejects_a_recipient_of_the_wrong_width_on_the_wire() {
        let call = lz_call(U256::from(1u64)).abi_encode();
        let mut release = lz_release(1);
        release.recipient = vec![0x05; 31];
        let err = lz_funds_out_digest(&lz_domain(), &call, &release, 1, 1).unwrap_err();
        assert!(err.to_string().contains("recipient"), "{err}");
    }

    #[test]
    fn lz_typehash_string_lists_thirteen_fields_in_contract_order() {
        let inner = TEE_LZ_FUNDS_OUT_TYPE_HASH_STR
            .strip_prefix("TeeLzFundsOut(")
            .and_then(|s| s.strip_suffix(')'))
            .unwrap();
        let fields: Vec<&str> = inner.split(',').collect();
        assert_eq!(fields.len(), 13);
        assert_eq!(fields[0], "uint256 amount");
        assert_eq!(fields[7], "uint32 dstEid");
        assert_eq!(fields[8], "bytes32 recipient");
        assert_eq!(fields[12], "uint256 deadline");
        let inner = TEE_FUNDS_OUT_TYPE_HASH_STR
            .strip_prefix("TeeFundsOut(")
            .and_then(|s| s.strip_suffix(')'))
            .unwrap();
        assert_eq!(inner.split(',').count(), 10);
    }
}
