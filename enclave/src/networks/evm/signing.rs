use sha3::{Digest, Keccak256};

use crate::error::{EnclaveError, Result};
use crate::networks::evm::validation::decode_funds_out_params;
use crate::networks::evm::{ADDRESS_LEN, HASH_LEN};
use crate::proto::EvmDestination;

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
/// Fallible, not `assert!` (audit final I-02): with `panic = "abort"` a short
/// calldata would take the enclave down, and dev-mode skips the validation layer.
pub fn funds_out_digest(
    domain: &Eip712Domain,
    call_data: &[u8],
    nonce: u64,
    deadline: u64,
) -> Result<[u8; HASH_LEN]> {
    if call_data.len() < 4 {
        return Err(EnclaveError::CrossCheck(format!(
            "call_data must contain at least a 4-byte selector, got {} bytes",
            call_data.len()
        )));
    }
    let params = decode_funds_out_params(call_data)?;

    let struct_hash = {
        let type_hash = Keccak256::digest(TEE_FUNDS_OUT_TYPE_HASH_STR.as_bytes());

        let mut buf = Vec::with_capacity(HASH_LEN * 11);
        buf.extend_from_slice(&type_hash);
        buf.extend_from_slice(&abi_encode_address(&params.recipient.into_array()));
        // Full-width uint256s — never narrowed to the cross-checks' u64.
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

/// Wrap a struct hash into the final EIP-712 digest: `keccak256(0x1901 ‖
/// domainSeparator ‖ structHash)`.
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

/// ABI-encode an address (20 bytes, left-padded to HASH_LEN bytes).
fn abi_encode_address(addr: &[u8; ADDRESS_LEN]) -> [u8; HASH_LEN] {
    let mut buf = [0u8; HASH_LEN];
    buf[12..].copy_from_slice(addr);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;

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
        let call_data = reference_call_data();
        let digest1 = funds_out_digest(&domain, &call_data, 0, 1_700_000_000).unwrap();
        let digest2 = funds_out_digest(&domain, &call_data, 0, 1_700_000_000).unwrap();
        assert_eq!(digest1, digest2);
        assert_ne!(digest1, [0u8; HASH_LEN]);
    }

    #[test]
    fn test_different_nonce_different_digest() {
        let domain = arbitrum_domain();
        let call_data = reference_call_data();
        let d1 = funds_out_digest(&domain, &call_data, 0, 1_700_000_000).unwrap();
        let d2 = funds_out_digest(&domain, &call_data, 1, 1_700_000_000).unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_short_call_data_rejected() {
        // audit final I-02: short calldata must yield an error, never an
        // abort — with `panic = "abort"` the old assert! killed the enclave.
        let err = funds_out_digest(&arbitrum_domain(), &[0xAA, 0xBB], 0, 1_000).unwrap_err();
        assert!(
            err.to_string().contains("at least a 4-byte selector"),
            "expected short-calldata rejection, got: {err}"
        );
    }

    /// Anything that is not a decodable `fundsOut` call must fail — the old
    /// scheme would happily hash an ERC-20 `transfer` blob.
    #[test]
    fn test_non_funds_out_calldata_rejected() {
        let erc20_transfer = decode(
            "a9059cbb000000000000000000000000abcdefabcdefabcdefabcdefabcdefabcdefabcd\
             0000000000000000000000000000000000000000000000000000000000000064",
        )
        .unwrap();
        assert!(funds_out_digest(&arbitrum_domain(), &erc20_transfer, 0, 1_000).is_err());
    }

    /// Cross-implementation vector: Solidity, Go and this module must agree
    /// byte-for-byte, or the chain recovers a garbage signer and reports it only
    /// as "not a registered enclave signer". Calldata and digest come from
    /// Foundry, not from this module's own helpers.
    ///
    /// Fields: recipient 0xf39F…2266, amount 1_000_000, burnId 123_456_789,
    /// sourceChainId 96, destinationChainId 31337, sourceAddress
    /// "rgb:localnet-test", proof = abi.encode(101, 0xaa…, 107, 0xbb…),
    /// settlementData = abi.encode([0xcc…], [999]), nonce 3,
    /// deadline 1_700_000_000, on the Arbitrum One domain.
    #[test]
    fn test_digest_matches_foundry_vector() {
        let digest =
            funds_out_digest(&arbitrum_domain(), &reference_call_data(), 3, 1_700_000_000).unwrap();
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
}
