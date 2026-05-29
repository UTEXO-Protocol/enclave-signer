use sha3::{Digest, Keccak256};

const DOMAIN_TYPE_HASH_STR: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const BRIDGE_OP_TYPE_HASH_STR: &str =
    "BridgeOperation(bytes4 selector,bytes callData,uint256 nonce,uint256 deadline)";

/// EIP-712 domain separator components.
/// Must match the deployed MultisigProxy contract exactly.
pub struct Eip712Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: [u8; 20],
}

impl Eip712Domain {
    /// Compute the domain separator hash per EIP-712.
    pub fn separator_hash(&self) -> [u8; 32] {
        let type_hash = Keccak256::digest(DOMAIN_TYPE_HASH_STR.as_bytes());
        let name_hash = Keccak256::digest(self.name.as_bytes());
        let version_hash = Keccak256::digest(self.version.as_bytes());

        let mut buf = Vec::with_capacity(32 * 5);
        buf.extend_from_slice(&type_hash);
        buf.extend_from_slice(&name_hash);
        buf.extend_from_slice(&version_hash);
        buf.extend_from_slice(&abi_encode_u256(self.chain_id));
        buf.extend_from_slice(&abi_encode_address(&self.verifying_contract));

        Keccak256::digest(&buf).into()
    }
}

/// Build the EIP-712 digest matching MultisigProxy._buildDigest():
///   keccak256(abi.encode(_BRIDGE_OP_TYPEHASH, selector, keccak256(callData), nonce, deadline))
pub fn sign_request_digest(
    domain: &Eip712Domain,
    call_data: &[u8],
    nonce: u64,
    deadline: u64,
) -> [u8; 32] {
    assert!(
        call_data.len() >= 4,
        "call_data must contain at least a 4-byte selector"
    );

    let struct_hash = {
        let type_hash = Keccak256::digest(BRIDGE_OP_TYPE_HASH_STR.as_bytes());

        // bytes4 selector: abi.encode pads to 32 bytes, left-aligned (same as Solidity).
        let mut selector_padded = [0u8; 32];
        selector_padded[..4].copy_from_slice(&call_data[..4]);

        let call_data_hash = Keccak256::digest(call_data);

        let mut buf = Vec::with_capacity(32 * 5);
        buf.extend_from_slice(&type_hash);
        buf.extend_from_slice(&selector_padded);
        buf.extend_from_slice(&call_data_hash);
        buf.extend_from_slice(&abi_encode_u256(nonce));
        buf.extend_from_slice(&abi_encode_u256(deadline));

        let hash: [u8; 32] = Keccak256::digest(&buf).into();
        hash
    };

    let domain_separator = domain.separator_hash();

    let mut buf = Vec::with_capacity(2 + 32 + 32);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(&domain_separator);
    buf.extend_from_slice(&struct_hash);

    Keccak256::digest(&buf).into()
}

/// ABI-encode a u64 as a uint256 (32 bytes, big-endian, right-aligned).
fn abi_encode_u256(val: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&val.to_be_bytes());
    buf
}

/// ABI-encode an address (20 bytes, left-padded to 32 bytes).
fn abi_encode_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[12..].copy_from_slice(addr);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_ne!(hash1, [0u8; 32]);
    }

    #[test]
    fn test_sign_request_digest_deterministic() {
        let domain = Eip712Domain {
            name: "MultisigProxy".to_string(),
            version: "1".to_string(),
            chain_id: 1,
            verifying_contract: [0u8; 20],
        };
        let call_data = hex::decode(
            "a9059cbb000000000000000000000000abcdefabcdefabcdefabcdefabcdefabcdefabcd\
             0000000000000000000000000000000000000000000000000000000000000064",
        )
        .unwrap();
        let digest1 = sign_request_digest(&domain, &call_data, 0, 1_700_000_000);
        let digest2 = sign_request_digest(&domain, &call_data, 0, 1_700_000_000);
        assert_eq!(digest1, digest2);
        assert_ne!(digest1, [0u8; 32]);
    }

    #[test]
    fn test_different_nonce_different_digest() {
        let domain = Eip712Domain {
            name: "MultisigProxy".to_string(),
            version: "1".to_string(),
            chain_id: 1,
            verifying_contract: [0u8; 20],
        };
        let call_data = hex::decode("aabbccdd").unwrap();
        let d1 = sign_request_digest(&domain, &call_data, 0, 1_700_000_000);
        let d2 = sign_request_digest(&domain, &call_data, 1, 1_700_000_000);
        assert_ne!(d1, d2);
    }

    #[test]
    #[should_panic(expected = "call_data must contain at least a 4-byte selector")]
    fn test_short_call_data_panics() {
        let domain = Eip712Domain {
            name: "MultisigProxy".to_string(),
            version: "1".to_string(),
            chain_id: 1,
            verifying_contract: [0u8; 20],
        };
        sign_request_digest(&domain, &[0xAA, 0xBB], 0, 1_000);
    }

    #[test]
    fn test_digest_matches_go_bridge_computation() {
        // Cross-check: reproduce the exact digest that bridge-utexo/blsProxy/transactor.go
        // computes for a known input, ensuring enclave and contract agree.
        //
        // Go side (buildExecuteDigest):
        //   bridgeOpTypehash = keccak256("BridgeOperation(bytes4 selector,bytes callData,uint256 nonce,uint256 deadline)")
        //   selectorBytes = callData[:4] left-aligned in 32 bytes
        //   structHash = keccak256(typehash || selectorBytes || keccak256(callData) || nonce || deadline)
        //   digest = keccak256(0x19 0x01 || domainSeparator || structHash)

        let domain = Eip712Domain {
            name: "MultisigProxy".to_string(),
            version: "1".to_string(),
            chain_id: 42161, // Arbitrum One
            verifying_contract: {
                let mut addr = [0u8; 20];
                addr.copy_from_slice(
                    &hex::decode("eAB44D217C5Af0Cc2A46ba296b5e0eBa5B4362d0").unwrap(),
                );
                addr
            },
        };

        let call_data = hex::decode(
            "a9059cbb000000000000000000000000abcdefabcdefabcdefabcdefabcdefabcdefabcd\
             0000000000000000000000000000000000000000000000000000000000000064",
        )
        .unwrap();

        let nonce: u64 = 0;
        let deadline: u64 = 1_700_000_000;

        // Manually compute the expected digest step by step.
        let type_hash = Keccak256::digest(
            b"BridgeOperation(bytes4 selector,bytes callData,uint256 nonce,uint256 deadline)",
        );

        let mut selector_padded = [0u8; 32];
        selector_padded[..4].copy_from_slice(&call_data[..4]);

        let call_data_hash = Keccak256::digest(&call_data);

        let mut struct_buf = Vec::new();
        struct_buf.extend_from_slice(&type_hash);
        struct_buf.extend_from_slice(&selector_padded);
        struct_buf.extend_from_slice(&call_data_hash);
        struct_buf.extend_from_slice(&abi_encode_u256(nonce));
        struct_buf.extend_from_slice(&abi_encode_u256(deadline));
        let expected_struct_hash = Keccak256::digest(&struct_buf);

        let domain_sep = domain.separator_hash();

        let mut digest_buf = Vec::new();
        digest_buf.extend_from_slice(&[0x19, 0x01]);
        digest_buf.extend_from_slice(&domain_sep);
        digest_buf.extend_from_slice(&expected_struct_hash);
        let expected_digest: [u8; 32] = Keccak256::digest(&digest_buf).into();

        let actual_digest = sign_request_digest(&domain, &call_data, nonce, deadline);
        assert_eq!(actual_digest, expected_digest);
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
                addr.copy_from_slice(
                    &hex::decode("eAB44D217C5Af0Cc2A46ba296b5e0eBa5B4362d0").unwrap(),
                );
                addr
            },
        };
        let on_chain =
            hex::decode("8da42c1b5850d914ac94e640f4edd2030e2330b104f8448fdf3c6639cb0542ff")
                .unwrap();
        assert_eq!(domain.separator_hash(), on_chain.as_slice());
    }
}
