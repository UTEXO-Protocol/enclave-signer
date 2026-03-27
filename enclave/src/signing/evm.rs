use sha3::{Digest, Keccak256};

// TODO: align with final MultisigProxy.sol — may need selector field
const DOMAIN_TYPE_HASH_STR: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const SIGN_REQUEST_TYPE_HASH_STR: &str =
    "SignRequest(bytes callData,uint256 nonce,uint256 deadline)";

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

/// Build the EIP-712 digest for: SignRequest(bytes callData, uint256 nonce, uint256 deadline)
/// Returns the 32-byte hash ready to be signed with ECDSA.
pub fn sign_request_digest(
    domain: &Eip712Domain,
    call_data: &[u8],
    nonce: u64,
    deadline: u64,
) -> [u8; 32] {
    let struct_hash = {
        let type_hash = Keccak256::digest(SIGN_REQUEST_TYPE_HASH_STR.as_bytes());
        let call_data_hash = Keccak256::digest(call_data);

        let mut buf = Vec::with_capacity(32 * 4);
        buf.extend_from_slice(&type_hash);
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
            name: "Tricorn".to_string(),
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
            name: "Tricorn".to_string(),
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
            name: "Tricorn".to_string(),
            version: "1".to_string(),
            chain_id: 1,
            verifying_contract: [0u8; 20],
        };
        let call_data = b"test";
        let d1 = sign_request_digest(&domain, call_data, 0, 1_700_000_000);
        let d2 = sign_request_digest(&domain, call_data, 1, 1_700_000_000);
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_different_chain_id_different_domain() {
        let d1 = Eip712Domain {
            name: "Tricorn".to_string(),
            version: "1".to_string(),
            chain_id: 1,
            verifying_contract: [0u8; 20],
        };
        let d2 = Eip712Domain {
            name: "Tricorn".to_string(),
            version: "1".to_string(),
            chain_id: 137,
            verifying_contract: [0u8; 20],
        };
        assert_ne!(d1.separator_hash(), d2.separator_hash());
    }
}
