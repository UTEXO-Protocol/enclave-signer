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
pub fn build_evm_domain(req: &EvmDestination) -> Result<Eip712Domain> {
    if req.chain_id == 0 {
        return Err(EnclaveError::CrossCheck("chain_id must be > 0".into()));
    }
    let chain_id = req.chain_id;

    let verifying_contract: [u8; ADDRESS_LEN] =
        req.proxy_contract.as_slice().try_into().map_err(|_| {
            EnclaveError::CrossCheck(format!(
                "proxy_contract must be {ADDRESS_LEN} bytes, got {}",
                req.proxy_contract.len()
            ))
        })?;

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
/// calldata would take the enclave down.
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
mod tests;
