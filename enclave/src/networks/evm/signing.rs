use sha3::{Digest, Keccak256};

use crate::error::{EnclaveError, Result};
use crate::networks::evm::validation::{decode_lz_funds_out_params, FundsOutParams};
use crate::networks::evm::{ADDRESS_LEN, HASH_LEN};
use crate::proto::{EvmDestination, LzReleaseParams};

const DOMAIN_TYPE_HASH_STR: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// EIP-712 type string for `MultisigProxy.fundsOutCall` (MultisigProxy.sol:173-175).
/// The digest commits to each release field. `sourceBurnTxId` (bridge PR #152)
/// follows `settlementData`.
///
/// A wrong struct recovers a different address. On chain, this shows only as
/// an unregistered-signer rejection.
const TEE_FUNDS_OUT_TYPE_HASH_STR: &str = "TeeFundsOut(address recipient,uint256 amount,\
     uint256 burnId,uint256 sourceChainId,uint256 destinationChainId,string sourceAddress,\
     bytes proof,bytes settlementData,bytes32 sourceBurnTxId,uint256 nonce,uint256 deadline)";

/// EIP-712 domain separator fields. They must match the deployed MultisigProxy.
pub struct Eip712Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: [u8; ADDRESS_LEN],
}

impl Eip712Domain {
    /// Computes the EIP-712 domain separator hash.
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

/// Builds the EIP-712 domain from the request fields.
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

/// Builds the EIP-712 digest that `MultisigProxy.fundsOutCall` verifies.
///
/// Mirrors `MultisigProxy._fundsOutStructHash` (MultisigProxy.sol:334-359):
/// eleven fields, `string`/`bytes` pre-hashed, `bytes32 sourceBurnTxId` as-is.
///
/// The enclave hashes the decoded fields, so it commits to the values that the
/// transactor submits.
///
/// Returns `Result`, not `assert!`: with `panic = "abort"`, bad input would
/// stop the enclave.
pub fn funds_out_digest(
    domain: &Eip712Domain,
    params: &FundsOutParams,
    nonce: u64,
    deadline: u64,
) -> Result<[u8; HASH_LEN]> {
    let struct_hash = {
        let type_hash = Keccak256::digest(TEE_FUNDS_OUT_TYPE_HASH_STR.as_bytes());

        let mut buf = Vec::with_capacity(HASH_LEN * 12);
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
        // bytes32 sourceBurnTxId: a static word, used as-is (not pre-hashed).
        buf.extend_from_slice(&params.sourceBurnTxId.0);
        buf.extend_from_slice(&abi_encode_u256(nonce));
        buf.extend_from_slice(&abi_encode_u256(deadline));

        let hash: [u8; HASH_LEN] = Keccak256::digest(&buf).into();
        hash
    };

    Ok(eip712_digest(domain, &struct_hash))
}

/// EIP-712 type string for `MultisigProxy.lzFundsOutCall` (MultisigProxy.sol:176-178).
/// Fourteen fields. `sourceBurnTxId` (bridge PR #152) follows `extraOptions`.
const TEE_LZ_FUNDS_OUT_TYPE_HASH_STR: &str = "TeeLzFundsOut(uint256 amount,uint256 burnId,\
     uint256 sourceChainId,uint256 destinationChainId,string sourceAddress,\
     bytes proof,bytes settlementData,uint32 dstEid,bytes32 recipient,\
     uint256 minAmountLD,bytes extraOptions,bytes32 sourceBurnTxId,uint256 nonce,\
     uint256 deadline)";

/// Builds the EIP-712 digest that `MultisigProxy.lzFundsOutCall` verifies.
///
/// Mirrors `MultisigProxy._lzFundsOutStructHash` (MultisigProxy.sol:504-544):
/// fourteen fields, dynamic fields pre-hashed, `dstEid` (uint32) padded to 32
/// bytes, `sourceBurnTxId` (bytes32) as-is. The `lz_release` proto fields must
/// match the decoded calldata before the digest is built.
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

    // Cross-check the LZ proto fields against the decoded calldata.
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

        let mut buf = Vec::with_capacity(HASH_LEN * 15);
        buf.extend_from_slice(&type_hash);
        buf.extend_from_slice(&params.amount.to_be_bytes::<HASH_LEN>());
        buf.extend_from_slice(&params.burnId.to_be_bytes::<HASH_LEN>());
        buf.extend_from_slice(&params.sourceChainId.to_be_bytes::<HASH_LEN>());
        buf.extend_from_slice(&params.destinationChainId.to_be_bytes::<HASH_LEN>());
        buf.extend_from_slice(&Keccak256::digest(params.sourceAddress.as_bytes()));
        buf.extend_from_slice(&Keccak256::digest(&params.proof));
        buf.extend_from_slice(&Keccak256::digest(&params.settlementData));
        // uint32 dstEid: right-aligned in a 32-byte word, as Solidity ABI-encodes it.
        buf.extend_from_slice(&abi_encode_u32(params.dstEid));
        // bytes32 recipient: used as-is.
        buf.extend_from_slice(&recipient_bytes);
        buf.extend_from_slice(&params.minAmountLD.to_be_bytes::<HASH_LEN>());
        buf.extend_from_slice(&Keccak256::digest(&params.extraOptions));
        buf.extend_from_slice(&params.sourceBurnTxId.0);
        buf.extend_from_slice(&abi_encode_u256(nonce));
        buf.extend_from_slice(&abi_encode_u256(deadline));

        let hash: [u8; HASH_LEN] = Keccak256::digest(&buf).into();
        hash
    };

    Ok(eip712_digest(domain, &struct_hash))
}

/// Wraps a struct hash into the final EIP-712 digest: `keccak256(0x1901 ||
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

/// ABI-encode a u32 as a uint32 (HASH_LEN bytes, big-endian, right-aligned),
/// as Solidity `abi.encode(uint32)` does.
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
