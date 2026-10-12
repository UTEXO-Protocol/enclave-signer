//! Fixtures shared by the crate's unit tests. Test builds only.

#[cfg(feature = "rgb-validation")]
pub(crate) mod bfa_consignment;

/// BFA ids as the flat summary carries them. `validation::tests` pins them
/// to `rgb-schemas`.
#[cfg(feature = "rgb-validation")]
pub(crate) mod bfa_ids {
    pub const TS_TRANSFER: u16 = 10000;
    pub const TS_BURN: u16 = 8010;
    pub const TS_MINT: u16 = 8013;
    pub const OS_ASSET: u16 = 4000;
    pub const OS_MINT: u16 = 4013;
}

/// A `uint256` ABI word holding `value`.
#[cfg(feature = "evm-rpc")]
pub(crate) fn abi_word(value: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&value.to_be_bytes());
    w
}

/// `BridgeFundsIn` log `data` in the real ABI shape: senderNonce, gross, net,
/// commission, nativeCommission, sourceChainId, destinationChainId, then the
/// `destinationAddress` tail offset, length word and padded bytes.
/// `operationId` is not here - it is an indexed topic.
#[cfg(feature = "evm-rpc")]
pub(crate) fn bridge_funds_in_data(gross: u64, net: u64, commission: u64, dest: &str) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&abi_word(0)); // senderNonce
    d.extend_from_slice(&abi_word(gross));
    d.extend_from_slice(&abi_word(net));
    d.extend_from_slice(&abi_word(commission));
    d.extend_from_slice(&[0u8; 32 * 2]); // nativeCommission, sourceChainId
    d.extend_from_slice(&abi_word(crate::networks::evm::RGB_CHAIN_ID)); // destinationChainId
    let mut bytes = dest.as_bytes().to_vec();
    bytes.resize(bytes.len().div_ceil(32) * 32, 0);
    // destinationAddress tail: after the head words.
    d.extend_from_slice(&abi_word(9 * 32));
    // settlementData tail (empty): after the string's length word and body.
    d.extend_from_slice(&abi_word((9 * 32 + 32 + bytes.len()) as u64));
    d.extend_from_slice(&abi_word(dest.len() as u64));
    d.extend_from_slice(&bytes);
    d.extend_from_slice(&abi_word(0)); // settlementData length
    d
}

/// In-memory EVM RPC: a fixed receipt, chain head, finalized block and chain.
#[cfg(feature = "evm-rpc")]
#[derive(Default)]
pub(crate) struct FakeEvm {
    pub receipt: Option<crate::networks::evm::events::ReceiptData>,
    pub head: u64,
    /// `None` is a node without the `finalized` tag.
    pub finalized: Option<u64>,
    pub chain_id: u64,
}

#[cfg(feature = "evm-rpc")]
impl crate::networks::evm::events::EvmReceiptProvider for FakeEvm {
    fn get_transaction_receipt(
        &self,
        _tx_hash: &[u8; 32],
    ) -> crate::error::Result<Option<crate::networks::evm::events::ReceiptData>> {
        Ok(self.receipt.clone())
    }

    fn get_block_number(&self) -> crate::error::Result<u64> {
        Ok(self.head)
    }

    fn get_finalized_block_number(&self) -> crate::error::Result<u64> {
        self.finalized.ok_or_else(|| {
            crate::error::EnclaveError::CrossCheck("the node has no finalized block".into())
        })
    }

    fn get_chain_id(&self) -> crate::error::Result<u64> {
        Ok(self.chain_id)
    }
}

/// An enclave clock past every `u32` header time, for tests that do not cover
/// the header clock bound (`spv::chain` tests do).
#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
pub(crate) const ANY_HEADER_CLOCK: u64 = u32::MAX as u64;

/// A fresh regtest header chain at its built-in checkpoint.
#[cfg(feature = "rgb-validation")]
pub(crate) fn regtest_header_chain() -> std::sync::Mutex<crate::networks::rgb::spv::HeaderChain> {
    use crate::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
    std::sync::Mutex::new(HeaderChain::new(
        Network::Regtest,
        checkpoint_for(Network::Regtest),
    ))
}
