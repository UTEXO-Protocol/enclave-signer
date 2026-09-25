//! Fixtures shared by the crate's unit tests. Test builds only.

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
    d.extend_from_slice(&[0u8; 32 * 3]); // nativeCommission, sourceChainId, destinationChainId
    d.extend_from_slice(&abi_word(8 * 32)); // tail offset: just past the head words
    d.extend_from_slice(&abi_word(dest.len() as u64));
    let mut bytes = dest.as_bytes().to_vec();
    bytes.resize(bytes.len().div_ceil(32) * 32, 0);
    d.extend_from_slice(&bytes);
    d
}

/// In-memory EVM RPC: a fixed receipt and chain head.
#[cfg(feature = "evm-rpc")]
pub(crate) struct FakeEvm {
    pub receipt: Option<crate::networks::evm::events::ReceiptData>,
    pub head: u64,
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
}

/// A fresh regtest header chain at its built-in checkpoint.
#[cfg(feature = "rgb-validation")]
pub(crate) fn regtest_header_chain() -> std::sync::Mutex<crate::networks::rgb::spv::HeaderChain> {
    use crate::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
    std::sync::Mutex::new(HeaderChain::new(
        Network::Regtest,
        checkpoint_for(Network::Regtest),
    ))
}
