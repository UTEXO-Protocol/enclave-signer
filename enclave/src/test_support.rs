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

/// In-memory EVM RPC: a fixed receipt covered by each tagged canonical head,
/// on chain `chain_id`.
#[cfg(feature = "evm-rpc")]
#[derive(Default)]
pub(crate) struct FakeEvm {
    pub receipt: Option<crate::networks::evm::events::ReceiptData>,
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

    fn get_block_by_tag(
        &self,
        _tag: attestation_verify::EvmFinalityTag,
    ) -> crate::error::Result<Option<crate::networks::evm::events::BlockData>> {
        use crate::networks::evm::events::BlockData;
        Ok(Some(BlockData {
            number: self.receipt.as_ref().map_or(0, |r| r.block_number),
            hash: self.receipt.as_ref().map_or([0x42; 32], |r| r.block_hash),
        }))
    }

    fn get_block_by_number(
        &self,
        number: u64,
    ) -> crate::error::Result<Option<crate::networks::evm::events::BlockData>> {
        Ok(self
            .receipt
            .as_ref()
            .map(|receipt| crate::networks::evm::events::BlockData {
                number,
                hash: receipt.block_hash,
            }))
    }

    fn get_chain_id(&self) -> crate::error::Result<u64> {
        Ok(self.chain_id)
    }
}

/// A request deadline no test reaches.
#[cfg(feature = "evm-rpc")]
pub(crate) fn far_deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(3600)
}

/// The `eth_call`s a [`ListEvm`] saw, as (selector, block).
#[cfg(feature = "bfa-validation")]
pub(crate) type CallLog = std::sync::Arc<std::sync::Mutex<Vec<([u8; 4], u64)>>>;

/// In-memory `IRgbRejectList` behind an EVM RPC on chain `chain_id`. The
/// first `finalized_len` entries are finalized; `None` means no code at the
/// finalized block. Records each `eth_call` as (selector, block).
#[cfg(feature = "bfa-validation")]
pub(crate) struct ListEvm {
    pub chain_id: u64,
    pub latest: u64,
    pub finalized: Option<u64>,
    pub deployed: bool,
    pub finalized_len: Option<u64>,
    pub entries: Vec<crate::networks::rgb::validation::RejectListEntry>,
    /// Replaces every `entries` reply.
    pub entries_reply: Option<Vec<u8>>,
    pub calls: CallLog,
}

#[cfg(feature = "bfa-validation")]
impl ListEvm {
    /// A deployed list of `entries` on chain `chain_id`, all finalized.
    pub fn new(
        chain_id: u64,
        entries: Vec<crate::networks::rgb::validation::RejectListEntry>,
    ) -> Self {
        Self {
            chain_id,
            latest: 200,
            finalized: Some(100),
            deployed: true,
            finalized_len: Some(entries.len() as u64),
            entries,
            entries_reply: None,
            calls: Default::default(),
        }
    }

    pub fn calls(&self) -> Vec<([u8; 4], u64)> {
        self.calls.lock().unwrap().clone()
    }

    fn length_reply(&self, block: u64) -> Vec<u8> {
        let len = if block == self.latest {
            self.deployed.then_some(self.entries.len() as u64)
        } else {
            self.finalized_len
        };
        len.map(|l| abi_word(l).to_vec()).unwrap_or_default()
    }

    fn entries_reply(&self, args: &[u8]) -> Vec<u8> {
        use crate::networks::evm::reject_list::{entriesCall, Entry};
        use alloy_sol_types::SolCall;
        if let Some(reply) = &self.entries_reply {
            return reply.clone();
        }
        let call = entriesCall::abi_decode_raw(args).unwrap();
        let end = usize::try_from(call.end).unwrap().min(self.entries.len());
        let start = usize::try_from(call.start).unwrap().min(end);
        let page: Vec<Entry> = self.entries[start..end]
            .iter()
            .map(|e| Entry {
                opId: e.opout.op.into(),
                assignmentType: e.opout.ty,
                no: e.opout.no,
                reject: e.reject,
            })
            .collect();
        entriesCall::abi_encode_returns(&page)
    }
}

#[cfg(feature = "bfa-validation")]
impl crate::networks::evm::events::EvmReceiptProvider for ListEvm {
    fn get_transaction_receipt(
        &self,
        _tx_hash: &[u8; 32],
    ) -> crate::error::Result<Option<crate::networks::evm::events::ReceiptData>> {
        Ok(None)
    }

    fn get_block_by_tag(
        &self,
        tag: attestation_verify::EvmFinalityTag,
    ) -> crate::error::Result<Option<crate::networks::evm::events::BlockData>> {
        use attestation_verify::EvmFinalityTag;
        let number = match tag {
            EvmFinalityTag::Latest => Some(self.latest),
            EvmFinalityTag::Finalized => self.finalized,
            EvmFinalityTag::Safe => None,
        };
        Ok(
            number.map(|number| crate::networks::evm::events::BlockData {
                number,
                hash: [0x42; 32],
            }),
        )
    }

    fn get_block_by_number(
        &self,
        _number: u64,
    ) -> crate::error::Result<Option<crate::networks::evm::events::BlockData>> {
        Ok(None)
    }

    fn get_chain_id(&self) -> crate::error::Result<u64> {
        Ok(self.chain_id)
    }

    fn call(&self, _to: &[u8; 20], data: &[u8], block: u64) -> crate::error::Result<Vec<u8>> {
        use crate::networks::evm::reject_list::{entriesCall, lengthCall};
        use alloy_sol_types::SolCall;
        let selector: [u8; 4] = data[..4].try_into().unwrap();
        self.calls.lock().unwrap().push((selector, block));
        match selector {
            lengthCall::SELECTOR => Ok(self.length_reply(block)),
            entriesCall::SELECTOR => Ok(self.entries_reply(&data[4..])),
            _ => panic!("unexpected eth_call selector 0x{}", hex::encode(selector)),
        }
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

/// A fresh regtest chain: one single-tx block per witness (display order)
/// from height 1, then `depth_above` empty blocks. Returns the chain and a
/// Merkle proof per witness.
#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
pub(crate) fn chain_with_witnesses(
    witness_txids: &[[u8; 32]],
    depth_above: u32,
) -> (
    std::sync::Mutex<crate::networks::rgb::spv::HeaderChain>,
    Vec<crate::proto::MerkleProofEntry>,
) {
    use crate::networks::rgb::spv::{Checkpoint, HeaderChain, Network};
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let start = now - 1_000;
    let mut chain = HeaderChain::new(
        Network::Regtest,
        Checkpoint {
            height: 0,
            hash: [0u8; 32],
            bits: 0x207f_ffff,
            time: start,
            is_real: false,
            chain_work: None,
        },
    );

    let empty = [0u8; 32];
    let roots = witness_txids
        .iter()
        .map(|display| {
            let mut internal = *display;
            internal.reverse();
            internal
        })
        .chain(std::iter::repeat_n(empty, depth_above as usize));
    let mut prev = bitcoin::BlockHash::from_byte_array([0u8; 32]);
    let mut raw = Vec::new();
    for (i, root) in roots.enumerate() {
        let header = Header {
            version: Version::ONE,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array(root),
            time: start + 1 + i as u32,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        prev = header.block_hash();
        raw.push(bitcoin::consensus::serialize(&header));
    }
    chain.submit_headers(1, &raw, ANY_HEADER_CLOCK).unwrap();

    let proofs = witness_txids
        .iter()
        .zip(1..)
        .map(|(txid, block_height)| crate::proto::MerkleProofEntry {
            txid: txid.to_vec(),
            block_height,
            tx_position: 0,
            merkle_path: vec![],
        })
        .collect();
    (std::sync::Mutex::new(chain), proofs)
}
