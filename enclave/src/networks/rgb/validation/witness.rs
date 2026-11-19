//! The adapter that lets rgb-lib place each witness from the SPV proof the
//! consignment carries, against the enclave's own header chain.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::num::NonZeroU32;

use bitcoin::block::Header;
use bitcoin::hashes::Hash as _;
use bitcoin::Txid;
use rgb_lib::{ChainNet, ResolveWitness, WitnessResolverError, WitnessStatus};

use crate::error::{EnclaveError, Result};

/// The enclave's header chain, as consignment validation reads it.
pub trait BuriedHeaders {
    /// The header at `height`, if it is buried at the required depth and at or
    /// below the safe height. `Err` says why not.
    fn buried_header(&self, height: u32) -> Result<Header>;

    /// The highest block buried at the required depth when the validation
    /// began, if any was. It does not move while the validation runs.
    fn safe_height(&self) -> Option<NonZeroU32>;
}

/// Serves block headers and looks no transaction up, so a witness is mined
/// only where its SPV proof holds against a header of the enclave's chain.
pub(super) struct HeadersOnlyResolver<'a> {
    chain_net: ChainNet,
    headers: &'a dyn BuriedHeaders,
    /// Hash of each header served, by height: what the proofs were checked against.
    served: RefCell<BTreeMap<u32, [u8; 32]>>,
    /// The first refusal, with its own reason.
    failure: RefCell<Option<EnclaveError>>,
}

impl<'a> HeadersOnlyResolver<'a> {
    pub(super) fn new(chain_net: ChainNet, headers: &'a dyn BuriedHeaders) -> Self {
        Self {
            chain_net,
            headers,
            served: RefCell::new(BTreeMap::new()),
            failure: RefCell::new(None),
        }
    }

    /// The hash of the header served at `height`, in internal byte order.
    pub(super) fn served_hash(&self, height: u32) -> Option<[u8; 32]> {
        self.served.borrow().get(&height).copied()
    }

    /// Our own refusal behind an rgb-lib error.
    pub(super) fn take_failure(&self) -> Option<EnclaveError> {
        self.failure.borrow_mut().take()
    }

    fn refuse(&self, failure: EnclaveError) -> String {
        let reason = failure.to_string();
        self.failure.borrow_mut().get_or_insert(failure);
        reason
    }
}

impl ResolveWitness for HeadersOnlyResolver<'_> {
    /// Reached for a witness with no proof, or with one that does not hold.
    fn resolve_witness(
        &self,
        witness_id: Txid,
    ) -> std::result::Result<WitnessStatus, WitnessResolverError> {
        let reason = self.refuse(EnclaveError::Spv(format!(
            "witness tx {witness_id} is not proven on chain: the consignment carries no SPV \
             proof of it that holds against the enclave header chain"
        )));
        Err(WitnessResolverError::ResolverIssue(
            Some(witness_id),
            reason,
        ))
    }

    fn get_block_header(
        &self,
        height: NonZeroU32,
    ) -> std::result::Result<Header, WitnessResolverError> {
        let header = self
            .headers
            .buried_header(height.get())
            .map_err(|failure| WitnessResolverError::ResolverIssue(None, self.refuse(failure)))?;
        // Each proof is checked against the header served here, so a height has one header
        // for the whole validation.
        let hash = header.block_hash().to_byte_array();
        let first = *self.served.borrow_mut().entry(height.get()).or_insert(hash);
        if first != hash {
            let reason = self.refuse(EnclaveError::Spv(format!(
                "witness proof: the enclave chain held block {} at height {height} earlier in \
                 this validation and holds {} there now - the header chain changed during \
                 validation, refusing to sign",
                hex::encode(first),
                hex::encode(hash)
            )));
            return Err(WitnessResolverError::ResolverIssue(None, reason));
        }
        Ok(header)
    }

    fn check_chain_net(
        &self,
        chain_net: ChainNet,
    ) -> std::result::Result<(), WitnessResolverError> {
        if chain_net != self.chain_net {
            return Err(WitnessResolverError::WrongChainNet);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
