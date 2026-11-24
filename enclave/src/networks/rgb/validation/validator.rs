//! The RGB consignment validator for one Bitcoin network.

#[cfg(all(rgb_to_evm, unix))]
use super::runner::ChildProgram;
use crate::error::EnclaveError;
use crate::error::Result;
use crate::networks::rgb::spv::Network;
use rgb_lib::ChainNet;

/// Validates RGB consignments of the configured Bitcoin network.
///
/// Witness status comes from the enclave's SPV proofs. The validator makes no
/// indexer call.
#[derive(Debug)]
pub struct RgbValidator {
    pub(super) chain_net: ChainNet,
    /// The program a burn validation runs in; `None` inside a validator child.
    #[cfg(all(rgb_to_evm, unix))]
    pub(super) program: Option<ChildProgram>,
}

impl RgbValidator {
    /// Creates a validator for `bitcoin_network`, a `BITCOIN_NETWORK` value
    /// (see [`Network::from_env_str`]).
    pub fn new(bitcoin_network: &str) -> Result<Self> {
        let chain_net = Network::from_env_str(bitcoin_network)
            .map_err(|e| {
                EnclaveError::Internal(format!("unknown bitcoin network {bitcoin_network}: {e}"))
            })?
            .chain_net();
        tracing::info!(%bitcoin_network, "RGB validator configured");
        Ok(Self {
            chain_net,
            #[cfg(all(rgb_to_evm, unix))]
            program: Some(child_program()?),
        })
    }

    /// This validator, with its burn validations in a child of `program`. A
    /// release build with `vsock`, as each image is, has no such choice.
    #[cfg(all(rgb_to_evm, unix, any(test, debug_assertions, not(feature = "vsock"))))]
    pub fn with_program(mut self, program: ChildProgram) -> Self {
        self.program = Some(program);
        self
    }

    /// The validator of `chain_net` inside a validator child.
    #[cfg(all(rgb_to_evm, unix))]
    pub(super) fn for_chain_net(chain_net: ChainNet) -> Self {
        Self {
            chain_net,
            program: None,
        }
    }
}

/// The program of a validator child: this binary.
#[cfg(all(rgb_to_evm, unix, not(test)))]
fn child_program() -> Result<ChildProgram> {
    ChildProgram::this_binary()
}

/// The lib entry of this test binary.
#[cfg(all(rgb_to_evm, unix, test))]
fn child_program() -> Result<ChildProgram> {
    ChildProgram::test_entry(super::child::lib_test_entry())
}
