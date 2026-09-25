// The `fundsOut` release checks, its EIP-712 digest and its gas tx belong to
// the RGB -> EVM direction only.
#[cfg(all(feature = "rgb-validation", rgb_to_evm))]
pub mod crosscheck;
#[cfg(feature = "evm-rpc")]
pub mod events;
#[cfg(rgb_to_evm)]
pub mod gas_tx;
#[cfg(rgb_to_evm)]
pub mod signing;
pub mod validation;

pub const HASH_LEN: usize = 32;
#[cfg(rgb_to_evm)]
pub const ADDRESS_LEN: usize = 20;
