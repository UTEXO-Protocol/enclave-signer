#[cfg(feature = "rgb-validation")]
pub mod crosscheck;
#[cfg(feature = "evm-rpc")]
pub mod evm_event;
pub mod gas_tx;
pub mod signing;
pub mod validation;

pub const HASH_LEN: usize = 32;
pub const ADDRESS_LEN: usize = 20;
