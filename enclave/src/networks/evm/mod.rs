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

/// Chain id of the RGB network in the bridge routes (`<evm> <-> 827166`). It is
/// a protocol constant, so code pins it and PCR0 measures it.
///
/// The Router and CommissionManager select the verifier, settlement module and
/// commission rate by `(sourceChainId, destinationChainId)`. A forged value
/// sends an RGB release through a foreign verifier or rate.
/// `validate_rgb_source_identity` enforces it as the release `sourceChainId`;
/// `verify_rgb_funds_in` enforces it as the deposit `destinationChainId`.
pub const RGB_CHAIN_ID: u64 = 827166;

#[cfg(rgb_to_evm)]
pub const ADDRESS_LEN: usize = 20;
