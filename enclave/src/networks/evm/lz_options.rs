//! Checks the LayerZero `extraOptions` of an `lzFundsOut` release.
//!
//! The adapter passes the bytes to `OFT.send`. A native drop, a compose
//! option or an `lzReceive` value moves native tokens that the burn did not
//! name, paid by the gas key. So the only allowed form is one executor
//! `lzReceive` gas option with no value, at most [`MAX_LZ_RECEIVE_GAS`].
//! Empty bytes are allowed: the adapter then uses its enforced options.

use crate::error::{EnclaveError, Result};

/// Highest `lzReceive` gas the enclave signs. PCR-attested.
pub const MAX_LZ_RECEIVE_GAS: u128 = 1_000_000;

/// Options type 3, the only type `OFT.combineOptions` accepts.
const OPTIONS_TYPE_3: u16 = 3;
/// LayerZero executor worker id.
const EXECUTOR_WORKER_ID: u8 = 1;
/// Executor option type `LZRECEIVE`.
const OPTION_TYPE_LZRECEIVE: u8 = 1;
/// `lzReceive` option body: `uint128 gas`, without the optional `uint128 value`.
const LZRECEIVE_GAS_LEN: usize = 16;

/// Refuses every `extraOptions` form except empty or one gas-only
/// executor `lzReceive` option within [`MAX_LZ_RECEIVE_GAS`].
pub fn validate_extra_options(options: &[u8]) -> Result<()> {
    if options.is_empty() {
        return Ok(());
    }
    let reject = |msg: String| {
        Err(EnclaveError::CrossCheck(format!(
            "lzFundsOut extraOptions: {msg}"
        )))
    };

    // uint16 type || uint8 worker || uint16 size || uint8 optionType || body
    let Some((type_bytes, rest)) = options.split_first_chunk::<2>() else {
        return reject(format!(
            "{} bytes is too short for the options type",
            options.len()
        ));
    };
    let options_type = u16::from_be_bytes(*type_bytes);
    if options_type != OPTIONS_TYPE_3 {
        return reject(format!("options type {options_type} is not type 3"));
    }
    let Some((&worker_id, rest)) = rest.split_first() else {
        return reject("no option after the type".into());
    };
    if worker_id != EXECUTOR_WORKER_ID {
        return reject(format!("worker id {worker_id} is not the executor"));
    }
    let Some((size_bytes, rest)) = rest.split_first_chunk::<2>() else {
        return reject("option size is truncated".into());
    };
    let size = usize::from(u16::from_be_bytes(*size_bytes));
    if size != rest.len() {
        // Also refuses a second option after the first.
        return reject(format!(
            "option size {size} != {} remaining bytes (only one option is allowed)",
            rest.len()
        ));
    }
    let Some((&option_type, body)) = rest.split_first() else {
        return reject("empty option".into());
    };
    if option_type != OPTION_TYPE_LZRECEIVE {
        return reject(format!(
            "executor option type {option_type} is not lzReceive (native drop, compose and \
             ordered execution are refused)"
        ));
    }
    let Ok(gas_bytes) = <[u8; LZRECEIVE_GAS_LEN]>::try_from(body) else {
        return reject(format!(
            "lzReceive option body is {} bytes, expected {LZRECEIVE_GAS_LEN} (gas only, no value)",
            body.len()
        ));
    };
    let gas = u128::from_be_bytes(gas_bytes);
    if gas > MAX_LZ_RECEIVE_GAS {
        return reject(format!("lzReceive gas {gas} exceeds {MAX_LZ_RECEIVE_GAS}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
