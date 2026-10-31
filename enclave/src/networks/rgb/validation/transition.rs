//! Reads the fields of one rgbstd `Transition`: its globals and its seals.
//!
//! Decode only. The consignment path and the mint signer's PSBT path share
//! it, so both read the same bytes the same way.

use bitcoin::hashes::Hash;
use rgbstd::txout::TxoSeal;
use rgbstd::{BuilderSeal, GlobalStateType, GraphSeal};

use super::types::OutputSeal;
use crate::error::{EnclaveError, Result};

/// The one value of a global, as exactly `N` raw bytes. `Ok(None)` when the
/// transition does not declare it.
///
/// The bytes are the strict encoding: an `Amount` is a little-endian `u64`, a
/// `BurnReason` its 32 bytes. Decoded by hand to keep the strict-encoding
/// crate out of the enclave's own code.
pub fn single_global<const N: usize>(
    globals: &rgbstd::GlobalState,
    ty: GlobalStateType,
    name: &str,
) -> Result<Option<[u8; N]>> {
    let Some(values) = globals.get(&ty) else {
        return Ok(None);
    };
    let [value] = values.as_slice() else {
        return Err(EnclaveError::CrossCheck(format!(
            "settling transition carries {} {name} values, expected one",
            values.len()
        )));
    };
    let bytes: [u8; N] = value.as_slice().try_into().map_err(|_| {
        EnclaveError::CrossCheck(format!(
            "{name} is {} bytes, expected {N}",
            value.as_slice().len()
        ))
    })?;
    Ok(Some(bytes))
}

/// The seal of an output as the flat summary shows it.
pub fn output_seal(seal: &BuilderSeal<GraphSeal>) -> OutputSeal {
    match seal {
        BuilderSeal::Revealed(seal) => OutputSeal::Revealed {
            txid: seal.txid().map(display_bytes),
            vout: seal.vout().into_u32(),
        },
        BuilderSeal::Concealed(secret) => OutputSeal::Confidential {
            secret_seal: secret.to_string(),
        },
    }
}

/// Display-order (big-endian) bytes of a txid, as the wire carries it.
fn display_bytes(txid: bitcoin::Txid) -> [u8; 32] {
    let mut bytes = txid.to_byte_array();
    bytes.reverse();
    bytes
}
