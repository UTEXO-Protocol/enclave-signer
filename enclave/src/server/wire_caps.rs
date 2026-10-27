//! Element-count caps checked on the raw request bytes, before decode.
//! An empty repeated entry costs 2-4 wire bytes but 24-56 bytes decoded, so a
//! full frame could decode to about 1 GiB.

use crate::error::{EnclaveError, Result};

/// Sibling hashes per Merkle proof (`spv_crosscheck::MAX_MERKLE_PATH_DEPTH`).
const MAX_MERKLE_PATH_ENTRIES: u64 = 32;
/// Headers per `SubmitHeaders`. The rate window takes no more.
const MAX_HEADERS: u64 = 100_000;

// Field numbers in enclave.proto.
const REQUEST_SIGN: u32 = 3;
const REQUEST_SUBMIT_HEADERS: u32 = 11;
const SIGN_RGB_SOURCE: u32 = 3;
const RGB_SOURCE_MERKLE_PROOFS: u32 = 6;
const PROOF_MERKLE_PATH: u32 = 4;
const SUBMIT_HEADERS_HEADERS: u32 = 1;

/// Refuse a request whose repeated fields hold more entries than any valid
/// request. Counts add up over repeated submessages, as prost merges them.
pub fn check_request_caps(buf: &[u8], max_merkle_proofs: usize) -> Result<()> {
    let mut proofs = 0u64;
    let mut headers = 0u64;
    for_each_len_field(buf, |field, body| match field {
        REQUEST_SIGN => for_each_len_field(body, |field, body| {
            if field != SIGN_RGB_SOURCE {
                return Ok(());
            }
            for_each_len_field(body, |field, body| {
                if field != RGB_SOURCE_MERKLE_PROOFS {
                    return Ok(());
                }
                proofs += 1;
                if proofs > max_merkle_proofs as u64 {
                    return Err(too_many("Merkle proofs", max_merkle_proofs as u64));
                }
                let mut path = 0u64;
                for_each_len_field(body, |field, _| {
                    if field == PROOF_MERKLE_PATH {
                        path += 1;
                    }
                    if path > MAX_MERKLE_PATH_ENTRIES {
                        return Err(too_many("Merkle path entries", MAX_MERKLE_PATH_ENTRIES));
                    }
                    Ok(())
                })
            })
        }),
        REQUEST_SUBMIT_HEADERS => for_each_len_field(body, |field, _| {
            if field == SUBMIT_HEADERS_HEADERS {
                headers += 1;
            }
            if headers > MAX_HEADERS {
                return Err(too_many("headers", MAX_HEADERS));
            }
            Ok(())
        }),
        _ => Ok(()),
    })
}

fn too_many(what: &str, max: u64) -> EnclaveError {
    EnclaveError::Framing(format!("request has more than {max} {what}"))
}

/// Call `f` with the number and body of each length-delimited field of one
/// message. Other fields are skipped. Groups are refused: proto3 has none.
fn for_each_len_field(mut buf: &[u8], mut f: impl FnMut(u32, &[u8]) -> Result<()>) -> Result<()> {
    while !buf.is_empty() {
        let key = read_varint(&mut buf)?;
        let field = u32::try_from(key >> 3).map_err(|_| malformed())?;
        match key & 7 {
            0 => {
                read_varint(&mut buf)?;
            }
            1 => buf = buf.get(8..).ok_or_else(malformed)?,
            2 => {
                let len = usize::try_from(read_varint(&mut buf)?).map_err(|_| malformed())?;
                if len > buf.len() {
                    return Err(malformed());
                }
                let (body, rest) = buf.split_at(len);
                f(field, body)?;
                buf = rest;
            }
            5 => buf = buf.get(4..).ok_or_else(malformed)?,
            _ => return Err(malformed()),
        }
    }
    Ok(())
}

fn read_varint(buf: &mut &[u8]) -> Result<u64> {
    let mut value = 0u64;
    for i in 0..10 {
        let (&byte, rest) = buf.split_first().ok_or_else(malformed)?;
        *buf = rest;
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(malformed())
}

fn malformed() -> EnclaveError {
    EnclaveError::Framing("malformed protobuf request".into())
}

#[cfg(test)]
mod tests;
