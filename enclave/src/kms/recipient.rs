//! Opens KMS `CiphertextForRecipient`.
//!
//! The value is a CMS `ContentInfo` holding `EnvelopedData` (RFC 5652 §6)
//! with exactly one `KeyTransRecipientInfo`: the content-encryption key is
//! wrapped with RSAES-OAEP (SHA-256, MGF1-SHA-256) to the public key from the
//! attestation document, and the content is AES-256-CBC with PKCS#7 padding.
//! That is the shape the AWS Nitro Enclaves SDK's `cms.c` accepts; every other
//! algorithm or recipient type is rejected before any key is used.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use cms::cert::x509::der::asn1::{ObjectIdentifier, OctetString};
use cms::cert::x509::der::Decode;
use cms::content_info::ContentInfo;
use cms::enveloped_data::{EnvelopedData, RecipientInfo};
use rsa::pkcs1::RsaOaepParams;
use rsa::sha2::Sha256;
use rsa::{Oaep, RsaPrivateKey};
use zeroize::Zeroizing;

use crate::error::{CustodyFailure, EnclaveError, Result};

pub(super) const ID_ENVELOPED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");
pub(super) const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
pub(super) const ID_RSAES_OAEP: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.7");
pub(super) const ID_MGF_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
pub(super) const ID_SHA_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
pub(super) const ID_AES_256_CBC: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");

/// AES-256 content-encryption key and CBC block size.
const CEK_BYTES: usize = 32;
const IV_BYTES: usize = 16;
/// A 64-byte seed envelope is well under 1 KiB; this bounds a hostile reply.
pub(super) const MAX_ENVELOPE_BYTES: usize = 8 * 1024;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Decrypt `envelope` with `key`. Returns the padded-out content.
pub(super) fn open_envelope(key: &RsaPrivateKey, envelope: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if envelope.is_empty() || envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(reject("envelope size"));
    }
    let info = ContentInfo::from_der(envelope).map_err(|_| reject("envelope is not DER CMS"))?;
    if info.content_type != ID_ENVELOPED_DATA {
        return Err(reject("content type is not EnvelopedData"));
    }
    let enveloped: EnvelopedData = info
        .content
        .decode_as()
        .map_err(|_| reject("EnvelopedData does not decode"))?;

    let mut recipients = enveloped.recip_infos.0.iter();
    let ktri = match (recipients.next(), recipients.next()) {
        (Some(RecipientInfo::Ktri(ktri)), None) => ktri,
        _ => return Err(reject("expected exactly one key-transport recipient")),
    };
    if ktri.key_enc_alg.oid != ID_RSAES_OAEP {
        return Err(reject("key encryption is not RSAES-OAEP"));
    }
    let params: RsaOaepParams = ktri
        .key_enc_alg
        .parameters
        .as_ref()
        .ok_or_else(|| reject("RSAES-OAEP parameters are missing"))?
        .decode_as()
        .map_err(|_| reject("RSAES-OAEP parameters do not decode"))?;
    let mgf_hash = params.mask_gen.parameters.as_ref().map(|p| p.oid);
    if params.hash.oid != ID_SHA_256
        || params.mask_gen.oid != ID_MGF_1
        || mgf_hash != Some(ID_SHA_256)
    {
        return Err(reject("RSAES-OAEP parameters are not SHA-256/MGF1-SHA-256"));
    }
    let cek = Zeroizing::new(
        key.decrypt(Oaep::new::<Sha256>(), ktri.enc_key.as_bytes())
            .map_err(|_| reject("content-encryption key does not unwrap"))?,
    );
    if cek.len() != CEK_BYTES {
        return Err(reject("content-encryption key is not 256 bits"));
    }

    let content = &enveloped.encrypted_content;
    if content.content_type != ID_DATA {
        return Err(reject("encrypted content is not id-data"));
    }
    if content.content_enc_alg.oid != ID_AES_256_CBC {
        return Err(reject("content encryption is not AES-256-CBC"));
    }
    let iv: OctetString = content
        .content_enc_alg
        .parameters
        .as_ref()
        .ok_or_else(|| reject("AES-CBC IV is missing"))?
        .decode_as()
        .map_err(|_| reject("AES-CBC IV does not decode"))?;
    if iv.as_bytes().len() != IV_BYTES {
        return Err(reject("AES-CBC IV is not 16 bytes"));
    }
    let ciphertext = content
        .encrypted_content
        .as_ref()
        .ok_or_else(|| reject("encrypted content is missing"))?
        .as_bytes();
    let plaintext = Aes256CbcDec::new_from_slices(&cek, iv.as_bytes())
        .map_err(|_| reject("AES-CBC key or IV length"))?
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| reject("AES-CBC padding"))?;
    Ok(Zeroizing::new(plaintext))
}

fn reject(reason: &'static str) -> EnclaveError {
    tracing::warn!(reason, "KMS recipient envelope rejected");
    EnclaveError::Custody {
        service: "KMS",
        failure: CustodyFailure::InvalidResponse,
    }
}
