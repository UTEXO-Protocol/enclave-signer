//! The RGB recipient an EVM deposit authorises.
//!
//! `BridgeFundsIn.destinationAddress` carries the user's invoice verbatim, in a
//! log the enclave verifies itself. The consignment comes from the coordinator,
//! so only the invoice says who the deposit meant to pay.

use std::str::FromStr;

use rgbinvoice::{Beneficiary, RgbInvoice};

use crate::error::{EnclaveError, Result};

/// Ceiling on the invoice string handed to the parser.
const MAX_INVOICE_LEN: usize = 2048;

/// The destination a verified deposit authorises paying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizedRecipient {
    /// `utxob:...` - the form a confidential recipient leg carries.
    BlindedSeal(String),
}

/// Parse `BridgeFundsIn.destinationAddress` into the recipient it authorises.
///
/// A witness-vout beneficiary is refused, not skipped: its recipient leg is a
/// revealed seal, which the per-output bind already rejects unless bridge-owned.
pub fn parse_authorized_recipient(destination_address: &str) -> Result<AuthorizedRecipient> {
    let trimmed = destination_address.trim();
    if trimmed.is_empty() {
        return Err(EnclaveError::CrossCheck(
            "BridgeFundsIn.destinationAddress is empty - the deposit names no RGB recipient to \
             bind the consignment against"
                .into(),
        ));
    }
    if trimmed.len() > MAX_INVOICE_LEN {
        return Err(EnclaveError::CrossCheck(format!(
            "BridgeFundsIn.destinationAddress is {} bytes (max {MAX_INVOICE_LEN})",
            trimmed.len()
        )));
    }

    let invoice = RgbInvoice::from_str(trimmed).map_err(|e| {
        EnclaveError::CrossCheck(format!(
            "BridgeFundsIn.destinationAddress is not a valid RGB invoice: {e}"
        ))
    })?;

    match invoice.beneficiary.into_inner() {
        Beneficiary::BlindedSeal(seal) => Ok(AuthorizedRecipient::BlindedSeal(seal.to_string())),
        Beneficiary::WitnessVout(..) => Err(EnclaveError::CrossCheck(
            "BridgeFundsIn.destinationAddress names a witness-vout beneficiary; the send-RGB \
             recipient bind supports blinded seals only"
                .into(),
        )),
    }
}

/// Require the consignment's confidential recipient legs to be the authorised
/// seal, and only it.
///
/// Exactly one leg: the amount bind pins their total, so a second would split an
/// authorised payment.
pub fn assert_recipient_authorized(
    seals: &[String],
    authorized: &AuthorizedRecipient,
) -> Result<()> {
    let AuthorizedRecipient::BlindedSeal(expected) = authorized;

    match seals {
        [] => Err(EnclaveError::CrossCheck(
            "send-RGB consignment pays no confidential recipient leg, but the deposit authorised \
             a blinded seal - refusing to sign"
                .into(),
        )),
        [only] if only == expected => Ok(()),
        [only] => Err(EnclaveError::CrossCheck(format!(
            "send-RGB recipient seal mismatch: the consignment pays {only}, but the on-chain \
             deposit authorised {expected} - refusing to sign a correct amount to the wrong \
             destination"
        ))),
        many => Err(EnclaveError::CrossCheck(format!(
            "send-RGB consignment pays {} confidential recipient legs; exactly one is \
             authorised by the deposit ({expected})",
            many.len()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blinded(seal: &str) -> AuthorizedRecipient {
        AuthorizedRecipient::BlindedSeal(seal.into())
    }

    /// Byte-identical to `evm_event`'s `SAMPLE_INVOICE`, so the ABI half and the
    /// parsing half cannot drift apart.
    const BLINDED_INVOICE: &str = "rgb:fuhLYX9G-eC8gDvf-V0XpYFH-ceSafoc-lGutAYq-~SExGU4/\
                                   XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/BF/bc:utxob:\
                                   UzR~73lD-JyzirTn-engdWia-qjd5NyV-mndAmmo-EbxdVEG-L6OiP";

    /// The beneficiary of [`BLINDED_INVOICE`]. Also the recipient leg of the
    /// in-tree transfer fixture, so both sources of the string are one value.
    const INVOICE_SEAL: &str = "utxob:UzR~73lD-JyzirTn-engdWia-qjd5NyV-mndAmmo-EbxdVEG-L6OiP";

    /// [`BLINDED_INVOICE`] with a `wvout:` beneficiary.
    const WITNESS_VOUT_INVOICE: &str = "rgb:fuhLYX9G-eC8gDvf-V0XpYFH-ceSafoc-lGutAYq-~SExGU4/\
                                        XvmU3d4_nQQ8S7oagbXi07x5vjMm7P~ERukQNX6SC4M/Sa/bc:wvout:\
                                        A8cJ7Ww3-NIzADo3-Tzp_5aD-7CTBWmA-AAAAAAA-AAAAAAA-ALSQkcw";

    /// A parser that refused every real invoice would still pass the negative
    /// tests below.
    #[test]
    fn a_real_invoice_yields_its_blinded_seal() {
        assert_eq!(
            parse_authorized_recipient(BLINDED_INVOICE).unwrap(),
            blinded(INVOICE_SEAL)
        );
    }

    /// Both sides render `SecretSeal`. A format change on either breaks here
    /// instead of refusing every deposit in production.
    #[test]
    fn a_real_invoice_binds_the_consignment_seal_it_names() {
        let authorized = parse_authorized_recipient(BLINDED_INVOICE).unwrap();
        assert!(assert_recipient_authorized(&[INVOICE_SEAL.to_string()], &authorized).is_ok());
    }

    #[test]
    fn a_witness_vout_invoice_is_refused() {
        let err = parse_authorized_recipient(WITNESS_VOUT_INVOICE).unwrap_err();
        assert!(err.to_string().contains("witness-vout"), "{err}");
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        assert_eq!(
            parse_authorized_recipient(&format!("  {BLINDED_INVOICE}\n")).unwrap(),
            blinded(INVOICE_SEAL)
        );
    }

    #[test]
    fn empty_destination_address_is_refused() {
        let err = parse_authorized_recipient("   ").unwrap_err();
        assert!(err.to_string().contains("names no RGB recipient"), "{err}");
    }

    #[test]
    fn non_invoice_destination_address_is_refused() {
        let err = parse_authorized_recipient("0xdeadbeef").unwrap_err();
        assert!(err.to_string().contains("not a valid RGB invoice"), "{err}");
    }

    #[test]
    fn oversized_destination_address_is_refused() {
        let err = parse_authorized_recipient(&"a".repeat(MAX_INVOICE_LEN + 1)).unwrap_err();
        assert!(err.to_string().contains("max"), "{err}");
    }

    /// The finding itself: right amount, wrong destination.
    #[test]
    fn a_seal_the_deposit_did_not_authorise_is_refused() {
        let err = assert_recipient_authorized(
            &["utxob:attacker-seal".to_string()],
            &blinded("utxob:real-recipient"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("recipient seal mismatch"), "{err}");
    }

    #[test]
    fn the_authorised_seal_binds() {
        assert!(assert_recipient_authorized(
            &["utxob:real-recipient".to_string()],
            &blinded("utxob:real-recipient"),
        )
        .is_ok());
    }

    /// A split would route part of an authorised payment elsewhere.
    #[test]
    fn a_second_confidential_leg_is_refused() {
        let err = assert_recipient_authorized(
            &[
                "utxob:real-recipient".to_string(),
                "utxob:attacker-seal".to_string(),
            ],
            &blinded("utxob:real-recipient"),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("2 confidential recipient legs"),
            "{err}"
        );
    }

    #[test]
    fn no_confidential_leg_at_all_is_refused() {
        let err = assert_recipient_authorized(&[], &blinded("utxob:real-recipient")).unwrap_err();
        assert!(err.to_string().contains("pays no confidential"), "{err}");
    }
}
