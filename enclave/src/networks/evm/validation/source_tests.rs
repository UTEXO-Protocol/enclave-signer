//! EVM source checks: the EVM -> RGB (mint) direction.

use super::*;

fn source() -> EvmSource {
    EvmSource {
        tx_hash: vec![0xAA; TX_HASH_LEN],
        event_valid: true,
        event_finalized: true,
        token: vec![0x11; 20],
        recipient: vec![0x22; 20],
        commission: 50,
        funds_in_operation_id: vec![0x33; 32],
    }
}

#[test]
fn valid_source_passes() {
    let proof = validate_source(1_000, &source()).expect("valid source");
    assert_eq!(proof.amount, 1_000);
    assert_eq!(proof.operation_id, None);
}

#[test]
fn source_rejects_invalid_tx_hash_length() {
    let mut source = source();
    source.tx_hash.truncate(16);
    assert!(validate_source(1_000, &source)
        .unwrap_err()
        .to_string()
        .contains(&format!("evm_tx_hash must be {TX_HASH_LEN} bytes")));
}

/// `validate_source` no longer reads the listener's
/// `event_valid` / `event_finalized` booleans, so flipping them changes
/// nothing. Validity and finality come from
/// `events::verify_funds_in_event`.
#[test]
fn source_ignores_listener_evm_booleans() {
    let mut source = source();
    source.event_valid = false;
    source.event_finalized = false;
    // Shape is still valid and the booleans are ignored now.
    assert!(validate_source(1_000, &source).is_ok());
}
