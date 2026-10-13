use super::*;

/// Same bytes as bridge-utexo `BuildLzReceiveOptions(gas)`.
fn lz_receive_options(gas: u128) -> Vec<u8> {
    let mut out = vec![0x00, 0x03, 0x01, 0x00, 0x11, 0x01];
    out.extend_from_slice(&gas.to_be_bytes());
    out
}

fn err_of(options: &[u8]) -> String {
    validate_extra_options(options).unwrap_err().to_string()
}

#[test]
fn accepts_empty_options() {
    validate_extra_options(&[]).unwrap();
}

#[test]
fn accepts_backend_lz_receive_gas_option() {
    validate_extra_options(&lz_receive_options(200_000)).unwrap();
    validate_extra_options(&lz_receive_options(0)).unwrap();
}

#[test]
fn accepts_gas_at_ceiling_and_refuses_above() {
    validate_extra_options(&lz_receive_options(MAX_LZ_RECEIVE_GAS)).unwrap();
    assert!(err_of(&lz_receive_options(MAX_LZ_RECEIVE_GAS + 1)).contains("exceeds"));
}

#[test]
fn refuses_native_drop() {
    // type 3 || executor || size 49 || NATIVE_DROP || uint128 amount || bytes32 receiver
    let mut options = vec![0x00, 0x03, 0x01, 0x00, 0x31, 0x02];
    options.extend_from_slice(&1_000_000_000_000_000_000u128.to_be_bytes());
    options.extend_from_slice(&[0xAB; 32]);
    assert!(err_of(&options).contains("not lzReceive"));
}

#[test]
fn refuses_compose_option() {
    // type 3 || executor || size 19 || LZCOMPOSE || uint16 index || uint128 gas
    let mut options = vec![0x00, 0x03, 0x01, 0x00, 0x13, 0x03, 0x00, 0x00];
    options.extend_from_slice(&200_000u128.to_be_bytes());
    assert!(err_of(&options).contains("not lzReceive"));
}

#[test]
fn refuses_lz_receive_with_value() {
    // size 33: uint128 gas || uint128 value
    let mut options = vec![0x00, 0x03, 0x01, 0x00, 0x21, 0x01];
    options.extend_from_slice(&200_000u128.to_be_bytes());
    options.extend_from_slice(&1u128.to_be_bytes());
    assert!(err_of(&options).contains("gas only"));
}

#[test]
fn refuses_second_option() {
    let mut options = lz_receive_options(200_000);
    options.extend_from_slice(&[0x01, 0x00, 0x11, 0x01]);
    options.extend_from_slice(&200_000u128.to_be_bytes());
    assert!(err_of(&options).contains("only one option"));
}

#[test]
fn refuses_other_options_types() {
    // Legacy type 1: uint16 type || uint256 gas.
    let mut options = vec![0x00, 0x01];
    options.extend_from_slice(&[0u8; 32]);
    assert!(err_of(&options).contains("not type 3"));
}

#[test]
fn refuses_non_executor_worker() {
    let mut options = lz_receive_options(200_000);
    options[2] = 0x02; // DVN
    assert!(err_of(&options).contains("not the executor"));
}

#[test]
fn refuses_truncated_options() {
    assert!(validate_extra_options(&[0x00]).is_err());
    assert!(validate_extra_options(&[0x00, 0x03]).is_err());
    assert!(validate_extra_options(&[0x00, 0x03, 0x01, 0x00]).is_err());
    let options = lz_receive_options(200_000);
    assert!(validate_extra_options(&options[..options.len() - 1]).is_err());
}
