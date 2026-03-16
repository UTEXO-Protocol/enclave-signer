use std::io::Cursor;

use utexo_bridge_enclave::framing;
use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::*;

#[test]
fn roundtrip_encode_decode() {
    let req = EnclaveRequest {
        request: Some(Request::GetPublicKey(GetPublicKeyRequest {})),
    };

    let mut buf = Vec::new();
    framing::write_message(&mut buf, &req).unwrap();

    let mut cursor = Cursor::new(buf);
    let decoded: EnclaveRequest = framing::read_message(&mut cursor).unwrap();

    eprintln!("{:?}", decoded);

    assert_eq!(req, decoded);
}

#[test]
fn reject_oversized_message() {
    // 5 MB > 4 MB limit
    let len: u32 = 5 * 1024 * 1024;
    let buf = len.to_le_bytes().to_vec();
    let mut cursor = Cursor::new(buf);
    let result: Result<EnclaveRequest, _> = framing::read_message(&mut cursor);
    assert!(result.is_err());
}

#[test]
fn reject_zero_length_message() {
    let buf = vec![0u8; 4]; // length = 0
    let mut cursor = Cursor::new(buf);
    let result: Result<EnclaveRequest, _> = framing::read_message(&mut cursor);
    assert!(result.is_err());
}
