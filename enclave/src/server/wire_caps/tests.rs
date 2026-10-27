use prost::Message;

use super::*;
use crate::proto::{
    enclave_request, sign_request, EnclaveRequest, MerkleProofEntry, RgbSource, SignRequest,
    SubmitHeadersRequest,
};

fn sign_with_proofs(proofs: Vec<MerkleProofEntry>) -> Vec<u8> {
    EnclaveRequest {
        request: Some(enclave_request::Request::Sign(SignRequest {
            source_network: Some(sign_request::SourceNetwork::RgbSource(RgbSource {
                consignment: vec![7; 100],
                merkle_proofs: proofs,
                ..Default::default()
            })),
            ..Default::default()
        })),
    }
    .encode_to_vec()
}

fn proof(path_len: usize) -> MerkleProofEntry {
    MerkleProofEntry {
        txid: vec![1; 32],
        block_height: 800_000,
        tx_position: 3,
        merkle_path: vec![vec![2; 32]; path_len],
    }
}

#[test]
fn accepts_a_request_at_the_caps() {
    let buf = sign_with_proofs(vec![proof(32); 16]);
    check_request_caps(&buf, 16).unwrap();
}

#[test]
fn refuses_more_proofs_than_the_cap() {
    let buf = sign_with_proofs(vec![proof(1); 17]);
    let err = check_request_caps(&buf, 16).unwrap_err().to_string();
    assert!(err.contains("Merkle proofs"), "{err}");
}

#[test]
fn refuses_a_proof_with_a_path_too_long() {
    let buf = sign_with_proofs(vec![proof(33)]);
    let err = check_request_caps(&buf, 16).unwrap_err().to_string();
    assert!(err.contains("Merkle path entries"), "{err}");
}

/// The decode-expansion shape: many empty entries, 2 wire bytes each.
#[test]
fn refuses_a_flood_of_empty_proofs() {
    let buf = sign_with_proofs(vec![MerkleProofEntry::default(); 100_000]);
    assert!(buf.len() < 300_000);
    assert!(check_request_caps(&buf, 16_384).is_err());
}

/// prost merges a repeated `sign` field, so the counts add up.
#[test]
fn counts_add_up_over_repeated_submessages() {
    let mut buf = sign_with_proofs(vec![proof(1); 10]);
    buf.extend(sign_with_proofs(vec![proof(1); 10]));
    let decoded = EnclaveRequest::decode(&buf[..]).unwrap();
    let Some(enclave_request::Request::Sign(sign)) = decoded.request else {
        panic!("sign")
    };
    let Some(sign_request::SourceNetwork::RgbSource(rgb)) = sign.source_network else {
        panic!("rgb source")
    };
    assert_eq!(rgb.merkle_proofs.len(), 20);
    assert!(check_request_caps(&buf, 19).is_err());
    check_request_caps(&buf, 20).unwrap();
}

#[test]
fn refuses_too_many_headers() {
    let req = |n| {
        EnclaveRequest {
            request: Some(enclave_request::Request::SubmitHeaders(
                SubmitHeadersRequest {
                    headers: vec![vec![]; n],
                    start_height: 1,
                },
            )),
        }
        .encode_to_vec()
    };
    check_request_caps(&req(MAX_HEADERS as usize), 1).unwrap();
    assert!(check_request_caps(&req(MAX_HEADERS as usize + 1), 1).is_err());
}

#[test]
fn refuses_a_truncated_field() {
    let mut buf = sign_with_proofs(vec![proof(1)]);
    buf.pop();
    assert!(check_request_caps(&buf, 16).is_err());
}

#[test]
fn ignores_other_requests() {
    let buf = EnclaveRequest {
        request: Some(enclave_request::Request::GetPublicKey(Default::default())),
    }
    .encode_to_vec();
    check_request_caps(&buf, 0).unwrap();
}
