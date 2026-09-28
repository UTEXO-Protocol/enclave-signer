//! Wire-level behaviour of the vendored protobuf types: every request and
//! response variant survives an encode/decode round trip, unknown fields are
//! skipped rather than rejected (so a newer parent can talk to an older
//! enclave), and malformed bytes fail to decode instead of yielding a default.

use enclave_proto::enclave_request::Request;
use enclave_proto::enclave_response::Response;
use enclave_proto::*;
use prost::Message;

fn request_variants() -> Vec<Request> {
    vec![
        Request::InitializeKey(InitializeKeyRequest {
            seed: vec![1; 64],
            mnemonic: "m".into(),
            cloning_secret: "s".into(),
        }),
        Request::GetPublicKey(GetPublicKeyRequest {}),
        Request::Sign(SignRequest {
            amount: 7,
            source_network: Some(sign_request::SourceNetwork::EvmSource(EvmSource {
                tx_hash: vec![2; 32],
                event_valid: true,
                event_finalized: false,
                token: vec![3; 20],
                recipient: vec![4; 20],
                commission: 5,
                funds_in_operation_id: vec![6; 32],
            })),
            destination_network: Some(sign_request::DestinationNetwork::RgbDestination(
                RgbDestination {
                    operation_idx: 1,
                    psbt_bytes: vec![0x70, 0x73, 0x62, 0x74],
                    psbt_output_amount: 9,
                    asset_id: "rgb:x".into(),
                    consignment: vec![8],
                    mint_ancestors: vec![MintAncestor {
                        op_id: vec![1; 32],
                        tx_hash: vec![2; 32],
                    }],
                    consignment_hash: vec![9; 32],
                },
            )),
        }),
        Request::SignRawMessage(SignRawMessageRequest { message: vec![1] }),
        Request::ProxyFederation(ProxyFederationRequest {
            message_hash: vec![2; 32],
        }),
        Request::InitiateCloning(InitiateCloningRequest {
            cloning_secret: "s".into(),
            cluster_public_key: vec![3; 20],
        }),
        Request::GetClone(GetCloneRequest {
            cluster_public_key: vec![4; 20],
            cloning_digest: vec![5; 32],
            encryption_pubkey: vec![6; 32],
            requester_attestation: vec![7],
        }),
        Request::SetClone(SetCloneRequest {
            encrypted_seed: vec![8; 80],
            donor_pubkey: vec![9; 32],
            donor_attestation: vec![10],
        }),
        Request::SignRawDigest(SignRawDigestRequest {
            digest: vec![11; 32],
            unsigned_tx: vec![12],
        }),
        Request::SubmitHeaders(SubmitHeadersRequest {
            headers: vec![vec![13; 80], vec![14; 80]],
            start_height: 15,
        }),
        Request::GetLastSavedBlock(GetLastSavedBlockRequest {}),
        Request::GetAttestedPublicKey(GetAttestedPublicKeyRequest {
            nonce: vec![16; 32],
        }),
        Request::SignBtc(SignBtcRequest {
            psbt_bytes: vec![17],
        }),
        Request::SignCcd(SignCcdRequest { hash: vec![18; 32] }),
    ]
}

fn response_variants() -> Vec<Response> {
    vec![
        Response::InitializeKey(InitializeKeyResponse {
            evm_address: vec![1; 20],
            chain_id: 2,
            ..Default::default()
        }),
        Response::PublicKeys(PublicKeysResponse {
            evm_address: vec![1; 20],
            rgb_asset_id: "rgb:x".into(),
            ..Default::default()
        }),
        Response::EvmSignature(EvmSignatureResponse::default()),
        Response::SignedPsbt(SignedPsbtResponse {
            signed_psbt: vec![1],
            inputs_signed: 1,
        }),
        Response::RawSignature(RawSignatureResponse::default()),
        Response::FederationSig(FederationSignatureResponse::default()),
        Response::InitiateCloning(InitiateCloningResponse {
            requester_attestation: vec![1],
            encryption_pubkey: vec![2; 32],
            cloning_digest: vec![3; 32],
        }),
        Response::GetClone(GetCloneResponse {
            encrypted_seed: vec![4; 80],
            donor_pubkey: vec![5; 32],
            donor_attestation: vec![6],
        }),
        Response::SetClone(SetCloneResponse {}),
        Response::RawDigestSig(RawDigestSignatureResponse {
            signature: vec![7; 65],
        }),
        Response::SubmitHeaders(SubmitHeadersResponse::default()),
        Response::GetLastSavedBlock(GetLastSavedBlockResponse::default()),
        Response::GetAttestedPublicKey(GetAttestedPublicKeyResponse {
            public_keys: Some(PublicKeysResponse::default()),
            attestation_doc: vec![8],
        }),
        Response::CcdSignature(CcdSignatureResponse {
            signature: vec![9; 64],
            public_key: vec![10; 32],
        }),
        Response::Error(ErrorResponse {
            code: 3,
            message: "cross-check failed".into(),
        }),
    ]
}

#[test]
fn every_request_variant_round_trips() {
    let variants = request_variants();
    assert_eq!(variants.len(), 14, "one per oneof arm");
    for v in variants {
        let req = EnclaveRequest { request: Some(v) };
        let bytes = req.encode_to_vec();
        assert!(!bytes.is_empty());
        assert_eq!(bytes.len(), req.encoded_len());
        let back = EnclaveRequest::decode(bytes.as_slice()).unwrap();
        assert_eq!(back, req);
    }
}

#[test]
fn every_response_variant_round_trips() {
    let variants = response_variants();
    assert_eq!(variants.len(), 15, "one per oneof arm");
    for v in variants {
        let resp = EnclaveResponse { response: Some(v) };
        let bytes = resp.encode_to_vec();
        assert!(!bytes.is_empty());
        let back = EnclaveResponse::decode(bytes.as_slice()).unwrap();
        assert_eq!(back, resp);
    }
}

#[test]
fn each_variant_encodes_to_a_distinct_wire_tag() {
    let mut tags = std::collections::HashSet::new();
    for v in request_variants() {
        let bytes = EnclaveRequest { request: Some(v) }.encode_to_vec();
        // Field number is the tag varint >> 3; every arm here fits in one byte.
        tags.insert(bytes[0] >> 3);
    }
    assert_eq!(tags.len(), 14);
    assert!(!tags.contains(&4), "tag 4 is reserved/unassigned");
}

#[test]
fn an_empty_request_encodes_to_nothing_and_decodes_back_to_none() {
    let req = EnclaveRequest { request: None };
    assert!(req.encode_to_vec().is_empty());
    assert_eq!(req.encoded_len(), 0);
    let back = EnclaveRequest::decode(&[][..]).unwrap();
    assert_eq!(back.request, None);
    let back = EnclaveResponse::decode(&[][..]).unwrap();
    assert_eq!(back.response, None);
}

#[test]
fn unknown_fields_are_skipped_not_rejected() {
    // Field 4 (unassigned in the request oneof), length-delimited, empty.
    let back = EnclaveRequest::decode(&[0x22u8, 0x00][..]).unwrap();
    assert_eq!(back.request, None);
    // Field 99 varint.
    let back = EnclaveRequest::decode(&[0x98u8, 0x06, 0x01][..]).unwrap();
    assert_eq!(back.request, None);
    // A known variant followed by an unknown trailing field keeps the variant.
    let mut bytes = EnclaveRequest {
        request: Some(Request::GetPublicKey(GetPublicKeyRequest {})),
    }
    .encode_to_vec();
    bytes.extend_from_slice(&[0x98, 0x06, 0x01]);
    let back = EnclaveRequest::decode(bytes.as_slice()).unwrap();
    assert!(matches!(back.request, Some(Request::GetPublicKey(_))));
}

#[test]
fn unknown_fields_inside_a_nested_message_are_also_skipped() {
    // SignCcdRequest with hash (field 1) plus an unknown field 7.
    let mut inner = vec![0x0a, 0x02, 0xaa, 0xbb]; // hash = [aa, bb]
    inner.extend_from_slice(&[0x38, 0x05]); // field 7 varint 5
    let mut bytes = vec![(15 << 3) | 2, inner.len() as u8];
    bytes.extend_from_slice(&inner);
    let back = EnclaveRequest::decode(bytes.as_slice()).unwrap();
    match back.request {
        Some(Request::SignCcd(r)) => assert_eq!(r.hash, vec![0xaa, 0xbb]),
        other => panic!("expected SignCcd, got {other:?}"),
    }
}

#[test]
fn truncated_and_malformed_bytes_fail_to_decode() {
    let full = EnclaveRequest {
        request: Some(Request::SignCcd(SignCcdRequest { hash: vec![1; 32] })),
    }
    .encode_to_vec();
    // Cut inside the length-delimited payload.
    assert!(EnclaveRequest::decode(&full[..full.len() - 1]).is_err());
    assert!(EnclaveRequest::decode(&full[..2]).is_err());
    // A tag with an impossible wire type.
    assert!(EnclaveRequest::decode(&[0x0f_u8][..]).is_err());
    // Length prefix pointing past the end.
    assert!(EnclaveRequest::decode(&[0x7a_u8, 0x10, 0x00][..]).is_err());
    // Bare 0xff bytes: varint with no terminator.
    assert!(EnclaveRequest::decode(&[0xff_u8; 4][..]).is_err());
}

#[test]
fn a_repeated_oneof_field_keeps_the_last_value() {
    // Two SignCcd payloads back to back: protobuf merge semantics keep the
    // last one, which is what a reader must assume when a peer is buggy.
    let a = EnclaveRequest {
        request: Some(Request::SignCcd(SignCcdRequest { hash: vec![1; 32] })),
    }
    .encode_to_vec();
    let b = EnclaveRequest {
        request: Some(Request::SignCcd(SignCcdRequest { hash: vec![2; 32] })),
    }
    .encode_to_vec();
    let mut both = a;
    both.extend_from_slice(&b);
    match EnclaveRequest::decode(both.as_slice()).unwrap().request {
        Some(Request::SignCcd(r)) => assert_eq!(r.hash, vec![2; 32]),
        other => panic!("expected SignCcd, got {other:?}"),
    }
}

#[test]
fn default_values_are_omitted_on_the_wire() {
    // Proto3 scalar defaults (0, "", empty bytes) take no space, so a fresh
    // ErrorResponse encodes to nothing and decodes back to the default.
    let e = ErrorResponse::default();
    assert!(e.encode_to_vec().is_empty());
    assert_eq!(ErrorResponse::decode(&[][..]).unwrap(), e);
    let e = ErrorResponse {
        code: 0,
        message: "x".into(),
    };
    assert_eq!(e.encode_to_vec(), vec![0x12, 0x01, b'x']);
}

#[test]
fn sign_request_oneofs_are_independent() {
    let req = SignRequest {
        amount: 1,
        source_network: Some(sign_request::SourceNetwork::CcdSource(CcdSource {
            tx_hash: vec![1; 32],
            commission: 2,
        })),
        destination_network: None,
    };
    let back = SignRequest::decode(req.encode_to_vec().as_slice()).unwrap();
    assert_eq!(back, req);
    assert!(back.destination_network.is_none());
    let req = SignRequest {
        amount: 0,
        source_network: None,
        destination_network: Some(sign_request::DestinationNetwork::EvmDestination(
            EvmDestination {
                lz_release: Some(LzReleaseParams {
                    dst_eid: 1,
                    min_amount_ld: 2,
                    recipient: vec![3; 32],
                }),
                ..Default::default()
            },
        )),
    };
    let back = SignRequest::decode(req.encode_to_vec().as_slice()).unwrap();
    assert_eq!(back, req);
}

#[test]
fn merkle_proof_entries_keep_their_path_order() {
    let src = RgbSource {
        merkle_proofs: vec![MerkleProofEntry {
            txid: vec![1; 32],
            block_height: 800_000,
            tx_position: 3,
            merkle_path: vec![vec![2; 32], vec![3; 32], vec![4; 32]],
        }],
        ..Default::default()
    };
    let back = RgbSource::decode(src.encode_to_vec().as_slice()).unwrap();
    assert_eq!(back.merkle_proofs[0].merkle_path.len(), 3);
    assert_eq!(back, src);
}
