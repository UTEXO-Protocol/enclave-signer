//! `kms` unit tests.
//!
//! The tests build the recipient envelope as KMS does (RSAES-OAEP-SHA-256 key
//! transport, AES-256-CBC content) and open it with `recipient::open_envelope`.
//! The KMS exchanges are canned HTTP responses through the SDK replay client,
//! so the signed request and the reply checks run without AWS. The exchange
//! cases inject a test recipient document without `/dev/nsm`; production builds
//! have no such transport hook. Mock-feature tests also cover plaintext replies.

use std::time::{Duration, Instant};

use aes::cipher::{block_padding::Pkcs7, BlockModeEncrypt, KeyIvInit};
use cms::cert::x509::der::asn1::{OctetString, SetOfVec};
use cms::cert::x509::der::{Any, Decode, Encode};
use cms::cert::x509::ext::pkix::SubjectKeyIdentifier;
use cms::cert::x509::spki::AlgorithmIdentifierOwned;
use cms::content_info::{CmsVersion, ContentInfo};
use cms::enveloped_data::{
    EncryptedContentInfo, EnvelopedData, KeyTransRecipientInfo, RecipientIdentifier, RecipientInfo,
    RecipientInfos,
};
use rsa::pkcs1::RsaOaepParams;
use rsa::sha2::Sha256;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};

use super::recipient::{
    open_envelope, ID_AES_256_CBC, ID_DATA, ID_ENVELOPED_DATA, ID_RSAES_OAEP, MAX_ENVELOPE_BYTES,
};
use super::*;

const KEY_ARN: &str = "arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012";

fn config() -> KmsConfig {
    KmsConfig {
        key_arn: KEY_ARN.into(),
        region: "eu-west-1".into(),
        seed_id: "mint-pool-1".into(),
    }
}

fn credentials() -> AwsCredentials {
    AwsCredentials::new("AKIDEXAMPLE".into(), "secret".into(), "token".into()).unwrap()
}

fn endpoint_digest() -> Option<[u8; 32]> {
    cfg!(all(feature = "rgb-validation", not(feature = "spv"))).then_some([0xab; 32])
}

#[test]
fn endpoint_binding_cannot_be_omitted_or_added_to_another_profile() {
    let client = |digest| KmsClient::new(config(), credentials(), Network::Bitcoin, digest);
    if cfg!(all(feature = "rgb-validation", not(feature = "spv"))) {
        assert!(client(None).is_err());
        assert!(client(Some([0; 32])).is_err());
        assert!(client(Some([0xab; 32])).is_ok());
    } else {
        assert!(client(None).is_ok());
        assert!(client(Some([0xab; 32])).is_err());
    }
}

/// Key generation is slow, so the tests share one key.
fn recipient_key() -> RsaPrivateKey {
    use std::sync::OnceLock;
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::new(&mut rsa::rand_core::OsRng, RECIPIENT_RSA_BITS).unwrap())
        .clone()
}

/// Seal `plaintext` to `public_key` the way KMS does for a Recipient.
fn seal(public_key: &RsaPublicKey, plaintext: &[u8]) -> Vec<u8> {
    let mut cek = [0u8; 32];
    let mut iv = [0u8; 16];
    getrandom::fill(&mut cek).unwrap();
    getrandom::fill(&mut iv).unwrap();
    let ciphertext = cbc::Encryptor::<aes::Aes256>::new(&cek.into(), &iv.into())
        .encrypt_padded_vec::<Pkcs7>(plaintext);
    let wrapped_key = public_key
        .encrypt(&mut rsa::rand_core::OsRng, Oaep::new::<Sha256>(), &cek)
        .unwrap();
    let ktri = KeyTransRecipientInfo {
        version: CmsVersion::V2,
        rid: RecipientIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(
            OctetString::new(vec![0u8; 20]).unwrap(),
        )),
        key_enc_alg: AlgorithmIdentifierOwned {
            oid: ID_RSAES_OAEP,
            parameters: Some(Any::encode_from(&RsaOaepParams::new::<Sha256>()).unwrap()),
        },
        enc_key: OctetString::new(wrapped_key).unwrap(),
    };
    let enveloped = EnvelopedData {
        version: CmsVersion::V2,
        originator_info: None,
        recip_infos: RecipientInfos(SetOfVec::try_from(vec![RecipientInfo::Ktri(ktri)]).unwrap()),
        encrypted_content: EncryptedContentInfo {
            content_type: ID_DATA,
            content_enc_alg: AlgorithmIdentifierOwned {
                oid: ID_AES_256_CBC,
                parameters: Some(
                    Any::encode_from(&OctetString::new(iv.to_vec()).unwrap()).unwrap(),
                ),
            },
            encrypted_content: Some(OctetString::new(ciphertext).unwrap()),
        },
        unprotected_attrs: None,
    };
    ContentInfo {
        content_type: ID_ENVELOPED_DATA,
        content: Any::encode_from(&enveloped).unwrap(),
    }
    .to_der()
    .unwrap()
}

#[test]
fn bitcoin_network_names_are_plain_context_values() {
    for network in [
        Network::Bitcoin,
        Network::Testnet,
        Network::Testnet4,
        Network::Signet,
        Network::Regtest,
    ] {
        let name = network.to_string();
        assert!((1..=8).contains(&name.len()));
        assert!(name.bytes().all(|b| b.is_ascii_graphic()));
    }
}

#[test]
fn configuration_rejects_endpoint_injection_alias_and_wrong_region() {
    assert!(config().validate().is_ok());
    assert_eq!(config().endpoint_host(), "kms.eu-west-1.amazonaws.com");
    for region in [
        "eu-west-1.attacker.example/",
        "eu-west-1:443",
        "cn-north-1",
        "us-gov-west-1",
    ] {
        let mut value = config();
        value.region = region.into();
        assert!(value.validate().is_err());
    }
    let mut value = config();
    value.key_arn = value.key_arn.replace("key/", "alias/");
    assert!(value.validate().is_err());
    let mut value = config();
    value.region = "eu-west-2".into();
    assert!(value.validate().is_err());
    value.key_arn = value.key_arn.replace("eu-west-1", "eu-west-2");
    assert!(value.validate().is_ok());
    let mut value = config();
    value.seed_id = "../other-pool".into();
    assert!(value.validate().is_err());
}

#[test]
fn credentials_reject_control_characters() {
    assert!(AwsCredentials::new("AKID".into(), "secret".into(), "token\r\nforged".into()).is_err());
}

#[test]
fn pinned_roots_are_the_amazon_trust_services_set() {
    let bundle = std::str::from_utf8(AMAZON_TRUST_ROOTS).unwrap();
    assert_eq!(bundle.matches("-----BEGIN CERTIFICATE-----").count(), 5);
    assert!(https_client().is_ok());
}

#[test]
fn recipient_envelope_round_trips_and_rejects_every_deviation() {
    let key = recipient_key();
    let public_key = key.to_public_key();
    let seed = [7u8; 64];

    let envelope = seal(&public_key, &seed);
    assert_eq!(open_envelope(&key, &envelope).unwrap().as_slice(), &seed);

    // A different recipient key: the OAEP unwrap fails closed.
    let other = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, RECIPIENT_RSA_BITS).unwrap();
    assert!(open_envelope(&other, &envelope).is_err());

    // Bounds and framing.
    assert!(open_envelope(&key, &[]).is_err());
    assert!(open_envelope(&key, &vec![0x30; MAX_ENVELOPE_BYTES + 1]).is_err());
    assert!(open_envelope(&key, &envelope[..envelope.len() - 1]).is_err());
    let mut flipped = envelope.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert!(open_envelope(&key, &flipped).is_err());

    // Not EnvelopedData at all.
    let signed = ContentInfo {
        content_type: cms::cert::x509::der::asn1::ObjectIdentifier::new_unwrap(
            "1.2.840.113549.1.7.2",
        ),
        content: Any::encode_from(&OctetString::new(vec![1]).unwrap()).unwrap(),
    }
    .to_der()
    .unwrap();
    assert!(open_envelope(&key, &signed).is_err());

    // Wrong algorithms are rejected before the private key is touched.
    let rewrite = |edit: &dyn Fn(&mut EnvelopedData)| {
        let info = ContentInfo::from_der(&envelope).unwrap();
        let mut enveloped: EnvelopedData = info.content.decode_as().unwrap();
        edit(&mut enveloped);
        ContentInfo {
            content_type: ID_ENVELOPED_DATA,
            content: Any::encode_from(&enveloped).unwrap(),
        }
        .to_der()
        .unwrap()
    };
    let with_ktri = |enveloped: &mut EnvelopedData, edit: &dyn Fn(&mut KeyTransRecipientInfo)| {
        let mut infos: Vec<RecipientInfo> = enveloped.recip_infos.0.iter().cloned().collect();
        if let RecipientInfo::Ktri(ktri) = &mut infos[0] {
            edit(ktri);
        }
        enveloped.recip_infos = RecipientInfos(SetOfVec::try_from(infos).unwrap());
    };
    let pkcs1 = rewrite(&|e| {
        with_ktri(e, &|k| {
            k.key_enc_alg = AlgorithmIdentifierOwned {
                oid: cms::cert::x509::der::asn1::ObjectIdentifier::new_unwrap(
                    "1.2.840.113549.1.1.1",
                ),
                parameters: None,
            }
        })
    });
    assert!(open_envelope(&key, &pkcs1).is_err());
    let oaep_sha1 = rewrite(&|e| {
        with_ktri(e, &|k| {
            k.key_enc_alg.parameters = Some(Any::encode_from(&RsaOaepParams::default()).unwrap())
        })
    });
    assert!(open_envelope(&key, &oaep_sha1).is_err());
    let aes128 = rewrite(&|e| {
        e.encrypted_content.content_enc_alg.oid =
            cms::cert::x509::der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.2")
    });
    assert!(open_envelope(&key, &aes128).is_err());
    let no_iv = rewrite(&|e| e.encrypted_content.content_enc_alg.parameters = None);
    assert!(open_envelope(&key, &no_iv).is_err());
    let no_content = rewrite(&|e| e.encrypted_content.encrypted_content = None);
    assert!(open_envelope(&key, &no_content).is_err());
    let two_recipients = rewrite(&|e| {
        let first = e.recip_infos.0.iter().next().unwrap().clone();
        let mut second = first.clone();
        if let RecipientInfo::Ktri(ktri) = &mut second {
            ktri.version = CmsVersion::V0;
        }
        e.recip_infos = RecipientInfos(SetOfVec::try_from(vec![first, second]).unwrap());
    });
    assert!(open_envelope(&key, &two_recipients).is_err());
}

/// KMS returns `CiphertextForRecipient` as streaming BER: indefinite lengths
/// and chunked encrypted content. A DER-only decode rejects it.
#[test]
fn recipient_envelope_accepts_streaming_ber_from_kms() {
    let key = recipient_key();
    let seed = [9u8; 64];
    let der = seal(&key.to_public_key(), &seed);
    let ber = super::ber::test_support::to_streaming_ber(&der);
    assert_ne!(ber, der);
    assert!(
        ContentInfo::from_der(&ber).is_err(),
        "strict DER must reject the BER form"
    );
    assert_eq!(open_envelope(&key, &ber).unwrap().as_slice(), &seed);
    // A missing end-of-contents marker is refused.
    assert!(open_envelope(&key, &ber[..ber.len() - 2]).is_err());
}

#[test]
fn service_errors_map_to_fixed_categories() {
    for (status, code, expected) in [
        (403, None, CustodyFailure::AccessDenied),
        (401, Some("Anything"), CustodyFailure::AccessDenied),
        (429, None, CustodyFailure::Unavailable),
        (503, Some("ServiceUnavailable"), CustodyFailure::Unavailable),
        (
            400,
            Some("AccessDeniedException"),
            CustodyFailure::AccessDenied,
        ),
        (
            400,
            Some("ExpiredTokenException"),
            CustodyFailure::AccessDenied,
        ),
        (
            400,
            Some("ThrottlingException"),
            CustodyFailure::Unavailable,
        ),
        (
            400,
            Some("KMSInternalException"),
            CustodyFailure::Unavailable,
        ),
        (
            400,
            Some("InvalidCiphertextException"),
            CustodyFailure::KeyOrCiphertext,
        ),
        (
            400,
            Some("NotFoundException"),
            CustodyFailure::KeyOrCiphertext,
        ),
        (
            400,
            Some("ValidationException"),
            CustodyFailure::Configuration,
        ),
        (
            400,
            Some("SomethingNewException"),
            CustodyFailure::InvalidResponse,
        ),
        (400, None, CustodyFailure::InvalidResponse),
        (302, None, CustodyFailure::InvalidResponse),
    ] {
        assert_eq!(
            classify_service(status, code),
            expected,
            "{status} {code:?}"
        );
    }
    assert_eq!(
        kms_error_name("com.amazonaws.kms#AccessDeniedException"),
        "AccessDeniedException"
    );
    assert_eq!(
        kms_error_name("AccessDeniedException"),
        "AccessDeniedException"
    );
}

#[test]
fn expired_deadline_never_starts_a_call() {
    let mut client =
        KmsClient::new(config(), credentials(), Network::Bitcoin, endpoint_digest()).unwrap();
    let transport = aws_smithy_http_client::test_util::infallible_client_fn(
        |_| -> http::Response<&'static str> {
            panic!("an expired deadline must not reach the transport");
        },
    );
    client.test_transport = Some((transport, recipient_key()));
    let error = client.generate_ciphertext(Instant::now()).unwrap_err();
    assert!(matches!(error, EnclaveError::Io(ref e) if e.kind() == std::io::ErrorKind::TimedOut));
    let error = client.decrypt_seed(&[1; 32], Instant::now()).unwrap_err();
    assert!(matches!(error, EnclaveError::Io(ref e) if e.kind() == std::io::ErrorKind::TimedOut));
    assert!(client
        .decrypt_seed(&[], Instant::now() + Duration::from_secs(1))
        .is_err());
    assert!(client
        .decrypt_seed(
            &[0; MAX_CIPHERTEXT_BYTES + 1],
            Instant::now() + Duration::from_secs(1)
        )
        .is_err());
}

/// Canned KMS exchanges. The ordinary build receives recipient envelopes;
/// `mock-attestation` receives plaintext, matching the two SDK request paths.
mod exchanges {
    use super::*;
    use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use serde_json::{json, Value};

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn placeholder_request() -> http::Request<SdkBody> {
        http::Request::builder()
            .method("POST")
            .uri("https://kms.eu-west-1.amazonaws.com/")
            .body(SdkBody::empty())
            .unwrap()
    }

    fn response(status: u16, body: Value) -> http::Response<SdkBody> {
        http::Response::builder()
            .status(status)
            .header("content-type", "application/x-amz-json-1.1")
            .body(SdkBody::from(body.to_string()))
            .unwrap()
    }

    fn seed_field() -> &'static str {
        if cfg!(feature = "mock-attestation") {
            "Plaintext"
        } else {
            "CiphertextForRecipient"
        }
    }

    fn seed_response(mut body: Value, seed: &[u8]) -> Value {
        let encoded = if cfg!(feature = "mock-attestation") {
            BASE64.encode(seed)
        } else {
            BASE64.encode(seal(&recipient_key().to_public_key(), seed))
        };
        body[seed_field()] = json!(encoded);
        body
    }

    fn assert_recipient(body: &Value) {
        if cfg!(feature = "mock-attestation") {
            assert!(body.get("Recipient").is_none());
        } else {
            assert_eq!(
                body["Recipient"]["KeyEncryptionAlgorithm"],
                "RSAES_OAEP_SHA_256"
            );
            assert_eq!(
                body["Recipient"]["AttestationDocument"],
                BASE64.encode(b"unit-test-recipient")
            );
        }
    }

    fn client_with(status: u16, body: Value) -> (KmsClient, StaticReplayClient) {
        let replay = StaticReplayClient::new(vec![ReplayEvent::new(
            placeholder_request(),
            response(status, body),
        )]);
        let mut client =
            KmsClient::new(config(), credentials(), Network::Bitcoin, endpoint_digest()).unwrap();
        client.test_transport = Some((SharedHttpClient::new(replay.clone()), recipient_key()));
        (client, replay)
    }

    fn sent_body(replay: &StaticReplayClient) -> Value {
        let request = replay.actual_requests().next().expect("one request");
        serde_json::from_slice(request.body().bytes().expect("in-memory body")).unwrap()
    }

    fn assert_custody(error: EnclaveError, expected: CustodyFailure) {
        match error {
            EnclaveError::Custody { failure, .. } => assert_eq!(failure, expected),
            other => panic!("expected custody failure {expected:?}, got {other:?}"),
        }
    }

    fn expected_context() -> Value {
        let mut context = json!({
            "application": "utexo-enclave-signer",
            "flow": "rgb-mint",
            "seed_id": "mint-pool-1",
            "bitcoin_network": "bitcoin",
        });
        if cfg!(all(feature = "rgb-validation", not(feature = "spv"))) {
            context["chain_endpoints_sha256"] = json!("ab".repeat(32));
        }
        context
    }

    #[test]
    fn decrypt_sends_the_measured_mint_request_and_returns_the_seed() {
        let seed = [42u8; 64];
        let (client, replay) = client_with(
            200,
            seed_response(
                json!({
                    "KeyId": KEY_ARN,
                    "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
                }),
                &seed,
            ),
        );
        let recovered = client.decrypt_seed(&[9; 100], deadline()).unwrap();
        assert_eq!(*recovered, seed);

        let request = replay.actual_requests().next().unwrap();
        assert_eq!(
            request.uri().to_string(),
            "https://kms.eu-west-1.amazonaws.com/"
        );
        assert_eq!(
            request.headers().get("x-amz-target"),
            Some("TrentService.Decrypt")
        );
        assert!(request
            .headers()
            .get("authorization")
            .unwrap()
            .starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"));
        assert_eq!(request.headers().get("x-amz-security-token"), Some("token"));

        let body = sent_body(&replay);
        assert_eq!(body["KeyId"], KEY_ARN);
        assert_eq!(body["EncryptionAlgorithm"], "SYMMETRIC_DEFAULT");
        assert_eq!(body["CiphertextBlob"], BASE64.encode([9; 100]));
        assert_eq!(body["EncryptionContext"], expected_context());
        assert_recipient(&body);
    }

    #[test]
    fn generate_sends_the_mint_context_and_returns_only_the_durable_ciphertext() {
        let (client, replay) = client_with(
            200,
            seed_response(
                json!({
                    "KeyId": KEY_ARN,
                    "CiphertextBlob": BASE64.encode([17; 200]),
                }),
                &[1; 64],
            ),
        );
        assert_eq!(client.generate_ciphertext(deadline()).unwrap(), [17; 200]);
        let request = replay.actual_requests().next().unwrap();
        assert_eq!(
            request.headers().get("x-amz-target"),
            Some("TrentService.GenerateDataKey")
        );
        let body = sent_body(&replay);
        assert_eq!(body["NumberOfBytes"], 64);
        assert_eq!(body["KeyId"], KEY_ARN);
        assert_eq!(body["EncryptionContext"], expected_context());
        assert!(body.get("KeySpec").is_none());
        assert_recipient(&body);
    }

    /// Model KMS's exact encryption-context check against the actual SDK
    /// request. Credential rotation recovers the same identity; changing any
    /// approved public endpoint property must not activate it.
    #[cfg(all(feature = "rgb-validation", not(feature = "spv")))]
    #[test]
    fn changed_endpoint_context_cannot_activate_the_saved_identity() {
        use crate::config::{chain_endpoints_sha256, Endpoints};
        use crate::keys::KeyManager;
        use crate::proto::SetEndpointsRequest;
        use crate::seed_persistence::SeedSource;
        use crate::state::EnclaveState;
        use aws_smithy_http_client::test_util::infallible_client_fn;
        use std::sync::{Arc, Mutex};

        struct SavedSeed(KmsClient);
        impl SeedSource for SavedSeed {
            fn load_keys(&self, network: Network, deadline: Instant) -> Result<KeyManager> {
                let seed = self.0.decrypt_seed(&[9; 100], deadline)?;
                KeyManager::from_seed(*seed, network)
            }
        }

        let original = SetEndpointsRequest {
            electrum_url: "ssl://electrum.test:50002".into(),
            evm_rpc_host: "rpc.test".into(),
            evm_rpc_ca_der: hex::decode(
                include_str!("../../tests/fixtures/evm_rpc_tls/ca_a.der.hex").trim(),
            )
            .unwrap(),
            evm_rpc_tls_port: 443,
            evm_rpc_path: "/v2/original-key".into(),
            kms_key_arn: KEY_ARN.into(),
            kms_region: "eu-west-1".into(),
            kms_seed_id: "mint-pool-1".into(),
            ..Default::default()
        };
        let approved_digest = chain_endpoints_sha256(&original);
        let mut approved_context = expected_context();
        approved_context["bitcoin_network"] = json!("signet");
        approved_context["chain_endpoints_sha256"] = json!(hex::encode(approved_digest));

        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&calls);
        let transport = infallible_client_fn(move |request| {
            assert_eq!(request.headers()["x-amz-target"], "TrentService.Decrypt");
            let body: Value = serde_json::from_slice(request.body().bytes().unwrap()).unwrap();
            assert_eq!(body["CiphertextBlob"], BASE64.encode([9; 100]));
            recorded
                .lock()
                .unwrap()
                .push(body["EncryptionContext"].clone());
            assert_recipient(&body);
            if body["EncryptionContext"] != approved_context {
                return response(400, json!({"__type": "InvalidCiphertextException"}));
            }
            response(
                200,
                seed_response(
                    json!({
                        "KeyId": KEY_ARN,
                        "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
                    }),
                    &[42; 64],
                ),
            )
        });
        let state = |request: &SetEndpointsRequest| {
            Endpoints::parse(request).unwrap();
            let digest = chain_endpoints_sha256(request);
            let mut client =
                KmsClient::new(config(), credentials(), Network::Signet, Some(digest)).unwrap();
            client.test_transport = Some((transport.clone(), recipient_key()));
            EnclaveState::new(Network::Signet).with_seed_source(Box::new(SavedSeed(client)))
        };

        let expected = KeyManager::from_seed([42; 64], Network::Signet).unwrap();
        let mut rotated = original.clone();
        rotated.evm_rpc_path = "/v2/rotated-key".into();
        for request in [&original, &rotated] {
            let approved = state(request);
            approved
                .initialize_from_persistence_until(deadline())
                .unwrap();
            assert_eq!(approved.evm_address().unwrap(), *expected.evm_address());
        }

        let mut host = original.clone();
        host.evm_rpc_host = "other-rpc.test".into();
        let mut ca = original.clone();
        ca.evm_rpc_ca_der =
            hex::decode(include_str!("../../tests/fixtures/evm_rpc_tls/ca_b.der.hex").trim())
                .unwrap();
        let mut port = original.clone();
        port.evm_rpc_tls_port = 8443;
        let mut indexer = original.clone();
        indexer.electrum_url = "ssl://other-electrum.test:50002".into();
        let changes = [host, ca, port, indexer];
        for request in &changes {
            let changed = state(request);
            assert_custody(
                changed
                    .initialize_from_persistence_until(deadline())
                    .unwrap_err(),
                CustodyFailure::KeyOrCiphertext,
            );
            assert_eq!(changed.phase_name(), "initial");
            assert!(!changed.is_initialized());
            assert!(changed.sign_evm(&[7; 32]).is_err());
        }
        // One request per launch: no retry with the old context or new seed.
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 6);
        assert_eq!(
            calls[0]["chain_endpoints_sha256"],
            hex::encode(approved_digest)
        );
        assert_eq!(calls[0], calls[1]);
        for (call, request) in calls[2..].iter().zip(&changes) {
            assert_ne!(call, &calls[0]);
            assert_eq!(
                call["chain_endpoints_sha256"],
                hex::encode(chain_endpoints_sha256(request))
            );
        }
    }

    #[test]
    fn responses_are_bound_to_the_key_and_the_seed_length() {
        let good = || {
            seed_response(
                json!({
                    "KeyId": KEY_ARN,
                    "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
                }),
                &[3; 64],
            )
        };
        let other_arn = KEY_ARN.replace("eu-west-1", "eu-west-2");
        let mut wrong_key = good();
        wrong_key["KeyId"] = json!(other_arn);
        let mut rsa_algorithm = good();
        rsa_algorithm["EncryptionAlgorithm"] = json!("RSAES_OAEP_SHA_256");
        let short_seed = seed_response(good(), &[3; 32]);
        let empty_seed = seed_response(good(), &[]);
        let mut no_seed = good();
        no_seed.as_object_mut().unwrap().remove(seed_field());

        for body in [wrong_key, rsa_algorithm, short_seed, empty_seed, no_seed] {
            let (client, _) = client_with(200, body);
            assert_custody(
                client.decrypt_seed(&[9; 100], deadline()).unwrap_err(),
                CustodyFailure::InvalidResponse,
            );
        }

        // Generation checks the seed length too, and bounds the blob.
        let mut huge = seed_response(
            json!({
                "KeyId": KEY_ARN,
                "CiphertextBlob": BASE64.encode(vec![1; MAX_CIPHERTEXT_BYTES + 1]),
            }),
            &[1; 64],
        );
        let (client, _) = client_with(200, huge.clone());
        assert_custody(
            client.generate_ciphertext(deadline()).unwrap_err(),
            CustodyFailure::InvalidResponse,
        );
        huge["CiphertextBlob"] = json!(BASE64.encode([1; 8]));
        huge = seed_response(huge, &[1; 65]);
        let (client, _) = client_with(200, huge.clone());
        assert_custody(
            client.generate_ciphertext(deadline()).unwrap_err(),
            CustodyFailure::InvalidResponse,
        );
        huge.as_object_mut().unwrap().remove(seed_field());
        let (client, _) = client_with(200, huge);
        assert_custody(
            client.generate_ciphertext(deadline()).unwrap_err(),
            CustodyFailure::InvalidResponse,
        );
    }

    #[test]
    fn service_failures_become_fixed_categories_without_service_text() {
        for (status, body, expected) in [
            (
                400,
                json!({"__type": "AccessDeniedException", "message": "sensitive detail"}),
                CustodyFailure::AccessDenied,
            ),
            (
                400,
                json!({"__type": "com.amazonaws.kms#InvalidCiphertextException", "message": "sensitive"}),
                CustodyFailure::KeyOrCiphertext,
            ),
            (
                400,
                json!({"__type": "ThrottlingException", "message": "sensitive"}),
                CustodyFailure::Unavailable,
            ),
            (
                500,
                json!({"__type": "KMSInternalException", "message": "sensitive"}),
                CustodyFailure::Unavailable,
            ),
            (
                403,
                json!({"message": "sensitive"}),
                CustodyFailure::AccessDenied,
            ),
            (200, json!("not an object"), CustodyFailure::InvalidResponse),
        ] {
            let (client, _) = client_with(status, body);
            let error = client.decrypt_seed(&[9; 100], deadline()).unwrap_err();
            assert!(!error.to_string().contains("sensitive"));
            assert_custody(error, expected);
        }
    }
}
