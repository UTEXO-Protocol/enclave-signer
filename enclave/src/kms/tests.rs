//! `kms` unit tests.
//!
//! The recipient envelope is built here by hand, exactly as KMS shapes it
//! (RSAES-OAEP-SHA-256 key transport, AES-256-CBC content), and opened by
//! `recipient::open_envelope`. The KMS exchanges are canned HTTP responses
//! through the SDK's replay client, so the request the enclave signs and the
//! way it validates each reply are exercised without AWS. The end-to-end
//! cases need `mock-attestation`, because a real recipient needs `/dev/nsm`.

use std::time::{Duration, Instant};

use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
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
        flow: CustodyFlow::RgbMint,
        key_arn: KEY_ARN.into(),
        region: "eu-west-1".into(),
        seed_id: "mint-pool-1".into(),
    }
}

fn credentials() -> AwsCredentials {
    AwsCredentials::new("AKIDEXAMPLE".into(), "secret".into(), "token".into()).unwrap()
}

/// Key generation dominates these tests; share one key.
fn recipient_key() -> RsaPrivateKey {
    use std::sync::OnceLock;
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::new(&mut rand_core::OsRng, RECIPIENT_RSA_BITS).unwrap())
        .clone()
}

/// Seal `plaintext` to `public_key` the way KMS does for a Recipient.
fn seal(public_key: &RsaPublicKey, plaintext: &[u8]) -> Vec<u8> {
    let mut cek = [0u8; 32];
    let mut iv = [0u8; 16];
    getrandom::fill(&mut cek).unwrap();
    getrandom::fill(&mut iv).unwrap();
    let ciphertext = cbc::Encryptor::<aes::Aes256>::new(&cek.into(), &iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    let wrapped_key = public_key
        .encrypt(&mut rand_core::OsRng, Oaep::new::<Sha256>(), &cek)
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
    let other = RsaPrivateKey::new(&mut rand_core::OsRng, RECIPIENT_RSA_BITS).unwrap();
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
    let client = KmsClient::new(config(), credentials(), Network::Bitcoin).unwrap();
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

/// Canned KMS exchanges. The recipient key is fixed so a response can be
/// sealed to it before the call is made.
#[cfg(feature = "mock-attestation")]
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

    fn client_with(status: u16, body: Value) -> (KmsClient, StaticReplayClient) {
        let replay = StaticReplayClient::new(vec![ReplayEvent::new(
            placeholder_request(),
            response(status, body),
        )]);
        let mut client = KmsClient::new(config(), credentials(), Network::Bitcoin).unwrap();
        client.test_transport = Some((SharedHttpClient::new(replay.clone()), recipient_key()));
        (client, replay)
    }

    fn sealed_seed(seed: &[u8]) -> String {
        BASE64.encode(seal(&recipient_key().to_public_key(), seed))
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

    #[test]
    fn decrypt_sends_the_measured_mint_request_and_returns_the_seed() {
        let seed = [42u8; 64];
        let (client, replay) = client_with(
            200,
            json!({
                "KeyId": KEY_ARN,
                "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
                "CiphertextForRecipient": sealed_seed(&seed),
            }),
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
        assert_eq!(
            body["EncryptionContext"],
            json!({
                "application": "utexo-enclave-signer",
                "flow": "rgb-mint",
                "seed_id": "mint-pool-1",
                "bitcoin_network": "bitcoin",
            })
        );
        assert_eq!(
            body["Recipient"]["KeyEncryptionAlgorithm"],
            "RSAES_OAEP_SHA_256"
        );
        // The attestation document carries the recipient's own public key.
        let document = BASE64
            .decode(body["Recipient"]["AttestationDocument"].as_str().unwrap())
            .unwrap();
        let verified = crate::attestation::verify_peer_attestation(
            &document,
            &attestation_verify::ExpectedPcrs::zero(),
            None,
        )
        .unwrap();
        let spki = recipient_key().to_public_key().to_public_key_der().unwrap();
        assert_eq!(verified.enclave_pubkey.as_slice(), spki.as_bytes());
    }

    #[test]
    fn generate_sends_the_mint_context_and_returns_only_the_durable_ciphertext() {
        let (client, replay) = client_with(
            200,
            json!({
                "KeyId": KEY_ARN,
                "CiphertextBlob": BASE64.encode([17; 200]),
                "CiphertextForRecipient": sealed_seed(&[1; 64]),
            }),
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
        assert_eq!(
            body["EncryptionContext"],
            json!({
                "application": "utexo-enclave-signer",
                "flow": "rgb-mint",
                "seed_id": "mint-pool-1",
                "bitcoin_network": "bitcoin",
            })
        );
        assert!(body.get("KeySpec").is_none());
    }

    #[test]
    fn responses_are_bound_to_the_key_and_never_accept_plaintext() {
        let good = || {
            json!({
                "KeyId": KEY_ARN,
                "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
                "CiphertextForRecipient": sealed_seed(&[3; 64]),
            })
        };
        let other_arn = KEY_ARN.replace("eu-west-1", "eu-west-2");
        let mut wrong_key = good();
        wrong_key["KeyId"] = json!(other_arn);
        let mut leaked = good();
        leaked["Plaintext"] = json!(BASE64.encode([3; 64]));
        let mut rsa_algorithm = good();
        rsa_algorithm["EncryptionAlgorithm"] = json!("RSAES_OAEP_SHA_256");
        let mut short_seed = good();
        short_seed["CiphertextForRecipient"] = json!(sealed_seed(&[3; 32]));
        let mut no_envelope = good();
        no_envelope
            .as_object_mut()
            .unwrap()
            .remove("CiphertextForRecipient");
        let mut garbage = good();
        garbage["CiphertextForRecipient"] = json!(BASE64.encode(b"not cms"));

        for body in [
            wrong_key,
            leaked,
            rsa_algorithm,
            short_seed,
            no_envelope,
            garbage,
        ] {
            let (client, _) = client_with(200, body);
            assert_custody(
                client.decrypt_seed(&[9; 100], deadline()).unwrap_err(),
                CustodyFailure::InvalidResponse,
            );
        }
        // An empty Plaintext is the documented attested shape.
        let mut empty_plaintext = good();
        empty_plaintext["Plaintext"] = json!("");
        let (client, _) = client_with(200, empty_plaintext);
        assert!(client.decrypt_seed(&[9; 100], deadline()).is_ok());

        // Generation validates the envelope too, and bounds the blob.
        let mut huge = json!({
            "KeyId": KEY_ARN,
            "CiphertextBlob": BASE64.encode(vec![1; MAX_CIPHERTEXT_BYTES + 1]),
            "CiphertextForRecipient": sealed_seed(&[1; 64]),
        });
        let (client, _) = client_with(200, huge.clone());
        assert_custody(
            client.generate_ciphertext(deadline()).unwrap_err(),
            CustodyFailure::InvalidResponse,
        );
        huge["CiphertextBlob"] = json!(BASE64.encode([1; 8]));
        huge["CiphertextForRecipient"] = json!(sealed_seed(&[1; 65]));
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
