//! Testing-branch-only client for the real enclave TCP protocol.
//!
//! The enclave binary owns initialization and signing; this client only sends
//! protobuf requests and verifies the returned signature with public keys.

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use k256::ecdsa::{signature::hazmat::PrehashVerifier, RecoveryId, Signature, VerifyingKey};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use utexo_bridge_enclave::framing;
use utexo_bridge_enclave::proto::enclave_request::Request;
use utexo_bridge_enclave::proto::enclave_response::Response;
use utexo_bridge_enclave::proto::*;

struct ClientError {
    code: u32,
    message: String,
}

type Result<T> = std::result::Result<T, ClientError>;

fn error(message: impl ToString) -> ClientError {
    ClientError {
        code: 0,
        message: message.to_string(),
    }
}

fn request(address: &str, request: Request) -> Result<Response> {
    let address: SocketAddr = address.parse().map_err(error)?;
    if !address.ip().is_loopback() {
        return Err(error("the local E2E client requires a loopback address"));
    }
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5)).map_err(error)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(90)))
        .map_err(error)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(error)?;
    framing::write_message(
        &mut stream,
        &EnclaveRequest {
            request: Some(request),
        },
    )
    .map_err(error)?;
    let response: EnclaveResponse = framing::read_message(&mut stream).map_err(error)?;
    match response.response {
        Some(Response::Error(failure)) => Err(ClientError {
            code: failure.code,
            message: failure.message,
        }),
        Some(response) => Ok(response),
        None => Err(error("empty enclave response")),
    }
}

fn keys(address: &str) -> Result<PublicKeysResponse> {
    match request(address, Request::GetPublicKey(GetPublicKeyRequest {}))? {
        Response::PublicKeys(keys) => Ok(keys),
        _ => Err(error("expected public keys response")),
    }
}

fn public_json(keys: PublicKeysResponse) -> Value {
    json!({
        "evm_address": hex::encode(keys.evm_address),
        "btc_compressed_pub": hex::encode(keys.btc_compressed_pub),
        "btc_xpub": keys.btc_xpub,
        "master_fingerprint": hex::encode(keys.master_fingerprint),
        "account_xpub_vanilla": keys.account_xpub_vanilla,
        "account_xpub_colored": keys.account_xpub_colored,
        "evm_uncompressed_pub": hex::encode(keys.evm_uncompressed_pub),
        "chain_id": keys.chain_id,
        "bridge_contract": hex::encode(keys.bridge_contract),
        "rgb_asset_id": keys.rgb_asset_id,
        "evm_gas_tx_uncompressed_pub": hex::encode(keys.evm_gas_tx_uncompressed_pub),
        "evm_gas_tx_address": hex::encode(keys.evm_gas_tx_address),
        "ccd_ed25519_pub": hex::encode(keys.ccd_ed25519_pub),
    })
}

fn default_unsigned_tx() -> Vec<u8> {
    // EIP-1559: chain=1, nonce=7, priority fee=1, max fee=100, gas=21000,
    // to=0xaa*20, value=0, calldata=deadbeef, accessList=[].
    hex::decode(format!(
        "02e30107016482520894{}8084deadbeefc0",
        "aa".repeat(20)
    ))
    .expect("fixed EIP-1559 test fixture")
}

fn sign(address: &str, unsigned_tx: Vec<u8>) -> Result<Value> {
    let signature = match request(
        address,
        Request::SignRawDigest(SignRawDigestRequest {
            digest: vec![],
            unsigned_tx: unsigned_tx.clone(),
        }),
    )? {
        Response::RawDigestSig(response) => response.signature,
        _ => return Err(error("expected gas signature response")),
    };
    if signature.len() != 65 {
        return Err(error("expected 65-byte recoverable signature"));
    }
    let keys = keys(address)?;
    let digest = Keccak256::digest(&unsigned_tx);
    let parsed = Signature::from_slice(&signature[..64]).map_err(error)?;
    let recovery = RecoveryId::from_byte(signature[64])
        .ok_or_else(|| error("invalid signature recovery ID"))?;
    let recovered =
        VerifyingKey::recover_from_prehash(&digest, &parsed, recovery).map_err(error)?;
    let encoded = recovered.to_encoded_point(false);
    let public_key = &encoded.as_bytes()[1..];
    if public_key != keys.evm_gas_tx_uncompressed_pub {
        return Err(error("gas signature recovered a different public key"));
    }
    recovered.verify_prehash(&digest, &parsed).map_err(error)?;
    let address_hash = Keccak256::digest(public_key);
    let recovered_address = &address_hash[12..];
    if recovered_address != keys.evm_gas_tx_address {
        return Err(error("gas signature recovered a different address"));
    }
    Ok(json!({
        "ok": true,
        "verified": true,
        "signature": hex::encode(signature),
        "unsigned_tx": hex::encode(unsigned_tx),
        "digest": hex::encode(digest),
        "public_key": hex::encode(public_key),
        "evm_address": hex::encode(recovered_address),
    }))
}

fn run() -> Result<Value> {
    let mut args = std::env::args().skip(1);
    let first = args.next().ok_or_else(|| error("usage: kms-e2e-client --addr 127.0.0.1:PORT init|keys|sign [TX_HEX]|clone|clone-get|clone-set|import"))?;
    let (address, command) = if first == "--addr" {
        (
            args.next().ok_or_else(|| error("missing --addr value"))?,
            args.next().ok_or_else(|| error("missing command"))?,
        )
    } else {
        ("127.0.0.1:5000".into(), first)
    };
    let extra = args.next();
    if args.next().is_some() || (extra.is_some() && command != "sign") {
        return Err(error("unexpected command arguments"));
    }
    match command.as_str() {
        "init" => {
            match request(
                &address,
                Request::InitializeKey(InitializeKeyRequest::default()),
            )? {
                Response::InitializeKey(_) => {}
                _ => return Err(error("expected initialize response")),
            }
            Ok(json!({"ok": true, "keys": public_json(keys(&address)?)}))
        }
        "keys" => Ok(json!({"ok": true, "keys": public_json(keys(&address)?)})),
        "sign" => sign(
            &address,
            match extra {
                Some(tx) => hex::decode(tx.strip_prefix("0x").unwrap_or(&tx)).map_err(error)?,
                None => default_unsigned_tx(),
            },
        ),
        "clone" => {
            request(
                &address,
                Request::InitiateCloning(InitiateCloningRequest {
                    cloning_secret: "local-e2e-clone-rejection-probe".into(),
                    cluster_public_key: vec![0x11; 20],
                }),
            )?;
            Ok(json!({"ok": true, "accepted": "InitiateCloning"}))
        }
        "clone-get" => {
            request(&address, Request::GetClone(GetCloneRequest::default()))?;
            Ok(json!({"ok": true, "accepted": "GetClone"}))
        }
        "clone-set" => {
            request(&address, Request::SetClone(SetCloneRequest::default()))?;
            Ok(json!({"ok": true, "accepted": "SetClone"}))
        }
        "import" => {
            request(
                &address,
                Request::InitializeKey(InitializeKeyRequest {
                    seed: vec![0x42; 64],
                    ..Default::default()
                }),
            )?;
            Ok(json!({"ok": true, "accepted": "plaintext seed import"}))
        }
        _ => Err(error("unknown command")),
    }
}

fn main() {
    match run() {
        Ok(result) => println!("{result}"),
        Err(failure) => {
            println!(
                "{}",
                json!({"ok": false, "error": {"code": failure.code, "message": failure.message}})
            );
            std::process::exit(1);
        }
    }
}
