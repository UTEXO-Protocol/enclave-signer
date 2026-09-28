use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use utexo_bridge_enclave::config::BridgeConfig;
use utexo_bridge_enclave::framing;
#[cfg(feature = "spv")]
use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
use utexo_bridge_enclave::policy::{BuildContext, EvmDataSource, SecurityPolicy};
use utexo_bridge_enclave::proto::*;
use utexo_bridge_enclave::server::{self, ServerContext};
use utexo_bridge_enclave::state::EnclaveState;

/// Start a test server on a random TCP port. Returns the port number.
/// The server runs in a background thread and handles connections until
/// the test process exits.
#[allow(dead_code)]
pub fn start_test_server() -> u16 {
    start_test_server_with(|_| {})
}

/// Start a test server, running the provided configuration closure against
/// the fresh `EnclaveState` before the listener accepts connections. Used
/// by the cloning integration test to seed the donor with a known seed
/// and a cloning secret before the first client request arrives.
pub fn start_test_server_with(configure: impl FnOnce(&EnclaveState)) -> u16 {
    start_test_server_with_config(configure, BridgeConfig::from_env())
}

/// Start a test server with an explicit `BridgeConfig`, for tests exercising
/// the pinned cross-check path. `start_test_server` / `_with` read env, which
/// is empty in CI, and mutating env across parallel tests is unsafe.
#[allow(dead_code)]
pub fn start_test_server_with_config(
    configure: impl FnOnce(&EnclaveState),
    bridge_config: BridgeConfig,
) -> u16 {
    start_test_server_with_policy(configure, bridge_config, BuildContext::current())
}

/// Start a test server whose security policy is resolved from an explicit
/// [`BuildContext`], so a production-shaped posture can be exercised without
/// a production build.
#[allow(dead_code)]
pub fn start_test_server_with_policy(
    configure: impl FnOnce(&EnclaveState),
    bridge_config: BridgeConfig,
    build: BuildContext,
) -> u16 {
    install_tracing();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let state = EnclaveState::new(bitcoin::Network::Bitcoin);
    configure(&state);
    // Tests run with the placeholder Regtest checkpoint. The header chain
    // is initialised but empty; tests that don't push headers leave it
    // alone, tests that do start from `checkpoint.height` (= 0). SPV-only.
    #[cfg(feature = "spv")]
    let header_chain = std::sync::Mutex::new(HeaderChain::new(
        Network::Regtest,
        checkpoint_for(Network::Regtest),
    ));
    let policy = SecurityPolicy::resolve(&build, &bridge_config, EvmDataSource::Disabled, None);
    let ctx = Arc::new(ServerContext {
        state,
        bridge_config,
        policy,
        #[cfg(feature = "rgb-validation")]
        rgb_validator: None,
        #[cfg(feature = "evm-rpc")]
        evm_rpc_client: None,
        #[cfg(feature = "evm-rpc")]
        evm_rpc_config: utexo_bridge_enclave::config::EvmRpcConfig::default(),
        #[cfg(feature = "spv")]
        header_chain,
        #[cfg(feature = "spv")]
        submit_rate_limiter: std::sync::Mutex::new(server::SubmitRateLimiter::default()),
    });

    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => server::handle_connection(stream, &ctx),
                Err(e) => eprintln!("test server accept error: {}", e),
            }
        }
    });

    port
}

/// Send a request to a test server and return the response.
/// Opens a new TCP connection (one connection per request, matching
/// the real vsock protocol).
pub fn send_request(port: u16, req: &EnclaveRequest) -> EnclaveResponse {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    framing::write_message(&mut stream, req).unwrap();
    framing::read_message(&mut stream).unwrap()
}

/// A tracing subscriber that enables every callsite and records nothing, so
/// the servers' log statements (and their field expressions) execute under
/// test instead of being skipped as disabled.
struct AllOn;

impl tracing::Subscriber for AllOn {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[allow(dead_code)]
pub fn install_tracing() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = tracing::subscriber::set_global_default(AllOn);
    });
}

/// Taproot PSBT fixtures whose script-path leaf carries one of the enclave's
/// own BIP-86 keys, so the signer has an input to sign.
#[allow(dead_code)]
pub mod taproot_fixture {
    use bitcoin::bip32::{ChildNumber, DerivationPath};
    use bitcoin::blockdata::opcodes::all::*;
    use bitcoin::blockdata::script::Builder as ScriptBuilder;
    use bitcoin::hashes::Hash;
    use bitcoin::key::{Keypair, Secp256k1, XOnlyPublicKey};
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
    use bitcoin::{
        Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use utexo_bridge_enclave::keys::{AccountType, KeyManager};

    /// NUMS internal key: the key path is unspendable.
    const NUMS_INTERNAL: [u8; 32] = [
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
        0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80,
        0x3a, 0xc0,
    ];

    pub fn xonly_from_byte(b: u8) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[b; 32]).unwrap();
        XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &sk)).0
    }

    fn multi_a_2_of_3(keys: &[XOnlyPublicKey; 3]) -> ScriptBuf {
        let mut sorted = *keys;
        sorted.sort();
        ScriptBuilder::new()
            .push_x_only_key(&sorted[0])
            .push_opcode(OP_CHECKSIG)
            .push_x_only_key(&sorted[1])
            .push_opcode(OP_CHECKSIGADD)
            .push_x_only_key(&sorted[2])
            .push_opcode(OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(OP_NUMEQUAL)
            .into_script()
    }

    /// The full BIP-86 path `m/86'/coin'/0'/0/0` the key manager resolves to
    /// `account`, found by asking the manager itself.
    fn full_path(km: &KeyManager, account: AccountType) -> DerivationPath {
        for coin in [0u32, 1, 827_166, 827_167] {
            let path = DerivationPath::from(vec![
                ChildNumber::from_hardened_idx(86).unwrap(),
                ChildNumber::from_hardened_idx(coin).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::Normal { index: 0 },
                ChildNumber::Normal { index: 0 },
            ]);
            if let Some((resolved, _)) = km.resolve_account_and_child_path(&path) {
                if resolved == account {
                    return path;
                }
            }
        }
        panic!("no coin type resolves to {account:?}");
    }

    /// A one-input PSBT whose P2TR input's leaf includes the enclave's key at
    /// `m/86'/coin'/0'/0/0` on `account`. With `pay_back` the single output
    /// returns to the very same script; otherwise it pays a third party.
    pub fn psbt_with_our_input(km: &KeyManager, account: AccountType, pay_back: bool) -> Psbt {
        let secp = Secp256k1::new();
        let sk = km
            .derive_btc_child(
                account,
                &[
                    ChildNumber::Normal { index: 0 },
                    ChildNumber::Normal { index: 0 },
                ],
            )
            .unwrap();
        let our = XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&secp, &sk)).0;
        let leaf_script = multi_a_2_of_3(&[our, xonly_from_byte(0xA1), xonly_from_byte(0xA2)]);
        let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);
        let internal_key = XOnlyPublicKey::from_slice(&NUMS_INTERNAL).unwrap();
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf_script.clone())
            .unwrap()
            .finalize(&secp, internal_key)
            .unwrap();
        let script_pubkey = ScriptBuf::new_p2tr(&secp, internal_key, spend_info.merkle_root());
        let control_block = spend_info
            .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
            .unwrap();
        let output_script = if pay_back {
            script_pubkey.clone()
        } else {
            ScriptBuf::new_p2tr(&secp, xonly_from_byte(0xC3), None)
        };
        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xBB; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: output_script,
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey,
        });
        psbt.inputs[0].tap_internal_key = Some(internal_key);
        psbt.inputs[0]
            .tap_scripts
            .insert(control_block, (leaf_script, LeafVersion::TapScript));
        psbt.inputs[0].tap_key_origins.insert(
            our,
            (
                vec![leaf_hash],
                (*km.master_fingerprint(), full_path(km, account)),
            ),
        );
        psbt
    }

    /// A one-input P2TR PSBT the enclave holds no key for, paying `pay_to`.
    pub fn psbt_with_foreign_input(pay_to: ScriptBuf) -> Psbt {
        let secp = Secp256k1::new();
        let script_pubkey = ScriptBuf::new_p2tr(&secp, xonly_from_byte(0xD4), None);
        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xCC; 32]),
                    vout: 1,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: pay_to,
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey,
        });
        psbt
    }
}
