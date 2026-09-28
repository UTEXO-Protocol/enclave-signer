use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use utexo_bridge_parent::client::{EnclaveClient, SignEvmRequest, SignPsbtRequest};
use utexo_bridge_parent::enclave_proto::{InitializeKeyResponse, PublicKeysResponse};

#[derive(Parser)]
#[command(
    name = "utexo-bridge-parent-cli",
    about = "UTEXO Bridge enclave host-side client (CLI tool)"
)]
struct Cli {
    /// Enclave address: `host:port` (TCP, dev builds) or `vsock://<cid>:<port>`
    /// (Nitro, vsock builds - e.g. `vsock://18:5000`). On a vsock build you MUST
    /// pass a `vsock://` addr or set ENCLAVE_VSOCK_CID; it will not default to CID 16.
    #[arg(long, default_value = "127.0.0.1:5000")]
    addr: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize keys (generate new mnemonic in the enclave)
    Init {
        /// Donor cloning secret, delivered at runtime (not baked into the EIF).
        /// Set only on enclaves that should serve clone requests.
        #[arg(long)]
        cloning_secret: Option<String>,
    },
    /// Initialize from a hex-encoded 64-byte seed (testing only)
    InitSeed {
        /// 128 hex characters = 64 bytes
        hex: String,
    },
    /// Initialize from a BIP-39 mnemonic phrase (testing only)
    InitMnemonic {
        /// BIP-39 mnemonic words (e.g. "word1 word2 ... word12")
        words: String,
    },
    /// Get public keys from the enclave
    GetKeys,
    /// Sign an EVM transaction (EIP-712 typed data)
    SignEvm {
        /// Hex-encoded ABI call data
        #[arg(long)]
        call_data: String,
        /// Per-selector sequential nonce
        #[arg(long)]
        nonce: u64,
        /// Unix timestamp deadline
        #[arg(long)]
        deadline: u64,
        /// Chain ID for EIP-712 domain
        #[arg(long, default_value = "1")]
        chain_id: u64,
        /// Hex-encoded proxy contract address (20 bytes)
        #[arg(long, default_value = "0000000000000000000000000000000000000000")]
        proxy_contract: String,
        /// RGB consignment amount (smallest unit)
        #[arg(long, default_value = "0")]
        rgb_amount: u64,
        /// RGB asset identifier
        #[arg(long, default_value = "")]
        rgb_asset_id: String,
        /// Pre-extracted calldata amount
        #[arg(long, default_value = "0")]
        calldata_amount: u64,
        /// Pre-extracted calldata commission
        #[arg(long, default_value = "0")]
        calldata_commission: u64,
        /// Mark consignment as valid (required unless enclave is in dev-mode)
        #[arg(long)]
        consignment_valid: bool,
    },
    /// Sign a PSBT (SegWit v0 P2WSH multisig)
    SignPsbt {
        /// Hex-encoded PSBT bytes
        #[arg(long)]
        psbt: String,
        /// Hex-encoded EVM tx hash (32 bytes)
        #[arg(long, default_value = "")]
        evm_tx_hash: String,
        /// EVM deposit amount
        #[arg(long, default_value = "0")]
        evm_amount: u64,
        /// EVM commission
        #[arg(long, default_value = "0")]
        evm_commission: u64,
        /// On-chain BridgeFundsIn.operationId, 32-byte hex. Required.
        #[arg(long, default_value = "")]
        evm_funds_in_operation_id: String,
        /// PSBT total non-change output amount
        #[arg(long, default_value = "0")]
        psbt_output_amount: u64,
        /// Mark EVM event as valid
        #[arg(long)]
        evm_event_valid: bool,
        /// Mark EVM event as finalized
        #[arg(long)]
        evm_event_finalized: bool,
        /// RGB asset identifier associated with the transfer
        #[arg(long, default_value = "")]
        rgb_asset_id: String,
        /// Hex-encoded RGB consignment bytes
        #[arg(long, default_value = "")]
        consignment: String,
    },
    /// Get the enclave's current SPV chain tip (height + hash).
    /// Listener calls this on startup to know where to resume header sync.
    GetLastSavedBlock,
    /// Push a batch of Bitcoin block headers into the enclave's SPV chain.
    ///
    /// Headers are read from a file: one hex-encoded 80-byte header per line,
    /// in ascending height order. Empty lines and lines starting with `#` are
    /// ignored. Pass an empty file to send a no-op batch (useful for smoke
    /// testing - proves the dispatch path without a fixture chain).
    SubmitHeaders {
        /// Block height of the first header in the batch.
        #[arg(long)]
        start_height: u32,
        /// Path to a file with one hex-encoded header per line (80 bytes = 160 hex chars).
        #[arg(long)]
        headers_file: PathBuf,
    },
    /// Clone the signing identity from a donor enclave into the local
    /// (requester) enclave. Runs the full three-step handshake:
    ///   1. InitiateCloning on the local enclave (vsock).
    ///   2. gRPC Clone to the donor's parent adapter (relayed to its GetClone).
    ///   3. SetClone on the local enclave (vsock), then verify the EVM address
    ///      now matches the donor's cluster identity.
    Clone {
        /// Pre-shared operator cloning secret (must match the donor enclave's
        /// baked UTEXO_CLONING_SECRET).
        #[arg(long)]
        cloning_secret: String,
        /// Donor parent-adapter gRPC endpoint, e.g. http://10.0.1.23:50051
        #[arg(long)]
        donor_grpc: String,
        /// Donor cluster identity: 20-byte EVM address, hex (with or without 0x).
        #[arg(long)]
        donor_evm: String,
    },
    /// Enter interactive REPL mode
    Interactive,
}

fn print_init_response(r: &InitializeKeyResponse) {
    println!("Keys initialized:");
    println!("  EVM address:         0x{}", hex::encode(&r.evm_address));
    println!(
        "  BTC pubkey:          {}",
        hex::encode(&r.btc_compressed_pub)
    );
    println!("  BTC xpub:            {}", r.btc_xpub);
    println!(
        "  Master fingerprint:  {}",
        hex::encode(&r.master_fingerprint)
    );
    println!("  Account xpub vanilla: {}", r.account_xpub_vanilla);
    println!("  Account xpub colored: {}", r.account_xpub_colored);
    println!(
        "  EVM gas TX address:  0x{}",
        hex::encode(&r.evm_gas_tx_address)
    );
    println!(
        "  EVM gas TX pubkey:   {}",
        hex::encode(&r.evm_gas_tx_uncompressed_pub)
    );
    println!("  CCD Ed25519 pubkey:  {}", hex::encode(&r.ccd_ed25519_pub));
    print_bridge_config(r.chain_id, &r.bridge_contract, &r.rgb_asset_id);
}

fn print_keys_response(r: &PublicKeysResponse) {
    println!("  EVM address:         0x{}", hex::encode(&r.evm_address));
    println!(
        "  BTC pubkey:          {}",
        hex::encode(&r.btc_compressed_pub)
    );
    println!("  BTC xpub:            {}", r.btc_xpub);
    println!(
        "  Master fingerprint:  {}",
        hex::encode(&r.master_fingerprint)
    );
    println!("  Account xpub vanilla: {}", r.account_xpub_vanilla);
    println!("  Account xpub colored: {}", r.account_xpub_colored);
    println!(
        "  EVM gas TX address:  0x{}",
        hex::encode(&r.evm_gas_tx_address)
    );
    println!(
        "  EVM gas TX pubkey:   {}",
        hex::encode(&r.evm_gas_tx_uncompressed_pub)
    );
    println!("  CCD Ed25519 pubkey:  {}", hex::encode(&r.ccd_ed25519_pub));
    print_bridge_config(r.chain_id, &r.bridge_contract, &r.rgb_asset_id);
}

fn print_bridge_config(chain_id: u64, bridge_contract: &[u8], rgb_asset_id: &str) {
    let configured =
        chain_id != 0 || bridge_contract.iter().any(|b| *b != 0) || !rgb_asset_id.is_empty();
    if configured {
        println!("  Bridge chain_id:     {chain_id}");
        println!("  Bridge contract:     0x{}", hex::encode(bridge_contract));
        println!("  RGB asset id:        {rgb_asset_id}");
    } else {
        println!("  Bridge config:       <unconfigured>");
    }
}

fn run_interactive(client: &EnclaveClient) {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    run_interactive_io(client, &mut stdin.lock(), &mut stdout);
}

/// The REPL over explicit streams, so it can be driven from a test.
fn run_interactive_io(client: &EnclaveClient, input: &mut impl BufRead, out: &mut impl Write) {
    loop {
        let _ = write!(out, "enclave> ");
        let _ = out.flush();

        let mut line = String::new();
        if input.read_line(&mut line).unwrap_or(0) == 0 {
            break; // EOF
        }

        let trimmed = line.trim();
        let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();

        match parts[0] {
            "init" => match client.initialize_keys(None) {
                Ok(r) => print_init_response(&r),
                Err(e) => eprintln!("Error: {}", e),
            },
            "init-seed" => {
                if parts.len() < 2 {
                    eprintln!("Usage: init-seed <128 hex chars>");
                    continue;
                }
                match hex::decode(parts[1]) {
                    Ok(seed) => match client.initialize_keys(Some(seed)) {
                        Ok(r) => print_init_response(&r),
                        Err(e) => eprintln!("Error: {}", e),
                    },
                    Err(e) => eprintln!("Invalid hex: {}", e),
                }
            }
            "init-mnemonic" => {
                if parts.len() < 2 {
                    eprintln!("Usage: init-mnemonic <word1 word2 ... word12>");
                    continue;
                }
                match client.initialize_keys_mnemonic(parts[1]) {
                    Ok(r) => print_init_response(&r),
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            "get-keys" => match client.get_public_keys() {
                Ok(r) => print_keys_response(&r),
                Err(e) => eprintln!("Error: {}", e),
            },
            "help" => {
                let _ = writeln!(
                    out,
                    "Commands: init, init-seed <hex>, init-mnemonic <words>, get-keys, help, quit, exit"
                );
            }
            "quit" | "exit" => break,
            "" => {}
            other => eprintln!("Unknown command: {}. Type 'help' for commands.", other),
        }
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    if let Err(message) = run(Cli::parse()) {
        eprintln!("{message}");
        process::exit(1);
    }
}

/// Execute one parsed command. Every failure is returned as the message the
/// binary prints before exiting non-zero.
fn run(cli: Cli) -> Result<(), String> {
    let client = EnclaveClient::new(&cli.addr);

    match cli.command {
        Command::Init { cloning_secret } => {
            let r = client
                .initialize_keys_with_secret(None, cloning_secret)
                .map_err(|e| format!("Error: {e}"))?;
            print_init_response(&r);
        }
        Command::InitSeed { hex: hex_str } => {
            let seed = hex::decode(&hex_str).map_err(|e| format!("Invalid hex: {e}"))?;
            let r = client
                .initialize_keys(Some(seed))
                .map_err(|e| format!("Error: {e}"))?;
            print_init_response(&r);
        }
        Command::InitMnemonic { words } => {
            let r = client
                .initialize_keys_mnemonic(&words)
                .map_err(|e| format!("Error: {e}"))?;
            print_init_response(&r);
        }
        Command::GetKeys => {
            let r = client
                .get_public_keys()
                .map_err(|e| format!("Error: {e}"))?;
            print_keys_response(&r);
        }
        Command::SignEvm {
            call_data,
            nonce,
            deadline,
            chain_id,
            proxy_contract,
            rgb_amount,
            rgb_asset_id,
            calldata_amount,
            calldata_commission,
            consignment_valid,
        } => {
            let data =
                hex::decode(&call_data).map_err(|e| format!("Invalid hex call_data: {e}"))?;
            let proxy = hex::decode(&proxy_contract)
                .map_err(|e| format!("Invalid hex proxy_contract: {e}"))?;
            let req = SignEvmRequest {
                call_data: data,
                nonce,
                deadline,
                consignment_valid,
                rgb_amount,
                rgb_asset_id,
                chain_id,
                proxy_contract: proxy,
                calldata_amount,
                calldata_commission,
                merkle_proofs: vec![],
                consignment: vec![],
                consignment_hash: vec![],
                lz_release: None,
            };
            let r = client.sign_evm(req).map_err(|e| format!("Error: {e}"))?;
            println!("EVM signature (65 bytes): {}", hex::encode(&r.signature));
        }
        Command::SignPsbt {
            psbt,
            evm_tx_hash,
            evm_amount,
            evm_commission,
            evm_funds_in_operation_id,
            psbt_output_amount,
            evm_event_valid,
            evm_event_finalized,
            rgb_asset_id,
            consignment,
        } => {
            let psbt_bytes = hex::decode(&psbt).map_err(|e| format!("Invalid hex PSBT: {e}"))?;
            let consignment_bytes = if consignment.is_empty() {
                vec![]
            } else {
                hex::decode(&consignment).map_err(|e| format!("Invalid hex consignment: {e}"))?
            };
            let consignment_hash = if consignment_bytes.is_empty() {
                vec![]
            } else {
                use sha3::{Digest, Keccak256};
                Keccak256::digest(&consignment_bytes).to_vec()
            };
            let tx_hash = if evm_tx_hash.is_empty() {
                vec![]
            } else {
                hex::decode(&evm_tx_hash).map_err(|e| format!("Invalid hex evm_tx_hash: {e}"))?
            };
            let funds_in_operation_id = hex::decode(
                evm_funds_in_operation_id
                    .strip_prefix("0x")
                    .unwrap_or(&evm_funds_in_operation_id),
            )
            .map_err(|e| format!("Invalid hex evm_funds_in_operation_id: {e}"))?;
            if funds_in_operation_id.len() != 32 {
                return Err(format!(
                    "--evm-funds-in-operation-id must be 32 bytes (BridgeFundsIn operationId), got {}",
                    funds_in_operation_id.len()
                ));
            }
            let req = SignPsbtRequest {
                evm_tx_hash: tx_hash,
                evm_funds_in_operation_id: funds_in_operation_id,
                operation_idx: 0,
                evm_event_valid,
                evm_event_finalized,
                evm_token: vec![],
                evm_amount,
                evm_recipient: vec![],
                evm_commission,
                psbt_bytes,
                psbt_output_amount,
                rgb_asset_id,
                consignment: consignment_bytes,
                consignment_hash,
            };
            let r = client.sign_psbt(req).map_err(|e| format!("Error: {e}"))?;
            println!("Signed PSBT: {}", hex::encode(&r.signed_psbt));
            println!("Inputs signed: {}", r.inputs_signed);
        }
        Command::GetLastSavedBlock => {
            let r = client
                .get_last_saved_block()
                .map_err(|e| format!("Error: {e}"))?;
            println!("Block height: {}", r.block_height);
            println!("Block hash:   {}", hex::encode(&r.block_hash));
        }
        Command::SubmitHeaders {
            start_height,
            headers_file,
        } => {
            let headers = read_headers_file(&headers_file)
                .map_err(|e| format!("Error reading {}: {e}", headers_file.display()))?;
            let r = client
                .submit_headers(start_height, headers)
                .map_err(|e| format!("Error: {e}"))?;
            println!("Last block height: {}", r.last_block_height);
            println!("Last block hash:   {}", hex::encode(&r.last_block_hash));
            println!("Headers accepted:  {}", r.headers_accepted);
        }
        Command::Clone {
            cloning_secret,
            donor_grpc,
            donor_evm,
        } => {
            run_clone(&client, &cloning_secret, &donor_grpc, &donor_evm)
                .map_err(|e| format!("Error: {e}"))?;
        }
        Command::Interactive => run_interactive(&client),
    }
    Ok(())
}

/// Drive the donor->requester cloning handshake. `client` targets the local
/// (requester) enclave over vsock; the donor enclave is reached through its
/// parent-adapter gRPC endpoint over TCP (cross-host within the VPC).
fn run_clone(
    client: &EnclaveClient,
    cloning_secret: &str,
    donor_grpc: &str,
    donor_evm: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use utexo_bridge_parent::grpc_proto::parent_service_client::ParentServiceClient;
    use utexo_bridge_parent::grpc_proto::CloneRequest;

    let donor_addr = hex::decode(donor_evm.trim_start_matches("0x"))?;
    if donor_addr.len() != 20 {
        return Err(format!(
            "donor_evm must be a 20-byte address, got {} bytes",
            donor_addr.len()
        )
        .into());
    }

    println!("[1/4] InitiateCloning on local enclave...");
    let init = client.initiate_cloning(cloning_secret, donor_addr.clone())?;
    println!(
        "      encryption_pubkey: {}",
        hex::encode(&init.encryption_pubkey)
    );

    println!("[2/4] Clone via donor parent gRPC at {donor_grpc} ...");
    let rt = tokio::runtime::Runtime::new()?;
    let clone_resp = rt.block_on(async {
        let mut grpc = ParentServiceClient::connect(donor_grpc.to_string()).await?;
        let req = CloneRequest {
            attestation: init.requester_attestation,
            encryption_pubkey: init.encryption_pubkey,
            cluster_public_key: donor_addr.clone(),
            cloning_digest: init.cloning_digest,
        };
        // Disambiguate the generated RPC `clone(&mut self, req)` from
        // `Clone::clone(&self)`: autoref tries `&self` before `&mut self`, so
        // `grpc.clone(req)` would wrongly resolve to the derive. Call the
        // inherent method via path syntax (inherent wins over the trait).
        let resp = ParentServiceClient::clone(&mut grpc, req).await?;
        Ok::<_, Box<dyn std::error::Error>>(resp.into_inner())
    })?;
    println!(
        "      donor_pubkey: {}",
        hex::encode(&clone_resp.donor_pubkey)
    );

    println!("[3/4] SetClone on local enclave...");
    client.set_clone(
        clone_resp.encrypted_seed,
        clone_resp.donor_pubkey,
        clone_resp.donor_attestation,
    )?;

    println!("[4/4] Verifying cloned identity...");
    let keys = client.get_public_keys()?;
    let local_evm = hex::encode(&keys.evm_address);
    let want_evm = hex::encode(&donor_addr);
    print_keys_response(&keys);
    if local_evm == want_evm {
        println!("\nOK: cloned EVM address matches donor (0x{local_evm})");
        Ok(())
    } else {
        Err(format!("clone mismatch: local EVM 0x{local_evm} != donor 0x{want_evm}").into())
    }
}

/// Parse a headers file: one hex-encoded 80-byte header per line, blank lines
/// and `#` comments ignored. Wrong-length lines are surfaced as errors so
/// silent corruption can't sneak in.
fn read_headers_file(path: &std::path::Path) -> std::io::Result<Vec<Vec<u8>>> {
    let contents = std::fs::read_to_string(path)?;
    let mut headers = Vec::new();
    for (lineno, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bytes = hex::decode(line).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("line {}: invalid hex: {}", lineno + 1, e),
            )
        })?;
        // Don't enforce 80 bytes here - the enclave will reject on parse.
        // Keeping the CLI permissive lets us deliberately send malformed
        // headers in smoke tests.
        headers.push(bytes);
    }
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- headers file --------------------------------------------------------

    fn temp_file(name: &str, contents: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("utexo-cli-test-{}-{name}", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn read_headers_file_skips_blanks_and_comments_and_keeps_order() {
        let path = temp_file(
            "ok.txt",
            &format!(
                "# leading comment\n\n  {}  \n{}\n# trailing\n",
                "ab".repeat(80),
                "cd".repeat(3)
            ),
        );
        let headers = read_headers_file(&path).unwrap();
        std::fs::remove_file(&path).ok();
        // Lengths are not enforced here: the enclave rejects on parse.
        assert_eq!(headers, vec![vec![0xab; 80], vec![0xcd; 3]]);
    }

    #[test]
    fn read_headers_file_reports_the_line_of_invalid_hex() {
        let path = temp_file("bad.txt", "aabb\n# c\n\nzz\n");
        let err = read_headers_file(&path).unwrap_err();
        std::fs::remove_file(&path).ok();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().starts_with("line 4: invalid hex"), "{err}");
    }

    #[test]
    fn read_headers_file_empty_and_missing() {
        let path = temp_file("empty.txt", "\n# nothing\n");
        assert!(read_headers_file(&path).unwrap().is_empty());
        std::fs::remove_file(&path).ok();
        let err = read_headers_file(std::path::Path::new("/nonexistent/headers.txt")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn printers_handle_configured_and_unconfigured_bridges() {
        print_bridge_config(0, &[0u8; 20], "");
        print_bridge_config(1, &[0u8; 20], "");
        print_bridge_config(0, &[1u8; 20], "");
        print_bridge_config(0, &[0u8; 20], "rgb:x");
        print_init_response(&InitializeKeyResponse::default());
        print_keys_response(&PublicKeysResponse::default());
    }

    // ---- run_clone against two real enclaves ---------------------------------

    /// The enclaves are reached over TCP, which a vsock build refuses.
    #[cfg(not(all(feature = "vsock", target_os = "linux")))]
    mod clone_flow {
        use super::*;
        use std::net::TcpListener;
        use std::sync::Arc;

        use utexo_bridge_enclave::config::BridgeConfig;
        use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
        use utexo_bridge_enclave::server::{self as enclave_server, ServerContext};
        use utexo_bridge_enclave::state::EnclaveState;
        use utexo_bridge_parent::grpc_proto::parent_service_server::ParentServiceServer;
        use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};

        /// A fresh, uninitialised real enclave. Returns its TCP address.
        fn start_enclave() -> String {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let ctx = Arc::new(ServerContext::new(
                EnclaveState::new(bitcoin::Network::Bitcoin),
                BridgeConfig::from_env(),
                std::sync::Mutex::new(HeaderChain::new(
                    Network::Regtest,
                    checkpoint_for(Network::Regtest),
                )),
            ));
            std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    enclave_server::handle_connection(stream, &ctx);
                }
            });
            addr.to_string()
        }

        /// The donor's parent gRPC, on its own runtime thread (`run_clone`
        /// builds a runtime of its own, so the test must not be async).
        fn start_donor_grpc(enclave_addr: &str) -> String {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            drop(listener);
            let enclave_addr = enclave_addr.to_string();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async move {
                    let service = ParentAdapterService::new(
                        EnclaveTarget::Tcp(enclave_addr),
                        Default::default(),
                    );
                    tonic::transport::Server::builder()
                        .add_service(ParentServiceServer::new(service))
                        .serve(addr)
                        .await
                        .unwrap();
                });
            });
            for _ in 0..100 {
                if std::net::TcpStream::connect(addr).is_ok() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            format!("http://{addr}")
        }

        /// A donor enclave initialised with `secret`, behind its parent gRPC.
        /// Returns `(donor_grpc_url, donor_evm_hex)`.
        fn donor(secret: &str) -> (String, String) {
            let enclave = start_enclave();
            let init = EnclaveClient::new(&enclave)
                .initialize_keys_with_secret(None, Some(secret.into()))
                .expect("donor initialises with its cloning secret");
            (
                start_donor_grpc(&enclave),
                format!("0x{}", hex::encode(&init.evm_address)),
            )
        }

        #[test]
        fn a_requester_clones_the_donor_identity_end_to_end() {
            let (donor_grpc, donor_evm) = donor("operator");
            let requester = EnclaveClient::new(&start_enclave());

            run_clone(&requester, "operator", &donor_grpc, &donor_evm)
                .expect("full clone handshake succeeds");

            let keys = requester.get_public_keys().unwrap();
            assert_eq!(format!("0x{}", hex::encode(&keys.evm_address)), donor_evm);
        }

        #[test]
        fn a_wrong_secret_is_refused_by_the_donor() {
            let (donor_grpc, donor_evm) = donor("operator");
            let requester = EnclaveClient::new(&start_enclave());
            let err = run_clone(&requester, "not-the-secret", &donor_grpc, &donor_evm)
                .expect_err("donor must refuse a digest under the wrong secret");
            assert!(err.to_string().contains("enclave error"), "{err}");
            // The requester is left in the Cloning phase, not Active.
            assert!(requester.get_public_keys().is_err());
        }

        #[test]
        fn a_donor_address_that_is_not_the_donors_is_refused() {
            let (donor_grpc, _donor_evm) = donor("operator");
            let requester = EnclaveClient::new(&start_enclave());
            let other = format!("0x{}", "42".repeat(20));
            let err = run_clone(&requester, "operator", &donor_grpc, &other)
                .expect_err("donor must refuse a request addressed to another enclave");
            assert!(err.to_string().contains("enclave error"), "{err}");
        }

        #[test]
        fn malformed_donor_addresses_are_rejected_before_any_connection() {
            // Nothing listens here: reaching the enclave would fail differently.
            let requester = EnclaveClient::new("127.0.0.1:1");
            let err = run_clone(&requester, "s", "http://127.0.0.1:1", "0x1234").unwrap_err();
            assert!(
                err.to_string()
                    .contains("must be a 20-byte address, got 2 bytes"),
                "{err}"
            );
            let err = run_clone(&requester, "s", "http://127.0.0.1:1", "zz").unwrap_err();
            assert!(!err.to_string().contains("20-byte"), "{err}");
        }

        #[test]
        fn an_unreachable_requester_or_donor_fails_the_handshake() {
            let donor_evm = format!("0x{}", "42".repeat(20));
            let err = run_clone(
                &EnclaveClient::new("127.0.0.1:1"),
                "s",
                "http://127.0.0.1:1",
                &donor_evm,
            )
            .unwrap_err();
            assert!(err.to_string().contains("connection failed"), "{err}");

            let requester = EnclaveClient::new(&start_enclave());
            let err = run_clone(&requester, "s", "http://127.0.0.1:1", &donor_evm)
                .expect_err("dead donor gRPC");
            assert!(!err.to_string().is_empty());
        }
    }

    /// Every subcommand through `run`, against a real enclave.
    #[cfg(not(all(feature = "vsock", target_os = "linux")))]
    mod dispatch {
        use super::*;
        use std::net::TcpListener;
        use std::sync::Arc;

        use utexo_bridge_enclave::config::BridgeConfig;
        use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
        use utexo_bridge_enclave::server::{self as enclave_server, ServerContext};
        use utexo_bridge_enclave::state::EnclaveState;

        const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon \
                                abandon abandon abandon abandon about";

        fn start_enclave() -> String {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let ctx = Arc::new(ServerContext::new(
                EnclaveState::new(bitcoin::Network::Bitcoin),
                BridgeConfig::from_env(),
                std::sync::Mutex::new(HeaderChain::new(
                    Network::Regtest,
                    checkpoint_for(Network::Regtest),
                )),
            ));
            std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    enclave_server::handle_connection(stream, &ctx);
                }
            });
            addr.to_string()
        }

        fn cli(addr: &str, args: &[&str]) -> Cli {
            let mut all = vec!["utexo-bridge-parent-cli", "--addr", addr];
            all.extend_from_slice(args);
            Cli::try_parse_from(all).expect("valid arguments")
        }

        fn run_err(addr: &str, args: &[&str]) -> String {
            run(cli(addr, args)).expect_err("expected an error")
        }

        #[test]
        fn init_variants_get_keys_and_reinit_refusal() {
            let addr = start_enclave();
            run_err(&addr, &["get-keys"]);
            run(cli(&addr, &["init-mnemonic", MNEMONIC])).unwrap();
            run(cli(&addr, &["get-keys"])).unwrap();
            assert!(run_err(&addr, &["init"]).starts_with("Error: "));
            assert!(run_err(&addr, &["init", "--cloning-secret", "s"]).starts_with("Error: "));

            let addr = start_enclave();
            run(cli(&addr, &["init-seed", &"5c".repeat(64)])).unwrap();
            let addr = start_enclave();
            run(cli(&addr, &["init"])).unwrap();
            let addr = start_enclave();
            run(cli(&addr, &["init", "--cloning-secret", "operator"])).unwrap();
        }

        #[test]
        fn init_seed_rejects_bad_hex_before_connecting() {
            let msg = run_err("127.0.0.1:1", &["init-seed", "zz"]);
            assert!(msg.starts_with("Invalid hex: "), "{msg}");
        }

        #[test]
        fn unreachable_enclave_is_reported_for_each_command() {
            for args in [
                vec!["init"],
                vec!["init-mnemonic", MNEMONIC],
                vec!["get-keys"],
                vec!["get-last-saved-block"],
                vec![
                    "sign-evm",
                    "--call-data",
                    "aa",
                    "--nonce",
                    "1",
                    "--deadline",
                    "1",
                ],
            ] {
                let msg = run_err("127.0.0.1:1", &args);
                assert!(
                    msg.starts_with("Error: connection failed"),
                    "{args:?}: {msg}"
                );
            }
        }

        #[test]
        fn sign_evm_validates_hex_then_lets_the_enclave_refuse() {
            let addr = start_enclave();
            run(cli(&addr, &["init-mnemonic", MNEMONIC])).unwrap();
            let base = ["sign-evm", "--nonce", "1", "--deadline", "1"];
            let mut a = base.to_vec();
            a.extend(["--call-data", "zz"]);
            assert!(run_err(&addr, &a).starts_with("Invalid hex call_data"));
            let mut a = base.to_vec();
            a.extend(["--call-data", "aa", "--proxy-contract", "zz"]);
            assert!(run_err(&addr, &a).starts_with("Invalid hex proxy_contract"));
            let mut a = base.to_vec();
            a.extend(["--call-data", "aa", "--consignment-valid"]);
            assert!(run_err(&addr, &a).starts_with("Error: enclave returned error"));
        }

        #[test]
        fn sign_psbt_validates_every_hex_field_then_lets_the_enclave_refuse() {
            let addr = start_enclave();
            run(cli(&addr, &["init-mnemonic", MNEMONIC])).unwrap();
            let opid = "0x".to_string() + &"33".repeat(32);
            assert!(run_err(&addr, &["sign-psbt", "--psbt", "zz"]).starts_with("Invalid hex PSBT"));
            assert!(
                run_err(&addr, &["sign-psbt", "--psbt", "aa", "--consignment", "zz"])
                    .starts_with("Invalid hex consignment")
            );
            assert!(
                run_err(&addr, &["sign-psbt", "--psbt", "aa", "--evm-tx-hash", "zz"])
                    .starts_with("Invalid hex evm_tx_hash")
            );
            assert!(run_err(
                &addr,
                &[
                    "sign-psbt",
                    "--psbt",
                    "aa",
                    "--evm-funds-in-operation-id",
                    "zz"
                ]
            )
            .starts_with("Invalid hex evm_funds_in_operation_id"));
            let msg = run_err(
                &addr,
                &[
                    "sign-psbt",
                    "--psbt",
                    "aa",
                    "--evm-funds-in-operation-id",
                    "0x1234",
                ],
            );
            assert!(
                msg.contains("must be 32 bytes") && msg.contains("got 2"),
                "{msg}"
            );
            let msg = run_err(
                &addr,
                &[
                    "sign-psbt",
                    "--psbt",
                    "aa",
                    "--evm-funds-in-operation-id",
                    &opid,
                    "--evm-tx-hash",
                    &"11".repeat(32),
                    "--consignment",
                    "c0c0",
                ],
            );
            assert!(msg.starts_with("Error: enclave returned error"), "{msg}");
        }

        #[test]
        fn header_chain_commands_talk_to_the_real_chain() {
            let addr = start_enclave();
            run(cli(&addr, &["get-last-saved-block"])).unwrap();

            let msg = run_err(
                &addr,
                &[
                    "submit-headers",
                    "--start-height",
                    "1",
                    "--headers-file",
                    "/nonexistent/h",
                ],
            );
            assert!(msg.starts_with("Error reading /nonexistent/h"), "{msg}");

            let empty = temp_file("empty-headers.txt", "# none\n");
            run(cli(
                &addr,
                &[
                    "submit-headers",
                    "--start-height",
                    "1",
                    "--headers-file",
                    empty.to_str().unwrap(),
                ],
            ))
            .unwrap();
            std::fs::remove_file(&empty).ok();

            let bad = temp_file("bad-headers.txt", &format!("{}\n", "00".repeat(80)));
            let msg = run_err(
                &addr,
                &[
                    "submit-headers",
                    "--start-height",
                    "1",
                    "--headers-file",
                    bad.to_str().unwrap(),
                ],
            );
            std::fs::remove_file(&bad).ok();
            assert!(msg.starts_with("Error: enclave returned error"), "{msg}");
        }

        #[test]
        fn clone_command_reports_handshake_failures() {
            let msg = run_err(
                "127.0.0.1:1",
                &[
                    "clone",
                    "--cloning-secret",
                    "s",
                    "--donor-grpc",
                    "http://127.0.0.1:1",
                    "--donor-evm",
                    "0x1234",
                ],
            );
            assert!(msg.contains("must be a 20-byte address"), "{msg}");
        }

        #[test]
        fn the_repl_runs_every_command_and_stops_on_quit_or_eof() {
            let addr = start_enclave();
            let client = EnclaveClient::new(&addr);
            let script = format!(
                "help\n\nbogus\ninit-seed\ninit-seed zz\nget-keys\ninit-mnemonic\n\
                 init-mnemonic {MNEMONIC}\nget-keys\ninit\ninit-seed {}\nquit\nget-keys\n",
                "5c".repeat(64)
            );
            let mut out = Vec::new();
            run_interactive_io(&client, &mut script.as_bytes(), &mut out);
            let out = String::from_utf8(out).unwrap();
            assert!(out.contains("Commands: init"), "{out}");
            // Twelve prompts: one per line up to and including `quit`.
            assert_eq!(out.matches("enclave> ").count(), 12, "{out}");

            // EOF without quit also ends the loop.
            let mut out = Vec::new();
            run_interactive_io(&client, &mut "exit\n".as_bytes(), &mut out);
            run_interactive_io(&client, &mut "".as_bytes(), &mut out);
            assert_eq!(
                String::from_utf8(out).unwrap().matches("enclave> ").count(),
                2
            );
        }

        #[test]
        fn main_style_exit_path_formats_the_error() {
            let err = run(cli("127.0.0.1:1", &["get-keys"])).unwrap_err();
            assert!(err.starts_with("Error: "));
        }
    }
}
