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
        /// DEPRECATED on the command line: visible in `ps` / shell history / SSM
        /// logs (F03-AF-06). Prefer --cloning-secret-file or UTEXO_CLONING_SECRET.
        #[arg(long)]
        cloning_secret: Option<String>,
        /// Read the cloning secret from this file instead of argv (F03-AF-06).
        /// Takes precedence over UTEXO_CLONING_SECRET and --cloning-secret.
        #[arg(long)]
        cloning_secret_file: Option<PathBuf>,
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
        /// DEPRECATED on the command line: visible in `ps` / shell history / SSM
        /// logs (F03-AF-06). Prefer --cloning-secret-file or UTEXO_CLONING_SECRET.
        #[arg(long)]
        cloning_secret: Option<String>,
        /// Read the cloning secret from this file instead of argv (F03-AF-06).
        /// Takes precedence over UTEXO_CLONING_SECRET and --cloning-secret.
        #[arg(long)]
        cloning_secret_file: Option<PathBuf>,
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
    loop {
        print!("enclave> ");
        io::stdout().flush().unwrap();

        let mut line = String::new();
        if stdin.lock().read_line(&mut line).unwrap_or(0) == 0 {
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
                println!("Commands: init, init-seed <hex>, init-mnemonic <words>, get-keys, help, quit, exit");
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

    let cli = Cli::parse();
    let client = EnclaveClient::new(&cli.addr);

    match cli.command {
        Command::Init {
            cloning_secret,
            cloning_secret_file,
        } => {
            let cloning_secret = match resolve_cloning_secret(cloning_secret, cloning_secret_file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            };
            match client.initialize_keys_with_secret(None, cloning_secret) {
                Ok(r) => print_init_response(&r),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            }
        }
        Command::InitSeed { hex: hex_str } => match hex::decode(&hex_str) {
            Ok(seed) => match client.initialize_keys(Some(seed)) {
                Ok(r) => print_init_response(&r),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("Invalid hex: {}", e);
                process::exit(1);
            }
        },
        Command::InitMnemonic { words } => match client.initialize_keys_mnemonic(&words) {
            Ok(r) => print_init_response(&r),
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        },
        Command::GetKeys => match client.get_public_keys() {
            Ok(r) => print_keys_response(&r),
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        },
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
            let data = match hex::decode(&call_data) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Invalid hex call_data: {}", e);
                    process::exit(1);
                }
            };
            let proxy = match hex::decode(&proxy_contract) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Invalid hex proxy_contract: {}", e);
                    process::exit(1);
                }
            };
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
            match client.sign_evm(req) {
                Ok(r) => {
                    println!("EVM signature (65 bytes): {}", hex::encode(&r.signature));
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            }
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
            let psbt_bytes = match hex::decode(&psbt) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Invalid hex PSBT: {}", e);
                    process::exit(1);
                }
            };
            let consignment_bytes = if consignment.is_empty() {
                vec![]
            } else {
                match hex::decode(&consignment) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("Invalid hex consignment: {}", e);
                        process::exit(1);
                    }
                }
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
                match hex::decode(&evm_tx_hash) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("Invalid hex evm_tx_hash: {}", e);
                        process::exit(1);
                    }
                }
            };
            let funds_in_operation_id = match hex::decode(
                evm_funds_in_operation_id
                    .strip_prefix("0x")
                    .unwrap_or(&evm_funds_in_operation_id),
            ) {
                Ok(d) if d.len() == 32 => d,
                Ok(d) => {
                    eprintln!(
                        "--evm-funds-in-operation-id must be 32 bytes (BridgeFundsIn operationId), got {}",
                        d.len()
                    );
                    process::exit(1);
                }
                Err(e) => {
                    eprintln!("Invalid hex evm_funds_in_operation_id: {}", e);
                    process::exit(1);
                }
            };
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
            match client.sign_psbt(req) {
                Ok(r) => {
                    println!("Signed PSBT: {}", hex::encode(&r.signed_psbt));
                    println!("Inputs signed: {}", r.inputs_signed);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            }
        }
        Command::GetLastSavedBlock => match client.get_last_saved_block() {
            Ok(r) => {
                println!("Block height: {}", r.block_height);
                println!("Block hash:   {}", hex::encode(&r.block_hash));
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        },
        Command::SubmitHeaders {
            start_height,
            headers_file,
        } => {
            let headers = match read_headers_file(&headers_file) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("Error reading {}: {}", headers_file.display(), e);
                    process::exit(1);
                }
            };
            match client.submit_headers(start_height, headers) {
                Ok(r) => {
                    println!("Last block height: {}", r.last_block_height);
                    println!("Last block hash:   {}", hex::encode(&r.last_block_hash));
                    println!("Headers accepted:  {}", r.headers_accepted);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            }
        }
        Command::Clone {
            cloning_secret,
            cloning_secret_file,
            donor_grpc,
            donor_evm,
        } => {
            let secret = match resolve_cloning_secret(cloning_secret, cloning_secret_file) {
                Ok(Some(s)) => s,
                Ok(None) => {
                    eprintln!(
                        "Error: a cloning secret is required for clone — pass \
                         --cloning-secret-file, set UTEXO_CLONING_SECRET, or (deprecated) \
                         --cloning-secret"
                    );
                    process::exit(1);
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            };
            if let Err(e) = run_clone(&client, &secret, &donor_grpc, &donor_evm) {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        }
        Command::Interactive => run_interactive(&client),
    }
}

/// Resolve the operator cloning secret WITHOUT forcing it onto the command line
/// (F03-AF-06). A `--cloning-secret <value>` arg is visible in `ps`, shell
/// history and SSM command logs, so the secret can be observed by any host-level
/// viewer and reused to authorize another requester. Priority (most to least
/// preferred): `--cloning-secret-file` > `UTEXO_CLONING_SECRET` env >
/// `--cloning-secret` (deprecated; warns). Returns `Ok(None)` only when every
/// source is absent, which is valid for `init` on a non-donor enclave.
fn resolve_cloning_secret(
    arg: Option<String>,
    file: Option<PathBuf>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if let Some(path) = file {
        let raw = std::fs::read_to_string(&path).map_err(|e| {
            format!(
                "failed to read --cloning-secret-file {}: {e}",
                path.display()
            )
        })?;
        let s = raw.trim().to_string();
        if s.is_empty() {
            return Err(format!("--cloning-secret-file {} is empty", path.display()).into());
        }
        return Ok(Some(s));
    }
    if let Ok(env_val) = std::env::var("UTEXO_CLONING_SECRET") {
        let s = env_val.trim().to_string();
        if !s.is_empty() {
            return Ok(Some(s));
        }
    }
    if let Some(s) = arg {
        eprintln!(
            "WARNING: --cloning-secret on the command line is visible in `ps`, shell history \
             and SSM logs (F03-AF-06); prefer --cloning-secret-file or the UTEXO_CLONING_SECRET \
             env var."
        );
        return Ok(Some(s));
    }
    Ok(None)
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
    use rand::RngCore;
    use utexo_bridge_parent::grpc_proto::parent_service_client::ParentServiceClient;
    use utexo_bridge_parent::grpc_proto::{AttestedPublicKeyRequest, CloneRequest};

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
    // Bound the cross-host donor stage end-to-end. The vsock legs (steps
    // 1/3/4) are already bounded by the enclave client's connect/read
    // timeouts; without matching limits here a donor that accepts the TCP
    // connection but never answers hangs the whole clone forever (F03-AF-19).
    const DONOR_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    const DONOR_RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
    let rt = tokio::runtime::Runtime::new()?;
    let clone_resp = rt.block_on(async {
        let endpoint = tonic::transport::Endpoint::from_shared(donor_grpc.to_string())?
            .connect_timeout(DONOR_CONNECT_TIMEOUT)
            .timeout(DONOR_RPC_TIMEOUT);
        let mut grpc = ParentServiceClient::new(endpoint.connect().await?);
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
    // F03-AF-05: SetClone may commit the requester to Active and only then have
    // its response lost/undecodable in transit. A bare `?` here would exit the
    // CLI with a hard error even though the expected identity is already
    // installed, misleading operators/automation into a needless "recovery".
    // On error we reconcile read-only: query the requester's identity ONCE (no
    // blind SetClone retry) and let the normal verification below decide. Only a
    // requester that is NOT Active (or is Active with the WRONG identity) is a
    // real failure.
    if let Err(set_err) = client.set_clone(
        clone_resp.encrypted_seed,
        clone_resp.donor_pubkey,
        clone_resp.donor_attestation,
    ) {
        eprintln!("[3/4] SetClone returned an error: {set_err}");
        eprintln!("      reconciling (read-only get-keys, no SetClone retry)...");
        match client.get_public_keys() {
            Ok(k) => {
                let got = hex::encode(&k.evm_address);
                let want = hex::encode(&donor_addr);
                if got == want {
                    eprintln!(
                        "      RECOVERED: requester is Active with the expected EVM 0x{got} \
                         despite the SetClone transport error — continuing to full verification."
                    );
                    // fall through: the verification below re-queries and runs
                    // the same 13-field donor cross-check as the happy path.
                } else {
                    return Err(format!(
                        "SetClone failed ({set_err}); requester IS Active but with identity \
                         0x{got}, not the expected donor 0x{want} — DO NOT trust this clone"
                    )
                    .into());
                }
            }
            Err(get_err) => {
                return Err(format!(
                    "SetClone failed ({set_err}); requester is not initialized \
                     (get-keys: {get_err}) — clone did not complete (still Cloning/Initial), \
                     no identity installed"
                )
                .into());
            }
        }
    }

    println!("[4/5] Verifying cloned identity (local)...");
    let keys = client.get_public_keys()?;
    let local_evm = hex::encode(&keys.evm_address);
    let want_evm = hex::encode(&donor_addr);
    print_keys_response(&keys);
    if local_evm != want_evm {
        return Err(
            format!("clone mismatch: local EVM 0x{local_evm} != donor 0x{want_evm}").into(),
        );
    }
    println!("      local EVM matches --donor-evm (0x{local_evm})");

    // F03-AF-08: completion + the EVM check above only assert the primary EVM
    // address. The same seed under a different baked Bitcoin/config could share
    // that address while other derived fields differ. Same-PCR clones cannot
    // diverge (identical baked config), but the CLI is the operator's
    // independent gate, so cross-check ALL 13 identity/config fields against the
    // donor's own reported bundle rather than trusting a single field.
    println!("[5/5] Cross-checking full identity bundle against the donor...");
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let donor_bundle = rt.block_on(async {
        let endpoint = tonic::transport::Endpoint::from_shared(donor_grpc.to_string())?
            .connect_timeout(DONOR_CONNECT_TIMEOUT)
            .timeout(DONOR_RPC_TIMEOUT);
        let mut grpc = ParentServiceClient::new(endpoint.connect().await?);
        let resp = grpc
            .attested_public_key(AttestedPublicKeyRequest {
                nonce: nonce.to_vec(),
            })
            .await?;
        Ok::<_, Box<dyn std::error::Error>>(resp.into_inner())
    })?;

    let mismatches = identity_field_mismatches(&keys, &donor_bundle);
    if mismatches.is_empty() {
        println!("\nOK: cloned identity matches the donor on all 13 fields (EVM 0x{local_evm})");
        Ok(())
    } else {
        Err(format!(
            "clone identity mismatch on {} of 13 field(s): {} - the requester derived a \
             DIFFERENT identity/config than the donor despite a matching EVM address",
            mismatches.len(),
            mismatches.join(", ")
        )
        .into())
    }
}

/// Compare the local (requester) key bundle against the donor's reported bundle
/// across all 13 identity/config fields (F03-AF-08). Returns the names of the
/// fields that differ; an empty result means byte-identical identities. The
/// donor bundle rides the authenticated clone endpoint, so this is an equality
/// check on the reported values, complementing the EVM-only assertion.
fn identity_field_mismatches(
    local: &PublicKeysResponse,
    donor: &utexo_bridge_parent::grpc_proto::AttestedPublicKeyResponse,
) -> Vec<&'static str> {
    let mut diff = Vec::new();
    if local.evm_address != donor.evm_address {
        diff.push("evm_address");
    }
    if local.evm_uncompressed_pub != donor.evm_uncompressed_pub {
        diff.push("evm_uncompressed_pub");
    }
    if local.btc_compressed_pub != donor.btc_compressed_pub {
        diff.push("btc_compressed_pub");
    }
    if local.btc_xpub != donor.btc_xpub {
        diff.push("btc_xpub");
    }
    if local.master_fingerprint != donor.master_fingerprint {
        diff.push("master_fingerprint");
    }
    if local.account_xpub_vanilla != donor.account_xpub_vanilla {
        diff.push("account_xpub_vanilla");
    }
    if local.account_xpub_colored != donor.account_xpub_colored {
        diff.push("account_xpub_colored");
    }
    if local.chain_id != donor.chain_id {
        diff.push("chain_id");
    }
    if local.bridge_contract != donor.bridge_contract {
        diff.push("bridge_contract");
    }
    if local.rgb_asset_id != donor.rgb_asset_id {
        diff.push("rgb_asset_id");
    }
    if local.evm_gas_tx_uncompressed_pub != donor.evm_gas_tx_uncompressed_pub {
        diff.push("evm_gas_tx_uncompressed_pub");
    }
    if local.evm_gas_tx_address != donor.evm_gas_tx_address {
        diff.push("evm_gas_tx_address");
    }
    if local.ccd_ed25519_pub != donor.ccd_ed25519_pub {
        diff.push("ccd_ed25519_pub");
    }
    diff
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
