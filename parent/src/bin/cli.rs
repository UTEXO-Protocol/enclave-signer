use std::io::{self, BufRead, Write};
use std::process;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use utexo_bridge_parent::client::EnclaveClient;
use utexo_bridge_parent::enclave_proto::{
    InitializeKeyResponse, PublicKeysResponse, SignEvmRequest, SignPsbtRequest,
};

#[derive(Parser)]
#[command(
    name = "utexo-bridge-parent-cli",
    about = "UTEXO Bridge enclave host-side client (CLI tool)"
)]
struct Cli {
    /// Enclave address (TCP)
    #[arg(long, default_value = "127.0.0.1:5000")]
    addr: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize keys (generate new mnemonic in the enclave)
    Init,
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
        /// PSBT total non-change output amount
        #[arg(long, default_value = "0")]
        psbt_output_amount: u64,
        /// Mark EVM event as valid
        #[arg(long)]
        evm_event_valid: bool,
        /// Mark EVM event as finalized
        #[arg(long)]
        evm_event_finalized: bool,
    },
    /// Sign a raw message (fundsIn authorization, 1-of-n)
    SignRawMessage {
        /// Hex-encoded message bytes
        #[arg(long)]
        message: String,
    },
    /// Enter interactive REPL mode
    Interactive,
}

fn print_init_response(r: &InitializeKeyResponse) {
    println!("Keys initialized:");
    println!("  EVM address: 0x{}", hex::encode(&r.evm_address));
    println!("  BTC pubkey:  {}", hex::encode(&r.btc_compressed_pub));
    println!("  BTC xpub:    {}", r.btc_xpub);
}

fn print_keys_response(r: &PublicKeysResponse) {
    println!("  EVM address: 0x{}", hex::encode(&r.evm_address));
    println!("  BTC pubkey:  {}", hex::encode(&r.btc_compressed_pub));
    println!("  BTC xpub:    {}", r.btc_xpub);
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
        Command::Init => match client.initialize_keys(None) {
            Ok(r) => print_init_response(&r),
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        },
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
                consignment: vec![],
                consignment_hash: vec![],
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
            psbt_output_amount,
            evm_event_valid,
            evm_event_finalized,
        } => {
            let psbt_bytes = match hex::decode(&psbt) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Invalid hex PSBT: {}", e);
                    process::exit(1);
                }
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
            let req = SignPsbtRequest {
                evm_tx_hash: tx_hash,
                operation_idx: 0,
                evm_event_valid,
                evm_event_finalized,
                evm_token: vec![],
                evm_amount,
                evm_recipient: vec![],
                evm_commission,
                psbt_bytes,
                psbt_output_amount,
                rgb_asset_id: String::new(),
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
        Command::SignRawMessage { message } => {
            let msg_bytes = match hex::decode(&message) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Invalid hex message: {}", e);
                    process::exit(1);
                }
            };
            match client.sign_raw_message(msg_bytes) {
                Ok(r) => {
                    println!("Signature (65 bytes): {}", hex::encode(&r.signature));
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            }
        }
        Command::Interactive => run_interactive(&client),
    }
}
