use std::io::{self, BufRead, Write};
use std::process;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use utexo_bridge_parent::client::EnclaveClient;
use utexo_bridge_parent::proto::{InitializeKeyResponse, PublicKeysResponse};

#[derive(Parser)]
#[command(
    name = "utexo-bridge-parent",
    about = "UTEXO Bridge enclave host-side client"
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
    },
    /// Sign a PSBT (SegWit v0 P2WSH multisig)
    SignPsbt {
        /// Hex-encoded PSBT bytes
        #[arg(long)]
        psbt: String,
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
            "get-keys" => match client.get_public_keys() {
                Ok(r) => print_keys_response(&r),
                Err(e) => eprintln!("Error: {}", e),
            },
            "help" => {
                println!("Commands: init, init-seed <hex>, get-keys, help, quit, exit");
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
        } => {
            let data = match hex::decode(&call_data) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Invalid hex call_data: {}", e);
                    process::exit(1);
                }
            };
            match client.sign_evm(data, nonce, deadline) {
                Ok(r) => {
                    println!("EVM signature (65 bytes): {}", hex::encode(&r.signature));
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            }
        }
        Command::SignPsbt { psbt } => {
            let psbt_bytes = match hex::decode(&psbt) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Invalid hex PSBT: {}", e);
                    process::exit(1);
                }
            };
            match client.sign_psbt(psbt_bytes) {
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
