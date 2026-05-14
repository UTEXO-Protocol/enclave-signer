//! `attest-verify` — externally verify that the bridge signing pubkey
//! belongs to the running TEE.
//!
//! Issues a fresh nonce, calls the parent's `AttestedPublicKey` gRPC,
//! and runs the AWS Nitro attestation verifier (cert chain + COSE
//! signature + PCR check + nonce equality + bundle commitment).
//!
//! Usage:
//!     attest-verify --endpoint http://127.0.0.1:50051 \
//!         --pcr0 <hex> --pcr1 <hex> --pcr2 <hex>
//!
//! Use `--mock` against an enclave built with `mock-attestation` (PCRs are
//! all zeros and the COSE wrapper is skipped).
//!
//! Exit codes:
//!     0 — verification succeeded
//!     1 — verification failed (output explains why)
//!     2 — usage / IO / connection error

use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use utexo_bridge_parent::attest_verify::{
    verify_attested_pubkey, AttestedPubkeyResult, VerifyMode,
};

#[derive(Parser)]
#[command(
    name = "attest-verify",
    about = "Verify a UTEXO bridge signing pubkey against its TEE attestation"
)]
struct Cli {
    /// Parent gRPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    endpoint: String,

    /// Expected PCR0 (96 hex chars = 48 bytes). Required unless --mock.
    #[arg(long)]
    pcr0: Option<String>,

    /// Expected PCR1 (96 hex chars = 48 bytes). Required unless --mock.
    #[arg(long)]
    pcr1: Option<String>,

    /// Expected PCR2 (96 hex chars = 48 bytes). Required unless --mock.
    #[arg(long)]
    pcr2: Option<String>,

    /// Verify a mock-attestation document (zero PCRs, no COSE wrapping).
    /// For dev/CI only. Real production verification MUST NOT use this flag.
    #[arg(long)]
    mock: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("FAIL: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let (expected_pcrs, mode) = if cli.mock {
        eprintln!(
            "warning: --mock skips COSE/cert-chain checks; do NOT use against production enclaves"
        );
        (attestation_verify::ExpectedPcrs::zero(), VerifyMode::Mock)
    } else {
        let pcr0 = cli.pcr0.context("--pcr0 required (or pass --mock)")?;
        let pcr1 = cli.pcr1.context("--pcr1 required (or pass --mock)")?;
        let pcr2 = cli.pcr2.context("--pcr2 required (or pass --mock)")?;
        let pcrs = attestation_verify::ExpectedPcrs::from_hex(&pcr0, &pcr1, &pcr2)
            .context("invalid PCR hex")?;
        (pcrs, VerifyMode::Real)
    };

    let result = verify_attested_pubkey(&cli.endpoint, expected_pcrs, mode).await?;
    print_ok(&result);
    Ok(())
}

fn print_ok(result: &AttestedPubkeyResult) {
    let r = &result.response;
    let v = &result.verified;
    println!("OK");
    println!(
        "  EVM address           : 0x{}",
        hex::encode(&r.evm_address)
    );
    println!(
        "  EVM uncompressed pub  : 0x{}",
        hex::encode(&r.evm_uncompressed_pub)
    );
    println!(
        "  BTC compressed pub    : 0x{}",
        hex::encode(&r.btc_compressed_pub)
    );
    println!("  BTC xpub              : {}", r.btc_xpub);
    println!(
        "  Master fingerprint    : 0x{}",
        hex::encode(&r.master_fingerprint)
    );
    println!("  Account xpub (vanilla): {}", r.account_xpub_vanilla);
    println!("  Account xpub (colored): {}", r.account_xpub_colored);
    println!(
        "  Bundle commitment     : 0x{}",
        hex::encode(result.bundle_commitment)
    );
    println!(
        "  PCR0                  : 0x{}",
        hex::encode(v.pcrs.get(&0).map(|v| v.as_slice()).unwrap_or(&[]))
    );
    println!(
        "  PCR1                  : 0x{}",
        hex::encode(v.pcrs.get(&1).map(|v| v.as_slice()).unwrap_or(&[]))
    );
    println!(
        "  PCR2                  : 0x{}",
        hex::encode(v.pcrs.get(&2).map(|v| v.as_slice()).unwrap_or(&[]))
    );
    println!("  Attestation timestamp : {}", v.timestamp);
    println!(
        "  Nonce echoed          : 0x{}",
        hex::encode(v.nonce.clone())
    );
}
