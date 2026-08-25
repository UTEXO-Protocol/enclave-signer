//! `attest-verify` - externally verify that the bridge signing pubkey
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
//!     0 - verification succeeded
//!     1 - verification failed (output explains why)
//!     2 - usage / IO / connection error

use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use attestation_verify::EvmDataSource;
use utexo_bridge_parent::attest_verify::{
    verify_attested_pubkey, AttestedPubkeyResult, ExpectedPolicy, VerifyMode,
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
    /// Implies the expected security policy is `Development`.
    #[arg(long)]
    mock: bool,

    /// Expect the enclave to enable the plain-BTC (vanilla / create_utxo)
    /// signing path. Default: expect it DISABLED (fail-closed). Ignored with
    /// --mock. This posture is committed into attestation user_data.
    #[arg(long)]
    expect_vanilla_psbt: bool,

    /// Expected EVM `FundsIn` deposit-verification data source the enclave must
    /// have committed to: `raw` (host-relayed RPC), `helios` (trustless,
    /// checkpoint-verified), or `disabled`. Defaults to `raw` - the source the
    /// shipped image uses. Pass `helios` to require the trustless path and fail
    /// verification if the enclave is only on raw RPC. Ignored with --mock.
    #[arg(long, default_value = "raw")]
    expect_evm_source: String,

    /// Expected Helios weak-subjectivity checkpoint (0x-prefixed 32-byte beacon
    /// block root) the enclave must have trust-rooted on. REQUIRED when
    /// `--expect-evm-source helios`: the verifier reconstructs the committed
    /// posture with this value, so an enclave that synced from a different
    /// checkpoint fails the `user_data` hash. Ignored otherwise.
    #[arg(long)]
    expect_helios_checkpoint: Option<String>,

    /// Expected gas-tx (`SignRawDigest`) allowed destination the enclave pinned
    /// (`GAS_TX_ALLOWED_TO`), as 0x-hex. Omit if the operator left the gas path
    /// unpinned (the enclave then commits the all-zero destination and fails the
    /// path closed). Ignored with --mock.
    #[arg(long)]
    expect_gas_tx_to: Option<String>,

    /// Expected gas-tx `gasLimit` ceiling (`GAS_TX_MAX_GAS_LIMIT`). Default 0
    /// (unpinned). Ignored with --mock.
    #[arg(long, default_value_t = 0)]
    expect_gas_max_gas_limit: u64,

    /// Expected gas-tx per-gas fee ceiling in wei (`GAS_TX_MAX_FEE_PER_GAS`).
    /// Default 0 (unpinned). Ignored with --mock.
    #[arg(long, default_value_t = 0)]
    expect_gas_max_fee_per_gas: u128,

    /// Expected gas-tx native-value ceiling in wei (`GAS_TX_MAX_VALUE_WEI`), the
    /// bound on the payable `lzFundsOutCall` carve-out. Default 0 (unpinned -
    /// the enclave then signs no non-zero value at all). Ignored with --mock.
    #[arg(long, default_value_t = 0)]
    expect_gas_max_value_wei: u128,

    /// Expected gas-tx calldata selector allowlist (`GAS_TX_ALLOWED_SELECTORS`):
    /// comma-separated 4-byte hex selectors. Default empty. Ignored with --mock.
    #[arg(long, default_value = "")]
    expect_gas_selectors: String,
}

/// Parse the `--expect-helios-checkpoint` flag into a 32-byte beacon block root.
fn parse_checkpoint(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s))
        .context("--expect-helios-checkpoint is not valid hex")?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!(
            "--expect-helios-checkpoint must be 32 bytes (a beacon block root), got {}",
            v.len()
        )
    })
}

/// Parse the `--expect-evm-source` flag into an [`EvmDataSource`].
fn parse_evm_source(s: &str) -> Result<EvmDataSource> {
    match s.to_ascii_lowercase().as_str() {
        "raw" | "raw-rpc" | "rawrpc" => Ok(EvmDataSource::RawRpc),
        "helios" | "helios-verified" => Ok(EvmDataSource::HeliosVerified),
        "disabled" | "none" | "off" => Ok(EvmDataSource::Disabled),
        other => anyhow::bail!(
            "invalid --expect-evm-source '{other}' (expected: raw | helios | disabled)"
        ),
    }
}

/// Parse an optional `0x`-hex Ethereum address into 20 bytes; `None` -> all-zero
/// (the "gas path unpinned" commitment).
fn parse_expect_gas_to(s: &Option<String>) -> Result<[u8; 20]> {
    match s {
        None => Ok([0u8; 20]),
        Some(s) => {
            let stripped = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(stripped)
                .with_context(|| format!("--expect-gas-tx-to '{s}' is not hex"))?;
            bytes.try_into().map_err(|v: Vec<u8>| {
                anyhow::anyhow!("--expect-gas-tx-to must be 20 bytes, got {}", v.len())
            })
        }
    }
}

/// Parse `--expect-gas-selectors` (comma-separated 4-byte hex) into selectors.
/// An empty string yields an empty allowlist.
fn parse_expect_gas_selectors(s: &str) -> Result<Vec<[u8; 4]>> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| {
            let stripped = p.strip_prefix("0x").unwrap_or(p);
            let bytes =
                hex::decode(stripped).with_context(|| format!("selector '{p}' is not hex"))?;
            <[u8; 4]>::try_from(bytes.as_slice())
                .map_err(|_| anyhow::anyhow!("selector '{p}' must be exactly 4 bytes"))
        })
        .collect()
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
    let (expected_pcrs, mode, expected_policy) = if cli.mock {
        eprintln!(
            "warning: --mock skips COSE/cert-chain checks; do NOT use against production enclaves"
        );
        (
            attestation_verify::ExpectedPcrs::zero(),
            VerifyMode::Mock,
            // A mock/dev enclave resolves to the Development posture.
            ExpectedPolicy::Development,
        )
    } else {
        let pcr0 = cli.pcr0.context("--pcr0 required (or pass --mock)")?;
        let pcr1 = cli.pcr1.context("--pcr1 required (or pass --mock)")?;
        let pcr2 = cli.pcr2.context("--pcr2 required (or pass --mock)")?;
        let pcrs = attestation_verify::ExpectedPcrs::from_hex(&pcr0, &pcr1, &pcr2)
            .context("invalid PCR hex")?;
        let evm_source = parse_evm_source(&cli.expect_evm_source)?;
        let evm_checkpoint = cli
            .expect_helios_checkpoint
            .as_deref()
            .map(parse_checkpoint)
            .transpose()?;
        // A Helios expectation without a pinned checkpoint could never match a
        // real trustless enclave (which always commits one), so refuse early
        // with a clear message rather than a downstream hash mismatch.
        if evm_source == EvmDataSource::HeliosVerified && evm_checkpoint.is_none() {
            anyhow::bail!(
                "--expect-evm-source helios requires --expect-helios-checkpoint \
                 (the beacon block root the enclave pinned)"
            );
        }
        let expected_policy = ExpectedPolicy::Production {
            allow_vanilla_psbt: cli.expect_vanilla_psbt,
            evm_source,
            evm_checkpoint,
            gas_tx_allowed_to: parse_expect_gas_to(&cli.expect_gas_tx_to)?,
            gas_tx_max_gas_limit: cli.expect_gas_max_gas_limit,
            gas_tx_max_fee_per_gas: cli.expect_gas_max_fee_per_gas,
            gas_tx_max_value_wei: cli.expect_gas_max_value_wei,
            gas_tx_allowed_selectors: parse_expect_gas_selectors(&cli.expect_gas_selectors)?,
        };
        (pcrs, VerifyMode::Real, expected_policy)
    };

    eprintln!("expecting security policy: {expected_policy:?}");
    let result =
        verify_attested_pubkey(&cli.endpoint, expected_pcrs, mode, expected_policy).await?;
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
