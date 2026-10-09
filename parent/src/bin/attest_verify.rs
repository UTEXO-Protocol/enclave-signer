//! `attest-verify`: verify from outside that the bridge signing key belongs
//! to the running TEE.
//!
//! Sends a fresh nonce to the parent `AttestedPublicKey` RPC. Then runs the
//! AWS Nitro attestation verifier: cert chain, COSE signature, PCRs, nonce
//! and bundle commitment.
//!
//! Usage:
//!     attest-verify --endpoint http://127.0.0.1:50051 \
//!         --pcr0 <hex> --pcr1 <hex> --pcr2 <hex>
//!
//! `--from-file <bundle.json>` runs the same checks offline on a bundle that
//! `utexo-bridge-parent-cli export-attestation` wrote. The nonce is the
//! bundle nonce, and the certificates are checked at the document time.
//!
//! Use `--mock` with a `mock-attestation` enclave (zero PCRs, no COSE).
//!
//! Exit codes:
//!     0 - verification succeeded
//!     1 - verification, IO, connection or missing-flag failure (output gives
//!         the reason)
//!     2 - argument parse error

use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use attestation_verify::{
    AttestedPolicy, EvmDataSource, EvmFinalityTag, EvmRpcTlsPin, KmsPin, SignerRole,
};
use utexo_bridge_parent::attest_verify::{
    verify_attested_pubkey, verify_bundle, AttestedPubkeyResult, ExpectedPolicy, VerifyMode,
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

    /// Verify this attestation bundle offline instead of `--endpoint`.
    #[arg(long, conflicts_with = "endpoint")]
    from_file: Option<std::path::PathBuf>,

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
    /// For dev and CI only. Do not use for production verification.
    /// Sets the expected security policy to `Development`.
    #[arg(long)]
    mock: bool,

    /// Expect the plain-BTC (vanilla / create_utxo) signing path to be on.
    /// Default: expect it off. Committed in attestation user_data.
    /// Ignored with --mock.
    #[arg(long)]
    expect_vanilla_psbt: bool,

    /// Expected signer role, committed in attestation user_data: `mint`
    /// (EVM -> RGB only), `burn` (RGB -> EVM only) or `combined` (both
    /// directions). Required for production verification. Ignored with --mock.
    #[arg(long)]
    expect_signer_role: Option<String>,

    /// Expected EVM `FundsIn` data source in the commitment: `tls` (RPC over
    /// pinned TLS, used by the shipped image), `raw` (plaintext, dev only) or
    /// `disabled`. Ignored with --mock.
    #[arg(long, default_value = "tls")]
    expect_evm_source: String,

    /// Expected Electrum host set at launch (the host of `ELECTRUM_URL`).
    /// Required for production verification. Ignored with --mock.
    #[arg(long)]
    expect_electrum_host: Option<String>,

    /// Expected EVM RPC TLS host (`EVM_RPC_HOST`). Required with
    /// `--expect-evm-source tls`. Ignored otherwise.
    #[arg(long)]
    expect_evm_rpc_host: Option<String>,

    /// Expected SHA-256 of the EVM RPC CA DER (`EVM_RPC_TLS_CA_DER_FILE`), as
    /// 64 hex characters. Required with `--expect-evm-source tls`. Ignored
    /// otherwise.
    #[arg(long)]
    expect_evm_rpc_ca_sha256: Option<String>,

    /// Require this EVM chain ID in the attestation. Omit to accept the
    /// authenticated value. Ignored with --mock.
    #[arg(long)]
    expect_chain_id: Option<u64>,

    /// Require this bridge or MultisigProxy address (20-byte 0x-hex). Omit to
    /// accept the authenticated value. Ignored with --mock.
    #[arg(long)]
    expect_bridge_contract: Option<String>,

    /// Require this RGB asset ID in the attestation. An empty string requires
    /// no RGB asset. Omit to accept the authenticated value. Ignored with --mock.
    #[arg(long)]
    expect_rgb_asset_id: Option<String>,

    /// Expected contract whose FundsIn events can authorize bridge signing.
    /// Required for production verification.
    #[arg(long)]
    expect_funds_in_contract: Option<String>,

    /// Expected EVM RPC head tag: latest, safe or finalized. Required for
    /// production verification. Ignored with --mock.
    #[arg(long, required_unless_present = "mock")]
    expect_evm_finality_tag: Option<EvmFinalityTag>,

    /// Expected ERC-20 that the Bridge releases (`TOKEN_CONTRACT`), as 0x-hex.
    /// It is an input to the `burnId` preimage. Required for production
    /// verification.
    #[arg(long)]
    expect_token_contract: Option<String>,

    /// Expected gas-tx (`SignRawDigest`) destination (`GAS_TX_ALLOWED_TO`), as
    /// 0x-hex. Omit if the gas path is not pinned. The enclave then commits an
    /// all-zero destination and rejects the path. Ignored with --mock.
    #[arg(long)]
    expect_gas_tx_to: Option<String>,

    /// Expected gas-tx `gasLimit` maximum (`GAS_TX_MAX_GAS_LIMIT`). Default 0
    /// (not pinned). Ignored with --mock.
    #[arg(long, default_value_t = 0)]
    expect_gas_max_gas_limit: u64,

    /// Expected gas-tx maximum fee per gas in wei (`GAS_TX_MAX_FEE_PER_GAS`).
    /// Default 0 (not pinned). Ignored with --mock.
    #[arg(long, default_value_t = 0)]
    expect_gas_max_fee_per_gas: u128,

    /// Expected gas-tx maximum native value in wei (`GAS_TX_MAX_VALUE_WEI`).
    /// It limits the payable `lzFundsOutCall`. Default 0: the enclave signs no
    /// non-zero value. Ignored with --mock.
    #[arg(long, default_value_t = 0)]
    expect_gas_max_value_wei: u128,

    /// Expected gas-tx selector allowlist (`GAS_TX_ALLOWED_SELECTORS`), as
    /// comma-separated 4-byte hex. Default empty. Ignored with --mock.
    #[arg(long, default_value = "")]
    expect_gas_selectors: String,

    /// Expected KMS key ARN set at launch (`KMS_KEY_ARN`). Required with
    /// `--expect-signer-role mint`. Ignored with --mock.
    #[arg(long)]
    expect_kms_key_arn: Option<String>,

    /// Expected KMS region set at launch (`KMS_REGION`). Required with
    /// `--expect-signer-role mint`. Ignored with --mock.
    #[arg(long)]
    expect_kms_region: Option<String>,

    /// Expected KMS seed ID set at launch (`KMS_SEED_ID`). Required with
    /// `--expect-signer-role mint`. Ignored with --mock.
    #[arg(long)]
    expect_kms_seed_id: Option<String>,

    /// Expected EVM address of the KMS seed (`KMS_EXPECTED_EVM_ADDRESS`), as
    /// 0x-hex. Omit to expect none. Ignored with --mock.
    #[arg(long)]
    expect_kms_evm_address: Option<String>,
}

/// Parse `--expect-evm-rpc-host` and `--expect-evm-rpc-ca-sha256`. Both are
/// required because a TLS enclave always commits both.
fn parse_evm_rpc_tls(host: Option<&str>, ca_sha256: Option<&str>) -> Result<EvmRpcTlsPin> {
    let host = host.context("--expect-evm-source tls requires --expect-evm-rpc-host")?;
    let ca = ca_sha256.context("--expect-evm-source tls requires --expect-evm-rpc-ca-sha256")?;
    let ca_sha256 = hex::decode(ca)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .context("--expect-evm-rpc-ca-sha256 must be 64 hex characters")?;
    Ok(EvmRpcTlsPin {
        host: host.into(),
        ca_sha256,
    })
}

/// Parse the `--expect-kms-*` flags. Key ARN, region and seed ID go together.
/// A mint signer requires them.
fn parse_expect_kms(
    role: SignerRole,
    key_arn: Option<&str>,
    region: Option<&str>,
    seed_id: Option<&str>,
    address: Option<&str>,
) -> Result<Option<KmsPin>> {
    match (key_arn, region, seed_id) {
        (Some(key_arn), Some(region), Some(seed_id)) => Ok(Some(KmsPin {
            key_arn: key_arn.into(),
            region: region.into(),
            seed_id: seed_id.into(),
            expected_evm_address: address
                .map(|a| parse_hex20(a, "--expect-kms-evm-address"))
                .transpose()?,
        })),
        (None, None, None) if role != SignerRole::Mint && address.is_none() => Ok(None),
        _ => anyhow::bail!(
            "--expect-kms-key-arn, --expect-kms-region and --expect-kms-seed-id go together, \
             and --expect-signer-role mint requires them"
        ),
    }
}

/// Parse the `--expect-signer-role` flag into a [`SignerRole`].
fn parse_signer_role(s: Option<&str>) -> Result<SignerRole> {
    let s = s.context("--expect-signer-role required: mint | burn | combined (or pass --mock)")?;
    match s.to_ascii_lowercase().as_str() {
        "mint" => Ok(SignerRole::Mint),
        "burn" => Ok(SignerRole::Burn),
        "combined" => Ok(SignerRole::Combined),
        other => {
            anyhow::bail!(
                "invalid --expect-signer-role '{other}' (expected: mint | burn | combined)"
            )
        }
    }
}

/// Parse the `--expect-evm-source` flag into an [`EvmDataSource`].
fn parse_evm_source(s: &str) -> Result<EvmDataSource> {
    match s.to_ascii_lowercase().as_str() {
        "tls" | "pinned-tls" => Ok(EvmDataSource::PinnedTlsRpc),
        "raw" | "raw-rpc" | "rawrpc" => Ok(EvmDataSource::RawRpc),
        "disabled" | "none" | "off" => Ok(EvmDataSource::Disabled),
        other => {
            anyhow::bail!("invalid --expect-evm-source '{other}' (expected: tls | raw | disabled)")
        }
    }
}

/// Parse an optional `0x`-hex address into 20 bytes. `None` gives all zeros,
/// the "gas path not pinned" commitment.
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

/// Parse a required 20-byte address in 0x-hex format.
fn parse_hex20(s: &str, flag: &str) -> Result<[u8; 20]> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(stripped).with_context(|| format!("{flag} '{s}' is not hex"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("{flag} must be 20 bytes, got {}", v.len()))
}

fn parse_expect_funds_in_contract(s: &Option<String>) -> Result<[u8; 20]> {
    let s = s
        .as_deref()
        .context("--expect-funds-in-contract required (or pass --mock)")?;
    parse_hex20(s, "--expect-funds-in-contract")
}

fn parse_expect_token_contract(s: &Option<String>) -> Result<[u8; 20]> {
    let s = s
        .as_deref()
        .context("--expect-token-contract required (or pass --mock)")?;
    parse_hex20(s, "--expect-token-contract")
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
            // A mock or dev enclave has the Development posture.
            ExpectedPolicy::Development,
        )
    } else {
        let pcr0 = cli.pcr0.context("--pcr0 required (or pass --mock)")?;
        let pcr1 = cli.pcr1.context("--pcr1 required (or pass --mock)")?;
        let pcr2 = cli.pcr2.context("--pcr2 required (or pass --mock)")?;
        let pcrs = attestation_verify::ExpectedPcrs::from_hex(&pcr0, &pcr1, &pcr2)
            .context("invalid PCR hex")?;
        let evm_source = parse_evm_source(&cli.expect_evm_source)?;
        let electrum_host = cli
            .expect_electrum_host
            .clone()
            .context("--expect-electrum-host required (or pass --mock)")?;
        let evm_rpc_tls = (evm_source == EvmDataSource::PinnedTlsRpc)
            .then(|| {
                parse_evm_rpc_tls(
                    cli.expect_evm_rpc_host.as_deref(),
                    cli.expect_evm_rpc_ca_sha256.as_deref(),
                )
            })
            .transpose()?;
        let expected_bridge_contract = cli
            .expect_bridge_contract
            .as_deref()
            .map(|s| parse_hex20(s, "--expect-bridge-contract"))
            .transpose()?;
        let signer_role = parse_signer_role(cli.expect_signer_role.as_deref())?;
        let kms = parse_expect_kms(
            signer_role,
            cli.expect_kms_key_arn.as_deref(),
            cli.expect_kms_region.as_deref(),
            cli.expect_kms_seed_id.as_deref(),
            cli.expect_kms_evm_address.as_deref(),
        )?;
        let expected_policy = ExpectedPolicy::Production {
            allow_vanilla_psbt: cli.expect_vanilla_psbt,
            signer_role,
            evm_source,
            electrum_host,
            evm_rpc_tls,
            expected_chain_id: cli.expect_chain_id,
            expected_bridge_contract,
            expected_rgb_asset_id: cli.expect_rgb_asset_id.clone(),
            funds_in_contract: parse_expect_funds_in_contract(&cli.expect_funds_in_contract)?,
            evm_finality_tag: cli
                .expect_evm_finality_tag
                .context("--expect-evm-finality-tag required (or pass --mock)")?,
            token_contract: parse_expect_token_contract(&cli.expect_token_contract)?,
            gas_tx_allowed_to: parse_expect_gas_to(&cli.expect_gas_tx_to)?,
            gas_tx_max_gas_limit: cli.expect_gas_max_gas_limit,
            gas_tx_max_fee_per_gas: cli.expect_gas_max_fee_per_gas,
            gas_tx_max_value_wei: cli.expect_gas_max_value_wei,
            gas_tx_allowed_selectors: parse_expect_gas_selectors(&cli.expect_gas_selectors)?,
            kms,
        };
        (pcrs, VerifyMode::Real, expected_policy)
    };

    eprintln!("expecting security policy: {expected_policy:?}");
    let result = match &cli.from_file {
        Some(path) => {
            let json = std::fs::read_to_string(path)
                .with_context(|| format!("cannot read {}", path.display()))?;
            verify_bundle(&json, &expected_pcrs, mode, &expected_policy)?
        }
        None => verify_attested_pubkey(&cli.endpoint, expected_pcrs, mode, expected_policy).await?,
    };
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
    if let AttestedPolicy::Production { kms: Some(k), .. } = &result.policy {
        println!("  KMS key ARN           : {}", k.key_arn);
        println!("  KMS region            : {}", k.region);
        println!("  KMS seed id           : {}", k.seed_id);
        println!(
            "  KMS expected address  : {}",
            k.expected_evm_address
                .map_or("none".into(), |a| format!("0x{}", hex::encode(a)))
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finality_tag_is_explicit_in_production_and_strictly_parsed() {
        let missing = Cli::try_parse_from(["attest-verify"]).err().unwrap();
        assert_eq!(
            missing.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        assert!(missing.to_string().contains("--expect-evm-finality-tag"));
        assert!(Cli::try_parse_from(["attest-verify", "--mock"]).is_ok());
        for (value, tag) in [
            ("latest", EvmFinalityTag::Latest),
            ("safe", EvmFinalityTag::Safe),
            ("finalized", EvmFinalityTag::Finalized),
        ] {
            let cli =
                Cli::try_parse_from(["attest-verify", "--expect-evm-finality-tag", value]).unwrap();
            assert_eq!(cli.expect_evm_finality_tag, Some(tag));
        }
        for invalid in ["", "SAFE", "pending"] {
            assert!(
                Cli::try_parse_from(["attest-verify", "--expect-evm-finality-tag", invalid])
                    .is_err()
            );
        }
    }

    #[test]
    fn parse_signer_role_accepts_the_three_roles() {
        assert_eq!(parse_signer_role(Some("mint")).unwrap(), SignerRole::Mint);
        assert_eq!(parse_signer_role(Some("burn")).unwrap(), SignerRole::Burn);
        assert_eq!(
            parse_signer_role(Some("Combined")).unwrap(),
            SignerRole::Combined
        );
    }

    #[test]
    fn tls_source_needs_host_and_ca_hash() {
        let hash = "ab".repeat(32);
        assert!(parse_evm_rpc_tls(None, Some(&hash)).is_err());
        assert!(parse_evm_rpc_tls(Some("rpc.test"), None).is_err());
        assert!(parse_evm_rpc_tls(Some("rpc.test"), Some("abcd")).is_err());
        let pin = parse_evm_rpc_tls(Some("rpc.test"), Some(&hash)).unwrap();
        assert_eq!(pin.host, "rpc.test");
        assert_eq!(pin.ca_sha256, [0xab; 32]);
        assert_eq!(
            parse_evm_source("tls").unwrap(),
            EvmDataSource::PinnedTlsRpc
        );
    }

    #[test]
    fn mint_requires_the_kms_flags() {
        let arn =
            Some("arn:aws:kms:eu-west-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef");
        let (region, seed) = (Some("eu-west-1"), Some("seed-1"));
        assert!(parse_expect_kms(SignerRole::Mint, None, None, None, None).is_err());
        assert!(parse_expect_kms(SignerRole::Mint, arn, region, None, None).is_err());
        assert!(parse_expect_kms(SignerRole::Burn, arn, None, None, None).is_err());
        assert!(parse_expect_kms(SignerRole::Burn, None, None, None, Some("0x00")).is_err());
        assert_eq!(
            parse_expect_kms(SignerRole::Burn, None, None, None, None).unwrap(),
            None
        );
        let pin = parse_expect_kms(SignerRole::Mint, arn, region, seed, None)
            .unwrap()
            .unwrap();
        assert_eq!(pin.expected_evm_address, None);
        let address = format!("0x{}", "ab".repeat(20));
        let pin = parse_expect_kms(SignerRole::Mint, arn, region, seed, Some(&address))
            .unwrap()
            .unwrap();
        assert_eq!(pin.expected_evm_address, Some([0xab; 20]));
    }

    #[test]
    fn parse_signer_role_rejects_missing_and_invalid() {
        let missing = parse_signer_role(None).unwrap_err();
        assert!(format!("{missing:#}").contains("required"), "{missing:#}");
        let invalid = parse_signer_role(Some("minter")).unwrap_err();
        assert!(format!("{invalid:#}").contains("invalid"), "{invalid:#}");
    }
}
