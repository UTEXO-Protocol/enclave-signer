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

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("attest-verify").chain(args.iter().copied()))
            .expect("valid arguments")
    }

    fn zero_pcr() -> String {
        "00".repeat(48)
    }

    fn err_of<T>(r: Result<T>) -> String {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => format!("{e:#}"),
        }
    }

    // ---- flag parsers -------------------------------------------------------

    #[test]
    fn parse_checkpoint_accepts_32_bytes_with_or_without_prefix() {
        let hex = "ab".repeat(32);
        assert_eq!(parse_checkpoint(&hex).unwrap(), [0xab; 32]);
        assert_eq!(parse_checkpoint(&format!("0x{hex}")).unwrap(), [0xab; 32]);
    }

    #[test]
    fn parse_checkpoint_rejects_bad_hex_and_wrong_length() {
        assert!(err_of(parse_checkpoint("0xzz")).contains("not valid hex"));
        let msg = err_of(parse_checkpoint(&"ab".repeat(31)));
        assert!(
            msg.contains("must be 32 bytes") && msg.contains("got 31"),
            "{msg}"
        );
        let msg = err_of(parse_checkpoint(""));
        assert!(msg.contains("got 0"), "{msg}");
    }

    #[test]
    fn parse_evm_source_accepts_every_alias_case_insensitively() {
        for s in ["raw", "RAW", "raw-rpc", "RawRpc"] {
            assert_eq!(parse_evm_source(s).unwrap(), EvmDataSource::RawRpc, "{s}");
        }
        for s in ["helios", "HELIOS", "helios-verified"] {
            assert_eq!(
                parse_evm_source(s).unwrap(),
                EvmDataSource::HeliosVerified,
                "{s}"
            );
        }
        for s in ["disabled", "none", "OFF"] {
            assert_eq!(parse_evm_source(s).unwrap(), EvmDataSource::Disabled, "{s}");
        }
        let msg = err_of(parse_evm_source("bogus"));
        assert!(msg.contains("invalid --expect-evm-source 'bogus'"), "{msg}");
    }

    #[test]
    fn parse_expect_gas_to_defaults_to_the_unpinned_zero_address() {
        assert_eq!(parse_expect_gas_to(&None).unwrap(), [0u8; 20]);
        let hex = "11".repeat(20);
        assert_eq!(
            parse_expect_gas_to(&Some(format!("0x{hex}"))).unwrap(),
            [0x11; 20]
        );
        assert_eq!(parse_expect_gas_to(&Some(hex)).unwrap(), [0x11; 20]);
        assert!(err_of(parse_expect_gas_to(&Some("0xzz".into()))).contains("is not hex"));
        let msg = err_of(parse_expect_gas_to(&Some("11".repeat(19))));
        assert!(msg.contains("must be 20 bytes, got 19"), "{msg}");
    }

    #[test]
    fn parse_expect_gas_selectors_handles_lists_prefixes_and_errors() {
        assert!(parse_expect_gas_selectors("").unwrap().is_empty());
        assert!(parse_expect_gas_selectors(" , ,").unwrap().is_empty());
        assert_eq!(
            parse_expect_gas_selectors(" 0xaabbccdd , 01020304 ,, ").unwrap(),
            vec![[0xaa, 0xbb, 0xcc, 0xdd], [1, 2, 3, 4]]
        );
        let msg = err_of(parse_expect_gas_selectors("0xaabbcc"));
        assert!(msg.contains("'0xaabbcc' must be exactly 4 bytes"), "{msg}");
        let msg = err_of(parse_expect_gas_selectors("aabbccdd,zz"));
        assert!(msg.contains("'zz' is not hex"), "{msg}");
    }

    // ---- run(): flag validation before any network access -------------------

    #[tokio::test]
    async fn run_without_mock_requires_every_pcr() {
        let z = zero_pcr();
        let msg = err_of(run(cli(&["--pcr1", &z, "--pcr2", &z])).await);
        assert!(msg.contains("--pcr0 required"), "{msg}");
        let msg = err_of(run(cli(&["--pcr0", &z, "--pcr2", &z])).await);
        assert!(msg.contains("--pcr1 required"), "{msg}");
        let msg = err_of(run(cli(&["--pcr0", &z, "--pcr1", &z])).await);
        assert!(msg.contains("--pcr2 required"), "{msg}");
    }

    #[tokio::test]
    async fn run_rejects_invalid_pcr_hex() {
        let z = zero_pcr();
        let msg = err_of(run(cli(&["--pcr0", "zz", "--pcr1", &z, "--pcr2", &z])).await);
        assert!(msg.contains("invalid PCR hex"), "{msg}");
    }

    #[tokio::test]
    async fn run_rejects_helios_without_a_checkpoint() {
        let z = zero_pcr();
        let msg = err_of(
            run(cli(&[
                "--pcr0",
                &z,
                "--pcr1",
                &z,
                "--pcr2",
                &z,
                "--expect-evm-source",
                "helios",
            ]))
            .await,
        );
        assert!(msg.contains("requires --expect-helios-checkpoint"), "{msg}");
    }

    #[tokio::test]
    async fn run_rejects_malformed_expectation_flags() {
        let z = zero_pcr();
        let base = |extra: &[&str]| {
            let mut v = vec!["--pcr0", "", "--pcr1", "", "--pcr2", ""];
            v[1] = "PCR";
            v[3] = "PCR";
            v[5] = "PCR";
            let mut owned: Vec<String> = v
                .into_iter()
                .map(|a| if a == "PCR" { z.clone() } else { a.to_string() })
                .collect();
            owned.extend(extra.iter().map(|s| s.to_string()));
            owned
        };
        let cases: [(&[&str], &str); 4] = [
            (
                &["--expect-evm-source", "bogus"],
                "invalid --expect-evm-source",
            ),
            (&["--expect-gas-tx-to", "0x12"], "must be 20 bytes"),
            (&["--expect-gas-selectors", "0xaabb"], "exactly 4 bytes"),
            (
                &[
                    "--expect-evm-source",
                    "helios",
                    "--expect-helios-checkpoint",
                    "zz",
                ],
                "not valid hex",
            ),
        ];
        for (extra, needle) in cases {
            let args = base(extra);
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let msg = err_of(run(cli(&refs)).await);
            assert!(msg.contains(needle), "{extra:?}: {msg}");
        }
    }

    #[tokio::test]
    async fn run_fails_to_connect_to_a_dead_endpoint_in_both_modes() {
        let msg = err_of(run(cli(&["--mock", "--endpoint", "http://127.0.0.1:1"])).await);
        assert!(msg.contains("connecting to http://127.0.0.1:1"), "{msg}");

        let z = zero_pcr();
        let msg = err_of(
            run(cli(&[
                "--pcr0",
                &z,
                "--pcr1",
                &z,
                "--pcr2",
                &z,
                "--endpoint",
                "http://127.0.0.1:1",
            ]))
            .await,
        );
        assert!(msg.contains("connecting to http://127.0.0.1:1"), "{msg}");
    }

    // ---- run(): against the real in-process stack ---------------------------

    mod live {
        use super::*;
        use std::net::TcpListener;
        use std::sync::Arc;

        use tonic::transport::Server;
        use utexo_bridge_enclave::config::BridgeConfig;
        use utexo_bridge_enclave::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
        use utexo_bridge_enclave::server::{self as enclave_server, ServerContext};
        use utexo_bridge_enclave::state::EnclaveState;
        use utexo_bridge_parent::grpc_proto::parent_service_server::ParentServiceServer;
        use utexo_bridge_parent::grpc_server::{EnclaveTarget, ParentAdapterService};

        const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                                abandon abandon abandon about";

        fn start_enclave() -> u16 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let state = EnclaveState::new(bitcoin::Network::Bitcoin);
            state.initialize_from_mnemonic(MNEMONIC).unwrap();
            let ctx = Arc::new(ServerContext::new(
                state,
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
            port
        }

        async fn start_parent(enclave_port: u16) -> String {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            drop(listener);
            let service = ParentAdapterService::new(
                EnclaveTarget::Tcp(format!("127.0.0.1:{enclave_port}")),
                Default::default(),
            );
            tokio::spawn(async move {
                Server::builder()
                    .add_service(ParentServiceServer::new(service))
                    .serve(addr)
                    .await
                    .unwrap();
            });
            for _ in 0..50 {
                if std::net::TcpStream::connect(addr).is_ok() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            format!("http://{addr}")
        }

        #[tokio::test]
        async fn mock_mode_verifies_the_live_stack_and_prints_the_bundle() {
            let endpoint = start_parent(start_enclave()).await;
            run(cli(&["--mock", "--endpoint", &endpoint]))
                .await
                .expect("mock verification of the live stack succeeds");

            // The success printer runs over a freshly verified result.
            let result = verify_attested_pubkey(
                &endpoint,
                attestation_verify::ExpectedPcrs::zero(),
                VerifyMode::Mock,
                ExpectedPolicy::Development,
            )
            .await
            .unwrap();
            print_ok(&result);
        }

        #[tokio::test]
        async fn real_mode_rejects_the_mock_stack() {
            let endpoint = start_parent(start_enclave()).await;
            let z = zero_pcr();
            let msg = err_of(
                run(cli(&[
                    "--pcr0",
                    &z,
                    "--pcr1",
                    &z,
                    "--pcr2",
                    &z,
                    "--endpoint",
                    &endpoint,
                ]))
                .await,
            );
            assert!(msg.contains("attestation verify failed"), "{msg}");
        }
    }
}
