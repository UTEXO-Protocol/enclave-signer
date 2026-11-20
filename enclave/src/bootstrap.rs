//! Boot sequence, one step per function. `main.rs` calls them in order.
//! Nothing in this module handles a request.

use crate::config::BridgeConfig;
#[cfg(feature = "rgb-validation")]
use crate::config::EvmRpcTls;
use crate::networks::rgb::spv::Network;
#[cfg(feature = "rgb-validation")]
use crate::networks::rgb::spv::{
    resolve_checkpoint, CheckpointSource, HeaderChain, CHECKPOINT_ENV,
};
#[cfg(all(feature = "rgb-validation", rgb_to_evm, unix))]
use crate::networks::rgb::validation::ChildReport;
#[cfg(feature = "rgb-validation")]
use crate::networks::rgb::validation::RgbValidator;
#[cfg(all(feature = "rgb-validation", rgb_to_evm, unix))]
use crate::policy::BuildContext;
use crate::policy::SecurityPolicy;
#[cfg(feature = "rgb-validation")]
use crate::policy::{EvmDataSource, EvmRpcTlsPin};
use crate::state::EnclaveState;

/// Install the tracing subscriber. `RUST_LOG` picks the filter, but Alloy HTTP
/// logs stay off at any level: they can carry the RPC URL, and its path is a
/// secret.
pub fn init_tracing() {
    let filter = alloy_http_off(tracing_subscriber::EnvFilter::from_default_env());
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Runs this process as a validator child of the burn signer when its one
/// argument is `CHILD_ARG`. Returns the child's exit code, or `None` for the
/// enclave. The host passes the enclave no argument, so it cannot pick this.
#[cfg(all(feature = "rgb-validation", rgb_to_evm, unix))]
pub fn validator_child() -> Option<i32> {
    use crate::networks::rgb::validation::{serve_validator_child, CHILD_ARG};
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next()) {
        (Some(arg), None) if arg == CHILD_ARG => Some(serve_validator_child()),
        _ => None,
    }
}

/// Install the tracing subscriber of a validator child: the filter of
/// [`init_tracing`], written to stderr, as the child's stdout goes nowhere.
#[cfg(all(feature = "rgb-validation", rgb_to_evm, unix))]
pub fn init_child_tracing() {
    let filter = alloy_http_off(tracing_subscriber::EnvFilter::from_default_env());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// `filter` with Alloy HTTP logging forced off.
fn alloy_http_off(filter: tracing_subscriber::EnvFilter) -> tracing_subscriber::EnvFilter {
    filter.add_directive(
        "alloy_transport_http=off"
            .parse()
            .expect("a fixed, valid directive"),
    )
}

#[cfg(test)]
mod log_filter_tests {
    use super::alloy_http_off;
    use tracing_subscriber::EnvFilter;

    #[test]
    fn a_trace_filter_still_turns_alloy_http_off() {
        for level in ["trace", "debug", "alloy_transport_http=trace"] {
            let filter = alloy_http_off(EnvFilter::new(level)).to_string();
            assert!(filter.contains("alloy_transport_http=off"), "{filter}");
            assert!(!filter.contains("alloy_transport_http=trace"), "{filter}");
        }
    }
}

/// Add the line `addr host` to the hosts file at `path` if it is missing, so
/// the connection to `host` goes to its local vsock forwarder and TLS still
/// checks the real certificate of `host`. The file changes in one rename.
#[cfg(any(
    test,
    all(feature = "vsock", feature = "kms-persistence", target_os = "linux")
))]
pub fn pin_host(
    path: &std::path::Path,
    addr: std::net::Ipv4Addr,
    host: &str,
) -> std::io::Result<()> {
    let existing = match std::fs::read_to_string(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        other => other?,
    };
    let line = format!("{addr} {host}");
    if existing.lines().any(|l| l.trim() == line) {
        return Ok(());
    }
    let sep = if existing.is_empty() || existing.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    std::fs::write(&tmp, format!("{existing}{sep}{line}\n"))?;
    std::fs::rename(&tmp, path)
}

/// The raw `BITCOIN_NETWORK` value, default `bitcoin`. [`resolve_network`]
/// parses it.
pub fn bitcoin_network_str() -> String {
    std::env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "bitcoin".into())
}

/// Parse `BITCOIN_NETWORK`. An unknown value is fatal: a fallback would put
/// the keys, the SPV rules and the RGB chain-network on another network.
pub fn resolve_network(bitcoin_network_str: &str) -> Network {
    let network = Network::from_env_str(bitcoin_network_str).unwrap_or_else(|e| {
        panic!(
            "BITCOIN_NETWORK '{bitcoin_network_str}' is not valid ({e}): use bitcoin, signet, \
             signetcustom, testnet3, testnet4 or regtest"
        )
    });
    tracing::info!(%bitcoin_network_str, ?network, "bitcoin network configured");
    network
}

/// Log the pinned bridge config, as an error when it is partially set.
///
/// An `rgb-validation` build refuses a `fundsOut` `Sign` without a full config,
/// and the boot gate in `main` stops a release bridge build on it.
pub fn log_bridge_config(bridge_config: &BridgeConfig) {
    if bridge_config.btc_relay_mode == crate::config::BtcRelayMode::None {
        tracing::warn!(
            "{}=none: fundsOut relay commitments are NOT verified (no BtcRelay); \
             heights, anchor and freshness are still bound",
            crate::config::BTC_RELAY_MODE_ENV
        );
    }
    // Production sets EVM_CHAIN_ID, EVM_PROXY_CONTRACT_ADDRESS and RGB_ASSET_ID.
    // The attestation bundle shows a bad config to external verifiers.
    if bridge_config.is_configured() {
        tracing::info!(
            chain_id = bridge_config.chain_id,
            bridge_contract = %hex::encode(bridge_config.bridge_contract),
            rgb_asset_id = %bridge_config.rgb_asset_id,
            btc_relay_mode = ?bridge_config.btc_relay_mode,
            evm_finality_tag = %bridge_config.evm_finality_tag,
            "bridge config pinned from env"
        );
    } else if bridge_config.is_partially_configured() {
        tracing::error!(
            chain_id = bridge_config.chain_id,
            bridge_contract = %hex::encode(bridge_config.bridge_contract),
            rgb_asset_id = %bridge_config.rgb_asset_id,
            "bridge config PARTIALLY set - EVM_CHAIN_ID / EVM_PROXY_CONTRACT_ADDRESS / RGB_ASSET_ID must all \
             be set (non-zero) or all unset; an rgb-validation build refuses fundsOut signing"
        );
    } else {
        tracing::warn!(
        "bridge config unconfigured (EVM_CHAIN_ID / EVM_PROXY_CONTRACT_ADDRESS / RGB_ASSET_ID unset) - \
         fundsOut pin checks are skipped (an rgb-validation build refuses to sign) and the \
         attestation bundle will commit to empty values"
    );
    }
}

/// The EVM `FundsIn` verification source and its TLS pin.
///
/// Uses the same rule as [`build_evm_rpc_client`]: the pinned TLS of `tls`.
#[cfg(feature = "rgb-validation")]
pub fn resolve_evm_data_source(tls: &EvmRpcTls) -> (EvmDataSource, Option<EvmRpcTlsPin>) {
    use sha2::Digest;
    let pin = EvmRpcTlsPin {
        host: tls.host.clone(),
        ca_sha256: sha2::Sha256::digest(&tls.ca_der).into(),
    };
    (EvmDataSource::PinnedTlsRpc, Some(pin))
}

/// Log the resolved policy. The attestation `user_data` commits it.
pub fn log_policy(policy: &SecurityPolicy) {
    match policy {
        SecurityPolicy::Production(p) => tracing::info!(
            chain_id = p.chain_id,
            allow_vanilla_psbt = p.allow_vanilla_psbt,
            evm_source = ?p.evm_source,
            evm_rpc_tls = ?p.evm_rpc_tls,
            funds_in_contract = %hex::encode(p.funds_in_contract),
            token_contract = %hex::encode(p.token_contract),
            evm_finality_tag = %p.evm_finality_tag,
            spv_min_confirmations = p.spv_min_confirmations,
            btc_source = ?p.btc_source,
            "resolved PRODUCTION security policy (committed into attestation user_data)"
        ),
        SecurityPolicy::Development { reason } => tracing::warn!(
            ?reason,
            "resolved DEVELOPMENT security policy - this is NOT a production bridge signer"
        ),
    }
}

/// Refuses to start a release burn signer whose validator child does not
/// start or confine itself, or whose kernel could end the enclave instead of
/// a child when memory runs out. A debug build logs a warning. `main` panics
/// on the refusal.
#[cfg(all(feature = "rgb-validation", rgb_to_evm, unix))]
pub fn check_validator_child(build: &BuildContext) -> Result<(), String> {
    use crate::networks::rgb::validation::{probe_validator_child, ChildProgram};
    let report = ChildProgram::this_binary()
        .and_then(|program| probe_validator_child(&program, crate::conn::IO_IDLE_TIMEOUT));
    judge_validator_child(kernel_oom_policy(), report, build)
}

/// Judges the kernel policy and the report of a probe child for
/// [`check_validator_child`].
#[cfg(all(feature = "rgb-validation", rgb_to_evm, unix))]
fn judge_validator_child(
    kernel: Result<(), String>,
    report: crate::error::Result<ChildReport>,
    build: &BuildContext,
) -> Result<(), String> {
    let mut problems = Vec::new();
    if let Err(e) = kernel {
        problems.push(format!(
            "the kernel could end the enclave before a validator child: {e}"
        ));
    }
    match &report {
        Ok(report) if !report.confined => problems.push(format!(
            "the validator child could not confine itself (OOM score adjustment {})",
            report.oom_score_adj
        )),
        Ok(_) => {}
        Err(e) => problems.push(format!("the validator child did not answer its probe: {e}")),
    }
    if !problems.is_empty() {
        let problem = problems.join("; ");
        if !build.debug_or_test {
            return Err(problem);
        }
        tracing::warn!("{problem}; continuing in a debug build");
    }
    if let Ok(report) = report {
        tracing::info!(
            spawn_ms = report.spawn_ms,
            confined = report.confined,
            oom_score_adj = report.oom_score_adj,
            vm_data_kib = report.vm_data_bytes / 1024,
            vm_rss_kib = report.vm_rss_bytes / 1024,
            "validator child ready"
        );
    }
    Ok(())
}

/// Refuses kernel settings under which an out-of-memory can end the enclave
/// before a validator child, which has the highest OOM score. Only Linux has
/// these settings to read.
#[cfg(all(feature = "rgb-validation", rgb_to_evm, unix))]
fn kernel_oom_policy() -> Result<(), String> {
    oom_policy(|name| std::fs::read_to_string(format!("/proc/sys/vm/{name}")))
}

/// [`kernel_oom_policy`] with `read` giving each `vm` sysctl by its name.
#[cfg(all(feature = "rgb-validation", rgb_to_evm, unix))]
fn oom_policy(read: impl Fn(&str) -> std::io::Result<String>) -> Result<(), String> {
    let value = |name: &str| -> Result<u64, String> {
        let text = read(name).map_err(|e| format!("cannot read vm.{name}: {e}"))?;
        let text = text.trim();
        text.parse()
            .map_err(|e| format!("vm.{name} reads {text:?}: {e}"))
    };
    // Strict accounting fails an allocation of whichever process asks.
    if value("overcommit_memory")? == 2 {
        return Err("vm.overcommit_memory is 2: an allocation of the enclave can fail".into());
    }
    if value("panic_on_oom")? != 0 {
        return Err("vm.panic_on_oom is set: an out-of-memory stops the whole kernel".into());
    }
    if value("oom_kill_allocating_task")? != 0 {
        return Err(
            "vm.oom_kill_allocating_task is set: the kernel ends the process that asked, not \
             the one with the highest OOM score"
                .into(),
        );
    }
    Ok(())
}

/// Dev fallback for the donor cloning secret, from `UTEXO_CLONING_SECRET`.
///
/// Use the `InitializeKey` `cloning_secret` field instead: it never goes into
/// the EIF or the PCRs. Never logged; `SecretBox` zeroizes it.
pub fn install_env_cloning_secret(state: &EnclaveState) {
    // Never bake this var into a release EIF. Only `GetClone` donors need it.
    if let Ok(secret) = std::env::var("UTEXO_CLONING_SECRET") {
        if !secret.is_empty() {
            if let Err(e) = state.set_donor_cloning_secret(secret) {
                tracing::error!("failed to set donor cloning secret: {e}");
            } else {
                tracing::warn!(
                    "donor cloning secret configured from UTEXO_CLONING_SECRET env \
                 (dev fallback; prefer the InitializeKey cloning_secret field)"
                );
            }
        }
    }
}

/// Build the RGB consignment validator of `BITCOIN_NETWORK`. `None` makes the
/// launch fail.
#[cfg(feature = "rgb-validation")]
pub fn build_rgb_validator() -> Option<RgbValidator> {
    match RgbValidator::new(&bitcoin_network_str()) {
        Ok(v) => {
            tracing::info!("RGB validator initialized");
            Some(v)
        }
        Err(e) => {
            tracing::error!("failed to create RGB validator: {e}");
            None
        }
    }
}

/// Create the in-enclave Bitcoin header chain at the compile-time checkpoint
/// of the active network. The chain starts empty. `SubmitHeaders` fills it.
///
/// Panics on a bad checkpoint: a placeholder in a release build, one not on a
/// retarget boundary on a PoW network, or a malformed `SPV_CHECKPOINT` override. Such a chain
/// cannot advance.
#[cfg(feature = "rgb-validation")]
pub fn build_header_chain(spv_network: Network) -> std::sync::Mutex<HeaderChain> {
    // Compiled-in anchor, or the dev-only `SPV_CHECKPOINT` override. A
    // production build does not boot with that var set. A malformed value is fatal.
    let (checkpoint, checkpoint_source) = resolve_checkpoint(spv_network).unwrap_or_else(|msg| {
        panic!("{msg}");
    });
    if checkpoint_source == CheckpointSource::Env {
        tracing::warn!(
            ?spv_network,
            checkpoint_height = checkpoint.height,
            "spv: checkpoint OVERRIDDEN from {} - dev builds only; headers below this height are \
             not verifiable by this enclave",
            CHECKPOINT_ENV
        );
    }
    if let Err(msg) = checkpoint.assert_real_in_release() {
        // No real header connects to a placeholder checkpoint.
        panic!("{msg}");
    }
    if let Err(msg) = checkpoint.assert_retarget_aligned(spv_network) {
        // On a PoW network, a misaligned checkpoint stops the chain at the next
        // retarget boundary: the epoch-start lookup falls below the checkpoint.
        panic!("{msg}");
    }
    if !checkpoint.is_real {
        tracing::warn!(
            ?spv_network,
            "spv: using PLACEHOLDER checkpoint (zeros) - header validation will reject any real chain. \
             Replace the constant in enclave/src/networks/rgb/spv/checkpoint.rs before deploying."
        );
    } else {
        tracing::info!(
            ?spv_network,
            checkpoint_height = checkpoint.height,
            "spv: header chain initialised at checkpoint"
        );
    }
    std::sync::Mutex::new(HeaderChain::new(spv_network, checkpoint))
}

/// Build the in-enclave EVM RPC client for independent `FundsIn` verification.
///
/// The client reaches the RPC through the loopback forwarder, with TLS to the
/// pinned host and CA. `None` makes the launch fail. There is no fallback to an
/// unverified path.
#[cfg(feature = "rgb-validation")]
pub fn build_evm_rpc_client(
    tls: &EvmRpcTls,
) -> Option<Box<dyn crate::networks::evm::events::EvmReceiptProvider + Send + Sync>> {
    use crate::networks::evm::events::{AlloyEvmClient, EvmReceiptProvider};

    tracing::info!(
        host = %tls.host,
        tls_port = tls.tls_port,
        "EVM FundsIn verification: pinned TLS (host must run: vsock-proxy \
         <EVM_RPC_VSOCK_PORT> {} {})",
        tls.host,
        tls.tls_port,
    );
    match AlloyEvmClient::with_pinned_tls(tls) {
        Ok(c) => Some(Box::new(c) as Box<dyn EvmReceiptProvider + Send + Sync>),
        Err(e) => {
            tracing::error!("failed to init EVM RPC client: {e}");
            None
        }
    }
}

/// The boot check of the validator child of the burn signer.
#[cfg(all(test, feature = "rgb-validation", rgb_to_evm, unix))]
mod validator_child_tests {
    use super::{judge_validator_child, oom_policy};
    use crate::error::EnclaveError;
    use crate::networks::rgb::validation::ChildReport;
    use crate::policy::BuildContext;

    fn build(debug_or_test: bool) -> BuildContext {
        BuildContext {
            debug_or_test,
            ..BuildContext::current()
        }
    }

    fn report(confined: bool) -> crate::error::Result<ChildReport> {
        Ok(ChildReport {
            confined,
            oom_score_adj: 1000,
            vm_data_bytes: 1 << 20,
            vm_rss_bytes: 1 << 20,
            spawn_ms: 5,
        })
    }

    /// A release burn signer starts only with a probe child that confined
    /// itself and a kernel that ends a child first. A debug build starts.
    #[test]
    fn a_release_burn_signer_refuses_to_start_without_a_working_child() {
        assert_eq!(
            judge_validator_child(Ok(()), report(true), &build(false)),
            Ok(())
        );
        type Case = (
            fn() -> Result<(), String>,
            fn() -> crate::error::Result<ChildReport>,
            &'static str,
        );
        let cases: [Case; 3] = [
            (|| Ok(()), || report(false), "could not confine itself"),
            (
                || Ok(()),
                || {
                    Err(EnclaveError::Internal(
                        "cannot start the RGB validator".into(),
                    ))
                },
                "did not answer its probe",
            ),
            (
                || Err("vm.panic_on_oom is set".into()),
                || report(true),
                "vm.panic_on_oom is set",
            ),
        ];
        for (kernel, child, what) in cases {
            let err = judge_validator_child(kernel(), child(), &build(false)).unwrap_err();
            assert!(err.contains(what), "{err}");
            let debug = judge_validator_child(kernel(), child(), &build(true));
            assert_eq!(debug, Ok(()), "{what}");
        }
    }

    /// The kernel policy passes only settings under which the OOM killer ends
    /// the process with the highest score, a validator child.
    #[test]
    fn a_kernel_that_could_end_the_enclave_first_is_refused() {
        let policy = |overcommit: u8, on_oom: u8, kill_allocating: u8| {
            oom_policy(|name| {
                let value = match name {
                    "overcommit_memory" => overcommit,
                    "panic_on_oom" => on_oom,
                    "oom_kill_allocating_task" => kill_allocating,
                    other => panic!("no sysctl vm.{other}"),
                };
                Ok(format!("{value}\n"))
            })
        };
        assert_eq!(policy(0, 0, 0), Ok(()));
        assert_eq!(policy(1, 0, 0), Ok(()));
        for (refused, what) in [
            (policy(2, 0, 0), "vm.overcommit_memory"),
            (policy(0, 1, 0), "vm.panic_on_oom"),
            (policy(0, 2, 0), "vm.panic_on_oom"),
            (policy(0, 0, 1), "vm.oom_kill_allocating_task"),
        ] {
            assert!(refused.unwrap_err().contains(what), "{what}");
        }
        let unreadable = oom_policy(|_| Err(std::io::ErrorKind::NotFound.into()));
        let err = unreadable.unwrap_err();
        assert!(err.contains("cannot read vm.overcommit_memory"), "{err}");
        let err = oom_policy(|_| Ok("many".into())).unwrap_err();
        assert!(err.contains("reads \"many\""), "{err}");
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    use super::pin_host;

    const ADDR: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
    const HOST: &str = "kms.eu-west-1.amazonaws.com";

    /// A fresh hosts file next to the test binary, not in /tmp.
    fn hosts(name: &str) -> PathBuf {
        let dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts");
        std::fs::write(&path, "127.0.0.1 localhost").unwrap();
        path
    }

    #[test]
    fn a_pin_is_written_once() {
        let path = hosts("a_pin_is_written_once");
        pin_host(&path, ADDR, HOST).unwrap();
        let first = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            first,
            "127.0.0.1 localhost\n127.0.0.2 kms.eu-west-1.amazonaws.com\n"
        );
        pin_host(&path, ADDR, HOST).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
    }

    #[test]
    fn a_failed_pin_leaves_the_file_unchanged() {
        let path = hosts("a_failed_pin_leaves_the_file_unchanged");
        let before = std::fs::read(&path).unwrap();
        // A directory in the way makes the write fail, also as root.
        let tmp = path.with_extension("tmp");
        std::fs::create_dir(&tmp).unwrap();
        assert!(pin_host(&path, ADDR, HOST).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_dir(&tmp).unwrap();
        pin_host(&path, ADDR, HOST).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after.matches(&format!("{ADDR} {HOST}")).count(), 1);
    }
}
