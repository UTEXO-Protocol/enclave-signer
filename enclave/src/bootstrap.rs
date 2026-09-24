//! Boot sequence, one step per function.
//!
//! `main.rs` reads as the order those steps run in; every step that has to
//! look at the environment, panic on a bad pin, or fail soft on a missing
//! dependency does it here. Nothing in this module handles a request.

use crate::config::BridgeConfig;
#[cfg(feature = "rgb-validation")]
use crate::networks::rgb::spv::{
    resolve_checkpoint, CheckpointSource, HeaderChain, Network, CHECKPOINT_ENV,
};
#[cfg(feature = "rgb-validation")]
use crate::networks::rgb::validation::RgbValidator;
use crate::policy::{EvmDataSource, SecurityPolicy};
use crate::state::EnclaveState;

/// Install the tracing subscriber. `RUST_LOG` picks the filter.
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}

/// Witness-resolver endpoint. `ELECTRUM_URL` (e.g. `ssl://host:50002`) is the
/// production path; `ESPLORA_URL` is the legacy REST fallback. Default targets
/// the legacy esplora forwarder port for backwards compatibility.
#[allow(dead_code)]
fn indexer_url_from_env() -> String {
    std::env::var("ELECTRUM_URL")
        .or_else(|_| std::env::var("ESPLORA_URL"))
        .unwrap_or_else(|_| "http://127.0.0.1:3443".into())
}

/// Map an indexer URL to (local forwarder listen port, optional hostname to pin
/// to loopback). For `ssl://host:port` / `tcp://host:port` we listen on the
/// URL's own port and return the host so it can be pinned to 127.0.0.1 (keeps
/// in-enclave TLS validating the real cert). For http(s)/legacy esplora we keep
/// the historical port 3443 and pin nothing.
#[cfg(all(feature = "vsock", feature = "rgb-validation", target_os = "linux"))]
fn forwarder_target(url: &str) -> (u16, Option<String>) {
    for scheme in ["ssl://", "tcp://"] {
        if let Some(rest) = url.strip_prefix(scheme) {
            let hostport = rest.split('/').next().unwrap_or(rest);
            if let Some((host, port)) = hostport.rsplit_once(':') {
                if let Ok(p) = port.parse::<u16>() {
                    return (p, Some(host.to_string()));
                }
            }
        }
    }
    (3443, None)
}

/// Append `127.0.0.1 <host>` to /etc/hosts (idempotent) so the enclave's
/// outbound connection to `host` lands on the local vsock forwarder while the
/// TLS layer still validates against `host`'s real certificate.
#[cfg(all(feature = "vsock", feature = "rgb-validation", target_os = "linux"))]
fn pin_host_to_loopback(host: &str) -> std::io::Result<()> {
    use std::io::Write;
    let existing = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    if existing
        .lines()
        .any(|l| l.split_whitespace().any(|tok| tok == host))
    {
        return Ok(());
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/etc/hosts")?;
    writeln!(f, "127.0.0.1 {host}")
}

/// The raw `BITCOIN_NETWORK` value, defaulted. Kept as a string because the
/// SPV chain parses it with its own network enum.
pub fn bitcoin_network_str() -> String {
    std::env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "bitcoin".into())
}

/// Map `BITCOIN_NETWORK` onto a `bitcoin::Network`. An unknown value warns and
/// falls back to mainnet rather than refusing to boot.
pub fn resolve_bitcoin_network(bitcoin_network_str: &str) -> bitcoin::Network {
    let bitcoin_network = match bitcoin_network_str {
        "bitcoin" | "mainnet" => bitcoin::Network::Bitcoin,
        "testnet" | "testnet3" => bitcoin::Network::Testnet,
        "signet" => bitcoin::Network::Signet,
        "regtest" => bitcoin::Network::Regtest,
        other => {
            tracing::warn!("unknown BITCOIN_NETWORK '{other}', defaulting to mainnet");
            bitcoin::Network::Bitcoin
        }
    };
    tracing::info!(%bitcoin_network_str, "bitcoin network configured");
    bitcoin_network
}

/// Log what the operator pinned, loudly when it is half-set.
///
/// A partially configured bridge is a botched production config: `SignEvm`
/// fails closed on it, and the boot gate in `main` turns it fatal in a
/// production build. This only makes it visible first.
pub fn log_bridge_config(bridge_config: &BridgeConfig) {
    // Production deployments must set EVM_CHAIN_ID, EVM_PROXY_CONTRACT_ADDRESS
    // and RGB_ASSET_ID. A misconfigured production enclave is detectable
    // externally via the attestation bundle.
    if bridge_config.is_configured() {
        tracing::info!(
            chain_id = bridge_config.chain_id,
            bridge_contract = %hex::encode(bridge_config.bridge_contract),
            rgb_asset_id = %bridge_config.rgb_asset_id,
            "bridge config pinned from env"
        );
    } else if bridge_config.is_partially_configured() {
        // Some-but-not-all pin fields set: a botched production config. SignEvm
        // fails closed on this; log it before the boot
        // gate below turns it fatal in a production build.
        tracing::error!(
            chain_id = bridge_config.chain_id,
            bridge_contract = %hex::encode(bridge_config.bridge_contract),
            rgb_asset_id = %bridge_config.rgb_asset_id,
            "bridge config PARTIALLY set - EVM_CHAIN_ID / EVM_PROXY_CONTRACT_ADDRESS / RGB_ASSET_ID must all \
             be set (non-zero) or all unset; SignEvm will refuse to sign with this ambiguous pin"
        );
    } else {
        tracing::warn!(
        "bridge config unconfigured (EVM_CHAIN_ID / EVM_PROXY_CONTRACT_ADDRESS / RGB_ASSET_ID unset) - \
         SignEvm cross-check will fall back to legacy behaviour and the attestation bundle \
         will commit to empty values"
    );
    }
}

/// Which EVM `FundsIn` deposit-verification source this build and deployment
/// uses, plus the Helios checkpoint when that path is selected.
///
/// Decided the same way the RPC client is built in [`build_evm_rpc_client`]:
/// no `evm-rpc` means none; `helios` plus `HELIOS_EXECUTION_RPC` means the
/// trustless path; otherwise the raw host-relayed RPC.
pub fn resolve_evm_data_source() -> (EvmDataSource, Option<[u8; 32]>) {
    #[cfg(not(feature = "evm-rpc"))]
    let out = (EvmDataSource::Disabled, None);
    #[cfg(all(feature = "evm-rpc", not(feature = "helios")))]
    let out = (EvmDataSource::RawRpc, None);
    #[cfg(all(feature = "evm-rpc", feature = "helios"))]
    let out = if std::env::var("HELIOS_EXECUTION_RPC").is_ok() {
        // The pinned weak-subjectivity checkpoint is Helios's trust root, so
        // it is committed into the attested policy: a verifier confirms which
        // checkpoint the enclave synced from, not just that it is in Helios
        // mode. A missing or malformed value yields `None`, and the boot
        // gate in `main` then refuses to boot.
        let checkpoint = std::env::var("HELIOS_CHECKPOINT")
            .ok()
            .and_then(|s| hex::decode(s.strip_prefix("0x").unwrap_or(&s)).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok());
        (EvmDataSource::HeliosVerified, checkpoint)
    } else {
        (EvmDataSource::RawRpc, None)
    };
    out
}

/// Say which posture was resolved. This is what gets committed into the
/// attestation `user_data`, so it belongs in the boot log.
pub fn log_policy(policy: &SecurityPolicy) {
    match policy {
        SecurityPolicy::Production(p) => tracing::info!(
            chain_id = p.chain_id,
            allow_vanilla_psbt = p.allow_vanilla_psbt,
            evm_source = ?p.evm_source,
            funds_in_contract = %hex::encode(p.funds_in_contract),
            evm_min_confirmations = p.evm_min_confirmations,
            btc_source = ?p.btc_source,
            "resolved PRODUCTION security policy (committed into attestation user_data)"
        ),
        SecurityPolicy::Development { reason } => tracing::warn!(
            ?reason,
            "resolved DEVELOPMENT security policy - this is NOT a production bridge signer"
        ),
    }
}

/// Legacy/dev fallback for the donor-side cloning secret.
///
/// The supported path is the `InitializeKey` `cloning_secret` field, which
/// never lands in the EIF or the PCRs. Never logged; `SecretBox` zeroizes it.
pub fn install_env_cloning_secret(state: &EnclaveState) {
    // `UTEXO_CLONING_SECRET` must not be baked into a release EIF, and is
    // needed only by enclaves that serve `GetClone`.
    if let Ok(secret) = std::env::var("UTEXO_CLONING_SECRET") {
        if !secret.is_empty() {
            if let Err(e) = state.set_donor_cloning_secret(secret) {
                tracing::error!("failed to set donor cloning secret: {e}");
            } else {
                tracing::warn!(
                    "donor cloning secret configured from UTEXO_CLONING_SECRET env \
                 (legacy fallback; prefer the InitializeKey cloning_secret field)"
                );
            }
        }
    }
}

/// Start every vsock-to-TCP forwarder this build needs.
///
/// No-op off Linux or without `vsock`. Untrusted egress in every case - the
/// host relays these bytes; see `vsock_forwarder`'s trust-boundary note.
pub fn start_vsock_forwarders() {
    // The indexer forwarder lets the in-enclave witness resolver reach the
    // host-side indexer. The host must run:
    //   vsock-proxy <ESPLORA_VSOCK_PORT> <indexer-host> <indexer-port>
    // 127.0.0.1:<local_port> is forwarded to vsock:<vsock_port>. For an Electrum
    // ssl:// endpoint we listen on the URL's own port and pin its hostname to
    // 127.0.0.1 in /etc/hosts, so TLS terminates inside the enclave against the
    // real server cert and the host relays ciphertext only.
    #[cfg(all(feature = "vsock", target_os = "linux"))]
    {
        // Esplora egress is only needed by the RGB/BTC stack (consignment
        // resolver + SPV). A `ccd`-only build starts no Esplora forwarder.
        #[cfg(feature = "rgb-validation")]
        {
            let vsock_port: u32 = std::env::var("ESPLORA_VSOCK_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8001);
            let (local_port, host_pin) = forwarder_target(&indexer_url_from_env());
            if let Some(host) = host_pin {
                match pin_host_to_loopback(&host) {
                    Ok(()) => tracing::info!(
                        "pinned {host} -> 127.0.0.1 for in-enclave TLS over the vsock forwarder"
                    ),
                    Err(e) => tracing::error!("failed to pin {host} in /etc/hosts: {e}"),
                }
            }
            tracing::info!(
            local_port,
            vsock_port,
            "starting indexer vsock forwarder (host must run: vsock-proxy {vsock_port} <indexer-host> <indexer-port>)"
        );
            if let Err(e) = crate::vsock_forwarder::start_forwarder(local_port, vsock_port) {
                tracing::error!("failed to start vsock forwarder: {e}");
            }
        }

        // Second forwarder for the EVM JSON-RPC used by in-enclave FundsIn
        // verification. Distinct loopback/vsock ports from Esplora
        // (3443/8001). Untrusted, host-controlled egress boundary;
        // the host must run: vsock-proxy <EVM_RPC_VSOCK_PORT> <evm-rpc-host> <port>.
        #[cfg(feature = "evm-rpc")]
        {
            let evm_vsock_port: u32 = std::env::var("EVM_RPC_VSOCK_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8002);
            tracing::info!(
            evm_vsock_port,
            "starting EVM RPC vsock forwarder (host must run: vsock-proxy {evm_vsock_port} <evm-rpc-host> <evm-rpc-port>)"
        );
            if let Err(e) = crate::vsock_forwarder::start_forwarder(3444, evm_vsock_port) {
                tracing::error!("failed to start EVM RPC vsock forwarder: {e}");
            }
        }

        // Helios execution + consensus RPC forwarders (trustless EVM
        // verification). Helios verifies these UNTRUSTED upstreams against a
        // pinned checkpoint. Local ports mirror HeliosConfig defaults
        // (18545/18550); the host must run one vsock-proxy per upstream.
        #[cfg(feature = "helios")]
        {
            let exec_local: u16 = std::env::var("HELIOS_EXECUTION_LOCAL_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(18545);
            let exec_vsock: u32 = std::env::var("HELIOS_EXECUTION_VSOCK_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8003);
            let cons_local: u16 = std::env::var("HELIOS_CONSENSUS_LOCAL_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(18550);
            let cons_vsock: u32 = std::env::var("HELIOS_CONSENSUS_VSOCK_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8004);
            tracing::info!(
                exec_local,
                exec_vsock,
                cons_local,
                cons_vsock,
                "starting Helios execution + consensus vsock forwarders"
            );
            if let Err(e) = crate::vsock_forwarder::start_forwarder(exec_local, exec_vsock) {
                tracing::error!("failed to start Helios execution RPC forwarder: {e}");
            }
            if let Err(e) = crate::vsock_forwarder::start_forwarder(cons_local, cons_vsock) {
                tracing::error!("failed to start Helios consensus RPC forwarder: {e}");
            }
        }
    }
}

/// Build the RGB consignment validator. Fails soft: a `None` makes the
/// handlers that need it refuse, rather than stopping the enclave booting.
#[cfg(feature = "rgb-validation")]
pub fn build_rgb_validator() -> Option<RgbValidator> {
    let indexer_url = indexer_url_from_env();
    let network = std::env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "bitcoin".into());
    match RgbValidator::new(indexer_url, &network) {
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

/// Initialise the in-enclave Bitcoin header chain, anchored to the
/// compile-time checkpoint for the active network. The chain starts empty; the
/// listener fills it via `SubmitHeaders`.
///
/// Panics on a checkpoint a release build must not run with - a placeholder,
/// a retarget-misaligned one, or a malformed `SPV_CHECKPOINT` override. Those
/// are build-time misconfigurations, and booting anyway wedges the chain.
#[cfg(feature = "rgb-validation")]
pub fn build_header_chain(bitcoin_network_str: &str) -> std::sync::Mutex<HeaderChain> {
    let spv_network = Network::from_env_str(bitcoin_network_str).unwrap_or_else(|e| {
        tracing::warn!(
            "spv: unknown BITCOIN_NETWORK '{bitcoin_network_str}' ({e}); defaulting to mainnet"
        );
        Network::Mainnet
    });
    // Compiled-in anchor, or the dev-only `SPV_CHECKPOINT` override. A
    // production-shaped build refuses to boot when that var is set, and a
    // malformed spec is fatal rather than silently ignored.
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
        // Fatal in a release build: with a placeholder checkpoint the
        // listener can never push headers that chain to anything real.
        panic!("{msg}");
    }
    if let Err(msg) = checkpoint.assert_retarget_aligned(spv_network) {
        // A misaligned PoW-network checkpoint wedges the chain at the first
        // retarget boundary above it, since the epoch-start lookup falls
        // below the checkpoint. A build-time misconfiguration.
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
/// The URL must be the loopback forwarder. Responses are host-relayed and
/// treated as evidence to verify, never as trusted input. A `None` client
/// makes bridge signing fail closed; it never downgrades to an unverified
/// path after a Helios sync failure.
#[cfg(feature = "evm-rpc")]
pub fn build_evm_rpc_client(
    bridge_config: &BridgeConfig,
    cfg: &crate::config::EvmRpcConfig,
) -> Option<Box<dyn crate::networks::evm::events::EvmReceiptProvider + Send + Sync>> {
    // Only the Helios path reads the pinned chain id.
    #[cfg(not(feature = "helios"))]
    let _ = bridge_config;

    use crate::networks::evm::events::{AlloyEvmClient, EvmReceiptProvider};
    type Boxed = Box<dyn EvmReceiptProvider + Send + Sync>;

    // Raw alloy provider: host-relayed, unverified.
    let build_alloy = || -> Option<Boxed> {
        match AlloyEvmClient::new(&cfg.rpc_url) {
            Ok(c) => {
                tracing::info!(
                    rpc_url = %cfg.rpc_url,
                    min_confirmations = cfg.min_confirmations,
                    "EVM FundsIn verification: raw alloy path (host-relayed/unverified)"
                );
                Some(Box::new(c) as Boxed)
            }
            Err(e) => {
                tracing::error!("failed to init EVM RPC client: {e}");
                None
            }
        }
    };

    // Runtime-selectable: HELIOS_EXECUTION_RPC set selects the
    // Helios-verified path, else raw alloy. Fail closed on the selected
    // provider - a Helios sync failure leaves the client unset so bridge
    // signing refuses, never downgrading to the unverified path.
    #[cfg(feature = "helios")]
    let client: Option<Boxed> = match crate::config::HeliosConfig::from_env() {
        Some(hcfg) => {
            // Pass the pinned EVM_CHAIN_ID so Helios rejects a
            // HELIOS_NETWORK inconsistent with it (predicate 1).
            match crate::networks::evm::events::HeliosEvmClient::new(&hcfg, bridge_config.chain_id)
            {
                Ok(c) => {
                    tracing::info!(
                        network = %hcfg.network,
                        min_confirmations = cfg.min_confirmations,
                        "EVM FundsIn verification: Helios-verified path (trustless)"
                    );
                    Some(Box::new(c) as Boxed)
                }
                Err(e) => {
                    tracing::error!(
                        "Helios client init/sync failed: {e} - bridge signing will fail closed"
                    );
                    None
                }
            }
        }
        None => build_alloy(),
    };
    #[cfg(not(feature = "helios"))]
    let client: Option<Boxed> = build_alloy();

    client
}
