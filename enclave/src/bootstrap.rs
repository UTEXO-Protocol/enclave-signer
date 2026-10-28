//! Boot sequence, one step per function. `main.rs` calls them in order.
//! Nothing in this module handles a request.

use crate::config::BridgeConfig;
#[cfg(feature = "evm-rpc")]
use crate::config::EvmRpcTls;
use crate::networks::rgb::spv::Network;
#[cfg(feature = "spv")]
use crate::networks::rgb::spv::{
    resolve_checkpoint, CheckpointSource, HeaderChain, CHECKPOINT_ENV,
};
#[cfg(feature = "rgb-validation")]
use crate::networks::rgb::validation::RgbValidator;
use crate::policy::SecurityPolicy;
#[cfg(feature = "evm-rpc")]
use crate::policy::{EvmDataSource, EvmRpcTlsPin};
use crate::state::EnclaveState;

/// Install the tracing subscriber. `RUST_LOG` picks the filter.
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}

/// Add each missing `addr host` line to the hosts file at `path`, so the
/// connection to `host` goes to its local vsock forwarder and TLS still checks
/// the real certificate of `host`. All lines land in one rename, or none do.
#[cfg(any(test, all(feature = "vsock", target_os = "linux")))]
pub fn pin_hosts(
    path: &std::path::Path,
    entries: &[(std::net::Ipv4Addr, &str)],
) -> std::io::Result<()> {
    let existing = match std::fs::read_to_string(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        other => other?,
    };
    let missing: String = entries
        .iter()
        .map(|(addr, host)| format!("{addr} {host}\n"))
        .filter(|line| !existing.lines().any(|l| l.trim() == line.trim_end()))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let sep = if existing.is_empty() || existing.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    std::fs::write(&tmp, format!("{existing}{sep}{missing}"))?;
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
    if cfg!(all(feature = "rgb-validation", not(feature = "spv"))) {
        tracing::warn!("public-signet indexer validation: Bitcoin finality is trusted from the indexer; SPV and BtcRelay agreement checks are disabled");
    } else if bridge_config.btc_relay_mode == crate::config::BtcRelayMode::None {
        tracing::warn!(
            "{}=none: fundsOut relay commitments are NOT verified (local stand without a \
             BtcRelay); heights, anchor and freshness are still bound",
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
#[cfg(feature = "evm-rpc")]
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
                 (legacy fallback; prefer the InitializeKey cloning_secret field)"
                );
            }
        }
    }
}

/// Build the BFA schema rules now, so an inconsistent built-in schema stops
/// the boot (the build panics) and not a request.
#[cfg(feature = "rgb-validation")]
pub fn load_schema_rules() {
    std::sync::LazyLock::force(&crate::networks::rgb::validation::BFA_RULES);
}

/// Build the RGB consignment validator for the Electrum URL set at launch.
/// `None` makes the launch fail.
#[cfg(feature = "rgb-validation")]
pub fn build_rgb_validator(indexer_url: String) -> Option<RgbValidator> {
    match RgbValidator::new(indexer_url, &bitcoin_network_str()) {
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
#[cfg(feature = "spv")]
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

/// Shared context storage only: builds without SPV never accept headers.
/// Anchor the unused empty chain at public signet genesis, not the custom
/// signet checkpoint. No SPV_CHECKPOINT is read in this mode.
#[cfg(all(feature = "rgb-validation", not(feature = "spv")))]
pub fn build_header_chain(
    network: Network,
) -> std::sync::Mutex<crate::networks::rgb::spv::HeaderChain> {
    use crate::networks::rgb::spv::{Checkpoint, HeaderChain};
    use bitcoin::hashes::Hash;
    assert_eq!(
        network,
        Network::Signet,
        "RGB validation without SPV requires public signet"
    );
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Signet);
    tracing::warn!("public-signet indexer validation: SPV disabled; Bitcoin confirmations are trusted from the indexer");
    std::sync::Mutex::new(HeaderChain::new(
        network,
        Checkpoint {
            height: 0,
            hash: genesis.block_hash().to_byte_array(),
            bits: genesis.header.bits.to_consensus(),
            time: genesis.header.time,
            is_real: true,
            chain_work: None,
        },
    ))
}

/// Build the in-enclave EVM RPC client for independent `FundsIn` verification.
///
/// The client reaches the RPC through the loopback forwarder, with TLS to the
/// pinned host and CA. `None` makes the launch fail. There is no fallback to an
/// unverified path.
#[cfg(feature = "evm-rpc")]
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    use super::pin_hosts;

    const PINS: [(Ipv4Addr, &str); 2] = [
        (Ipv4Addr::new(127, 0, 0, 1), "electrum.test"),
        (Ipv4Addr::new(127, 0, 0, 2), "kms.eu-west-1.amazonaws.com"),
    ];

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
    fn pins_are_written_once_and_together() {
        let path = hosts("pins_are_written_once_and_together");
        pin_hosts(&path, &PINS).unwrap();
        let first = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            first,
            "127.0.0.1 localhost\n127.0.0.1 electrum.test\n127.0.0.2 kms.eu-west-1.amazonaws.com\n"
        );
        pin_hosts(&path, &PINS).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
    }

    #[test]
    fn a_failed_pin_leaves_the_file_unchanged() {
        let path = hosts("a_failed_pin_leaves_the_file_unchanged");
        let before = std::fs::read(&path).unwrap();
        // A directory in the way makes the write fail, also as root.
        let tmp = path.with_extension("tmp");
        std::fs::create_dir(&tmp).unwrap();
        assert!(pin_hosts(&path, &PINS).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_dir(&tmp).unwrap();
        pin_hosts(&path, &PINS).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        for (addr, host) in PINS {
            assert_eq!(after.matches(&format!("{addr} {host}")).count(), 1);
        }
    }
}
