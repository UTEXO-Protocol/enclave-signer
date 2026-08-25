//! Enclave-side bridge configuration pinned at boot.
//!
//! The chain, MultisigProxy contract (`EVM_PROXY_CONTRACT_ADDRESS`), and RGB
//! asset this enclave will sign for are read from the environment once at
//! startup, then folded into the attestation `user_data` commitment (see
//! `canonical_pubkey_bundle` in `server.rs`). So:
//!
//!   1. a verifier fetching `GetAttestedPublicKey` can prove the enclave was
//!      provisioned for a specific (chain_id, contract, asset) tuple;
//!   2. `SignEvm` cross-checks the listener-supplied fields against this config
//!      and rejects on mismatch.
//!
//! Production must set all three env vars. Dev / mock builds may leave them
//! unset, which makes the config "unconfigured": the cross-check is skipped and
//! the bundle commits to empty values, so a missing-env production deploy is
//! externally visible.

use crate::error::{EnclaveError, Result};

/// Default aggregate request-size caps for the RGB signing path, used when the
/// matching env var is unset (`MAX_CONSIGNMENT_BYTES`, `MAX_MERKLE_PROOFS`,
/// `MAX_TOTAL_PROOF_BYTES`). Defense-in-depth DoS bounds on the serial signing
/// path; consignment size is also hard-capped by the 4 MB wire frame.
///
/// Real USDT-swap consignments are a few KB, so 1 MiB is generous.
pub const DEFAULT_MAX_CONSIGNMENT_BYTES: usize = 1024 * 1024;
/// Default cap on the number of Merkle proofs a source may carry (env
/// `MAX_MERKLE_PROOFS`). A consignment anchors a handful of witness txs.
pub const DEFAULT_MAX_MERKLE_PROOFS: usize = 256;
/// Default cap on total variable-length proof bytes (txids + Merkle-path
/// siblings) across all proofs (env `MAX_TOTAL_PROOF_BYTES`), bounding aggregate
/// Merkle-hashing work independently of the per-proof depth cap.
pub const DEFAULT_MAX_TOTAL_PROOF_BYTES: usize = 128 * 1024;

/// Bridge config pinned at enclave boot from env. See module docs.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub chain_id: u64,
    /// MultisigProxy contract pinned for the EVM signing cross-check (env
    /// `EVM_PROXY_CONTRACT_ADDRESS`), the EIP-712 `verifyingContract` stamped
    /// into every funds-out request. Not the bridge entry contract that emits
    /// `FundsIn` - that is `funds_in_contract`. The field keeps the legacy name
    /// `bridge_contract` for wire/attestation-bundle stability.
    pub bridge_contract: [u8; 20],
    pub rgb_asset_id: String,
    /// Operator-pinned allowed destination for **gas-key** transactions
    /// (`GAS_TX_ALLOWED_TO`). When set, `SignRawDigest` only signs a gas tx
    /// whose `to` equals this address. `None` =
    /// unset, which fails gas-tx signing closed in release builds.
    ///
    /// A gas tx must carry `value == 0`, except for the payable
    /// `lzFundsOutCall` - which also requires this pin to equal
    /// [`Self::bridge_contract`] and the value to fit under
    /// [`Self::gas_tx_max_value_wei`]. See `networks::evm::gas_tx`.
    ///
    /// The destination is the bridge or an operational contract the gas EOA
    /// calls. Safety does not rest on it being a plain wallet:
    /// [`gas_tx_allowed_selectors`](Self::gas_tx_allowed_selectors) bounds
    /// which functions may be called, and the gas/fee caps bound what it can
    /// burn.
    ///
    /// The whole gas-tx rule is folded into the attestation `user_data`
    /// commitment via [`crate::policy::SecurityPolicy`].
    pub gas_tx_allowed_to: Option<[u8; 20]>,
    /// Operator-pinned upper bound on a gas tx's `gasLimit` (`GAS_TX_MAX_GAS_LIMIT`).
    /// `0` = unset, which - like [`gas_tx_allowed_to`](Self::gas_tx_allowed_to) -
    /// fails gas-tx signing closed. With [`gas_tx_max_fee_per_gas`](Self::gas_tx_max_fee_per_gas)
    /// it caps the most ETH a signed gas tx can burn as fees (`gasLimit *
    /// maxFeePerGas`), bounding the fee-griefing residual.
    pub gas_tx_max_gas_limit: u64,
    /// Operator-pinned upper bound (wei) on a gas tx's per-gas fee
    /// (`GAS_TX_MAX_FEE_PER_GAS`): `maxFeePerGas` and `maxPriorityFeePerGas` for
    /// EIP-1559, `gasPrice` for legacy. `0` = unset, which fails gas-tx signing
    /// closed. `u128` holds any realistic wei fee (a value wider than that is
    /// rejected as exceeding the cap). See [`gas_tx_max_gas_limit`](Self::gas_tx_max_gas_limit).
    pub gas_tx_max_fee_per_gas: u128,
    /// Operator-pinned allowlist of 4-byte function selectors a gas tx's
    /// calldata may invoke (`GAS_TX_ALLOWED_SELECTORS`, comma-separated hex).
    /// Every signed gas tx must lead with one; empty calldata is refused, since
    /// it would still invoke the destination's fallback/receive. Empty = unset,
    /// which refuses all gas-tx signing.
    pub gas_tx_allowed_selectors: Vec<[u8; 4]>,
    /// Operator-pinned ceiling (wei) on the native value a single gas tx may
    /// carry (`GAS_TX_MAX_VALUE_WEI`). `None` = unset, which refuses any
    /// non-zero value, so a deployment without the LayerZero release path needs
    /// no new configuration.
    ///
    /// The fee is not a field of the `TeeLzFundsOut` payload the proxy
    /// verifies, so nothing binds it to the release it pays for; this ceiling
    /// bounds the blast radius until that exists.
    pub gas_tx_max_value_wei: Option<u128>,
    /// Operator-pinned cap (sats) on the total input value spent by a plain-BTC
    /// PSBT (`BTC_MAX_TOTAL_SATS`). `0` = unset, and a production build then
    /// refuses plain-BTC signing. Bounds the blast radius including value routed
    /// to miner fees, on top of the destination rule, which needs no
    /// configuration (see [`crate::networks::rgb::btc_ownership`]).
    ///
    /// Whether the path is enabled at all
    /// ([`allows_vanilla_btc`](Self::allows_vanilla_btc)) is attested as
    /// `allow_vanilla_psbt` in the security policy.
    ///
    /// The old `BTC_ALLOWED_SCRIPTS` output allowlist was removed: the scripts
    /// to pin derive from a seed that only exists after boot, and enclave env is
    /// measured into PCR0, so baking them in changes the identity that seed is
    /// bound to.
    pub btc_max_total_sats: u64,
    /// Address expected to emit `FundsIn`/`BridgeFundsIn` (env
    /// `FUNDS_IN_CONTRACT`), falling back to `bridge_contract` when unset. The
    /// deposit event comes from the bridge entry contract while
    /// `EVM_PROXY_CONTRACT_ADDRESS` pins the MultisigProxy, and one pin cannot
    /// serve both lookups. These two contracts differ on this deployment, so
    /// `FUNDS_IN_CONTRACT` must be set explicitly.
    pub funds_in_contract: [u8; 20],
    /// Aggregate request-size caps for the RGB signing path, operator-tunable
    /// via env (`MAX_CONSIGNMENT_BYTES` / `MAX_MERKLE_PROOFS` /
    /// `MAX_TOTAL_PROOF_BYTES`); each defaults to its `DEFAULT_*` constant when
    /// unset (or set to 0). Defense-in-depth DoS bounds, not attested - like the
    /// operational pins above. See [`DEFAULT_MAX_CONSIGNMENT_BYTES`].
    pub max_consignment_bytes: usize,
    pub max_merkle_proofs: usize,
    pub max_total_proof_bytes: usize,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            chain_id: 0,
            bridge_contract: [0u8; 20],
            rgb_asset_id: String::new(),
            gas_tx_allowed_to: None,
            gas_tx_max_gas_limit: 0,
            gas_tx_max_fee_per_gas: 0,
            gas_tx_allowed_selectors: Vec::new(),
            gas_tx_max_value_wei: None,
            btc_max_total_sats: 0,
            funds_in_contract: [0u8; 20],
            max_consignment_bytes: DEFAULT_MAX_CONSIGNMENT_BYTES,
            max_merkle_proofs: DEFAULT_MAX_MERKLE_PROOFS,
            max_total_proof_bytes: DEFAULT_MAX_TOTAL_PROOF_BYTES,
        }
    }
}

impl BridgeConfig {
    /// Load from `EVM_CHAIN_ID` (decimal), `EVM_PROXY_CONTRACT_ADDRESS`
    /// (0x-prefixed or bare 40-hex), `RGB_ASSET_ID` (string). Any missing/invalid
    /// field degrades to its zero/empty value; `is_configured()` reports whether
    /// the operator supplied anything at all.
    pub fn from_env() -> Self {
        let chain_id = std::env::var("EVM_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        let bridge_contract = std::env::var("EVM_PROXY_CONTRACT_ADDRESS")
            .ok()
            .and_then(|s| parse_eth_address(&s).ok())
            .unwrap_or([0u8; 20]);

        let rgb_asset_id = std::env::var("RGB_ASSET_ID").unwrap_or_default();

        let gas_tx_allowed_to = std::env::var("GAS_TX_ALLOWED_TO")
            .ok()
            .and_then(|s| parse_eth_address(&s).ok());

        // Gas-tx fee/gas ceilings. Unset (`0`) fails the gas path
        // closed, so a malformed value degrading to 0 is safe.
        let gas_tx_max_gas_limit = std::env::var("GAS_TX_MAX_GAS_LIMIT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        let gas_tx_max_fee_per_gas = std::env::var("GAS_TX_MAX_FEE_PER_GAS")
            .ok()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);

        // Comma-separated 4-byte hex selectors, parsed independently. A malformed
        // entry is dropped rather than poisoning the list, but logged so an
        // operator typo shows up at boot.
        let gas_tx_allowed_selectors = std::env::var("GAS_TX_ALLOWED_SELECTORS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .filter_map(|part| {
                        let hexpart = part.strip_prefix("0x").unwrap_or(part);
                        match hex::decode(hexpart)
                            .ok()
                            .and_then(|bytes| <[u8; 4]>::try_from(bytes.as_slice()).ok())
                        {
                            Some(sel) => Some(sel),
                            None => {
                                tracing::warn!(
                                    entry = %part,
                                    "GAS_TX_ALLOWED_SELECTORS: dropping malformed selector \
                                     (expected exactly 4 hex bytes, e.g. 0xdeadbeef)"
                                );
                                None
                            }
                        }
                    })
                    .collect::<Vec<[u8; 4]>>()
            })
            .unwrap_or_default();

        // Unset or unparseable stays `None`: a typo must not widen the ceiling.
        let gas_tx_max_value_wei = std::env::var("GAS_TX_MAX_VALUE_WEI")
            .ok()
            .and_then(|s| s.trim().parse::<u128>().ok());

        let btc_max_total_sats = std::env::var("BTC_MAX_TOTAL_SATS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        // Separate FundsIn event-emitter pin; defaults to `bridge_contract`.
        let funds_in_contract = std::env::var("FUNDS_IN_CONTRACT")
            .ok()
            .and_then(|s| parse_eth_address(&s).ok())
            .unwrap_or(bridge_contract);

        // Migration guard: a deployment pinning only
        // GAS_TX_ALLOWED_TO refuses every gas tx until both caps are set.
        // Surfaced at boot rather than as a per-request rejection.
        if gas_tx_allowed_to.is_some() && (gas_tx_max_gas_limit == 0 || gas_tx_max_fee_per_gas == 0)
        {
            tracing::warn!(
                "GAS_TX_ALLOWED_TO is set but GAS_TX_MAX_GAS_LIMIT and/or GAS_TX_MAX_FEE_PER_GAS \
                 is unset - gas-tx (SignRawDigest) signing will FAIL CLOSED until both caps are \
                 pinned"
            );
        }

        // Aggregate request-size caps (operator-tunable, defense-in-depth). An
        // unset, unparseable, or zero value falls back to the default.
        let parse_cap = |name: &str, default: usize| -> usize {
            std::env::var(name)
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|&n| n > 0)
                .unwrap_or(default)
        };
        let max_consignment_bytes =
            parse_cap("MAX_CONSIGNMENT_BYTES", DEFAULT_MAX_CONSIGNMENT_BYTES);
        let max_merkle_proofs = parse_cap("MAX_MERKLE_PROOFS", DEFAULT_MAX_MERKLE_PROOFS);
        let max_total_proof_bytes =
            parse_cap("MAX_TOTAL_PROOF_BYTES", DEFAULT_MAX_TOTAL_PROOF_BYTES);

        Self {
            chain_id,
            bridge_contract,
            rgb_asset_id,
            gas_tx_allowed_to,
            gas_tx_max_gas_limit,
            gas_tx_max_fee_per_gas,
            gas_tx_allowed_selectors,
            gas_tx_max_value_wei,
            btc_max_total_sats,
            funds_in_contract,
            max_consignment_bytes,
            max_merkle_proofs,
            max_total_proof_bytes,
        }
    }

    /// True only when all three fields are non-zero / non-empty. Only a
    /// fully-pinned config authorises bridge signing.
    ///
    /// An AND, not an OR: under an OR a zero `chain_id` made the enclave
    /// permanently un-signable while still claiming configured, and a zero
    /// `bridge_contract` let an EVM request for the zero address match the pin.
    ///
    /// A fully-empty config (dev / mock builds) still degrades to the legacy
    /// trust-the-request path; a partial config is a misconfiguration, see
    /// [`is_partially_configured`](Self::is_partially_configured).
    pub fn is_configured(&self) -> bool {
        self.chain_id != 0 && self.bridge_contract != [0u8; 20] && !self.rgb_asset_id.is_empty()
    }

    /// True when some but not all pin fields are set: a botched production
    /// config, distinct from a fully-empty one that selects the dev path.
    /// Callers fail closed rather than falling back to listener-trusting mode.
    pub fn is_partially_configured(&self) -> bool {
        let any = self.chain_id != 0
            || self.bridge_contract != [0u8; 20]
            || !self.rgb_asset_id.is_empty();
        any && !self.is_configured()
    }

    /// Whether the plain-BTC (vanilla / create_utxo) signing path is
    /// authorised, gated solely by the `BTC_MAX_TOTAL_SATS` cap: the output
    /// destination rule needs no configuration
    /// ([`crate::networks::rgb::btc_ownership`]).
    ///
    /// [`crate::policy::SecurityPolicy`] records this as `allow_vanilla_psbt`
    /// and `btc_crosscheck::validate_btc_request` enforces it per request. The
    /// two must agree.
    pub fn allows_vanilla_btc(&self) -> bool {
        self.btc_max_total_sats != 0
    }
}

/// Parse `0xABCD...` (40 hex chars) or bare 40-hex into 20 bytes. Shared by the
/// `EVM_PROXY_CONTRACT_ADDRESS`, `GAS_TX_ALLOWED_TO`, and `FUNDS_IN_CONTRACT`
/// address pins, so the error text is address-agnostic.
fn parse_eth_address(s: &str) -> Result<[u8; 20]> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(stripped)
        .map_err(|e| EnclaveError::InvalidRequest(format!("eth address not hex: {e}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        EnclaveError::InvalidRequest(format!(
            "eth address must decode to 20 bytes, got {}",
            v.len()
        ))
    })
}

/// EVM JSON-RPC config for in-enclave `FundsIn` event verification,
/// loaded at boot when the `evm-rpc` feature is built.
///
/// Operational plumbing, not part of the committed identity: like
/// [`BridgeConfig::funds_in_contract`] it is not folded into the attestation
/// bundle. The choice of EVM data source (raw RPC vs Helios) is attested, as
/// `evm_source` in the security policy; this URL is not.
///
/// Trust boundary: `rpc_url` must be loopback. The enclave reaches the EVM RPC
/// only through the vsock forwarder ([`crate::vsock_forwarder`]), so responses
/// are relayed by the untrusted host. `verify_funds_in_event` treats them as
/// evidence and fails closed; full trustlessness needs Helios.
#[cfg(feature = "evm-rpc")]
#[derive(Debug, Clone)]
pub struct EvmRpcConfig {
    /// Loopback URL of the in-enclave EVM RPC forwarder
    /// (`EVM_RPC_URL`, default `http://127.0.0.1:3444`).
    pub rpc_url: String,
    /// Minimum confirmation depth a `FundsIn` receipt must have, measured
    /// against the RPC head block (`EVM_MIN_CONFIRMATIONS`, default 12).
    pub min_confirmations: u64,
}

#[cfg(feature = "evm-rpc")]
impl EvmRpcConfig {
    /// Default loopback RPC URL - the enclave side of the EVM vsock forwarder.
    const DEFAULT_RPC_URL: &'static str = "http://127.0.0.1:3444";
    /// Default confirmation depth (~a safe head distance for most EVM chains).
    const DEFAULT_MIN_CONFIRMATIONS: u64 = 12;

    /// Load from `EVM_RPC_URL` and `EVM_MIN_CONFIRMATIONS`. Both fall back to
    /// safe defaults. A non-loopback `EVM_RPC_URL` is rejected back to the
    /// default and logged: routing EVM RPC anywhere but the vsock forwarder
    /// would bypass the only sanctioned egress path.
    pub fn from_env() -> Self {
        let rpc_url = match std::env::var("EVM_RPC_URL") {
            Ok(url) if is_loopback_url(&url) => url,
            Ok(url) => {
                tracing::error!(
                    %url,
                    "EVM_RPC_URL is not loopback - ignoring and using the default vsock-forwarder \
                     URL; the enclave must reach the EVM RPC only via the loopback forwarder"
                );
                Self::DEFAULT_RPC_URL.to_string()
            }
            Err(_) => Self::DEFAULT_RPC_URL.to_string(),
        };
        let min_confirmations = std::env::var("EVM_MIN_CONFIRMATIONS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(Self::DEFAULT_MIN_CONFIRMATIONS);
        Self {
            rpc_url,
            min_confirmations,
        }
    }
}

#[cfg(feature = "evm-rpc")]
impl Default for EvmRpcConfig {
    fn default() -> Self {
        Self {
            rpc_url: Self::DEFAULT_RPC_URL.to_string(),
            min_confirmations: Self::DEFAULT_MIN_CONFIRMATIONS,
        }
    }
}

/// True if `url`'s host is exactly a loopback literal (`127.0.0.1`, `[::1]`, or
/// `localhost`). Narrow and dependency-free. Matches the host exactly, after
/// stripping scheme, userinfo, path, and port, so `127.0.0.1.evil.com` is not
/// treated as loopback.
#[cfg(feature = "evm-rpc")]
fn is_loopback_url(url: &str) -> bool {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    // Drop path/query/fragment, then any `userinfo@` prefix.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // Strip the port. IPv6 literals are bracketed (`[::1]:8545`), so split off
    // the `]` first; otherwise the host is everything before the first `:`.
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        match rest.split_once(']') {
            // Valid IPv6 authority: `]` is followed by nothing or `:port`.
            Some((inner, after)) => {
                return inner == "::1" && (after.is_empty() || after.starts_with(':'))
            }
            None => hostport,
        }
    } else {
        hostport.split(':').next().unwrap_or(hostport)
    };
    host == "127.0.0.1" || host == "localhost"
}

/// Helios light-client config for TRUSTLESS in-enclave EVM event
/// verification, loaded at boot when the `helios` feature is built.
///
/// Selection is runtime: [`HeliosConfig::from_env`] returns `Some` only when
/// `HELIOS_EXECUTION_RPC` is set, which selects the Helios-verified provider
/// over the raw alloy path. Like [`EvmRpcConfig`] the URLs must be
/// loopback; Helios treats those upstreams as untrusted and verifies them
/// against the pinned checkpoint.
#[cfg(feature = "helios")]
#[derive(Debug, Clone)]
pub struct HeliosConfig {
    /// Untrusted execution RPC Helios verifies against (`HELIOS_EXECUTION_RPC`,
    /// required - typically the local exec forwarder `http://127.0.0.1:18545`).
    /// Its presence is the signal to select the Helios-verified path.
    pub execution_rpc: String,
    /// Consensus (beacon) RPC for light-client sync (`HELIOS_CONSENSUS_RPC`,
    /// loopback forwarder, default `http://127.0.0.1:18550`).
    pub consensus_rpc: String,
    /// Helios network name: `mainnet` | `sepolia` | `holesky`
    /// (`HELIOS_NETWORK`, default `mainnet`).
    pub network: String,
    /// Weak-subjectivity checkpoint: 0x-prefixed 32-byte beacon block root
    /// (`HELIOS_CHECKPOINT`). Required for a trustless build - without it Helios
    /// would fall back to an untrusted community checkpoint list, which the
    /// enclave never enables. `None` here fails client init closed.
    pub checkpoint: Option<String>,
    /// Reject a checkpoint older than the safe weak-subjectivity window
    /// (`HELIOS_STRICT_CHECKPOINT_AGE`, default `true`).
    pub strict_checkpoint_age: bool,
}

#[cfg(feature = "helios")]
impl HeliosConfig {
    const DEFAULT_CONSENSUS_RPC: &'static str = "http://127.0.0.1:18550";

    /// Load from `HELIOS_*` env. Returns `None` when `HELIOS_EXECUTION_RPC` is
    /// unset (the raw alloy path is used instead). A non-loopback RPC URL is
    /// logged as an error but kept - the enclave has no direct egress, so a
    /// non-loopback URL simply won't connect.
    pub fn from_env() -> Option<Self> {
        let execution_rpc = std::env::var("HELIOS_EXECUTION_RPC").ok()?;
        warn_if_not_loopback("HELIOS_EXECUTION_RPC", &execution_rpc);

        let consensus_rpc = std::env::var("HELIOS_CONSENSUS_RPC")
            .unwrap_or_else(|_| Self::DEFAULT_CONSENSUS_RPC.to_string());
        warn_if_not_loopback("HELIOS_CONSENSUS_RPC", &consensus_rpc);

        let network = std::env::var("HELIOS_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
        let checkpoint = std::env::var("HELIOS_CHECKPOINT").ok();
        let strict_checkpoint_age = std::env::var("HELIOS_STRICT_CHECKPOINT_AGE")
            .ok()
            .map(|s| s != "false" && s != "0")
            .unwrap_or(true);

        Some(Self {
            execution_rpc,
            consensus_rpc,
            network,
            checkpoint,
            strict_checkpoint_age,
        })
    }
}

#[cfg(feature = "helios")]
fn warn_if_not_loopback(var: &str, url: &str) {
    if !is_loopback_url(url) {
        tracing::error!(
            %var, %url,
            "Helios RPC URL is not loopback - the enclave reaches upstreams only via the vsock \
             forwarder; a non-loopback URL will not connect"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_eth_address_with_prefix() {
        let a = parse_eth_address("0x0102030405060708090a0b0c0d0e0f1011121314").unwrap();
        assert_eq!(
            a,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        );
    }

    #[test]
    fn parse_eth_address_without_prefix() {
        let a = parse_eth_address("0102030405060708090a0b0c0d0e0f1011121314").unwrap();
        assert_eq!(a[0], 1);
        assert_eq!(a[19], 20);
    }

    #[test]
    fn parse_eth_address_rejects_wrong_length() {
        assert!(parse_eth_address("0xabcd").is_err());
    }

    #[test]
    fn parse_eth_address_rejects_non_hex() {
        assert!(parse_eth_address("0xzz02030405060708090a0b0c0d0e0f1011121314").is_err());
    }

    #[test]
    fn unconfigured_when_all_unset() {
        let c = BridgeConfig {
            chain_id: 0,
            bridge_contract: [0u8; 20],
            rgb_asset_id: String::new(),
            ..Default::default()
        };
        assert!(!c.is_configured());
        assert!(!c.is_partially_configured());
    }

    #[test]
    fn configured_only_when_all_three_set() {
        let c = BridgeConfig {
            chain_id: 1,
            bridge_contract: [1u8; 20],
            rgb_asset_id: "rgb:asset".into(),
            gas_tx_allowed_to: None,
            ..Default::default()
        };
        assert!(c.is_configured());
        assert!(!c.is_partially_configured());
    }

    #[test]
    fn partial_config_is_not_configured() {
        // chain_id set, contract still zero, asset set: a botched pin. The
        // OR-logic bug used to report this "configured" and then accept
        // an EVM request for the zero address.
        let c = BridgeConfig {
            chain_id: 1,
            bridge_contract: [0u8; 20],
            rgb_asset_id: "rgb:asset".into(),
            ..Default::default()
        };
        assert!(!c.is_configured());
        assert!(c.is_partially_configured());
    }

    /// Must default to the fail-closed `None` so an existing deployment keeps
    /// the old `value == 0` posture.
    #[test]
    fn gas_tx_value_ceiling_defaults_to_unset() {
        assert_eq!(BridgeConfig::default().gas_tx_max_value_wei, None);
    }

    #[test]
    fn zero_chain_id_is_not_configured() {
        let c = BridgeConfig {
            chain_id: 0,
            bridge_contract: [1u8; 20],
            rgb_asset_id: "rgb:asset".into(),
            gas_tx_allowed_to: None,
            ..Default::default()
        };
        assert!(!c.is_configured());
        assert!(c.is_partially_configured());
    }

    #[cfg(feature = "evm-rpc")]
    #[test]
    fn loopback_url_accepts_real_loopback() {
        assert!(is_loopback_url("http://127.0.0.1:3444"));
        assert!(is_loopback_url("http://127.0.0.1"));
        assert!(is_loopback_url("http://localhost:8545"));
        assert!(is_loopback_url("http://[::1]:18545/path"));
        assert!(is_loopback_url("http://[::1]"));
        assert!(is_loopback_url("http://user:pass@127.0.0.1:3444"));
    }

    #[cfg(feature = "evm-rpc")]
    #[test]
    fn loopback_url_rejects_lookalike_authorities() {
        // The old `starts_with` check accepted all of these.
        assert!(!is_loopback_url("http://127.0.0.1.evil.com"));
        assert!(!is_loopback_url("http://localhost.evil.com/rpc"));
        assert!(!is_loopback_url("http://127.0.0.1@evil.com"));
        assert!(!is_loopback_url("http://[::1].evil.com"));
        assert!(!is_loopback_url("http://10.0.0.1:8545"));
        assert!(!is_loopback_url("http://evil.com/127.0.0.1"));
    }
}
