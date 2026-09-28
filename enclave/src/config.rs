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
    /// Budget (sats) for send-RGB outputs the enclave cannot prove it controls
    /// (`RGB_MAX_UNOWNED_SATS`). The recipient's witness output is blinded, so
    /// the enclave bounds what leaves rather than identifying the payout.
    /// `0` = unset; a production build then refuses send-RGB signing.
    pub rgb_max_unowned_sats: u64,
    /// Budget (sats) for plain-BTC outputs that do not pay back into the same
    /// custody (`BTC_MAX_UNOWNED_SATS`). Covers `create_utxo` allocation dust
    /// (1000 sats each, 5 by default), which is funded out of vanilla inputs so
    /// its script is not one being spent. `0` = unset; a production build then
    /// refuses plain-BTC signing.
    pub btc_max_unowned_sats: u64,
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
            rgb_max_unowned_sats: 0,
            btc_max_unowned_sats: 0,
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

        let rgb_max_unowned_sats = std::env::var("RGB_MAX_UNOWNED_SATS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        let btc_max_unowned_sats = std::env::var("BTC_MAX_UNOWNED_SATS")
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
            rgb_max_unowned_sats,
            btc_max_unowned_sats,
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

/// `from_env` reads process-global state, so these tests serialise on one
/// mutex, set exactly the variables they need, and clear them again. The
/// only other readers of these names are the enclave binary and the
/// integration harness, both of which run in other processes.
#[cfg(test)]
mod env_tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const BRIDGE_VARS: &[&str] = &[
        "EVM_CHAIN_ID",
        "EVM_PROXY_CONTRACT_ADDRESS",
        "RGB_ASSET_ID",
        "GAS_TX_ALLOWED_TO",
        "GAS_TX_MAX_GAS_LIMIT",
        "GAS_TX_MAX_FEE_PER_GAS",
        "GAS_TX_ALLOWED_SELECTORS",
        "GAS_TX_MAX_VALUE_WEI",
        "BTC_MAX_TOTAL_SATS",
        "RGB_MAX_UNOWNED_SATS",
        "BTC_MAX_UNOWNED_SATS",
        "FUNDS_IN_CONTRACT",
        "MAX_CONSIGNMENT_BYTES",
        "MAX_MERKLE_PROOFS",
        "MAX_TOTAL_PROOF_BYTES",
        "EVM_RPC_URL",
        "EVM_MIN_CONFIRMATIONS",
    ];

    /// Holds the lock and clears every variable on construction and drop, so a
    /// failing assertion in one test cannot leak state into the next.
    struct EnvScope {
        _guard: MutexGuard<'static, ()>,
    }

    impl EnvScope {
        fn new() -> Self {
            let guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            for v in BRIDGE_VARS {
                std::env::remove_var(v);
            }
            Self { _guard: guard }
        }
        fn set(&self, pairs: &[(&str, &str)]) {
            for (k, v) in pairs {
                std::env::set_var(k, v);
            }
        }
    }

    impl Drop for EnvScope {
        fn drop(&mut self) {
            for v in BRIDGE_VARS {
                std::env::remove_var(v);
            }
        }
    }

    fn assert_is_default(c: &BridgeConfig) {
        let d = BridgeConfig::default();
        assert_eq!(c.chain_id, d.chain_id);
        assert_eq!(c.bridge_contract, d.bridge_contract);
        assert_eq!(c.rgb_asset_id, d.rgb_asset_id);
        assert_eq!(c.gas_tx_allowed_to, d.gas_tx_allowed_to);
        assert_eq!(c.gas_tx_max_gas_limit, d.gas_tx_max_gas_limit);
        assert_eq!(c.gas_tx_max_fee_per_gas, d.gas_tx_max_fee_per_gas);
        assert_eq!(c.gas_tx_allowed_selectors, d.gas_tx_allowed_selectors);
        assert_eq!(c.gas_tx_max_value_wei, d.gas_tx_max_value_wei);
        assert_eq!(c.btc_max_total_sats, d.btc_max_total_sats);
        assert_eq!(c.rgb_max_unowned_sats, d.rgb_max_unowned_sats);
        assert_eq!(c.btc_max_unowned_sats, d.btc_max_unowned_sats);
        assert_eq!(c.funds_in_contract, d.funds_in_contract);
        assert_eq!(c.max_consignment_bytes, d.max_consignment_bytes);
        assert_eq!(c.max_merkle_proofs, d.max_merkle_proofs);
        assert_eq!(c.max_total_proof_bytes, d.max_total_proof_bytes);
    }

    #[test]
    fn empty_env_is_the_default_unconfigured_config() {
        let _env = EnvScope::new();
        let c = BridgeConfig::from_env();
        assert_is_default(&c);
        assert!(!c.is_configured());
        assert!(!c.is_partially_configured());
        assert!(!c.allows_vanilla_btc());
    }

    #[test]
    fn default_caps_are_the_documented_constants() {
        let d = BridgeConfig::default();
        assert_eq!(d.max_consignment_bytes, 1024 * 1024);
        assert_eq!(d.max_merkle_proofs, 256);
        assert_eq!(d.max_total_proof_bytes, 128 * 1024);
        assert_eq!(DEFAULT_MAX_CONSIGNMENT_BYTES, d.max_consignment_bytes);
        assert_eq!(DEFAULT_MAX_MERKLE_PROOFS, d.max_merkle_proofs);
        assert_eq!(DEFAULT_MAX_TOTAL_PROOF_BYTES, d.max_total_proof_bytes);
    }

    #[test]
    fn fully_pinned_env_is_parsed_field_by_field() {
        let env = EnvScope::new();
        env.set(&[
            ("EVM_CHAIN_ID", "42161"),
            (
                "EVM_PROXY_CONTRACT_ADDRESS",
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            ("RGB_ASSET_ID", "rgb:asset-id"),
            (
                "GAS_TX_ALLOWED_TO",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            ("GAS_TX_MAX_GAS_LIMIT", "300000"),
            (
                "GAS_TX_MAX_FEE_PER_GAS",
                "340282366920938463463374607431768211455",
            ),
            (
                "GAS_TX_ALLOWED_SELECTORS",
                "0xdeadbeef, 01020304 ,,0xDEADBEEF",
            ),
            ("GAS_TX_MAX_VALUE_WEI", " 12345 "),
            ("BTC_MAX_TOTAL_SATS", "100000"),
            ("RGB_MAX_UNOWNED_SATS", "2000"),
            ("BTC_MAX_UNOWNED_SATS", "5000"),
            (
                "FUNDS_IN_CONTRACT",
                "0xcccccccccccccccccccccccccccccccccccccccc",
            ),
            ("MAX_CONSIGNMENT_BYTES", "4096"),
            ("MAX_MERKLE_PROOFS", "7"),
            ("MAX_TOTAL_PROOF_BYTES", "999"),
        ]);
        let c = BridgeConfig::from_env();
        assert_eq!(c.chain_id, 42161);
        assert_eq!(c.bridge_contract, [0xaa; 20]);
        assert_eq!(c.rgb_asset_id, "rgb:asset-id");
        assert_eq!(c.gas_tx_allowed_to, Some([0xbb; 20]));
        assert_eq!(c.gas_tx_max_gas_limit, 300_000);
        assert_eq!(c.gas_tx_max_fee_per_gas, u128::MAX);
        assert_eq!(
            c.gas_tx_allowed_selectors,
            vec![
                [0xde, 0xad, 0xbe, 0xef],
                [0x01, 0x02, 0x03, 0x04],
                [0xde, 0xad, 0xbe, 0xef]
            ],
            "entries are kept in order, trimmed, blanks dropped, case-insensitive hex"
        );
        assert_eq!(c.gas_tx_max_value_wei, Some(12_345));
        assert_eq!(c.btc_max_total_sats, 100_000);
        assert_eq!(c.rgb_max_unowned_sats, 2_000);
        assert_eq!(c.btc_max_unowned_sats, 5_000);
        assert_eq!(c.funds_in_contract, [0xcc; 20]);
        assert_eq!(c.max_consignment_bytes, 4096);
        assert_eq!(c.max_merkle_proofs, 7);
        assert_eq!(c.max_total_proof_bytes, 999);
        assert!(c.is_configured());
        assert!(!c.is_partially_configured());
        assert!(c.allows_vanilla_btc());
    }

    #[test]
    fn funds_in_contract_defaults_to_the_proxy_pin_when_unset() {
        let env = EnvScope::new();
        env.set(&[(
            "EVM_PROXY_CONTRACT_ADDRESS",
            "0x1111111111111111111111111111111111111111",
        )]);
        let c = BridgeConfig::from_env();
        assert_eq!(c.funds_in_contract, [0x11; 20]);
        // And a malformed FUNDS_IN_CONTRACT also falls back to the pin.
        env.set(&[("FUNDS_IN_CONTRACT", "not-an-address")]);
        let c = BridgeConfig::from_env();
        assert_eq!(c.funds_in_contract, [0x11; 20]);
    }

    #[test]
    fn malformed_values_degrade_to_the_fail_closed_zero_or_none() {
        let env = EnvScope::new();
        env.set(&[
            ("EVM_CHAIN_ID", "not-a-number"),
            ("EVM_PROXY_CONTRACT_ADDRESS", "0x1234"),
            ("GAS_TX_ALLOWED_TO", "0xzz"),
            ("GAS_TX_MAX_GAS_LIMIT", "-1"),
            ("GAS_TX_MAX_FEE_PER_GAS", "1.5"),
            ("GAS_TX_MAX_VALUE_WEI", "1e18"),
            ("BTC_MAX_TOTAL_SATS", ""),
            ("RGB_MAX_UNOWNED_SATS", "x"),
            ("BTC_MAX_UNOWNED_SATS", "99999999999999999999999"),
        ]);
        let c = BridgeConfig::from_env();
        assert_eq!(c.chain_id, 0);
        assert_eq!(c.bridge_contract, [0u8; 20]);
        assert_eq!(c.gas_tx_allowed_to, None);
        assert_eq!(c.gas_tx_max_gas_limit, 0);
        assert_eq!(c.gas_tx_max_fee_per_gas, 0);
        assert_eq!(c.gas_tx_max_value_wei, None);
        assert_eq!(c.btc_max_total_sats, 0);
        assert_eq!(c.rgb_max_unowned_sats, 0);
        assert_eq!(c.btc_max_unowned_sats, 0);
        assert!(!c.is_configured());
        assert!(!c.allows_vanilla_btc());
    }

    #[test]
    fn a_partial_pin_set_is_reported_as_partially_configured() {
        let env = EnvScope::new();
        env.set(&[("EVM_CHAIN_ID", "1"), ("RGB_ASSET_ID", "rgb:x")]);
        let c = BridgeConfig::from_env();
        assert!(!c.is_configured());
        assert!(c.is_partially_configured());
    }

    #[test]
    fn selector_list_drops_malformed_entries_without_poisoning_the_rest() {
        let env = EnvScope::new();
        env.set(&[(
            "GAS_TX_ALLOWED_SELECTORS",
            "0xdeadbeef,0xdeadbeefaa,abc,0xgggggggg,,0x01020304",
        )]);
        let c = BridgeConfig::from_env();
        assert_eq!(
            c.gas_tx_allowed_selectors,
            vec![[0xde, 0xad, 0xbe, 0xef], [0x01, 0x02, 0x03, 0x04]]
        );
        env.set(&[("GAS_TX_ALLOWED_SELECTORS", "")]);
        assert!(BridgeConfig::from_env().gas_tx_allowed_selectors.is_empty());
        env.set(&[("GAS_TX_ALLOWED_SELECTORS", " , , ")]);
        assert!(BridgeConfig::from_env().gas_tx_allowed_selectors.is_empty());
    }

    #[test]
    fn zero_and_unparseable_caps_fall_back_to_defaults_but_positive_values_stick() {
        let env = EnvScope::new();
        env.set(&[
            ("MAX_CONSIGNMENT_BYTES", "0"),
            ("MAX_MERKLE_PROOFS", "abc"),
            ("MAX_TOTAL_PROOF_BYTES", "-5"),
        ]);
        let c = BridgeConfig::from_env();
        assert_eq!(c.max_consignment_bytes, DEFAULT_MAX_CONSIGNMENT_BYTES);
        assert_eq!(c.max_merkle_proofs, DEFAULT_MAX_MERKLE_PROOFS);
        assert_eq!(c.max_total_proof_bytes, DEFAULT_MAX_TOTAL_PROOF_BYTES);
        env.set(&[("MAX_CONSIGNMENT_BYTES", "1")]);
        assert_eq!(BridgeConfig::from_env().max_consignment_bytes, 1);
    }

    #[test]
    fn gas_value_ceiling_accepts_zero_and_u128_max_and_rejects_negatives() {
        let env = EnvScope::new();
        env.set(&[("GAS_TX_MAX_VALUE_WEI", "0")]);
        assert_eq!(BridgeConfig::from_env().gas_tx_max_value_wei, Some(0));
        env.set(&[("GAS_TX_MAX_VALUE_WEI", &u128::MAX.to_string())]);
        assert_eq!(
            BridgeConfig::from_env().gas_tx_max_value_wei,
            Some(u128::MAX)
        );
        env.set(&[("GAS_TX_MAX_VALUE_WEI", "-1")]);
        assert_eq!(BridgeConfig::from_env().gas_tx_max_value_wei, None);
        env.set(&[("GAS_TX_MAX_VALUE_WEI", "0x10")]);
        assert_eq!(BridgeConfig::from_env().gas_tx_max_value_wei, None);
    }

    #[test]
    fn allows_vanilla_btc_tracks_only_the_total_sats_cap() {
        let mut c = BridgeConfig::default();
        assert!(!c.allows_vanilla_btc());
        c.btc_max_unowned_sats = 5_000;
        assert!(
            !c.allows_vanilla_btc(),
            "the unowned budget alone does not enable the path"
        );
        c.btc_max_total_sats = 1;
        assert!(c.allows_vanilla_btc());
    }

    #[test]
    fn address_pins_accept_upper_case_hex() {
        let env = EnvScope::new();
        env.set(&[
            (
                "EVM_PROXY_CONTRACT_ADDRESS",
                "0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD",
            ),
            (
                "GAS_TX_ALLOWED_TO",
                "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD",
            ),
        ]);
        let c = BridgeConfig::from_env();
        let expected = hex::decode("abcdefabcdefabcdefabcdefabcdefabcdefabcd").unwrap();
        assert_eq!(c.bridge_contract.to_vec(), expected);
        assert_eq!(c.gas_tx_allowed_to.map(|a| a.to_vec()), Some(expected));
    }

    #[test]
    fn parse_eth_address_rejects_empty_and_prefix_only() {
        assert!(parse_eth_address("").is_err());
        assert!(parse_eth_address("0x").is_err());
        assert!(parse_eth_address("0x0x0102030405060708090a0b0c0d0e0f1011121314").is_err());
        // 21 bytes.
        assert!(parse_eth_address("0102030405060708090a0b0c0d0e0f101112131415").is_err());
    }

    #[cfg(feature = "evm-rpc")]
    #[test]
    fn evm_rpc_config_defaults_and_env_overrides() {
        let env = EnvScope::new();
        let d = EvmRpcConfig::default();
        assert_eq!(d.rpc_url, "http://127.0.0.1:3444");
        assert_eq!(d.min_confirmations, 12);
        let c = EvmRpcConfig::from_env();
        assert_eq!(c.rpc_url, d.rpc_url);
        assert_eq!(c.min_confirmations, d.min_confirmations);

        env.set(&[
            ("EVM_RPC_URL", "http://localhost:8545"),
            ("EVM_MIN_CONFIRMATIONS", "3"),
        ]);
        let c = EvmRpcConfig::from_env();
        assert_eq!(c.rpc_url, "http://localhost:8545");
        assert_eq!(c.min_confirmations, 3);

        // A non-loopback URL is refused back to the default; a malformed
        // confirmation count falls back to 12.
        env.set(&[
            ("EVM_RPC_URL", "http://10.0.0.1:8545"),
            ("EVM_MIN_CONFIRMATIONS", "many"),
        ]);
        let c = EvmRpcConfig::from_env();
        assert_eq!(c.rpc_url, "http://127.0.0.1:3444");
        assert_eq!(c.min_confirmations, 12);
    }

    #[cfg(feature = "helios")]
    mod helios {
        use super::ENV_LOCK;
        use crate::config::HeliosConfig;

        const VARS: [&str; 5] = [
            "HELIOS_EXECUTION_RPC",
            "HELIOS_CONSENSUS_RPC",
            "HELIOS_NETWORK",
            "HELIOS_CHECKPOINT",
            "HELIOS_STRICT_CHECKPOINT_AGE",
        ];

        struct Scope {
            _guard: std::sync::MutexGuard<'static, ()>,
        }
        impl Scope {
            fn new(vars: &[(&str, &str)]) -> Self {
                let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                for v in VARS {
                    std::env::remove_var(v);
                }
                for (k, v) in vars {
                    std::env::set_var(k, v);
                }
                Self { _guard: guard }
            }
        }
        impl Drop for Scope {
            fn drop(&mut self) {
                for v in VARS {
                    std::env::remove_var(v);
                }
            }
        }

        #[test]
        fn unset_execution_rpc_selects_the_raw_path() {
            let _s = Scope::new(&[("HELIOS_CONSENSUS_RPC", "http://127.0.0.1:1")]);
            assert!(HeliosConfig::from_env().is_none());
        }

        #[test]
        fn execution_rpc_alone_yields_the_documented_defaults() {
            let _s = Scope::new(&[("HELIOS_EXECUTION_RPC", "http://127.0.0.1:18545")]);
            let c = HeliosConfig::from_env().expect("selected");
            assert_eq!(c.execution_rpc, "http://127.0.0.1:18545");
            assert_eq!(c.consensus_rpc, "http://127.0.0.1:18550");
            assert_eq!(c.network, "mainnet");
            assert!(c.checkpoint.is_none(), "no community checkpoint fallback");
            assert!(c.strict_checkpoint_age);
        }

        #[test]
        fn every_variable_is_read() {
            let _s = Scope::new(&[
                ("HELIOS_EXECUTION_RPC", "http://localhost:1"),
                ("HELIOS_CONSENSUS_RPC", "http://localhost:2"),
                ("HELIOS_NETWORK", "sepolia"),
                ("HELIOS_CHECKPOINT", "0xabcd"),
                ("HELIOS_STRICT_CHECKPOINT_AGE", "false"),
            ]);
            let c = HeliosConfig::from_env().expect("selected");
            assert_eq!(c.execution_rpc, "http://localhost:1");
            assert_eq!(c.consensus_rpc, "http://localhost:2");
            assert_eq!(c.network, "sepolia");
            assert_eq!(c.checkpoint.as_deref(), Some("0xabcd"));
            assert!(!c.strict_checkpoint_age);
        }

        #[test]
        fn strict_checkpoint_age_is_off_only_for_false_or_zero() {
            for (v, want) in [
                ("false", false),
                ("0", false),
                ("true", true),
                ("1", true),
                ("no", true),
                ("", true),
                ("FALSE", true),
            ] {
                let _s = Scope::new(&[
                    ("HELIOS_EXECUTION_RPC", "http://127.0.0.1:18545"),
                    ("HELIOS_STRICT_CHECKPOINT_AGE", v),
                ]);
                assert_eq!(
                    HeliosConfig::from_env().unwrap().strict_checkpoint_age,
                    want,
                    "HELIOS_STRICT_CHECKPOINT_AGE={v:?}"
                );
            }
        }

        #[test]
        fn a_non_loopback_url_is_kept_and_only_logged() {
            let _s = Scope::new(&[
                ("HELIOS_EXECUTION_RPC", "http://10.0.0.5:8545"),
                ("HELIOS_CONSENSUS_RPC", "http://beacon.example:5052"),
            ]);
            let c = HeliosConfig::from_env().expect("selected");
            assert_eq!(c.execution_rpc, "http://10.0.0.5:8545");
            assert_eq!(c.consensus_rpc, "http://beacon.example:5052");
        }
    }
}
