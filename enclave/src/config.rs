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
    /// The ERC-20 the Bridge releases (`TOKEN_CONTRACT`, i.e. `Bridge.TOKEN`).
    /// An input of the on-chain `burnId` preimage, so the enclave needs it to
    /// recompute `burnId` (`networks::evm::validation::validate_burn_id`).
    /// Zero = unset: the recompute is skipped in dev builds, and a production
    /// policy refuses to boot ([`crate::policy::ProductionPolicy`]). Attested.
    pub token_contract: [u8; 20],
    /// Whether a `fundsOut` proof must carry BtcRelay commitments the enclave
    /// verifies against its own chain (`BTC_RELAY_MODE`). Unset = `required`,
    /// which fails closed; `none` is only for a local stand that has no
    /// BtcRelay, and a production policy refuses to boot on it
    /// ([`crate::policy::ProductionPolicy::check_invariants`]).
    pub btc_relay_mode: BtcRelayMode,
    /// Aggregate request-size caps for the RGB signing path, operator-tunable
    /// via env (`MAX_CONSIGNMENT_BYTES` / `MAX_MERKLE_PROOFS` /
    /// `MAX_TOTAL_PROOF_BYTES`); each defaults to its `DEFAULT_*` constant when
    /// unset (or set to 0). Defense-in-depth DoS bounds, not attested - like the
    /// operational pins above. See [`DEFAULT_MAX_CONSIGNMENT_BYTES`].
    pub max_consignment_bytes: usize,
    pub max_merkle_proofs: usize,
    pub max_total_proof_bytes: usize,
}

/// Env var selecting [`BtcRelayMode`].
pub const BTC_RELAY_MODE_ENV: &str = "BTC_RELAY_MODE";

/// How the `fundsOut` finality proof's BtcRelay commitment words are checked.
/// See `networks::evm::crosscheck::verify_btc_relay_agreement`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcRelayMode {
    /// `BTC_RELAY_MODE=required` (the default): both commitment words must
    /// equal the relay records the enclave rebuilds from its own chain. A
    /// zero word is refused. The only mode a production policy accepts.
    Required,
    /// `BTC_RELAY_MODE=none`: the deployment has no BtcRelay (the route's
    /// verifier is `NullVerifier`), so the bridge sends both words as zero
    /// and the enclave requires exactly that. The height, anchor and
    /// freshness binds still run. Refused by a production policy.
    None,
}

impl BtcRelayMode {
    /// Parse the env value. Unset is `Required`. Anything other than
    /// `required` / `none` (case-insensitive, trimmed) is also `Required`,
    /// with a boot warning: a typo must never turn the relay check off.
    pub fn from_env_value(value: Option<String>) -> Self {
        match value.as_deref().map(str::trim) {
            None | Some("") => Self::Required,
            Some(v) if v.eq_ignore_ascii_case("required") => Self::Required,
            Some(v) if v.eq_ignore_ascii_case("none") => Self::None,
            Some(v) => {
                tracing::warn!(
                    value = %v,
                    "{BTC_RELAY_MODE_ENV}: unknown value, keeping `required` (expected `required` \
                     or `none`)"
                );
                Self::Required
            }
        }
    }
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
            token_contract: [0u8; 20],
            btc_relay_mode: BtcRelayMode::Required,
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

        // The released ERC-20, a `burnId` preimage input. Unset stays zero:
        // dev skips the recompute, production refuses to boot.
        let token_contract = std::env::var("TOKEN_CONTRACT")
            .ok()
            .and_then(|s| parse_eth_address(&s).ok())
            .unwrap_or([0u8; 20]);

        let btc_relay_mode = BtcRelayMode::from_env_value(std::env::var(BTC_RELAY_MODE_ENV).ok());

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
            token_contract,
            btc_relay_mode,
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
/// The endpoint is not here: the operator sets it at launch ([`Endpoints`]).
#[cfg(feature = "evm-rpc")]
#[derive(Debug, Clone)]
pub struct EvmRpcConfig {
    /// Minimum confirmation depth a `FundsIn` receipt must have, measured
    /// against the RPC head block (`EVM_MIN_CONFIRMATIONS`, default 12).
    pub min_confirmations: u64,
}

/// The TLS pin of the EVM RPC endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmRpcTls {
    /// The name for SNI and the certificate check, lowercased.
    pub host: String,
    /// DER of the only trusted root.
    pub ca_der: Vec<u8>,
    /// The upstream TLS port. The forwarder listens on it in the enclave.
    pub tls_port: u16,
}

#[cfg(feature = "evm-rpc")]
impl EvmRpcConfig {
    /// Default confirmation depth (~a safe head distance for most EVM chains).
    const DEFAULT_MIN_CONFIRMATIONS: u64 = 12;

    /// Load `EVM_MIN_CONFIRMATIONS` from the process environment.
    pub fn from_env() -> Self {
        let min_confirmations = std::env::var("EVM_MIN_CONFIRMATIONS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(Self::DEFAULT_MIN_CONFIRMATIONS);
        Self { min_confirmations }
    }
}

#[cfg(feature = "evm-rpc")]
impl Default for EvmRpcConfig {
    fn default() -> Self {
        Self {
            min_confirmations: Self::DEFAULT_MIN_CONFIRMATIONS,
        }
    }
}

/// True if `url`'s host is exactly a loopback literal (`127.0.0.1`, `[::1]`, or
/// `localhost`). Narrow and dependency-free. Matches the host exactly, after
/// stripping scheme, userinfo, path, and port, so `127.0.0.1.evil.com` is not
/// treated as loopback.
#[cfg(feature = "helios")]
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

/// Endpoints and KMS pins set once at launch and committed in the attested policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Endpoints {
    /// `ssl://host:port` or `tcp://host:port`. Empty without `rgb-validation`.
    pub electrum_url: String,
    pub electrum_host: String,
    pub electrum_port: u16,
    /// `None` without `evm-rpc`.
    pub evm_rpc_tls: Option<EvmRpcTls>,
    /// `None` without `kms-persistence`, and in an import-only build with no
    /// KMS values.
    pub kms: Option<crate::policy::KmsPin>,
}

impl Endpoints {
    /// Check the values this build uses. A value the build does not use
    /// must be empty.
    pub fn parse(req: &crate::proto::SetEndpointsRequest) -> std::result::Result<Self, String> {
        // Allow one trailing slash. The Electrum client does not.
        let electrum_url = req
            .electrum_url
            .strip_suffix('/')
            .unwrap_or(&req.electrum_url);
        #[cfg(feature = "rgb-validation")]
        let (electrum_host, electrum_port) = parse_electrum_url(electrum_url)?;
        #[cfg(not(feature = "rgb-validation"))]
        let (electrum_host, electrum_port) = {
            unused("electrum_url", req.electrum_url.is_empty())?;
            (String::new(), 0)
        };

        #[cfg(feature = "evm-rpc")]
        let evm_rpc_tls = {
            let host = parse_host("evm_rpc_host", &req.evm_rpc_host)?;
            let ca = rustls_pki_types::CertificateDer::from(req.evm_rpc_ca_der.as_slice());
            // The same check the client root store makes, so a bad CA never
            // gets an attested pin.
            webpki::anchor_from_trusted_cert(&ca)
                .map_err(|e| format!("evm_rpc_ca_der is not a valid CA certificate: {e}"))?;
            let tls_port = parse_port("evm_rpc_tls_port", req.evm_rpc_tls_port)?;
            // Both forwarders listen on loopback in the enclave.
            if tls_port == electrum_port {
                return Err(format!(
                    "evm_rpc_tls_port {tls_port} is also the Electrum port"
                ));
            }
            Some(EvmRpcTls {
                host,
                ca_der: req.evm_rpc_ca_der.clone(),
                tls_port,
            })
        };
        #[cfg(not(feature = "evm-rpc"))]
        let evm_rpc_tls = {
            unused("evm_rpc_host", req.evm_rpc_host.is_empty())?;
            unused("evm_rpc_ca_der", req.evm_rpc_ca_der.is_empty())?;
            unused("evm_rpc_tls_port", req.evm_rpc_tls_port == 0)?;
            None
        };

        let kms_values = [
            ("kms_key_arn", &req.kms_key_arn),
            ("kms_region", &req.kms_region),
            ("kms_seed_id", &req.kms_seed_id),
            ("kms_expected_evm_address", &req.kms_expected_evm_address),
        ];
        #[cfg(feature = "kms-persistence")]
        let kms = if cfg!(feature = "allow-seed-import")
            && kms_values.iter().all(|(_, v)| v.is_empty())
        {
            // Development import-only mode.
            None
        } else {
            let config = crate::kms::KmsConfig {
                flow: crate::kms::CustodyFlow::RgbMint,
                key_arn: req.kms_key_arn.clone(),
                region: req.kms_region.clone(),
                seed_id: req.kms_seed_id.clone(),
            };
            config.validate().map_err(|e| e.to_string())?;
            // The Electrum pin must not catch the KMS host.
            if electrum_host == config.endpoint_host() {
                return Err(format!("electrum_url host {electrum_host} is the KMS host"));
            }
            let address = &req.kms_expected_evm_address;
            let expected_evm_address = if address.is_empty() {
                None
            } else {
                Some(
                    hex::decode(address.strip_prefix("0x").unwrap_or(address))
                        .ok()
                        .and_then(|v| v.try_into().ok())
                        .ok_or("kms_expected_evm_address must be 20-byte hex")?,
                )
            };
            Some(crate::policy::KmsPin {
                key_arn: config.key_arn,
                region: config.region,
                seed_id: config.seed_id,
                expected_evm_address,
            })
        };
        #[cfg(not(feature = "kms-persistence"))]
        let kms = {
            for (name, value) in kms_values {
                unused(name, value.is_empty())?;
            }
            None
        };

        Ok(Self {
            electrum_url: electrum_url.to_string(),
            electrum_host,
            electrum_port,
            evm_rpc_tls,
            kms,
        })
    }
}

#[cfg(not(all(feature = "evm-rpc", feature = "kms-persistence")))]
fn unused(name: &str, empty: bool) -> std::result::Result<(), String> {
    if empty {
        Ok(())
    } else {
        Err(format!("{name} is set, but this build does not use it"))
    }
}

#[cfg(feature = "rgb-validation")]
fn parse_port(name: &str, port: u32) -> std::result::Result<u16, String> {
    u16::try_from(port)
        .ok()
        .filter(|&p| p != 0)
        .ok_or_else(|| format!("{name} {port} is not in 1-65535"))
}

/// `ssl://host:port` or `tcp://host:port`, nothing after the port.
#[cfg(feature = "rgb-validation")]
fn parse_electrum_url(url: &str) -> std::result::Result<(String, u16), String> {
    let rest = url
        .strip_prefix("ssl://")
        .or_else(|| url.strip_prefix("tcp://"))
        .ok_or_else(|| format!("electrum_url {url:?} is not ssl:// or tcp://"))?;
    let (host, port) = rest
        .rsplit_once(':')
        .ok_or_else(|| format!("electrum_url {url:?} has no port"))?;
    let port = port
        .parse::<u32>()
        .map_err(|_| format!("electrum_url {url:?} has a bad port"))?;
    Ok((
        parse_host("electrum_url host", host)?,
        parse_port("electrum_url port", port)?,
    ))
}

/// A DNS host name, lowercased. No scheme, `/`, `:`, whitespace or IP
/// literal.
#[cfg(feature = "rgb-validation")]
fn parse_host(name: &str, host: &str) -> std::result::Result<String, String> {
    use rustls_pki_types::DnsName;
    // `DnsName` rejects an empty label, a label over 63 bytes, a label
    // starting with a hyphen, and an all-numeric last label (no IPv4
    // literals). It allows a trailing dot and `_`, so those are checked here.
    if host.contains('_') || host.ends_with('.') {
        return Err(format!("{name} {host:?} is not a host name"));
    }
    let dns_name =
        DnsName::try_from(host).map_err(|_| format!("{name} {host:?} is not a host name"))?;
    // SNI and the Host header go out lowercase.
    Ok(dns_name.to_lowercase_owned().as_ref().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::SetEndpointsRequest;

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
    fn btc_relay_mode_defaults_to_required() {
        assert_eq!(BtcRelayMode::from_env_value(None), BtcRelayMode::Required);
        assert_eq!(
            BtcRelayMode::from_env_value(Some("".into())),
            BtcRelayMode::Required
        );
        assert_eq!(
            BtcRelayMode::from_env_value(Some("required".into())),
            BtcRelayMode::Required
        );
    }

    #[test]
    fn btc_relay_mode_none_must_be_spelled_out() {
        assert_eq!(
            BtcRelayMode::from_env_value(Some("none".into())),
            BtcRelayMode::None
        );
        assert_eq!(
            BtcRelayMode::from_env_value(Some(" None ".into())),
            BtcRelayMode::None
        );
    }

    /// A typo must fail closed, never relax the relay check.
    #[test]
    fn btc_relay_mode_unknown_value_stays_required() {
        for v in ["off", "false", "0", "disabled", "nope"] {
            assert_eq!(
                BtcRelayMode::from_env_value(Some(v.into())),
                BtcRelayMode::Required,
                "{v}"
            );
        }
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

    #[cfg(feature = "helios")]
    #[test]
    fn loopback_url_accepts_real_loopback() {
        assert!(is_loopback_url("http://127.0.0.1:3444"));
        assert!(is_loopback_url("http://127.0.0.1"));
        assert!(is_loopback_url("http://localhost:8545"));
        assert!(is_loopback_url("http://[::1]:18545/path"));
        assert!(is_loopback_url("http://[::1]"));
        assert!(is_loopback_url("http://user:pass@127.0.0.1:3444"));
    }

    #[cfg(feature = "helios")]
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

    const CA_HEX: &str = include_str!("../tests/fixtures/evm_rpc_tls/ca_a.der.hex");

    /// A valid set for this build: only the values it uses.
    fn valid() -> SetEndpointsRequest {
        let mut req = SetEndpointsRequest::default();
        if cfg!(feature = "rgb-validation") {
            req.electrum_url = "ssl://Electrum.test:50002".into();
        }
        if cfg!(feature = "evm-rpc") {
            req.evm_rpc_host = "RPC.Test".into();
            req.evm_rpc_ca_der = hex::decode(CA_HEX.trim()).unwrap();
            req.evm_rpc_tls_port = 443;
        }
        if cfg!(feature = "kms-persistence") {
            req.kms_key_arn = KEY_ARN.into();
            req.kms_region = "eu-west-1".into();
            req.kms_seed_id = "seed-1".into();
        }
        req
    }

    const KEY_ARN: &str =
        "arn:aws:kms:eu-west-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef";

    fn parse_with(
        edit: impl FnOnce(&mut SetEndpointsRequest),
    ) -> std::result::Result<Endpoints, String> {
        let mut req = valid();
        edit(&mut req);
        Endpoints::parse(&req)
    }

    #[test]
    fn valid_endpoints_parse_and_hosts_are_lowercased() {
        let e = parse_with(|_| {}).unwrap();
        if cfg!(feature = "rgb-validation") {
            assert_eq!(e.electrum_host, "electrum.test");
            assert_eq!(e.electrum_port, 50002);
        }
        assert_eq!(e.evm_rpc_tls.is_some(), cfg!(feature = "evm-rpc"));
        if let Some(tls) = e.evm_rpc_tls {
            assert_eq!(tls.host, "rpc.test");
            assert_eq!(tls.tls_port, 443);
        }
    }

    #[cfg(feature = "rgb-validation")]
    #[test]
    fn electrum_url_must_be_ssl_or_tcp_host_and_port() {
        assert!(parse_with(|r| r.electrum_url = "tcp://electrum.test:50001".into()).is_ok());
        let e = parse_with(|r| r.electrum_url = "ssl://electrum.test:50002/".into()).unwrap();
        assert_eq!(e.electrum_url, "ssl://electrum.test:50002");
        for url in [
            "",
            "http://electrum.test:50001",
            "electrum.test:50001",
            "ssl://electrum.test",
            "ssl://electrum.test:50002/x",
            "ssl://electrum.test:0",
            "ssl://electrum.test:65536",
            "ssl://127.0.0.1:50002",
            "ssl://electrum_test:50002",
            "ssl://electrum test:50002",
        ] {
            assert!(
                parse_with(|r| r.electrum_url = url.into()).is_err(),
                "{url:?}"
            );
        }
    }

    #[cfg(feature = "evm-rpc")]
    #[test]
    fn evm_rpc_host_must_be_a_host_name() {
        // A DNS name up to 253 bytes total, no label over 63.
        let long = [
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(61),
        ]
        .join(".");
        assert_eq!(long.len(), 253);
        for host in ["rpc.test", "a", "rpc-1.Example.com", &long] {
            assert!(
                parse_with(|r| r.evm_rpc_host = host.into()).is_ok(),
                "{host}"
            );
        }
        let too_long_label = "a".repeat(64);
        for host in [
            "",
            ".rpc.test",
            "rpc.test.",
            "rpc..test",
            "-rpc.test",
            "https://rpc.test",
            "rpc.test/v2",
            "rpc.test:443",
            "rpc test",
            "rpc.test\n",
            "rpc_test",
            "127.0.0.1",
            &too_long_label,
        ] {
            assert!(
                parse_with(|r| r.evm_rpc_host = host.into()).is_err(),
                "{host:?}"
            );
        }
    }

    #[cfg(feature = "evm-rpc")]
    #[test]
    fn evm_rpc_ca_must_be_a_valid_certificate() {
        let der = hex::decode(CA_HEX.trim()).unwrap();
        let truncated = der[..der.len() - 10].to_vec();
        for ca in [Vec::new(), b"not der".to_vec(), truncated] {
            assert!(
                parse_with(|r| r.evm_rpc_ca_der = ca.clone()).is_err(),
                "{ca:?}"
            );
        }
    }

    #[cfg(feature = "evm-rpc")]
    #[test]
    fn evm_rpc_tls_port_must_be_a_free_port() {
        for port in [0, 65536, 50002] {
            assert!(parse_with(|r| r.evm_rpc_tls_port = port).is_err(), "{port}");
        }
    }

    #[test]
    fn a_value_the_build_does_not_use_is_refused() {
        if !cfg!(feature = "rgb-validation") {
            assert!(parse_with(|r| r.electrum_url = "ssl://electrum.test:50002".into()).is_err());
        }
        if !cfg!(feature = "evm-rpc") {
            assert!(parse_with(|r| r.evm_rpc_host = "rpc.test".into()).is_err());
            assert!(parse_with(|r| r.evm_rpc_ca_der = vec![1]).is_err());
            assert!(parse_with(|r| r.evm_rpc_tls_port = 443).is_err());
        }
    }

    #[cfg(feature = "kms-persistence")]
    #[test]
    fn kms_values_are_checked_at_launch() {
        let edits: [fn(&mut SetEndpointsRequest); 8] = [
            |r| r.kms_key_arn = "arn:aws:kms:eu-west-1:123456789012:alias/seed".into(),
            |r| r.kms_key_arn = KEY_ARN.replace("eu-west-1", "eu-west-2"),
            |r| {
                r.kms_region = "cn-north-1".into();
                r.kms_key_arn = KEY_ARN.replace("eu-west-1", "cn-north-1");
            },
            |r| r.kms_seed_id = "seed 1".into(),
            |r| r.kms_expected_evm_address = "00".repeat(19),
            |r| r.kms_expected_evm_address = "zz".repeat(20),
            |r| {
                r.kms_region.clear();
                r.kms_seed_id.clear();
            },
            |r| r.electrum_url = "ssl://kms.eu-west-1.amazonaws.com:50002".into(),
        ];
        for edit in edits {
            assert!(parse_with(edit).is_err());
        }
        if cfg!(feature = "allow-seed-import") {
            let e = parse_with(|r| {
                r.kms_key_arn.clear();
                r.kms_region.clear();
                r.kms_seed_id.clear();
            })
            .unwrap();
            assert_eq!(e.kms, None);
        }
        let e =
            parse_with(|r| r.kms_expected_evm_address = format!("0x{}", "ab".repeat(20))).unwrap();
        assert_eq!(
            e.kms,
            Some(crate::policy::KmsPin {
                key_arn: KEY_ARN.into(),
                region: "eu-west-1".into(),
                seed_id: "seed-1".into(),
                expected_evm_address: Some([0xab; 20]),
            })
        );
        assert_eq!(
            parse_with(|_| {})
                .unwrap()
                .kms
                .unwrap()
                .expected_evm_address,
            None
        );
    }

    #[cfg(not(feature = "kms-persistence"))]
    #[test]
    fn kms_values_are_refused_without_kms_persistence() {
        let edits: [fn(&mut SetEndpointsRequest); 4] = [
            |r| r.kms_key_arn = KEY_ARN.into(),
            |r| r.kms_region = "eu-west-1".into(),
            |r| r.kms_seed_id = "seed-1".into(),
            |r| r.kms_expected_evm_address = "ab".repeat(20),
        ];
        for edit in edits {
            assert!(parse_with(edit).is_err());
        }
    }
}
