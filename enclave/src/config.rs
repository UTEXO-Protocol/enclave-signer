//! Bridge configuration, pinned from env at boot.
//!
//! The chain, MultisigProxy contract (`EVM_PROXY_CONTRACT_ADDRESS`) and RGB
//! asset go into the attestation `user_data` (`canonical_pubkey_bundle` in
//! `server/keys.rs`). So:
//!
//!   1. a `GetAttestedPublicKey` verifier sees the (chain_id, contract, asset);
//!   2. `SignEvm` rejects request fields that do not match this config.
//!
//! Production sets all three env vars. Dev and mock builds can leave them unset.
//! Then the cross-check is skipped and the bundle commits empty values, so a
//! production deploy without them is visible externally.

use crate::error::{EnclaveError, Result};

/// Default consignment size cap (`MAX_CONSIGNMENT_BYTES`). Defense-in-depth DoS
/// bound. The 4 MiB wire frame also caps it. Real consignments are a few KB.
pub const DEFAULT_MAX_CONSIGNMENT_BYTES: usize = 1024 * 1024;
/// Default cap on Merkle proofs per source (`MAX_MERKLE_PROOFS`). A consignment
/// anchors only a few witness txs.
pub const DEFAULT_MAX_MERKLE_PROOFS: usize = 256;
/// Default cap on total proof bytes, txids and Merkle siblings, in all proofs
/// (`MAX_TOTAL_PROOF_BYTES`). Bounds the total Merkle hashing work.
pub const DEFAULT_MAX_TOTAL_PROOF_BYTES: usize = 128 * 1024;

/// Bridge config pinned at enclave boot from env. See module docs.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub chain_id: u64,
    /// MultisigProxy contract (`EVM_PROXY_CONTRACT_ADDRESS`), the EIP-712
    /// `verifyingContract` of every funds-out request. The `FundsIn` emitter is
    /// `funds_in_contract`. The name stays stable for the attestation bundle.
    pub bridge_contract: [u8; 20],
    pub rgb_asset_id: String,
    /// The only allowed `to` of a gas-key tx (`GAS_TX_ALLOWED_TO`). `None`
    /// fails gas-tx signing closed in release builds.
    ///
    /// A gas tx carries `value == 0`. The exception is the payable
    /// `lzFundsOutCall`: this pin must equal [`Self::bridge_contract`] and the
    /// value must fit [`Self::gas_tx_max_value_wei`]. See `networks::evm::gas_tx`.
    ///
    /// [`gas_tx_allowed_selectors`](Self::gas_tx_allowed_selectors) limits the
    /// callable functions. The gas and fee caps limit the burn.
    ///
    /// [`crate::policy::SecurityPolicy`] commits the gas-tx rule in `user_data`.
    pub gas_tx_allowed_to: Option<[u8; 20]>,
    /// Max `gasLimit` of a gas tx (`GAS_TX_MAX_GAS_LIMIT`). `0` = unset, which
    /// fails gas-tx signing closed. With
    /// [`gas_tx_max_fee_per_gas`](Self::gas_tx_max_fee_per_gas) it caps the fee
    /// a gas tx can burn (`gasLimit * maxFeePerGas`).
    pub gas_tx_max_gas_limit: u64,
    /// Max per-gas fee in wei (`GAS_TX_MAX_FEE_PER_GAS`): `maxFeePerGas` and
    /// `maxPriorityFeePerGas` for EIP-1559, `gasPrice` for legacy. `0` = unset,
    /// which fails gas-tx signing closed. A fee wider than `u128` exceeds the cap.
    pub gas_tx_max_fee_per_gas: u128,
    /// Allowed 4-byte selectors of gas-tx calldata (`GAS_TX_ALLOWED_SELECTORS`,
    /// comma-separated hex). Empty calldata is refused: it calls the fallback or
    /// receive function. An empty list refuses all gas-tx signing.
    pub gas_tx_allowed_selectors: Vec<[u8; 4]>,
    /// Max native value in wei of one gas tx (`GAS_TX_MAX_VALUE_WEI`). `None`
    /// refuses any non-zero value.
    ///
    /// The `TeeLzFundsOut` payload has no fee field, so nothing binds the fee to
    /// its release. This cap limits the possible loss.
    pub gas_tx_max_value_wei: Option<u128>,
    /// Max total input value in sats of a plain-BTC PSBT (`BTC_MAX_TOTAL_SATS`).
    /// `0` = unset: a production build refuses plain-BTC signing. It also bounds
    /// miner fees. The destination rule needs no config
    /// ([`crate::networks::rgb::btc_ownership`]).
    ///
    /// The policy attests [`allows_vanilla_btc`](Self::allows_vanilla_btc) as
    /// `allow_vanilla_psbt`.
    ///
    /// There is no output script allowlist: the scripts come from a seed that
    /// exists only after boot, and env is measured into PCR0.
    pub btc_max_total_sats: u64,
    /// Budget in sats for send-RGB outputs the enclave cannot prove it owns
    /// (`RGB_MAX_UNOWNED_SATS`). The recipient output is blinded, so the enclave
    /// bounds the value that leaves. `0` = unset: production refuses send-RGB.
    pub rgb_max_unowned_sats: u64,
    /// Budget in sats for plain-BTC outputs that do not pay back into the same
    /// custody (`BTC_MAX_UNOWNED_SATS`). Covers `create_utxo` dust (1000 sats
    /// each, 5 by default). `0` = unset: production refuses plain-BTC signing.
    pub btc_max_unowned_sats: u64,
    /// Emitter of `FundsIn`/`BridgeFundsIn` (`FUNDS_IN_CONTRACT`), default
    /// `bridge_contract`. The bridge entry contract is not the MultisigProxy in
    /// this deployment, so set it explicitly.
    pub funds_in_contract: [u8; 20],
    /// The ERC-20 that the Bridge releases (`TOKEN_CONTRACT`, `Bridge.TOKEN`).
    /// An input of the `burnId` preimage
    /// (`networks::evm::validation::validate_burn_id`). Zero = unset: dev skips
    /// the check, production does not boot ([`crate::policy::ProductionPolicy`]).
    /// Attested.
    pub token_contract: [u8; 20],
    /// If a `fundsOut` proof must carry BtcRelay commitments that the enclave
    /// checks against its own chain (`BTC_RELAY_MODE`). Default `required`.
    /// `none` is for a local stand only; production does not boot on it
    /// ([`crate::policy::ProductionPolicy::check_invariants`]).
    pub btc_relay_mode: BtcRelayMode,
    /// RGB request-size caps (`MAX_CONSIGNMENT_BYTES`, `MAX_MERKLE_PROOFS`,
    /// `MAX_TOTAL_PROOF_BYTES`). Unset or 0 gives the `DEFAULT_*` value.
    /// Defense-in-depth DoS bounds, not attested.
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
    /// `BTC_RELAY_MODE=required` (default): both commitment words must equal
    /// the relay records that the enclave rebuilds from its own chain. A zero
    /// word is refused. The only mode that production accepts.
    Required,
    /// `BTC_RELAY_MODE=none`: no BtcRelay (`NullVerifier`), so both words must
    /// be zero. The height, anchor and freshness checks still run. Production
    /// refuses it.
    None,
}

impl BtcRelayMode {
    /// Parse the env value. Unset or unknown gives `Required`, so a typo never
    /// turns the relay check off. Case-insensitive and trimmed.
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
    /// Load from env. A missing or invalid field gives its zero or empty value.
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

        // `0` fails the gas path closed, so a malformed value is safe.
        let gas_tx_max_gas_limit = std::env::var("GAS_TX_MAX_GAS_LIMIT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        let gas_tx_max_fee_per_gas = std::env::var("GAS_TX_MAX_FEE_PER_GAS")
            .ok()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);

        // A malformed selector is dropped and logged. The others stay.
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

        let funds_in_contract = std::env::var("FUNDS_IN_CONTRACT")
            .ok()
            .and_then(|s| parse_eth_address(&s).ok())
            .unwrap_or(bridge_contract);

        let token_contract = std::env::var("TOKEN_CONTRACT")
            .ok()
            .and_then(|s| parse_eth_address(&s).ok())
            .unwrap_or([0u8; 20]);

        let btc_relay_mode = BtcRelayMode::from_env_value(std::env::var(BTC_RELAY_MODE_ENV).ok());

        // Without both caps every gas tx fails. Show this at boot.
        if gas_tx_allowed_to.is_some() && (gas_tx_max_gas_limit == 0 || gas_tx_max_fee_per_gas == 0)
        {
            tracing::warn!(
                "GAS_TX_ALLOWED_TO is set but GAS_TX_MAX_GAS_LIMIT and/or GAS_TX_MAX_FEE_PER_GAS \
                 is unset - gas-tx (SignRawDigest) signing will FAIL CLOSED until both caps are \
                 pinned"
            );
        }

        // Unset, unparseable or zero gives the default.
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

    /// True only when all three pin fields are set. Only a full pin allows
    /// bridge signing.
    ///
    /// AND, not OR: a zero `bridge_contract` must not match a request for the
    /// zero address.
    ///
    /// An empty config (dev, mock) uses the dev path. For a partial config, see
    /// [`is_partially_configured`](Self::is_partially_configured).
    pub fn is_configured(&self) -> bool {
        self.chain_id != 0 && self.bridge_contract != [0u8; 20] && !self.rgb_asset_id.is_empty()
    }

    /// True when some, but not all, pin fields are set. Callers fail closed and
    /// do not use the dev path.
    pub fn is_partially_configured(&self) -> bool {
        let any = self.chain_id != 0
            || self.bridge_contract != [0u8; 20]
            || !self.rgb_asset_id.is_empty();
        any && !self.is_configured()
    }

    /// If plain-BTC (vanilla, create_utxo) signing is allowed. Only the
    /// `BTC_MAX_TOTAL_SATS` cap controls it.
    ///
    /// [`crate::policy::SecurityPolicy`] attests it as `allow_vanilla_psbt`.
    /// `btc_crosscheck::validate_btc_request` enforces it. The two must agree.
    pub fn allows_vanilla_btc(&self) -> bool {
        self.btc_max_total_sats != 0
    }
}

/// Parse 40 hex chars, with or without `0x`, into 20 bytes.
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

/// Boot config of the in-enclave `FundsIn` verification (`evm-rpc`).
/// The endpoint comes at launch ([`Endpoints`]).
#[cfg(feature = "evm-rpc")]
#[derive(Debug, Clone)]
pub struct EvmRpcConfig {
    /// Min confirmations of a `FundsIn` receipt below the RPC head block
    /// (`EVM_MIN_CONFIRMATIONS`, default 12).
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
    /// A safe head distance for most EVM chains.
    const DEFAULT_MIN_CONFIRMATIONS: u64 = 12;

    /// Load `EVM_MIN_CONFIRMATIONS` from env.
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

/// True if the host of `url` is exactly `127.0.0.1`, `[::1]` or `localhost`.
/// Exact match, so `127.0.0.1.evil.com` is not loopback.
#[cfg(feature = "helios")]
fn is_loopback_url(url: &str) -> bool {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    // Drop path/query/fragment, then any `userinfo@` prefix.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // Strip the port. IPv6 literals have brackets (`[::1]:8545`).
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

/// Helios light-client config (`helios` feature, not in production).
///
/// [`HeliosConfig::from_env`] gives `Some` only when `HELIOS_EXECUTION_RPC`
/// is set. The URLs must be loopback. Helios verifies the untrusted upstreams
/// against the pinned checkpoint.
#[cfg(feature = "helios")]
#[derive(Debug, Clone)]
pub struct HeliosConfig {
    /// Untrusted execution RPC (`HELIOS_EXECUTION_RPC`, required), for example
    /// `http://127.0.0.1:18545`.
    pub execution_rpc: String,
    /// Beacon RPC (`HELIOS_CONSENSUS_RPC`, default `http://127.0.0.1:18550`).
    pub consensus_rpc: String,
    /// Helios network name: `mainnet` | `sepolia` | `holesky`
    /// (`HELIOS_NETWORK`, default `mainnet`).
    pub network: String,
    /// Weak-subjectivity checkpoint: 0x-prefixed 32-byte beacon block root
    /// (`HELIOS_CHECKPOINT`). `None` fails client init closed.
    pub checkpoint: Option<String>,
    /// Reject a checkpoint older than the safe weak-subjectivity window
    /// (`HELIOS_STRICT_CHECKPOINT_AGE`, default `true`).
    pub strict_checkpoint_age: bool,
}

#[cfg(feature = "helios")]
impl HeliosConfig {
    const DEFAULT_CONSENSUS_RPC: &'static str = "http://127.0.0.1:18550";

    /// Load from `HELIOS_*` env. `None` when `HELIOS_EXECUTION_RPC` is unset.
    /// A non-loopback URL is logged as an error. It cannot connect, because the
    /// enclave has no direct egress.
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
            // The same check as the client root store, so a bad CA is never
            // attested.
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
            // Dev import-only mode.
            None
        } else {
            let config = crate::kms::KmsConfig {
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
        // Contract zero: an OR check accepts a request for the zero address.
        let c = BridgeConfig {
            chain_id: 1,
            bridge_contract: [0u8; 20],
            rgb_asset_id: "rgb:asset".into(),
            ..Default::default()
        };
        assert!(!c.is_configured());
        assert!(c.is_partially_configured());
    }

    /// Default is the fail-closed `None`: only `value == 0`.
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
        // A `starts_with` check accepts all of these.
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
