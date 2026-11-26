//! Bridge configuration, pinned from env at boot.
//!
//! The chain, MultisigProxy contract (`EVM_PROXY_CONTRACT_ADDRESS`) and RGB
//! asset go into the attestation `user_data` (`canonical_pubkey_bundle` in
//! `server/keys.rs`). So:
//!
//!   1. a `GetAttestedPublicKey` verifier sees the (chain_id, contract, asset);
//!   2. a `fundsOut` `Sign` rejects request fields that do not match this config.
//!
//! Production sets all three env vars. A release bridge build without them does
//! not boot ([`crate::policy`]). Dev and mock builds can leave them unset. Then
//! the bundle commits empty values.

use crate::error::{EnclaveError, Result};
use attestation_verify::{BitcoinNetwork, EvmFinalityTag};

/// Default consignment size limit (`MAX_CONSIGNMENT_BYTES`), and the largest
/// value that variable may set. The wire frame
/// ([`crate::framing::MAX_MESSAGE_SIZE`]) also limits it.
///
/// The default is sized for a history of 10_000 state transitions. A V1
/// consignment carries no schema or types. Each transition adds about 470
/// bytes, or 890 with an SPV proof of a full mainnet block. Measured: 10_002
/// transitions with a proof each are 8_932_069 bytes
/// (`a_history_of_10_000_transfers_fits_the_default_limits`).
///
/// The memory model caps the value here. Validating the densest consignment
/// measured takes about 53 times its bytes. At this size a burn request, in
/// the enclave and its validator child together, fits the heap of a worker
/// (`memory.rs`) with little room left. A larger image value stops the boot
/// ([`parse_consignment_limit`]). `SetLimits` checks a runtime value
/// (`limits.rs`).
pub const DEFAULT_MAX_CONSIGNMENT_BYTES: usize = 10 * 1024 * 1024;

/// The most bytes a fascia may have. The operator cannot change it: the rules
/// of the image set how large a valid fascia is. The widest one is a refill of
/// `MAX_REFILL_RIGHTS` rights, measured at about 60 bytes for each right, and
/// a mint is under 1 KiB. So the limit leaves about four times that room for
/// the bundles of other contracts that the tx moves.
pub const MAX_FASCIA_BYTES: usize = 64 * 1024;

/// The most bundles a fascia may hold, one for each contract the tx moves. It
/// is the most allocations the connector's wallet keeps on one UTXO, so a mint
/// or a refill of one right never holds more.
pub const MAX_FASCIA_BUNDLES: u32 = 20;

/// The most bytes a PSBT may have in the image, on every path that parses
/// one. The operator can change it (`max_psbt_bytes`). A decoded input or
/// output takes far more memory than its bytes. The densest shape measured
/// parses at about 102 times its bytes: one input, and outputs that each
/// carry two empty records. At this limit, the two PSBTs a request can hold
/// parsed at once fit the heap each worker holds (`memory.rs`).
///
/// The tested flows are far smaller: a mint is about 1 KiB, and a rights
/// refill of 255 outputs measured about 40 KiB. rgb-lib puts the whole
/// previous transaction into each input. So the size of a plain-BTC PSBT
/// grows with its inputs and the size of their previous transactions. A PSBT
/// that spends very many outputs of large transactions must be split.
pub const MAX_PSBT_BYTES: usize = 1024 * 1024;

/// Refuses `bytes` over `max_psbt_bytes`, the limit in force, before any
/// parse. `what` names the field in the error.
pub fn check_psbt_size(what: &str, bytes: &[u8]) -> crate::error::Result<()> {
    check_size(what, bytes, crate::limits::get().max_psbt_bytes)
}

/// Refuses a fascia over [`MAX_FASCIA_BYTES`], before any parse.
pub fn check_fascia_size(what: &str, bytes: &[u8]) -> crate::error::Result<()> {
    check_size(what, bytes, MAX_FASCIA_BYTES as u64)
}

fn check_size(what: &str, bytes: &[u8], max: u64) -> crate::error::Result<()> {
    if bytes.len() as u64 > max {
        return Err(crate::error::EnclaveError::CrossCheck(format!(
            "{what} is {} bytes; the limit is {max}",
            bytes.len()
        )));
    }
    Ok(())
}

/// Env var of [`BridgeConfig::spv_min_confirmations`].
pub const SPV_MIN_CONFIRMATIONS_ENV: &str = "SPV_MIN_CONFIRMATIONS";
/// Default depth of each Bitcoin witness tx before the enclave signs.
pub const DEFAULT_SPV_MIN_CONFIRMATIONS: u32 = 3;

/// Env var of [`BridgeConfig::mint_witness_sat`].
pub const MINT_WITNESS_SAT_ENV: &str = "MINT_WITNESS_SAT";
/// Default sats a witness mint pays to its recipient's output.
pub const DEFAULT_MINT_WITNESS_SAT: u64 = 1_500;
/// P2PKH dust, the highest of the scripts a `wvout` invoice can name.
pub const MIN_MINT_WITNESS_SAT: u64 = 546;
/// A typo guard: every witness mint pays `MINT_WITNESS_SAT` of the bridge's sats.
pub const MAX_MINT_WITNESS_SAT: u64 = 10_000;

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
    /// value must fit the runtime limit `gas_tx_max_value_wei`. See
    /// `networks::evm::gas_tx`.
    ///
    /// [`gas_tx_allowed_selectors`](Self::gas_tx_allowed_selectors) limits the
    /// callable functions. The runtime limits `gas_tx_max_fee_per_gas` and
    /// `gas_tx_max_gas_limit` limit the burn.
    ///
    /// [`crate::policy::SecurityPolicy`] commits the gas-tx rule in `user_data`.
    pub gas_tx_allowed_to: Option<[u8; 20]>,
    /// Allowed 4-byte selectors of gas-tx calldata (`GAS_TX_ALLOWED_SELECTORS`,
    /// comma-separated hex). Empty calldata is refused: it calls the fallback or
    /// receive function. An empty list refuses all gas-tx signing.
    pub gas_tx_allowed_selectors: Vec<[u8; 4]>,
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
    /// Emitter of `FundsIn`/`BridgeFundsIn` (`FUNDS_IN_CONTRACT`), default
    /// `bridge_contract`. The bridge entry contract is not the MultisigProxy in
    /// this deployment, so set it explicitly.
    pub funds_in_contract: [u8; 20],
    /// RPC block tag required for deposit inclusion (`EVM_FINALITY_TAG`). Attested.
    pub evm_finality_tag: EvmFinalityTag,
    /// The ERC-20 that the Bridge releases (`TOKEN_CONTRACT`, `Bridge.TOKEN`).
    /// An input of the `burnId` preimage
    /// (`networks::evm::validation::validate_burn_id`). Zero = unset: dev skips
    /// the check, production does not boot ([`crate::policy::ProductionPolicy`]).
    /// Attested.
    pub token_contract: [u8; 20],
    /// Bitcoin network (`BITCOIN_NETWORK`, default mainnet). The same value
    /// selects the SPV header chain and the consignment network. Attested.
    pub bitcoin_network: BitcoinNetwork,
    /// If a `fundsOut` proof must carry BtcRelay commitments that the enclave
    /// checks against its own chain (`BTC_RELAY_MODE`). Default `required`.
    /// `none` is for a local stand or a public-Signet image. Production does
    /// not boot on it ([`crate::policy::ProductionPolicy::check_invariants`]).
    pub btc_relay_mode: BtcRelayMode,
    /// Image value of the consignment size limit (`MAX_CONSIGNMENT_BYTES`).
    /// Unset or 0 gives [`DEFAULT_MAX_CONSIGNMENT_BYTES`], and a larger value
    /// stops the boot ([`parse_consignment_limit`]). Not attested. `SetLimits`
    /// can change it.
    pub max_consignment_bytes: usize,
    /// Min depth of each Bitcoin witness tx (`SPV_MIN_CONFIRMATIONS`, default
    /// [`DEFAULT_SPV_MIN_CONFIRMATIONS`], at least 1). Image env, so PCR0
    /// measures it, and attested.
    pub spv_min_confirmations: u32,
    /// Exact sats a witness mint pays to its recipient's output
    /// (`MINT_WITNESS_SAT`, default [`DEFAULT_MINT_WITNESS_SAT`], from
    /// [`MIN_MINT_WITNESS_SAT`] to [`MAX_MINT_WITNESS_SAT`]). It must equal the
    /// connector's value. Image env, so PCR0 measures it; not attested.
    pub mint_witness_sat: u64,
    /// The AWS accounts a KMS key may live in (`KMS_ALLOWED_ACCOUNT_IDS`). Image
    /// env, so PCR0 measures it. Empty when unset; a release mint image then
    /// refuses every key in `SetEndpoints`. A build with no KMS key, such as
    /// burn, has no list and does not read the env var.
    #[cfg(feature = "kms-persistence")]
    pub kms_allowed_accounts: Vec<String>,
}

/// Image env var: the AWS accounts a KMS key may live in.
#[cfg(feature = "kms-persistence")]
pub const KMS_ALLOWED_ACCOUNTS_ENV: &str = "KMS_ALLOWED_ACCOUNT_IDS";

/// Env var selecting [`BtcRelayMode`].
pub const BTC_RELAY_MODE_ENV: &str = "BTC_RELAY_MODE";

fn parse_evm_finality_tag(
    value: std::result::Result<String, std::env::VarError>,
) -> std::result::Result<EvmFinalityTag, String> {
    match value {
        Ok(value) => value.parse(),
        Err(std::env::VarError::NotPresent) => Ok(EvmFinalityTag::Finalized),
        Err(std::env::VarError::NotUnicode(_)) => Err("value must be valid Unicode".into()),
    }
}

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
            gas_tx_allowed_selectors: Vec::new(),
            btc_max_total_sats: 0,
            funds_in_contract: [0u8; 20],
            evm_finality_tag: EvmFinalityTag::Finalized,
            token_contract: [0u8; 20],
            bitcoin_network: BitcoinNetwork::Mainnet,
            btc_relay_mode: BtcRelayMode::Required,
            max_consignment_bytes: DEFAULT_MAX_CONSIGNMENT_BYTES,
            spv_min_confirmations: DEFAULT_SPV_MIN_CONFIRMATIONS,
            mint_witness_sat: DEFAULT_MINT_WITNESS_SAT,
            #[cfg(feature = "kms-persistence")]
            kms_allowed_accounts: Vec::new(),
        }
    }
}

impl BridgeConfig {
    /// Required settings of a public-Signet image with BtcRelay off.
    pub fn validate_public_signet(&self) -> std::result::Result<(), String> {
        if self.bitcoin_network != BitcoinNetwork::Signet {
            return Err("a public-Signet image requires BITCOIN_NETWORK=signet".into());
        }
        if self.btc_relay_mode != BtcRelayMode::None {
            return Err("a public-Signet image requires BTC_RELAY_MODE=none".into());
        }
        if self.spv_min_confirmations == 0 {
            return Err("a public-Signet image requires at least one Bitcoin confirmation".into());
        }
        if !self.is_configured()
            || self.funds_in_contract == [0; 20]
            || self.token_contract == [0; 20]
        {
            return Err("a public-Signet image requires the EVM_CHAIN_ID, EVM_PROXY_CONTRACT_ADDRESS and RGB_ASSET_ID pins and a non-zero FUNDS_IN_CONTRACT and TOKEN_CONTRACT".into());
        }
        Ok(())
    }

    /// Load from env. An invalid `EVM_FINALITY_TAG` refuses startup.
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

        let btc_max_total_sats = std::env::var("BTC_MAX_TOTAL_SATS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        let funds_in_contract = parse_funds_in_contract(
            std::env::var("FUNDS_IN_CONTRACT").ok().as_deref(),
            bridge_contract,
        )
        .unwrap_or_else(|e| panic!("{e}"));

        let evm_finality_tag = parse_evm_finality_tag(std::env::var("EVM_FINALITY_TAG"))
            .expect("EVM_FINALITY_TAG must be latest, safe, or finalized");

        let token_contract = std::env::var("TOKEN_CONTRACT")
            .ok()
            .and_then(|s| parse_eth_address(&s).ok())
            .unwrap_or([0u8; 20]);

        let btc_relay_mode = BtcRelayMode::from_env_value(std::env::var(BTC_RELAY_MODE_ENV).ok());

        // The SPV parser, so the attested network is the one the chain runs.
        let bitcoin_network = crate::networks::rgb::spv::Network::from_env_str(
            &crate::bootstrap::bitcoin_network_str(),
        )
        .expect("BITCOIN_NETWORK must be a known network")
        .attested();

        let max_consignment_bytes =
            parse_consignment_limit(std::env::var("MAX_CONSIGNMENT_BYTES").ok().as_deref())
                .unwrap_or_else(|e| panic!("{e}"));

        let spv_min_confirmations =
            parse_spv_min_confirmations(std::env::var(SPV_MIN_CONFIRMATIONS_ENV).ok().as_deref())
                .unwrap_or_else(|e| panic!("{e}"));

        let mint_witness_sat =
            parse_mint_witness_sat(std::env::var(MINT_WITNESS_SAT_ENV).ok().as_deref())
                .unwrap_or_else(|e| panic!("{e}"));

        Self {
            chain_id,
            bridge_contract,
            rgb_asset_id,
            gas_tx_allowed_to,
            gas_tx_allowed_selectors,
            btc_max_total_sats,
            funds_in_contract,
            evm_finality_tag,
            token_contract,
            bitcoin_network,
            btc_relay_mode,
            max_consignment_bytes,
            spv_min_confirmations,
            mint_witness_sat,
            #[cfg(feature = "kms-persistence")]
            kms_allowed_accounts: parse_kms_allowed_accounts(
                std::env::var(KMS_ALLOWED_ACCOUNTS_ENV).ok().as_deref(),
            )
            .unwrap_or_else(|e| panic!("{e}")),
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

/// Parses `KMS_ALLOWED_ACCOUNT_IDS`: comma-separated 12-digit AWS account ids.
/// Unset or blank gives an empty list. A malformed entry is an error, so a bad
/// image does not boot with a partial list.
#[cfg(feature = "kms-persistence")]
pub fn parse_kms_allowed_accounts(value: Option<&str>) -> std::result::Result<Vec<String>, String> {
    let ids: Vec<String> = value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(String::from)
        .collect();
    if ids
        .iter()
        .any(|id| id.len() != 12 || !id.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(format!(
            "{KMS_ALLOWED_ACCOUNTS_ENV} must list 12-digit AWS account ids"
        ));
    }
    Ok(ids)
}

/// Parses `MAX_CONSIGNMENT_BYTES`, the image value of `max_consignment_bytes`.
/// Unset, unparseable or zero gives the default. A value above
/// [`DEFAULT_MAX_CONSIGNMENT_BYTES`] is refused, because at the image frame the memory
/// model holds only up to that size (`memory.rs`). `SetLimits` can change it later.
pub fn parse_consignment_limit(value: Option<&str>) -> std::result::Result<usize, String> {
    match value
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
    {
        None => Ok(DEFAULT_MAX_CONSIGNMENT_BYTES),
        Some(n) if n <= DEFAULT_MAX_CONSIGNMENT_BYTES => Ok(n),
        Some(n) => Err(format!(
            "MAX_CONSIGNMENT_BYTES {n} is above {DEFAULT_MAX_CONSIGNMENT_BYTES}, the largest \
             consignment the request memory model allows (memory.rs); set a smaller value or \
             leave it unset"
        )),
    }
}

/// Parse `SPV_MIN_CONFIRMATIONS`. Unset or empty gives the default. Zero or a
/// non-number is an error, so a typo cannot lower the depth.
pub fn parse_spv_min_confirmations(value: Option<&str>) -> std::result::Result<u32, String> {
    let Some(raw) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(DEFAULT_SPV_MIN_CONFIRMATIONS);
    };
    match raw.parse::<u32>() {
        Ok(n) if n >= 1 => Ok(n),
        _ => Err(format!(
            "{SPV_MIN_CONFIRMATIONS_ENV} {raw:?} is not valid: set a whole number of at least 1, \
             or leave it unset for {DEFAULT_SPV_MIN_CONFIRMATIONS}"
        )),
    }
}

/// Parse `MINT_WITNESS_SAT`. Unset or empty gives the default. A non-number or
/// a value out of bounds is an error, so a typo cannot change what a mint pays.
pub fn parse_mint_witness_sat(value: Option<&str>) -> std::result::Result<u64, String> {
    let Some(raw) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(DEFAULT_MINT_WITNESS_SAT);
    };
    match raw.parse::<u64>() {
        Ok(n) if (MIN_MINT_WITNESS_SAT..=MAX_MINT_WITNESS_SAT).contains(&n) => Ok(n),
        _ => Err(format!(
            "{MINT_WITNESS_SAT_ENV} {raw:?} is not valid: set a whole number of sats from \
             {MIN_MINT_WITNESS_SAT} to {MAX_MINT_WITNESS_SAT}, or leave it unset for \
             {DEFAULT_MINT_WITNESS_SAT}"
        )),
    }
}

/// Unset gives the proxy address (`EVM_PROXY_CONTRACT_ADDRESS`). A set value
/// that is not an address stops the boot: a typo must not move the FundsIn pin
/// to the proxy address.
fn parse_funds_in_contract(
    raw: Option<&str>,
    bridge_contract: [u8; 20],
) -> std::result::Result<[u8; 20], String> {
    match raw {
        None => Ok(bridge_contract),
        Some(v) => {
            parse_eth_address(v).map_err(|e| format!("FUNDS_IN_CONTRACT is not an address: {e}"))
        }
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

/// The most bytes the EVM RPC CA certificate may have. A CA certificate is a
/// few KiB. The DER parse only borrows the bytes, and the enclave keeps one
/// copy of them for the TLS client. The limit bounds that copy (`memory.rs`).
pub const MAX_EVM_RPC_CA_DER_BYTES: usize = 16 * 1024;

/// The most bytes of each string in `SetEndpoints`. It fits the longest AWS
/// key ARN, and the other strings are shorter.
pub const MAX_ENDPOINT_STRING_BYTES: usize = 2048;

/// The TLS pin of the EVM RPC endpoint.
#[derive(Clone, PartialEq, Eq)]
pub struct EvmRpcTls {
    /// The name for SNI and the certificate check, lowercased.
    pub host: String,
    /// DER of the only trusted root.
    pub ca_der: Vec<u8>,
    /// The upstream TLS port. The forwarder listens on it in the enclave.
    pub tls_port: u16,
    /// Runtime RPC path. May contain a credential; redact in diagnostics.
    pub path: String,
}

impl std::fmt::Debug for EvmRpcTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvmRpcTls")
            .field("host", &self.host)
            .field("ca_der", &self.ca_der)
            .field("tls_port", &self.tls_port)
            .field("path", &"[REDACTED]")
            .finish()
    }
}

/// Accept only an absolute path with unreserved ASCII characters. Keeping
/// authority, query, fragment and escaping out makes the TLS host independent
/// of the credential and avoids URL-parser normalization of dot segments.
#[cfg(feature = "rgb-validation")]
fn parse_evm_rpc_path(value: &str) -> std::result::Result<String, String> {
    let path = if value.is_empty() { "/" } else { value };
    if path.len() > 2048
        || !path.starts_with('/')
        || path.starts_with("//")
        || !path
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"/-._~".contains(&c))
        || path.split('/').any(|s| s == "." || s == "..")
    {
        return Err("evm_rpc_path must be an absolute ASCII path (max 2048 bytes), without query, fragment, escapes or dot segments".into());
    }
    Ok(path.into())
}

/// Endpoints and KMS pins set once at launch. Production policy commits its
/// public fields; Development policy does not attest these runtime values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Endpoints {
    /// `None` without `rgb-validation`.
    pub evm_rpc_tls: Option<EvmRpcTls>,
    /// `None` without `kms-persistence`, and in an import-only build with no
    /// KMS values.
    pub kms: Option<crate::policy::KmsPin>,
    /// The (chain ID, EID) pairs that a LayerZero release may name.
    pub lz_routes: Vec<LzRoute>,
}

/// One destination network of a LayerZero release: the `destinationChainId`
/// of a burn record and the `dstEid` that it must come with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LzRoute {
    pub chain_id: u64,
    pub eid: u32,
}

/// Most LayerZero routes that `SetEndpoints` takes.
pub const MAX_LZ_ROUTES: usize = 64;

/// Checks the LayerZero routes of `SetEndpoints`: at most [`MAX_LZ_ROUTES`], a
/// chain ID and an EID above 0, and no repeat of either. A repeat would let
/// one chain have two EIDs, or two chains share one.
fn parse_lz_routes(routes: &[crate::proto::LzRoute]) -> std::result::Result<Vec<LzRoute>, String> {
    if routes.len() > MAX_LZ_ROUTES {
        return Err(format!(
            "lz_routes has {} entries; the limit is {MAX_LZ_ROUTES}",
            routes.len()
        ));
    }
    let mut parsed: Vec<LzRoute> = Vec::with_capacity(routes.len());
    for route in routes {
        if route.chain_id == 0 || route.eid == 0 {
            return Err("lz_routes: chain_id and eid must be above 0".into());
        }
        if parsed
            .iter()
            .any(|seen| seen.chain_id == route.chain_id || seen.eid == route.eid)
        {
            return Err(format!(
                "lz_routes: chain_id {} or eid {} is listed twice",
                route.chain_id, route.eid
            ));
        }
        parsed.push(LzRoute {
            chain_id: route.chain_id,
            eid: route.eid,
        });
    }
    Ok(parsed)
}

impl Endpoints {
    /// Check the values this build uses. A value the build does not use
    /// must be empty. `kms_accounts` is the image's account list
    /// (`KMS_ALLOWED_ACCOUNT_IDS`). With no list, `allow_unpinned`
    /// (a dev or test build) skips the account check and a release build refuses.
    pub fn parse(
        req: &crate::proto::SetEndpointsRequest,
        kms_accounts: &[String],
        allow_unpinned: bool,
    ) -> std::result::Result<Self, String> {
        // The parsers below split a string into parts that take more memory
        // than its bytes, so the size limit runs first (`memory.rs`).
        for (name, value) in [
            ("evm_rpc_host", &req.evm_rpc_host),
            ("kms_key_arn", &req.kms_key_arn),
            ("kms_region", &req.kms_region),
            ("kms_seed_id", &req.kms_seed_id),
            ("kms_expected_evm_address", &req.kms_expected_evm_address),
        ] {
            if value.len() > MAX_ENDPOINT_STRING_BYTES {
                return Err(format!(
                    "{name} is {} bytes; the limit is {MAX_ENDPOINT_STRING_BYTES}",
                    value.len()
                ));
            }
        }
        #[cfg(feature = "rgb-validation")]
        let evm_rpc_tls = {
            let host = parse_host("evm_rpc_host", &req.evm_rpc_host)?;
            // A CA certificate is a few KiB. Refuse more before the parse and
            // before the copy that the TLS client keeps.
            if req.evm_rpc_ca_der.len() > MAX_EVM_RPC_CA_DER_BYTES {
                return Err(format!(
                    "evm_rpc_ca_der is {} bytes; the limit is {MAX_EVM_RPC_CA_DER_BYTES}",
                    req.evm_rpc_ca_der.len()
                ));
            }
            let ca = rustls_pki_types::CertificateDer::from(req.evm_rpc_ca_der.as_slice());
            // The same check as the client root store, so a bad CA is never
            // attested.
            webpki::anchor_from_trusted_cert(&ca)
                .map_err(|e| format!("evm_rpc_ca_der is not a valid CA certificate: {e}"))?;
            Some(EvmRpcTls {
                host,
                ca_der: req.evm_rpc_ca_der.clone(),
                tls_port: parse_port("evm_rpc_tls_port", req.evm_rpc_tls_port)?,
                path: parse_evm_rpc_path(&req.evm_rpc_path)?,
            })
        };
        #[cfg(not(feature = "rgb-validation"))]
        let evm_rpc_tls = {
            unused("evm_rpc_path", req.evm_rpc_path.is_empty())?;
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
            config
                .validate_account(kms_accounts, allow_unpinned)
                .map_err(|e| e.to_string())?;
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
            // This build takes no KMS key, so it has no account list to apply.
            let _ = (kms_accounts, allow_unpinned);
            for (name, value) in kms_values {
                unused(name, value.is_empty())?;
            }
            None
        };

        let lz_routes = parse_lz_routes(&req.lz_routes)?;
        Ok(Self {
            evm_rpc_tls,
            kms,
            lz_routes,
        })
    }
}

#[cfg(any(not(feature = "rgb-validation"), not(feature = "kms-persistence")))]
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
mod tests;
