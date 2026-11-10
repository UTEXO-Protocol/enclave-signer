//! Canonical encoding of the enclave attested security policy.
//!
//! The enclave resolves its posture once at boot. This module serializes it,
//! and the enclave adds it to the attestation `user_data` commitment with the
//! public-key bundle (see
//! `enclave/src/server/keys.rs::handle_get_attested_public_key`).
//!
//! This module is the only definition of the encoding. The enclave and every
//! verifier (the `attest-verify` CLI, the clone peer check) build an
//! [`AttestedPolicy`] and call [`AttestedPolicy::to_bytes`]. A posture
//! mismatch gives a `user_data` hash mismatch.
//!
//! Wire contract: discriminants and field order are fixed. Do not renumber a
//! variant or reorder fields. Bump [`POLICY_COMMITMENT_V1`] instead.

/// Version tag at the start of every policy commitment. A verifier rejects a
/// different policy version instead of accepting different security semantics.
/// Bump it on every layout change or change to a fixed policy requirement.
/// V1 encodes the selected EVM RPC finality tag and the Bitcoin witness depth.
/// Every accepted FundsIn receipt must belong to the canonical chain at or
/// below that tagged head. The selected tag is attested so verifiers can
/// reject a weaker policy, including `latest` when they require `safe`.
/// It also commits the clone-peer PCR3 of a cloning role.
pub const POLICY_COMMITMENT_V1: u8 = 1;

/// Bridge directions that the image signs. It comes from build features, so
/// PCR0 measures it and no host config can widen it.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerRole {
    /// No signer role: an image that is neither mint nor burn.
    Combined = 0,
    /// `mint-signer`: EVM -> RGB only. Refuses every `fundsOut` release.
    Mint = 1,
    /// `burn-signer`: EVM releases only. Refuses every RGB mint PSBT.
    Burn = 2,
}

impl SignerRole {
    /// True for a role that clones its seed. The mint signer persists its
    /// seed with KMS and refuses cloning; the other roles clone.
    pub fn clones(self) -> bool {
        self != SignerRole::Mint
    }
}

/// Source of the EVM `FundsIn` deposit evidence that the enclave verifies
/// before it signs an EVM->RGB bridge PSBT. The shipped image uses
/// [`PinnedTlsRpc`](EvmDataSource::PinnedTlsRpc). The discriminants are wire
/// values.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvmDataSource {
    /// No EVM verification in the build (`rgb-validation` off). The enclave rejects
    /// every EVM->RGB bridge request.
    Disabled = 0,
    /// Plaintext JSON-RPC over the host relay. The host can forge the
    /// responses. Dev and test builds only.
    RawRpc = 1,
    // 2 is reserved. Do not use it.
    /// JSON-RPC over TLS that ends inside the enclave. The host relays only
    /// ciphertext. The pinned CA and host ([`EvmRpcTlsPin`]) authenticate the
    /// endpoint. The chain state is not verified.
    PinnedTlsRpc = 3,
}

/// RPC head that must cover an EVM FundsIn receipt. The discriminants are
/// stable values in the attested policy, independent of the tag's spelling.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EvmFinalityTag {
    Latest = 0,
    Safe = 1,
    #[default]
    Finalized = 2,
}

impl EvmFinalityTag {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Latest => "latest",
            Self::Safe => "safe",
            Self::Finalized => "finalized",
        }
    }
}

impl std::fmt::Display for EvmFinalityTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for EvmFinalityTag {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "latest" => Ok(Self::Latest),
            "safe" => Ok(Self::Safe),
            "finalized" => Ok(Self::Finalized),
            _ => Err(format!(
                "invalid EVM finality tag {value:?}; expected latest, safe or finalized"
            )),
        }
    }
}

/// Bitcoin network of the image (`BITCOIN_NETWORK`). The consignment network
/// and the SPV header chain follow it. The discriminants are wire values.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinNetwork {
    Mainnet = 0,
    Testnet3 = 1,
    Signet = 2,
    Regtest = 3,
    Testnet4 = 4,
    /// The UTEXO custom signet (RGB `sbc`).
    SignetCustom = 5,
}

impl BitcoinNetwork {
    /// Parses a `BITCOIN_NETWORK` value, with the names the enclave accepts.
    pub fn from_env_str(s: &str) -> Option<Self> {
        match s {
            "bitcoin" | "mainnet" => Some(Self::Mainnet),
            "testnet" | "testnet3" => Some(Self::Testnet3),
            "signet" => Some(Self::Signet),
            "signetcustom" => Some(Self::SignetCustom),
            "testnet4" => Some(Self::Testnet4),
            "regtest" => Some(Self::Regtest),
            _ => None,
        }
    }
}

/// TLS pin of the EVM RPC endpoint. `host` is the name the certificate must
/// match. `ca_sha256` is the SHA-256 of the DER of the only trusted CA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmRpcTlsPin {
    pub host: String,
    pub ca_sha256: [u8; 32],
}

/// KMS key and seed object set at launch. Present only in a
/// `kms-persistence` build with KMS configured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KmsPin {
    pub key_arn: String,
    pub region: String,
    pub seed_id: String,
    /// The EVM address the recovered seed must give.
    pub expected_evm_address: Option<[u8; 20]>,
}

/// Source of Bitcoin anchor evidence for RGB consignment witness txs. Only
/// SPV is safe, so a production build always reports
/// [`SpvVerified`](BtcDataSource::SpvVerified).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcDataSource {
    /// Witness txids are checked against the enclave PoW-verified header
    /// chain (`spv`), not the host-controlled indexer.
    SpvVerified = 1,
}

/// Attestation root of trust: a real NSM device or the zero-PCR mock. Mock is
/// a `compile_error!` in release builds, so production is always
/// [`Real`](AttestationMode::Real). It is committed so the posture is complete.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationMode {
    Mock = 0,
    Real = 1,
}

/// The full enclave security posture in commitment form.
///
/// [`Production`](AttestedPolicy::Production) is the fail-closed bridge
/// posture: fully pinned, real attestation, SPV anchors and a known EVM data
/// source. A debug, dev-feature, no-SPV, unpinned or non-bridge build is
/// [`Development`](AttestedPolicy::Development). A production verifier must
/// reject it.
// Built once at boot, so the variant size difference does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestedPolicy {
    Production {
        allow_vanilla_psbt: bool,
        /// Bridge directions this image signs.
        signer_role: SignerRole,
        attestation: AttestationMode,
        evm_source: EvmDataSource,
        btc_source: BtcDataSource,
        chain_id: u64,
        /// Bitcoin network of the burns and mints this image accepts.
        bitcoin_network: BitcoinNetwork,
        bridge_contract: [u8; 20],
        rgb_asset_id: String,
        /// Contract whose FundsIn events can authorize bridge signing.
        funds_in_contract: [u8; 20],
        /// Required RPC head tag, selected at boot.
        evm_finality_tag: EvmFinalityTag,
        /// Minimum depth of each Bitcoin witness tx (`SPV_MIN_CONFIRMATIONS`).
        spv_min_confirmations: u32,
        /// Host of the Electrum server the operator set at launch.
        electrum_host: String,
        /// The EVM RPC TLS pin. `Some` only for [`EvmDataSource::PinnedTlsRpc`].
        evm_rpc_tls: Option<EvmRpcTlsPin>,
        /// Gas-tx (`SignRawDigest`) rule: the pinned destination, the gas and
        /// fee limits, and the allowed calldata selectors. An unset
        /// `GAS_TX_ALLOWED_TO` gives all zeros, and the enclave rejects the
        /// gas path.
        gas_tx_allowed_to: [u8; 20],
        gas_tx_max_gas_limit: u64,
        gas_tx_max_fee_per_gas: u128,
        /// Maximum native value (wei) of a gas tx, for the payable
        /// `lzFundsOutCall`. `0` means no non-zero value is signed. An unset
        /// `GAS_TX_MAX_VALUE_WEI` gives `0`.
        gas_tx_max_value_wei: u128,
        /// Allowed 4-byte calldata selectors. [`to_bytes`](AttestedPolicy::to_bytes)
        /// sorts and dedups them, so env order does not change the commitment.
        gas_tx_allowed_selectors: Vec<[u8; 4]>,
        /// ERC-20 that the Bridge releases (`TOKEN_CONTRACT`). It is an input
        /// to the on-chain `burnId` preimage, which the enclave recomputes.
        token_contract: [u8; 20],
        /// KMS pin set at launch.
        kms: Option<KmsPin>,
        /// PCR3 that a cloning peer must have: the enclave's own PCR3, the
        /// measurement of the parent instance IAM role. It binds clone peers
        /// to the operator's role. `Some` exactly for a role that clones (not
        /// [`SignerRole::Mint`]), and never all zero there.
        clone_peer_pcr3: Option<[u8; 48]>,
    },
    Development,
}

impl AttestedPolicy {
    /// Deterministic, length-prefixed encoding for attestation `user_data`.
    /// Layout (see the wire contract in the module docs):
    ///
    /// ```text
    /// [POLICY_COMMITMENT_V1]
    /// Production:  [0x01][allow_vanilla u8][signer_role u8][attestation u8]
    ///              [evm_source u8]
    ///              [btc_source u8][chain_id u64 BE][bitcoin_network u8]
    ///              [bridge_contract 20]
    ///              [len(asset) u32 BE][asset bytes][funds_in_contract 20]
    ///              [evm_finality_tag u8: 0 latest | 1 safe | 2 finalized]
    ///              [spv_min_confirmations u32 BE]
    ///              [len(electrum_host) u32 BE][electrum_host bytes]
    ///              [evm_rpc_tls: 0x00 | 0x01 ++ len(host) u32 BE ++ host
    ///               ++ ca_sha256 32]
    ///              [gas_tx_allowed_to 20][gas_tx_max_gas_limit u64 BE]
    ///              [gas_tx_max_fee_per_gas u128 BE]
    ///              [gas_tx_max_value_wei u128 BE]
    ///              [len(selectors) u32 BE][selector 4]...   (sorted, deduped)
    ///              [token_contract 20]
    ///              [kms: 0x00 | 0x01 ++ len(arn) u32 BE ++ arn
    ///               ++ len(region) u32 BE ++ region ++ len(seed_id) u32 BE
    ///               ++ seed_id ++ (0x00 | 0x01 ++ address 20)]
    ///              [clone_peer_pcr3: 0x00 | 0x01 ++ pcr3 48]
    /// Development: [0x00]
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(POLICY_COMMITMENT_V1);
        match self {
            AttestedPolicy::Production {
                allow_vanilla_psbt,
                signer_role,
                attestation,
                evm_source,
                btc_source,
                chain_id,
                bitcoin_network,
                bridge_contract,
                rgb_asset_id,
                funds_in_contract,
                evm_finality_tag,
                spv_min_confirmations,
                electrum_host,
                evm_rpc_tls,
                gas_tx_allowed_to,
                gas_tx_max_gas_limit,
                gas_tx_max_fee_per_gas,
                gas_tx_max_value_wei,
                gas_tx_allowed_selectors,
                token_contract,
                kms,
                clone_peer_pcr3,
            } => {
                out.push(0x01);
                out.push(*allow_vanilla_psbt as u8);
                out.push(*signer_role as u8);
                out.push(*attestation as u8);
                out.push(*evm_source as u8);
                out.push(*btc_source as u8);
                out.extend_from_slice(&chain_id.to_be_bytes());
                out.push(*bitcoin_network as u8);
                out.extend_from_slice(bridge_contract);
                out.extend_from_slice(&(rgb_asset_id.len() as u32).to_be_bytes());
                out.extend_from_slice(rgb_asset_id.as_bytes());
                out.extend_from_slice(funds_in_contract);
                out.push(*evm_finality_tag as u8);
                out.extend_from_slice(&spv_min_confirmations.to_be_bytes());
                out.extend_from_slice(&(electrum_host.len() as u32).to_be_bytes());
                out.extend_from_slice(electrum_host.as_bytes());
                match evm_rpc_tls {
                    Some(pin) => {
                        out.push(0x01);
                        out.extend_from_slice(&(pin.host.len() as u32).to_be_bytes());
                        out.extend_from_slice(pin.host.as_bytes());
                        out.extend_from_slice(&pin.ca_sha256);
                    }
                    None => out.push(0x00),
                }
                // Gas-tx rule.
                out.extend_from_slice(gas_tx_allowed_to);
                out.extend_from_slice(&gas_tx_max_gas_limit.to_be_bytes());
                out.extend_from_slice(&gas_tx_max_fee_per_gas.to_be_bytes());
                out.extend_from_slice(&gas_tx_max_value_wei.to_be_bytes());
                // Sort and dedup the selectors, so env order and duplicates
                // do not change the commitment.
                let mut selectors = gas_tx_allowed_selectors.clone();
                selectors.sort_unstable();
                selectors.dedup();
                out.extend_from_slice(&(selectors.len() as u32).to_be_bytes());
                for sel in &selectors {
                    out.extend_from_slice(sel);
                }
                // Released token, a `burnId` preimage input.
                out.extend_from_slice(token_contract);
                match kms {
                    Some(pin) => {
                        out.push(0x01);
                        for field in [&pin.key_arn, &pin.region, &pin.seed_id] {
                            out.extend_from_slice(&(field.len() as u32).to_be_bytes());
                            out.extend_from_slice(field.as_bytes());
                        }
                        match pin.expected_evm_address {
                            Some(address) => {
                                out.push(0x01);
                                out.extend_from_slice(&address);
                            }
                            None => out.push(0x00),
                        }
                    }
                    None => out.push(0x00),
                }
                match clone_peer_pcr3 {
                    Some(pcr3) => {
                        out.push(0x01);
                        out.extend_from_slice(pcr3);
                    }
                    None => out.push(0x00),
                }
            }
            AttestedPolicy::Development => {
                out.push(0x00);
            }
        }
        out
    }

    /// Inverse of [`to_bytes`](AttestedPolicy::to_bytes). Rejects another
    /// version, an unknown tag, a short or long input, a string that is not
    /// UTF-8 and a selector list that is not sorted and unique.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PolicyDecodeError> {
        let mut r = Reader(bytes);
        if r.u8()? != POLICY_COMMITMENT_V1 {
            return Err(PolicyDecodeError("unknown policy version"));
        }
        let policy = match r.u8()? {
            0x00 => AttestedPolicy::Development,
            0x01 => {
                let allow_vanilla_psbt = r.flag()?;
                let signer_role = match r.u8()? {
                    0 => SignerRole::Combined,
                    1 => SignerRole::Mint,
                    2 => SignerRole::Burn,
                    _ => return Err(PolicyDecodeError("unknown signer role")),
                };
                let attestation = match r.u8()? {
                    0 => AttestationMode::Mock,
                    1 => AttestationMode::Real,
                    _ => return Err(PolicyDecodeError("unknown attestation mode")),
                };
                let evm_source = match r.u8()? {
                    0 => EvmDataSource::Disabled,
                    1 => EvmDataSource::RawRpc,
                    3 => EvmDataSource::PinnedTlsRpc,
                    _ => return Err(PolicyDecodeError("unknown EVM data source")),
                };
                let btc_source = match r.u8()? {
                    1 => BtcDataSource::SpvVerified,
                    _ => return Err(PolicyDecodeError("unknown BTC data source")),
                };
                let chain_id = u64::from_be_bytes(r.array()?);
                let bitcoin_network = match r.u8()? {
                    0 => BitcoinNetwork::Mainnet,
                    1 => BitcoinNetwork::Testnet3,
                    2 => BitcoinNetwork::Signet,
                    3 => BitcoinNetwork::Regtest,
                    4 => BitcoinNetwork::Testnet4,
                    5 => BitcoinNetwork::SignetCustom,
                    _ => return Err(PolicyDecodeError("unknown Bitcoin network")),
                };
                let bridge_contract = r.array()?;
                let rgb_asset_id = r.string()?;
                let funds_in_contract = r.array()?;
                let evm_finality_tag = match r.u8()? {
                    0 => EvmFinalityTag::Latest,
                    1 => EvmFinalityTag::Safe,
                    2 => EvmFinalityTag::Finalized,
                    _ => return Err(PolicyDecodeError("unknown EVM finality tag")),
                };
                let spv_min_confirmations = u32::from_be_bytes(r.array()?);
                let electrum_host = r.string()?;
                let evm_rpc_tls = r
                    .flag()?
                    .then(|| -> Result<_, PolicyDecodeError> {
                        Ok(EvmRpcTlsPin {
                            host: r.string()?,
                            ca_sha256: r.array()?,
                        })
                    })
                    .transpose()?;
                let gas_tx_allowed_to = r.array()?;
                let gas_tx_max_gas_limit = u64::from_be_bytes(r.array()?);
                let gas_tx_max_fee_per_gas = u128::from_be_bytes(r.array()?);
                let gas_tx_max_value_wei = u128::from_be_bytes(r.array()?);
                let count = r.len()?;
                let mut gas_tx_allowed_selectors: Vec<[u8; 4]> = Vec::new();
                for _ in 0..count {
                    let selector = r.array()?;
                    if gas_tx_allowed_selectors.last() >= Some(&selector) {
                        return Err(PolicyDecodeError("selectors are not sorted and unique"));
                    }
                    gas_tx_allowed_selectors.push(selector);
                }
                let token_contract = r.array()?;
                let kms = r
                    .flag()?
                    .then(|| -> Result<_, PolicyDecodeError> {
                        Ok(KmsPin {
                            key_arn: r.string()?,
                            region: r.string()?,
                            seed_id: r.string()?,
                            expected_evm_address: r.flag()?.then(|| r.array()).transpose()?,
                        })
                    })
                    .transpose()?;
                let clone_peer_pcr3 = r.flag()?.then(|| r.array()).transpose()?;
                AttestedPolicy::Production {
                    allow_vanilla_psbt,
                    signer_role,
                    attestation,
                    evm_source,
                    btc_source,
                    chain_id,
                    bitcoin_network,
                    bridge_contract,
                    rgb_asset_id,
                    funds_in_contract,
                    evm_finality_tag,
                    spv_min_confirmations,
                    electrum_host,
                    evm_rpc_tls,
                    gas_tx_allowed_to,
                    gas_tx_max_gas_limit,
                    gas_tx_max_fee_per_gas,
                    gas_tx_max_value_wei,
                    gas_tx_allowed_selectors,
                    token_contract,
                    kms,
                    clone_peer_pcr3,
                }
            }
            _ => return Err(PolicyDecodeError("unknown policy kind")),
        };
        if !r.0.is_empty() {
            return Err(PolicyDecodeError("trailing bytes"));
        }
        Ok(policy)
    }
}

/// `user_data` of a policy-only attestation, which an enclave without keys
/// gives. A keyed attestation commits the key bundle too, so the two never
/// collide.
pub fn policy_commitment(policy: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"utexo/attested-policy/v1\0");
    hash.update(policy);
    hash.finalize().into()
}

/// Why [`AttestedPolicy::from_bytes`] rejected its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("cannot decode the attested policy: {0}")]
pub struct PolicyDecodeError(pub &'static str);

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], PolicyDecodeError> {
        if self.0.len() < n {
            return Err(PolicyDecodeError("truncated"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, PolicyDecodeError> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PolicyDecodeError> {
        Ok(self.take(N)?.try_into().expect("take returns N bytes"))
    }

    fn flag(&mut self) -> Result<bool, PolicyDecodeError> {
        match self.u8()? {
            0x00 => Ok(false),
            0x01 => Ok(true),
            _ => Err(PolicyDecodeError("unknown presence byte")),
        }
    }

    fn len(&mut self) -> Result<usize, PolicyDecodeError> {
        Ok(u32::from_be_bytes(self.array()?) as usize)
    }

    fn string(&mut self) -> Result<String, PolicyDecodeError> {
        let n = self.len()?;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| PolicyDecodeError("not UTF-8"))
    }
}

#[cfg(test)]
mod tests;
