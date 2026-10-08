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
//! variant or reorder fields. Bump [`POLICY_COMMITMENT_V9`] instead.

/// Version tag at the start of every policy commitment. A verifier rejects a
/// different encoding version instead of computing a wrong hash. Bump it on
/// every layout change.
pub const POLICY_COMMITMENT_V9: u8 = 9;

/// Bridge directions that the image signs. It comes from build features, so
/// PCR0 measures it and no host config can widen it.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerRole {
    /// Both directions in one image (`Dockerfile.enclave`,
    /// `Dockerfile.enclave.rgb`; retired swap flow).
    Combined = 0,
    /// `mint-signer`: EVM -> RGB only. Refuses every `fundsOut` release.
    Mint = 1,
    /// `burn-signer`: EVM releases only. Refuses every RGB mint PSBT. A `ccd`
    /// dev build also signs CCD -> EVM. No shipped burn image has `ccd`.
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
    /// No EVM verification in the build (`evm-rpc` off). The enclave rejects
    /// every EVM->RGB bridge request.
    Disabled = 0,
    /// Plaintext JSON-RPC over the host relay. The host can forge the
    /// responses. Dev and test builds only.
    RawRpc = 1,
    // 2 is retired. Do not reuse it.
    /// JSON-RPC over TLS that ends inside the enclave. The host relays only
    /// ciphertext. The pinned CA and host ([`EvmRpcTlsPin`]) authenticate the
    /// endpoint. The chain state is not verified.
    PinnedTlsRpc = 3,
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
/// source. A debug, dev-feature, unpinned or non-bridge build is
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
        bridge_contract: [u8; 20],
        rgb_asset_id: String,
        /// Contract whose FundsIn events can authorize bridge signing.
        funds_in_contract: [u8; 20],
        /// Minimum EVM receipt depth before a deposit can authorize signing.
        evm_min_confirmations: u64,
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
    /// [POLICY_COMMITMENT_V9]
    /// Production:  [0x01][allow_vanilla u8][signer_role u8][attestation u8]
    ///              [evm_source u8]
    ///              [btc_source u8][chain_id u64 BE][bridge_contract 20]
    ///              [len(asset) u32 BE][asset bytes][funds_in_contract 20]
    ///              [evm_min_confirmations u64 BE]
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
        out.push(POLICY_COMMITMENT_V9);
        match self {
            AttestedPolicy::Production {
                allow_vanilla_psbt,
                signer_role,
                attestation,
                evm_source,
                btc_source,
                chain_id,
                bridge_contract,
                rgb_asset_id,
                funds_in_contract,
                evm_min_confirmations,
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
                out.extend_from_slice(bridge_contract);
                out.extend_from_slice(&(rgb_asset_id.len() as u32).to_be_bytes());
                out.extend_from_slice(rgb_asset_id.as_bytes());
                out.extend_from_slice(funds_in_contract);
                out.extend_from_slice(&evm_min_confirmations.to_be_bytes());
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
        if r.u8()? != POLICY_COMMITMENT_V9 {
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
                let bridge_contract = r.array()?;
                let rgb_asset_id = r.string()?;
                let funds_in_contract = r.array()?;
                let evm_min_confirmations = u64::from_be_bytes(r.array()?);
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
                    bridge_contract,
                    rgb_asset_id,
                    funds_in_contract,
                    evm_min_confirmations,
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
mod tests {
    use super::*;

    /// Production policy with parameters, so each test changes one field.
    /// Gas-tx fields are fixed here. The gas tests change them.
    fn prod(
        vanilla: bool,
        evm: EvmDataSource,
        chain_id: u64,
        contract: u8,
        asset: &str,
    ) -> AttestedPolicy {
        AttestedPolicy::Production {
            allow_vanilla_psbt: vanilla,
            signer_role: SignerRole::Mint,
            attestation: AttestationMode::Real,
            evm_source: evm,
            btc_source: BtcDataSource::SpvVerified,
            chain_id,
            bridge_contract: [contract; 20],
            rgb_asset_id: asset.into(),
            funds_in_contract: [0x44; 20],
            evm_min_confirmations: 12,
            electrum_host: "electrum.test".into(),
            evm_rpc_tls: None,
            gas_tx_allowed_to: [0xAA; 20],
            gas_tx_max_gas_limit: 21_000,
            gas_tx_max_fee_per_gas: 1_000,
            gas_tx_max_value_wei: 0,
            gas_tx_allowed_selectors: vec![[0xde, 0xad, 0xbe, 0xef]],
            token_contract: [0x77; 20],
            kms: None,
            clone_peer_pcr3: None,
        }
    }

    fn base() -> AttestedPolicy {
        prod(false, EvmDataSource::RawRpc, 1, 0x11, "rgb:asset")
    }

    /// `base()` with the gas-tx fields overridden, for the gas tests.
    fn base_with_gas(
        to: [u8; 20],
        max_gas: u64,
        max_fee: u128,
        max_value: u128,
        selectors: Vec<[u8; 4]>,
    ) -> AttestedPolicy {
        match base() {
            AttestedPolicy::Production {
                allow_vanilla_psbt,
                signer_role,
                attestation,
                evm_source,
                btc_source,
                chain_id,
                bridge_contract,
                rgb_asset_id,
                funds_in_contract,
                evm_min_confirmations,
                electrum_host,
                evm_rpc_tls,
                token_contract,
                kms,
                clone_peer_pcr3,
                ..
            } => AttestedPolicy::Production {
                allow_vanilla_psbt,
                signer_role,
                attestation,
                evm_source,
                btc_source,
                chain_id,
                bridge_contract,
                rgb_asset_id,
                funds_in_contract,
                evm_min_confirmations,
                electrum_host,
                evm_rpc_tls,
                gas_tx_allowed_to: to,
                gas_tx_max_gas_limit: max_gas,
                gas_tx_max_fee_per_gas: max_fee,
                gas_tx_max_value_wei: max_value,
                gas_tx_allowed_selectors: selectors,
                token_contract,
                kms,
                clone_peer_pcr3,
            },
            AttestedPolicy::Development => unreachable!(),
        }
    }

    #[test]
    fn every_encoding_starts_with_the_version_tag() {
        assert_eq!(base().to_bytes()[0], POLICY_COMMITMENT_V9);
        assert_eq!(
            AttestedPolicy::Development.to_bytes()[0],
            POLICY_COMMITMENT_V9
        );
    }

    #[test]
    fn production_and_development_never_collide() {
        assert_ne!(base().to_bytes(), AttestedPolicy::Development.to_bytes());
    }

    #[test]
    fn every_posture_field_changes_the_bytes() {
        let cases = [
            prod(true, EvmDataSource::RawRpc, 1, 0x11, "rgb:asset"),
            prod(false, EvmDataSource::PinnedTlsRpc, 1, 0x11, "rgb:asset"),
            prod(false, EvmDataSource::RawRpc, 2, 0x11, "rgb:asset"),
            prod(false, EvmDataSource::RawRpc, 1, 0x22, "rgb:asset"),
            prod(false, EvmDataSource::RawRpc, 1, 0x11, "rgb:other"),
        ];
        for c in cases {
            assert_ne!(
                c.to_bytes(),
                base().to_bytes(),
                "posture change must alter the commitment"
            );
        }
    }

    #[test]
    fn signer_role_changes_the_bytes() {
        let encodings: Vec<Vec<u8>> = [SignerRole::Combined, SignerRole::Mint, SignerRole::Burn]
            .into_iter()
            .map(|role| {
                let mut p = base();
                if let AttestedPolicy::Production { signer_role, .. } = &mut p {
                    *signer_role = role;
                }
                p.to_bytes()
            })
            .collect();
        assert_ne!(encodings[0], encodings[1]);
        assert_ne!(encodings[0], encodings[2]);
        assert_ne!(encodings[1], encodings[2]);
    }

    #[test]
    fn deposit_authorization_fields_change_the_bytes() {
        let mut emitter = base();
        if let AttestedPolicy::Production {
            funds_in_contract, ..
        } = &mut emitter
        {
            *funds_in_contract = [0x55; 20];
        }
        let mut confirmations = base();
        if let AttestedPolicy::Production {
            evm_min_confirmations,
            ..
        } = &mut confirmations
        {
            *evm_min_confirmations = 13;
        }
        assert_ne!(base().to_bytes(), emitter.to_bytes());
        assert_ne!(base().to_bytes(), confirmations.to_bytes());
    }

    #[test]
    fn token_contract_changes_the_bytes() {
        // The token is a burnId preimage input, so it must be in the bytes.
        let mut other = base();
        if let AttestedPolicy::Production { token_contract, .. } = &mut other {
            *token_contract = [0x78; 20];
        }
        assert_ne!(base().to_bytes(), other.to_bytes());
        // Only the token bytes change. The KMS and the PCR3 presence bytes
        // follow them.
        let a = base().to_bytes();
        let b = other.to_bytes();
        assert_eq!(a[..a.len() - 22], b[..b.len() - 22]);
        assert_eq!(&a[a.len() - 22..a.len() - 2], &[0x77; 20]);
    }

    #[test]
    fn electrum_host_changes_the_bytes() {
        let mut other = base();
        if let AttestedPolicy::Production { electrum_host, .. } = &mut other {
            *electrum_host = "other.test".into();
        }
        assert_ne!(base().to_bytes(), other.to_bytes());
    }

    fn with_tls(host: &str, ca_sha256: [u8; 32]) -> AttestedPolicy {
        let mut p = base();
        if let AttestedPolicy::Production { evm_rpc_tls, .. } = &mut p {
            *evm_rpc_tls = Some(EvmRpcTlsPin {
                host: host.into(),
                ca_sha256,
            });
        }
        p
    }

    #[test]
    fn evm_rpc_tls_pin_presence_host_and_ca_change_the_bytes() {
        let pinned = with_tls("rpc.test", [1; 32]).to_bytes();
        assert_ne!(base().to_bytes(), pinned);
        assert_ne!(with_tls("other.test", [1; 32]).to_bytes(), pinned);
        assert_ne!(with_tls("rpc.test", [2; 32]).to_bytes(), pinned);
    }

    fn a_kms_pin() -> KmsPin {
        KmsPin {
            key_arn: "arn:aws:kms:eu-west-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef"
                .into(),
            region: "eu-west-1".into(),
            seed_id: "seed-1".into(),
            expected_evm_address: Some([0x42; 20]),
        }
    }

    fn with_kms(kms: Option<KmsPin>) -> AttestedPolicy {
        let mut p = base();
        if let AttestedPolicy::Production { kms: k, .. } = &mut p {
            *k = kms;
        }
        p
    }

    #[test]
    fn kms_changes_the_bytes() {
        let pinned = with_kms(Some(a_kms_pin())).to_bytes();
        assert_ne!(base().to_bytes(), pinned);
        let edits: [fn(&mut KmsPin); 4] = [
            |k| k.key_arn.push('0'),
            |k| k.region = "eu-west-2".into(),
            |k| k.seed_id = "seed-2".into(),
            |k| k.expected_evm_address = None,
        ];
        for edit in edits {
            let mut pin = a_kms_pin();
            edit(&mut pin);
            assert_ne!(with_kms(Some(pin)).to_bytes(), pinned);
        }
    }

    /// `base()` as a burn signer with the given clone-peer PCR3.
    fn with_clone_peer_pcr3(pcr3: Option<[u8; 48]>) -> AttestedPolicy {
        let mut p = base();
        if let AttestedPolicy::Production {
            signer_role,
            clone_peer_pcr3,
            ..
        } = &mut p
        {
            *signer_role = SignerRole::Burn;
            *clone_peer_pcr3 = pcr3;
        }
        p
    }

    /// Two enclaves under different IAM roles attest different policies, so a
    /// verifier sees which role the clone peers are bound to.
    #[test]
    fn clone_peer_pcr3_changes_the_bytes() {
        let role_a = with_clone_peer_pcr3(Some([0x33; 48])).to_bytes();
        assert_ne!(role_a, with_clone_peer_pcr3(Some([0x34; 48])).to_bytes());
        assert_ne!(role_a, with_clone_peer_pcr3(None).to_bytes());
    }

    #[test]
    fn from_bytes_inverts_to_bytes() {
        let mut policies = vec![AttestedPolicy::Development, base()];
        policies.push(with_kms(Some(a_kms_pin())));
        policies.push(with_kms(Some(KmsPin {
            expected_evm_address: None,
            ..a_kms_pin()
        })));
        let mut full = with_tls("rpc.test", [1; 32]);
        if let AttestedPolicy::Production {
            gas_tx_allowed_selectors,
            kms,
            ..
        } = &mut full
        {
            *gas_tx_allowed_selectors = vec![[1, 1, 1, 1], [2, 2, 2, 2]];
            *kms = Some(a_kms_pin());
        }
        policies.push(full);
        policies.push(with_clone_peer_pcr3(Some([0x33; 48])));
        for p in policies {
            assert_eq!(AttestedPolicy::from_bytes(&p.to_bytes()), Ok(p));
        }
    }

    #[test]
    fn from_bytes_refuses_bad_input() {
        let good = with_kms(Some(a_kms_pin())).to_bytes();
        for n in 0..good.len() {
            assert!(AttestedPolicy::from_bytes(&good[..n]).is_err(), "{n}");
        }
        let mut bad = vec![[&good[..], &[0]].concat()];
        let mut v7 = good.clone();
        v7[0] = 7;
        bad.push(v7);
        // A V8 policy has no PCR3 field, so a V9 decoder refuses it.
        let mut v8 = good.clone();
        v8[0] = 8;
        bad.push(v8);
        // The last byte is the PCR3 presence flag. Only 0 and 1 are valid.
        let mut flag = good.clone();
        *flag.last_mut().unwrap() = 2;
        bad.push(flag);
        let mut kind = good.clone();
        kind[1] = 2;
        bad.push(kind);
        let mut role = good.clone();
        role[3] = 3;
        bad.push(role);
        // EVM source 2 (retired) is no longer valid.
        let mut evm = good.clone();
        evm[5] = 2;
        bad.push(evm);
        // The Electrum host is "electrum.test"; make its first byte invalid UTF-8.
        let at = good
            .windows(13)
            .position(|w| w == b"electrum.test")
            .unwrap();
        let mut utf8 = good.clone();
        utf8[at] = 0xff;
        bad.push(utf8);
        let unsorted = base_with_gas(
            [0xAA; 20],
            21_000,
            1_000,
            0,
            vec![[1, 1, 1, 1], [2, 2, 2, 2]],
        )
        .to_bytes();
        let at = unsorted
            .windows(8)
            .position(|w| w == [1, 1, 1, 1, 2, 2, 2, 2])
            .unwrap();
        let mut swapped = unsorted.clone();
        swapped[at..at + 8].copy_from_slice(&[2, 2, 2, 2, 1, 1, 1, 1]);
        bad.push(swapped);
        for b in bad {
            assert!(AttestedPolicy::from_bytes(&b).is_err(), "{b:?}");
        }
    }

    #[test]
    fn asset_is_length_prefixed_not_ambiguous() {
        // The u32 length prefix stops confusion between asset IDs that share
        // a prefix.
        let a = prod(false, EvmDataSource::RawRpc, 1, 0x11, "ab");
        let b = prod(false, EvmDataSource::RawRpc, 1, 0x11, "abc");
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    // ---- gas-tx rule commitment ----

    #[test]
    fn every_gas_tx_field_changes_the_bytes() {
        let base_gas = base_with_gas([0xAA; 20], 21_000, 1_000, 0, vec![[1, 2, 3, 4]]);
        let cases = [
            base_with_gas([0xBB; 20], 21_000, 1_000, 0, vec![[1, 2, 3, 4]]), // destination
            base_with_gas([0xAA; 20], 30_000, 1_000, 0, vec![[1, 2, 3, 4]]), // gas cap
            base_with_gas([0xAA; 20], 21_000, 2_000, 0, vec![[1, 2, 3, 4]]), // fee cap
            base_with_gas([0xAA; 20], 21_000, 1_000, 5, vec![[1, 2, 3, 4]]), // value ceiling
            base_with_gas([0xAA; 20], 21_000, 1_000, 0, vec![[9, 9, 9, 9]]), // selector
            base_with_gas([0xAA; 20], 21_000, 1_000, 0, vec![]),             // no selectors
        ];
        for c in cases {
            assert_ne!(
                c.to_bytes(),
                base_gas.to_bytes(),
                "a gas-tx rule change must alter the commitment"
            );
        }
    }

    #[test]
    fn selector_allowlist_is_order_and_dup_independent() {
        // Selector order and duplicates do not change the attested bytes.
        let a = base_with_gas(
            [0xAA; 20],
            21_000,
            1_000,
            0,
            vec![[1, 1, 1, 1], [2, 2, 2, 2]],
        );
        let b = base_with_gas(
            [0xAA; 20],
            21_000,
            1_000,
            0,
            vec![[2, 2, 2, 2], [1, 1, 1, 1], [1, 1, 1, 1]],
        );
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn selector_count_is_length_prefixed() {
        // The selector count is length-prefixed, so a set cannot be confused
        // with a longer set that shares a prefix.
        let one = base_with_gas([0xAA; 20], 21_000, 1_000, 0, vec![[1, 1, 1, 1]]);
        let two = base_with_gas(
            [0xAA; 20],
            21_000,
            1_000,
            0,
            vec![[1, 1, 1, 1], [2, 2, 2, 2]],
        );
        assert_ne!(one.to_bytes(), two.to_bytes());
    }
}
