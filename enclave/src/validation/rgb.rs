//! In-enclave RGB consignment validation using rgbstd + Esplora resolver.
//!
//! Validates raw consignment bytes by deserializing them into an RGB `Transfer`,
//! connecting to an Esplora indexer to resolve witness transactions, and running
//! the full rgbstd validation pipeline. This replaces trusting the Listener's
//! `consignment_valid` boolean.

use std::io::Cursor;

use rgbstd::containers::{ConsignmentExt, FileContent, Transfer};
use rgbstd::indexers::esplora_blocking::esplora_client;
use rgbstd::indexers::AnyResolver;
use rgbstd::validation::ValidationConfig;
use rgbstd::ChainNet;

use crate::error::{EnclaveError, Result};

/// Data extracted from a successfully validated RGB consignment.
#[derive(Debug)]
pub struct ValidatedConsignment {
    /// RGB contract identifier (e.g., "rgb:2TGhRyP3-...")
    pub contract_id: String,
    // TODO: extract rgb_amount from state transitions in a future PR.
    // For now, rely on Listener's rgb_amount + existing calldata cross-checks.
}

/// Validates RGB consignments using rgbstd and an Esplora-backed resolver.
#[derive(Debug)]
pub struct RgbValidator {
    esplora_url: String,
    chain_net: ChainNet,
}

impl RgbValidator {
    /// Create a new validator.
    ///
    /// - `esplora_url`: HTTP URL for the Esplora API (e.g., `http://127.0.0.1:3443`
    ///   when using the vsock forwarder, or a direct URL in dev mode).
    /// - `bitcoin_network`: One of "bitcoin", "testnet", "signet", "regtest".
    pub fn new(esplora_url: String, bitcoin_network: &str) -> Result<Self> {
        let chain_net = match bitcoin_network {
            "bitcoin" | "mainnet" => ChainNet::BitcoinMainnet,
            "testnet" | "testnet3" => ChainNet::BitcoinTestnet3,
            "signet" => ChainNet::BitcoinSignet,
            "regtest" => ChainNet::BitcoinRegtest,
            other => {
                return Err(EnclaveError::Internal(format!(
                    "unknown bitcoin network: {other}"
                )))
            }
        };
        tracing::info!(%esplora_url, %bitcoin_network, "RGB validator configured");
        Ok(Self {
            esplora_url,
            chain_net,
        })
    }

    /// Validate raw consignment bytes. Returns extracted data on success,
    /// or a `CrossCheck` error if validation fails.
    pub fn validate_consignment(&self, consignment_bytes: &[u8]) -> Result<ValidatedConsignment> {
        let start = std::time::Instant::now();
        let bytes_len = consignment_bytes.len();
        tracing::info!(
            bytes_len,
            esplora_url = %self.esplora_url,
            "starting RGB consignment validation"
        );

        // 1. Deserialize the consignment from its file format (magic + strict-encoded).
        let transfer = Transfer::load(Cursor::new(consignment_bytes)).map_err(|e| {
            tracing::warn!(bytes_len, "consignment deserialization failed: {e}");
            EnclaveError::CrossCheck(format!("consignment deserialization failed: {e}"))
        })?;

        let contract_id = transfer.contract_id().to_string();
        let bundles_count = transfer.bundles.len();
        tracing::info!(
            %contract_id,
            bundles_count,
            elapsed_ms = start.elapsed().as_millis() as u64,
            "deserialized RGB transfer"
        );

        // 2. Create an Esplora-backed resolver.
        let builder = esplora_client::Builder::new(&self.esplora_url);
        let mut resolver = AnyResolver::esplora_blocking(builder).map_err(|e| {
            tracing::error!(esplora_url = %self.esplora_url, "esplora resolver creation failed: {e}");
            EnclaveError::CrossCheck(format!("esplora resolver creation failed: {e}"))
        })?;

        // Register transactions bundled in the consignment so the resolver
        // treats them as tentative witnesses (not yet mined).
        resolver.add_consignment_txes(&transfer);

        // 3. Build validation config.
        let config = ValidationConfig {
            chain_net: self.chain_net,
            trusted_typesystem: transfer.types.clone(),
            build_opouts_dag: true,
            ..Default::default()
        };

        // 4. Run full RGB validation (makes blocking HTTP calls to Esplora).
        tracing::debug!(%contract_id, "calling rgbstd validate (this may block on Esplora)");
        let _valid = transfer.validate(&resolver, &config).map_err(|e| {
            tracing::warn!(
                %contract_id,
                elapsed_ms = start.elapsed().as_millis() as u64,
                "RGB validation failed: {e}"
            );
            EnclaveError::CrossCheck(format!("RGB consignment validation failed: {e}"))
        })?;

        tracing::info!(
            %contract_id,
            elapsed_ms = start.elapsed().as_millis() as u64,
            "RGB consignment validated successfully"
        );

        Ok(ValidatedConsignment { contract_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_bytes() {
        let validator = RgbValidator::new("http://localhost:1".to_string(), "regtest").unwrap();
        let err = validator
            .validate_consignment(b"not-a-consignment")
            .unwrap_err();
        assert!(
            err.to_string().contains("deserialization failed"),
            "expected deserialization error, got: {err}"
        );
    }

    #[test]
    fn rejects_unknown_network() {
        let err = RgbValidator::new("http://localhost:1".to_string(), "foonet").unwrap_err();
        assert!(err.to_string().contains("unknown bitcoin network"));
    }
}
