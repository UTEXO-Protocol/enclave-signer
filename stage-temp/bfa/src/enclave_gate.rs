//! Temporary stage policy. The mode is compiled into the measured binary.
use crate::{
    config::BridgeConfig,
    error::{EnclaveError, Result},
    proto::enclave_request::Request,
};

#[cfg(all(not(test), any(feature = "dev-mode", feature = "mock-attestation")))]
compile_error!("stage-bfa-temp requires real validation and NSM attestation");

fn mode() -> &'static str {
    option_env!("STAGE_BFA_MODE").unwrap_or("invalid")
}

pub fn validate_boot(config: &BridgeConfig) -> Result<()> {
    validate_mode(mode(), config)
}

fn validate_mode(mode: &str, config: &BridgeConfig) -> Result<()> {
    let valid_asset = match mode {
        "bootstrap" => config.rgb_asset_id.is_empty(),
        "configured" => config.is_configured(),
        _ => false,
    };
    if !valid_asset
        || config.chain_id != 42161
        || config.bridge_contract == [0; 20]
        || config.btc_max_total_sats == 0
    {
        return Err(EnclaveError::InvalidRequest(
            "temporary BFA mode or pins are invalid".into(),
        ));
    }
    Ok(())
}

pub fn authorize(request: &Request, config: &BridgeConfig) -> Result<()> {
    authorize_mode(mode(), request, config)
}

fn authorize_mode(mode: &str, request: &Request, config: &BridgeConfig) -> Result<()> {
    validate_mode(mode, config)?;
    if let Request::InitializeKey(req) = request {
        if req.seed.len() != 64 || !req.mnemonic.is_empty() || req.cloning_secret.is_empty() {
            return Err(EnclaveError::InvalidRequest(
                "temporary BFA requires a retained seed and cloning secret in one init".into(),
            ));
        }
        crate::cloning::validate_cloning_secret(&req.cloning_secret)?;
    }
    if mode == "bootstrap"
        && matches!(
            request,
            Request::Sign(_)
                | Request::SignRawDigest(_)
                | Request::SignRawMessage(_)
                | Request::SignCcd(_)
                | Request::ProxyFederation(_)
        )
    {
        return Err(EnclaveError::InvalidRequest(
            "BFA bootstrap: business signing disabled".into(),
        ));
    }
    // SignBtc still passes through the vanilla-only, self-output and value-cap checks.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::*;
    fn config() -> BridgeConfig {
        BridgeConfig {
            chain_id: 42161,
            bridge_contract: [1; 20],
            btc_max_total_sats: 1_000_000,
            ..Default::default()
        }
    }
    #[test]
    fn bootstrap_refuses_business_signing() {
        for req in [
            Request::Sign(Default::default()),
            Request::SignRawDigest(Default::default()),
            Request::SignCcd(Default::default()),
            Request::SignRawMessage(Default::default()),
            Request::ProxyFederation(Default::default()),
        ] {
            assert!(authorize_mode("bootstrap", &req, &config()).is_err());
        }
        assert!(authorize_mode(
            "bootstrap",
            &Request::SignBtc(Default::default()),
            &config()
        )
        .is_ok());
    }
    #[test]
    fn modes_fail_closed_on_missing_or_wrong_pins() {
        assert!(validate_mode("unknown", &config()).is_err());
        assert!(validate_mode("configured", &config()).is_err());
        let mut c = config();
        c.rgb_asset_id = "rgb:fixture".into();
        assert!(validate_mode("bootstrap", &c).is_err());
        assert!(validate_mode("configured", &c).is_ok());
        c.btc_max_total_sats = 0;
        assert!(validate_mode("configured", &c).is_err());
    }
    #[test]
    fn import_requires_seed_and_clone_secret_together() {
        let mut req = InitializeKeyRequest::default();
        assert!(
            authorize_mode("bootstrap", &Request::InitializeKey(req.clone()), &config()).is_err()
        );
        req.seed = vec![7; 64];
        assert!(
            authorize_mode("bootstrap", &Request::InitializeKey(req.clone()), &config()).is_err()
        );
        req.cloning_secret = "0123456789abcdef0123456789abcdef".into();
        assert!(authorize_mode("bootstrap", &Request::InitializeKey(req), &config()).is_ok());
    }
    #[test]
    fn retained_seed_restores_keys_but_double_init_is_refused() {
        let a = crate::state::EnclaveState::new(bitcoin::Network::Bitcoin);
        let b = crate::state::EnclaveState::new(bitcoin::Network::Bitcoin);
        a.initialize_from_seed([7; 64]).unwrap();
        b.initialize_from_seed([7; 64]).unwrap();
        let ka = a
            .with_keys(|k| {
                Ok((
                    *k.evm_address(),
                    k.btc_xpub().to_string(),
                    k.account_xpub_vanilla().to_string(),
                    k.account_xpub_colored().to_string(),
                    k.master_fingerprint().to_string(),
                ))
            })
            .unwrap();
        let kb = b
            .with_keys(|k| {
                Ok((
                    *k.evm_address(),
                    k.btc_xpub().to_string(),
                    k.account_xpub_vanilla().to_string(),
                    k.account_xpub_colored().to_string(),
                    k.master_fingerprint().to_string(),
                ))
            })
            .unwrap();
        assert_eq!(ka, kb);
        assert!(a.initialize_from_seed([8; 64]).is_err());
    }
    #[test]
    fn wire_init_checks_secret_before_mutating_and_blocks_bridge_signing() {
        use crate::networks::rgb::spv::{checkpoint_for, HeaderChain, Network};
        use crate::proto::enclave_response::Response;
        use crate::{
            framing,
            server::{handle_connection, ServerContext},
            state::EnclaveState,
        };
        use std::io::{self, Cursor, Read, Write};
        struct Stream {
            input: Cursor<Vec<u8>>,
            output: Vec<u8>,
        }
        impl Read for Stream {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.input.read(buf)
            }
        }
        impl Write for Stream {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.output.write(buf)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let ctx = ServerContext::new(
            EnclaveState::new(bitcoin::Network::Bitcoin),
            config(),
            std::sync::Mutex::new(HeaderChain::new(
                Network::Regtest,
                checkpoint_for(Network::Regtest),
            )),
        );
        let send = |req| {
            let mut input = Vec::new();
            framing::write_message(&mut input, &EnclaveRequest { request: Some(req) }).unwrap();
            let mut stream = Stream {
                input: Cursor::new(input),
                output: Vec::new(),
            };
            handle_connection(&mut stream, &ctx);
            framing::read_message::<EnclaveResponse>(&mut Cursor::new(stream.output))
                .unwrap()
                .response
                .unwrap()
        };
        let mut req = InitializeKeyRequest {
            seed: vec![7; 64],
            mnemonic: String::new(),
            cloning_secret: "weak".into(),
        };
        assert!(matches!(
            send(Request::InitializeKey(req.clone())),
            Response::Error(_)
        ));
        assert!(ctx.state.get_keys().is_err());
        req.cloning_secret = "0123456789abcdef0123456789abcdef".into();
        assert!(matches!(
            send(Request::InitializeKey(req.clone())),
            Response::InitializeKey(_)
        ));
        assert!(ctx
            .state
            .with_donor_cloning_secret(|s| Ok(s == req.cloning_secret))
            .unwrap());
        assert!(matches!(
            send(Request::InitializeKey(req)),
            Response::Error(_)
        ));
        match send(Request::Sign(Default::default())) {
            Response::Error(e) => assert!(e.message.contains("business signing disabled")),
            _ => panic!("bootstrap signed a bridge request"),
        }
        match send(Request::SignBtc(Default::default())) {
            Response::Error(e) => assert!(!e.message.contains("business signing disabled")),
            _ => panic!("accepted an empty Bitcoin PSBT"),
        }
    }
}
