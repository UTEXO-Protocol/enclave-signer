//! `SetEndpoints`: the operator sets the chain endpoints once, at launch.
//!
//! Every step that can fail runs before the slot is written. A refused set
//! leaves the slot empty, so the operator can retry. A second set is refused
//! and the running values stay.

use super::context::{Launch, ServerContext};
use crate::config::Endpoints;
use crate::error::{EnclaveError, Result};
use crate::policy::SecurityPolicy;
use crate::proto::enclave_response::Response;
use crate::proto::*;

pub(super) fn handle_set_endpoints(
    ctx: &ServerContext,
    req: SetEndpointsRequest,
) -> Result<EnclaveResponse> {
    let _guard = ctx
        .launch_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if ctx.launch.get().is_some() {
        return Err(EnclaveError::InvalidRequest(
            "endpoints are already set".into(),
        ));
    }

    let endpoints = Endpoints::parse(&req).map_err(EnclaveError::InvalidRequest)?;
    #[cfg(feature = "evm-rpc")]
    let tls = endpoints
        .evm_rpc_tls
        .as_ref()
        .ok_or_else(|| EnclaveError::InvalidRequest("the EVM RPC endpoint is not set".into()))?;
    #[cfg(feature = "evm-rpc")]
    let (evm_source, evm_checkpoint, evm_rpc_tls) = crate::bootstrap::resolve_evm_data_source(tls);
    #[cfg(feature = "evm-rpc")]
    let evm_min_confirmations = ctx.evm_rpc_config.min_confirmations;
    #[cfg(not(feature = "evm-rpc"))]
    let (evm_source, evm_checkpoint, evm_rpc_tls, evm_min_confirmations) =
        (crate::policy::EvmDataSource::Disabled, None, None, 0);
    let policy = SecurityPolicy::resolve(
        &ctx.build_ctx,
        &ctx.bridge_config,
        evm_source,
        evm_checkpoint,
        evm_rpc_tls,
        &endpoints.electrum_host,
        evm_min_confirmations,
    );
    policy
        .assert_valid_for_build(&ctx.build_ctx)
        .map_err(EnclaveError::InvalidRequest)?;

    #[cfg(all(feature = "vsock", target_os = "linux"))]
    let listeners = bind_forwarders(&endpoints)?;

    #[cfg(feature = "rgb-validation")]
    let rgb_validator = crate::bootstrap::build_rgb_validator(endpoints.electrum_url.clone())
        .ok_or_else(|| EnclaveError::Internal("cannot build the RGB validator".into()))?;
    #[cfg(feature = "evm-rpc")]
    let evm_rpc_client =
        crate::bootstrap::build_evm_rpc_client(&ctx.bridge_config, &ctx.evm_rpc_config, tls)
            .ok_or_else(|| EnclaveError::Internal("cannot build the EVM RPC client".into()))?;
    let launch = Launch {
        #[cfg(feature = "rgb-validation")]
        rgb_validator: Some(rgb_validator),
        #[cfg(feature = "evm-rpc")]
        evm_rpc_client: Some(evm_rpc_client),
        endpoints,
        policy,
    };

    #[cfg(all(feature = "vsock", feature = "rgb-validation", target_os = "linux"))]
    crate::bootstrap::pin_host_to_loopback(&launch.endpoints.electrum_host).map_err(|e| {
        EnclaveError::Internal(format!(
            "cannot pin {} in /etc/hosts: {e}",
            launch.endpoints.electrum_host
        ))
    })?;
    #[cfg(all(feature = "vsock", target_os = "linux"))]
    for (listener, vsock_port) in listeners {
        crate::vsock_forwarder::spawn(listener, vsock_port);
    }

    crate::bootstrap::log_policy(&launch.policy);
    tracing::info!(endpoints = ?launch.endpoints, "endpoints set");
    // Under the lock, and the slot was empty.
    let _ = ctx.launch.set(launch);
    Ok(EnclaveResponse {
        response: Some(Response::SetEndpoints(SetEndpointsResponse {})),
    })
}

/// Bind the loopback end of each forwarder this build needs. The host must
/// run `vsock-proxy <vsock port> <host> <port>` for each.
#[cfg(all(feature = "vsock", target_os = "linux"))]
fn bind_forwarders(endpoints: &Endpoints) -> Result<Vec<(std::net::TcpListener, u32)>> {
    #[allow(unused_mut)]
    let mut listeners = Vec::new();
    #[cfg(feature = "rgb-validation")]
    listeners.push((
        bind(endpoints.electrum_port)?,
        vsock_port("ESPLORA_VSOCK_PORT", 8001),
    ));
    #[cfg(feature = "evm-rpc")]
    if let Some(tls) = &endpoints.evm_rpc_tls {
        listeners.push((bind(tls.tls_port)?, vsock_port("EVM_RPC_VSOCK_PORT", 8002)));
    }
    let _ = endpoints;
    Ok(listeners)
}

#[cfg(all(feature = "vsock", feature = "rgb-validation", target_os = "linux"))]
fn bind(port: u16) -> Result<std::net::TcpListener> {
    std::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .map_err(|e| EnclaveError::Internal(format!("cannot listen on 127.0.0.1:{port}: {e}")))
}

#[cfg(all(feature = "vsock", feature = "rgb-validation", target_os = "linux"))]
fn vsock_port(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::BuildContext;
    use crate::proto::enclave_request::Request;
    use crate::state::EnclaveState;

    fn awaiting(build_ctx: BuildContext) -> ServerContext {
        let bridge_config = crate::config::BridgeConfig::default();
        ServerContext::awaiting_launch(
            EnclaveState::new(bitcoin::Network::Regtest),
            bridge_config,
            #[cfg(feature = "rgb-validation")]
            std::sync::Mutex::new(crate::networks::rgb::spv::HeaderChain::new(
                crate::networks::rgb::spv::Network::Regtest,
                crate::networks::rgb::spv::checkpoint_for(
                    crate::networks::rgb::spv::Network::Regtest,
                ),
            )),
            build_ctx,
        )
    }

    /// A valid set for this build. `n` varies the hosts.
    fn valid(n: u8) -> SetEndpointsRequest {
        let mut req = SetEndpointsRequest::default();
        if cfg!(feature = "rgb-validation") {
            req.electrum_url = format!("ssl://electrum{n}.test:50002");
        }
        if cfg!(feature = "evm-rpc") {
            req.evm_rpc_host = format!("rpc{n}.test");
            req.evm_rpc_ca_der =
                hex::decode(include_str!("../../tests/fixtures/evm_rpc_tls/ca_a.der.hex").trim())
                    .unwrap();
            req.evm_rpc_tls_port = 443;
        }
        req
    }

    fn call(ctx: &ServerContext, request: Request) -> Response {
        super::super::dispatch::dispatch(
            EnclaveRequest {
                request: Some(request),
            },
            ctx,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .0
        .response
        .unwrap()
    }

    fn not_ready(r: Response) -> bool {
        matches!(r, Response::Error(e) if e.code == 2 && e.message.contains("endpoints-unset"))
    }

    fn health(ctx: &ServerContext) -> HealthResponse {
        match call(ctx, Request::Health(HealthRequest {})) {
            Response::Health(h) => h,
            other => panic!("expected Health, got {other:?}"),
        }
    }

    #[test]
    fn before_the_set_signing_and_attestation_are_refused() {
        let ctx = awaiting(BuildContext::current());
        call(
            &ctx,
            Request::InitializeKey(InitializeKeyRequest::default()),
        );
        assert!(ctx.state.is_initialized());
        for request in [
            Request::Sign(SignRequest::default()),
            Request::SignBtc(SignBtcRequest::default()),
            Request::SignRawDigest(SignRawDigestRequest::default()),
            Request::SignCcd(SignCcdRequest::default()),
            Request::GetAttestedPublicKey(GetAttestedPublicKeyRequest { nonce: vec![0; 32] }),
        ] {
            // A request this build does not serve is refused for its own reason.
            let got = call(&ctx, request.clone());
            assert!(matches!(got, Response::Error(_)), "{request:?}: {got:?}");
        }
        for request in [
            Request::Sign(SignRequest::default()),
            Request::GetAttestedPublicKey(GetAttestedPublicKeyRequest { nonce: vec![0; 32] }),
        ] {
            assert!(not_ready(call(&ctx, request)));
        }
        let h = health(&ctx);
        assert!(!h.endpoints_set && !h.ready && h.key_loaded);

        call(&ctx, Request::SetEndpoints(valid(1)));
        assert!(health(&ctx).endpoints_set);
    }

    #[test]
    fn a_refused_set_leaves_the_slot_empty() {
        let ctx = awaiting(BuildContext::current());
        let mut bad = vec![SetEndpointsRequest {
            electrum_url: "http://electrum.test:1".into(),
            ..valid(1)
        }];
        if cfg!(feature = "evm-rpc") {
            bad.push(SetEndpointsRequest {
                evm_rpc_host: "rpc.test:443".into(),
                ..valid(1)
            });
            bad.push(SetEndpointsRequest {
                evm_rpc_ca_der: b"not der".to_vec(),
                ..valid(1)
            });
            bad.push(SetEndpointsRequest {
                evm_rpc_tls_port: 0,
                ..valid(1)
            });
        }
        for req in bad {
            assert!(handle_set_endpoints(&ctx, req.clone()).is_err(), "{req:?}");
            assert!(ctx.launch.get().is_none(), "{req:?}");
        }
        handle_set_endpoints(&ctx, valid(1)).unwrap();
        assert!(ctx.launch().is_ok());
    }

    /// A release bridge build with no bridge pins resolves a policy that
    /// fails the launch gate. The set is refused, not a panic.
    #[test]
    fn a_policy_that_fails_the_launch_gate_is_refused() {
        let release = BuildContext {
            debug_or_test: false,
            mock_attestation: false,
            allow_seed_import: false,
            rgb_validation: true,
            ..BuildContext::current()
        };
        let ctx = awaiting(release);
        assert!(handle_set_endpoints(&ctx, valid(1)).is_err());
        assert!(ctx.launch.get().is_none());
    }

    #[test]
    fn a_second_set_is_refused_and_the_first_values_stay() {
        let ctx = awaiting(BuildContext::current());
        handle_set_endpoints(&ctx, valid(1)).unwrap();
        let first = ctx.launch().unwrap().endpoints.clone();
        for req in [valid(2), valid(1)] {
            let err = handle_set_endpoints(&ctx, req).unwrap_err();
            assert!(err.to_string().contains("already set"), "{err}");
        }
        assert_eq!(ctx.launch().unwrap().endpoints, first);
    }

    #[test]
    fn concurrent_sets_have_one_winner() {
        let ctx = awaiting(BuildContext::current());
        let results: Vec<_> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8u8)
                .map(|n| {
                    let ctx = &ctx;
                    s.spawn(move || (n, handle_set_endpoints(ctx, valid(n)).is_ok()))
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let winners: Vec<u8> = results.iter().filter(|r| r.1).map(|r| r.0).collect();
        assert_eq!(winners.len(), 1, "{results:?}");
        let want = Endpoints::parse(&valid(winners[0])).unwrap();
        assert_eq!(ctx.launch().unwrap().endpoints, want);
    }
}
