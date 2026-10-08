//! `SetEndpoints`: the operator sets the chain endpoints and the KMS pin once,
//! at launch.
//!
//! All steps that can fail run before the slot is written. A refused set
//! keeps the slot empty, so the operator can retry. A second set is refused,
//! and the current values stay.

use super::context::{Launch, ServerContext};
use crate::config::Endpoints;
use crate::error::{EnclaveError, Result};
use crate::policy::SecurityPolicy;
use crate::proto::enclave_response::Response;
use crate::proto::*;
#[cfg(any(test, all(feature = "vsock", target_os = "linux")))]
use std::net::{SocketAddrV4, TcpListener};

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
    let (evm_source, evm_rpc_tls) = crate::bootstrap::resolve_evm_data_source(tls);
    #[cfg(feature = "evm-rpc")]
    let evm_min_confirmations = ctx.evm_rpc_config.min_confirmations;
    #[cfg(not(feature = "evm-rpc"))]
    let (evm_source, evm_rpc_tls, evm_min_confirmations) =
        (crate::policy::EvmDataSource::Disabled, None, 0);
    let policy = SecurityPolicy::resolve(
        &ctx.build_ctx,
        &ctx.bridge_config,
        evm_source,
        evm_rpc_tls,
        &endpoints.electrum_host,
        evm_min_confirmations,
    )
    .with_kms(endpoints.kms.clone())
    // A production policy of a cloning role reads its own PCR3 (the parent
    // IAM role) here. The gate below refuses an all-zero PCR3.
    .with_clone_peer_pcr3(crate::attestation::get_own_pcr3)?;
    policy
        .assert_valid_for_build(&ctx.build_ctx)
        .map_err(EnclaveError::InvalidRequest)?;

    // `set_seed_source` refuses a second install.
    #[cfg(feature = "kms-persistence")]
    let seed_source = endpoints
        .kms
        .as_ref()
        .map(crate::seed_persistence::PersistentSeed::new)
        .transpose()?;

    // Unit tests cannot do the loopback binds and the /etc/hosts pin
    // (port 443, root). Thus `cfg(test)` skips them.
    #[cfg(all(feature = "vsock", target_os = "linux", not(test)))]
    let listeners = bind_all(&forwarder_plan(&endpoints))?;

    #[cfg(feature = "rgb-validation")]
    let rgb_validator = crate::bootstrap::build_rgb_validator(endpoints.electrum_url.clone())
        .ok_or_else(|| EnclaveError::Internal("cannot build the RGB validator".into()))?;
    #[cfg(feature = "evm-rpc")]
    let evm_rpc_client = crate::bootstrap::build_evm_rpc_client(tls)
        .ok_or_else(|| EnclaveError::Internal("cannot build the EVM RPC client".into()))?;
    let launch = Launch {
        #[cfg(feature = "rgb-validation")]
        rgb_validator: Some(rgb_validator),
        #[cfg(feature = "evm-rpc")]
        evm_rpc_client: Some(evm_rpc_client),
        endpoints,
        policy,
    };

    // The last step that can fail.
    #[cfg(all(feature = "vsock", target_os = "linux", not(test)))]
    {
        let electrum = cfg!(feature = "rgb-validation").then(|| {
            (
                std::net::Ipv4Addr::LOCALHOST,
                launch.endpoints.electrum_host.clone(),
            )
        });
        #[cfg(feature = "kms-persistence")]
        let kms = launch.endpoints.kms.as_ref().map(|k| {
            (
                crate::kms::KMS_LOOPBACK,
                crate::kms::endpoint_host(&k.region),
            )
        });
        #[cfg(not(feature = "kms-persistence"))]
        let kms = None;
        let pins: Vec<_> = electrum
            .iter()
            .chain(&kms)
            .map(|(a, h)| (*a, h.as_str()))
            .collect();
        crate::bootstrap::pin_hosts(std::path::Path::new("/etc/hosts"), &pins)
            .map_err(|e| EnclaveError::Internal(format!("cannot pin hosts in /etc/hosts: {e}")))?;
    }
    #[cfg(all(feature = "vsock", target_os = "linux", not(test)))]
    for (listener, vsock_port, require_tls) in listeners {
        crate::vsock_forwarder::spawn(listener, vsock_port, require_tls);
    }
    #[cfg(feature = "kms-persistence")]
    if let Some(source) = seed_source {
        ctx.state.set_seed_source(Box::new(source))?;
    }

    crate::bootstrap::log_policy(&launch.policy);
    tracing::info!(endpoints = ?launch.endpoints, "endpoints set");
    // The lock is held and the slot is empty, so this set cannot fail.
    let _ = ctx.launch.set(launch);
    Ok(EnclaveResponse {
        response: Some(Response::SetEndpoints(SetEndpointsResponse {})),
    })
}

/// The loopback end, the parent vsock port and the TLS rule of each forwarder
/// this build needs. The host must run `vsock-proxy <vsock port> <host>
/// <port>` for each. A TLS endpoint gets only TLS ([`crate::egress`]).
#[cfg(any(test, all(feature = "vsock", target_os = "linux")))]
// Each push depends on a feature.
#[allow(clippy::vec_init_then_push)]
fn forwarder_plan(endpoints: &Endpoints) -> Vec<(SocketAddrV4, u32, bool)> {
    #[allow(unused_mut)]
    let mut plan = Vec::new();
    #[cfg(feature = "rgb-validation")]
    plan.push((
        SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, endpoints.electrum_port),
        vsock_port("ESPLORA_VSOCK_PORT", 8001),
        endpoints.indexer_uses_tls(),
    ));
    #[cfg(feature = "evm-rpc")]
    if let Some(tls) = &endpoints.evm_rpc_tls {
        plan.push((
            SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, tls.tls_port),
            vsock_port("EVM_RPC_VSOCK_PORT", 8002),
            true,
        ));
    }
    // KMS and EVM RPC both use port 443, so KMS takes its own address.
    #[cfg(feature = "kms-persistence")]
    if endpoints.kms.is_some() {
        plan.push((
            SocketAddrV4::new(crate::kms::KMS_LOOPBACK, crate::kms::KMS_PORT),
            vsock_port("KMS_VSOCK_PORT", crate::kms::DEFAULT_KMS_VSOCK_PORT),
            true,
        ));
    }
    let _ = endpoints;
    plan
}

#[cfg(any(test, all(feature = "vsock", target_os = "linux")))]
fn bind_all(plan: &[(SocketAddrV4, u32, bool)]) -> Result<Vec<(TcpListener, u32, bool)>> {
    plan.iter()
        .map(|&(addr, vsock_port, require_tls)| {
            TcpListener::bind(addr)
                .map(|listener| (listener, vsock_port, require_tls))
                .map_err(|e| EnclaveError::Internal(format!("cannot listen on {addr}: {e}")))
        })
        .collect()
}

#[cfg(all(
    feature = "rgb-validation",
    any(test, all(feature = "vsock", target_os = "linux"))
))]
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
    #[cfg(feature = "kms-persistence")]
    use std::net::Ipv4Addr;

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

    const KEY_ARN: &str =
        "arn:aws:kms:eu-west-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef";

    /// A valid set for this build. `n` varies the hosts and the seed id.
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
        if cfg!(feature = "kms-persistence") {
            req.kms_key_arn = KEY_ARN.into();
            req.kms_region = "eu-west-1".into();
            req.kms_seed_id = format!("seed-{n}");
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
        // A persistence build gets the seed from KMS, which a unit test
        // cannot reach. Import a mnemonic there instead.
        let init = InitializeKeyRequest {
            mnemonic: if cfg!(feature = "kms-persistence") {
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into()
            } else {
                String::new()
            },
            ..InitializeKeyRequest::default()
        };
        let got = call(&ctx, Request::InitializeKey(init));
        assert!(ctx.state.is_initialized(), "{got:?}");
        for request in [
            Request::Sign(SignRequest::default()),
            Request::SignBtc(SignBtcRequest::default()),
            Request::SignRawDigest(SignRawDigestRequest::default()),
            Request::SignCcd(SignCcdRequest::default()),
            Request::GetAttestedPublicKey(GetAttestedPublicKeyRequest { nonce: vec![0; 32] }),
        ] {
            // A request that this build does not serve has its own refusal.
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
            electrum_url: "ftp://electrum.test:1".into(),
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
        if cfg!(feature = "kms-persistence") {
            bad.push(SetEndpointsRequest {
                kms_region: "eu-west-2".into(),
                ..valid(1)
            });
            bad.push(SetEndpointsRequest {
                kms_key_arn: "arn:aws:kms:eu-west-1:123456789012:alias/seed".into(),
                ..valid(1)
            });
            bad.push(SetEndpointsRequest {
                kms_seed_id: "seed 1".into(),
                ..valid(1)
            });
            bad.push(SetEndpointsRequest {
                kms_expected_evm_address: "00".repeat(19),
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

    #[cfg(feature = "kms-persistence")]
    #[test]
    fn a_set_with_a_seed_source_already_set_is_refused() {
        struct Unused;
        impl crate::seed_persistence::SeedSource for Unused {
            fn load_keys(
                &self,
                _: bitcoin::Network,
                _: std::time::Instant,
            ) -> Result<crate::keys::KeyManager> {
                unreachable!()
            }
        }
        let mut ctx = awaiting(BuildContext::current());
        ctx.state = EnclaveState::new(bitcoin::Network::Regtest).with_seed_source(Box::new(Unused));
        assert!(handle_set_endpoints(&ctx, valid(1)).is_err());
        assert!(ctx.launch.get().is_none());
    }

    /// The README launch: EVM RPC on port 443, and KMS in a mint build.
    /// The test maps port 443 to one free port, and other ports to any port.
    #[test]
    fn the_forwarders_bind_together() {
        // macOS has only 127.0.0.1 on lo0. Linux (CI, the enclave) has all of
        // 127/8. Add it locally with `sudo ifconfig lo0 alias 127.0.0.2 up`.
        #[cfg(all(target_os = "macos", feature = "kms-persistence"))]
        if TcpListener::bind((crate::kms::KMS_LOOPBACK, 0)).is_err() {
            eprintln!("skipped: {} is not on lo0", crate::kms::KMS_LOOPBACK);
            return;
        }
        let plan = forwarder_plan(&Endpoints::parse(&valid(1)).unwrap());
        let addrs: std::collections::HashSet<_> = plan.iter().map(|(a, _, _)| *a).collect();
        assert_eq!(addrs.len(), plan.len(), "{plan:?}");
        let free = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let plan: Vec<_> = plan
            .into_iter()
            .map(|(a, v, t)| {
                let port = if a.port() == 443 { free } else { 0 };
                (SocketAddrV4::new(*a.ip(), port), v, t)
            })
            .collect();
        let listeners = bind_all(&plan).unwrap();
        assert_eq!(listeners.len(), plan.len());
        #[cfg(feature = "kms-persistence")]
        {
            let bound: Vec<_> = listeners
                .iter()
                .map(|(l, _, _)| l.local_addr().unwrap())
                .collect();
            for ip in [Ipv4Addr::LOCALHOST, crate::kms::KMS_LOOPBACK] {
                assert!(bound.contains(&(ip, free).into()), "{bound:?}");
            }
            drop(listeners);
            // Control: KMS on 127.0.0.1 collides with the EVM RPC forwarder.
            let control: Vec<_> = plan
                .iter()
                .map(|&(a, v, t)| (SocketAddrV4::new(Ipv4Addr::LOCALHOST, a.port()), v, t))
                .collect();
            assert!(bind_all(&control).is_err());
        }
    }

    /// Each forwarder of a TLS endpoint refuses plaintext. The indexer
    /// forwarder follows the URL scheme: a dev build can still use a
    /// plaintext indexer.
    #[test]
    fn tls_endpoints_get_tls_only_forwarders() {
        let tls = forwarder_plan(&Endpoints::parse(&valid(1)).unwrap());
        assert!(
            tls.iter().all(|&(_, _, require_tls)| require_tls),
            "{tls:?}"
        );

        #[cfg(feature = "rgb-validation")]
        {
            let plaintext = forwarder_plan(
                &Endpoints::parse(&SetEndpointsRequest {
                    electrum_url: "tcp://electrum1.test:50001".into(),
                    ..valid(1)
                })
                .unwrap(),
            );
            let indexer = plaintext
                .iter()
                .find(|(a, _, _)| a.port() == 50001)
                .unwrap();
            assert!(!indexer.2, "a plaintext dev indexer is not gated");
            assert!(
                plaintext
                    .iter()
                    .filter(|(a, _, _)| a.port() != 50001)
                    .all(|&(_, _, require_tls)| require_tls),
                "the EVM RPC and KMS forwarders stay TLS-only: {plaintext:?}"
            );
        }
    }

    #[cfg(feature = "kms-persistence")]
    #[test]
    fn no_broker_call_before_or_after_a_refused_set() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let broker = TcpListener::bind((
            Ipv4Addr::LOCALHOST,
            crate::seed_persistence::BROKER_LOCAL_PORT,
        ))
        .unwrap();
        let connections: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
        std::thread::spawn(move || {
            // Count each connection and close it.
            for _ in broker.incoming() {
                connections.fetch_add(1, Ordering::SeqCst);
            }
        });
        let ctx = awaiting(BuildContext::current());
        let init = || {
            call(
                &ctx,
                Request::InitializeKey(InitializeKeyRequest::default()),
            )
        };

        assert!(not_ready(init()));
        assert_eq!(connections.load(Ordering::SeqCst), 0);

        let bad = SetEndpointsRequest {
            kms_region: "eu-west-2".into(),
            ..valid(1)
        };
        assert!(handle_set_endpoints(&ctx, bad).is_err());
        assert!(not_ready(init()));
        assert_eq!(connections.load(Ordering::SeqCst), 0);

        handle_set_endpoints(&ctx, valid(1)).unwrap();
        assert!(matches!(init(), Response::Error(_)));
        assert!(!ctx.state.is_initialized());
        assert_eq!(connections.load(Ordering::SeqCst), 1);
    }

    /// A release bridge build with no bridge pins gets a policy that fails
    /// the launch gate. The set is refused without a panic.
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
