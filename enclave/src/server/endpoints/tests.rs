use super::*;
use crate::policy::BuildContext;
use crate::proto::enclave_request::Request;
use crate::state::EnclaveState;
#[cfg(feature = "kms-persistence")]
use std::net::Ipv4Addr;

fn awaiting(build_ctx: BuildContext) -> ServerContext {
    awaiting_with(crate::config::BridgeConfig::default(), build_ctx)
}

fn awaiting_with(
    bridge_config: crate::config::BridgeConfig,
    build_ctx: BuildContext,
) -> ServerContext {
    ServerContext::awaiting_launch(
        EnclaveState::new(bitcoin::Network::Regtest),
        bridge_config,
        #[cfg(feature = "rgb-validation")]
        std::sync::Mutex::new(crate::networks::rgb::spv::HeaderChain::new(
            crate::networks::rgb::spv::Network::Regtest,
            crate::networks::rgb::spv::checkpoint_for(crate::networks::rgb::spv::Network::Regtest),
        )),
        build_ctx,
    )
}

const KEY_ARN: &str = "arn:aws:kms:eu-west-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef";

/// A valid set for this build. `n` varies the hosts and the seed id.
fn valid(n: u8) -> SetEndpointsRequest {
    let mut req = SetEndpointsRequest::default();
    if cfg!(feature = "rgb-validation") {
        req.electrum_url = format!("ssl://electrum{n}.test:50002");
    }
    if cfg!(feature = "rgb-validation") {
        req.evm_rpc_host = format!("rpc{n}.test");
        req.evm_rpc_ca_der =
            hex::decode(include_str!("../../../tests/fixtures/evm_rpc_tls/ca_a.der.hex").trim())
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
        Request::SignRightsRefill(SignRightsRefillRequest::default()),
        Request::SignRawDigest(SignRawDigestRequest::default()),
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
    // The mint signer serves the refill, so it waits for the set too.
    if cfg!(all(feature = "rgb-validation", evm_to_rgb)) {
        let refill = Request::SignRightsRefill(SignRightsRefillRequest::default());
        assert!(not_ready(call(&ctx, refill)));
    }
    let h = health(&ctx);
    assert!(!h.endpoints_set && !h.ready && h.key_loaded);

    call(&ctx, Request::SetEndpoints(valid(1)));
    assert!(health(&ctx).endpoints_set);
}

/// The image pins the AWS accounts of the KMS key. A key ARN in another
/// account is refused, and a release image with no list refuses every key.
#[cfg(feature = "kms-persistence")]
#[test]
fn a_key_in_an_unpinned_account_is_refused() {
    let message = |ctx: &ServerContext| match call(ctx, Request::SetEndpoints(valid(1))) {
        Response::Error(e) => e.message,
        other => panic!("expected an error, got {other:?}"),
    };
    // KEY_ARN is in account 123456789012.
    let other_account = crate::config::BridgeConfig {
        kms_allowed_accounts: vec!["999999999999".into()],
        ..Default::default()
    };
    let ctx = awaiting_with(other_account, BuildContext::current());
    let got = message(&ctx);
    assert!(got.contains("does not pin"), "{got}");
    assert!(!health(&ctx).endpoints_set);

    let release = BuildContext {
        debug_or_test: false,
        ..BuildContext::current()
    };
    let ctx = awaiting_with(crate::config::BridgeConfig::default(), release);
    let got = message(&ctx);
    assert!(got.contains("not pinned"), "{got}");
    assert!(!health(&ctx).endpoints_set);
}

#[test]
fn a_refused_set_leaves_the_slot_empty() {
    let ctx = awaiting(BuildContext::current());
    let mut bad = vec![SetEndpointsRequest {
        electrum_url: "ftp://electrum.test:1".into(),
        ..valid(1)
    }];
    if cfg!(feature = "rgb-validation") {
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

/// The `docs/operations.md` launch: EVM RPC on port 443, KMS in a mint build.
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
    let plan = forwarder_plan(&Endpoints::parse(&valid(1), &[], true).unwrap());
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
    let tls = forwarder_plan(&Endpoints::parse(&valid(1), &[], true).unwrap());
    assert!(
        tls.iter().all(|&(_, _, require_tls)| require_tls),
        "{tls:?}"
    );

    #[cfg(feature = "rgb-validation")]
    {
        let plaintext = forwarder_plan(
            &Endpoints::parse(
                &SetEndpointsRequest {
                    electrum_url: "tcp://electrum1.test:50001".into(),
                    ..valid(1)
                },
                &[],
                true,
            )
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

#[cfg(feature = "spv")]
#[test]
fn the_same_spv_build_accepts_different_runtime_hosts_ports_and_ca() {
    let first = valid(1);
    let second = SetEndpointsRequest {
        electrum_url: "ssl://member-two-indexer.test:50003".into(),
        evm_rpc_host: "member-two-rpc.test".into(),
        evm_rpc_ca_der: hex::decode(
            include_str!("../../../tests/fixtures/evm_rpc_tls/ca_b.der.hex").trim(),
        )
        .unwrap(),
        evm_rpc_tls_port: 8443,
        ..first.clone()
    };
    let build = BuildContext::current();
    for request in [&first, &second] {
        let ctx = awaiting(build);
        handle_set_endpoints(&ctx, request.clone()).unwrap();
        let launch = ctx.launch().unwrap();
        assert_eq!(
            launch.endpoints,
            Endpoints::parse(request, &[], true).unwrap()
        );
        assert!(launch.rgb_validator.is_some());
        assert!(launch.evm_rpc_client.is_some());
    }
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
    let want = Endpoints::parse(&valid(winners[0]), &[], true).unwrap();
    assert_eq!(ctx.launch().unwrap().endpoints, want);
}
