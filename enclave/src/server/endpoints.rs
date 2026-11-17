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

    #[cfg(feature = "kms-persistence")]
    let kms_accounts = ctx.bridge_config.kms_allowed_accounts.as_slice();
    // This build takes no KMS key, so it has no account list.
    #[cfg(not(feature = "kms-persistence"))]
    let kms_accounts: &[String] = &[];
    let endpoints = Endpoints::parse(&req, kms_accounts, ctx.build_ctx.debug_or_test)
        .map_err(EnclaveError::InvalidRequest)?;
    // A mint signer signs no release, so a route list there is a mistake.
    if ctx.build_ctx.signer_role == crate::policy::SignerRole::Mint
        && !endpoints.lz_routes.is_empty()
    {
        return Err(EnclaveError::InvalidRequest(
            "lz_routes must be empty on a mint signer".into(),
        ));
    }
    #[cfg(feature = "rgb-validation")]
    let tls = endpoints
        .evm_rpc_tls
        .as_ref()
        .ok_or_else(|| EnclaveError::InvalidRequest("the EVM RPC endpoint is not set".into()))?;
    #[cfg(feature = "rgb-validation")]
    let (evm_source, evm_rpc_tls) = crate::bootstrap::resolve_evm_data_source(tls);
    #[cfg(not(feature = "rgb-validation"))]
    let (evm_source, evm_rpc_tls) = (crate::policy::EvmDataSource::Disabled, None);
    let policy =
        SecurityPolicy::resolve(&ctx.build_ctx, &ctx.bridge_config, evm_source, evm_rpc_tls)
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
    // (privileged ports, root). Thus `cfg(test)` skips them.
    #[cfg(all(feature = "vsock", target_os = "linux", not(test)))]
    let listeners = bind_all(&forwarder_plan(&endpoints))?;

    #[cfg(feature = "rgb-validation")]
    let rgb_validator = crate::bootstrap::build_rgb_validator()
        .ok_or_else(|| EnclaveError::Internal("cannot build the RGB validator".into()))?;
    #[cfg(feature = "rgb-validation")]
    let evm_rpc_client = crate::bootstrap::build_evm_rpc_client(tls)
        .ok_or_else(|| EnclaveError::Internal("cannot build the EVM RPC client".into()))?;
    let launch = Launch {
        #[cfg(feature = "rgb-validation")]
        rgb_validator: Some(rgb_validator),
        #[cfg(feature = "rgb-validation")]
        evm_rpc_client: Some(evm_rpc_client),
        endpoints,
        policy,
    };

    // The last step that can fail.
    #[cfg(all(
        feature = "vsock",
        feature = "kms-persistence",
        target_os = "linux",
        not(test)
    ))]
    if let Some(kms) = &launch.endpoints.kms {
        crate::bootstrap::pin_host(
            std::path::Path::new("/etc/hosts"),
            crate::kms::KMS_LOOPBACK,
            &crate::kms::endpoint_host(&kms.region),
        )
        .map_err(|e| {
            EnclaveError::Internal(format!("cannot pin the KMS host in /etc/hosts: {e}"))
        })?;
    }
    #[cfg(all(feature = "vsock", target_os = "linux", not(test)))]
    for (listener, vsock_port) in listeners {
        crate::vsock_forwarder::spawn(listener, vsock_port);
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

/// The loopback end and the parent vsock port of each forwarder this build
/// needs. The host must run `vsock-proxy <vsock port> <host> <port>` for each.
/// Each forwarder sends on only TLS ([`crate::egress`]).
#[cfg(any(test, all(feature = "vsock", target_os = "linux")))]
fn forwarder_plan(endpoints: &Endpoints) -> Vec<(SocketAddrV4, u32)> {
    #[allow(unused_mut)]
    let mut plan = Vec::new();
    #[cfg(feature = "rgb-validation")]
    if let Some(tls) = &endpoints.evm_rpc_tls {
        plan.push((
            SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, tls.tls_port),
            vsock_port("EVM_RPC_VSOCK_PORT", 8002),
        ));
    }
    // The EVM RPC can use the KMS port (`crate::kms::KMS_PORT`), so KMS takes
    // its own loopback address.
    #[cfg(feature = "kms-persistence")]
    if endpoints.kms.is_some() {
        plan.push((
            SocketAddrV4::new(crate::kms::KMS_LOOPBACK, crate::kms::KMS_PORT),
            vsock_port("KMS_VSOCK_PORT", crate::kms::DEFAULT_KMS_VSOCK_PORT),
        ));
    }
    let _ = endpoints;
    plan
}

#[cfg(any(test, all(feature = "vsock", target_os = "linux")))]
fn bind_all(plan: &[(SocketAddrV4, u32)]) -> Result<Vec<(TcpListener, u32)>> {
    plan.iter()
        .map(|&(addr, vsock_port)| {
            TcpListener::bind(addr)
                .map(|listener| (listener, vsock_port))
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
mod tests;
