//! BFA lock binding: each mint is paired with the deposit id it derives.
//! RGB consensus gets the `cea` events to check the minted amounts.
//!
//! `server/mod.rs` gates this module on `bfa-validation`.

use super::context::ServerContext;
use crate::error::Result;
use crate::networks::evm::events::{derived_lock, VerifiedLock};
use crate::networks::rgb::validation::BfaMint;

/// The derived lock of each mint, in consignment order; no RPC read.
fn derived_locks(ctx: &ServerContext, mints: &[BfaMint]) -> Result<Vec<VerifiedLock>> {
    mints
        .iter()
        .map(|mint| derived_lock(&ctx.bridge_config, mint.opid, mint.minted))
        .collect()
}

/// The `cea` events for RGB consensus: one `(mint OpId, minted amount)` per
/// lock, in consignment order.
pub(super) fn cea_events(locks: &[VerifiedLock]) -> Vec<rgbstd::vm::ether_extension::Event> {
    use rgbstd::vm::ether_extension::Event;
    use rgbstd::{OpId, RevealedValue};

    locks
        .iter()
        .map(|l| Event::new(OpId::from(l.mint_opid), RevealedValue::from(l.minted)))
        .collect()
}

/// The contract pin that both directions apply before a log is trusted.
/// The extension does not check the source contract of an event. Thus this
/// pin is the only barrier against an attacker contract.
fn bfa_binding_for(
    ctx: &ServerContext,
    consignment: &[u8],
    label: &str,
) -> Result<Option<crate::networks::rgb::validation::BfaBinding>> {
    use crate::networks::evm::events::check_bridge_location;
    use crate::networks::rgb::validation::{assert_consignment_size, bfa_binding};

    // Same cap as the anchor validation. That check runs after this parse,
    // so the cap is applied here too.
    assert_consignment_size(consignment, &ctx.bridge_config, label)?;

    // Not a BFA consignment. Other schemas run no extension opcode, so an
    // empty event set is correct.
    let Some(binding) = bfa_binding(consignment)? else {
        return Ok(None);
    };
    check_bridge_location(
        &binding.bridge_location,
        &ctx.bridge_config.funds_in_contract,
    )?;
    Ok(Some(binding))
}

/// The locks behind each mint in a burn's history.
#[cfg(rgb_to_evm)]
pub(super) fn bfa_burn_ancestry_events(
    ctx: &ServerContext,
    source: &enclave_proto::RgbSource,
) -> Result<Vec<VerifiedLock>> {
    let Some(binding) = bfa_binding_for(ctx, &source.consignment, "RGB source")? else {
        return Ok(Vec::new());
    };
    derived_locks(ctx, &binding.mints)
}

/// The locks of a BFA mint and its ancestors. The request's deposit must be
/// the one the terminal mint derives. Empty for a non-BFA consignment.
#[cfg(all(feature = "rgb-mint-burn", evm_to_rgb))]
pub(super) fn bfa_mint_events(
    ctx: &ServerContext,
    source: &enclave_proto::EvmSource,
    destination: &enclave_proto::RgbDestination,
) -> Result<Vec<VerifiedLock>> {
    let Some(binding) = bfa_binding_for(ctx, &destination.consignment, "send-RGB")? else {
        return Ok(Vec::new());
    };
    let terminal = binding.terminal_opid()?;
    let tx_hash: [u8; 32] = source.tx_hash.as_slice().try_into().map_err(|_| {
        crate::error::EnclaveError::CrossCheck(format!(
            "evm_tx_hash must be 32 bytes, got {}",
            source.tx_hash.len()
        ))
    })?;

    let locks = derived_locks(ctx, &binding.mints)?;
    let terminal_lock = locks
        .iter()
        .find(|lock| lock.mint_opid == terminal)
        .ok_or_else(|| {
            crate::error::EnclaveError::CrossCheck("the terminal mint has no derived lock".into())
        })?;
    bind_request_deposit(
        terminal_lock,
        &verify_request_deposit(ctx, &tx_hash, &terminal)?,
    )?;
    Ok(locks)
}

/// The receipt of the request's deposit, checked against the pins.
#[cfg(all(feature = "rgb-mint-burn", evm_to_rgb))]
fn verify_request_deposit(
    ctx: &ServerContext,
    tx_hash: &[u8; 32],
    mint_opid: &[u8; 32],
) -> Result<VerifiedLock> {
    let client = ctx.launch()?.evm_rpc_client.as_ref().ok_or_else(|| {
        crate::error::EnclaveError::CrossCheck(
            "bfa-mint build but the EVM RPC client is unavailable - refusing to sign a mint \
             without independently verifying its FundsIn lock"
                .into(),
        )
    })?;
    crate::networks::evm::events::verify_rgb_funds_in(
        &**client,
        &ctx.bridge_config.funds_in_contract,
        ctx.bridge_config.evm_finality_tag,
        tx_hash,
        mint_opid,
    )
}

/// The request's deposit must equal the mint's derived lock.
#[cfg(all(feature = "rgb-mint-burn", evm_to_rgb))]
fn bind_request_deposit(derived: &VerifiedLock, paid: &VerifiedLock) -> Result<()> {
    if paid != derived {
        return Err(crate::error::EnclaveError::CrossCheck(format!(
            "the request's deposit is not the one mint 0x{} derives: operationId 0x{} for {} \
             (net {}), the mint needs 0x{} for {} - refusing to sign",
            hex::encode(derived.mint_opid),
            hex::encode(paid.operation_id),
            paid.minted,
            paid.net_amount,
            hex::encode(derived.operation_id),
            derived.minted,
        )));
    }
    Ok(())
}

/// The derived locks of the mints a swap transfer descends from.
#[cfg(feature = "rgb-swap")]
pub(super) fn bfa_transfer_ancestry_events(
    ctx: &ServerContext,
    destination: &enclave_proto::RgbDestination,
) -> Result<Vec<VerifiedLock>> {
    let Some(binding) = bfa_binding_for(ctx, &destination.consignment, "send-RGB")? else {
        return Ok(Vec::new());
    };
    derived_locks(ctx, &binding.mints)
}

#[cfg(all(test, feature = "bfa-mint", rgb_to_evm))]
mod burn_locks {
    use enclave_proto::RgbSource;

    use super::{bfa_burn_ancestry_events, ServerContext};
    use crate::config::BridgeConfig;
    use crate::error::Result;
    use crate::networks::evm::events::{
        rgb_mint_deposit_id, BlockData, EvmReceiptProvider, ReceiptData,
    };
    use crate::networks::rgb::validation::bfa_binding;
    use crate::state::EnclaveState;
    use crate::test_support::regtest_header_chain;

    /// One mint of 100_000, then burns (see `tests/fixtures`).
    const BURN: &[u8] = include_bytes!("../../tests/fixtures/bfa_burn_consignment.rgbc");

    /// The burn path reads nothing from the chain.
    struct NoRpc;

    impl EvmReceiptProvider for NoRpc {
        fn get_transaction_receipt(&self, _: &[u8; 32]) -> Result<Option<ReceiptData>> {
            panic!("a burn's locks are derived, not read")
        }

        fn get_block_by_tag(
            &self,
            _tag: attestation_verify::EvmFinalityTag,
        ) -> Result<Option<BlockData>> {
            panic!("a burn's locks are derived, not read")
        }

        fn get_block_by_number(&self, _: u64) -> Result<Option<BlockData>> {
            panic!("a burn's locks are derived, not read")
        }
    }

    fn context(token_contract: [u8; 20]) -> (ServerContext, [u8; 32]) {
        let binding = bfa_binding(BURN).unwrap().expect("a BFA consignment");
        let mut bridge = [0u8; 20];
        hex::decode_to_slice(
            binding.bridge_location.trim_start_matches("0x"),
            &mut bridge,
        )
        .unwrap();
        let cfg = BridgeConfig {
            funds_in_contract: bridge,
            token_contract,
            chain_id: 42161,
            ..BridgeConfig::default()
        };
        let mut ctx = ServerContext::new(EnclaveState::default(), cfg, regtest_header_chain());
        ctx.launch.get_mut().unwrap().evm_rpc_client = Some(Box::new(NoRpc));
        (ctx, binding.mints[0].opid)
    }

    fn burn() -> RgbSource {
        RgbSource {
            consignment: BURN.to_vec(),
            ..Default::default()
        }
    }

    /// Finding 47: a burn's locks come from its mints alone.
    #[test]
    fn derives_the_burn_locks_from_its_mints() {
        let (ctx, mint) = context([0x7e; 20]);

        let locks = bfa_burn_ancestry_events(&ctx, &burn()).unwrap();
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].mint_opid, mint);
        assert_eq!(locks[0].minted, 100_000);
        assert_eq!(locks[0].net_amount, 100_000);
        assert_eq!(
            locks[0].operation_id,
            rgb_mint_deposit_id(&ctx.bridge_config, &mint, 100_000).unwrap()
        );
    }

    #[test]
    fn refuses_a_burn_when_the_token_is_not_pinned() {
        let (ctx, _) = context([0u8; 20]);
        let err = bfa_burn_ancestry_events(&ctx, &burn()).unwrap_err();
        assert!(err.to_string().contains("TOKEN_CONTRACT"), "{err}");
    }
}

#[cfg(all(test, feature = "bfa-mint", evm_to_rgb))]
mod request_deposit {
    use super::bind_request_deposit;
    use crate::networks::evm::events::VerifiedLock;

    const DERIVED: VerifiedLock = VerifiedLock {
        mint_opid: [1; 32],
        minted: 100,
        operation_id: [0xd1; 32],
        net_amount: 100,
    };

    #[test]
    fn accepts_the_deposit_the_mint_derives() {
        assert!(bind_request_deposit(&DERIVED, &DERIVED).is_ok());
    }

    #[test]
    fn refuses_another_deposit_for_the_same_mint() {
        let shadow = VerifiedLock {
            operation_id: [0xd2; 32],
            ..DERIVED
        };
        let err = bind_request_deposit(&DERIVED, &shadow).unwrap_err();
        assert!(err.to_string().contains("not the one mint"), "{err}");
    }

    #[test]
    fn refuses_a_deposit_of_another_amount() {
        let other = VerifiedLock {
            minted: 101,
            net_amount: 101,
            ..DERIVED
        };
        assert!(bind_request_deposit(&DERIVED, &other).is_err());
    }
}
