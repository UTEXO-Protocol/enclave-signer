//! BFA lock verification. Each mint in a consignment is paired with the EVM
//! `FundsIn` deposit that paid for it, and each pair is verified.
//! RGB consensus gets the `cea` events to check the minted amounts.
//!
//! `server/mod.rs` gates this module on `bfa-validation`.

use super::context::ServerContext;
use crate::error::{EnclaveError, Result};

/// The EVM tx hash that the listener gives for `mint_opid`.
///
/// Fails closed. An unlisted mint, or a malformed hash, stops the operation.
/// A mint lock is never left unchecked.
fn ancestor_tx_hash(
    mint_opid: &[u8; 32],
    ancestors: &[enclave_proto::MintAncestor],
) -> Result<[u8; 32]> {
    let ancestor = ancestors
        .iter()
        .find(|a| a.op_id.as_slice() == mint_opid.as_slice())
        .ok_or_else(|| {
            EnclaveError::CrossCheck(format!(
                "no mint_ancestors entry for bridge transition 0x{} - the operation cannot \
                 be validated without the EVM lock behind every mint it descends from",
                hex::encode(mint_opid)
            ))
        })?;

    ancestor.tx_hash.as_slice().try_into().map_err(|_| {
        EnclaveError::CrossCheck(format!(
            "mint_ancestors tx_hash for 0x{} must be 32 bytes, got {}",
            hex::encode(mint_opid),
            ancestor.tx_hash.len()
        ))
    })
}

/// Pair each `TS_BRIDGE` in a mint consignment with its EVM deposit.
/// The terminal mint gets the deposit of this request. Each ancestor gets the
/// lock that the caller lists for it. Consignment order is kept.
///
/// Pure function, so tests can check it without an EVM client. It is the only
/// place where a spent lock could replace the current deposit.
#[cfg(all(feature = "rgb-mint-burn", evm_to_rgb))]
fn mint_lock_plan(
    mint_opids: &[[u8; 32]],
    terminal_opid: &[u8; 32],
    this_deposit: &[u8; 32],
    ancestors: &[enclave_proto::MintAncestor],
) -> Result<Vec<([u8; 32], [u8; 32])>> {
    if ancestors
        .iter()
        .any(|a| a.op_id.as_slice() == terminal_opid.as_slice())
    {
        return Err(EnclaveError::CrossCheck(format!(
            "mint_ancestors lists 0x{}, the mint this request authorises - its lock is this \
             request's own deposit and nothing else",
            hex::encode(terminal_opid)
        )));
    }

    mint_opids
        .iter()
        .map(|opid| {
            let lock = if opid == terminal_opid {
                *this_deposit
            } else {
                ancestor_tx_hash(opid, ancestors)?
            };
            Ok((*opid, lock))
        })
        .collect()
}

/// Verify the `FundsIn` lock for each mint in `plan`. Returns one `cea` event
/// per mint, in plan order.
///
/// `plan` is `(mint OpId, EVM tx hash)`. The OpId is untrusted and only selects
/// the log that must exist. The tx hash is a listener hint. Both are checked
/// against the enclave contract pin. Consensus binds OpId and amount again when
/// `cea` runs. Each failure refuses the signature.
///
/// `unavailable` is the error message when the EVM client is missing.
fn verify_mint_locks(
    ctx: &ServerContext,
    plan: &[([u8; 32], [u8; 32])],
    unavailable: &str,
) -> Result<Vec<crate::networks::evm::events::VerifiedLock>> {
    use crate::networks::evm::events::verify_rgb_funds_in;

    if plan.is_empty() {
        return Ok(Vec::new());
    }

    let client = ctx
        .launch()?
        .evm_rpc_client
        .as_ref()
        .ok_or_else(|| EnclaveError::CrossCheck(unavailable.into()))?;

    plan.iter()
        .map(|(mint_opid, lock)| {
            verify_rgb_funds_in(
                &**client,
                &ctx.bridge_config.funds_in_contract,
                ctx.evm_rpc_config.min_confirmations,
                lock,
                mint_opid,
            )
        })
        .collect()
}

/// The `cea` events for RGB consensus: one `(mint OpId, minted amount)` per
/// verified lock, in plan order.
pub(super) fn cea_events(
    locks: &[crate::networks::evm::events::VerifiedLock],
) -> Vec<rgbstd::vm::ether_extension::Event> {
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

/// Verify the `FundsIn` lock behind each mint in a burn consignment history.
/// Returns one `cea` event per mint.
///
/// The listener supplies `(op_id, tx_hash)` pairs as hints, because only it
/// can search the chain. [`verify_mint_locks`] checks each pair. A mint with
/// no pair, or with a log that does not bind to it, fails the validation.
/// A burn can only release funds that a real, verified lock created.
#[cfg(rgb_to_evm)]
pub(super) fn bfa_burn_ancestry_events(
    ctx: &ServerContext,
    source: &enclave_proto::RgbSource,
) -> Result<Vec<crate::networks::evm::events::VerifiedLock>> {
    let Some(binding) = bfa_binding_for(ctx, &source.consignment, "RGB source")? else {
        return Ok(Vec::new());
    };

    let plan = binding
        .mint_opids
        .iter()
        .map(|opid| Ok((*opid, ancestor_tx_hash(opid, &source.mint_ancestors)?)))
        .collect::<Result<Vec<_>>>()?;

    verify_mint_locks(
        ctx,
        &plan,
        "bfa-mint build but the EVM RPC client is unavailable - refusing to validate a burn \
         without independently verifying the locks behind its mints",
    )
}

/// Verify the EVM lock of a BFA mint and the lock of each ancestor.
/// Returns them as the event set for RGB consensus.
///
/// Returns an empty vec for a non-BFA consignment.
#[cfg(all(feature = "rgb-mint-burn", evm_to_rgb))]
pub(super) fn bfa_mint_events(
    ctx: &ServerContext,
    source: &enclave_proto::EvmSource,
    destination: &enclave_proto::RgbDestination,
) -> Result<Vec<crate::networks::evm::events::VerifiedLock>> {
    let Some(binding) = bfa_binding_for(ctx, &destination.consignment, "send-RGB")? else {
        return Ok(Vec::new());
    };

    let tx_hash: [u8; 32] = source.tx_hash.as_slice().try_into().map_err(|_| {
        EnclaveError::CrossCheck(format!(
            "evm_tx_hash must be 32 bytes, got {}",
            source.tx_hash.len()
        ))
    })?;
    let plan = mint_lock_plan(
        &binding.mint_opids,
        &binding.terminal_opid()?,
        &tx_hash,
        &destination.mint_ancestors,
    )?;

    verify_mint_locks(
        ctx,
        &plan,
        "bfa-mint build but the EVM RPC client is unavailable - refusing to sign a mint \
         without independently verifying its FundsIn lock",
    )
}

/// A swap transfer spends BFA allocations from earlier mints. Verify each
/// mint in its consignment history before the consensus extension runs.
#[cfg(feature = "rgb-swap")]
pub(super) fn bfa_transfer_ancestry_events(
    ctx: &ServerContext,
    destination: &enclave_proto::RgbDestination,
) -> Result<Vec<crate::networks::evm::events::VerifiedLock>> {
    let Some(binding) = bfa_binding_for(ctx, &destination.consignment, "send-RGB")? else {
        return Ok(Vec::new());
    };
    let plan = binding
        .mint_opids
        .iter()
        .map(|opid| Ok((*opid, ancestor_tx_hash(opid, &destination.mint_ancestors)?)))
        .collect::<Result<Vec<_>>>()?;
    verify_mint_locks(
        ctx,
        &plan,
        "BFA transfer requires independent verification of its mint ancestry",
    )
}

#[cfg(all(test, feature = "bfa-mint", evm_to_rgb))]
mod mint_ancestry {
    use super::mint_lock_plan;
    use enclave_proto::MintAncestor;

    const DEPOSIT: [u8; 32] = [0xde; 32];

    fn ancestor(op: u8, tx: u8) -> MintAncestor {
        MintAncestor {
            op_id: vec![op; 32],
            tx_hash: vec![tx; 32],
        }
    }

    /// The first mint on a bridge right has no ancestors. Its only lock is
    /// the deposit of the request.
    #[test]
    fn a_first_mint_is_paid_by_this_requests_deposit() {
        let terminal = [1u8; 32];
        assert_eq!(
            mint_lock_plan(&[terminal], &terminal, &DEPOSIT, &[]).unwrap(),
            vec![(terminal, DEPOSIT)]
        );
    }

    /// Mint N carries mints 1..N-1. Each is verified against its own deposit.
    #[test]
    fn a_chained_mint_pairs_each_predecessor_with_its_own_lock() {
        let (first, second, terminal) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let plan = mint_lock_plan(
            &[first, second, terminal],
            &terminal,
            &DEPOSIT,
            &[ancestor(1, 0xaa), ancestor(2, 0xbb)],
        )
        .unwrap();

        assert_eq!(
            plan,
            vec![
                (first, [0xaa; 32]),
                (second, [0xbb; 32]),
                (terminal, DEPOSIT),
            ],
            "consignment order must survive, and only the terminal mint may use the deposit"
        );
    }

    /// Replay case. If the caller lists the terminal mint, it could pay for it
    /// with a lock that an earlier mint already spent.
    #[test]
    fn refuses_a_caller_that_lists_the_mint_being_authorised() {
        let terminal = [3u8; 32];
        let err = mint_lock_plan(
            &[terminal],
            &terminal,
            &DEPOSIT,
            &[MintAncestor {
                op_id: terminal.to_vec(),
                tx_hash: vec![0xaa; 32],
            }],
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("the mint this request authorises"),
            "{err}"
        );
    }

    /// An unlisted predecessor must stop the mint. Its lock must not reach
    /// consensus unchecked. The burn direction has the same rule.
    #[test]
    fn refuses_a_predecessor_with_no_listed_lock() {
        let (first, terminal) = ([1u8; 32], [3u8; 32]);
        let err = mint_lock_plan(&[first, terminal], &terminal, &DEPOSIT, &[]).unwrap_err();
        assert!(err.to_string().contains("no mint_ancestors entry"), "{err}");
    }

    /// The op id identifies the terminal mint, not the position. If it is
    /// first, it still uses the deposit. Later transitions need their own locks.
    #[test]
    fn the_terminal_mint_is_found_by_op_id_not_by_position() {
        let (terminal, later) = ([3u8; 32], [4u8; 32]);
        let plan = mint_lock_plan(
            &[terminal, later],
            &terminal,
            &DEPOSIT,
            &[ancestor(4, 0xcc)],
        )
        .unwrap();
        assert_eq!(plan, vec![(terminal, DEPOSIT), (later, [0xcc; 32])]);
    }
}

#[cfg(all(test, feature = "bfa-mint"))]
mod burn_ancestry {
    use super::ancestor_tx_hash;
    use enclave_proto::MintAncestor;

    fn ancestor(op: u8, tx: u8) -> MintAncestor {
        MintAncestor {
            op_id: vec![op; 32],
            tx_hash: vec![tx; 32],
        }
    }

    #[test]
    fn returns_the_tx_hash_listed_for_that_mint() {
        let ancestors = vec![ancestor(1, 0xaa), ancestor(2, 0xbb)];
        assert_eq!(
            ancestor_tx_hash(&[2u8; 32], &ancestors).unwrap(),
            [0xbb; 32]
        );
    }

    /// An unlisted mint must stop the burn. An unchecked lock would let an
    /// unbacked mint be redeemed on EVM.
    #[test]
    fn rejects_a_mint_with_no_listed_ancestor() {
        let err = ancestor_tx_hash(&[9u8; 32], &[ancestor(1, 0xaa)]).unwrap_err();
        assert!(err.to_string().contains("no mint_ancestors entry"), "{err}");
    }

    #[test]
    fn rejects_an_empty_ancestor_list() {
        assert!(ancestor_tx_hash(&[1u8; 32], &[]).is_err());
    }

    /// A lenient decoder could pad a short hash and find a different transaction.
    #[test]
    fn rejects_a_tx_hash_that_is_not_32_bytes() {
        let listed = MintAncestor {
            op_id: vec![1u8; 32],
            tx_hash: vec![0xaa; 31],
        };
        let err = ancestor_tx_hash(&[1u8; 32], &[listed]).unwrap_err();
        assert!(err.to_string().contains("must be 32 bytes"), "{err}");
    }

    /// An op id with the same prefix is a different transition.
    #[test]
    fn matches_the_op_id_exactly() {
        let mut near = ancestor(1, 0xaa);
        near.op_id[31] = 2;
        assert!(ancestor_tx_hash(&[1u8; 32], &[near]).is_err());
    }
}

/// Finding 47. `fundsIn` is public, so anyone can make a second deposit that
/// names a mint's RGB OpId. The burn must still settle under one `burnId`.
#[cfg(all(test, feature = "bfa-mint", rgb_to_evm))]
mod shadow_deposit {
    use std::collections::HashMap;

    use alloy_primitives::{B256, U256};
    use alloy_sol_types::SolValue;
    use enclave_proto::{MintAncestor, RgbSource};
    use sha3::{Digest, Keccak256};

    use super::{bfa_burn_ancestry_events, ServerContext};
    use crate::config::BridgeConfig;
    use crate::error::Result;
    use crate::networks::evm::crosscheck::validate_funds_out_settlement;
    use crate::networks::evm::events::{
        EvmReceiptProvider, LogEntry, ReceiptData, VerifiedLock, BRIDGE_FUNDS_IN_SIG, FUNDS_IN_SIG,
    };
    use crate::networks::evm::validation::{expected_burn_id, ReleaseIdentity};
    use crate::networks::rgb::validation::bfa_binding;
    use crate::state::EnclaveState;
    use crate::test_support::{abi_word, bridge_funds_in_data, regtest_header_chain};

    /// One mint of 100_000, then burns (see `tests/fixtures`).
    const BURN: &[u8] = include_bytes!("../../tests/fixtures/bfa_burn_consignment.rgbc");
    const MINTED: u64 = 100_000;
    const REAL_DEPOSIT: [u8; 32] = [0xaa; 32];
    const SHADOW_DEPOSIT: [u8; 32] = [0xbb; 32];

    /// Answers each receipt by its tx hash.
    struct Chain(HashMap<[u8; 32], ReceiptData>);

    impl EvmReceiptProvider for Chain {
        fn get_transaction_receipt(&self, tx_hash: &[u8; 32]) -> Result<Option<ReceiptData>> {
            Ok(self.0.get(tx_hash).cloned())
        }

        fn get_block_number(&self) -> Result<u64> {
            Ok(1_000)
        }
    }

    fn topic0(signature: &str) -> [u8; 32] {
        Keccak256::digest(signature.as_bytes()).into()
    }

    /// A `fundsIn` that names `rgb_opid`, with the `operationId` the Bridge
    /// derived for this deposit.
    fn deposit(bridge: [u8; 20], rgb_opid: [u8; 32], operation_id: [u8; 32]) -> ReceiptData {
        let mut funds_in = rgb_opid.to_vec();
        funds_in.extend_from_slice(&abi_word(MINTED));
        ReceiptData {
            status_success: true,
            block_number: 100,
            logs: vec![
                LogEntry {
                    address: bridge,
                    topics: vec![topic0(FUNDS_IN_SIG), abi_word(0xdead)],
                    data: funds_in,
                },
                LogEntry {
                    address: bridge,
                    topics: vec![
                        topic0(BRIDGE_FUNDS_IN_SIG),
                        operation_id,
                        [0x5c; 32],
                        abi_word(0xdead),
                    ],
                    data: bridge_funds_in_data(MINTED, MINTED, 0, ""),
                },
            ],
        }
    }

    fn release(locks: &[VerifiedLock]) -> ReleaseIdentity {
        let ids: Vec<B256> = locks.iter().map(|l| B256::from(l.operation_id)).collect();
        let amounts: Vec<U256> = locks.iter().map(|l| U256::from(l.net_amount)).collect();
        ReleaseIdentity {
            burn_id: U256::ZERO,
            amount: U256::from(50_000),
            source_chain_id: U256::from(96),
            source_address: "rgb-burner".into(),
            settlement_data: (ids, amounts).abi_encode_params(),
            source_burn_tx_id: [0x0b; 32],
            recipient: [0u8; 32],
            proof: Vec::new(),
        }
    }

    #[test]
    fn a_shadow_deposit_does_not_give_the_burn_a_second_burn_id() {
        let binding = bfa_binding(BURN).unwrap().expect("a BFA consignment");
        assert_eq!(binding.mint_opids.len(), 1, "the fixture has one mint");
        let mint = binding.mint_opids[0];
        let mut bridge = [0u8; 20];
        hex::decode_to_slice(
            binding.bridge_location.trim_start_matches("0x"),
            &mut bridge,
        )
        .unwrap();

        // The user's deposit paid for the mint. The attacker later calls
        // `fundsIn` with the same RGB OpId and amount: a new `operationId`.
        let chain = Chain(HashMap::from([
            (REAL_DEPOSIT, deposit(bridge, mint, [0x11; 32])),
            (SHADOW_DEPOSIT, deposit(bridge, mint, [0x22; 32])),
        ]));
        let cfg = BridgeConfig {
            funds_in_contract: bridge,
            ..BridgeConfig::default()
        };
        let mut ctx =
            ServerContext::new(EnclaveState::default(), cfg.clone(), regtest_header_chain());
        ctx.launch.get_mut().unwrap().evm_rpc_client = Some(Box::new(chain));

        let locks_with = |deposit: [u8; 32]| {
            bfa_burn_ancestry_events(
                &ctx,
                &RgbSource {
                    consignment: BURN.to_vec(),
                    mint_ancestors: vec![MintAncestor {
                        op_id: mint.to_vec(),
                        tx_hash: deposit.to_vec(),
                    }],
                    ..Default::default()
                },
            )
        };

        let real = locks_with(REAL_DEPOSIT).expect("the user's deposit backs the burn");
        let Ok(shadow) = locks_with(SHADOW_DEPOSIT) else {
            return; // the shadow deposit is refused: one lock set
        };

        // Both requests pass the settlement check, so both would be signed.
        let (first, second) = (release(&real), release(&shadow));
        validate_funds_out_settlement(&first, &real).unwrap();
        validate_funds_out_settlement(&second, &shadow).unwrap();
        assert_eq!(
            expected_burn_id(&cfg, &first),
            expected_burn_id(&cfg, &second),
            "one burn, two burnIds: the Bridge pays it twice (settlementData cites 0x{} or 0x{})",
            hex::encode(real[0].operation_id),
            hex::encode(shadow[0].operation_id),
        );
    }
}
