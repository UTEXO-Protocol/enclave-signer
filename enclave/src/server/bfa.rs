//! BFA lock verification: pair every mint in a consignment with the EVM
//! `FundsIn` deposit that paid for it, verify each one, and hand RGB consensus
//! the `cea` events it checks the minted amounts against.
//!
//! `bfa-validation`-only; `server/mod.rs` gates the whole module.

use super::context::ServerContext;
use crate::error::{EnclaveError, Result};

/// The EVM tx hash the listener claims backs `mint_opid`.
///
/// Fails closed: an unlisted mint, or one listed with a malformed hash, aborts
/// the burn rather than validating with that mint's lock unchecked.
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

/// Pair every `TS_BRIDGE` in a mint consignment with the EVM deposit that must
/// back it: the terminal mint with this request's own deposit, every ancestor
/// with the lock the caller listed for it. Consignment order is preserved.
///
/// Pure, so the rule that decides which lock pays for which mint is testable
/// without an EVM client - it is the one place a spent lock could be
/// substituted for the one being paid now.
#[cfg(feature = "rgb-mint-burn")]
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

/// Verify the `FundsIn` lock paired with every mint in `plan` and return one
/// `cea` event per mint, in plan order.
///
/// `plan` is `(mint OpId, EVM tx hash)`: the OpId is untrusted and only selects
/// which log must exist, and the tx hash is a listener hint. Both are checked
/// here against the enclave's own contract pin, through the same Helios-backed
/// path the swap flow uses, and consensus re-binds OpId and amount when `cea`
/// runs. Every failure refuses the signature.
///
/// `unavailable` names, in the rejection, what the missing EVM client would
/// have been used to authorise.
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

/// The `cea` events RGB consensus checks the mints against: one per verified
/// lock, `(mint OpId, minted amount)`, in plan order.
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

/// The contract pin both directions apply before any log is trusted: the
/// extension never checks which contract an event came from, so this is the
/// only thing between a mint or a redemption and an attacker's contract.
fn bfa_binding_for(
    ctx: &ServerContext,
    consignment: &[u8],
    label: &str,
) -> Result<Option<crate::networks::rgb::validation::BfaBinding>> {
    use crate::networks::evm::events::check_bridge_location;
    use crate::networks::rgb::validation::{assert_consignment_size, bfa_binding};

    // The same cap the anchor validation applies, repeated because that check
    // now runs after this parse rather than before it.
    assert_consignment_size(consignment, &ctx.bridge_config, label)?;

    // Not a BFA consignment: the other schemas run no extension opcode, so an
    // empty event set is correct rather than merely tolerated.
    let Some(binding) = bfa_binding(consignment)? else {
        return Ok(None);
    };
    check_bridge_location(
        &binding.bridge_location,
        &ctx.bridge_config.funds_in_contract,
    )?;
    Ok(Some(binding))
}

/// Verify the `FundsIn` lock behind every mint a burn consignment descends
/// from, and return one `cea` event per mint.
///
/// The listener supplies `(op_id, tx_hash)` pairs because only it can search
/// the chain; they are hints. Every pair is fetched and checked by
/// [`verify_mint_locks`], and a mint with no pair - or with one whose log does
/// not bind to it - fails the whole validation. That is the point: a burn may
/// only release funds that a real, verified lock once created.
pub(super) fn bfa_burn_ancestry_events(
    ctx: &ServerContext,
    source: &enclave_proto::RgbSource,
) -> Result<Vec<crate::networks::evm::events::VerifiedLock>> {
    if cfg!(feature = "dev-mode") {
        return Ok(Vec::new());
    }

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

/// Verify the EVM lock a BFA mint commits to, plus the lock behind each of its
/// ancestors, and return them as the event set RGB consensus checks the minted
/// amounts against.
///
/// Empty vec when this is not an EVM-to-RGB request or the consignment is not a
/// BFA one, so the swap path is unaffected.
#[cfg(feature = "rgb-mint-burn")]
pub(super) fn bfa_mint_events(
    ctx: &ServerContext,
    source: &enclave_proto::EvmSource,
    destination: &enclave_proto::RgbDestination,
) -> Result<Vec<crate::networks::evm::events::VerifiedLock>> {
    // dev-mode compiles no destination-anchor validation, so these events would
    // have no consumer and the RPC call would be pure cost.
    if cfg!(feature = "dev-mode") {
        return Ok(Vec::new());
    }

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

/// A swap transfer spends previously minted BFA allocations. Verify every
/// mint in its consignment history before running the consensus extension.
#[cfg(feature = "rgb-swap")]
pub(super) fn bfa_transfer_ancestry_events(
    ctx: &ServerContext,
    destination: &enclave_proto::RgbDestination,
) -> Result<Vec<crate::networks::evm::events::VerifiedLock>> {
    if cfg!(feature = "dev-mode") {
        return Ok(Vec::new());
    }
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

#[cfg(all(test, feature = "bfa-mint"))]
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

    /// The first mint on a bridge right carries nothing else, so the only
    /// lock in play is the deposit that arrived with the request.
    #[test]
    fn a_first_mint_is_paid_by_this_requests_deposit() {
        let terminal = [1u8; 32];
        assert_eq!(
            mint_lock_plan(&[terminal], &terminal, &DEPOSIT, &[]).unwrap(),
            vec![(terminal, DEPOSIT)]
        );
    }

    /// What the whole change is for: mint N carries mints 1..N-1, and each
    /// of them is verified against the deposit that actually paid for it.
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

    /// The replay this design has to refuse. Listing the terminal mint would
    /// let a caller pay for it with a lock some earlier mint already spent.
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

    /// A predecessor nobody accounted for must abort the mint rather than
    /// reach consensus with its lock unchecked - the same rule the burn
    /// direction already enforces.
    #[test]
    fn refuses_a_predecessor_with_no_listed_lock() {
        let (first, terminal) = ([1u8; 32], [3u8; 32]);
        let err = mint_lock_plan(&[first, terminal], &terminal, &DEPOSIT, &[]).unwrap_err();
        assert!(err.to_string().contains("no mint_ancestors entry"), "{err}");
    }

    /// The terminal mint is identified by op id, not by position: a
    /// consignment that lists it first must still pay for it with the
    /// deposit, and the later transitions must bring their own locks.
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

    /// The whole point of the pre-pass. A mint the listener did not account
    /// for must abort the burn - never validate with its lock unchecked,
    /// which is what would let an unbacked mint be redeemed on EVM.
    #[test]
    fn rejects_a_mint_with_no_listed_ancestor() {
        let err = ancestor_tx_hash(&[9u8; 32], &[ancestor(1, 0xaa)]).unwrap_err();
        assert!(err.to_string().contains("no mint_ancestors entry"), "{err}");
    }

    #[test]
    fn rejects_an_empty_ancestor_list() {
        assert!(ancestor_tx_hash(&[1u8; 32], &[]).is_err());
    }

    /// A short hash would otherwise be silently padded by a lenient decoder
    /// and look up a different transaction.
    #[test]
    fn rejects_a_tx_hash_that_is_not_32_bytes() {
        let listed = MintAncestor {
            op_id: vec![1u8; 32],
            tx_hash: vec![0xaa; 31],
        };
        let err = ancestor_tx_hash(&[1u8; 32], &[listed]).unwrap_err();
        assert!(err.to_string().contains("must be 32 bytes"), "{err}");
    }

    /// An op id that merely shares a prefix is a different transition.
    #[test]
    fn matches_the_op_id_exactly() {
        let mut near = ancestor(1, 0xaa);
        near.op_id[31] = 2;
        assert!(ancestor_tx_hash(&[1u8; 32], &[near]).is_err());
    }
}
