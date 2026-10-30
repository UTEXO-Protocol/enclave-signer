//! The flat transition summary over every consignment shape the generator
//! makes. A reference reading of the rgbstd `Transfer` pins each field, and
//! rgb-lib's inspection must match it, as must the parser the bridge reads
//! burns with (consignment-utils).

use amplify::Wrapper;
use rgb_consignment::{ConsignmentInfo, SealInfo};
use rgbstd::containers::Transfer;
use rgbstd::contract::TransitionBuilder;
use rgbstd::{ChainNet, ContractId, Operation, TypedAssigns};

use super::super::scratch::with_scratch_file;
use super::super::transition::output_seal;
use super::*;

type Summary = Vec<(bitcoin::Txid, Vec<TransitionSummary>)>;

/// The summary read straight from the rgbstd types: every transition per
/// witness, its `OS_ASSET` fungible outputs, seals as the consignment holds them.
fn reference_summary(transfer: &Transfer) -> Summary {
    transfer
        .bundles
        .iter()
        .map(|wb| {
            let summaries = wb
                .bundle
                .known_transitions
                .iter()
                .map(|k| reference_transition(&k.transition, k.opid))
                .collect();
            (wb.witness_id(), summaries)
        })
        .collect()
}

fn reference_transition(t: &rgbstd::Transition, opid: rgbstd::OpId) -> TransitionSummary {
    let outputs: Vec<TransitionOutput> = t
        .assignments
        .iter()
        .filter(|(ty, _)| **ty == schemata::OS_ASSET)
        .flat_map(|(_, assigns)| match assigns {
            TypedAssigns::Fungible(vec) => vec.iter().map(reference_output).collect(),
            _ => Vec::new(),
        })
        .collect();
    let total = outputs.iter().map(|o| o.amount).sum();
    TransitionSummary {
        op_id: opid.to_string(),
        transition_type: t.transition_type.to_inner(),
        total_output_amount: total,
        asset_output_amount: total,
        outputs,
        burned_asset_amount: None,
        burn_reason: None,
    }
}

fn reference_output(a: &rgbstd::Assign<RevealedValue, GraphSeal>) -> TransitionOutput {
    TransitionOutput {
        assignment_type: schemata::OS_ASSET.to_inner(),
        amount: a.state.as_u64(),
        seal: output_seal(&a.seal),
    }
}

/// A seal on `vout` of an explicit funding tx, not the witness.
fn explicit_seal(tag: u8, vout: u32) -> BuilderSeal<GraphSeal> {
    BuilderSeal::from(GraphSeal::with_blinding(
        gen::outpoint(tag, 0).txid,
        vout,
        0x7000 + u64::from(tag),
    ))
}

fn concealed_seal(tag: u8) -> BuilderSeal<GraphSeal> {
    let seal = GraphSeal::with_blinding(gen::outpoint(tag, 0).txid, 0u32, 0x8000 + u64::from(tag));
    BuilderSeal::Concealed(seal.to_secret_seal())
}

/// A mint of `MINTED` to `to`, on an asset of `chain_net`.
fn mint_to(chain_net: ChainNet, to: BuilderSeal<GraphSeal>) -> History {
    let mut history = History::issue(Issue {
        chain_net,
        ..Issue::new(EVM_CHAIN_ID, BRIDGE, vec![right_utxo()])
    });
    let right = history.genesis_right(0, right_utxo());
    history.mint(right, MINTED, 90, to, vec![], vec![gen::dust(1)]);
    history
}

/// A transfer of `units` (holding `MINTED`) to a blinded recipient, with the
/// change on vout 1 of its witness, as a send to an invoice.
fn send_to_invoice(history: &mut History, units: Utxo, recipient: BuilderSeal<GraphSeal>) {
    let sent = MINTED / 4;
    let send = history
        .transition("transfer")
        .add_input(
            units.opout,
            AllocatedState::from(RevealedValue::from(MINTED)),
        )
        .unwrap()
        .add_fungible_state("assetOwner", recipient, sent)
        .unwrap()
        .add_fungible_state(
            "assetOwner",
            GraphSeal::with_blinded_vout(1u32, 0x51),
            MINTED - sent,
        )
        .unwrap()
        .complete_transition()
        .unwrap();
    history.commit(vec![send], vec![units.outpoint], vec![gen::dust(2)]);
}

/// The burn and a companion transfer in one bundle, as rgb-lib builds a burn.
fn burn_beside_transfer(burn_first: bool) -> History {
    let (mut history, [kept, burned]) = minted_in_halves();
    let half = MINTED / 2;
    let transfer = history
        .transition("transfer")
        .add_input(kept.opout, AllocatedState::from(RevealedValue::from(half)))
        .unwrap()
        .add_fungible_state("assetOwner", GraphSeal::with_blinded_vout(1u32, 3), half)
        .unwrap()
        .complete_transition()
        .unwrap();
    let burn = history.burn_transition(burned, half, Some(half), Some(gen::burn_reason_for(PAYEE)));
    let bundle = if burn_first {
        vec![burn, transfer]
    } else {
        vec![transfer, burn]
    };
    history.commit(
        bundle,
        vec![kept.outpoint, burned.outpoint],
        vec![gen::dust(3)],
    );
    history
}

/// A burn whose bundle commits a transition the consignment does not show.
fn burn_with_hidden_transition() -> History {
    let (mut history, units) = minted();
    let burn = history.burn_transition(units, MINTED, Some(MINTED), None);
    let mut bundle = gen::bundle_of(vec![burn]);
    let hidden = rgbstd::Opout::new(rgbstd::OpId::from([0x99; 32]), schemata::OS_MINT, 0);
    bundle
        .input_map
        .insert(hidden, rgbstd::OpId::from([0x98; 32]))
        .unwrap();
    history.commit_bundle(bundle, vec![units.outpoint], vec![gen::dust(5)]);
    history
}

/// Rights sent on, then a mint on one of them and a burn of the units.
fn burn_after_rights_send() -> History {
    let mut history = issue();
    let right = history.genesis_right(0, right_utxo());
    let rights = history.duplicate_right(right, 3);
    let units = history.mint_owned(rights[2], MINTED, 90);
    history.burn(
        units,
        MINTED,
        Some(MINTED),
        Some(gen::burn_reason_for(PAYEE)),
    );
    history
}

/// The rights refill a mint wallet sends: one right to several vouts, with a
/// fee input.
fn rights_refill() -> History {
    let mut history = issue();
    let right = history.genesis_right(0, right_utxo());
    history.send_rights(
        right,
        &[1, 2, 3],
        vec![gen::outpoint(0xF1, 0)],
        vec![gen::dust(1), gen::dust(2), gen::dust(3)],
    );
    history
}

/// One right in, twenty out, in one propagate.
fn wide_rights_propagate() -> History {
    let mut history = issue();
    let right = history.genesis_right(0, right_utxo());
    let vouts: Vec<u32> = (1..=20).collect();
    let outputs = vouts.iter().map(|_| gen::dust(6)).collect();
    history.send_rights(right, &vouts, vec![], outputs);
    history
}

/// A refill, a mint on one of its rights, then a burn with change.
fn split_burn_after_refill() -> History {
    let mut history = issue();
    let right = history.genesis_right(0, right_utxo());
    let refill = history.send_rights(
        right,
        &[1, 2],
        vec![gen::outpoint(0xF1, 0)],
        vec![gen::dust(1), gen::dust(2)],
    );
    let rights = gen::rights_made(&refill, &[1, 2]);
    let units = history.mint_owned(rights[1], MINTED, 90);
    history.burn(
        units,
        MINTED,
        Some(MINTED / 3),
        Some(gen::burn_reason_for(PAYEE)),
    );
    history
}

fn link_utxo() -> OutPoint {
    gen::outpoint(0xAB, 0)
}

/// An asset whose genesis also holds a link right.
fn issue_with_link() -> History {
    History::issue(Issue {
        link_right: Some(link_utxo()),
        ..Issue::new(EVM_CHAIN_ID, BRIDGE, vec![right_utxo()])
    })
}

/// A transition of `name` that spends the genesis link right.
fn spending_the_link(history: &mut History, name: &'static str) -> TransitionBuilder {
    let link = rgbstd::Opout::new(history.genesis.id(), schemata::OS_LINK, 0);
    history
        .transition(name)
        .add_input(link, AllocatedState::Void)
        .unwrap()
}

/// The link right moved on to vout 1 of its witness.
fn link_right_transfer() -> History {
    let mut history = issue_with_link();
    let moved = spending_the_link(&mut history, "transferLink")
        .add_rights("linkRight", GraphSeal::with_blinded_vout(1u32, 0x61))
        .unwrap()
        .complete_transition()
        .unwrap();
    history.commit(vec![moved], vec![link_utxo()], vec![gen::dust(1)]);
    history
}

/// The link right spent to name the contract this asset links to.
fn link_to_another_contract() -> History {
    let mut history = issue_with_link();
    let link = spending_the_link(&mut history, "link")
        .add_global_state("linkedToContract", ContractId::from([0x77; 32]))
        .unwrap()
        .complete_transition()
        .unwrap();
    history.commit(vec![link], vec![link_utxo()], vec![gen::dust(2)]);
    history
}

/// A mint, then a burn of its units that also spends the link right.
fn burn_with_the_link_right() -> History {
    let mut history = issue_with_link();
    let right = history.genesis_right(0, right_utxo());
    let units = history.mint_owned(right, MINTED, 90);
    let burn = spending_the_link(&mut history, "burn")
        .add_input(
            units.opout,
            AllocatedState::from(RevealedValue::from(MINTED)),
        )
        .unwrap()
        .add_global_state("burnedAsset", rgbstd::Amount::from(MINTED))
        .unwrap()
        .complete_transition()
        .unwrap();
    let inputs = vec![units.outpoint, link_utxo()];
    history.commit(vec![burn], inputs, vec![gen::dust(3)]);
    history
}

/// Every shape, by name, as TFR bytes.
fn generated_shapes() -> Vec<(String, Vec<u8>)> {
    let mut shapes: Vec<(String, Vec<u8>)> = vec![
        ("genesis only".into(), issue().consignment()),
        ("mint, then split and burn with change".into(), burn_bytes()),
    ];
    let mut push = |name: &str, history: History| {
        shapes.push((name.to_string(), history.consignment()));
    };
    push(
        "burn of everything",
        burn_history(Some(MINTED), Some(gen::burn_reason_for(PAYEE))).0,
    );
    push(
        "burn without burnReason",
        burn_history(Some(MINTED), None).0,
    );
    push(
        "burn beside a transfer, burn first",
        burn_beside_transfer(true),
    );
    push(
        "burn beside a transfer, transfer first",
        burn_beside_transfer(false),
    );
    push("split in halves", minted_in_halves().0);
    push(
        "hidden transition in the last bundle",
        burn_with_hidden_transition(),
    );
    push("burn after a rights send", burn_after_rights_send());
    push("rights refill", rights_refill());
    push("wide rights propagate", wide_rights_propagate());
    push("split burn after a refill", split_burn_after_refill());
    push("listed asset burn", listed_burn().0);
    push("link right transfer", link_right_transfer());
    push("link to another contract", link_to_another_contract());
    push("burn with the link right", burn_with_the_link_right());
    for chain_net in [
        ChainNet::BitcoinRegtest,
        ChainNet::BitcoinMainnet,
        ChainNet::BitcoinTestnet4,
        ChainNet::BitcoinSignet,
    ] {
        let to = concealed_seal(0xC0);
        let name = format!("mint to a blinded seal on {}", chain_net.prefix());
        push(&name, mint_to(chain_net, to));
    }
    let to = explicit_seal(0xC1, 3);
    push(
        "mint to an explicit seal",
        mint_to(ChainNet::BitcoinRegtest, to),
    );
    let to = BuilderSeal::from(GraphSeal::with_blinded_vout(1u32, 0x52));
    push(
        "mint to a witness seal",
        mint_to(ChainNet::BitcoinRegtest, to),
    );
    for (name, recipient) in [
        ("send to a blinded invoice", concealed_seal(0xC2)),
        ("send to an explicit seal", explicit_seal(0xC3, 1)),
    ] {
        let (mut history, units) = minted();
        let units = history.transfer(units, MINTED);
        send_to_invoice(&mut history, units, recipient);
        push(name, history);
    }
    shapes
}

fn reference_of(bytes: &[u8]) -> Summary {
    reference_summary(&Transfer::load(std::io::Cursor::new(bytes)).unwrap())
}

/// The summary validation reads: rgb-lib's inspection of the file.
pub(super) fn inspected(bytes: &[u8]) -> Result<Summary> {
    with_scratch_file(bytes, |path| {
        extract_transition_summary(path.to_str().unwrap())
    })
}

/// The bridge's reading of the same fields with consignment-utils.
fn bridge_summary(bytes: &[u8]) -> Summary {
    let ConsignmentInfo::Transfer(info) = rgb_consignment::parse(bytes).unwrap() else {
        panic!("a transfer");
    };
    let display = |hex: &str| -> [u8; 32] { hex::decode(hex).unwrap().try_into().unwrap() };
    info.witnesses
        .iter()
        .map(|w| {
            let txid = w.txid.parse::<bitcoin::Txid>().unwrap();
            let summaries = w
                .transitions
                .iter()
                .map(|t| {
                    let outputs: Vec<TransitionOutput> = t
                        .fungible_allocations
                        .iter()
                        .filter(|a| a.assignment_type == schemata::OS_ASSET.to_inner())
                        .flat_map(|a| a.entries.iter())
                        .map(|e| TransitionOutput {
                            assignment_type: schemata::OS_ASSET.to_inner(),
                            amount: e.amount,
                            seal: match &e.seal {
                                SealInfo::Revealed { txid, vout } => OutputSeal::Revealed {
                                    txid: txid.as_deref().map(display),
                                    vout: *vout,
                                },
                                SealInfo::Confidential { secret_seal } => {
                                    OutputSeal::Confidential {
                                        secret_seal: secret_seal.clone(),
                                    }
                                }
                            },
                        })
                        .collect();
                    let total = outputs.iter().map(|o| o.amount).sum();
                    TransitionSummary {
                        op_id: t.op_id.clone(),
                        transition_type: t.transition_type,
                        total_output_amount: total,
                        asset_output_amount: total,
                        outputs,
                        burned_asset_amount: None,
                        burn_reason: None,
                    }
                })
                .collect();
            (txid, summaries)
        })
        .collect()
}

/// The inspected summary equals the rgbstd reading on every shape.
#[test]
fn the_summary_matches_the_rgbstd_reading_on_every_generated_shape() {
    for (name, bytes) in generated_shapes() {
        assert_eq!(inspected(&bytes).unwrap(), reference_of(&bytes), "{name}");
    }
}

/// The bridge reads the same summary from every shape as the enclave.
#[test]
fn the_bridge_parser_reads_the_same_summary_on_every_generated_shape() {
    for (name, bytes) in generated_shapes() {
        assert_eq!(bridge_summary(&bytes), inspected(&bytes).unwrap(), "{name}");
    }
}

/// The shapes cover every seal kind and every BFA transition type, so the
/// tests above compare each mapping rule.
#[test]
fn the_generated_shapes_cover_every_seal_kind_and_transition_type() {
    let all: Vec<TransitionSummary> = generated_shapes()
        .iter()
        .flat_map(|(_, bytes)| reference_of(bytes))
        .flat_map(|(_, summaries)| summaries)
        .collect();
    let seals: Vec<&OutputSeal> = all
        .iter()
        .flat_map(|t| &t.outputs)
        .map(|o| &o.seal)
        .collect();
    assert!(seals
        .iter()
        .any(|s| matches!(s, OutputSeal::Confidential { .. })));
    assert!(seals
        .iter()
        .any(|s| matches!(s, OutputSeal::Revealed { txid: None, .. })));
    assert!(seals
        .iter()
        .any(|s| matches!(s, OutputSeal::Revealed { txid: Some(_), .. })));
    for ty in [
        schemata::TS_MINT,
        schemata::TS_BURN,
        schemata::TS_TRANSFER,
        schemata::TS_PROPAGATE,
        schemata::TS_LINK,
        schemata::TS_TRANSFER_LINK,
    ] {
        assert!(
            all.iter().any(|t| t.transition_type == ty.to_inner()),
            "{ty}"
        );
    }
    assert!(
        all.iter().any(|t| t.outputs.is_empty()),
        "a rights-only transition"
    );
}
