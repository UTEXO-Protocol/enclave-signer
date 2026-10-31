use bitcoin::bip32::ChildNumber;
use bitcoin::psbt::Psbt;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut};

use super::*;
use crate::config::BridgeConfig;
use crate::error::EnclaveError;
use crate::keys::{AccountType, KeyManager};
use crate::networks::rgb::btc_ownership::tests as fx;
use crate::proto::enclave_response::Response;
use crate::state::{EnclaveState, MAX_REFILLS_PER_HOUR};
use crate::test_support::bfa_consignment::{self as gen, Committed, History, Issue, Utxo};

/// The seed of `fx::km()`, so the fixtures derive the enclave's keys.
const SEED: [u8; 64] = [0x42; 64];
const RIGHT_SATS: u64 = 1_000;
const FEE: u64 = 1_000;
const FEE_INPUT_SATS: u64 = 10_000;
const CHANGE_SATS: u64 = 2_000;

fn normal(i: u32) -> ChildNumber {
    ChildNumber::from_normal_idx(i).unwrap()
}

/// How a test refill is built.
struct Shape {
    rights: u32,
    /// The fee the right's UTXO pays on top of the rights.
    fee: u64,
    /// BTC change from the right's own UTXO, on the last output.
    change: bool,
    /// One Colored fee input, paid back as change on the last output.
    fee_input: bool,
    /// Where the right on vout 1 goes.
    first_right: (AccountType, Vec<ChildNumber>),
}

impl Shape {
    fn rights(rights: u32) -> Self {
        Self {
            rights,
            fee: FEE,
            change: false,
            fee_input: false,
            first_right: (AccountType::Colored, vec![normal(0), normal(1)]),
        }
    }
}

/// Where each output of `shape` goes: the rights on vouts 1..=k, then change.
fn destinations(shape: &Shape) -> Vec<(AccountType, Vec<ChildNumber>)> {
    let mut all = vec![shape.first_right.clone()];
    all.extend((2..=shape.rights).map(|i| (AccountType::Colored, vec![normal(0), normal(i)])));
    if shape.change || shape.fee_input {
        all.push((AccountType::Colored, vec![normal(0), normal(99)]));
    }
    all
}

/// The change output's value: the right's extra sats and the fee input.
fn change_value(shape: &Shape) -> u64 {
    let from_right = if shape.change { CHANGE_SATS } else { 0 };
    let from_fee_input = if shape.fee_input { FEE_INPUT_SATS } else { 0 };
    from_right + from_fee_input
}

/// The sats on output `i` of the destinations: a right's, then the change's.
fn output_sats(shape: &Shape, i: usize) -> u64 {
    if i < shape.rights as usize {
        RIGHT_SATS
    } else {
        change_value(shape)
    }
}

/// Our key-path output at `child` below `account`.
fn output_to(
    keys: &KeyManager,
    (account, child): &(AccountType, Vec<ChildNumber>),
    sats: u64,
) -> TxOut {
    let (key, _) = fx::our_key_at(keys, *account, child);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    TxOut {
        value: Amount::from_sat(sats),
        script_pubkey: ScriptBuf::new_p2tr(&secp, key, None),
    }
}

/// An asset whose genesis right the issuer seeds to our right on vout 1.
/// Returns the seed, the right's parent, and that right.
fn seeded(keys: &KeyManager) -> (History, Committed, Utxo) {
    let genesis_right = gen::outpoint(0xA0, 0);
    let mut history = History::issue(Issue::new(42161, [0xB1; 20], vec![genesis_right]));
    let right = history.genesis_right(0, genesis_right);
    let seeded_to = output_to(
        keys,
        &(AccountType::Colored, vec![normal(0), normal(0)]),
        3_000,
    );
    let seed = history.send_rights(right, &[1], vec![], vec![seeded_to]);
    let seeded = gen::rights_made(&seed, &[1])[0];
    (history, seed, seeded)
}

/// A seeded right sent as `shape` says: that send, and its parent.
fn build(keys: &KeyManager, shape: &Shape) -> (History, Committed, Committed) {
    let (mut history, seed, right) = seeded(keys);
    let refill = send(&mut history, right, keys, shape);
    (history, refill, seed)
}

/// Sends `right` as `shape` says, with the PSBT metadata rgb-lib writes.
fn send(history: &mut History, right: Utxo, keys: &KeyManager, shape: &Shape) -> Committed {
    let destinations = destinations(shape);
    let outputs = destinations
        .iter()
        .enumerate()
        .map(|(i, to)| output_to(keys, to, output_sats(shape, i)))
        .collect();
    let fee_inputs: Vec<OutPoint> = shape
        .fee_input
        .then(|| gen::outpoint(0xF1, 0))
        .into_iter()
        .collect();
    let vouts: Vec<u32> = (1..=shape.rights).collect();
    let mut sent = history.send_rights(right, &vouts, fee_inputs, outputs);
    sent.psbt = with_metadata(keys, shape, sent.psbt, &destinations);
    sent
}

/// `psbt` with the input and output metadata rgb-lib writes.
fn with_metadata(
    keys: &KeyManager,
    shape: &Shape,
    mut psbt: Psbt,
    destinations: &[(AccountType, Vec<ChildNumber>)],
) -> Psbt {
    let right_change = if shape.change { CHANGE_SATS } else { 0 };
    let right_value = RIGHT_SATS * u64::from(shape.rights) + shape.fee + right_change;
    fx::anchor_input(&mut psbt, 0, keys, AccountType::Colored, 0, 0, right_value);
    if shape.fee_input {
        fx::anchor_input(
            &mut psbt,
            1,
            keys,
            AccountType::Colored,
            0,
            100,
            FEE_INPUT_SATS,
        );
    }
    for (i, (account, child)) in destinations.iter().enumerate() {
        fx::claim_output(&mut psbt, i + 1, keys, *account, child);
    }
    psbt
}

fn request(history: &History, refill: &Committed, parent: &Committed) -> SignRightsRefillRequest {
    SignRightsRefillRequest {
        psbt_bytes: refill.psbt.serialize(),
        asset_id: history.contract_id.to_string(),
        fascia: refill.fascia_bytes(),
        parent_fascia: parent.fascia_bytes(),
    }
}

/// A mint signer with the fixture keys, pinned to `asset_id`. No endpoint is
/// set: a refill reads no network.
fn context(asset_id: &str) -> ServerContext {
    let state = EnclaveState::new(Network::Testnet);
    state.initialize_from_seed(SEED).unwrap();
    let config = BridgeConfig {
        rgb_asset_id: asset_id.into(),
        ..BridgeConfig::default()
    };
    ServerContext::new(state, config, crate::test_support::regtest_header_chain())
}

fn sign(ctx: &ServerContext, req: SignRightsRefillRequest) -> Result<EnclaveResponse> {
    handle_sign_rights_refill(ctx, req)
}

/// Signs the refill of `shape` and checks every input carries our signature.
fn signs(shape: Shape) {
    let keys = fx::km();
    let (history, refill, seed) = build(&keys, &shape);
    let ctx = context(&history.contract_id.to_string());
    let response = sign(&ctx, request(&history, &refill, &seed)).unwrap();
    let Some(Response::SignedPsbt(signed)) = response.response else {
        panic!("expected a signed PSBT, got {response:?}");
    };
    let signed_psbt = Psbt::deserialize(&signed.signed_psbt).unwrap();
    assert_eq!(signed.inputs_signed as usize, signed_psbt.inputs.len());
    for i in 0..signed_psbt.inputs.len() {
        fx::verify_own_signature(&signed_psbt, i).unwrap();
    }
}

fn refusal(shape: Shape) -> String {
    let keys = fx::km();
    let (history, refill, seed) = build(&keys, &shape);
    let ctx = context(&history.contract_id.to_string());
    sign(&ctx, request(&history, &refill, &seed))
        .unwrap_err()
        .to_string()
}

#[test]
fn signs_one_right_sent_to_two_and_to_three() {
    signs(Shape::rights(2));
    signs(Shape::rights(3));
}

/// The largest refill carries the largest fascia the mint signer reads. Its
/// 255 outputs are about 11 100 vB, so it pays 12 000 sat for 1 sat/vB.
#[test]
fn signs_a_refill_of_max_refill_rights() {
    signs(Shape {
        fee: 12_000,
        ..Shape::rights(psbt_validation::MAX_REFILL_RIGHTS as u32)
    });
}

#[test]
fn signs_a_refill_with_btc_change() {
    signs(Shape {
        change: true,
        ..Shape::rights(2)
    });
}

#[test]
fn signs_a_refill_with_one_unclosed_fee_input() {
    signs(Shape {
        fee_input: true,
        ..Shape::rights(3)
    });
}

/// Rule C holds on either account, so only RR9 stops this one.
#[test]
fn refuses_a_right_on_a_vanilla_output() {
    let err = refusal(Shape {
        first_right: (AccountType::Vanilla, vec![normal(0), normal(1)]),
        ..Shape::rights(2)
    });
    assert!(err.contains("not a Colored key-path output"), "{err}");
}

/// Rule C refuses these paths, so the sats gate refuses first.
#[test]
fn refuses_a_right_on_a_colored_key_rgb_lib_never_scans() {
    let hardened = ChildNumber::from_hardened_idx(1).unwrap();
    for child in [
        vec![normal(0), hardened],
        vec![normal(0), normal(1), normal(0)],
    ] {
        let err = refusal(Shape {
            first_right: (AccountType::Colored, child),
            ..Shape::rights(2)
        });
        assert!(err.contains("this enclave does not derive"), "{err}");
    }
}

/// PP4: a right an old-form mint passed on has a mint for its parent.
#[test]
fn refuses_a_right_a_mint_passed_on() {
    let keys = fx::km();
    let (mut history, _, right) = seeded(&keys);
    let to = rgbstd::BuilderSeal::from(rgbstd::GraphSeal::with_blinded_vout(2u32, 7));
    let outputs = vec![gen::dust(1), gen::dust(2)];
    let (mint, kept) = history.mint_keeping_right(right, 100_000, 90, to, vec![], outputs);
    let refill = send(&mut history, kept, &keys, &Shape::rights(2));
    let ctx = context(&history.contract_id.to_string());
    let err = sign(&ctx, request(&history, &refill, &mint)).unwrap_err();
    assert!(err.to_string().contains("not a propagate"), "{err}");
}

#[test]
fn refuses_a_refill_without_its_parent_fascia() {
    let keys = fx::km();
    let (history, refill, seed) = build(&keys, &Shape::rights(2));
    let ctx = context(&history.contract_id.to_string());
    let mut req = request(&history, &refill, &seed);
    req.parent_fascia.clear();
    let err = sign(&ctx, req).unwrap_err();
    assert!(err.to_string().contains("parent_fascia required"), "{err}");
}

/// rgb-lib strips the refill's PSBT, so without its fascia it shows nothing.
#[test]
fn refuses_a_refill_without_its_fascia() {
    let keys = fx::km();
    let (history, refill, seed) = build(&keys, &Shape::rights(2));
    let ctx = context(&history.contract_id.to_string());
    let mut req = request(&history, &refill, &seed);
    req.fascia.clear();
    let err = sign(&ctx, req).unwrap_err().to_string();
    assert!(err.contains("fascia required"), "{err}");
    assert!(!err.contains("parent_fascia"), "{err}");
}

/// The fascia of the parent, not of the refill's tx: refused, unsigned.
#[test]
fn refuses_a_refill_whose_fascia_is_of_another_tx() {
    let keys = fx::km();
    let (history, refill, seed) = build(&keys, &Shape::rights(2));
    let ctx = context(&history.contract_id.to_string());
    let req = SignRightsRefillRequest {
        fascia: seed.fascia_bytes(),
        ..request(&history, &refill, &seed)
    };
    let err = sign(&ctx, req).unwrap_err();
    assert!(err.to_string().contains("fascia is of tx"), "{err}");
}

#[test]
fn refuses_the_thirteenth_refill_in_an_hour() {
    let keys = fx::km();
    let (history, refill, seed) = build(&keys, &Shape::rights(2));
    let ctx = context(&history.contract_id.to_string());
    for _ in 0..MAX_REFILLS_PER_HOUR {
        sign(&ctx, request(&history, &refill, &seed)).unwrap();
    }
    let err = sign(&ctx, request(&history, &refill, &seed)).unwrap_err();
    assert!(err.to_string().contains("rate limit"), "{err}");
}

/// A request the gate refuses costs nothing, so it uses no slot.
#[test]
fn a_gate_refusal_does_not_count_against_the_rate_limit() {
    let keys = fx::km();
    let (history, refill, seed) = build(&keys, &Shape::rights(2));
    let ctx = context(&history.contract_id.to_string());
    let mut junk = refill.clone();
    junk.psbt.unsigned_tx.output[1].script_pubkey = fx::foreign_address(0xB1);
    for _ in 0..MAX_REFILLS_PER_HOUR + 1 {
        let err = sign(&ctx, request(&history, &junk, &seed)).unwrap_err();
        assert!(err.to_string().contains("does not derive"), "{err}");
    }
    for _ in 0..MAX_REFILLS_PER_HOUR {
        sign(&ctx, request(&history, &refill, &seed)).unwrap();
    }
}

/// A refusal of the RGB data comes after the gate, so it counts.
#[test]
fn a_refusal_past_the_gate_counts_against_the_rate_limit() {
    let keys = fx::km();
    let (history, refill, seed) = build(&keys, &Shape::rights(2));
    let other = History::issue(Issue::new(1, [0xB9; 20], vec![gen::outpoint(0xA9, 0)]));
    let ctx = context(&other.contract_id.to_string());
    for _ in 0..MAX_REFILLS_PER_HOUR {
        let err = sign(&ctx, request(&history, &refill, &seed)).unwrap_err();
        assert!(err.to_string().contains("not of the pinned"), "{err}");
    }
    let err = sign(&ctx, request(&history, &refill, &seed)).unwrap_err();
    assert!(err.to_string().contains("rate limit"), "{err}");
}

#[test]
fn refuses_before_any_check_while_the_key_is_not_ready() {
    let keys = fx::km();
    let (history, refill, seed) = build(&keys, &Shape::rights(2));
    let mut ctx = context(&history.contract_id.to_string());
    ctx.state = EnclaveState::new(Network::Testnet);
    let err = sign(&ctx, request(&history, &refill, &seed)).unwrap_err();
    assert!(matches!(err, EnclaveError::KeyNotInitialized), "{err}");
}
