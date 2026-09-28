# F1: plain-BTC self-pay accepts a host-built script

Severity: Critical. Status: Open. Probe: `plain_btc_refuses_an_output_to_a_tree_the_host_can_spend_alone` in `enclave/tests/test_adversarial.rs`.

A compromised host can make the enclave sign away plain BTC by planting one dust input to a script it built around the enclave's public key. The check that is meant to prove an output stays in bridge custody accepts any script the enclave co-signs, and the host chooses which inputs the enclave co-signs.

## The exploit transaction

```
Input 0: bridge UTXO       100,000 sats, script S_bridge   genuine custody, enclave co-signs
Input 1: planted UTXO       10,000 sats, script S_host     host funded, enclave co-signs
Output 0                   105,000 sats to S_host          accepted as self-owned

S_host = taproot tree the host built
  internal key: NUMS (unspendable)
  leaf A: <host key> CHECKSIG
  leaf B: <our key>  CHECKSIG      (our key derived from the public account xpub)
```

Check 5 (below) finds S_host among the co-signed input scripts, so the output counts as self-owned. The enclave signs both inputs; the host later spends the output via leaf A alone. Input 1 exists only to put S_host on the list of co-signed input scripts; the value comes from input 0.

## Why the rule fails

The spec and the code state two different rules, and the host can drive a transaction through the gap between them.

**What the spec promises** (`docs/tee-spec.md` section 7.3): "every output must pay back into the custody its inputs were already in." It adds that a matching key in one taproot leaf is not treated as proof that the enclave controls an output. That is a statement about value: what came out of a script goes back to that script.

**What the code checks** (`enclave/src/networks/rgb/btc_ownership.rs`): an output is self-owned when its `script_pubkey` equals the `script_pubkey` of any PSBT input for which `find_taproot_sign_jobs` produced a signing job. A job is produced when the input's control block verifies against its output key, the leaf contains a 32-byte key, the PSBT's key-origin map names that key with our master fingerprint and a path that derives to it. That is a statement about membership: the enclave has a key in the tree.

**The gap.** Membership is per input and the host assembles the input list. Nothing ties the output's script to the inputs that carry the value. So the host can satisfy the membership test with one input of its own choosing, then route the value of every other input to that script. The module comment acknowledges that the rule proves "custody is unchanged, not that only we can spend", on the assumption that the custody script is the bridge's own multisig. The assumption fails because the enclave's leaf key is public: `GetPublicKey` and `GetStatus` return `account_xpub_vanilla` (`m/86'/<coin>'/0'`) and `account_xpub_colored`, from which anyone derives every child key. Building a tree around a public key needs no secret.

**Why the earlier fix did not close it.** The previous rule B (an output is ours if any leaf in its tree pushes a key we derive) was removed for exactly this reason: a leaf says nothing about the rest of the tree. The replacement moved the leaf test from the output side to the input side and bridged the two with script equality. The weakness moved with it. The only added cost to the host is funding a dust UTXO.

## Code path

A `SignBtc` request passes eight checks before signing. The exploit transaction satisfies all of them; only step 5 is at fault, and step 8 then signs the planted input with the enclave's own key.

| Step | Where | Check | Exploit transaction |
| --- | --- | --- | --- |
| 1 | `server.rs` `handle_sign_btc` | Production policy has `allow_vanilla_psbt` (set when `BTC_MAX_TOTAL_SATS` is non-zero) | Passes on any deployment that uses SignBtc |
| 2 | `psbt_validation::parse_psbt_shape` | Structural whitelist | Passes: two inputs, one output |
| 3 | `psbt_validation::assert_sighash_all` | Every input's sighash is default or ALL (fixed F10) | Passes: no sighash set |
| 4 | `btc_crosscheck::validate_btc_request` step 1 | Every input carries `witness_utxo`; sum the values | Passes: 110,000 sats |
| 5 | `btc_ownership::self_controlled_input_scripts` | Collect the `script_pubkey` of every input that yields a Vanilla-account signing job | **At fault.** Yields S_bridge and S_host, because input 1 carries a valid control block for a leaf holding our derived key |
| 6 | `btc_crosscheck` step 3 | Sum outputs whose script is not in that set; refuse if over `BTC_MAX_UNOWNED_SATS` | Passes with zero unowned sats |
| 7 | `btc_crosscheck` step 4 | Total input value at most `BTC_MAX_TOTAL_SATS` | Passes: 110,000 at most 1,000,000 in the probe |
| 8 | `state.sign_psbt_scoped(Vanilla)` | Sign every Vanilla-account job | Signs both inputs; `inputs_signed = 2` |

For the planted input, step 5 (`find_taproot_sign_jobs`) walks: `witness_utxo` is P2TR, the control block in `tap_scripts` verifies against the output key, the leaf script pushes a 32-byte key, `tap_key_origins` maps that key to our master fingerprint and to `m/86'/0'/0'/0/0`, the KeyManager derives that path and the key matches, no signature is present yet. Every one of those facts is either public or chosen by the host.

## Prerequisites and reproduction

- Control of the host that feeds the enclave, or of any path that can submit `SignBtc` requests to it. The enclave, its image and its pinned config stay intact.
- Plain-BTC signing enabled in the attested policy, which any deployment that uses `SignBtc` has.
- The enclave's vanilla account xpub, which `GetPublicKey` and `GetStatus` return to any caller.
- A small amount of the host's own BTC for the planted UTXO (10,000 sats in the probe; taproot dust is enough).

Reproduction is the ignored probe:

```
cargo test -p utexo-bridge-enclave --features allow-seed-import --test test_adversarial \
  plain_btc_refuses_an_output_to_a_tree_the_host_can_spend_alone -- --ignored
```

It currently fails with `signed 2 input(s) of a transaction paying 105_000 sats to a script the host can spend alone`. Once the fix lands, remove the `#[ignore]` attribute and the same test becomes the regression guard.

**Loss per transaction.** Up to `BTC_MAX_TOTAL_SATS` minus the planted dust and the fee. Nothing bounds the number of transactions, so the whole vanilla-account balance is reachable in slices.

## Blast radius

Four code paths decide ownership with the same primitive, so the fix has to land in `btc_ownership.rs`, not in the plain-BTC caller alone. Only the first was reproduced over the wire; the send-RGB paths need the real consignment parser and are marked for confirmation in CI.

| Path | Account scope | Call | What a compromised host gains | Bound today |
| --- | --- | --- | --- | --- |
| Plain-BTC `SignBtc` (`btc_crosscheck::validate_btc_request`) | Vanilla | `self_controlled_input_scripts` | BTC from the vanilla account, signed to a script only the host can spend | `BTC_MAX_TOTAL_SATS` per transaction; no bound on count. Reproduced. |
| Send-RGB sats budget (`btc_crosscheck::validate_rgb_psbt_sats`) | Vanilla and Colored | `self_controlled_input_scripts_scoped(None)` | Bitcoin backing in the bridge PSBT's inputs routed to the host script without consuming `RGB_MAX_UNOWNED_SATS` | No per-transaction cap on the send-RGB path; bounded by the inputs the host includes. Needs CI confirmation. |
| Send-RGB change-leg oracle, same transaction (`server.rs` closure, `self_owned_output_indices`) | Vanilla and Colored | `self_owned_output_indices` | A revealed seal on the host script is classed as bridge change instead of a payout; under `rgb-swap` coverage is `>=`, so surplus asset units can be assigned there | Bounded by the asset balance of the UTXOs in the transfer. Needs CI confirmation. |
| Send-RGB change-leg oracle, off-PSBT outpoint (`server.rs` closure, script fetched from the indexer) | Vanilla and Colored | `self_controlled_input_scripts_scoped(None)` | Same as above for a change seal parked on an earlier transaction whose script matches a planted input | Same. Needs CI confirmation. |

The send-RGB paths are an amplifier, not a source: the host still needs a legitimate bridge operation with a verified FundsIn receipt to ride on, and every RGB-unit bind still applies. Plain-BTC needs nothing but the policy flag.

## Fix options compared

| Option | Rule | Closes plain-BTC | Closes RGB sats budget | Closes change-leg oracle | Config | Legitimate flows affected |
| --- | --- | --- | --- | --- | --- | --- |
| A. Per-script value conservation | For every output script S, the sats paid to S may not exceed the sats of co-signed inputs whose script is S. Anything else counts against the unowned budget. | Yes, together with a fee bound (F5), since otherwise the diverted value goes to miners | Yes | No: units are not sats | None | Consolidating several bridge addresses into one; the module doc says the wallet reuses addresses, so likely none |
| B. Pinned tree reconstruction | Pin the co-signer xpubs and the script template. An input or output is ours only when its full taproot tree rebuilds from the pinned keys and our derived key at the claimed path. | Yes | Yes | Yes | Co-signer xpubs and template in env, committed into the attested policy | None once the template matches the wallet's descriptor |
| C. Single custody script per PSBT | Every co-signed input must share one script, and every self-owned output must equal it. | Yes: a mixed PSBT is refused, an all-host PSBT moves only host money | Yes | Yes, for the same-transaction case | None | Any spend across two bridge addresses |

**Why A alone is not enough.** The change-leg oracle answers whether an output is bridge change so that asset units assigned to it are not counted as payout. Sats conservation says nothing about units, so a host script that satisfies A (it funds its own output) still passes as change.

**Why B needs care.** The rejected `BTC_ALLOWED_SCRIPTS` allowlist failed because scripts derive from a seed that exists only after boot. B avoids that: the co-signer xpubs are not seed-derived, our xpub is known after boot, and the script is computed at runtime per path. The open question is the exact descriptor the wallet uses for bridge UTXOs (leaf structure, threshold, internal key), which this review could not read from the code. The checkpoint module describes the signet challenge as a 3-of-3 over federation keys, which suggests the same shape.

## Recommended fix

Ship A and C now as one change, with the fee bound from F5, then replace both with B once the wallet's descriptor is pinned. Both stages keep the current input-side gate (control block, leaf key, derivation) as the signing rule; they change only what counts as a self-owned output.

### Stage 1: conservation and a single custody script (no config)

1. In `btc_ownership.rs`, replace `self_controlled_input_scripts` with a function that returns the co-signed input value per script: a map from `script_pubkey` to summed sats, scoped by account as today.
2. In `btc_crosscheck::validate_btc_request`, for each output script look up that map. Sats up to the input value for that script are self-owned; the excess counts against `BTC_MAX_UNOWNED_SATS`. Add the fee bound from F5 in the same function, so value cannot escape as fee instead.
3. Apply the same rule in `validate_rgb_psbt_sats` with the `None` scope.
4. For the change-leg oracle (`self_owned_output_indices` and the off-PSBT branch of the closure in `server.rs`), require that every co-signed input in the PSBT shares one script and that the candidate output equals it. Refuse with a cross-check error naming the second script when the inputs disagree.
5. Update the rule text in `docs/tee-spec.md` section 7.3 and the `btc_ownership.rs` module comment so they describe the value rule rather than script membership.

### Stage 2: pinned reconstruction

1. Add `BTC_COSIGNER_XPUBS` (comma-separated) and `BTC_CUSTODY_TEMPLATE` (the leaf and threshold shape) to `config.rs`, and commit both into the attested policy in `policy.rs` so a change alters the attestation.
2. In `btc_ownership.rs`, for a candidate input or output with a claimed derivation path, derive our key and each co-signer's key at the same path, build the tree from the template, and compare the resulting `script_pubkey` to the one in the PSBT. Only an exact match is self-owned.
3. Apply the reconstruction on the input side too, so an input whose tree has a leaf the template does not predict is not signed at all.
4. Remove the stage 1 single-script restriction on the oracle; conservation can stay as defence in depth.

**Migration.** Stage 1 needs no operator action. Stage 2 fails closed: a production build with plain-BTC or send-RGB enabled refuses to sign until the xpubs and template are pinned, matching how `BTC_MAX_TOTAL_SATS` already gates the path.

## Test plan

The existing probe becomes the regression guard, and each stage adds its own positive and negative cases beside the code it changes. The send-RGB cases need the real parser, so they run only in the CI lanes with the private crates.

### Un-ignore

- [ ] `plain_btc_refuses_an_output_to_a_tree_the_host_can_spend_alone` in `enclave/tests/test_adversarial.rs`; remove the `#[ignore]` attribute and keep the assertion.

### Stage 1, plain-BTC (wire tests in `test_dispatch.rs`, unit tests in `btc_crosscheck.rs`)

- [ ] Self-pay with change to the same script signs.
- [ ] Two inputs on the same bridge script, one output to it, signs.
- [ ] Output to a script whose co-signed input value is smaller than the output, with no unowned budget, is refused and the error names the script.
- [ ] The same, with `BTC_MAX_UNOWNED_SATS` covering the excess, signs.
- [ ] `create_utxo` dust to a fresh script within the unowned budget signs.
- [ ] Consolidation from two bridge scripts into one is refused (document this as intended, or switch to stage 2 if it must work).
- [ ] Fee above the new bound is refused (F5).

### Stage 1, send-RGB (unit tests in `btc_ownership.rs`, wire tests gated on `rgb-validation`)

- [ ] A revealed change seal on an output whose script matches every co-signed input is accepted as change.
- [ ] A PSBT with a planted colored-leaf input to a second script is refused before the oracle answers, and the error names both scripts.
- [ ] Off-PSBT change outpoint whose fetched script matches a planted input is refused.
- [ ] `validate_rgb_psbt_sats` counts sats above the per-script input value against `RGB_MAX_UNOWNED_SATS`.

### Stage 2, reconstruction

- [ ] Output to the script rebuilt from pinned co-signer xpubs and our key at the claimed path is self-owned.
- [ ] Same tree with one co-signer key replaced is not.
- [ ] Same tree with an extra leaf is not.
- [ ] Same keys with a different threshold or internal key is not.
- [ ] An input whose tree does not rebuild is not signed; the response reports zero inputs signed and the production guard refuses.
- [ ] Unset `BTC_COSIGNER_XPUBS` in a production build refuses plain-BTC and send-RGB signing.
- [ ] Policy commitment changes when the xpubs or template change (extend the `policy.rs` invariant tests).

## Status against pull request 240

Not reproducible on `audit_fixes` (head `acdde48`, pull request 240 into `dev`). The probe above, copied unchanged and run against that head in the `ccd` + `allow-seed-import` lane with `btc_max_unowned_sats` pinned to 1,000, is refused:

```
cross-check failed: plain-BTC PSBT pays 105000 sats to outputs the enclave cannot prove
pay back into the same custody, over the pinned budget of 1000 sats - refusing to sign.
```

That branch rewrites `btc_ownership.rs` around three rules that correspond to options A, C and a partial B above:

- An input is ours only when it is a BIP-86 key-path spend: the claimed internal key derives from our seed at the claimed path and, tweaked with `tap_merkle_root`, reproduces the output key. Script-path inputs are never ours (`find_controlled_taproot_inputs`).
- An output on a co-signed input script is exempt only up to the input value on that script (`unowned_output_sats`).
- An output is fully ours when its claimed internal key derives from our seed and it carries no script tree (`output_is_self_derived`).
- The asset change oracle accepts exactly one Colored input script (`asset_change_scripts`).

The exposure that branch documents itself, a planted input whose internal key is ours but whose tree carries a foreign leaf, is bounded per transaction by `BTC_MAX_UNOWNED_SATS`, which is 0 unless the operator pins it for allocation dust. The analysis in this document describes the code on `dev` and on `claude/gallant-pascal-snk3xu`, which pull request 240 has not merged into yet.

Other probes from this branch against the same head, same lane: F5 (fee burn) and F9 (seed plus mnemonic accepted) still reproduce; F4 (replay-guard flood) and F6 (gas-tx count) still reproduce; F10 (sighash) is closed there by the signer refusing anything but DEFAULT or ALL. F2, F3, F7 and F8 are feature-gated out of that lane; by code reading, that branch still skips work on signet, still accepts any 32-byte CCD hash, still ignores high Merkle position bits, and keys its replay guard only on the EVM-to-RGB direction.
