# Burn flow (RGB -> EVM)

**Signer image:** `burn-signer` (`--no-default-features --features vsock,rgb,burn-signer`).
**Checked against repository code:** 2026-10-29 (rgb-lib f3975623 move, burns
validated by rgb-lib's `validate_consignment_with_resolver`); B2.2 and section
10 on 2026-10-30 (rgb-lib 1ae1c160: no DAG cap, opouts and genesis hashes in
the time budget).
Deployment was not checked.

This document tells how the burn signer checks and signs a release. The
[spec](tee-spec.md) describes the rules and known limits. If the code and this
document differ, investigate the difference. Either can contain an error.

## 1. What the burn flow does

1. The user burns RGB units on Bitcoin.
2. The burn records how many units it destroys (`burnedAsset`) and which
   destination gets the tokens (`burnReason`: an EVM address, or the hash of a
   destination record, see [burn-destination.md](burn-destination.md)). A
   burn has no outputs: rgb-lib first splits the units in a transfer of the
   same bundle, which keeps the change, and the burn destroys the split's
   other output.
3. The burn signer checks the burn.
4. The burn signer signs an EIP-712 release for `MultisigProxy`.
5. `MultisigProxy` needs M of N such signatures. Then the Bridge contract
   releases the tokens to the user.

The burn signer signs nothing on Bitcoin.

## 2. Who does what

| Part | Where | Trusted for | Job |
|------|-------|-------------|-----|
| User | Bitcoin | - | Burns RGB units. |
| Backend and listener | Operator servers | Nothing | Build the `fundsOut` calldata. Send the request. |
| Parent | EC2 host | Nothing | Moves bytes. Sends Bitcoin headers to the enclave. |
| Burn signer | Nitro Enclave | Checks and keys | Checks the burn. Signs the release and the gas transaction. |
| `MultisigProxy` and Bridge | EVM | Quorum and replay | Count signatures. Use the nonce. Check `burnId` again. |

The burn signer checks request claims before it signs. It derives the burn
amount from the consignment. It reads no Bitcoin indexer, and reads the EVM
RPC only for an asset whose genesis names a reject list (Stage 3b): the
deposits behind the burn are derived, and the witnesses are checked on chain against
the enclave's own header chain. One call of rgb-lib's
`validate_consignment_with_resolver` runs RGB consensus. It takes each witness
transaction from the consignment, but the enclave's resolver treats it as mined
only if a Merkle proof in the request places it at least
`SPV_MIN_CONFIRMATIONS` deep in that chain. An unmined witness anywhere in the
history fails consensus. So two conflicting
off-chain transfers of the same units cannot both back a burn: only one of
them can be mined.

On mainnet and testnet4, SPV checks witness inclusion against the enclave
header chain with proof of work. On testnet4, min-difficulty blocks count as
confirmations and freshness, for testing convenience: testnets carry no
production value. Signet and regtest do not enforce proof of work. See
[Bitcoin network limits](tee-spec.md#8-rgb--bitcoin--spv-verification).

## 3. Sequence

```mermaid
sequenceDiagram
    participant U as User
    participant BT as Bitcoin
    participant L as Listener
    participant P as Parent (untrusted)
    participant E as Burn signer (enclave)
    participant C as MultisigProxy + Bridge (EVM)

    U->>BT: burn transaction
    loop every 10 s
        P->>E: SubmitHeaders (own header sync)
    end
    L->>P: Sign(RgbSource -> EvmDestination)
    P->>E: forward over vsock
    E->>E: Stage 1: payload caps
    E->>E: Stage 2: work caps, then rgb-lib consensus: mint anchors bound to<br/>derived deposits, each witness mined per its SPV proof, reject list
    E->>E: Stage 3: SPV freshness, proof coverage, block pins
    E->>E: Stage 4: decode and check calldata
    E->>E: Stage 5: bind release to burn
    E->>E: Stage 6: EIP-712 digest, sign
    E-->>P: signature + calldata (unchanged)
    P-->>L: signature
    L->>P: Sign(EVM_GAS_TX)
    P->>E: SignRawDigest
    E-->>L: gas transaction signature
    L->>L: assemble signed gas transaction
    L->>C: send transaction with M of N signatures
    C-->>U: tokens released
```

## 4. Key values

| Name | Value | Meaning |
|------|-------|---------|
| `TS_BURN` | 8010 | Burn transition. The only settling transition the burn signer accepts. |
| `TS_MINT` | 8013 | Mint transition. It shows in the burn's history (the ancestry). |
| `GS_BURNED_ASSET` | 2015 | Burn global: the number of units destroyed (u64). Required. |
| `GS_REJECT_LIST` | 3010 | Genesis global: where the reject list is. The enclave reads only an `IRgbRejectList` contract on `EVM_CHAIN_ID` (B3.7). |
| `GS_BURN_REASON` | 3009 | Burn global: 32 bytes. A left-padded EVM address (V0), or the hash of a destination record (V1). See [burn-destination.md](burn-destination.md). Required. |
| `RGB_CHAIN_ID` | 827166 | The bridge's id for the RGB network. Compiled in. |
| `SPV_MIN_CONFIRMATIONS` | 6 (default) | Minimum depth of each Bitcoin transaction. Image env, attested. Zero stops the boot. |
| `SPV_MAX_TIP_AGE_SECS` | 7200 | Maximum age of the header-chain tip. |
| `SPV_MAX_TIP_FUTURE_SECS` | 7200 | Maximum time the tip can be in the future. |
| `MAX_RELAY_TIP_LAG_BLOCKS` | 100 | Maximum distance from the BtcRelay tip to the enclave tip. |
| `fundsOut` selector | `0x340276aa` | Pools route. |
| `lzFundsOut` selector | from the enclave ABI | LayerZero route. |
| Calldata cap | 96 KiB | Maximum calldata size. |
| EIP-712 domain | `("MultisigProxy", "1", chainId, verifyingContract)` | Tests compare it with contract fixtures. |

## 5. Checks, in order

If one check fails, the burn signer stops. It signs nothing. It returns an
error.

### Stage 0 - Can this enclave do this request?

- **B0.1** The endpoints must be set (`SetEndpoints`).
- **B0.2** The source must be RGB and the destination must be EVM. The burn
  signer refuses a mint request.

The enclave must be `Active`, but no check runs here. Signing (Stage 6) is
the first step that reads the keys. It refuses an enclave without keys.

### Stage 1 - Is the request within the caps?

- **B1.1** The consignment must not be larger than `MAX_CONSIGNMENT_BYTES`
  (default 12 MiB).
- **B1.2** Proof count must be at most `MAX_MERKLE_PROOFS` (default 16384).
  Proof bytes must be at most `MAX_TOTAL_PROOF_BYTES` (default 8 MiB).
- **B1.3** `keccak256(consignment)` must equal `consignment_hash`. This check
  finds a damaged copy only. It is not a safety proof.

### Stage 2 - Is the RGB history valid, and is each mint backed?

- **B2.1** The bytes must be a V1 transfer file (`TFR`). The genesis schema
  must be BFA. If the genesis names a reject list (`GS_REJECT_LIST`), it must
  be an EVM contract; a URL list is refused.
- **B2.2** Before rgb-lib runs, the contract id must pass the asset bind
  (B2.7), so a foreign genesis never reaches rgb-lib, and no foreign contract
  is ever read as its list. Then the enclave bounds rgb-lib's work on the
  parsed transfer (`validation/cost.rs`). In phase 1, before any witness is
  checked, rgb-lib checks each transition of every BFA against the whole
  witness tx, anchor and input map of its bundle. So the sum over bundles of
  transitions x (tx bytes + Tapret partner leaf bytes) plus seals x tx inputs
  must be at most `MAX_WITNESS_CHECK_COST`, and the sum over bundles of
  (transitions + 1) x input map entries at most `MAX_BUNDLE_ID_COST`. The
  operations DAG rgb-lib builds in the same pass costs one step per spent
  opout since rgb-consensus af0b751d, so it has no cap of its own: the time
  budget covers it. Each opout costs rgb-lib far more than its bytes, since it
  hashes every opout into its operation id more than once, so the budget
  counts opouts on their own. It also hashes every genesis global and
  assignment into the contract id once per operation (`validate_state`), so
  the budget counts those leaves times the operations. If the genesis names a
  reject list, the enclave also
  counts rgb-lib's reject walk (B3.10), one walk per origin with no list entry
  to cut it short, which must be at most `MAX_REJECT_WALK_COST`. Once
  validation passed, rgb-lib's inspection reads the summary from the same file
  (B2.8): it reads the file again, hashes every operation id three times more
  and each witness tx once per transition. The caps add up on top of the
  file's own cost, so the modeled rgb-lib time of validation (the file bytes,
  its opouts, the genesis hashes and the three costs) and of the inspection
  (the file bytes, its opouts, its operations and the witness checks) together
  must be at most `MAX_RGB_LIB_NS` (18 s). The caps and the timings behind
  them are in [Work caps](#10-work-caps).
- **B2.3** One call of rgb-lib's `validate_consignment_with_resolver` runs
  consensus phase 1 over the whole history under the BFA rules from
  `rgb-schemas`, then phase 2 through three resolvers of the enclave: the
  witness resolver (B2.9), the anchor resolver (B2.4, B2.5) and the reject-list
  resolver (Stage 3b). No `safe_height` is passed: the witness resolver already
  enforces the depth. rgb-lib must report the transfer the enclave parsed (same
  consignment id) and no warning; neither of its warnings can arise with this
  resolver, so one refuses. Each mint leaves an anchor: its OpId and its
  `issuedSupply`.
- **B2.4** The anchor resolver asks the binder once with no anchor: the
  genesis `bridgeLocation` must name the pinned `FUNDS_IN_CONTRACT` on
  `EVM_CHAIN_ID`, and rgb-lib compares that chain id with the genesis one. Then
  it asks once per anchor. For each anchor, the burn signer derives the
  `operationId` of the one deposit that can back it:
  `keccak256(abi.encode(RGB_MINT_DEPOSIT_TYPEHASH, FUNDS_IN_CONTRACT,
  EVM_CHAIN_ID, TOKEN_CONTRACT, RGB_CHAIN_ID, mint OpId, minted units))`. It
  reads nothing from the chain. `TOKEN_CONTRACT` and `EVM_CHAIN_ID` must be
  pinned.
- **B2.5** rgb-lib confirms each anchor only against its derived lock, one
  for one; rgb-lib makes no RPC for it. The Bridge holds a record under that id only if a
  deposit of exactly the minted units was made for that mint, and the release
  checks each cited record, so a mint with no deposit fails on chain.
- **B2.6** The result is a list of locks: deposit `operationId`s. One burn
  has one list, so one `settlementData`; `burnId` does not hash it. Stage 5
  uses this list.
- **B2.7** The contract id must equal the declared `asset_id` and the pinned
  `RGB_ASSET_ID`.
- **B2.8** The settling transition must be `TS_BURN`: the burn of the last
  witness, so one tx also carries rgb-lib's split (or a plain transfer). Two
  burns there are refused. The amount comes from `burnedAsset`, never from
  the outputs or the host. The flat summary of each transition (the split's
  outputs included) comes from rgb-lib's `inspect_consignment` over every
  bundle (`BundleFilter::All`), run on the scratch file rgb-lib just validated,
  which is removed after it. rgb-lib's validation returns no amounts or burn
  facts, so these are read from the same bytes once it passed them. The burn
  facts themselves (`burnedAsset`, `burnReason`, the OpId) come from the
  validated rgbstd transition, and the summary must name the same settling
  transition. The bridge reads the same fields with consignment-utils, and the
  tests compare both readings on every generated shape.
- **B2.9** The witness resolver resolves every witness, the burn included, on
  chain: the transaction comes from the consignment, its block from the
  request's Merkle proof for it. That proof must pass B3.4 and B3.5 first. A
  witness with no such proof is unmined and fails consensus. A proof the
  consignment itself carries is never used: the resolver serves no block
  headers, so rgb-lib asks it instead. Stage 3 runs these proof checks again
  with coverage and pins.

### Stage 3 - Is the burn buried in Bitcoin?

The parent sends block headers. The burn signer builds its own header chain.
On mainnet and the testnets, it checks linkage, proof of work, and `nBits`.
On testnet4 it applies the 20-minute rule and BIP94 (retarget from the first
block of the period, the timewarp rule). On every network a header may be at
most 2 hours ahead of the enclave clock, so a host cannot date free blocks
ahead to lower its fork's difficulty. It accepts a replacement chain only
when it has more work and meets the reorganization limits. Signet and regtest
skip proof-of-work and `nBits` checks.

- **B3.1** The chain tip must not be older than 2 hours, nor more than 2
  hours in the future. On the testnets a min-difficulty tip counts.
- **B3.2** The consignment's network (`chain_net`) must equal the enclave's
  Bitcoin network.
- **B3.3** The Merkle proofs must be exactly the set of witness transactions
  in the consignment. None missing. None extra. No duplicates.
- **B3.4** Each Merkle path must be at most 32 levels. Each proof must verify
  against the header that the enclave stores at that height.
- **B3.5** Each witness transaction must be at least `SPV_MIN_CONFIRMATIONS`
  blocks deep (default 6). On the testnets min-difficulty blocks count.
- **B3.6** The enclave records the heights and hashes it used. Just before it
  uses the key, it checks that they did not change.

### Stage 3b - Did the issuer reject the burned units?

Only for an asset whose genesis names a reject list. rgb-lib runs it at the
end of its validation (B2.3), once every witness and anchor passed, through
the enclave's reject-list resolver. So it refuses, and reads the EVM RPC,
before the Stage 3 checks that run after rgb-lib (B3.1, B3.3 and B3.6); B3.4
and B3.5 already passed for every proof the witness resolver uses. The asset
bind ran before rgb-lib (B2.2), so a foreign genesis cannot make the signer read a contract of its
choice. The resolver reads only the list that genesis names, and a failed
read refuses with the reader's own error. The reads trust the pinned EVM RPC for their
contents, as the trust table in tee-spec.md states: TLS authenticates the
endpoint, not the answers.

- **B3.7** The list must be on `EVM_CHAIN_ID`, and the node must report it.
  Another chain is refused: the enclave has no RPC for it.
- **B3.8** Over the pinned EVM RPC: the latest block and the `finalized`
  block (capped at the latest), `length()` at both, then `entries` in pages of
  1000 at the latest block. Any RPC error, no code at the latest block, a list
  shorter at the latest block, a bad or short page, or more than 20,000
  entries refuses. About 5 calls plus one per 1000 entries; the history
  length does not matter. A call that, at the pace of the slowest call so
  far, would end within 2 s of the 30 s request deadline is not started:
  the read refuses with "exceeded the request budget".
- **B3.9** Decisions: the latest finalized entry for an opout wins. A
  pending reject counts at once, also over a finalized allow. A pending allow
  does not count. `finalized` is fixed in code, not `EVM_FINALITY_TAG`, so the
  signer never releases what an rgb-lib wallet still refuses.
- **B3.10** rgb-lib's rule: the origins are the inputs and the outputs of
  every terminal operation of the consignment, the ones nothing in it builds
  on. Each origin is walked back through rgb-lib's operations DAG. An allowed
  opout stops its branch. A rejected opout on a branch nothing stopped refuses
  the release ("Consignment rejected by the reject list"). The burn has no
  outputs, so its inputs are origins; its input is the split's output, so the
  walk goes through the split to the burned units. The split itself is not
  terminal (the burn spends its output), so the change on it is not checked.
  This rule is stricter than the burn's inputs alone: a companion transfer of
  the same bundle is terminal too, so a rejected line behind it refuses the
  release even when the burned units do not descend from it.

### Stage 4 - Is the calldata correct?

- **B4.1** Calldata must be at least 4 bytes and at most 96 KiB.
- **B4.2** The selector must be `fundsOut` (`0x340276aa`) or `lzFundsOut`.
- **B4.3** The burn signer decodes the calldata and encodes it again. The two
  must be byte-equal. This stops a non-canonical encoding.
- **B4.4** The decoded amount must equal the request's `calldata_amount`. It
  must fit in a u64.
- **B4.5** `chain_id` must equal the pinned `EVM_CHAIN_ID`. `proxy_contract`
  must equal the pinned `EVM_PROXY_CONTRACT_ADDRESS`.
- **B4.6** `destinationChainId`:
  - pools route: must equal `EVM_CHAIN_ID`;
  - LayerZero route: must not be zero, and must not equal `EVM_CHAIN_ID`.
- **B4.7** The deadline must be in the future, and at most 1 day after now
  (`MAX_TEE_DEADLINE_SECS`, the same value as `MultisigProxy.MAX_TEE_DEADLINE`).
  So every signature expires 1 day after signing.
- **B4.8** LayerZero route only: `minAmountLD` must be > 0 and at most `amount`.
  The backend sets it from the net quoted at signing.
- **B4.9** LayerZero route only: `extraOptions` must be empty or one executor
  `lzReceive` gas option (type 3, no value), with gas at most
  `MAX_LZ_RECEIVE_GAS`. Native drop, compose and every other option are refused.

### Stage 5 - Does the release belong to this burn?

Both routes (`fundsOut` and `lzFundsOut`), in this order:

- **B5.1** The burned amount must be at least the calldata amount.
- **B5.2** `sourceChainId` must equal 827166 (`RGB_CHAIN_ID`).
- **B5.3** `sourceAddress` must be empty. RGB has no source address.
- **B5.4** The burn signer calculates `burnId` the same way as
  `Bridge._deriveBurnIdFromFields`. It uses the pinned `FUNDS_IN_CONTRACT`,
  `EVM_CHAIN_ID` and `TOKEN_CONTRACT`, and the calldata fields. The calldata
  `burnId` must be equal.
- **B5.5** BtcRelay proof: the calldata `proof` is
  `(sourceHeight, sourceCommit, latestHeight, latestCommit)`, 128 bytes.
  - `sourceHeight` must be the block that holds the last witness transaction.
  - The enclave must have a header at `latestHeight`. That header must be at
    most 100 blocks below the enclave tip.
  - With `BTC_RELAY_MODE=required` (the production mode), each commit word must
    equal `keccak256` of the 160-byte BtcRelay record that the enclave builds
    from its own chain. A zero word is refused.
  - With `BTC_RELAY_MODE=none` (local stand only), both words must be zero.
    A production policy does not boot in this mode.
- **B5.6** Amount: `burnedAsset` must **equal** the calldata `amount`.
- **B5.7** Burn id: `sourceBurnTxId` must not be zero. It must equal the
  OpId of the burn transition.
- **B5.8** Destination: `burnReason` must be present.
  - High 12 bytes zero (V0): the low 20 bytes are an EVM address. The request
    must carry no `burn_destination`. Pools route only. The calldata
    `recipient` must equal the address.
  - Otherwise (V1): the request must carry `burn_destination`, and its hash
    must equal the 32 bytes ([burn-destination.md](burn-destination.md)).
    `destinationChainId` must equal the record. `dstEid == 0` means the pools
    route, with a 20-byte `recipient` equal to the calldata. `dstEid != 0`
    means the LayerZero route: the calldata `dstEid` must equal it, and the
    left-padded record `recipient` must equal the LayerZero `recipient`.
- **B5.9** Settlement: `settlementData` is
  `abi.encode(bytes32[] operationIds)`. It must be canonical. The ids must be
  in strictly ascending order, so no id repeats. They must equal, as a set,
  the locks consensus confirmed in Stage 2. An empty list is refused.

> **Note - LayerZero route.** Only a V1 burn can leave via LayerZero, because
> only V1 names a chain. `min_amount_ld` is checked against the request only.

### Stage 6 - Sign

- **B6.1** The domain is `("MultisigProxy", "1", chainId, verifyingContract)`.
- **B6.2** The digest uses the **decoded fields**, never the raw bytes:
  - pools route: `TeeFundsOut(recipient, amount, burnId, sourceChainId,
    destinationChainId, sourceAddress, proof, settlementData,
    sourceBurnTxId, nonce, deadline)`;
  - LayerZero route: `TeeLzFundsOut(...)`, 14 fields.
- **B6.3** The burn signer signs with the EVM bridge key `m/44'/60'/0'/0/0`.
  The signature is 65 bytes (`r || s || v`). `v` is the raw recovery id, 0 to 3, with no +27.
- **B6.4** The response has the signature and the calldata. The calldata is
  not changed.

This path creates only `TeeFundsOut` and `TeeLzFundsOut` digests. It does not
create a batch digest. The receiving contract must interpret these signatures
according to the same ABI.

## 6. The gas transaction (`SignRawDigest`)

The burn signer also signs the EVM transaction that sends the release. It
uses the gas key `m/44'/60'/0'/0/1`.

- **G1** The request must have the unsigned transaction. The enclave
  calculates the digest itself.
- **G2** RLP decode must be strict and canonical. EIP-1559 and legacy EIP-155
  are accepted.
- **G3** `chain_id` must equal `EVM_CHAIN_ID`. `to` must equal
  `GAS_TX_ALLOWED_TO`. Contract creation is refused.
- **G4** `gasLimit` must be at most `GAS_TX_MAX_GAS_LIMIT`. Each fee field must
  be at most `GAS_TX_MAX_FEE_PER_GAS`.
- **G5** Calldata must start with a selector in `GAS_TX_ALLOWED_SELECTORS`.
  Empty calldata is refused.
- **G6** `value` must be zero. One exception: the payable `lzFundsOutCall` to
  `EVM_PROXY_CONTRACT_ADDRESS`, with `value` at most `GAS_TX_MAX_VALUE_WEI`.
- **G7** The destination, gas ceiling, fee ceiling, and selector allowlist
  must be configured. An unset value ceiling prevents non-zero `value`. It
  does not prevent a transaction with zero `value`.

The gas rule is part of the attested policy. The gas transaction is not
linked to one checked release. The limits apply to one transaction, not to a
sum of transactions.

## 7. Replay

The burn signer keeps no replay state for releases. Replay protection is on
chain:

- the `MultisigProxy` nonce is in the signed digest;
- the Bridge refuses a `burnId` that it used before.

On both routes, `burnId` is bound to the burn through B5.3, B5.6 and B5.7.

## 8. What the burn signer refuses

| Request | Result |
|---------|--------|
| `Sign` with an EVM source or an RGB destination (mint) | Refused: wrong signer role. |
| `SignBtc` | Refused: wrong signer role. |
| `SignRightsRefill` | Refused: wrong signer role. The burn signer holds no mint rights. |
| `SignCcd` | Refused: not in this build. |
| `SignRawMessage` | Refused in every build. |

## 9. The main idea

The amount and the payee of a burn are its `burnedAsset` and `burnReason`
globals. So the burn signer needs three proofs that agree:

1. RGB consensus: the burn and its whole history are valid, and every mint in
   it is confirmed against the deposit it derives.
2. SPV: every witness transaction of the history is buried, and consensus
   saw each one as mined (B2.9).
3. Globals: the amount and the payee in the burn equal those in the calldata.

The contract proves that the cited deposits exist. The burn signer proves that
they are the deposits behind this burn (B5.9). Each half needs the other.

## 10. Work caps

The request deadline is 30 s (`TOTAL_REQUEST_TIMEOUT`), and a worker is not
interrupted when it passes. So before rgb-lib runs, the burn signer bounds the
three parts of rgb-lib's work that grow faster than the file (B2.2,
`validation/cost.rs`), and then their sum with the file, its opouts, its
operations and the genesis hashes, for rgb-lib's validation and for its
inspection, which reads the summary from the same file once validation
passed (B2.8):

| Cap | Cost of a consignment | Value | Honest burn of 2810 mints |
|-----|-----------------------|-------|---------------------------|
| `MAX_WITNESS_CHECK_COST` | per bundle: transitions x (tx bytes + Tapret partner leaf bytes) + seals x tx inputs | 134,217,728 (128 Mi) | 8,539,773 |
| `MAX_BUNDLE_ID_COST` | per bundle: (transitions + 1) x input map entries | 262,144 (256 Ki) | 11,242 |
| `MAX_REJECT_WALK_COST` | listed asset only: the steps of rgb-lib's walk from each origin | 67,108,864 (64 Mi) | 14,050 |
| `MAX_RGB_LIB_NS` | modeled rgb-lib time. Validation: 1100 ns per file byte, 55,000 per opout (each one the genesis or a transition creates, and each one a transition spends), 15,000 per genesis leaf hash (each genesis global and assignment, once for the genesis and once per transition), 14 per witness step, 4500 per bundle id step, 75 per walk step. Inspection: 650 per file byte, 65,000 per opout, 90,000 per operation (the genesis and each transition), 8 per witness step | 18,000,000,000 (18 s) | 6.1 s on the pinned genesis of 10 mint rights, listed: 3.7 s of validation and 2.4 s of inspection (5.0 to 6.3 s measured end to end) |

Each cap alone holds its part to a few seconds, but the parts add up with
the file's own cost: a listed merge of 1400 lines after 23,900 transfers is
12.1 MB, within the size cap and each cap (its walk at 66.98M), and took
rgb-lib 19.5 to 19.9 s to validate, 15.0 to 15.2 s of it without the walk. So
the gate also models rgb-lib's whole time, from release timings rounded up,
and refuses past 18 s. A file alone models at 1.75 us per byte (1.1 to
validate, 0.65 to inspect), so the budget holds a file to about 10.3 MB,
below the 12 MiB default, whatever it holds. On the pinned genesis of 10 mint
rights the 2810-mint burn's opouts, operations, genesis hashes and costs model
at 2.5 s besides its file. On a genesis of 255 its genesis hashes alone model
at 11.0 s (below). The budget is rgb-lib's alone: the burn signer's own parse,
gate and reads of the validated transfer run outside it, in the rest of the
30 s. End to end, the 2810-mint burn with 3 transfers a line took 1.1 to 1.6 s
more than rgb-lib's validation and inspection timed alone (2.3 s at a load of
5.6).

The opout term closes a gap the per-byte model had before the rgb-lib
1ae1c160 move. rgb-consensus merklizes every opout an operation creates or
spends into the operation id, and it computes that id three times or more per
operation (`validate_transition`, `validate_state` and the state it evolves;
in a profile of a fan-out to 65,535 outputs these hashes took most of
rgb-lib's time). So an opout costs rgb-lib about 35 to 55 us beyond its
bytes, however few they are: a right of a propagate is 14 bytes. A forged
chain of 13 propagates of 65,535 rights each is 11.9 MB with 852k opouts,
within the size cap and every cap, and the old model (1300 ns per byte) let it
through at 15.5 s. It took rgb-lib 42.8 to 44.3 s, and its inspection 51.3 s
more. The model counts 123.1 s now and refuses it.

The genesis term counts the work that grows with the pinned asset's genesis.
For every operation it validates, rgb-consensus `validate_state` takes the
contract id from `genesis.contract_id()`, which merklizes every genesis global
and assignment again (`logic.rs`, unchanged since 4a614b72). A BFA genesis has
5 globals (up to 8 with details, a reject list and the contract it is linked
from) and one assignment per mint right (one more with a link right).
Chains of 2000 one-right propagates, nothing mined, took rgb-lib 0.94 to
0.97 s from a genesis of 1 right, 2.68 to 2.73 s from 64 and 7.83 to 7.86 s
from 255: 13.6 to 13.7 us per genesis leaf and operation, linear in both. The
model counts 15,000 ns and puts the 255-right chain's validation at 9.1 s. On
the pinned genesis of 10 rights (15 leaves, 16 with a reject list) this adds
about 0.23 ms an operation, part of which the per-byte and per-opout rates
already held. On a genesis of 255 rights an operation costs rgb-lib 3.6 ms and
the model 3.9 ms, so the 18 s budget admits about 4,000 operations, whatever
their size: a chain of 5000 one-right propagates (2.3 MB) is refused
(`tests/caps.rs`). Before this term the gate let through about 27,000 such
propagates under the size cap, which would have taken rgb-lib about 110 s.
Rights a propagate or a refill makes later do not widen the genesis. The
inspection hashes the genesis a fixed few times per call, not per operation.

rgb-consensus af0b751d ("restructure dag for performance") builds the
operations DAG with one edge per spent opout and no scan of the edges already
there, so the DAG has no cap of its own any more (it had `MAX_OPOUTS_DAG_COST`,
the sum of k^2 over transitions of k inputs, at 8192^2). A forged burn of n
rights now costs rgb-lib the same per byte at every n (1.16 to 1.24 us per byte
at 4096, 16,384 and 65,535 rights), and the 65,535-right burn that took 17.7 s
on rgb-consensus 4a614b72 takes 9.0 to 9.3 s to validate and 9.7 to 9.8 s to
inspect. Its validation models at 16.3 s, so it passed the gate before the
inspection counted; with it, it models at 29.9 s and is refused before rgb-lib.

The inspection term. rgb-lib's validation returns no amounts, so the summary
is read by its `inspect_consignment` over every bundle, on the scratch file
validation just read (B2.8). No cap bounds it, and it costs about as much per
opout as validation: it strict-decodes the file again through an unbuffered
`File` (about 0.46 us per byte of `read` calls), computes each transition id
three times more (about 15 us per opout and pass at opt-level z), serializes
every bundle again for the consignment id and formats every output. Two of its
steps are superlinear, and the witness cap holds both: it hashes the bundle's
witness tx once per transition (about 6.4 ns per byte) and scans its inputs
once per input (about 2 ns a step), the two terms of the witness cost, so
under 1.1 s at the cap. A third, its scan of the bundle's transitions once per
input, is at most the bundle id cost at a few ns a step, as long as no bundle
lists a transition twice. A bundle may (its transitions are a list, and every
copy passes the inspection's commitment check), but rgb-lib refuses the copy:
its inputs are already spent by the first ("references previous state"), and
the inspection runs only on what validation passed (`tests/caps.rs`). Measured
on the shapes below, the inspection takes 0.46 to 0.5 us per byte, about 46 to
54 us per right and 60 us per asset output beyond the bytes, and up to about
130 us more per operation of one small transition per bundle. The model's
rates (650 ns per byte, 65 us per opout, 90 us per operation, 8 ns per witness
step) hold every shape measured at a load under 4 by 8 percent or more: the
honest 2810-mint burn closest (2.2 s at a load of 4 against 2.4 s), then the
fan-outs (11 to 13 percent). On the burn path every witness of what the
inspection reads is mined. In the swap flow (`allow_unbroadcast_last` in
`networks/rgb/route.rs`) the last bundle need not be, so a host can forge one
within the caps at no chain cost; the gate counts its inspection the same way.

The honest burn here is 2810 mints, each on its own right, all burned by one
transition (2810 allocations in one tx), the widest the bridge expects, on the
pinned asset's genesis of 10 mint rights; the timings below also run it with
3 transfers a line. rgb-lib's own burn (a split, then the burn of the split's
output) has one origin.

rgb-consensus checks each transition against its bundle: it clones, hashes
and compares the whole witness tx and the anchor's Tapret partner leaf (a
script of any length), scans the tx inputs for each seal, and hashes the
bundle id, a commitment to the whole input map (`validate_transition`, and
the bundle id once more per bundle). An honest bundle carries one or two
transitions, so these stay linear; a forged one of thousands of transitions does not. The
walk cost is counted the way rgb-lib walks (`rejected_opouts`): from each
origin on its own, with no list entry to cut it short, stopping just past the
cap. So a burn of many separate lines costs a few steps per line, however
long each line's history; only origins that share a long history cost much.

Measured in release mode on an Apple M1 Pro (`cargo test --release -p
utexo-bridge-enclave --no-default-features --features rgb,burn-signer --lib
caps -- --ignored --nocapture --test-threads=1`, `validation/tests/caps.rs`),
on rgb-lib 1ae1c160, 2026-10-30, at a load under 4 unless a cell names more,
two runs each; a row marked "one run" ran once. The enclave's CPU may be
slower; the times scale with it. The honest burns are on the pinned genesis of
10 mint rights (`GENESIS_RIGHTS=10`) unless their row names more; each forged
history is on a genesis of 1 right (`GENESIS_RIGHTS` unset) unless its row
names more. Each model is validation plus inspection, the genesis hashes
included, and the honest rows give the listed asset's. The end-to-end times
include our parse of the transfer and the gate (0.1 to 0.5 s), the inspection
and our read of the last bundle, 3 to 21 ms on these burns.

| Consignment | Bytes | Opouts | Cost against its cap, model (validation + inspection) | rgb-lib validation (of which its file load) | rgb-lib inspection |
|-------------|-------|--------|--------------------------------------------------------|---------------------------------------------|--------------------|
| Honest burn, 1404 mints | 1.0 MB | 5.6k | witness 2.3M, walk 7k, model 3.0 s (1.8 + 1.2) | 1.37 to 1.45 s (0.4 s) | 0.94 to 0.98 s; 2.5 to 2.6 s end to end |
| Honest burn, 1404 mints, 3 transfers a line | 3.0 MB | 14k | witness 2.8M, walk 15k, model 8.9 s (5.5 + 3.4) | 4.5 to 4.7 s (1.3 s) | 2.8 to 2.9 s; 7.9 to 8.3 s end to end |
| Honest burn, 2810 mints | 2.0 MB | 11k | witness 8.5M, walk 14k, model 6.1 s (3.7 + 2.4) | 2.7 to 2.8 s (0.9 to 1.1 s), one run 3.5 s | 1.9 to 2.2 s; 5.0 to 6.3 s end to end |
| Honest burn, 2810 mints, 3 transfers a line | 6.0 MB | 28k | witness 9.6M, walk 31k, model 17.9 s (11.1 + 6.8) | 8.8 to 9.2 s (2.5 to 2.6 s) | 5.7 to 5.8 s; 15.9 to 16.2 s end to end |
| Honest burn, 2810 mints, genesis of 255 rights (one run) | 2.1 MB | 11k | model 16.5 s (14.1 + 2.4) | 12.5 to 13.4 s (0.9 s) | 2.0 s (3.7 s at a load of 11); 15.3 to 16.2 s end to end |
| Forged chain of 2000 one-right propagates | 0.9 MB | 4k | model 2.5 s (1.4 + 1.0) | 0.94 to 0.97 s (0.4 s) | 0.87 to 0.89 s |
| Forged chain of 2000 one-right propagates, genesis of 64 rights | 0.9 MB | 4k | model 4.4 s (3.3 + 1.0) | 2.68 to 2.73 s (0.4 s) | 0.88 to 0.90 s |
| Forged chain of 2000 one-right propagates, genesis of 255 rights | 0.9 MB | 4k | model 10.1 s (9.1 + 1.1) | 7.83 to 7.86 s (0.4 s) | 0.88 to 0.89 s |
| Forged burn of 4096 rights | 0.5 MB | 8k | ids 8k, model 1.9 s (1.0 + 0.8) | 0.59 to 0.60 s (0.2 s) | 0.60 to 0.61 s |
| Forged burn of 16,384 rights | 1.9 MB | 33k | ids 33k, model 7.5 s (4.1 + 3.4) | 2.28 to 2.34 s (0.9 s) | 2.42 to 2.44 s (2.9 s at a load of 4.5) |
| Forged burn of 65,535 rights (refused since the inspection counts) | 7.7 MB | 131k | ids 131k, model 29.9 s (16.3 + 13.5) | 9.0 to 9.3 s (3.5 s) | 9.7 to 9.8 s (14.2 s at a load of 4.5) |
| Forged fan-out to 16,384 outputs | 0.4 MB | 16k | model 2.6 s (1.3 + 1.3) | 1.18 to 1.22 s (0.1 s) | 1.15 to 1.16 s |
| Forged fan-out to 65,535 outputs | 1.5 MB | 66k | model 10.5 s (5.3 + 5.2) | 4.69 to 4.70 s (0.5 s) | 4.65 to 4.67 s |
| Forged chain of 13 propagates of 65,535 rights (refused, one run) | 11.9 MB | 852k | model 123.1 s (60.0 + 63.1) | 44.3 s (5.5 s), plus 4.0 s of our pre-checks | 51.3 s |
| Forged chain of 217 propagates of 4096 rights (refused) | 12.5 MB | 889k | model 128.7 s (62.7 + 66.0) | 44.9 to 46.1 s (6.0 to 7.2 s), plus 4.2 s of our pre-checks | 54.3 s (one run) |
| Forged file at the size cap: 150 burns of 700 rights, genesis of 150 rights (refused) | 12.5 MB | 210k | model 48.8 s (27.0 + 21.8) | 16.1 to 16.5 s (5.7 to 5.8 s) | 16.8 s (one run, at a load of 5) |
| Forged file at the size cap: 13 burns of 8192 rights, genesis of 13 rights (refused) | 12.6 MB | 213k | model 48.5 s (26.5 + 22.0) | 14.6 to 14.9 s (5.8 to 6.0 s) | 15.9 s (one run, at a load of 5) |
| Forged bundle of 64 burns, tx of 49,900 dummy inputs | 2.4 MB | 130 | witness 134.1M (at the cap), model 7.2 s (4.6 + 2.7) | 1.94 to 1.95 s (0.9 s) | 1.96 to 1.97 s |
| Forged bundle of 256 burns, tx of 12,480 dummy inputs (refused) | 0.7 MB | 514 | witness 134.2M (126 over the cap) | 1.58 to 1.59 s (0.2 s) | 1.16 s |
| Forged bundle of 64 burns, Tapret partner leaf of 2.09 MB | 2.1 MB | 130 | witness 133.8M (at the cap), model 6.7 s (4.2 + 2.5) | 2.26 to 2.27 s (0.9 s) | 1.00 to 1.03 s |
| Forged bundle of 256 burns, Tapret partner leaf of 523 KB | 0.6 MB | 514 | witness 133.9M (at the cap), model 4.4 s (2.9 + 1.5) | 1.89 s (0.3 s) | 0.31 s |
| Forged bundle of 511 burns, Tapret partner leaf of 262 KB | 0.4 MB | 1k | witness 133.9M (at the cap), ids 261,634, model 5.0 s (3.6 + 1.4) | 2.57 to 2.58 s (0.2 s) | 0.26 s |
| Forged burn of 8192 rights, tx of 16,000 dummy inputs | 1.7 MB | 16k | witness 131.7M (seal scans), model 8.0 s (4.7 + 3.2) | 1.54 s (0.7 s) | 1.82 s |
| Forged bundle of 512 burns (one over the bundle id cap) | 0.1 MB | 1k | ids 262,658 | 1.16 s (0.05 s) | 0.14 s |
| Forged bundle of 2048 burns (refused) | 0.4 MB | 4k | ids 4.2M | 15.5 to 15.8 s (0.2 s) | 0.55 to 0.56 s |
| Forged fan-out of 65,535 after 500 transfers, listed | 1.7 MB | 67k | walk 65.9M, model 16.1 s (10.6 + 5.5) | 9.5 to 9.6 s, of which the walk 4.4 to 4.7 s | 4.86 s |
| Forged merge of 4096 lines after 8180 transfers, listed (refused since the inspection counts) | 6.6 MB | 33k | walk 67.1M (at the cap), model 23.5 s (15.8 + 7.7) | 12.8 to 12.9 s, of which the walk 4.8 s | 6.29 to 6.32 s |
| Forged merge of 1400 lines after 23,900 transfers, listed (refused) | 12.1 MB | 53k | walk 67.0M, model 38.0 s (24.3 + 13.7) | 19.5 to 19.9 s, of which the walk 4.5 to 4.6 s (5.2 s) | 11.6 s (14.0 s at a 5-minute load of 10) |
| Forged merge of 600 lines after 23,900 transfers, listed (refused) | 11.6 MB | 50k | walk 28.7M, model 33.5 s (20.5 + 13.0) | 16.6 to 16.8 s, of which the walk 2.1 to 2.3 s (4.9 to 5.0 s) | 11.0 s |

The forged burns are schema-valid, with no witness mined, so rgb-lib refuses
them only after phase 1 ran in full. The inspection runs only once validation
passed, so it is timed on the forged files directly; it checks no witness. The
walk runs only once every witness passed, so a forged walk needs mined
transactions. One rgb-lib walk step takes 45 to 73 ns, so the walk cap holds a
walk under about 5 s; the enclave's own count of it took 0.2 s at the cap. One
bundle id entry takes about 3.5 to 4 us, one byte of a forged tx or partner
leaf about 7 to 11 ns, one seal scan about 2 ns. Every shape measured at a
load under 4 stays within its model, on the genesis of its row. The validation rates' margin is
about the spread between runs: one of nine runs of the 4096-line merge, while
the machine was still settling from other load, took 16.2 s against the 15.8 s
its validation models. A busy or slower host runs past the model by that much:
at a load of 4.5 the 65,535-right burn's inspection took 14.2 s, 5 percent
over its 13.5 s.

What the caps do not bound: rgb-lib's work that is linear in the file, its
opouts and its operations. Validation takes about 0.8 to 1.1 us per byte
(strict-decoding the file through an unbuffered `File` takes about 0.45 us per
byte of `read` calls), about 35 to 55 us per opout beyond its bytes, and
13.7 us per genesis leaf for each operation; the inspection about 0.5 us per
byte, 46 to 60 us per opout and up to 130 us per operation. That part is
bounded by `MAX_CONSIGNMENT_BYTES` (12 MiB by default) and by
`MAX_RGB_LIB_NS`, which holds the modeled sum of file, opouts, operations,
genesis hashes and capped parts to 18 s: at most about 2.5 s of witness checks
in validation and 1.1 s in the inspection, 1.2 s of bundle ids and 5 s of walk
on top of the file. It is what dominates an honest burn with a long history:
on the pinned genesis the 2810-mint burn with 3 transfers a line takes 15.9 to
16.2 s end to end. The validation rates are rounded up from the shapes above,
5 to 12 percent above the costliest per opout (fan-outs) and per byte (merges
of transfers and honest burns), and 9 percent above the genesis chains; the
inspection rates 8 percent above the costliest, the honest 2810-mint burn. A
shape that costs rgb-lib more per byte, per opout, per operation or per genesis
leaf than those measured would run past it by that much. The genesis rate
double counts on a small genesis: its leaves an operation were already in the
measured shapes the other rates come from.

What the caps can refuse in an honest history. The walk cap (listed asset
only) can refuse an exact-amount burn: with no change there is no split, so
each of its k inputs is an origin and walks on its own. If those
k allocations were paid off one payer chain after D earlier links, the walk
costs 2kD + k^2 + 4k steps: k = 3478 (2 allocations per input) and D = 8000
cost 67.8M. At one allocation per input (k <= 1739) it needs D of at least
18.4k, more witnesses than `MAX_MERKLE_PROOFS`. A burn with change has one
origin, the split's output, which walks its ancestry once. The time budget
refuses an honest history past about 18 s of modeled work, validation and
inspection together. On the pinned genesis of 10 rights a history of
transfers alone is about 230 bytes per opout, and each opout models at about
0.7 ms, so it reaches 18 s at about 6 MB: the 2810-mint burn with 3 transfers
a line (6.0 MB) passes at 17.9 s, and a longer history is refused. On a
genesis of 255 rights each operation adds 3.9 ms, so the budget refuses a
history past about 4,000 operations, whatever its size. The 2810-mint burn
passes there at 16.5 s, 14.1 s of it validation. 1404 or 2810 mints with 3
transfers a line are refused there; they would take rgb-lib 22.7 and 45.9 s
to validate, the second past the 30 s deadline.
