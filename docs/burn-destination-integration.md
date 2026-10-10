# Burn destination: integration design

Status: draft for the bridge, wallet and contract teams.
Format spec: [burn-destination.md](burn-destination.md).

## Problem

Audit MAJOR finding (burn signer): `lzFundsOut` carries two destination
fields. `destinationChainId` picks the route and the commission. `dstEid` picks
where LayerZero delivers. The burn named no chain, so nothing compared them
with the user's intent. A compromised backend could pay the right address on
the wrong chain. The `burnId` is then spent, so the user cannot redo it.

## Fix

The burn names the destination. `MS_BURN_RECIPIENT` stays 32 bytes (RGB team
decision). From V1 it holds `hash_v1(destinationChainId, dstEid, recipient)`.
The user signs it with the burn. The enclave gets the record, checks the hash,
and signs only the release that the record names.

## Data flow

```
wallet ----(record + burn)----> backend (tricorn) ---> listener ---> enclave
  |  hash_v1(record) -> burn      | check + store          |  EvmDestination.
  |  MS_BURN_RECIPIENT            | pick route              |  burn_destination
```

## Changes per component

### Wallet / SDK (rgb-lib callers, rgb-sdk, wallets)

- The user picks the destination chain and address.
- Build the V1 record. Compute `hash_v1`. Pass the hash as `burn_recipient`
  (`rgb-lib` already takes `Option<[u8; 32]>`).
- Send the record to the backend together with the burn. Keep a copy.
- Run the shared test vectors before release.
- Optional: a `hash_v1` helper in rgb-lib, so every wallet uses one code path.

### Backend (bridge-utexo / tricorn)

- Accept the record with the burn request.
- Check `hash_v1(record) == MS_BURN_RECIPIENT` of the burn. Refuse a mismatch
  early.
- Store the record with the burn. Losing it makes the burn unreleasable.
- Pick the route from the record: `dstEid == 0` -> `fundsOut`, else
  `lzFundsOut` with `dstEid` and `destinationChainId` from the record.
- A V0 burn (legacy address) goes on the direct route only.

### Listener (federated-signer-node)

- Copy the record into `EvmDestination.burn_destination`. No other logic.

### Proto (federated-signer-proto)

- Add `BurnDestination` and `EvmDestination.burn_destination = 9`
  (branch `feat/burn-destination`, commit `607ba86`). Not yet on `main`.
- enclave-signer vendors and pins that commit. Re-pin after the merge.

### Enclave (enclave-signer)

- Done on branch `feat/burn-destination-hash`: record checks, V0/V1 rules,
  tests, spec, and the proto resync.

### Contracts (bridge-smart-contracts, usdt0-smart-contracts)

Not required for the fix. Defense in depth, as the audit recommends:

- `UtexoLZAdapter.sendOut` takes `destinationChainId` and checks a governed
  outbound map: `outboundChainIdOf[dstEid] == destinationChainId`, else revert.
  This mirrors the inbound `eidToChainId[srcEid] == sourceChainId` check in
  `lzCompose`.
- Outbound-only chains need their own map entry (the inbound map is set only
  with a trusted entrypoint).

With the enclave bind and this check, both the signer and the chain refuse a
mismatched pair.

## Rollout order

1. Proto PR merged.
2. Enclave release with the resync (new PCR0, re-attest).
3. Listener, then backend.
4. Wallets start writing V1.

Between step 2 and step 4, LayerZero releases stop: a V0 burn is refused on
LayerZero. Agree a cut-over date, or ship steps 2 to 4 together.

## Open questions

- **Stuck burns.** A V1 burn whose record is lost, or whose route is disabled
  later, cannot be released. The RGB tokens are already destroyed; the backing
  stays in the Bridge pool. Options: treat as lost, or a federation recovery
  path. A user-signed `refund` field is planned for record V2.
- **Record storage.** Should the record also be kept somewhere public (for
  example the RGB transfer's off-chain data) so that the backend is not the
  only copy?
