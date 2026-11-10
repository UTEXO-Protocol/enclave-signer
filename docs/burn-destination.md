# Burn destination record

This file is the normative format of the destination that a burn names. V1 is
published. The enclave code is
`enclave/src/networks/evm/burn_destination.rs`.

## Why a record

A burn has one 32-byte field for the payout target: the BFA global
`burnReason` (`GS_BURN_REASON`, 3009). rgb-lib treats it as opaque bytes. A
release also needs a destination chain, and a non-EVM address can be 32 bytes
alone.

So the field holds the hash of a larger record. The user signs the burn, so
the user signs the hash. The record travels next to the burn. Anyone can
check it: hash the record and compare.

## Versions

| Version | What the 32 bytes hold | Routes |
|---|---|---|
| V0 | 12 zero bytes + 20-byte EVM address | Direct `fundsOut` only |
| V1 | `hash_v1(record)` | Direct `fundsOut` or `lzFundsOut` |

If the high 12 bytes are zero, the field is V0. Otherwise it is a hash. A V1
hash starts with 12 zero bytes with odds of 2^-96.

## V1

Type string (EIP-712 style):

```
UtexoBurnDestinationV1(uint64 destinationChainId,uint32 dstEid,bytes recipient)
```

Hash:

```
TYPEHASH_V1 = keccak256("UtexoBurnDestinationV1(uint64 destinationChainId,uint32 dstEid,bytes recipient)")
            = 0xa1cba9d766975eb04c6a31c3b68dbb2381444a222c9972b6bf3ab26fcb829b00

hash_v1 = keccak256(abi.encode(
    TYPEHASH_V1,
    uint64  destinationChainId,
    uint32  dstEid,
    keccak256(recipient)
))
```

`abi.encode` gives four 32-byte words: numbers are big-endian, left-padded with
zeros. `recipient` is hashed first, as EIP-712 does for `bytes`. This is the
EIP-712 `hashStruct` rule, so any EIP-712 or ABI library gives the same bytes.
In Solidity:

```solidity
keccak256(abi.encode(TYPEHASH_V1, destinationChainId, dstEid, keccak256(recipient)))
```

Fields:

| Field | Type | Rule |
|---|---|---|
| `destinationChainId` | uint64 | Bridge route chain id: the `destinationChainId` of `fundsOut` / `lzFundsOut`. Not 0. With `dstEid` 0 it must equal `EVM_CHAIN_ID`. With a non-zero `dstEid` it must not. |
| `dstEid` | uint32 | LayerZero endpoint id. `0` = direct `fundsOut` on the Bridge chain. |
| `recipient` | bytes | Chain-native payee, 1 to 32 bytes. Direct route: exactly 20 bytes. |

What the enclave checks for V1:

- The record hash equals the burn's 32 bytes.
- Calldata `destinationChainId` == `destinationChainId`.
- `dstEid == 0`: calldata is `fundsOut`, and `recipient` (20 bytes) == calldata
  `recipient`.
- `dstEid != 0`: calldata is `lzFundsOut`, calldata `dstEid` == `dstEid`, and
  `recipient` left-padded to 32 bytes == calldata `bytes32 recipient`.

A V0 burn names no chain, so it is released on the direct route only, and its
request must carry no record.

## Test vectors

[burn-destination-vectors.json](burn-destination-vectors.json). Each vector
gives the inputs, the `abi.encode` bytes and the hash. They were made with
go-ethereum `accounts/abi`. The enclave unit tests check the same file. Run it
in your language before you ship.

## Transport

The record travels from the wallet to the enclave as typed fields
(`BurnDestination { version, destination_chain_id, dst_eid, recipient }`).
The proto bytes are never hashed: the enclave rebuilds the hash from the
fields.

| Hop | Field |
|---|---|
| Backend to listener | node `EvmSignData.burn_destination` (4) |
| Listener to parent | parent `EnrichedEvmPayload.burn_destination` (10) |
| Parent to enclave | enclave `EvmDestination.burn_destination` (9) |

What each component does:

- **Wallet.** Builds the record, computes `hash_v1` and passes the hash as
  the `burnReason` of the burn. Sends the record to the backend with the
  burn.
- **Backend.** Checks `hash_v1(record) == burnReason` and refuses a mismatch.
  Stores the record with the burn: a burn whose record is lost cannot be
  released. Picks the route from the record: `dstEid == 0` is `fundsOut`,
  otherwise `lzFundsOut`.
- **Listener.** Copies the record unchanged. It must not rebuild the record
  from the calldata: the padded recipient loses its length.
- **Enclave.** Checks the record against the burn and the calldata, as above.

## Rules for new versions

- A new version gets a new type string, for example
  `UtexoBurnDestinationV2(...)`. Its TYPEHASH differs, so its hash never
  equals a V1 hash.
- Never change a published version. Not the type string, not the field rules.
- Add new proto fields with new numbers. Keep the old numbers.
- The enclave keeps the verifier of every version. A burn on RGB is
  permanent, so an old burn must stay releasable.
- An unknown version is refused.
