# Burn destination record

Status: V1 draft. This file is the normative format. The enclave code is
`enclave/src/networks/evm/burn_destination.rs`.

## Why

A burn has one 32-byte field for the payout target: BFA metadata
`MS_BURN_RECIPIENT` (key 1003). The RGB schema will not grow it. A release
also needs a destination chain, and non-EVM addresses can be 32 bytes alone.

So the field holds a hash of a larger record. The user signs the burn, so the
user signs the hash. The record itself travels next to the burn. Anyone can
check it: hash the record and compare.

## Versions

| Version | What the 32 bytes hold | Routes |
|---|---|---|
| V0 (legacy) | 12 zero bytes + 20-byte EVM address | Direct `fundsOut` only |
| V1 | `hash_v1(record)` | Direct `fundsOut` or `lzFundsOut` |

How to tell them apart: if the high 12 bytes are zero, it is V0. Otherwise it
is a hash. A V1 hash starts with 12 zero bytes with odds of 2^-96.

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
| `destinationChainId` | uint64 | Bridge route chain id: the `destinationChainId` of `fundsOut` / `lzFundsOut`. Not 0. |
| `dstEid` | uint32 | LayerZero endpoint id. `0` = direct `fundsOut` on the Bridge chain. |
| `recipient` | bytes | Chain-native payee, 1 to 32 bytes. Direct route: exactly 20 bytes. |

What the enclave checks for V1:

- The record hash equals the burn's 32 bytes.
- Calldata `destinationChainId` == `destinationChainId`.
- `dstEid == 0`: calldata is `fundsOut`, and `recipient` (20 bytes) == calldata
  `recipient`.
- `dstEid != 0`: calldata is `lzFundsOut`, calldata `dstEid` == `dstEid`, and
  `recipient` left-padded to 32 bytes == calldata `bytes32 recipient`.

## Test vectors

[burn-destination-vectors.json](burn-destination-vectors.json). Each vector
gives the inputs, the `abi.encode` bytes and the hash. They were made with
go-ethereum `accounts/abi`. The enclave unit tests check the same file. Run it
in your language before you ship.

## Transport

The record goes to the enclave in proto `EvmDestination.burn_destination`
(`BurnDestination { version, destination_chain_id, dst_eid, recipient }`). The
proto bytes are never hashed. The enclave rebuilds the hash from the typed
fields. A V0 burn must not carry a record.

## Rules for new versions

- A new version gets a new type string, for example
  `UtexoBurnDestinationV2(...,bytes refund)`. Its TYPEHASH differs, so a V2
  hash never equals a V1 hash.
- Never change a published version. Not the type string, not the field rules.
- Add new proto fields with new numbers. Keep the old numbers.
- The enclave keeps every version's verifier forever. A burn on RGB is
  permanent, so an old burn must stay releasable.
- An unknown version is refused (fail closed).

## Planned

- V2: optional `refund` target for stuck burns. It waits for the stuck-burn
  policy.
