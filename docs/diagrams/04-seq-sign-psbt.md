# Sign (EVM → RGB, mint PSBT) — mint signer

The mint signer path, in code order. Step-by-step text:
[mint flow](../mint-flow.md).

The request must have the EVM deposit hash, the PSBT rgb-lib committed and
the parent PSBT of the spent right. The mint signer reads no consignment. It
uses Taproot key-path signatures from the colored BIP-86 account. Every
output must be its own or carry 0 sat (M8).

Plain-BTC PSBTs do not use this path. They use the separate `SignBtc` request
(vanilla account, attested `allow_vanilla_psbt`, `BTC_MAX_TOTAL_SATS`,
`BTC_MAX_UNOWNED_SATS`).

```mermaid
sequenceDiagram
    actor Orc as Orchestrator
    participant Listener as Go Listener
    participant Parent as utexo-bridge-parent<br/>(grpc_server.rs)
    participant Wire as enclave/server/wire.rs
    participant Srv as enclave/server/sign.rs<br/>handle_sign
    participant Evt as networks::evm::events
    participant Rpc as EVM RPC<br/>(TLS to pinned host, ends in enclave)
    participant Core as networks::rgb::psbt_commit<br/>+ parent_proof (psbtu)
    participant Anchor as networks::rgb::psbt_validation
    participant Inv as networks::rgb::invoice
    participant State as EnclaveState<br/>op_replay_guard
    participant Km as KeyManager::sign_psbt

    Orc->>Listener: FundsIn deposit observed on EVM
    Listener->>Parent: gRPC Sign(TRANSACTION, PSBT + parent_psbt)
    Parent->>Wire: Sign{EvmSource, RgbDestination}
    Wire->>Srv: dispatch (endpoints must be set)

    Note over Srv: 0 — role check
    Srv->>Srv: RgbSource or EvmDestination ⇒ REFUSE (wrong signer role)

    Note over Srv,State: 1 — replay precheck (read only, before network I/O)
    Srv->>State: check(keccak(chain_id, proxy, evm_tx_hash,<br/>funds_in_operation_id, asset_id))
    State-->>Srv: unexpired entry still in cache ⇒ REFUSE

    Note over Srv,Rpc: 2 — this deposit (verify_funds_in_event)
    Srv->>Evt: tx_hash, funds_in_operation_id (32 bytes each), amount, commission
    Evt->>Rpc: eth_getTransactionReceipt<br/>eth_getBlockByNumber(EVM_FINALITY_TAG, false) / block at receipt height (15 s per call)
    Rpc-->>Evt: receipt / selected head / canonical block
    Evt->>Evt: receipt exists + status success
    Evt->>Evt: exactly ONE BridgeFundsIn from FUNDS_IN_CONTRACT<br/>(zero or two ⇒ REFUSE, no plain FundsIn fallback)
    Evt->>Evt: topic1 operationId == funds_in_operation_id<br/>gross == amount, tokenCommission == commission<br/>netAmount ≤ gross − commission, u64 only
    Evt->>Evt: receipt height ≤ selected head, canonical blockHash matches,<br/>revalidate head snapshot; missing head or receipt above head ⇒ REFUSE
    Evt-->>Srv: destinationAddress (may be empty)

    Note over Srv,Core: 3 - the committed mint (validate_destination_anchor)
    Srv->>Core: F1 parse; F2 witness_utxo native SegWit, sighash ALL / DEFAULT
    Srv->>Core: F3 first OP_RETURN-or-P2TR output is the OP_RETURN<br/>F4 one bundle, of RGB_ASSET_ID (== asset_id)<br/>F5 MPC tree of every disclosed bundle + entropy == opret commitment<br/>F6 one transition, its own id, input map == its inputs
    Srv->>Anchor: M1 TS_MINT, M2 one OS_MINT input, M3 OS_ASSET only,<br/>M4 issuedSupply > 0 and afterBlock (8 bytes each),<br/>M5 units == issuedSupply == amount − commission,<br/>M7 one blinded leg
    Srv->>Anchor: F7 one input, Colored key path of this enclave
    Srv->>Core: PP1-PP7 parent PSBT: core again, TS_TRANSFER parent,<br/>right alone on a witness seal, the PSBT spends that output
    Srv->>Anchor: fee ≤ 100 000 sats, ≤ 200 sat/vB (unsigned size),<br/>≥ 1 sat/vB (estimated signed size)
    Note over Srv,Rpc: 4 - M6 the deposit is this mint's (server::bfa::bind_mint_deposit)
    Srv->>Srv: TOKEN_CONTRACT, EVM_CHAIN_ID pinned (before any RPC)
    Srv->>Rpc: eth_chainId, receipt of evm_tx_hash,<br/>EVM_FINALITY_TAG head, canonical block
    Srv->>Srv: eth_chainId == EVM_CHAIN_ID; one FundsIn (rgbOpId == mint OpId)<br/>+ one BridgeFundsIn, block > afterBlock, height ≤ selected head,<br/>canonical blockHash matches, head snapshot revalidated;<br/>deposit == the mint's derived lock

    Note over Srv,Inv: 5 — route and recipient
    Srv->>Srv: amount ≥ minted units + commission
    alt destinationAddress not empty (legacy deposit)
        Srv->>Inv: RGB invoice, blinded seal only
        Srv->>Inv: the M7 seal == invoice seal
    else empty (v2 Bridge)
        Note right of Srv: recipient bound by the mint OpId (step 3)
    end

    Note over Srv,State: 6 — reserve replay key
    Srv->>State: reserve (rolled back on error)

    Note over Srv,Km: 7 — sign
    Srv->>Srv: mint: M8 no unowned output sats; send-RGB: ≤ RGB_MAX_UNOWNED_SATS
    Srv->>Km: sign_psbt_scoped(psbt, Colored)
    Km->>Km: per input: P2TR, origin fp == ours,<br/>derived key == tap_internal_key,<br/>tweak(internal, merkle_root) == output key<br/>⇒ Schnorr key-path signature
    Km-->>Srv: signed PSBT, inputs_signed
    Srv->>Srv: inputs_signed == 0 ⇒ REFUSE
    Srv-->>Wire: SignedPsbtResponse + reservation
    Wire->>Parent: write response
    Wire->>State: commit replay key only after the write succeeds
    Note over Wire,Parent: A successful write does not prove receipt by the caller.
    Parent-->>Listener: signed PSBT (not finalized)
    Listener-->>Orc: finalize + broadcast
```

The mint signer checks no RGB history and reads no indexer: a bad history
makes the mint invalid for every receiver. The parent proof pins the one UTXO
the mint spends, so every signature for the mint spends it. The replay cache
is in memory and per enclave. It is not a durable deposit ledger.

See [the spec](../tee-spec.md#72-evm-lock---rgb-bridge-psbt) for the deposit
rules.
