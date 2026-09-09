# Sign (EVM → RGB, bridge PSBT) — taproot + segwit-v0, anchored authorisation

Plain-BTC (non-bridge) PSBTs do **not** go through this path anymore: they use
the separate `SignBtc` request, gated by the attested `allow_vanilla_psbt`
policy, the output self-ownership rule (an output must repay a script the
transaction is already spending, with `BTC_MAX_UNOWNED_SATS` budgeting those
that do not), and the `BTC_MAX_TOTAL_SATS` cap, with signing scoped to the
vanilla BIP-86 account only.

The bridge path below always requires the EVM deposit hash **and** the RGB
consignment, is scoped to the colored account, and bounds Bitcoin outputs it
cannot prove by `RGB_MAX_UNOWNED_SATS` -- every other bind on this path is
denominated in RGB asset units and says nothing about sats.

```mermaid
sequenceDiagram
    actor Orc as Orchestrator
    participant Listener as Go Listener
    participant Parent as utexo-bridge-parent<br/>(grpc_server.rs)
    participant Srv as enclave/server.rs<br/>handle_sign
    participant Evm as networks::evm::validation
    participant Evt as networks::evm::evm_event
    participant Rpc as EVM RPC / Helios<br/>loopback→vsock→host
    participant Rgb as networks::rgb<br/>(rgbstd + Esplora + SPV)
    participant Anchor as networks::rgb::psbt_validation
    participant State as EnclaveState<br/>op_replay_guard
    participant Km as KeyManager::sign_psbt
    participant Tap as signing::taproot<br/>find_taproot_sign_jobs
    participant Sw as signing::psbt<br/>should_sign_segwit_input
    participant Crypto as secp256k1 / k256

    Note over Orc,Listener: Intent
    Orc->>Listener: bridge intent (FundsIn deposit observed on EVM)
    Listener->>Listener: fetch PSBT from rgb-multisig-bridge,<br/>enrich with EVM event fields + RGB consignment
    Listener->>Parent: gRPC Sign(TRANSACTION, enriched payload)

    Note over Parent,Srv: Translate
    Parent->>Srv: Sign{source_network: EvmSource,<br/>destination_network: RgbDestination}

    Note over Srv,Evm: 1 — validate_source (EVM, skipped in dev-mode)
    Srv->>Evm: validate_source(EvmSource)
    Evm->>Evm: len(evm_tx_hash) == 32
    Note right of Evm: listener event_valid / event_finalized<br/>are IGNORED — validity and finality<br/>are established below, never trusted
    Evm-->>Srv: Ok / CrossCheck err

    Note over Srv,Anchor: 2 — validate_destination_anchor (rgb-validation, consignment MANDATORY)
    Srv->>Rgb: validate_consignment (cheap hash gate first, then<br/>rgbstd + Esplora resolver + typesystem pin)
    Rgb-->>Srv: ValidatedConsignment / REFUSE
    Srv->>Anchor: keccak256(consignment) == consignment_hash (integrity)
    Srv->>Anchor: asset pin: declared asset_id == validated contract_id<br/>== pinned RGB_ASSET_ID (unconditional on this path)
    Srv->>Anchor: PSBT unsigned txid == last witness txid —<br/>input prevouts == witness prevouts —<br/>sighash ALL / taproot DEFAULT only
    Srv->>Anchor: last transition TS_TRANSFER or TS_INFLATION (mint-RGB) —<br/>asset_output_amount (OS_ASSET only)<br/>≥ amount − commission
    Srv->>Anchor: fee sanity: implied fee rate ≤ 3x the<br/>enclave-fetched Esplora estimate, fail-closed<br/>(compile-time floor only on non-mainnet)
    Anchor-->>Srv: Ok / CrossCheck err

    Note over Srv: 3 — validate_route_proofs
    Srv->>Srv: source amount ≥ psbt_output_amount + commission

    Note over Srv,Rpc: 4 — independent FundsIn verification
    alt evm-rpc (or helios) build
        Srv->>Evt: verify_funds_in_event(pinned FUNDS_IN_CONTRACT,<br/>tx_hash, funds_in_operation_id, amount, commission)
        Evt->>Rpc: eth_getTransactionReceipt / eth_blockNumber
        Note right of Rpc: raw alloy path = host-relayed evidence<br/>Helios path = verified in-TEE vs pinned checkpoint —<br/>Helios sync failure fails closed, no raw fallback
        Rpc-->>Evt: receipt / head (or none)
        Evt->>Evt: receipt exists + status success
        Evt->>Evt: UNIQUE deposit event from the PINNED contract<br/>(FUNDS_IN_CONTRACT, else EVM_PROXY_CONTRACT_ADDRESS) —<br/>BridgeFundsIn preferred, same-tx FundsIn+BridgeFundsIn<br/>pair counts as ONE deposit
        Evt->>Evt: on-chain operationId (full 32-byte word) == funds_in_operation_id (NOT the hub's operation_idx) —<br/>gross == amount, commission bound,<br/>net == gross − commission — amount uint256 > u64 ⇒ REFUSE
        Evt->>Evt: depth ≥ EVM_MIN_CONFIRMATIONS (default 12) —<br/>receipt above head (reorg) ⇒ REFUSE
        Evt-->>Srv: Ok / CrossCheck err (fail closed)
    else no evm-rpc feature
        Srv->>Srv: REFUSE — deposit cannot be independently verified —<br/>rebuild with --features evm-rpc (or helios)
    end

    Note over Srv,State: 5 — soft replay guard
    Srv->>State: op_replay_guard.check_and_record(<br/>hash(chain_id, bridge_contract, evm_tx_hash,<br/>operation_idx, asset_id)) — 24 h TTL
    State-->>Srv: Ok / duplicate operation → REFUSE

    Note over Srv,Km: 6 — Sign PSBT inputs
    Srv->>Km: sign_psbt(psbt_bytes)
    Km->>Km: Psbt::deserialize(...)
    Note over Km: Two passes per input:<br/>1. Taproot script-path (Schnorr)<br/>2. SegWit v0 P2WSH (ECDSA)<br/>Skip if already signed.

    Note over Km,Tap: Taproot pass
    Km->>Tap: find_taproot_sign_jobs(psbt, fp, key_manager)
    loop each input
        Tap->>Tap: witness_utxo.script_pubkey.is_p2tr() ?
        Tap->>Tap: output_key := spk[2..34]
        loop (control_block, (script, leaf_version)) in tap_scripts
            Tap->>Crypto: control_block.verify_taproot_commitment(output_key, script)
            Note right of Tap: Anchor: rejects any leaf whose<br/>control block does not commit<br/>under the on-chain output_key.
            loop 32-byte PushBytes in script
                Tap->>Tap: tap_key_origins[xonly]?<br/>fp == master_fingerprint?<br/>leaf_hashes contains this leaf?
                Tap->>Tap: resolve_account_and_child_path(<br/>BIP-86 path)
                Tap->>Crypto: derive child secret,<br/>xonly(derived) == xonly_from_psbt
                alt all match
                    Tap->>Tap: emit TaprootSignJob
                end
            end
        end
    end
    Tap-->>Km: jobs

    alt jobs non-empty
        Km->>Km: sighash_cache (Prevouts::All)
        loop each TaprootSignJob
            Km->>Crypto: taproot_script_spend_signature_hash(<br/>input, prevouts, leaf, Default)
            Km->>Crypto: sign_schnorr_no_aux_rand(sighash, keypair)
            Km->>Km: insert tap_script_sigs[(xonly, leaf_hash)]
        end
    end

    Note over Km,Sw: SegWit v0 P2WSH pass
    loop each input
        Km->>Sw: should_sign_segwit_input(psbt, i, our_pubkey)
        Sw->>Sw: witness_utxo P2WSH present<br/>+ partial_sigs missing<br/>+ witness_script present
        Sw->>Sw: sha256(witness_script) ==<br/>witness_program in script_pubkey
        Sw->>Sw: our_pubkey appears as exact 33-byte<br/>PushBytes in witness_script
        Sw-->>Km: SignP2wsh / Skip
        alt SignP2wsh
            Km->>Crypto: p2wsh_signature_hash(i, ws, value, ALL)
            Km->>Crypto: secp.sign_ecdsa(sighash, sk)
            Km->>Km: insert partial_sigs[pubkey] = sig
        end
    end

    Km-->>Srv: (signed_psbt_bytes, inputs_signed)
    Srv->>Srv: reject inputs_signed == 0 (no-op not a contribution)
    Srv-->>Parent: SignedPsbtResponse
    Parent-->>Listener: gRPC Signature
    Listener-->>Orc: signed PSBT (assembles + broadcasts)
```

## FundsIn verification predicate (`networks::evm::evm_event`)

Bridge PSBT signing releases RGB against an EVM deposit. The listener-supplied
`event_valid` / `event_finalized` booleans are **not trusted**; the enclave establishes validity + finality itself, fail-closed:

1. **Receipt exists** for `evm_tx_hash` — `None` (not mined / host withheld) → refuse.
2. **Receipt status == success** — a reverted tx emits no real deposit event.
3. **Unique** deposit event from the **pinned** `FUNDS_IN_CONTRACT` (falls back
   to `EVM_PROXY_CONTRACT_ADDRESS` — address from config, never the request).
   `BridgeFundsIn` is preferred; a same-tx `FundsIn` + `BridgeFundsIn` pair is
   one deposit. Two real deposits in one tx are ambiguous → refuse.
4. **Field binding** — on-chain `operationId` == `funds_in_operation_id`
   (the bridge transfer id, **not** the hub's `operation_idx`). A
   `BridgeFundsIn` event additionally chain-binds gross `amount` and
   `tokenCommission` (`net == gross − commission`); the plain `FundsIn`
   fallback binds only `operationId` and the net amount, leaving the
   commission split listener-supplied. A `uint256` exceeding `u64` is
   rejected, not truncated.
5. **Confirmation depth** — `head − receipt.block` ≥ `EVM_MIN_CONFIRMATIONS`
   (default 12); a receipt block above head (reorg) → refuse.

**Provider selection (build/runtime):**
- No `evm-rpc` feature → bridge PSBT signing is **refused** (deposit unverifiable).
- `evm-rpc` → raw alloy JSON-RPC over the loopback vsock forwarder; responses are
  **host-relayed evidence**, verified fail-closed but not trustless.
- `helios` + `HELIOS_EXECUTION_RPC` set → the Helios light client verifies the
  execution/consensus RPCs against an operator-pinned checkpoint **inside the
  TEE** (trustless); `HELIOS_NETWORK` must be consistent with the pinned
  `EVM_CHAIN_ID`. A Helios init/sync failure fails closed — it never downgrades
  to the raw path. The selected source is part of the attested security policy
.

See [`10-signing-gate.md`](10-signing-gate.md) for the `fundsOut` (RGB → EVM) direction.
