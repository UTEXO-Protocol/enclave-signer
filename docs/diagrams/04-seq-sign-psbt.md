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
denominated in RGB asset units and says nothing about sats. Because signing is
account-scoped, only the taproot pass runs here; the legacy SegWit v0 P2WSH
pass exists only for the unscoped CLI `sign_psbt` path.

```mermaid
sequenceDiagram
    actor Orc as Orchestrator
    participant Listener as Go Listener
    participant Parent as utexo-bridge-parent<br/>(grpc_server.rs)
    participant Srv as enclave/server.rs<br/>handle_sign
    participant Evm as networks::evm::validation
    participant Evt as networks::evm::evm_event
    participant Rpc as EVM RPC<br/>loopback→vsock→host
    participant Rgb as networks::rgb<br/>(rgb-ops + Electrum/Esplora + SPV)
    participant Anchor as networks::rgb::psbt_validation
    participant Inv as networks::rgb::invoice
    participant State as EnclaveState<br/>op_replay_guard
    participant Km as KeyManager::sign_psbt
    participant Tap as signing::taproot<br/>find_taproot_sign_jobs
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
    Srv->>Rgb: validate_consignment (cheap hash + size gate first, then<br/>rgb-ops + resolver + typesystem pin)
    Rgb-->>Srv: ValidatedConsignment / REFUSE
    Srv->>Anchor: keccak256(consignment) == consignment_hash (integrity)
    Srv->>Anchor: asset pin: declared asset_id == validated contract_id<br/>== pinned RGB_ASSET_ID (unconditional on this path)
    Srv->>Anchor: PSBT unsigned txid == last witness txid —<br/>input prevouts == witness prevouts —<br/>sighash ALL / taproot DEFAULT only
    Srv->>Anchor: every transition the PSBT commits to is the build flow's deposit shape:<br/>rgb-swap ⇒ TS_TRANSFER, group asset_output_amount ≥ amount − commission<br/>rgb-mint-burn ⇒ TS_INFLATION (or TS_BRIDGE with bfa-mint),<br/>group asset_output_amount == amount − commission<br/>(OS_ASSET only - OS_INFLATION allowance excluded)
    Srv->>Anchor: split OS_ASSET outputs into legs:<br/>confidential seal ⇒ recipient leg -<br/>revealed seal ⇒ must be self-owned (script == a co-signed input,<br/>≤ 4 off-PSBT change outpoints) else REFUSE -<br/>sum(recipient legs) == amount − commission exactly
    Srv->>Anchor: fee sanity: implied fee rate ≤ 3x the<br/>enclave-fetched estimate, fail-closed<br/>(compile-time floor only on non-mainnet)
    Anchor-->>Srv: Ok / CrossCheck err (destination amount = recipient-leg total)

    Note over Srv: 3 — validate_route_proofs
    Srv->>Srv: source amount ≥ enclave-derived recipient total + commission

    Note over Srv,Rpc: 4 — independent FundsIn verification
    alt evm-rpc build
        Srv->>Evt: verify_funds_in_event(pinned FUNDS_IN_CONTRACT,<br/>tx_hash, funds_in_operation_id, amount, commission)
        Evt->>Rpc: eth_getTransactionReceipt / eth_blockNumber
        Note right of Rpc: host-relayed evidence —<br/>verified fail-closed, not trustless
        Rpc-->>Evt: receipt / head (or none)
        Evt->>Evt: receipt exists + status success
        Evt->>Evt: exactly ONE BridgeFundsIn from the PINNED contract<br/>(FUNDS_IN_CONTRACT, else EVM_PROXY_CONTRACT_ADDRESS) —<br/>zero or two ⇒ REFUSE - no plain FundsIn fallback
        Evt->>Evt: topic1 operationId == funds_in_operation_id (NOT the hub's operation_idx) —<br/>gross == amount, tokenCommission == commission,<br/>netAmount ≤ gross − commission — uint256 > u64 ⇒ REFUSE
        Evt->>Evt: depth ≥ EVM_MIN_CONFIRMATIONS (default 12) —<br/>receipt above head (reorg) ⇒ REFUSE
        Evt-->>Srv: VerifiedFundsIn{destination_address} / CrossCheck err (fail closed)
        Srv->>Inv: parse_authorized_recipient(destination_address):<br/>RgbInvoice, blinded-seal beneficiary only
        Srv->>Inv: assert_recipient_authorized:<br/>exactly one confidential leg AND it == invoice seal
        Inv-->>Srv: Ok / CrossCheck err
    else no evm-rpc feature
        Srv->>Srv: REFUSE — deposit cannot be independently verified —<br/>rebuild with --features evm-rpc
    end

    Note over Srv,State: 5 — soft replay guard
    Srv->>State: op_replay_guard.reserve(<br/>hash(chain_id, bridge_contract, evm_tx_hash,<br/>funds_in_operation_id, asset_id)) — 24 h TTL,<br/>committed only after signing succeeds
    State-->>Srv: Ok / duplicate operation → REFUSE

    Note over Srv,Km: 6 — Sign PSBT inputs
    Srv->>Srv: validate_rgb_psbt_sats: unowned output sats ≤ RGB_MAX_UNOWNED_SATS
    Srv->>Km: sign_psbt_scoped(psbt_bytes, AccountType::Colored)
    Km->>Km: Psbt::deserialize(...)
    Note over Km: Taproot script-path (Schnorr) only —<br/>jobs on the vanilla account are dropped,<br/>the legacy P2WSH pass is skipped on a scoped call.

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
3. **Exactly one** `BridgeFundsIn` event from the **pinned** `FUNDS_IN_CONTRACT`
   (falls back to `EVM_PROXY_CONTRACT_ADDRESS` — address from config, never the
   request). Zero or two → refuse. The plain `FundsIn` event is never used
   here: it carries an RGB OpId, a different id space.
4. **Field binding** — topic-1 `operationId` == `funds_in_operation_id`
   (the bridge transfer id, **not** the hub's `operation_idx`); gross
   `amount` == request amount; `tokenCommission` == request commission;
   `netAmount` ≤ `gross − commission` (lower is tolerated with a warning for
   fee-on-transfer tokens). A `uint256` exceeding `u64` is rejected, not
   truncated.
5. **Confirmation depth** — `head − receipt.block` ≥ `EVM_MIN_CONFIRMATIONS`
   (default 12); a receipt block above head (reorg) → refuse.
6. **Recipient** — the event's `destinationAddress` is parsed as an RGB
   invoice (blinded-seal beneficiary only) and the consignment's single
   confidential recipient leg must equal that seal.

**Provider selection (build/runtime):**
- No `evm-rpc` feature → bridge PSBT signing is **refused** (deposit unverifiable).
- `evm-rpc` → raw alloy JSON-RPC over the loopback vsock forwarder; responses are
  **host-relayed evidence**, verified fail-closed but not trustless.
- The selected source is part of the attested security policy.

See [`10-signing-gate.md`](10-signing-gate.md) for the `fundsOut` (RGB → EVM) direction.
