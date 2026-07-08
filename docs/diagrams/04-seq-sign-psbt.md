# Sign PSBT (EVM → RGB lock) — taproot + segwit-v0, anchored authorisation

```mermaid
sequenceDiagram
    actor Orc as Orchestrator
    participant Listener as Go Listener
    participant Parent as utexo-bridge-parent<br/>(grpc_server.rs)
    participant Srv as enclave/server.rs<br/>handle_sign_psbt
    participant PsbtCx as validation::psbt_crosscheck
    participant Rgb as validation::rgb<br/>(rgbstd + Esplora + SPV)
    participant Evt as validation::evm_event
    participant Rpc as EVM RPC / Helios<br/>loopback→vsock→host
    participant State as EnclaveState<br/>op_replay_guard
    participant Km as KeyManager::sign_psbt
    participant Tap as signing::taproot<br/>find_taproot_sign_jobs
    participant Sw as signing::psbt<br/>should_sign_segwit_input
    participant Crypto as secp256k1 / k256

    Note over Orc,Listener: Intent
    Orc->>Listener: bridge intent (FundsIn deposit observed on EVM)
    Listener->>Listener: fetch PSBT from rgb-multisig-bridge,<br/>enrich with EVM event fields + RGB consignment
    Listener->>Parent: gRPC Sign(TRANSACTION, EnrichedPsbtPayload)

    Note over Parent,Srv: Translate
    Parent->>Srv: SignPsbtRequest (psbt_bytes, evm_tx_hash, operation_idx,<br/>amounts, consignment, ...)

    Note over Srv,PsbtCx: Shape + amount cross-checks (skipped in dev-mode)
    Srv->>PsbtCx: validate_psbt_request(req)
    PsbtCx->>PsbtCx: PSBT shape whitelist (#40):<br/>psbt_bytes non-empty,<br/>Psbt::deserialize ok,<br/>unsigned tx has ≥ 1 input
    alt evm_tx_hash empty (vanilla, e.g. create_utxo)
        PsbtCx-->>Srv: Ok — only psbt_bytes required, skip bridge checks
    else bridge mode
        PsbtCx->>PsbtCx: len(evm_tx_hash) == 32
        Note right of PsbtCx: listener evm_event_valid /<br/>evm_event_finalized are IGNORED (#51) —<br/>validity/finality established below, not trusted
        PsbtCx->>PsbtCx: evm_amount ≥ psbt_output_amount + evm_commission
    end
    PsbtCx-->>Srv: Ok / CrossCheck err

    Note over Srv,State: Bridge-mode authorisation (bridge mode only)
    opt rgb-validation build — send-RGB consignment binding (#79)
        Srv->>Rgb: psbt_consignment_crosscheck: validate_consignment<br/>(rgbstd + Esplora resolver + SPV anchoring)
        Rgb-->>Srv: ValidatedConsignment / REFUSE
        Srv->>Srv: keccak256(consignment)==consignment_hash<br/>contract_id==pinned RGB_ASSET_ID<br/>unsigned txid==last TS_TRANSFER witness txid<br/>input prevouts match, sighash ALL/DEFAULT<br/>total_output ≥ evm_amount − evm_commission
    end
    alt evm-rpc build — independent FundsIn verification (M-06 / #60, #77)
        Srv->>Evt: verify_funds_in_event(PINNED contract, EVM_MIN_CONFIRMATIONS,<br/>tx_hash, operation_id, evm_amount, evm_commission)
        Evt->>Rpc: eth_getTransactionReceipt / eth_blockNumber
        Note right of Rpc: raw alloy path = host-relayed evidence (#60)<br/>Helios path = cryptographically verified in-TEE (#77)
        Rpc-->>Evt: receipt / head (or none)
        Evt->>Evt: receipt exists + status success<br/>UNIQUE FundsIn/BridgeFundsIn log from PINNED contract<br/>operationId/amount/commission bind (net==gross−commission)<br/>depth ≥ EVM_MIN_CONFIRMATIONS
        Evt-->>Srv: Ok / CrossCheck err (fail closed)
    else no evm-rpc feature (bridge mode)
        Srv->>Srv: REFUSE — deposit cannot be independently verified<br/>rebuild with --features evm-rpc (or helios)
    end
    opt bridge mode — soft replay guard (#84)
        Srv->>State: op_replay_guard.check_and_record(op_key)
        State-->>Srv: Ok / duplicate operation → REFUSE
    end

    Note over Srv,Km: Sign PSBT inputs
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
    Srv->>Srv: reject inputs_signed == 0 (#85, no-op not a contribution)
    Srv-->>Parent: SignedPsbtResponse
    Parent-->>Listener: gRPC Signature
    Listener-->>Orc: signed PSBT (assembles + broadcasts)
```

## FundsIn verification predicate (`validation::evm_event`, #60 / #77)

Bridge-mode `signPsbt` releases RGB against an EVM deposit. The listener-supplied
`evm_event_valid` / `evm_event_finalized` booleans are **no longer trusted** (audit
M-06 / #51); the enclave establishes validity + finality itself, fail-closed:

1. **Receipt exists** for `evm_tx_hash` — `None` (not mined / host withheld) → refuse.
2. **Receipt status == success** — a reverted tx emits no real `FundsIn`.
3. **Unique** `FundsIn` / `BridgeFundsIn` log from the **pinned** `BRIDGE_CONTRACT`
   (address from config, never the request); multiple matches are ambiguous → refuse.
4. **Field binding** — decoded `operationId` (== `operation_idx`), gross `amount`
   (== `evm_amount`), `tokenCommission` (== `evm_commission`), and the internal
   `net == gross − commission`. A `uint256` exceeding `u64` is rejected, not truncated.
5. **Confirmation depth** — `head − receipt.block` ≥ `EVM_MIN_CONFIRMATIONS`
   (default 12); a receipt block above head (reorg) → refuse.

**Provider selection (build/runtime):**
- No `evm-rpc` feature → bridge-mode `signPsbt` is **refused** (deposit unverifiable).
- `evm-rpc` → raw alloy JSON-RPC over the loopback vsock forwarder; responses are
  **host-relayed evidence**, verified fail-closed but not trustless.
- `helios` + `HELIOS_EXECUTION_RPC` set → the a16z Helios light client verifies the
  execution/consensus RPCs against a pinned checkpoint **inside the TEE** (trustless);
  `HELIOS_NETWORK` must be consistent with the pinned `EVM_CHAIN_ID`.

See [`10-signing-gate.md`](10-signing-gate.md) for the `fundsOut` (RGB → EVM) direction.
```
