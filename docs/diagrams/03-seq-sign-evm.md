# Sign (RGB → EVM unlock, `fundsOut`) — burn signer

The burn signer path. Step-by-step text: [burn flow](../burn-flow.md).

```mermaid
sequenceDiagram
    actor Orc as Orchestrator
    participant Listener as Go Listener
    participant Parent as utexo-bridge-parent<br/>(grpc_server.rs)
    participant Srv as enclave/server/sign.rs<br/>handle_sign
    participant Rgb as networks::rgb::validation<br/>RgbValidator
    participant Spv as networks::rgb::spv_crosscheck
    participant Chain as spv::HeaderChain
    participant Electrum as vsock_forwarder →<br/>Electrum
    participant Evm as networks::evm::validation
    participant Cx as networks::evm::crosscheck
    participant Sign as networks::evm::signing<br/>+ KeyManager

    Note over Orc,Listener: Intent
    Orc->>Listener: signing intent (op, calldata)
    Listener->>Listener: enrich (chain_id, proxy_contract, consignment, merkle_proofs)
    Listener->>Parent: gRPC ParentService.Sign(TRANSACTION, enriched payload)

    Note over Parent,Srv: Translate gRPC → enclave wire
    Parent->>Srv: Sign{source_network: RgbSource,<br/>destination_network: EvmDestination}<br/>(TCP/vsock, length-prefixed proto)

    opt always (burn signer)
        Srv->>Srv: bfa_burn_ancestry_events:<br/>derive the deposit id of each mint<br/>(no EVM RPC read)FORE RGB validation
    end

    Note over Srv,Electrum: 1 — validate_source (RGB)
    Srv->>Rgb: validate_source(RgbSource)
    Rgb->>Rgb: cheap payload gate first:<br/>consignment bytes present, size caps,<br/>keccak256(consignment) == consignment_hash (integrity),<br/>asset_id declared
    Rgb->>Rgb: Transfer::load(...), extract chain_net + witness_txids<br/>+ last transition + burned/total amounts
    Rgb->>Rgb: trusted typesystem pinned per schema_id,<br/>unknown schema ⇒ REFUSE
    Rgb->>Electrum: resolver (15 s timeout)
    Electrum-->>Rgb: witness tx data
    Rgb->>Rgb: rgb-ops validate(chain_net, trusted_typesystem)<br/>(bfa-mint: + Bridge transitions vs verified FundsIn locks)
    Rgb->>Rgb: contract_id == declared asset_id<br/>(== pinned RGB_ASSET_ID when configured)
    Rgb-->>Srv: ValidatedConsignment

    Note over Srv,Chain: SPV gate (inside validate_source, feature spv)
    Srv->>Chain: lock chain
    Srv->>Spv: assert_chain_not_stale (≤ 2 h old, ≤ 2 h future)
    Srv->>Spv: assert_chain_net(consignment, enclave network)
    Srv->>Spv: validate_spv_proofs(witness_txids, proofs)
    Spv->>Spv: exact set-equality(expected txids, proofs)
    loop each MerkleProofEntry
        Spv->>Spv: merkle path depth ≤ 32
        Spv->>Chain: header_at(block_height)
        Spv->>Spv: depth ≥ SPV_MIN_CONFIRMATIONS (6)
        Spv->>Spv: verify_merkle_proof(txid, position, path, root)
    end
    Spv->>Chain: pin each proof block (ChainPins)
    Spv-->>Srv: Ok / Spv err
    Srv->>Srv: source amount := TS_BURN MS_BURNED_ASSET<br/>(other last transition => REFUSE, host rgb_amount NOT used)

    Note over Srv,Evm: 2 — validate_destination (EVM)
    Srv->>Evm: validate_destination(EvmDestination)
    Evm->>Evm: calldata ≥ 4 bytes, ≤ 96 KiB
    Evm->>Evm: selector is fundsOut 0x340276aa or lzFundsOut
    Evm->>Evm: canonical ABI check: decode FundsOutParams,<br/>then re-encode must byte-equal input
    Evm->>Evm: decoded amount == declared calldata_amount (fits u64)
    Evm->>Evm: config pinned? chain_id / proxy_contract == env pins<br/>(unconfigured ⇒ REFUSE on bridge builds)
    Evm->>Evm: calldata destinationChainId:<br/>pools route == pinned chain, LZ route != pinned and > 0
    Evm->>Evm: deadline strictly in the future
    Evm-->>Srv: Ok / CrossCheck err

    Note over Srv: 3 — validate_route_proofs
    Srv->>Srv: source amount (consignment) ≥ destination amount

    Srv->>Srv: validate_rgb_source_identity (RGB source, both routes):<br/>calldata sourceChainId == 96 (RGB network id, compile-time constant)<br/>AND sourceAddress == "" (RGB has no source address)
    Srv->>Srv: validate_burn_id (both routes):<br/>calldata burnId == keccak(BURN_TYPEHASH, FUNDS_IN_CONTRACT, EVM_CHAIN_ID, TOKEN_CONTRACT,<br/>amount, sourceChainId, keccak(sourceAddress), sourceBurnTxId)
    Note over Srv,Cx: 4 — apply_funds_out_binding (both routes: fundsOut and lzFundsOut)
    Srv->>Cx: require validated consignment for any fundsOut
    Srv->>Cx: assert_witnesses_confirmed (no unmined witness tx)
    Srv->>Cx: verify_btc_relay_agreement (proof REQUIRED, empty => REFUSE):<br/>decode (sourceHeight, sourceCommit, latestHeight, latestCommit),<br/>enclave holds header at latestHeight,<br/>tip - latestHeight <= 100,<br/>sourceHeight == block anchoring the last witness tx<br/>(re-derived from the consignment + SPV proof under one lock),<br/>BTC_RELAY_MODE=required: sourceCommit, latestCommit == keccak256 of the relay record the enclave rebuilds (zero word => REFUSE),<br/>BTC_RELAY_MODE=none (local stand, never production): both words must be zero
    Srv->>Cx: validate_funds_out_amount:<br/>last transition == TS_BURN AND<br/>burned amount == calldata amount
    Srv->>Cx: validate_funds_out_source_burn_tx_id:<br/>calldata sourceBurnTxId == last transition OpId (non-zero)
    Srv->>Cx: validate_funds_out_burn_recipient:<br/>MS_BURN_RECIPIENT[12..] == calldata recipient
    Srv->>Cx: validate_funds_out_settlement:<br/>settlementData (operationIds, netAmounts) ==<br/>BridgeFundsIn records of the verified ancestry locks,<br/>set equality, canonical, non-empty
    Note right of Cx: LayerZero route: recipient = the LayerZero recipient.<br/>dstEid is NOT bound to the burn (spec Sec 13).
    Cx-->>Srv: Ok / CrossCheck err

    Note over Srv,Sign: 5 — Sign
    Srv->>Sign: build_evm_domain(chain_id, proxy_contract)<br/>name "MultisigProxy", version "1"<br/>(pinned by contract-fixture test)
    alt lzFundsOut selector AND lz_release present
        Srv->>Sign: lz_funds_out_digest: request lz_release<br/>(dst_eid, min_amount_ld, recipient) must match decoded calldata
        Sign->>Sign: structHash TeeLzFundsOut(12 decoded fields + nonce, deadline)
    else pools fundsOut
        Srv->>Sign: funds_out_digest(decoded FundsOutParams, nonce, deadline)
        Sign->>Sign: structHash TeeFundsOut(9 decoded fields + nonce, deadline)
    end
    Sign->>Sign: digest = keccak256(0x1901 || domSep || structHash)
    Srv->>Chain: assert_chain_pins_unchanged<br/>(pinned SPV blocks still in the chain, else REFUSE)
    Sign->>Sign: k256 ECDSA sign_prehash_recoverable (r‖s‖v)
    Sign-->>Srv: signature (65 bytes)

    Srv-->>Parent: EvmSignatureResponse{signature, call_data echoed unchanged}
    Parent-->>Listener: gRPC Signature
    Listener-->>Orc: signed (relays to MultisigProxy)
```

The on-chain quorum (`MultisigProxy` M-of-N) and nonce consumption are the
authoritative replay guards for this direction; the enclave commits `nonce`
and `deadline` into the digest but keeps no fundsOut nonce state.
