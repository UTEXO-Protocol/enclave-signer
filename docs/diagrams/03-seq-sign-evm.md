# Sign (RGB → EVM unlock, `fundsOut`) — full path with cross-checks

```mermaid
sequenceDiagram
    actor Orc as Orchestrator
    participant Listener as Go Listener
    participant Parent as utexo-bridge-parent<br/>(grpc_server.rs)
    participant Srv as enclave/server.rs<br/>handle_sign
    participant Rgb as networks::rgb::validation<br/>RgbValidator
    participant Spv as networks::rgb::spv_validation
    participant Chain as spv::HeaderChain
    participant Esplora as vsock_forwarder →<br/>Electrum / Esplora
    participant Evm as networks::evm::validation
    participant Cx as networks::evm::crosscheck
    participant Sign as networks::evm::signing<br/>+ KeyManager

    Note over Orc,Listener: Intent
    Orc->>Listener: signing intent (op, calldata)
    Listener->>Listener: enrich (chain_id, proxy_contract, consignment, merkle_proofs)
    Listener->>Parent: gRPC ParentService.Sign(TRANSACTION, enriched payload)

    Note over Parent,Srv: Translate gRPC → enclave wire
    Parent->>Srv: Sign{source_network: RgbSource,<br/>destination_network: EvmDestination}<br/>(TCP/vsock, length-prefixed proto)

    Note over Srv,Esplora: 1 — validate_source (RGB, skipped under dev-mode)
    Srv->>Rgb: validate_source(RgbSource)
    Rgb->>Rgb: cheap payload gate first:<br/>consignment bytes present, size caps,<br/>keccak256(consignment) == consignment_hash (integrity),<br/>asset_id declared
    Rgb->>Rgb: Transfer::load(...), extract chain_net + witness_txids<br/>+ last transition + burned/total amounts
    Rgb->>Rgb: trusted typesystem pinned per schema_id,<br/>unknown schema ⇒ REFUSE
    Rgb->>Esplora: resolver (Electrum 15 s / Esplora 30 s timeout)
    Esplora-->>Rgb: witness tx data
    Rgb->>Rgb: rgb-ops validate(chain_net, trusted_typesystem)<br/>(bfa-mint: + Bridge transitions vs verified FundsIn locks)
    Rgb->>Rgb: contract_id == declared asset_id<br/>(== pinned RGB_ASSET_ID when configured)
    Rgb-->>Srv: SourceProof (amount from consignment, per build flow —<br/>rgb-swap ⇒ TS_TRANSFER total_output /<br/>rgb-mint-burn ⇒ TS_BURN burned amount —<br/>host rgb_amount is NOT used)

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
    Spv-->>Srv: Ok / Spv err

    Note over Srv,Evm: 2 — validate_destination (EVM, skipped under dev-mode)
    Srv->>Evm: validate_destination(EvmDestination)
    Evm->>Evm: calldata ≥ 4 bytes, ≤ 64 KiB
    Evm->>Evm: selector is fundsOut 0xdc771390 or lzFundsOut
    Evm->>Evm: canonical ABI check: decode FundsOutParams,<br/>then re-encode must byte-equal input
    Evm->>Evm: decoded amount == declared calldata_amount (fits u64)
    Evm->>Evm: config pinned? chain_id / proxy_contract == env pins<br/>(unconfigured ⇒ REFUSE on bridge builds)
    Evm->>Evm: calldata destinationChainId:<br/>pools route == pinned chain, LZ route != pinned and > 0
    Evm->>Evm: deadline strictly in the future
    Evm-->>Srv: Ok / CrossCheck err

    Note over Srv: 3 — validate_route_proofs
    Srv->>Srv: source amount (consignment) ≥ destination amount

    Note over Srv,Cx: 4 — apply_funds_out_binding (rgb-validation builds)
    Srv->>Cx: require validated consignment for any fundsOut
    Srv->>Cx: assert_witnesses_confirmed (no unmined witness tx)
    Srv->>Cx: verify_btc_relay_agreement (proof REQUIRED, empty ⇒ REFUSE):<br/>decode (sourceHeight, sourceCommit, latestHeight, latestCommit),<br/>enclave holds header at latestHeight,<br/>tip − latestHeight ≤ 100,<br/>sourceHeight == block anchoring the last witness tx<br/>(re-derived from the consignment + SPV proof under one lock)
    Srv->>Cx: validate_funds_out_amount:<br/>last transition == the build flow's unlock shape AND<br/>consignment-derived amount ≥ decoded calldata amount
    opt rgb-mint-burn build
        Srv->>Cx: validate_funds_out_burn_recipient:<br/>MS_BURN_RECIPIENT[12..] == calldata recipient
    end
    Note right of Cx: burnId / settlementData are signed as received —<br/>no in-enclave OpId derivation exists (spec P6).<br/>commitmentHash words are relay-internal, not compared.
    Cx-->>Srv: Ok / CrossCheck err

    Note over Srv,Sign: 5 — Sign
    Srv->>Sign: build_evm_domain(chain_id, proxy_contract)<br/>name "MultisigProxy", version "1"<br/>(pinned by contract-fixture test)
    alt lzFundsOut selector AND lz_release present
        Srv->>Sign: lz_funds_out_digest: request lz_release<br/>(dst_eid, min_amount_ld, recipient) must match decoded calldata
        Sign->>Sign: structHash TeeLzFundsOut(13 decoded fields + nonce, deadline)
    else pools fundsOut
        Srv->>Sign: funds_out_digest(decoded FundsOutParams, nonce, deadline)
        Sign->>Sign: structHash TeeFundsOut(10 decoded fields)
    end
    Sign->>Sign: digest = keccak256(0x1901 ‖ domSep ‖ structHash)
    Sign->>Sign: k256 ECDSA sign_prehash_recoverable (r‖s‖v)
    Sign-->>Srv: signature (65 bytes)

    Srv-->>Parent: EvmSignatureResponse{signature, call_data echoed unchanged}
    Parent-->>Listener: gRPC Signature
    Listener-->>Orc: signed (relays to MultisigProxy)
```

The on-chain quorum (`MultisigProxy` M-of-N) and nonce consumption are the
authoritative replay guards for this direction; the enclave commits `nonce`
and `deadline` into the digest but keeps no fundsOut nonce state.
