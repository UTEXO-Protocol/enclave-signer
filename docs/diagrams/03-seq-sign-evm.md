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
    participant Esplora as vsock_forwarder →<br/>Esplora
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
    Rgb->>Rgb: cheap payload gate first:<br/>consignment bytes present,<br/>keccak256(consignment) == consignment_hash (integrity),<br/>asset_id declared
    Rgb->>Rgb: Transfer::load(...), extract chain_net + witness_txids<br/>+ last transition + burned/total amounts
    Rgb->>Rgb: trusted typesystem pinned per schema_id,<br/>unknown schema ⇒ REFUSE
    Rgb->>Esplora: esplora_blocking (30 s timeout)
    Esplora-->>Rgb: witness tx data
    Rgb->>Rgb: rgbstd validate(chain_net, trusted_typesystem)
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
    Evm->>Evm: selector == 0xccddb768<br/>fundsOut(address,uint256,uint256,uint256,uint256,string,bytes,bytes)
    Evm->>Evm: canonical ABI check: abi_decode_validate,<br/>then re-encode must byte-equal input
    Evm->>Evm: decoded amount == declared calldata_amount (fits u64)
    Evm->>Evm: config pinned? chain_id / proxy_contract == env pins<br/>(unconfigured ⇒ REFUSE on bridge builds)
    Evm->>Evm: deadline strictly in the future
    Evm-->>Srv: Ok / CrossCheck err

    Note over Srv: 3 — validate_route_proofs
    Srv->>Srv: source amount (consignment) ≥ destination amount

    Note over Srv,Cx: 4 — apply_funds_out_binding (rgb-validation builds)
    Srv->>Cx: require validated consignment for any fundsOut
    Srv->>Cx: assert_witnesses_confirmed (no unmined witness tx)
    opt calldata proof slot populated
        Srv->>Cx: verify_btc_relay_agreement:<br/>decode (blockHeight, commitmentHash),<br/>enclave header at that height must match<br/>(inert while the listener sends an empty proof)
    end
    Srv->>Cx: validate_funds_out_amount:<br/>last transition == the build flow's unlock shape AND<br/>consignment-derived amount ≥ amount read from calldata bytes
    Note right of Cx: burnId / fundsInIds are preserved as received —<br/>the in-enclave OpId rewrite exists but is dormant<br/>until flows are routed by network id.
    Cx-->>Srv: Ok / CrossCheck err

    Note over Srv,Sign: 5 — Sign
    Srv->>Sign: build_evm_domain(chain_id, proxy_contract)<br/>name "MultisigProxy", version "1"<br/>(pinned by contract-fixture test)
    Srv->>Sign: sign_request_digest(domain, calldata, nonce, deadline)
    Sign->>Sign: digest = keccak256(0x1901 ‖ domSep ‖<br/>structHash BridgeOperation(selector, callData, nonce, deadline))
    Sign->>Sign: k256 ECDSA sign_prehash_recoverable (r‖s‖v)
    Sign-->>Srv: signature (65 bytes)

    Srv-->>Parent: EvmSignatureResponse{signature, call_data}
    Parent-->>Listener: gRPC Signature
    Listener-->>Orc: signed (relays to MultisigProxy)
```

The on-chain quorum (`MultisigProxy` M-of-N) and nonce consumption are the
authoritative replay guards for this direction; the enclave commits `nonce`
and `deadline` into the digest but keeps no fundsOut nonce state.
