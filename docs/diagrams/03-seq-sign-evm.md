# Sign (RGB → EVM unlock, `fundsOut`) — burn signer

The burn signer path. Step-by-step text: [burn flow](../burn-flow.md).

```mermaid
sequenceDiagram
    actor Orc as Orchestrator
    participant Listener as Go Listener
    participant Parent as utexo-bridge-parent<br/>(grpc_server.rs)
    participant Srv as enclave/server/sign.rs<br/>handle_sign
    participant Rgb as networks::rgb::validation<br/>RgbValidator
    participant Child as validator child<br/>(validation::child, this binary)
    participant Spv as networks::rgb::spv_crosscheck
    participant Chain as spv::HeaderChain
    participant Bind as server::bfa<br/>derived_locks
    participant Evm as networks::evm::validation
    participant Cx as networks::evm::crosscheck
    participant Sign as networks::evm::signing<br/>+ KeyManager

    Note over Orc,Listener: Intent
    Orc->>Listener: signing intent (op, calldata)
    Listener->>Listener: enrich (chain_id, proxy_contract, consignment with its SPV proofs)
    Listener->>Parent: gRPC ParentService.Sign(TRANSACTION, enriched payload)

    Note over Parent,Srv: Translate gRPC → enclave wire
    Parent->>Srv: Sign{source_network: RgbSource,<br/>destination_network: EvmDestination}<br/>(TCP/vsock, length-prefixed proto)
    Srv->>Srv: signer role, key ready (else KeyNotInitialized,<br/>before any validation)

    Note over Srv,Bind: 1 - validate_source (RGB), no network call but the reject list
    Srv->>Rgb: validate_source(RgbSource)
    Rgb->>Rgb: cheap payload gate first:<br/>consignment bytes present, size caps,<br/>keccak256(consignment) == consignment_hash (integrity),<br/>asset_id declared
    Rgb->>Rgb: one safe height read, kill time = deadline - RESPONSE_MARGIN<br/>(passed => REFUSE, no child), consignment to a scratch file
    Rgb->>Child: spawn this binary --rgb-validator: no environment,<br/>fd 0 = socket pair, Start{limits in force, file path, chain, safe height}
    Note over Rgb,Child: every read and write on the socket stops at the kill time.<br/>A refused question: the enclave keeps its error, the child ends held.
    Child->>Child: Transfer::load (V1 TFR only),<br/>genesis schema BFA
    Child->>Rgb: BindAsset(contract_id), the first question
    Rgb->>Rgb: asset bind: contract_id == declared asset_id<br/>(== pinned RGB_ASSET_ID when configured)
    Rgb-->>Child: AssetBound
    Child->>Child: reject list, if the genesis names one, must be an EVM contract
    Child->>Child: work caps (cost.rs): witness checks, bundle ids,<br/>reject walk (listed asset only),<br/>then their modeled time with the file,<br/>validation and inspection together
    Child->>Child: one rgb-lib validate_consignment_with_resolver:<br/>phase 1 under the BFA rules, phase 2 through three resolvers
    Child->>Rgb: anchor resolver: Anchors once with no anchor,<br/>then once per mint anchor
    Rgb->>Bind: AnchorBinder
    Bind->>Bind: per anchor: derived lock = rgb_mint_deposit_id<br/>(lockId(mint OpId, witness txid), minted units, no EVM RPC read)
    Bind-->>Rgb: BoundAnchors (one lock per anchor)
    Rgb-->>Child: Bound (EVM_CHAIN_ID, the locks)
    Child->>Child: rgb-ops: genesis bridgeLocation chain == the resolver's EVM_CHAIN_ID
    Child->>Child: witness resolver: chain_net == enclave network, else REFUSE
    Child->>Rgb: Header(height) for each witness with a proof
    Rgb->>Spv: buried_header(height) under a short chain lock,<br/>not above the safe height, only at depth ≥ SPV_MIN_CONFIRMATIONS,<br/>else REFUSE
    Rgb-->>Child: the 80-byte header
    Child->>Child: no transaction lookup: a witness is Mined(height) only when<br/>the SPV proof in the consignment holds against that header
    opt genesis names a reject list
        Child->>Rgb: RejectList(chain id, address), once, after the asset bind
        Rgb->>Srv: reject-list resolver: list on EVM_CHAIN_ID, eth_chainId == EVM_CHAIN_ID,<br/>length() at finalized and latest, entries pages at latest
        Rgb-->>Child: Decisions
        Child->>Child: rgb-lib: an input or output of a terminal operation<br/>reaches a rejected opout before an allowed one => REFUSE
    end
    Child->>Child: the bound locks are the anchors, one for one
    Child->>Child: rgb-lib inspect_consignment(Terminals) on the same file:<br/>the flat summary of the terminal bundles
    Child->>Child: settling transition (their one burn):<br/>burnedAsset, burnReason, OpId
    Child-->>Rgb: Verdict: Validated, Refused or held
    Rgb->>Child: SIGKILL and reap after the verdict, the end of the socket,<br/>the kill time or a broken protocol, then remove the scratch file
    Rgb->>Rgb: the kept enclave error first, else the verdict:<br/>bound contract, chain, witness blocks sorted and not above the safe height,<br/>settling witness among them (else REFUSE)
    Rgb-->>Srv: ValidatedConsignment

    Note over Srv,Chain: SPV gate (inside validate_source)
    Srv->>Chain: lock chain
    Srv->>Spv: assert_chain_not_stale: tip<br/>≤ 2 h old, ≤ 2 h future
    loop each witness block of the validated consignment
        Spv->>Chain: header_at(height): the header the proof was checked against
        Spv->>Spv: depth ≥ SPV_MIN_CONFIRMATIONS (attested)
    end
    Spv->>Chain: pin each witness block (ChainPins)
    Spv-->>Srv: Ok / Spv err
    Srv->>Srv: source amount := TS_BURN burnedAsset<br/>(other settling transition => REFUSE, host rgb_amount NOT used)

    Note over Srv,Evm: 2 — validate_destination (EVM)
    Srv->>Evm: validate_destination(EvmDestination)
    Evm->>Evm: calldata ≥ 4 bytes, ≤ max_funds_out_call_data_bytes
    Evm->>Evm: selector is fundsOut 0x340276aa or lzFundsOut
    Evm->>Evm: lz_release present only with lzFundsOut, else REFUSE
    Evm->>Evm: canonical ABI check: decode FundsOutParams,<br/>then re-encode must byte-equal input
    Evm->>Evm: lzFundsOut only: 1 ≤ minAmountLD ≤ amount,<br/>extraOptions empty or one lzReceive gas option,<br/>no value, gas ≤ MAX_LZ_RECEIVE_GAS
    Evm->>Evm: decoded amount == declared calldata_amount (fits u64)
    Evm->>Evm: config pinned? chain_id / proxy_contract == env pins<br/>(unconfigured ⇒ REFUSE on bridge builds)
    Evm->>Evm: calldata destinationChainId:<br/>direct route == pinned chain, LZ route != pinned and > 0
    Evm->>Evm: deadline after now and ≤ now + MAX_TEE_DEADLINE_SECS
    Evm-->>Srv: Ok / CrossCheck err

    Note over Srv: 3 — validate_route_proofs
    Srv->>Srv: source amount (consignment) ≥ destination amount

    Srv->>Srv: validate_rgb_source_identity (RGB source, both routes):<br/>calldata sourceChainId == 827166 (RGB network id, compile-time constant)<br/>AND sourceAddress == "" (RGB has no source address)
    Srv->>Srv: validate_burn_id (both routes):<br/>calldata burnId == keccak(BURN_TYPEHASH, FUNDS_IN_CONTRACT, EVM_CHAIN_ID, TOKEN_CONTRACT,<br/>amount, sourceChainId, keccak(sourceAddress), sourceBurnTxId)
    Note over Srv,Cx: 4 — apply_funds_out_binding (both routes: fundsOut and lzFundsOut)
    Srv->>Cx: require validated consignment for any fundsOut
    Srv->>Cx: assert_witnesses_confirmed (no unmined witness tx)
    Srv->>Cx: verify_btc_relay_agreement (proof REQUIRED, empty => REFUSE):<br/>decode (sourceHeight, sourceCommit, latestHeight, latestCommit),<br/>latestHeight ≥ sourceHeight,<br/>enclave holds header at latestHeight,<br/>tip - latestHeight <= MAX_RELAY_TIP_LAG_BLOCKS,<br/>sourceHeight == block anchoring the settling burn's witness tx<br/>(the block validation placed it in, confirmed under one lock),<br/>BTC_RELAY_MODE=required: sourceCommit, latestCommit == keccak256 of the relay record the enclave rebuilds (zero word => REFUSE),<br/>BTC_RELAY_MODE=none (local stand or public-Signet image, never production): both words must be zero
    Srv->>Cx: validate_funds_out_amount:<br/>settling transition == TS_BURN AND<br/>burned amount == calldata amount
    Srv->>Cx: validate_funds_out_source_burn_tx_id:<br/>calldata sourceBurnTxId == settling transition OpId (non-zero)
    Srv->>Cx: validate_funds_out_burn_recipient:<br/>burn_destination::resolve(burnReason, record)<br/>V0: burnReason[12..] == calldata recipient, direct only<br/>V1: hash_v1(record) == burnReason, then<br/>destinationChainId, dstEid, recipient == record
    Srv->>Cx: validate_funds_out_settlement:<br/>settlementData operationIds ==<br/>BridgeFundsIn records of the verified ancestry locks,<br/>set equality, canonical, non-empty
    Note right of Cx: LayerZero route: recipient = the LayerZero recipient.<br/>Only a V1 burn can leave via LayerZero.
    Cx-->>Srv: Ok / CrossCheck err

    Note over Srv,Sign: 5 — Sign
    Srv->>Sign: build_evm_domain(chain_id, proxy_contract)<br/>name "MultisigProxy", version "1"<br/>(pinned by contract-fixture test)
    alt lzFundsOut selector AND lz_release present
        Srv->>Sign: lz_funds_out_digest: request lz_release<br/>(dst_eid, min_amount_ld, recipient) must match decoded calldata
        Sign->>Sign: structHash TeeLzFundsOut(12 decoded fields + nonce, deadline)
    else direct fundsOut
        Srv->>Sign: funds_out_digest(decoded FundsOutParams, nonce, deadline)
        Sign->>Sign: structHash TeeFundsOut(9 decoded fields + nonce, deadline)
    end
    Sign->>Sign: digest = keccak256(0x1901 || domSep || structHash)
    Srv->>Chain: sign_with_chain_pins_unchanged<br/>(lock chain, pinned SPV blocks still in the chain<br/>and as deep as their check required, else REFUSE)
    Sign->>Sign: k256 ECDSA sign_prehash_recoverable (r‖s‖v)
    Sign-->>Srv: signature (65 bytes)
    Srv->>Chain: release chain lock

    Srv-->>Parent: EvmSignatureResponse{signature, call_data echoed unchanged}
    Parent-->>Listener: gRPC Signature
    Listener-->>Orc: signed (relays to MultisigProxy)
```

The on-chain quorum (`MultisigProxy` M-of-N) and nonce consumption are the
authoritative replay guards for this direction; the enclave commits `nonce`
and `deadline` into the digest but keeps no fundsOut nonce state.
