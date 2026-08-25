# SubmitHeaders — Listener-driven SPV chain sync

```mermaid
sequenceDiagram
    participant Listener as Go Listener
    participant Esplora as Esplora API
    participant Parent as utexo-bridge-parent<br/>grpc_server.rs
    participant Srv as enclave/server.rs<br/>handle_submit_headers
    participant Chain as spv::HeaderChain
    participant Val as spv::validation
    participant Cp as spv::checkpoint

    Note over Listener,Srv: Bootstrap
    Listener->>Parent: gRPC GetLastSavedBlock
    Parent->>Srv: GetLastSavedBlockRequest
    Srv->>Chain: tip_height + tip_hash
    Chain-->>Srv: (height, hash) — checkpoint when empty
    Srv-->>Parent: GetLastSavedBlockResponse
    Parent-->>Listener: tip = N

    Note over Listener,Chain: Fetch + push loop
    loop while remote_tip > N
        Listener->>Esplora: fetch hashes + headers<br/>(/block-height/:h, /block/:hash/header)
        Esplora-->>Listener: raw 80-byte headers
        Listener->>Parent: gRPC SubmitHeaders{start_height=N+1, headers[]}
        Parent->>Srv: SubmitHeadersRequest

        Srv->>Srv: rate limiter: ≤ 100 000 headers per 60 s window<br/>(cumulative, counted before validation)
        Srv->>Chain: submit_headers(start_height, &headers)
        Chain->>Chain: batch ≤ MAX_HEADERS_PER_SUBMIT (10 000)
        Chain->>Chain: check bounds:<br/>start_height > checkpoint AND<br/>start_height ≤ tip+1
        Chain->>Chain: reorg_depth := (tip+1) − start_height
        Chain->>Chain: require reorg_depth ≤ MAX_REORG_DEPTH (100)
        Chain->>Chain: projected retained count ≤<br/>MAX_STORED_HEADERS (1 000 000) — REJECT, never prune

        loop staged in batch
            Chain->>Chain: deserialize 80-byte Header (atomic fail)
            Chain->>Chain: epoch_start_time on retarget heights<br/>(staged batch → chain → checkpoint base_time)
            Chain->>Val: expected_bits(height, prev_bits, prev_time,<br/>epoch_start_time, network)
            Val-->>Chain: Some(bits) for mainnet/testnet3,<br/>None for signet/regtest
            Chain->>Val: validate_header_full(<br/>header, height, prev_hash, expected_bits, net)
            Val->>Val: check_linkage (prev_blockhash equality)
            Val->>Val: nBits match if Some(expected)
            Val->>Val: check_pow (skipped on signet/regtest)
            Val-->>Chain: Ok / SpvError
        end

        alt reorg_depth > 0
            Chain->>Chain: compare cumulative Work:<br/>require sum(new) > sum(existing)
            Chain->>Chain: else: SpvError::WeakerChain
            Chain->>Chain: truncate displaced tail
        end

        Chain->>Chain: append all staged (all-or-nothing)
        Chain-->>Srv: SubmitOutcome{last_height, last_hash,<br/>headers_accepted, reorg_depth}

        Srv-->>Parent: SubmitHeadersResponse
        Parent-->>Listener: last_block_height = N'
        Listener->>Listener: N := N'
    end

    Note over Chain: Boot-time invariants:<br/>— Checkpoint::assert_real_in_release() panics<br/> on placeholder checkpoint in release builds.<br/>— assert_retarget_aligned() panics (all profiles)<br/> on a non-retarget-aligned PoW checkpoint.<br/>— header_at(checkpoint.height) returns None<br/> (we never store the checkpoint header itself,<br/> only its hash/bits/time metadata).<br/>Retention: ALL headers from the checkpoint are kept<br/>(no sliding window; deep RGB anchors stay verifiable).
```
