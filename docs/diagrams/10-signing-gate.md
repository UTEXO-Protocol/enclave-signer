# `fundsOut` signing gate — TEE validation predicates (`handle_sign`)

```mermaid
flowchart TD
    start([Sign request received<br/>RgbSource + EvmDestination:<br/>consignment, merkle_proofs, call_data,<br/>nonce, deadline, chain_id, proxy_contract, ...])

    subgraph P1 ["P1 — RGB source (validate_source)"]
        p1w["cheap payload gate first:<br/>consignment bytes present,<br/>keccak256 == consignment_hash,<br/>asset_id declared"]
        p1w --> p1wq{pass?}
        p1wq -->|no| p1wr[REFUSE — payload gate]:::refuse
        p1wq -->|yes| p1a["Transfer::load + typesystem pinned<br/>per schema_id"]
        p1a --> p1b[rgbstd validate against Esplora resolver<br/>30 s timeout]
        p1b --> p1q{valid?}
        p1q -->|no| p1r[REFUSE — invalid consignment]:::refuse
        p1q -->|yes| p1c{"contract_id == declared asset_id<br/>(== pinned RGB_ASSET_ID when configured)?"}
        p1c -->|no| p1cr[REFUSE — asset mismatch]:::refuse
        p1c -->|yes| p1e["source amount from consignment, per build flow:<br/>rgb-swap ⇒ TS_TRANSFER total_output /<br/>rgb-mint-burn ⇒ TS_BURN burned amount<br/>(host rgb_amount NOT used);<br/>any other transition ⇒ REFUSE"]
    end
    start --> p1w

    subgraph P3 ["P2 — SPV / Bitcoin anchoring (feature spv)"]
        p3stale{"chain tip fresh?<br/>≤ 2 h old, ≤ 2 h future"}
        p3stale -->|no| p3sr[REFUSE — chain stale, frozen feed]:::refuse
        p3stale -->|yes| p3net{consignment chain_net == enclave network?}
        p3net -->|no| p3nr[REFUSE — cross-network replay]:::refuse
        p3net -->|yes| p3v["for EVERY witness txid:<br/>exact proof set-equality,<br/>merkle path ≤ 32,<br/>inclusion vs stored header,<br/>depth ≥ 6"]
        p3v --> p3q{all proofs pass?}
        p3q -->|no| p3qr[REFUSE — SPV failure]:::refuse
    end
    p1e --> p3stale

    subgraph P2 ["P3 — EVM destination (validate_destination)"]
        p2len{"calldata ≥ 4 bytes AND ≤ 64 KiB?"}
        p2len -->|no| p2lenr[REFUSE — size]:::refuse
        p2len -->|yes| p2sel{"selector == 0xccddb768<br/>fundsOut(address,uint256,uint256,<br/>uint256,uint256,string,bytes,bytes)?"}
        p2sel -->|no| p2selr[REFUSE — unknown selector]:::refuse
        p2sel -->|yes| p2abi{"canonical ABI:<br/>abi_decode_validate AND<br/>re-encode byte-equals input?"}
        p2abi -->|no| p2abir[REFUSE — non-canonical calldata]:::refuse
        p2abi -->|yes| p2am{"decoded amount == declared<br/>calldata_amount, fits u64?"}
        p2am -->|no| p2amr[REFUSE — amount mismatch]:::refuse
        p2am -->|yes| p2p{"config pinned AND chain_id /<br/>proxy_contract == env pins?"}
        p2p -->|no| p2pr[REFUSE — pinned-config mismatch]:::refuse
        p2p -->|yes| p2d{deadline strictly in the future?}
        p2d -->|no| p2dr[REFUSE — expired]:::refuse
    end
    p3q -->|yes| p2len

    subgraph P4 ["P4 — route + fundsOut binding (apply_funds_out_binding)"]
        p4r{"route: source amount ≥ destination amount?"}
        p4r -->|no| p4rr[REFUSE — not covered]:::refuse
        p4r -->|yes| p4w{all consignment witnesses mined?}
        p4w -->|no| p4wr[REFUSE — unmined witness]:::refuse
        p4w -->|yes| p4b{"calldata proof slot populated?<br/>(empty pre-migration)"}
        p4b -->|yes| p4bv{"decoded (blockHeight, commitmentHash)<br/>matches enclave header at that height?"}
        p4bv -->|no| p4bvr[REFUSE — BtcRelay disagreement]:::refuse
        p4b -->|"no (inert)"| p4t
        p4bv -->|yes| p4t{"last transition == the build flow's unlock shape<br/>(TS_TRANSFER / TS_BURN) AND<br/>consignment-derived amount ≥<br/>amount read from calldata bytes?"}
        p4t -->|no| p4tr[REFUSE — fundsOut amount bind]:::refuse
    end
    p2d -->|yes| p4r

    subgraph S [Sign]
        s1["EIP-712 domain: name MultisigProxy, version 1,<br/>chain_id, proxy_contract<br/>(pinned by contract-fixture test)"] --> s2["digest = BridgeOperation(selector,<br/>callData, nonce, deadline)"]
        s2 --> s3[signature = ECDSA over digest<br/>Active KeyManager]
        s3 --> sR([RETURN signature + call_data]):::accept
    end
    p4t -->|yes| s1

    classDef refuse fill:#FADBD8,stroke:#922,color:#222
    classDef accept fill:#D5F5E3,stroke:#292,color:#222
```

### Notes

- `burnId` / `fundsInIds` inside the calldata are **preserved as received**
. The in-enclave OpId rewrite (`burnId` derived from the validated
  consignment OpId) is implemented but dormant until flows are
  routed by network id.
- Which unlock shape completes this gate is chosen at build time: an
  `rgb-swap` enclave signs `TS_TRANSFER` only, an `rgb-mint-burn` enclave
  `TS_BURN` only. They are separate instances with separate PCR0s; neither
  binary contains the other's rules.
- With `bfa-mint` (a mint/burn build on the bridged schema) the burn carries
  mint ancestry: every `TS_BRIDGE` behind it is checked against its own
  verified `FundsIn` lock before the gate completes.
- `dev-mode` builds bypass the validation subgraphs entirely; every dev
  feature is a `compile_error!` in release builds, and a release bridge build
  refuses to boot without a valid attested `Production` policy.

### Status

**Closed since the original review:** amount bound to the consignment (host
`rgb_amount` unused); canonical ABI validation; single pools selector,
pinned by an ABI-derived test; EIP-712 domain `MultisigProxy`/`1` pinned by a
deployed-contract fixture test; chain / contract / asset env-pinned; BtcRelay
proof agreement wired (inert until the listener populates it).

**Remaining gaps:**
- Recipient binding covers the burn path only: a `TS_BURN` commits its
  payout target in `MS_BURN_RECIPIENT` and the enclave refuses a release
  naming a different address. A swap's recipient is still unbound.
- OpId binding dormant (see note above); backend `burnId` is signed as
  received.
- Amount bind is coverage (`≥`), not strict `==` (per-output recipient-leg
  binding is).
