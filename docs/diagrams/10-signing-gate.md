# `fundsOut` signing gate — TEE validation predicates (`handle_sign_evm`)

```mermaid
flowchart TD
    start([SignEvmRequest received<br/>call_data, nonce, deadline, consignment,<br/>merkle_proofs, chain_id, proxy_contract, ...])
    start --> bs{built without 'spv' but<br/>request carries merkle_proofs?}
    bs -->|yes| bsr[REFUSE — build/feature mismatch]:::refuse

    subgraph P1 [P1 — RGB consignment validity, Sec 10.1]
        p1a[Transfer::load consignment_bytes] --> p1b[rgbstd validate against Esplora resolver]
        p1b --> p1q{valid?}
        p1q -->|no| p1r[REFUSE — invalid consignment]:::refuse
        p1q -->|yes| p1e[extract chain_net, witness_txids,<br/>all_op_ids, last_transition]
        p1e --> p1c{contract_id == pinned RGB_ASSET_ID?<br/>bound to env pin, declared id advisory — #75}
        p1c -->|no| p1cr[REFUSE — contract_id mismatch]:::refuse
    end
    bs -->|no| p1a

    subgraph P2 [P2 — EVM cross-checks, validate_evm_request, Sec 10.3/4/5]
        p2sel{selector in FUNDS_OUT allowlist?<br/>single fundsOut 0xccddb768 — #78}
        p2sel -->|no| p2selr[REFUSE — unknown selector]:::refuse
        p2sel -->|yes| p2cp{consignment bytes present?<br/>consignment_valid flag NOT trusted — #47}
        p2cp -->|no| p2cpr[REFUSE — fundsOut needs validated consignment]:::refuse
        p2cp -->|yes| p2h{keccak256(consignment)<br/>== consignment_hash?}
        p2h -->|no| p2hr[REFUSE — consignment tampered]:::refuse
        p2h -->|yes| p2am{legacy: rgb_amount ≥ calldata_amount + commission<br/>AND offsets 68/100 == declared?}
        p2am -->|no| p2amr[REFUSE — amount / calldata mismatch]:::refuse
        p2am -->|yes| p2d{chain_id > 0 AND<br/>len(proxy_contract)==20 AND<br/>deadline not expired?}
        p2d -->|no| p2dr[REFUSE — bad domain / expired]:::refuse
        p2d -->|yes| p2p{bridge config pinned (#43)?<br/>chain_id / proxy_contract / rgb_asset_id == env pins}
        p2p -->|no| p2pr[REFUSE — pinned-config mismatch]:::refuse
    end
    p1c -->|yes| p2sel

    subgraph P2b [P2b — Amount bound to consignment, #44/#47, Sec 9/10.2/10.3]
        p2bv{validated consignment present?<br/>rgb_validator ran}
        p2bv -->|no| p2bvr[REFUSE — fundsOut requires validated consignment]:::refuse
        p2bv -->|yes| p2bb{mint-burn: last == TS_BURN<br/>AND calldata amount@36 ≤ burned_asset_amount?}
        p2bb -->|no| p2bbr[REFUSE — burn amount / type mismatch]:::refuse
        p2bb -->|yes| p2bt{legacy: last == TS_TRANSFER<br/>AND amount+commission ≤ total_output_amount?}
        p2bt -->|no| p2btr[REFUSE — transfer amount / type mismatch]:::refuse
    end
    p2p -->|yes| p2bv

    subgraph P2c [P2c — OpId binding, bind_op_id, TEE-SE-02 / Sec 6]
        p2oid{op_id present?<br/>advisory on pools — empty allowed}
        p2oid -->|present| p2oidc{op_id == last_transition.op_id<br/>AND op_id ∈ all_op_ids?}
        p2oidc -->|no| p2oidr[REFUSE — op_id not authorised by consignment]:::refuse
    end

    subgraph P3 [P3 — SPV / Bitcoin anchoring, Sec 10.7/8, Sec 12]
        p3stale{chain tip fresh?<br/>not stale / not future}
        p3stale -->|no| p3sr[REFUSE — chain stale, frozen feed]:::refuse
        p3stale -->|yes| p3net{consignment chain_net == enclave network?}
        p3net -->|no| p3nr[REFUSE — cross-network replay]:::refuse
        p3net -->|yes| p3v[for EVERY witness txid: coverage (set equality),<br/>inclusion proof vs stored header root,<br/>confirmation depth ≥ 6]
        p3v --> p3q{all proofs pass?}
        p3q -->|no| p3qr[REFUSE — SPV failure]:::refuse
    end
    p2bt -->|yes| p2oid
    p2oid -->|empty| p3stale
    p2oidc -->|yes| p3stale

    subgraph S [Sign]
        s1[build EIP-712 domain<br/>name, version, chain_id, proxy_contract] --> s2[digest = EIP-712 BridgeOperation<br/>selector, callData, nonce, deadline]
        s2 --> s3[signature = ECDSA over digest<br/>Active KeyManager]
        s3 --> sR([RETURN EvmSignatureResponse signature]):::accept
    end
    p3q -->|yes| s1

    classDef refuse fill:#FADBD8,stroke:#922,color:#222
    classDef accept fill:#D5F5E3,stroke:#292,color:#222
```

### Status vs spec (see `audit/cross-flow-findings.md` Part 7)

**Closed since original review:**
- Sec 9 / 10.2 — burn amount now bound to the consignment (`TS_BURN` + amount ≤ `burned_asset_amount`, #44; transfer amount ≤ `total_output_amount`, #47).
- Sec 10.1 — `consignment_valid` bypass removed (#47).
- Sec 10.4/5 — `chain_id` / contract / asset pinned from env (#43).
- EIP-712 typehash now `BridgeOperation(bytes4 selector, ...)` matching `MultisigProxy._buildDigest()` (PR #48); domain `name`/`version` are `"MultisigProxy"`/`"1"`, verified against the deployed contract's domain separator.
- Sec 6 / 10.6 — `OpId` now on the wire (`SignEvmRequest.op_id`) and cross-checked against the validated consignment (`bind_op_id`, `TEE-SE-02` / #63). Advisory on the pools/transfer flow (no on-chain OpId there); the staged `bind_burn_id` adds the `burnId`-slot value-binding for the mint/burn unlock flow (#59) once that path is wired and the OpId→burnId transform is confirmed.

**Remaining gaps:**
- Sec 13 — EVM recipient NOT derived from / bound to the RGB payload (`TEE-SE-03`, #66).
- Amount bind is `≤`, not the spec's strict `==` (`TEE-SE-04`).
- Calldata offsets pinned to the deployed `0xccddb768` `fundsOut` ABI but not yet asserted against a contract-derived fixture (`TEE-SE-05`).
- Mint-burn unlock path inert: `validate_funds_out_burn` / `bind_burn_id` implemented + tested but not wired into a handler dispatch.
