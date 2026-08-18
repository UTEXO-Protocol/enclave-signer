# UTEXO Bridge Enclave-Signer — Deployment

```mermaid
flowchart TB
    subgraph NET [Internet — untrusted]
        V[External verifier]
    end

    subgraph ORC [Orchestrator host — operator-controlled]
        L[Go Listener<br/>federated-signer-node]
    end

    subgraph EC2 [EC2 instance — Nitro-enabled, UNTRUSTED parent host]
        Parent[utexo-bridge-parent<br/>tonic gRPC, 127.0.0.1:5000<br/>―<br/>Bound to 127.0.0.1 only.<br/>30 s timeout per enclave RPC.<br/>USE_VSOCK=true in production.]
        Cli[utexo-bridge-parent-cli<br/>attest-verify CLI]
        VP[vsock-proxy port 8001<br/>―<br/>Allowlist → Esplora endpoint.]
        VPe["vsock-proxy 8002 / 8003 / 8004<br/>―<br/>evm-rpc / helios builds only.<br/>8002 → EVM JSON-RPC #60.<br/>8003 / 8004 → Helios exec / consensus #77.<br/>Allowlisted per upstream."]

        subgraph ENCL [AWS Nitro Enclave — TRUSTED, PCR-pinned]
            Bin[utexo-bridge-enclave<br/>static-linked Rust<br/>―<br/>Listens on vsock CID 16, port 5000.<br/>One connection = one request;<br/>4 worker threads, queue of 16,<br/>10 s idle / 30 s total deadlines.<br/>No filesystem persistence.<br/>No shell. No /dev access except /dev/nsm.<br/>Env pins read at boot:<br/>EVM_CHAIN_ID / EVM_PROXY_CONTRACT_ADDRESS / RGB_ASSET_ID<br/>GAS_TX_ALLOWED_TO / GAS_TX_MAX_GAS_LIMIT<br/>GAS_TX_MAX_FEE_PER_GAS / GAS_TX_MAX_VALUE_WEI<br/>GAS_TX_ALLOWED_SELECTORS<br/>FUNDS_IN_CONTRACT / BTC_MAX_TOTAL_SATS<br/>→ SecurityPolicy resolved once, committed<br/>into attestation user_data C-01.<br/>Release bridge build refuses to boot<br/>unless the policy is valid Production.]
            Headers[(Header chain<br/>in-memory)]
            State[(EnclaveState<br/>Phase + KeyManager in SecretBox)]
            Replay[(NonceReplayGuard — cloning<br/>≤10 000 entries, 1 h TTL<br/>+ op_replay_guard — bridge ops<br/>≤100 000 entries, 24 h TTL)]
            Fwd[vsock_forwarder<br/>loopback → vsock, per-port<br/>3443/3444/18545/18550]
            RgbVal[RgbValidator<br/>rgbstd + Esplora HTTP]
            EvmVer[evm_event verifier<br/>alloy #60 / Helios #77<br/>fail-closed FundsIn check]
            NSM[/dev/nsm — Nitro Security Module/]
        end
    end

    Esp{{Esplora API}}
    EvmRpc{{EVM JSON-RPC / Helios<br/>exec + consensus upstreams}}

    V -->|"gRPC /5000 (GRPC_PORT)<br/>AttestedPublicKey(nonce)"| Parent
    L -->|"gRPC /5000<br/>Sign / PublicKey / SubmitHeaders ..."| Parent
    Cli -->|"direct enclave RPC (dev/ops only)<br/>TCP 127.0.0.1:5000 or vsock CID 16:5000"| ENCL

    Parent -->|"vsock CID 16:5000<br/>u32 LE len + EnclaveRequest /<br/>u32 LE len + EnclaveResponse"| ENCL

    Bin --> State
    Bin --> Replay
    Bin --> Headers
    Bin --> RgbVal
    Bin --> EvmVer
    Bin -->|"DescribePCR / Attestation"| NSM
    Bin -->|"intra-enclave loopback"| Fwd
    RgbVal --> Fwd
    EvmVer --> Fwd
    Fwd -->|"vsock CID 3:8001"| VP
    Fwd -->|"vsock CID 3:8002/8003/8004"| VPe
    VP -->|"real HTTP"| Esp
    VPe -->|"real HTTP"| EvmRpc
```

### Build / cluster notes

- Built as an **EIF** via `nitro-cli build-enclave` from `build/Dockerfile.enclave`.
  PCR0/1/2 are pinned at build time; any change in source → different PCRs → external
  verifiers reject.
- A cluster of N ≥ 2 EC2 instances share **one HD seed** via the cloning handshake.
  Each node holds an identical `KeyManager` after `Cloning → Active`.
- **Bridge-mode `signPsbt` requires the `evm-rpc` feature** (or `helios`): a build
  without it refuses bridge PSBTs, since it cannot independently verify the EVM
  `FundsIn` deposit (audit M-06 / #60, #51). Operators MUST run the matching host
  `vsock-proxy` allowlists (8002 for `evm-rpc`; 8003 + 8004 for `helios`). Env:
  `EVM_RPC_URL` / `EVM_MIN_CONFIRMATIONS`, and for Helios `HELIOS_EXECUTION_RPC`
  (selects the trustless path), `HELIOS_CHECKPOINT` (required), `HELIOS_NETWORK`
  (must match `EVM_CHAIN_ID`). See the README env table.
