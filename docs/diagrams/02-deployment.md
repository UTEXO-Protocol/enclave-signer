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
        Parent[utexo-bridge-parent<br/>tonic gRPC, GRPC_HOST:GRPC_PORT<br/>―<br/>Default 127.0.0.1:5000.<br/>Deployed hosts: 0.0.0.0:50051-50053,<br/>one parent per enclave CID 16 / 18 / 20.<br/>30 s timeout per enclave RPC.<br/>USE_VSOCK=true in production.]
        Cli[utexo-bridge-parent-cli<br/>attest-verify CLI]
        VP[vsock-proxy port 8001<br/>―<br/>Allowlist → Electrum ssl:// or Esplora.]
        VPe["vsock-proxy 8002<br/>―<br/>evm-rpc builds only.<br/>8002 → EVM JSON-RPC via host nginx.<br/>Allowlisted upstream."]

        subgraph ENCL [AWS Nitro Enclave — TRUSTED, PCR-pinned]
            Bin[utexo-bridge-enclave<br/>Rust binary<br/>―<br/>Listens on vsock port 5000, any CID.<br/>One connection = one request;<br/>4 worker threads, queue of 16,<br/>10 s idle / 30 s total deadlines.<br/>No filesystem persistence.<br/>Env pins read at boot:<br/>EVM_CHAIN_ID / EVM_PROXY_CONTRACT_ADDRESS / RGB_ASSET_ID<br/>GAS_TX_ALLOWED_TO / GAS_TX_MAX_GAS_LIMIT<br/>GAS_TX_MAX_FEE_PER_GAS / GAS_TX_MAX_VALUE_WEI<br/>GAS_TX_ALLOWED_SELECTORS<br/>FUNDS_IN_CONTRACT / BTC_MAX_TOTAL_SATS<br/>BTC_MAX_UNOWNED_SATS / RGB_MAX_UNOWNED_SATS<br/>→ SecurityPolicy resolved once, committed<br/>into attestation user_data.<br/>Release bridge build refuses to boot<br/>unless the policy is valid Production.]
            Headers[(Header chain<br/>in-memory)]
            State[(EnclaveState<br/>Phase + KeyManager in SecretBox)]
            Replay[(NonceReplayGuard — cloning<br/>≤10 000 entries, 1 h TTL<br/>+ op_replay_guard — bridge ops<br/>≤100 000 entries, 24 h TTL)]
            Fwd[vsock_forwarder<br/>loopback → vsock, per-port<br/>Electrum port or 3443 / 3444<br/>Electrum host pinned to loopback in /etc/hosts]
            RgbVal[RgbValidator<br/>rgb-ops + Electrum or Esplora]
            EvmVer[evm_event verifier<br/>raw RPC (supplied images)<br/>receipt/head correctness trusted]
            NSM[/dev/nsm — Nitro Security Module/]
        end
    end

    Esp{{Electrum / Esplora}}
    EvmRpc{{EVM JSON-RPC}}

    V -->|"gRPC GRPC_PORT<br/>AttestedPublicKey(nonce)"| Parent
    L -->|"gRPC GRPC_PORT<br/>Sign / PublicKey / SubmitHeaders ..."| Parent
    Cli -->|"direct enclave RPC (ops only)<br/>TCP host:port or vsock://cid:5000"| ENCL

    Parent -->|"vsock CID:5000<br/>u32 LE len + EnclaveRequest /<br/>u32 LE len + EnclaveResponse"| ENCL

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
    Fwd -->|"vsock CID 3:8002"| VPe
    VP -->|"Electrum TCP/TLS or Esplora HTTP"| Esp
    VPe -->|"real HTTP"| EvmRpc
```

### Build / cluster notes

- Built as an **EIF** via `nitro-cli build-enclave` from `build/Dockerfile.enclave`
  (combined), `.rgb`, `.mint-burn`, `.ccd` or `.bfa`. PCR0/1/2 are pinned at build
  time; changes to the measured image require updating accepted measurements.
  `build-eif.yml` publishes EIF + `PCR.json` + `SHA256SUMS` to S3 under the git
  sha; `deploy/deploy-host.sh` verifies both before and after start.
- Cloned enclaves share **one HD seed** via the cloning handshake
  (`utexo-bridge-parent-cli clone`). Each node holds an identical `KeyManager`
  after `Cloning → Active`. Keys live only in memory; a restart needs re-init or
  re-clone.
- **Bridge-mode `signPsbt` requires the `evm-rpc` feature**: a build without it
  refuses bridge PSBTs, since it cannot independently verify the EVM `FundsIn`
  deposit. Operators MUST run the host `vsock-proxy` allowlist on 8002. Env:
  `EVM_RPC_URL` / `EVM_MIN_CONFIRMATIONS`. See the README env table.

Clones provide replicas of one signing identity. Independent quorum members
need independently initialized seeds.

Optional `helios` builds use execution and consensus forwarders on host vsock
ports 8003/8004 (enclave loopback 18545/18550) when Helios is selected. These
replace the raw receipt provider and require a pinned beacon checkpoint.
