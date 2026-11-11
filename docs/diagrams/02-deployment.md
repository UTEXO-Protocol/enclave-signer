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
        Parent[utexo-bridge-parent<br/>tonic gRPC, GRPC_HOST:GRPC_PORT<br/>-<br/>Default 127.0.0.1:5000.<br/>Deployed hosts: private ENI IP, ports 50051-50053,<br/>mTLS + client ACL - GRPC_TLS_*,<br/>one parent per enclave CID 16 / 18 / 20.<br/>Waits longer than the request deadline for each enclave RPC.<br/>Keeps each RGB sign reply for SIGNED_RESPONSE_TTL_SECS;<br/>a retry of the same request is answered from it.<br/>USE_VSOCK=true in production.<br/>Header sync from HEADER_ELECTRUM_URL.]
        Cli[utexo-bridge-parent-cli<br/>attest-verify CLI]
        VP[vsock-proxy port 8001<br/>―<br/>Allowlist → Electrum ssl:// or Esplora https://.]
        VPk["vsock-proxy 8003<br/>-<br/>mint signers only.<br/>8003 -> KMS 443. Relays TLS bytes only."]
        VPe["vsock-proxy 8002<br/>―<br/>Mint and burn builds only.<br/>8002 → EVM JSON-RPC TLS port.<br/>Relays TLS bytes only."]

        subgraph ENCL [AWS Nitro Enclave — TRUSTED, PCR-pinned]
            Bin[utexo-bridge-enclave<br/>Rust binary<br/>-<br/>Listens on vsock port 5000, any CID.<br/>One connection = one request;<br/>4 worker threads, queue of 16,<br/>idle timeout and socket deadline from the runtime limits.<br/>Handler work is not cancelled by this deadline.<br/>No filesystem persistence.<br/>Env pins read at boot:<br/>EVM_CHAIN_ID / EVM_PROXY_CONTRACT_ADDRESS / RGB_ASSET_ID<br/>GAS_TX_ALLOWED_TO / GAS_TX_MAX_GAS_LIMIT<br/>GAS_TX_MAX_FEE_PER_GAS / GAS_TX_MAX_VALUE_WEI<br/>GAS_TX_ALLOWED_SELECTORS<br/>FUNDS_IN_CONTRACT / TOKEN_CONTRACT / BTC_RELAY_MODE<br/>BTC_MAX_TOTAL_SATS<br/>BTC_MAX_UNOWNED_SATS<br/>EVM_FINALITY_TAG / SPV_MIN_CONFIRMATIONS / BITCOIN_NETWORK<br/>MINT_WITNESS_SAT.<br/>Release spv build refuses to boot<br/>unless the boot policy is valid Production.<br/>A no-SPV build needs IndexerTrusted.<br/>SetEndpoints resolves the SecurityPolicy once<br/>and commits it into attestation user_data.]
            Headers[(Header chain<br/>in-memory)]
            State[(EnclaveState<br/>Phase + KeyManager in SecretBox)]
            Replay[(NonceReplayGuard — cloning<br/>+ op_replay_guard — bridge ops<br/>each bounded in entries and in time)]
            Fwd["vsock_forwarder<br/>loopback -> vsock, per-port<br/>Electrum port / EVM RPC TLS port / KMS 443<br/>Electrum and KMS hosts pinned to loopback in /etc/hosts"]
            RgbVal["RgbValidator<br/>rgb-lib validate_consignment_with_resolver<br/>+ inspect_consignment, burn witnesses by SPV proof.<br/>Indexer only on a no-SPV burn."]
            EvmVer[events.rs verifier<br/>pinned TLS RPC<br/>receipt/head correctness trusted]
            NSM[/dev/nsm — Nitro Security Module/]
        end
    end

    Esp{{Electrum or Esplora indexer}}
    EvmRpc{{EVM JSON-RPC}}
    Kms{{AWS KMS}}

    V -->|"gRPC GRPC_PORT<br/>AttestedPublicKey(nonce)"| Parent
    L -->|"gRPC GRPC_PORT<br/>Sign / PublicKey / AttestedPublicKey ..."| Parent
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
    Fwd -->|"vsock CID 3:8003, mint only"| VPk
    VPk -->|"TLS bytes (ends in enclave)"| Kms
    Bin -->|"vsock CID 3:8004, mint only<br/>seed custody broker"| Parent
    VP -->|"Electrum or Esplora, TLS"| Esp
    VPe -->|"TLS bytes (ends in enclave)"| EvmRpc
```

### Notes

- The image is an EIF. Its build reports PCR0, PCR1 and PCR2, and a verifier
  pins the approved values ([building.md](../building.md)).
- The enclave gets its endpoints once after launch and signs nothing before
  that. Members run one image with their own endpoints
  ([configuration.md](../configuration.md#launch-values)).
- A deploy installs only the units, control scripts, launch file and
  artifacts of its CID. The other enclaves of the host can run other roles
  and PCRs ([operations.md](../operations.md#deploy-hostsh)).
- Keys live in enclave memory only. A mint signer recovers its seed through
  [KMS](../kms-persistence.md). A burn signer [clones](../cloning.md) it.
  Clones are replicas of one signing identity; independent quorum members
  need independently made seeds.
- [operations.md](../operations.md) has the launch steps and the checks.
