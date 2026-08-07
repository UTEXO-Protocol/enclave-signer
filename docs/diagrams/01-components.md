# UTEXO Bridge Enclave-Signer — Component Structure

```mermaid
flowchart TB
    %% External actors
    V[External verifier<br/>attest-verify]
    Op[Operator / CLI user]
    L[Go Listener<br/>federated-signer-node]

    %% parent crate
    subgraph PARENT [parent crate — utexo-bridge-parent]
        PMain[main.rs<br/>gRPC server tonic, 127.0.0.1]
        Grpc[grpc_server.rs<br/>ParentAdapterService — gRPC ↔ enclave wire<br/>TRANSACTION → Sign, EVM_GAS_TX → SignRawDigest,<br/>BTC_UTXO → SignBtc]
        PClient[client.rs<br/>EnclaveClient<br/>TCP / vsock]
        PFr[framing.rs<br/>u32 LE len + protobuf]
        PALib[attest_verify.rs<br/>library half of CLI —<br/>rebuilds expected policy + bundle]
        PCli[bin/cli.rs<br/>utexo-bridge-parent-cli]
        AVCli[attest-verify CLI<br/>--pcr0/1/2, --expect-vanilla-psbt,<br/>--expect-evm-source raw or helios or disabled]
        PMisc[config.rs / error.rs]
    end

    %% attestation-verify shared crate
    subgraph ATTV [attestation-verify crate — shared]
        AV[verify_attestation<br/>COSE_Sign1, alg pinned ES384, raw 96-byte sig,<br/>cert chain + CA constraints + PCR0/1/2]
        AVPol[policy.rs<br/>AttestedPolicy — canonical policy<br/>commitment encoding v1, audit C-01]
        AVMock[verify_mock_attestation<br/>feature 'mock']
        Root[Embedded AWS Nitro<br/>root CA PEM]
    end

    %% enclave crate
    subgraph ENC [enclave crate — utexo-bridge-enclave]
        EMain[main.rs<br/>boot: resolve SecurityPolicy — a release<br/>bridge build panics unless valid Production —<br/>then listener loop vsock / TCP]
        EConn[conn.rs<br/>DeadlineStream 10 s idle / 30 s total<br/>4 worker threads, queue of 16]
        ESrv[server.rs<br/>ServerContext + handler dispatch<br/>+ SubmitHeaders rate limiter]
        EPol[policy.rs<br/>SecurityPolicy C-01<br/>Production / Development,<br/>resolved once at boot]
        EState[state.rs<br/>Phase Initial / Cloning / Active<br/>NonceReplayGuard 1 h TTL<br/>op_replay_guard 24 h TTL]
        EFr[framing.rs<br/>len-prefixed proto, 4 MiB cap]
        BCfg[config.rs — BridgeConfig env pins<br/>EVM_CHAIN_ID / BRIDGE_CONTRACT / RGB_ASSET_ID<br/>GAS_TX_ALLOWED_TO / FUNDS_IN_CONTRACT<br/>BTC_MAX_TOTAL_SATS]
        VFwd[vsock_forwarder.rs<br/>loopback → vsock, per-port instances<br/>3443→8001 Esplora, 3444→8002 EVM RPC,<br/>18545→8003 / 18550→8004 Helios]
        KM[keys.rs — KeyManager<br/>BIP-39/32/44/84/86<br/>SecretBox seed + keys]

        subgraph NEVM [networks/evm/]
            NEV[validation.rs<br/>selector allowlist 0xccddb768,<br/>canonical ABI decode + re-encode,<br/>64 KiB cap, pins, deadline]
            NEC[crosscheck.rs<br/>witnesses-confirmed, BtcRelay proof,<br/>consignment amount bind]
            NEE[evm_event.rs<br/>independent FundsIn verify —<br/>alloy raw RPC or Helios in-TEE]
            NEG[gas_tx.rs<br/>gas-tx preimage allowlist:<br/>strict RLP + chain / to pins]
            NES[signing.rs<br/>EIP-712 MultisigProxy v1<br/>BridgeOperation digest]
        end
        subgraph NRGB [networks/rgb/]
            NRV[validation.rs<br/>rgbstd Transfer + Esplora resolver,<br/>typesystem pinned per schema]
            NRP[psbt_validation.rs<br/>PSBT ↔ consignment anchor,<br/>fee-rate 3x cap]
            NRB[btc_crosscheck.rs<br/>plain-BTC output self-ownership<br/>btc_ownership.rs + total-sats cap]
            NRS[spv_validation.rs<br/>coverage + depth ≥ 6<br/>+ chain_net + staleness]
            NRSIG[signing/<br/>psbt.rs P2WSH ECDSA<br/>taproot.rs BIP-341 Schnorr]
            subgraph SPVMOD [spv/]
                SCh[chain.rs — HeaderChain<br/>full retention, 1M cap,<br/>bounded reorg ≤ 100]
                SCp[checkpoint.rs<br/>compile-time anchors → PCR0]
                SMk[merkle.rs]
                SVal[validation.rs<br/>linkage + PoW + nBits]
            end
        end
        subgraph ATTGRP [attestation + cloning]
            AF[attestation.rs<br/>NSM facade<br/>+ verify_peer_attestation]
            CL[cloning.rs<br/>X25519 + HKDF-SHA256<br/>+ ChaCha20Poly1305]
        end
    end

    %% External
    NSM[(AWS NSM device<br/>/dev/nsm)]
    Esp{{Esplora indexer}}
    VP[(host vsock-proxy<br/>port 8001)]
    EvmRpc{{EVM JSON-RPC / Helios<br/>exec + consensus upstreams}}
    VPe[(host vsock-proxy<br/>8002 / 8003 / 8004)]

    %% Wires
    L -->|"gRPC ParentService<br/>Sign (data_type TRANSACTION /<br/>EVM_GAS_TX / BTC_UTXO) /<br/>PublicKey / Initialize / Clone /<br/>SubmitHeaders / GetLastSavedBlock /<br/>AttestedPublicKey"| PMain
    Op --> PCli
    V --> AVCli
    PCli --> PClient
    AVCli --> PALib
    PALib -->|"verify_attestation()"| AV
    PALib -->|"expected policy commitment"| AVPol
    PALib -->|"feature mock"| AVMock

    PMain --> Grpc
    Grpc --> PFr
    Grpc -.->|"u32 LE len + EnclaveRequest<br/>TCP 127.0.0.1:5000 or vsock CID 16:5000"| EFr

    EMain --> EPol
    EMain --> EConn
    EConn --> ESrv
    ESrv --> EFr
    ESrv --> EState
    ESrv --> NEV
    ESrv --> NEC
    ESrv --> NEE
    ESrv --> NEG
    ESrv --> NRV
    ESrv --> NRP
    ESrv --> NRB
    ESrv --> NRS
    ESrv -->|"InitiateCloning / GetClone / SetClone /<br/>GetAttestedPublicKey"| AF
    ESrv --> CL
    ESrv -->|"SubmitHeaders / lookup"| SCh

    EState -->|"Phase::Active(km)"| KM
    KM --> NES
    KM --> NRSIG

    NRV -->|"esplora_blocking via localhost:3443,<br/>30 s timeout"| VFwd
    VFwd -->|"vsock CID 3:8001"| VP
    VP -->|"real HTTP"| Esp

    NEE -.->|"eth_getTransactionReceipt /<br/>eth_blockNumber — host-relayed evidence,<br/>or Helios-verified in-TEE"| VFwd
    VFwd -->|"vsock 8002 / 8003 / 8004"| VPe
    VPe -->|"real HTTP"| EvmRpc

    NRS --> SCh
    NRS --> SMk
    SCh --> SVal
    SCh --> SCp

    AF -->|"Linux only — Request::Attestation /<br/>DescribePCR"| NSM
    AF -->|"peer verification (real)"| AV
    AF -->|"peer verification (mock)"| AVMock
    CL -.->|"ephemeral pubkey ↔ attestation user_data"| AF
    AV --> Root

    BCfg -->|"pinned chain / contract / asset cross-check"| NEV
    BCfg -->|"gas-tx to-pin"| NEG
    BCfg -->|"BTC total-sats cap"| NRB
    BCfg --> EPol
    EPol -.->|"user_data = sha256(pubkey_bundle ‖<br/>policy commitment) — C-01"| AF
```
