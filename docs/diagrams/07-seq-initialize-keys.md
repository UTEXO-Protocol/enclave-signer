# Initialize keys — first enclave in a cluster, from OS entropy

```mermaid
sequenceDiagram
    actor Op as Operator
    participant Cli as utexo-bridge-parent-cli<br/>bin/cli.rs
    participant PClient as EnclaveClient<br/>parent/client.rs
    participant Srv as enclave/server.rs<br/>handle_initialize
    participant State as EnclaveState<br/>state.rs
    participant Km as KeyManager<br/>keys.rs
    participant Rand as getrandom<br/>(OS entropy)

    Op->>Cli: utexo-bridge-parent-cli init
    Cli->>PClient: initialize_keys(seed=None)
    PClient->>Srv: InitializeKeyRequest{seed=[], mnemonic=""}<br/>(length-prefixed proto)

    Srv->>Srv: path == "entropy" (no seed, no mnemonic)
    Srv->>Rand: getrandom::fill(&mut entropy[32])
    Rand-->>Srv: 32 bytes
    Srv->>State: initialize_from_entropy(&mut entropy)

    State->>State: lock Phase
    State->>State: ensure_initial(guard) — else AlreadyInitialized
    State->>Km: KeyManager::generate(entropy, network)

    Km->>Km: Mnemonic::from_entropy(entropy), entropy.zeroize()
    Km->>Km: seed := mnemonic.to_seed("")
    Km->>Km: seed_box := SecretBox::new(seed), seed.zeroize()
    Km->>Km: master := Xpriv::new_master(network, seed)
    Km->>Km: EVM   = m/44'/60'/0'/0/0<br/>BTC   = m/84'/0'/0'/0/0<br/>BIP-86 vanilla = m/86'/COIN'/0'<br/>BIP-86 colored = m/86'/827167'/0'
    Km->>Km: evm_address = keccak256(uncomp_pub[1..])[12..]
    Km-->>State: (KeyManager, Mnemonic)

    State->>State: *guard = Phase::Active(Box::new(km))
    State-->>Srv: mnemonic (one-time return for log)

    Srv->>State: get_keys()
    State-->>Srv: KeyInfo

    Note over Srv: tracing::info! evm_address, master_fingerprint,<br/>account_xpubs (public values only).<br/>The mnemonic is dropped here — its content lives<br/>only in the SecretBox(seed) from now on.

    Srv-->>PClient: InitializeKeyResponse{evm_address, btc_compressed_pub,<br/>btc_xpub, master_fingerprint, account xpubs,<br/>evm_uncompressed_pub}
    PClient-->>Cli: print pubkeys
    Cli-->>Op: enclave ready
```
