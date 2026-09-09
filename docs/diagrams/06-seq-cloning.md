# Enclave-to-enclave seed cloning — three-message handshake

```mermaid
sequenceDiagram
    actor Op as Operator
    participant Parent as parent<br/>(untrusted relay)
    participant Req as REQUESTER enclave<br/>(new, Phase::Initial)
    participant Don as DONOR enclave<br/>(existing, Phase::Active)
    participant RN as Req NSM
    participant DN as Don NSM

    Note over Req,Don: Both enclaves must have IDENTICAL PCRs<br/>(same compiled binary) for cloning to succeed.<br/>The cloning_secret is a pre-shared operator value,<br/>the donor reads it from UTEXO_CLONING_SECRET.

    Note over Op,Req: Message 1 — operator tooling → requester<br/>(the parent's gRPC Clone RPC is currently a stub —<br/>the handshake runs over the enclave wire protocol,<br/>the parent acting only as an untrusted relay)
    Op->>Parent: start cluster clone
    Parent->>Req: InitiateCloningRequest{cloning_secret, cluster_public_key=donor_evm}
    Req->>Req: ephemeral X25519 keypair (StaticSecret + PublicKey)
    Req->>Req: digest := HMAC-SHA256(secret, encryption_pubkey)
    Req->>Req: nonce := getrandom_32()
    Req->>RN: NSM Attestation(nonce, public_key=encryption_pubkey, user_data=digest)
    RN-->>Req: requester_attestation (COSE_Sign1)
    Req->>Req: enter_cloning: ensure Phase::Initial (else reject),<br/>state := Phase::Cloning(session, cluster_pk)
    Req-->>Parent: InitiateCloningResponse{requester_attestation, encryption_pubkey, cloning_digest}

    Note over Parent,Don: Message 2 — parent → donor
    Parent->>Don: GetCloneRequest{cluster_public_key, cloning_digest,<br/>encryption_pubkey, requester_attestation}
    Don->>Don: ensure Phase::Active
    Don->>Don: cluster_public_key == my evm_address ?
    Don->>DN: read_own_pcrs()
    DN-->>Don: ExpectedPcrs{pcr0, pcr1, pcr2}
    Don->>Don: verify_peer_attestation(requester_attestation,<br/>expected=own_PCRs, nonce=None)
    Note right of Don: Cert-chain → AWS Nitro root,<br/>COSE_Sign1 signature, PCR equality.<br/>No expected_nonce — freshness via the<br/>replay guard after auth.
    Don->>Don: verified.public_key == encryption_pubkey (pubkey binding)
    Don->>Don: verified.user_data == cloning_digest (digest binding)
    Don->>Don: with_donor_cloning_secret:<br/>HMAC(secret, encryption_pubkey) == cloning_digest
    Don->>Don: replay_guard.check_and_record(verified.nonce)
    Note right of Don: Nonce recorded only AFTER all auth checks<br/>pass — a rejected handshake<br/>never consumes guard capacity. Guard is<br/>TTL-bounded: 1 h, oldest-first eviction.
    Don->>Don: with_seed: (ct, donor_pubkey) :=<br/>encrypt_seed_for_peer(encryption_pubkey, seed)
    Note right of Don: encrypt_seed_for_peer:<br/>our_eph := EphemeralSecret::random<br/>shared := our_eph * encryption_pubkey<br/>reject_non_contributory(shared) — small-order guard<br/>key := HKDF-SHA256(shared, salt="utexo-cloning-v1",<br/>  info="seed-encryption" ‖ donor_pub ‖ requester_pub)<br/>ct := ChaCha20Poly1305(key, nonce=[0,12]).encrypt(seed)
    Don->>Don: donor_nonce := getrandom_32()
    Don->>DN: NSM Attestation(donor_nonce, public_key=donor_pubkey, user_data=None)
    DN-->>Don: donor_attestation
    Don-->>Parent: GetCloneResponse{encrypted_seed, donor_pubkey, donor_attestation}

    Note over Parent,Req: Message 3 — parent → requester
    Parent->>Req: SetCloneRequest{encrypted_seed, donor_pubkey, donor_attestation}
    Req->>RN: read_own_pcrs()
    RN-->>Req: ExpectedPcrs
    Req->>Req: verify_peer_attestation(donor_attestation,<br/>expected=own_PCRs, nonce=None)
    Req->>Req: verified.public_key == donor_pubkey
    Req->>Req: complete_cloning {<br/>  seed := session.decrypt_seed_from_peer(donor_pubkey, ct)<br/>  km := KeyManager::from_seed(seed, network)<br/>  assert km.evm_address() == session.cluster_public_key<br/>  return km<br/>}
    Req->>Req: state := Phase::Active(km)
    Req->>Req: replay_guard.check_and_record(verified.nonce)<br/>(after auth + commit)
    Req-->>Parent: SetCloneResponse{} (empty)
    Parent-->>Op: Initialize OK (probes GetPublicKey for confirmation)

    Note over Req,Don: After SetClone the requester has the IDENTICAL HD seed<br/>as the donor and signs as the same address. Plaintext seed<br/>exists only inside the requester's TEE briefly<br/>(Zeroizing 64-byte buffer), ciphertext on the wire is bound to<br/>the per-handshake DH key by HKDF info = donor‖requester.
```
