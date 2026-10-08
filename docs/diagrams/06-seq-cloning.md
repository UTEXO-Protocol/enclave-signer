# Enclave-to-enclave seed cloning - three-message handshake

This lifecycle applies to burn signers and other builds without `kms-persistence`.
Mint signers use [KMS seed persistence](../kms-persistence.md) instead.

```mermaid
sequenceDiagram
    actor Op as Operator
    participant Cli as utexo-bridge-parent-cli clone<br/>(requester host)
    participant DP as donor parent<br/>(gRPC Clone, untrusted relay)
    participant Req as REQUESTER enclave<br/>(new, Phase::Initial)
    participant Don as DONOR enclave<br/>(existing, Phase::Active)
    participant RN as Req NSM
    participant DN as Don NSM

    Note over Req,Don: Both enclaves must have IDENTICAL PCR0/1/2<br/>(same compiled binary) and PCR3<br/>(same parent IAM role) for cloning to succeed.<br/>The cloning_secret is a pre-shared operator value - the donor<br/>received it at runtime via InitializeKey.cloning_secret<br/>(or the legacy UTEXO_CLONING_SECRET env). Never in the image.

    Note over Cli,Req: Message 1 - the CLI talks to the requester over the enclave wire<br/>protocol and to the donor through its parent's gRPC Clone RPC
    Op->>Cli: clone --cloning-secret-file --donor-grpc --donor-evm
    Cli->>Req: InitiateCloningRequest{cloning_secret, cluster_public_key=donor_evm}
    Req->>Req: validate_cloning_secret (strength check)
    Req->>Req: ephemeral X25519 keypair (StaticSecret + PublicKey)
    Req->>Req: digest := HMAC-SHA256(secret, encryption_pubkey || donor_evm)
    Req->>Req: nonce := getrandom_32()
    Req->>RN: NSM Attestation(nonce, public_key=encryption_pubkey, user_data=digest)
    RN-->>Req: requester_attestation (COSE_Sign1)
    Req->>Req: enter_cloning: Phase::Initial or expired Cloning (else reject),<br/>state := Phase::Cloning(session, cluster_pk)
    Req-->>Cli: InitiateCloningResponse{requester_attestation, encryption_pubkey, cloning_digest}

    Note over Cli,Don: Message 2 - gRPC Clone -> donor parent -> GetClone
    Cli->>DP: CloneRequest{attestation, encryption_pubkey,<br/>cluster_public_key, cloning_digest}
    DP->>Don: GetCloneRequest{cluster_public_key, cloning_digest,<br/>encryption_pubkey, requester_attestation}
    Don->>Don: cluster_public_key == my evm_address ?<br/>(needs Phase::Active)
    Don->>Don: with_donor_cloning_secret:<br/>HMAC(secret, encryption_pubkey || cluster_public_key) == cloning_digest<br/>(before the costly attestation checks)
    Don->>DN: get_own_pcrs()
    DN-->>Don: ExpectedPcrs{pcr0, pcr1, pcr2}
    Don->>Don: verify_peer_attestation(requester_attestation,<br/>expected=own_PCRs, nonce=None)
    Note right of Don: Cert-chain -> AWS Nitro root,<br/>COSE_Sign1 signature, PCR equality.<br/>No expected_nonce - freshness via the<br/>replay guard after auth.
    Don->>DN: get_own_pcr3()
    Don->>Don: check_clone_peer_pcr3: own PCR3 not all zero,<br/>requester PCR3 present and equal (same IAM role)
    Don->>Don: verified.public_key == encryption_pubkey (pubkey binding)
    Don->>Don: verified.user_data == cloning_digest (digest binding)
    Don->>Don: reserve_export_quota() (optional CLONE_EXPORT_HARD_CAP)
    Don->>Don: replay_guard.reserve(verified.nonce)
    Note right of Don: The nonce is reserved only AFTER all auth checks<br/>pass, and committed after the seal succeeds.<br/>A rejected handshake never consumes guard<br/>capacity. Guard is TTL-bounded: 1 h, oldest-first eviction.
    Don->>Don: with_seed: (ct, donor_pubkey) :=<br/>encrypt_seed_for_peer(encryption_pubkey, seed)
    Note right of Don: encrypt_seed_for_peer:<br/>our_eph := EphemeralSecret::random<br/>shared := our_eph * encryption_pubkey<br/>reject_non_contributory(shared) - small-order guard<br/>key := HKDF-SHA256(shared, salt="utexo-cloning-v1",<br/>  info="seed-encryption" || donor_pub || requester_pub)<br/>ct := ChaCha20Poly1305(key, nonce=[0,12]).encrypt(seed)
    Don->>Don: donor_nonce := getrandom_32()<br/>commitment := clone_commitment(bundle, policy,<br/>requester_pub, donor_pub, sha256(ct))
    Don->>DN: NSM Attestation(donor_nonce, public_key=donor_pubkey, user_data=commitment)
    DN-->>Don: donor_attestation
    Don->>Don: commit nonce + export count
    Don-->>DP: GetCloneResponse{encrypted_seed, donor_pubkey, donor_attestation}
    DP-->>Cli: CloneResponse

    Note over Cli,DP: Before SetClone the CLI reads the donor bundle<br/>(gRPC AttestedPublicKey) and requires evm_address == --donor-evm

    Note over Cli,Req: Message 3 - CLI -> requester
    Cli->>Req: SetCloneRequest{encrypted_seed, donor_pubkey, donor_attestation}
    Req->>RN: get_own_pcrs()
    RN-->>Req: ExpectedPcrs
    Req->>Req: verify_peer_attestation(donor_attestation,<br/>expected=own_PCRs, nonce=None)
    Req->>RN: get_own_pcr3()
    Req->>Req: check_clone_peer_pcr3: own PCR3 not all zero,<br/>donor PCR3 present and equal (same IAM role)
    Req->>Req: verified.public_key == donor_pubkey
    Req->>Req: replay_guard.reserve(verified.nonce)
    Req->>Req: complete_cloning {<br/>  seed := session.decrypt_seed_from_peer(donor_pubkey, ct)<br/>  km := KeyManager::from_seed(seed, network)<br/>  assert km.evm_address() == session.cluster_public_key<br/>  verify_clone_commitment(user_data, own bundle + policy + transcript)<br/>  return km<br/>}
    Req->>Req: state := Phase::Active(km)<br/>(on error: stays Cloning, nonce released)
    Req->>Req: commit nonce
    Req-->>Cli: SetCloneResponse{} (empty)
    Cli->>Req: GetPublicKey
    Cli->>Cli: all 13 identity fields == donor bundle
    Cli-->>Op: CLONE_RESULT_V1=success

    Note over Req,Don: After SetClone the requester has the IDENTICAL HD seed<br/>as the donor and signs as the same address. The seed remains resident in each TEE's SecretBox,<br/>temporary plaintext buffers are zeroized.<br/>Ciphertext on the wire is bound to<br/>the per-handshake DH key by HKDF info = donor || requester.
```
