# Verify an attested signing key

Attestation binds a public-key bundle to measured enclave code and its declared
security policy. The verifier must trust AWS Nitro and approve the expected
PCR0, PCR1, and PCR2 measurements.

## Trust statement

Successful verification shows that measured code answered the verifier's nonce
with this key bundle and policy. The measured code controls how keys are
created, recovered, or cloned. The attestation document alone does not prove
where a private key was first created.

The policy covers selected settings. These include signer role, bridge pins,
plain-BTC permission, gas limits, data sources, and mint KMS configuration.
`Production` uses SPV. The public-Signet `IndexerTrusted` policy uses the
approved TLS indexer for Bitcoin confirmations and requires explicit verifier
opt-in. Both policies commit the full signing rules. `Development` does not.
The enclave resolves the policy once, at `SetEndpoints`. The verifier compares
its expected policy with the authenticated response.

### What attestation does NOT prove

Real verification proves only that **approved, measured code (PCR0/1/2 = X/Y/Z)
answered a fresh-nonce request with these public bytes**. It does
**not** establish any of the following, and consumers MUST NOT rely on them:

- **Key origin.** The document does not prove where or when the private key
  was created. The code can attest a generated, recovered, or cloned key.
- **Exclusive custody.** The same seed can exist in several enclaves. Burn
  replicas can use peer cloning. Mint replicas can recover the same KMS seed.
- **No previous copy.** Attestation cannot prove that no party previously held
  or copied the private key.

Trust requires both approved measurements and a fresh-nonce response.
Review the measured code to establish its key-custody rules. See the
[key management specification](tee-spec.md#5-key-management).

The chain of trust is:

```
AWS Nitro Root CA  (public, hardcoded)
       │ signs
AWS region intermediate(s)
       │ signs
This EC2 instance's NSM signing cert
       │ signs (P-384 ECDSA, COSE_Sign1)
Attestation document { pcrs, public_key, user_data, nonce, timestamp, ... }
```

### Identity is not provider readiness

`AttestedPublicKey` attests the installed public keys and configured policy.
It does not contact the EVM RPC provider, so verification can succeed while that
provider is unavailable. It does not show that the node can complete a signing
request. The current `Health` response checks whether endpoints are set, keys
are loaded and, where required, SPV is ready; it does not probe EVM RPC
availability either. Routing that requires live provider availability needs
a separate check.

## Protocol

```
verifier                                 parent gRPC                      enclave (Nitro)
   │                                          │                                 │
   │ 1. nonce ← rand(32)                      │                                 │
   │ 2. AttestedPublicKey(nonce) ────────────▶│                                 │
   │                                          │ 3. GetAttestedPublicKey(nonce) ▶│
   │                                          │                                 │ 4. NSM produces COSE_Sign1 doc
   │                                          │                                 │    binding {nonce,
   │                                          │                                 │            public_key=evm_uncompressed_pub,
   │                                          │                                 │            user_data=sha256(bundle || policy)}
   │                                          │                                 │    to PCR0/1/2
   │                                          │ ◀── (public_keys, doc) ─────────│
   │ ◀── AttestedPublicKeyResponse ───────────│                                 │
   │                                                                            │
   │ 5. Verify chain → AWS root, COSE sig, validity, PCRs, nonce equal,
   │    public_key == evm_uncompressed_pub,
   │    user_data == sha256(bundle || expected_policy).                         │
```

## Bindings

The NSM attestation document carries three caller-supplied fields. The enclave
populates them as:

| NSM field    | Bound value                                                                                 |
|--------------|---------------------------------------------------------------------------------------------|
| `public_key` | `evm_uncompressed_pub` — the bridge's primary signing key (64 bytes, X\|\|Y)              |
| `user_data`  | `sha256(canonical_bundle \|\| policy_commitment)` — 32-byte commitment over the key bundle *and* the resolved security policy |
| `nonce`      | the 32-byte nonce supplied by the verifier                                                 |

Checking `public_key` alone binds that key to the document, but does not
check the full key bundle or the expected policy. Signer approval must also
rebuild the canonical bundle and expected policy, then check `user_data`.
This checks that the parent did not replace any bundle field and that the
attested policy matches the approved rules.

### Canonical bundle encoding

Concatenate all fields of `PublicKeysResponse` in proto field order.
Prefix each field with its length as a big-endian u32. Encode strings as UTF-8.
`chain_id` is encoded as 8-byte big-endian (length prefix is the constant 8).

```
canonical_bundle =
    u32_be(len(evm_address))                 || evm_address
    u32_be(len(btc_compressed_pub))          || btc_compressed_pub
    u32_be(len(btc_xpub))                    || btc_xpub_utf8
    u32_be(len(master_fingerprint))          || master_fingerprint
    u32_be(len(account_xpub_vanilla))        || account_xpub_vanilla_utf8
    u32_be(len(account_xpub_colored))        || account_xpub_colored_utf8
    u32_be(len(evm_uncompressed_pub))        || evm_uncompressed_pub
    u32_be(8)                                || chain_id_be8
    u32_be(len(bridge_contract))             || bridge_contract       // 20 bytes (zeros = unset)
    u32_be(len(rgb_asset_id))                || rgb_asset_id_utf8
    u32_be(len(evm_gas_tx_uncompressed_pub)) || evm_gas_tx_uncompressed_pub   // 64 bytes
    u32_be(len(evm_gas_tx_address))          || evm_gas_tx_address            // 20 bytes
    u32_be(len(ccd_ed25519_pub))             || ccd_ed25519_pub               // 32 bytes
```

Thirteen fields. `chain_id`, `bridge_contract` and `rgb_asset_id` are bridge
config pinned at enclave boot from env (`EVM_CHAIN_ID`,
`EVM_PROXY_CONTRACT_ADDRESS`, `RGB_ASSET_ID`). They commit the enclave to a
specific chain / contract / asset triple — a misconfigured or
maliciously-redirected enclave is observable through this commitment. (The
attestation-bundle/proto field keeps the legacy name `bridge_contract`; its
value is the MultisigProxy from `EVM_PROXY_CONTRACT_ADDRESS`.)
Production deployments MUST set all three; the commitment for a dev /
mock build with no env is `chain_id=0`, `bridge_contract=20 zero bytes`,
`rgb_asset_id=""`. The gas-tx key and the Concordium key are derived in every
build, so the bundle has the same shape regardless of features.

The CLI reconstructs policy using the chain/contract/asset pins from the
response. These values are always authenticated (they are inside the signed
commitment); to also compare them against the operator's intended deployment,
pass `--expect-chain-id`, `--expect-bridge-contract` and/or
`--expect-rgb-asset-id`. When set, verification fails unless the enclave attests
exactly those pins, so onboarding can reject a valid attestation of the *wrong*
chain, contract or RGB asset. When omitted, the pins are authenticated but not
compared for the SPV `Production` policy. `IndexerTrusted` requires all three
pins to be supplied, with a nonempty asset ID. A successful run prints every
verified field as one `name: value` line. The names are the paths of the
exported bundle. Bundle metadata is not a source of trusted expectations;
approve the measurements and deployment values independently.

The verifier MUST use the same field set, the same order, and the same
length-prefix encoding. The reference encoder is `canonical_pubkey_bundle`
in [`enclave/src/server/keys.rs`](../enclave/src/server/keys.rs) and the reference
decoder/checker is `canonical_bundle` in
[`parent/src/attest_verify.rs`](../parent/src/attest_verify.rs).

### Security policy commitment

The canonical bundle above is followed by the enclave's resolved security
policy, and `user_data = sha256(canonical_bundle || policy_commitment)`. The
policy is the single source of truth for the enclave's posture - resolved once
at launch (`SetEndpoints`) in [`enclave/src/policy.rs`](../enclave/src/policy.rs) and serialized by
[`attestation-verify/src/policy.rs`](../attestation-verify/src/policy.rs), which
both the enclave and every verifier share so the bytes are identical.

```
policy_commitment =
    u8(POLICY_COMMITMENT_V1 = 1)                    // version tag
    u8(policy_kind)                                // 0x01 Production | 0x02 IndexerTrusted
    u8(allow_vanilla_psbt)                          // plain-BTC path enabled?
    u8(signer_role)                                 // 0 combined | 1 mint | 2 burn (from build features)
    u8(attestation_mode)                            // 1 = real NSM (0 = mock)
    u8(evm_source)                                  // 0 disabled | 1 plaintext rpc (dev) | 2 retired | 3 pinned TLS rpc
    u8(btc_source)                                  // 1 = SPV (Production) | 2 = indexer (IndexerTrusted)
    chain_id_be8
    u8(bitcoin_network)                             // 0 mainnet | 1 testnet3 | 2 signet | 3 regtest | 4 testnet4 | 5 signetcustom
    bridge_contract(20)
    u32_be(len(rgb_asset_id)) || rgb_asset_id_utf8
    funds_in_contract(20)                           // authorized event emitter
    u8(evm_finality_tag)                            // 0 latest | 1 safe | 2 finalized
    spv_min_confirmations_be4                       // required Bitcoin witness depth (the mint signer does not check it)
    u32_be(len(electrum_host)) || electrum_host     // Electrum host set at launch
    u8(evm_rpc_tls_present)                         // 0 absent; 1 followed by:
      u32_be(len(host)) || host || ca_sha256(32)    //   EVM RPC host, SHA-256 of the CA DER, set at launch
    // Gas-tx (SignRawDigest) rule:
    gas_tx_allowed_to(20)                           // all-zero = gas path unpinned
    gas_tx_max_gas_limit_be8                        // gasLimit ceiling (0 = unset)
    gas_tx_max_fee_per_gas_be16                     // per-gas fee ceiling, wei (0 = unset)
    gas_tx_max_value_wei_be16                       // native-value ceiling, wei (0 = unset)
    u32_be(len(selectors)) || selector(4)...        // sorted + deduped 4-byte selectors
    token_contract(20)                              // released ERC-20 (burnId preimage input)
    u8(kms_present)                                 // 0 absent; 1 followed by (set at launch):
      u32_be(len(key_arn)) || key_arn || u32_be(len(region)) || region
      || u32_be(len(seed_id)) || seed_id
      || u8(address_present) [|| expected_evm_address(20)]
    u8(clone_peer_pcr3_present)                     // 1 for a cloning role (burn, combined), 0 for mint
      [|| clone_peer_pcr3(48)]                      //   own PCR3 (parent IAM role), never all zero
    // Only IndexerTrusted appends this field:
    endpoints_sha256(32)                            // public endpoint identity; no RPC path or KMS fields
```

The existing V1 `Production` encoding is unchanged: kind `0x01`, Bitcoin
source `1`, and no endpoint digest at the end. `IndexerTrusted` uses kind
`0x02`, Bitcoin source `2`, the same fields in the same order, then the 32-byte
endpoint digest after the clone-peer PCR3 option. The decoder rejects a
policy kind with the wrong Bitcoin source. `Development` is exactly two bytes:
`[0x01, 0x00]`.

V1 commits to `evm_finality_tag` (`EVM_FINALITY_TAG`) and Bitcoin witness
depth (`SPV_MIN_CONFIRMATIONS`). The mint and burn image recipes, including
the public-Signet stage profile, use `finalized` and depth 3. Raw configuration
and the combined image default to `safe` and depth 6. Use the values from the
approved image. Burn checks witness depth; mint commits it without checking it.
Every EVM `FundsIn` receipt must be at or below the selected head, with its
block hash matching the canonical block at that height. The enclave
revalidates the selected head snapshot to detect a reorg. The enclave trusts
the pinned RPC for the correctness of these responses. Real policy verification
requires `--expect-evm-finality-tag` with the approved `safe` or `finalized`
value. Both release policies refuse `latest`, and so does the verifier.
`IndexerTrusted` is restricted to public Signet, a mint or burn role, real
attestation, TLS endpoints, and `BTC_RELAY_MODE=none`. It retains the full
contract, asset, finality, gas, custody and clone-peer checks. A mint signer
requires KMS custody; a burn signer does not accept a KMS pin. It provides no
SPV claim: the indexer supplies the Bitcoin confirmation evidence.

`clone_peer_pcr3` binds clone peers to the parent instance IAM role (#270). A
verifier does not configure it: it takes PCR3 from the verified document (the
NSM signs it), requires it to be present and not all zero for a cloning role,
and expects no value for the mint signer. An enclave on an instance without an
IAM role therefore fails verification, and does not start.

Use enclave images and verifiers from the same release with approved EIF
measurements. Clone peers must have matching policy commitments.

`bitcoin_network` is `BITCOIN_NETWORK`, the network of the accepted
consignments and, for `Production`, the SPV header chain. A verifier declares
it with `--expect-bitcoin-network` (default `bitcoin`). A `Production` policy
pinned to EVM chain `1` or `42161` with another Bitcoin network does not boot.
`IndexerTrusted` explicitly permits public Signet with the approved EVM chain;
the stage profile uses Arbitrum One (`42161`). Approve its exact contracts and
asset as well as its indexer trust model. Real attestation does not turn
Signet evidence into Bitcoin-mainnet evidence or prove the deployment safe
for production assets. Unknown Bitcoin network names are refused.

The `Production` tuple has the indexer host and EVM RPC host/CA hash, but
omits the indexer URL scheme and ports. A release image accepts only `ssl://`
or `https://` indexer URLs; a development build can accept plaintext.
Matching `Production` policies do not prove specific endpoint ports.
`IndexerTrusted` additionally commits the public endpoint digest below,
which binds the exact indexer URL, EVM RPC host, TLS port and CA DER bytes.

The sats values are image env, so PCR0 measures them. The policy does not
commit `BTC_MAX_UNOWNED_SATS`, `RGB_MAX_UNOWNED_SATS` or `MINT_WITNESS_SAT`,
and `attest-verify` has no flag for them. `BTC_MAX_TOTAL_SATS` shows only as
`allow_vanilla_psbt`: a non-zero value allows plain-BTC signing, except on a
burn signer.

Image-baked values remain measured in the EIF. The endpoints are not in the
image; the operator sets them and the KMS values once at launch
(`SetEndpoints`). The policy commits only the fields listed above. Until
the set, `GetAttestedPublicKey` is refused. The response carries the policy bytes
that `user_data` commits (`attested_policy`), so a verifier can decode them.

A `Production` or `IndexerTrusted` enclave commits its full tuple. A dev/mock
enclave commits only `[version, 0x00]`, without individual policy settings. The response
contains this encoding in `attested_policy`. The verifier authenticates and
decodes those bytes.
It then constructs the expected policy from its own settings and the authenticated
bridge pins. The policies must match. Do not use the response itself to decide
which policy is acceptable.

The gas-tx rule is the `SignRawDigest` allowlist: the pinned
destination, the `gasLimit`/fee ceilings that bound fee-griefing, the
native-value ceiling that bounds the payable `lzFundsOutCall` carve-out, and the
4-byte calldata selectors the gas EOA may invoke. Committing it makes the
enclave's gas-signing policy externally verifiable instead of a self-protection
pin the operator has to trust; `attest-verify` declares the expected rule via
`--expect-gas-tx-to` / `--expect-gas-max-gas-limit` / `--expect-gas-max-fee-per-gas`
/ `--expect-gas-max-value-wei` / `--expect-gas-selectors`.

An unset `GAS_TX_MAX_VALUE_WEI` commits as `0`, which is exactly the posture it
enforces (no non-zero value is signable) — so "unpinned" is itself attested, the
same way an unset destination commits as all-zero. `None` and `Some(0)` therefore
produce identical bytes; one enforced rule cannot yield two attestations.

### Public endpoint digest and credential rotation

`IndexerTrusted.endpoints_sha256` is:

```
sha256(b"utexo/chain-endpoints/v2\0" || protobuf(public_endpoints))
```

`public_endpoints` is the `SetEndpointsRequest` with the entire `evm_rpc_path`
and all KMS fields cleared. The remaining fields are the exact `electrum_url`,
`evm_rpc_host`, `evm_rpc_tls_port` and `evm_rpc_ca_der` bytes. The enclave computes
this digest from the validated launch request; the host cannot substitute an
opaque digest. `set-endpoints --print-sha256` computes the same value without
contacting an enclave.

Approve these public values independently. Keep the exact CA DER bytes used
for the calculation on the launch hosts. An RPC API key stored in the path is
not needed to calculate or publish the digest. For example:

```bash
env -u EVM_RPC_PATH_FILE utexo-bridge-parent-cli set-endpoints --print-sha256 \
  --electrum-url ssl://electrum.example:50002 \
  --evm-rpc-host rpc.example \
  --evm-rpc-tls-port 443 \
  --evm-rpc-ca-der-file approved-rpc-ca.der
```

At launch, supply the provider's absolute RPC path through a restricted file
and `EVM_RPC_PATH_FILE`. It defaults to `/` when omitted. The path accepts only
absolute ASCII paths; authorities, queries, fragments, percent escapes and
dot segments are refused. The file is read at launch. The path is not baked
into the EIF and is excluded from the policy digest and public bundle.

Rotating only the path/API key leaves the endpoint digest, attested policy
and EIF measurements unchanged. Restart the enclave with the new restricted
file because `SetEndpoints` runs once per boot. Changing the public host, CA,
port or indexer URL requires approval of the new runtime policy and digest;
it does not require a member-specific EIF. A changed mint digest changes the
KMS encryption context. Existing ciphertext needs a trusted operator to
rewrap it from the old context to the approved new one with KMS `ReEncrypt`
on the same key, without exporting plaintext. Updating the key policy alone
is insufficient. The first move from the old four-entry stage context to the
new endpoint-bound context also needs this migration. The signer role must
not receive `ReEncrypt` permission. Rotating the API key in the path leaves
the context unchanged and needs no rewrap. See [KMS persistence](kms-persistence.md).

## Where the expected PCRs come from

The attestation document contains signed PCR values. A verifier must obtain
its expected values from a trusted source outside that response.

PCR0 measures the image. PCR1 measures the kernel and bootstrap. PCR2 measures
the application. Rebuild the EIF to determine whether a change affects them.
A file checksum and a PCR measurement are different values.

Federation members using the same release, role and build profile use the
same public EIF and PCR0/1/2. They can choose different approved RPC providers
and credentials at launch. Those runtime choices change `user_data` policy
values where applicable, not the EIF measurements. Mint and burn images, and
SPV and indexer profiles, have different build inputs and must use their own
approved measurements. PCR3 measures the parent IAM role; it can differ
between members even when PCR0/1/2 match.

This repository publishes measurements with EIF artifacts. Verify those
artifacts before you use their PCRs. A trusted configuration or registry can
also distribute approved measurements. Its security depends on how updates
are authorized, not on where the values are stored.

## Verification recipe (manual)

Given `(public_keys_bundle, attestation_doc, nonce_sent, expected_pcrs)`:

1. Parse `attestation_doc` as `COSE_Sign1` (CBOR array of length 4).
   Require ES384 (`alg = -35`) in the protected header.
2. Parse the inner CBOR payload as `AttestationDocument`.
3. Verify the certificate chain in `cabundle`:
    - `cabundle[0]` must equal the AWS Nitro root CA bytewise (DER).
    - For each `i`, `cabundle[i]` must sign `cabundle[i+1]` (DER ECDSA).
    - `cabundle[last]` must sign `signing_cert` (the cert in the doc).
    - Check certificate validity against the local clock, with the implementation
      tolerance of 60 seconds.
    - Require CA `BasicConstraints` on each issuer. Check path-length limits.
    - If an issuer has `KeyUsage`, require `keyCertSign`.
    - If the signing certificate has `KeyUsage`, require `digitalSignature`.
4. Verify the COSE signature: P-384 ECDSA over
   `Sig_structure1 = ["Signature1", protected, h"", payload]`. Per RFC 8152
   §8.1 the COSE signature is raw `r||s` (96 bytes for P-384), not DER.
5. Reject all-zero PCR0/1/2. Compare each PCR with its expected value, byte for byte.
   The unsafe `allow-debug-pcrs` feature disables the shared verifier's all-zero
   rejection. `IndexerTrusted` still requires each of PCR0/1/2 to be nonzero
   in the parent verifier; it never accepts Nitro debug measurements.
6. Nonce check: `doc.nonce == nonce_sent`.
7. Pubkey check: `doc.public_key == public_keys_bundle.evm_uncompressed_pub`.
8. Commitment check: confirm
   `doc.user_data == sha256(canonical_bundle(public_keys_bundle) || attested_policy)`,
   decode `attested_policy`, and confirm it equals the expected policy (from
   the expected posture + the wire pins).

The verifier returns the document timestamp but does not enforce a maximum
document age. Freshness depends on a new unpredictable nonce and the caller's
request timing. Do not reuse nonces.

If all eight checks pass, the bridge's EVM address (`keccak256(evm_uncompressed_pub)[12..]`)
is bound to the running TEE measurement *and* the enclave's attested posture
equals the explicitly expected `Production` or `IndexerTrusted` policy.

## Verification recipe (with `attest-verify`)

The `attest-verify` CLI in this repo runs the full recipe. Configure the client
CA/certificate/key environment from [Parent mTLS](parent-mtls.md) first; an
`observer` certificate is sufficient for verification.
To check a published bundle offline (`--from-file`), see
[Verify a signer](verify-a-signer.md).

```bash
# Production verification (against a real Nitro enclave). By default it expects a
# production policy with plain-BTC signing DISABLED and the pinned-TLS EVM data
# source (`--expect-evm-source tls`, what the shipped image uses), which needs the
# Electrum host, the EVM RPC host and the CA the operator set at launch. Compute
# the CA hash from the same DER the operator set:
#   openssl x509 -in ca.pem -outform der | openssl dgst -sha256 -hex
attest-verify \
    --endpoint https://parent.example:50051 \
    --pcr0 <96-hex-chars> \
    --pcr1 <96-hex-chars> \
    --pcr2 <96-hex-chars> \
    --expect-signer-role burn \
    --expect-gas-tx-to 0x6711f1a319B37847fa0234181C34D883774c4951 \
    --expect-funds-in-contract 0x6711f1a319B37847fa0234181C34D883774c4951 \
    --expect-evm-finality-tag finalized \
    --expect-token-contract 0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9 \
    --expect-spv-min-confirmations 3 \
    --expect-electrum-host <electrum host> \
    --expect-evm-rpc-host <rpc host> \
    --expect-evm-rpc-ca-sha256 <64-hex-chars>

# --expect-signer-role is required: `mint` for the mint signer image
# (Dockerfile.enclave.mint), `burn` for the burn signer
# (Dockerfile.enclave.burn), `combined` for a swap image. A burn signer that
# attests `mint` fails verification. A role attests the other role's path as
# off whatever its env says: a burn signer never attests plain-BTC signing
# (omit --expect-vanilla-psbt), a mint signer never attests a gas rule (omit
# the --expect-gas-* flags). A mint signer also needs --expect-kms-key-arn,
# --expect-kms-region and --expect-kms-seed-id, and --expect-kms-evm-address
# when the operator set one.

# Gas signing: also supply the image's exact expected rule when configured:
# --expect-gas-tx-to <hex20> --expect-gas-max-gas-limit <units>
# --expect-gas-max-fee-per-gas <wei> --expect-gas-max-value-wei <wei>
# --expect-gas-selectors <comma-separated-hex4>
# Omitted flags expect an unpinned gas rule, not values discovered from the enclave.

# Deployment pins: compare the attested chain/contract/asset against the
# approved deployment. These flags are required for indexer trust and optional
# for SPV; omitted SPV pins are authenticated but not compared:
# --expect-chain-id <u64> --expect-bridge-contract <hex20> \
# --expect-rgb-asset-id <asset>   # empty string pins "no RGB asset"
# --expect-bitcoin-network <bitcoin|testnet3|testnet4|signet|signetcustom|regtest>   # default bitcoin

# Expect the plain-BTC path enabled:
attest-verify --endpoint https://parent.example:50051 \
    --pcr0 <..> --pcr1 <..> --pcr2 <..> --expect-signer-role mint \
    --expect-funds-in-contract <hex20> --expect-token-contract <hex20> \
    --expect-evm-finality-tag finalized \
    --expect-spv-min-confirmations 3 \
    --expect-electrum-host <electrum host> \
    --expect-kms-key-arn <arn> --expect-kms-region <region> --expect-kms-seed-id <id> \
    --expect-evm-rpc-host <rpc host> --expect-evm-rpc-ca-sha256 <64-hex-chars> \
    --expect-vanilla-psbt

# Dev / CI verification (against an enclave built with --features mock-attestation).
# --mock implies the expected policy is Development.
# For this loopback plaintext example, remove PARENT_TLS_* and explicitly
# enable GRPC_ALLOW_INSECURE_LOOPBACK=true on the loopback-bound Parent.
attest-verify --endpoint http://127.0.0.1:50051 --mock
```

For public-Signet indexer trust, use the same full verification command with
`--expect-btc-source indexer --expect-endpoints-sha256 <approved-public-digest>`
and `--expect-bitcoin-network signet`. Supply the independently approved chain,
bridge and nonempty asset pins, and the correct mint or burn role. These flags
are required for both live and offline checks. The default `spv` expectation
rejects `IndexerTrusted`; an indexer expectation rejects `Production` and
`Development`. `--mock` and `--allow-development-policy` cannot approve this
stage policy. A complete offline example is in
[the signer guide](verify-a-signer.md#verify-a-public-signet-indexer-signer).

Exit codes:

| Code | Meaning                                                         |
|------|-----------------------------------------------------------------|
| 0    | All eight checks passed                                         |
| 1    | Error after argument parsing: verification, connection, file I/O or missing/invalid settings (e.g. PCR hex); see stderr |
| 2    | Command-line argument parsing failed (e.g. unknown/conflicting flags or non-numeric `--expect-chain-id`) |

## Launch check at deploy

Before keys exist, `GetAttestedPublicKey` returns a policy-only answer:
`public_keys` is empty, the document has no `public_key`, and `user_data` is
`sha256("utexo/attested-policy/v1\0" || policy_bytes)`. The parent gRPC
`AttestedPublicKey` still refuses an answer without keys.

`deploy/deploy-host.sh` runs `utexo-bridge-parent-cli verify-launch` on each
enclave after `set-endpoints`. The script deploys only the combined image
(`utexo-bridge-enclave.eif`) and passes `SIGNER_ROLE=combined`. For a mint or
burn signer, run `set-endpoints` and `verify-launch --signer-role mint` (or
`burn`) yourself. `verify-launch` verifies the document for a fresh nonce
against `PCR.json`, and compares every attested policy field with the deploy
inputs: the image role, `IMAGE-ENV.json` (the env of the measured image, from
the build) and the `set-endpoints` values. On a mismatch it names the field,
the expected value and the attested value. The enclave is then terminated,
all enclaves stop, and the deploy exits 1 before a parent starts. The deploy
inputs do not give `clone_peer_pcr3`: `verify-launch` takes it from the
verified document, as described above.

For an indexer release, `verify-launch` reads `BTC_RELAY_MODE=none` and
`BITCOIN_NETWORK=signet` from the approved measured `IMAGE-ENV.json`. It requires
a mint or burn role and computes the expected public digest from the approved
launch endpoints. Other `BTC_RELAY_MODE=none` combinations are refused.
`export-attestation` supports the same full policy for mint and burn after
keys are loaded.

`ENCLAVE_DEBUG_MODE=1` skips the deploy launch check because the PCRs are zero.
That path does not approve a real `IndexerTrusted` release.

## Threat model

Trusted: AWS Nitro root CA private key (off-machine), the running enclave
image (PCR-pinned), the verifier's own machine.

NOT trusted: the parent host process, the network between parent and
verifier, any TLS-terminating proxy, any operator with shell on the EC2
instance. None of them can forge an attestation document because none
holds the AWS Nitro per-instance signing key.

Defended:

- **Replay** — the verifier-supplied nonce is signed into the doc and checked
  for equality on response. An old doc is rejected.
- **Pubkey swap by parent** — `public_key` is inside the signed payload.
- **BTC key / xpub swap** — `user_data` commits to the full bundle. A parent
  cannot change one field of `PublicKeysResponse` without breaking the
  commitment match.
- **Posture downgrade** — `user_data` also commits to the resolved
  security policy (signing modes, pins, attestation mode, data sources). An
  enclave that shipped with a weaker posture than expected — plain-BTC signing
  enabled, a different EVM source, indexer trust where SPV was expected, or a
  dev build — fails
  the commitment match against the verifier's expected policy.
- **Fork to a different enclave image** — PCR mismatch on verify.
- **Unapproved image** — verification rejects measurements outside the expected
  PCR set. An old or vulnerable image still passes if its PCRs remain approved.

NOT defended (out of scope for attestation):

- AWS hardware key compromise (same trust assumption as TLS roots).
- Bugs in the enclave code _after_ measurement (PCRs only attest the
  binary; runtime correctness is a separate problem solved by code review,
  fuzzing, audits).
- **Key origin / exclusivity.** The document does not prove where the private
  key was generated, that it lives in only one enclave, or that no cloned or
  imported copy exists — seed cloning is an explicit feature, so the same key
  can run in multiple same-measurement enclaves. Constraints on how keys are
  generated, sealed and cloned come from reviewing the PCR-pinned code, not from
  the attestation document itself. See *What attestation does NOT prove* above.

## Code references

- Enclave-side handler: [`enclave/src/server/keys.rs`](../enclave/src/server/keys.rs)
  (`handle_get_attested_public_key`).
- Parent gRPC handler: [`parent/src/grpc_server.rs`](../parent/src/grpc_server.rs)
  (`attested_public_key`).
- Verifier crate: [`attestation-verify/src/lib.rs`](../attestation-verify/src/lib.rs).
- Verifier library (`verify_attested_pubkey`, `ExpectedPolicy`): [`parent/src/attest_verify.rs`](../parent/src/attest_verify.rs).
- CLI binary: [`parent/src/bin/attest_verify.rs`](../parent/src/bin/attest_verify.rs).
- Security policy: resolved in [`enclave/src/policy.rs`](../enclave/src/policy.rs);
  shared canonical encoding in [`attestation-verify/src/policy.rs`](../attestation-verify/src/policy.rs).
- Wire definitions:
  - Enclave wire: [`enclave-proto/proto/enclave.proto`](../enclave-proto/proto/enclave.proto)
    (`GetAttestedPublicKeyRequest`/`Response`).
  - Parent gRPC: `proto/enclave/parent.proto` in the upstream
    `federated-signer-proto` repo (`ParentService.AttestedPublicKey`).
- Tests:
  - Enclave handler: [`enclave/tests/test_attested_pubkey.rs`](../enclave/tests/test_attested_pubkey.rs).
  - End-to-end gRPC: [`parent/tests/test_grpc_bridge.rs`](../parent/tests/test_grpc_bridge.rs)
    (`grpc_attested_public_key_*`).
