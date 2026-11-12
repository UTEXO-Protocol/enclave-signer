# Attested signing keys

An attestation binds a public-key bundle to measured enclave code and its
security policy. This document says what that proves, how the bytes are
built, and how to verify them. For a step-by-step check of a published
bundle, see [verify-a-signer.md](verify-a-signer.md).

## What an attestation proves

Successful verification shows one thing: **approved, measured code (PCR0,
PCR1, PCR2) answered the verifier's fresh nonce with this key bundle and
this policy.** The verifier must trust AWS Nitro and approve the expected
measurements.

It does **not** show any of these, and a consumer MUST NOT rely on them:

- **Key origin.** The document does not prove where or when the private key
  was made. The code can attest a generated, a recovered or a cloned key.
- **Exclusive custody.** The same seed can exist in several enclaves. Burn
  replicas clone it. Mint replicas recover the same KMS seed.
- **No earlier copy.** Attestation cannot prove that no party held the key
  before.
- **Readiness.** The request does not contact the EVM RPC. Verification can
  succeed while the provider is down, and it does not show that the signer
  can complete a request now.
- **Honest data.** The policy names the configured endpoint. It does not
  prove that the provider's answers are true.

The rules for how keys are made, kept and cloned come from the measured code,
not from the document ([tee-spec.md](tee-spec.md#5-keys-and-lifecycle)).

The chain of trust:

```
AWS Nitro root CA  (public, embedded in the verifier)
       │ signs
AWS region intermediates
       │ sign
The NSM signing certificate of this EC2 instance
       │ signs (P-384 ECDSA, COSE_Sign1)
Attestation document { pcrs, public_key, user_data, nonce, timestamp, ... }
```

## Protocol

```
verifier                                 parent gRPC                      enclave (Nitro)
   │ 1. nonce ← rand(32)                      │                                 │
   │ 2. AttestedPublicKey(nonce) ────────────▶│                                 │
   │                                          │ 3. GetAttestedPublicKey(nonce) ▶│
   │                                          │                                 │ 4. the NSM signs a document
   │                                          │                                 │    over the PCRs, the nonce,
   │                                          │                                 │    public_key and user_data
   │                                          │ ◀── (public_keys, doc, policy) ─│
   │ ◀── AttestedPublicKeyResponse ───────────│                                 │
   │ 5. verify the chain, the signature, the PCRs, the nonce,
   │    public_key and user_data.
```

See the [sequence diagram](diagrams/05-seq-attested-pubkey.md).

Until `SetEndpoints`, the enclave refuses the request. Before keys exist it
attests the policy only: `public_keys` is empty, the document has no
`public_key`, and `user_data` is
`sha256("utexo/attested-policy/v1\0" || policy_bytes)`. The deploy reads
this answer through the CLI for its
[launch check](operations.md#launch-check). The parent's gRPC
`AttestedPublicKey` refuses an answer without keys.

## What the document binds

The enclave fills the three caller fields of the NSM document:

| NSM field | Value |
|-----------|-------|
| `public_key` | `evm_uncompressed_pub`: the bridge signing key, 64 bytes, X \|\| Y |
| `user_data` | `sha256(canonical_bundle \|\| policy_commitment)`: 32 bytes over the key bundle and the security policy |
| `nonce` | The 32-byte nonce of the verifier |

A verifier that needs only the signing address can stop at `public_key`. A
full verifier rebuilds the bundle and the expected policy and checks
`user_data`. That shows that the parent swapped no account key, and that the
posture of the enclave is the expected one.

### Canonical bundle encoding

Concatenate every field of `PublicKeysResponse` in proto field order. Prefix
each field with its length as a big-endian u32. Strings are UTF-8.
`chain_id` is 8 bytes, big-endian.

```
canonical_bundle =
    u32_be(len(evm_address))                 || evm_address
    u32_be(len(master_fingerprint))          || master_fingerprint
    u32_be(len(account_xpub_vanilla))        || account_xpub_vanilla_utf8
    u32_be(len(account_xpub_colored))        || account_xpub_colored_utf8
    u32_be(len(evm_uncompressed_pub))        || evm_uncompressed_pub
    u32_be(8)                                || chain_id_be8
    u32_be(len(bridge_contract))             || bridge_contract       // 20 bytes (zeros = unset)
    u32_be(len(rgb_asset_id))                || rgb_asset_id_utf8
    u32_be(len(evm_gas_tx_uncompressed_pub)) || evm_gas_tx_uncompressed_pub   // 64 bytes
    u32_be(len(evm_gas_tx_address))          || evm_gas_tx_address            // 20 bytes
```

Ten fields, in every build. `chain_id`, `bridge_contract` and `rgb_asset_id`
are the image pins `EVM_CHAIN_ID`, `EVM_PROXY_CONTRACT_ADDRESS` (the
`MultisigProxy`) and `RGB_ASSET_ID`. An unpinned dev build commits
`chain_id=0`, 20 zero bytes and an empty asset id.

A verifier MUST use the same fields, order and length prefixes. The reference
encoder is `canonical_pubkey_bundle` in
[`enclave/src/server/keys.rs`](../enclave/src/server/keys.rs). The verifier's
encoder is `canonical_bundle` in
[`parent/src/attest_verify.rs`](../parent/src/attest_verify.rs). The offline
bundle format is `utexo-signer-attestation/3`.

### Security policy commitment

The enclave resolves its policy once, at `SetEndpoints`
([`enclave/src/policy.rs`](../enclave/src/policy.rs)). The encoding is in
[`attestation-verify/src/policy.rs`](../attestation-verify/src/policy.rs),
which the enclave and every verifier share. The response carries the bytes
(`attested_policy`).

```
policy_commitment =
    u8(POLICY_COMMITMENT_V1 = 1)                    // version tag
    // Production (release, fully pinned bridge signer):
    u8(0x01)                                        // production discriminant
    u8(allow_vanilla_psbt)                          // plain-BTC path on?
    u8(signer_role)                                 // 0 combined | 1 mint | 2 burn
    u8(attestation_mode)                            // 1 = real NSM (0 = mock)
    u8(evm_source)                                  // 0 disabled | 1, 2 reserved | 3 pinned TLS rpc
    u8(btc_source)                                  // 1 = SPV-verified
    chain_id_be8
    u8(bitcoin_network)                             // 0 mainnet | 1 testnet3 | 2 signet | 3 regtest | 4 testnet4 | 5 signetcustom
    bridge_contract(20)
    u32_be(len(rgb_asset_id)) || rgb_asset_id_utf8
    funds_in_contract(20)                           // authorized event emitter
    u8(evm_finality_tag)                            // 0 latest | 1 safe | 2 finalized
    spv_min_confirmations_be4                       // required Bitcoin witness depth
    u32_be(len(electrum_host)) || electrum_host     // indexer host, set at launch
    u8(evm_rpc_tls_present)                         // 0 absent; 1 followed by:
      u32_be(len(host)) || host || ca_sha256(32)    //   EVM RPC host, SHA-256 of the CA DER, set at launch
    // Gas-tx (SignRawDigest) rule:
    gas_tx_allowed_to(20)                           // all-zero = gas path unpinned
    gas_tx_max_gas_limit_be8                        // gasLimit ceiling (0 = unset)
    gas_tx_max_fee_per_gas_be16                     // per-gas fee ceiling, wei (0 = unset)
    gas_tx_max_value_wei_be16                       // native-value ceiling, wei (0 = unset)
    u32_be(count(selectors)) || selector(4)...      // sorted, without duplicates
    token_contract(20)                              // released ERC-20 (burnId preimage input)
    u8(kms_present)                                 // 0 absent; 1 followed by (set at launch):
      u32_be(len(key_arn)) || key_arn || u32_be(len(region)) || region
      || u32_be(len(seed_id)) || seed_id
      || u8(address_present) [|| expected_evm_address(20)]
    u8(clone_peer_pcr3_present)                     // 1 for a cloning role (burn, combined), 0 for mint
      [|| clone_peer_pcr3(48)]                      //   own PCR3 (parent IAM role), never all zero
    // Development (debug, test, dev-feature, no-SPV, or unpinned build):
    u8(0x00)                                        // development discriminant
```

Notes on the fields:

- **Development.** A dev or mock enclave, and a real-attestation build
  without `spv`, commit only `[version, 0x00]`: no endpoint, no pin, no rule.
- **`evm_finality_tag`.** Production verification requires
  `--expect-evm-finality-tag` with the approved `safe` or `finalized`. A
  production enclave refuses `latest`, and so does the verifier.
- **`spv_min_confirmations`.** Only the burn signer checks it.
- **`bitcoin_network`.** The network of the header chain and of the accepted
  consignments. A verifier declares it (`--expect-bitcoin-network`).
- **The gas rule.** The whole `SignRawDigest` rule is committed, so a
  verifier can check it. An unset ceiling commits as 0, which is the rule it
  enforces: a zero gas or fee ceiling refuses every gas transaction, and a
  zero value ceiling refuses every non-zero value. So an unset rule and a
  zero rule give the same bytes.
- **`clone_peer_pcr3`.** A verifier sets no expected value. It takes PCR3
  from the verified document, requires it to be present and not all zero for
  a cloning role, and expects none for the mint signer.
- **Not committed.** The scheme and port of the indexer URL, the EVM RPC
  port and path, `BTC_MAX_UNOWNED_SATS`, the value of `BTC_MAX_TOTAL_SATS`
  (only on or off, as `allow_vanilla_psbt`), `MINT_WITNESS_SAT` and the
  runtime limits ([tee-spec.md](tee-spec.md#4-security-policy)).

## Expected values

A verifier must get its expected values from a source outside the response.
The document under check cannot say what is acceptable.

**PCRs.** PCR0 measures the image, PCR1 the kernel and bootstrap, PCR2 the
application. This repository publishes the measurements with the EIF
artifacts (`PCR.json`). A verifier can also rebuild the EIF
([building.md](building.md#reproducibility)). A file checksum and a PCR are
different values. An old or weak image still verifies while its PCRs stay
approved, so the approval of measurements is part of the security.

**Policy.** The verifier builds the expected policy from its own settings:
the role, the image pins and acceptance rules, and the independently approved
launch values ([configuration.md](configuration.md)). Checking the image
identity and approving the launch values are two separate checks. The
launch values are not in the PCRs, and a provider API key is in neither the
PCRs nor the policy.

**Bridge pins.** `attest-verify` reads `chain_id`, `bridge_contract` and
`rgb_asset_id` from the authenticated response. To compare them with the
intended deployment, pass `--expect-chain-id`, `--expect-bridge-contract`
and `--expect-rgb-asset-id`. Without these flags the pins are authenticated
but not compared: the caller must compare the printed values.

## Verification by hand

Given `(public_keys_bundle, attestation_doc, nonce_sent, expected_pcrs)`:

1. Parse `attestation_doc` as `COSE_Sign1` (a CBOR array of length 4).
   Require ES384 (`alg = -35`) in the protected header.
2. Parse the inner CBOR payload as `AttestationDocument`.
3. Verify the certificate chain in `cabundle`:
    - `cabundle[0]` must equal the AWS Nitro root CA, byte for byte (DER).
    - For each `i`, `cabundle[i]` must sign `cabundle[i+1]`.
    - `cabundle[last]` must sign `signing_cert`, the certificate in the
      document.
    - Check the validity of each certificate against the local clock, with a
      tolerance of 60 seconds.
    - Require CA `BasicConstraints` on each issuer. Check the path-length
      limits.
    - If an issuer has `KeyUsage`, require `keyCertSign`. If the signing
      certificate has `KeyUsage`, require `digitalSignature`.
4. Verify the COSE signature: P-384 ECDSA over
   `Sig_structure1 = ["Signature1", protected, h"", payload]`. The signature
   is raw `r||s` (96 bytes), not DER (RFC 8152, section 8.1).
5. Reject a document whose PCR0, PCR1 and PCR2 are all zero: it comes from
   an enclave in debug mode. Compare each PCR with its expected value, byte
   for byte.
6. Nonce: `doc.nonce == nonce_sent`.
7. Public key: `doc.public_key == public_keys_bundle.evm_uncompressed_pub`.
8. Commitment:
   `doc.user_data == sha256(canonical_bundle(public_keys_bundle) || attested_policy)`.
   Then decode `attested_policy` and require it to equal the expected policy.

If all eight checks pass, the EVM address
(`keccak256(evm_uncompressed_pub)[12..]`) is bound to the measured code, and
the attested posture is the expected one.

The verifier returns the document timestamp but enforces no maximum age.
Freshness comes from a new unpredictable nonce. Do not reuse a nonce.

## Verification with `attest-verify`

The `attest-verify` CLI runs the whole recipe. It calls the parent, so
configure the client certificate first
([parent-mtls.md](parent-mtls.md#clients)); the `observer` role is enough.

```bash
# The CA hash, from the same DER that the operator set:
#   openssl x509 -in ca.pem -outform der | openssl dgst -sha256 -hex
attest-verify \
    --endpoint https://parent.example:50051 \
    --pcr0 <96-hex-chars> --pcr1 <96-hex-chars> --pcr2 <96-hex-chars> \
    --expect-signer-role burn \
    --expect-funds-in-contract 0x6711f1a319B37847fa0234181C34D883774c4951 \
    --expect-token-contract 0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9 \
    --expect-evm-finality-tag finalized \
    --expect-spv-min-confirmations 3 \
    --expect-gas-tx-to 0xC985c12bbCECe96A13A72A62FD75d8aB9381ef5A \
    --expect-electrum-host <electrum host> \
    --expect-evm-rpc-host <rpc host> \
    --expect-evm-rpc-ca-sha256 <64-hex-chars>
```

| Flags | Expected value |
|-------|----------------|
| `--pcr0`, `--pcr1`, `--pcr2` | Required: the approved measurements. |
| `--expect-signer-role` | Required: `mint` or `burn`. `combined` names a build with no signer role; such a build attests `Development` and does not pass this check. |
| `--expect-evm-finality-tag` | Required: `safe` or `finalized`. |
| `--expect-funds-in-contract`, `--expect-token-contract` | Required: the image pins. |
| `--expect-spv-min-confirmations`, `--expect-bitcoin-network` | The image values. Defaults: 3 and `bitcoin`. |
| `--expect-electrum-host` | Required: the approved indexer host. |
| `--expect-evm-rpc-host`, `--expect-evm-rpc-ca-sha256` | Required with the `tls` source: the approved RPC host and CA hash. |
| `--expect-evm-source` | `tls` (the default, and what the images use) or `disabled`. |
| `--expect-gas-tx-to`, `--expect-gas-max-gas-limit`, `--expect-gas-max-fee-per-gas`, `--expect-gas-max-value-wei`, `--expect-gas-selectors` | The gas rule of a burn signer. An omitted flag expects an unset value, not the value of the enclave. |
| `--expect-vanilla-psbt` | A mint signer with plain-BTC signing on. |
| `--expect-kms-key-arn`, `--expect-kms-region`, `--expect-kms-seed-id`, `--expect-kms-evm-address` | The KMS values of a mint signer. The first three are required with the role `mint`; the address only when the operator set one. |
| `--expect-chain-id`, `--expect-bridge-contract`, `--expect-rgb-asset-id` | Optional: compare the bridge pins. |
| `--from-file <bundle.json>` | Verify a published bundle offline ([verify-a-signer.md](verify-a-signer.md)). |
| `--mock` | Dev and CI only: a `mock-attestation` enclave. Expects a `Development` policy. |

A role attests the path of the other role as off, whatever its env says. A
burn signer never attests plain-BTC signing, so omit `--expect-vanilla-psbt`.
A mint signer never attests a gas rule, so omit the `--expect-gas-*` flags.
The mint recipe sets `BTC_MAX_TOTAL_SATS`, so its check needs
`--expect-vanilla-psbt`:

```bash
attest-verify --endpoint https://parent.example:50051 \
    --pcr0 <..> --pcr1 <..> --pcr2 <..> --expect-signer-role mint \
    --expect-funds-in-contract <hex20> --expect-token-contract <hex20> \
    --expect-evm-finality-tag finalized \
    --expect-electrum-host <electrum host> \
    --expect-evm-rpc-host <rpc host> --expect-evm-rpc-ca-sha256 <64-hex-chars> \
    --expect-kms-key-arn <arn> --expect-kms-region <region> --expect-kms-seed-id <id> \
    --expect-vanilla-psbt
```

A successful run prints `OK` and every verified field as one `name: value`
line. Most names are the paths of the exported bundle.

| Exit code | Meaning |
|-----------|---------|
| 0 | All checks passed. |
| 1 | An error after argument parsing: verification, connection, file I/O, or a missing or invalid setting. See stderr. |
| 2 | Argument parsing failed, for example an unknown flag or a missing `--expect-evm-finality-tag`. |

## Threat model

Trusted: the AWS Nitro root CA, the enclave image with the approved PCRs, and
the verifier's own machine.

Not trusted: the parent, the network between the parent and the verifier, a
proxy that ends TLS, and an operator with a shell on the EC2 instance. None
of them holds the NSM signing key, so none can forge a document.

| Attack | Defense |
|--------|---------|
| Replay of an old document | The verifier's nonce is in the signed document. |
| The parent swaps the signing key | `public_key` is in the signed document. |
| The parent swaps an account xpub or another bundle field | `user_data` commits the whole bundle. |
| A weaker posture: plain-BTC signing on, another EVM source, a dev build | `user_data` commits the policy, and the verifier compares it with the expected one. |
| Another enclave image | The PCRs differ. |

Out of scope for attestation: a compromise of the AWS hardware keys, and a
bug in the measured code. The PCRs identify the binary; they do not show
that it is correct.

## Code references

- Enclave handler: [`enclave/src/server/keys.rs`](../enclave/src/server/keys.rs)
  (`handle_get_attested_public_key`).
- Parent gRPC handler: [`parent/src/grpc_server.rs`](../parent/src/grpc_server.rs)
  (`attested_public_key`).
- Verifier crate: [`attestation-verify/src/lib.rs`](../attestation-verify/src/lib.rs).
- Verifier library (`verify_attested_pubkey`, `ExpectedPolicy`):
  [`parent/src/attest_verify.rs`](../parent/src/attest_verify.rs).
- CLI: [`parent/src/bin/attest_verify.rs`](../parent/src/bin/attest_verify.rs).
- Wire: [`enclave-proto/proto/enclave.proto`](../enclave-proto/proto/enclave.proto)
  (`GetAttestedPublicKeyRequest`), and `proto/enclave/parent.proto` in
  `federated-signer-proto` (`ParentService.AttestedPublicKey`).
- Tests: [`enclave/tests/test_attested_pubkey.rs`](../enclave/tests/test_attested_pubkey.rs),
  [`parent/tests/test_grpc_bridge.rs`](../parent/tests/test_grpc_bridge.rs).
