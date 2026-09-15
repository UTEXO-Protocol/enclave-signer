# RGB-swap KMS helper

`swap-kms-tool` links the official [AWS Nitro Enclaves SDK for C](https://github.com/aws/aws-nitro-enclaves-sdk-c/tree/cd61b6187c8b20867ba4368d1ae62c5790c0269a), using the same AWS libraries as `kmstool_enclave_cli` at maintained, security-updated versions. The dependency build pins the SDK and its dependencies to immutable revisions; it intentionally does not copy the obsolete dependency versions in upstream’s sample Dockerfile.

The stock CLI's `genkey` command exposes only 16- and 32-byte key specs. RGB swaps retain their existing 64-byte seed and four-field encryption context. This adapter builds SDK request structures with `NumberOfBytes=64`, invokes the SDK's authenticated HTTPS REST client, and checks the KMS response's key ARN, absence of plaintext, and decrypt algorithm before recipient unwrap. Attestation, RSA generation, CMS parsing, RSA-OAEP and AES decryption all call the official SDK code used by kmstool; no replacement cryptography is included. A scoped SDK patch makes REST request completion and error cleanup safe; its base revision, patch and effective source hashes ship in provenance.

Each invocation uses direct vsock to parent CID 3, port 8003. The configured region determines the SDK's KMS hostname, TLS certificate verification, SNI and SigV4 scope. NSM entropy seeds the operating system pool through the SDK before its TLS and ephemeral RSA operations. KMS generates the persistent seed itself.

The measured Rust enclave invokes `/usr/local/bin/swap-kms-tool` once per request, using private stdin/stdout pipes. Input is one JSON object containing `operation` (`generate` or `decrypt`), `region`, full `key_arn`, `seed_id`, `bitcoin_network`, `access_key_id`, `secret_access_key`, and `session_token`. Decrypt additionally requires base64 `ciphertext`. Generation returns exactly `key_arn` and base64 `ciphertext`. Decryption returns exactly `key_arn` and base64 `seed`; Rust rejects fields belonging to the other operation, including null fields. The four KMS encryption context entries are constructed internally: `application=utexo-enclave-signer`, `flow=rgb-swap`, `seed_id`, and `bitcoin_network`.

Input is restricted to the exact eight/nine named string fields. After json-c
validates JSON, a bounded count of structural member separators must equal the
parsed field count. This rejects duplicate names, including escape-equivalent
names, without replacing JSON parsing. The per-field ASCII check also rejects
lone surrogates or other non-ASCII values accepted by a JSON parser.

The `session_token` field is required but can be empty for long-term AWS
credentials; the official credential and SigV4 APIs treat the token as optional.
Temporary credentials, including the production EC2 role credentials, must
include their issued token. The adapter does not infer credential type from an
access-key prefix or reject valid tokenless credentials.

Messages are limited to 64 KiB, ciphertext blobs to 6144 bytes, and unwrapped seeds to exactly 64 bytes. Core dumps are disabled; execution, CPU and address space are bounded. Credentials and seeds never enter command arguments, environment variables, temporary files or logs. Owned raw seed and credential buffers are erased during cleanup. Live json-c credential strings are overwritten through its public API immediately after creating the SDK credential strings, including rejected-input cleanup. Stdin is unbuffered to avoid another stdio credential copy. json-c parser scratch allocations remain protected by the short-lived process boundary; this is not a guarantee that every library-owned allocation is wiped. Rust clears the child environment and rejects failed, oversized or malformed responses.

The returned `key_arn` comes from the official SDK response's `key_id`, after
an exact match against the measured request ARN. The preceding HTTP response
gate independently checks the actual KMS `KeyId` before SDK parsing and CMS
unwrap; an absent, malformed or different key cannot reach successful output.
This follows the response contract for [GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html)
and [Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html).

Failures use a fixed exit-code contract; no raw HTTP body, SDK error string or
service message is forwarded. Rust retains these categories while discarding
child diagnostics. The adapter adds no automatic retry loop.

| Exit | Meaning |
| --- | --- |
| 0 | Successful operation |
| 64 | Invalid helper input or an allowlisted KMS configuration error |
| 65 | Invalid response, key mismatch, TLS authentication or recipient-integrity failure |
| 69 | Recognized transport failure; retryable within the caller's deadline |
| 70 | Local SDK, NSM or resource failure; no retryability claim |
| 75 | Authenticated KMS throttling, server or documented temporary failure |
| 77 | KMS authentication or authorization failure |
| 78 | KMS key state, key usage or ciphertext rejection |

Only recognized SDK transport constants and authenticated HTTP status/error
types receive retryable categories. Unknown or malformed service errors are
invalid responses. KMS error classification reads an allowlisted `__type`,
never the free-form message; see [KMS common errors](https://docs.aws.amazon.com/kms/latest/APIReference/CommonErrors.html).
New service error types require an explicit review instead of optimistic retry.

The build executes native response-contract tests covering both operations,
wrong/malformed response keys, authoritative output and safe error categories.
It also exercises real stdin parsing for duplicate/escaped names, surrogate and
control values, and the official optional session-token contract, plus a regression test proving that the pinned json-c erases the original credential allocation, including the maximum IPC string length. NSM uses upstream’s `libnsm.so.0` SONAME in the runtime; the unversioned symlink is needed only while linking.

Build with CMake using only `-DCMAKE_PREFIX_PATH=/path/to/installed/prefix`. The dependency build installs the official exported CMS functions' header verbatim and records its checksum in `share/swap-kms/headers.sha256`. It uses json-c's installed CMake package; no separate SDK source path is required when building this helper. The helper and NSM runtime library are included only in RGB-swap images. Signing, HD derivation, S3 ciphertext persistence and RGB mint/burn behavior remain in their existing components.


## Ownership and upgrade policy

This is application-owned integration code, and we maintain it. AWS supplies
all cryptographic, attestation, TLS and signing implementations. The adapter
retains only the behavior needed around the SDK:

- Rust validates measured region/key/seed configuration and typed network
  values. C validates the bounded IPC message and constructs the four KMS
  context entries. C does not maintain a second region or ARN policy parser.
- The helper checks response key identity, absence of plaintext, decryption
  algorithm, ciphertext bounds and the 64-byte recipient seed. Generation still
  unwraps and validates its envelope before permitting the first S3 write, but
  wipes that seed locally and returns only ciphertext. Rust receives plaintext
  only when decrypting the committed storage winner.
- The public SDK decrypt convenience API discards response metadata; its
  generation convenience API lacks our byte-count/context combination. Using
  them directly would remove checks or change the seed/policy contract. The
  short CMS call sequence uses the same exported AWS functions as kmstool.
- A bootstrap reference keeps the SDK-owned event loop alive until connection
  cleanup. Removing it can crash when the peer closes its HTTP response.

The CMS header is under upstream's `internal/` directory. Installing it does
not make it a stable public API. Both that dependency and the bootstrap wrapper
must be reviewed on SDK upgrades. CRT 1.0 also needs explicit installed CMake
module/library paths for this SDK and build-time inclusion of its official
hash-table and Linux vsock headers where upstream relied on transitive include
order. These scoped compiler/CMake settings preserve upstream code apart from that explicit cleanup patch. Do not remove checks merely to reduce line
count or replace them with additional response-interception wrappers.

For an upgrade, compare the pinned SDK/CRT sources and API ownership rules,
rebuild from the dependency manifest and NSM lock, and verify that the installed
header checksum matches upstream. Run the official local SDK tests, the strict
helper IPC tests and full local KMS E2E suite on `kms-testing`, including peer
close, malformed responses, restart, concurrency and legacy-ciphertext recovery.
Build and verify the AL2023 runtime and EIF again. Never publish new PCRs from a
fixture validation image as production measurements.

Upstream API improvements that would let us delete more adapter code are a
GenerateDataKey request API supporting byte count and encryption context, a
public recipient-unwrapping API or decrypt API exposing response metadata, and
a client lifetime fix retaining its bootstrap through connection destruction.
These are documented integration gaps; no upstream acceptance is assumed.

## Security dependency baseline

The manifest uses AWS-LC 5.8.0, s2n-tls 1.7.10, the coordinated AWS CRT 1.0.0
releases, json-c after 0.19 at commit `2094974`, and NSM 0.5.2 with SDK 0.4.5. These contain the fixes for
[s2n TLS record authentication](https://github.com/aws/s2n-tls/security/advisories/GHSA-684c-v35q-fvx7)
and [HTTP/2 HPACK memory corruption](https://github.com/awslabs/aws-c-http/security/advisories/GHSA-rmjr-3qpm-vh98).
The Docker builder verifies architecture-specific SHA-256 hashes of Go 1.27.1
because AWS-LC requires Go 1.20 or newer; Bullseye's Go 1.15 is unsupported.
Recheck the official advisories when updating pins; the manifest is a reviewed
snapshot, not an assurance against future vulnerabilities.

The json-c 0.19 release omits container deallocation under `NDEBUG`: its free
call is inside an assertion. Release sanitizer stress tests detected the leak.
The manifest therefore pins the unmodified upstream snapshot through
[`2094974`](https://github.com/json-c/json-c/commit/2094974201fc75b07673110cc40a3e144cbd3b0d),
which includes the [release deallocation correction](https://github.com/json-c/json-c/commit/f291fa81c6f21d925ea771a8cca597f5886309cc)
and subsequent object-lifetime/failed-insertion corrections. This is an explicit
post-release source pin until a stable release includes those fixes; it is not
a local patch or a change to release assertion behavior.

## Scoped SDK cleanup patch

`build/patches/nitro-sdk-cleanup.patch` fixes two uninitialized local pointers in
SDK `source/rest.c`: `stream` and `sign_request` can otherwise reach cleanup
before their declarations on early failures. It initializes them to `NULL`,
checks partial allocations and makes partial response destruction safe. A
completion predicate records completion under the request mutex so synchronous
notifications are not lost and spurious wakes cannot end the wait early;
mutex/condition resources are released on both exits. TLS, SigV4, attestation and CMS algorithms remain
the upstream implementation. GCC builds retain the SDK's `-Werror` checks;
there is no blanket suppression of the uninitialized-variable diagnostic.

This is a maintained application patch until an official SDK revision contains
the correction. The build applies it only over a clean pinned SDK checkout and
then requires the complete tracked diff to match the checked-in patch exactly.
Reused caches with any other changes fail; use a fresh dependency build
directory when changing the patch. Runtime provenance includes the
original SDK commit, patch SHA-256 and effective `rest.c` SHA-256 in
`share/swap-kms/sdk-source.json`, plus the patch itself. Fault-injection tests
exercise SDK early cleanup, synchronous/asynchronous completion and spurious
wakes through test-only linker wrappers.
