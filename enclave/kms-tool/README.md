# RGB-swap KMS helper

`swap-kms-tool` links the unmodified official [AWS Nitro Enclaves SDK for C](https://github.com/aws/aws-nitro-enclaves-sdk-c/tree/cd61b6187c8b20867ba4368d1ae62c5790c0269a), using the same AWS libraries as `kmstool_enclave_cli`. The dependency build pins the SDK and its dependencies to immutable revisions.

The stock CLI's `genkey` command exposes only 16- and 32-byte key specs. RGB swaps retain their existing 64-byte seed and four-field encryption context. This adapter builds SDK request structures with `NumberOfBytes=64`, invokes the SDK's authenticated HTTPS REST client, and checks the KMS response's key ARN, absence of plaintext, and decrypt algorithm before recipient unwrap. Attestation, RSA generation, CMS parsing, RSA-OAEP and AES decryption all call the official SDK code used by kmstool; no SDK source patch or replacement cryptography is included.

Each invocation uses direct vsock to parent CID 3, port 8003. The configured region determines the SDK's KMS hostname, TLS certificate verification, SNI and SigV4 scope. NSM entropy seeds the operating system pool through the SDK before its TLS and ephemeral RSA operations. KMS generates the persistent seed itself.

The measured Rust enclave invokes `/usr/local/bin/swap-kms-tool` once per request, using private stdin/stdout pipes. Input is one JSON object containing `operation` (`generate` or `decrypt`), `region`, full `key_arn`, `seed_id`, `bitcoin_network`, `access_key_id`, `secret_access_key`, and `session_token`. Decrypt additionally requires base64 `ciphertext`. Generation returns exactly `key_arn` and base64 `ciphertext`. Decryption returns exactly `key_arn` and base64 `seed`; Rust rejects fields belonging to the other operation, including null fields. The four KMS encryption context entries are constructed internally: `application=utexo-enclave-signer`, `flow=rgb-swap`, `seed_id`, and `bitcoin_network`.

Messages are limited to 64 KiB, ciphertext blobs to 6144 bytes, and unwrapped seeds to exactly 64 bytes. Core dumps are disabled; execution, CPU and address space are bounded. Credentials and seeds never enter command arguments, environment variables, temporary files or logs. Owned raw seed and credential buffers are erased during cleanup; json-c's input copies exist only for the short-lived helper process. Rust clears the child environment and rejects failed, oversized or malformed responses.

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
- A bootstrap reference keeps the pinned CRT event loop alive until connection
  cleanup. Removing it can crash when the peer closes its HTTP response.

The CMS header is under upstream's `internal/` directory. Installing it does
not make it a stable public API. Both that dependency and the bootstrap wrapper
must be reviewed on SDK upgrades. Do not remove checks merely to reduce line
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
