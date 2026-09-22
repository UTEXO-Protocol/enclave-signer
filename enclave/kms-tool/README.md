# KMS seed helper

`kms-tool` links the official [AWS Nitro Enclaves SDK for C](https://github.com/aws/aws-nitro-enclaves-sdk-c/tree/cd61b6187c8b20867ba4368d1ae62c5790c0269a) used by `kmstool_enclave_cli`. The stock CLI generates only 16- or 32-byte keys and does not expose our encryption context. This adapter uses a 64-byte signer seed and constructs four context entries: `application=utexo-enclave-signer`, `flow`, `seed_id`, and `bitcoin_network`. Rust supplies the required `flow` from its compiled custody scope, not host configuration.

AWS implements TLS, SigV4, NSM attestation, RSA and CMS recipient decryption. The helper checks the actual KMS response key ARN, rejects plaintext responses, and requires a 64-byte recipient seed. Generation returns ciphertext only; recovery returns the seed. It connects over vsock to parent CID 3, port 8003; the configured region selects the authenticated KMS hostname and signing scope.

Rust invokes the helper with private stdin/stdout JSON pipes. Credentials are never passed in arguments or environment variables. Messages are bounded, owned credential/seed buffers are erased, core dumps are disabled, and each invocation has a 12-second limit. Failures use fixed exit codes consumed by Rust; raw service diagnostics are discarded. Signing and S3 persistence remain in their existing Rust components.

Build on Linux with `build/build-kms-tool.sh`, or through the Dockerfiles that enable KMS persistence. `build/kms-dependencies.tsv` pins the official sources and `build/kms-nsm.Cargo.lock` pins NSM's Rust dependencies. Security-fixed dependency versions are used instead of upstream's older sample Dockerfile pins. The installed prefix contains dependency revisions, licenses and the unmodified SDK source hash.

The SDK source is unmodified. Its `rest.c` emits cleanup-pointer warnings under GCC; only this dependency uses `-Wno-error=maybe-uninitialized`, so the warnings remain visible. The helper itself retains `-Werror`.

Upstream v0.4.5 can lose a completion notification when a connection closes before its synchronous signing callback finishes, leaving the request waiting until the helper's 12-second deadline. Internal SDK cleanup failures can also terminate the child. Rust rejects failed or late results, and callers can retry without replacing an existing stored identity. This one-request process boundary bounds failed invocations; it does not fix upstream unsafe cleanup paths. The pinned AWS allocator aborts on out-of-memory. TLS, SigV4, attestation and CMS remain the official implementations.

The helper also retains the SDK's bootstrap reference until client cleanup to prevent premature event-loop destruction. Its CMS header is an upstream internal API installed verbatim, so both integrations need review when upgrading the SDK.
