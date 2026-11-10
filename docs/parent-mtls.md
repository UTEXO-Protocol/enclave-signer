# Parent mTLS and access to the enclave

The parent serves `parent.ParentService` over gRPC. It requires mTLS, and a
client ACL gives each caller a role. This document lists the settings, the
roles, and every path into the enclave. Source:
`parent/src/transport_security.rs`.

The parent decides only who may call the enclave. Every signing check runs
inside the enclave, on every path.

## Configuration

| Variable | Meaning |
| --- | --- |
| `GRPC_TLS_CERT_FILE` | Server certificate chain (PEM). |
| `GRPC_TLS_KEY_FILE` | Server private key (PEM). |
| `GRPC_TLS_CLIENT_CA_FILE` | CA that signs the client certificates (PEM). A client without a certificate from this CA fails the handshake. |
| `GRPC_TLS_ACL_FILE` | Client ACL. One `<leaf_sha256> <role>` line per client. `<leaf_sha256>` is the SHA-256 of the client leaf certificate (DER), 64 hex characters. `#` starts a comment. At most 512 identities. |
| `GRPC_MAX_CONNECTIONS` | Open connection cap, `1..4096`, default `64`. |
| `GRPC_CLONE_MAX_PER_MINUTE` | `Clone` calls per minute for all clients, `1..10000`, default `30`. |
| `GRPC_ATTEST_MAX_PER_MINUTE` | `AttestedPublicKey` calls per minute for all clients, `1..10000`, default `6`. |
| `GRPC_ALLOW_INSECURE_LOOPBACK` | `true` turns off TLS and the ACL. The parent then requires a loopback bind and no `GRPC_TLS_*` setting. Use it only for tests. |

The parent refuses to start with only some of the four `GRPC_TLS_*` files,
and with a `GRPC_MAX_CONNECTIONS` or a budget that is out of range or not a
number. With mTLS, a call over the `Clone` or `AttestedPublicKey` budget gets
`RESOURCE_EXHAUSTED` before it reaches the enclave. The loopback mode has no
budget. The other parent settings are in
[configuration.md](configuration.md#parent-settings).

A debug build with the `insecure-dev` feature serves plaintext with no ACL,
on any address, and its clients accept plaintext to any host. A release build
refuses that feature at compile time.

## Roles

| Role | RPCs |
| --- | --- |
| every role | `PublicKey`, `AttestedPublicKey`, `GetLastSavedBlock` |
| `listener` | the above, and `Sign` |
| `clone-operator` | the above, and `Clone` |
| `observer` | the above only |

No role may call `Initialize`. The `SubmitHeaders` handler refuses every
caller (`parent/src/grpc_server.rs`). An unknown certificate gets
`PermissionDenied: client not authorized`. A known certificate that calls
an RPC outside its role gets `PermissionDenied: RPC not authorized`.

## Clients

`attest-verify` and `cli clone --donor-grpc` use `https://` with
`PARENT_TLS_CA_FILE`, `PARENT_TLS_CERT_FILE`, `PARENT_TLS_KEY_FILE` and, if
the certificate name differs from the host, `PARENT_TLS_SERVER_NAME`. They
use plaintext only to a loopback IP.

## Connection lifetime

The parent sends HTTP/2 `GOAWAY` when a connection reaches its maximum age of
300 seconds. Accepted RPCs finish on the old connection while the client
opens a new one. The parent closes the old connection when its RPCs end, or
at the connection deadline: the connection age plus
`GRPC_REQUEST_TIMEOUT_SECS` plus 10 seconds, counted from the TLS handshake.
The startup log reports these values.

The parent leaves `max_connection_age_grace` unset. In tonic 0.14.9, a grace
together with a maximum age skips the graceful drain and closes the
connection by force at age plus grace.

## Host rollout

`deploy/deploy-host.sh` reads `server.pem`, `server.key`, `client-ca.pem` and
`clients.acl` from `$PARENT_TLS_DIR/<CID>/` (default `/etc/utexo/tls`). It
stops before it changes a service if one of them is missing, empty or not
readable by the `ubuntu` user.

## Access matrix

| Path into the enclave | Who can use it | Checks before the enclave | What it can send |
| --- | --- | --- | --- |
| Parent gRPC with mTLS | A client with a certificate from the client CA whose SHA-256 is in the ACL | TLS handshake, ACL pin, role, `Clone` and `AttestedPublicKey` budgets, connection cap, concurrency limit, request timeout (`parent/src/main.rs`) | The RPCs of its role |
| Parent gRPC, insecure loopback | Any process on the parent instance | Connection cap, concurrency limit, request timeout. No TLS, ACL, role or budget. | Every parent RPC. `SubmitHeaders` is still refused. |
| Parent `GET /health` (`HEALTH_HOST:HEALTH_PORT`, default `127.0.0.1:5001`) | Any process that reaches that address | None | `Health` only |
| Parent CLI `utexo-bridge-parent-cli --addr vsock://<CID>:5000` | Any process on the parent instance | None. The CLI opens the vsock connection itself. | Its fixed commands: `init`, `init-seed`, `init-mnemonic`, `get-keys`, `sign-evm`, `sign-psbt`, `get-last-saved-block`, `health`, `set-endpoints`, `verify-launch`, `export-attestation`, `clone`, `limits`, `interactive` |
| Direct vsock, port 5000 (`enclave/src/main.rs`) | Any process on the parent instance with its own client | None. The enclave does not identify the caller (`enclave/src/server/wire.rs`). | Every `EnclaveRequest` in `enclave-proto/proto/enclave.proto` |

The enclave applies the same checks on every path
(`enclave/src/server/dispatch.rs`):

- `Sign`, `SignBtc`, `SignRightsRefill` and `SignRawDigest` are
  refused until `SetEndpoints` is accepted.
- `Sign` checks the signer role, then the source, destination and route
  proofs, then signs with the key.
- `SignRawMessage` is always refused.
- `SignRawDigest` signs only a gas transaction that passes the pinned
  checks, with the gas key only.
- `SetEndpoints` is accepted once.
- `SetLimits` has no check of the caller. It changes only the limits at
  which the enclave refuses or delays a request, not what the enclave signs.
- `GetClone` checks the requester attestation and the cloning secret.
- `Health` has no check.

Only the parent instance can reach the enclave CID. That is the AWS Nitro
Enclaves model, not a check in this code. A dev build without `vsock`
listens on TCP `ENCLAVE_LISTEN_ADDR` (default `127.0.0.1:5000`) instead.
