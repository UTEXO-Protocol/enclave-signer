# Parent mTLS and access to the enclave

The parent serves `parent.ParentService` over gRPC. It requires mTLS unless
it runs in the loopback test mode. Source: `parent/src/transport_security.rs`.

## Configuration

| Variable | Meaning |
| --- | --- |
| `GRPC_TLS_CERT_FILE` | Server certificate chain (PEM). |
| `GRPC_TLS_KEY_FILE` | Server private key (PEM). |
| `GRPC_TLS_CLIENT_CA_FILE` | CA that signs the client certificates (PEM). A client without a certificate from this CA fails the handshake. |
| `GRPC_TLS_ACL_FILE` | Client ACL. One `<leaf_sha256> <role>` line per client. `<leaf_sha256>` is the SHA-256 of the client leaf certificate (DER), 64 hex characters. `#` starts a comment. At most 512 lines. |
| `GRPC_MAX_CONNECTIONS` | Open connection cap, `1..4096`, default `64`. |
| `GRPC_CLONE_MAX_PER_MINUTE` | `Clone` calls per minute for all clients, `1..10000`, default `30`. |
| `GRPC_ALLOW_INSECURE_LOOPBACK` | `true` turns off TLS and the ACL. The parent then requires a loopback bind and no `GRPC_TLS_*` setting. Use it only for tests. |

The parent refuses to start with only some of the four `GRPC_TLS_*` files.

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

## Host rollout

`deploy/deploy-host.sh` reads `server.pem`, `server.key`, `client-ca.pem` and
`clients.acl` from `$PARENT_TLS_DIR/<CID>/` (default `/etc/utexo/tls`). It
stops before it changes a service if one of them is missing or not readable
by the `ubuntu` user.

Clients (`attest-verify`, `cli clone --donor-grpc`) use `https://` with
`PARENT_TLS_CA_FILE`, `PARENT_TLS_CERT_FILE`, `PARENT_TLS_KEY_FILE` and, if
the certificate name differs from the host, `PARENT_TLS_SERVER_NAME`. They
use plaintext only to a loopback IP.

## Access matrix

| Path into the enclave | Who can use it | Checks before the enclave | What it can send |
| --- | --- | --- | --- |
| Parent gRPC with mTLS | A client with a certificate from the client CA whose SHA-256 is in the ACL | TLS handshake, ACL pin, role, `Clone` budget (on `Clone` only), connection cap, concurrency limit, request timeout (`parent/src/main.rs`) | The RPCs of its role |
| Parent gRPC, insecure loopback | Any process on the parent instance | None | Every parent RPC. `SubmitHeaders` is still refused. |
| Parent `GET /health` (`HEALTH_HOST:HEALTH_PORT`, default `127.0.0.1:5001`) | Any process that reaches that address | None | `Health` only |
| Parent CLI `utexo-bridge-parent-cli --addr vsock://<CID>:5000` | Any process on the parent instance | None. The CLI opens the vsock connection itself. | Its fixed commands: `init`, `init-seed`, `init-mnemonic`, `get-keys`, `sign-evm`, `sign-psbt`, `get-last-saved-block`, `health`, `set-endpoints`, `verify-launch`, `export-attestation`, `clone`, `interactive` |
| Direct vsock, port 5000 (`enclave/src/main.rs`) | Any process on the parent instance with its own client | None. The enclave does not identify the caller (`enclave/src/server/wire.rs`). | Every `EnclaveRequest` in `enclave-proto/proto/enclave.proto` |

Every signing check lives in the enclave. The parent decides only who may
call it. The enclave applies the same checks on every path
(`enclave/src/server/dispatch.rs`):

- `Sign`, `SignBtc`, `SignRawDigest` and `SignCcd` are refused until
  `SetEndpoints` is accepted.
- `Sign` checks the signer role, then the source, destination and route
  proofs, then signs with the key.
- `SignRawMessage` is always refused.
- `SignRawDigest` signs only a gas transaction that passes the pinned
  checks, with the gas key only.
- `SetEndpoints` is accepted once.
- `GetClone` checks the requester attestation and the cloning secret.
- `Health` has no check.

Only the parent instance can reach the enclave CID. That is the AWS Nitro
Enclaves model, not a check in this code. A dev build without `vsock`
listens on TCP `ENCLAVE_LISTEN_ADDR` (default `127.0.0.1:5000`) instead.
