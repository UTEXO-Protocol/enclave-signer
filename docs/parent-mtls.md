# Parent gRPC mTLS and authorization (F03-AF-13)

This is a breaking host/client transport change. Deploy the matching Parent,
Rust CLI/attest-verify and Go listener client together with provisioned TLS files.
The enclave protocol, EIF and PCRs are unchanged. TLS certificates identify
host-side callers; enclave NSM attestation, PCR policy and cloning-secret HMAC
remain separate checks and are still required for seed export.

## Server configuration

Required environment variables:

- `GRPC_TLS_CERT_FILE`: server PEM certificate chain (leaf first).
- `GRPC_TLS_KEY_FILE`: corresponding PEM private key.
- `GRPC_TLS_CLIENT_CA_FILE`: CA PEM bundle for verifying client certificates.
- `GRPC_TLS_ACL_FILE`: authorized client leaf SHA-256 fingerprints and roles.

Missing, empty, malformed or partial configuration fails startup. Client
certificates are mandatory. Issue server certificates with serverAuth EKU and
DNS/IP SANs matching the addresses clients use; issue clients with clientAuth
EKU. Keep the issuing CA key off the enclave hosts. Store host/client keys outside
images, build logs and Git, with access restricted to the service account.

ACL format (one identity/role per line, optional `#` comment):

```text
<64-hex-leaf-certificate-sha256> clone-operator
<another-64-hex-leaf-certificate-sha256> listener
<a-third-64-hex-leaf-certificate-sha256> observer
```

Compute the fingerprint over the certificate DER, not PEM text or public key:

```bash
openssl x509 -in client.pem -outform DER | sha256sum
```

Each Parent has its own ACL. Assign distinct certificates per operator/listener
and restrict each listener to its intended Parent/CID. A CA-signed certificate
alone grants no RPC access. Duplicate fingerprints, unknown roles, an empty ACL
and more than 512 entries fail startup.

- All three roles may call `PublicKey`, `AttestedPublicKey`, `GetLastSavedBlock`.
- `clone-operator` may additionally call `Clone`.
- `listener` may additionally call `Sign` and `SubmitHeaders`.
- `observer` has no mutation permissions.
- `Initialize` is denied for every network role. Initialize locally through the
  host CLI over vsock. Unknown RPCs are denied by default.

Authorization runs before protobuf decoding/handler dispatch and enclave I/O.
These host controls do not protect against a compromised Parent host.

## Resource and logging bounds

- `GRPC_MAX_CONNECTIONS`: 64 by default, range 1–4096. Includes sockets still
  performing TLS handshakes, not only established HTTP/2 sessions. Excess sockets
  are closed immediately. TLS handshakes time out after 5 seconds.
- Connections have a 300-second maximum age plus 30 seconds graceful drain.
- Existing global/per-connection request concurrency, stream and request timeout
  limits remain in effect; overload is shed instead of queued indefinitely.
- `GRPC_CLONE_MAX_PER_MINUTE`: 30 by default, range 1–10000. One fixed window per
  Parent process shared by all authorized clone callers/connections. A window
  resets after 60 seconds or a Parent restart. This is an admission limit, not
  the enclave's separate export quota or a rolling-window guarantee.
- ACL rejection and Clone rate-limit rejection do not log each request. The
  Clone handler no longer logs caller-provided public-key bytes. Use normal
  production log levels: tonic TLS errors can produce per-connection debug logs
  when debug/trace is explicitly enabled.

Connection caps and private security groups remain necessary: a caller can
occupy the finite budget and temporarily deny service. The limits bound resource
use; they do not guarantee availability under arbitrary network load.

## Rust CLI and attest-verify

Configure both tools with:

```bash
export PARENT_TLS_CA_FILE=/etc/utexo/client/parent-ca.pem
export PARENT_TLS_CERT_FILE=/etc/utexo/client/operator.pem
export PARENT_TLS_KEY_FILE=/etc/utexo/client/operator.key
# Optional: override the verified SAN name when connecting by a routed IP.
export PARENT_TLS_SERVER_NAME=parent.example
```

Use `--donor-grpc https://parent.example:50051` for clone and
`--endpoint https://parent.example:50051` for attest-verify. The override does
not disable CA/name verification. The clone CLI validates transport settings
before initiating cloning. Both donor RPCs use the same TLS configuration.
The cloning secret continues to use `UTEXO_CLONING_SECRET` on the local CLI;
it is not sent as a gRPC bearer token.

Local development only: bind Parent to a literal loopback IP, set
`GRPC_ALLOW_INSECURE_LOOPBACK=true`, and remove all server TLS variables. This
mode bypasses certificate authorization and the Clone admission budget. Clients
may use explicit `http://127.0.0.1:port` (or `[::1]`) with all client TLS variables
removed. Plaintext DNS names/non-loopback IPs are rejected; there is no automatic
TLS-to-plaintext fallback. Do not expose the local development port through a
proxy or tunnel.

## Go listener

The corresponding `federated-signer-node` update requires:

```text
PARENT_ADAPTER_GRPC=parent.example:50051
PARENT_ADAPTER_TLS_CA_FILE=/etc/utexo/client/parent-ca.pem
PARENT_ADAPTER_TLS_CERT_FILE=/etc/utexo/client/listener.pem
PARENT_ADAPTER_TLS_KEY_FILE=/etc/utexo/client/listener.key
```

Optional `PARENT_ADAPTER_TLS_SERVER_NAME` overrides the verified SAN name. Mount
files read-only inside the listener container. The address stays `host:port`.
`PARENT_ADAPTER_ALLOW_INSECURE_LOOPBACK=true` is for explicit loopback development
with all TLS fields removed. Custom in-process test dialers can opt in as well.

Initial setup rejects missing/bad files. The Manager reloads files when it
recreates a connection after a failed health/RPC probe. Existing connections and
normal gRPC reconnects may retain the loaded identity. For a planned rotation,
restart the listener after atomically installing a complete new file set. A
failed file reload leaves the current connection in place. Health checks use
`PublicKey` over the same authenticated connection.

## Deployment, rotation and rollback

`deploy/deploy-host.sh` requires readable files under
`PARENT_TLS_DIR/<CID>/` (default `/etc/utexo/tls/<CID>/`): `server.pem`,
`server.key`, `client-ca.pem`, `clients.acl`, for every expected CID. It checks
file availability before altering services and writes the corresponding paths
into each Parent environment file. Provision and validate certificates/ACLs
before invoking the script; the file check alone is not a handshake test.
The normal deploy script restarts enclaves; for a host-only update, replace the
Parent/client binaries and environment files and restart only Parent services.

1. Record expected CID, Parent route, server SAN, CA, client leaf fingerprint,
   role and binary checksums. Keep the last approved binaries/configuration.
2. Provision files with least-privilege ownership (private keys, for example,
   root/service-group `0640`). Use a managed secret channel; never put key PEM in
   command arguments, SSM command text or build artifacts.
3. Validate one Parent canary: authorized public-key/attestation calls, a genuine
   clone, denied client/role calls, unchanged donor/requester identity and healthy
   Go client connection. Then repeat for every intended route/CID.
4. For client rotation, add the replacement pin alongside the old pin, restart
   Parent to reload the ACL, distribute the new client identity and restart the
   client. After successful verification remove the old pin and restart Parent
   again. Use versioned directories plus an atomic symlink switch for file sets.
5. ACLs and server TLS files are loaded at startup. Revoking a pin requires a
   Parent restart to terminate old authenticated sessions. There is no automatic
   CRL/OCSP or file watch. For CA rotation overlap CA bundles and pins deliberately,
   replace leaves, verify, then remove the old trust root and pins on both sides.
6. Roll back matching Parent/client binaries and approved configuration together.
   Returning to an old plaintext Parent reopens the old transport gap and requires
   an explicit operational decision with private-network restrictions intact.
   Do not restart EIFs or change registrations for a Parent-only rollback.

## Evidence and limits

Local tests cover actual TLS and the generated Parent router with a counting
mock enclave transport: role denials, missing/foreign/expired client certs, wrong
server name/CA, plaintext, shared Clone budget, socket exhaustion/recovery and
pin replacement. Denied requests must make zero enclave calls. The complete
clone CLI tests additionally run real enclave clone/state/crypto handlers with
mock NSM, both over loopback plaintext and mTLS, including AF-05 response faults.
Test PKI is generated temporarily with OpenSSL; no test private keys are committed.

These are source/local checks, **not F03-IT-19 deployment proof**. Retain stage
SG/VPC and route evidence, allowed and denied source-network results, successful
real-NSM clone/identity equality, Go-client interoperability, bounded resource/log
measurements and recovery after load. Pair transcript evidence with F03-UT-11.
Do not mark F03-AF-13 closed until that deployment evidence exists.
