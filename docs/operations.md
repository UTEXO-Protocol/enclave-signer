# Operations

How to launch, check and restart an enclave on a Nitro host. The settings
are in [configuration.md](configuration.md), the image build in
[building.md](building.md), and local development in the
[README](../README.md#run-locally).

## Launch

A launch has these steps, in this order:

1. Start the host proxies for the endpoints that the enclave reaches.
2. Run the enclave.
3. Send the runtime limits file, if the host has one
   ([runtime-limits.md](runtime-limits.md#after-a-restart)).
4. Send the launch values once (`set-endpoints`).
5. Check the attested launch policy (`verify-launch`).
6. Start the parent.
7. Initialize the keys: `init` on a mint signer,
   `init --cloning-secret-file <file>` on the first burn signer, and `clone`
   on each other burn signer ([cloning.md](cloning.md)). A burn signer that
   got `init` without the secret can never donate its seed.

By hand:

```bash
# Host proxies. Allowlist each upstream.
vsock-proxy 8001 <electrum-host> 50002
vsock-proxy 8002 <EVM_RPC_HOST> 443

nitro-cli run-enclave --cpu-count 2 --memory 4096 --enclave-cid 16 \
  --eif-path build/utexo-bridge-enclave.eif

# Once per boot. The enclave signs nothing before it.
utexo-bridge-parent-cli --addr vsock://16:5000 set-endpoints \
  --electrum-url ssl://<electrum-host>:50002 \
  --evm-rpc-host <EVM_RPC_HOST> --evm-rpc-tls-port 443 --evm-rpc-ca-der-file ca.der \
  --kms-key-arn <KMS_KEY_ARN> --kms-region <KMS_REGION> --kms-seed-id <KMS_SEED_ID>   # mint only

GRPC_HOST=0.0.0.0 GRPC_PORT=50051 USE_VSOCK=true ENCLAVE_VSOCK_CID=16 \
  GRPC_TLS_CERT_FILE=server.pem GRPC_TLS_KEY_FILE=server.key \
  GRPC_TLS_CLIENT_CA_FILE=client-ca.pem GRPC_TLS_ACL_FILE=clients.acl \
  HEADER_ELECTRUM_URL=ssl://<electrum-host>:50002 \
  ./utexo-bridge-parent
```

- A burn signer built with `spv` gets its Bitcoin headers from the header
  sync of the parent. Without `HEADER_ELECTRUM_URL` it never becomes ready.
- A mint signer also needs the KMS proxy and the parent's storage settings
  ([kms-persistence.md](kms-persistence.md)).
- The CLI of a Nitro host is built with the parent feature `vsock`
  ([building.md](building.md#workspaces)).

Before an enclave takes traffic, check that a genuine request of its flow
succeeds and that a request of the other flow is refused.

### `deploy-host.sh`

`deploy/deploy-host.sh` runs steps 2 to 6 for one enclave and its parent. It
needs `GIT_SHA`, `BUCKET`, `AWS_REGION`, `CLUSTER_DIR` and `SIGNER_ROLE`
(`mint` or `burn`). It installs the systemd units and fetches the EIF of that
commit from S3.

- It starts no host proxy. Run `deploy/host-prep-evmrpc.sh` first: it starts
  the EVM RPC proxy and writes the `EVM_RPC_HOST` and `EVM_RPC_TLS_PORT`
  that the launch sends.
- Before the start it checks the EIF checksum and the PCR0 of the EIF file
  against the published files. After the start it checks the PCR0 of the
  running enclave. `ENCLAVE_DEBUG_MODE=1` skips the second check.
- It checks its inputs before it changes a service: the TLS files of the
  parent, the limits file, and the memory pool.
- It does a cold deployment. It does not initialize keys, and it is not a
  rolling restart.
- One run deploys one enclave. The default CID is 16; `ENCLAVE_CID=18` or
  `20` selects another supported CID, with parents on ports 50051 to 50053.
- It stops and starts only the units of its own CID. But it ends every
  `utexo-bridge-parent` process of the host, and it replaces
  `/etc/utexo/enclave.env`, the unit files and the EIF in `CLUSTER_DIR`,
  which all enclaves of the host share. Its check after the start fails when
  an enclave of another CID runs.

### Memory

`--memory` must be at least 4096 MiB, a whole number of GiB. The enclave
needs 3072 MiB of usable memory (`enclave/src/memory.rs`), and the kernel and
the root file system keep part of the launch value. A release enclave refuses
to start with less, or when it cannot read its memory total. nitro-cli gives
an enclave whole hugepages, 1 GiB pages first, so the deploy scripts refuse a
value that is not a whole number of GiB. `ENCLAVE_MEMORY` sets the value for
`deploy-host.sh`; its default is the minimum.

The allocator pool. `memory_mib` in `/etc/nitro_enclaves/allocator.yaml`
sets the hugepage pool when `nitro-enclaves-allocator.service` starts.

- The pool comes out of the memory of the parent instance. Leave enough for
  the system and the parents. If the allocator cannot reserve the pool, its
  service fails and no enclave of the host starts. A new start of the
  allocator does not start the enclave units: set `memory_mib` to a value
  that the instance can hold, then reboot the host or start the
  `utexo-parent@` units. Each parent unit also starts its enclave unit and
  the allocator.
- The allocator refuses to change the pool while an enclave runs, and the
  enclave units require its service. So a restart of the allocator stops and
  restarts every enclave of the host, which removes their keys. Change the
  pool only when every enclave of the host can stop.
- `deploy-host.sh` refuses a pool that is smaller than the launch value of
  its one enclave, before it downloads or stops anything. It does not count
  the pages that another enclave holds.
- `utexo-enclave-ctl.sh check <cid>` makes the same checks and changes
  nothing. Run it before each step of a rolling restart: `systemctl restart`
  stops the old enclave before the new one starts. `start` itself refuses
  only when the free hugepages cannot hold its own enclave.

`check` reads its values from `/etc/utexo/enclave.env`, the file that
systemd gives to the unit. Run it as root, or as a user that can read the
file. A key that is not in the file gets its default. `check` reads only
plain lines, on which it reads the same values as systemd:

- `KEY=value`. The key has only ASCII letters, digits and `_`, and does not
  start with a digit. The key and the `=` can have blanks around them. The
  value has no backslash. It can have one pair of the same quotes around it,
  and no other quote.
- A comment line. Its first character that is not a blank is `#` or `;`, and
  it does not end with a backslash.
- A blank line.

A plain line has only tabs and printable ASCII, and at most 4096 bytes. It
can end with a carriage return. The file has at most 65536 bytes. `check`
refuses a file with any other line, because systemd joins, splits, changes
or ignores such lines. Write the file again with plain lines only.

A new launch value needs one check before a release. Run one image at that
value with `ENCLAVE_DEBUG_MODE=1`. `nitro-cli describe-enclaves` must show
the value in `MemoryMiB`, and the "memory check passed" line on the console
must report a `total_mib` of at least the usable minimum.

## Launch check

`utexo-enclave-ctl.sh start` runs `set-endpoints` and then
`utexo-bridge-parent-cli verify-launch --pcr-file <PCR.json> --image-env <IMAGE-ENV.json> --signer-role <role>`,
with the launch values as flags or in its environment.

Before keys exist, `GetAttestedPublicKey` attests the policy only.
`verify-launch` verifies that document for a fresh nonce against `PCR.json`.
It then compares every attested policy field with the deploy inputs: the
image role, `IMAGE-ENV.json` (the env of the measured image, from the build)
and the `set-endpoints` values. On a mismatch it names the field, the
expected value and the attested value. The enclave is then terminated, its
unit stops, and the deploy exits before a parent starts.

- `verify-launch` accepts a `Production` policy only. It refuses an image
  built without `spv`.
- `export-attestation --allow-development-policy` exports a bundle of an
  enclave that attests `Development` with a real NSM document, such as a
  build without `spv`. It needs approved PCRs that are not zero. It verifies
  those PCRs, not the role and not the endpoint settings. Approve the launch
  values separately.
- `ENCLAVE_DEBUG_MODE=1` skips the check, because the PCRs are zero.
- The check runs on the host. It protects against a wrong launch, not against
  a compromised host. An outside verifier runs its own check
  ([verify-a-signer.md](verify-a-signer.md)).

## Readiness

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5001/health
```

- `200`: the launch values are set and the signing key is loaded. A burn
  signer built with `spv` also needs a fresh header chain with at least
  `SPV_MIN_CONFIRMATIONS` headers above the checkpoint. A mint signer does
  not.
- `503`: the enclave is not ready, cannot be reached, or did not answer
  within the probe timeout.

A `200` does not prove that a signing request will succeed. The probe does
not contact the EVM RPC.

The body has the readiness, key, phase and SPV fields, and the header-sync
status of the parent:

```json
{"header_sync": {"state": "synced", "source_tip": 412345, "enclave_tip": 412345, "lag_blocks": 0, "tip_age_secs": 41, "last_ok_unix": 1790000000, "last_error": null}}
```

`state` is `synced`, `syncing`, `stalled` (three failed steps in a row),
`off` (a build with no header chain) or `unconfigured` (no
`HEADER_ELECTRUM_URL`). It does not change the HTTP code.

The probe binds to loopback (`HEALTH_HOST`, `HEALTH_PORT`). Keep it away from
other hosts. The deploy script gives the three parents the health ports
50061 to 50063, and the parent Docker image uses the probe as its
`HEALTHCHECK`. The CLI gives the enclave part of the answer, without
`header_sync`:

```bash
utexo-bridge-parent-cli --addr vsock://16:5000 health
```

## Lost `SetEndpoints` reply

`utexo-enclave-ctl.sh start` terminates the enclave that it launched if
`set-endpoints` or the launch check fails. That enclave has no key. Run
`start` again.

After a manual `set-endpoints` with no reply, do not send it again blindly:
the enclave refuses a second set. Read the state first with the `health`
command. Its exit code 1 means "not ready" or no answer: read the
`Endpoints set` and `Key loaded` lines. With no such lines, the read failed.

| `Endpoints set` | `Key loaded` | Action |
| --- | --- | --- |
| false | any | The set did not take effect. Send `set-endpoints` again. |
| true | false | The set took effect. Run `verify-launch` with `--pcr-file`, `--image-env`, `--signer-role` and the same launch values. On a mismatch, terminate the enclave and start it again. It has no key to lose. |
| true | true | The set took effect. Do not run `verify-launch`: it refuses an enclave with keys. Do not restart: a restart removes the keys. Check the attested values with `attest-verify`, through the parent. On a mismatch, stop and report. |

## Restart and upgrade

A restart removes the keys in memory. systemd restores only the processes.

- A mint signer recovers its seed with `init`, through KMS. It needs the
  verified address pin ([kms-persistence.md](kms-persistence.md)).
- A burn signer clones its seed again from a live donor with the same PCRs
  and the same attested policy ([cloning.md](cloning.md)). The seed exists
  only in enclave memory, so recovery needs a live donor.
- A new image has new PCRs. Approve them, and update the verifier
  expectations and the KMS key policy, before the image takes traffic. A burn
  signer on a new image cannot clone from an enclave of the old image: it
  starts from a new seed.
- New launch values need a new launch of the same EIF. The PCR allowlists do
  not change.

## Debug mode

`nitro-cli run-enclave ... --debug-mode` zeroes PCR0, PCR1 and PCR2, so
attestation against pinned PCRs fails. Use it only to read logs:

```bash
nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
nitro-cli describe-enclaves
nitro-cli terminate-enclave --enclave-id <id>
```
