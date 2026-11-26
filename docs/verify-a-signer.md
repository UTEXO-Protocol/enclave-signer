# Verify a burn signer

This guide shows how to check, without access to the operator, that the EVM
address of a burn signer is bound to approved enclave code and is a signer of
the bridge on Arbitrum One.

The operator publishes one attestation bundle per burn enclave:
`attestation-<CID>.json`. [pubkey-attestation.md](pubkey-attestation.md)
gives the format and the checks in full.

## What one bundle proves

The bundle holds an AWS Nitro attestation document for a burn key.
Verification with independently approved PCRs and an expected policy binds
the public-key bundle and the policy to the measured code.

It does not prove:

- Where the key was first made, or that only one enclave holds it. Cloned
  burn enclaves share one seed. The release burn build has no seed import,
  and cloning checks the PCRs of the peer; these are rules of the measured
  code, not a proof of the key's history
  ([limits of an attestation](pubkey-attestation.md#what-an-attestation-proves)).
- That the enclave runs now. The document is a record of one moment.
- That the document is fresh. The operator chose the nonce. For a live
  check, run `attest-verify --endpoint`, which makes a fresh nonce. That
  call needs a client certificate that the operator's parent accepts.
- Anything about the mint signer.
- Anything about the time, memory and size limits. The operator can change
  them, and they do not change what the enclave signs
  ([runtime-limits.md](runtime-limits.md)).

The certificates in the document expire a few hours after it is made.
`--from-file` checks them at the document's own time. If an AWS signing key
leaks after its certificate expires, it can sign a backdated document.

## What you need

- `attest-verify`, built from the release tag:
  `cd parent && cargo build --release --bin attest-verify`. The build needs
  the access that [building.md](building.md#requirements) describes.
- `cast` ([Foundry](https://getfoundry.sh)), and an Arbitrum One RPC URL.
- The trusted `PCR.json` of the release: the release artifact, or your own
  rebuild of the EIF
  ([expected values](pubkey-attestation.md#expected-values)).
- The `MultisigProxy` address. The burn image pins it as
  `EVM_PROXY_CONTRACT_ADDRESS` in `build/Dockerfile.enclave.burn`.

## Choose the expected values

The bundle's `policy` lists every attested value. Do not copy them. Read
them, and decide whether you accept each one:

| Policy field | Flag | Source |
|---|---|---|
| `signer_role` | `--expect-signer-role burn` | Always `burn`. |
| `rgb_asset_id` | `--expect-rgb-asset-id` | The BFA asset of the deployment. |
| `funds_in_contract` | `--expect-funds-in-contract` | `FUNDS_IN_CONTRACT` in `IMAGE-ENV.json`. |
| `token_contract` | `--expect-token-contract` | `TOKEN_CONTRACT` in `IMAGE-ENV.json`. |
| `evm_finality_tag` | `--expect-evm-finality-tag` | `EVM_FINALITY_TAG` in `IMAGE-ENV.json`: `safe` or `finalized`. `latest` is refused. |
| `spv_min_confirmations` | `--expect-spv-min-confirmations` | `SPV_MIN_CONFIRMATIONS` in `IMAGE-ENV.json`. |
| `gas_tx_*` | `--expect-gas-tx-to`, `--expect-gas-max-*`, `--expect-gas-selectors` | `GAS_TX_*` in `IMAGE-ENV.json`. |
| `evm_rpc_tls.host` | `--expect-evm-rpc-host` | The EVM RPC host that you accept. |
| `evm_rpc_tls.ca_sha256` | `--expect-evm-rpc-ca-sha256` | The SHA-256 of the CA that you accept, without `0x`. |

The script sets `chain_id` (42161) and `bridge_contract` (your
`MULTISIG_PROXY`) itself.

- The host and the CA hash are launch values. They are not in the image, so
  the PCRs do not cover them. Approve them independently.
- A provider API key is in the RPC path, which is not attested and is not in
  the bundle. Approval covers the endpoint, not one provider account.
- The `policy` also lists `clone_peer_pcr3`, the PCR3 of the parent instance
  IAM role. You set no flag for it. `attest-verify` takes the expected value
  from the signed document, and refuses a burn signer whose PCR3 is missing
  or all zero.
- This recipe accepts a `Production` policy only. A public-Signet image
  attests `Development`, which commits no endpoint, and fails here.

## Run the check

```bash
PCR_FILE=PCR.json \
ARB_RPC_URL=https://arb1.arbitrum.io/rpc \
MULTISIG_PROXY=0xC985c12bbCECe96A13A72A62FD75d8aB9381ef5A \
ATTEST_VERIFY=parent/target/release/attest-verify \
bash build/verify-signer.sh https://<published location>/attestation-16.json \
  --expect-signer-role burn \
  --expect-rgb-asset-id 'rgb:<BFA contract id>' \
  --expect-funds-in-contract 0x6711f1a319B37847fa0234181C34D883774c4951 \
  --expect-token-contract 0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9 \
  --expect-evm-finality-tag finalized \
  --expect-spv-min-confirmations 3 \
  --expect-gas-tx-to 0xC985c12bbCECe96A13A72A62FD75d8aB9381ef5A \
  --expect-evm-rpc-host <rpc host> \
  --expect-evm-rpc-ca-sha256 <64 hex characters>
```

The script:

1. Checks that the RPC serves chain 42161.
2. Downloads the bundle when you give an `https://` URL.
3. Runs `attest-verify --from-file` with your PCRs and flags. This checks the
   certificate chain to the AWS Nitro root, the COSE signature, the PCRs, the
   nonce, the public key and the commitment of the keys and the policy.
4. Reads the EVM address from the verified output.
5. Checks that the address is in `MultisigProxy.getEnclaveSigners(827166)`.
   827166 is the bridge's id for the RGB network (`RGB_CHAIN_ID`).

Exit 0 means that all checks pass. Exit 1 names the check that failed. Exit 2
is a usage error. The script refuses `--mock` with exit 2: a signer is
verified in real mode only. Run the script once for each published bundle.

The bundle format is `utexo-signer-attestation/3`. Its `verification_mode`
field tells how the exporter checked the document (`real` or `mock`).
`attest-verify` refuses a bundle whose mode is not its own, and a bundle of
any other format.

## Operator: approve every signer before routing

`deploy/verify-identity.sh` writes the bundles. It runs after each enclave
has its key, and it needs the complete approved identity map.

Get the expected main EVM address of **every CID** from the approved
deployment record, and confirm its on-chain registration. Do not make this
map from the live keys of the nodes under check.

Run the gate on each enclave host, once for every CID that receives traffic.
Use the artifact directory, the launch file and the independently approved
address of that CID. For burn CID 18:

```bash
CLUSTER_DIR='/path/to/artifacts/enclave-18/<git_sha>/rgb-burn' \
ENCLAVE_ENV=/etc/utexo/enclave-18.env \
CIDS="18" \
EXPECTED_EVM="18=0x<40-hex-address>" \
EXPECTED_EVM_RPC_HOST='<approved-host>' \
EXPECTED_EVM_RPC_CA_SHA256='<approved-64-hex-CA-hash>' \
bash deploy/verify-identity.sh
```

- Every CID must pass before it receives traffic. Do not use the launch file
  or the release directory of one CID to verify another role or release.
- `CIDS` can list several signers when all of them use the same launch
  settings and binaries. An unset `CIDS` means `16 18 20`; an empty one is an
  error.
- `EXPECTED_EVM` must have exactly one address for each listed CID. An empty
  or partial map, a duplicate or extra CID and a malformed address return
  exit 2 before any enclave is queried.
- For both roles, set `SIGNER_ROLE`, `PCR_FILE` and `IMAGE_ENV` in the
  approved, root-owned `ENCLAVE_ENV`, with the launch values of the release.
  Every export uses a fresh nonce and verifies real attestation, the complete Production
  policy, PCRs and the address supplied through `--expect-evm-address`.
- Supply `EXPECTED_EVM_RPC_HOST` and `EXPECTED_EVM_RPC_CA_SHA256` from the
  independent endpoint approval. The gate compares them with the launch host
  and SHA-256 of `EVM_RPC_TLS_CA_DER_FILE` before querying the enclave. The
  attestation then binds those endpoint values to the measured code.
- The script also reads `/etc/nitro_enclaves/vsock-proxy-evmrpc.env` for the
  launch host and port. `EVM_RPC_ENV` can select an approved alternative;
  an explicitly empty value omits that file. When run as root, the gate
  requires both files and their parent directories to be root-owned, not
  writable by group/others, and free of symlinks. These files describe launch
  values; the gate retains the caller's identity and endpoint approval maps
  and CID selection before reading them.
- Mint requires `EXPECTED_XPUB_VANILLA`, `EXPECTED_XPUB_COLORED` and
  `EXPECTED_MASTER_FINGERPRINT`, each a complete `CID=value` map. The first
  two values are the approved account xpubs; fingerprints are eight hex
  characters. Missing, partial, duplicate or malformed maps fail before
  an enclave is queried.
- Debug mode cannot approve an identity. A Development policy, including
  public Signet, cannot pass this Production gate. Use liveness only for
  diagnostics; it does not approve traffic.
- The script checks the approvals that you supply. It does not read the
  contract signer set, register keys, check readiness or enable traffic.
  Follow [rollout acceptance](role-rollout.md) for those steps.

For a mint candidate, obtain its complete keyset from independently verified
bootstrap evidence and approve it before configuring the gate:

```bash
CLUSTER_DIR='/path/to/artifacts/enclave-24/<git_sha>/rgb-mint' \
ENCLAVE_ENV=/etc/utexo/enclave-24.env CIDS=24 \
EXPECTED_EVM='24=0x<40-hex-address>' \
EXPECTED_XPUB_VANILLA='24=<approved-account-xpub>' \
EXPECTED_XPUB_COLORED='24=<approved-account-xpub>' \
EXPECTED_MASTER_FINGERPRINT='24=<8-hex-fingerprint>' \
EXPECTED_EVM_RPC_HOST='<approved-host>' \
EXPECTED_EVM_RPC_CA_SHA256='<approved-64-hex-CA-hash>' \
bash deploy/verify-identity.sh
```

The CLI's `export-attestation` accepts the same mint checks directly as
`--expect-account-xpub-vanilla`, `--expect-account-xpub-colored` and
`--expect-master-fingerprint`. Supply all three together. It compares them
with the verified bundle before writing the file. The host CLI must be built
from a revision that supports these flags; an older CLI fails the gate.

Routing automation must run this default mode and require exit 0 for each
CID, or for the full list of a shared configuration, with the other
readiness checks of the deployment. A node
failure or an identity mismatch returns exit 1, and a configuration error
exit 2. Do not route on either, and do not use a partial set of bundles in
place of the passed gate: a failure can come after some bundles were written.

For a diagnostic check of running enclaves and loaded keys only:

```bash
CLUSTER_DIR='/path/to/artifacts/enclave-18/<git_sha>/rgb-burn' \
ENCLAVE_ENV=/etc/utexo/enclave-18.env CIDS="18" \
bash deploy/verify-identity.sh --liveness
```

This mode needs no identity map and no PCRs, exports no bundle, and reports
`LIVE` with `identity NOT approved`. Its exit 0 must never enable routing.
