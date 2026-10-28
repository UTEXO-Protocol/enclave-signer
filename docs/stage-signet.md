# Public Signet staging on Nitro

Use the existing mint and burn images with `spv` omitted. There is no separate
staging feature or build profile. Key custody is the same as production:
`mint-signer` always enables KMS persistence, and `burn-signer` uses authenticated
enclave-to-enclave cloning for replicas and replacement.

| Image | Production features (default) | Public Signet features |
| --- | --- | --- |
| Mint | `vsock,rgb,mint-signer` | `vsock,mint-signer` |
| Burn | `vsock,rgb,burn-signer` | `vsock,burn-signer` |

`rgb` enables SPV. Without it, startup requires public
`BITCOIN_NETWORK=signet`, `BTC_RELAY_MODE=none`, nonzero chain/contract pins,
an asset ID, a positive Bitcoin confirmation depth, and the measured
`ENDPOINTS_SHA256` pin described below. The EVM chain can be
Arbitrum One (`42161`); it need not be an EVM testnet. Use the staging bridge,
proxy, token and RGB asset configured for that deployment.

Both roles use real NSM attestation. Seed/mnemonic import and mock/debug
attestation features are forbidden for this combination. Run Nitro without
`--debug-mode`, and approve the measured image and launch inputs before use.
The absence of SPV results in a **Development** policy even though the enclave,
attestation and key-custody paths are real.

## Build and launch

Approve the Bitcoin indexer, EVM RPC and its CA before building. Use the parent
CLI from the same revision to calculate their digest offline; this command
does not contact an enclave or require a CID:

```bash
export ELECTRUM_URL='ssl://<public-signet indexer>:<port>'
export EVM_RPC_HOST='<approved EVM RPC TLS host>'
export EVM_RPC_TLS_PORT=443
export EVM_RPC_TLS_CA_DER_FILE='/path/to/approved-rpc-ca.der'
CLI=./utexo-bridge-parent-cli
ENDPOINTS_SHA256=$("$CLI" set-endpoints --print-sha256) || exit 1
export ENDPOINTS_SHA256
```

The digest is SHA-256 of the decoded `SetEndpointsRequest`, re-encoded with
prost after clearing all four KMS fields. It binds the indexer URL, EVM RPC
host, CA DER contents and TLS port. The CA file's local path is not hashed.
The build bakes this digest into the image, so its PCR0 binds those approved
network inputs. At launch, `set-endpoints` must match: reuse the exact URL and
host spelling, CA bytes and port. A network endpoint or CA change requires a
new digest, image and approved PCRs. A rebuilt burn EIF cannot clone from a
donor with different PCRs.

`KMS_KEY_ARN`, `KMS_REGION`, `KMS_SEED_ID` and `KMS_EXPECTED_EVM_ADDRESS` are
excluded by design. They remain operator-approved runtime inputs under the
existing custody rules. Setting the verified address pin after first bootstrap
therefore uses the **same EIF** for recovery; it does not require a rebuild.

With `ENDPOINTS_SHA256` exported, provide the deployment's public pins and use
the existing build script:

```bash
export RGB_ASSET_ID='rgb:<issued public-signet BFA contract id>'
export EVM_CHAIN_ID=42161
export EVM_PROXY_CONTRACT_ADDRESS='0x<staging MultisigProxy>'
export FUNDS_IN_CONTRACT='0x<staging Bridge entry contract>'
export TOKEN_CONTRACT='0x<configured token>'
export BITCOIN_NETWORK=signet BTC_RELAY_MODE=none
# Maximum non-enclave-owned input value in each mint PSBT, in satoshis.
export RGB_MAX_UNOWNED_SATS=1000
# Supply the existing BuildKit credential through PRIVATE_DEPS_DIR or
# RGB_LIB_BFA_DEPLOY_KEY, as for production builds.
ENCLAVE_FEATURES=vsock,mint-signer DOCKERFILE=Dockerfile.enclave.mint \
  OUT_DIR=build/signet-mint EIF_NAME=signet-mint.eif \
  IMAGE_TAG=utexo-signet-mint:latest build/build-enclave.sh
ENCLAVE_FEATURES=vsock,burn-signer DOCKERFILE=Dockerfile.enclave.burn \
  OUT_DIR=build/signet-burn EIF_NAME=signet-burn.eif \
  IMAGE_TAG=utexo-signet-burn:latest build/build-enclave.sh
```

These overrides are baked into the EIF and change its PCRs. Use distinct output
paths and retain each image's `PCR.json` and `IMAGE-ENV.json`. Launch with
`nitro-cli run-enclave` using separate CIDs and enough allocator capacity for
all active enclaves. The examples below use mint CID 16, burn donor CID 18 and
burn requester CID 20.

Set the chain endpoints once per enclave with the existing parent CLI. The
indexer must serve public Signet over TLS; for example,
`ssl://node202.fra.mempool.space:60602` was used in the Bitcoin integration test.
Run host `vsock-proxy` listeners with upstream allowlists: Bitcoin indexer on
8001, EVM TLS RPC on 8002, and mint KMS HTTPS on 8003. TLS terminates inside the
enclave. The EVM RPC must serve JSON-RPC at `/` and support `safe` finality.
Choose distinct indexer and EVM TLS ports for their enclave loopback listeners.

No Bitcoin header source is needed. Health reports zero SPV diagnostics, so
parent header synchronization stops automatically. Header RPCs refuse requests.
Health does not prove that the upstream indexer or EVM RPC is reachable.

## Mint: bootstrap once, recover the same identity

Follow [KMS seed persistence](kms-persistence.md) to provision the normal
`PersistentSeed` flow: a dedicated KMS key, protected S3 ciphertext object,
parent custody broker on vsock 8004, and KMS proxy on 8003. Configure the parent
with `KMS_S3_BUCKET`, `KMS_S3_KEY`, the same stable `KMS_SEED_ID`,
`USE_VSOCK=true`, and the mint's `ENCLAVE_VSOCK_CID`. Keep the normal parent
mTLS/ACL configuration. Only one parent process per host should own the broker.

The KMS key policy must authorize the approved **stage mint PCR0**, and require
this exact encryption context (with your stable seed ID):

```json
{"application":"utexo-enclave-signer","flow":"rgb-mint","seed_id":"signet-mint-1","bitcoin_network":"signet"}
```

Do not reuse the production `bitcoin` context or authorize debug/zero PCRs.
The `rgb-mint` flow is selected by the compiled code. Stage uses the same
recipient-attested `GenerateDataKey`/`Decrypt`, conditional S3 writes and
failure handling as production; the parent never receives the plaintext seed.

For the first bootstrap only, with no saved object:

```bash
export KMS_KEY_ARN='arn:aws:kms:<region>:<account>:key/<key-id>'
export KMS_REGION='<region>'
export KMS_SEED_ID=signet-mint-1
unset KMS_EXPECTED_EVM_ADDRESS
"$CLI" --addr vsock://16:5000 set-endpoints
"$CLI" --addr vsock://16:5000 init
"$CLI" --addr vsock://16:5000 export-attestation \
  --allow-development-policy --pcr-file build/signet-mint/PCR.json \
  --out mint-attestation.json
```

Independently verify the saved ciphertext and the attested public identity.
For every subsequent launch or replica, keep the same KMS key, seed ID, S3
object and Bitcoin network, set `KMS_EXPECTED_EVM_ADDRESS` to that verified
address, then call `set-endpoints` and `init` again. Verify the recovered key
bundle against the original, including `--expect-evm-address` when exporting.
An unpinned restart refuses an existing object; pinned recovery refuses a
missing object or wrong identity. KMS/storage failures never create a
replacement seed. Follow the KMS guide's backup, recovery test and post-bootstrap
`GenerateDataKey` denial procedure before using the identity.

## Burn: retain a live approved donor

Burn initialization generates its seed inside the enclave. Supply the donor's
cloning secret at runtime through a protected file, using the normal secret
requirements. Do not bake it into an image. Clear mint-only launch values before
setting burn endpoints:

```bash
unset KMS_KEY_ARN KMS_REGION KMS_SEED_ID KMS_EXPECTED_EVM_ADDRESS
"$CLI" --addr vsock://18:5000 set-endpoints
"$CLI" --addr vsock://18:5000 init --cloning-secret-file /path/to/burn-cloning-secret
"$CLI" --addr vsock://18:5000 export-attestation \
  --allow-development-policy --pcr-file build/signet-burn/PCR.json \
  --out burn-attestation.json
```

For a fresh requester, launch the same approved burn EIF, set the same approved
endpoints, and use the existing clone command without calling `init` first:

```bash
"$CLI" --addr vsock://20:5000 set-endpoints
"$CLI" --addr vsock://20:5000 clone \
  --cloning-secret-file /path/to/burn-cloning-secret \
  --donor-grpc 'https://<donor-parent>:50051' \
  --donor-evm '0x<verified burn identity>'
"$CLI" --addr vsock://20:5000 export-attestation \
  --allow-development-policy --pcr-file build/signet-burn/PCR.json \
  --expect-evm-address '0x<verified burn identity>' --out burn-replica-attestation.json
```

Configure the clone operator's mTLS credentials and ACL as in
[Parent mTLS](parent-mtls.md). Donor and requester must have matching PCR0/1/2,
the same **nonzero PCR3** (parent instance IAM role), the authenticated cloning
secret and intended cluster identity. Development policy does not bypass any
of those handshake checks. A completed clone retains the secret and can become
a donor. Check the [CLI completion result](clone-cli-results.md) and verified
public keys before retiring the old enclave.

Cloning preserves the identity only while an approved donor with that seed is
still running. Keep a live replica before replacing or restarting the last
donor. Cloning alone provides no permanent storage or recovery after all
replicas stop.

## Attestation and validation boundary

`export-attestation --allow-development-policy` uses the real AWS NSM trust root,
nonce and key-bundle binding, with independently approved nonzero PCRs. The
Development policy does **not** separately commit endpoint hosts, RPC CA, KMS
launch pins or clone-peer PCR3. Instead, PCR0 binds the measured
`ENDPOINTS_SHA256` network digest and the enclave enforces it at `SetEndpoints`.
The image also commits its other baked configuration. KMS launch values remain
operator-approved runtime inputs, including the expected-address pin that
changes from empty at first bootstrap to the verified recovery identity.
Clone peers still enforce nonzero, matching PCR3 directly. Production policy
verification deliberately rejects these images.

Burns still undergo RGB consensus, asset, amount, recipient, burn-operation,
settlement and ancestry checks. Their Bitcoin witness confirmations come from
the TLS indexer at `SPV_MIN_CONFIRMATIONS` depth (burn image default 6).
No caller-supplied Merkle/header proofs are required, and no independent SPV
or BtcRelay agreement checks run. Caller-supplied relay proof bytes are not
independently verified. Configure the EVM route consistently: disabling signer
SPV does not disable checks in the deployed bridge. Mint signing retains its
existing PSBT/parent-proof and in-enclave EVM receipt/finality checks; it does
not check Bitcoin witness depth. The mint image still bakes the value 3, as
described in [Mint flow](mint-flow.md).

An earlier Bitcoin integration run created and confirmed actual RGB rights,
mint and burn transactions on public Signet in real Nitro enclaves using a
controlled TLS EVM fixture. That run did not execute an external EVM bridge
release or validate this production-custody staging deployment's KMS recovery
and authenticated burn cloning. Those require their own deployed checks.
