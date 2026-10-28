# Public-signet staging on AWS Nitro

`stage-signet` runs separate mint and burn signers inside real AWS Nitro
Enclaves, using vsock and real NSM attestation. Each enclave generates its own
random seed on an empty `InitializeKey` request. It refuses seed/mnemonic
imports, cloning, and KMS launch values. The seed stays in enclave memory;
restarting the enclave loses that identity and a subsequent initialization
creates new keys. Re-register the new public keys and update the staging
wallet setup after every restart.

This profile disables SPV synchronization and the enclave's BtcRelay checks.
Burn consignments still undergo RGB validation, asset/amount/operation and
burn-destination binding, EVM mint-ancestry verification and reject-list checks.
Burn witness confirmations come from the TLS indexer, which is trusted for Bitcoin
chain status in this profile. `SPV_MIN_CONFIRMATIONS=3` remains the required
burn indexer confirmation depth. An unconfirmed burn witness is still rejected.
The existing mint path verifies the supplied parent PSBT and the EVM deposit,
without reading Bitcoin history; its connector remains responsible for waiting
for mint-right confirmations, as described in [mint-flow.md](mint-flow.md).

The profile accepts only `BITCOIN_NETWORK=signet` and `BTC_RELAY_MODE=none`,
with explicit bridge, asset and token pins. Ethereum mainnet and Arbitrum One
chain IDs are refused. The image attests a **Development** policy because its
Bitcoin evidence is not SPV verified; its NSM document and measured PCRs are
still real. Production feature sets and verification requirements are unchanged.
The Cargo dependency graph retains SPV and mint KMS code, but stage does not
run those services.

## Build the two EIFs

Use the same x86_64 build prerequisites and Nitro CLI version as the production
EIF builds. `build/Dockerfile.enclave.stage` uses the digest-pinned base images,
signed package snapshots and deterministic build settings of the other EIFs.
The private RGB dependency is supplied through the existing BuildKit secret.

Set the public identifiers of the **staging** deployment. The proxy is the
EIP-712 verifying contract; `FUNDS_IN_CONTRACT` is the bridge entry contract,
which may be a different address. The RGB asset must have been issued on
public signet.

```bash
export RGB_ASSET_ID='rgb:<public-signet BFA contract id>'
export EVM_CHAIN_ID='<staging EVM chain id>'
export EVM_PROXY_CONTRACT_ADDRESS='0x<staging MultisigProxy>'
export FUNDS_IN_CONTRACT='0x<staging Bridge entry contract>'
export TOKEN_CONTRACT='0x<staging ERC-20 token>'
export PRIVATE_DEPS_DIR='/path/to/private-deps' # contains lib_key

for role in mint burn; do
  DOCKERFILE=Dockerfile.enclave.stage SIGNER_ROLE="$role-signer" \
    IMAGE_TAG="utexo-stage-$role:latest" \
    OUT_DIR="$PWD/build/stage-$role" \
    EIF_NAME="utexo-bridge-enclave-stage-$role.eif" \
    ./build/build-enclave.sh
done
```

No seed, mnemonic, KMS key, endpoint host, or RPC CA is baked into the image.
The build fails if a required deployment pin or signer role is missing.
The mint image permits the existing `create_utxo` path up to
`BTC_MAX_TOTAL_SATS=1000000` and pins `RGB_MAX_UNOWNED_SATS=1000` for RGB
PSBTs. This is the maximum Bitcoin value paid to outputs the enclave cannot
prove it controls; the existing mint ownership checks still apply. Leaving
this limit unset refuses every RGB mint PSBT, even when all outputs belong
to the enclave. Gas-transaction signing remains disabled by the
zero default gas/fee caps; use the normal staging transaction submitter or
explicitly review and bake gas limits before enabling that separate API.

Alternatively, manually run **Build EIF** with profile
`public-signet-stage`. Configure these repository variables:

- `STAGE_BFA_RGB_ASSET_ID`
- `STAGE_EVM_CHAIN_ID`
- `STAGE_EVM_PROXY_CONTRACT_ADDRESS`
- `STAGE_FUNDS_IN_CONTRACT`
- `STAGE_TOKEN_CONTRACT`

The existing build credentials and AWS artifact settings also apply. Stage
artifacts are named `eif-<sha>-stage-mint` / `eif-<sha>-stage-burn`, and S3
uploads use `eif/<sha>/stage-signet/mint/` / `burn/`. Production tag builds
retain the existing five variants and paths. The Docker CD workflow does not
select these EIFs.

## Run and initialize

Provision an enclave-enabled EC2 host and its Nitro allocator as for the
existing EIFs. Copy each EIF and its matching `PCR.json`, `IMAGE-ENV.json`,
`SHA256SUMS`, parent and CLI artifacts to the host. Verify the checksums and
compare `nitro-cli describe-eif` measurements with that role's PCR manifest.

Start a host `vsock-proxy` on port 8001 to the public-signet TLS indexer, and
another on 8002 to the staging EVM TLS RPC. Configure their allowlists as in
the normal deployment. TLS terminates inside the enclave. The EVM RPC must
serve JSON-RPC at `/` and support the `safe` finality tag. The indexer and EVM
RPC must use distinct TLS ports inside the enclave; for example Electrum
50002 and EVM RPC 443.

Launch each role with a separate CID. Run without Nitro `--debug-mode`, so
runtime PCRs remain populated:

Running both commands at once requires four enclave vCPUs and 6144 MiB of
enclave memory, in addition to the parent instance's resources. A host that
reserves only two vCPUs for Nitro can run the roles sequentially for testing;
use sufficient capacity or separate hosts for a simultaneous deployment.

```bash
nitro-cli run-enclave --cpu-count 2 --memory 3072 --enclave-cid 16 \
  --enclave-name stage-mint --eif-path build/stage-mint/utexo-bridge-enclave-stage-mint.eif
nitro-cli run-enclave --cpu-count 2 --memory 3072 --enclave-cid 18 \
  --enclave-name stage-burn --eif-path build/stage-burn/utexo-bridge-enclave-stage-burn.eif
```

Compare the running enclave measurements with each role's approved PCR
manifest. Using the matching host CLI, set endpoints once per enclave, then
initialize without any seed, mnemonic or cloning secret:

```bash
export ELECTRUM_URL='ssl://<public-signet indexer>:50002'
export EVM_RPC_HOST='<staging RPC TLS host>'
export EVM_RPC_TLS_PORT=443
export EVM_RPC_TLS_CA_DER_FILE='/path/to/staging-rpc-ca.der'
unset KMS_KEY_ARN KMS_REGION KMS_SEED_ID KMS_EXPECTED_EVM_ADDRESS
unset UTEXO_CLONING_SECRET
CLI=./utexo-bridge-parent-cli
for cid in 16 18; do
  "$CLI" --addr "vsock://$cid:5000" set-endpoints
  "$CLI" --addr "vsock://$cid:5000" init
  "$CLI" --addr "vsock://$cid:5000" get-keys
  "$CLI" --addr "vsock://$cid:5000" health
done
```

Before registering keys, verify a fresh keyed NSM attestation for each role
against the **independently approved** PCR manifest from its trusted stage
build. The stage exporter requires nonzero PCR0/1/2, verifies the real AWS
certificate chain and COSE signature, binds a fresh nonce and the public-key
bundle, and requires Development policy. It has no mock mode:

```bash
"$CLI" --addr vsock://16:5000 export-stage-attestation \
  --pcr-file build/stage-mint/PCR.json --out stage-mint-attestation.json
"$CLI" --addr vsock://18:5000 export-stage-attestation \
  --pcr-file build/stage-burn/PCR.json --out stage-burn-attestation.json
```

Use the verified bundle's public keys to register the stage signer and
configure its wallet descriptors. On subsequent checks, also pass
`--expect-evm-address 0x<approved address>` to detect a changed identity.
The approved PCRs select the stage role and baked configuration. Development
policy does not separately commit the launch endpoint hosts or RPC CA; approve
those as deployment inputs before initialization. The operator controlling
`SetEndpoints` is trusted: a real stage attestation proves the measured code
and public keys, not which chain endpoints were installed. Registration and
on-chain consumers must pin the approved stage PCRs as well; accepting the
Development policy alone does not distinguish this image from another dev build.

Each enclave has a distinct identity; repeated `init`
does not replace an already initialized seed. Keep the enclave's vsock
listener private to its host. Run the parent using `USE_VSOCK=true` and the
matching `ENCLAVE_VSOCK_CID`; keep the existing parent mTLS certificates and
ACLs described in [parent-mtls.md](parent-mtls.md).

Health becomes ready after endpoints and keys are set. Its SPV diagnostics
are zero, causing the parent header-sync loop to report `Off`; no
`HEADER_ELECTRUM_URL` is needed. This does not remove the indexer requirement
for RGB validation and confirmation checks. The stage caller need not supply
Merkle proofs. Any calldata `proof` bytes are caller supplied and are not
validated against Bitcoin headers in this profile. If the EVM deployment
itself requires BtcRelay proofs, configure
its stage deployment consistently: the signer does not disable checks in the
on-chain contract.

The existing `Release EIF` / `deploy-host.sh` path deploys the combined
production artifact and calls `verify-launch`, which requires a Production
policy. It intentionally rejects these stage images. Use the explicit launch
procedure above (or a stage-specific deployment wrapper) rather than relaxing
that verifier or enabling Nitro debug mode. Use `export-stage-attestation` for
the explicit stage identity check above;
`verify-launch` and the normal `export-attestation` command retain their
production requirements. The saved stage bundle records verification mode
`real`; the existing offline CLI does not expose a stage-policy option.
