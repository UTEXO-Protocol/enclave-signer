# Verify a signer

This guide shows how to verify a published signer bundle without access to the
operator. The default example checks an SPV burn signer and its registration
on Arbitrum One. The [public-Signet example](#verify-a-public-signet-indexer-signer)
checks the separate `IndexerTrusted` policy for a mint or burn signer.

The operator publishes one attestation bundle per burn enclave:
`attestation-<CID>.json`. `deploy/verify-identity.sh` writes it after the
enclave has its key and the operator supplies the complete approved identity
map. An attestation failure returns nonzero; other CIDs may already have exported
bundles. Do not treat individual files as approval of the whole deployment.

## Operator: approve every signer before routing

Obtain the expected main EVM address for **every CID** from the approved deployment
record and confirm its on-chain registration. Do not generate this map from the
live keys returned by the nodes you are checking.

Run on each enclave host, replacing the paths and all three addresses:

```bash
CLUSTER_DIR=/path/to/release \
ENCLAVE_ENV=/etc/utexo/enclave.env \
CIDS="16 18 20" \
EXPECTED_EVM="16=0x<40-hex-address> 18=0x<40-hex-address> 20=0x<40-hex-address>" \
bash deploy/verify-identity.sh
```

`CIDS` must list every signer that will receive traffic on this host.
`EXPECTED_EVM` must contain exactly one address for each listed CID. Empty or
partial maps, duplicate or extra CIDs, and malformed addresses return exit 2
before any enclave is queried or bundle exported. An explicitly empty `CIDS`
is also an error; only an unset `CIDS` defaults to `16 18 20`.

For burn/combined signers in normal mode, configure `SIGNER_ROLE`, `PCR_FILE` and
`IMAGE_ENV` in `ENCLAVE_ENV`, along with the release's launch values. Each export
receives its approved address through `--expect-evm-address`. Mint or debug mode
checks the main address with `get-keys`; this is a structural identity check,
not an attestation. The script compares supplied approvals, not on-chain state.
The CLI also supports full mint attestation export, but the script does not
perform it. Use the explicit export command in the public-Signet section when
a mint attestation is required.

Routing automation must invoke the default identity mode and require exit 0
for the full CID list, along with the deployment's other readiness checks.
Any node failure or identity mismatch returns exit 1; configuration errors
return exit 2. Do not continue routing on either error or use a partial bundle
set as a substitute for the successful gate.

For a diagnostic check of running enclaves and initialized keys only:

```bash
CLUSTER_DIR=/path/to/release CIDS="16 18 20" \
bash deploy/verify-identity.sh --liveness
```

This explicit mode needs no identity map or release PCRs, exports no bundles,
and reports `LIVE` with `identity NOT approved`. Its exit 0 must never enable
routing. Omitting the map in the default mode no longer falls back to liveness.

The bundle format is `utexo-signer-attestation/2`. The `verification_mode`
field tells how the exporter checked the document (`real` or `mock`).
`attest-verify` refuses a bundle whose mode is not its own, and refuses an
older format. This field is metadata, not proof of real attestation. The
verifier checks the signed document itself. Neither the `policy` display
fields nor the bundle's PCRs supply trusted expected values.

## What one bundle proves

The bundle holds an AWS Nitro attestation document for a burn key. Verification
with independently approved PCRs and expected policy binds the public-key
bundle and policy to the measured code.

The release burn build has no seed import, and cloning checks the peer's PCRs.
These are key-handling rules of the measured code, not an independent proof of
the key's history. See the [attestation trust limits](pubkey-attestation.md#what-attestation-does-not-prove).

## What it does not prove

- Where the key was first created, exclusive custody, or where every signature
  was produced. Cloned burn enclaves can share the same seed.
- That the enclave runs now. The document is a record of one moment.
- That the document is fresh. The operator chose the nonce. Use
  `attest-verify --endpoint` with your own nonce for a live check (see
  [pubkey-attestation.md](pubkey-attestation.md)).
- Anything about another signer. A burn bundle does not attest a mint signer;
  a mint signer needs its own verified bundle.

The certificates in the document expire a few hours after it is made.
`--from-file` checks them at the document's own time. If an AWS signing key
leaks after its certificate expires, it can sign a backdated document.

## What you need

- `attest-verify`, built from the release tag: `cd parent && cargo build
  --release --bin attest-verify`. The build needs the access described in the
  README.
- `cast` ([Foundry](https://getfoundry.sh)), and an Arbitrum One RPC URL.
- The trusted `PCR.json` of the release: the release artifact, or your own
  rebuild of the EIF. See
  [Where the expected PCRs come from](pubkey-attestation.md#where-the-expected-pcrs-come-from).
- The approved MultisigProxy address. The image pins it as
  `EVM_PROXY_CONTRACT_ADDRESS`; use `IMAGE-ENV.json` from the approved build.

A single public EIF is shared by federation members for each release, signer
role and build profile. Different approved RPC providers or API keys do not
require different PCR0/1/2. The runtime policy can differ between members.
PCR3 depends on the parent IAM role and can differ even when the image
measurements match. Mint, burn, SPV and indexer builds must each use their own
approved artifact measurements.

## Choose the expected launch values

Obtain expected values from the approved release and deployment record before
verification. The bundle's `policy` lists claimed values for inspection; do
not copy those claims into the verifier as expectations. Authenticating a
value does not establish that the deployment approved it.

| policy field | flag | source |
|---|---|---|
| `signer_role` | `--expect-signer-role` | approved `burn` or `mint` role; the Arbitrum script below checks burn |
| `btc_source` | `--expect-btc-source` | `spv` by default; explicit `indexer` for the public-Signet profile |
| `bitcoin_network` | `--expect-bitcoin-network` | approved image; `signet` is required for indexer trust |
| `chain_id` | `--expect-chain-id` | approved EVM chain ID |
| `bridge_contract` | `--expect-bridge-contract` | approved MultisigProxy address |
| `rgb_asset_id` | `--expect-rgb-asset-id` | the BFA asset of the deployment |
| `funds_in_contract` | `--expect-funds-in-contract` | `FUNDS_IN_CONTRACT` in `IMAGE-ENV.json` |
| `token_contract` | `--expect-token-contract` | `TOKEN_CONTRACT` in `IMAGE-ENV.json` |
| `evm_finality_tag` | `--expect-evm-finality-tag` | `EVM_FINALITY_TAG` in `IMAGE-ENV.json` (`safe` or `finalized`; `latest` is refused) |
| `spv_min_confirmations` | `--expect-spv-min-confirmations` (default 3 for mint/burn, 6 for combined) | `SPV_MIN_CONFIRMATIONS` in `IMAGE-ENV.json` |
| `gas_tx_*` | `--expect-gas-tx-to`, `--expect-gas-max-*`, `--expect-gas-selectors` | `GAS_TX_*` in `IMAGE-ENV.json` |
| `electrum_host` | `--expect-electrum-host` | the Electrum server you accept |
| `evm_rpc_tls.host` | `--expect-evm-rpc-host` | the EVM RPC host you accept |
| `evm_rpc_tls.ca_sha256` | `--expect-evm-rpc-ca-sha256` | SHA-256 of the exact approved CA DER bytes |
| `endpoints_sha256` | `--expect-endpoints-sha256` | public endpoint digest computed from approved inputs; required only for indexer trust |

The Arbitrum script below sets `chain_id` (42161) and `bridge_contract` (your
`MULTISIG_PROXY`) itself. For direct indexer verification, supply all three
chain, bridge and asset pins explicitly; the asset must not be empty.

Policy version 1 commits to the selected finality tag and the Bitcoin witness
depth. Real policy verification requires `--expect-evm-finality-tag` with the approved value. Receipt checks
require coverage by that head and canonical block-hash matching. Use the
verifier and EIF from the same release with approved PCRs.

The `policy` also lists `clone_peer_pcr3`, the PCR3 of the parent instance IAM
role. You set no flag for it. `attest-verify` takes the expected value from the
signed document, and refuses a burn signer whose PCR3 is missing or all zero.

## Run the SPV burn check

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
  --expect-gas-tx-to 0x6711f1a319B37847fa0234181C34D883774c4951 \
  --expect-electrum-host <electrum host> \
  --expect-evm-rpc-host <rpc host> \
  --expect-evm-rpc-ca-sha256 <64 hex characters>
```

The script:

1. Checks that the RPC serves chain 42161.
2. Downloads the bundle when you give a URL.
3. Runs `attest-verify --from-file` with your PCRs and flags. This checks the
   certificate chain to the AWS Nitro root, the COSE signature, the PCRs, the
   nonce, the public key and the commitment of the keys and the policy.
4. Reads the EVM address from the verified output.
5. Checks that the address is in `MultisigProxy.getEnclaveSigners(827166)`.
   827166 is the bridge's id for the RGB network (`RGB_CHAIN_ID`).

Exit 0 means all checks pass. Exit 1 names the check that failed. Exit 2 is a
usage error. The script refuses `--mock` with exit 2: a signer is verified in
real mode only. Run the script once for each published bundle.

## Verify a public-Signet indexer signer

`IndexerTrusted` is a real attested policy with full signing and custody pins.
It trusts the approved TLS indexer for Bitcoin confirmation evidence and does
not claim SPV validation. It is limited to public Signet and mint or burn
images. `Production` keeps its existing SPV encoding. The mint and burn image
recipes, including the stage profile, use `finalized` and Bitcoin witness
depth 3. The raw configuration and combined image default to `safe` and depth
6; use the approved image values when verifying.

The stage profile deliberately pairs public Signet with Arbitrum One
(`42161`). Approve the exact stage contracts and asset. A real attestation
proves the declared policy; it does not make the Signet trust model suitable
for production assets.

Approve the public endpoint inputs for each member: the exact indexer URL,
EVM RPC host, TLS port and CA DER bytes. Compute the public digest locally:

```bash
env -u EVM_RPC_PATH_FILE utexo-bridge-parent-cli set-endpoints --print-sha256 \
  --electrum-url ssl://electrum.example:50002 \
  --evm-rpc-host rpc.example \
  --evm-rpc-tls-port 443 \
  --evm-rpc-ca-der-file approved-rpc-ca.der
```

This command does not contact an enclave. It clears the RPC path and KMS
fields before hashing the protobuf request with the domain tag
`utexo/chain-endpoints/v2\0`. It binds the full indexer URL and endpoint ports
for `IndexerTrusted`; the existing `Production` policy binds the indexer host
and EVM RPC host/CA without these port fields. Copy the exact CA DER file to
the launch hosts. Hash that same file for `--expect-evm-rpc-ca-sha256`.

Provider API keys are not needed to verify or publish this digest. Operators
store the absolute RPC path in a restricted file and supply
`EVM_RPC_PATH_FILE` at launch. Rotating the path/API key leaves the public
digest, policy and EIF measurements unchanged. `SetEndpoints` is set once,
so rotation takes effect on the next enclave launch. A host, CA, port or
indexer URL change requires a newly approved runtime policy and digest, while
all members can continue using the common EIF. For mint, that digest also
binds the KMS ciphertext context: a trusted operator must rewrap existing
ciphertext to the approved new context; a key-policy update alone is
insufficient. Rotating the API key in the path needs no rewrap. See [KMS persistence](kms-persistence.md).
The path rules and digest encoding are in [the attestation specification](pubkey-attestation.md#public-endpoint-digest-and-credential-rotation).

After the mint enclave has its approved key, an operator can export it directly:

```bash
utexo-bridge-parent-cli --addr vsock://16:5000 export-attestation \
  --pcr-file PCR.json --image-env IMAGE-ENV.json --signer-role mint \
  --expect-evm-address "$APPROVED_MINT_ADDRESS" \
  --out attestation-16.json
```

Run this with the approved launch endpoint and KMS environment. Use the
`PCR.json` and `IMAGE-ENV.json` for the mint indexer release. The measured
image environment must contain `BTC_RELAY_MODE=none` and
`BITCOIN_NETWORK=signet`. The exporter verifies the complete policy and key
binding. It does not need `--allow-development-policy` or `--mock`; either
would expect `Development` and refuse an `IndexerTrusted` document. For burn,
use `--signer-role burn`, the burn release artifacts, and no KMS values.

For a public check of a burn bundle, set every variable below from approved
release artifacts and deployment records. `PUBLIC_ENDPOINTS_SHA256` is the
digest you calculated above. Gas flags must match the approved burn rule,
including zero limits or an empty selector list when that is the approved
rule. Do not populate these values from the bundle being checked.

```bash
attest-verify --from-file attestation-16.json \
  --pcr0 "$PCR0" --pcr1 "$PCR1" --pcr2 "$PCR2" \
  --expect-signer-role burn \
  --expect-btc-source indexer \
  --expect-endpoints-sha256 "$PUBLIC_ENDPOINTS_SHA256" \
  --expect-bitcoin-network signet \
  --expect-chain-id "$EVM_CHAIN_ID" \
  --expect-bridge-contract "$MULTISIG_PROXY" \
  --expect-rgb-asset-id "$RGB_ASSET_ID" \
  --expect-funds-in-contract "$FUNDS_IN_CONTRACT" \
  --expect-token-contract "$TOKEN_CONTRACT" \
  --expect-evm-finality-tag "$EVM_FINALITY_TAG" \
  --expect-spv-min-confirmations "$SPV_MIN_CONFIRMATIONS" \
  --expect-electrum-host "$ELECTRUM_HOST" \
  --expect-evm-rpc-host "$EVM_RPC_HOST" \
  --expect-evm-rpc-ca-sha256 "$EVM_RPC_CA_SHA256" \
  --expect-gas-tx-to "$GAS_TX_ALLOWED_TO" \
  --expect-gas-max-gas-limit "$GAS_TX_MAX_GAS_LIMIT" \
  --expect-gas-max-fee-per-gas "$GAS_TX_MAX_FEE_PER_GAS" \
  --expect-gas-max-value-wei "$GAS_TX_MAX_VALUE_WEI" \
  --expect-gas-selectors "$GAS_TX_ALLOWED_SELECTORS"
```

For mint, select `--expect-signer-role mint` and the mint measurements, remove
the gas flags, and add `--expect-kms-key-arn`, `--expect-kms-region` and
`--expect-kms-seed-id` with the approved values. Add `--expect-kms-evm-address`
when the launch policy sets one, and `--expect-vanilla-psbt` only when the
approved mint image enables that path.

The verifier requires real AWS Nitro attestation and nonzero PCR0/1/2. It
rejects the wrong role, network, host, CA, public digest, or trust mode. Its
default `spv` expectation refuses an indexer policy. The explicit indexer
expectation refuses `Production` and `Development`; `--mock` cannot bypass
these checks. Burn verification also requires the committed clone-peer PCR3
to match the nonzero PCR3 in the signed document.

This direct command verifies attestation only. Check the verified address
against the approved bridge registration too. `build/verify-signer.sh` is
fixed to EVM chain 42161 and RGB chain ID 827166. It can perform that check for
an indexer burn deployment using those IDs: set its approved stage
`MULTISIG_PROXY` and pass all the indexer expectation flags. It is not a mint
registration check. For a live nonce check, replace `--from-file` with the
approved parent `--endpoint` and configure the
[parent mTLS client](parent-mtls.md).
