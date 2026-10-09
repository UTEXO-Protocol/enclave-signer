# Verify a burn signer

This guide shows how to check, without access to the operator, that a burn
signer's EVM address belongs to approved enclave code and is a signer of the
bridge on Arbitrum One.

The operator publishes one attestation bundle per burn enclave:
`attestation-<CID>.json`. `deploy/verify-identity.sh` writes it after the
enclave has its key. It fails and writes nothing if the attestation does not
verify.

## What one bundle proves

The bundle holds an AWS Nitro attestation document for a burn key. When it
verifies, the approved code (the PCRs you trust) created this key and holds it:

- The release burn build has no seed import.
- Cloning sends the seed only to an enclave with the same PCRs.

So every signature by the attested EVM address comes from that code.

## What it does not prove

- That the enclave runs now. The document is a record of one moment.
- That the document is fresh. The operator chose the nonce. Use
  `attest-verify --endpoint` with your own nonce for a live check (see
  [pubkey-attestation.md](pubkey-attestation.md)).
- Anything about the mint signer.

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
- The MultisigProxy address. The burn image pins it as
  `EVM_PROXY_CONTRACT_ADDRESS` in `build/Dockerfile.enclave.burn`.

## Choose the expected launch values

The bundle's `policy` lists every attested launch value. Do not copy them. Read
them, and decide whether you accept each one:

| policy field | flag | source |
|---|---|---|
| `signer_role` | `--expect-signer-role burn` | always `burn` |
| `rgb_asset_id` | `--expect-rgb-asset-id` | the BFA asset of the deployment |
| `funds_in_contract` | `--expect-funds-in-contract` | `FUNDS_IN_CONTRACT` in `IMAGE-ENV.json` |
| `token_contract` | `--expect-token-contract` | `TOKEN_CONTRACT` in `IMAGE-ENV.json` |
| `evm_finality_tag` | `--expect-evm-finality-tag` | `EVM_FINALITY_TAG` in `IMAGE-ENV.json` (`latest`, `safe`, or `finalized`) |
| `gas_tx_*` | `--expect-gas-tx-to`, `--expect-gas-max-*`, `--expect-gas-selectors` | `GAS_TX_*` in `IMAGE-ENV.json` |
| `electrum_host` | `--expect-electrum-host` | the Electrum server you accept |
| `evm_rpc_tls.host` | `--expect-evm-rpc-host` | the EVM RPC host you accept |
| `evm_rpc_tls.ca_sha256` | `--expect-evm-rpc-ca-sha256` | SHA-256 of the CA you accept, without `0x` |

The script sets `chain_id` (42161) and `bridge_contract` (your
`MULTISIG_PROXY`) itself.

Policy version 9 commits to the selected finality tag. Production verification
requires `--expect-evm-finality-tag` with the approved value. Receipt checks
require coverage by that head and canonical block-hash matching. Use the
verifier and EIF from the same release with approved PCRs.

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
  --expect-evm-finality-tag safe \
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
usage error. Run the script once for each published bundle.
