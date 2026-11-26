# Mint and burn rollout acceptance

A successful release starts a measured enclave and its parent. It does not
register a signing identity or enable backend traffic. Complete the checks
below for the intended backend deployment before enabling that traffic.
Keep the evidence outside this public source tree, in the deployment's
access-controlled release record. Do not include credentials or seed material.

## Approved inputs

Name the environment and the person or change record that approves it. Record
the following inputs before querying the candidate signers. A live response is
an observation, not its own approval.

| Input | Required record |
| --- | --- |
| Release | Signer source commit, build profile, measured build inputs, artifact location, EIF and host checksums, `PCR.json`, `IMAGE-ENV.json`, and verifier source/binary checksum. |
| Routing | Host, CID, enclave and parent service names, parent mTLS endpoint, backend service and role for every signer. Give mint and burn distinct endpoints. |
| Identity | Mint main EVM address, vanilla and colored account xpubs and master fingerprint; burn main EVM address for each independent signer. Mark replicas that share a seed. |
| Custody | Mint KMS key/context, seed object/version and recovery pin; burn donor, compatible image/policy, parent IAM role and restricted cloning-secret reference. |
| Endpoint policy | Approved EVM RPC hostname and CA DER SHA-256, plus port/network and the restricted credential-file reference. Keep the credential itself out of evidence. |
| Backend and contracts | Backend revision/configuration digest, RGB asset/network, chain ID, Bridge, MultisigProxy, token, payout route, signer set, threshold, relay and any LayerZero settings. |

Compare deployed Burn values against this record. For each value, record the
approved source revision, observed value, observation time and result. A missing
approval is `not verified`; equality between two deployed values is insufficient.

- Compare the RGB asset, chain, contracts, finality, witness depth and gas rule
  with the verified attestation and the measured image environment.
- Compare the enclave's EVM RPC host and CA with independently approved pins. The
  policy commits the host and CA; it does not commit the port or credential
  path. Check those separately without recording a secret path value.
- Read the deployed bridge signer set and threshold at a recorded block. A
  replica of the same seed counts as one identity, not another vote.
- Check the backend payout route and relay mode, contract and synchronization
  against the approved network. Attestation does not establish that a relay
  is deployed, synchronized or used by the backend.
- If LayerZero is enabled, record the local adapter, remote peer, source and
  destination chain/EID, message type and enforced delivery options. Compare
  the contract reads and backend route with the approved deployment. Exercise
  that route separately from direct payout. If disabled, record the evidence
  that the backend cannot select it; do not silently omit the check.

Use the ABI matching each deployed contract revision. In
`bridge-smart-contracts/ethereum/src/interfaces/IMultisigProxy.sol`,
`getEnclaveSigners(sourceChainId)` and `enclaveThreshold(sourceChainId)` give
the Burn signer set and threshold for the approved RGB source network;
`bridge()` gives its Bridge and `lzAdapter()` gives its LayerZero adapter.
Read `Bridge.routeRegistry()` and that registry's
`getRoute(sourceChainId, destChainId)`. Compare all three route fields:
`enabled`, `finalityVerifier` and `settlementModule`. Their definitions are in
`ethereum/src/interfaces/IBridge.sol`, `IRouteRegistry.sol` and `RouteTypes.sol`
in the same repository.

For an RGBVerifier route, compare `btcRelay()`, `minSourceConfirmations()`,
`maxLatestConfirmations()` and `minConfirmationGap()` with the approved relay
policy. These getters are defined in
`bridge-smart-contracts/ethereum/src/verifiers/RGBVerifier.sol`. A contract
read proves configuration at the recorded block, not current relay progress.

For LayerZero, the adapter getters `endpoint()`, `token()`, `bridge()`,
`multisigProxy()` and `oftByEid(destinationEid)` identify the local path. At
the selected OFT, compare `peers(destinationEid)` and
`enforcedOptions(destinationEid, messageType)` with approved values. Enforced
options belong to the OFT/OApp, not to the UTEXO adapter. Use the actual
message-type definitions of that deployed OFT. For an inbound path, also
compare the adapter's `trustedEntrypoints(sourceEid)` and
`eidToChainId(sourceEid)`. Adapter definitions are in
`usdt0-smart-contracts/ethereum/src/interfaces/IUtexoLZAdapter.sol`; the
`bridge` repository's `internal/contracts/lzexecutor/lzexecutor.go` exposes
the enforced-options getter. Retain the deployed revisions and ABIs alongside
the reads; source defaults are not deployment approvals.

## Verifier compatibility

Use the policy encoding and bundle format from
[attested keys](pubkey-attestation.md#security-policy-commitment), with the
matching enclave, parent CLI and external verifier. Approve complete release
measurements, not just a policy version number.

| Candidate | Acceptance |
| --- | --- |
| Current Production image and matching verifier | Real NSM, fresh nonce, approved nonzero PCRs, exact role and policy, endpoint pins and approved keys must all pass. |
| Legacy V4 or an older verifier/image | Keep out of the new routing set. The current decoder accepts its own format only; a version name or a successful historical check is no compatibility proof. Retain a separately approved old verifier only for old-image rollback evidence. |
| Public-Signet Development policy | Real NSM can bind keys to approved PCRs, but the policy commits neither role nor endpoint. `--allow-development-policy` is diagnostic evidence and cannot pass the Production identity gate. |
| Nitro debug or mock attestation | Cannot approve an identity for this rollout. |

Before switching consumers, run the matching verifier on the candidate and
record rejection of a wrong role, PCR set, identity and endpoint. Check every
backend verifier and standalone consumer. Never retry a failed Production
verification in Development/mock mode or remove an expected field to make it
pass. A successful legacy verification must stay labelled with its source
revision and policy; it does not establish current-policy compliance.

## Deploy, recover and register

1. Keep candidate endpoints out of the backend's active routing set. Record
   current peer enclave IDs, public identities, parent process IDs and config
   digests. Check free host/allocator capacity without restarting the allocator.
2. Approve the new PCRs in consumer verifiers and, for mint, the KMS key policy
   before deployment. Retain only the explicitly approved rollback PCRs and
   artifacts during the rollback window. Follow
   [mint release](mint-release.md) for provisioning and release inputs.
3. Deploy each role with `Release EIF (deploy)`, its explicit role and CID,
   matching artifacts and approved per-CID configuration. Record the workflow
   run and SSM command results. Debug mode is off. A failed launch-role check
   must stop the selected candidate before its parent starts.
4. Bootstrap a fresh, isolated mint identity once, with an absent seed object.
   Verify and approve its attested keys before registration. Pin the approved
   address, remove bootstrap permission and recover the same seed on a separate
   host. Compare both xpubs, the fingerprint and EVM address. Record unchanged
   ciphertext version/checksum. An existing signer always uses recovery.
5. Initialize a new burn identity with a restricted cloning-secret file, or
   clone from a compatible live donor. Verify the resulting attested address.
   Record the clone result and compare the full key bundle. A fresh burn image
   needs a new identity and a deliberate registration change; see below.
6. Run the [identity gate](verify-a-signer.md#operator-approve-every-signer-before-routing)
   for every candidate using approved pins. Require exit 0 from every run;
   neither liveness nor a partial set of bundles approves the routing set.
7. Register exactly the verified mint vanilla/colored xpubs and fingerprint
   in the intended RGB wallet/backend. Read the effective running configuration
   back and compare it, including the network and derivation assumptions. Save
   a configuration revision/digest and the comparison result. This script does
   not perform registration for the backend.
8. Register each verified burn EVM address through the bridge's approved
   administration process. Read the signer set and threshold back after the
   required finality. Save transaction/block references and the comparison.
   A `get-keys` printout or submitted transaction alone is not registration.

Run a fresh external attestation check through each parent's real mTLS
endpoint as well as the local host gate. A local vsock check does not prove
which enclave the backend's endpoint reaches. Retain the independent expected
values and the nonce/result with that endpoint's record.

## Backend routing and activation

The `bridge` repository's `signer/routing.go` and
`signer/microservice/microservice.go` own backend routing. Check the deployed
revision rather than assuming it matches the source under review.
`FEDERATED_NODES_TOPOLOGY` gives each group its burn `listeners` and its
separate mint `rgbSigner`. Compare the effective topology with the approved
host/CID/parent mapping. Require an explicit, nonempty `rgbSigner` in every
active group: the backend's legacy behavior when it is absent sends mint to
the listener group. An address present in both roles must be refused.

Check the following effective configuration in the running backend, using the
definitions from its deployed source revision:

| Component | Fields and source |
| --- | --- |
| RGB wallet | `WALLET_XPUB_VAN`, `WALLET_XPUB_COL`, `WALLET_MASTER_FINGERPRINT` and `WALLET_VANILLA_KEYCHAIN`; `bridge/connectors/rgb/microservice/microservice.go`. Compare both account xpubs, not only the root xpub or EVM address. |
| Signer router | Each `FEDERATED_NODES_TOPOLOGY.groups` entry's `lane`, `threshold`, `listeners` and `rgbSigner`, plus `adminLanes`; `bridge/signer/routing.go`. |
| Listener to parent | `PARENT_ADAPTER_GRPC_ADDR`, `PARENT_ADAPTER_TLS_SERVER_NAME` and the public CA/client-certificate fingerprints; `federated-signer-node/README.md`. Keep private key bytes out of evidence. |
| Listener policy | `RGB_EXPECTED_ASSET_ID`, `EVM_CHAIN_ID`, `EVM_BRIDGE_CONTRACT_ADDRESS` and `EVM_PROXY_CONTRACT_ADDRESS`; `federated-signer-node/README.md` and its configuration example. |
| EVM connector | `BRIDGE_CONTRACT_ADDRESS`, `MULTISIG_PROXY_ADDRESS`, `BTC_RELAY_ADDRESS`, `BURN_MIN_CONFIRMATIONS`, `CONFIRMATION_BLOCKS`, `CHAIN_NAME` and `LZ_EID`; `bridge/connectors/evm/connector.go` and `connectors/evm/microservice/microservice.go`. |

An existing RGB wallet also needs a compatible network, derivation and stored
wallet state. Do not recreate the wallet to make a changed key pass. Compare
the router's threshold and independent signer identities with the contract
read-back. A listener's mTLS client certificate needs the `listener` role in
its intended Parent ACL. An `observer` certificate can check public identity
but cannot establish that signing traffic works. Preserve existing ACL entries
when provisioning a separately approved client.

Use an isolated backend with fresh disposable identities, its own database,
token/asset and credentials for acceptance. A mock enclave test or direct
vsock request is not an end-to-end backend test. A public-Signet Bitcoin
profile can still name a mainnet EVM chain; check the actual chain/contracts
before creating a transaction.

Record these cases with request IDs, endpoint observations and verified
responses. Send the same valid flow request to the opposite role, so that a
parse error cannot masquerade as role enforcement.

| Case | Required result |
| --- | --- |
| Candidate identity is unverified or mismatched | Candidate receives no routed signing traffic; activation refuses. |
| Valid mint through the backend | Only the mint parent receives the signing request. Verify the returned PSBT signatures against the registered mint keys and approved intent. |
| Same mint request to burn | Explicit wrong-role refusal and no signature. |
| Valid burn through the backend | Only the burn parent receives the signing request. Recover the signer from the EIP-712 signature and compare its digest, route and membership with the approved burn identity. |
| Same burn request to mint | Explicit wrong-role refusal and no signature. |
| Direct/LayerZero payout and relay, when enabled | Each approved route succeeds with its genuine evidence; an unapproved route/options combination fails. |
| Peer preservation | Existing peer enclave IDs, identities and parent processes/configuration remain unchanged throughout candidate deployment and refusal tests. |

Enable the candidate in the backend only after identity, registration,
configuration, readiness and genuine signing checks pass. Record the activation
time and configuration revision after the last verification time. Re-read the
effective topology and perform a bounded post-activation check. A parent port
being open or returning healthy is not evidence of this ordering.

## Rollback and identity continuity

Stop candidate traffic on a policy/identity mismatch, missing registration,
wrong route, failed genuine signing, failed relay check or lost quorum.
Preserve evidence before changing the candidate. Restore an approved route
only after its own identity and readiness checks pass again.

**Mint:** retain the compatible old image, KMS key/context, ciphertext and
approved keyset. The old PCRs must still be permitted by KMS and verifiers.
Redeploy in recovery mode and verify the same full identity before restoring
traffic. Do not overwrite the seed or bootstrap a replacement on recovery
failure. Remove old PCR permissions only after the rollback window ends.

**Burn:** persistence means retaining compatible live donors, not a disk seed.
Keep an old-image donor alive and out of candidate deployment. A new-image
burn cannot clone from it because the measurements differ. Initialize and
attest a new identity, update membership/threshold with the bridge's approved
transition procedure, then switch traffic while preserving quorum. If rolling
back, restore the old membership and route only after verifying a live old
identity or cloning it onto the compatible old image. An old EIF without a
live donor cannot recover the old key. If every old donor is lost, stop: the
recovery is a new identity and registration process, not a restart.

## Evidence required for completion

Attach the source/artifact and approval record, per-role host/CID mapping,
real attestation outputs, bootstrap/recovery/clone comparisons, registration
read-backs, configuration comparisons, routing/signing results, refusal cases,
activation ordering and upgrade/rollback results. Include timestamps, command
exit codes and before/after peer snapshots. Hash the retained files.

For each case report `passed`, `failed` or `not verified`, with its evidence
path. Record why a case could not run. Unit tests, historical tests on another
policy, and a documented procedure remain separate evidence; none completes
an unexecuted deployment check.
