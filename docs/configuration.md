# Configuration

A setting of the enclave or the parent has one of four homes. The home
decides who can change the setting and what proves its value. The inputs of
the deploy script are in [operations.md](operations.md).

| Kind | Set by | Takes effect | Proven by |
|------|--------|--------------|-----------|
| [Image settings](#image-settings) | The image recipe, as `ENV` | A new image | PCR0. The attested policy also commits some of them. |
| [Launch values](#launch-values) | The operator, once per boot (`SetEndpoints`) | A new launch | A `Production` policy commits the public ones. PCR0 does not. |
| [Runtime limits](runtime-limits.md) | The operator, at any time (`limits set`) | The next request | Nothing. They only refuse or delay work. |
| [Parent settings](#parent-settings) | The environment of the parent | A parent restart | Nothing. The parent is not trusted. |

A Nitro enclave takes no environment from the host. So an image setting
cannot change after the build.

## Image settings

### Bridge pins

All of the first three are required for a `Production` policy.

| Variable | Default | Description |
|----------|---------|-------------|
| `EVM_CHAIN_ID` | `0` | Pinned chain id. It must match the destination chain and the `destinationChainId` of the direct route. |
| `EVM_PROXY_CONTRACT_ADDRESS` | zero | The `MultisigProxy` address: the EIP-712 `verifyingContract`, and the `to` of the payable `lzFundsOutCall`. Attested as `bridge_contract`. |
| `RGB_ASSET_ID` | empty | Pinned RGB contract id. There is no default asset. |
| `FUNDS_IN_CONTRACT` | the proxy address | The emitter of `FundsIn` and `BridgeFundsIn`. Unset uses the proxy address; a set value that is not an address stops the boot. Attested. It must be non-zero in production. |
| `TOKEN_CONTRACT` | zero | The ERC-20 that the Bridge releases. An input of `burnId` and of the deposit id. Attested. It must be non-zero in production. |
| `BTC_RELAY_MODE` | `required` | `required` checks both BtcRelay words of a release against the enclave's own records. `none` requires both words to be zero. A production policy refuses to boot on `none`, and a build without `spv` boots only on `none`. Any other value acts as `required`, with a warning at boot. |
| `BITCOIN_NETWORK` | `bitcoin` | `bitcoin` (or `mainnet`), `testnet3` (or `testnet`), `testnet4`, `signet`, `signetcustom` or `regtest`. It selects the SPV rules and checkpoint, the RGB chain network, the coin types and the xpub prefix. An unknown value stops the boot. Attested. A production policy on EVM chain 1 or 42161 requires `bitcoin`. |

### Acceptance rules

| Variable | Default | Description |
|----------|---------|-------------|
| `EVM_FINALITY_TAG` | `finalized` | The head that must cover a deposit receipt: `latest`, `safe` or `finalized`, in exactly this spelling. Another value stops the boot. Attested. A production policy refuses `latest`. Both EIF recipes set `finalized`. |
| `SPV_MIN_CONFIRMATIONS` | `3` | Minimum depth of each Bitcoin witness transaction on the burn path. Zero or a non-number stops the boot. Attested. Both EIF recipes set 3. No mint check reads it. |
| `MINT_WITNESS_SAT` | `1500` | Mint signer: the exact sats that a witness mint pays to the user's output. A non-number or a value outside 546 to 10000 stops the boot. It must equal the connector's `MINT_WITNESS_SAT` ([mint-flow.md](mint-flow.md), M8). Measured, not attested: read the value of an image from its `IMAGE-ENV.json`. |
| `BTC_MAX_TOTAL_SATS` | `0` | Cap on the total input value of one `SignBtc` transaction. On a mint signer a non-zero value also turns `allow_vanilla_psbt` on in the attested policy. |
| `BTC_MAX_UNOWNED_SATS` | `0` | `SignBtc` budget for outputs that the enclave does not prove it owns. |
| `GAS_TX_ALLOWED_TO` | unset | The only `to` that a gas transaction may have. |
| `GAS_TX_MAX_GAS_LIMIT` | `0` | Ceiling on `gasLimit`. |
| `GAS_TX_MAX_FEE_PER_GAS` | `0` | Ceiling, in wei, on `maxFeePerGas`, `maxPriorityFeePerGas` and the legacy `gasPrice`. |
| `GAS_TX_ALLOWED_SELECTORS` | empty | Comma-separated 4-byte selectors that a gas transaction may call. A malformed entry is dropped with a warning. |
| `GAS_TX_MAX_VALUE_WEI` | unset | Ceiling on the native `value`. Only `lzFundsOutCall` to the proxy may carry value. |
| `KMS_ALLOWED_ACCOUNT_IDS` | none | Mint signer: the AWS accounts that the seed KMS key may live in ([kms-persistence.md](kms-persistence.md)). |

An unset destination, gas ceiling, fee ceiling or selector list refuses every
gas transaction. An unset `GAS_TX_MAX_VALUE_WEI` refuses only a gas
transaction with a non-zero value. The whole gas rule is part of the attested
policy, and an unset value commits as zero.

`EVM_FINALITY_TAG` on Arbitrum:

| Tag | What the head covers |
|-----|----------------------|
| `latest` | The current L2 tip. Sequencer and L1 reorganization risk. Development builds only. |
| `safe` | A batch that is posted and covered by the safe head of L1. Some L1 reorganization risk remains. |
| `finalized` | A batch covered by the finalized head of L1. |

See the
[Arbitrum finality guidance](https://docs.arbitrum.io/how-arbitrum-works/reference/finality-and-reorgs).

### Transport, limits and dev settings

| Variable | Default | Description |
|----------|---------|-------------|
| `ESPLORA_VSOCK_PORT` | `8001` | Host `vsock-proxy` port for the Bitcoin indexer. |
| `EVM_RPC_VSOCK_PORT` | `8002` | Host `vsock-proxy` port for the EVM RPC. |
| `KMS_VSOCK_PORT` | `8003` | Mint signer: host `vsock-proxy` port for AWS KMS. |
| `ENCLAVE_LISTEN_ADDR` | `127.0.0.1:5000` | TCP listen address, on a build without `vsock` only. |
| `RUST_LOG` | unset | Log filter. The enclave always turns `alloy_transport_http` logs off: they can hold the full RPC URL. |
| `MAX_CONSIGNMENT_BYTES` | the image value of `max_consignment_bytes` | It can only lower the image value of that [runtime limit](runtime-limits.md); a larger value stops the boot. Unset, zero or a non-number gives the default. No supplied image sets it. |
| `MAX_MERKLE_PROOFS`, `MAX_TOTAL_PROOF_BYTES` | the image values of `max_merkle_proofs` and `max_total_proof_bytes` | Each replaces the image value of its runtime limit with any positive number, lower or higher. Unset, zero or a non-number gives the default. No supplied image sets them. |
| `CLONE_EXPORT_SOFT_CAP` | unset | Seed exports of one enclave process before a warning. It blocks nothing. |
| `CLONE_EXPORT_HARD_CAP` | unset | Seed exports of one enclave process. A restart resets the count. Unset or zero means no cap. A set value that is not an unsigned integer stops the boot. No supplied image sets it. |
| `UTEXO_CLONING_SECRET` | unset | For dev images: the donor cloning secret, read from the image env at boot. Every build without `kms-persistence` reads it, a release burn image too, so no release recipe may set it. |
| `SPV_CHECKPOINT` | unset | Dev builds only: `height:hash:bits:time[:chainwork]` moves the SPV anchor forward. `bits` and `time` are those of that block. Without `chainwork`, a release fails under `BTC_RELAY_MODE=required`. A production-shaped build refuses to boot when it is set. |

## Launch values

The operator sends these once after launch, with
`utexo-bridge-parent-cli set-endpoints` (`SetEndpoints`). A build requires
the values that it uses and refuses the others. `deploy-host.sh` reads
`ELECTRUM_URL`, `EVM_RPC_TLS_CA_DER_FILE`, `EVM_RPC_PATH_FILE` and the KMS
values from its environment and writes them to `/etc/utexo/enclave-<CID>.env`.
`EVM_RPC_HOST` and `EVM_RPC_TLS_PORT` come from
`/etc/nitro_enclaves/vsock-proxy-evmrpc.env`, which
`deploy/host-prep-evmrpc.sh` writes.

| CLI flag / variable | Build | Description |
|---------------------|-------|-------------|
| `--electrum-url` / `ELECTRUM_URL` | mint, burn | `ssl://host:port` (Electrum) or `https://host[:port]` (Esplora), serving the configured Bitcoin network. Electrum must support verbose transaction lookup. TLS ends inside the enclave. Plaintext `tcp://` and `http://` URLs are allowed only in test, debug or dev-feature builds. |
| `--evm-rpc-host` / `EVM_RPC_HOST` | mint, burn | TLS host name of the EVM RPC. No scheme, path, port or IP literal. |
| `--evm-rpc-tls-port` / `EVM_RPC_TLS_PORT` | mint, burn | TLS port, 1 to 65535, not the indexer port. |
| `--evm-rpc-ca-der-file` / `EVM_RPC_TLS_CA_DER_FILE` | mint, burn | DER of the only CA that the EVM RPC connection trusts. |
| `--evm-rpc-path-file` / `EVM_RPC_PATH_FILE` | mint, burn, optional | A restricted file with the absolute RPC path, such as `/v2/<key>`. Without it the path is `/`. |
| `--kms-key-arn` / `KMS_KEY_ARN` | mint | Full ARN of the symmetric KMS key. An alias is refused. |
| `--kms-region` / `KMS_REGION` | mint | Commercial AWS region of the key. |
| `--kms-seed-id` / `KMS_SEED_ID` | mint | Stable signer id, used in the KMS encryption context and sent in each storage request. It must equal the `KMS_SEED_ID` of the parent. |
| `--kms-expected-evm-address` / `KMS_EXPECTED_EVM_ADDRESS` | mint, optional | The identity pin: 40 hex digits, `0x` optional. Empty for the first bootstrap only ([kms-persistence.md](kms-persistence.md)). |

**What is attested.** A `Production` policy commits the indexer host, the EVM
RPC host, the SHA-256 of the CA and the four KMS values. It does not commit
the ports, the scheme or the RPC path. A `Development` policy commits none of
these. A verifier compares the committed values with independently approved
ones ([pubkey-attestation.md](pubkey-attestation.md)).

**One image, many members.** The launch values are not build inputs. Members
with the same role, release and build profile run the same EIF with their own
endpoints, and a rebuild reproduces PCR0 without knowing them. The exception
is `KMS_ALLOWED_ACCOUNT_IDS`, which is in the mint image: members share one
mint image only if the list has the account of each member's key.

**Changes.** The enclave refuses a second `SetEndpoints`. New values need a
new launch, with the same EIF. A restart removes the keys in memory. A burn
donor with another attested endpoint policy cannot clone into the new launch.

**The RPC path and provider keys.** A provider such as Alchemy or Infura puts
an API key in the URL path. Put the path in a restricted file and pass
`EVM_RPC_PATH_FILE`.

- The path must be absolute ASCII, at most 2048 bytes, of letters, digits
  and `/-._~` only. An authority, a query, a fragment, a
  percent escape and a dot segment are refused. An empty file is refused.
- The path is not in the EIF, the image metadata, the attestation or the KMS
  context. Error texts and debug output leave it out.
- To rotate a key, replace the file and launch again with the same public
  values. No rebuild and no change of a PCR allowlist is needed.
- The parent supplies the file, so a compromised parent can read the key.
- `deploy-host.sh` keeps a copy in `/etc/utexo/evm-rpc-path-<CID>`, with mode
  0600 and the service user as owner, and the launch reads that copy. A
  deploy without the variable keeps the copy of that CID. To rotate a key on such a host,
  replace the copy and restart the enclave, or deploy again with
  `EVM_RPC_PATH_FILE`. To go back to the path `/`, delete the copy and deploy
  again.

## Parent settings

The parent reads these from its environment at start. A number that does not
parse takes the default with no log, unless the row says otherwise.
`deploy-host.sh` rewrites `/etc/utexo/parent-<CID>.env` on each run, so a
value set by hand in that file is lost. It passes through
`GRPC_REQUEST_TIMEOUT_SECS` (default 120) and `GRPC_MAX_CONCURRENT_SIGN`
(default 8), rejecting an empty value, zero,
leading zeros, non-digits or more than seven digits before changing the host.
Supply those values on each deploy. It writes no `GRPC_MAX_CONCURRENT`,
`GRPC_MAX_CONCURRENT_PER_CONN` or
`SIGNED_RESPONSE_*` value, so a deployed parent uses their defaults.
The TLS and ACL settings are in
[parent-mtls.md](parent-mtls.md), and the KMS storage settings in
[kms-persistence.md](kms-persistence.md).

| Variable | Default | Description |
|----------|---------|-------------|
| `GRPC_HOST` | `127.0.0.1` | Bind address. The deploy script uses the private EC2 address. |
| `GRPC_PORT` | `5000` | gRPC port. Deployments use 50051 to 50053. |
| `GRPC_MAX_CONCURRENT` | `128` | Requests in progress over all connections. The parent refuses a request above the limit and does not queue it. `0` acts as `1`. |
| `GRPC_MAX_CONCURRENT_SIGN` | `8` | `Sign` requests in progress. A `Sign` above the limit gets `UNAVAILABLE` at once. `0` acts as `1`. The `MemoryMax` of the parent unit counts on the default. |
| `GRPC_MAX_CONCURRENT_PER_CONN` | `32` | Requests in progress on one connection, and the HTTP/2 stream limit. `0` acts as `1`. |
| `GRPC_REQUEST_TIMEOUT_SECS` | `120` | Longest run of one gRPC request. Keep it above the request deadline of the enclave plus `ENCLAVE_WAIT_MARGIN_SECS`. The parent logs an error when the deadline in force reaches it. `0` acts as `1`. |
| `GRPC_CLONE_MAX_PER_MINUTE` | `30` | `Clone` calls per minute for all clients, 1 to 10000. A value out of range, a non-number or an empty value stops the parent at boot. A parent without mTLS does not read it and has no budget. |
| `GRPC_ATTEST_MAX_PER_MINUTE` | `6` | `AttestedPublicKey` calls per minute for all clients, with the same rules. Each call makes one NSM attestation. |
| `ENCLAVE_ADDR` | `127.0.0.1:5000` | Enclave TCP address (dev). |
| `USE_VSOCK` | `false` | `true` or `1` selects vsock (Linux only). |
| `ENCLAVE_VSOCK_CID` | `16` | Enclave CID. With `USE_VSOCK`, a set value that is not a number stops the parent at start. |
| `ENCLAVE_VSOCK_PORT` | `5000` | Enclave vsock port. With `USE_VSOCK`, a set value that is not a number stops the parent at start. |
| `SIGNED_RESPONSE_TTL_SECS` | `3600` | How long the parent keeps the reply of an EVM -> RGB sign and answers a retry of the same request from it. Keep it at or above the enclave's `mint_replay_ttl_secs`. The parent logs a warning when it is below the value in force. With `0`, no retry gets a kept reply. |
| `SIGNED_RESPONSE_MAX_ENTRIES` | `1024` | Count limit of kept replies. `0` still keeps one reply. |
| `SIGNED_RESPONSE_MAX_BYTES` | `16777216` | Byte limit over all kept replies. The parent does not keep a larger reply. `0` keeps none. |
| `HEADER_ELECTRUM_URL` | unset | `ssl://host:port` (WebPKI roots, host name checked, so no private or self-signed certificate), or `tcp://` to a loopback IP. The header sync of the parent reads Bitcoin headers here. Unset or malformed: the parent still serves, and `header_sync.state` is `unconfigured`. The deploy passes it through; it does not copy `ELECTRUM_URL`. |
| `HEADER_SYNC_INTERVAL_SECS` | `10` | Seconds between header sync steps, 1 to 600. A malformed value stops the parent at boot. |
| `HEALTH_HOST` | `127.0.0.1` | Bind host of `GET /health`. Keep it on loopback. |
| `HEALTH_PORT` | `5001` | Port of `GET /health`. |
| `RUST_LOG` | unset | Log filter. |
