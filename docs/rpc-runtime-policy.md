# Runtime RPC policy and common EIF measurements

Members using the same signer role, release and build profile use the same EIF
and image PCR0/1/2 reference. Their RPC provider, CA, port and API key are launch
inputs, not build inputs. PCR3 can differ because it measures the parent IAM
role. Image measurements identify code and baked configuration; attested policy
identifies the public configuration accepted at launch.

The public-Signet profile without SPV uses the explicit `IndexerTrusted` policy.
It trusts the approved Bitcoin indexer for witness status and confirmation
depth. Both the RGB Merkle proof list and the release proof must be empty;
it endorses no Bitcoin header claims. TLS authenticates the chosen providers;
it does not prove their answers.
The default `Production` policy still requires SPV. A verifier must explicitly
approve indexer trust. Neither real policy can be replaced by Development or
mock verification.

## Public endpoint digest

After validating `SetEndpoints`, the enclave calculates:

```text
SHA256("utexo/chain-endpoints/v2\0" || protobuf(public_request))
```

The domain is ASCII with one trailing NUL byte. `public_request` is a fresh
`SetEndpointsRequest` with these exact received values:

| Included field | Meaning |
| --- | --- |
| `electrum_url` | Complete approved indexer URL, including scheme and port. |
| `evm_rpc_host` | Approved TLS host name. |
| `evm_rpc_ca_der` | Exact approved CA DER bytes. |
| `evm_rpc_tls_port` | Approved TLS port. |

All four KMS fields and `evm_rpc_path` are cleared before protobuf encoding.
The protobuf encoder omits their default values. Unknown wire fields are not
part of the decoded request. No host, URL or certificate normalization is
applied to the retained fields. Use the exact same strings and CA bytes when
calculating and launching. The public digest has no environment override and
is not an EIF build argument.

`cli set-endpoints --print-sha256` calculates the same digest without contacting
an enclave. The implementations in `enclave/src/config.rs` and
`parent/src/launch_check.rs` share a golden vector and classify every request
field explicitly. A schema change requires review of both implementations.

## Provider credentials

Pass a restricted `EVM_RPC_PATH_FILE` at launch for a path such as `/v2/<key>`.
Omit it to use `/`. A supplied empty file is invalid. Only absolute ASCII paths
up to 2048 bytes are accepted. Authorities, queries, fragments, percent escapes
and dot segments are rejected. The parser validates a supplied path even when
only printing the public digest.

The whole path is private runtime configuration. It is absent from the EIF,
public endpoint digest, KMS encryption context and attested policy. A verifier
needs no API key. Approval covers all accepted paths under the approved host
and CA; it does not identify a provider account. The parent supplies the key
and can read that file, so this does not hide it from a compromised parent.

`SetEndpoints` is one-shot. Rotate a key by replacing the restricted file and
restarting with the same public endpoint inputs. This changes no image PCR,
public digest or custody context. Host, CA, port or indexer URL changes do
change the public digest and require a new policy approval, but no EIF rebuild.

## Enforce the approved policy

`IndexerTrusted` commits the full bridge, role, network, finality, gas, TLS and
custody pins, followed by the public endpoint digest. Public verification needs
independently approved PCRs and configuration. Do not copy expectations from an
unverified bundle or the parent being checked.

- `verify-launch` and `export-attestation` derive the policy kind from approved
  image metadata and calculate the digest from approved launch inputs.
- `attest-verify` defaults to SPV. For stage, explicitly provide
  `--expect-btc-source indexer --expect-bitcoin-network signet
  --expect-endpoints-sha256 <digest>` and all required bridge and launch pins.
- A no-SPV mint supplies the digest as the fifth KMS context entry,
  `chain_endpoints_sha256`. KMS access policy must require the member's approved
  digest. An attacker who chooses other endpoints cannot decrypt the existing
  seed with the new context. The enclave never retries the old context.
- Burn clone activation checks exact donor/requester policy equality. A
  different endpoint digest fails before installing the donor's keys. API-key
  paths can differ because they do not change that policy.

An external verification script alone cannot constrain a compromised parent.
KMS context and clone commitments enforce the endpoint binding during seed
recovery. They do not turn a dishonest approved provider into a verified data
source, or prevent the parent from withholding data.

Separate federation members may have different approved policies and different
signer identities while sharing one image. Replicas of the same identity need
matching public endpoints. For an existing mint identity, changing the public
digest requires a controlled KMS context migration. Burn has no automatic
cross-policy clone migration. Do not remove address or clone-policy checks to
move an identity.

## Upgrade existing no-SPV deployments

This release changes the no-SPV policy encoding and KMS context. Use a verifier
from the same release. Old verifiers reject the new policy kind; the SPV
Production encoding and its four-field KMS context are unchanged.

An old no-SPV mint ciphertext cannot be decrypted using the new five-field
context. Follow the controlled migration in
[KMS persistence](kms-persistence.md#change-the-context-of-an-existing-no-spv-seed).
Do not initialize a replacement seed for a funded identity. Burn cloning still
requires matching image measurements and policy; this change does not add a
way to move a burn seed across different EIFs.
