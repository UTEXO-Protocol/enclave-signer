#!/usr/bin/env bash
# Verify a published burn-signer attestation bundle offline. Then check that
# its attested EVM address is an enclave signer of the MultisigProxy on
# Arbitrum One. See docs/verify-a-signer.md.
#
# Usage:
#   PCR_FILE=PCR.json ARB_RPC_URL=<Arbitrum One RPC> MULTISIG_PROXY=0x... \
#   [ATTEST_VERIFY=attest-verify] \
#   bash build/verify-signer.sh <bundle file or https URL> [attest-verify --expect-* flags]
#
# The script sets --expect-chain-id 42161 and --expect-bridge-contract
# $MULTISIG_PROXY itself, so the attestation and the on-chain list refer to
# the same contract.
#
# Exit: 0 = the bundle verifies and the address is a signer.
#       1 = a check failed.
#       2 = usage error.
set -uo pipefail

EVM_CHAIN_ID=42161
# The bridge's id for the RGB network.
SOURCE_CHAIN_ID=827166

usage() { echo "verify-signer: $*" >&2; exit 2; }
fail() { echo "FAIL: $*" >&2; exit 1; }

[ $# -ge 1 ] || usage "a bundle file or URL is required"
src="$1"; shift
[ -n "${PCR_FILE:-}" ] || usage "PCR_FILE required (the trusted PCR.json)"
[ -n "${ARB_RPC_URL:-}" ] || usage "ARB_RPC_URL required (an Arbitrum One RPC)"
[ -n "${MULTISIG_PROXY:-}" ] || usage "MULTISIG_PROXY required (the MultisigProxy address)"
ATTEST_VERIFY="${ATTEST_VERIFY:-attest-verify}"
for a in "$@"; do
  case "$a" in
    --expect-chain-id*|--expect-bridge-contract*|--endpoint*|--from-file*)
      usage "$a is set by this script";;
  esac
done

pcr() {
  grep -oE "\"$1\"[[:space:]]*:[[:space:]]*\"[0-9a-fA-F]{96}\"" "$PCR_FILE" | grep -oE '[0-9a-fA-F]{96}'
}
pcr0="$(pcr PCR0)" && pcr1="$(pcr PCR1)" && pcr2="$(pcr PCR2)" \
  || usage "$PCR_FILE has no PCR0, PCR1 and PCR2"

rpc_chain="$(cast chain-id --rpc-url "$ARB_RPC_URL")" || fail "cast chain-id failed"
[ "$rpc_chain" = "$EVM_CHAIN_ID" ] || fail "RPC chain id $rpc_chain is not $EVM_CHAIN_ID"

bundle="$src"
case "$src" in
  https://*)
    bundle="$(mktemp)"
    trap 'rm -f "$bundle"' EXIT
    curl -fsSL "$src" -o "$bundle" || fail "cannot download $src";;
esac

out="$("$ATTEST_VERIFY" --from-file "$bundle" --pcr0 "$pcr0" --pcr1 "$pcr1" --pcr2 "$pcr2" \
  --expect-chain-id "$EVM_CHAIN_ID" --expect-bridge-contract "$MULTISIG_PROXY" "$@")" \
  || fail "attest-verify rejected the bundle"
printf '%s\n' "$out"
# The address comes from the verified output, not from the file.
addr="$(printf '%s\n' "$out" | sed -n 's/^ *EVM address *: *\(0x[0-9a-fA-F]\{40\}\)$/\1/p')"
[ -n "$addr" ] || fail "attest-verify printed no EVM address"

signers="$(cast call "$MULTISIG_PROXY" "getEnclaveSigners(uint256)(address[])" "$SOURCE_CHAIN_ID" \
  --rpc-url "$ARB_RPC_URL")" || fail "getEnclaveSigners call failed"
printf '%s\n' "$signers" | grep -oiE '0x[0-9a-f]{40}' | grep -qix "$addr" \
  || fail "$addr is not in getEnclaveSigners($SOURCE_CHAIN_ID) of $MULTISIG_PROXY"
echo "OK: $addr is attested and is an enclave signer of $MULTISIG_PROXY"
