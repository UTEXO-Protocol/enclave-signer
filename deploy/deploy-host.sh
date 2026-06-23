#!/usr/bin/env bash
# Deploy the enclave-signer cluster on THIS host from S3 by git_sha.
#
# Pulls the matching {EIF, parent, cli} set (published by the build-eif CI
# workflow under eif/<git_sha>/), verifies checksums and PCRs, tears down any
# running enclaves, then runs 3 enclaves (CID 16/18/20) + 3 parents
# (gRPC 50051/52/53). Artifact-only: the host never builds or clones the repo.
#
# It does NOT bootstrap identity. A fresh enclave has no key; after this script
# run `utexo-bridge-parent-cli init --cloning-secret ...` on a donor, or
# `... clone ...` on a requester. (Identity lives in enclave memory and is lost
# on restart — see TODO #5 for KMS-sealed DR.)
#
# Usage (run as root, e.g. via SSM):
#   GIT_SHA=<40-hex> BUCKET=<s3-bucket> AWS_REGION=<region> bash deploy-host.sh
# No infra identifiers are baked in (public repo) — pass them via env.
set -euo pipefail

GIT_SHA="${GIT_SHA:?GIT_SHA required (40-hex commit)}"
BUCKET="${BUCKET:?BUCKET required (S3 artifact bucket)}"
REGION="${AWS_REGION:?AWS_REGION required (e.g. eu-central-1)}"
DIR="${CLUSTER_DIR:-/home/ubuntu/clone-stage}"
EIF="$DIR/utexo-bridge-enclave-clone-stage.eif"
SRC="s3://$BUCKET/eif/$GIT_SHA"
CIDS=(16 18 20)
declare -A PORT=([16]=50051 [18]=50052 [20]=50053)

log(){ echo "[deploy $(date -u +%H:%M:%S)] $*"; }
asubuntu(){ su - ubuntu -c "$1"; }

# --- 0. perm guard (until #7 makes this persistent via udev/systemd) -------
getent group ne >/dev/null || groupadd -g 986 ne
id -nG ubuntu | grep -qw ne || usermod -aG ne ubuntu
mkdir -p /run/nitro_enclaves && chown root:ne /run/nitro_enclaves && chmod 0770 /run/nitro_enclaves
chgrp ne /dev/nitro_enclaves 2>/dev/null || true
chmod 0660 /dev/nitro_enclaves 2>/dev/null || true
mkdir -p "$DIR"

# --- 1. fetch artifacts ----------------------------------------------------
log "pulling artifacts from $SRC"
asubuntu "aws s3 cp $SRC/utexo-bridge-enclave.eif $EIF                 --region $REGION --no-progress"
asubuntu "aws s3 cp $SRC/PCR.json                 $DIR/PCR.json         --region $REGION --no-progress"
asubuntu "aws s3 cp $SRC/SHA256SUMS               $DIR/SHA256SUMS.eif   --region $REGION --no-progress"
asubuntu "aws s3 cp $SRC/utexo-bridge-parent      $DIR/utexo-bridge-parent     --region $REGION --no-progress"
asubuntu "aws s3 cp $SRC/utexo-bridge-parent-cli  $DIR/utexo-bridge-parent-cli --region $REGION --no-progress"
asubuntu "aws s3 cp $SRC/HOST-SHA256SUMS          $DIR/HOST-SHA256SUMS  --region $REGION --no-progress"
chmod +x "$DIR/utexo-bridge-parent" "$DIR/utexo-bridge-parent-cli"
chown ubuntu:ubuntu "$DIR/utexo-bridge-parent" "$DIR/utexo-bridge-parent-cli"

# --- 2. verify checksums ---------------------------------------------------
EXP=$(awk '{print $1}' "$DIR/SHA256SUMS.eif")
ACT=$(sha256sum "$EIF" | awk '{print $1}')
[ "$EXP" = "$ACT" ] || { log "EIF sha mismatch ($ACT != $EXP)"; exit 1; }
( cd "$DIR" && sha256sum -c HOST-SHA256SUMS ) || { log "host binary sha mismatch"; exit 1; }
log "checksums OK"

# --- 3. pre-flight PCR (static EIF measurement vs manifest) ----------------
EIF_PCR=$(asubuntu "nitro-cli describe-eif --eif-path $EIF" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["Measurements"]["PCR0"])')
MAN_PCR=$(python3 -c 'import json;print(json.load(open("'"$DIR"'/PCR.json"))["PCR0"])')
[ "$EIF_PCR" = "$MAN_PCR" ] || { log "PCR0 manifest mismatch ($EIF_PCR != $MAN_PCR)"; exit 1; }
log "PCR0 (manifest) = $MAN_PCR"

# --- 4. teardown (clears the E39 / 'CPU pool busy' wedge) -------------------
pkill -f utexo-bridge-parent 2>/dev/null || true
sleep 2
asubuntu 'nitro-cli terminate-enclave --all' 2>/dev/null || true
pkill -f 'nitro-cli run-enclave' 2>/dev/null || true
sleep 3

# --- 5. run enclaves -------------------------------------------------------
for CID in "${CIDS[@]}"; do
  asubuntu "nitro-cli run-enclave --eif-path $EIF --cpu-count 2 --memory 3072 --enclave-cid $CID --enclave-name clone-stage-$CID" >/dev/null
  sleep 2
done

# --- 6. verify runtime PCR matches the manifest ----------------------------
asubuntu 'nitro-cli describe-enclaves' > /tmp/desc.json
python3 - "$MAN_PCR" <<'PY'
import json, sys
man = sys.argv[1]
d = json.load(open("/tmp/desc.json"))
bad = [e["EnclaveCID"] for e in d if e.get("Measurements", {}).get("PCR0") != man]
print("running CIDs:", sorted(e["EnclaveCID"] for e in d))
if bad:
    sys.exit(f"runtime PCR0 mismatch on CID {bad}")
print("runtime PCR0 == manifest on all enclaves")
PY

# --- 7. start parents ------------------------------------------------------
for CID in "${CIDS[@]}"; do
  P=${PORT[$CID]}
  asubuntu "cd $DIR && GRPC_HOST=0.0.0.0 GRPC_PORT=$P USE_VSOCK=true ENCLAVE_VSOCK_CID=$CID ENCLAVE_VSOCK_PORT=5000 setsid -f ./utexo-bridge-parent >> $DIR/parent_$P.log 2>&1"
done
sleep 4
ss -ltnp | grep -E '5005[123]' || { log "parents not listening"; exit 1; }

log "deploy OK (git_sha $GIT_SHA) — run init/clone to bootstrap identity"
