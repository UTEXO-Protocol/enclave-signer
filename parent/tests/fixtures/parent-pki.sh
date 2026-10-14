#!/usr/bin/env bash
# Ephemeral test-only certificates. Requires openssl; no keys are checked in.
set -euo pipefail
cd "${1:?temporary directory required}"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -subj /CN=test-ca -days 2 >/dev/null 2>&1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout foreign-ca.key -out foreign-ca.pem -subj /CN=foreign-ca -days 2 >/dev/null 2>&1
for name in server operator listener observer unknown expired foreign rotated; do
  ca=ca
  days=1
  [ "$name" != foreign ] || ca=foreign-ca
  [ "$name" != expired ] || days=-1
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$name.key" -out "$name.csr" -subj "/CN=$name" >/dev/null 2>&1
  if [ "$name" = server ]; then
    printf 'subjectAltName=DNS:parent.test\nextendedKeyUsage=serverAuth\n' > "$name.ext"
  else
    printf 'extendedKeyUsage=clientAuth\n' > "$name.ext"
  fi
  openssl x509 -req -in "$name.csr" -CA "$ca.pem" -CAkey "$ca.key" -CAcreateserial -out "$name.pem" -days "$days" -extfile "$name.ext" >/dev/null 2>&1
  openssl x509 -in "$name.pem" -outform DER -out "$name.der"
done
