#!/usr/bin/env bash
#
# capture-maa.sh — run ON a freshly-booted Azure Confidential VM (DCasv5/ECasv5
# for SEV-SNP, DCesv5/ECesv5 for TDX). Captures a real Microsoft Azure
# Attestation (MAA) token + the MAA signing JWKS into fixture files.
#
# The token is produced by Azure's guest-attestation client, which reads the
# hardware quote (via the vTPM/guest) and exchanges it with an MAA instance for a
# signed JWT. Build the client on the VM:
#   https://github.com/Azure/confidential-computing-cvm-guest-attestation
#     git clone https://github.com/Azure/confidential-computing-cvm-guest-attestation
#     # follow its README to build the AttestationClient sample for Linux,
#     # then run it to emit a JWT (it prints / writes the token).
#
# This script fetches the JWKS (stable, documented endpoint) and expects you to
# drop the token into $OUT/token.jwt. The MAA endpoint must be the SAME instance
# the client attested against, or the JWKS won't contain the signing key.
set -euo pipefail

OUT=${1:-./maa-out}
# The MAA instance the guest-attestation client used. The regional shared
# endpoints are the default for the stock client; override for a custom MAA.
MAA_ENDPOINT=${MAA_ENDPOINT:-https://sharedeus.eus.attest.azure.net}

mkdir -p "$OUT"

# 1. MAA signing keys (JWKS). verifyMAAToken matches the token's `kid` here.
curl -fsSL "$MAA_ENDPOINT/certs" -o "$OUT/jwks.json"
echo "fetched JWKS from $MAA_ENDPOINT/certs"

# 2. The token. If you've already produced it with the guest-attestation client,
#    point TOKEN_FILE at it; otherwise drop it at $OUT/token.jwt yourself.
if [[ -n "${TOKEN_FILE:-}" && -f "${TOKEN_FILE}" ]]; then
  cp "$TOKEN_FILE" "$OUT/token.jwt"
  echo "copied token from $TOKEN_FILE"
elif [[ -f "$OUT/token.jwt" ]]; then
  echo "using existing $OUT/token.jwt"
else
  cat >&2 <<EOF
No token yet. Build & run the Azure guest-attestation client (see header), then:
  TOKEN_FILE=<path-to-jwt> $0 $OUT
or place the JWT at $OUT/token.jwt and re-run.
EOF
  exit 1
fi

echo
echo "captured into $OUT:"
ls -1 "$OUT"
echo "Expected by the golden test: token.jwt jwks.json"
