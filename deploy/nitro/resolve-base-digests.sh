#!/usr/bin/env bash
# Resolve the current manifest-list digest for each base image the Nitro enclave
# Dockerfile pins, so a maintainer bumping a tag can update the `FROM …@sha256:`
# pins deterministically. Pinning by digest is what makes PCR0 reproducible: the
# same source then always yields the same enclave measurement.
#
# Usage: deploy/nitro/resolve-base-digests.sh
# After running, paste the printed digests into deploy/nitro/Dockerfile, rebuild
# the EIF, and re-capture + re-pin the measurement.
set -euo pipefail

# Bases pinned by the Dockerfile (keep in sync with the FROM lines).
BASES=(
  "golang:1.25.12"
  "alpine:3.20"
)

resolve() {
  local ref="$1" repo="${1%%:*}" tag="${1##*:}" token
  token=$(curl -fsSL "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/${repo}:pull" \
    | sed -E 's/.*"token":"([^"]+)".*/\1/')
  curl -fsSLI \
    -H "Authorization: Bearer ${token}" \
    -H "Accept: application/vnd.oci.image.index.v1+json" \
    -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
    "https://registry-1.docker.io/v2/library/${repo}/manifests/${tag}" \
    | tr -d '\r' \
    | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}'
}

for ref in "${BASES[@]}"; do
  digest="$(resolve "$ref")"
  if [ -z "$digest" ]; then
    echo "ERROR: could not resolve $ref" >&2
    exit 1
  fi
  printf 'FROM %s@%s\n' "$ref" "$digest"
done
