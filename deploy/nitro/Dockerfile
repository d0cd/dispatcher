# Enclave image for AWS Nitro Enclaves confidential runs. `nitro-cli build-enclave`
# converts this image into an EIF whose PCR0/1/2 (hashes of the whole image /
# kernel+bootstrap / application) are the attested measurement — so the agent is
# measured, unlike the scp'd SEV-SNP path. Build context is the repo root.
#
# The enclave has no network and no persistent disk (tmpfs root only), so the
# workload it runs must be self-contained (no pip/apt at run time). Bake any
# runtime the workload needs into this image.
#
# REPRODUCIBILITY: PCR0 is a content hash of this whole image, so any base-image
# or package change silently changes PCR0. The bases are pinned by digest below so
# the same source always produces the same PCR0 even if an upstream tag is
# re-pushed. Re-resolve with `deploy/nitro/resolve-base-digests.sh` when bumping a
# tag, then re-capture + re-pin the measurement. RESIDUAL FLOAT: the
# `apk add ca-certificates` still pulls the current package version from the
# alpine repo; pin it (ca-certificates=<ver>) for bit-for-bit reproducibility.
FROM golang:1.25.12@sha256:d2e20dc1b35aefd666909163e4ace41efb521359aa2ce31fff59d86837050f6f AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Pure-Go static binary (vsock/nsm need no cgo), so it runs on a minimal rootfs.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /dispatcher-attest-nitro ./cmd/dispatcher-attest-nitro

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache ca-certificates
COPY --from=build /dispatcher-attest-nitro /usr/local/bin/dispatcher-attest-nitro
# The agent listens on vsock; the parent's dispatcher-nitro-proxy bridges to it.
ENTRYPOINT ["/usr/local/bin/dispatcher-attest-nitro", "--port", "8443"]
