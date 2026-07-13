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
# or package change silently changes PCR0. For a stable, verifiable PCR0, pin the
# bases by digest (FROM golang:1.25.0@sha256:… / alpine:3.20.3@sha256:…) and the
# ca-certificates version, and record the expected PCR0 next to the pin. The
# tags below are pinned to the go.mod toolchain version but not yet by digest.
FROM golang:1.25.0 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Pure-Go static binary (vsock/nsm need no cgo), so it runs on a minimal rootfs.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /dispatcher-attest-nitro ./cmd/dispatcher-attest-nitro

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /dispatcher-attest-nitro /usr/local/bin/dispatcher-attest-nitro
# The agent listens on vsock; the parent's dispatcher-nitro-proxy bridges to it.
ENTRYPOINT ["/usr/local/bin/dispatcher-attest-nitro", "--port", "8443"]
