# Measured confidential images: the build → capture → pin → run pipeline

Every cloud measures the agent differently — GCP's container digest, AWS Nitro's
PCR0, Azure's PCR11 — but the **lifecycle is identical**, and dispatcher shares it:

```
build (per-cloud) ──▶ capture (measurement) ──▶ pin (registry) ──▶ run (adapter reads the pin)
```

Measurements are **content-addressed**: any change to the image, kernel, or agent
changes the measurement, so you **re-capture and re-pin on every rebuild**. The pin
registry (`internal/confidential`, YAML in the state dir) is the single source of
truth; the adapters read it (falling back to `DISPATCHER_*` env vars).

## Commands

```
dispatcher confidential pins                      # list current pins
dispatcher confidential pin <target> --image … --measurement …
dispatcher confidential capture <target> <source> [--pin]
dispatcher confidential build <target>            # build + capture + pin (Nitro; guidance for the rest)
dispatcher confidential check                     # fail if a pin drifted from the source (CI guard)
```

`<target>` is `gcp` | `aws-nitro` | `azure-snp`.

`build` wraps the whole build → capture → pin for **AWS Nitro** (a single-host
build); GCP has no pre-build (the per-run workload container is measured at run
time) and Azure is a multi-host build (mkosi → VHD → gallery), so `build` prints
the exact next step for those.

## Per cloud

### GCP (Confidential Space — container digest)

The digest **is** the measurement. Build + push the measured agent image (digest-
pinned), then:

```
dispatcher confidential capture gcp <ref>@sha256:<digest> --pin
dispatcher run .        # confidential GCP run
```

### AWS Nitro (enclave PCR0)

On a Nitro instance, one command builds the EIF, captures PCR0, and pins it:

```
dispatcher confidential build aws-nitro --repo-root . --proxy dispatcher-nitro-proxy
dispatcher run .        # workload with confidential.type: nitro
```

Or capture from an already-built EIF's `nitro-cli describe-eif` JSON:

```
dispatcher confidential capture aws-nitro describe-eif.json \
    --eif dispatcher-attest-nitro.eif --proxy dispatcher-nitro-proxy --pin
```

### Azure (measured CVM — PCR11 via dm-verity)

Build the measured image (`deploy/azure-uki/mkosi/`, VHD → gallery image), boot a
CVM from it, then capture PCR11 from the running agent and pin the gallery image:

```
dispatcher confidential capture azure-snp http://<cvm-ip>:8443 \
    --image /subscriptions/…/versions/1.0.0 --pin
dispatcher run .        # workload with confidential.type: azure-snp
```

## Durability: the CI drift guard

Because measurements are content-addressed, a routine change to the attestation
agent, its build config, or its dependencies changes the measurement — and silently
invalidates any pin captured from the old inputs. `dispatcher confidential check`
catches this: each pin records a hash of its measurement inputs at capture
(`internal/confidential/inputs.go` — the agent source, per-cloud build config, and
`go.mod`/`go.sum`), and `check` fails if the current tree no longer matches. CI runs
it (`.github/workflows/ci.yml`) so a bump that would break attestation reds the build
with the fix spelled out: rebuild, re-capture, re-pin.

To activate it for your images, produce the registry with `capture --pin --pins
deploy/confidential-pins.yaml` (write and check share the `--pins` path) and commit
it — that's the path CI checks. Until it exists the guard is inactive and CI says so;
once committed, `check --pins <missing>` is a hard error, so a mistyped path or a
dropped commit can't read as "verified". It does **not** build images — that needs
the per-cloud hosts; it only detects drift in the inputs it can see. External inputs
(the base image and kernel's floating package versions) aren't covered, so re-capture
periodically too.

> **Privacy:** the committed registry publishes each pin's `image` — for Azure a full
> gallery-image resource ID (`/subscriptions/<sub>/resourceGroups/<rg>/…`) and for
> Nitro a local EIF/proxy path. Those reveal your subscription/resource-group/build
> layout, so treat the committed pins file as internal — fine for a private repo, not
> for a public one.

## What's shared vs per-cloud

- **Shared** (`internal/confidential`): the pin registry, the capture parsers, the
  `dispatcher confidential` command, and the run-path resolution.
- **Per-cloud** (irreducible): the *build* — `docker build` / `nitro-cli
  build-enclave` / `mkosi`, each running on its own build host with its own tooling.
