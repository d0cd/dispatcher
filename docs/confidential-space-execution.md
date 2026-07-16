# Confidential Space execution model

**Status:** built + live-validated end-to-end (hardware-validated `dispatcher run`; see the "What's built" table below). The verifier is specified in
[`confidential-computing.md`](confidential-computing.md); this doc is how a `dispatcher run`
actually *executes* on GCP Confidential Space, which is a distinct execution
path from the SSH-into-a-VM model every current adapter uses.

## Why it can't reuse the SSH-VM path

`CloudVMAdapter` is SSH-shaped end to end: create VM → SSH in → `rsync` source →
`nohup` the command → poll a PID over SSH → `tail -f` the log over SSH →
`rsync` artifacts back. **Confidential Space has none of that.** The workload
*is* a measured container image the CS runtime launches at boot; there is no SSH,
no shell, no rsync, no PID to poll. The attested identity is the **container
image digest**, not a VM launch measurement. So a confidential GCP run is a
different adapter, not a flag on the existing one.

## Topology

Two cooperating pieces of code, on opposite sides of the trust boundary:

```
 ┌─ dispatcher (client, user's machine — UNTRUSTED by the TEE) ─────────────┐
 │  1. package workload → OCI image, push to Artifact Registry              │
 │  2. provision CS VM pinned to image digest (tee-image-reference)         │
 │  3. dial the agent over attested TLS; VERIFY the token (verifyCSToken)   │
 │  4. deliver source/secrets over the attested session                    │
 │  5. receive results, tear down                                          │
 └──────────────────────────────────────────────────────────────────────────┘
                    │ attested TLS 1.3 over untrusted TCP (VM public IP)
 ┌─ dispatcher-attest (in-TEE agent — MEASURED, its digest is the identity) ┐
 │  a. serve TLS 1.3 with a fresh ephemeral cert (key never leaves the TEE) │
 │  b. bindData ← SHA-256(cert SPKI ‖ RFC 5705 exporter)                    │
 │  c. token ← teeserver socket, nonces = [runNonce, SHA-256(bindData)]    │
 │  d. deliver token as the session evidence; on verify, receive payload   │
 │     over the session → stage source/secrets                             │
 │  e. exec the workload; return exit code + results over the session      │
 └──────────────────────────────────────────────────────────────────────────┘
```

The channel between them is **untrusted** — exactly like the raw SSH channel was.
dispatcher dials with `InsecureSkipVerify` (trust is the attestation, not PKI).
What makes it safe is unchanged in spirit from the raw path: verify the
attestation *before* shipping anything, and bind that attestation to *this* TLS
session, so a relay/MITM can't sit between dispatcher and the measured agent.

## The keystone: binding the session on the vendor path

On raw SEV-SNP the report's `REPORT_DATA = SHA-512(nonce ‖ bindData)` binds the
session into the hardware evidence. A Confidential Space token has no
`REPORT_DATA` — the only caller-controlled field is `eat_nonce` (a list). So the
agent requests **two** nonces:

```
nonces = [ hex(runNonce) ,  hex(SHA-256(bindData)) ]
```

where `bindData = SHA-256(agent-cert-SPKI ‖ exporter)` and `exporter` is the
RFC 5705 keying material both sides derive from the completed TLS handshake
(label `dispatcher/confidential/atls/v1`). The verifier enforces both: `runNonce`
present → freshness/anti-replay; `SHA-256(bindData)` present → the token was
minted for *this* attested container inside *this* TLS session, so a relay or
on-path host can't reuse a genuine token against a session it doesn't control.
This is the CS analog of the SNP `REPORT_DATA` binding.

The binding is **conditional**: enforced only when `bindData` is in play (the run
path). The verify-only capture path passes a nil bind value and checks the run
nonce alone.

## Packaging (image build)

The workload becomes an OCI image carrying `dispatcher-attest` as the entrypoint
and the workload command as its payload — the container analog of the runner
script the SSH path streams over stdin. MVP: a pinned base image + the agent +
the workload source baked in (`base-wrap`), built locally (`docker`/`buildah`)
and pushed to Artifact Registry. BYO-Dockerfile is a later mode. The pushed
image **digest** is what gets pinned at provision and what the token attests —
so build+push must report the digest, and dispatcher allowlists exactly it.

## Live-validated (real SEV hardware)

The full loop was proven end-to-end against a live Confidential Space VM running
`dispatcher-attest`: dial the agent's `:8443` over attested TLS → verify the
Google-signed token (live JWKS + run nonce + **session binding** + image digest)
→ deliver `.env`/source over the session → run inside the TEE → results returned
over the same session, then tear down (`TestGolden_CSLiveAdapter`, gated on
`DISPATCHER_CS_LIVE_BUILD`).

Hard-won provisioning facts (all validated live):

- **`--scopes=cloud-platform` is required.** Without it the container-launcher's
  verifier client fails (`insufficient authentication scopes`,
  `confidentialcomputing.googleapis.com`) and the **workload never runs** — the VM
  boots, reports "Workload completed", and shuts down. This is the single
  non-obvious blocker.
- Inbound TCP to the container **works** with a firewall rule — CS honours the
  image's `EXPOSE 8443` (`Exposed Ports: 8443/tcp` in the launcher log). The
  aTLS session needs this inbound port.
- The attested `submods.container.image_digest` equals the **Artifact Registry
  image digest** we build and pin, so the allowlist is exactly that digest.
- Required create flags: `--confidential-compute-type=SEV --shielded-secure-boot
  --maintenance-policy=TERMINATE` + `--image-family=confidential-space
  --image-project=confidential-space-images`, metadata `tee-image-reference=<ref>,
  tee-container-log-redirect=true, tee-restart-policy=Never`, and a firewall for
  the agent port scoped to dispatcher's egress IP.
- n2d SEV capacity is regional and flaky — shop zones on create.

## Provisioning + retrieval (argv, over the `runCLI` seam)

- Provision: `gcloud compute instances create … --confidential-compute-type=SEV
  --shielded-secure-boot --image-family=confidential-space
  --image-project=confidential-space-images --metadata
  tee-image-reference=<digest>,tee-container-log-redirect=true,tee-restart-policy=Never
  …` plus the per-run nonce delivered via a `tee-env-*`/arg the manifest opts
  into (`tee.launch_policy.allow_env_override`, discovered live).
- The run's two-way path (payload delivery, results) rides the agent's TCP
  endpoint on the VM's public IP over attested TLS; `tee-container-log-redirect=true`
  streams the agent's stdout to Cloud Logging for diagnostics.

## What's built vs. remaining

| Piece | State |
|---|---|
| CS token verifier (`verifyCSToken`) | ✅ built, golden-validated |
| `CSValidator` (aTLS binding + minTCB fail-closed) | ✅ built (`atls_validators.go`) |
| attested-TLS transport (`internal/attest/atls`) | ✅ built, unit-tested end-to-end |
| teeserver socket client (agent's token fetch) | ✅ built (`teeserver.go`) |
| session binding (SHA-256(bindData) in eat_nonce) | ✅ built (`confidential_space.go`) |
| `dispatcher-attest` agent (measured entrypoint + aTLS + exec runner) | ✅ built (`agent.go`, `runner.go`, `cmd/dispatcher-attest`) |
| `ConfidentialSpaceAdapter` (dispatcher-side orchestration) | ✅ built (`confidential_space_adapter.go`) |
| image build/push + provisioning argv + agent-port firewall | ✅ built (`confidential_image.go`, `confidential_space_provision.go`) |
| run-selection wiring (route confidential GCP → CS adapter) | ✅ built (`internal/cli/confidential.go`) |
| **live attested `dispatcher run` end-to-end** | ✅ **validated** (`TestGolden_CSLiveAdapter`, real SEV VM, image build→attest→run→result→teardown) |

## Operating a confidential GCP run

`dispatcher run` on a workload with `confidential.required: true` (and attestation
not `off`) on GCP automatically takes the container path. Configure via env:

- `DISPATCHER_GCP_PROJECT` (or the active `gcloud` project) and
  `DISPATCHER_GCP_ZONE` (pick one with n2d SEV capacity).
- The measured agent image, one of:
  - `DISPATCHER_CS_AGENT_IMAGE=<ref>@sha256:<digest>` — a prebuilt, digest-pinned
    image (skips the build); or
  - `DISPATCHER_CS_REPO_ROOT=<dispatcher source>` (+ optional
    `DISPATCHER_CS_REGISTRY`, default `us-east1-docker.pkg.dev`) to build+push it.

Unconfigured, the run fails closed with guidance rather than provisioning
something unverifiable. `attestation: off` stays on the SSH path (TEE without
verification) — the explicit escape hatch.

## How it got here

The transport was originally an HTTP sealed exchange: the agent handed dispatcher
an X25519 channel key over `/attest`, dispatcher HPKE-sealed the payload to it and
`POST`ed `/payload`, then polled `/result` for a sealed result. That was replaced
by the attested TLS session above — the token now binds the TLS session's
`bindData` instead of a handed-out channel key, which defeats relay/MITM and drops
the HPKE machinery entirely. All three measured backends (this one, AWS Nitro,
Azure SNP+vTPM) share the same aTLS transport, each live-validated on real
hardware.
