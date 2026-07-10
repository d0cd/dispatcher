# Confidential Space execution model

**Status:** design + phased build. The verifier is done and golden-validated
(`docs/confidential-attestation-plan.md`); this doc is how a `dispatcher run`
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
 │  3. pull the attestation token, VERIFY (verifyCSToken)                   │
 │  4. seal source/secrets to the attested channel key (HPKE, seal.go)      │
 │  5. pull results, tear down                                              │
 └──────────────────────────────────────────────────────────────────────────┘
                    │ untrusted TCP (VM public IP) / Cloud Logging
 ┌─ dispatcher-attest (in-TEE agent — MEASURED, its digest is the identity) ┐
 │  a. Kpub,Kpriv ← fresh X25519 keypair (Kpriv never leaves the TEE)       │
 │  b. token ← teeserver socket, nonces = [runNonce, SHA256(Kpub)]         │
 │  c. publish (token, Kpub) where dispatcher can read                     │
 │  d. receive sealed payload → open with Kpriv → stage source/secrets     │
 │  e. exec the workload; publish exit code + results                      │
 └──────────────────────────────────────────────────────────────────────────┘
```

The channel between them is **untrusted** — exactly like the raw SSH channel was.
What makes it safe is unchanged from the raw path: verify the attestation
*before* shipping anything, and *seal* everything to a key bound inside that
attestation.

## The keystone: binding the channel key on the vendor path

On raw SEV-SNP the report's `REPORT_DATA = SHA-512(nonce ‖ Kpub)` binds the
sealing key into the hardware evidence. A Confidential Space token has no
`REPORT_DATA` — the only caller-controlled field is `eat_nonce` (a list). So the
agent requests **two** nonces:

```
nonces = [ hex(runNonce) ,  hex(SHA-256(Kpub)) ]
```

and the verifier enforces both: `runNonce` present → freshness/anti-replay;
`SHA-256(Kpub)` present (for the `Kpub` the agent also handed over) → the sealing
key is committed to *this* attested container, so a relay host can't substitute
its own key and read the sealed secrets. This is the CS analog of the SNP
`REPORT_DATA` binding and the precondition for sealing (R9) on this path.

The binding is **conditional**: enforced only when a channel key is in play
(sealed path). The verify-only path (no secrets) passes a nil channel key and
checks the run nonce alone — which is what the golden capture validated.

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
`dispatcher-attest`: attest over the untrusted `:8443` endpoint → verify the
Google-signed token (live JWKS + nonce + **channel-key binding** + image digest)
→ HPKE-seal `.env` to the attested key → run inside the TEE → open the sealed
result. The sealed secret reached the workload inside the TEE and its output came
back sealed (`TestGolden_CSLiveExchange`, gated on `DISPATCHER_CS_LIVE_ENDPOINT`).

Hard-won provisioning facts (all validated live):

- **`--scopes=cloud-platform` is required.** Without it the container-launcher's
  verifier client fails (`insufficient authentication scopes`,
  `confidentialcomputing.googleapis.com`) and the **workload never runs** — the VM
  boots, reports "Workload completed", and shuts down. This is the single
  non-obvious blocker.
- Inbound TCP to the container **works** with a firewall rule — CS honours the
  image's `EXPOSE 8443` (`Exposed Ports: 8443/tcp` in the launcher log). The
  golden capture used outbound/logs; the sealed path needs this inbound port.
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
- Token pull (MVP): `tee-container-log-redirect=true` streams the agent's stdout
  (the token) to Cloud Logging; dispatcher reads it with `gcloud logging read`.
  The two-way path (sealed-secret delivery, results) needs the agent's TCP
  endpoint on the VM's public IP.

## What's built vs. remaining

| Piece | State |
|---|---|
| CS token verifier (`verifyCSToken`) | ✅ built, golden-validated |
| `csAttester` framework wiring | ✅ built |
| HPKE seal-to-channel-key (`seal.go`) | ✅ built |
| teeserver socket client (agent's token fetch) | ✅ built (`teeserver.go`) |
| channel-key binding (SHA-256(Kpub) in eat_nonce) | ✅ built (`confidential_space.go`) |
| sealed exchange protocol (attest → seal payload → sealed result) | ✅ built (`confidential_exchange.go`), unit-tested end-to-end via `httptest` |
| `dispatcher-attest` agent (measured entrypoint + exec runner) | ✅ built (`agent.go`, `agent_runner.go`, `cmd/dispatcher-attest`) |
| `ConfidentialSpaceAdapter` (dispatcher-side orchestration) | ✅ built (`confidential_space_adapter.go`) |
| image build/push + provisioning argv + agent-port firewall | ✅ built (`confidential_image.go`, `confidential_space_provision.go`) |
| run-selection wiring (route confidential GCP → CS adapter) | ✅ built (`internal/cli/confidential.go`) |
| **live attested `dispatcher run` end-to-end** | ✅ **validated** (`TestGolden_CSLiveAdapter`, real SEV VM, image build→attest→seal→run→result→teardown) |

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

## Build phasing

- **Phase 1 (done):** the teeserver client and the channel-key binding — the
  cores that turn `csFetch` from a stub into something real and make sealing safe.
- **Phase 2a (done):** the `dispatcher-attest` agent (teeserver client + seal +
  the SHA-256(Kpub) nonce + exec runner) and the sealed exchange protocol
  (`csEndpointFetch`, `runSealedExchange`), unit-tested end-to-end via `httptest`.
- **Phase 2b (done):** the `ConfidentialSpaceAdapter` — build+push the agent
  image, provision the CS VM pinned to its digest with the agent-port firewall,
  verify over the endpoint, seal source/`.env`, run the exchange, retrieve
  results, tear down (VM + firewall).
- **Phase 3 (done):** run-selection routes confidential GCP runs to the container
  path; validated end-to-end on real SEV hardware (`TestGolden_CSLiveAdapter`).
