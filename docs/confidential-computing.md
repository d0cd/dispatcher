# Spec: Confidential computing (secure jobs)

**Status:** Implemented end-to-end on all three clouds — provisioning + verifier cores + pinned ARK/AWS roots + the in-TEE measured agent and live evidence fetch. The raw SEV-SNP report parser is golden-validated against a report captured on GCP hardware (GCP's own run path uses Confidential Space). Residual: on the standard AWS SEV-SNP / Azure MAA paths the scp'd agent isn't in the launch measurement (the measured `profile` backends and GCP Confidential Space close it). Cert revocation is enforced on the AMD-cert-chain paths (AWS, Azure `profile: azure-snp`) via the AMD KDS CRL, and the MAA path enforces `minTCB` by recombining the token's per-component SVN claims.
**Related:** [ROADMAP](ROADMAP.md) → "Confidential computing (secure jobs)".

Run a workload on a TEE-backed VM (hardware-encrypted memory) so the cloud
provider can't read its data *in use* — **and prove it** via attestation before
the workload (or any secret) ever reaches the VM. This spec is deliberately
strict: a confidential run that can't meet every requirement **fails closed**,
because a *partial* confidential guarantee is a false one.

Reader's map: §1 threat model · §2 **security guarantees** · §3 **the protocol** ·
§4 requirements/hygiene · §5 **operational protocol** · §6 status & gaps ·
§7 build plan · §8 decisions.

---

## 1. Threat model

**Protected:** the workload's data and code *in use* (memory) and the integrity of
its execution environment.

**Adversary:** the cloud provider and anyone with host/hypervisor access — a
malicious/compromised operator, an escaping co-tenant, a host-level attacker. They
can read/modify host memory, the hypervisor, the network, and unencrypted disk;
intercept the cloud API and the SSH connection; and boot a VM of their choosing to
impersonate a TEE.

**Trusted computing base:**
- TEE hardware + firmware and the silicon vendor root of trust (AMD ARK/ASK; Intel/
  Azure roots).
- The **measured** guest image (a pinned vendor confidential image whose launch
  measurement is on an allowlist).
- The user's `dispatcher` CLI and the machine it runs on (the operator).

**Out of scope:** side-channel/microarchitectural attacks; a malicious workload
exfiltrating its own data; physical attacks; bugs in the TEE itself.

**Core consequence:** dispatcher runs *outside* the TEE, so the VM is **untrusted
until attestation proves otherwise**. No secret (workload source, `.env`,
credentials) is sent before that proof, and only over a channel cryptographically
bound to the attested TEE.

---

## 2. Security guarantees

When a confidential run **completes successfully** (attestation verified),
dispatcher guarantees:

- **G1 — Genuine TEE, requested type.** The workload ran on real TEE hardware of
  the requested type (SEV/SEV-SNP/TDX); its RAM was hardware-encrypted and opaque
  to the cloud host/hypervisor.
- **G2 — Known-good, safe launch.** The VM booted a measurement on the allowlist,
  with debug disabled and TCB ≥ the configured minimum — the host did not substitute
  a malicious image or a debuggable/migratable VM. Migration-disabled is verified on
  every SEV-SNP path (AWS, Azure MAA, Azure `profile: azure-snp`) and is n/a on the
  Nitro and Confidential Space paths (see the enforcement matrix).
- **G3 — Fresh and bound.** The attestation answered this run's random nonce and
  committed the in-TEE channel key — so it is not a replayed or relayed proof from
  another machine; dispatcher provably talked to *that* TEE.
- **G4 — Secret-after-proof.** No workload source, `.env`, or output crossed the
  channel before G1–G3 verified.
- **G5 — Auditable.** The verdict (verified, type, measurement, TCB, nonce) is
  recorded on the run, shown in `status --json`, and rendered in human-readable
  `status` and `diagnose` output.

**Explicit NON-guarantees** (state these plainly to users):

- **N1 — Disk at rest.** On **all three providers the OS disk is *not* host-opaque**
  today: GCP/AWS use cloud-KMS encryption, and Azure provisions `VMGuestStateOnly`
  (which encrypts only the guest-state/vTPM blob, not the OS disk — confidential
  OS-disk encryption is not yet wired). dispatcher **warns** and records this. Keep
  durable secrets in memory on every provider; don't write them to the OS disk.
- **N2 — Retrieved outputs.** Artifacts rsynced back to the operator's machine
  leave the TEE and are no longer confidential (by design).
- **N3 — Trust assumptions.** Confidentiality is *vs. the cloud*, not vs. the
  operator: dispatcher and the operator's machine are in the TCB. The hardware
  vendor's root of trust is trusted. Side-channels and a self-exfiltrating
  workload are out of scope (§1).
- **N4 — `attestation: off`.** This opt-out provisions a TEE (memory encryption)
  **without** verification — it gives N-none of G2–G5. Used only when the operator
  explicitly accepts unverified encrypted memory; dispatcher warns.

### Enforcement matrix (per backend)

The guarantees above are ragged across backends — each verifier enforces a
different subset. This table is the authoritative statement of *which control each
backend actually checks*.

<!-- BEGIN generated matrix — source of truth: internal/attest/matrix.go; do not
edit by hand. TestMatrix_DocInSync fails if this drifts from the code. -->

| Control | GCP CS | Azure MAA | Azure SNP | AWS SNP | AWS Nitro |
|---|---|---|---|---|---|
| Genuine TEE (signature + chain to pinned root) | ✓ | ✓ | ✓ | ✓ | ✓ |
| Measurement/identity on exact allowlist (empty fails closed) | ✓ | ✓ | ✓ | ✓ | ✓ |
| Per-run nonce freshness | ✓ | ✓ | ✓ | ✓ | ✓ |
| Channel-key binding (sealed only to the attested key) | ✓ | ✓ | ✓ | ✓ | ✓ |
| Debug disabled | ✓ | ✓ | ✓ | ✓ | n/a |
| Migration disabled | n/a | ✓ | ✓ | ✓ | n/a |
| Minimum TCB / firmware floor | fail-closed | ✓ | ✓ | ✓ | n/a |
| Certificate revocation | n/a | n/a | ✓ | ✓ | n/a |
| Attestation agent folded into the measured boot | ✓ | ✗ | ✓ | ✗ | ✓ |

**Roots of trust:** GCP CS = Google JWKS; Azure MAA = pinned MAA issuer + JWKS; Azure SNP = pinned AMD ARK; AWS SNP = pinned AMD ARK (go-sev-guest); AWS Nitro = pinned AWS Nitro root.

- **GCP CS — Measurement/identity on exact allowlist (empty fails closed):** the attested identity is the container image digest
- **GCP CS — Migration disabled:** the Confidential Space token exposes no migration claim
- **GCP CS — Minimum TCB / firmware floor:** the CS token carries no reported TCB, so a run that sets minTCB is rejected (GCP has no measured-TCB backend)
- **GCP CS — Certificate revocation:** delegated to the Google Confidential Space service; dispatcher validates no AMD cert chain locally
- **GCP CS — Attestation agent folded into the measured boot:** the measured container image is the workload
- **Azure MAA — Migration disabled:** verified via the x-ms-sevsnpvm-migration-allowed token claim
- **Azure MAA — Minimum TCB / firmware floor:** reconstructed from the token's per-component SEV-SNP SVN claims and compared per component
- **Azure MAA — Certificate revocation:** delegated to the Azure MAA service; dispatcher validates no AMD cert chain locally
- **Azure MAA — Attestation agent folded into the measured boot:** the standard path scp's the agent; measured only when a custom measured image + PCR pins are configured
- **Azure SNP — Measurement/identity on exact allowlist (empty fails closed):** PCR11 (the UKI carrying the agent), pinned
- **Azure SNP — Certificate revocation:** the ARK-signed CRL at the ASK's AMD KDS distribution point; a revoked VCEK/ASK is rejected, fail-closed if the CRL is missing or unreachable
- **Azure SNP — Attestation agent folded into the measured boot:** PCR11 = the UKI carrying the agent
- **AWS SNP — Certificate revocation:** ASVK CRL checked against the pinned ARK (via go-sev-guest)
- **AWS SNP — Attestation agent folded into the measured boot:** the standard path scp's the agent; it is not folded into the launch measurement (use profile: nitro)
- **AWS Nitro — Measurement/identity on exact allowlist (empty fails closed):** PCR0 (the enclave image), pinned
- **AWS Nitro — Debug disabled:** Nitro enclaves have no SEV-SNP debug/migration policy bits
- **AWS Nitro — Certificate revocation:** AWS uses ephemeral certs (leaf valid ~3h) instead of CRLs and instructs validators to disable CRL checking; short validity is the revocation mechanism, enforced by chain-validity checking
- **AWS Nitro — Attestation agent folded into the measured boot:** PCR0 = the enclave image carrying the agent

<!-- END generated matrix -->

---

## 3. The protocol

```
operator (dispatcher, outside the TEE)              cloud TEE VM (untrusted until 3.5)
─────────────────────────────────────              ──────────────────────────────────
3.1 generate per-run nonce N (random 32B)
3.2 provision confidential VM:
      - type flag (SEV / SEV-SNP / TDX)
      - PINNED vendor confidential image
        (its measurement is on the allowlist,
         and it ships the measured in-TEE
         attestation agent)
      - confidential OS-disk encryption where
        offered (else warn — N1)
      - policy: debug off, migration off
      - NO secrets in cloud-init/user-data      ── boots inside the TEE ──▶
3.3 connect over SSH (untrusted; used ONLY to
    drive the agent and fetch evidence).
3.4 challenge the measured in-TEE agent:        ──▶ agent generates an EPHEMERAL
      send N; agent binds its in-TEE key            keypair *inside* the TEE, reads the
                                                     HW report (/dev/sev-guest) or calls
                                                     MAA with
                                                     REPORT_DATA = H(N ‖ agent_pubkey)
                                                ◀── returns report/token + cert chain
                                                     + agent_pubkey
3.5 VERIFY (ALL must hold, else destroy + fail):
      a. signature chains to vendor root; TCB ≥
         minimum; certs not revoked (AMD KDS CRL on
         the AWS and Azure-SNP paths — see matrix).
      b. TEE type == requested
      c. policy: debug off; migration off (on every
         SEV-SNP path — AWS, Azure MAA, azure-snp;
         n/a on Nitro/CS — see the matrix)
      d. measurement ∈ allowlist (EXACT)
      e. REPORT_DATA == H(N ‖ agent_pubkey)
         → freshness (N) + binding (agent_pubkey)
    Record AttestationResult.
3.6 wrap workload source + .env to agent_pubkey
    (or RA-TLS to it) and run the command.        ──▶ workload runs in the TEE
3.7 retrieve outputs over the bound channel.       (leaves the TEE on arrival — N2)
3.8 teardown.

Any failure in 3.4–3.5 ⇒ destroy the VM, send nothing, fail the run.
```

**Why this is sound.** The untrusted SSH connection in 3.3–3.4 is used *only* to
fetch evidence — nothing secret is sent until 3.5e proves the channel key was
generated **inside** the genuine, freshly-challenged TEE (so a host that terminates
SSH and relays our nonce to a real TEE elsewhere cannot bind *its own* key). The
agent is part of the **measured** image (3.2), so the host can't swap it for a
relaying one. The exact-measurement allowlist (3.5d) stops the host from booting a
malicious genuinely-SEV-SNP image.

---

## 4. Requirements & hygiene checklist

| # | Requirement | Why |
|---|---|---|
| R1 | Per-run random nonce in `REPORT_DATA` | replay/relay resistance (G3) |
| R2 | `REPORT_DATA` commits an **in-TEE-generated** channel key (not a host-injectable one) | channel binding (G3) |
| R3 | Verify full cert chain to the vendor root | report is genuine hardware (G1) |
| R4 | Check certificate revocation (AMD KDS CRL / MAA keys) | revoked platforms rejected — enforced on the AMD-cert-chain paths (AWS SEV-SNP, Azure `profile: azure-snp`); delegated to the cloud service on GCP CS / MAA; n/a on Nitro (ephemeral certs) — see the matrix |
| R5 | Enforce a minimum reported TCB/firmware version | reject out-of-date silicon (G2) — the raw-report paths and the MAA path (recombined from per-component SVN claims); GCP CS has no reported TCB, so it fails closed when `minTCB` is set |
| R6 | Require `policy.debug == false`, `policy.migration == false` | a debuggable/migratable VM isn't confidential (G2) — verified on every SEV-SNP path (AWS, Azure MAA, azure-snp); n/a on Nitro/CS |
| R7 | Measurement ∈ **exact allowlist** of known-good vendor confidential images | host can't boot a malicious image (G2) |
| R8 | TEE type in report == requested type | a `tdx` job isn't silently SEV (G1) |
| R9 | Send **no secret** before R1–R8 pass; wrap secrets to the in-TEE key | secret-after-proof (G4) |
| R10 | Confidential OS-disk encryption where offered; otherwise **warn** + record (N1) | data-at-rest honesty |
| R11 | No secrets in cloud-init / argv / process listings | host reads provisioning inputs |
| R12 | Fail closed + destroy VM on any verification failure | no false guarantee |
| R13 | Record verdict (measurement, type, TCB, nonce) on the run | auditability (G5) |
| R14 | Per-run keys and nonce; never reused | no cross-run linkage/replay |

---

## 5. Operational protocol (how an operator uses it)

**Request a confidential run** — in `dispatcher.yaml`:

```yaml
confidential:
  type: sev-snp          # sev | sev-snp | tdx | any   (default: any)
  attestation: required  # required | off              (default: required)
  profile: azure-snp     # (optional) azure-snp | nitro — select a measured-boot
                         # backend whose launch measurement includes the agent.
                         # Unset uses the provider's standard confidential path.
                         # azure-snp pins target azure-vm; nitro pins aws-vm.
```

**Images & measurements (consequence of exact attestation):**
- **Default — pinned vendor image.** dispatcher provisions a known vendor
  confidential image (Azure CVM, GCP Confidential Space, an AWS SEV-SNP image) whose
  launch measurement and built-in (measured) attestation agent dispatcher ships in
  its allowlist. No image work for the operator.
  > **Partially shipped.** The three **measured** backends are live: GCP Confidential
  > Space (measurement = the measured container-image digest, resolved from the pin
  > registry), Azure `profile: azure-snp` (PCR11), and AWS `profile: nitro` (PCR0) —
  > their measurement comes from the built image / pin registry, not `dispatcher.yaml`.
  > Only the **standard** (no-`profile`) AWS SEV-SNP and Azure MAA paths still boot a
  > stock image and scp the agent (so the agent isn't in the launch measurement — see
  > §6). dispatcher ships **no base measurement allowlist**, so on those standard paths
  > measurements come from the operator's `dispatcher.yaml` and an empty allowlist
  > fails closed.
- **Custom image — escape hatch.** To run your own image, build it with the in-TEE
  attestation agent, capture its launch measurement, and register it in dispatcher's
  measurement allowlist (config). A confidential run on an unlisted measurement is
  rejected — by design.

**What a run does:** `plan` shows feasibility + the confidential-SKU cost premium;
`run` provisions → boots → challenges the in-TEE agent with a fresh nonce → verifies
(chain, TCB, policy, exact measurement, type, freshness+binding — plus cert
revocation on the AMD-cert-chain paths, AWS and Azure `profile: azure-snp`) → only
then sends source/secrets and runs → retrieves outputs → tears down.

**Failure modes the operator sees (all fail closed):**
- No confidential-capable target for the requested type → **infeasible** at plan.
- `attestation: required` but the operator hasn't supplied the measured agent /
  pinned image for the provider → refused **before** provisioning (no VM billed).
- Measurement not on the allowlist → **rejected**, showing the actual measurement so
  a legitimate new image can be added.
- Policy/TCB/type/binding failure (plus revocation on the AWS and Azure-SNP paths)
  → VM **destroyed**, run fails with the verdict.
- Provider without host-opaque disk (GCP/AWS) → **warning** (N1), run proceeds.

**Audit:** the run records `AttestationResult{verified, type, measurement, tcb,
nonce}` — shown in `status --json` and rendered in human-readable `status` and
`diagnose` output. `attestation: off` is recorded as an unverified verdict and
warned.

---

## 6. Status & gap analysis (built vs. this spec)

**Built (safe scaffolding + verifier crypto):**
- Typed requirement/capability and the **no-silent-downgrade** feasibility gate
  (right type or rejected).
- Provisioning flags (GCP/AWS/Azure) + confidential-capable builtins.
- The **verify-and-gate flow**: pluggable per-provider `Attester`, post-boot
  verify that **destroys the VM** on failure, verdict recorded on run state.
- **Verifier cores** behind the per-provider `Attester`: raw SEV-SNP report parse
  + ECDSA-P384/SHA-384 signature + VCEK←ASK←ARK (VLEK←ASVK←ARK on AWS) chain — **hand-rolled on Go
  stdlib** (`crypto/ecdsa`/`x509`/`encoding/binary`, `internal/attest/snp.go`) on
  the **Azure measured direct-SNP** path, and via **go-sev-guest** on the **AWS**
  VLEK path; token JWS (`go-jose/v4`) for **Azure MAA** (compliance/type/measurement
  claims) and **GCP Confidential Space** (Google-signed EAT + container image-digest
  allowlist). Each enforces R3–R8 + freshness/binding (R1/R2) via `applyPolicy` (or,
  for Confidential Space, the digest allowlist + nonce/channel-key binding).
- **Measurement allowlist + minTCB** config (`confidential.measurements` /
  `minTCB`), threaded to the verifier (R7); empty allowlist fails closed.
- **Pinned AMD ARK roots** (Milan/Genoa/Turin), embedded from AMD's KDS; the
  SEV-SNP chain anchors on them (R4) and a captured ASK chains to a pinned ARK
  offline.
- **Live-fetch attesters**: each attester is registered ready with a live
  evidence fetch; `attestation: required` verifies the bound report before any
  secret ships and fails closed if the operator hasn't provisioned the agent.
- **Audit surfacing (R13)**: the verdict is rendered in human-readable `status`
  and `diagnose`, not just `status --json`.
- Secret-free cloud-init (R11).

**Delivered / remaining:**
- ✅ **In-TEE agent + evidence fetch** — the measured guest-agent
  (`internal/attest/agent` + `cmd/dispatcher-attest*`) that, given the verifier's
  per-run nonce, generates the in-TEE ephemeral key, sets `REPORT_DATA = H(N ‖
  key)`, and returns the report/token (R1/R2/G3). Live on all three clouds.
- **Provision hardening** — pinned vendor images (R7), confidential disk where
  offered + warn (R10/N1), explicit policy bits (R6).
- **Format bind** — ✅ the raw SEV-SNP report parser is golden-validated against a
  real captured **v4** report (taken on GCP hardware) through the coded ABI offsets
  + VCEK→ASK→ARK-Milan; this parser backs the **Azure measured direct-SNP** path.
  GCP's own run path is **Confidential Space** (Google-signed EAT/JWS + image-digest
  allowlist), not the raw report. ✅ **Azure MAA** claim names + JWKS fetch/pinning +
  guest agent implemented; ✅ **AWS VLEK** — AWS masks the chip id and signs with VLEK
  not VCEK, so verification uses a `VLEK→ASVK→ARK` path (via go-sev-guest; ARK/ASK-Milan
  roots match).
- **MAA TCB mapping** — MAA reports per-component SVNs rather than one packed TCB,
  so the MAA attester recombines the `x-ms-sevsnpvm-{bootloader,tee,snpfw,microcode}-svn`
  claims into the SEV-SNP `REPORTED_TCB` layout and compares it per component against
  `minTCB` (identical to the direct-SNP paths). A token missing those claims yields 0,
  failing any positive floor closed.
- **Revocation** (R4) — enforced on the AMD-cert-chain paths (AWS SEV-SNP and Azure
  `profile: azure-snp`): the ARK-signed CRL at the ASK's AMD KDS distribution point,
  fail-closed if unreachable. Delegated to the cloud service on GCP CS / Azure MAA;
  n/a on Nitro (ephemeral certs).

A verified confidential run works today given the operator-supplied agent /
pinned measured image; `attestation: off` remains the explicit opt-out that
provisions encrypted memory with no proof (N4).

---

## 7. Build plan (TDD, incremental)

| # | Increment | Delivers |
|---|---|---|
| ✅ | Typed requirement/capability/feasibility | no silent downgrade |
| ✅ | Provisioning flags + builtins | the TEE itself |
| ✅ | Verify-and-gate flow + fail-closed | safe scaffolding |
| ✅ | Verifiers — **both** cores (synthetic-tested): SEV-SNP report (stdlib x509/ecdsa/binary) and MAA/token JWS (go-jose/v4): chain + TCB + policy + exact-measurement + type + `REPORT_DATA` | the proof crypto |
| ✅ | Measurement allowlist + minTCB config (R7) | policy inputs |
| ✅ | Pinned AMD ARK roots (Milan/Genoa/Turin), embedded from KDS (R4) | SEV-SNP trust anchor |
| ✅ | Audit surfacing in `status`/`diagnose` (R13) | usability + audit |
| 1 | Provision hardening: pinned vendor images, confidential disk + warn, policy bits | safe, known launch |
| 2 | In-TEE agent evidence fetch: nonce + ephemeral in-TEE key, `REPORT_DATA=H(N‖key)` (vendor-image agent, measured); flips attesters to ready | bound, fresh evidence |
| ~ | Format bind + revocation: GCP SEV-SNP layout confirmed on a real capture ✅; MAA claims ✅, AWS **VLEK** path ✅, AMD KDS CRL revocation (AWS + azure-snp) ✅; MAA per-component TCB ✅ | live trust |
| 4 | Channel binding: trust the channel key only after R2 verifies; wrap secrets to it (R9) | no MITM/relay |

Each verifier core is unit-tested against synthetic evidence; the binary/claim
formats are confirmed against a real captured sample before the live fetch (§7
increment 2/3) is trusted.

---

## 8. Decisions

- **Measurement bar — EXACT (R7).** Allowlist of known-good launch measurements per
  pinned vendor confidential image; reject anything else. dispatcher ships **no** base
  allowlist: on the standard SEV-SNP / MAA paths the operator supplies
  `confidential.measurements` (an empty allowlist fails closed), and the measured
  `profile` backends resolve it from the pin registry (§5).
- **Guest-agent delivery — vendor image (C), custom-image escape hatch (B), drop
  cloud-init (A).** Use the pinned vendor confidential image's built-in, **measured**
  attestation agent (Azure guest-attestation/MAA, GCP Confidential Space, AWS image
  with `snpguest`). For a custom image, the operator bakes the agent in and registers
  its measurement. A cloud-init-injected agent is **rejected** — it runs after the
  measured boot, so it's host-swappable and defeats R7.
- **Verifiers — BOTH formats** behind the `Attester` interface: SEV-SNP hardware
  report (hand-rolled stdlib on the Azure measured-SNP path, `snp.go`; go-sev-guest
  on AWS VLEK) and token JWS for Azure MAA and GCP Confidential Space (`go-jose/v4`,
  see `internal/attest/jws.go`); shared nonce/measurement/policy/binding checks via
  `applyPolicy`.
- **Disk-at-rest — allow both, warn (R10/N1).** Confidential disk where the provider
  offers it; elsewhere run but warn + record that disk-at-rest isn't host-opaque.
