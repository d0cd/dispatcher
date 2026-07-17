# Spec: Confidential computing (secure jobs)

**Status:** Implemented end-to-end on the three **measured** backends — GCP Confidential Space, Azure `profile: azure-snp` (SEV-SNP + vTPM, agent in PCR11), and AWS `profile: nitro` (COSE + pinned PCR0) — provisioning + verifier cores + pinned ARK/AWS roots + the in-TEE measured agent and live evidence fetch, all hardware-validated. The raw SEV-SNP report parser is golden-validated against a report captured on GCP hardware. The **unmeasured** standard SEV-SNP / MAA paths (post-boot scp'd agent, not in the launch measurement) were **removed**: an attested run on aws-vm/azure-vm requires the measured `profile`, and `attestation: off` is the escape hatch for encrypted-memory-without-verification. Cert revocation is enforced on the AMD-cert-chain path (`profile: azure-snp`) via the AMD KDS CRL.
**Related:** [ROADMAP](ROADMAP.md) → "Confidential computing (secure jobs)".

Run a workload on a TEE-backed VM (hardware-encrypted memory) so the cloud
provider can't read its data *in use* — **and prove it** via attestation before
the workload (or any secret) ever reaches the VM. This spec is deliberately
strict: a confidential run that can't meet every requirement **fails closed**,
because a *partial* confidential guarantee is a false one.

Reader's map: §1 threat model · §2 **security guarantees** · §3 **the protocol** ·
§4 requirements/hygiene · §5 **operational protocol** · §6 decisions.

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
  the SEV-SNP path (`profile: azure-snp`) and is n/a on the
  Nitro and Confidential Space paths (see the enforcement matrix).
- **G3 — Fresh and bound.** The attestation answered this run's random nonce and
  committed the attested TLS session (`bindData`) — so it is not a replayed or
  relayed proof from another machine; dispatcher provably talked to *that* TEE over
  *this* session.
- **G4 — Secret-after-proof.** No workload source, `.env`, or output crossed the
  session before G1–G3 verified.
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

| Control | GCP CS | Azure SNP | AWS Nitro |
|---|---|---|---|
| Genuine TEE (signature + chain to pinned root) | ✓ | ✓ | ✓ |
| Measurement/identity on exact allowlist (empty fails closed) | ✓ | ✓ | ✓ |
| Per-run nonce freshness | ✓ | ✓ | ✓ |
| Session binding (evidence bound to the attested TLS session) | ✓ | ✓ | ✓ |
| Debug disabled | ✓ | ✓ | n/a |
| Migration disabled | n/a | ✓ | n/a |
| Minimum TCB / firmware floor | fail-closed | ✓ | n/a |
| Certificate revocation | n/a | ✓ | n/a |
| Attestation agent folded into the measured boot | ✓ | ✓ | ✓ |

**Roots of trust:** GCP CS = Google JWKS; Azure SNP = pinned AMD ARK; AWS Nitro = pinned AWS Nitro root.

- **GCP CS — Measurement/identity on exact allowlist (empty fails closed):** the attested identity is the container image digest
- **GCP CS — Migration disabled:** the Confidential Space token exposes no migration claim
- **GCP CS — Minimum TCB / firmware floor:** the CS token carries no reported TCB, so a run that sets minTCB is rejected (GCP has no measured-TCB backend)
- **GCP CS — Certificate revocation:** delegated to the Google Confidential Space service; dispatcher validates no AMD cert chain locally
- **GCP CS — Attestation agent folded into the measured boot:** the measured container image is the workload
- **Azure SNP — Measurement/identity on exact allowlist (empty fails closed):** PCR11 (the UKI carrying the agent), pinned
- **Azure SNP — Certificate revocation:** the ARK-signed CRL at the ASK's AMD KDS distribution point; a revoked VCEK/ASK is rejected, fail-closed if the CRL is missing or unreachable
- **Azure SNP — Attestation agent folded into the measured boot:** PCR11 = the UKI carrying the agent
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
3.3 dial the measured in-TEE agent over TLS
    (untrusted transport; trust is attestation,
    not PKI — InsecureSkipVerify).
3.4 challenge the agent over the session:       ──▶ agent serves TLS with an EPHEMERAL
      send N; the agent binds the session           cert whose key never leaves the TEE,
                                                     derives bindData = H(certSPKI ‖ exporter),
                                                     reads the HW report (/dev/sev-guest) or
                                                     calls the NSM/teeserver with
                                                     REPORT_DATA = H(N ‖ bindData)
                                                ◀── returns report/token + cert chain
3.5 VERIFY (ALL must hold, else destroy + fail):
      a. signature chains to vendor root; TCB ≥
         minimum; certs not revoked (AMD KDS CRL on
         the Azure-SNP path — see matrix).
      b. TEE type == requested
      c. policy: debug off; migration off (on every
         SEV-SNP path — azure-snp;
         n/a on Nitro/CS — see the matrix)
      d. measurement ∈ allowlist (EXACT)
      e. REPORT_DATA == H(N ‖ bindData), where
         dispatcher recomputes bindData from the cert
         it handshook with + its own exporter
         → freshness (N) + session binding
    Record AttestationResult.
3.6 deliver workload source + .env over the
    attested session and run the command.         ──▶ workload runs in the TEE
3.7 retrieve outputs over the attested session.    (leaves the TEE on arrival — N2)
3.8 teardown.

Any failure in 3.4–3.5 ⇒ destroy the VM, send nothing, fail the run.
```

**Why this is sound.** The untrusted TLS transport in 3.3–3.4 carries nothing
secret until 3.5e proves the evidence committed to *this* TLS session's `bindData`
inside the genuine, freshly-challenged TEE (so a host that relays our nonce to a
real TEE elsewhere cannot bind *its own* session — the evidence would commit to a
`bindData` dispatcher never handshook with). The agent is part of the **measured**
image (3.2), so the host can't swap it for a relaying one. The exact-measurement
allowlist (3.5d) stops the host from booting a malicious genuinely-SEV-SNP image.

---

## 4. Requirements & hygiene checklist

| # | Requirement | Why |
|---|---|---|
| R1 | Per-run random nonce in `REPORT_DATA` | replay/relay resistance (G3) |
| R2 | `REPORT_DATA` commits the attested TLS session's `bindData` = H(agent-cert-SPKI ‖ RFC 5705 exporter), tied to an **in-TEE** key (not a host-injectable one) | session binding (G3) |
| R3 | Verify full cert chain to the vendor root | report is genuine hardware (G1) |
| R4 | Check certificate revocation (AMD KDS CRL) | revoked platforms rejected — enforced on the AMD-cert-chain path (Azure `profile: azure-snp`); delegated to the cloud service on GCP CS; n/a on Nitro (ephemeral certs) — see the matrix |
| R5 | Enforce a minimum reported TCB/firmware version | reject out-of-date silicon (G2) — the SNP report path (`profile: azure-snp`); GCP CS carries no reported TCB, so it fails closed when `minTCB` is set, and Nitro is n/a (see the matrix) |
| R6 | Require `policy.debug == false`, `policy.migration == false` | a debuggable/migratable VM isn't confidential (G2) — verified on the SEV-SNP path (azure-snp); n/a on Nitro/CS |
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
  profile: azure-snp     # azure-snp | nitro — select a measured-boot backend
                         # whose launch measurement includes the agent. Required
                         # on aws-vm/azure-vm for an attested run; GCP Confidential
                         # Space needs none. azure-snp pins azure-vm; nitro pins aws-vm.
```

**Images & measurements (consequence of exact attestation):**
- **Default — pinned vendor image.** dispatcher provisions a known measured
  image (the azure-snp CVM image, a GCP Confidential Space container, an AWS Nitro
  enclave) whose
  launch measurement and built-in (measured) attestation agent dispatcher ships in
  its allowlist. No image work for the operator.
  > **Shipped.** The three **measured** backends are live: GCP Confidential
  > Space (measurement = the measured container-image digest, resolved from the pin
  > registry), Azure `profile: azure-snp` (PCR11), and AWS `profile: nitro` (PCR0) —
  > their measurement comes from the built image / pin registry, not `dispatcher.yaml`.
  > The unmeasured standard (no-`profile`) SEV-SNP / MAA paths — stock image + scp'd
  > agent, so the agent isn't in the launch measurement (see §6) — were removed; an
  > attested run on aws-vm/azure-vm requires the measured `profile`.
- **Custom image — escape hatch.** To run your own image, build it with the in-TEE
  attestation agent, capture its launch measurement, and register it in dispatcher's
  measurement allowlist (config). A confidential run on an unlisted measurement is
  rejected — by design.

**What a run does:** `plan` shows feasibility + the confidential-SKU cost premium;
`run` provisions → boots → challenges the in-TEE agent with a fresh nonce → verifies
(chain, TCB, policy, exact measurement, type, freshness+session-binding — plus cert
revocation on the AMD-cert-chain path, Azure `profile: azure-snp`) → only
then sends source/secrets and runs → retrieves outputs → tears down.

**Failure modes the operator sees (all fail closed):**
- No confidential-capable target for the requested type → **infeasible** at plan.
- `attestation: required` but the operator hasn't supplied the measured agent /
  pinned image for the provider → refused **before** provisioning (no VM billed).
- Measurement not on the allowlist → **rejected**, showing the actual measurement so
  a legitimate new image can be added.
- Policy/TCB/type/binding failure (plus revocation on the Azure-SNP path)
  → VM **destroyed**, run fails with the verdict.
- Provider without host-opaque disk (GCP/AWS) → **warning** (N1), run proceeds.

**Audit:** the run records `AttestationResult{verified, type, measurement, tcb,
nonce}` — shown in `status --json` and rendered in human-readable `status` and
`diagnose` output. `attestation: off` is recorded as an unverified verdict and
warned.

---

## 6. Decisions

- **Measurement bar — EXACT (R7).** Allowlist of known-good launch measurements per
  pinned measured image; reject anything else. dispatcher ships **no** base
  allowlist: the measured `profile` backends resolve it from the pin registry (§5),
  and a custom image supplies its own via `confidential.measurements` (an empty
  allowlist fails closed).
- **Guest-agent delivery — vendor image (C), custom-image escape hatch (B), drop
  cloud-init (A).** Use the pinned vendor confidential image's built-in, **measured**
  attestation agent (Azure direct SNP+vTPM `profile: azure-snp`, GCP Confidential
  Space, AWS Nitro Enclaves `profile: nitro`). For a custom image, the operator bakes the agent in and registers
  its measurement. A cloud-init-injected agent is **rejected** — it runs after the
  measured boot, so it's host-swappable and defeats R7.
- **Verifiers — multiple formats** behind the per-cloud aTLS validators
  (`atls_validators.go`): the SEV-SNP hardware report (hand-rolled stdlib on the
  azure-snp path, `snp.go`), a COSE chain to the pinned Nitro root on the nitro path,
  and token JWS for GCP Confidential Space (`go-jose/v4`, see `internal/attest/jws.go`);
  shared nonce/measurement/policy/binding checks via `applyPolicy`. Each validator
  verifies evidence supplied by the attested TLS exchange.
- **Disk-at-rest — allow both, warn (R10/N1).** Confidential disk where the provider
  offers it; elsewhere run but warn + record that disk-at-rest isn't host-opaque.
