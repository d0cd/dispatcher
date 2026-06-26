# Spec: Confidential computing (secure jobs)

**Status:** Specification under review (supersedes the earlier provisioning-only design)
**Related:** ROADMAP Theme 6.

This is the complete protocol for running a workload confidentially via dispatcher.
It is deliberately strict: a confidential run that doesn't meet every requirement
below **must fail closed**, because a *partial* confidential guarantee is a false
one. Sections 1–4 are the spec; §5 is an honest gap analysis of what's built today
versus this spec; §6 is the build plan.

## 1. Threat model

**What we protect:** the workload's data and code *in use* (in memory) and the
integrity of its execution environment.

**Adversary:** the cloud provider and anyone with host/hypervisor access — a
malicious or compromised cloud operator, a co-tenant escaping isolation, a
host-level attacker. They can read/modify host memory, the hypervisor, the
network, and unencrypted disk; they can intercept the cloud API and the SSH
connection; they can boot a VM of their choosing and try to impersonate a TEE.

**Trusted computing base (TCB) we rely on:**
- The TEE hardware + firmware (AMD SEV-SNP, Intel TDX) and the silicon vendor's
  root of trust (AMD ARK/ASK, Intel/Azure roots).
- The measured guest image (a vendor confidential-VM image, whose launch
  measurement we check).
- The user's `dispatcher` CLI and the machine it runs on (the operator).

**Explicitly out of scope:** side-channel/microarchitectural attacks; a malicious
workload exfiltrating its own data; physical de-capping; bugs in the TEE itself.

**Key consequence:** dispatcher runs *outside* the TEE. Therefore dispatcher must
treat the VM as untrusted **until attestation proves otherwise**, and must never
hand the VM any secret (workload source, `.env`, credentials) before that proof —
and only over a channel **cryptographically bound to the attested TEE**.

## 2. Security goals (the "desired requirements")

A confidential run MUST provide all of:

1. **Memory encryption** — the workload's RAM is hardware-encrypted (the TEE).
2. **Attested launch** — a hardware-signed report proves a genuine TEE of the
   requested type booted a **known-good measurement** with a **safe policy**
   (debug disabled, migration disabled, minimum TCB).
3. **Freshness** — the report answers a per-run **nonce** dispatcher chose, so a
   replayed or relayed report from another machine is rejected.
4. **Channel binding** — the report binds the **public key of the channel**
   dispatcher will use to talk to the VM, so a host can't MITM/relay (prove a real
   TEE *elsewhere* while terminating our connection itself).
5. **Secret-after-proof** — workload source, `.env`, and outputs cross the channel
   **only after** 1–4 verify.
6. **Confidential at rest** — anything the workload persists to the OS disk is
   encrypted with a key the host can't read (confidential OS-disk encryption /
   vTPM-bound), or stays in encrypted memory.
7. **No silent downgrade & fail-closed** — if any of the above can't be met, the
   run is rejected/destroyed; it never falls back to a normal VM or runs unproven.

## 3. The protocol

```
operator (dispatcher, outside the TEE)              cloud TEE VM (untrusted until §3.5)
─────────────────────────────────────              ──────────────────────────────────
3.1 generate per-run nonce N (random 32B)
    generate per-run SSH keypair
3.2 provision confidential VM:
      - type flag (SEV/SEV-SNP/TDX)
      - confidential OS-disk encryption ON
      - measured vendor confidential image
      - policy: no-debug, no-migration
      - inject SSH *public* key via cloud-init
      - NO secrets in cloud-init/user-data       ── boots inside the TEE ──▶
3.3 connect over SSH (TOFU — still untrusted).
    Record the server's host key K_host.
3.4 ask the guest agent for evidence with
    REPORT_DATA = H(N ‖ K_host):                  ──▶ guest reads HW report
                                                       (/dev/sev-guest) or calls MAA,
                                                  ◀── returns report/token + cert chain
3.5 VERIFY (all must hold):
      a. signature chains to the vendor root;
         certs not revoked; TCB ≥ minimum
      b. TEE type == requested
      c. policy: debug off, migration off
      d. measurement == expected image
      e. REPORT_DATA == H(N ‖ K_host)   ← freshness + channel binding
    → only now is K_host PROVEN to be this TEE.
    Record AttestationResult (measurement, type, TCB).
3.6 NOW trust the channel: send workload source
    + .env + run the command over SSH (pinned to
    the proven K_host).                            ──▶ workload runs in the TEE
3.7 retrieve outputs over the same bound channel.
3.8 teardown.

Any failure in 3.4–3.5 ⇒ destroy the VM, send nothing, fail the run.
```

The chicken-and-egg ("we SSH to an untrusted VM to fetch the report") is resolved
by §3.5e: the untrusted SSH connection is used **only** to fetch the report, and
nothing secret is sent until the report's `REPORT_DATA` proves that this exact SSH
host key belongs to the genuine, freshly-challenged TEE. TOFU is acceptable here
*because* attestation retroactively proves the key — it is not trusted on its own.

## 4. Requirements checklist (what "good hygiene" means here)

| # | Requirement | Why |
|---|---|---|
| R1 | Per-run random nonce in `REPORT_DATA` | replay/relay resistance (§2.3) |
| R2 | `REPORT_DATA` commits an **in-TEE-generated** channel key (see note) | channel binding (§2.4) |
| R3 | Verify full cert chain to the vendor root | the report is genuine hardware |
| R4 | Check certificate revocation (AMD KDS CRL / MAA keys) | revoked platforms rejected |
| R5 | Enforce a minimum reported TCB/firmware version | reject patched-out-of-date silicon |
| R6 | Require `policy.debug == false`, `policy.migration == false` | a debuggable/migratable VM isn't confidential |
| R7 | Pin the **exact** expected launch measurement(s) — an allowlist of known-good vendor confidential-image measurements | host can't boot a malicious SEV-SNP image |

> **R2 note (in-TEE key binding).** Binding to the SSH *host* key only defeats a
> relay/MITM if that key was generated **inside the TEE** and never exposed to the
> host — otherwise a host that terminates SSH (holding the host key itself) can
> relay our nonce to a *real* TEE elsewhere and get a valid report that commits
> *its* key. The robust form: the in-TEE agent generates an **ephemeral keypair
> inside the TEE**, puts `H(nonce ‖ agent_pubkey)` in `REPORT_DATA`, and dispatcher
> wraps the workload secrets to `agent_pubkey` (or runs RA-TLS to it). The SSH host
> key is acceptable *only if* it is provably in-TEE-generated by the measured image
> (which R7's exact-measurement pinning helps establish).
| R8 | TEE type in report == requested type | a `tdx` job isn't silently SEV |
| R9 | Send **no secret** (source/.env/outputs) before R1–R8 pass | secret-after-proof (§2.5) |
| R10 | Confidential OS-disk encryption where the provider offers it; otherwise **warn** about the disk-at-rest residual | data at rest not host-readable (or the user is told it isn't) |
| R11 | No secrets in cloud-init / argv / process listings | host reads provisioning inputs |
| R12 | Fail closed + destroy VM on any verification failure | no false guarantee |
| R13 | Record verdict (measurement, type, TCB, nonce) on the run | auditability / `diagnose` |
| R14 | Per-run keys and nonce; never reused | no cross-run linkage/replay |

## 5. Current state vs. this spec (honest gap analysis)

**Built and correct:**
- R8 partial / no-silent-downgrade: typed feasibility gate rejects unsupported
  type/provider combos (never runs on a non-confidential or wrong-type VM).
- R12: fail-closed — a confidential run with attestation required is refused
  pre-provision (no verifier) and the post-boot gate destroys the VM on failure.
- The provisioning flow emits the per-provider confidential flag, and the
  attestation **verify-and-gate stage** exists (pluggable per-provider verifier).
- R11: secrets aren't placed in cloud-init/argv (existing user-data hygiene).

**Gaps that MUST close before this is a real guarantee (not yet built):**
- **R1/R2 (freshness + channel binding) — NOT met.** Today SSH host keys are
  trusted via TOFU (`ssh-keyscan` pin), *independent* of attestation. Without
  binding `REPORT_DATA = H(nonce ‖ host_key)`, a malicious host can relay a real
  report from a TEE it controls while MITMing our connection. **This is the most
  important gap** and it requires a **guest agent** that produces the report with
  our nonce+key in `REPORT_DATA`.
- **R7 (measurement policy) — NOT met.** The MVP plan verified only "a valid
  report of the requested type." A genuine SEV-SNP report can come from a
  host-chosen *malicious* image. We must pin/allow expected measurements (or, at
  minimum, rely on a known vendor image + check policy bits).
- **R6 (policy bits) / R5 (TCB) / R4 (revocation) — NOT met.** The verifier must
  check debug/migration off, minimum TCB, and revocation.
- **R9 ordering — partially met.** The attestation stage is placed *before* source
  rsync, which is necessary; but until R2 binds the channel, "before rsync" alone
  doesn't prevent a relay MITM.
- **R10 (confidential disk) — partial.** Azure path sets `VMGuestStateOnly`;
  full disk-at-rest confidentiality wants `DiskWithVMGuestState` (a disk-encryption
  set). GCP/AWS rely on the TEE for memory; disk is cloud-KMS-encrypted (not
  host-opaque) — document the residual.
- **R3 (real signature verification) — NOT built.** No verifier registered yet.

**Conclusion:** the work so far establishes the *safe scaffolding* (feasibility,
fail-closed, the gate), but a confidential run today can only `attestation: off`
(provision a TEE without proof). To deliver the actual guarantee we need: a
**guest attestation agent** (R1/R2/R7 evidence), a **real verifier** (R3–R8), and
**channel binding**. Building only the verifier — without the nonce/key binding
and measurement policy — would *look* done while remaining relay-vulnerable.

## 6. Build plan (revised to meet the spec)

| # | Increment | Delivers |
|---|---|---|
| ✅ | Requirement/capability/feasibility (typed) | no silent downgrade |
| ✅ | Provisioning flags (GCP/AWS/Azure) + builtins | the TEE itself |
| ✅ | Verify-and-gate flow + fail-closed | safe scaffolding |
| 1 | **Provision hardening**: confidential OS-disk encryption (R10), explicit policy bits no-debug/no-migration (R6), vendor measured image pinning (R7 setup) | safe launch |
| 2 | **Guest attestation agent**: a small step run on the booted VM that produces a fresh report with `REPORT_DATA = H(nonce ‖ ssh_host_key)` (R1/R2) — SEV-SNP via `/dev/sev-guest`, Azure via MAA runtime data | bound, fresh evidence |
| 3 | **Verifiers — both formats**: (a) SEV-SNP hardware report (stdlib x509/ecdsa/binary), (b) MAA/token JWS (`go-jose`). Each does chain-to-root + revocation + TCB + policy + exact-measurement allowlist + type + `REPORT_DATA`=H(nonce‖key) (R3–R8). Unit-tested against synthetic evidence; format confirmed against a real sample | the proof |
| 4 | **Channel binding**: trust the SSH host key *only* after R2 verifies; secrets/source strictly after (R9) | no MITM/relay |
| 5 | Record verdict (R13); docs; `diagnose` surfaces measurement/type/TCB | auditability |

## 7. Decisions

- **R7 measurement bar — EXACT.** Maintain an allowlist of known-good launch
  measurements per pinned vendor confidential image; reject anything else. Higher
  maintenance (track image updates), but it's the only bar that stops a
  host-chosen malicious image. The allowlist is config dispatcher ships + lets
  operators extend.
- **Verifier — BOTH formats.** Providers use different evidence: a **hardware
  report** (AMD SEV-SNP on AWS/GCP — stdlib `crypto/x509` + `crypto/ecdsa` +
  `encoding/binary`) **and** a **signed token** (Azure MAA / GCP Confidential
  Space — JWS, via the vetted `go-jose` dependency). Build both behind the
  `Attester` interface; share the nonce/measurement/policy checks.
- **Disk-at-rest — allow both, warn.** Enable confidential OS-disk encryption
  where the provider offers it (Azure); where it isn't host-opaque (GCP/AWS:
  cloud-KMS-encrypted, not host-opaque), still run, but **emit a clear warning**
  that disk-at-rest is not confidential — and record it on the run.

**Still open — guest agent delivery (need your call; tradeoffs below):**
where the in-TEE attestation agent (R2/R7 evidence) comes from — baked into
cloud-init by dispatcher, required in the workload image, or the pinned vendor
image's built-in tooling.
