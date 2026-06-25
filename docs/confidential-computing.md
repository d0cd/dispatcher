# Design: Confidential computing (secure jobs)

**Status:** Proposed
**Related:** ROADMAP Theme 6.

## 1. Goal & non-goals

Let a workload request a **TEE-backed VM** — one whose memory is hardware-encrypted
so the cloud host/hypervisor can't read it (AMD SEV/SEV-SNP, Intel TDX). The
mechanism mirrors how `--gpu` already flows: a workload **requirement** →
`VMOptions` → a per-provider create flag, gated by **capability + feasibility** so
a confidential run never silently lands on a non-confidential VM.

**MVP delivers:** provisioning a confidential VM where the provider/instance/
region supports it, and a hard rejection where it doesn't.

**Non-goals (MVP):**
- **No attestation verification.** A confidential VM encrypts memory, but the
  *proof* that it did is a signed attestation report. The MVP provisions the TEE
  but does **not** fetch/verify attestation — so it raises the bar (host can't
  trivially read memory) without yet *proving* confidentiality. This limitation
  must be stated plainly to users; attestation is a separate, larger effort (§7).
- **No AWS Nitro Enclaves / k8s Confidential Containers (CoCo).** Those are a
  different model (an enclave *within* an instance, custom tooling/images), not a
  VM create flag. Out of scope until there's demand.
- Doesn't change dispatcher's existing operator-boundary security model; this is
  additive (protects *data-in-use* from the cloud, an orthogonal threat model).

## 2. How it flows (mirrors the GPU pattern)

| Layer | GPU (existing) | Confidential (new) |
|---|---|---|
| Workload requirement | `Requirements.GPU` | `Requirements.Confidential bool` |
| dispatcher.yaml | `gpu:` | `confidential: true` |
| VM request | `VMOptions.GPUCount` | `VMOptions.Confidential bool` |
| Catalog/capability | GPU model/count on instance | `ConfidentialCapable` on instance + target capability |
| Feasibility | gpu-unschedulable rejection | confidential-unschedulable rejection |
| Provider create | GPU flags | the per-provider confidential flag (§4) |

This keeps the change small and consistent with code reviewers already know.

## 3. Workload contract

```yaml
# dispatcher.yaml
confidential: true   # run only on a TEE-backed (memory-encrypted) VM
```

→ `WorkloadSpec.Requirements.Confidential = true`. The planner then only considers
targets/instances flagged confidential-capable, and `VMOptions.Confidential`
drives the create flag.

## 4. Per-provider create flag (verify exact syntax at implementation)

| Provider | Mechanism | Notes |
|---|---|---|
| **GCP** | `--confidential-compute-type=SEV` (or `SEV_SNP`/`TDX`) + `--maintenance-policy=TERMINATE` | SEV needs `n2d`; TDX needs `c3`. |
| **AWS** | `--cpu-options AmdSevSnp=enabled` | Supported on specific later-gen AMD instance types only. |
| **Azure** | `--security-type ConfidentialVM` + confidential VM size (DCasv5/ECasv5/…) + `--os-disk-security-encryption-type` + vTPM/secure-boot | The most involved (SKU + OS-disk encryption). |
| **Hetzner / Lima** | not available | Reject as unsupported. |

Exact flags/instance lists are verified and table-tested at implementation time
(via the existing `runCLI` argv seam), not trusted from this doc.

## 5. Capability & feasibility

- The catalog marks which instance types are confidential-capable (per provider/
  region). `Capabilities` gains a `Confidential bool` on targets.
- Feasibility: if `Requirements.Confidential` and the target/instance can't do it,
  reject with a clear reason (mirrors `gpu-unschedulable`). Add a
  `confidential-unsupported` risk/feasibility reason.
- Cost: confidential instances carry a premium; the estimate uses the
  confidential SKU's price where the catalog has it (else flag as an assumption).

## 6. Implementation order (TDD, incremental)

1. **Deterministic core first** (no provider calls): `Requirements.Confidential`
   + `dispatcher.yaml` `confidential:` parsing; `VMOptions.Confidential`;
   capability + feasibility rejection. Fully unit-testable.
2. **Provider argv**: thread `VMOptions.Confidential` into each provider's
   `CreateVM` flag, table-tested via the `runCLI` seam (GCP/AWS/Azure; reject on
   Hetzner/Lima).
3. **Catalog**: flag confidential-capable instances + (where known) confidential
   pricing.
4. **Docs**: USAGE + SECURITY (the data-in-use boundary, and the honest
   no-attestation-yet caveat).

## 7. Attestation (future, separate design)

The real "secure jobs" guarantee is **verifiable attestation**: fetch the TEE's
signed report, check the measurement/root-of-trust, and record it on the run so a
user can *prove* the job ran confidentially. This is substantial (per-provider
attestation APIs, a trust policy, verification) and gets its own design when the
MVP lands and demand is real. Until then, the feature is documented as
"provisions a TEE-backed VM; does not yet verify attestation."

## 8. Open questions

- Where does `confidential:` live in `dispatcher.yaml` — top-level (like `gpu:`)
  or under a `security:`/`sandbox:` block? Lean: top-level, matching `gpu`.
- Do we expose the TEE *type* (SEV vs SEV-SNP vs TDX) or keep it a boolean and let
  the provider pick its default? Lean: boolean for the MVP; revisit with
  attestation (where the type matters for verification).
