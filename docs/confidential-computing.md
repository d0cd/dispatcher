# Design: Confidential computing (secure jobs)

**Status:** Proposed (revised — typed TEE + attestation in scope)
**Related:** ROADMAP Theme 6.

## 1. Goal & non-goals

Let a workload demand a **TEE-backed VM** — hardware-encrypted memory (AMD
SEV/SEV-SNP, Intel TDX) so the cloud host/hypervisor can't read it — **and prove
it** via attestation. The workload names the TEE type it needs; dispatcher only
runs it on hardware that delivers that type, fetches and verifies the TEE's
attestation report, and refuses to run the workload if the proof doesn't check
out.

**In scope (this plan):**
- Provision a confidential VM of a requested **type** (SEV / SEV-SNP / TDX).
- **Attestation:** fetch the TEE's signed report, verify it to the hardware/cloud
  root of trust, record the verdict on the run, and **fail closed** when
  attestation is required and can't be verified.

**Non-goals:**
- **AWS Nitro Enclaves / k8s Confidential Containers (CoCo)** — a different model
  (enclave-within-instance, custom tooling/images), not a VM create flag. Out of
  scope until demand.
- Custom/operator-supplied expected-measurement policies beyond "valid report
  from the right vendor root for the requested type" — a later refinement.
- Doesn't change the existing operator-boundary security model; this is additive
  (protects *data-in-use* from the cloud, an orthogonal threat model).

## 2. Workload contract (top-level, typed)

`confidential:` is a top-level block in `dispatcher.yaml`, parallel to `gpu:`:

```yaml
confidential:
  type: sev-snp          # sev | sev-snp | tdx | any   (default: any)
  attestation: required  # required | off              (default: required)
```

- **`type`** — the TEE technology. `any` lets dispatcher pick whatever the chosen
  provider/instance supports.
- **`attestation`** — `required` (default) means the run only proceeds after the
  attestation report verifies; `off` provisions the TEE but skips verification
  (explicit opt-out, for users who only want memory encryption).

Secure by default: a bare `confidential: {}` (or `confidential: {type: any}`)
means "any TEE, attestation required."

## 3. Data model

Mirrors the GPU shapes (`GPURequirement` / `GPUCapability`) so it's familiar.

```go
// types.ResourceRequirements
type ConfidentialRequirement struct {
    Required    bool   // a confidential VM is required
    Type        string // "sev" | "sev-snp" | "tdx" | "" (any)
    Attestation string // "required" (default) | "off"
}

// types.ResourceCapability
type ConfidentialCapability struct {
    Supported bool     // target can provision confidential VMs
    Types     []string // which TEE types it offers, e.g. ["sev-snp","tdx"]
}
```

> **Evolves the first increment.** The committed deterministic core used a plain
> `bool` for both the requirement and the capability. This typed model replaces
> it (the bool → the `Required`/`Supported` field), with `Type`/`Types` and the
> attestation knob added. A small, mechanical refactor of already-tested code.

## 4. Feasibility (mirrors GPU model matching)

```
if Requirements.Confidential.Required:
    if not cap.Supported:                      → "confidential required but target can't"
    elif Type != "" and Type != "any"
         and Type not in cap.Types:            → "confidential type <T> not offered (has: …)"
```

So a `tdx` job won't land on an SEV-only target; an `any` job takes whatever the
target offers. Same structure as the GPU-model gate already in `match.go`.

## 5. Provisioning — per-provider create flag (verify exact syntax at impl)

`VMOptions` gains `Confidential ConfidentialRequirement` (or just `Type`); each
provider's `CreateVM` emits the right flag, argv-table-tested via the `runCLI`
seam. The catalog marks which instance types offer which TEE type.

| Provider | Mechanism | Notes |
|---|---|---|
| **GCP** | `--confidential-compute-type=SEV\|SEV_SNP\|TDX` + `--maintenance-policy=TERMINATE` | SEV→`n2d`, TDX→`c3` |
| **AWS** | `--cpu-options AmdSevSnp=enabled` (SEV-SNP) | specific later-gen AMD types only; no TDX today |
| **Azure** | `--security-type ConfidentialVM` + DCasv5/ECasv5 (SEV-SNP) or TDX SKU + OS-disk encryption + vTPM | most involved |
| **Hetzner / Lima** | — | not confidential-capable; rejected by feasibility |

## 6. Attestation (in scope) — fetch → verify → gate

After the VM is reachable and **before the workload runs**, the cloud-VM adapter
runs an attestation step:

1. **Fetch** the TEE's attestation evidence (per-provider, §6.1).
2. **Verify** the signature chain to the hardware/cloud root of trust and that
   the report's TEE type matches what was requested. (MVP policy = "a valid,
   correctly-signed report of the requested type"; expected-measurement pinning
   is a later refinement.)
3. **Record** an `AttestationResult{Verified, Type, Measurement, Verdict}` on the
   run state, surfaced by `diagnose`/`status`.
4. **Gate:** if `attestation: required` and verification fails (or isn't
   implemented for that provider yet), **fail the run before executing the
   workload** — never run on an unproven VM. If `attestation: off`, skip 1–2 and
   record `Verified: false (skipped by request)`.

This adds one stage to the cloud-VM execute flow (a `RunStateAttesting` between
"provisioned/ready" and "running") — small surface, fail-closed.

### 6.1 Per-provider evidence (verify exact APIs at impl)
- **Azure** — Microsoft Azure Attestation (MAA): the guest gets a report, MAA
  returns a signed JWT; dispatcher verifies the JWT against MAA's keys. Most
  turnkey.
- **AWS SEV-SNP** — the guest reads an SEV-SNP report (`/dev/sev-guest`);
  dispatcher verifies it against AMD's key distribution service (KDS) cert chain.
  Needs a tiny guest-side fetch step + AMD root verification.
- **GCP** — Confidential VM vTPM / Confidential Space attestation token; verify
  against Google's attestation root.

Honest note: attestation is the **larger, cryptographically-involved** half of
this work and is per-provider. It's in the plan (not punted), but it lands after
provisioning and is the bulk of the effort.

## 7. Build order (TDD, incremental — all in this plan)

| # | Increment | Status |
|---|---|---|
| 1 | Deterministic core: requirement/capability/feasibility (was bool) | ✅ shipped (bool) |
| 2 | **Evolve to the typed model** (§3) + type-aware feasibility (§4) | next |
| 3 | Mark cloud builtins/catalog confidential-capable (with types) + thread into `CreateVM` flags (§5), argv-tested | |
| 4 | Attestation: `RunStateAttesting` stage + `AttestationResult` + fail-closed gate (§6); per-provider verify (§6.1), Azure first | |
| 5 | Docs: USAGE + SECURITY (data-in-use boundary + attestation semantics) | |

Until a provider's attestation verify (4) exists, `attestation: required` on that
provider **fails closed** — so the secure default is honored from the start.

## 8. Cost & risk
Confidential instances carry a price premium; the estimate uses the confidential
SKU's price where the catalog has it (else flagged as an assumption). A
`confidential-unschedulable` feasibility reason mirrors `gpu-unschedulable`.

## 9. Open questions
- **Expected-measurement policy:** MVP verifies "valid report of the requested
  type from the right root." Do we later let users pin expected measurements
  (full remote-attestation policy)? Deferred refinement.
- **Where attestation runs:** a guest-side fetch (a short command over SSH on the
  ready VM) vs. a provider control-plane API. Likely per-provider (Azure=API,
  AWS=guest-side). Decided per provider in increment 4.
