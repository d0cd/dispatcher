# Roadmap

Remaining work on dispatcher, from a cross-cutting audit (feature gaps, provider
parity, docs-vs-code, test coverage, UX, robustness). The tool is mature — three
prior audit rounds closed the security/correctness backlog and the CLI surface is
complete — so what's left is a coherent set of *completeness* gaps, headlined by
one load-bearing wiring fix.

**Refreshed against HEAD:** the headline provisioning fix and all of Themes 1–2
(plus the provider-argv seam and several Theme 4–5 items) have since landed —
rows marked **✅ Done** below carry their commit refs. This work is unpushed on
`gap-audit-fixes`. What remains is Theme 1 residuals (GPU model, region), Theme 3
(provider parity, incl. the SSH-artifact no-op), the rest of Theme 4 coverage,
and Themes 6–7.

Effort: **S** ≈ <½ day · **M** ≈ 1–2 days · **L** ≈ 3+ days. Impact is user-facing
severity.

## Theme 1 — The provisioning gap (critical)

The catalog / pricing / GPU / region selection pipeline is **plan-time only**.
`CloudVMAdapter.Execute` builds `VMOptions` without `InstanceType`, `Image`, or a
workload-derived `Region`, so every cloud run provisions the provider's hardcoded
floor instance (`cax11` / `t3.micro` / …) in the default region — regardless of
`--gpu` or workload requirements. **The cost estimate is for an instance the run
never launches.**

| Item | Effort | Impact |
|---|---|---|
| **✅ Done** (`db3b6a7`). Thread the catalog-selected instance type into `VMOptions`, reusing the same-provider selection that priced the plan. Populate the currently-dead `CloudVMState.InstanceType`. | M | High |
| **✅ Done** (`b2d3892`, `7aa4cd5`, `a8b4f1b`). Wire `--gpu` through to real GPU provisioning (VM instance + k8s `nvidia.com/gpu`); interim: reject `--gpu` on cloud/k8s and document it, mirroring the firewall-rejection pattern. | M | High |
| Propagate GPU *model* into matching — `requirementsFromSpec` drops `GPU.Model`, so `model: h100` prices/matches the cheapest *any* GPU. | S | Medium |
| Region/zone selection (`--region` / config). Note AWS AMI is region-pinned, so a region→AMI map is needed and per-VM `Region` must be honored on teardown. Prerequisite for reliable GPU runs (SKU availability). | M | Medium |

## Theme 2 — Durable / long-running execution

| Item | Effort | Impact |
|---|---|---|
| **✅ Done** (`3587643`). **Watchdog is never renewed.** `ExtendWatchdog` is called once at handoff; nothing renews it, so a healthy detached workload self-destructs at the TTL. Add renewal (via `status`/`list --refresh` side-effect or an explicit command) and honor `Constraints.WatchdogTTL` instead of the hardcoded 30m. | M | High |
| **✅ Done** (`90e7e0b`). **No signal handling.** SIGINT/SIGTERM during provisioning bypasses the on-error VM cleanup, billing the user until the watchdog fires. Add `signal.NotifyContext`; keep adapter teardown on a fresh `context.Background()` so the cancel doesn't kill cleanup too. | M | High |
| **✅ Done** (`ecc2adc`, `746f782`). **K8s has no cost backstop.** `sleep 86400`, no `activeDeadlineSeconds`, fixed `ttlSecondsAfterFinished: 300`, no-op `ExtendWatchdog`. Emit `activeDeadlineSeconds` from `WatchdogTTL`. | M | Medium |
| **✅ Done** (`f7e1ce1`). `gc`/`recover` leak per-run SSH private keys — they destroy the VM but never remove `<state>/keys/dispatcher-<run-id>`. | S | Medium |

## Theme 3 — Provider parity

| Item | Effort | Impact |
|---|---|---|
| **✅ SSH done** (`1eb0550`, on `byo-hosts`). Artifacts retrieval is cloud-VM-only; `outputs:` silently no-ops on local/docker/ssh/k8s. Implement `docker cp` / `kubectl cp` / scp-back; at minimum warn when `outputs:` is set but unretrievable instead of returning `(nil, nil)`. *Done: SSH scp-back. Residual: docker/k8s/local.* | M | Medium |
| Per-run firewall (`--allow-ssh-from`) is Hetzner-only; AWS security groups and Azure NSGs are natural fits. Opt-in and fail-closed today, so no silent insecurity. | L | Medium |
| No spot/preemptible support, despite lowest-cost-success being the headline and the planner advising spot. Surface as "variable/evictable, not estimable" rather than a wrong precise price. | L | Medium |

## Theme 4 — Test coverage on cost-critical paths

cloudvm ≈ 32%, adapter ≈ 46% — exactly where cost and security live.

| Item | Effort | Impact |
|---|---|---|
| Executor transient-retry path (re-`Execute` + handle-swap + re-`Status`) — 0% covered. | M | High |
| `startLongRunning` (durable handoff + initial watchdog TTL) — 0% covered. | M | High |
| Watchdog SSH argv builder (`sshCmdArgs`) — 0% covered; decides `StrictHostKeyChecking`, the live MITM defense. Trivially table-testable. | S | High |
| **✅ Mostly done** (`6b800ca`). Provider teardown/list/wait argv (Destroy/Get/List/WaitReady) — 0% across all providers; no command-runner seam. Extract pure argv builders (mirror `firewall.go`) or add a `runCLI` override. *Done: `runCLI` seam + Destroy/Get/List argv pinned for all four providers. Residual: `WaitReady`/create argv still uncovered.* | L | High |
| Docker adapter has no test file; `FailureDetails` (OOM→SIGKILL, exit code, secret truncation) and `runtimeCommand` are untested pure-parse logic. | M | Medium |
| K8s job-manifest backstop unverified by tests (lands with the Theme-2 k8s fix). | M | Medium |

## Theme 5 — UX & docs polish

| Item | Effort | Impact |
|---|---|---|
| **✅ Done** (`af53c2a`). **`dispatcher run` swallows pre-execution errors → silent exit 1.** `SilenceErrors` + no print in `main.go`; `run` in a wrong/empty dir exits 1 with zero output. `plan` already handles this correctly. | S | High |
| **✅ Done** (`903d0a7`). "target not found" doesn't list available targets, despite the registry knowing them. | S | Medium |
| **✅ Done** (`903d0a7`). No `targets remove` / `rm` (add/remove asymmetry). | S | Medium |
| **✅ Mostly done** (`903d0a7`). Add `dispatcher validate [path]` — no way to check `dispatcher.yaml` without a full plan; the strict-decode engine already exists. Enrich "no feasible targets" with remediation hints. *Done: `validate` command. Residual: no-feasible-targets remediation hints.* | S–M | Medium |
| Shell completion ships but is inert — no `ValidArgsFunction` for run-ids, target-ids, or enum flags. | M | Medium |
| `--json` missing on `history` / `gc` / `recover` — the commands operators script. | M | Low |
| **✅ Done** (`0ecd487`). Corrupt run-state JSON is silently skipped by `list`, hiding stranded runs. | S | Low |
| Doc fixes: `plan.go` comment falsely claims GCP firewall support; `outputs:` documented unconditionally but VM-only; `watchdogTtl` doesn't apply to k8s; `completion` undocumented. | S | Low |

## Solid — no action

Policy / risk / approval-gate concurrency tests; run-state durability (atomic +
flocked writes, 0700 hardening, panic-recovery cleanup); the CLI/`--json`
framework; and docs-vs-code alignment overall. No TODO/FIXME/panic debt.

## Suggested order

The original top three (provisioning gap; `run` silent-failure + watchdog
renewal; provider-argv seam) have all landed, as has Theme 7 Phase 1 (with its
SSH-artifact prerequisite). Remaining priorities:

1. **Region/zone selection + GPU-model matching (Theme 1 residuals).** Needed for
   reliable GPU and region-pinned runs.
2. **Remaining cost-critical coverage (Theme 4).** Executor transient-retry,
   `startLongRunning`, `sshCmdArgs`, the Docker adapter.
3. **Docker/k8s/local artifact retrieval + spot/preemptible (Theme 3).** Extend
   the artifact retrieval just shipped for SSH; price evictable capacity honestly.

## Theme 6 — Complete CI

CI today runs gofmt / vet / build / `test -race` on the unit suite. To make it
complete:

| Item | Effort | Impact |
|---|---|---|
| **Run the `k8se2e` tests in CI** against an ephemeral cluster (`kind` or `k3d`, both run in GitHub Actions). Stand up the cluster, `go test -tags k8se2e ./internal/cloudvm/`, tear down. This is the only way the k8s execution path (init-container handoff, source delivery, real exit-code status) is exercised automatically. | M | High |
| **A live-provider integration lane** (opt-in, credentialed, manual/scheduled) that exercises at least one real cloud provider's create/wait/destroy argv against the actual CLI — covers the 0%-tested teardown paths end-to-end. Gate behind secrets so it never runs on forks/PRs. | L | Medium |
| **Coverage reporting + a floor** on the cost/security-critical packages (cloudvm, adapter, run) so coverage can't silently regress. | S | Medium |
| **golangci-lint** (or staticcheck) beyond `go vet`, plus a `govulncheck` job for dependency CVEs. | S | Medium |
| **Build & smoke-test the release binary** (`go build` is covered; add a `--version` / `--help` smoke run) and, if downloadable binaries are ever offered, a GoReleaser dry-run. | S | Low |

## Theme 7 — Bring your own hosts (IaC interop)

**✅ Phase 1 shipped** (`1eb0550`…`8ec7c8d` on the `byo-hosts` branch): the three
prerequisites and `targets import --from-json`/`--from-terraform`. The rows below
are done; k8s/cloud/`--from-state` remain cancelled.

Terraform/OpenTofu/Pulumi own the **durable substrate**; dispatcher runs
**transient jobs** on it, adding the layer they skip — pre-flight cost/risk, an
approval gate, crash-safe execution, **no control plane**. The differentiator is
that run-time layer, **not** the import (importing an SSH host is parity with
dstack SSH fleets / SkyPilot SSH node pools). So this ships as *plumbing* and the
pitch leads with the governance layer, not the parser. Full design (revised after
adversarial + product review): [terraform-interop.md](terraform-interop.md).

Two shaping decisions from review: (1) the importer is **source-agnostic** —
`targets import --from-json` reads a `dispatcher_targets` blob; `--from-terraform`
is a thin shell over `terraform output -json` — which gets Pulumi/CFN/scripts for
free and **kills the k8s/cloud/state phase-creep ladder**. (2) **SSH-only**, and
the value is *fleet sync* (idempotent re-import of a changing fleet), not the
single-host case where `targets add` already suffices.

**Prerequisites (gating):** SSH artifact retrieval (Theme 3 — `ssh.go` `Artifacts`
returns `(nil,nil)`, so `outputs:` silently no-ops on every imported host); a
shared, fail-closed SSH-field validator wired into `SaveTarget`/`targets add`; and
a real `targets add --key-file` flag (none today).

| Item | Effort | Impact |
|---|---|---|
| ✅ `targets import --from-json`/`--from-terraform` (SSH only) via a testable `runTF` seam → SSH `TargetConfig`s with **`Enabled: true`** and populated `Capabilities` (else the planner drops them — `CheckFeasibility` rejects disabled/uncapable targets). Factor `defaultCapabilitiesForKind` into `internal/target`. | M | High |
| ✅ **Validation/security:** three purpose-built validators — `host` (hostname/IP, reject `:`/`/`/`@`/leading-`-`), `user` (strict), `key_file` (path, `~`-aware) — **not** `isSafeArg` (too permissive for ssh/rsync URIs, too strict for `~` paths). Refuse to persist targets from `sensitive` outputs (`--allow-sensitive` to override); never log raw `output -json`/stderr. | M | High |
| ✅ **Persistence:** new `target.WriteTargetsFile` (atomic temp+fsync+rename, `0600`) for one managed `terraform-import.yaml`. Idempotent re-import (add/update/remove); explicit empty-list = delete-all vs no-output = no-op. **Deterministically** reject id collisions with builtins (mis-route risk) and hand-added targets, and duplicate ids within the blob — load order is filename-sorted, so "warn" is not a boundary. | S | High |
| ✅ Document the `dispatcher_targets` contract in `docs/USAGE.md`; qualify "read-only" (true for IaC state/lifecycle; dispatcher still `rm -rf`s its working dir on the host). | S | Medium |

**Cancelled as standing commitments:** k8s import (needs `K8sTargetConfig` +
`adapterForTarget` wiring), cloud-target import, and `--from-state` parsing
(raw-secret handling). Reopen only on real, repeated demand — pre-announcing them
manufactures the "why doesn't it read my EKS?" expectation.

**Non-goals (the line that keeps dispatcher a dispatcher):** no desired-state
reconciliation or drift detection; never mutate IaC-owned resources or state;
don't generate Terraform for dispatcher's own ephemeral VMs; dispatcher is not the
system of record for the substrate.
