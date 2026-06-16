# Roadmap

Remaining work on dispatcher, from a cross-cutting audit (feature gaps, provider
parity, docs-vs-code, test coverage, UX, robustness). The tool is mature — three
prior audit rounds closed the security/correctness backlog and the CLI surface is
complete — so what's left is a coherent set of *completeness* gaps, headlined by
one load-bearing wiring fix.

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
| Thread the catalog-selected instance type into `VMOptions`, reusing the same-provider selection that priced the plan. Populate the currently-dead `CloudVMState.InstanceType`. | M | High |
| Wire `--gpu` through to real GPU provisioning (VM instance + k8s `nvidia.com/gpu`); interim: reject `--gpu` on cloud/k8s and document it, mirroring the firewall-rejection pattern. | M | High |
| Propagate GPU *model* into matching — `requirementsFromSpec` drops `GPU.Model`, so `model: h100` prices/matches the cheapest *any* GPU. | S | Medium |
| Region/zone selection (`--region` / config). Note AWS AMI is region-pinned, so a region→AMI map is needed and per-VM `Region` must be honored on teardown. Prerequisite for reliable GPU runs (SKU availability). | M | Medium |

## Theme 2 — Durable / long-running execution

| Item | Effort | Impact |
|---|---|---|
| **Watchdog is never renewed.** `ExtendWatchdog` is called once at handoff; nothing renews it, so a healthy detached workload self-destructs at the TTL. Add renewal (via `status`/`list --refresh` side-effect or an explicit command) and honor `Constraints.WatchdogTTL` instead of the hardcoded 30m. | M | High |
| **No signal handling.** SIGINT/SIGTERM during provisioning bypasses the on-error VM cleanup, billing the user until the watchdog fires. Add `signal.NotifyContext`; keep adapter teardown on a fresh `context.Background()` so the cancel doesn't kill cleanup too. | M | High |
| **K8s has no cost backstop.** `sleep 86400`, no `activeDeadlineSeconds`, fixed `ttlSecondsAfterFinished: 300`, no-op `ExtendWatchdog`. Emit `activeDeadlineSeconds` from `WatchdogTTL`. | M | Medium |
| `gc`/`recover` leak per-run SSH private keys — they destroy the VM but never remove `<state>/keys/dispatcher-<run-id>`. | S | Medium |

## Theme 3 — Provider parity

| Item | Effort | Impact |
|---|---|---|
| Artifacts retrieval is cloud-VM-only; `outputs:` silently no-ops on local/docker/ssh/k8s. Implement `docker cp` / `kubectl cp` / scp-back; at minimum warn when `outputs:` is set but unretrievable instead of returning `(nil, nil)`. | M | Medium |
| Per-run firewall (`--allow-ssh-from`) is Hetzner-only; AWS security groups and Azure NSGs are natural fits. Opt-in and fail-closed today, so no silent insecurity. | L | Medium |
| No spot/preemptible support, despite lowest-cost-success being the headline and the planner advising spot. Surface as "variable/evictable, not estimable" rather than a wrong precise price. | L | Medium |

## Theme 4 — Test coverage on cost-critical paths

cloudvm ≈ 32%, adapter ≈ 46% — exactly where cost and security live.

| Item | Effort | Impact |
|---|---|---|
| Executor transient-retry path (re-`Execute` + handle-swap + re-`Status`) — 0% covered. | M | High |
| `startLongRunning` (durable handoff + initial watchdog TTL) — 0% covered. | M | High |
| Watchdog SSH argv builder (`sshCmdArgs`) — 0% covered; decides `StrictHostKeyChecking`, the live MITM defense. Trivially table-testable. | S | High |
| Provider teardown/list/wait argv (Destroy/Get/List/WaitReady) — 0% across all providers; no command-runner seam. Extract pure argv builders (mirror `firewall.go`) or add a `runCLI` override. | L | High |
| Docker adapter has no test file; `FailureDetails` (OOM→SIGKILL, exit code, secret truncation) and `runtimeCommand` are untested pure-parse logic. | M | Medium |
| K8s job-manifest backstop unverified by tests (lands with the Theme-2 k8s fix). | M | Medium |

## Theme 5 — UX & docs polish

| Item | Effort | Impact |
|---|---|---|
| **`dispatcher run` swallows pre-execution errors → silent exit 1.** `SilenceErrors` + no print in `main.go`; `run` in a wrong/empty dir exits 1 with zero output. `plan` already handles this correctly. | S | High |
| "target not found" doesn't list available targets, despite the registry knowing them. | S | Medium |
| No `targets remove` / `rm` (add/remove asymmetry). | S | Medium |
| Add `dispatcher validate [path]` — no way to check `dispatcher.yaml` without a full plan; the strict-decode engine already exists. Enrich "no feasible targets" with remediation hints. | S–M | Medium |
| Shell completion ships but is inert — no `ValidArgsFunction` for run-ids, target-ids, or enum flags. | M | Medium |
| `--json` missing on `history` / `gc` / `recover` — the commands operators script. | M | Low |
| Corrupt run-state JSON is silently skipped by `list`, hiding stranded runs. | S | Low |
| Doc fixes: `plan.go` comment falsely claims GCP firewall support; `outputs:` documented unconditionally but VM-only; `watchdogTtl` doesn't apply to k8s; `completion` undocumented. | S | Low |

## Solid — no action

Policy / risk / approval-gate concurrency tests; run-state durability (atomic +
flocked writes, 0700 hardening, panic-recovery cleanup); the CLI/`--json`
framework; and docs-vs-code alignment overall. No TODO/FIXME/panic debt.

## Suggested order

1. **Theme 1 — provisioning gap.** Makes pricing honest and `--gpu` real.
2. **`run` silent-failure (Theme 5) + watchdog renewal (Theme 2).** Cheapest large UX + durability win.
3. **Provider-argv test seam (Theme 4).** Retires the biggest risk-weighted coverage hole on the money paths.
