# Roadmap

Remaining work on dispatcher, grouped by theme. The tool is mature — the
provisioning/pricing pipeline, durable execution, the bring-your-own-hosts
importer, and the audit backlog have all landed — so what's left is a coherent
set of *completeness* gaps. (Shipped feature designs live in their own docs, e.g.
[terraform-interop.md](terraform-interop.md).)

Effort: **S** ≈ <½ day · **M** ≈ 1–2 days · **L** ≈ 3+ days. Impact is user-facing
severity.

## Theme 1 — Provisioning residuals

| Item | Effort | Impact |
|---|---|---|
| Region/zone selection (`--region` / config). AWS AMIs are region-pinned, so a region→AMI map is needed and per-VM `Region` must be honored on teardown. Prerequisite for reliable GPU runs (SKU availability). | M | Medium |

## Theme 2 — Provider parity

| Item | Effort | Impact |
|---|---|---|
| Artifact retrieval on docker/k8s/local (`outputs:`). SSH and cloud-VM are done; implement `docker cp` / `kubectl cp` / local copy, or at minimum warn when `outputs:` is set but unretrievable. | M | Medium |
| Per-run firewall (`--allow-ssh-from`) is Hetzner-only; AWS security groups and Azure NSGs are natural fits. Opt-in and fail-closed today, so no silent insecurity. | L | Medium |
| No spot/preemptible support, despite lowest-cost-success being the headline and the planner advising spot. Surface as "variable/evictable, not estimable" rather than a wrong precise price. | L | Medium |

## Theme 3 — Test coverage on cost-critical paths

| Item | Effort | Impact |
|---|---|---|
| Executor transient-retry path (re-`Execute` + handle-swap + re-`Status`) — 0% covered. | M | High |
| `startLongRunning` (durable handoff + initial watchdog TTL) — 0% covered. | M | High |
| Watchdog SSH argv builder (`sshCmdArgs`) — 0% covered; decides `StrictHostKeyChecking`, the live MITM defense. Trivially table-testable. | S | High |
| Provider `WaitReady`/create argv — still 0% (Destroy/Get/List now pinned via the `runCLI` seam). | M | Medium |
| Docker adapter has no test file; `FailureDetails` (OOM→SIGKILL, exit code, secret truncation) and `runtimeCommand` are untested pure-parse logic. | M | Medium |

## Theme 4 — UX & docs polish

| Item | Effort | Impact |
|---|---|---|
| Shell completion ships but is inert — no `ValidArgsFunction` for run-ids, target-ids, or enum flags. | M | Medium |
| `--json` missing on `history` / `gc` / `recover` — the commands operators script. | M | Low |
| Doc fixes: `watchdogTtl` doesn't apply to k8s; `completion` undocumented. | S | Low |

## Theme 5 — Complete CI

CI today runs gofmt / vet / build / `test -race` on the unit suite. To make it
complete:

| Item | Effort | Impact |
|---|---|---|
| **Run the `k8se2e` tests in CI** against an ephemeral cluster (`kind` or `k3d`). Stand up the cluster, `go test -tags k8se2e ./internal/cloudvm/`, tear down — the only automated exercise of the k8s execution path. | M | High |
| **Run `sshe2e` / `tfe2e`** (SSH artifact retrieval; real `terraform output`) against localhost ssh and a terraform binary in CI. | S | Medium |
| **A live-provider integration lane** (opt-in, credentialed, manual/scheduled) exercising at least one real cloud provider's create/wait/destroy against the actual CLI. Gate behind secrets so it never runs on forks/PRs. | L | Medium |
| **Coverage reporting + a floor** on the cost/security-critical packages (cloudvm, adapter, run, target). | S | Medium |
| **golangci-lint** (or staticcheck) beyond `go vet`, plus a `govulncheck` job for dependency CVEs. | S | Medium |
| **Build & smoke-test the release binary** (`--version` / `--help` smoke run); if downloadable binaries are offered, a GoReleaser dry-run. | S | Low |

## Solid — no action

Policy / risk / approval-gate concurrency tests; run-state durability (atomic +
flocked writes, 0700 hardening, panic-recovery cleanup); the CLI/`--json`
framework; provisioning/pricing/GPU wiring; durable execution (watchdog renewal,
signal teardown, k8s deadline); the bring-your-own-hosts importer; and
docs-vs-code alignment overall. No TODO/FIXME/panic debt.

## Suggested order

1. **Region/zone selection (Theme 1).** Needed for reliable GPU and region-pinned runs.
2. **Cost-critical coverage (Theme 3).** Executor transient-retry, `startLongRunning`, `sshCmdArgs`, the Docker adapter.
3. **Complete CI (Theme 5).** Wire the e2e suites and a coverage floor so the above can't silently regress.
