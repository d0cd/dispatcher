# Roadmap

Remaining work on dispatcher, grouped by theme. The tool is mature — the
provisioning/pricing pipeline, durable execution, the bring-your-own-hosts
importer, and the audit backlog have all landed — so what's left is a coherent
set of *completeness* gaps, plus new capabilities: confidential computing (in
flight), efficiency/observability borrows, and low-latency burst execution.

Effort: **S** ≈ <½ day · **M** ≈ 1–2 days · **L** ≈ 3+ days. Impact is user-facing
severity.

## Theme 1 — Provisioning residuals

| Item | Effort | Impact |
|---|---|---|
| ✅ Region/zone selection (`--region` / `region:`; flag wins). Region rides the plan (create) and `CloudVMState` (reconnect); providers gain `SetRegion` so **teardown hits the VM's region** (was leaking non-default-region AWS VMs). AWS resolves its region-correct AMI via SSM (no hand-maintained region→AMI map). Feasibility isn't region-filtered yet — GPU-SKU-per-region is a follow-up. | M | Medium |

## Theme 2 — Provider parity

| Item | Effort | Impact |
|---|---|---|
| Artifact retrieval on docker/k8s/local (`outputs:`). SSH and cloud-VM are done; implement `docker cp` / `kubectl cp` / local copy, or at minimum warn when `outputs:` is set but unretrievable. | M | Medium |
| Per-run firewall (`--allow-ssh-from`) is Hetzner-only; AWS security groups and Azure NSGs are natural fits. Opt-in and fail-closed today, so no silent insecurity. | L | Medium |
| No spot/preemptible support, despite lowest-cost-success being the headline and the planner advising spot. Surface as "variable/evictable, not estimable" rather than a wrong precise price. | L | Medium |

## Theme 3 — Test coverage on cost-critical paths

Most of this landed as it went — the roadmap below is kept for the residual.

| Item | Effort | Impact |
|---|---|---|
| ✅ Executor transient-retry path — covered (`executor_retry_test.go`). | M | High |
| ✅ `startLongRunning` (durable handoff + initial watchdog TTL) — 78.6% covered. | M | High |
| ✅ Watchdog SSH argv builder (`sshCmdArgs`) — 100% (`watchdog_argv_test.go`); the `StrictHostKeyChecking` MITM defense is pinned. | S | High |
| ✅ Runtime/parse logic — `parseDockerInspect` 100%, `RuntimeCommand`/`runtimeCommand` 100%; the docker adapter now has tests. | M | Medium |
| Residual: `FailureDetails` (the `docker inspect` exec glue) and each provider's `WaitReady` are still 0% — both need a command seam or a live SSH host to exercise, low value to force. Provider create argv is now pinned for confidential/region flags. | M | Low |

## Theme 4 — UX & docs polish

| Item | Effort | Impact |
|---|---|---|
| Shell completion ships but is inert — no `ValidArgsFunction` for run-ids, target-ids, or enum flags. | M | Medium |
| `--json` missing on `history` / `gc` / `recover` — the commands operators script. | M | Low |

## Theme 5 — Complete CI

CI runs gofmt / vet / build / `test -race`, plus (now) a coverage report, a
binary build+smoke, and a non-blocking `govulncheck`. Remaining:

| Item | Effort | Impact |
|---|---|---|
| **Run the `k8se2e` tests in CI** against an ephemeral cluster (`kind` or `k3d`). Stand up the cluster, `go test -tags k8se2e ./internal/cloudvm/`, tear down — the only automated exercise of the k8s execution path. | M | High |
| **Run `sshe2e` / `tfe2e`** (SSH artifact retrieval; real `terraform output`) against localhost ssh and a terraform binary in CI. | S | Medium |
| **A live-provider integration lane** (opt-in, credentialed, manual/scheduled) exercising at least one real cloud provider's create/wait/destroy against the actual CLI. Gate behind secrets so it never runs on forks/PRs. | L | Medium |
| ✅ **Coverage reporting** — CI prints the total; a per-package *floor* on cost/security-critical packages (cloudvm, adapter, run, target) is still open (kept off to avoid flaky reds until baselines are pinned). | S | Medium |
| ✅ **govulncheck** job (non-blocking so a fresh stdlib advisory doesn't red the build pre-patch). **staticcheck** is deferred: 4 pre-existing findings (2 `ST1005` in `lima.go` — proper-noun false positives, 1 `ST1005` in `run.go`, 1 `U1000` unused var in `runtime.go`) would need cleanup first. | S | Medium |
| **Build & smoke-test the release binary** (`--version` / `--help` smoke run); if downloadable binaries are offered, a GoReleaser dry-run. | S | Low |

## Theme 6 — Confidential computing (secure jobs)

Run a workload on a TEE-backed VM (hardware-encrypted memory) of a requested type
**and prove it via attestation**. Design: [confidential-computing.md](confidential-computing.md).
The deterministic-core gate (requirement/capability/feasibility) shipped as a
boolean; the rest evolves it to the typed model below.

| Item | Effort | Impact |
|---|---|---|
| ✅ Deterministic core: `confidential` requirement + capability + feasibility rejection (shipped as a bool). | M | Medium |
| ✅ **Typed model** — top-level `confidential: {type, attestation, measurements, minTCB}`; typed feasibility (mirrors GPU-model matching). | S | Medium |
| ✅ **Provisioning** — per-provider `CreateVM` flags (GCP `--confidential-compute-type` + `--min-cpu-platform="AMD Milan"` for SEV-SNP, AWS `AmdSevSnp=enabled`, Azure `ConfidentialVM`), argv-tested; confidential-capable builtins/catalog by type; Hetzner/Lima rejected. | M | Medium |
| ✅ **Verifier cores + trust anchor** — SEV-SNP report/chain + MAA token verifiers (stdlib, synthetic-tested); pinned AMD ARK roots (Milan/Genoa/Turin, embedded from KDS); measurement allowlist + minTCB; readiness-gated registration (fails closed *before* provisioning); audit surfacing in `status`/`diagnose` (R13). | L | High |
| **Live evidence fetch** — the measured guest-agent that binds the per-run nonce + in-TEE key (`REPORT_DATA=H(N‖key)`) and returns the report/token, flipping the attesters to *ready*. Needs a live confidential VM (see `experiments/confidential-attestation`). The remaining gate to a real guarantee. | L | High |
| **Format-bind + secret wrapping** — run the capture experiment (GCP now emits v4 SEV-SNP reports) to pin the ABI/claim layout as golden vectors; then secret wrapping (R9 — source/secrets only into the proven TEE), VCEK revocation, MAA per-component TCB. | M | High |
| Nitro Enclaves / k8s Confidential Containers — different, larger models. Out of scope until demand. | — | — |

## Theme 7 — Efficiency & observability (borrowed from imbue-ai/offload)

`offload` is a parallel *test* runner, but several of its mechanics transfer to
dispatcher's placer/runner model. (Its historical-duration feedback loop we
already have — `internal/cost/history.go` records `ActualDuration`/`ActualCost`
and `EstimateCostWithHistory` uses the median + a confidence recalibration.)

| Item | Effort | Impact |
|---|---|---|
| ✅ **Per-phase run timeline + `dispatcher trace`** — each phase's entry time is stamped on the run state (`Timeline []PhaseMark`, seeded at `Created`, appended on every transition incl. `SetError`/`MarkTerminal`); `dispatcher trace <run-id>` emits Chrome/Perfetto trace JSON. The measurement foundation for the latency work (Theme 8). | M | High |
| ✅ **Content-addressed build cache** — the docker adapter records a content digest (Dockerfile + source tree) as an image label and skips the rebuild when `:latest` already carries it. Single-image (no digest-tag accumulation). Cross-host/registry caching is a follow-up. | M | Medium |
| ✅ **Flaky classification from history** — `HistoryStore.Flakiness` flags a workload+target with mixed pass/fail history; surfaced as a `flaky-history` risk in the planner's target evaluation. (Deterministic `plan` doesn't use history, so it's the planner path for now.) | M | Medium |
| ✅ **Env-var expansion in `dispatcher.yaml`** (`${VAR}` / `${VAR:-default}`), applied in `LoadConfig` before the strict decode. Only the braced form expands; a bare `$VAR` is left for remote expansion. | S | Low |

Not borrowed, deliberately: split-requeue **hedging** (speculative duplicate
execution is unsafe for a single side-effecting workload — only relevant if
fan-out lands), and offload's committed/merge-driver history (dispatcher's
history is local state-dir, not shared).

## Theme 8 — Low-latency burst execution

`offload`'s superpower is fanning out across ~200 sub-second sandboxes;
dispatcher's cloud VMs boot in *minutes*, so it's the wrong shape for short or
bursty work. Two coupled pieces — plus design decisions to settle first, because
this stretches dispatcher's identity from "place one workload well" toward "burst
many."

Design: [low-latency-execution.md](low-latency-execution.md). Decisions settled:
backends built in order **Firecracker → cloud-native fast → Modal**; **fan-out is
in-lane**, declared via a `shard:` config block (supporting both a fixed `count`
and a `discover` command).

| Item | Effort | Impact |
|---|---|---|
| **Firecracker microVM backend** — a `FirecrackerProvider` behind `CloudVMAdapter` (reuses SSH/rsync/runner/cleanup). Offline core (config-JSON + launch argv) is testable; the live launch needs a KVM host. | L | High |
| **Cloud-native fast backend** — prebaked images / warm pools on the existing cloud providers to cut boot from minutes toward seconds. | M | Medium |
| **Modal backend** — sub-second sandboxes via the modal CLI; weigh the external-dep cost against the 3-direct-dep minimum. | M | High |
| **Startup-latency feasibility** — a latency dimension so the planner prefers fast backends for short jobs, VMs for long-running ones. | S | Medium |
| ✅ **Sharding core** — `shard:`/`aggregate:` config → `ShardSpec`; `shard.Plan` (count + discover split), `shard.Discover`, `Assignment.Env`, and `shard.Engine` (bounded-parallel, fail/retry/continue, race-clean). All deterministic + tested. | L | High |
| ✅ **Shard fan-out wired (count + discover)** — `runRun` branches to `runSharded`; each shard is a full dispatcher run with `SHARD_INDEX`/`SHARD_COUNT` injected via `WorkloadSpec.Env` (threaded through the 4 secret-handling env helpers), and discover-mode work items delivered via `SHARD_ITEMS_FILE`. Approval isn't bypassed. **Both modes verified end-to-end over local-process.** | L | High |
| ✅ **Shard output aggregation** — each shard-run's artifacts dir is symlinked under `runs/<plan>-shards/shard-<index>` (one place, no copy). No-op for local (outputs in-place); real for cloud/ssh. | M | Medium |
| **Shard refinements** — (1) discover-mode on docker/cloud (item file needs per-shard staging; local works today); (2) LPT scheduling — reorder assignments by `cost/history.go` durations once per-shard history accrues (engine runs index-order today). | M | Low |

Depends on Theme 7's phase-trace (you can't optimize burst latency you can't
measure) and reuses the existing duration history for scheduling.

## Solid — no action

Policy / risk / approval-gate concurrency tests; run-state durability (atomic +
flocked writes, 0700 hardening, panic-recovery cleanup); the CLI/`--json`
framework; provisioning/pricing/GPU wiring; durable execution (watchdog renewal,
signal teardown, k8s deadline); the bring-your-own-hosts importer; and
docs-vs-code alignment overall. No TODO/FIXME/panic debt.

## Suggested order

1. ✅ **Run timeline + `dispatcher trace` (Theme 7).** Shipped — the measurement foundation for the latency work.
2. ✅ **Region/zone selection (Theme 1).** Shipped with correct teardown + AWS SSM AMI resolution.
3. ✅ **Cost-critical coverage (Theme 3).** Retry, `startLongRunning`, `sshCmdArgs`, docker parse/runtime all covered; residual (`FailureDetails`/`WaitReady`) needs seams, low value.
4. **Finish confidential attestation (Theme 6).** *On hold* — gated on a live GCP capture (format-bind experiment), then the evidence fetch + secret wrapping.
5. **Complete CI (Theme 5).** Wire the e2e suites and a coverage floor so the above can't silently regress.
6. **Low-latency burst execution (Theme 8).** Settle the backend/fan-out decisions first, then the sandbox adapter, then fan-out.
