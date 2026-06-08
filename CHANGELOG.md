# Changelog

## Unreleased

### Added
- `dispatcher bill` — per-cloud dispatcher-tagged spend month-to-date.
  AWS uses Cost Explorer; Azure uses consumption API; GCP requires
  BigQuery export setup (documented); Hetzner falls back to dispatcher's
  own tracking since hcloud has no billing endpoint.
- `dispatcher list --refresh` — reconnect to non-terminal durable runs
  and persist any discovered terminal state.
- `dispatcher recover --attach` — after listing orphaned VMs, refresh
  each recoverable run's state. Per-run 15s timeout so one slow provider
  doesn't block the loop.
- `STALE` flag on `dispatcher list` for non-terminal runs idle >6h.
- Right-sizing risk in plans: workloads declaring `gpu` without
  `gpu.model` get a `right-sizing` Risk noting the planner picks the
  cheapest GPU instance, which may not match expectations.
- `LICENSE` (MIT).
- GitHub Actions CI: gofmt, vet, build, test --race.
- `CONTRIBUTING.md`.
- `K8sAdapter.FailureDetails` — k8s pod terminations now report exit
  code / signal / OOMKilled, enabling the retry-transient classifier.

### Changed
- Cost values stored at 4-decimal precision (was: truncated to whole
  cents at storage time). Sub-cent runs are no longer silently zeroed
  in `history.jsonl`. Display layer (`formatCost`) chooses precision.
- `formatCost` used uniformly across `list`, `status`, `cost`, `history`,
  `run`, `plan`, `stop`, and `bill`.
- `dispatcher status` now persists any terminal state discovered via
  live reconnect, so the next `dispatcher list` doesn't show "running"
  for a VM that's gone.
- `recordRunHistory` now fires for failed runs too, so `dispatcher bill`
  and historical-confidence don't undercount.
- `RunHistory` records carry `finalState` and `failureMessage` for
  post-hoc analysis of failed runs.
- Watchdog deadline is computed at VM-boot time inside cloud-init
  (was: at script-generation time). Slow provisioning no longer
  pre-expires the watchdog.
- `ComputeLiveCost` and `HistoryStore.SpendSince` clamp negative values
  to zero — clock skew or arithmetic bugs can't produce negative spend.
- `bill` AWS/Azure parsers report skipped malformed cost entries
  rather than silently treating them as zero.
- Docs restructured: `README.md` (index) → `docs/{DESIGN,USAGE,SECURITY}.md`.
  Deleted `dispatcher_design_doc.md`, `docs/PLAN.md`.

### Removed
- `DotEnvArgs` (deprecated, no callers).
- `migrateLegacy` from history (no legacy `history.json` to migrate from).
- Duplicate `writeSecureTempFile` in cloudvm (unified under
  `adapter.WriteSecureTempFile`).
- Hand-rolled string helpers in `recover.go` (`indexOf`, `containsAll`).

### Security
- Per-run Unix-socket approval gate replaces the HMAC-signed JSON
  file format (eliminated signature replay, torn writes, requirements
  mutation, secret-file leak classes).
- Per-run SSH wrapper script eliminates rsync `-e` injection.
- Cloud CLI argument discipline: file inputs for UserData, repeated
  flags for tags, label-charset validation at the boundary.
- `inspect_workload` MCP tool contains paths to the configured workload
  root.
- UNTRUSTED markers in plan and audit system prompts.
- `state.ensureSecureDir` enforces 0700 on pre-existing dirs;
  `syscall.Umask(0o077)` at process start.

## v0.1.0 — 2026-05-19
- Initial public release.
