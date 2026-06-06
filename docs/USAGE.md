# Usage

## Install

```bash
go install github.com/d0cd/dispatcher/cmd/dispatcher@latest
```

Or build from source:

```bash
git clone https://github.com/d0cd/dispatcher
cd dispatcher
go build -o dispatcher ./cmd/dispatcher
```

## Quick start

All commands default to the current directory; pass an explicit path to operate elsewhere.

```bash
dispatcher init                # Scaffold dispatcher.yaml from workload inspection
dispatcher audit               # Pre-run risk audit
dispatcher plan                # Where can it run? what will it cost?
dispatcher run                 # Execute on the recommended target
dispatcher status <run-id>     # Check on a run
dispatcher diagnose <run-id>   # Why did it fail / stall / overrun?
dispatcher stop <run-id>       # Stop and clean up
```

## Commands

### Planning and execution

| Command | Purpose |
|---|---|
| `init [path]` | Scaffold `dispatcher.yaml` from workload inspection. |
| `plan <path> [--ai]` | Generate execution plan with cost / risk analysis. `--ai` uses the LLM-driven planner. |
| `audit <path>` | Pre-run risk audit: cost surprises, missing secrets, missing Dockerfile, no-feasible-target. |
| `run <path>` | Plan and execute. See *Exit codes* below. |
| `explain <plan-id>` | Verbose recommendation for a saved plan. |

### Observability

| Command | Purpose |
|---|---|
| `status <run-id>` | Run state (reconnects to live VMs). |
| `logs <run-id>` | Stream logs (reconnects to live VMs). |
| `cost <run-id>` | Realized cost, broken down. |
| `list` | All runs with status / cost / duration. |
| `history` | Per-target historical statistics. |
| `diagnose <run-id>` | Explain why a run failed, stalled, or overran. |

### Lifecycle

| Command | Purpose |
|---|---|
| `stop <run-id>` | Terminate and clean up a running workload. |
| `gc [--dry-run]` | Find and destroy orphaned cloud VMs. |
| `recover` | Inventory cloud VMs whose local run record is missing. |

### Policy

| Command | Purpose |
|---|---|
| `approve <run-id>` | Approve a pending policy gate (out-of-band). |
| `deny <run-id>` | Deny a pending policy gate. |

### Targets

| Command | Purpose |
|---|---|
| `targets list` | List configured targets. |
| `targets add <id>` | Add a target. |
| `targets doctor <id>` | Health check a target. |

## Supported targets

| Target | Status | Requires |
|---|---|---|
| `local-process` | builtin | — |
| `local-docker` | builtin | Docker |
| `ssh` | builtin | reachable SSH host |
| `lima-vm` | builtin | `limactl` |
| `kubernetes` | builtin | `kubectl` + cluster |
| `aws-vm` | builtin | `aws` CLI |
| `gcp-vm` | builtin | `gcloud` |
| `azure-vm` | builtin | `az` |
| `hetzner-vm` | builtin | `hcloud` |

User-defined targets (any SSH host, custom cloud) are added with `dispatcher targets add`.

## `dispatcher.yaml`

Lives in the workload directory and overrides auto-detection. Decoded in strict mode — typos fail loudly.

```yaml
name: my-app                  # Workload identifier (used in VM names, log files)
image: registry/tool:latest   # Pre-built image; skips build, runs as-is
command: ["python", "main.py"] # Override detected entrypoint
gpu:                          # GPU requirements
  count: 1
  model: h100
  framework: pytorch
service:                      # Long-running service
  port: 8080
sandbox: true                 # Run in an isolated sandbox target
maxCost: 50                   # Hard budget in USD
maxTime: 2h                   # Wall-clock cap
target: hetzner-vm            # Force a specific target
outputs:                      # Workload-relative paths to retrieve before cleanup
  - results/
  - model.bin
watchdogTtl: 30m              # Cloud VM self-destruct timer (default 30m)
```

State lives in `.dispatcher/` (per-project, found by walking up from cwd) or `~/.dispatcher/` (fallback). Override with `$DISPATCHER_HOME`.

## Live pricing

Real instance pricing is fetched at plan time:

- **Azure**: public Retail Prices API, no auth.
- **AWS**: public Bulk Price List API, no auth.
- **GCP**: Cloud Billing Catalog via `gcloud auth print-access-token`.
- **Hetzner**: `hcloud server-type list` (requires hcloud token).

Providers without configured credentials are skipped; pricing falls back to built-in estimates with `confidence: low`.

Bypass pricing in tooling with `DISPATCHER_DISABLE_LIVE_PRICING=1`.

## AI assistance

When [aitelier](https://github.com/aitelier/aitelier) is reachable, `plan --ai`, `audit`, and `diagnose` use a Claude agent driving an in-process MCP server. Tools exposed to the LLM are sandboxed to the workload root; tool output is treated as untrusted (filenames, log tails, etc. cannot manipulate the LLM via prompt injection). Without aitelier, deterministic rulesets handle the same commands.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Setup / plan / cleanup failure (no feasible target, validation error, etc.). |
| 2 | Approval denied. |
| 3 | Workload-level failure (non-zero exit, OOM, budget exceeded). |

## Approval flow

Runs whose plan includes policy requirements (GPU, high cost, public endpoints, secrets on external providers) block until approved.

- **Interactive (default)**: terminal prompt at the running process.
- **`--yes` flag**: auto-approve, stamped `yes-flag:<user>` in the audit record.
- **Out-of-band**: `dispatcher approve <run-id>` in another shell connects to the run's Unix socket and delivers the decision. The dispatcher run process must still be active.

Approvals are recorded on the run state for audit; see [SECURITY.md](SECURITY.md) for the trust model.
