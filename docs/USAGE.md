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

Shell completion is available via the standard Cobra command, e.g.:

```bash
dispatcher completion bash > /etc/bash_completion.d/dispatcher   # or zsh/fish/powershell
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
| `init [path] [--force]` | Scaffold `dispatcher.yaml` from workload inspection. `--force`/`-f` overwrites an existing file. |
| `plan <path>` | Generate execution plan with cost / risk analysis. Flags: `--ai` (LLM-driven planner), `--target`, `--optimize cost\|speed`, `--max-cost <usd>`, `--gpu <spec>`. |
| `validate [path]` | Validate `dispatcher.yaml` (schema + semantic checks) without planning or running. |
| `audit <path>` | Pre-run risk audit: cost surprises, missing secrets, missing Dockerfile, no-feasible-target. |
| `run <path>` | Plan and execute. Flags: `--target`, `--optimize cost\|speed`, `--max-cost <usd>`, `--timeout <dur>`, `--gpu <spec>`, `--watchdog-ttl <dur>`, `--retry-transient`, `--allow-ssh-from <cidr>` (per-run SSH firewall; Hetzner only — see [SECURITY.md](SECURITY.md)), `--yes`. See *Exit codes* below. |
| `explain <plan-id>` | Verbose recommendation for a saved plan. |

### Observability

| Command | Purpose |
|---|---|
| `status <run-id>` | Run state (reconnects to live VMs; persists discovered terminal states). Reconnecting to a still-running cloud run also extends its watchdog (see `renew`). |
| `logs <run-id>` | Stream logs (reconnects to live VMs). |
| `cost <run-id>` | Realized cost, broken down. |
| `list [--refresh]` | All runs with status / cost / duration. `--refresh` reconnects to non-terminal runs and updates state. Idle non-terminal runs (>6h) are flagged `STALE` so you can spot orphans. |
| `history` | Per-target historical statistics. |
| `diagnose <run-id>` | Explain why a run failed, stalled, or overran. |
| `bill` | Per-cloud dispatcher-tagged spend month-to-date (AWS Cost Explorer, Azure Consumption; GCP requires BigQuery export; Hetzner falls back to dispatcher's tracking since no public billing API). |

### Lifecycle

| Command | Purpose |
|---|---|
| `stop <run-id> [--force]` | Terminate and clean up a running workload. `--force` finalizes a stranded run whose record can no longer be reconnected (no handle state, provider unreachable), marking it terminal without cleanup — reclaim any leftover resources with `gc`. |
| `renew <run-id>` | Extend a running cloud run's self-destruct watchdog by its configured TTL. Run periodically (cron / systemd timer) to keep an unattended long-running workload alive past its watchdog TTL. |
| `gc [--dry-run] [--yes]` | Find and destroy orphaned cloud VMs. Prompts for confirmation before destroying; `--dry-run` previews without destroying, `--yes`/`-y` skips the prompt. |
| `recover [--attach]` | Inventory cloud VMs whose local run record is missing. `--attach` runs `status` against each recoverable run to refresh and persist live state. |

### Policy

| Command | Purpose |
|---|---|
| `approve <run-id>` | Approve a pending policy gate (out-of-band). |
| `deny <run-id>` | Deny a pending policy gate. |

### Targets

| Command | Purpose |
|---|---|
| `targets list` | List configured targets. |
| `targets add <id>` | Add a target. `--kind docker\|ssh\|kubernetes\|cloud-vm` (default `docker`), `--enabled` (default true), and `--host/--user/--port/--key-file` for SSH. |
| `targets remove <id>` | Remove a target you added (alias `rm`). |
| `targets import` | Import hosts as SSH targets (see [Bring your own hosts](#bring-your-own-hosts)). |
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

## Bring your own hosts

If your hosts are already provisioned — by Terraform/OpenTofu, Pulumi, or any
script — `dispatcher targets import` registers them as SSH targets so the
plan/cost/risk/approval/teardown layer can run jobs on them. Dispatcher reads
your infra; it never mutates it.

```bash
dispatcher targets import --from-json hosts.json        # or - for stdin
dispatcher targets import --from-terraform ./infra      # runs `terraform output -json`
dispatcher targets import --from-terraform ./infra --dry-run
```

The contract is a single `dispatcher_targets` value — a `{"targets":[...]}`
object where each entry maps to an SSH target:

```json
{ "targets": [
  { "id": "trainer", "kind": "ssh",
    "ssh": { "host": "203.0.113.10", "user": "ubuntu", "port": 22, "key_file": "/home/me/.ssh/id_ed25519" } }
] }
```

For Terraform, expose exactly that as an output named `dispatcher_targets`:

```hcl
output "dispatcher_targets" {
  value = { targets = [{
    id   = "trainer"
    kind = "ssh"
    ssh  = { host = aws_instance.trainer.public_ip, user = "ubuntu", port = 22, key_file = "/home/me/.ssh/id_ed25519" }
  }] }
}
```

Notes:

- **SSH only** today; other kinds are rejected at import.
- Prints an add/update/remove **plan and asks for confirmation**; pass `--yes`
  (`-y`) to skip the prompt for scripting.
- **Re-import reconciles** add/update/remove against the previous import and
  never shadows a target that already exists (builtin, hand-added, or project
  `dispatcher.yaml`). An empty `targets` list clears all imported targets; an
  absent `dispatcher_targets` output is a no-op.
- **Sensitive** Terraform outputs are refused unless `--allow-sensitive`;
  `--workspace` reads a specific Terraform workspace.
- `host`/`user`/`key_file` are validated at the boundary (no shell or ssh-option
  metacharacters); a leading `~` in `key_file` is expanded. A missing or
  group/world-accessible key is warned (`--strict` makes it an error).
- `--binary` selects `terraform` (default) or `tofu`.

## `dispatcher.yaml`

Lives in the workload directory and overrides auto-detection. Decoded in strict mode — typos fail loudly.

```yaml
name: my-app                  # Workload identifier (used in VM names, log files)
image: registry/tool:latest   # Pre-built image; skips build, runs as-is
command: ["python", "main.py"] # Override detected entrypoint
gpu:                          # GPU requirements
  count: 1
  model: a100                 # pin a catalog model (a100, l4, t4, v100, a10g); unset = cheapest GPU
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
watchdogTtl: 30m              # Cloud-VM self-destruct timer (default 30m; renewed while supervised). k8s Jobs use maxTime → activeDeadlineSeconds instead.
retryTransientFailures: true  # Retry once on transient failure (OOM/SIGKILL); CLI --retry-transient wins
```

**GPU workloads:** dispatcher provisions the catalog instance that matches the GPU requirement. If no catalog instance matches (an unknown `gpu.model`, or a provider with no GPU inventory), `plan` flags a `gpu-unschedulable` risk and `run` refuses rather than silently launching a CPU-only box.

State lives in `.dispatcher/` (per-project, found by walking up from cwd) or `~/.dispatcher/` (fallback). Override with `$DISPATCHER_HOME` or the global `--state-dir` flag.

## Global flags

Available on every command:

| Flag | Purpose |
|---|---|
| `--output text\|json` (`--json`) | Emit machine-readable JSON instead of prose. Supported on `plan`, `audit`, `status`, `list`, `cost`, `bill`. |
| `--no-color` | Disable colored output (also honors `$NO_COLOR` and non-TTY). |
| `--state-dir <path>` | Override the state directory (equivalent to `$DISPATCHER_HOME`); useful for `recover`/`gc` against a restored backup. |

## Cost display

Cost values display with adaptive precision:

- `<$0.01` → 4 decimals (`$0.0007` for a sub-cent cax11 run).
- `≥$0.01` → 2 decimals.
- Zero or unknown → blank.

This is uniform across `list`, `status`, `cost`, `history`, `run`, `plan`, and `bill`. Sub-cent values are *stored* at full precision in `history.jsonl`; only display rounds.

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

For `dispatcher run`:

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Setup / plan / cleanup failure (no feasible target, validation error, etc.). |
| 2 | Approval denied. |
| 3 | Workload-level failure (non-zero exit, OOM, budget exceeded). |

`dispatcher audit` reuses codes 2 and 3 with audit-specific meanings (2 = blocked by a risk finding, 3 = AI produced non-conforming output); see `dispatcher audit --help`.

## Approval flow

Runs whose plan includes policy requirements (GPU, high cost, public endpoints, secrets on external providers) block until approved.

- **Interactive (default)**: terminal prompt at the running process.
- **`--yes` flag**: auto-approve, stamped `yes-flag:<user>` in the audit record.
- **Out-of-band**: `dispatcher approve <run-id>` in another shell connects to the run's Unix socket and delivers the decision. The dispatcher run process must still be active.

Approvals are recorded on the run state for audit; see [SECURITY.md](SECURITY.md) for the trust model.
