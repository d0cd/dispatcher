# Dispatcher Design

**Status:** Implemented
**Project name:** Dispatcher
**One-line description:** Dispatcher plans, prices, and runs workloads across configured execution targets.

## Overview

Dispatcher is an AI-assisted workload planner and runner. Given a workload and user constraints, it answers where a workload can run, what it will cost, what might go wrong, and executes the chosen plan with observability and cleanup.

Core loop:

```
Workload -> Inspect -> Plan -> Cost/Risk -> Approve -> Run -> Observe -> Cleanup
```

Architectural principle:

```
The agent proposes.
Deterministic tools verify.
Policy gates risky actions.
The executor runs approved plans.
The reconciler audits what happened.
```

## What's Built

### CLI Commands (17)

```bash
dispatcher init [path]              # Scaffold dispatcher.yaml from workload inspection
dispatcher plan <path> [--ai]       # Generate execution plan with cost/risk analysis
dispatcher audit <path>             # Pre-run risk audit (workload + targets)
dispatcher run <path>               # Plan and execute a workload
dispatcher stop <run-id>            # Terminate and clean up a running workload
dispatcher status <run-id>          # Show run status (reconnects to live VMs)
dispatcher logs <run-id>            # Stream logs (reconnects to live VMs)
dispatcher cost <run-id>            # Show cost tracking
dispatcher diagnose <run-id>        # Explain why a run failed / stalled / overran
dispatcher explain <plan-id>        # Detailed plan explanation
dispatcher list                     # List all runs with status/cost/duration
dispatcher history                  # Historical run statistics per target
dispatcher approve <run-id>         # Approve a pending policy gate (out-of-band)
dispatcher deny <run-id>            # Deny a pending policy gate
dispatcher targets list             # List configured targets
dispatcher targets add <id>         # Add a new target
dispatcher targets doctor <id>      # Health check a target
dispatcher gc [--dry-run]           # Find and destroy orphaned cloud resources
dispatcher recover                  # Inventory cloud VMs whose local record is missing
```

### Execution Targets (9 with adapters)

| Target | Kind | Adapter | Status |
|--------|------|---------|--------|
| local-process | local | LocalAdapter | Working |
| local-docker | docker | DockerAdapter | Working (needs Docker) |
| ssh | ssh | SSHAdapter | Working (needs SSH host) |
| lima-vm | cloud-vm | CloudVMAdapter + LimaProvider | Working (needs limactl) |
| kubernetes | kubernetes | K8sAdapter | Working (needs kubectl) |
| hetzner-vm | cloud-vm | CloudVMAdapter + HetznerProvider | Built (needs hcloud CLI) |
| aws-vm | cloud-vm | CloudVMAdapter + AWSProvider | Built (needs aws CLI) |
| gcp-vm | cloud-vm | CloudVMAdapter + GCPProvider | Built (needs gcloud CLI) |
| azure-vm | cloud-vm | CloudVMAdapter + AzureProvider | Built (needs az CLI) |

### Key Features

- **Workload inspection**: Recursive scanning for runtime, entrypoints, ports, GPU, secrets, data deps, monorepo detection
- **dispatcher.yaml**: Declarative config that overrides auto-detection (name, command, GPU, service port, budget, timeout, target)
- **Cost estimation**: Per-target rate cards, historical run data, instance catalog with ~50 cloud VM types
- **Risk analysis**: 7 risk categories (cost uncertainty, capacity, credentials, data egress, public endpoint, network, packaging)
- **Policy gates**: Per-run Unix-socket approval gate. In-process approver (terminal / `--yes`) races an external `dispatcher approve <id>`; filesystem perms (0700 dir, 0600 socket) are the auth boundary.
- **Durable execution**: Runs survive CLI restarts. Serializable adapter state, reconnection, cloud-init watchdog with self-destruct timer
- **Budget enforcement**: `--max-cost` (USD) and `--timeout` (duration) limits
- **Garbage collection**: `dispatcher gc` finds orphaned VMs across all cloud providers
- **AI planner**: Tool-use architecture with 5 tools (inspect_workload, evaluate_all_targets, find_cheapest_instances, get_run_history, inspect_run). Aitelier backend (Claude). Deterministic fallback when no LLM configured.

## Project Structure

```
cmd/
  dispatcher/         # CLI entry point
internal/
  cli/                # Cobra command definitions
  workload/           # Workload inspection, config loading, recursive scanning
  target/             # Target registry, builtins, YAML config, feasibility matching
  plan/               # Plan generation, validation, formatting, persistence
  cost/               # Cost estimation (JSONL append-only history)
  policy/             # Policy engine and approval requirements
  risk/               # Risk analysis
  run/                # Run state machine, executor, persistence, reconnection, cost tracking
  approval/           # Per-run Unix-socket approval gate (audit Record embedded in run state)
  adapter/            # TargetAdapter interface, shared utilities, local/docker/ssh adapters
  cloudvm/            # Cloud VM adapter, providers (Hetzner/AWS/GCP/Azure/Lima), watchdog, catalog
  planner/            # AI planner, tool registry, aitelier backend, MCP server
  state/              # State-dir resolution + 0700 enforcement
  dlog/               # Structured JSON log file
  types/              # Shared Go types and constants
docs/                 # Design doc, implementation plan
```

## Security

- File permissions: `0600` for data files, `0700` for state directories; `state.ensureSecureDir` enforces 0700 on pre-existing dirs.
- `syscall.Umask(0o077)` at process start.
- Credentials delegated to provider CLIs — never stored in-process.
- SSH keys: ed25519, generated per-run in `<state-dir>/keys/`, cleaned up after run. ssh-keyscan + StrictHostKeyChecking=yes against a pinned known_hosts.
- SSH wrapper script (`<state-dir>/keys/ssh-wrapper-<runid>.sh`): all shell-quoting happens once at write time; rsync uses `-e <wrapper>` so no runtime quoting at call sites.
- Cloud CLI argv: repeated `--flag k=v` pairs or `file://` inputs only; no key=value concatenation. Tag/label values restricted to `[a-zA-Z0-9_.-]` at the boundary.
- Cloud-init watchdog: VMs self-destruct if dispatcher CLI crashes.
- Approval gate: per-run Unix socket; filesystem perms are the auth boundary; audit Record embedded in run state.
- LLM tools: `inspect_workload` resolves and rejects paths outside the configured workload root.

See [USAGE.md](USAGE.md) for commands and configuration; see [SECURITY.md](SECURITY.md) for the threat model and hardening details.
