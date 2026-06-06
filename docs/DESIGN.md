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

### CLI Commands (15)

```bash
dispatcher init [path]              # Scaffold dispatch.yaml from workload inspection
dispatcher plan <path>              # Generate execution plan with cost/risk analysis
dispatcher run <path>               # Plan and execute a workload
dispatcher stop <run-id>            # Terminate and clean up a running workload
dispatcher status <run-id>          # Show run status (reconnects to live VMs)
dispatcher logs <run-id>            # Stream logs (reconnects to live VMs)
dispatcher cost <run-id>            # Show cost tracking
dispatcher explain <plan-id>        # Detailed plan explanation
dispatcher list                     # List all runs with status/cost/duration
dispatcher history                  # Historical run statistics per target
dispatcher targets list             # List configured targets
dispatcher targets add <id>         # Add a new target
dispatcher targets doctor <id>      # Health check a target
dispatcher gc [--dry-run]           # Find and destroy orphaned cloud resources
```

### Execution Targets (10)

| Target | Kind | Adapter | Status |
|--------|------|---------|--------|
| local-process | local | LocalAdapter | Working |
| local-docker | docker | DockerAdapter | Working (needs Docker) |
| ssh | ssh | SSHAdapter | Working (needs SSH host) |
| hetzner-vm | cloud-vm | CloudVMAdapter + HetznerProvider | Built (needs hcloud CLI) |
| aws-vm | cloud-vm | CloudVMAdapter + AWSProvider | Built (needs aws CLI) |
| gcp-vm | cloud-vm | CloudVMAdapter + GCPProvider | Built (needs gcloud CLI) |
| azure-vm | cloud-vm | CloudVMAdapter + AzureProvider | Built (needs az CLI) |
| kubernetes | kubernetes | — | Planning only (no adapter) |
| modal | modal | — | Planning only (no adapter) |
| e2b | e2b | — | Planning only (no adapter) |

### Key Features

- **Workload inspection**: Recursive scanning for runtime, entrypoints, ports, GPU, secrets, data deps, monorepo detection
- **dispatch.yaml**: Declarative config that overrides auto-detection (name, command, GPU, service port, budget, timeout, target)
- **Cost estimation**: Per-target rate cards, historical run data, instance catalog with ~50 cloud VM types
- **Risk analysis**: 7 risk categories (cost uncertainty, capacity, credentials, data egress, public endpoint, network, packaging)
- **Policy gates**: Interactive approval prompts for GPU, high cost, public endpoints, unknown cost, secrets on external providers
- **Durable execution**: Runs survive CLI restarts. Serializable adapter state, reconnection, cloud-init watchdog with self-destruct timer
- **Budget enforcement**: `--max-cost` (USD) and `--timeout` (duration) limits
- **Garbage collection**: `dispatcher gc` finds orphaned VMs across all cloud providers
- **AI planner**: Tool-use architecture with 4 tools (inspect, evaluate, catalog, history). Backend-agnostic (Claude, OpenAI, local models). Deterministic fallback when no LLM configured.

## Project Structure

```
cmd/
  dispatcher/         # CLI entry point
internal/
  cli/                # Cobra command definitions (15 commands)
  workload/           # Workload inspection, config loading, recursive scanning
  target/             # Target registry, builtins, YAML config, feasibility matching
  plan/               # Plan generation, validation, formatting, persistence
  cost/               # Cost estimation, rate cards, historical data
  policy/             # Policy engine and approval gates
  risk/               # Risk analysis
  run/                # Run state machine, executor, persistence, reconnection, cost tracking
  adapter/            # TargetAdapter interface, shared utilities, local/docker/ssh adapters
  cloudvm/            # Cloud VM adapter, provider interface, Hetzner/AWS/GCP/Azure, watchdog, catalog
  planner/            # AI planner, tool registry, LLM backend interface
  types/              # Shared Go types and constants
docs/                 # Design doc, implementation plan
```

## Security

- File permissions: `0600` for run/plan records, `0700` for directories and SSH keys
- Credentials delegated to provider CLIs — never stored in-process
- SSH keys: ed25519, generated per-run in `~/.dispatcher/keys/`, cleaned up after run
- Cloud-init watchdog: VMs self-destruct if dispatcher CLI crashes
- Interactive approval prompts for risky operations (GPU, high cost, public endpoints)

See the full design document at `dispatch_design_doc.md` in the repo root.
See the implementation plan at `docs/PLAN.md`.
