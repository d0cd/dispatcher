# Dispatcher

AI-assisted workload planner and runner. See `docs/DESIGN.md` for architecture, `docs/PLAN.md` for implementation plan, and `dispatch_design_doc.md` for the full design document.

## Quick Start

```bash
go build -o dispatcher ./cmd/dispatcher
./dispatcher init .                    # Scaffold dispatch.yaml
./dispatcher plan .                    # See where it can run and what it will cost
./dispatcher run .                     # Execute the workload
./dispatcher status <run-id>           # Check on it
./dispatcher stop <run-id>             # Tear it down
```

## Project Structure

```
cmd/
  dispatcher/         # CLI entry point (main.go)
internal/
  cli/                # Cobra command definitions (12 commands)
  workload/           # Workload inspection, config loading, recursive scanning
  target/             # Target registry, builtins, YAML config, feasibility matching
  plan/               # Plan generation, validation, formatting, persistence
  cost/               # Cost estimation, rate cards, historical run data
  policy/             # Policy engine and approval gates
  risk/               # Risk analysis
  run/                # Run state machine, executor, persistence, reconnection
  adapter/            # Target adapter interface, shared utilities, local/docker/ssh adapters
  cloudvm/            # Cloud VM adapter, providers (Hetzner/AWS/GCP/Azure), watchdog, catalog
  planner/            # AI planner, tool registry, LLM backend interface
  types/              # Shared Go types and constants
docs/                 # Design doc, implementation plan
```

## Commands

```bash
go build -o dispatcher ./cmd/dispatcher   # Build binary
go test ./...                         # Run all tests (~270 tests)
go vet ./...                          # Lint
```

## Dev Conventions

- Test-driven: write failing tests before implementation.
- Validate all external input at system boundaries.
- Every target adapter must implement the TargetAdapter interface.
- Durable adapters (cloud VMs) must also implement DurableAdapter.
- Plan schema must match `dispatch_design_doc.md` section 10.
- Keep CLI commands thin — delegate to domain packages in internal/.
- No silent failures: errors must surface with actionable context.
- Implementation order: all deterministic primitives and tools first, AI planner last.
- File permissions: 0600 for data files, 0700 for directories containing sensitive data.
- Shared utilities go in adapter/shared.go (SanitizeName, RuntimeCommand, DefaultValidationResult).

## Key Types

- `WorkloadSpec` — detected workload shape (internal/types)
- `TargetConfig` — target definition with capabilities (internal/types)
- `Plan` — structured recommendation per design doc section 10 (internal/types)
- `CostEstimate` — cost with confidence and assumptions (internal/types)
- `RunState` — 18-state machine for execution (internal/types)
- `TargetAdapter` — execution interface every target implements (internal/adapter)
- `DurableAdapter` — extends TargetAdapter with reconnection/watchdog/GC (internal/adapter)
- `CloudProvider` — cloud VM lifecycle interface (internal/cloudvm)
- `DispatchConfig` — dispatch.yaml schema (internal/workload)

## Tech Stack

- Go 1.23, Cobra (CLI), Viper (config), go-yaml
- Standard library testing + testify
- fatih/color for terminal output
- Cloud provider CLIs (hcloud, aws, gcloud, az) for VM management
