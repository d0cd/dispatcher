# Dispatcher

AI-assisted workload planner and runner. See `docs/DESIGN.md` for architecture, `docs/USAGE.md` for commands and config, and `docs/SECURITY.md` for the security model.

## Quick Start

```bash
go build -o dispatcher ./cmd/dispatcher
./dispatcher init .                    # Scaffold dispatcher.yaml
./dispatcher plan .                    # See where it can run and what it will cost
./dispatcher run .                     # Execute the workload
./dispatcher status <run-id>           # Check on it
./dispatcher stop <run-id>             # Tear it down
```

## Project Structure

```
cmd/
  dispatcher/            # CLI entry point (main.go)
  dispatcher-attest/     # in-TEE attestation agent (generic)
  dispatcher-attest-aws/ # per-cloud measured agents (aws/azure/azuresnp/nitro)
  dispatcher-attest-azure/
  dispatcher-attest-azuresnp/
  dispatcher-attest-nitro/
  dispatcher-nitro-proxy/ # parent-side vsock<->TCP proxy for Nitro enclaves
internal/
  cli/                # Cobra command definitions (22 top-level + 5 targets + 5 confidential subcommands)
  workload/           # Workload inspection, config loading, recursive scanning
  target/             # Target registry, builtins, YAML config, feasibility matching
  plan/               # Plan generation, validation, formatting, persistence
  cost/               # Cost estimation (JSONL append-only history)
  policy/             # Policy engine and approval requirements
  risk/               # Risk analysis
  run/                # Run state machine, executor, persistence, reconnection
  approval/           # Per-run Unix-socket approval gate (audit Record embedded in run state)
  adapter/            # TargetAdapter interface, shared utilities, local/docker/ssh adapters
  cloudvm/            # Cloud VM adapter, providers (Hetzner/AWS/GCP/Azure/Lima/Firecracker), watchdog, gc, bill, confidential adapters
  attest/             # Attestation verifiers (SNP/MAA/Nitro), pinned roots, in-TEE agent
  confidential/       # HPKE (RFC 9180) payload sealing + measured-image pin registry
  shard/              # Sharding / fan-out
  planner/            # AI planner, tool registry, LLM backend (aitelier)
  state/              # State-dir resolution + 0700 enforcement
  dlog/               # Structured JSON log file
  types/              # Shared Go types and constants
docs/                 # DESIGN, USAGE, SECURITY, ROADMAP, confidential-* design/plan docs
```

## Commands

```bash
go build -o dispatcher ./cmd/dispatcher   # Build binary
go test ./...                         # Run all tests (~900 tests across 19 packages)
go vet ./...                          # Lint
gofmt -l .                            # Find unformatted files
```

## Dev Conventions

- Test-driven: write failing tests before implementation.
- Validate all external input at system boundaries.
- Every target adapter must implement the TargetAdapter interface.
- Durable adapters (cloud VMs) must also implement DurableAdapter.
- Plan schema is defined by the `types.Plan` struct (internal/types/plan.go).
- Keep CLI commands thin — delegate to domain packages in internal/.
- No silent failures: errors must surface with actionable context.
- Implementation order: all deterministic primitives and tools first, AI planner last.
- File permissions: 0600 for data files, 0700 for directories containing sensitive data.
- Shared utilities live in adapter/shared.go (SanitizeName, RuntimeCommand, ShellQuote, WriteSecureTempFile).
- Cloud CLI argv: never concatenate `k=v` into a single arg — use repeated `--flag k=v` or file:// inputs.
- Label/tag values: validate at the boundary via cloudvm.validateLabels (charset `[a-zA-Z0-9_.-]`).

## Key Types

- `WorkloadSpec` — detected workload shape (internal/types)
- `TargetConfig` — target definition with capabilities (internal/types)
- `Plan` — structured recommendation per design doc section 10 (internal/types)
- `CostEstimate` — cost with confidence and assumptions (internal/types)
- `RunState` — 20-state machine for execution (internal/types)
- `TargetAdapter` — execution interface every target implements (internal/adapter)
- `DurableAdapter` — extends TargetAdapter with reconnection/watchdog/GC (internal/adapter)
- `Provider` — cloud VM lifecycle interface (internal/cloudvm)
- `DispatcherConfig` — dispatcher.yaml schema (internal/workload)
- `ConfidentialRequirement` — TEE demand: Type (sev/sev-snp/tdx) + Profile (azure-snp/nitro measured backend) + Attestation (internal/types)
- `AttestationResult` — TEE attestation verdict rendered by `status` (internal/attest)
- `Pin` / `Registry` — measured-image pin registry backing `dispatcher confidential` (internal/confidential)
- `approval.Gate` — per-run Unix-socket approval gate (filesystem perms are the auth boundary)
- `approval.Record` — audit-trail entry embedded in the persisted run state

## Tech Stack

- Go 1.25, Cobra (CLI), Viper (config), go-yaml
- Standard library testing + testify
- fatih/color for terminal output
- cloudflare/circl for HPKE (RFC 9180) confidential-payload sealing
- Cloud provider CLIs (hcloud, aws, gcloud, az) for VM management
