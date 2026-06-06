# Dispatcher Implementation Plan

## Decisions Made

- **Language: Go** — Dispatcher is infrastructure CLI tooling. Single binary distribution, first-class Docker/K8s/cloud client libraries, instant compilation, goroutines for log streaming and parallel target evaluation. Cobra + Viper for CLI/config.
- **Implementation order: primitives first, AI last.** Build all deterministic inspection, matching, cost estimation, validation, policy, and execution machinery first. The AI planner is layered on top as an orchestration layer that calls well-tested tools.

## Architecture Layers (build order)

1. **Types & Schemas** — all core types with struct tags for YAML/JSON
2. **Workload Inspection** — deterministic: path in, WorkloadSpec out
3. **Target Registry & Capability Matching** — YAML config, capability advertisement, feasibility matching
4. **Cost Estimation** — rate cards, duration heuristics, historical data, confidence levels
5. **Risk Analysis & Policy** — risk enumeration, policy gates, approval requirements
6. **Plan Builder & Validator** — deterministic assembly from layers 2-5, validation
7. **CLI** — thin commands wiring layers together, output formatting
8. **Execution** — adapter interface, run state machine, durable execution, cloud VM adapters
9. **AI Planner** — orchestration layer that uses all the above as tools

---

## Phase 0: Planner-Only Prototype — COMPLETE

Goal: `dispatcher plan .` produces useful recommendations, alternatives, rejected targets, cost estimates, and risks.

### Milestone 0.1: Project Skeleton
- [x] Initialize Go module (github.com/d0cd/dispatcher)
- [x] Add dependencies: cobra, viper, go-yaml, color, testify
- [x] Set up directory structure
- [x] Wire up CLI entry point with `dispatcher plan` and `dispatcher init` stubs

### Milestone 0.2: Core Types
- [x] WorkloadSpec (detected workload shape)
- [x] TargetConfig + Capabilities (target definition)
- [x] Plan (structured recommendation, matching design doc section 10)
- [x] CostEstimate (value, confidence, assumptions, exclusions)
- [x] ValidationResult, Risk, PolicyRequirement
- [x] RunState (state machine enum with 18 states)

### Milestone 0.3: Workload Inspection
- [x] `InspectCodebase(path)` — scan directory for project signals
- [x] `DetectRuntime(path)` — identify language/runtime (Python, Node, Go, etc.)
- [x] `DetectEntrypoints(path)` — find main files, Dockerfiles, docker-compose, Procfile, Makefile, src/
- [x] `DetectPorts(path)` — scan for port bindings (recursive, service detection)
- [x] `DetectGPURequirements(path)` — scan imports/configs for GPU frameworks (recursive)
- [x] `DetectDataRequirements(path)` — identify data dependencies (recursive)
- [x] `DetectSecrets(path)` — find secret/credential references
- [x] `DetectSubWorkloads(path)` — monorepo detection
- [x] `dispatch.yaml` consumption — config overrides auto-detection

### Milestone 0.4: Target Registry
- [x] Built-in target definitions: local-process, local-docker, ssh, kubernetes, modal, e2b, aws-vm, gcp-vm, azure-vm, hetzner-vm
- [x] Target config loading from YAML (~/.dispatcher/targets/, dispatch.yaml)
- [x] `dispatcher targets list` command
- [x] `dispatcher targets add <target>` command
- [x] `dispatcher targets doctor <target>` command
- [x] Capability advertisement per target

### Milestone 0.5: Cost Estimator
- [x] Per-target rate cards (local, ssh, internal, modal, e2b, aws, gcp, azure, hetzner)
- [x] Duration estimation heuristics (1h default, 24h for services)
- [x] Historical run data — median duration, confidence from past accuracy
- [x] `EstimateCost(workload, target)` and `EstimateCostWithHistory()`
- [x] Cost comparison across targets
- [x] Confidence level assignment (high/medium/low/unknown)
- [x] Cloud VM instance catalog (~50 instance types across 4 providers)

### Milestone 0.6: Risk Analysis & Policy
- [x] Risk enumeration: cost uncertainty, capacity, credentials, data egress, public endpoint, packaging
- [x] Policy gates: cost threshold ($5 auto-approve), GPU, public endpoint, unknown cost, secrets on external
- [x] Approval requirement generation
- [x] Interactive terminal approval prompts (`--yes` to skip)

### Milestone 0.7: Plan Builder & Validator
- [x] Deterministic plan assembly from inspection+matching+cost+risk+policy
- [x] Capability matching: workload requirements vs target capabilities
- [x] Feasibility checker (reject targets with reasons)
- [x] Plan validation (schema, capabilities, cost bounds, cleanup plan)
- [x] Plan output formatter (colored terminal display)

### Milestone 0.8: CLI Polish
- [x] `dispatcher plan .` end-to-end flow
- [x] `dispatcher plan . --target <name>` single-target feasibility
- [x] `dispatcher plan . --optimize cost|speed`
- [x] `dispatcher plan . --max-cost <n>`
- [x] `dispatcher plan . --gpu <spec>`
- [x] `dispatcher plan . --timeout <duration>`
- [x] `dispatcher explain <plan-id>`
- [x] `dispatcher init [path]` — scaffold dispatch.yaml from inspection
- [x] Plan persistence (local JSON store, 0600 permissions)
- [x] Colored terminal output

### Milestone 0.9: Testing
- [x] Unit tests for each inspector (including recursive scanning)
- [x] Unit tests for capability matching
- [x] Unit tests for cost estimation (including historical)
- [x] Unit tests for plan validation
- [x] Golden planner corpus (15 test fixtures from design doc section 24.1)
- [x] Policy/approval tests (design doc section 24.8)
- [x] Secret detection tests
- [x] Config loading/application tests

---

## Phase 1: Local and SSH Execution — COMPLETE

Goal: `dispatcher run .` executes simple workloads locally or on a remote machine.

- [x] TargetAdapter interface (10 methods)
- [x] Local process adapter (no Docker required)
- [x] Local Docker adapter
- [x] SSH adapter (rsync + remote execution)
- [x] Run state machine (18 states, validated transitions)
- [x] Log streaming
- [x] Artifact collection interface
- [x] Cleanup manager with 3x retry
- [x] `dispatcher run .` end-to-end
- [x] `dispatcher status <run>`, `dispatcher logs <run>`, `dispatcher cost <run>`
- [x] `dispatcher list` — show all runs with status/cost/duration
- [x] `dispatcher stop <run>` — terminate + cleanup
- [x] Adapter contract test suite
- [x] Run state machine tests (all transitions + failure states)
- [x] Executor integration tests (14 tests: happy path, failures, panic recovery, approval denial, cleanup retry)
- [x] Local adapter real process tests (Execute, Status, Terminate, context timeout)
- [x] Basic cost tracking during run (elapsed-time scaling, finalize on completion)
- [x] Run persistence (save/load to ~/.dispatcher/runs/, 0600 permissions)
- [x] User-defined targets from YAML (~/.dispatcher/targets/, dispatch.yaml)
- [x] Budget enforcement (`--max-cost`, `--timeout`)
- [x] Historical run recording and `dispatcher history` command

---

## Phase 2: Durable Execution & Cloud VMs — COMPLETE

Goal: Support cloud VM targets with durable execution that survives CLI restarts.

### Durable Execution
- [x] Serializable adapter state (`SerializableState` interface)
- [x] `DurableAdapter` interface (Reconnect, ExtendWatchdog, ListResources, DestroyResource)
- [x] Durable RunRecord (HandleID, HandleState, Lifecycle, WatchdogTTL, LastHeartbeat)
- [x] Executor hardening: panic recovery, deferred guaranteed cleanup, handle persisted immediately
- [x] New states: Detached, Reconnecting, Stopping
- [x] `ReconnectToRun()` — rebuild live Run from persisted record
- [x] Live reconnection in `dispatcher status/logs/cost` for non-terminal runs
- [x] Ephemeral vs long-running lifecycle (auto-detected from workload kind)

### Cloud VM Adapters
- [x] `CloudProvider` interface (CreateVM, WaitReady, GetVM, DestroyVM, ListVMs)
- [x] CloudVMAdapter implementing TargetAdapter + DurableAdapter
- [x] Hetzner provider (hcloud CLI)
- [x] AWS provider (aws CLI)
- [x] GCP provider (gcloud CLI)
- [x] Azure provider (az CLI)
- [x] Mock provider for testing
- [x] Cloud-init watchdog (self-destruct timer, SSH-based heartbeat extension)
- [x] SSH key generation (ed25519, ~/.dispatcher/keys/, 0700)
- [x] Instance catalog (~50 types across 4 providers with pricing)
- [x] `dispatcher gc --dry-run` — orphan resource cleanup

### Cloud VM Targets
- [x] hetzner-vm (cheapest, simplest API)
- [x] aws-vm (EC2 via aws CLI)
- [x] gcp-vm (Compute Engine via gcloud CLI)
- [x] azure-vm (VMs via az CLI)

---

## Phase 3: AI Planner — COMPLETE

Goal: LLM-powered planning that uses deterministic tools to make intelligent recommendations.

- [x] Tool registry with 4 tools: inspect_workload, evaluate_all_targets, find_cheapest_instances, get_run_history
- [x] Typed tool schemas (ToolSchema, ToolParam)
- [x] `Backend` interface for LLM providers (Claude, OpenAI, local models)
- [x] Orchestration loop (messages → tool calls → execute → feed results → repeat)
- [x] Goal-oriented system prompt
- [x] Deterministic fallback (`DeterministicPlan()` — same tools, no LLM)
- [x] Mock backend tests

---

## Remaining Work

### Not yet started
- [ ] Wire AI planner into `dispatcher plan --ai` CLI flag
- [ ] Implement a real LLM backend (Anthropic, OpenAI, or LiteLLM)
- [ ] Kubernetes adapter (kubectl CLI)
- [ ] Modal adapter (modal CLI)
- [ ] E2B adapter (e2b CLI)
- [ ] `dispatcher artifacts <run>` command
- [ ] Run log persistence to disk (~/.dispatcher/runs/{id}.log)
- [ ] `dispatcher reproduce <run>` — re-run a previous plan

### Security
- [x] File permissions: 0600 for run/plan records, 0700 for directories and SSH keys
- [x] Credentials delegated to provider CLIs (never stored in-process)
- [x] SSH key paths in run records (metadata only, not the key itself)
- [ ] Consider encrypting sensitive fields in run records

---

## Tech Stack

- **Language:** Go 1.23
- **CLI framework:** Cobra
- **Config:** Viper + go-yaml
- **Testing:** Go standard testing + testify
- **Build:** `go build -o dispatcher ./cmd/dispatcher` (single binary)
- **Output formatting:** fatih/color

## Stats

- 61 source files, 26 test files
- ~8,200 lines of Go
- 219 tests (217 pass, 2 skip)
- 15 CLI commands
- 10 execution targets
- 7 working adapters (local-process, local-docker, SSH, Hetzner, AWS, GCP, Azure)
