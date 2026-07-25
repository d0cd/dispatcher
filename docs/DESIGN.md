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

### CLI Commands (22 top-level + 5 `targets` + 5 `confidential` subcommands)

```bash
dispatcher init [path]              # Scaffold dispatcher.yaml from workload inspection
dispatcher plan <path> [--ai]       # Generate execution plan with cost/risk analysis
dispatcher audit <path>             # Pre-run risk audit (workload + targets)
dispatcher run <path>               # Plan and execute a workload
dispatcher validate [path]          # Validate dispatcher.yaml without planning or running
dispatcher stop <run-id>            # Terminate and clean up a running workload
dispatcher status <run-id>          # Show run status (reconnects to live VMs)
dispatcher logs <run-id>            # Stream logs (reconnects to live VMs)
dispatcher cost <run-id>            # Show cost tracking
dispatcher diagnose <run-id>        # Explain why a run failed / stalled / overran
dispatcher trace <run-id>           # Emit a Chrome/Perfetto phase-timeline trace
dispatcher explain <plan-id>        # Detailed plan explanation
dispatcher list                     # List all runs with status/cost/duration
dispatcher history                  # Historical run statistics per target
dispatcher approve <run-id>         # Approve a pending policy gate (out-of-band)
dispatcher deny <run-id>            # Deny a pending policy gate
dispatcher targets list             # List configured targets
dispatcher targets add <id>         # Add a new target (--kind/--host/--user/--port/--key-file)
dispatcher targets remove <id>      # Remove a target you added (alias rm)
dispatcher targets import           # Import hosts as SSH targets (--from-json/--from-terraform)
dispatcher targets doctor <id>      # Health check a target
dispatcher renew <run-id>           # Extend a running cloud run's self-destruct watchdog
dispatcher gc [--dry-run]           # Find and destroy orphaned cloud resources
dispatcher recover                  # Inventory cloud VMs whose local record is missing
dispatcher bill                     # Per-cloud dispatcher-tagged spend month-to-date
dispatcher confidential pins        # Show/pin/capture/build/check measured-image pins
                                    #   (subcommands: pins, pin, capture, build, check)
```

### Execution Targets (12 with adapters)

| Target | Kind | Adapter | Status |
|--------|------|---------|--------|
| local-process | local | LocalAdapter | Working |
| local-docker | docker | DockerAdapter | Working (needs Docker) |
| ssh | ssh | SSHAdapter | Working (needs SSH host) |
| lima-vm | cloud-vm | CloudVMAdapter + LimaProvider | Working (needs limactl) |
| firecracker-vm | local-vm | CloudVMAdapter + FirecrackerProvider | Working (needs a KVM host; live-validated) |
| kubernetes | kubernetes | K8sAdapter | Working (needs kubectl) |
| hetzner-vm | cloud-vm | CloudVMAdapter + HetznerProvider | Live-validated: provisioning + gc reap/safety (needs hcloud CLI) |
| aws-vm | cloud-vm | CloudVMAdapter + AWSProvider | Live-validated: provisioning + gc reap/safety (GPU provisioning test-covered, live validation pending quota). Confidential = AWS Nitro Enclaves (`confidential.profile: nitro`, measured enclave image → PCR0), attested over aTLS and hardware-validated. |
| gcp-vm | cloud-vm | CloudVMAdapter + GCPProvider | Live-validated: provisioning + GPU + gc reap/safety. Confidential = Confidential Space (measured agent image digest, Google JWS), attested over aTLS and hardware-validated. |
| azure-vm | cloud-vm | CloudVMAdapter + AzureProvider | Live-validated: provisioning + gc reap/teardown-cascade, and a ConfidentialVM (SEV-SNP, vTPM, secure boot) create+reap. Confidential = measured direct SNP+vTPM path (`confidential.profile: azure-snp`, agent in PCR11), attested over aTLS and hardware-validated. |
| oci-vm | cloud-vm | CloudVMAdapter + OCIProvider | Enabled (provisioning only; needs `oci` CLI). No confidential capability. |
| lambda-vm | cloud-vm | CloudVMAdapter + LambdaProvider | Enabled (REST-based; needs `DISPATCHER_LAMBDA_API_KEY`; GPU). |

### Key Features

- **Workload inspection**: Recursive scanning for runtime, entrypoints, ports, GPU, secrets, data deps, monorepo detection
- **dispatcher.yaml**: Declarative config that overrides auto-detection (name, command, GPU, service port, budget, timeout, target)
- **Cost estimation**: Per-target rate cards, historical run data, instance catalog with ~50 cloud VM types
- **Risk analysis**: 13 risk categories (spot-interruption, cost uncertainty, runtime uncertainty, capacity, right-sizing, gpu-unschedulable, credentials, data egress, public endpoint, network, packaging, confidential-disk-residual, outputs-unretrievable)
- **Host import**: register externally-provisioned hosts (Terraform/OpenTofu/Pulumi/scripts) as SSH targets via `targets import`, with cost/risk/approval/teardown on top. See [USAGE.md](USAGE.md#bring-your-own-hosts).
- **Policy gates**: Per-run Unix-socket approval gate. In-process approver (terminal / `--yes`) races an external `dispatcher approve <id>`; filesystem perms (0700 dir, 0600 socket) are the auth boundary.
- **GPU workloads**: detection → feasibility → catalog/pricing → provisioning. **Live-validated end-to-end** on `lambda-vm` and on `gcp-vm` (GCP L4): provision a real GPU box → `nvidia-smi` in-VM → teardown, zero residual. GCP and AWS provision GPU instances from an operator driver-baked image (`DISPATCHER_{GCP,AWS}_GPU_IMAGE`); the AWS path is test-covered, its live validation pending a GPU-quota grant (hyperscaler quota starts at 0). k8s uses `nvidia.com/gpu` limits.
- **Confidential computing**: typed `confidential:` requirement → TEE-capable machine selection + provisioning (GCP SEV-SNP/AMD Milan, AWS Nitro Enclaves, Azure ConfidentialVM) → per-cloud attestation verifiers (SEV-SNP with pinned AMD ARK roots, Nitro COSE with the pinned AWS root, Confidential Space JWS) delivered over an attested TLS session. All three measured backends hardware-validated. See [confidential-computing.md](confidential-computing.md).
- **Sharding / fan-out**: `shard:`/`aggregate:` config fans a workload across N shards (fixed `count` or a `discover` command), each a full dispatcher run; bounded-parallel engine with fail/retry/continue; artifact aggregation. See [low-latency-execution.md](low-latency-execution.md).
- **Durable execution**: Runs survive CLI restarts. Serializable adapter state, reconnection, cloud-init watchdog with self-destruct timer.
- **Budget enforcement**: `--max-cost` (USD) and `--timeout` (duration) limits.
- **Garbage collection & cost audit**: `dispatcher gc` is a three-tier ownership sweep (orphan → reaped / standing → kept / external → listed) with a hard `dispatcher=true` reap boundary. Each provider enumerates its idle-billable resources (instances, disks, images, snapshots, IPs, per-run SGs/firewalls) with an estimated `$/mo`; `--warn-over` flags ongoing cost. `dispatcher bill [--all] [--by-service] [--reconcile]` reports authoritative per-cloud spend. See ROADMAP.
- **AI planner**: Tool-use architecture with 5 tools (inspect_workload, evaluate_all_targets, find_cheapest_instances, get_run_history, inspect_run). Aitelier backend (Claude). Deterministic fallback when no LLM configured.

## Project Structure

```
cmd/
  dispatcher/            # CLI entry point
  dispatcher-attest*/    # in-TEE measured attestation agents (generic CS + azuresnp/nitro)
  dispatcher-nitro-proxy/ # parent-side vsock<->TCP proxy for Nitro enclaves
internal/
  cli/                # Cobra command definitions
  workload/           # Workload inspection, config loading, recursive scanning
  target/             # Target registry, builtins, YAML config, feasibility matching
  plan/               # Plan generation, validation, formatting, persistence
  cost/               # Cost estimation (JSONL append-only history)
  policy/             # Policy engine and approval requirements
  risk/               # Risk analysis
  run/                # Run state machine, executor, persistence, reconnection, cost tracking, trace
  approval/           # Per-run Unix-socket approval gate (audit Record embedded in run state)
  adapter/            # TargetAdapter interface, shared utilities, local/docker/ssh adapters
  cloudvm/            # Cloud VM adapter, providers (Hetzner/AWS/GCP/Azure/OCI/Lambda/Lima/Firecracker), watchdog, catalog, gc, bill, confidential adapters
  attest/             # Attestation verifiers (SEV-SNP/Nitro/CS-JWS) + per-cloud aTLS validators, pinned AMD/AWS roots, in-TEE agent + attested-TLS transport
  confidential/       # Measured-image pin registry (input-hash drift guard)
  shard/              # Shard planning (count/discover), bounded-parallel fan-out engine
  planner/            # AI planner, tool registry, aitelier backend, MCP server
  state/              # State-dir resolution + 0700 enforcement
  dlog/               # Structured JSON log file
  types/              # Shared Go types and constants
docs/                 # DESIGN, USAGE, SECURITY, ROADMAP, confidential-* design/plan docs
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
