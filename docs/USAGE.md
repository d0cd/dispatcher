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
| `run <path>` | Plan and execute. Flags: `--target`, `--optimize cost\|speed`, `--max-cost <usd>`, `--timeout <dur>`, `--gpu <spec>`, `--region <region>` (cloud region/zone; overrides `region:`), `--watchdog-ttl <dur>`, `--retry-transient`, `--allow-ssh-from <cidr>` (per-run SSH firewall; hetzner-vm, aws-vm, gcp-vm, azure-vm — see [SECURITY.md](SECURITY.md)), `--yes`. See *Exit codes* below. |
| `explain <plan-id>` | Verbose recommendation for a saved plan. |

### Observability

| Command | Purpose |
|---|---|
| `status <run-id>` | Run state (reconnects to live VMs; persists discovered terminal states). Reconnecting to a still-running cloud run also extends its watchdog (see `renew`). Also warns when non-terminal runs' combined cost crosses `DISPATCHER_WARN_OVER` (default `$25`), so a forgotten still-billing run is caught during the check you run most. |
| `logs <run-id>` | Stream logs (reconnects to live VMs). |
| `trace <run-id>` | Emit a Chrome/Perfetto timeline of the run's phases (provision, run, collect, teardown) as JSON — pipe to a file and open in `chrome://tracing` or `ui.perfetto.dev` to see where wall-clock time went. |
| `cost <run-id>` | Realized cost, broken down. |
| `list [--refresh]` | All runs with status / cost / duration. `--refresh` reconnects to non-terminal runs and updates state. Idle non-terminal runs (>6h) are flagged `STALE` so you can spot orphans. |
| `history` | Per-target historical statistics. |
| `diagnose <run-id>` | Explain why a run failed, stalled, or overran. |
| `bill [--all] [--by-service] [--reconcile]` | Per-cloud spend month-to-date (AWS Cost Explorer, Azure Consumption, GCP BigQuery export, Hetzner falls back to dispatcher's tracking since no public billing API). Default shows only `dispatcher=true`-tagged spend; **`--all`** shows total spend across every service; **`--by-service`** breaks it down per service; **`--reconcile`** shows dispatcher's tracked estimate beside the authoritative bill and flags a positive delta as possible untracked spend. GCP needs `DISPATCHER_GCP_BILLING_TABLE=project.dataset.gcp_billing_export_v1_XXXX`. |

### Lifecycle

| Command | Purpose |
|---|---|
| `stop <run-id> [--force]` | Terminate and clean up a running workload. `--force` finalizes a stranded run whose record can no longer be reconnected (no handle state, provider unreachable), marking it terminal without cleanup — reclaim any leftover resources with `gc`. |
| `renew <run-id>` | Extend a running cloud run's self-destruct watchdog by its configured TTL. Run periodically (cron / systemd timer) to keep an unattended long-running workload alive past its watchdog TTL. |
| `gc [--dry-run] [--yes] [--warn-over <usd>] [--allow-empty-store]` | Find and destroy orphaned cloud resources, and summarize ongoing cost. Classifies every listed resource three ways: **orphan** (dispatcher-owned, its run is gone) is reaped; **standing** (dispatcher-owned, tied to no run — e.g. a driver-baked image) is listed and kept; **external** (not dispatcher-owned) is listed only and never touched. Reaping only ever acts on resources tagged `dispatcher=true`. The cost audit covers idle-billable resources per provider — GCP (instances, disks, images, snapshots, static IPs), AWS (instances, EBS volumes, snapshots, Elastic IPs, per-run security groups — swept across **all enabled regions**), Azure (VMs, disks, public IPs, snapshots), Hetzner (servers, volumes, primary/floating IPs, snapshots, per-run firewalls) — each with an estimated `~$/mo` (instances are repriced from the live catalog so the estimate tracks live rates — most impactful for the GPU long tail); a running instance whose type isn't in the catalog shows `cost unknown` rather than $0. **Scope:** AWS sweeps all enabled regions, Azure scans the whole active subscription (dispatcher-owned resources in **any** resource group; external ones stay scoped to `dispatcher-rg`), and GCP scans **every project the credential can list** (best-effort — a project it can't list is logged and skipped; owned-only). Each resource is destroyed in the RG/project it lives in. The residual blind spots are other Azure subscriptions and unlistable GCP projects. `--warn-over` (default `$10`/mo, `0` disables) warns loudly when total ongoing cost crosses the threshold. As a safety guard, gc **refuses to destroy** when the run store has zero records but owned resources reference run IDs (a mispointed state dir would otherwise misclassify the whole live fleet as orphans); `--allow-empty-store` overrides this for a genuinely-empty store. Prompts before destroying; `--dry-run` previews, `--yes`/`-y` skips the prompt. |
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

### Confidential images

Manage the measured-image pins that back attested confidential runs (see
[Confidential computing](#confidentialyaml) and [confidential-pipeline.md](confidential-pipeline.md)).

| Command | Purpose |
|---|---|
| `confidential pins` | List the committed measured-image pins. |
| `confidential pin <gcp\|aws-nitro\|azure-snp>` | Record/update a pin (image ref + measurement). |
| `confidential capture <gcp\|aws-nitro\|azure-snp> <source>` | Capture a measurement from a built image / booted CVM. |
| `confidential build <aws-nitro\|gcp\|azure-snp>` | Build the measured image for a backend. |
| `confidential check` | Fail if a pin drifted from the current tree (the CI drift guard). |

## Supported targets

| Target | Status | Requires |
|---|---|---|
| `local-process` | builtin | — |
| `local-docker` | builtin | Docker |
| `ssh` | builtin | reachable SSH host |
| `lima-vm` | builtin | `limactl` |
| `firecracker-vm` | builtin | KVM host + Firecracker |
| `kubernetes` | builtin | `kubectl` + cluster |
| `aws-vm` | builtin | `aws` CLI |
| `gcp-vm` | builtin | `gcloud` |
| `azure-vm` | builtin | `az` |
| `hetzner-vm` | builtin | `hcloud` |
| `oci-vm` | builtin | `oci` CLI |
| `lambda-vm` | builtin | `DISPATCHER_LAMBDA_API_KEY` (Lambda Cloud REST API; GPU) |

`lambda-vm` is dispatcher's first REST-based provider — it talks to the Lambda
Cloud API directly, so it needs `DISPATCHER_LAMBDA_API_KEY` (and optionally
`DISPATCHER_LAMBDA_REGION`, default `us-east-1`) rather than a vendor CLI. Set
the instance type via the plan (e.g. `gpu_1x_a100`); Lambda has no safe default.
Provisioning only — no confidential execution, no per-run SSH firewall, and no
in-VM watchdog (a dead dispatcher is reclaimed by `dispatcher gc`).

### Secrets from a command

Rather than exporting a credential in plaintext, dispatcher can resolve any
`DISPATCHER_*` secret from a command whose stdout is the value. It's generic —
supply whatever command reads your secret (a secret manager, `pass`, a script):

```yaml
secrets:
  DISPATCHER_LAMBDA_API_KEY: ["pass", "show", "lambda/api-key"]
```

Secret **commands are only honored from the user-global** config at
`~/.config/dispatcher/config.yaml` (honors `$XDG_CONFIG_HOME`), set once per
machine. A secret command runs against your (unlocked) secret manager, so a
per-project `dispatcher.yaml` is **not** allowed to define one — running an
untrusted repo must not be able to read your credentials; a project-level
`secrets:` block is ignored with a warning. An explicit environment variable
still overrides the resolved value. The command runs lazily — only when that
provider actually provisions or tears down a VM, not when pricing it as an
alternative during `plan`/`run` — so an unrelated run never touches your secret
manager. Its trimmed output is cached, and a command that fails leaves the
variable unset so the provider fails closed. (Live pricing for such a provider
still works if the credential is already exported in the environment.)

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
cpu: "16"                     # Minimum logical CPUs
memory: 30G                   # Minimum RAM (G/Gi/GB or M/Mi/MB)
arch: x86_64                  # Required architecture: x86_64 or arm64
gpu:                          # GPU requirements
  count: 1
  model: a100                 # pin a catalog model (a100, l4, t4, v100, a10g); unset = cheapest GPU
  framework: pytorch
service:                      # Long-running service
  port: 8080
sandbox: true                 # Run in an isolated sandbox target
confidential:                 # Run on a TEE-backed (memory-encrypted) VM
  type: sev-snp               # sev | sev-snp | tdx | any   (default: any) — the TEE technology
  profile: azure-snp          # azure-snp | nitro (optional) — a measured attestation backend
  attestation: required       # required | off              (default: required)
  measurements:               # exact allowlist of accepted launch measurements (hex)
    - <hex-launch-measurement>
  minTCB: 0                   # minimum accepted reported TCB version
maxCost: 50                   # Hard budget in USD
maxTime: 2h                   # Wall-clock cap
target: hetzner-vm            # Force a specific target
region: eu-central-1          # Cloud region/zone to provision in (AWS region, GCP zone, Azure location); --region wins
outputs:                      # Workload-relative paths to retrieve before cleanup
  - results/
  - model.bin
watchdogTtl: 30m              # Cloud-VM self-destruct timer (default 30m; renewed while supervised). k8s Jobs use maxTime → activeDeadlineSeconds instead.
retryTransientFailures: true  # Retry once on transient failure (OOM/SIGKILL); CLI --retry-transient wins
shard:                        # Fan the workload out across many runs (see below)
  count: 20                   #   fixed shard count, OR
  discover: "pytest --collect-only -q"  # command whose stdout lines are work items
  maxParallel: 8              #   cap on concurrent shards (0 = engine default)
aggregate:
  outputs: [results/]         #   per-shard outputs, symlinked together after the fan-out
  onShardFailure: fail        #   fail | retry | continue
```

**Region/zone:** `--region` (or `region:` in config; the flag wins) pins where a cloud VM provisions — an AWS region, a GCP zone, or an Azure location. It's honored on teardown too, so a VM created in a non-default region is torn down there rather than leaked. On AWS the region-correct Ubuntu AMI is resolved automatically via SSM (no hand-maintained region→AMI map). Empty = the provider's default region.

**Compute resources:** `cpu` and `memory` are lower bounds used during catalog selection; `arch` is an exact architecture requirement. Planning fails when the selected target has no matching instance rather than provisioning an incompatible host.

**Sharding (fan-out):** `shard:` runs the workload across many shards, each a full dispatcher run. Use `count: N` (each shard gets `SHARD_INDEX`/`SHARD_COUNT` and partitions its own work) or `discover: <cmd>` (dispatcher runs the command, distributes its stdout lines across shards, and hands each shard its slice via a `SHARD_ITEMS_FILE`). `maxParallel` caps concurrency; `aggregate.outputs` symlinks every shard's outputs under one directory; `aggregate.onShardFailure` is `fail` (fail-fast), `retry` (one retry then fail-fast), or `continue` (run all, report partial). A plan that needs approval must be approved once with `--yes`. Discover mode currently runs on `local-process`; count mode works on any target. Design: [docs/low-latency-execution.md](low-latency-execution.md).

**GPU workloads:** dispatcher provisions the catalog instance that matches the GPU requirement. If no catalog instance matches (an unknown `gpu.model`, or a provider with no GPU inventory), `plan` flags a `gpu-unschedulable` risk and `run` refuses rather than silently launching a CPU-only box.

**Confidential computing:** `confidential:` requests a TEE-backed VM (hardware-encrypted memory) of the given `type`, so the cloud host can't read the workload's memory. `type` is the TEE technology — GCP (`sev`, via Confidential Space; sev-snp/tdx are rejected early — Google Cloud Attestation supports SEV only for CS), AWS (`sev-snp`), Azure (`sev-snp`/`tdx`); a job whose `type` no target offers is rejected (it never silently lands on a non-confidential VM, nor on a weaker TEE than requested). `profile` (optional, orthogonal to `type`) selects a *measured* attestation backend: `azure-snp` (Azure direct SNP+vTPM, agent measured into PCR11) or `nitro` (AWS Nitro Enclaves, PCR0). `attestation` defaults to `required`, and the verified path runs over an **attested TLS session**: dispatcher dials the in-TEE measured agent, and the agent's report/token binds a per-run nonce + the TLS session's `bindData` (`REPORT_DATA = H(nonce‖bindData)`, where `bindData = H(agent-cert-SPKI ‖ RFC 5705 exporter)`), which dispatcher verifies before delivering the workload over that same session — GCP Confidential Space (agent-image digest + JWS), Azure measured direct SNP+vTPM (`profile: azure-snp`, PCR11), AWS Nitro Enclaves (`profile: nitro`, PCR0). Set `attestation: off` to provision the encrypted-memory VM without verification (recorded as an unverified run). `measurements` is an exact allowlist enforced by the verifier (an empty allowlist fails closed under `required`); `minTCB` rejects reports below a firmware version (enforced on the SNP report path — `profile: azure-snp`; GCP Confidential Space carries no reported TCB and so **fails closed** when `minTCB` is set, and Nitro is n/a). **Operator setup:** supply a pinned measured image via the `DISPATCHER_*` env vars or `dispatcher confidential pin`; an unconfigured measured backend fails closed before provisioning. The in-TEE agent's port is firewalled to dispatcher's auto-detected public IP (a `/32`); behind CGNAT, a NAT pool, or an egress proxy that `/32` won't match your real connection source and the agent will be unreachable — set `DISPATCHER_AGENT_ALLOW_CIDR` to your actual egress range to scope it correctly. All three attested backends are measured — the agent is in the launch measurement (CS container digest, Nitro PCR0, Azure PCR11). See [docs/confidential-computing.md](confidential-computing.md) and [SECURITY.md](SECURITY.md).

**GPU images (operator):** GPU instances need the NVIDIA driver preinstalled, which stock cloud images lack. Point dispatcher at an operator-built driver-baked image via `DISPATCHER_GCP_GPU_IMAGE` (a GCP image name in the current project) or `DISPATCHER_AWS_GPU_IMAGE` (an AMI id); GPU instance families then boot from it instead of stock Ubuntu. Build one once (install `nvidia-driver-*-server`, reboot, then `gcloud compute images create` / `aws ec2 create-image`). Without it, a GPU run comes up driverless.

**Firecracker microVMs (operator):** the `firecracker-vm` target runs local microVMs on a Linux host with `/dev/kvm`. Set `DISPATCHER_FC_KERNEL` (a guest `vmlinux`) and `DISPATCHER_FC_ROOTFS` (an ext4 rootfs shipping `sshd` + `rsync` + a PID1 that starts sshd); the preflight fails closed if either is missing. See [docs/low-latency-execution.md](low-latency-execution.md) for the base-image recipe.

**Environment expansion:** values in `dispatcher.yaml` may reference environment variables as `${VAR}` or `${VAR:-default}`, expanded at load time from dispatcher's process environment. Only the braced form is expanded — a bare `$VAR` (e.g. inside a `command` meant to expand on the remote host) is left untouched. A `${VAR}` with no default that isn't set is an error, so typos surface loudly.

State lives in `.dispatcher/` (per-project, found by walking up from cwd) or `~/.dispatcher/` (fallback). Override with `$DISPATCHER_HOME` or the global `--state-dir` flag.

## Global flags

Available on every command:

| Flag | Purpose |
|---|---|
| `--output text\|json` (`--json`) | Emit machine-readable JSON instead of prose. Supported on `plan`, `audit`, `status`, `list`, `cost`, `bill`, `history`, `recover`, and `gc` (`gc --json` requires `--dry-run` or `--yes` since it can't prompt). |
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
