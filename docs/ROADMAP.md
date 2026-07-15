# Roadmap

Remaining work, grouped by theme. dispatcher has broad backend coverage — landed
and live-validated: provisioning/pricing across Hetzner / AWS / GCP / Azure, plus
Kubernetes, Lima, local process/docker, and **Firecracker microVMs**; durable
execution; **GPU end-to-end** (GCP + AWS, via driver-baked images);
**measured confidential computing paths on GCP, Azure, and AWS** (Confidential
Space / measured SNP / Nitro plus live evidence, GCP SEV-SNP
golden-validated on real hardware) with the `dispatcher confidential` measured-image
pin pipeline; **sharding/fan-out**; per-run SSH-key injection + per-run
firewalls; and the bring-your-own-hosts importer. What's left is completeness
gaps and new capabilities. A July 2026 live 37 GB, CPU-saturating cloud workload
also exposed reliability gaps hidden by the smaller provider bring-up tests;
closing those takes priority over adding another backend.

Effort: **S** ≈ <½ day · **M** ≈ 1–2 days · **L** ≈ 3+ days. Impact is user-facing.

## Garbage collection & cost audit  ✓ delivered

`gc` is now a provider-pluggable three-tier audit: **orphan** (dispatcher-owned,
run gone → reaped), **standing** (owned, no run → kept & listed), **external**
(not owned → listed only, never touched — the `dispatcher=true` tag is the hard
reap boundary). Each provider's `resourceEnumerator` surfaces its idle-billable
resources with an estimated `~$/mo` and a total-ongoing figure: GCP (instances,
disks, images, snapshots, IPs), AWS (instances, EBS, snapshots, EIPs, per-run
SGs), Azure (VMs, disks, IPs, snapshots), Hetzner (servers, volumes, IPs,
snapshots, per-run firewalls). Per-run SGs/firewalls are now tagged at creation
so leaked ones are reapable, and `az vm delete`'s satellite-resource leak (OS
disk + public IP) is fixed at the source via a teardown cascade. Uncatalogued
instances render `cost unknown` rather than $0.

`dispatcher bill [--all] [--by-service] [--reconcile]` complements it with the
authoritative per-cloud spend (Cost Explorer / Azure Consumption / GCP
BigQuery export), and `gc --warn-over <usd>` warns loudly when total ongoing
cost crosses a threshold.

Remaining polish: also surface the spend warning in `status` (not only on
`gc`/`bill`); wire GPU long-tail pricing to the live catalog; and the
lower-priority items surfaced by audit (Azure/GCP GC are scoped to the
configured RG/project; Azure auto-created VNet handled best-effort).

## Large artifacts & supervised cloud jobs

A live x86 genomics baseline pressure-tested the path from provisioning through
large input staging, CPU saturation, output recovery, and teardown. Delivered and
live-validated on Hetzner (provision → stage → CPU-saturating run → artifact →
teardown, zero residual):

- provider-running VMs no longer go terminal after a burst of SSH timeouts, and
  attached ephemeral jobs renew the watchdog through compute (not only setup);
- **the billing/budget clock spans create→destroy** — the cost sampler starts
  before provisioning, so a breach during the (most expensive) staging phase
  aborts it, and live cost is persisted each tick so `list`/records show real
  spend and survive a CLI crash;
- **recoverable artifact collection** — output-transport failures retry with
  backoff and then preserve the VM (ArtifactFailed, under the watchdog TTL as the
  recovery lease) instead of destroying a finished job's unretrieved outputs;
- **control-plane CPU headroom** — the workload runs under `nice` so a
  CPU-saturating job can't starve sshd, watchdog renewal, or log streaming.

Remaining work stays generic and evidence-driven rather than growing a
genomics-specific subsystem:

| Item | Effort | Impact |
|---|---|---|
| **External-input preflight + bulk-data contract** — *delivered:* `DISPATCHER_INPUT*` env vars carry `<uri> [sha256]` (no new config type); before provisioning, a bounded `Range` read of each URI fails the run on a 403/404 (definitive source error) vs a 5xx/timeout (transport, possibly transient), live-validated to provision no VM on a bad input. The workload fetches + digest-verifies the full object on the VM. Follow-up: auth-header (non-presigned) inputs; today presigned/public URLs authenticate via the URL. | — | — |
| **Structured failure evidence before cleanup** — *delivered:* wrapped signal exits (137/247 = SIGKILL, 143/241 = SIGTERM) classify transient (crash signals stay permanent); and on a cloud failure, `FailureDetails` captures kernel OOM-killer lines + the cgroup oom_kill counter from the still-alive VM before teardown, so OOM is recorded as a fact (OOMKilled=true + the kernel line), uncertainty preserved when evidence is absent. Live-validated. Follow-up: the same kernel-tail capture for docker/k8s beyond today's `docker inspect`. | S | Medium |
| **Concurrency-aware resource fit** — *CPU control-plane headroom is delivered (the `nice` wrapper).* Still open: model worker concurrency together with peak per-worker memory and reserve **memory** for the control plane, reflecting both workload and control-plane headroom in instance selection so a job doesn't OOM the box (taking sshd/agent with it) or discover the limit through a paid run. | M | Medium |
| **Real stress lane** — add an opt-in live-provider scenario with a sparse/multipart multi-GB input and a CPU-saturating job. Assert watchdog renewal, temporary SSH unobservability, artifact recovery, budget accounting, and zero residual resources. Keep it scheduled/manual so CI cost stays bounded. | L | High |

**Boundary (decided):** dispatcher is not a bulk-data transfer, cache, or
content-addressed-storage service, nor a data lake / workflow engine. It owns the
mechanisms it controls end-to-end — provisioning, billing/budget, the control
plane it installs (agent/sshd/watchdog/log stream), staging code + small declared
inputs (integrity-checked), retrieving declared outputs, and teardown. Large
immutable inputs belong in operator-controlled object storage the workload fetches
directly (e.g. `aws s3 cp` on the VM); ordinary workload args/environment already
carry the URI and expected digest. A bounded source probe and an end-to-end digest
check make failures explicit, but they do not turn Dispatcher into a transfer or
caching layer. This meets the demonstrated need without a new data subsystem.

## Provider parity

| Item | Effort | Impact |
|---|---|---|
| **docker/k8s `outputs:` retrieval** — local/SSH/cloud copy declared outputs into `runs/<id>/artifacts/`; docker needs the `--rm` lifecycle changed + mount-vs-image path resolution, `kubectl cp` needs the pod alive at collection. At minimum, warn when `outputs:` is set but unretrievable. | M | Medium |
| **Per-run SSH firewall beyond Hetzner** — `--allow-ssh-from` is honored only on hetzner-vm today; the CLI (`run.go`) rejects it for every other target. AWS has provider-level per-run-SG restriction wired but it's unreachable until the CLI gate widens; GCP/Azure/Lima/Kubernetes have no per-run firewall (Azure `az vm create` opens tcp/22 by default; a scoped NSG rule is unimplemented). Widen the gate + add the GCP/Azure NSG/firewall rules. | S | Low |
| **Spot/preemptible support** — lowest-cost-success is the headline and the planner advises spot, but there's no spot provisioning. Surface as "variable/evictable, not estimable" rather than a wrong precise price. | L | Medium |

## Confidential computing (secure jobs)

Design: [confidential-computing.md](confidential-computing.md). Provisioning
(GCP SEV-SNP + AMD Milan pin, AWS `AmdSevSnp`, Azure ConfidentialVM), the typed
`confidential:` model, verifier cores, pinned AMD ARK/AWS roots, **and the live
evidence path** have landed on all three clouds: the measured in-TEE agent
(`internal/attest/agent` + `cmd/dispatcher-attest*`) binds the per-run nonce +
in-TEE key (`REPORT_DATA=H(N‖key)`) and returns the report/token, and a
`required` run verifies before shipping any secret — GCP Confidential Space,
Azure MAA (JWKS pinned) + measured direct-SNP (`profile: azure-snp`), AWS
SEV-SNP (`VLEK→ASK→ARK`) + Nitro (`profile: nitro`). The `dispatcher
confidential pins|pin|capture|build|check` pipeline manages measured-image pins.
The **GCP SEV-SNP golden capture is validated on real hardware**. Secret release
fails closed unless the plan selects a measured backend: Nitro on AWS,
`profile: azure-snp` on Azure, or Confidential Space on GCP. The standard AWS
SEV-SNP and Azure MAA routes no longer execute because their SSH-delivered agent
is outside the measured launch chain. **MAA per-component TCB** and **AMD KDS CRL
revocation** remain implemented for verifier reuse. Remaining:

| Item | Effort | Impact |
|---|---|---|
| **AWS live pricing** — the EC2 bulk price list is ~479 MB and rarely parses in the plan timeout (now correctly skipped → static/rate-card fallback). Replace with the lightweight Price List Query API (`get-products`). | M | Low |
| k8s Confidential Containers — a different, larger model. Out of scope until demand. | — | — |

## Low-latency burst execution

Design: [low-latency-execution.md](low-latency-execution.md). The **Firecracker
microVM backend** (tap/NAT networking, per-run rootfs + key injection) and
**sharding/fan-out** (`shard:`/`aggregate:`, count + discover, bounded-parallel
engine, output aggregation) have landed and are live-validated. Remaining:

| Item | Effort | Impact |
|---|---|---|
| **Cloud-native fast backend** — prebaked images / warm pools on the existing clouds to cut boot from minutes toward seconds. | M | Medium |
| **Startup-latency feasibility** — a latency dimension so the planner prefers fast backends for short jobs, VMs for long ones. | S | Medium |
| **Shard refinements** — discover-mode on docker/cloud (per-shard item-file staging; local works today); LPT scheduling — reorder assignments by `cost/history.go` durations once per-shard history accrues. | M | Low |

## Candidate backends

Today: Hetzner / AWS / GCP / Azure (cloud VMs), Kubernetes, Lima, local
process/docker, and Firecracker (local microVM). The bar for a *new* provider
is that it adds something the current set lacks — **cheaper/more-available GPU**,
a **free tier** for CI/testing, a distinct **accelerator/region**, or a lower
price floor. "Another general VM cloud" is low value: Hetzner already anchors
cheap general compute.

**Effort is set by the access shape.** Every backend today shells out to a
provider CLI (`hcloud`/`aws`/`gcloud`/`az`). Candidates split three ways, and
the first REST provider is the real investment (it establishes an HTTP-based
`Provider` pattern the rest reuse):

| Provider | Access | Fits cloud-VM adapter? | Distinct value | Effort |
|---|---|---|---|---|
| **Oracle Cloud (OCI)** | `oci` CLI, SSH VMs | ✅ near-identical to AWS/GCP | Large always-free tier (Ampere ARM) for CI; cheap ARM | **disabled — needs live validation** |
| **Vultr** | `vultr-cli` + API, SSH VMs | ✅ | Cheap general + many regions; some GPU | M (low) |
| **Lambda Cloud** | REST API (no rich CLI), SSH VMs | ~ VM lifecycle fits, but HTTP not CLI | On-demand H100/A100 well below hyperscaler list, often more available | M (first REST adapter) |
| **RunPod** | REST/GraphQL + CLI, SSH-able pods | ~ container/VM hybrid | Very cheap community-cloud GPUs, per-second billing; burst GPU | M–L |
| **Thunder Compute** | `tnr` CLI, SSH VMs | ✅ | Cheap GPU (GPU-over-TCP); newer/less proven | M (immature) |
| **Modal** | Python SDK, serverless sandboxes | ❌ submit-and-invoke (k8s-shaped, no SSH) | Sub-second sandboxes, autoscale; adds a Python dep | L |

**Why this matters (validated in provider bring-up):** hyperscaler GPU is
expensive ($0.5–3.7/h), **quota-gated** (starts at 0; hours-to-days to approve;
Azure new subs are capacity-restricted), and **stockout-prone** (L4/n2d shopping
across zones). The cheap-GPU specialists sidestep all three — the strongest
argument to prioritize them over more general-compute clouds.

**OCI status:** lifecycle, pricing, CLI wiring, and argv tests are built, but the
builtin target is disabled until a real account validates the complete lifecycle.
Confidential execution separately fails closed; OCI BYAS must be implemented
rather than approximated with AWS evidence semantics.

| Item | Effort | Impact |
|---|---|---|
| **Validate OCI against a real account** — run create → VNIC/IP retry → SSH → destroy end-to-end, confirm image users and billing, and add a scheduled live-provider lane before enabling the target. | M | Medium |
| **Implement OCI BYAS attestation** — retrieve provider-documented evidence, validate its certificate chain and nonce/channel-key binding, and exercise secret sealing on a VM.Standard.E5/E6 Flex guest. Do not use the bare-metal host or AWS VLEK verifier as substitutes. | L | High |

**Suggested order:** (1) **Oracle** — validate the built adapter live (above); free
tier gives a no-cost CI lane + a second AMD-SEV confidential target. (2) **Lambda
Cloud** — highest-value GPU add; builds the reusable REST `Provider` pattern.
(3) **RunPod** — cheapest burst GPU once REST exists. (4) **Vultr / Thunder** —
opportunistic. (5) **Modal** — separate serverless track, not a VM provider.

GPU backends reuse the driver-baked-image mechanism already built
(`DISPATCHER_GCP_GPU_IMAGE` / `DISPATCHER_AWS_GPU_IMAGE`); most specialists ship
GPU-driver images by default, so this is often simpler than the hyperscalers.

## CI

CI runs gofmt / vet / build / `test -race`, a coverage report, binary smoke, a
non-blocking `govulncheck`, and e2e lanes (`kind` + terraform + localhost ssh,
main-push/`workflow_dispatch`). Remaining:

| Item | Effort | Impact |
|---|---|---|
| **Live-provider integration lane** — opt-in, credentialed, manual/scheduled; exercise one real cloud's create/wait/destroy. Gate behind secrets so it never runs on forks/PRs. | L | Medium |
| **Coverage floor** on cost/security-critical packages (cloudvm, adapter, run, target) — off today to avoid flaky reds until baselines are pinned. | S | Medium |
| **staticcheck** — 4 pre-existing findings to clean first (2 `ST1005` in `lima.go`, 1 `ST1005` in `run.go`, 1 `U1000` in `runtime.go`). | S | Medium |
| **Release-binary smoke** (`--version`/`--help`) + GoReleaser dry-run if binaries are offered. | S | Low |

## UX polish

| Item | Effort | Impact |
|---|---|---|
| Shell completion ships but is inert — no `ValidArgsFunction` for run-ids, target-ids, or enum flags. | M | Medium |

## Test-coverage residual

`FailureDetails` (the `docker inspect` exec glue) and each provider's `WaitReady`
are still ~0% — both need a command seam or a live host to exercise; low value to
force now that a live-provider lane is planned.

## Solid — no action

Policy / risk / approval-gate concurrency; run-state durability (atomic + flocked
writes, 0700 hardening, panic-recovery cleanup); the CLI/`--json` framework;
provisioning/GPU wiring; per-run SSH-key injection (GCP metadata / AWS + Azure
key-values / user-data); sharding core + fan-out; the BYO-hosts importer. Cloud
job supervision, setup-phase pricing, large staging, and cleanup ordering are
explicitly not in this list until the stress lane above passes.

## Suggested order

Confidential secret release is available on measured profiles and fails closed on
the unmeasured standard routes. Remaining priorities:

1. **Cloud-job reliability** — bill create-to-destroy, recover artifact transfer,
   and add the real stress lane.
2. **Large immutable inputs** — document the URI + digest contract and add the
   bounded source preflight; keep storage, caching, and multipart transfer outside
   Dispatcher.
3. **Candidate backends** — Oracle first (free CI lane + AMD SEV), then Lambda
   (establishes the REST `Provider` pattern + cheap GPU).
4. **Low-latency** — cloud-native fast backend + startup-latency feasibility.
5. **Shell completion** and **AWS live pricing** (replace the 479 MB bulk list
   with the Price List Query API).
