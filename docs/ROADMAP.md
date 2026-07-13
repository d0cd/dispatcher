# Roadmap

Remaining work, grouped by theme. dispatcher is mature — landed and
live-validated: provisioning/pricing across Hetzner / AWS / GCP / Azure, plus
Kubernetes, Lima, local process/docker, and **Firecracker microVMs**; durable
execution; **GPU end-to-end** (GCP + AWS, via driver-baked images);
**confidential computing end-to-end on all three clouds** (SEV-SNP/MAA/Nitro
verifiers + the in-TEE measured agent's live evidence fetch, GCP SEV-SNP
golden-validated on real hardware) with the `dispatcher confidential` measured-image
pin pipeline; **sharding/fan-out**; per-run SSH-key injection + per-run
firewalls; and the bring-your-own-hosts importer. What's left is completeness
gaps and new capabilities.

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

## Provider parity

| Item | Effort | Impact |
|---|---|---|
| **docker/k8s `outputs:` retrieval** — local/SSH/cloud copy declared outputs into `runs/<id>/artifacts/`; docker needs the `--rm` lifecycle changed + mount-vs-image path resolution, `kubectl cp` needs the pod alive at collection. At minimum, warn when `outputs:` is set but unretrievable. | M | Medium |
| **Azure per-run firewall** — AWS (per-run SG) and Hetzner inject SSH ingress; `az vm create` opens tcp/22 by default so it works, but `--allow-ssh-from` isn't honored on Azure (an NSG rule). | S | Low |
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
The **GCP SEV-SNP golden capture is validated on real hardware**. Remaining:

| Item | Effort | Impact |
|---|---|---|
| **Standard-path agent measurement** — on the *standard* AWS SEV-SNP and Azure MAA paths the scp'd agent isn't folded into the launch measurement (the measured `profile` backends and GCP Confidential Space close it). Fold the agent into the measured image for those paths too. Plan: [confidential-attestation-plan.md](confidential-attestation-plan.md). | M | Medium |
| **Secret wrapping (R9) hardening** — source/secrets seal only into the proven TEE (delivered); still open: live VCEK/cert **revocation** and **MAA per-component TCB** mapping (`minTCB` is a no-op on MAA until then). | M | Medium |
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
| **Oracle Cloud (OCI)** | `oci` CLI, SSH VMs | ✅ near-identical to AWS/GCP | Large always-free tier (Ampere ARM) for CI; AMD SEV confidential; cheap ARM | M |
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

**Suggested order:** (1) **Oracle** — highest value/effort: mirrors the existing
CLI adapter, free tier gives a no-cost CI lane + a second AMD-SEV confidential
target. (2) **Lambda Cloud** — highest-value GPU add; builds the reusable REST
`Provider` pattern. (3) **RunPod** — cheapest burst GPU once REST exists.
(4) **Vultr / Thunder** — opportunistic. (5) **Modal** — separate serverless
track, not a VM provider.

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
provisioning/pricing/GPU wiring; per-run SSH-key injection (GCP metadata / AWS +
Azure key-values / user-data); durable execution (watchdog renewal, signal
teardown, k8s deadline); sharding core + fan-out; the BYO-hosts importer. No
TODO/FIXME/panic debt.

## Suggested order

1. **Confidential: close the residuals** — fold the agent into the measured
   image on the standard AWS SEV-SNP / Azure MAA paths, then live VCEK/cert
   revocation and MAA per-component TCB mapping. (The live evidence fetch, VLEK
   path, and Nitro backend already shipped.)
2. **Candidate backends** — Oracle first (free CI lane + AMD SEV), then Lambda
   (establishes the REST `Provider` pattern + cheap GPU).
3. **Low-latency** — cloud-native fast backend + startup-latency feasibility.
4. **CI live-provider lane** and **shell completion**.
