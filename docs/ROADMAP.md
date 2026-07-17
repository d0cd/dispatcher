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
`gc`/`bill`); wire GPU long-tail pricing to the live catalog; **an auto-deallocating
Azure watchdog** — the guest `shutdown` self-destruct leaves an Azure VM
*Stopped (allocated)* (still compute-billing), so if the CLI dies before teardown
only `gc` reclaims it; a managed-identity + IMDS-token `deallocate` would make the
Azure cost backstop automatic like the other clouds; and the lower-priority items
surfaced by audit (Azure/GCP GC are scoped to the configured RG/project; Azure
auto-created VNet handled best-effort).

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
| **Control-plane headroom** — *CPU delivered (the `nice` wrapper).* Sizing the box for the *workload's* memory is the application's job: it declares `resources.memory` and dispatcher already honors it in feasibility + instance selection (catalog `MinMemoryGB`); dispatcher does not model a workload's internal concurrency/footprint. A control-plane *memory* reserve (cgroup-cap the workload so it can't starve sshd/agent) is **deferred pending evidence** — the observed failure was CPU (fixed), and the live OOM test showed the kernel OOM-killer targets the workload, not sshd, so the control plane already survives. | S | Low |
| **Real stress lane** — *delivered:* a `hetznere2e`-tagged integration test provisions a real Hetzner VM, runs a CPU-saturating job, and asserts run completion under saturation, artifact recovery, budget accounting, and zero residual (safety-net reaper by run-id tag); a manual/weekly workflow gated on `secrets.HCLOUD_TOKEN` (skipped on forks) keeps cost bounded. Follow-up: a multi-GB sparse input (paired with the external-input contract) and explicit SSH-unobservability assertion. | S | Medium |

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

Likewise, a workload's own resource footprint (memory, internal concurrency) is
the author's to declare, not dispatcher's to model: dispatcher sizes the box to
the declared `resources.*` and gets out of the way. Dispatcher hardens only its
own control plane against a greedy workload (CPU `nice` today; a memory reserve
only if control-plane starvation is ever actually observed).

## Provider parity

| Item | Effort | Impact |
|---|---|---|
| **docker/k8s `outputs:` retrieval** — local/SSH/cloud copy declared outputs into `runs/<id>/artifacts/`; docker needs the `--rm` lifecycle changed + mount-vs-image path resolution, `kubectl cp` needs the pod alive at collection. At minimum, warn when `outputs:` is set but unretrievable. | M | Medium |
| **Per-run SSH firewall beyond Hetzner + AWS** — `--allow-ssh-from` is honored end-to-end on hetzner-vm and aws-vm (per-run firewall / security group); GCP/Azure/Lima/Kubernetes still reject it — no per-run firewall (Azure `az vm create` opens tcp/22 by default; a scoped NSG rule is unimplemented; GCP's additive default-allow-ssh can't be subtracted). Add the GCP/Azure NSG/firewall rules. | S | Low |
| **Spot/preemptible support** — lowest-cost-success is the headline and the planner advises spot, but there's no spot provisioning. Surface as "variable/evictable, not estimable" rather than a wrong precise price. | L | Medium |

## Confidential computing (secure jobs)

Design: [confidential-computing.md](confidential-computing.md). Provisioning
(GCP SEV-SNP + AMD Milan pin, AWS `AmdSevSnp`, Azure ConfidentialVM), the typed
`confidential:` model, verifier cores, pinned AMD ARK/AWS roots, **and the live
attested-TLS evidence path** have landed on all three measured backends: dispatcher
dials the measured in-TEE agent (`internal/attest/agent` + `cmd/dispatcher-attest*`)
over attested TLS, the agent binds the per-run nonce + the TLS session
(`REPORT_DATA=H(N‖bindData)`) into the report/token, and a `required` run verifies
before delivering any secret over that session — GCP Confidential Space, Azure
measured direct SNP+vTPM (`profile: azure-snp`), AWS Nitro Enclaves
(`profile: nitro`) — each hardware-validated. The `dispatcher
confidential pins|pin|capture|build|check` pipeline manages measured-image pins.
The **GCP SEV-SNP golden capture is validated on real hardware**. Secret release
fails closed unless the plan selects a measured backend: Nitro on AWS,
`profile: azure-snp` on Azure, or Confidential Space on GCP. The unmeasured
standard AWS SEV-SNP and Azure MAA routes were removed — their SSH-delivered agent
sat outside the measured launch chain. **AMD KDS CRL revocation** remains,
enforced on the `azure-snp` path. Remaining:

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
| **Oracle Cloud (OCI)** | `oci` CLI, SSH VMs | ✅ near-identical to AWS/GCP | Large always-free tier (Ampere ARM) for CI; cheap ARM | **done — validated + enabled (provisioning only)** |
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

**OCI status:** *delivered* as a plain provisioning target — lifecycle validated
end-to-end on a live tenancy (create → VNIC/IP → SSH → run → artifact → destroy),
enabled by default. **Confidential execution is not supported and will not be:**
hardware testing on E5/Genoa showed OCI SEV-SNP reports do not verify against the
AMD KDS VCEK (reproduced with snpguest, go-sev-guest, and manual verification),
and OCI forbids a vTPM/measured boot alongside SEV-SNP, so there is no
measured-agent path. All OCI confidential code was removed; `oci-vm` declares no
confidential capability. Remaining OCI work is optional polish (a scheduled live
lane).

**Suggested order:** (1) **Oracle** — *done* (validated + enabled; provisioning
only, confidential not supported); free always-free tier gives a no-cost CI lane.
(2) **Lambda Cloud** — *code delivered* (`lambda-vm`): the first REST `Provider`
(HTTP + API key, not a CLI), with unit tests over a stubbed transport; GPU
capability advertised, provisioning-only (no confidential, no per-run firewall,
no in-VM watchdog). Pending live-account validation before it's proven end-to-end.
(3) **RunPod** — cheapest burst GPU, now that the REST pattern exists. (4) **Vultr /
Thunder** — opportunistic. (5) **Modal** — separate serverless track, not a VM provider.

GPU backends reuse the driver-baked-image mechanism already built
(`DISPATCHER_GCP_GPU_IMAGE` / `DISPATCHER_AWS_GPU_IMAGE`); most specialists ship
GPU-driver images by default, so this is often simpler than the hyperscalers.

## CI

CI runs gofmt / vet / build / `test -race`, a coverage report, binary smoke, a
non-blocking `govulncheck`, and e2e lanes (`kind` + terraform + localhost ssh,
main-push/`workflow_dispatch`). Remaining:

| Item | Effort | Impact |
|---|---|---|
| **Live-provider integration lane** — *delivered for Hetzner* (the `hetznere2e` stress lane: manual/weekly, gated on `secrets.HCLOUD_TOKEN`, skipped on forks). Extend to a second cloud's create/wait/destroy when useful. | M | Low |
| **Coverage floor** — *delivered:* per-package floors on cloudvm/adapter/run/target/cost/attest, a few points below current so a real regression fails the build. Raise as coverage improves. | — | — |
| **staticcheck** — *delivered:* enforced and blocking in CI on the full default check set (U1000 unused-code included). All findings fixed, including removal of the orphaned standard-confidential helpers (`confidential_aws.go`/`confidential_azure.go`) left dead by the measured-profile refactor. | — | — |
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
the unmeasured standard routes. **Cloud-job reliability** and the **large-input
contract** are delivered and live-validated on Hetzner: billing create-to-destroy,
recoverable artifact collection, control-plane CPU headroom, kernel OOM evidence,
signal-exit retry classification, and the URI+digest bounded source preflight, plus
the opt-in live stress lane. Remaining priorities:

1. **Candidate backends** — **Oracle (OCI)** is built but gated experimental
   (`DISPATCHER_OCI_EXPERIMENTAL`) pending a live-tenancy validation; then **Lambda
   Cloud**, which establishes the reusable REST `Provider` pattern (every current
   backend shells out to a CLI) and adds cheap on-demand H100/A100.
2. **Low-latency** — cloud-native fast backend (prebaked images / warm pools) +
   startup-latency feasibility so the planner prefers fast backends for short jobs.
3. **Shell completion** and **AWS live pricing** (replace the 479 MB bulk list
   with the Price List Query API).

CI hardening is delivered — `staticcheck` (full default set, U1000 included) and
per-package coverage floors are enforced and blocking.
