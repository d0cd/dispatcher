# Design: Low-latency burst execution

Give dispatcher a **fast ephemeral-sandbox backend** (boot in seconds, not
minutes) and a **config-declared sharding** layer that fans one workload out
across many sandboxes and aggregates the results.

Two capabilities, built in this order:

1. **Fast backends** — new execution targets: **Firecracker microVM** (first),
   then **cloud-native fast** (prebaked images / warm pools on existing
   providers), then **Modal** (external sub-second sandboxes).
2. **Sharding (fan-out)** — a `shard:` block in `dispatcher.yaml` that splits a
   workload into N shards, runs them across the fast backend, and aggregates.

This is dispatcher's identity stretch from "place one workload well" toward
"burst many" — taken deliberately, gated on the fast backend proving out first.

§1 backend architecture · §2 Firecracker · §3 feasibility · §4 sharding ·
§5 security/hygiene · §6 build plan · §7 decisions.

---

## 1. Backend architecture — reuse, don't reinvent

A fast backend is **a new `Provider` behind the existing `CloudVMAdapter`**, not a
standalone adapter. `CloudVMAdapter` already implements `TargetAdapter` +
`DurableAdapter` and owns the transport: per-run SSH key, host-key pinning,
`known_hosts`, the SSH wrapper, `rsync` of source in, the runner script (exit-code
capture, `nohup`, PID tracking), artifact rsync out, cleanup, and state
serialization for reconnect. A `Provider` only implements lifecycle:

```
Name() · CheckCLI() · CreateVM(opts) (*VMInfo) · WaitReady(id, ip, key)
GetVM(id) · DestroyVM(id) · ListVMs(tags)
```

The **Lima provider is the precedent**: a local VM reached over SSH on
`127.0.0.1:<forwarded-port>`, with a provider-owned identity key. Firecracker
follows the same shape (SSH to a local microVM), so the entire workload-execution
path is inherited for free. Provider CLI calls go through the `runCLI` seam, so
argv is unit-testable without the real binary — the same pattern the cloud
providers and the confidential attesters use.

Cloud-native-fast reuses the AWS/GCP/Azure providers with a prebaked image and
(optionally) a warm pool. Modal is a provider that shells out to the `modal` CLI.

---

## 2. Firecracker microVM backend (first)

Firecracker boots a microVM in ~125ms on Linux with `/dev/kvm`. A `Provider`
launches one microVM per run, dispatcher SSHes in, runs the workload, retrieves
outputs, and tears the VM down.

**What a microVM needs (the infrastructure):**
- **KVM** — `/dev/kvm` on a Linux host. Not available on macOS/dev laptops, so
  the live path is validated on a KVM host (bare metal or nested-virt VM), the
  same "needs real hardware" boundary confidential computing hit.
- **Kernel + rootfs** — a `vmlinux` and an ext4 rootfs image carrying the OS,
  `sshd`, and the injected per-run public key. Image management is real work.
- **Networking** — a host `tap` device per VM (or a shared bridge + NAT for
  egress); the guest is reachable at the tap IP. This is the fiddliest part.

**What's offline-testable (build now, no KVM):**
- **Config builder** — Firecracker is configured by a JSON document
  (`boot-source` {kernel_image_path, boot_args}, `drives` {rootfs, is_root},
  `machine-config` {vcpu_count, mem_size_mib}, `network-interfaces`
  {host_dev_name, guest_mac}). Building this from `VMOptions` is a pure function
  → table-tested.
- **Launch argv** — `firecracker --api-sock <sock> --config-file <json>` (or the
  `--no-api` form) → asserted via the `runCLI` seam.
- **Lifecycle bookkeeping** — VM id ↔ socket/config/tap mapping, `GetVM`/`ListVMs`
  over dispatcher-tagged config files, `DestroyVM` (stop process, free tap, rm
  files) → testable against a fake process/fs.

The provider **fails closed** in a preflight when `/dev/kvm`, the `firecracker`
binary, or the configured kernel/rootfs are absent — so on a laptop
`firecracker-vm` is simply infeasible rather than mysteriously broken.

**Live lifecycle (implemented).** `FirecrackerProvider` runs microVMs as a local
backend: dispatcher runs *on* the KVM host and SSHes to the guest over a per-run
tap. Chosen model (raw firecracker, zero new Go deps):
- **Networking** — tap-per-run on a `/30` derived from the run id (host `.1` =
  gateway, guest `.2`), host `MASQUERADE` for egress. The guest self-configures
  `eth0` from the kernel `ip=` boot-arg — no in-guest network manager.
- **SSH** — a per-run copy of the base rootfs with dispatcher's public key
  injected into `root/.ssh/authorized_keys` (mounted via loopback).
- **Lifecycle** — `CreateVM` = rootfs copy + key inject + tap + NAT + launch;
  `DestroyVM` = kill the VM (by config-path marker) + del tap + remove NAT + rm
  run dir. Privileged steps go through `sudo` (a dedicated KVM host).

**Operator requirements:**
- `DISPATCHER_FC_KERNEL` and `DISPATCHER_FC_ROOTFS` point at the guest `vmlinux`
  and base ext4 rootfs; the preflight checks both exist.
- **The base rootfs must ship `sshd` and `rsync`** (dispatcher rsyncs the source
  in) and a PID1 that starts `sshd`. The Firecracker CI `ubuntu-*.ext4` images
  boot but are stripped (no `rsync`, no working `dpkg`), so build a base:

  ```sh
  # kernel: a firecracker CI vmlinux, e.g.
  #   firecracker-ci/v1.10/x86_64/vmlinux-6.1.102
  sudo debootstrap --variant=minbase \
    --include=openssh-server,rsync,iproute2,ca-certificates \
    jammy /tmp/rootfs http://archive.ubuntu.com/ubuntu/
  # minbase has no init; a tiny /sbin/init mounts proc/sys/dev, brings up
  # lo+eth0, ssh-keygen -A, then execs sshd and stays alive (PID1).
  sudo sed -i 's/#*PermitRootLogin.*/PermitRootLogin yes/' /tmp/rootfs/etc/ssh/sshd_config
  sudo truncate -s 1500M rootfs.ext4 && sudo mkfs.ext4 -F -d /tmp/rootfs rootfs.ext4
  ```

**Status:** validated **end-to-end** on a nested-virt GCP host — a real
`dispatcher run --target firecracker-vm` provisions a microVM (per-run tap +
NAT), SSHes in, rsyncs the workload, runs it in the guest, retrieves outputs,
and tears down with no leftover tap/NAT/mount/state. Pure net helpers +
config/argv are unit-tested.

---

## 3. Startup-latency feasibility

Today `CheckFeasibility` is pure capability matching — no notion of "this job is
short, prefer a fast boot." Add a **latency dimension**:

- A target advertises an approximate **startup latency** (Firecracker: sub-second;
  cloud VM: minutes; local-process: instant).
- The planner prefers low-latency targets for short/among-many workloads and
  amortizes VM boot only for long-running ones.

Kept minimal: a `StartupLatency` hint on `Capabilities` + a tie-breaker in
ranking, not a new constraint language. Sharding makes this matter — 20 shards ×
minutes of boot is untenable; 20 × sub-second is the point.

---

## 4. Sharding (config-declared fan-out)

A `shard:` block turns one workload into N runs across the fast backend. The
config **declares** it; the engine sits in the run/executor layer, *above* the
adapter (each shard is an ordinary single-target run).

```yaml
shard:
  count: 20                              # even split into 20 shards, OR
  discover: "pytest --collect-only -q"   # a command whose stdout lines are the work items
aggregate:
  outputs: [results/]                    # rsync + merge each shard's outputs
  onShardFailure: fail                   # fail | retry | continue
```

**Split model (both supported):**
- `count: N` — dispatcher runs the workload N times; each shard gets
  `SHARD_INDEX` (0..N-1) and `SHARD_COUNT` in its environment and decides how to
  partition its own work (the pytest-xdist / offload model).
- `discover: <cmd>` — dispatcher runs the command once, treats each stdout line as
  a work item, and distributes items across shards (offload's `--collect-only`
  model). `count` may cap the shard fan-out; items are balanced across shards.

**Execution & scheduling:**
- Each shard is a run on the fast backend (its own microVM/sandbox), so isolation,
  cleanup, and reconnect come from the existing machinery.
- Scheduling assigns items **round-robin** today; Longest-Processing-Time
  assignment from the duration history in `internal/cost/history.go` is planned
  (once per-shard history accrues — see ROADMAP). Concurrency is capped
  (a `shard.maxParallel`, defaulting to 4 when unset).

**Aggregation & failure:**
- Each shard's declared `outputs` are rsynced back into a per-shard subdir under
  the run's artifacts, then merged.
- `onShardFailure`: `fail` (first failure fails the run, others cancelled),
  `retry` (re-run a failed shard once — safe only for idempotent shards, so it's
  opt-in), or `continue` (collect what succeeded, report partial). No silent
  truncation — a partial result is always reported as partial.

**Cost/plan:** `plan` shows the shard count, per-shard estimate, and the fan-out
total, so the bill of a 200-way burst is visible before `run`.

---

## 5. Security & hygiene

- **Isolation** — a microVM is a real hardware-virtualization boundary (stronger
  than a container); each shard runs in its own VM, no shared kernel.
- **Secrets** — per-run key + `.env` injection is inherited from `CloudVMAdapter`;
  no secret crosses argv (already enforced via `--env-file`/`file://` patterns).
- **Cleanup** — every shard VM (and its tap/rootfs) is torn down on completion or
  failure; the watchdog TTL bounds a leaked shard's lifetime.
- **Blast radius** — `shard.maxParallel` and the plan's visible fan-out total keep
  a `discover` that emits 10⁶ items from spawning 10⁶ VMs; the cap is logged, not
  silent.

---

## 6. Build plan (incremental, TDD)

| # | Increment | Delivers |
|---|---|---|
| 1 | Firecracker offline core: config-JSON builder + launch argv + lifecycle bookkeeping (fake process/fs), fail-closed preflight when no `/dev/kvm`. | provider, synthetic-tested |
| 2 | Firecracker live: rootfs/kernel/tap on a KVM host; register `firecracker-vm` builtin + `adapterForTarget` wiring; runbook. | a real fast target |
| 3 | Startup-latency feasibility hint + planner tie-break. | short jobs prefer fast boot |
| 4 | `shard:` config schema + validation (`count`/`discover`, `aggregate`, `maxParallel`). | declared fan-out |
| 5 | Shard engine: split → N runs → LPT schedule → aggregate → failure policy. | the burst |
| 6 | Cloud-native fast backend (prebaked images / warm pool). | fast without self-hosting |
| 7 | Modal backend (CLI shell-out) — if the external dep is judged worth it. | sub-second at scale |

Each increment is unit-tested against synthetic evidence (config, argv, split,
schedule); the KVM-dependent launch is confirmed on a real host before trust, as
with the confidential-computing verifier.

---

## 7. Decisions

- **Backend order — Firecracker → cloud-native → Modal.** Self-hosted control
  first, external SaaS last (weigh the dep cost then).
- **Fan-out is in-lane, declared in config.** `shard:` with both `count` and
  `discover`. Dispatcher becomes an orchestrator for *declared* shards; it does
  not auto-shard arbitrary workloads.
- **Reuse `CloudVMAdapter`.** Fast backends are `Provider`s; sharding is an
  executor-layer loop over single-target runs. No parallel execution stack.
- **Fail closed off-KVM.** `firecracker-vm` is infeasible without `/dev/kvm`
  rather than failing deep in provisioning.
- **No silent truncation.** A capped `discover`, a skipped retry, or a partial
  aggregate is always logged/reported as such.
