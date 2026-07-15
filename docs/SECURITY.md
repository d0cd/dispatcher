# Security model

## Threat model

Dispatcher is a single-user CLI. The trust boundary is **the operator's UID**: anything running as that UID has access equivalent to the operator. We defend against:

- A malicious or compromised **workload** running under the operator's UID (cloud-VM workloads run as `dispatcher`/`ubuntu`/`root` on a separate machine, but local-docker / local-process workloads run on the operator's host).
- Other **users on the same machine** (different UIDs) reading state files or process arguments.
- Network attackers on the SSH path to a cloud VM (man-in-the-middle on host keys, in-flight tampering).
- A workload supplying **untrusted strings** that flow into LLM prompts (prompt injection).

We do not defend against:

- Root on the operator's machine.
- An attacker who has full code execution as the operator's UID and can mutate ongoing CLI processes.

## State directory

State lives at `$DISPATCHER_HOME` or `~/.dispatcher/`, mode `0700`. Every subdirectory (`runs/`, `plans/`, `keys/`, `approvals/`, `targets/`) is enforced to `0700`. `state.ensureSecureDir` chmods pre-existing directories that have looser perms — and **fails closed** if the chmod can't succeed, rather than silently using a leaky dir.

`DISPATCHER_HOME` is validated: must be absolute, must not contain `..` segments. The process startup also sets `syscall.Umask(0o077)` so any file created without an explicit mode is owner-only.

All state files are mode `0600`.

## Approval gate

Runs that require policy approval (GPU, high cost, public endpoints, secrets on external providers) open a per-run **Unix domain socket** at `<state-dir>/approvals/<run-id>.sock`.

- The socket is mode `0600` in a `0700` directory: only the operator's UID can connect.
- Single-shot: the first valid decision wins via an atomic CAS; subsequent decisions get `"already decided"`.
- The in-process approver (terminal prompt, `--yes`) races the socket — whichever produces a decision first wins.
- Wire-supplied decider names are tagged `external:` on the server side, so the audit record honestly distinguishes locally-verified approvers (`interactive:<user>`, `yes-flag:<user>`) from unauthenticated wire input.
- The audit `Record` is embedded in the persisted run state via the run package's atomic write-locked persistence — there is no separate signed approval file. An HMAC-signed JSON file was considered and rejected: same-UID is not a trust boundary (an attacker with the uid also holds the key), so the signature adds ceremony without a real guarantee.

A same-UID attacker can still connect to the socket and forge a decider name. This is acknowledged: same-UID is not a security boundary.

## SSH and rsync

Every cloud-VM run pins the VM's host key as soon as SSH is reachable (`ssh-keyscan` into `<state-dir>/keys/known_hosts-<run-id>`). All subsequent SSH/rsync calls use `StrictHostKeyChecking=yes` against the pinned file. The MITM window shrinks to a single first-contact moment.

The pinned `known_hosts` file is written with `O_EXCL` to refuse following a planted symlink, and stat-checked for non-symlink mode.

**rsync invocation** is the historical attack surface: rsync re-parses the `-e` value with shell-like splitting, so naively building `fmt.Sprintf("ssh -i %s -p %d -o UserKnownHostsFile=%s", ...)` is an injection vector. Dispatcher writes a **per-run SSH wrapper script** (`<state-dir>/keys/ssh-wrapper-<run-id>.sh`, mode `0700`) with every embedded value shell-quoted **once at write time**. Every rsync call is `-e <wrapper>` — a single filesystem path, no runtime interpolation.

Both directions use `--protect-args` to disable remote-shell re-tokenization of paths. `--safe-links` is applied on artifact **retrieval** (download from the VM), where a malicious workload could plant a symlink escaping the transferred tree into the local filesystem; the upload path (trusted local source) uses `--protect-args` only.

## Host import (bring your own hosts)

`dispatcher targets import` registers externally-provisioned hosts as SSH targets. Its trust boundary:

- **`--from-terraform`** shells out to `terraform output -json` through a read-only seam. `terraform output` reads state — it never refreshes or mutates resources. The raw output and the binary's stderr are **never echoed** (they may carry unrelated secret outputs); errors are reduced to a safe, actionable hint.
- A `dispatcher_targets` output marked **`sensitive`** is **refused** unless `--allow-sensitive`.
- Every imported `host`/`user`/`key_file` is validated at the boundary (`target.ValidateSSHTarget`): host as a hostname/IP, user as a strict word, rejecting the `:`/`/`/`@`/leading-`-` metacharacters that would inject into the `user@host` / `-e` ssh/rsync argv.
- Imported targets are written to `<state-dir>/targets/` at `0600`. An operator-supplied `key_file` is **referenced, not copied**; a leading `~` is expanded, and a missing or group/world-accessible key is warned (`--strict` makes it an error).
- Import **refuses to shadow** an existing target (builtin, hand-added, or project `dispatcher.yaml`) — load order would otherwise decide silently.

The cloud-VM host-key pinning above does not apply to imported targets: they are long-lived operator infra reached with the operator's own key and `known_hosts`, not dispatcher-generated per-run identities.

## Confidential computing

`confidential:` provisions a TEE-backed VM (AMD SEV/SEV-SNP, Intel TDX) so the cloud host/hypervisor can't read the workload's memory — a *data-in-use* protection orthogonal to the operator-boundary hardening above. Boundaries:

- **No silent downgrade.** A confidential job is only feasible on a target/type that supports it; otherwise it's rejected, never run on a normal VM. The provider create flag is emitted from a verified mapping (GCP `--confidential-compute-type`, AWS `--cpu-options AmdSevSnp=enabled`, Azure `--security-type ConfidentialVM`), and unsupported type/provider combos error before launch.
- **Attestation.** A TEE encrypts memory, but the *proof* is a signed attestation report from code that is itself measured. Secret release is enabled only for the measured backends: **GCP** Confidential Space (agent-image digest + Google JWS), **Azure** `confidential.profile: azure-snp` (agent in a dm-verity root measured into PCR11), and **AWS** `confidential.profile: nitro` (COSE chain + pinned PCR0). The older standard AWS SEV-SNP and Azure MAA paths remain useful verifier code, but execution fails closed because their post-boot SSH-delivered agents are not part of the measured launch chain. `attestation: off` is the explicit escape hatch for encrypted-memory-without-verification; no attestation-based credential release occurs in that mode.
- **OCI.** The provider adapter is disabled pending a live tenancy test. OCI confidential execution additionally fails closed until its BYAS evidence format and certificate chain are implemented and verified on real hardware; dispatcher never substitutes the AWS VLEK verifier or treats a confidential bare-metal host as a guest-scoped TEE.

## Cloud CLI argument discipline

Cloud CLIs (gcloud, az, aws, hcloud) each have their own tokenization rules for `--tag`, `--label`, `--metadata`, `--custom-data`. Dispatcher follows two rules:

1. **Never concatenate `k=v` into a single argv slot.** Tags use repeated `--flag k=v` pairs (Azure, Hetzner), comma-joined single args with pre-validated content (GCP, AWS), or file-based inputs for blobs.
2. **Pass UserData via `file://` / `@path`, never on argv.** GCP uses `--metadata-from-file startup-script=<tempfile>`; Azure uses `--custom-data @<tempfile>`; AWS uses `--user-data file://<tempfile>`; Hetzner uses `--user-data-from-file`. Bootstrap content (potentially containing secrets) never appears in `ps`.

Tag and label keys/values are validated at the boundary: `[a-zA-Z0-9_.-]` only. This is a strict subset of every provider's documented charset and excludes every separator/quote in any provider's CLI argument format.

Tempfiles holding sensitive content use `WriteSecureTempFile` (O_CREATE|O_EXCL|O_WRONLY|0600) — atomic, no create-then-chmod TOCTOU.

## Network exposure

Dispatcher-provisioned cloud VMs default to an **SSH-open posture**, which varies by provider:

- **AWS** — dispatcher creates a **per-run security group** on every VM (deleted on teardown) admitting inbound SSH from `0.0.0.0/0` by default. The default VPC group only permits intra-group traffic, so this group is what makes the VM reachable at all.
- **GCP** — the instance lands on the project's default network, whose built-in `default-allow-ssh` rule permits tcp:22 from `0.0.0.0/0`; dispatcher adds no per-run rule.
- **Azure** — `az vm create` auto-creates an NSG that commonly allows SSH from any source; dispatcher adds no per-run rule of its own.
- **Hetzner** — no firewall unless `--allow-ssh-from` is set (below).

So SSH (port 22) and any port the workload itself binds are reachable from the public internet by default on every provider.

SSH access is gated by a **per-run ed25519 key with no password** and host-key pinning (see above), so the open SSH port is not brute-forceable. The residual exposure is defense-in-depth: SSH-daemon attack surface for the VM's lifetime, and **any workload-bound port (dev server, debugger, datastore) is world-reachable with no network-layer restriction**.

**Per-run SSH allowlist (`--allow-ssh-from`).** Pass `dispatcher run --allow-ssh-from <CIDR>` (e.g. `203.0.113.4/32`) to restrict inbound SSH to that range:

- **Hetzner** — creates an `hcloud firewall` with an inbound TCP/22 rule from the CIDR, attached at create time; deleted on teardown.
- **AWS** — the *provider* already applies the CIDR as the per-run security group's SSH ingress (replacing the `0.0.0.0/0` default). **But the CLI currently gates `--allow-ssh-from` to `hetzner-vm` only** (`run` rejects it for other targets), so this AWS capability is not yet reachable end-to-end — an AWS VM's SG defaults to `0.0.0.0/0` until the gate is widened.
- **GCP / Azure** — **rejected** (no silent fallback). GCP's built-in `default-allow-ssh` permits tcp:22 from `0.0.0.0/0` and an additive ALLOW rule cannot subtract that access, so a per-run rule would imply a restriction it does not enforce; restrict SSH at the network/NSG level instead.

The CIDR is validated (`net.ParseCIDR`) at the CLI boundary and again before use, and passed as a standalone argv token. *The AWS per-run SG and Hetzner firewall are covered by argv-level unit tests and live-validated via `gc` reap; live `--allow-ssh-from` restriction on AWS awaits wiring the CLI gate.* Operators remain responsible for restricting any non-SSH workload-bound ports.

## LLM trust boundary

Workload-controlled data flows into the LLM via tool results (filenames, log tails, error messages, secret keys, etc.). Two defenses:

1. **Path containment.** `inspect_workload` resolves and rejects any path outside the configured workload root. The path argument's effective domain is structurally restricted to a single directory.
2. **UNTRUSTED markers in system prompts.** `plan`, `audit`, and `diagnose` all explicitly instruct the LLM that tool result strings are quoted data, never instructions. A workload-planted filename like `"IGNORE PRIOR INSTRUCTIONS"` is treated as a literal value.

User-supplied strings (workload path, target name, run ID) flowing into LLM messages are `%q`-quoted.

## Cloud VM watchdog

Cloud VMs created by dispatcher run a watchdog that polls a deadline file. If dispatcher fails to extend the deadline (because the CLI crashed, or the laptop went to sleep), the VM self-destructs.

The watchdog is installed by cloud-init as a `systemd` service (`Restart=always`, enabled for `multi-user.target`) with its deadline persisted under `/var/lib/dispatcher` (on-disk, not tmpfs). This means the backstop survives a VM reboot — after a reboot systemd re-launches it and it re-reads the persisted deadline, shutting down immediately if the deadline already passed.

Default TTL is 30 minutes; tune via `watchdogTtl` in `dispatcher.yaml` or `--watchdog-ttl`.

## History and run state

Run history (`<state-dir>/history.jsonl`) is append-only via `O_APPEND`. POSIX guarantees atomic writes below PIPE_BUF (4 KiB); records are bounded to stay well under that. Concurrent dispatchers writing simultaneously do not lose each other's entries (this was a real data-loss bug in an earlier load-modify-save design).

Run records (`<state-dir>/runs/<run-id>.json`) use exclusive `flock` plus write-temp-then-rename — concurrent readers always see either the prior version or the new one, never a torn write.

## What we delegate

- **Credentials**: all cloud auth flows through the provider CLIs (`aws`, `gcloud`, `az`, `hcloud`). Dispatcher never stores credentials in-process and never logs them.
- **Workload sandboxing**: dispatcher does not isolate the workload from itself — Docker / Kubernetes / a cloud VM is the isolation boundary. A workload running under `local-process` has full UID-level access to the operator's machine, and is documented as such.
