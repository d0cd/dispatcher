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

State lives at `$DISPATCHER_HOME` or `~/.dispatcher/`, mode `0700`. Every subdirectory (`runs/`, `plans/`, `keys/`, `approvals/`) is enforced to `0700`. `state.ensureSecureDir` chmods pre-existing directories that have looser perms — and **fails closed** if the chmod can't succeed, rather than silently using a leaky dir.

`DISPATCHER_HOME` is validated: must be absolute, must not contain `..` segments. The process startup also sets `syscall.Umask(0o077)` so any file created without an explicit mode is owner-only.

All state files are mode `0600`.

## Approval gate

Runs that require policy approval (GPU, high cost, public endpoints, secrets on external providers) open a per-run **Unix domain socket** at `<state-dir>/approvals/<run-id>.sock`.

- The socket is mode `0600` in a `0700` directory: only the operator's UID can connect.
- Single-shot: the first valid decision wins via an atomic CAS; subsequent decisions get `"already decided"`.
- The in-process approver (terminal prompt, `--yes`) races the socket — whichever produces a decision first wins.
- Wire-supplied decider names are tagged `external:` on the server side, so the audit record honestly distinguishes locally-verified approvers (`interactive:<user>`, `yes-flag:<user>`) from unauthenticated wire input.
- The audit `Record` is embedded in the persisted run state via the run package's atomic write-locked persistence — there is no separate signed approval file (the old HMAC-signed JSON had a long list of subtle gaps; see [DESIGN.md](DESIGN.md) for the rewrite rationale).

A same-UID attacker can still connect to the socket and forge a decider name. This is acknowledged: same-UID is not a security boundary.

## SSH and rsync

Every cloud-VM run pins the VM's host key as soon as SSH is reachable (`ssh-keyscan` into `<state-dir>/keys/known_hosts-<run-id>`). All subsequent SSH/rsync calls use `StrictHostKeyChecking=yes` against the pinned file. The MITM window shrinks to a single first-contact moment.

The pinned `known_hosts` file is written with `O_EXCL` to refuse following a planted symlink, and stat-checked for non-symlink mode.

**rsync invocation** is the historical attack surface: rsync re-parses the `-e` value with shell-like splitting, so naively building `fmt.Sprintf("ssh -i %s -p %d -o UserKnownHostsFile=%s", ...)` is an injection vector. Dispatcher writes a **per-run SSH wrapper script** (`<state-dir>/keys/ssh-wrapper-<run-id>.sh`, mode `0700`) with every embedded value shell-quoted **once at write time**. Every rsync call is `-e <wrapper>` — a single filesystem path, no runtime interpolation.

Rsync also uses `--protect-args` to disable remote-shell re-tokenization of paths, and `--safe-links` to refuse symlinks pointing outside the transferred tree.

## Cloud CLI argument discipline

Cloud CLIs (gcloud, az, aws, hcloud) each have their own tokenization rules for `--tag`, `--label`, `--metadata`, `--custom-data`. Dispatcher follows two rules:

1. **Never concatenate `k=v` into a single argv slot.** Tags use repeated `--flag k=v` pairs (Azure, Hetzner), comma-joined single args with pre-validated content (GCP, AWS), or file-based inputs for blobs.
2. **Pass UserData via `file://` / `@path`, never on argv.** GCP uses `--metadata-from-file startup-script=<tempfile>`; Azure uses `--custom-data @<tempfile>`; AWS uses `--user-data file://<tempfile>`; Hetzner uses `--user-data-from-file`. Bootstrap content (potentially containing secrets) never appears in `ps`.

Tag and label keys/values are validated at the boundary: `[a-zA-Z0-9_.-]` only. This is a strict subset of every provider's documented charset and excludes every separator/quote in any provider's CLI argument format.

Tempfiles holding sensitive content use `WriteSecureTempFile` (O_CREATE|O_EXCL|O_WRONLY|0600) — atomic, no create-then-chmod TOCTOU.

## LLM trust boundary

Workload-controlled data flows into the LLM via tool results (filenames, log tails, error messages, secret keys, etc.). Two defenses:

1. **Path containment.** `inspect_workload` resolves and rejects any path outside the configured workload root. The path argument's effective domain is structurally restricted to a single directory.
2. **UNTRUSTED markers in system prompts.** `plan`, `audit`, and `diagnose` all explicitly instruct the LLM that tool result strings are quoted data, never instructions. A workload-planted filename like `"IGNORE PRIOR INSTRUCTIONS"` is treated as a literal value.

User-supplied strings (workload path, target name, run ID) flowing into LLM messages are `%q`-quoted.

## Cloud VM watchdog

Cloud VMs created by dispatcher run a cloud-init watchdog script that polls a deadline file. If dispatcher fails to extend the deadline (because the CLI crashed, or the laptop went to sleep), the VM self-destructs.

Default TTL is 30 minutes; tune via `watchdogTtl` in `dispatcher.yaml` or `--watchdog-ttl`.

## History and run state

Run history (`<state-dir>/history.jsonl`) is append-only via `O_APPEND`. POSIX guarantees atomic writes below PIPE_BUF (4 KiB); records are bounded to stay well under that. Concurrent dispatchers writing simultaneously do not lose each other's entries (this was a real data-loss bug in an earlier load-modify-save design).

Run records (`<state-dir>/runs/<run-id>.json`) use exclusive `flock` plus write-temp-then-rename — concurrent readers always see either the prior version or the new one, never a torn write.

## What we delegate

- **Credentials**: all cloud auth flows through the provider CLIs (`aws`, `gcloud`, `az`, `hcloud`). Dispatcher never stores credentials in-process and never logs them.
- **Workload sandboxing**: dispatcher does not isolate the workload from itself — Docker / Kubernetes / a cloud VM is the isolation boundary. A workload running under `local-process` has full UID-level access to the operator's machine, and is documented as such.
