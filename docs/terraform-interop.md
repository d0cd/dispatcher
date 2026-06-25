# Design: `targets import` — bring your own hosts (v2)

**Status:** Implemented — Phase 1 (v2 design, revised after adversarial + product review)
**Related:** ROADMAP Theme 7. Reuses the target registry (`internal/target`).

> Phase 1 shipped: prerequisites (SSH artifact retrieval, the shared SSH-field
> validator, `targets add --key-file`) and `targets import --from-json` /
> `--from-terraform` with `Enabled:true`/capabilities, the atomic
> `WriteTargetsFile`, deterministic collision rejection, sensitive-output
> refusal, and add/update/remove reconciliation. See `docs/USAGE.md` →
> "Bring your own hosts". k8s/cloud/`--from-state` remain cancelled (§13).

## 1. The pitch (read this first)

The differentiator is **not** the import. Importing an SSH host is parity with
dstack SSH fleets and SkyPilot SSH node pools. The wedge is what dispatcher does
*after* a target is registered, which neither of those will do on a
bring-your-own host:

> Terraform (or Pulumi, or a script) provisions the box. Dispatcher is the only
> one of these tools that won't run a job on it until it has **priced it,
> risk-audited it, and gotten your approval** — then runs it crash-safe and
> **tears the job down** — with **no daemon and no control plane**, just a static
> binary next to your existing IaC.

So the import is the *on-ramp*, and the value is **fleet sync**: keep
dispatcher's target list reconciled with a changing fleet (add/update/remove)
from a source of truth, idempotently — not the one-host case, where `targets add`
is already fine.

Two consequences shape the whole design:

- **The importer is source-agnostic.** The core command is `targets import
  --from-json`, reading a `dispatcher_targets` blob. `--from-terraform` is a thin
  shell that runs `terraform output -json` and pipes the blob in. This kills the
  "works with Terraform → now do k8s/cloud/state too" scope-creep treadmill and
  gets Pulumi/OpenTofu/CloudFormation/any-script for free.
- **Lead the docs/README with the governance layer, not the parser.**

## 2. Goal & non-goals

**Goal:** turn a declared list of reachable hosts (however provisioned) into
dispatcher SSH targets, idempotently, so the cost/risk/approval/teardown layer
can run jobs on infra you already own.

**Non-goals:**

- No desired-state reconciliation or drift detection of the *substrate*.
- Never mutate the source's resources or state — read-only (see §10 for the
  precise, honest scope of "read-only").
- No generation of Terraform/IaC for dispatcher's own ephemeral VMs.
- **No pre-announced k8s / cloud / raw-state phase ladder.** SSH only. k8s and
  cloud import are *not* committed roadmap; they reopen only on real, repeated
  demand (§13). Pre-announcing them manufactures the "why doesn't it read my
  EKS?" expectation the non-goals exist to fence off.

## 3. Prerequisites (must land before/with Phase 1)

These are gating — the feature feels broken on arrival without them.

1. **SSH artifact retrieval is a silent no-op today.** `internal/adapter/ssh.go`
   `Artifacts()` returns `(nil, nil)`. Every imported host runs via SSH, so a
   user's first job with `outputs:` would silently lose its results. Fix:
   implement scp-back, **or at minimum** make `outputs:` on SSH a loud warning
   instead of silent success. (Already ROADMAP Theme 3.)
2. **A real SSH-field validator must exist and be shared.** The security model
   (§8) depends on it; today `cloudvm.isSafeArg` is package-private and, anyway,
   wrong for this job (§8). Add `internal/target` validators (or a small
   `internal/validate` package) and call them from the importer **and**
   `SaveTarget`/`targets add`, so no path can persist an unsafe SSH target.
3. **`targets add --key-file`.** The manual baseline this feature builds on has
   no key-file flag today (`targets add` exposes only `--kind/--host/--user/
   --port/--enabled`). Add it so manual and imported targets are at parity.

## 4. Prior art (validates SSH-first, source-agnostic)

dstack "SSH fleets" and SkyPilot "SSH node pools" both reduce existing infra to
SSH endpoints, provisioning-agnostic — dstack's docs literally describe *"use
Terraform for base networking, then dstack for dynamic workload scheduling."*
SSH is the universal handoff; dispatcher's registry already executes custom
`kind: ssh` targets, so SSH is the correct, low-risk MVP.

## 5. The data contract: a `dispatcher_targets` blob

One structured value — **the only supported input** (heuristic `*_ssh_host`
scanning is dropped: it misses the common real shapes, and half-built magic is a
support liability on a no-daemon tool). It maps 1:1 to `types.TargetConfig`:

```json
{
  "targets": [
    {"id": "trainer", "kind": "ssh",
     "ssh": {"host": "203.0.113.10", "user": "ubuntu", "port": 22, "key_file": "/home/me/.ssh/id_ed25519"}}
  ]
}
```

- **`--from-json <file|->`** reads this blob directly.
- **`--from-terraform <dir>`** runs `<binary> -chdir=<dir> output -json`, then
  reads the `dispatcher_targets` output's `.value` (the `{sensitive,type,value}`
  envelope — see §8 for the `sensitive` handling). The user declares:

  ```hcl
  output "dispatcher_targets" {
    value = { targets = [{
      id = "trainer", kind = "ssh"
      ssh = { host = aws_instance.trainer.public_ip, user = "ubuntu", port = 22, key_file = "/home/me/.ssh/id_ed25519" }
    }] }
  }
  ```

`port` is a JSON number; decode it as such (the TF envelope and any nested value
are typed JSON, not strings).

## 6. Mapping → `TargetConfig`

For each entry the importer produces a `types.TargetConfig`:

| Field | Value |
|---|---|
| `ID` | entry `id` (validated, §8) |
| `Kind` | `ssh` (any other kind → hard error in Phase 1, §11) |
| `Enabled` | **`true`, set explicitly** |
| `Capabilities` | from `defaultCapabilitiesForKind(SSH)` |
| `SSH` | `{Host, User, Port (default 22), KeyFile}` |

Two non-obvious correctness requirements (both were false-assumptions in v1):

- **`Enabled` must be set to `true`.** `TargetConfig.Enabled` is a plain bool;
  YAML/JSON-absent → `false`; `CheckFeasibility` marks a disabled target
  infeasible, so the planner would **never select it**. The contract has no
  `enabled` field by design — the importer sets it.
- **`Capabilities` must be populated**, or the target is infeasible/unselectable.
  `defaultCapabilitiesForKind` currently lives in `internal/cli` (unexported);
  factor it into `internal/target` (exported) and use it from both `targets add`
  and the importer.

## 7. CLI

```
dispatcher targets import [--from-json <file|-> | --from-terraform <dir>] [flags]
  --binary terraform|tofu   # --from-terraform only; default: auto-detect (terraform, then tofu)
  --dry-run                 # print the add/update/remove plan; touch nothing
  --yes                     # skip the confirmation prompt
  --strict                  # promote warnings (missing key_file, perms) to errors
  --allow-sensitive         # permit importing a target sourced from a sensitive output (default: refuse)
```

`--from-terraform` uses `-chdir=<dir>` (never `cd`). Without `--dry-run` it prints
an add/update/remove summary against the current managed file and confirms unless
`--yes`.

## 8. Validation & security (load-bearing)

**Three purpose-built validators** — *not* a reuse of `isSafeArg`, which is both
too permissive and too strict for SSH:

- **`host`** — validate as a hostname or IP. Reject `:`/`/`/`@`, a leading `-`
  (ssh/rsync option injection via `user@host` and `-e` reparsing), whitespace,
  NUL, newline. `isSafeArg` wrongly permits `: / @`.
- **`user`** — strict charset `[a-zA-Z0-9_.-]`, reject leading `-`.
- **`key_file`** — a *path* validator (the host/user one would reject its own
  `~/.ssh/...` example): clean the path, expand a leading `~` to the user's home
  and store the absolute path (or require absolute and reject `~`/relative —
  pick one and document it), reject NUL/newline. At import: `stat` it; if missing
  or not `0600`-owned-by-current-user, **warn** (or error under `--strict`). This
  is referenced, not copied; document the run-time TOCTOU (the key is read at ssh
  time, not import time).

Enforce these in the importer **and** in `SaveTarget`/`targets add` so every
persist path is fail-closed (Prereq §3.2).

**Secrets:**

- **`sensitive` outputs:** by default **refuse to persist** a target whose source
  output is flagged `sensitive` (a host/user/key path generally shouldn't be);
  `--allow-sensitive` overrides. Either way, never echo a sensitive value.
- **Never log raw `output -json`.** It may contain *unrelated* secret outputs.
  Parse stdout into the typed structure immediately; on parse failure emit a
  generic message plus the offending field path/index only — never the raw bytes.
  Same for TF **stderr** (init-required/no-state messages can carry detail):
  summarize/redact, don't echo verbatim.

**ID safety:**

- **Hard-reject** an imported `id` equal to a **reserved builtin** (`local-
  process`, `local-docker`, `lima-vm`, `ssh`, `kubernetes`, `hetzner-vm`,
  `aws-vm`, `gcp-vm`, `azure-vm`). A builtin-id collision is *mis-routed* by
  `adapterForTarget` (which matches builtin ids first), not merely shadowed.
- **Deterministic collision detection.** "Never clobbers hand-added targets" is
  filename-sort luck today (all `*.yaml` load into one last-write-wins map
  ordered by filename). So the importer must **read existing target ids**
  (builtins + every `<id>.yaml`) and treat a collision with a *non-managed*
  target as a **hard error by default** (not a warning) — load order otherwise
  decides "who wins" alphabetically.
- **Reject duplicate ids *within* the blob** (per-index error, all-or-nothing).

## 9. Persistence

Imported targets are written as one managed file
`<state-dir>/targets/terraform-import.yaml` (a multi-target `TargetsFile`).

- **New writer required.** `SaveTarget` is one-target-per-file and uses plain
  `os.WriteFile` (not atomic). Add `target.WriteTargetsFile(name, []TargetConfig)`
  that marshals the full set, writes a temp file in the same dir at `0600`,
  fsyncs, and `os.Rename`s over the target (mirror the atomic write used for run
  state). All parse+validate happens **before** the write, so a failure leaves
  the previous file intact (no half-written state).
- **Idempotent re-import** regenerates the file wholesale → add/update/remove
  reflect the current source. Hand-added `<id>.yaml` files are physically
  untouched (but see the §8 collision rule for run-time precedence).
- **Removal semantics, explicit:** distinguish *no `dispatcher_targets` output /
  empty `--from-json`* (treat as error/no-op — likely misconfig, leave the file
  untouched) from *a present-but-empty `targets: []`* (legitimate — rewrite to
  zero targets, deleting everything previously imported).
- `LoadFromDir` already globs `*.yaml`, so no loader change.

## 10. The "read-only / preserves infra" guarantee — precisely

- **True for the substrate:** dispatcher never mutates Terraform/IaC resources or
  state. `terraform output -json` is read-only; `gc`/`recover`/`stop` never
  destroy an imported SSH host (verified — for SSH targets dispatcher doesn't own
  the VM lifecycle).
- **Not true for the host filesystem:** running a job still creates a working
  directory on the host and **`rm -rf`s it on teardown** (dispatcher's own
  cleanup, beyond what the workload writes). Document the default working dir and
  that imported hosts are shared, long-lived infra dispatcher *runs on* but does
  not *manage*.

## 11. Failure modes

| Case | Behavior |
|---|---|
| `--binary` absent | Clear error: install terraform/tofu or pass `--binary`. |
| TF present but `output -json` non-zero (init needed / no state / wrong dir) | Distinct from "absent": detect common stderr markers, give tailored remediation, **redact** raw stderr. |
| No `dispatcher_targets` output / empty `--from-json` | "no targets found; declare a `dispatcher_targets` output (see docs)". No-op; managed file untouched. |
| `targets: []` (present, empty) | Legitimate: rewrite managed file to zero targets (removes all imported). |
| Malformed entry (missing `id`/`kind`/`ssh.host`, wrong envelope type) | Per-index error; nothing written (all-or-nothing). |
| `kind` ≠ `ssh` | Hard error "only `kind: ssh` is importable today" (all-or-nothing; not a silent skip). |
| Duplicate id within blob | Per-index error; nothing written. |
| id == reserved builtin | Hard error (mis-route risk). |
| id collides with a hand-added target | Hard error by default; `--strict` no-op (already error). |
| `key_file` missing / wrong perms / relative | Warn (error under `--strict`); never silently defer the failure to run time. |
| Source output flagged `sensitive` | Refuse unless `--allow-sensitive`; value never echoed. |
| Host unreachable now (infra changed) | Out of scope at import; `targets doctor <id>` is the reachability check. |

## 12. Required code changes (the honest list)

v1 claimed "no new types or adapter code." That was false. Phase 1 needs:

1. Importer + `runTF`/`runJSON` seam (testable, no shell) in a new
   `internal/target` path.
2. `target.WriteTargetsFile` — atomic multi-target writer.
3. SSH-field validators (`host`/`user`/`key_file`), wired into the importer
   **and** `SaveTarget`/`targets add`.
4. Export `defaultCapabilitiesForKind` into `internal/target`; importer sets
   `Capabilities` and `Enabled: true`.
5. `targets add --key-file` flag (Prereq §3.3).
6. SSH `Artifacts()` fix or loud warning (Prereq §3.1).
7. CLI `targets import` command (thin wrapper).

No new execution path or adapter — but not "no new code."

## 13. Phasing

| Phase | Scope | Effort |
|---|---|---|
| 1 | `--from-json` + `--from-terraform` shell, SSH only, all of §3/§8/§9, tests. | M |
| — | **k8s / cloud / `--from-state` are NOT scheduled.** Reopen only on real, repeated demand. Each reintroduces type+adapter work and (for state/cloud) raw-secret handling and per-target credentials — the IaC-accessory tail this design refuses to pre-commit to. | — |

## 14. Testing (TDD)

- **Feasibility, not just file-written:** assert an imported target passes
  `CheckFeasibility` for a script/job workload (catches the `Enabled`/
  `Capabilities` traps).
- **Validators:** table-driven — `~/.ssh/id_ed25519` accepted as `key_file`,
  rejected as `host`; `-oProxyCommand=…` / `a:b` / `u@h` rejected as host/user;
  reserved-builtin and intra-blob duplicate ids rejected.
- **Atomic write + idempotency:** stubbed source → assert `terraform-import.yaml`
  contents; re-import with changed/empty/removed entries → correct add/update/
  remove; a failed write leaves the prior file intact.
- **Secrets:** `sensitive` output refused without `--allow-sensitive`; raw
  `output -json`/stderr never appears in emitted errors.
- **Hermetic source seam:** stub `runTF` (canned JSON), mirroring the
  `runCLI`/`provider_argv_test.go` pattern — no real terraform binary.

## 15. Open questions

- **`key_file` `~`-expansion vs. require-absolute:** pick one (lean: expand `~`
  at import, store absolute) and document it.
- **Workspaces:** `output -json` reflects the selected workspace; confirm whether
  a `--workspace` flag is worth it or `TF_WORKSPACE` suffices.
- **`tofu` parity:** OpenTofu's `output -json` is format-compatible; auto-detect
  order vs. explicit default.
