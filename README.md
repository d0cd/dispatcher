# Dispatcher

**Declare a job once. Dispatch it to any cloud — or none.**

Dispatcher is a declarative, cloud-agnostic job runner. You describe a workload
in a single `dispatcher.yaml`; Dispatcher works out where it can run, what each
option will cost, and what could go wrong — then executes it on the target you
choose: your laptop, a container, an SSH host, Kubernetes, or a cloud VM on
Hetzner, AWS, GCP, or Azure. It tracks the run crash-safely, gates spend behind
an approval step, and tears everything down when it's done.

**One spec. Every target. No lock-in.**

```bash
dispatcher init        # Scaffold dispatcher.yaml from workload inspection
dispatcher plan        # Where can it run? what will it cost?
dispatcher run         # Execute on the recommended target
dispatcher status <id> # Check on a run
dispatcher diagnose <id>
dispatcher stop <id>
```

## Why Dispatcher

- **Declarative.** Your workload is config, not provider-specific glue. The same
  `dispatcher.yaml` runs locally and on every supported cloud.
- **Plan before you pay.** `dispatcher plan` shows feasible targets, cost
  estimates with confidence, and a risk audit *before* anything launches.
- **Robust by construction.** A state-machine executor with watchdogs,
  reconnection, orphan GC, and an approval gate — a crash never strands a cloud
  VM or your money.
- **No lock-in.** Swap or add providers without rewriting your workload. Leaving
  a cloud is a config change, not a migration.
- **Bring your own hosts.** Already provisioned with Terraform/OpenTofu, Pulumi,
  or a script? `dispatcher targets import` registers those hosts as targets and
  runs jobs on them — read-only with respect to your IaC. See
  [docs/USAGE.md](docs/USAGE.md#bring-your-own-hosts).

## Documentation

- **[docs/USAGE.md](docs/USAGE.md)** — install, commands, `dispatcher.yaml`, supported targets, AI assistance, exit codes.
- **[docs/DESIGN.md](docs/DESIGN.md)** — architecture, packages, execution flow, types.
- **[docs/SECURITY.md](docs/SECURITY.md)** — threat model, approval gate, SSH/rsync hardening, cloud CLI discipline, LLM trust boundary.
- **[CLAUDE.md](CLAUDE.md)** — guidance for AI assistants working in this repo.

## Build

```bash
go build -o dispatcher ./cmd/dispatcher
go test ./...                # ~1090 tests across 21 packages
go vet ./...
```

## License

Released under the [MIT License](LICENSE).
