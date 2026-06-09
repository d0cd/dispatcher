# Dispatcher

An AI-assisted workload planner and runner. Inspect a workload, get cost and
risk analysis across local + cloud execution targets, then run it on whichever
target makes sense.

```bash
dispatcher init        # Scaffold dispatcher.yaml
dispatcher plan        # Where can it run? what will it cost?
dispatcher run         # Execute on the recommended target
dispatcher status <id> # Check on a run
dispatcher diagnose <id>
dispatcher stop <id>
```

## Documentation

- **[docs/USAGE.md](docs/USAGE.md)** — install, commands, `dispatcher.yaml`, supported targets, AI assistance, exit codes.
- **[docs/DESIGN.md](docs/DESIGN.md)** — architecture, packages, execution flow, types.
- **[docs/SECURITY.md](docs/SECURITY.md)** — threat model, approval gate, SSH/rsync hardening, cloud CLI discipline, LLM trust boundary.
- **[CLAUDE.md](CLAUDE.md)** — guidance for AI assistants working in this repo.

## Build

```bash
go build -o dispatcher ./cmd/dispatcher
go test ./...                # ~575 tests across 15 packages
go vet ./...
```

## License

Released under the [MIT License](LICENSE).
