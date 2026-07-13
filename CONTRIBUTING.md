# Contributing

Thanks for thinking about contributing. This is a small project and
maintenance bandwidth is limited; PRs are welcome but may sit for a while.

## Before you start

For anything non-trivial — new adapter, new command, change to the run
state machine or the approval gate — please open an issue first. Quick
bug fixes, doc improvements, and dependency bumps don't need that
preamble.

## Local checks

```bash
go build ./...
go test ./...           # ~900 tests across 19 packages; race-clean
go vet ./...
gofmt -l .              # must produce no output
```

CI runs all four; PRs that don't pass them won't be merged.

## Conventions

- Validate external input at system boundaries.
- File permissions: `0600` for data files, `0700` for state directories.
- Cloud CLI calls: never concatenate `k=v` into a single argv slot — use
  repeated `--flag k=v` or file inputs. Tag values must satisfy
  `cloudvm.validateLabelKV`.
- Comments: explain *why*, not *what*. Default to no comment.
- Tests live alongside the code (`foo_test.go`).

See [docs/DESIGN.md](docs/DESIGN.md) for architecture and
[docs/SECURITY.md](docs/SECURITY.md) for the threat model.
