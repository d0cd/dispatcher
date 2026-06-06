# Example workloads

Small, runnable workloads for testing dispatcher end-to-end. Each is a real
directory you can `cd` into and run, not an inline test fixture.

| Example | What it exercises | Try |
|---|---|---|
| `hello-python/` | Local-process happy path. Smallest possible test. Also exercises `.env` injection. | `dispatcher run examples/hello-python` |
| `hello-node/` | Node.js runtime detection + local-process for non-Python. | `dispatcher run examples/hello-node` |
| `hello-docker/` | Local-docker path. Verifies `--env-file` credential safety (env values don't appear in `ps`). | `dispatcher run examples/hello-docker` |
| `flask-service/` | Service classification: long-running lifecycle, 24h cost assumption, container-required packaging, port handling. | `dispatcher run examples/flask-service` |
| `produces-outputs/` | Artifact retrieval. Writes JSON + log to `outputs/`; on cloud targets it gets rsynced back. | `dispatcher run examples/produces-outputs` |
| `failing-exit/` | Workload exits 1. Verifies exit-code surfacing + failure classification (was hidden on CloudVM before the runner-script fix). | `dispatcher run examples/failing-exit` |
| `pull-image/` | Pre-built image (`PackageTypeImage`) — no source code, no Dockerfile, just `image:` in yaml. Tests the no-build path. | `dispatcher run examples/pull-image` |
| `with-dispatchignore/` | `.dispatchignore` patterns excluded from cloud rsync. Most relevant on cloud targets; local execution doesn't ship anything. | `dispatcher run --target hetzner-vm examples/with-dispatchignore` |

Each example ships a `dispatcher.yaml` showing typical configuration —
including the optional fields (`outputs:`, `watchdogTtl:`,
`retryTransientFailures:`) so you can see what's available.

## First-run checklist

Before running cloud examples, verify the safety rails:

```bash
# Audit before launch — should show the workload's classification + risks
dispatcher audit examples/hello-python

# Plan it — see cost estimate, watchdog TTL, exclusions
dispatcher plan examples/hello-python

# Run with a low ceiling so you can sleep at night
dispatcher run --max-cost 0.10 --watchdog-ttl 10m examples/hello-python
```

If anything goes wrong, `dispatcher recover` lists what's still alive on the
cloud side, and `dispatcher diagnose <run-id>` explains what happened.
