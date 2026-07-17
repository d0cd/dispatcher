# Changelog

## Unreleased

Landed since v0.1.0 (on the `confidential-compute` branch):

- **Confidential computing, end-to-end on GCP / AWS / Azure.** Typed
  `confidential:` requirement (`type` + measured `profile: azure-snp | nitro`),
  SEV-SNP / MAA / Nitro verifiers with pinned roots, an in-TEE measured agent
  that binds the per-run nonce, HPKE (RFC 9180) secret sealing, and the
  `dispatcher confidential pins|pin|capture|build|check` measured-image pin
  pipeline.
- **Sharding / fan-out** (`shard:` / `aggregate:`, count + discover modes,
  bounded-parallel engine, output aggregation).
- **Firecracker microVM backend** and **GPU end-to-end** (GCP + AWS, driver-baked
  images).
- **`dispatcher trace`** (Chrome/Perfetto phase timeline), `gc` cost audit +
  `bill` per-cloud spend, and the bring-your-own-hosts `targets import`.

## v0.1.0 — 2026-06-15

Initial public release.

### Highlights
- **Declarative workloads.** Describe a job once in `dispatcher.yaml`, then plan,
  price, and run it across local, Docker, SSH, Kubernetes, and cloud-VM targets
  (Hetzner, AWS, GCP, Azure, Lima).
- **Plan before you pay.** `dispatcher plan` and `dispatcher audit` give
  feasible-target matching, cost estimates with confidence, and pre-run risk
  analysis before anything launches.
- **Crash-safe execution.** A persisted run state machine with watchdogs,
  reconnection, orphaned-VM recovery (`dispatcher recover`), and garbage
  collection — a crash never strands a cloud VM.
- **Approval gate.** A per-run Unix-socket approval step gates spend; filesystem
  permissions are the authorization boundary, with an audit record embedded in
  run state.
- **Spend tracking.** `dispatcher bill` reports per-cloud dispatcher-tagged spend
  month-to-date (AWS Cost Explorer, Azure consumption, GCP BigQuery export,
  Hetzner via dispatcher's own tracking).
- **Hardened by default.** Single-quoted-heredoc SSH env injection, cloud-CLI
  argument discipline, label-charset validation at the boundary, `0700` state
  directories, and UNTRUSTED markers around LLM-facing content.
