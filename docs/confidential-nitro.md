# AWS Nitro Enclaves confidential runs

Nitro Enclaves is dispatcher's path to a **measured agent on AWS**. EC2 SEV-SNP
measures only the guest firmware and has no vTPM, so the scp'd agent there is not
attested (see `docs/confidential-attestation-plan.md`). A Nitro enclave is
different: the **enclave image itself is measured** — PCR0 is the whole image,
PCR1 the kernel+bootstrap, PCR2 the application — and attested by the AWS Nitro
hypervisor's PKI. Pinning PCR0 attests the exact agent+workload image.

## Execution model (important constraints)

A Nitro enclave is a stripped VM carved from the parent instance:

- **No network.** Only a `vsock` channel to the parent. dispatcher reaches the
  in-enclave agent through `dispatcher-nitro-proxy` on the parent (TCP ⇄ vsock).
- **No persistent disk.** A memory-backed root only; RAM is fixed at launch.
- **Self-contained workloads only.** The workload runs inside the enclave via the
  agent's exec runner, but cannot `pip install` / `apt get` / fetch at run time —
  bake everything it needs into the enclave image (`deploy/nitro/Dockerfile`).

These are inherent to Nitro. The sealed exchange (attest → seal source/.env → run
→ sealed result) is identical to the other clouds; only the transport (vsock) and
the attestation format (Nitro COSE doc) differ.

## Pieces

| Component | Where it runs | Code |
| --- | --- | --- |
| `dispatcher-attest-nitro` | inside the enclave | `internal/attest/agent/nitro` (vsock + NSM) |
| `dispatcher-nitro-proxy` | the parent instance | `cmd/dispatcher-nitro-proxy` |
| verifier | dispatcher | `attest.NewAWSNitroAttester` (pinned Root-G1 + PCR pins) |

## Live validation runbook

1. **Launch a Nitro-enabled parent** (enclave support needs a supported instance
   type and `--enclave-options Enabled=true`), e.g. `c6a.xlarge` in a region with
   Nitro Enclaves. Install docker + `aws-nitro-enclaves-cli`, enable the allocator
   (`nitro-cli-config`), and reserve CPUs/memory for the enclave.

2. **Build the EIF + capture PCR0** (on the parent, repo synced):

   ```
   ./deploy/nitro/build-eif.sh          # prints Measurements{PCR0,PCR1,PCR2}
   ```

3. **Cross-compile + copy the proxy** to the parent:

   ```
   GOOS=linux GOARCH=amd64 go build -o dispatcher-nitro-proxy ./cmd/dispatcher-nitro-proxy
   ```

4. **Run the enclave + proxy** (on the parent):

   ```
   sudo ./deploy/nitro/run-enclave.sh   # runs the enclave, bridges :8443 -> vsock
   ```

5. **Run via dispatcher** — the adapter automates provisioning the parent, the
   nitro-cli install, shipping the EIF + proxy, running the enclave, and the
   attest → seal → run exchange. Select it with `confidential.profile: nitro` in the
   workload and pin the pre-built enclave image:

   ```
   DISPATCHER_AWS_NITRO_EIF=<path to dispatcher-attest-nitro.eif from step 2> \
   DISPATCHER_AWS_NITRO_PCR0=<pcr0 from step 2> \
   DISPATCHER_AWS_NITRO_PROXY_BIN=<linux/amd64 dispatcher-nitro-proxy> \
   DISPATCHER_AWS_REGION=us-east-1 \
   ./dispatcher run .
   ```

   The adapter fails closed if the EIF / PCR0 / proxy aren't set. Optional:
   `DISPATCHER_AWS_NITRO_INSTANCE_TYPE` (default `c6a.xlarge`),
   `DISPATCHER_AWS_NITRO_AMI`. Steps 1–4 above are the *manual* equivalent, useful
   for capturing PCR0 and validating a new image before pinning it.

6. **Reap**: dispatcher's `stop`/cleanup terminates the parent (which tears down
   the enclave). For the manual path: `nitro-cli terminate-enclave --all` and
   terminate the instance.

## Status

- ✅ **Core loop live-validated** on a real enclave (c6a.xlarge, us-east-1):
  build EIF → capture PCR0 → run enclave + proxy → fetch the real NSM attestation
  doc → verify (chain to Root-G1 + COSE signature + nonce + PCR0) → seal → run the
  workload inside the enclave → open the sealed result. Verifier
  (`attest.NewAWSNitroAttester`), pinned Root-G1, in-enclave agent (vsock + NSM),
  parent proxy, and EIF packaging all confirmed against hardware.
  - Finding: the NSM emits an *untagged* COSE_Sign1 (no CBOR tag 18); the verifier
    accepts either form.
- ✅ **Dispatcher-side adapter** (`AWSNitroConfidentialAdapter`): `dispatcher run`
  with `confidential.profile: nitro` provisions the parent, installs nitro-cli, ships
  the pinned EIF + proxy, runs the enclave, and drives the sealed exchange —
  **live-validated end-to-end** (`TestGolden_NitroLiveAdapter`, us-east-1): sealed
  .env + source reached the enclave, the workload ran, the sealed result came back,
  and Cleanup reaped the parent. The AWS measured-agent path is complete.
