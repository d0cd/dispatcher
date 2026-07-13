# Making confidential attestation operational

**Status:** all three major clouds are operational and live-validated end-to-end
(build/provision → attest → seal → run-in-TEE → sealed result → teardown):
- **GCP Confidential Space** — vendor CS token; container path.
- **Azure MAA** — vendor MAA token (nested schema, client-payload binding);
  SSH-VM path (`docs/confidential-azure-maa.md`).
- **AWS SEV-SNP** — raw report verified with `go-sev-guest` + the VLEK/ASVK KDS
  chain; SSH-VM path.

All verification uses **vetted libraries** — go-jose (JWS), cloudflare/circl
(HPKE), google/go-sev-guest (SEV-SNP), edgelesssys/go-azguestattestation (Azure
vTPM/MAA) — no hand-rolled crypto in any operational path. This doc is the
"how/why" — requirements R1–R13 + threat model live in
[confidential-computing.md](confidential-computing.md).

## Known limitations

- ✅ **AWS ARK pinning + CRL (cc-6): closed.** The AWS verifier pins the KDS ARK
  to go-sev-guest's embedded AMD root and checks the ASVK CRL (stdlib x509).
- ⚠️ **Agent not in the measurement (Azure + AWS): verifier done, image build
  pending.** GCP measures the agent (the container digest *is* the measurement).
  On the SSH-VM paths the agent is scp'd after boot, so it's outside the launch
  measurement. What each measurement *does* anchor, and how each closes:
  - **GCP** — the workload container image digest (agent included). ✅ closed.
  - **Azure** — ✅ **closed.** The agent is baked into a **dm-verity root** in a
    custom mkosi image; the verity roothash rides in the UKI cmdline, measured into
    **PCR11**, verified **directly** (SEV-SNP report + vTPM quote, no MAA — which
    sidesteps MAA's 0–7 PCR limit and its secure-boot policy). Live-validated E2E
    (`NewAzureSNPAttester`, `dispatcher-attest-azuresnp`, the mkosi image, and the
    `AzureSNPConfidentialAdapter`). See `docs/confidential-azure-uki.md`.
  - **AWS** — EC2 SEV-SNP measures the AWS guest **firmware** only, and there is
    **no vTPM/PCR chain**, so the agent cannot be folded into the launch
    measurement via a custom AMI. The only path is **Nitro Enclaves**, where the
    enclave image itself is measured (PCR0). **Verifier + enclave loop
    live-validated** on real hardware (`NewAWSNitroAttester`, in-enclave agent
    over vsock + NSM, pinned Root-G1 — see `docs/confidential-nitro.md`). The
    dispatcher-side adapter that automates provisioning has shipped
    (`AWSNitroConfidentialAdapter`, selected via `confidential.profile: nitro`).
    Note Nitro is a distinct, restricted execution model (no direct network/disk
    in the enclave).

  Until the image/enclave builds land, agent integrity on the SSH-VM paths
  assumes the host does not tamper with the on-disk binary before it runs (a
  malicious-cloud-provider threat; passive host reads of live guest memory are
  already blocked by SEV-SNP).

**Assurance (read before shipping):** this is an **MVP — the happy path is
live-validated, not a security-audited production feature.** All cryptography
uses vetted libraries — JWS/JWT verification via **go-jose v4**, HPKE (RFC 9180)
sealing via **cloudflare/circl**, hashes via the Go stdlib; there is no
hand-rolled crypto in any operational path. What remains bespoke is a small,
non-cryptographic **policy + binding layer** (issuer/`kid` pinning, measurement
allowlist, debug-off, and the nonce ↔ channel-key binding), covered by adversarial
negative tests + a bit-exact binding property test + an SNP-parser fuzz target.
Before customers rely on this, that policy layer still warrants a **lightweight
independent security review** (an app-logic review, not a crypto audit).

## Where we are

- ✅ **Verifier is correct** (audited): SEV-SNP ECDSA-P384 report verify + VCEK←ASK←ARK
  chain (pinned, embedded roots); JWS verifier hardened against alg-confusion;
  `applyPolicy` enforces measurement allowlist + debug/migration off + the
  `REPORT_DATA == SHA-512(nonce ‖ channelKey)` binding, with self-defense on the
  binding inputs.
- ✅ **Gate is wired fail-closed**: `confidentialAttestationPreflight` rejects an
  `attestation: required` run *before* provisioning if the attester isn't ready;
  post-boot `verifyConfidential` runs *before* any secret is shipped; a failed
  verdict tears the VM down.
- ✅ **Seams exist**: `snpFetch` / `maaFetch` function types, `snpAttester{roots,
  fetch, isReady}` / `azureAttester{keys, fetch, isReady}`, and
  `VerificationPolicy{Nonce, ChannelKey, ...}`.
- ✅ **The evidence source is wired.** Every attester constructor sets
  `isReady=true` with a live `fetch` (`csEndpointFetch` / `endpointMAAFetch` /
  `endpointSNPFetch`); the in-TEE measured agent (`internal/attest/agent` +
  `cmd/dispatcher-attest*`) returns the report/token bound to the per-run nonce
  and channel key (`REPORT_DATA = H(N‖key)`), and a `required` run verifies
  before shipping any secret. Measured images exist for all three clouds (GCP
  Confidential Space digest, Azure `profile: azure-snp` PCR11, AWS `profile:
  nitro` PCR0). Residual: the *standard* AWS SEV-SNP / Azure MAA agent is scp'd,
  not folded into the launch measurement — the measured backends close that.

## The trust-bootstrap chain (target)

```
verifier: N ← 32 random bytes
   │  (over the not-yet-trusted SSH channel)
   ▼
in-TEE agent  [MEASURED — part of the launch image]:
   Kpub,Kpriv ← fresh X25519 keypair          (ephemeral, per fetch)
   REPORT_DATA ← SHA-512(N ‖ Kpub)
   evidence ← hardware attestation over REPORT_DATA   (firmware/vendor-signed)
   return (evidence, cert-chain, Kpub)
   │
   ▼
verifier:
   verify signature + chain to pinned root      → genuine TEE          (R3/R4)
   measurement ∈ allowlist                       → expected image+agent (R7)
   REPORT_DATA == SHA-512(N ‖ Kpub)              → fresh, this run/key  (R1/R2)
   │
   ▼
dispatcher: seal(source+.env → Kpub)             → only the measured agent decrypts (R9)
```

**Keystone:** the agent must be *inside the launch measurement*. That is what
makes "measurement ∈ allowlist" mean "the code that produced `Kpub` is the real
agent," which is what lets us seal secrets to `Kpub` and nothing else. Booting
stock Ubuntu with a cloud-init-injected agent is host-swappable and defeats this
(cc-3) — the agent must ship in a pinned, measured image.

## The design fork (per provider)

| Path | Evidence | Verify with | Ops burden |
|---|---|---|---|
| **Raw hardware** | SEV-SNP report from `/dev/sev-guest` + VCEK/ASK chain | existing SNP verifier (`snp.go`) | **You own measurement stability** — every kernel/agent/image rebuild changes the launch measurement → re-capture + re-ship the allowlist |
| **Vendor runtime** | vendor-signed JWT (GCP Confidential Space / Azure MAA) asserting genuine-CVM + image/container digest + nonce | existing **`verifyJWS`** + a digest allowlist | Low — the vendor manages the measured image; you trust their attestation service |

**Recommendation:** MVP on **GCP Confidential Space** (vendor path). It reuses
`verifyJWS`, avoids the raw-image measurement treadmill, and reaches a real
guarantee fastest. Then **AWS** (raw SEV-SNP + VLEK — no clean managed
equivalent) and **Azure** (MAA). AWS *must* be raw; GCP/Azure *can* be vendor.

## Components to build

### 1. In-TEE agent contract

A small static binary shipped in the measured image. One operation:

```
attest(nonce []byte) -> {
    evidence:  <SNP report bytes>  |  <vendor JWT>
    chain:     <VCEK+ASK PEM>      |  (n/a for vendor JWT)
    channelKey: <X25519 pubkey, 32B>     # Kpub; Kpriv never leaves the TEE
}
    where REPORT_DATA / runtime-data = SHA-512(nonce ‖ channelKey)
```

Plus a `seal-open` operation: given a sealed payload, decrypt with `Kpriv`
inside the TEE and stage it. Invocation: over the per-run SSH channel (simplest;
the binding makes the channel's trust irrelevant) — a tiny `dispatcher-attest`
CLI run over SSH, stdout = JSON evidence.

### 2. Measured-image pipeline

- **Raw path:** bake the agent into the CVM image, boot it once, capture the
  launch measurement (`snpguest`/vTPM), and commit it as the **base allowlist**
  (fixes cc-4). Document the re-capture step for every image rebuild. Pin the
  image by digest at create (fixes cc-3).
- **Vendor path (GCP CS):** the workload is a *container*; Confidential Space's
  measured runtime attests the container **image digest**. Allowlist = the set
  of accepted container digests; no per-VM measurement capture.
- **Azure:** a CVM-gen image (already switched to `...:cvm:latest`) + the Azure
  guest-attestation agent → MAA token.

### 3. Fetch wiring (`snpFetch` / `maaFetch`)

Implement the existing seams: SSH to the booted VM with the per-run key, run
`dispatcher-attest <nonce>`, parse stdout into `snpEvidence`/`maaEvidence`
(report/token, chain, `channelKey`). Set the attester's `.fetch` and flip
`isReady=true` (only then does `required` stop failing closed).

### 4. Seal-to-channel-key (R9)

Replace "verify, then rsync source in the clear" with: after a verified verdict,
**seal** the source tarball + `.env` to `channelKey` (X25519 → HPKE or NaCl
sealed-box + AEAD), ship the ciphertext, and have the agent `seal-open` inside
the TEE. This closes the host-relay gap the raw SSH channel leaves open.

## Per-provider specifics + crypto gaps to close

- **GCP — Confidential Space (MVP):** consume the CS attestation JWT via
  `verifyJWS(token, googleJWKS)`; enforce the container-digest claim against the
  allowlist and the nonce binding. Pin Google's JWKS. *No SNP hardening needed on
  this path.*
- **GCP/AWS — raw SEV-SNP:** close **cc-5** (parse `REPORTED_TCB` into per-
  component SVNs, compare as a tuple — not a raw u64) and **cc-6** (add CRL/AMD-
  KDS revocation, VCEK/ASK NotBefore/NotAfter validity, VCEK-TCB == report-TCB
  binding, and map the report's product line to the *matching* ARK instead of
  accepting any pinned root).
- **AWS — VLEK (cc-2):** AWS signs with **VLEK, not VCEK** (chip id masked). Add a
  `VLEK→ASK→ARK` path (VLEK is CSP-provided, not KDS-fetchable) or the raw path
  can't verify AWS at all.
- **Azure — MAA:** wire MAA **JWKS fetch + pinning** to the trusted MAA instance;
  add **`exp`/`nbf` and `iss`** checks to `verifyMAAToken` (defense-in-depth on
  top of the nonce binding); wire per-component TCB (MAA reports SVNs, so the
  current `TCB=0` rejects any positive `minTCB`).

## Small hardening (independent of the above, cheap now)

- `verifyMAAToken`: check `exp`/`nbf`/`iss`.
- `bindingHash`/`applyPolicy`: assert the nonce is *exactly* 32 bytes (the
  verifier already generates 32; removes a theoretical concatenation ambiguity).
- cc-5 TCB per-component parse (also needed for the raw path).

## MVP scope + sequencing

**Progress:** the verification path is built + tested + **golden-validated on a
real token** (`TestGolden_CSToken`): a live CS VM (SEV, secure boot) ran a
container that requested an OIDC token bound to a per-run nonce, and
`verifyCSToken` verified it against Google's live JWKS — signature, issuer,
`eat_nonce`, `GCP_AMD_SEV`/`CONFIDENTIAL_SPACE`/debug-off, and the image digest
all check. HPKE sealing is built. **Remaining: the run integration** — a
container-based execution path (CS is container-shaped, no SSH), wiring the
`csFetch` to the teeserver socket during a run, flipping GCP's registration to
`csAttester` + `isReady`, and sealing secrets to the channel key.

> **CS capture recipe (validated):** enable `confidentialcomputing` +
> `artifactregistry`; push a container that POSTs
> `{"audience","token_type":"OIDC","nonces":[<hex nonce>]}` to
> `/run/container_launcher/teeserver.sock`; the hardened image **requires**
> `LABEL tee.launch_policy.allow_env_override` (per-run nonce) and
> `tee.launch_policy.log_redirect=always` (to read the token); provision
> `--confidential-compute-type=SEV --shielded-secure-boot` from
> `confidential-space-images/confidential-space` with
> `tee-image-reference`/`tee-container-log-redirect`/`tee-env-*` metadata; read
> the token from the serial console / Cloud Logging.

1. **GCP Confidential Space, end-to-end** — ✅ verifier + golden capture + container
   run-integration + seal-to-`Kpub`. First real guarantee, delivered.
2. **Secret sealing (R9)** — ✅ generalized (HPKE, `internal/confidential`), reused by all paths.
3. **AWS raw SEV-SNP + VLEK** — ✅ agent (`/dev/sev-guest`), pinned image + measurement
   capture, `VLEK→ASK→ARK` path; plus a measured Nitro Enclaves backend (`profile: nitro`).
4. **Azure MAA** — ✅ guest-attestation agent, JWKS pin + `exp`/`iss`; plus a measured
   direct-SNP backend (`profile: azure-snp`, PCR11). Per-component TCB mapping remains.
5. Cheap hardening folded in as each path landed.

The remaining honest caveat is narrow: on the *standard* AWS SEV-SNP / Azure MAA
paths the scp'd agent is not itself in the launch measurement — the measured
`profile` backends (and GCP Confidential Space) close it. `attestation: off`
stays the explicit opt-out that provisions the TEE without verification.

## Decisions (approved)

- **Raw vs vendor per provider** — ✅ **vendor for GCP/Azure** (trust GCP
  Confidential Space / Microsoft MAA), **raw for AWS** (no clean managed
  equivalent; needs the VLEK path).
- **Container vs VM agent** — ✅ GCP confidential runs go through **Confidential
  Space (container-shaped)** — a distinct execution path from the SSH-into-a-VM
  model.
- **Sealing scheme** — ✅ **HPKE (RFC 9180)** for seal-to-`Kpub` (`Kpub` = X25519).
  **Built** (`seal.go`): `sealToChannelKey`/`openSealed`/`newChannelKeypair`,
  DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/ChaCha20Poly1305 via `cloudflare/circl`
  (required bumping the toolchain to go 1.24; CI updated).
- **Measurement update process** (raw AWS path) — re-capture + PR the allowlist on
  every image rebuild; a CI check pins the expected measurement per image digest.

Cheap hardening from the security review is **done** (commit `4f74487`): MAA
`exp`/`nbf`/`iss` checks, per-component TCB comparison, fixed-32-byte nonce.
