# Spike: attested-TLS agent channel (sizing)

**Status: shipped.** The aTLS channel is now the transport for all three measured
backends (GCP Confidential Space, AWS Nitro, Azure SNP+vTPM), and the HTTP/HPKE
sealed exchange it replaced has been retired. Each backend was live-validated on
real hardware. The current execution path is in
[`confidential-space-execution.md`](confidential-space-execution.md); the code is
`internal/attest/atls/` (the primitive), `internal/attest/agent/atls_transport.go`
(the agent + dispatcher transport), and `internal/attest/atls_validators.go` (the
per-cloud validators).

**Outcome vs. the plan below.** It landed close to the sizing: the agents serve
`RunServerATLS`/`ServeATLSOn`; dispatcher dials `RunOverATLS` (and `AttestOverATLS`
for capture); the per-cloud `Attester` types were replaced by `AttestValidator`s
that verify evidence supplied by the TLS exchange. The **client-side preemption**
caveat still holds: aTLS closes the relay/MITM class, and the fail-closed per-run
firewall remains the boundary against a rogue client (mutual aTLS / single-accept
not yet added). The rest of this document is the original proposal, kept as the
design record.

## The gap it closes

The in-TEE agent already binds its channel key into the attestation report
(`REPORT_DATA = H(nonce ‖ channelKey)`), and dispatcher verifies that before
sealing. But `/attest` hands the channel key to any caller and `/payload` runs
the **first** ciphertext sealed to it, so a co-located / on-path host can fetch
the key and submit its own workload first. Confidentiality holds (the attacker
can't read our sealed payload); the exposure is **preemption / DoS**, gated only
by the per-run firewall — which itself only fails safe now (audit item #28).

aTLS as designed here binds the payload to **one** TLS session that is
cryptographically tied to the attestation, which defeats the **imposter-agent /
relay / MITM** angle: dispatcher will only deliver to a session that verifies as a
genuine, measurement-pinned TEE holding the attested key.

**Scope caveat (important):** this authenticates the *server* (agent) to the
*client* (dispatcher), not the reverse. It adds **no client authentication**, so a
*rogue client* that can reach the agent (past the firewall) can still open its own
attested session and deliver a payload first — the preemption race is **not**
closed by this alone. Eliminating client-side preemption additionally needs
**mutual aTLS** (client auth over the session) or a **single-accept / session-lock**
on the agent. Until one of those lands, the per-run firewall remains the boundary
against a rogue client; aTLS demotes it to defense-in-depth only for the
relay/MITM class.

## Key finding: we build it clean-room on stdlib (no dependency)

The obvious "adopt Edgeless `atls`" plan is **not viable**:

- It is `github.com/edgelesssys/constellation/v2/internal/atls` — an `internal/`
  package, so Go **blocks importing it** outside that module.
- It is **BUSL-1.1** licensed (source-available, not permissive OSS), so we can't
  vendor or copy it either.

So we mirror only its *shape* — the standard aTLS `Issuer`/`Validator` split
(`Issue(userData, nonce)` / `Validate(attDoc, nonce)`) — on top of the Go
standard library. **Net new dependencies: zero.** This is strictly better than
taking the dep.

## Design (what the spike implements and proves)

stdlib `crypto/tls` does not expose the handshake randoms, so freshness/binding
comes from **RFC 5705 exported keying material**
(`tls.ConnectionState.ExportKeyingMaterial`) rather than a cert-embedded quote:

1. Agent serves TLS 1.3 using its **ephemeral, attestation-bound key** as the
   cert (`ServerConfig`). Dispatcher dials with `InsecureSkipVerify` — trust is
   attestation, not PKI (`ClientConfig`).
2. After the handshake, both derive `exporter = ExportKeyingMaterial("dispatcher/confidential/atls/v1", …)`.
3. Dispatcher sends a fresh 32-byte `nonce` over the (encrypted) session.
4. Agent's `Issue` returns evidence whose `REPORT_DATA` commits to
   `bindData = H(agentCertPubKey ‖ exporter)` **and** the nonce.
5. Dispatcher's `Validate` runs the existing per-cloud verifier **and** checks
   that `REPORT_DATA` commits to `H(theCertKeyItSaw ‖ itsOwnExporter)` and its
   nonce. Only then is the workload delivered over the same `conn`.

Because `bindData` includes the session exporter, evidence verified on one
session cannot be relayed onto another; because it includes the cert key,
completing the handshake proves liveness of the TEE that holds the attested key.

The spike's tests (`go test ./internal/attest/atls/`) exercise this over **real
loopback TLS 1.3 handshakes** and pass:

| Test | Proves |
|---|---|
| `HonestAgentVerifies` | end-to-end wiring: handshake → exporter → nonce → issue → validate |
| `RelayRejected` | **real relay** (dispatcher → relay-with-its-own-cert → genuine agent): relayed genuine evidence is bound to the agent↔relay session, so dispatcher rejects it |
| `ExporterBindingIsLoadBearing` | same cert key + nonce but a different session exporter fails → a regression dropping the exporter from `bindData` would fail this |
| `StaleNonceRejected` | a report that omits the fresh nonce is rejected |
| `ClientAttestTimesOutOnStalledPeer` | a peer that handshakes then stalls fails fast via the ctx deadline (no hang) |
| `ExporterIsPerSession` | distinct exporter per handshake (a TLS property the binding leans on) |

## Mapping to what we already have

- **`Issuer` ← existing evidence producers.** The in-TEE producers — `agent.Serve`
  + the per-cloud `AttestFunc` in `internal/attest/agent/{aws,azure,nitro}`, run by
  the `cmd/dispatcher-attest*` binaries — already generate a report/token with
  `REPORT_DATA = H(nonce ‖ key)`. Change: bind `bindData` (key ‖ exporter) instead
  of the bare channel key. (`agent.FetchAttestation` is the *dispatcher-side* fetch
  that `ClientAttest` replaces, not a producer.)
- **`Validator` ← existing verifiers.** `internal/attest`'s SNP/MAA/Nitro
  verifiers + `applyPolicy` already verify chain, measurement pins, and the
  `REPORT_DATA` binding. Change: expose a `Validate(evidence, bindData, nonce)`
  seam. Today the `attest.Attester` interface is `Verify(ctx, req)` and each
  attester *fetches its own* evidence via an internal `fetch` seam; aTLS supplies
  the evidence from the TLS exchange instead, so we split "fetch" from "verify".
- **Per-backend:** evidence differs (SNP report / MAA JWT / Nitro COSE doc). The
  `Validator` stays evidence-agnostic (opaque `evidence []byte` + a backend tag,
  like Edgeless's `variant.Getter`); the existing verifiers already branch.

## Sizing

**New (`internal/attest/atls/`):** ~230 LOC of config builders + the exchange +
framing (already written in the spike) + tests. No new deps.

**Changes to wire it in (the real work):**

| Area | Change | Rough size |
|---|---|---|
| Verifier seam | Expose `Validate(evidence, bindData, nonce)` on the SNP/MAA/Nitro verifiers (split fetch from verify) | M — refactor, existing logic |
| Agent producers | Bind `bindData` (key ‖ exporter) in `Issue`; serve the sealed exchange over the aTLS listener | M |
| Agent server | `cmd/dispatcher-attest*` + `agent.Serve` listen with `ServerConfig`; run `ServerAttest` post-handshake | S |
| Dispatcher client | The confidential adapters dial `ClientConfig` + `ClientAttest`, then deliver the payload over the session; drop the `/attest`+anonymous-HPKE key hand-out | M |
| **Client-side preemption** | To actually close the rogue-client race (not just relay/MITM), add **mutual aTLS** (a dispatcher-authenticated client cert the agent checks) **or** a single-accept/session-lock on the agent. Without it the firewall stays the boundary against a rogue client. | S–M |
| I/O deadlines | Bound the post-handshake exchange (done in the spike via ctx → `conn.SetDeadline`) so a stalled peer fails fast | done |
| Firewall | Keep the fail-closed `/32` firewall as defense-in-depth (still the boundary against a rogue client until client auth lands) | none |
| Tests | Negative tests per backend (tampered evidence, wrong measurement, wrong nonce, relayed session — see `RelayRejected`/`ExporterBindingIsLoadBearing`) | M |

Ballpark: **~1–2 focused days**, no new dependencies, and it *removes* code (the
anonymous-HPKE `/attest`/`/payload` dance and the key hand-out).

## Risks

- **aTLS is subtle.** The USENIX ATC '25 formal analysis found real bugs in
  shipping attested-TLS protocols. Mitigation: the design binds to the TLS
  exporter (RFC 5705) rather than a hand-rolled channel, keeps the nonce
  challenge we already have, and every failure mode has a negative test.
- **Verifier refactor** touches security-critical code — do it test-first, keep
  the current golden tests green.
- Not a data-plane change: keep the firewall fail-closed as belt-and-suspenders.

## Cheaper per-cloud alternative (no aTLS at all)

For **AWS Nitro**, the gap can be closed with **zero custom crypto** by using
**KMS recipient-attestation** (PCR-gated `Decrypt`): the enclave pulls secrets
from KMS, which encrypts them to the attestation document's public key. Azure
CVMs have the analogous **Secure Key Release**, and GCP Confidential Space has
Workload Identity Federation. These offload the gate to the cloud KMS but change
the model from "dispatcher pushes a sealed workload" to "enclave pulls a secret",
so they don't uniformly replace the cross-cloud sealed-exchange design — aTLS
does.

## Recommendation

Adopt the aTLS channel (clean-room, stdlib) as the uniform fix for the
relay/MITM/imposter-agent class, **plus** mutual aTLS or a single-accept
session-lock to close client-side preemption; keep the fail-closed firewall as
the boundary against a rogue client until that lands. Consider KMS-recipient/SKR
as a per-cloud simplification later. The spike in `internal/attest/atls/` is the
starting skeleton (its own focused audit found the client-auth gap, the missing
I/O deadlines — now fixed — and that the initial tests proved the fake rather than
the binding, now replaced by a real relay test).
