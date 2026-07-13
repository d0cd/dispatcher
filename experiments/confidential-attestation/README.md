# Live TEE attestation experiment

Goal: capture a **real** attestation report (AMD SEV-SNP) or **MAA token** (Azure)
from a live confidential VM, save it as a fixture, and run it through dispatcher's
verifier cores. This closes the **format-bind gap** (`docs/confidential-computing.md`
§6/§7): it confirms the AMD ABI byte offsets and the MAA claim names the verifiers
were coded against match what the hardware/service actually emit.

It does **not** build the in-TEE guest-agent fetch (the larger increment). It is the
cheap validation step before that — a single short-lived CVM, cents of runtime.

The verifier crypto is already unit-tested against synthetic vectors. What only a
live TEE can confirm:
- SEV-SNP: the signed-region length, the r/s little-endian signature layout, the
  REPORT_DATA/MEASUREMENT/TCB offsets, and that a real VCEK→ASK→ARK chain verifies.
- MAA: the JWS signature against the live JWKS, and the `x-ms-*` claim names.

## How the golden test consumes fixtures

`internal/attest/confidential_golden_test.go` reads:

```
fixtures/
  snp/  report.bin  report-data.hex  vcek.pem  ask.pem  ark.pem
  maa/  token.jwt   jwks.json
```

Default location is `experiments/confidential-attestation/fixtures` (override with
`DISPATCHER_ATTESTATION_FIXTURES`). With no fixtures the tests **skip**, so CI stays
offline. Once captured:

```bash
go test ./internal/attest -run Golden -v
```

Fixtures are git-ignored (they're per-capture and bulky). Reports/certs aren't
secret, but don't commit them.

---

## A. AMD SEV-SNP (GCP or AWS)

### 1. Launch a confidential VM

GCP (SEV-SNP). `--min-cpu-platform="AMD Milan"` is required — without it the VM
can land on AMD Rome, which only supports SEV (not SEV-SNP). Ubuntu 22.04 ships
the `/dev/sev-guest` device; some images (e.g. Debian 12) don't.

```bash
# Optional pre-checks: zone has Milan, and an SEV-SNP-capable image exists.
gcloud compute zones describe us-central1-a --format="value(availableCpuPlatforms)"
gcloud compute images list --filter="guestOsFeatures[].type:SEV_SNP_CAPABLE"

gcloud compute instances create snp-experiment \
  --zone=us-central1-a \
  --machine-type=n2d-standard-2 \
  --min-cpu-platform="AMD Milan" \
  --confidential-compute-type=SEV_SNP \
  --maintenance-policy=TERMINATE \
  --image-family=ubuntu-2204-lts --image-project=ubuntu-os-cloud
```

> Note: recent GCP firmware emits **v4** SEV-SNP reports. The verifier was coded
> to the documented ABI (the fields it reads — REPORT_DATA, MEASUREMENT,
> REPORTED_TCB, signature — are stable across v3/v4). If `Golden_SNPReport` fails
> the signature or REPORT_DATA check, that's a v4 layout change to fold into
> `snp.go` — which is exactly what this experiment is for.

AWS (SEV-SNP; M6a/C6a/R6a on a supported region/AMI):

```bash
aws ec2 run-instances \
  --image-id <ubuntu-ami> --instance-type m6a.large \
  --cpu-options AmdSevSnp=enabled \
  --key-name <your-key> --region <region>
```

### 2. Capture on the VM

SSH in, copy `capture-snp.sh` over, and run it:

```bash
sudo ./capture-snp.sh ./snp-out
```

The script writes `report.bin`, `report-data.hex`, `vcek.pem`, `ask.pem`, `ark.pem`.

### 3. Pull fixtures back and verify

```bash
scp -r <vm>:snp-out/* experiments/confidential-attestation/fixtures/snp/
go test ./internal/attest -run Golden_SNPReport -v
```

### 4. Tear down

```bash
gcloud compute instances delete snp-experiment --zone=us-central1-a --quiet
# or: aws ec2 terminate-instances --instance-ids <id> --region <region>
```

---

## B. Azure MAA

### 1. Launch a confidential VM

```bash
az vm create -g <rg> -n maa-experiment \
  --size Standard_DC2as_v5 \
  --image Canonical:ubuntu-24_04-lts-cvm:cvm:latest \
  --security-type ConfidentialVM --enable-vtpm true --enable-secure-boot true \
  --os-disk-security-encryption-type VMGuestStateOnly \
  --admin-username azureuser --generate-ssh-keys
```

### 2. Capture on the VM

SSH in, copy `capture-maa.sh` over, and run it. It fetches the MAA JWKS and
obtains a token via Azure's guest-attestation client (see the script header for the
client build step):

```bash
sudo ./capture-maa.sh ./maa-out
```

Writes `token.jwt` and `jwks.json`.

### 3. Pull fixtures back and verify

```bash
scp -r <vm>:maa-out/* experiments/confidential-attestation/fixtures/maa/
go test ./internal/attest -run Golden_MAAToken -v
```

### 4. Tear down

```bash
az vm delete -g <rg> -n maa-experiment --yes
```

---

## If a golden test fails

That's the experiment working — it found a real mismatch between our verifier and
the hardware/service. Likely culprits and where to fix:

- **SNP signature fails** → `snpSignedLen` or the r/s layout in `snp.go`.
- **REPORT_DATA assertion fails** → `snpOffData` (or another field offset).
- **SNP chain fails** → cert encoding / `verifySNPChain` (or the ARK is a different
  root than the captured chain — pin the right AMD root).
- **MAA empty measurement/report-data** → the `x-ms-sevsnpvm-*` claim names in
  `maa.go` differ from this MAA instance's schema.
