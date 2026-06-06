# Dispatcher Design Doc

**Status:** Draft  
**Project name:** Dispatcher  
**One-line description:** Dispatcher plans, prices, and runs workloads across configured execution targets.

---

## 1. Summary

Dispatcher is an AI-assisted workload planner and runner.

Given a workload and user constraints, Dispatcher answers:

1. Where can this workload run?
2. What will it likely cost?
3. What might go wrong?
4. What is the recommended execution plan?
5. Can Dispatcher execute that plan reliably, with logs, artifacts, cost tracking, and cleanup?

The core product loop is:

```text
Workload → Plan → Cost/Risk → Run → Observe → Cleanup
```

The key architectural principle is:

```text
The agent proposes.
Deterministic tools verify.
Policy gates risky actions.
The executor runs approved plans.
The reconciler audits what happened.
```

Dispatcher should feel simple to use:

```bash
dispatcher plan .
dispatcher run .
```

But internally it should support a capability-based model that can grow to include local machines, SSH targets, Kubernetes, cloud VMs, managed platforms like Modal, sandbox platforms like E2B, neo clouds, devices, bare metal, and eventually performance profiling.

---

## 2. Product Promise

Dispatcher tells you:

> Given this workload and my constraints, here is where it can run, what it will cost, what might go wrong, and how to execute the chosen plan reliably.

Dispatcher should not promise that every workload can run everywhere.

Instead, Dispatcher should promise:

> We will inspect your workload, evaluate your configured targets, tell you which targets are feasible or rejected, explain why, estimate cost with confidence, and execute validated plans with cleanup and observability.

---

## 3. Goals

### 3.1 User Goals

Users should be able to:

- Define a workload with minimal configuration.
- Ask Dispatcher where it can run.
- Specify a target explicitly and check feasibility.
- Ask Dispatcher to recommend a target based on cost, speed, reliability, or policy.
- See cost estimates before running.
- See cost confidence and cost assumptions.
- Understand risks before execution.
- Execute the chosen plan.
- View logs, status, artifacts, cost, and cleanup status.
- Re-run, explain, or debug previous runs.

### 3.2 System Goals

Dispatcher should:

- Keep the default UX simple.
- Support structured planning.
- Use deterministic validation for correctness.
- Keep the agent bounded and auditable.
- Track resources and costs.
- Avoid silent cloud resource leaks.
- Make rejected targets explainable.
- Produce a durable run manifest.
- Support progressively more execution targets through adapters.

---

## 4. Non-Goals for v1

Dispatcher v1 should not try to be:

- A full Terraform replacement.
- A full Kubernetes replacement.
- A full PaaS.
- A full workflow engine.
- A full database provisioning system.
- A full FinOps platform.
- A universal mobile/edge/device orchestration platform.
- A deep performance lab by default.
- A system that guarantees every workload is portable everywhere.

These may become future expansion areas, but the first version should focus on the planning and running loop.

---

## 5. Core Concepts

Dispatcher has five main user-visible objects.

### 5.1 Workload

A workload is what the user wants to run.

Examples:

- Python script
- Containerized batch job
- Containerized service
- GPU job
- Sandbox task
- Simple CLI command

v1 should focus on:

- Single jobs
- Simple services
- Container images
- Scripts that can be packaged into containers
- Sandbox tasks

### 5.2 Target

A target is a place where Dispatcher may run a workload.

Examples:

- Local Docker
- Remote SSH machine
- Kubernetes cluster
- Cloud VM
- Modal
- E2B
- Internal platform
- Future: neo cloud, bare metal, Slurm, enrolled device

Targets advertise capabilities. Dispatcher does not assume every target supports every workload.

### 5.3 Plan

A plan is Dispatcher’s structured answer to:

```text
Where can this workload run, what will it cost, what might go wrong, and what do we recommend?
```

A plan includes:

- Workload analysis
- Candidate targets
- Recommended target
- Alternatives
- Rejected targets and reasons
- Cost estimates
- Confidence levels
- Risks
- Required approvals
- Execution steps
- Validation status

### 5.4 Run

A run is an execution instance of a validated plan.

A run tracks:

- Status
- Target
- Logs
- Metrics
- Artifacts
- Cost
- Errors
- Cleanup
- Manifest

### 5.5 Artifact

Artifacts are outputs produced by a run.

Examples:

- Logs
- Output files
- Run manifest
- Metrics
- Profiles
- Generated configs
- Failure reports

---

## 6. Default Mode

Default mode is central to Dispatcher.

The default command should be:

```bash
dispatcher plan .
dispatcher run .
```

Default mode should mean:

```text
Use safe defaults.
Use configured targets.
Infer workload shape.
Estimate cost.
Recommend a reasonable plan.
Do not use privileged access.
Do not use expensive or unknown-cost resources without approval.
Track logs, artifacts, cost, and cleanup.
```

Default mode should not mean:

```text
Try literally every possible provider.
Run on expensive GPUs without approval.
Expose public endpoints silently.
Use bare metal automatically.
Enable deep profiling automatically.
Inject cloud credentials into workloads.
```

---

## 7. Example UX

### 7.1 Plan a Repo

```bash
dispatcher plan .
```

Example output:

```text
Detected:
  Python FastAPI service
  Port: 8000
  Dockerfile: not found
  Package plan: generate container image from Python 3.11

Recommended:
  Target: internal-kubernetes
  Runtime: Kubernetes Deployment
  Estimated cost: $2.10/day
  Confidence: medium

Why:
  - service workload detected
  - no GPU required
  - internal Kubernetes has private registry access
  - cheaper than provisioning a dedicated VM

Alternatives:
  Modal: $3.40/day, easier setup, less private networking control
  AWS VM: $6.20/day, more isolated, more setup

Rejected:
  E2B: long-running service is not a sandbox task
  GPU cloud: no accelerator requested
  Bare metal: unnecessary for standard profile

Risks:
  - no health endpoint detected
  - runtime estimate is based on default assumptions
  - public endpoint requires approval

Proposed files:
  + Dockerfile.dispatch
  + dispatch.yaml
```

### 7.2 Run the Recommended Plan

```bash
dispatcher run .
```

Example output:

```text
Using plan: plan_123
Target: internal-kubernetes
Estimated cost: $2.10/day
Approval required: public endpoint

Approved.

Run: run_456
Status: running
Logs: dispatcher logs run_456
Cost: dispatcher cost run_456
```

### 7.3 Specify a Target

```bash
dispatcher plan . --target modal
```

Example output:

```text
Modal is conditionally feasible.

Blocked by:
  - private database access is not configured

Possible fixes:
  1. Configure private network access for Modal.
  2. Use internal-kubernetes, which already has private network access.
  3. Remove the private database dependency for this run.
```

### 7.4 Optimize for Cost

```bash
dispatcher plan . --optimize cost --max-cost 50
```

Example output:

```text
Recommended:
  Target: internal-kubernetes
  Estimated cost: $12.40
  Confidence: high

Cheapest feasible target:
  Local workstation: $0 marginal cost

Not recommended because:
  - slower historical runtime
  - no team cost accounting
  - not allowed by workspace policy for shared runs
```

---

## 8. CLI Surface

v1 should keep the command surface small.

```bash
dispatcher init

dispatcher targets list
dispatcher targets add <target>
dispatcher targets doctor <target>

dispatcher plan <path-or-image>
dispatcher run <path-or-image>

dispatcher status <run>
dispatcher logs <run>
dispatcher cost <run>
dispatcher artifacts <run>
dispatcher explain <plan-or-run>
dispatch cleanup <run>
```

Advanced examples:

```bash
dispatcher plan . --target aws
dispatcher plan . --target modal
dispatcher plan . --target e2b
dispatcher plan . --gpu 1
dispatcher plan . --gpu h100:1
dispatcher plan . --max-cost 50
dispatcher plan . --optimize cost
dispatcher plan . --optimize speed
dispatcher plan . --sandbox
dispatcher plan . --profile perf
```

---

## 9. User-Facing Workload Spec

The user-facing spec should be small.

### 9.1 Minimal Container Job

```yaml
name: train-small
image: ghcr.io/acme/train:latest
command: ["python", "train.py"]
maxCost: 25
```

### 9.2 GPU Job

```yaml
name: train-gpu
image: ghcr.io/acme/train:latest
command: ["python", "train.py"]
gpu: 1
maxCost: 50
```

### 9.3 Service

```yaml
name: api
image: ghcr.io/acme/api:latest
service:
  port: 8080
maxCost: 20
```

### 9.4 Sandbox Task

```yaml
name: agent-code-task
sandbox: true
command: ["python", "solve.py"]
maxCost: 5
```

Internally, Dispatcher can expand these into a richer plan model.

---

## 10. Internal Plan Schema

A plan should be structured and validateable.

```yaml
apiVersion: dispatcher.dev/v1
kind: Plan

metadata:
  id: plan_123
  createdAt: 2026-05-06T12:00:00Z
  createdBy: user_abc

workload:
  name: api-service
  detectedKind: service
  source:
    type: repo
    path: .
  package:
    type: container
    dockerfile: ./Dockerfile
    buildRequired: true
  command: null
  ports:
    - 8080
  requirements:
    cpu: 2
    memory: 4Gi
    gpu: none

constraints:
  targetScope: workspace-defaults
  optimizeFor: lowest-cost-success
  maxEstimatedCostUsd: 25

recommendation:
  target: internal-kubernetes
  runtime: kubernetes-deployment
  estimatedCost:
    value: 3.20
    currency: USD
    confidence: medium
    assumptions:
      - assumes 24h runtime
      - excludes unexpected egress
  reason:
    - workload is containerized
    - service port 8080 detected
    - no GPU required
    - target has registry access
    - cheaper than provisioning a dedicated VM

alternatives:
  - target: modal
    runtime: managed-service
    estimatedCost:
      value: 4.80
      currency: USD
      confidence: medium
    tradeoff:
      - simpler autoscaling
      - less private networking control

  - target: aws-vm
    runtime: cloud-vm
    estimatedCost:
      value: 7.50
      currency: USD
      confidence: low
    tradeoff:
      - more isolation
      - more setup and cleanup risk

rejected:
  - target: e2b
    reason: workload is a long-running service, not a sandbox task

  - target: bare-metal-pool
    reason: feasible, but unnecessary for standard profile

risks:
  - runtime estimate is not based on historical data
  - public endpoint exposure requires approval
  - data egress was not detected but could affect cost

validation:
  schema: pass
  packageBuild: pass
  targetCapabilities: pass
  credentials: pass
  quota: pass
  network: pass
  policy: pass
  costEstimate: pass
  cleanupPlan: pass

requiredApprovals:
  - public-endpoint

executionSteps:
  - build-image
  - push-image
  - deploy-service
  - wait-for-health-check
  - stream-logs
  - track-cost
  - register-cleanup
```

---

## 11. Architecture

```text
CLI / UI / SDK
    │
    ▼
Workload API
    │
    ▼
Planner Service
    ├── Agentic Planner
    ├── Code Inspector
    ├── Package Builder
    ├── Target Registry
    ├── Capability Checker
    ├── Cost Estimator
    ├── Policy Engine
    ├── Risk Analyzer
    └── Plan Validator
    │
    ▼
Plan Store
    │
    ▼
Approval Gate
    │
    ▼
Executor
    ├── Local Docker Adapter
    ├── SSH / Device Agent Adapter
    ├── Kubernetes Adapter
    ├── Cloud VM Adapter
    ├── Modal Adapter
    ├── E2B Adapter
    └── Future Provider Adapters
    │
    ▼
Run Reconciler
    ├── Status
    ├── Logs
    ├── Metrics
    ├── Artifacts
    ├── Cost Tracking
    ├── Cleanup
    └── Failure Explanation
```

---

## 12. Agent Design

The agent is a planner and explainer. It is not an unchecked executor.

### 12.1 Agent Responsibilities

The agent may:

- Inspect the codebase.
- Infer workload shape.
- Translate user intent into constraints.
- Generate candidate plans.
- Ask tools for target capabilities, prices, quota, network access, and policy.
- Explain recommendations.
- Generate config files.
- Suggest fixes when planning or execution fails.

The agent must not:

- Invent provider prices.
- Invent provider capabilities.
- Ignore policy.
- Execute without approval when required.
- Silently create expensive resources.
- Inject privileged access unless explicitly requested and approved.

### 12.2 Agent Tools

The agent should use tools such as:

```text
inspect_codebase(path)
detect_runtime(path)
detect_entrypoints(path)
detect_ports(path)
detect_gpu_requirements(path)
detect_data_requirements(path)
detect_secrets(path)

list_targets()
describe_target(target)
query_capabilities(target)
query_quota(target)
query_capacity(target)
query_price(target, workload)
query_network_access(target, workload)
query_secret_access(target, workload)
query_policy(workload, target)

generate_package_plan(workload)
generate_runtime_plan(workload, target)
estimate_cost(plan)
validate_plan(plan)
execute_plan(plan)
monitor_run(run_id)
cleanup_run(run_id)
explain_failure(run_id)
```

### 12.3 Agent Invariant

```text
Agent text has no side effects.
Only validated plans can be executed.
Only the executor mutates infrastructure.
```

---

## 13. Target Model

Targets advertise capabilities.

Example Kubernetes target:

```yaml
target:
  id: internal-kubernetes
  kind: kubernetes
  enabled: true

capabilities:
  workloadKinds:
    - container-job
    - container-service

  resources:
    cpu: true
    memory: true
    gpu:
      supported: true
      models:
        - a10
        - l4

  networking:
    publicEndpoint: true
    privateVpcAccess: true
    staticEgressIp: false

  accounting:
    costEstimate: true
    actualBilling: false
    rateCard: internal

  isolation:
    levels:
      - container
      - dedicated-node

  observability:
    logs: true
    metrics: true
    artifacts: true
```

Example E2B target:

```yaml
target:
  id: e2b
  kind: managed-sandbox
  enabled: true

capabilities:
  workloadKinds:
    - sandbox-task
    - code-interpreter

  networking:
    publicInternet: true
    privateVpcAccess: false

  accounting:
    costEstimate: true
    actualBilling: vendor-metered

  notSupported:
    - long-running-service
    - deep-perf
    - arbitrary-bare-metal
```

---

## 14. Adapter Interface

Every target adapter should implement a small contract.

```ts
interface TargetAdapter {
  describeCapabilities(): Promise<Capabilities>;

  validate(workload: WorkloadSpec): Promise<ValidationResult>;

  estimateCost(workload: WorkloadSpec): Promise<CostEstimate>;

  prepare(plan: Plan): Promise<PreparedPlan>;

  execute(plan: PreparedPlan): Promise<RunHandle>;

  status(run: RunHandle): Promise<RunStatus>;

  logs(run: RunHandle): AsyncIterable<LogEvent>;

  artifacts(run: RunHandle): Promise<ArtifactRef[]>;

  terminate(run: RunHandle): Promise<void>;

  cleanup(run: RunHandle): Promise<CleanupResult>;

  account(run: RunHandle): Promise<ResourceAccounting>;
}
```

Provisionable targets can implement an additional interface:

```ts
interface ProvisionableTargetAdapter extends TargetAdapter {
  provision(plan: Plan): Promise<ProvisionedResource>;
  deprovision(resource: ProvisionedResource): Promise<void>;
}
```

---

## 15. Execution Model

Runs should be managed by a state machine.

```text
Created
→ Planning
→ Validated
→ AwaitingApproval
→ Preparing
→ Running
→ CollectingArtifacts
→ ReconcilingCost
→ CleaningUp
→ Completed
```

Failure states:

```text
PlanInvalid
ApprovalDenied
PackageFailed
ProvisioningFailed
ExecutionFailed
BudgetExceeded
ArtifactFailed
CleanupFailed
CostUnknown
```

Every run should have:

- Run ID
- Plan ID
- Workload fingerprint
- Target ID
- Owner
- Budget policy
- Cleanup policy
- Resource tags
- Logs
- Artifacts
- Cost records
- Final manifest

Important invariant:

```text
No created resource should lack a run_id, owner, and cleanup policy.
```

---

## 16. Cost Model

v1 should provide honest estimates, not perfect billing reconciliation.

Dispatcher should track:

- Estimated cost before run
- Live estimated cost during run
- Final estimated cost after run
- Cost confidence
- Cost assumptions
- Known exclusions

Example:

```yaml
estimatedCost:
  value: 6.40
  currency: USD
  confidence: medium
  basis:
    - target rate card
    - expected duration: 45m
    - one GPU requested
  exclusions:
    - possible network egress
    - storage after run
```

Cost confidence levels:

```text
High:
  Price source known, runtime known or historically estimated, no major hidden variables.

Medium:
  Price source known, runtime estimated, some unknowns.

Low:
  Runtime unknown, egress unknown, provider price incomplete, or capacity uncertain.
```

Unknown-cost execution should require approval.

---

## 17. Risk Model

Plans should include risk analysis.

Risk categories:

- Cost uncertainty
- Runtime uncertainty
- Capacity risk
- Quota risk
- Credential risk
- Secret access risk
- Network access risk
- Data egress risk
- Data locality risk
- Package/build risk
- Runtime compatibility risk
- Cleanup risk
- Public endpoint risk
- Preemption risk
- Retry/idempotency risk
- Side-effect risk

Example:

```text
Risks:
  - Runtime estimate is based on a default 30-minute assumption.
  - The workload may need private package registry access.
  - Dataset is in S3 us-east-1; running outside AWS may incur egress cost.
  - Retry safety is unknown, so user-code retries are disabled by default.
```

---

## 18. Policy and Approvals

Dispatcher should include policy gates from the beginning.

Examples:

```text
under $5: auto-run allowed
unknown cost: approval required
GPU: approval required
public endpoint: approval required
privileged execution: blocked by default
external provider: approval required
production secrets: approved targets only
large data egress: approval required
bare metal: approval required
deep perf: approval required
```

The agent cannot override policy.

---

## 19. Security Model

Default security posture:

- No privileged containers.
- No host mounts.
- No Docker socket mounts.
- No long-lived cloud credentials inside workloads.
- No production secrets on unapproved targets.
- Scoped per-run identity where possible.
- Short-lived credentials where possible.
- Redacted logs for secrets.
- Audit trail for plan, approval, execution, and cleanup.

For untrusted code:

- Use sandbox targets.
- Restrict egress where possible.
- Require stronger isolation.
- Disable sensitive secrets.

For privileged/perf/bare-metal execution:

- Require explicit profile.
- Require approval.
- Prefer dedicated target.
- Record expanded audit data.

---

## 20. Data and Networking

Planning must account for data and network access.

Questions Dispatcher should answer:

- Where is the input data?
- How large is it?
- Can it move?
- What will staging cost?
- What will egress cost?
- Does the target have private network access?
- Does the workload need a public endpoint?
- Does the workload need a static egress IP?
- Can the target reach private package registries?
- Can the target reach databases or internal APIs?

A cheap compute target may be rejected if data movement or networking makes it impractical.

---

## 21. Reliability and Cleanup

Reliability requirements:

- Idempotent execution steps.
- Durable run state.
- Heartbeats for active runs.
- Resource tagging.
- Cleanup policy on every run.
- Orphan resource sweeper.
- Clear cleanup status.
- Continuing-cost warning when cleanup fails.

Example cleanup failure output:

```text
Run failed.
Cleanup incomplete.
Still running:
  aws:ec2:i-123456
Estimated continuing cost:
  $0.52/hour

Next cleanup retry:
  scheduled
```

---

## 22. Debugging UX

Users need strong failure explanations.

Commands:

```bash
dispatcher explain run_123
dispatcher logs run_123
dispatcher artifacts run_123
dispatcher reproduce run_123 --local
dispatch shell run_123
```

Example:

```text
Run failed before execution.

Reason:
  Image build failed.

Root cause:
  requirements.txt references a private package registry.
  No package registry secret is configured for target modal.

Suggested fixes:
  1. Add secret pypi_token.
  2. Use internal-kubernetes, which already has registry access.
  3. Vendor the dependency into the image.
```

---

## 23. Implementation Phases

### Phase 0: Planner-Only Prototype

Build:

- CLI skeleton
- Workload inspection
- Target registry
- Mock targets
- Cost estimator
- Agentic planner
- Plan schema
- Plan validator

Goal:

```text
dispatcher plan .
```

should produce useful recommendations, alternatives, rejected targets, cost estimates, and risks.

### Phase 1: Local and SSH Execution

Build:

- Local Docker adapter
- SSH adapter
- Run state machine
- Logs
- Artifacts
- Cleanup
- Basic cost accounting

Goal:

```text
dispatcher run .
```

can execute simple workloads locally or on a remote machine.

### Phase 2: Kubernetes, Modal, and E2B

Build:

- Kubernetes Job adapter
- Kubernetes service adapter
- Modal adapter
- E2B adapter
- Policy gates
- Approvals
- Run manifests

Goal:

Support meaningfully different target types.

### Phase 3: Cloud VM Support

Build:

- One major cloud VM adapter
- VM provisioning
- Startup agent
- Resource tagging
- Quota checks
- Rate-card pricing
- Cleanup sweeper

Goal:

Support raw cloud execution.

### Phase 4: Recommendation Quality

Build:

- Historical run database
- Runtime prediction
- Cache awareness
- Cost comparison
- Recommendation regret tracking
- Failure learning

Goal:

Improve recommendations from real outcomes.

### Phase 5: Expansion

Add later:

- More clouds
- Neo clouds
- On-device agents
- Bare metal
- Slurm
- Deep perf profile
- Billing reconciliation
- Workflow integrations

---

## 24. Testing Strategy

Dispatcher must test three things separately:

```text
Planner correctness
Execution reliability
Recommendation quality
```

### 24.1 Golden Planner Corpus

Create test fixtures with:

- Workload repo or image
- User constraints
- Configured targets
- Expected feasible targets
- Expected rejected targets
- Expected risks
- Expected approvals
- Expected cost confidence

Fixtures:

| Fixture | Expected behavior |
|---|---|
| Simple Python script | Detect script, package into container, recommend local/K8s |
| Dockerized batch job | Use existing image/Dockerfile, recommend cheapest eligible target |
| FastAPI service | Detect service port, require health-check/endpoint handling |
| GPU PyTorch job | Detect GPU need, reject CPU-only targets |
| Sandbox code task | Recommend E2B/sandbox target |
| Missing Dockerfile | Generate package plan or warn |
| Private package dependency | Require secret or reject targets without access |
| Private database dependency | Require private networking/secrets |
| Large dataset | Account for data locality and egress risk |
| Unknown duration | Produce cost range and low/medium confidence |
| Cost above budget | Reject or require approval |
| Public endpoint | Require approval |
| No GPU quota | Reject GPU target despite theoretical support |
| Unsupported architecture | Reject incompatible target |
| Untrusted code | Require sandbox isolation |
| Deep perf request | Reject Modal/E2B/shared targets |

### 24.2 Adapter Contract Tests

Every adapter must pass a shared test suite:

```text
describe capabilities
validate supported workload
reject unsupported workload
estimate cost
execute hello-world
stream logs
collect artifacts
terminate run
cleanup resources
report accounting
handle failure
```

### 24.3 Fake Provider Simulator

Build a fake target that can simulate:

- Capacity unavailable
- Quota exceeded
- Pricing unknown
- Slow provisioning
- Image pull failure
- Network unavailable
- Secret missing
- Run crash
- Run hang
- Cleanup failure
- Cost overrun
- API timeout
- Preemption

Expected behavior:

- Invalid targets are rejected before execution.
- Failed execution is explained.
- Cleanup failures are visible.
- Continuing costs are reported.

### 24.4 End-to-End Canaries

For each real target, run canaries:

- Hello-world batch job
- Log streaming job
- Artifact upload job
- Failing job
- Timeout job
- Service health-check job
- Cost-tracked job
- Cleanup verification job

For GPU targets:

- GPU visibility
- Small framework import
- Small GPU computation
- GPU metrics if supported

For sandbox targets:

- Code execution
- File read/write
- Timeout
- Cleanup

### 24.5 Agent Evaluation

Agent evals should check:

- Did it inspect before recommending?
- Did it use tools?
- Did it avoid unsupported claims?
- Did it produce a valid plan?
- Did it include alternatives?
- Did it include rejected targets?
- Did it include risks?
- Did it require approval when needed?
- Did it avoid exact prices without a cost tool?

Bad behavior should fail evals:

- Recommending a target with missing quota
- Ignoring budget
- Forgetting cleanup
- Recommending E2B for a long-running service
- Claiming unsupported deep perf capability
- Hiding cost uncertainty

### 24.6 Cost Accuracy Tests

Track:

- Estimated cost before run
- Live cost estimate
- Final estimate
- Actual cost when available
- Runtime assumption
- Actual runtime
- Confidence calibration

Metrics:

- Absolute cost error
- Percent cost error
- Over-budget rate
- Unknown-cost execution rate
- Confidence calibration

### 24.7 Cleanup and Leak Tests

Test:

- Executor crash during provisioning
- Control plane disconnect
- Run timeout
- User cancellation
- Provider cleanup API failure
- Artifact upload failure
- Budget stop

Expected:

- Resources are tagged.
- Sweeper finds orphans.
- Continuing cost is reported.
- Cleanup eventually succeeds or escalates.

### 24.8 Security and Policy Tests

Scenarios:

- GPU requires approval
- Public endpoint requires approval
- Production secrets blocked on external providers
- Unknown cost requires approval
- Privileged container blocked by default
- Host mount blocked by default
- Cloud credentials not injected into workload
- Untrusted code requires sandbox
- Large data egress requires approval

---

## 25. Success Metrics

Product metrics:

- Time to first useful plan
- Time to first successful run
- Plan acceptance rate
- Manual override rate
- Run success rate
- Cost estimate accuracy
- Cleanup success rate
- Rejected target explanation quality
- User-reported recommendation usefulness

System metrics:

- Plan validation failure rate
- False feasible rate
- False rejection rate
- Cost overrun rate
- Unknown-cost execution rate
- Orphan resource count
- Cleanup failure duration
- Adapter contract pass rate
- Agent eval pass rate

Recommendation metrics:

- Cost regret
- Latency regret
- Failure regret
- Historical recommendation improvement

---

## 26. Key Invariants

Dispatcher should enforce these invariants:

```text
No execution without a structured plan.
No plan execution without validation.
No risky execution without policy approval.
No important claim without a source of truth.
No resource without run_id, owner, and cleanup policy.
No unknown-cost execution without approval.
No silent cleanup failure.
No hidden rejected targets.
No agent-side infrastructure mutation from prose.
```

---

## 27. Open Questions

1. Should v1 prioritize jobs or services?
2. Which first cloud VM provider should be supported?
3. Should Modal and E2B be first-class v1 targets or added after Kubernetes/local/SSH?
4. How much automatic packaging should Dispatcher attempt before asking the user?
5. Should Dispatcher run plans automatically under a small cost threshold?
6. What should the default expected duration be when runtime is unknown?
7. How should Dispatcher represent internal/marginal cost for local or existing Kubernetes capacity?
8. Should Dispatcher be SaaS, self-hosted, or hybrid first?
9. What is the first target user: ML engineers, platform teams, AI-agent developers, or general app developers?
10. How much of the initial product should be planner-only before execution support?

---

## 28. Recommended v1 Scope

Recommended v1:

```text
Workloads:
  - simple scripts
  - containerized jobs
  - containerized services
  - sandbox tasks

Targets:
  - local Docker
  - SSH machine
  - Kubernetes
  - Modal
  - E2B
  - one cloud VM provider

Core capabilities:
  - inspect workload
  - generate plan
  - estimate cost
  - show alternatives/rejections/risks
  - validate plan
  - run approved plan
  - stream logs
  - collect artifacts
  - track estimated cost
  - cleanup resources
  - explain failures
```

Delay:

```text
full cloud coverage
full neo-cloud coverage
mobile devices
Slurm
deep perf
billing reconciliation
multi-service stateful apps
full workflows
advanced FinOps
```

---

## 29. Final Summary

Dispatcher should be built as:

```text
An AI-assisted workload planner and runner with deterministic validation,
capability-based target matching, honest cost estimation, policy-gated execution,
and reconciled run tracking.
```

The user experience should stay simple:

```bash
dispatcher plan .
dispatcher run .
```

The system should answer:

```text
Where can this run?
Where can it not run, and why?
What will it likely cost?
What assumptions affect that estimate?
What might go wrong?
What is the recommended plan?
What happened when it ran?
Was cleanup successful?
```

The agent makes Dispatcher feel intelligent.

The validators, adapters, policies, and reconciler make Dispatcher trustworthy.
