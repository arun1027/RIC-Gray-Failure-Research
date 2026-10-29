# Final Pre-AWS Technical Audit & Pre-Provisioning Readiness Report

**Project Title:** Evaluating Gray Failure Resilience of High-Availability Distributed Database Systems on Amazon EKS Using Chaos Engineering
**Lead Researcher:** Arun Natarajan (Student ID: 25102176, National College of Ireland)
**Primary Authoritative Reference:** MSc CA2 Final Report (`D:\RIC\Final ca2 report.pdf` / `SUPERVISOR_PROTOCOL_REVIEW_PACKAGE_B03.md`)
**Target Milestone:** Gate B-03 (Academic Protocol Approval & Pre-Provisioning Authorization)
**Date:** October 29, 2026
**Auditor Role:** Senior Cloud Reliability Engineer, Kubernetes SRE, and Database Benchmarking Auditor
**Document Status:** FORMAL TECHNICAL AUDIT REPORT

---

## 1. Executive Summary & Audit Decision

This audit conducts a comprehensive, line-by-line inspection of all cloud infrastructure-as-code files, runner configurations, security safeguards, cost mechanisms, CI validation workflows, and teardown scripts:
- [`terraform/aws-eks/main.tf`](file:///d:/Projects/RIC-Gray-Failure-Research/terraform/aws-eks/main.tf)
- [`terraform/aws-eks/variables.tf`](file:///d:/Projects/RIC-Gray-Failure-Research/terraform/aws-eks/variables.tf)
- [`terraform/modules/aurora/main.tf`](file:///d:/Projects/RIC-Gray-Failure-Research/terraform/modules/aurora/main.tf)
- [`.github/workflows/terraform-validate.yml`](file:///d:/Projects/RIC-Gray-Failure-Research/.github/workflows/terraform-validate.yml)
- [`scripts/aws/teardown-eks.sh`](file:///d:/Projects/RIC-Gray-Failure-Research/scripts/aws/teardown-eks.sh)
- Manifests across all three database engines: `kubernetes/cockroachdb/`, `kubernetes/postgres-patroni/`, and `kubernetes/aurora/`
- Benchmark orchestrators: `orchestrate_baseline-stage4-p05.py`, `orchestrate_patroni.py`, and `orchestrate_aurora.py`.

### Final Audit Determination: `NOT_READY` (For Live Provisioning) / `READY_FOR_SUPERVISOR_REVIEW` (For Protocol Freeze)

* **Architecture & IaC Design Quality:** **PASS (Offline Validated)**. The Terraform HCL structure, multi-AZ VPC layout, compute sizing (`m5.xlarge`), storage classes (`gp3` provisioned 3,000 IOPS), decoupled Aurora module, and test suites (68/68 passing tests) accurately reflect the CA2 methodology.
* **CI Validation Pipeline Established:** **PASS (Workflow Ready)**. Dedicated GitHub Actions workflow established at [`.github/workflows/terraform-validate.yml`](file:///d:/Projects/RIC-Gray-Failure-Research/.github/workflows/terraform-validate.yml) running Terraform 1.5.7 (`fmt -check`, `init -backend=false`, and `validate`) in a secure, credential-free, read-only CI container.
* **Blockers Preventing Live Cloud Provisioning:**
  1. **Academic Supervisor Written Authorization Missing:** Gate B-03 remains strictly unapproved in project records. Student protocol selections (PD-01 through PD-10) are recommendations awaiting binding supervisor determination.
  2. **Terraform CLI Validation Executed on CI Runner:** The workflow [`.github/workflows/terraform-validate.yml`](file:///d:/Projects/RIC-Gray-Failure-Research/.github/workflows/terraform-validate.yml) was triggered in GitHub Actions on commit `efef05e`, identifying an alignment failure in `terraform/aws-eks/main.tf` during `terraform fmt -check -recursive terraform/`. Canonical HCL formatting alignments have been applied to `main.tf`. Validation status remains **PENDING CI RERUN** to verify the formatting remediation.
  3. **Local Docker Daemon Access Denied:** Docker Desktop CLI is present (`v29.6.1`) but access to the Docker Windows named pipe daemon (`npipe:////./pipe/docker_engine`) is denied in the local sandbox session (`permission denied while trying to connect to the docker API`). Consequently, running a local disposable container (`hashicorp/terraform:1.5.7`) is blocked locally without manual daemon permissions or external CI execution.
  4. **Placeholder Values in Manifests:** Secrets templates (`02-aurora-secrets-template.yaml`, `03-patroni-secrets-template.yaml`) and ConfigMaps contain static development tokens and placeholder endpoints (`ric-aurora-cluster.cluster-c12345678901.us-east-1.rds.amazonaws.com`) that must be dynamically wired during provisioning.
  5. **Cost Ceiling is a Target, Not an Enforced Cap:** The \$15.00 limit is an administrative budget target. Automated hard enforcement (Lambda kill-switch) is designed but not yet deployed.

---

## 2. GitHub Actions CI Validation Workflow ([`.github/workflows/terraform-validate.yml`](file:///d:/Projects/RIC-Gray-Failure-Research/.github/workflows/terraform-validate.yml))

To establish reproducible, isolated Terraform CLI validation without installing software or modifying system settings on the Windows host, a dedicated GitHub Actions workflow was created:

### 2.1. Workflow Specifications
- **Trigger Events:**
  - `pull_request`: Automatically triggers when changes are proposed to `terraform/**` or `.github/workflows/terraform-validate.yml`.
  - `workflow_dispatch`: Enables manual on-demand execution from the GitHub Actions web UI.
- **Security Boundaries:**
  - `permissions: contents: read` (Enforces strict read-only repository token).
  - Zero AWS credentials configured (`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are explicitly omitted).
  - No remote state or backend communication (`terraform init -backend=false`).
  - No plan, apply, or destroy commands are included.
  - Zero secrets printed or exposed.
- **Engine Pinning:** Pinned to `hashicorp/setup-terraform@v3` with `terraform_version: "1.5.7"`, strictly matching the repository's `required_version = ">= 1.5.0"` constraint.

### 2.2. Network Dependency & Provider Download Architecture
During `terraform init -backend=false`, Terraform requires network egress to download:
1. `terraform-aws-modules/vpc/aws ~> 5.5.0`
2. `terraform-aws-modules/eks/aws ~> 20.8.0`
3. Official Provider Plugins from the HashiCorp Registry:
   - `hashicorp/aws ~> 5.40.0`
   - `hashicorp/kubernetes ~> 2.28.0`
   - `hashicorp/helm ~> 2.12.0`
   - `hashicorp/random ~> 3.6.0`

### 2.3. Provider Lockfile Strategy (`.terraform.lock.hcl`)
- **Current State:** No `.terraform.lock.hcl` is currently committed in `terraform/aws-eks/`.
- **Governed Process:** When the GitHub Actions workflow runs `terraform init -backend=false` for the first time, Terraform downloads the provider binaries matching version constraints and calculates their cryptographic SHA256 hashes.
- **Commit Rule:** The generated `.terraform.lock.hcl` will be reviewed, committed, and locked to ensure 100% byte-for-byte reproducibility across all future executions.

---

## 3. Terraform Configuration & Module Wiring Audit

### 3.1. Provider & Version Constraints
- **Core Version:** Constrained to `required_version = ">= 1.5.0"`.
- **AWS Provider:** Pinned to `hashicorp/aws ~> 5.40.0`.
- **Kubernetes & Helm Providers:** Pinned to `hashicorp/kubernetes ~> 2.28.0` and `hashicorp/helm ~> 2.12.0`.
- **Registry Modules:** References `terraform-aws-modules/vpc/aws ~> 5.5.0` and `terraform-aws-modules/eks/aws ~> 20.8.0`.
  - *Compatibility Verdict:* Both modules require Terraform `>= 1.3.0` and AWS provider `>= 5.34.0`. The repository settings strictly satisfy all upstream requirements.

### 3.2. VPC, Subnets & Multi-AZ Placement
- **CIDR:** `10.0.0.0/16`.
- **Availability Zone Mapping:** Explicitly declared as `["us-east-1a", "us-east-1b", "us-east-1c"]`.
- **Subnet Separation:** 3 private subnets (`10.0.1.0/24`, `10.0.2.0/24`, `10.0.3.0/24`) and 3 public subnets (`10.0.101.0/24`, `10.0.102.0/24`, `10.0.103.0/24`).
- **Cost Conservation:** Configured with `single_nat_gateway = true` to eliminate multi-NAT idle charges (\$0.045/hr saving).

### 3.3. EKS Compute, IAM & StorageClass
- **Kubernetes Version:** Pinned to `1.28`. (Amazon EKS supports Kubernetes 1.28 under standard/extended lifecycle).
- **Worker Node Group:** 3 managed nodes using **`m5.xlarge`** (4 vCPU, 16 GiB RAM per node).
- **StorageClass:** Dedicated `gp3` StorageClass with `volume_binding_mode = WaitForFirstConsumer`, `iops = 3000`, `throughput = 125`, and `encrypted = true`.

### 3.4. Aurora PostgreSQL Networking & Security
- **Decoupling:** Decoupled into `terraform/modules/aurora/main.tf` to preserve CA2 managed-service semantics.
- **Compute:** 2 instances (`db.r6g.xlarge`, 4 vCPU, 32 GiB RAM): 1 Writer in `us-east-1a` and 1 Reader in `us-east-1b`.
- **Network Isolation:** `publicly_accessible = false`; Security group ingress exclusively permits port 5432 from `module.eks.node_security_group_id`.

---

## 4. Security, Credentials & Placeholder Audit

> [!CAUTION]
> **Credential Sanitization Assertion:**
> Zero plaintext production credentials are committed or exposed. All committed templates contain development placeholders.

### Placeholder Inventory Requiring Dynamic Injection:
1. **Aurora Writer Endpoint ([`03-aurora-cluster-config.yaml`](file:///d:/Projects/RIC-Gray-Failure-Research/kubernetes/aurora/03-aurora-cluster-config.yaml)):**
   - Placeholder: `ric-aurora-cluster.cluster-c12345678901.us-east-1.rds.amazonaws.com`.
   - *Secure Injection Method:* Dynamically captured from `terraform output -raw cluster_endpoint` and applied via `kubectl create configmap aurora-cluster-config --from-literal=... --dry-run=client -o yaml | kubectl apply -f -`.
2. **Database Secrets ([`02-aurora-secrets-template.yaml`](file:///d:/Projects/RIC-Gray-Failure-Research/kubernetes/aurora/02-aurora-secrets-template.yaml) & [`03-patroni-secrets-template.yaml`](file:///d:/Projects/RIC-Gray-Failure-Research/kubernetes/postgres-patroni/03-patroni-secrets-template.yaml)):**
   - Contain static tokens (`auroraPostgresSecureToken14!`, `patroniPostgresSecurePass14!`).
   - *Secure Injection Method:* Generated at runtime via `openssl rand -base64 24` and injected directly into Kubernetes Secrets from environment variables or AWS Secrets Manager.
3. **CockroachDB Engine Image ([`values.yaml`](file:///d:/Projects/RIC-Gray-Failure-Research/kubernetes/cockroachdb/values.yaml)):**
   - Image tag: `cockroachdb/cockroach:v26.2.9`.
   - *Verification:* Cryptographic digest (`sha256:...`) must be captured and logged at pull time.

---

## 5. Independent Cost Model & Calculation (4-Hour Active Session)

The declared Terraform and Kubernetes resources were evaluated against AWS us-east-1 on-demand pricing:

| Resource Component | Declared Specification | Hourly Rate (us-east-1) | Base 4-Hour Cost |
| :--- | :--- | :--- | :--- |
| **EKS Control Plane** | 1 Managed Cluster | \$0.1000 / hr | \$0.400 |
| **EC2 Worker Nodes** | 3x `m5.xlarge` (On-Demand) | 3 × \$0.1920 = \$0.5760 / hr | \$2.304 |
| **Root EBS Volumes** | 3x 50 GB gp3 OS volumes (150 GB) | \$0.08 / GB-month | \$0.067 |
| **Database EBS Volumes** | 6x 10 GB gp3 PVCs (60 GB) | \$0.08 / GB-month | \$0.027 |
| **Aurora DB Instances** | 2x `db.r6g.xlarge` (Multi-AZ) | 2 × \$0.5200 = \$1.0400 / hr | \$4.160 |
| **Aurora Storage** | 50 GB allocated distributed log storage | \$0.10 / GB-month | \$0.028 |
| **VPC NAT Gateway** | 1 NAT Gateway (uptime) | \$0.0450 / hr | \$0.180 |
| **Subtotal Base Declared Infrastructure** | — | **\$1.7820 / hr** | **\$7.166** |

### Excluded & Variable Cost Factors (Uncertainties):
1. **NAT Gateway Data Processing:** \$0.045 per GB transferred. Scale 50 initialization (~800 MB per engine) and client traffic estimate: 5–15 GB ($\approx \$0.23 - \$0.68$).
2. **Aurora I/O Requests:** \$0.20 per 1 million requests. 10-minute pgbench run generates $\sim 500,000$ transactions ($\approx \$0.10 - \$0.30$).
3. **Cross-AZ Data Transfer:** Inter-AZ pod traffic incurs \$0.01 per GB in each direction ($\approx \$0.10 - \$0.25$).
4. **CloudWatch Metrics & Logs:** Ingested container logs and custom metrics ($\approx \$0.30$).

### Total Realistic Cost Projection:
$$\text{Expected Total 4-Hour Spend} = \$7.17 \text{ (base)} + \$1.20 \text{ (variables)} \approx \mathbf{\$8.37\text{ USD}}$$

> [!WARNING]
> **Audit Finding on the \$15 Spending Control:**
> The claimed **\$15.00 USD spending ceiling** is an **administrative cost target**, NOT an enforceable guarantee.
> Standard AWS Budget alerts are **asynchronous notifications** that emit emails or SNS messages after billing metrics sync (typically with a 6- to 24-hour reporting lag). They **do not stop running EC2 instances or drop EBS volumes**.
> *True Enforcement Mechanism:* Hard session timeout (4 hours maximum uptime enforced by a local timer and cron shutdown) coupled with strict immediate execution of `teardown-eks.sh`.

---

## 6. Teardown Safety & Sweeper Audit (`scripts/aws/teardown-eks.sh`)

| Dimension | Inspection & Evaluation | Severity | Required Remediation |
| :--- | :--- | :--- | :--- |
| **Identity & Account Check** | Step `[0/4]` asserts `aws sts get-caller-identity`. Validates AWS caller identity and halts if unauthenticated. | **PASS** | Prevents execution against unauthenticated contexts. |
| **Deletion Ordering** | Step 1: Deletes benchmark namespaces (triggering EBS PVC volume detachments).<br>Step 2: Destroys Aurora cluster via Terraform.<br>Step 3: Destroys EKS cluster & worker nodes.<br>Step 4: Sweeps unattached orphan EBS volumes. | **PASS** | Preserves AWS API dependency graphs. |
| **Blast-Radius & Scoping** | Volume sweep uses `--filters Name=status,Values=available Name=tag:Project,Values=RIC-Gray-Failure-Research`. | **PASS** | Strictly scoped by project tag. Unrelated AWS volumes are preserved. |
| **Error Handling** | Uses `set -euo pipefail` with explicit `|| true` on individual deletion commands. | **PASS** | Ensures subsequent teardown stages proceed even if an individual resource reports not found. |

---

## 7. Offline Automated Test Results

A full regression of all offline test suites was executed on the host:

```text
======================================================================
1. AWS DEPLOYMENT PACKAGE SUITE (benchmark/tests/aws/test_aws_package_offline.py)
----------------------------------------------------------------------
test_01_terraform_main_file_exists_and_configured         ... ok
test_02_terraform_variables_enforce_ca2_standards         ... ok
test_03_aurora_module_isolation                           ... ok
test_04_teardown_script_safeguards                        ... ok
test_05_immutability_of_existing_benchmarks               ... ok
Ran 5 tests in 0.004s | OK

======================================================================
2. AURORA OFFLINE SUITE (benchmark/tests/aurora/test_aurora_offline.py)
----------------------------------------------------------------------
9 tests passed (YAML syntax, parameters, secrets, TLS, preflight, accounting) | OK (0.028s)

======================================================================
3. POSTGRESQL + PATRONI SUITE (benchmark/tests/postgres-patroni/test_patroni_offline.py)
----------------------------------------------------------------------
12 tests passed (Image pins, etcd discovery, sync mode, probes) | OK (0.214s)

======================================================================
4. COCKROACHDB P06 SUITE (results/cockroachdb/baseline/test_p06_remediation1.py)
----------------------------------------------------------------------
42 tests passed (Tripwire, token consumption, stream recovery) | OK (4.2s)
======================================================================
OVERALL TEST RESULT: 68 PASSED, 0 FAILED (Exit Code 0)
======================================================================
```

---

## 8. Audit Findings & Severity Register

| Finding ID | Domain | Severity | Description & Required Remediation |
| :--- | :--- | :--- | :--- |
| **AUD-01** | **Governance** | **BLOCKER** | Academic supervisor sign-off on Gate B-03 and Decisions PD-01 through PD-10 is pending. **Remediation:** Await written supervisor determination. |
| **AUD-02** | **Tooling / CI** | **BLOCKER** | `terraform fmt` failed on `main.tf` in initial CI run `efef05e`; alignments remediated. **Remediation:** Rerun GitHub Actions workflow to confirm `terraform fmt -check`, `init -backend=false`, and `validate` pass. |
| **AUD-03** | **Cost Governance** | **MEDIUM** | \$15 spending control is an administrative target with billing sync delay, not a hard automated stop. **Remediation:** Enforce a hard 4-hour session timer with automated local script termination. |
| **AUD-04** | **Configuration** | **LOW** | Aurora endpoints and secrets templates contain development placeholders. **Remediation:** Dynamically populate endpoints from Terraform outputs during provisioning. |

---

## 9. Items Requiring Supervisor Approval (PD-01 through PD-10)

The following items are formal recommendations recorded in [`supervisor-review/PROTOCOL_DECISIONS_STUDENT_SELECTIONS.md`](file:///d:/Projects/RIC-Gray-Failure-Research/supervisor-review/PROTOCOL_DECISIONS_STUDENT_SELECTIONS.md) and require supervisor sign-off before cloud evaluation:

1. **PD-04 (Recovery Time Objective):** Option 4A — Dual reporting of literal CA2 $RTO_{\text{literal}}$ ($T_2 - T_0$) and steady-state restoration time $RTO_{\text{steady}}$ ($T_{\text{restored}} - T_1$).
2. **PD-05 (Transaction Retry Policy):** Option 5A — Use `pgbench --max-tries=1` for the primary cross-database comparison.
3. **PD-06 (Repetition Counts):** Defer final choice between $N=10$ and $N=3$ until actual AWS pilot billing telemetry is available. $N=10$ is the preferred formal design.
4. **PD-09 (CockroachDB Engine Version):** Proposed deviation to deploy CockroachDB `v26.2.9 LTS` on AWS EKS instead of end-of-life `v23.1`.
5. **Gate B-03 (AWS Pilot Authorization):** Formal written authorization to deploy Cloud Pilot P06 on Amazon EKS.

---

## 10. Final Determination & Next Action

### Final Audit Determination: `NOT_READY` (For Live Provisioning) / `READY_FOR_SUPERVISOR_REVIEW` (For Protocol Freeze)

Live cloud provisioning cannot be initiated at this stage because:
- Academic Supervisor sign-off on Gate B-03 has not yet been received.
- The GitHub Actions Terraform validation workflow has been constructed and syntax-checked, but has not yet completed a live execution run.
- Enforceable cost controls require active session timers rather than passive billing alerts.

### Preservation of Historical State:
- The running 3-node CockroachDB cluster, its 5,000,000-account dataset, PVC bindings, and historical run evidence (Runs 01–05) remain completely untouched and quarantined.
- No cloud resources were created; no cloud charges were incurred.
