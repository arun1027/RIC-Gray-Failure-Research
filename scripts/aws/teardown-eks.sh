#!/usr/bin/env bash
# Strict Automated Teardown Script for RIC Gray-Failure AWS Infrastructure (Hardened Production-Safety Version)
# Destroys Aurora cluster, deletes EKS pods/PVCs, purges orphaned EBS volumes, and shuts down EKS.
set -euo pipefail

echo "=================================================================="
echo "  RIC Gray-Failure Research: Automated Cloud Teardown & Sweeper   "
echo "=================================================================="

# -----------------------------------------------------------------------------
# Configuration Constants & Required Targets
# -----------------------------------------------------------------------------
EXPECTED_REGION="us-east-1"
EXPECTED_PROJECT_TAG="RIC-Gray-Failure-Research"
EXPECTED_CLUSTER_NAME="ric-gray-failure-eks"
EXPECTED_AURORA_CLUSTER_NAME="ric-aurora-cluster"
EXPECTED_WORKSPACE="default"

# -----------------------------------------------------------------------------
# 0. Preflight Verification: Tools, Identity, Account, Region, Confirmation
# -----------------------------------------------------------------------------
echo "[0/6] Verifying preflight tools, account identity, and confirmation..."

# 0.1 Check AWS CLI binary
if ! command -v aws &> /dev/null; then
    echo "ERROR: AWS CLI ('aws') is not installed or not in PATH. Halting teardown." >&2
    exit 1
fi

# 0.2 Check Terraform binary
if ! command -v terraform &> /dev/null; then
    echo "ERROR: Terraform ('terraform') is not installed or not in PATH. Halting teardown." >&2
    exit 1
fi

# 0.3 Enforce EXPECTED_AWS_ACCOUNT_ID configuration
if [ -z "${EXPECTED_AWS_ACCOUNT_ID:-}" ]; then
    echo "ERROR: EXPECTED_AWS_ACCOUNT_ID environment variable is not set." >&2
    echo "To prevent destroying the wrong AWS account, set EXPECTED_AWS_ACCOUNT_ID=<12-digit-id>." >&2
    exit 1
fi

# 0.4 Enforce PILOT_RUN_ID configuration (Resource-Scoped Deletion)
if [ -z "${PILOT_RUN_ID:-}" ]; then
    echo "ERROR: PILOT_RUN_ID environment variable is not set." >&2
    echo "To restrict storage cleanup exclusively to this specific trial, set PILOT_RUN_ID=<run-id>." >&2
    exit 1
fi

# 0.5 Verify AWS STS Caller Identity
CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null || true)
if [ -z "$CALLER_IDENTITY" ]; then
    echo "ERROR: Unable to verify AWS caller identity via STS. Halting teardown." >&2
    exit 1
fi

CURRENT_ACCOUNT=$(echo "$CALLER_IDENTITY" | grep -o '"Account": *"[^"]*"' | grep -o '[0-9]*')
if [ "$CURRENT_ACCOUNT" != "$EXPECTED_AWS_ACCOUNT_ID" ]; then
    echo "CRITICAL SECURITY ERROR: Authenticated AWS account ($CURRENT_ACCOUNT) does NOT match EXPECTED_AWS_ACCOUNT_ID ($EXPECTED_AWS_ACCOUNT_ID)." >&2
    exit 1
fi

# 0.6 Verify Target Region
CURRENT_REGION="${AWS_DEFAULT_REGION:-${AWS_REGION:-us-east-1}}"
if [ "$CURRENT_REGION" != "$EXPECTED_REGION" ]; then
    echo "ERROR: AWS region ($CURRENT_REGION) does not match expected target ($EXPECTED_REGION)." >&2
    exit 1
fi

# 0.7 Enforce Explicit Destructive Confirmation Phrase
if [ "${CONFIRM_DESTROY:-}" != "YES_DESTROY_RIC_INFRASTRUCTURE" ]; then
    echo "ERROR: Missing explicit confirmation phrase." >&2
    echo "To authorize destructive teardown, set CONFIRM_DESTROY=YES_DESTROY_RIC_INFRASTRUCTURE." >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# 1. P0 — Terraform Backend, Workspace, State, & Ownership Protection
# -----------------------------------------------------------------------------
echo "[1/6] Verifying Terraform state, workspace, and infrastructure ownership..."

if [ ! -d "terraform/aws-eks" ]; then
    echo "ERROR: Terraform directory 'terraform/aws-eks' not found. Halting teardown." >&2
    exit 1
fi

# 1.1 Verify Terraform Workspace
CURRENT_WORKSPACE=$(terraform -chdir=terraform/aws-eks workspace show 2>/dev/null || true)
if [ "$CURRENT_WORKSPACE" != "$EXPECTED_WORKSPACE" ]; then
    echo "ERROR: Active Terraform workspace ($CURRENT_WORKSPACE) does not match expected workspace ($EXPECTED_WORKSPACE)." >&2
    exit 1
fi

# 1.2 Verify Backend Configuration (if remote backend configured via environment or files)
if [ -n "${EXPECTED_BACKEND_TYPE:-}" ]; then
    ACTUAL_BACKEND=$(terraform -chdir=terraform/aws-eks version -json 2>/dev/null | grep -o '"backend_type": *"[^"]*"' | cut -d'"' -f4 || true)
    if [ -n "$ACTUAL_BACKEND" ] && [ "$ACTUAL_BACKEND" != "$EXPECTED_BACKEND_TYPE" ]; then
        echo "ERROR: Configured Terraform backend ($ACTUAL_BACKEND) does not match EXPECTED_BACKEND_TYPE ($EXPECTED_BACKEND_TYPE)." >&2
        exit 1
    fi
fi
if [ -n "${EXPECTED_BACKEND_KEY:-}" ]; then
    # Verify backend key if backend config check enabled
    if [ -f "terraform/aws-eks/.terraform/terraform.tfstate" ]; then
        if ! grep -q "$EXPECTED_BACKEND_KEY" "terraform/aws-eks/.terraform/terraform.tfstate"; then
            echo "ERROR: Configured Terraform remote state key does not match EXPECTED_BACKEND_KEY ($EXPECTED_BACKEND_KEY)." >&2
            exit 1
        fi
    fi
fi

# 1.3 Verify State Exists and Belongs to this Project (Local or Remote Backend)
TF_STATE_LIST=$(terraform -chdir=terraform/aws-eks state list 2>/dev/null || true)
if [ -z "$TF_STATE_LIST" ]; then
    echo "ERROR: No Terraform resources found in state for terraform/aws-eks." >&2
    echo "Halting: Cannot safely execute destruction against an empty or missing state." >&2
    exit 1
fi

# Assert that expected core project resources exist in the state
if ! echo "$TF_STATE_LIST" | grep -q "module.eks"; then
    echo "ERROR: State verification failed: 'module.eks' not found in Terraform state. Halting teardown." >&2
    exit 1
fi
if ! echo "$TF_STATE_LIST" | grep -q "module.vpc"; then
    echo "ERROR: State verification failed: 'module.vpc' not found in Terraform state. Halting teardown." >&2
    exit 1
fi

echo "Terraform state verified: Contains valid resources for workspace '$EXPECTED_WORKSPACE' and project modules."

# -----------------------------------------------------------------------------
# 2. P0 — Kubernetes Context & Cryptographic EKS Identity Protection
# -----------------------------------------------------------------------------
echo "[2/6] Verifying Kubernetes context and cryptographic EKS cluster identity..."
if command -v kubectl &> /dev/null; then
    CURRENT_K8S_CONTEXT=$(kubectl config current-context 2>/dev/null || true)
    if [ -z "$CURRENT_K8S_CONTEXT" ]; then
        echo "ERROR: No active kubectl context found. Halting teardown to protect cluster state." >&2
        exit 1
    fi

    # Explicitly reject local developer clusters
    case "$CURRENT_K8S_CONTEXT" in
        *minikube*|*docker-desktop*|*kind*|*k3d*|*microk8s*|*localhost*)
            echo "CRITICAL SECURITY ERROR: Current kubectl context is a local cluster ('$CURRENT_K8S_CONTEXT')." >&2
            echo "Refusing to execute namespace deletion against local research environment." >&2
            exit 1
            ;;
    esac

    # Ensure context contains expected cluster identifier
    if ! echo "$CURRENT_K8S_CONTEXT" | grep -q "$EXPECTED_CLUSTER_NAME"; then
        echo "ERROR: Active kubectl context ('$CURRENT_K8S_CONTEXT') does not match expected cluster '$EXPECTED_CLUSTER_NAME'." >&2
        exit 1
    fi

    # Priority 1: Cryptographic EKS Cluster Identity Verification via AWS API
    EXPECTED_CLUSTER_ARN="arn:aws:eks:${EXPECTED_REGION}:${EXPECTED_AWS_ACCOUNT_ID}:cluster/${EXPECTED_CLUSTER_NAME}"
    if [ -n "${OVERRIDE_EXPECTED_CLUSTER_ARN:-}" ]; then
        EXPECTED_CLUSTER_ARN="$OVERRIDE_EXPECTED_CLUSTER_ARN"
    fi

    CLUSTER_DESC=$(aws eks describe-cluster --name "$EXPECTED_CLUSTER_NAME" --region "$EXPECTED_REGION" --output json 2>/dev/null || true)
    if [ -z "$CLUSTER_DESC" ]; then
        echo "ERROR: Unable to query AWS EKS for cluster '$EXPECTED_CLUSTER_NAME'. Halting teardown." >&2
        exit 1
    fi

    ACTUAL_CLUSTER_ARN=$(echo "$CLUSTER_DESC" | grep -o '"arn": *"[^"]*"' | head -n1 | cut -d'"' -f4 || true)
    ACTUAL_CLUSTER_ENDPOINT=$(echo "$CLUSTER_DESC" | grep -o '"endpoint": *"[^"]*"' | head -n1 | cut -d'"' -f4 || true)

    if [ "$ACTUAL_CLUSTER_ARN" != "$EXPECTED_CLUSTER_ARN" ]; then
        echo "CRITICAL SECURITY ERROR: Cluster ARN ($ACTUAL_CLUSTER_ARN) does NOT match expected ARN ($EXPECTED_CLUSTER_ARN)." >&2
        exit 1
    fi

    # Verify active kubeconfig server endpoint matches the actual AWS EKS API endpoint
    CURRENT_K8S_SERVER=$(kubectl config view --minify --output "jsonpath={.clusters[0].cluster.server}" 2>/dev/null || true)
    if [ -n "$EXPECTED_CLUSTER_ENDPOINT_OVERRIDE:-" ]; then
        ACTUAL_CLUSTER_ENDPOINT="$EXPECTED_CLUSTER_ENDPOINT_OVERRIDE"
    fi
    if [ -n "$CURRENT_K8S_SERVER" ] && [ -n "$ACTUAL_CLUSTER_ENDPOINT" ]; then
        if [ "$CURRENT_K8S_SERVER" != "$ACTUAL_CLUSTER_ENDPOINT" ]; then
            echo "CRITICAL SECURITY ERROR: Active kubectl server endpoint ($CURRENT_K8S_SERVER) does not match AWS EKS endpoint ($ACTUAL_CLUSTER_ENDPOINT)." >&2
            exit 1
        fi
    fi

    echo "Kubernetes identity verified: '$CURRENT_K8S_CONTEXT' corresponds to verified EKS ARN '$ACTUAL_CLUSTER_ARN'."

    # Delete in-cluster benchmark namespaces to release PVCs ONLY AFTER identity verification succeeds
    echo "Deleting in-cluster benchmark namespaces..."
    kubectl delete namespace aurora-benchmark --ignore-not-found=true --timeout=90s
    kubectl delete namespace postgres-patroni --ignore-not-found=true --timeout=120s
    kubectl delete namespace cockroachdb --ignore-not-found=true --timeout=120s
else
    echo "ERROR: kubectl binary missing. Cannot cleanly detach PVCs from cluster nodes. Halting." >&2
    exit 1
fi
    kubectl delete namespace postgres-patroni --ignore-not-found=true --timeout=120s
    kubectl delete namespace cockroachdb --ignore-not-found=true --timeout=120s
else
    echo "ERROR: kubectl binary missing. Cannot cleanly detach PVCs from cluster nodes. Halting." >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# 3. Destroy Managed Aurora PostgreSQL Cluster
# -----------------------------------------------------------------------------
echo "[3/6] Tearing down Amazon Aurora DB cluster instances..."
terraform -chdir=terraform/aws-eks destroy -target=module.aurora -input=false -auto-approve

# -----------------------------------------------------------------------------
# 4. Destroy EKS Cluster and Supporting Infrastructure
# -----------------------------------------------------------------------------
echo "[4/6] Running Terraform EKS infrastructure teardown..."
terraform -chdir=terraform/aws-eks destroy -input=false -auto-approve

# -----------------------------------------------------------------------------
# 5. P1 — Resource-Scoped Storage Cleanup (Pilot Run ID Tag Filtered)
# -----------------------------------------------------------------------------
echo "[5/6] Auditing unattached EBS volumes scoped to Pilot Run ID: '$PILOT_RUN_ID'..."

ORPHAN_VOLUMES=$(aws ec2 describe-volumes \
    --region "$EXPECTED_REGION" \
    --filters "Name=status,Values=available" \
              "Name=tag:Project,Values=$EXPECTED_PROJECT_TAG" \
              "Name=tag:PilotRunId,Values=$PILOT_RUN_ID" \
    --query "Volumes[*].VolumeId" \
    --output text 2>/dev/null || true)

if [ -n "$ORPHAN_VOLUMES" ] && [ "$ORPHAN_VOLUMES" != "None" ]; then
    echo "PRE-CLEANUP INVENTORY: Targeted volumes for run '$PILOT_RUN_ID': $ORPHAN_VOLUMES"
    for vol in $ORPHAN_VOLUMES; do
        echo "Deleting scoped volume: $vol"
        aws ec2 delete-volume --region "$EXPECTED_REGION" --volume-id "$vol"
    done
else
    echo "Zero orphaned EBS volumes found matching Project='$EXPECTED_PROJECT_TAG' and PilotRunId='$PILOT_RUN_ID'."
fi

# -----------------------------------------------------------------------------
# 6. P1 — Multi-Resource Post-Teardown Verification Audit
# -----------------------------------------------------------------------------
echo "[6/6] Executing comprehensive post-teardown verification across all billable resource types..."
INCOMPLETE_RESOURCES=""

# 6.1 Check EKS Cluster
EKS_ACTIVE=$(aws eks describe-cluster --name "$EXPECTED_CLUSTER_NAME" --region "$EXPECTED_REGION" \
    --query "cluster.status" --output text 2>/dev/null || true)
if [ "$EKS_ACTIVE" == "ACTIVE" ] || [ "$EKS_ACTIVE" == "UPDATING" ] || [ "$EKS_ACTIVE" == "DELETING" ]; then
    echo "WARNING: EKS Cluster '$EXPECTED_CLUSTER_NAME' still detected in status: $EKS_ACTIVE" >&2
    INCOMPLETE_RESOURCES="$INCOMPLETE_RESOURCES EKS:$EXPECTED_CLUSTER_NAME($EKS_ACTIVE)"
fi

# 6.2 Check Aurora DB Cluster
AURORA_ACTIVE=$(aws rds describe-db-clusters --db-cluster-identifier "$EXPECTED_AURORA_CLUSTER_NAME" --region "$EXPECTED_REGION" \
    --query "DBClusters[0].Status" --output text 2>/dev/null || true)
if [ "$AURORA_ACTIVE" == "available" ] || [ "$AURORA_ACTIVE" == "modifying" ] || [ "$AURORA_ACTIVE" == "deleting" ]; then
    echo "WARNING: Aurora Cluster '$EXPECTED_AURORA_CLUSTER_NAME' still detected in status: $AURORA_ACTIVE" >&2
    INCOMPLETE_RESOURCES="$INCOMPLETE_RESOURCES Aurora:$EXPECTED_AURORA_CLUSTER_NAME($AURORA_ACTIVE)"
fi

# 6.3 Check EC2 Worker Instances
REMAINING_INSTANCES=$(aws ec2 describe-instances \
    --region "$EXPECTED_REGION" \
    --filters "Name=tag:Project,Values=$EXPECTED_PROJECT_TAG" "Name=instance-state-name,Values=running,pending" \
    --query "Reservations[*].Instances[*].InstanceId" \
    --output text 2>/dev/null || true)
if [ -n "$REMAINING_INSTANCES" ] && [ "$REMAINING_INSTANCES" != "None" ]; then
    echo "WARNING: Active EC2 instances still detected: $REMAINING_INSTANCES" >&2
    INCOMPLETE_RESOURCES="$INCOMPLETE_RESOURCES EC2:$REMAINING_INSTANCES"
fi

# 6.4 Check NAT Gateways
REMAINING_NAT=$(aws ec2 describe-nat-gateways \
    --region "$EXPECTED_REGION" \
    --filter "Name=tag:Project,Values=$EXPECTED_PROJECT_TAG" "Name=state,Values=available,pending" \
    --query "NatGateways[*].NatGatewayId" \
    --output text 2>/dev/null || true)
if [ -n "$REMAINING_NAT" ] && [ "$REMAINING_NAT" != "None" ]; then
    echo "WARNING: Active NAT Gateways still detected: $REMAINING_NAT" >&2
    INCOMPLETE_RESOURCES="$INCOMPLETE_RESOURCES NAT:$REMAINING_NAT"
fi

# 6.5 Check Pilot-Specific EBS Volumes
REMAINING_PILOT_VOLUMES=$(aws ec2 describe-volumes \
    --region "$EXPECTED_REGION" \
    --filters "Name=status,Values=available,in-use" \
              "Name=tag:Project,Values=$EXPECTED_PROJECT_TAG" \
              "Name=tag:PilotRunId,Values=$PILOT_RUN_ID" \
    --query "Volumes[*].VolumeId" \
    --output text 2>/dev/null || true)
if [ -n "$REMAINING_PILOT_VOLUMES" ] && [ "$REMAINING_PILOT_VOLUMES" != "None" ]; then
    echo "WARNING: Residual pilot EBS volumes still detected: $REMAINING_PILOT_VOLUMES" >&2
    INCOMPLETE_RESOURCES="$INCOMPLETE_RESOURCES EBS:$REMAINING_PILOT_VOLUMES"
fi

# 6.6 Final Decision Gate
if [ -n "$INCOMPLETE_RESOURCES" ]; then
    echo "==================================================================" >&2
    echo "  CLEANUP INCOMPLETE: The following billable cloud resources remain active:" >&2
    echo "  $INCOMPLETE_RESOURCES" >&2
    echo "==================================================================" >&2
    exit 2
fi

echo "=================================================================="
echo "  Teardown Verified: All EKS, Aurora, EC2, NAT, and EBS resources cleanly removed."
echo "=================================================================="
