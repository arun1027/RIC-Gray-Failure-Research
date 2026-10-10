<#
.SYNOPSIS
    Reproducible Secret Provisioning Script for CockroachDB AWS EKS Deployment.
    Applies cockroachdb-node-secret and cockroachdb-client-secret to namespace 'cockroachdb'.

.DESCRIPTION
    Execute ONLY when CockroachDB deployment is formally authorized.
    Reads verified certificates from certs/cockroach-tls-stage2:
      - ca.crt, node.crt, node.key
      - ca.crt, client.root.crt, client.root.key
    Strict Security Guarantee: Zero secret contents or private keys are printed or logged.
#>

[CmdletBinding()]
param (
    [string]$Namespace = "cockroachdb",
    [string]$CertDir = "certs/cockroach-tls-stage2",
    [switch]$DryRunOnly
)

$ErrorActionPreference = "Stop"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "COCKROACHDB KUBERNETES SECRET PROVISIONING" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Verify files exist
$requiredFiles = @(
    "ca.crt", "ca.key",
    "node.crt", "node.key",
    "client.root.crt", "client.root.key"
)

foreach ($f in $requiredFiles) {
    $fullPath = Join-Path $CertDir $f
    if (-not (Test-Path $fullPath)) {
        throw "Required certificate file not found: $fullPath"
    }
}
Write-Host "[OK] All 6 verified certificate files confirmed present in: $CertDir" -ForegroundColor Green

# 2. Check cluster context
$currentContext = (kubectl config current-context).Trim()
Write-Host "[INFO] Active kubectl context: $currentContext"
if ($currentContext -notmatch "ric-gray-failure-eks") {
    Write-Warning "Current context '$currentContext' does not match 'ric-gray-failure-eks'. Proceed with caution."
}

# 3. Ensure namespace exists
if (-not $DryRunOnly) {
    $nsExists = kubectl get namespace $Namespace --ignore-not-found -o jsonpath='{.metadata.name}'
    if (-not $nsExists) {
        Write-Host "[INFO] Creating namespace '$Namespace'..."
        kubectl create namespace $Namespace
    } else {
        Write-Host "[INFO] Namespace '$Namespace' already exists."
    }
}

# 4. Provision Node Secret
Write-Host "`n[STEP 1/2] Preparing Secret: cockroachdb-node-secret" -ForegroundColor Yellow
$nodeCmd = "kubectl create secret generic cockroachdb-node-secret -n $Namespace " + `
           "--from-file=ca.crt=$CertDir/ca.crt " + `
           "--from-file=tls.crt=$CertDir/node.crt " + `
           "--from-file=tls.key=$CertDir/node.key --dry-run=client -o yaml"

if ($DryRunOnly) {
    Write-Host "[DRY-RUN] Command to apply:"
    Write-Host "$nodeCmd | kubectl apply -f -"
} else {
    Invoke-Expression "$nodeCmd | kubectl apply -f -"
    Write-Host "[OK] Secret 'cockroachdb-node-secret' applied successfully." -ForegroundColor Green
    kubectl describe secret cockroachdb-node-secret -n $Namespace | Select-String -Pattern "Name:|Namespace:|Type:|Data|ca.crt:|tls.crt:|tls.key:"
}

# 5. Provision Client Secret
Write-Host "`n[STEP 2/2] Preparing Secret: cockroachdb-client-secret" -ForegroundColor Yellow
$clientCmd = "kubectl create secret generic cockroachdb-client-secret -n $Namespace " + `
             "--from-file=ca.crt=$CertDir/ca.crt " + `
             "--from-file=tls.crt=$CertDir/client.root.crt " + `
             "--from-file=tls.key=$CertDir/client.root.key --dry-run=client -o yaml"

if ($DryRunOnly) {
    Write-Host "[DRY-RUN] Command to apply:"
    Write-Host "$clientCmd | kubectl apply -f -"
} else {
    Invoke-Expression "$clientCmd | kubectl apply -f -"
    Write-Host "[OK] Secret 'cockroachdb-client-secret' applied successfully." -ForegroundColor Green
    kubectl describe secret cockroachdb-client-secret -n $Namespace | Select-String -Pattern "Name:|Namespace:|Type:|Data|ca.crt:|tls.crt:|tls.key:"
}

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "COCKROACHDB SECRETS PROVISIONING STATUS: READY FOR APPLICATION" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

