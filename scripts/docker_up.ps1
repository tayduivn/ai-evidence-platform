<#
.SYNOPSIS
    Automated build, startup, and healthcheck polling for AI Evidence Platform Docker cluster.
.DESCRIPTION
    1. Validates Docker daemon connectivity.
    2. Builds container images via `docker compose build`.
    3. Boots cluster via `docker compose up -d`.
    4. Polls service health checks until all services report healthy or timeout expires.
    5. Displays endpoints and status summary.
#>

[CmdletBinding()]
param(
    [switch]$NoBuild,
    [int]$TimeoutSec = 60,
    [int]$PollIntervalSec = 3
)

$ErrorActionPreference = "Stop"

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host " STARTING AI EVIDENCE & ACCOUNTABILITY PLATFORM CLUSTER" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Check Docker Daemon
Write-Host "[*] Checking Docker daemon status..." -ForegroundColor Gray
try {
    $null = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Docker daemon is not responding. Please start Docker Desktop and retry."
        exit 1
    }
    Write-Host "[+] Docker daemon is active." -ForegroundColor Green
} catch {
    Write-Error "Failed to invoke docker: $($_.Exception.Message)"
    exit 1
}

# 2. Build Container Images
if (-not $NoBuild) {
    Write-Host "`n[*] Building container images from monorepo root context..." -ForegroundColor Gray
    docker compose build
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Docker Compose build failed."
        exit $LASTEXITCODE
    }
    Write-Host "[+] All images built successfully." -ForegroundColor Green
} else {
    Write-Host "[*] Skipping build step (-NoBuild specified)." -ForegroundColor Yellow
}

# 3. Launch Services in Detached Mode
Write-Host "`n[*] Starting containers via docker compose up -d..." -ForegroundColor Gray
docker compose up -d
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker Compose up failed."
    exit $LASTEXITCODE
}
Write-Host "[+] Containers launched." -ForegroundColor Green

# 4. Poll Service Health Checks
Write-Host "`n[*] Waiting for all 5 services to become healthy (timeout: ${TimeoutSec}s)..." -ForegroundColor Gray
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$expectedServices = @("immudb", "mock-llm", "ledger-worker", "gateway", "approval")
$healthyAll = $false

while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
    $psOutput = docker compose ps --format json 2>$null
    $serviceStates = @{}

    if ($psOutput) {
        try {
            $parsed = $psOutput | ConvertFrom-Json
            foreach ($item in $parsed) {
                $sName = $item.Service
                $state = $item.Health
                if (-not $state) { $state = $item.State }
                $serviceStates[$sName] = $state
            }
        } catch {
            # Fallback if json parsing output is lines of objects
            $lines = $psOutput -split "`r?`n"
            foreach ($line in $lines) {
                if ($line.Trim() -ne "") {
                    try {
                        $obj = $line | ConvertFrom-Json
                        $serviceStates[$obj.Service] = if ($obj.Health) { $obj.Health } else { $obj.State }
                    } catch {}
                }
            }
        }
    }

    $allOk = $true
    foreach ($svc in $expectedServices) {
        $st = $serviceStates[$svc]
        if ($st -ne "healthy" -and $st -ne "running") {
            $allOk = $false
            break
        }
    }

    if ($allOk -and ($serviceStates.Count -ge $expectedServices.Count)) {
        $healthyAll = $true
        break
    }

    $elapsed = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    Write-Host "    [${elapsed}s] Waiting for services... ($($serviceStates.Count)/5 reporting)" -ForegroundColor DarkGray
    Start-Sleep -Seconds $PollIntervalSec
}

$sw.Stop()

# 5. Run Health Diagnostic Script
Write-Host "`n[*] Running cluster health probes..." -ForegroundColor Gray
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& "$scriptDir\healthcheck.ps1"
$healthExitCode = $LASTEXITCODE

# 6. Display Service Endpoints
Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host " SERVICE ACCESS POINTS" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  * AI Reverse Proxy Gateway   : http://localhost:8081" -ForegroundColor Yellow
Write-Host "  * Human Approval UI & Signer : http://localhost:8082" -ForegroundColor Yellow
Write-Host "  * Upstream Mock LLM          : http://localhost:8080" -ForegroundColor Yellow
Write-Host "  * Ledger Micro-Batch Worker  : http://localhost:8083" -ForegroundColor Yellow
Write-Host "  * immudb Console & REST API  : http://localhost:3324" -ForegroundColor Yellow
Write-Host "  * immudb gRPC Port           : localhost:3322" -ForegroundColor Yellow
Write-Host "======================================================================`n" -ForegroundColor Cyan

if ($healthExitCode -eq 0 -or $healthyAll) {
    Write-Host "[+] AI Evidence Platform cluster is UP and operational!`n" -ForegroundColor Green
    exit 0
} else {
    Write-Warning "[-] Cluster started, but one or more health checks have not yet passed."
    exit 1
}
