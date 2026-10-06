<#
.SYNOPSIS
    Tear down the AI Evidence Platform Docker Compose stack.
.DESCRIPTION
    Stops and removes containers, networks, and optionally named volumes.
    Supports -Volumes to purge persistent immudb and WAL state, and -Prune to remove dangling images.
#>

[CmdletBinding()]
param(
    [switch]$Volumes,
    [switch]$Prune,
    [int]$TimeoutSec = 10
)

$ErrorActionPreference = "Stop"

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host " STOPPING AI EVIDENCE & ACCOUNTABILITY PLATFORM CLUSTER" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$downArgs = @("down", "--timeout", $TimeoutSec.ToString())

if ($Volumes) {
    Write-Host "[!] -Volumes specified: Persistent volumes (immudb-data, ledger-wal) will be removed!" -ForegroundColor Yellow
    $downArgs += "-v"
}

Write-Host "[*] Executing: docker compose $($downArgs -join ' ')..." -ForegroundColor Gray
docker compose @downArgs

if ($LASTEXITCODE -ne 0) {
    Write-Error "docker compose down failed."
    exit $LASTEXITCODE
}
Write-Host "[+] All cluster containers and networks stopped and removed." -ForegroundColor Green

if ($Prune) {
    Write-Host "`n[*] Pruning dangling container images..." -ForegroundColor Gray
    docker image prune -f
    Write-Host "[+] Dangling images pruned." -ForegroundColor Green
}

Write-Host "`n[+] Cluster shutdown complete.`n" -ForegroundColor Green
exit 0
