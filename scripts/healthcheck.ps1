<#
.SYNOPSIS
    Diagnostic healthcheck probe script for the AI Evidence & Accountability Platform cluster.
.DESCRIPTION
    Probes all 5 services in the Docker Compose stack:
    - immudb (port 3324 REST / 3322 gRPC)
    - mock-llm (port 8080)
    - gateway (port 8081)
    - approval (port 8082)
    - ledger-worker (port 8083)
    Returns exit code 0 if all services respond with healthy status, 1 otherwise.
#>

[CmdletBinding()]
param(
    [int]$TimeoutSec = 3,
    [switch]$Quiet
)

$ErrorActionPreference = "SilentlyContinue"

$probes = @(
    @{
        Name     = "immudb"
        URL      = "http://localhost:3324"
        Port     = 3324
        Endpoint = "/"
    },
    @{
        Name     = "mock-llm"
        URL      = "http://localhost:8080/health"
        Port     = 8080
        Endpoint = "/health"
    },
    @{
        Name     = "gateway"
        URL      = "http://localhost:8081/health"
        Port     = 8081
        Endpoint = "/health"
    },
    @{
        Name     = "approval"
        URL      = "http://localhost:8082/health"
        Port     = 8082
        Endpoint = "/health"
    },
    @{
        Name     = "ledger-worker"
        URL      = "http://localhost:8083/health"
        Port     = 8083
        Endpoint = "/health"
    }
)

$allHealthy = $true
$results = @()

foreach ($probe in $probes) {
    $name = $probe.Name
    $url = $probe.URL
    $port = $probe.Port
    $status = "UNKNOWN"
    $detail = ""
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.Timeout = $TimeoutSec * 1000
        $req.Method = "GET"
        $req.UserAgent = "HealthcheckProbe/1.0"

        $resp = $req.GetResponse()
        $statusCode = [int]$resp.StatusCode
        $resp.Close()

        if ($statusCode -ge 200 -and $statusCode -lt 400) {
            $status = "HEALTHY"
            $detail = "HTTP $statusCode"
        } else {
            $status = "UNHEALTHY"
            $detail = "HTTP $statusCode"
            $allHealthy = $false
        }
    } catch [System.Net.WebException] {
        $webEx = $_.Exception
        if ($webEx.Response -ne $null) {
            $statusCode = [int]$webEx.Response.StatusCode
            # For immudb root, 404 or 401 still means web server is responsive
            if ($name -eq "immudb" -and ($statusCode -eq 404 -or $statusCode -eq 401 -or $statusCode -eq 405)) {
                $status = "HEALTHY"
                $detail = "HTTP $statusCode (responsive)"
            } else {
                $status = "UNHEALTHY"
                $detail = "HTTP $statusCode"
                $allHealthy = $false
            }
        } else {
            # Try TCP connection test as fallback
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $connect = $tcp.BeginConnect("127.0.0.1", $port, $null, $null)
                $success = $connect.AsyncWaitHandle.WaitOne($TimeoutSec * 1000, $false)
                if ($success -and $tcp.Connected) {
                    $status = "HEALTHY"
                    $detail = "TCP $port Open"
                    $tcp.EndConnect($connect)
                    $tcp.Close()
                } else {
                    $status = "DOWN"
                    $detail = "Connection refused"
                    $allHealthy = $false
                }
            } catch {
                $status = "DOWN"
                $detail = "Connection failed: $($_.Exception.Message)"
                $allHealthy = $false
            }
        }
    } catch {
        $status = "ERROR"
        $detail = $_.Exception.Message
        $allHealthy = $false
    } finally {
        $sw.Stop()
    }

    $results += [PSCustomObject]@{
        Service   = $name
        Status    = $status
        Port      = $port
        LatencyMS = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
        Details   = $detail
    }
}

if (-not $Quiet) {
    Write-Host "`n======================================================================" -ForegroundColor Cyan
    Write-Host " AI EVIDENCE & ACCOUNTABILITY PLATFORM - CLUSTER HEALTH REPORT" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    $results | Format-Table -AutoSize
    
    if ($allHealthy) {
        Write-Host "=== CLUSTER STATUS: ALL SERVICES HEALTHY (EXIT 0) ===" -ForegroundColor Green
    } else {
        Write-Host "=== CLUSTER STATUS: ONE OR MORE SERVICES UNHEALTHY (EXIT 1) ===" -ForegroundColor Red
    }
}

if ($allHealthy) {
    exit 0
} else {
    exit 1
}
