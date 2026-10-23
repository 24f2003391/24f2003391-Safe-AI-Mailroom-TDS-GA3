param(
    [string]$BaseUrl = "https://safe-ai-mailroom-tds-ga3.onrender.com"
)
$ErrorActionPreference = "Stop"
$BaseUrl = $BaseUrl.TrimEnd("/")
$failures = 0
function Assert-Equal([string]$Name, $Actual, $Expected) {
    if ($Actual -eq $Expected) {
        Write-Host "[PASS] $Name" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $Name — expected '$Expected', got '$Actual'" -ForegroundColor Red
        $script:failures++
    }
}
Write-Host "Safe AI Mailroom smoke tests: $BaseUrl"
Write-Host "Synthetic tests only. This script does not call the grader Check/Save."
try {
    $health = Invoke-RestMethod -Method Get -Uri "$BaseUrl/health" -TimeoutSec 20
    Assert-Equal "health status" $health.status "ok"
    Assert-Equal "profile" $health.profile "ga5-mailroom-action-gate/v2"
    Assert-Equal "PostgreSQL configured" $health.database "postgresql"
} catch {
    Write-Host "[FAIL] health endpoint: $($_.Exception.Message)" -ForegroundColor Red
    $failures++
}
try {
    $root = Invoke-RestMethod -Method Get -Uri "$BaseUrl/" -TimeoutSec 20
    Assert-Equal "root service" $root.service "safe-ai-mailroom"
    Assert-Equal "root lists propose and commit" (@($root.operations) -join ",") "propose,commit"
} catch {
    Write-Host "[FAIL] root endpoint: $($_.Exception.Message)" -ForegroundColor Red
    $failures++
}
try {
    $body = @{ profile = "wrong-profile"; operation = "propose" } | ConvertTo-Json -Compress
    try {
        $response = Invoke-WebRequest -Method Post -Uri "$BaseUrl/" -ContentType "application/json" -Body $body -TimeoutSec 20
        $status = [int]$response.StatusCode
    } catch {
        $status = 0
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $status = [int]$_.Exception.Response.StatusCode
        }
    }
    Assert-Equal "invalid profile returns 422" $status 422
} catch {
    Write-Host "[FAIL] invalid envelope test: $($_.Exception.Message)" -ForegroundColor Red
    $failures++
}
if ($failures -gt 0) {
    Write-Host "$failures test(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host "All smoke tests passed." -ForegroundColor Green
