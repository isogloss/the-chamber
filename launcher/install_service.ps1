# install_service.ps1 -- one-time SCM service registration for THE_CHAMBER.
# Service: SERVICE_KERNEL_DRIVER + SERVICE_DEMAND_START.
# Idempotent: deletes any stale copy first.

$ErrorActionPreference = 'Stop'

$gate = 'C:\Users\lkhnj\Downloads\testbench\gpu_spoof\_safety_gate.ps1'
if (Test-Path $gate) {
    . $gate
    Assert-NoAntiCheatRunning
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath)
    exit 0
}

$svc = 'winhvmon'
$sys = 'C:\THE_CHAMBER\driver\winhvmon.sys'

if (-not (Test-Path $sys)) {
    Write-Host "Driver file not found: $sys" -ForegroundColor Red
    exit 1
}

# Delete any prior registration
$existing = Get-Service -Name $svc -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne 'Stopped') {
        Write-Host "Stopping existing $svc..." -ForegroundColor Yellow
        try { Stop-Service -Name $svc -Force -ErrorAction Stop } catch {}
    }
    Write-Host "Deleting existing $svc registration..." -ForegroundColor Yellow
    sc.exe delete $svc | Out-Null
    Start-Sleep -Milliseconds 300
}

# Create
Write-Host "Creating service $svc -> $sys" -ForegroundColor Cyan
sc.exe create $svc binPath= $sys type= kernel start= demand error= normal DisplayName= "THE_CHAMBER SVM Instrumentation" | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "sc create failed (exit $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}
sc.exe description $svc "AMD SVM ring-0 performance instrumentation driver." | Out-Null

Write-Host "Service installed. Use load.ps1 to start." -ForegroundColor Green
