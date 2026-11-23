#Requires -RunAsAdministrator

# INSTALL.ps1 -- one-time setup for THE_CHAMBER.
# Compiles the driver, signs it, installs the SCM service, creates the
# desktop shortcut, and prints a short next-step summary.

. "C:\Users\lkhnj\Downloads\testbench\gpu_spoof\_safety_gate.ps1"
Assert-NoAntiCheatRunning

$ErrorActionPreference = 'Stop'
$root = 'C:\THE_CHAMBER'

Write-Host "=== THE_CHAMBER install ===" -ForegroundColor Cyan

# 1. Build the driver (compile + link + sign)
Write-Host "Step 1/4: Building driver..." -ForegroundColor White
& "$root\driver\build.ps1"
$sys = "$root\driver\build_output.sys"
if (-not (Test-Path $sys)) { throw "Build did not produce $sys" }

# 2. Create SCM service (DEMAND_START — never auto-loads at boot)
Write-Host ""
Write-Host "Step 2/4: Installing service..." -ForegroundColor White
& "$root\launcher\install_service.ps1"

# 3. Create desktop shortcut
Write-Host ""
Write-Host "Step 3/4: Creating desktop shortcut..." -ForegroundColor White
& "$root\launcher\MAKE_SHORTCUT.ps1"

# 4. Best-effort System Restore point
Write-Host ""
Write-Host "Step 4/4: System Restore point (best effort)..." -ForegroundColor White
try { Checkpoint-Computer -Description "THE_CHAMBER pre-first-launch" -RestorePointType 'APPLICATION_INSTALL' -ErrorAction Stop } catch {}

Write-Host ""
Write-Host "=== Setup complete ===" -ForegroundColor Green
Write-Host "Double-click THE_CHAMBER on your desktop to activate."
Write-Host "Stop with: $root\launcher\stop.ps1 (or close the launcher window)."
Write-Host "Uninstall: $root\UNINSTALL.ps1"
Write-Host "Recovery:  Safe Mode, then $root\recovery\recover.ps1"
