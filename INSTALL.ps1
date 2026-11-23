#Requires -RunAsAdministrator

# INSTALL.ps1 -- one-time setup for THE_CHAMBER.
# Compiles the driver, signs it, installs the SCM service, creates the
# desktop shortcut, and prints a short next-step summary.

$ErrorActionPreference = 'Stop'
$root = 'C:\THE_CHAMBER'

# --- Safety gate (anti-cheat refuse-to-load) ---
# Prefer the in-repo gate; fall back to the author's legacy per-user path
# for backwards compatibility. Refuse to proceed if neither is available --
# a missing gate is never a silent skip.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$gateCandidates = @(
    (Join-Path $scriptDir 'pentest\_safety_gate.ps1'),
    (Join-Path $root      'pentest\_safety_gate.ps1'),
    'C:\Users\lkhnj\Downloads\testbench\gpu_spoof\_safety_gate.ps1'
)
$gate = $gateCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $gate) {
    throw ("Safety gate not found at any known location; refusing to install. Tried:`n  " + ($gateCandidates -join "`n  "))
}
. $gate
if (-not (Get-Command Assert-NoAntiCheatRunning -ErrorAction SilentlyContinue)) {
    throw "Safety gate loaded but Assert-NoAntiCheatRunning is undefined; refusing to install."
}
Assert-NoAntiCheatRunning

Write-Host "=== THE_CHAMBER install ===" -ForegroundColor Cyan

# 1. Build the driver (compile + link + sign)
Write-Host "Step 1/5: Building driver..." -ForegroundColor White
& "$root\driver\build.ps1"
$sys = "$root\driver\build_output.sys"
if (-not (Test-Path $sys)) { throw "Build did not produce $sys" }

# 2. Snapshot BCD state BEFORE any bcdedit mutation. UNINSTALL.ps1 reads
#    this back to decide whether to clear testsigning / nointegritychecks;
#    if we never turned them on, we never turn them off.
Write-Host ""
Write-Host "Step 2/5: Snapshotting BCD state..." -ForegroundColor White
$logs = Join-Path $root 'logs'
if (-not (Test-Path $logs)) { New-Item -ItemType Directory -Path $logs -Force | Out-Null }
$bcdExport = Join-Path $logs 'bcd_pre_install.bcd'
try {
    # /export produces a hive we can later /import on recovery. Best effort:
    # some restricted systems refuse /export. We still parse the current
    # flags below either way.
    bcdedit /export $bcdExport | Out-Null
} catch {
    Write-Warning ("bcdedit /export failed: " + $_.Exception.Message + " (continuing; flag snapshot still taken)")
}

function Get-BcdFlag([string]$flag) {
    $out = bcdedit /enum '{current}' 2>$null | Out-String
    if ($out -match ('(?im)^\s*' + [regex]::Escape($flag) + '\s+(Yes|No|On|Off|true|false)\s*$')) {
        $v = $Matches[1].ToLowerInvariant()
        return ($v -eq 'yes' -or $v -eq 'on' -or $v -eq 'true')
    }
    return $false
}

$preTestSigning = Get-BcdFlag 'testsigning'
$preNoIntegrity = Get-BcdFlag 'nointegritychecks'
$snap = [pscustomobject]@{
    testsigning_before       = $preTestSigning
    nointegritychecks_before = $preNoIntegrity
    installer_touched_testsigning       = $false
    installer_touched_nointegritychecks = $false
    export_path              = if (Test-Path $bcdExport) { $bcdExport } else { $null }
    captured_utc             = (Get-Date).ToUniversalTime().ToString('o')
}

# Only enable testsigning if it was NOT already on. UNINSTALL inspects the
# same file to decide whether to toggle it back.
if (-not $preTestSigning) {
    Write-Host "Enabling bcdedit testsigning (was off)..." -ForegroundColor Yellow
    bcdedit /set testsigning on | Out-Null
    $snap.installer_touched_testsigning = $true
} else {
    Write-Host "bcdedit testsigning already on; leaving it." -ForegroundColor DarkGray
}
# We DO NOT turn nointegritychecks on. Phase 1.7 NtLoadDriver + re-sign
# path uses testsigning only; recording state here anyway so UNINSTALL has
# a complete baseline.

$snap | ConvertTo-Json | Set-Content -Path (Join-Path $logs 'bcd_pre_install.json') -Encoding ASCII

# 3. Create SCM service (DEMAND_START - never auto-loads at boot)
Write-Host ""
Write-Host "Step 3/5: Installing service..." -ForegroundColor White
& "$root\launcher\install_service.ps1"

# 4. Create desktop shortcut
Write-Host ""
Write-Host "Step 4/5: Creating desktop shortcut..." -ForegroundColor White
& "$root\launcher\MAKE_SHORTCUT.ps1"

# 5. Best-effort System Restore point
Write-Host ""
Write-Host "Step 5/5: System Restore point (best effort)..." -ForegroundColor White
try { Checkpoint-Computer -Description "pre-first-launch" -RestorePointType 'APPLICATION_INSTALL' -ErrorAction Stop } catch {}

Write-Host ""
Write-Host "=== Setup complete ===" -ForegroundColor Green
Write-Host "Double-click the launcher shortcut on your desktop to activate."
Write-Host "Stop with: $root\launcher\stop.ps1 (or close the launcher window)."
Write-Host "Uninstall: $root\UNINSTALL.ps1"
Write-Host "Recovery:  Safe Mode, then $root\recovery\recover.ps1"
