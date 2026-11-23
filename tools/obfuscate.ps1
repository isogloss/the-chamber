param(
    [switch]$KeepLegacyDisplayName  # no-op; retained for script-call compatibility.
)

# obfuscate.ps1 -- thin wrapper around launcher/install_service.ps1.
#
# The old behaviour (sc.exe create/stop/delete against a hardcoded
# 'winhvmon.sys' with a "Windows Hypervisor Monitor" DisplayName) was
# removed: it emitted SCM 7045 / 7036 events, baked the brand strings
# "Hv" / "Hypervisor" straight into the service metadata, and used a
# deterministic C:\Windows\System32\drivers\winhvmon.sys path across
# installs -- every Phase 1.7 stealth leak that install_service.ps1
# goes out of its way to suppress.
#
# install_service.ps1 is now the single install path: a per-install
# 10-char random name, direct registry write, NtLoadDriver, re-signed
# cfg-patched driver. There is no second obfuscation axis to add; any
# rename, DisplayName, Description, or Parameters key would recreate
# the surface this script was built to avoid.

$ErrorActionPreference = 'Stop'

# --- Safety gate ---
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = Split-Path -Parent $scriptDir
$gateCandidates = @(
    (Join-Path $repoRoot 'pentest\_safety_gate.ps1'),
    'C:\THE_CHAMBER\pentest\_safety_gate.ps1',
    'C:\Users\lkhnj\Downloads\testbench\gpu_spoof\_safety_gate.ps1'
)
$gate = $gateCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $gate) {
    Write-Host "Safety gate not found; refusing to run." -ForegroundColor Red
    exit 1
}
. $gate
if (-not (Get-Command Assert-NoAntiCheatRunning -ErrorAction SilentlyContinue)) {
    Write-Host "Safety gate loaded but Assert-NoAntiCheatRunning is undefined; refusing to run." -ForegroundColor Red
    exit 1
}
Assert-NoAntiCheatRunning

#Requires -RunAsAdministrator

Write-Host "obfuscate.ps1 -> delegating to install_service.ps1" -ForegroundColor Cyan
Write-Host "(per-install random name via NtLoadDriver; no sc.exe, no 7045/7036 events)" -ForegroundColor DarkGray

$installer = $null
try {
    $installer = (Resolve-Path (Join-Path $PSScriptRoot '..\launcher\install_service.ps1') -ErrorAction Stop).Path
} catch {
    # $PSScriptRoot-relative resolve failed (packaged binary, script
    # invoked from an arbitrary cwd). Fall back to the deployed tree,
    # then to $repoRoot (Split-Path -Parent $scriptDir) as a last resort.
    $candidates = @(
        'C:\THE_CHAMBER\launcher\install_service.ps1',
        (Join-Path $repoRoot 'launcher\install_service.ps1')
    )
    $installer = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $installer -or -not (Test-Path -LiteralPath $installer)) {
    Write-Host "install_service.ps1 not found (tried PSScriptRoot-relative, C:\THE_CHAMBER\launcher, repoRoot); aborting." -ForegroundColor Red
    exit 1
}
& $installer
exit $LASTEXITCODE
