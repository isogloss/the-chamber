param(
    [switch]$KeepTestSigning
)

#Requires -RunAsAdministrator

# UNINSTALL.ps1 -- reverses INSTALL.ps1.
# Stops + deletes the service, removes the desktop shortcut, clears the crash
# marker, and (unless -KeepTestSigning) restores bcdedit settings to defaults.

. "C:\Users\lkhnj\Downloads\testbench\gpu_spoof\_safety_gate.ps1"
Assert-NoAntiCheatRunning

$ErrorActionPreference = 'Continue'
$root = 'C:\THE_CHAMBER'

Write-Host "=== THE_CHAMBER uninstall ===" -ForegroundColor Cyan

# 1. Stop + delete service
Write-Host "Stopping + deleting service..." -ForegroundColor White
sc.exe stop winhvmon 2>$null | Out-Null
sc.exe delete winhvmon 2>$null | Out-Null

# 2. Remove desktop shortcut
$desktop = [Environment]::GetFolderPath('Desktop')
$shortcuts = @(Join-Path $desktop 'THE_CHAMBER.lnk', "$root\launcher\THE_CHAMBER.lnk")
foreach ($lnk in $shortcuts) { if (Test-Path $lnk) { Remove-Item $lnk -Force } }

# 3. Clear the crash marker (so next boot without the driver is clean)
$marker = "$root\last_session.marker"
if (Test-Path $marker) { Remove-Item $marker -Force }

# 4. BCD restore (optional)
if (-not $KeepTestSigning) {
    Write-Host "Reverting bcdedit (test-signing + nointegritychecks)..." -ForegroundColor White
    bcdedit /set testsigning off | Out-Null
    bcdedit /set nointegritychecks off | Out-Null
} else {
    Write-Host "-KeepTestSigning set; leaving bcdedit flags enabled." -ForegroundColor Yellow
}

# 5. Keep project files (recovery folder stays for future reinstalls)
Write-Host ""
Write-Host "=== Uninstall complete ===" -ForegroundColor Green
Write-Host "Project files remain at $root (delete manually if you no longer need them)."
if (-not $KeepTestSigning) { Write-Host "Reboot to clear the Test Mode watermark." }
