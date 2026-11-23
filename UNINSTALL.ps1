param(
    [switch]$KeepTestSigning
)

#Requires -RunAsAdministrator

# UNINSTALL.ps1 -- reverses INSTALL.ps1.
# Phase 1.7: the installer wrote the chosen per-install service/driver name
# to C:\THE_CHAMBER\logs\last_install.txt. We read it back here and use
# NtUnloadDriver (NOT sc.exe stop/delete) so the stop path emits no SCM
# 7036 event and the delete path emits none either.

. "C:\Users\lkhnj\Downloads\testbench\gpu_spoof\_safety_gate.ps1"
Assert-NoAntiCheatRunning

$ErrorActionPreference = 'Continue'
$root = 'C:\THE_CHAMBER'

Write-Host "=== Uninstall ===" -ForegroundColor Cyan

# 1. Recover the install name
$stateFile = Join-Path $root 'logs\last_install.txt'
$name = $null
if (Test-Path $stateFile) {
    $name = (Get-Content $stateFile -First 1).Trim()
}
if (-not $name) {
    Write-Host "No install state file; nothing to unload." -ForegroundColor Yellow
} else {
    Write-Host "Unloading service: $name" -ForegroundColor White

    # NtUnloadDriver via P/Invoke, same pattern as install_service.ps1.
    $sig = @'
using System;
using System.Runtime.InteropServices;

public static class NtUnload {
    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [DllImport("ntdll.dll")]
    public static extern int RtlAdjustPrivilege(
        int privilege, bool enable, bool currentThread, out bool previous);

    [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
    public static extern void RtlInitUnicodeString(
        ref UNICODE_STRING dst, [MarshalAs(UnmanagedType.LPWStr)] string src);

    [DllImport("ntdll.dll")]
    public static extern int NtUnloadDriver(ref UNICODE_STRING name);

    public static int Unload(string regPath) {
        bool prev;
        RtlAdjustPrivilege(10, true, false, out prev);
        var us = new UNICODE_STRING();
        RtlInitUnicodeString(ref us, regPath);
        return NtUnloadDriver(ref us);
    }
}
'@
    Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue
    $rc = [NtUnload]::Unload("\Registry\Machine\SYSTEM\CurrentControlSet\Services\$name")
    if ($rc -ne 0) {
        Write-Host ("NtUnloadDriver returned 0x{0:X8}" -f $rc) -ForegroundColor Yellow
    }

    # Delete registry service key + the dropped .sys
    Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -Recurse -Force -ErrorAction SilentlyContinue
    $drv = "$env:SystemRoot\System32\drivers\$name.sys"
    if (Test-Path $drv) { Remove-Item $drv -Force -ErrorAction SilentlyContinue }
    Remove-Item $stateFile -Force -ErrorAction SilentlyContinue
}

# 2. Remove desktop shortcut
$desktop = [Environment]::GetFolderPath('Desktop')
$shortcuts = @(Join-Path $desktop 'launcher.lnk', "$root\launcher\launcher.lnk")
foreach ($lnk in $shortcuts) { if (Test-Path $lnk) { Remove-Item $lnk -Force } }

# 3. Clear the crash marker (if the launcher's name directory left one)
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

Write-Host ""
Write-Host "=== Uninstall complete ===" -ForegroundColor Green
Write-Host "Project files remain at $root (delete manually if you no longer need them)."
if (-not $KeepTestSigning) { Write-Host "Reboot to clear the Test Mode watermark." }
