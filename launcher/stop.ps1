# stop.ps1 -- graceful unload of THE_CHAMBER.
# Sends IOCTL_SHUTDOWN then stops the SCM service.

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
$existing = Get-Service -Name $svc -ErrorAction SilentlyContinue
if (-not $existing) {
    Write-Host 'THE_CHAMBER service not installed; nothing to stop.' -ForegroundColor Yellow
    exit 0
}
if ($existing.Status -eq 'Stopped') {
    Write-Host 'Service already stopped.' -ForegroundColor Green
    exit 0
}

if (-not ('TheChamber.Pinvoke' -as [type])) {
    Add-Type -Namespace TheChamber -Name Pinvoke -MemberDefinition @'
        using System;
        using System.Runtime.InteropServices;
        using Microsoft.Win32.SafeHandles;
        public static class Native {
            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern SafeFileHandle CreateFile(
                string lpFileName, uint dwDesiredAccess, uint dwShareMode,
                IntPtr lpSecurityAttributes, uint dwCreationDisposition,
                uint dwFlagsAndAttributes, IntPtr hTemplateFile);
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool DeviceIoControl(
                SafeFileHandle hDevice, uint IoControlCode,
                IntPtr InBuffer, uint nInBufferSize,
                IntPtr OutBuffer, uint nOutBufferSize,
                out uint pBytesReturned, IntPtr Overlapped);
        }
'@
}

$IOCTL_SHUTDOWN = 0x8008214
$h = [TheChamber.Pinvoke+Native]::CreateFile(
    '\\.\WinHvMon', 0xC0000000, 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
if (-not $h.IsInvalid) {
    $junk = 0
    [TheChamber.Pinvoke+Native]::DeviceIoControl(
        $h, $IOCTL_SHUTDOWN, [IntPtr]::Zero, 0,
        [IntPtr]::Zero, 0, [ref]$junk, [IntPtr]::Zero) | Out-Null
    $h.Close()
}

Stop-Service -Name $svc -Force
Write-Host 'THE_CHAMBER stopped.' -ForegroundColor Green
