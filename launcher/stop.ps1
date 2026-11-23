# stop.ps1 -- graceful unload.
# Reads the per-install random name from logs/last_install.txt, issues
# IOCTL_SHUTDOWN against \\.\<rand>, then NtUnloadDriver on the registry
# service key. No sc.exe. No hardcoded 'winhvmon'.

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
    Write-Host "Safety gate not found; refusing to stop (operator must confirm quiet state first)." -ForegroundColor Red
    exit 1
}
. $gate
if (-not (Get-Command Assert-NoAntiCheatRunning -ErrorAction SilentlyContinue)) {
    Write-Host "Safety gate loaded but Assert-NoAntiCheatRunning is undefined; refusing to stop." -ForegroundColor Red
    exit 1
}
Assert-NoAntiCheatRunning

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath)
    exit 0
}

$root      = 'C:\THE_CHAMBER'
$stateFile = Join-Path $root 'logs\last_install.txt'
if (-not (Test-Path -LiteralPath $stateFile)) {
    Write-Host "No install state file ($stateFile); nothing to stop." -ForegroundColor Yellow
    exit 0
}
$name = (Get-Content -LiteralPath $stateFile -First 1 -ErrorAction SilentlyContinue)
if ($null -ne $name) { $name = $name.Trim() }
if (-not $name) {
    Write-Host "Install state file is empty; nothing to stop." -ForegroundColor Yellow
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

# CTL_CODE(0x8000, 0x803, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
$IOCTL_SHUTDOWN = [uint32]((0x8000 -shl 16) -bor (0x803 -shl 2))
if ($IOCTL_SHUTDOWN -ne 0x8000200C) { throw ("IOCTL_SHUTDOWN recompute mismatch: 0x{0:X}" -f $IOCTL_SHUTDOWN) }

$symlink = "\\.\$name"
$h = [TheChamber.Pinvoke+Native]::CreateFile(
    $symlink, 0xC0000000, 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
if (-not $h.IsInvalid) {
    $junk = 0
    [TheChamber.Pinvoke+Native]::DeviceIoControl(
        $h, $IOCTL_SHUTDOWN, [IntPtr]::Zero, 0,
        [IntPtr]::Zero, 0, [ref]$junk, [IntPtr]::Zero) | Out-Null
    $h.Close()
    # Driver's IOCTL_SHUTDOWN handler sets unload_requested but does not
    # itself drop the driver object; give it a beat before NtUnloadDriver.
    Start-Sleep -Milliseconds 300
} else {
    Write-Host ("Device symlink {0} did not open (LastError={1}); proceeding to NtUnloadDriver anyway." -f $symlink, [Runtime.InteropServices.Marshal]::GetLastWin32Error()) -ForegroundColor Yellow
}

# --- NtUnloadDriver ---
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
if (-not ('NtUnload' -as [type])) { Add-Type -TypeDefinition $sig -ErrorAction Stop }
$rc = [NtUnload]::Unload("\Registry\Machine\SYSTEM\CurrentControlSet\Services\$name")
if ($rc -ne 0) {
    Write-Host ("NtUnloadDriver returned 0x{0:X8}" -f $rc) -ForegroundColor Yellow
} else {
    Write-Host "Stopped $name." -ForegroundColor Green
}
