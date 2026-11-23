# load.ps1 -- double-clickable launcher for THE_CHAMBER.
#
# Flow:
#   1. Elevate to administrator (self-restart with RunAs if not elevated)
#   2. Read C:\THE_CHAMBER\logs\last_install.txt for the per-install random
#      service name and derived \\.\<rand> symlink. install_service.ps1
#      writes this file; load.ps1 is a no-op without it.
#   3. If the service isn't already loaded, invoke install_service.ps1 once
#      (NOT on every launch -- avoids piling up orphan random-named driver
#      files + registry keys when the previous shutdown left NtLoadDriver
#      state intact).
#   4. Open the symlink and spawn a watchdog runspace that fires
#      IOCTL_KICK every 20s.
#   5. Idle in the foreground until user closes window / Ctrl+C.
#   6. On exit: IOCTL_SHUTDOWN -> NtUnloadDriver -> close handle.

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
    Write-Host "Safety gate not found; refusing to launch." -ForegroundColor Red
    $gateCandidates | ForEach-Object { Write-Host "  tried: $_" -ForegroundColor DarkGray }
    Read-Host 'Press Enter to close'
    exit 1
}
. $gate
if (-not (Get-Command Assert-NoAntiCheatRunning -ErrorAction SilentlyContinue)) {
    Write-Host "Safety gate loaded but Assert-NoAntiCheatRunning is undefined; refusing to launch." -ForegroundColor Red
    Read-Host 'Press Enter to close'
    exit 1
}
Assert-NoAntiCheatRunning

# --- Elevate ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath)
    exit 0
}

$installer = Join-Path $PSScriptRoot 'install_service.ps1'
$root      = 'C:\THE_CHAMBER'
$stateFile = Join-Path $root 'logs\last_install.txt'
$srcSys    = "$root\driver\build_output.sys"

# --- Resolve per-install name via last_install.txt ---
# The installer is responsible for minting the random name and persisting
# it. We never guess here; a missing state file means "no live install".
function Read-InstallName {
    if (-not (Test-Path -LiteralPath $stateFile)) { return $null }
    $n = (Get-Content -LiteralPath $stateFile -First 1 -ErrorAction SilentlyContinue)
    if ($null -eq $n) { return $null }
    $n = $n.Trim()
    if ($n -eq '') { return $null }
    return $n
}

function Test-ServiceLoaded([string]$name) {
    # A live NtLoadDriver install leaves HKLM\...\Services\<name> on disk
    # and the device symlink reachable via CreateFile. Get-Service also
    # reports it as "Running" without round-tripping through SCM start.
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    return ($null -ne $svc -and $svc.Status -eq 'Running')
}

$name = Read-InstallName
if (-not $name -or -not (Test-ServiceLoaded $name)) {
    # Nothing live -- do a one-shot install. install_service.ps1 mints a
    # fresh random name and (re)writes last_install.txt.
    if (-not (Test-Path -LiteralPath $srcSys)) {
        Write-Host "Driver binary not found at $srcSys. Build it first via $root\driver\build.ps1" -ForegroundColor Red
        Read-Host 'Press Enter to close'
        exit 1
    }
    Write-Host 'Installing driver (one-shot per launch window)...' -ForegroundColor Cyan
    & $installer
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'Install failed.' -ForegroundColor Red
        Read-Host 'Press Enter to close'
        exit 1
    }
    $name = Read-InstallName
    if (-not $name) {
        Write-Host "Installer did not write $stateFile; cannot continue." -ForegroundColor Red
        Read-Host 'Press Enter to close'
        exit 1
    }
} else {
    Write-Host "Driver already loaded as $name; skipping install." -ForegroundColor DarkCyan
}

$symlink = "\\.\$name"

# --- P/Invoke DeviceIoControl ---
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

# CTL_CODE(DeviceType, Function, Method, Access) =
#   (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
# with DeviceType=0x8000, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0,
# FILE_READ_ACCESS=1, FILE_WRITE_ACCESS=2. KICK/SHUTDOWN mutate device
# state and require FILE_WRITE_ACCESS so the I/O manager's access-check
# passes on a GENERIC_WRITE-opened handle.
function New-CtlCode {
    param([uint32]$DeviceType, [uint32]$Function, [uint32]$Method = 0, [uint32]$Access = 0)
    return ([uint32](($DeviceType -shl 16) -bor ($Access -shl 14) -bor ($Function -shl 2) -bor $Method))
}

$GENERIC_READ_WRITE = 0xC0000000
$OPEN_EXISTING      = 3
$IOCTL_STATUS   = New-CtlCode -DeviceType 0x8000 -Function 0x801 -Access 0   # 0x80002004
$IOCTL_KICK     = New-CtlCode -DeviceType 0x8000 -Function 0x802 -Access 2   # 0x8000A008
$IOCTL_SHUTDOWN = New-CtlCode -DeviceType 0x8000 -Function 0x803 -Access 2   # 0x8000A00C

# Self-check: re-derive and assert. A mistyped literal here cost us a
# watchdog kick in an earlier revision -- never again.
if ($IOCTL_STATUS   -ne 0x80002004) { throw ("IOCTL_STATUS   recompute mismatch: 0x{0:X}" -f $IOCTL_STATUS) }
if ($IOCTL_KICK     -ne 0x8000A008) { throw ("IOCTL_KICK     recompute mismatch: 0x{0:X}" -f $IOCTL_KICK) }
if ($IOCTL_SHUTDOWN -ne 0x8000A00C) { throw ("IOCTL_SHUTDOWN recompute mismatch: 0x{0:X}" -f $IOCTL_SHUTDOWN) }

$h = [TheChamber.Pinvoke+Native]::CreateFile(
    $symlink, $GENERIC_READ_WRITE, 0,
    [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
if ($h.IsInvalid) {
    Write-Host ("Could not open device handle for {0} (LastError={1})" -f $symlink, [Runtime.InteropServices.Marshal]::GetLastWin32Error()) -ForegroundColor Red
    Read-Host 'Press Enter to close'
    exit 1
}

Write-Host "[ACTIVE] running as $name ($symlink). Close this window to unload." -ForegroundColor Green
Write-Host '          (Watchdog: driver auto-unloads after 60s without a kick.)' -ForegroundColor Gray
Write-Host ''

# --- Watchdog kicker runspace ---
$rsPool = [runspacefactory]::CreateRunspacePool(1, 1)
$rsPool.Open()
$script = {
    param($hVal, $ioctl)
    while ($true) {
        $junk = 0
        [TheChamber.Pinvoke+Native]::DeviceIoControl(
            [System.Runtime.InteropServices.SafeHandle]$hVal, $ioctl,
            [IntPtr]::Zero, 0, [IntPtr]::Zero, 0, [ref]$junk, [IntPtr]::Zero) | Out-Null
        Start-Sleep -Seconds 20
    }
}
$ps = [powershell]::Create()
$ps.RunspacePool = $rsPool
$ps.AddScript($script).AddArgument($h).AddArgument($IOCTL_KICK) | Out-Null
$async = $ps.BeginInvoke()

# --- Idle until Ctrl+C or window close ---
try {
    while ($true) { Start-Sleep -Seconds 1 }
} finally {
    Write-Host ''
    Write-Host 'Shutting down...' -ForegroundColor Yellow
    $junk = 0
    try {
        [TheChamber.Pinvoke+Native]::DeviceIoControl(
            $h, $IOCTL_SHUTDOWN, [IntPtr]::Zero, 0,
            [IntPtr]::Zero, 0, [ref]$junk, [IntPtr]::Zero) | Out-Null
    } catch {}
    try { $h.Close() } catch {}
    try { $ps.Stop() } catch {}
    try { $rsPool.Close() } catch {}
    # NtUnloadDriver so no SCM 7036 event fires.
    try {
        $sig = @'
using System;
using System.Runtime.InteropServices;
public static class NtUnloadLoad {
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
        if (-not ('NtUnloadLoad' -as [type])) { Add-Type -TypeDefinition $sig -ErrorAction Stop }
        [void][NtUnloadLoad]::Unload("\Registry\Machine\SYSTEM\CurrentControlSet\Services\$name")
    } catch {}
    Write-Host 'Unloaded.' -ForegroundColor Green
}
