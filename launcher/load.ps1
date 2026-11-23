# load.ps1 -- double-clickable launcher for THE_CHAMBER.
#
# Flow:
#   1. Elevate to administrator (self-restart with RunAs if not elevated)
#   2. Install SCM service (idempotent) pointing at the signed .sys
#   3. sc start the_chamber
#   4. Open \\.\WinHvMon device
#   5. Spawn a background runspace that fires IOCTL_KICK (0x802) every 20s
#   6. Idle in the foreground until user closes window / Ctrl+C
#   7. On exit: IOCTL_SHUTDOWN (0x803) -> sc stop -> close handle

$ErrorActionPreference = 'Stop'

# Dot-source the AC safety gate (from the testbench project)
$gate = 'C:\Users\lkhnj\Downloads\testbench\gpu_spoof\_safety_gate.ps1'
if (Test-Path $gate) {
    . $gate
    Assert-NoAntiCheatRunning
}

# --- Elevate ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath)
    exit 0
}

$svc = 'winhvmon'
$sys = 'C:\THE_CHAMBER\driver\winhvmon.sys'
$installer = Join-Path $PSScriptRoot 'install_service.ps1'

if (-not (Test-Path $sys)) {
    Write-Host "THE_CHAMBER.sys not found at $sys. Build it first via C:\THE_CHAMBER\driver\build.ps1" -ForegroundColor Red
    Read-Host 'Press Enter to close'
    exit 1
}

# --- Install service if missing ---
$existing = Get-Service -Name $svc -ErrorAction SilentlyContinue
if (-not $existing) {
    Write-Host 'Installing service...' -ForegroundColor Cyan
    & $installer
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'Service install failed.' -ForegroundColor Red
        Read-Host 'Press Enter to close'
        exit 1
    }
}

# --- Start ---
Write-Host 'Starting THE_CHAMBER service...' -ForegroundColor Cyan
Start-Service -Name $svc
Start-Sleep -Milliseconds 500

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

$GENERIC_READ_WRITE = 0xC0000000
$OPEN_EXISTING = 3
$IOCTL_STATUS   = 0x800820C  # (0x8000<<16) | (FILE_ANY_ACCESS<<14) | (0x801<<2) | METHOD_BUFFERED
$IOCTL_KICK     = 0x8008210  # (0x8000<<16) | (0<<14) | (0x802<<2) | 0
$IOCTL_SHUTDOWN = 0x8008214  # 0x803<<2 | 0

$h = [TheChamber.Pinvoke+Native]::CreateFile(
    '\\.\WinHvMon', $GENERIC_READ_WRITE, 0,
    [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
if ($h.IsInvalid) {
    Write-Host ("Could not open device handle (LastError={0})" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error()) -ForegroundColor Red
    Stop-Service -Name $svc -Force
    Read-Host 'Press Enter to close'
    exit 1
}

Write-Host '[ACTIVE] THE_CHAMBER running. Close this window to unload.' -ForegroundColor Green
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
    Write-Host 'Shutting down THE_CHAMBER...' -ForegroundColor Yellow
    $junk = 0
    [TheChamber.Pinvoke+Native]::DeviceIoControl(
        $h, $IOCTL_SHUTDOWN, [IntPtr]::Zero, 0,
        [IntPtr]::Zero, 0, [ref]$junk, [IntPtr]::Zero) | Out-Null
    $h.Close()
    try { $ps.Stop() } catch {}
    $rsPool.Close()
    try { Stop-Service -Name $svc -Force -ErrorAction Stop } catch {}
    Write-Host 'Unloaded.' -ForegroundColor Green
}
