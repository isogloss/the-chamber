# install_service.ps1 -- Phase 1.7 per-install randomized loader.
#
# Goals:
#   1. No SCM 7045/7036 events. sc.exe create / Start-Service go through SCM
#      and log 7045 / 7036 in the System log. We avoid both by:
#         * writing SYSTEM\CurrentControlSet\Services\<random> directly;
#         * loading with NtLoadDriver, not StartService.
#   2. No deterministic service / device / symlink / file name anywhere.
#      Every install mints a fresh 10-char alphanumeric name.
#   3. The driver's .cfg section carries the per-install name; we patch it
#      in place before re-signing.
#
# Known telemetry caveats (source comment -- no silent "fixes"):
#   * Sysmon EID 6 (driver loaded) fires from PsSetLoadImageNotifyRoutine
#     regardless of the load path. NtLoadDriver cannot suppress it.
#   * NT Kernel Logger Image_Load MOF events fire when the kernel-logger
#     session is active; same story.
#   * Microsoft-Windows-Kernel-Process EID 5 for kernel loads is
#     documented inconsistently across builds; its presence is unverified.
#   * SCM events 7045 / 7036 are what we target here, and that we can
#     avoid.
#   * SeLoadDriverPrivilege is enabled via RtlAdjustPrivilege, not
#     AdjustTokenPrivileges, to skip the "Special Privilege Assigned"
#     Audit 4672 that AdjustTokenPrivileges tends to trip on EV-audited
#     policies.

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
    Write-Host "Safety gate not found; refusing to install." -ForegroundColor Red
    exit 1
}
. $gate
if (-not (Get-Command Assert-NoAntiCheatRunning -ErrorAction SilentlyContinue)) {
    Write-Host "Safety gate loaded but Assert-NoAntiCheatRunning is undefined; refusing to install." -ForegroundColor Red
    exit 1
}
Assert-NoAntiCheatRunning

# ---- Elevation ----
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath)
    exit 0
}

# ---- Locate the newly-built driver ----
# build.ps1 writes build_output.sys. We rename a copy of it to a random
# name, patch the config blob, sign, and load that copy.
$srcSys  = 'C:\THE_CHAMBER\driver\build_output.sys'
if (-not (Test-Path $srcSys)) {
    Write-Host "Driver file not found: $srcSys" -ForegroundColor Red
    exit 1
}

# ---- Generate per-install random identity ----
# 10 character lowercase alphanumeric, starting with a letter so it looks
# like a plausible driver / service name.
function New-RandomName {
    $letters = [char[]]'abcdefghijklmnopqrstuvwxyz'
    $alnum   = [char[]]'abcdefghijklmnopqrstuvwxyz0123456789'
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $buf = New-Object byte[] 16
    $rng.GetBytes($buf)
    $s  = $letters[$buf[0] % $letters.Length]
    for ($i = 1; $i -lt 10; $i++) {
        $s += $alnum[$buf[$i] % $alnum.Length]
    }
    $s
}

$randName = New-RandomName
$dstSys   = "$env:SystemRoot\System32\drivers\$randName.sys"

# ---- copy + patch + sign gate ----
# Track whether the re-sign step fully succeeded. The outer try/finally
# removes the dropped .sys if we leave with $signSucceeded = $false, so
# a mid-sequence throw never leaves a patched-unsigned driver lingering
# in System32\drivers.
$signSucceeded = $false
try {

Copy-Item $srcSys $dstSys -Force
Write-Host "Installed as $dstSys" -ForegroundColor Cyan

# ---- Patch the .cfg section in place ----
# Locate the launcher signature (CHAMBER_CFG_MAGIC_V1 = 0x5F474643, bytes
# "CFG_") and overwrite the three path strings. Section layout matches
# CHAMBER_CFG in the_chamber.h:
#     +0   ULONG  magic           = 0x5F474643
#     +4   ULONG  version
#     +8   WCHAR  device_path [64]  -- 128 bytes
#     +136 WCHAR  symlink_path[64]  -- 128 bytes
#     +264 WCHAR  marker_path [128] -- 256 bytes
#     +520 ULONG  pool_tag_override
#     +524 ULONG  reserved[16]     -- 64 bytes
function Patch-DriverConfig {
    param(
        [string]$Path,
        [string]$DevicePath,
        [string]$SymlinkPath,
        [string]$MarkerPath
    )
    $bytes  = [System.IO.File]::ReadAllBytes($Path)
    # Magic is 0x5F474643 ("CFG_") followed by version 1 (little-endian);
    # we match 8 bytes together to avoid collisions with a bare "CFG_"
    # that could appear elsewhere in the binary (strings, resources).
    $magic  = [BitConverter]::GetBytes([uint32]0x5F474643)
    $ver    = [BitConverter]::GetBytes([uint32]1)
    $offset = -1
    for ($i = 0; $i -le $bytes.Length - 8; $i++) {
        if ($bytes[$i]   -eq $magic[0] -and
            $bytes[$i+1] -eq $magic[1] -and
            $bytes[$i+2] -eq $magic[2] -and
            $bytes[$i+3] -eq $magic[3] -and
            $bytes[$i+4] -eq $ver[0]   -and
            $bytes[$i+5] -eq $ver[1]   -and
            $bytes[$i+6] -eq $ver[2]   -and
            $bytes[$i+7] -eq $ver[3]) {
            $offset = $i
            break
        }
    }
    if ($offset -lt 0) {
        throw "CHAMBER_CFG magic+version not found in $Path"
    }

    function Write-Wide {
        param([byte[]]$Buf, [int]$At, [int]$MaxChars, [string]$Value)
        $enc = [System.Text.Encoding]::Unicode
        $vb  = $enc.GetBytes($Value + [char]0)
        if ($vb.Length -gt ($MaxChars * 2)) {
            throw "String too long for field: $Value"
        }
        # Zero the whole field first so no stale bytes leak through.
        for ($k = 0; $k -lt ($MaxChars * 2); $k++) { $Buf[$At + $k] = 0 }
        [Array]::Copy($vb, 0, $Buf, $At, $vb.Length)
    }

    Write-Wide $bytes ($offset + 8)   64  $DevicePath
    Write-Wide $bytes ($offset + 136) 64  $SymlinkPath
    Write-Wide $bytes ($offset + 264) 128 $MarkerPath

    [System.IO.File]::WriteAllBytes($Path, $bytes)
    Write-Host "Patched .cfg at offset 0x$($offset.ToString('X'))" -ForegroundColor DarkCyan
}

$devicePath  = "\Device\$randName"
$symlinkPath = "\DosDevices\$randName"
$markerPath  = "\??\$env:SystemRoot\System32\config\$randName.dat"

Patch-DriverConfig -Path $dstSys `
                   -DevicePath $devicePath `
                   -SymlinkPath $symlinkPath `
                   -MarkerPath $markerPath

# ---- Re-sign (signature is invalidated by the patch) ----
$pfx = 'C:\THE_CHAMBER\recovery\the_chamber_test.pfx'
$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter 'signtool.exe' -EA SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if (-not $signtool) { throw "signtool.exe not found" }
Write-Host "Re-signing patched driver..." -ForegroundColor Cyan
& $signtool.FullName sign /f $pfx /p 'build-test' /fd SHA256 $dstSys | Out-Null
if ($LASTEXITCODE -ne 0) { throw "signtool sign failed" }
$signSucceeded = $true

} finally {
    # If we leave the copy+patch+sign sequence without signSucceeded=true,
    # the dropped .sys is an unsigned (or signature-stripped) kernel driver
    # sitting in System32\drivers; remove it so repeated failed installs
    # don't accumulate. A locked file (another handle still open) is a
    # loud failure, not a silent one -- the operator needs to clean it up.
    if (-not $signSucceeded -and (Test-Path -LiteralPath $dstSys)) {
        try {
            Remove-Item -LiteralPath $dstSys -Force -ErrorAction Stop
            Write-Host "Removed un-signed intermediate driver: $dstSys" -ForegroundColor DarkYellow
        } catch {
            Write-Warning ("Could not remove intermediate driver {0}: {1}. Manual cleanup required." -f $dstSys, $_.Exception.Message)
        }
    }
}

# ---- Write the registry service key directly (no sc.exe) ----
$svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$randName"
New-Item -Path $svcKey -Force | Out-Null
# REG_EXPAND_SZ so the \SystemRoot\ prefix resolves correctly at load.
$imagePath = "\SystemRoot\System32\drivers\$randName.sys"
New-ItemProperty -Path $svcKey -Name 'ImagePath'   -Value $imagePath -PropertyType ExpandString -Force | Out-Null
New-ItemProperty -Path $svcKey -Name 'Type'        -Value 1 -PropertyType DWord -Force | Out-Null   # SERVICE_KERNEL_DRIVER
New-ItemProperty -Path $svcKey -Name 'Start'       -Value 3 -PropertyType DWord -Force | Out-Null   # SERVICE_DEMAND_START
New-ItemProperty -Path $svcKey -Name 'ErrorControl' -Value 1 -PropertyType DWord -Force | Out-Null  # SERVICE_ERROR_NORMAL

# ---- NtLoadDriver via P/Invoke ----
# RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &prev) first.
# NtLoadDriver on \Registry\Machine\SYSTEM\CurrentControlSet\Services\<random>.
$sig = @'
using System;
using System.Runtime.InteropServices;

public static class Nt {
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
    public static extern int NtLoadDriver(ref UNICODE_STRING name);

    public static int EnableLoadDriver() {
        bool prev;
        return RtlAdjustPrivilege(10, true, false, out prev);  // 10 = SE_LOAD_DRIVER_PRIVILEGE
    }

    public static int Load(string regPath) {
        var us = new UNICODE_STRING();
        RtlInitUnicodeString(ref us, regPath);
        return NtLoadDriver(ref us);
    }
}
'@
Add-Type -TypeDefinition $sig -ErrorAction Stop

$adjust = [Nt]::EnableLoadDriver()
if ($adjust -ne 0 -and $adjust -ne 0x40000016) {   # STATUS_PRIVILEGE_NOT_HELD is unlikely from admin; NOTIFY_CLEANUP is harmless
    Write-Host ("RtlAdjustPrivilege returned 0x{0:X8}" -f $adjust) -ForegroundColor Yellow
}

$loadSucceeded = $false
try {
    $nt = [Nt]::Load("\Registry\Machine\SYSTEM\CurrentControlSet\Services\$randName")
    if ($nt -ne 0) {
        Write-Host ("NtLoadDriver failed 0x{0:X8}" -f $nt) -ForegroundColor Red
    } else {
        $loadSucceeded = $true
    }
} catch {
    Write-Host ("NtLoadDriver threw: " + $_.Exception.Message) -ForegroundColor Red
    $nt = -1
}
if (-not $loadSucceeded) {
    # Roll back the on-disk + registry footprint we just created so a
    # failed load doesn't leave an orphan .sys + HKLM\...\Services\<name>
    # pair for the next install / UNINSTALL to trip over.
    if (Test-Path -LiteralPath $dstSys) {
        try {
            Remove-Item -LiteralPath $dstSys -Force -ErrorAction Stop
        } catch {
            Write-Warning ("NtLoadDriver rollback: could not remove {0}: {1}" -f $dstSys, $_.Exception.Message)
        }
    }
    try {
        Remove-Item -Path $svcKey -Recurse -Force -ErrorAction Stop
    } catch {
        Write-Warning ("NtLoadDriver rollback: could not remove {0}: {1}" -f $svcKey, $_.Exception.Message)
    }
    exit $nt
}

# Persist the chosen name so UNINSTALL / stop paths can find it. The state
# file itself lives under the install root (not SCM), so no SCM events.
$stateDir = 'C:\THE_CHAMBER\logs'
if (-not (Test-Path $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
"$randName" | Out-File -FilePath (Join-Path $stateDir 'last_install.txt') -Encoding ASCII -Force

Write-Host "Driver loaded via NtLoadDriver. Internal service name: $randName" -ForegroundColor Green
Write-Host "  Device path : $devicePath"
Write-Host "  DOS symlink : $symlinkPath"
