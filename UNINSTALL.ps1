param(
    [switch]$KeepTestSigning
)

#Requires -RunAsAdministrator

# UNINSTALL.ps1 -- reverses INSTALL.ps1. NtUnloadDriver-based, with
# registry-enumeration fallback for stale / wiped state files, and
# BCD-snapshot-driven revert (never blanket "off").

$ErrorActionPreference = 'Continue'
$root = 'C:\THE_CHAMBER'
$logs = Join-Path $root 'logs'

# --- Safety gate ---
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$gateCandidates = @(
    (Join-Path $scriptDir 'pentest\_safety_gate.ps1'),
    (Join-Path $root      'pentest\_safety_gate.ps1'),
    'C:\Users\lkhnj\Downloads\testbench\gpu_spoof\_safety_gate.ps1'
)
$gate = $gateCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $gate) {
    Write-Host "Safety gate not found; refusing to uninstall." -ForegroundColor Red
    exit 1
}
. $gate
if (-not (Get-Command Assert-NoAntiCheatRunning -ErrorAction SilentlyContinue)) {
    Write-Host "Safety gate loaded but Assert-NoAntiCheatRunning is undefined; refusing to uninstall." -ForegroundColor Red
    exit 1
}
Assert-NoAntiCheatRunning

Write-Host "=== Uninstall ===" -ForegroundColor Cyan

# --- NtUnloadDriver P/Invoke ---
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
if (-not ('NtUnload' -as [type])) { Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue }

function Remove-InstallByName {
    param([string]$Name)
    if (-not $Name) { return }
    $rc = [NtUnload]::Unload("\Registry\Machine\SYSTEM\CurrentControlSet\Services\$Name")
    if ($rc -ne 0) {
        Write-Host ("NtUnloadDriver on {0} returned 0x{1:X8}" -f $Name, $rc) -ForegroundColor Yellow
    }
    Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Recurse -Force -ErrorAction SilentlyContinue
    $drv = "$env:SystemRoot\System32\drivers\$Name.sys"
    if (Test-Path -LiteralPath $drv) { Remove-Item -LiteralPath $drv -Force -ErrorAction SilentlyContinue }
}

# --- 1. Fast path: last_install.txt ---
$stateFile = Join-Path $logs 'last_install.txt'
$seen = @{}
$fastName = $null
if (Test-Path -LiteralPath $stateFile) {
    $n = (Get-Content -LiteralPath $stateFile -First 1 -ErrorAction SilentlyContinue)
    if ($null -ne $n) { $n = $n.Trim() }
    if ($n) { $fastName = $n }
}
if ($fastName) {
    Write-Host "Unloading install from state file: $fastName" -ForegroundColor White
    Remove-InstallByName -Name $fastName
    $seen[$fastName] = $true
} else {
    Write-Host "No install state file; falling straight through to registry enumeration." -ForegroundColor DarkGray
}

# --- 2. Fallback: registry enumeration by CHAMBER_CFG fingerprint ---
# install_service.ps1 only writes last_install.txt with -Force; two earlier
# installs orphan prior drivers, and a wiped state file would silently leave
# the driver loaded. Walk the services hive, look for ImagePaths that point
# at a 10-char hex-style name in System32\drivers, and match against the
# CHAMBER_CFG magic in the .sys bytes.
$magicBytes = [byte[]](0x43, 0x46, 0x47, 0x5F)  # 0x5F474643 "CFG_"
function Test-ChamberFingerprint {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'Read')
        try {
            $buf  = New-Object byte[] 8192
            $prev = New-Object byte[] 4
            while ($true) {
                $n = $fs.Read($buf, 0, $buf.Length)
                if ($n -le 0) { break }
                $search = New-Object byte[] ($n + 3)
                [Array]::Copy($prev, 0, $search, 0, 3)
                [Array]::Copy($buf, 0, $search, 3, $n)
                for ($i = 0; $i -le $search.Length - 4; $i++) {
                    if ($search[$i]   -eq $magicBytes[0] -and
                        $search[$i+1] -eq $magicBytes[1] -and
                        $search[$i+2] -eq $magicBytes[2] -and
                        $search[$i+3] -eq $magicBytes[3]) {
                        return $true
                    }
                }
                [Array]::Copy($buf, [math]::Max(0, $n - 3), $prev, 0, [math]::Min(3, $n))
            }
            return $false
        } finally { $fs.Dispose() }
    } catch { return $false }
}

try {
    $svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $candidates = Get-ChildItem -Path $svcRoot -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^[a-z][a-z0-9]{9}$' }
    foreach ($svc in $candidates) {
        $name = $svc.PSChildName
        if ($seen.ContainsKey($name)) { continue }
        $img = (Get-ItemProperty -Path $svc.PSPath -Name 'ImagePath' -ErrorAction SilentlyContinue).ImagePath
        if (-not $img) { continue }
        # Keep only entries whose ImagePath ends in <10-hex>.sys under System32\drivers.
        if ($img -notmatch '[Dd]rivers[\\/]([a-z][a-z0-9]{9})\.sys$') { continue }
        $leaf = $Matches[1]
        $fullPath = "$env:SystemRoot\System32\drivers\$leaf.sys"
        if (-not (Test-ChamberFingerprint $fullPath)) { continue }
        Write-Host ("Fallback: unloading orphan {0}" -f $leaf) -ForegroundColor White
        Remove-InstallByName -Name $leaf
        $seen[$leaf] = $true
    }
} catch {
    Write-Host ("Service enumeration failed: " + $_.Exception.Message) -ForegroundColor Yellow
}

if ($seen.Count -eq 0) {
    Write-Host "Nothing to unload." -ForegroundColor Yellow
}

if (Test-Path -LiteralPath $stateFile) { Remove-Item -LiteralPath $stateFile -Force -EA SilentlyContinue }

# --- 3. Remove desktop shortcut ---
$desktop = [Environment]::GetFolderPath('Desktop')
$shortcuts = @(
    (Join-Path $desktop 'launcher.lnk'),
    (Join-Path $desktop 'THE_CHAMBER.lnk'),
    "$root\launcher\launcher.lnk",
    "$root\launcher\THE_CHAMBER.lnk"
)
foreach ($lnk in $shortcuts) { if (Test-Path -LiteralPath $lnk) { Remove-Item -LiteralPath $lnk -Force } }

# --- 4. Clear the crash marker ---
$marker = "$root\last_session.marker"
if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker -Force }

# --- 5. BCD restore from snapshot (never blanket off) ---
if (-not $KeepTestSigning) {
    $snapJson = Join-Path $logs 'bcd_pre_install.json'
    $snapHive = Join-Path $logs 'bcd_pre_install.bcd'
    $restoredFromHive = $false
    if (Test-Path -LiteralPath $snapHive) {
        try {
            bcdedit /import $snapHive /clean | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "BCD restored from snapshot: $snapHive" -ForegroundColor Green
                $restoredFromHive = $true
            }
        } catch {}
    }
    if (-not $restoredFromHive) {
        if (Test-Path -LiteralPath $snapJson) {
            try {
                $snap = Get-Content -LiteralPath $snapJson -Raw | ConvertFrom-Json
                if ($snap.installer_touched_testsigning) {
                    Write-Host "Reverting testsigning (INSTALL enabled it)..." -ForegroundColor White
                    bcdedit /set testsigning off | Out-Null
                } else {
                    Write-Host "testsigning was not changed by INSTALL; leaving as-is." -ForegroundColor DarkGray
                }
                if ($snap.installer_touched_nointegritychecks) {
                    Write-Host "Reverting nointegritychecks (INSTALL enabled it)..." -ForegroundColor White
                    bcdedit /set nointegritychecks off | Out-Null
                }
            } catch {
                Write-Host ("Could not parse $snapJson; leaving BCD flags untouched. " + $_.Exception.Message) -ForegroundColor Yellow
            }
        } else {
            Write-Host "No BCD snapshot found; leaving bcdedit flags untouched (INSTALL may have been skipped)." -ForegroundColor Yellow
        }
    }
    # Remove snapshot files so a later INSTALL takes a fresh baseline.
    Remove-Item -LiteralPath $snapJson -Force -EA SilentlyContinue
    Remove-Item -LiteralPath $snapHive -Force -EA SilentlyContinue
} else {
    Write-Host "-KeepTestSigning set; leaving BCD flags as-is." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Uninstall complete ===" -ForegroundColor Green
Write-Host "Project files remain at $root (delete manually if you no longer need them)."
if (-not $KeepTestSigning) { Write-Host "Reboot to clear the Test Mode watermark (if INSTALL set it)." }
