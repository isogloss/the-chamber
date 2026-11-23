# recover.ps1 -- emergency recovery. Run from Safe Mode or WinRE.
#
# Unloads the driver by whatever random name INSTALL.ps1 persisted to
# C:\THE_CHAMBER\logs\last_install.txt. Falls back to enumerating
# HKLM\SYSTEM\CurrentControlSet\Services\* for ImagePaths that point at
# <10-hex>.sys in System32\drivers whose bytes carry the CHAMBER_CFG
# magic -- so a stale / wiped state file does not strand a loaded
# driver.
#
# BCD restore comes from the snapshot INSTALL.ps1 wrote (see
# logs/bcd_pre_install.{bcd,json}); we only toggle testsigning /
# nointegritychecks when the snapshot says INSTALL turned them on.

Write-Host "emergency recovery" -ForegroundColor Red
$ErrorActionPreference = 'Continue'
$root = 'C:\THE_CHAMBER'
$logs = Join-Path $root 'logs'

# ---- NtUnloadDriver P/Invoke ----
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

function Remove-InstallByName {
    param([string]$Name)
    if (-not $Name) { return }
    $rc = [NtUnload]::Unload("\Registry\Machine\SYSTEM\CurrentControlSet\Services\$Name")
    if ($rc -eq 0) {
        Write-Host ("Unloaded {0}" -f $Name) -ForegroundColor Green
    } else {
        Write-Host ("NtUnloadDriver on {0} returned 0x{1:X8} (proceeding to delete regkey/.sys)" -f $Name, $rc) -ForegroundColor Yellow
    }
    Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Recurse -Force -ErrorAction SilentlyContinue
    $drv = "$env:SystemRoot\System32\drivers\$Name.sys"
    if (Test-Path -LiteralPath $drv) { Remove-Item -LiteralPath $drv -Force -ErrorAction SilentlyContinue }
}

# ---- 1. Fast path: last_install.txt ----
$stateFile = Join-Path $logs 'last_install.txt'
$seen = @{}
if (Test-Path -LiteralPath $stateFile) {
    $n = (Get-Content -LiteralPath $stateFile -First 1 -ErrorAction SilentlyContinue)
    if ($null -ne $n) { $n = $n.Trim() }
    if ($n) {
        Write-Host ("Fast path: unloading {0}" -f $n) -ForegroundColor White
        Remove-InstallByName -Name $n
        $seen[$n] = $true
    }
}

# ---- 2. Fallback: enumerate services by ImagePath signature ----
# Walk every service key; for each ImagePath that resolves to a file in
# System32\drivers whose basename is 10 lowercase-alnum chars starting
# with a letter and whose bytes contain CHAMBER_CFG magic (0x5F474643),
# treat it as a chamber install and unload / clean it up.
$magicBytes = [byte[]](0x43, 0x46, 0x47, 0x5F, 0x01, 0x00, 0x00, 0x00)  # "CFG_" + version 1 (LE)
function Test-ChamberFingerprint {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'Read')
        try {
            $buf = New-Object byte[] 8192
            $prev = New-Object byte[] 7
            while ($true) {
                $n = $fs.Read($buf, 0, $buf.Length)
                if ($n -le 0) { break }
                # Join with trailing 7 bytes of previous chunk so an 8-byte
                # magic straddling the window boundary is still found.
                $search = New-Object byte[] ($n + 7)
                [Array]::Copy($prev, 0, $search, 0, 7)
                [Array]::Copy($buf, 0, $search, 7, $n)
                for ($i = 0; $i -le $search.Length - 8; $i++) {
                    if ($search[$i]   -eq $magicBytes[0] -and
                        $search[$i+1] -eq $magicBytes[1] -and
                        $search[$i+2] -eq $magicBytes[2] -and
                        $search[$i+3] -eq $magicBytes[3] -and
                        $search[$i+4] -eq $magicBytes[4] -and
                        $search[$i+5] -eq $magicBytes[5] -and
                        $search[$i+6] -eq $magicBytes[6] -and
                        $search[$i+7] -eq $magicBytes[7]) {
                        return $true
                    }
                }
                [Array]::Copy($buf, [math]::Max(0, $n - 7), $prev, 0, [math]::Min(7, $n))
            }
            return $false
        } finally {
            $fs.Dispose()
        }
    } catch {
        return $false
    }
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
        # Normalize \SystemRoot\System32\drivers\<rand>.sys to a real path
        $resolved = $img -replace '^(\\SystemRoot\\|\\\?\?\\|system32)', ''
        if ($resolved -match '^(.*[\\/])?([a-z][a-z0-9]{9})\.sys$') {
            $leaf = $Matches[2]
            $fullPath = "$env:SystemRoot\System32\drivers\$leaf.sys"
            if (Test-ChamberFingerprint $fullPath) {
                Write-Host ("Fallback: unloading orphan {0}" -f $leaf) -ForegroundColor White
                Remove-InstallByName -Name $leaf
                $seen[$leaf] = $true
            }
        }
    }
} catch {
    Write-Host ("Service enumeration failed: " + $_.Exception.Message) -ForegroundColor Yellow
}

if ($seen.Count -eq 0) {
    Write-Host "No chamber install found via state file or service enumeration." -ForegroundColor DarkGray
}

# ---- 3. BCD restore from snapshot (not blanket off) ----
$snapJson = Join-Path $logs 'bcd_pre_install.json'
$snapHive = Join-Path $logs 'bcd_pre_install.bcd'
$restoredFromHive = $false
if (Test-Path -LiteralPath $snapHive) {
    try {
        bcdedit /import $snapHive /clean | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "BCD restored from $snapHive" -ForegroundColor Green
            $restoredFromHive = $true
        }
    } catch {}
}
if (-not $restoredFromHive) {
    if (Test-Path -LiteralPath $snapJson) {
        try {
            $snap = Get-Content -LiteralPath $snapJson -Raw | ConvertFrom-Json
            # Only revert what INSTALL.ps1 recorded itself as touching.
            if ($snap.installer_touched_testsigning) {
                bcdedit /set testsigning off | Out-Null
                Write-Host "Reverted testsigning (INSTALL enabled it)." -ForegroundColor Green
            } else {
                Write-Host "testsigning was not changed by INSTALL; leaving as-is." -ForegroundColor DarkGray
            }
            if ($snap.installer_touched_nointegritychecks) {
                bcdedit /set nointegritychecks off | Out-Null
                Write-Host "Reverted nointegritychecks (INSTALL enabled it)." -ForegroundColor Green
            }
        } catch {
            Write-Host ("Could not parse $snapJson; leaving BCD flags untouched. " + $_.Exception.Message) -ForegroundColor Yellow
        }
    } else {
        Write-Host "No BCD snapshot found; leaving bcdedit flags as-is." -ForegroundColor Yellow
    }
}

Remove-Item -LiteralPath (Join-Path $root 'last_session.marker') -EA SilentlyContinue
if (Test-Path -LiteralPath $stateFile) { Remove-Item -LiteralPath $stateFile -Force -EA SilentlyContinue }
Write-Host "Recovery complete. Reboot normally." -ForegroundColor Green
