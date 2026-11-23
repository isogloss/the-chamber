# build.ps1 -- compile, link, sign chamber_fingerprint.sys.
# Mirrors driver/build.ps1 with the fingerprint source set and the
# minifilter library additions.
#
# Produces: driver/fingerprint/build_output.sys (placeholder filename;
# launcher renames and re-signs after CFG patch).

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$root    = 'C:\THE_CHAMBER'
$driver  = Join-Path $root 'driver\fingerprint'
$objDir  = Join-Path $root 'build\obj_fp'
$pfx     = Join-Path $root 'recovery\the_chamber_test.pfx'
$cer     = Join-Path $root 'recovery\the_chamber_test.cer'
New-Item -ItemType Directory -Path $objDir -Force | Out-Null

Write-Host "=== chamber_fingerprint build ===" -ForegroundColor Cyan

# --- Locate WDK ---
$kitsRoot = 'C:\Program Files (x86)\Windows Kits\10'
$incRoot  = Join-Path $kitsRoot 'Include'
$libRoot  = Join-Path $kitsRoot 'Lib'
$versions = @()
if (Test-Path $incRoot) {
    $versions = Get-ChildItem $incRoot -Directory |
        Where-Object { Test-Path (Join-Path $_.FullName 'km\ntddk.h') } |
        Sort-Object { [Version]$_.Name } -Descending
}
if ($versions.Count -eq 0) {
    throw "WDK (km\ntddk.h) not found under $incRoot. Install Windows Driver Kit."
}
$wdkVer   = $versions[0].Name
$wdkInc   = Join-Path $incRoot $wdkVer
$wdkLib   = Join-Path $libRoot "$wdkVer\km\x64"
Write-Host "  WDK version   : $wdkVer"
Write-Host "  WDK include   : $wdkInc"
Write-Host "  WDK kernel lib: $wdkLib"

# --- Locate MSVC via vswhere ---
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe not found. Install Visual Studio 2022 Build Tools."
}
$vsPath = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) { throw "MSVC x86.x64 toolset not installed." }
$vcvars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found at $vcvars" }

Write-Host "  Importing MSVC env..."
$envDump = cmd /c "`"$vcvars`" >nul 2>nul && set"
foreach ($line in $envDump) {
    if ($line -match '^([^=]+)=(.*)$') {
        [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }
}

# --- Compile ---
$sources = @(
    'entry.c',
    'cfg_shared.c',
    'target_pid.c',
    'instrumentation.c',
    'syscall_rewrite.c',
    'dmi_rewrite.c',
    'edid_template.c',
    'cm_filter.c',
    'flt_filter.c'
) | ForEach-Object { Join-Path $driver $_ } | Where-Object { Test-Path $_ }

if ($sources.Count -eq 0) { throw "No .c sources found under $driver." }

$includes = @(
    "/I`"$wdkInc\km\crt`"",
    "/I`"$wdkInc\km`"",
    "/I`"$wdkInc\shared`"",
    "/I`"$(Join-Path $root 'driver')`"",
    "/I`"$driver`""
) -join ' '

$defines = '/D"_AMD64_" /D"AMD64" /D"_WIN64" /D"WIN64" /D"NDEBUG"'
$cflags  = "/nologo /c /Zi /W4 /WX- /Gz /GS- /kernel /std:c17 /Zc:wchar_t-"

Write-Host ""
Write-Host "=== Compile ==="
$objFiles = @()
foreach ($src in $sources) {
    $obj = Join-Path $objDir ([IO.Path]::GetFileNameWithoutExtension($src) + '.obj')
    $cmd = "cl.exe $cflags $defines $includes /Fo`"$obj`" `"$src`""
    Write-Host "  cl $([IO.Path]::GetFileName($src))"
    $out = cmd /c "$cmd 2>&1"
    if ($LASTEXITCODE -ne 0) {
        $out | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        throw "cl.exe failed on $src"
    }
    $objFiles += $obj
}

# --- Assemble ic_trampoline.asm if present ---
$asm = Join-Path $driver 'ic_trampoline.asm'
if (Test-Path $asm) {
    $asmObj = Join-Path $objDir 'ic_trampoline.obj'
    Write-Host "  ml64 ic_trampoline.asm"
    $out = cmd /c "ml64.exe /c /nologo /Zi /Fo`"$asmObj`" `"$asm`" 2>&1"
    if ($LASTEXITCODE -ne 0) {
        $out | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        throw "ml64 failed on ic_trampoline.asm"
    }
    $objFiles += $asmObj
}

# --- Link ---
# Placeholder output name; launcher renames per install after CFG patch
# and before signing, like the_chamber.sys does.
$sys = Join-Path $driver 'build_output.sys'
$linkFlags = "/NOLOGO /SUBSYSTEM:NATIVE,10.0 /DRIVER /ENTRY:DriverEntry /MACHINE:X64 /INCREMENTAL:NO /NODEFAULTLIB /OPT:REF /OPT:ICF /RELEASE /PDBALTPATH:build_output.pdb /DEBUG:NONE"

# Minifilter adds fltmgr.lib. Fltmgr is the one extra kernel library
# beyond the HV driver's set.
$libs = @(
    (Join-Path $wdkLib 'ntoskrnl.lib'),
    (Join-Path $wdkLib 'hal.lib'),
    (Join-Path $wdkLib 'wmilib.lib'),
    (Join-Path $wdkLib 'fltmgr.lib'),
    (Join-Path $wdkLib 'BufferOverflowFastFailK.lib')
) | Where-Object { Test-Path $_ } | ForEach-Object { "`"$_`"" }
$objArg = ($objFiles | ForEach-Object { "`"$_`"" }) -join ' '
$libArg = $libs -join ' '
Write-Host ""
Write-Host "=== Link ==="
$cmd = "link.exe $linkFlags /OUT:`"$sys`" $objArg $libArg"
$out = cmd /c "$cmd 2>&1"
if ($LASTEXITCODE -ne 0) {
    $out | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    throw "link.exe failed"
}
Write-Host "  Built: $sys ($([int]((Get-Item $sys).Length / 1024)) KiB)"

# --- Test cert (shared with the_chamber.sys) ---
if (-not (Test-Path $pfx)) {
    Write-Host "  No test cert; driver/build.ps1 creates one. Run that first."
    exit 1
}

# --- Sign ---
$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter 'signtool.exe' -EA SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if (-not $signtool) { throw "signtool.exe not found" }
Write-Host ""
Write-Host "=== Sign ==="
& $signtool.FullName sign /f $pfx /p 'THE_CHAMBER' /fd SHA256 /t http://timestamp.digicert.com $sys
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Timestamp failed, retrying without timestamp..." -ForegroundColor Yellow
    & $signtool.FullName sign /f $pfx /p 'THE_CHAMBER' /fd SHA256 $sys
    if ($LASTEXITCODE -ne 0) { throw "signtool sign failed" }
}
& $signtool.FullName verify /pa /v $sys

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
Write-Host "  $sys"
