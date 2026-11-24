# build.ps1 -- compile and link chamber_shim.dll.
#
# A user-mode DLL (not a driver) so no WDK is required; MSVC x64
# (Visual Studio 2022 Build Tools, workload "C++ build tools") is
# enough. The build.ps1 at driver/ already imports vcvars64; this
# script duplicates the vswhere step so it is standalone, callable
# both from CI and from an operator at a plain prompt.
#
# Produces: launcher/shim/build/chamber_shim.dll (+ .pdb + .lib).
#
# The shim is signed by the launcher at install time, not here --
# running this script offline produces an unsigned DLL. The release
# pipeline signs it after build.

$ErrorActionPreference = 'Stop'
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$objDir = Join-Path $here 'build\obj'
$outDir = Join-Path $here 'build'
New-Item -ItemType Directory -Path $objDir -Force | Out-Null
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

Write-Host '=== chamber_shim build ===' -ForegroundColor Cyan

# --- Locate MSVC via vswhere ---
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) {
    throw 'vswhere.exe not found. Install Visual Studio 2022 Build Tools.'
}
$vsPath = & $vswhere -latest -products '*' `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
if (-not $vsPath) { throw 'MSVC x86.x64 toolset not installed.' }
$vcvars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found at $vcvars" }

Write-Host '  Importing MSVC env...'
$envDump = cmd /c "`"$vcvars`" >nul 2>nul && set"
foreach ($line in $envDump) {
    if ($line -match '^([^=]+)=(.*)$') {
        [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }
}

# --- Compile C++ ---
$cpp = Join-Path $here 'chamber_shim.cpp'
$obj = Join-Path $objDir 'chamber_shim.obj'
$cflags = '/nologo /c /W4 /WX- /O2 /GS- /Zi /std:c++17 /EHa'
$defines = '/D"_WIN64" /D"_AMD64_" /D"NDEBUG" /D"_WINDLL"'
Write-Host '  cl chamber_shim.cpp'
$cmd = "cl.exe $cflags $defines /I`"$here`" /Fo`"$obj`" `"$cpp`""
$out = cmd /c "$cmd 2>&1"
if ($LASTEXITCODE -ne 0) {
    $out | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
    throw 'cl.exe failed on chamber_shim.cpp'
}

# --- Assemble trampoline / vmmcall emitter ---
$asm = Join-Path $here 'chamber_shim_trampoline.asm'
$asmObj = Join-Path $objDir 'chamber_shim_trampoline.obj'
Write-Host '  ml64 chamber_shim_trampoline.asm'
$out = cmd /c "ml64.exe /c /nologo /Zi /Fo`"$asmObj`" `"$asm`" 2>&1"
if ($LASTEXITCODE -ne 0) {
    $out | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
    throw 'ml64 failed on chamber_shim_trampoline.asm'
}

# --- Link ---
$dll  = Join-Path $outDir 'chamber_shim.dll'
$def  = Join-Path $here 'chamber_shim.def'
$pdb  = Join-Path $outDir 'chamber_shim.pdb'

# User-mode DLL -- SUBSYSTEM:WINDOWS. No /DRIVER, no /NODEFAULTLIB.
# /DEF plumbs chamber_shim.def so chamber_shim_trampoline and
# chamber_shim_bind_sysnum are exported by name, not ordinal.
$linkFlags = "/NOLOGO /DLL /MACHINE:X64 /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF /RELEASE /DEF:`"$def`" /DEBUG /PDB:`"$pdb`""

$libs = @('kernel32.lib', 'user32.lib') -join ' '
Write-Host ''
Write-Host '=== Link ==='
$cmd = "link.exe $linkFlags /OUT:`"$dll`" `"$obj`" `"$asmObj`" $libs"
$out = cmd /c "$cmd 2>&1"
if ($LASTEXITCODE -ne 0) {
    $out | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    throw 'link.exe failed'
}
Write-Host "  Built: $dll ($([int]((Get-Item $dll).Length / 1024)) KiB)"
Write-Host '  (unsigned -- launcher / release pipeline signs at install time)'
Write-Host ''
Write-Host '=== Done ===' -ForegroundColor Green
