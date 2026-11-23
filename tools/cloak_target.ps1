param(
    [Parameter(Mandatory=$true)]
    [string]$TargetExe,
    [switch]$BuildOnly
)

# cloak_target.ps1 -- drops the user-mode shim DLLs next to a target .exe so
# the Windows loader finds them first on LoadLibrary and they hook the APIs
# the target's detection logic reads from. Companion to the ring-0 driver
# which handles the CPUID/MSR surface at ring -1; these shims handle TBS,
# NCrypt, firmware tables, DXGI, GDI, and PE module enumeration at ring 3.

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
    Write-Host "Safety gate not found; refusing to run." -ForegroundColor Red
    exit 1
}
. $gate
if (-not (Get-Command Assert-NoAntiCheatRunning -ErrorAction SilentlyContinue)) {
    Write-Host "Safety gate loaded but Assert-NoAntiCheatRunning is undefined; refusing to run." -ForegroundColor Red
    exit 1
}
Assert-NoAntiCheatRunning

$testbench = 'C:\Users\lkhnj\Downloads\testbench'
$buildOut  = 'C:\THE_CHAMBER\tools\shim_bin'
New-Item -ItemType Directory -Path $buildOut -Force | Out-Null

# Shim sources: (source file, output DLL name, extra libs)
$shims = @(
    @{ Src = "$testbench\vtpm_setup\07_tbs_hook.c";                Out = 'tbs_shim.dll';         Libs = @('tbs.lib','bcrypt.lib') },
    @{ Src = "$testbench\vtpm_setup\08_tbs_hook_pcr_extended.c";   Out = 'tbs_pcr_shim.dll';     Libs = @('tbs.lib','bcrypt.lib') },
    @{ Src = "$testbench\vtpm_setup\10_firmware_table_hook.c";     Out = 'firmware_shim.dll';    Libs = @('kernel32.lib') },
    @{ Src = "$testbench\vtpm_setup\11_tbs_log_hook.c";            Out = 'tbs_log_shim.dll';     Libs = @('tbs.lib') },
    @{ Src = "$testbench\vtpm_setup\12_ncrypt_crypt32_shim.c";     Out = 'ncrypt_shim.dll';      Libs = @('bcrypt.lib','ncrypt.lib','crypt32.lib') },
    @{ Src = "$testbench\vtpm_setup\13_synthetic_tcg_log.c";       Out = 'synth_log_shim.dll';   Libs = @('tbs.lib','bcrypt.lib') },
    @{ Src = "$testbench\vtpm_setup\14_tbs_quote_credential_shim.c"; Out = 'quote_shim.dll';     Libs = @('tbs.lib','bcrypt.lib') },
    @{ Src = "$testbench\gpu_spoof\13_nvapi_stub.c";               Out = 'nvapi64.dll';          Libs = @() },
    @{ Src = "$testbench\gpu_spoof\16_dxgi_hook.c";                Out = 'dxgi_shim.dll';        Libs = @('dxgi.lib','d3d11.lib') },
    @{ Src = "$testbench\gpu_spoof\19_d3d12_feature_hook.c";       Out = 'd3d12_shim.dll';       Libs = @('d3d12.lib') },
    @{ Src = "$testbench\gpu_spoof\20_gdi32_hook.c";               Out = 'gdi32_shim.dll';       Libs = @('gdi32.lib') },
    @{ Src = "$testbench\gpu_spoof\21_signature_scanner_dll.c";    Out = 'scanner_shim.dll';     Libs = @('psapi.lib') }
)

# MinHook path (operator must supply; look in common spots)
$minhookCandidates = @(
    'C:\MinHook',
    'C:\THE_CHAMBER\tools\MinHook',
    "$testbench\MinHook"
)
$minhook = $minhookCandidates | Where-Object { Test-Path "$_\include\MinHook.h" } | Select-Object -First 1
if (-not $minhook) {
    Write-Host "MinHook not found. Install to one of:" -ForegroundColor Yellow
    $minhookCandidates | ForEach-Object { Write-Host "    $_" }
    Write-Host "Shims that require MinHook will fail to build; nvapi64 will build regardless." -ForegroundColor Yellow
}

# Locate MSVC
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "vswhere not found; VS Build Tools missing" }
$vsPath = (& $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -property installationPath).Trim()
$vcvars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat'

# Build each shim
Write-Host "=== Building shims ===" -ForegroundColor Cyan
$built = @()
foreach ($s in $shims) {
    if (-not (Test-Path $s.Src)) {
        Write-Host "  SKIP  $($s.Out): source missing ($($s.Src))" -ForegroundColor DarkGray
        continue
    }
    $needsMh = (Get-Content $s.Src -Raw) -match 'MinHook\.h'
    if ($needsMh -and -not $minhook) {
        Write-Host "  SKIP  $($s.Out): requires MinHook" -ForegroundColor Yellow
        continue
    }
    $libs = ($s.Libs -join ' ')
    $mhInclude = if ($minhook) { "/I`"$minhook\include`"" } else { "" }
    $mhLib     = if ($minhook) { "`"$minhook\lib\MinHook.x64.lib`"" } else { "" }
    $out = Join-Path $buildOut $s.Out
    $cmd = "cl.exe /nologo /O2 /LD /W3 $mhInclude `"$($s.Src)`" $mhLib $libs /link /OUT:`"$out`" /SUBSYSTEM:WINDOWS"
    $batch = "`"$vcvars`" >nul 2>&1 && $cmd"
    Write-Host "  cl $($s.Out)" -ForegroundColor White
    $output = cmd /c $batch 2>&1
    if ($LASTEXITCODE -eq 0 -and (Test-Path $out)) {
        $built += $out
        Write-Host "      OK ($([int]((Get-Item $out).Length / 1024)) KiB)" -ForegroundColor Green
    } else {
        Write-Host "      FAIL" -ForegroundColor Red
        $output | Select-Object -Last 5 | ForEach-Object { Write-Host "        $_" -ForegroundColor DarkGray }
    }
}

Write-Host ""
Write-Host "Built $($built.Count) shims." -ForegroundColor Cyan

if ($BuildOnly) {
    Write-Host "Done (-BuildOnly)."
    return
}

# Drop built shims next to the target
if (-not (Test-Path $TargetExe)) {
    Write-Host "Target not found: $TargetExe" -ForegroundColor Red
    return
}
$targetDir = Split-Path -Parent $TargetExe
Write-Host ""
Write-Host "=== Dropping shims next to $TargetExe ===" -ForegroundColor Cyan
foreach ($dll in $built) {
    Copy-Item $dll $targetDir -Force
    Write-Host "  dropped $(Split-Path -Leaf $dll)" -ForegroundColor Green
}
Write-Host ""
Write-Host "Ready. Launch $TargetExe; shims will load first on PATH order." -ForegroundColor Green
