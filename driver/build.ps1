# build.ps1 -- compile, link, and sign THE_CHAMBER.sys
# Needs: Visual Studio 2022 Build Tools (MSVC x64) + Windows Driver Kit
# (ntddk.h) + Windows SDK. The install_wdk.ps1 companion handles setup.

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$root    = 'C:\THE_CHAMBER'
$driver  = Join-Path $root 'driver'
$objDir  = Join-Path $root 'build\obj'
$pfx     = Join-Path $root 'recovery\the_chamber_test.pfx'
$cer     = Join-Path $root 'recovery\the_chamber_test.cer'
New-Item -ItemType Directory -Path $objDir -Force | Out-Null

Write-Host "=== THE_CHAMBER build ===" -ForegroundColor Cyan

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

# Import vcvars64 environment
Write-Host "  Importing MSVC env..."
$envDump = cmd /c "`"$vcvars`" >nul 2>nul && set"
foreach ($line in $envDump) {
    if ($line -match '^([^=]+)=(.*)$') {
        [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }
}

# --- Compile ---
$sources = @(
    'the_chamber.c',
    'svm_bringup.c',
    'svm_vmcb.c',
    'npt.c',
    'vmexit.c',
    'stealth.c',
    'timing.c'
) | ForEach-Object { Join-Path $driver $_ } | Where-Object { Test-Path $_ }

if ($sources.Count -eq 0) { throw "No .c sources found under $driver." }

$includes = @(
    "/I`"$wdkInc\km\crt`"",
    "/I`"$wdkInc\km`"",
    "/I`"$wdkInc\shared`"",
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

# --- Assemble every .asm file present ---
foreach ($asmName in @('vmrun.asm','asm_helpers.asm')) {
    $asm = Join-Path $driver $asmName
    if (Test-Path $asm) {
        $asmObj = Join-Path $objDir ([IO.Path]::GetFileNameWithoutExtension($asmName) + '.obj')
        Write-Host "  ml64 $asmName"
        $out = cmd /c "ml64.exe /c /nologo /Zi /Fo`"$asmObj`" `"$asm`" 2>&1"
        if ($LASTEXITCODE -ne 0) {
            $out | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
            throw "ml64 failed on $asmName"
        }
        $objFiles += $asmObj
    }
}

# --- Link ---
$sys = Join-Path $driver 'winhvmon.sys'
$linkFlags = "/NOLOGO /SUBSYSTEM:NATIVE,10.0 /DRIVER /ENTRY:DriverEntry /MACHINE:X64 /INCREMENTAL:NO /NODEFAULTLIB /OPT:REF /OPT:ICF /RELEASE /PDBALTPATH:winhvmon.pdb /DEBUG:NONE"
$libs = @(
    (Join-Path $wdkLib 'ntoskrnl.lib'),
    (Join-Path $wdkLib 'hal.lib'),
    (Join-Path $wdkLib 'wmilib.lib'),
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

# --- Test cert ---
if (-not (Test-Path $pfx)) {
    Write-Host ""
    Write-Host "=== Generating self-signed test cert ==="
    New-Item -ItemType Directory -Path (Split-Path $pfx) -Force | Out-Null
    $cert = New-SelfSignedCertificate `
        -Subject 'CN=WinHvMon Test' `
        -Type CodeSigningCert `
        -KeyUsage DigitalSignature `
        -KeyExportPolicy Exportable `
        -KeyLength 2048 `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter (Get-Date).AddYears(5) `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3')
    $pw = ConvertTo-SecureString -String 'THE_CHAMBER' -AsPlainText -Force
    Export-PfxCertificate -Cert "Cert:\CurrentUser\My\$($cert.Thumbprint)" -FilePath $pfx -Password $pw | Out-Null
    Export-Certificate -Cert "Cert:\CurrentUser\My\$($cert.Thumbprint)" -FilePath $cer -Type CERT | Out-Null
    # Trust it on this machine so test-signing accepts it
    Import-Certificate -FilePath $cer -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null
    Write-Host "  Cert   : $pfx"
    Write-Host "  Trusted in LocalMachine\Root + TrustedPublisher"
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
    # Timestamping may fail offline; retry without timestamp
    Write-Host "  Timestamp failed, retrying without timestamp..." -ForegroundColor Yellow
    & $signtool.FullName sign /f $pfx /p 'THE_CHAMBER' /fd SHA256 $sys
    if ($LASTEXITCODE -ne 0) { throw "signtool sign failed" }
}
& $signtool.FullName verify /pa /v $sys

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
Write-Host "  $sys"
