param(
    [string]$TargetName = "winhvmon",
    [string]$DisplayName = "Windows Hypervisor Monitor",
    [string]$Description = "Local hypervisor instrumentation service."
)

# obfuscate.ps1 -- renames the signed driver binary to a neutral name and
# installs it as a plain SCM kernel driver. Does NOT impersonate any specific
# vendor; uses operator-provided or default-neutral metadata.
# Run AFTER build.ps1 has produced C:\THE_CHAMBER\driver\winhvmon.sys.

. "C:\Users\lkhnj\Downloads\testbench\gpu_spoof\_safety_gate.ps1"
Assert-NoAntiCheatRunning

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$srcSys = "C:\THE_CHAMBER\driver\winhvmon.sys"
if (-not (Test-Path $srcSys)) { Write-Host "Missing $srcSys -- run build.ps1 first" -ForegroundColor Red; exit 1 }

$sig = Get-AuthenticodeSignature $srcSys
if ($sig.Status -ne 'Valid') {
    Write-Host "Driver signature not valid ($($sig.Status)). Resign via build.ps1 before obfuscating." -ForegroundColor Yellow
}

$targetFile = "C:\Windows\System32\drivers\$TargetName.sys"
Copy-Item $srcSys $targetFile -Force
Write-Host "Copied -> $targetFile" -ForegroundColor Green

sc.exe stop $TargetName 2>$null | Out-Null
sc.exe delete $TargetName 2>$null | Out-Null

sc.exe create $TargetName binPath= $targetFile type= kernel start= demand error= normal DisplayName= $DisplayName | Out-Null
sc.exe description $TargetName $Description | Out-Null

$paramKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$TargetName\Parameters"
if (-not (Test-Path $paramKey)) { New-Item -Path $paramKey -Force | Out-Null }
Set-ItemProperty -Path $paramKey -Name 'LogLevel' -Value 1 -Type DWord
Set-ItemProperty -Path $paramKey -Name 'MaxCpus' -Value 256 -Type DWord

$sig2 = Get-AuthenticodeSignature $targetFile
Write-Host ""
Write-Host "=== obfuscate complete ===" -ForegroundColor Cyan
Write-Host "  service name  : $TargetName"
Write-Host "  display name  : $DisplayName"
Write-Host "  binary path   : $targetFile"
Write-Host "  signature     : $($sig2.Status)"
Write-Host ""
Write-Host "To activate: Start-Service $TargetName  (or sc start $TargetName)"
