# MAKE_SHORTCUT.ps1 -- creates THE_CHAMBER.lnk on the Desktop and in the
# launcher folder, both set to "Run as administrator".

$ErrorActionPreference = 'Stop'

$load    = 'C:\THE_CHAMBER\launcher\load.ps1'
$icon    = "$env:SystemRoot\System32\SecurityHealthSystray.exe,0"
$desktop = [Environment]::GetFolderPath('Desktop')
$lnkDesk = Join-Path $desktop 'THE_CHAMBER.lnk'
$lnkHere = 'C:\THE_CHAMBER\launcher\THE_CHAMBER.lnk'

function New-Shortcut {
    param($Path, $Target, $Args, $Icon)
    $sh = New-Object -ComObject WScript.Shell
    $lnk = $sh.CreateShortcut($Path)
    $lnk.TargetPath       = $Target
    $lnk.Arguments        = $Args
    $lnk.WorkingDirectory = Split-Path $load
    $lnk.IconLocation     = $Icon
    $lnk.WindowStyle      = 1
    $lnk.Save()

    # Toggle the "Run as administrator" byte in the .lnk header.
    # (Byte 21 of the shell link data; set bit 0x20.)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $bytes[21] = [byte]($bytes[21] -bor 0x20)
    [IO.File]::WriteAllBytes($Path, $bytes)
}

New-Shortcut -Path $lnkDesk -Target 'powershell.exe' `
    -Args ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $load) -Icon $icon
New-Shortcut -Path $lnkHere -Target 'powershell.exe' `
    -Args ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $load) -Icon $icon

Write-Host "Shortcuts created:" -ForegroundColor Green
Write-Host "  $lnkDesk"
Write-Host "  $lnkHere"
