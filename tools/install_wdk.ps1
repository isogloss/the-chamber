# Installs VS Build Tools + WDK via winget. Output to stdout, non-interactive.
$ErrorActionPreference = 'Continue'
Write-Host "[$(Get-Date -Format HH:mm:ss)] Installing Visual Studio Build Tools..."
winget install --id Microsoft.VisualStudio.2022.BuildTools `
  --silent --accept-source-agreements --accept-package-agreements `
  --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.26100"
Write-Host "[$(Get-Date -Format HH:mm:ss)] Installing Windows SDK..."
winget install --id Microsoft.WindowsSDK.10.0.26100 --silent --accept-source-agreements --accept-package-agreements
Write-Host "[$(Get-Date -Format HH:mm:ss)] Installing Windows WDK..."
winget install --id Microsoft.WindowsWDK.10.0.26100 --silent --accept-source-agreements --accept-package-agreements
Write-Host "[$(Get-Date -Format HH:mm:ss)] Done."
