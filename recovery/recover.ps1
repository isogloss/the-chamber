# THE_CHAMBER recovery -- run from Safe Mode or WinRE command prompt
# Removes the hypervisor driver service and reverts BCD to pre-install.
Write-Host "THE_CHAMBER emergency recovery" -ForegroundColor Red
# Stop + delete service
sc.exe stop winhvmon 2>$null
sc.exe delete winhvmon 2>$null
# Restore BCD
$backup = "C:\the_chamber_bcd_*.bcd"
$latest = Get-ChildItem $backup | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($latest) {
  bcdedit /import $latest.FullName /clean
  Write-Host "BCD restored from $($latest.Name)" -ForegroundColor Green
} else {
  bcdedit /set testsigning off
  bcdedit /set nointegritychecks off
  Write-Host "No BCD backup found -- cleared test-signing manually" -ForegroundColor Yellow
}
Remove-Item 'C:\THE_CHAMBER\last_session.marker' -EA SilentlyContinue
Write-Host "Recovery complete. Reboot normally." -ForegroundColor Green
