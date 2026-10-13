# Removes the app and its link handler. Enrolled keys stay in %LOCALAPPDATA%\ThessleyPasskey unless you pass -Purge.
param([switch]$Purge)
$dest = Join-Path $env:LOCALAPPDATA "Programs\ThessleyPasskey"
$cli = Join-Path $dest "thessley-passkey-cli.exe"
if (Test-Path $cli) { & $cli --unregister-handler }
Remove-Item -Recurse -Force $dest -ErrorAction SilentlyContinue
Remove-Item -Force (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Thessley Passkey.lnk") -ErrorAction SilentlyContinue
if ($Purge) { Remove-Item -Recurse -Force (Join-Path $env:LOCALAPPDATA "ThessleyPasskey") -ErrorAction SilentlyContinue; Write-Host "Enrolled devices deleted." }
Write-Host "Uninstalled."
