# Installs the built app for the current user (no administrator needed) and makes thessleypasskey:// links open it.
$ErrorActionPreference = "Stop"
$src = Resolve-Path "$PSScriptRoot\..\..\dist\ThessleyPasskey"
$dest = Join-Path $env:LOCALAPPDATA "Programs\ThessleyPasskey"
if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
Copy-Item -Recurse $src $dest
# Start menu shortcut
$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut((Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Thessley Passkey.lnk"))
$lnk.TargetPath = Join-Path $dest "ThessleyPasskey.exe"
$lnk.WorkingDirectory = $dest
$lnk.Save()
# link handler (HKCU only)
& (Join-Path $dest "thessley-passkey-cli.exe") --register-handler
Write-Host "Installed to $dest"
Write-Host "Your enrolled keys are kept in $env:LOCALAPPDATA\ThessleyPasskey (not touched by install or uninstall)."
