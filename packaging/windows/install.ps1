# Installs the built app for the current user (no administrator needed) and makes Thessley links open it.
# Can run in an interactive PowerShell session over SSH. Shortcuts and URI handlers are per-user.
$ErrorActionPreference = "Stop"
$src = Resolve-Path "$PSScriptRoot\..\..\dist\ThessleyPasskey"
$dest = Join-Path $env:LOCALAPPDATA "Programs\ThessleyPasskey"
if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
Copy-Item -Recurse $src $dest
# Start menu shortcut
$shell = New-Object -ComObject WScript.Shell
$exe = Join-Path $dest "ThessleyPasskey.exe"
$shortcutPaths = @(
    (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Thessley Passkey.lnk"),
    (Join-Path ([Environment]::GetFolderPath("Desktop")) "Thessley Passkey.lnk")
)
foreach ($shortcutPath in $shortcutPaths) {
    New-Item -ItemType Directory -Force -Path (Split-Path $shortcutPath) | Out-Null
    $lnk = $shell.CreateShortcut($shortcutPath)
    $lnk.TargetPath = $exe
    $lnk.WorkingDirectory = $dest
    $lnk.IconLocation = "$exe,0"
    $lnk.Save()
}
# link handler (HKCU only)
& (Join-Path $dest "thessley-passkey-cli.exe") --register-handler
Write-Host "Installed to $dest"
Write-Host "Created Start menu and Desktop shortcuts for $env:USERNAME. Run this installer once for each Windows account that needs the app."
Write-Host "Your enrolled keys are kept in $env:LOCALAPPDATA\ThessleyPasskey (not touched by install or uninstall)."
