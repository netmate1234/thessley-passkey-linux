# Builds dist\ThessleyPasskey\ on Windows. Needs Python 3.10+ (64-bit) from python.org or: winget install Python.Python.3.12
$ErrorActionPreference = "Stop"
Set-Location (Resolve-Path "$PSScriptRoot\..\..")
if (-not (Test-Path .venv)) { py -3 -m venv .venv }
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r packaging\windows\requirements.txt pyinstaller
.\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean packaging\windows\ThessleyPasskey.spec
Write-Host ""
Write-Host "Built: dist\ThessleyPasskey\ThessleyPasskey.exe"
Write-Host "Next: .\packaging\windows\install.ps1"
