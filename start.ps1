$ErrorActionPreference = "Stop"
$appRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCommand) {
    $pythonCommand = Get-Command py -ErrorAction SilentlyContinue
}
if (-not $pythonCommand) {
    Write-Host "Python 3.10 or newer is required." -ForegroundColor Red
    Write-Host "Install Python from https://www.python.org/downloads/windows/ and run this file again."
    Read-Host "Press Enter to close"
    exit 1
}
Set-Location -LiteralPath $appRoot
& $pythonCommand.Source backend.py
