param(
    [string]$Uri = "",
    [string]$PuttyPath = ""
)

$ErrorActionPreference = "Stop"

if ($Uri) {
    if (-not $PuttyPath -or -not (Test-Path -LiteralPath $PuttyPath -PathType Leaf)) {
        throw "The registered PuTTY executable was not found. Run this script again to repair the NetAtlas PuTTY handler."
    }
    $parsed = [System.Uri]$Uri
    if ($parsed.Scheme -ne "netatlas-putty" -or -not $parsed.Host) {
        throw "Invalid NetAtlas PuTTY link."
    }
    $targetHost = $parsed.Host
    $targetPort = if ($parsed.Port -gt 0) { $parsed.Port } else { 22 }
    $targetUser = [System.Uri]::UnescapeDataString($parsed.UserInfo)
    $destination = if ($targetUser) { "$targetUser@$targetHost" } else { $targetHost }
    Start-Process -FilePath $PuttyPath -ArgumentList @("-ssh", ('"{0}"' -f $destination), "-P", [string]$targetPort)
    exit 0
}

$candidatePaths = @()
if ($PuttyPath) { $candidatePaths += $PuttyPath }
$puttyCommand = Get-Command putty.exe -ErrorAction SilentlyContinue
if ($puttyCommand) { $candidatePaths += $puttyCommand.Source }
$candidatePaths += "${env:ProgramFiles}\PuTTY\putty.exe"
if (${env:ProgramFiles(x86)}) { $candidatePaths += "${env:ProgramFiles(x86)}\PuTTY\putty.exe" }
$resolvedPutty = $candidatePaths | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
if (-not $resolvedPutty) {
    throw "PuTTY was not found. Install PuTTY or rerun: .\register-putty-handler.ps1 -PuttyPath C:\Path\To\putty.exe"
}
$resolvedPutty = (Resolve-Path -LiteralPath $resolvedPutty).Path

$handlerDirectory = Join-Path $env:LOCALAPPDATA "NetAtlas"
$handlerScript = Join-Path $handlerDirectory "open-putty-url.ps1"
New-Item -ItemType Directory -Path $handlerDirectory -Force | Out-Null
if ((Resolve-Path -LiteralPath $PSCommandPath).Path -ne $handlerScript) {
    Copy-Item -LiteralPath $PSCommandPath -Destination $handlerScript -Force
}

$protocolKey = "HKCU:\Software\Classes\netatlas-putty"
$commandKey = Join-Path $protocolKey "shell\open\command"
New-Item -Path $commandKey -Force | Out-Null
Set-Item -Path $protocolKey -Value "URL:NetAtlas PuTTY Protocol"
New-ItemProperty -Path $protocolKey -Name "URL Protocol" -Value "" -PropertyType String -Force | Out-Null
$launchCommand = '"powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "{0}" -Uri "%1" -PuttyPath "{1}"' -f $handlerScript, $resolvedPutty
Set-Item -Path $commandKey -Value $launchCommand

Write-Host "NetAtlas PuTTY links are ready for the current Windows user."
Write-Host "PuTTY: $resolvedPutty"
