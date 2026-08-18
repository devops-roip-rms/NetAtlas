param(
    [string]$Tag = "netatlas:1.2.5",
    [ValidateSet("linux/amd64", "linux/arm64")]
    [string]$Platform = "linux/amd64"
)

$ErrorActionPreference = "Stop"
$appRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$distPath = Join-Path $appRoot "dist"
$safePlatform = $Platform.Replace("/", "-")
$archive = Join-Path $distPath "netatlas-1.2.5-$safePlatform.tar"

Set-Location -LiteralPath $appRoot
docker info | Out-Null
New-Item -ItemType Directory -Path $distPath -Force | Out-Null

Write-Host "Building $Tag for $Platform..." -ForegroundColor Cyan
docker build --platform $Platform --build-arg APP_VERSION=1.2.5 --tag $Tag .
if ($LASTEXITCODE -ne 0) { throw "Docker build failed." }

Write-Host "Saving offline image..." -ForegroundColor Cyan
docker save --output $archive $Tag
if ($LASTEXITCODE -ne 0) { throw "Docker image export failed." }

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
$checksumText = "$hash  $(Split-Path -Leaf $archive)`n"
[System.IO.File]::WriteAllText("$archive.sha256", $checksumText, [System.Text.UTF8Encoding]::new($false))
Copy-Item -LiteralPath (Join-Path $appRoot "scripts\load-and-run-airgap.ps1") -Destination $distPath -Force
Copy-Item -LiteralPath (Join-Path $appRoot "scripts\load-and-run-airgap.sh") -Destination $distPath -Force
Copy-Item -LiteralPath (Join-Path $appRoot "AIRGAP.md") -Destination $distPath -Force
Copy-Item -LiteralPath (Join-Path $appRoot "ROADMAP.md") -Destination $distPath -Force
Copy-Item -LiteralPath (Join-Path $appRoot "CHANGELOG.md") -Destination $distPath -Force

Write-Host "Offline bundle created:" -ForegroundColor Green
Write-Host "  $archive"
Write-Host "  $archive.sha256"
