param(
    [Parameter(Mandatory = $true)]
    [string]$Archive,
    [string]$Tag = "netatlas:1.2.4",
    [int]$Port = 8765,
    [string]$DataPath = ".\netatlas-data",
    [string]$BindAddress = "0.0.0.0"
)

$ErrorActionPreference = "Stop"
$archivePath = (Resolve-Path -LiteralPath $Archive).Path
$checksumPath = "$archivePath.sha256"

if (Test-Path -LiteralPath $checksumPath) {
    $expected = ((Get-Content -LiteralPath $checksumPath -Raw).Trim() -split "\s+")[0]
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    if ($actual -ne $expected.ToLowerInvariant()) { throw "Image checksum verification failed." }
    Write-Host "Checksum verified." -ForegroundColor Green
}

docker load --input $archivePath
if ($LASTEXITCODE -ne 0) { throw "Docker image load failed." }

New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
$resolvedData = (Resolve-Path -LiteralPath $DataPath).Path
docker rm --force netatlas 2>$null | Out-Null
$dockerArgs = @(
    "run", "--detach", "--name", "netatlas", "--restart", "unless-stopped",
    "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN",
    "--security-opt", "no-new-privileges:true",
    "--publish", "${BindAddress}:${Port}:8765", "--volume", "${resolvedData}:/app/data"
)
$dockerArgs += $Tag
& docker @dockerArgs
if ($LASTEXITCODE -ne 0) { throw "NetAtlas container failed to start." }

Write-Host "NetAtlas is starting on ${BindAddress}:$Port" -ForegroundColor Green
Write-Host "Remote URL: http://<NETATLAS-NODE-IP>:$Port" -ForegroundColor Cyan
if ($BindAddress -eq "127.0.0.1") { Start-Process "http://127.0.0.1:$Port" }
