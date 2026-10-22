# run-lantern.ps1 — single-line paste-and-run launcher (WinUtils style)
# Usage from any machine:
#   irm https://raw.githubusercontent.com/wilcox101-maker/osint-lantern/main/run-lantern.ps1 | iex

$ErrorActionPreference = "Stop"
$Port = 43123
$NodeVersion = "v22.20.0"
$Repo = "https://github.com/wilcox101-maker/osint-lantern.git"
$Dir = Join-Path $env:TEMP "osint-lantern"

# Clone or update the repo
if (-not (Test-Path $Dir)) {
    Write-Host "Cloning repo..." -ForegroundColor Cyan
    git clone $Repo $Dir
} else {
    Write-Host "Updating repo..." -ForegroundColor Cyan
    Set-Location $Dir
    git pull
}
Set-Location $Dir

$NodeDir = Join-Path $Dir ".node"
$NodeExe = Join-Path $NodeDir "node.exe"
$Npm = Join-Path $NodeDir "npm.cmd"

if (-not (Test-Path $NodeExe)) {
    Write-Host "Fetching portable Node.js $NodeVersion..." -ForegroundColor Cyan
    $zip = Join-Path $env:TEMP "node.zip"
    Invoke-WebRequest "https://nodejs.org/dist/$NodeVersion/node-$NodeVersion-win-x64.zip" -OutFile $zip -UseBasicParsing
    if (Test-Path $NodeDir) { Remove-Item $NodeDir -Recurse -Force }
    Expand-Archive $zip $Dir -Force
    Rename-Item (Join-Path $Dir "node-$NodeVersion-win-x64") ".node"
    Remove-Item $zip -Force
}

# Put Node on PATH so postinstall scripts (esbuild, etc.) can find node
$env:PATH = "$NodeDir;$env:PATH"

Write-Host "Installing dependencies..." -ForegroundColor Cyan
& $Npm install --no-fund --no-audit

if (-not (Test-Path ".env") -and (Test-Path ".env.example")) {
    Copy-Item ".env.example" ".env"
}

Write-Host "Starting Lantern on http://127.0.0.1:$Port" -ForegroundColor Green
Start-Process "http://127.0.0.1:$Port"
& $Npm run dev
