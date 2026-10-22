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
$NpmCli = Join-Path $NodeDir "node_modules\npm\bin\npm-cli.js"

if (-not (Test-Path $NodeExe)) {
    Write-Host "Fetching portable Node.js $NodeVersion..." -ForegroundColor Cyan
    $zip = Join-Path $env:TEMP "node.zip"
    Invoke-WebRequest "https://nodejs.org/dist/$NodeVersion/node-$NodeVersion-win-x64.zip" -OutFile $zip -UseBasicParsing
    if (Test-Path $NodeDir) { Remove-Item $NodeDir -Recurse -Force }
    Expand-Archive $zip $Dir -Force
    Rename-Item (Join-Path $Dir "node-$NodeVersion-win-x64") ".node"
    Remove-Item $zip -Force
}

# Ensure Node is first on PATH for any child processes
$env:PATH = "$NodeDir;$env:PATH"

Write-Host "Installing dependencies..." -ForegroundColor Cyan
# Call npm-cli.js directly through node.exe so scripts always find node
& $NodeExe $NpmCli install --no-fund --no-audit

if (-not (Test-Path ".env") -and (Test-Path ".env.example")) {
    Copy-Item ".env.example" ".env"
}

Write-Host "Starting Lantern on http://127.0.0.1:$Port" -ForegroundColor Green
Start-Process "http://127.0.0.1:$Port"
& $NodeExe $NpmCli run dev
