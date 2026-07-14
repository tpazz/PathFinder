[CmdletBinding()]
param(
    [string]$Python = "python",
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "..\dist")
)

$ErrorActionPreference = "Stop"
$collector = Join-Path $PSScriptRoot "ai_loot_collector.py"
$buildRoot = Join-Path ([System.IO.Path]::GetTempPath()) "pathfinder-ai-loot-collector-build"
$workDirectory = Join-Path $buildRoot "work"
$specDirectory = Join-Path $buildRoot "spec"

& $Python -m PyInstaller --version *> $null
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller is not installed. Run: $Python -m pip install pyinstaller"
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $workDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $specDirectory | Out-Null
& $Python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --console `
    --name "pathfinder-ai-loot-collector" `
    --distpath $OutputDirectory `
    --workpath $workDirectory `
    --specpath $specDirectory `
    $collector

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller build failed with exit code $LASTEXITCODE."
}

$executable = Join-Path $OutputDirectory "pathfinder-ai-loot-collector.exe"
Write-Host "[+] Built $executable"
