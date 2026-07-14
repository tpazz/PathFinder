[CmdletBinding()]
param(
    [string]$Python = "python",
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "..\dist")
)

$ErrorActionPreference = "Stop"
$collector = Join-Path $PSScriptRoot "manual_privesc_collector.py"
$buildRoot = Join-Path ([System.IO.Path]::GetTempPath()) "pathfinder-manual-privesc-collector-build"
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
    --name "pathfinder-manual-privesc-collector" `
    --distpath $OutputDirectory `
    --workpath $workDirectory `
    --specpath $specDirectory `
    $collector

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller build failed with exit code $LASTEXITCODE."
}

$executable = Join-Path $OutputDirectory "pathfinder-manual-privesc-collector.exe"
Write-Host "[+] Built $executable"
