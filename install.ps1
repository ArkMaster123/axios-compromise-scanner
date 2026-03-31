Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRaw = "https://raw.githubusercontent.com/noahsark/axios-compromise-scanner/main"
$targetDir = Join-Path $HOME ".local\bin"
$targetFile = Join-Path $targetDir "axios-scan.py"

New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
Invoke-WebRequest -Uri "$repoRaw/scan.py" -OutFile $targetFile

Write-Host "Installed axios-scan to $targetFile"
Write-Host "Run: python $targetFile"
Write-Host "Optional alias (current session): Set-Alias axios-scan \"python $targetFile\""
