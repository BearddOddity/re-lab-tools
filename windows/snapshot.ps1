# Take a snapshot of the RE lab so it can be rolled back after breaking something.
# Usage:  .\snapshot.ps1  [-Name "before-unpacking-thing"]
param([string]$Name = "")

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'relab-common.ps1')
$distro = 'kali-linux'
$dir = $SnapshotDir
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$label = if ($Name) { ($Name -replace '[^\w\-]', '-') } else { 'snapshot' }
$out = Join-Path $dir "$stamp`_$label.tar"

Write-Host "Snapshotting $distro -> $out"
Write-Host "This takes a minute or two and the lab must be stopped; doing that now." -ForegroundColor DarkGray
wsl --terminate $distro 2>$null | Out-Null

wsl --export $distro $out
if ($LASTEXITCODE -ne 0) { throw "wsl --export failed with exit code $LASTEXITCODE" }

$size = [math]::Round((Get-Item $out).Length / 1GB, 2)
Write-Host "Done. ${size} GB written." -ForegroundColor Green
Write-Host "Restore it with:  .\restore.ps1 -File `"$out`""
