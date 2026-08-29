# Roll the RE lab back to a snapshot.
#
# THIS DESTROYS THE CURRENT LAB. Everything in the distro since that snapshot is
# gone: installed tools, files in the home directory, notes. Anything you want to
# keep should already be in D:\re-lab-share, which lives on Windows and is not
# touched by this script.
#
# Usage:  .\restore.ps1                    (lists snapshots, pick one)
#         .\restore.ps1 -File <path.tar>
param([string]$File = "")

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'relab-common.ps1')
$distro = 'kali-linux'
$dir = $SnapshotDir
$target = $DistroDir

if (-not $File) {
    $snaps = @(Get-ChildItem -Path $dir -Filter *.tar -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if (-not $snaps) { throw "No snapshots found in $dir. Run .\snapshot.ps1 first." }
    Write-Host "Snapshots, newest first:`n"
    for ($i = 0; $i -lt $snaps.Count; $i++) {
        "{0,3}. {1}  ({2:N2} GB, {3})" -f ($i + 1), $snaps[$i].Name, ($snaps[$i].Length / 1GB), $snaps[$i].LastWriteTime
    }
    $pick = Read-Host "`nNumber to restore (anything else cancels)"
    if ($pick -notmatch '^\d+$' -or [int]$pick -lt 1 -or [int]$pick -gt $snaps.Count) { Write-Host "Cancelled."; exit }
    $File = $snaps[[int]$pick - 1].FullName
}

if (-not (Test-Path $File)) { throw "Snapshot not found: $File" }

Write-Host "`nAbout to REPLACE the current '$distro' lab with:" -ForegroundColor Yellow
Write-Host "  $File"
Write-Host "Everything currently in the lab will be permanently lost." -ForegroundColor Yellow
if ((Read-Host "Type RESTORE to go ahead") -ne 'RESTORE') { Write-Host "Cancelled."; exit }

wsl --terminate $distro 2>$null | Out-Null
wsl --unregister $distro
if ($LASTEXITCODE -ne 0) { throw "wsl --unregister failed with exit code $LASTEXITCODE" }

New-Item -ItemType Directory -Force -Path $target | Out-Null
wsl --import $distro $target $File
if ($LASTEXITCODE -ne 0) { throw "wsl --import failed with exit code $LASTEXITCODE" }

Write-Host "Restored. Launching a shell to confirm it comes up..." -ForegroundColor Green
wsl -d $distro -- bash -lc 'echo "user: $(whoami); mounts:"; ls /mnt'
