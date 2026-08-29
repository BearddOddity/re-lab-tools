# Where the lab's bulk data lives. Dot-sourced by snapshot.ps1 and restore.ps1.
#
# Both default to sitting beside these scripts, which is right for a portable
# copy. Install.ps1 writes relab.config.ps1 overriding them when the app is
# installed somewhere small: the default install location is under %LOCALAPPDATA%
# on C:, and a snapshot of this lab is 16 GB.
$SnapshotDir = Join-Path $PSScriptRoot 'snapshots'
$DistroDir   = Join-Path $PSScriptRoot 'distro'

$cfg = Join-Path $PSScriptRoot 'relab.config.ps1'
if (Test-Path $cfg) { . $cfg }
