<#
.SYNOPSIS
    Removes the Kali RE Lab Windows app.

.DESCRIPTION
    Deletes the shortcuts, the Apps & features entry, and the scripts Install.ps1
    put in place.

    It does NOT touch the WSL distro, the shared folder, or your snapshots. A
    snapshot is often the only copy of a lab's state, and deleting one because
    someone removed a launcher would be indefensible. Both are reported, with
    sizes, so you can remove them deliberately if that is what you want.

.PARAMETER KeepFiles
    Remove the shortcuts and registry entry but leave the install directory.

.PARAMETER DesktopDir
.PARAMETER StartMenuDir
    Where to look for the shortcuts. These match the same parameters on
    make-shortcuts.ps1 and exist so the uninstaller can be exercised without
    deleting the real shortcuts on someone's desktop.
#>
param(
    [switch]$KeepFiles,
    [string]$DesktopDir = [Environment]::GetFolderPath('Desktop'),
    [string]$StartMenuDir = (Join-Path ([Environment]::GetFolderPath('Programs')) 'RE Lab')
)

$ErrorActionPreference = 'Stop'
$AppName = 'Kali RE Lab'
$RegKey  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\KaliRELab'
$here    = $PSScriptRoot

function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }

Say "Uninstalling $AppName" 'Cyan'

# Shortcut names exactly as make-shortcuts.ps1 creates them.
$names = @('Kali RE Lab', 'Kali RE Lab (Fullscreen)', 'Kali RE Lab (Portrait)',
           'Ghidra (RE Lab)', 'RE Lab - Terminal', 'RE Lab - Snapshot',
           'RE Lab - Restore', 'RE Lab - Shared Folder')
$desktop   = $DesktopDir
$startMenu = $StartMenuDir

# Delete a shortcut only if it actually belongs to THIS install.
#
# Matching on name alone is not safe enough. An earlier revision of this script
# did that, and a test run against redirected folders - using a stale copy that
# predated the redirect - deleted the real shortcuts on the desktop instead.
# make-shortcuts.ps1 stamps WorkingDirectory with its own folder, so ownership
# is checkable rather than assumed, and a shortcut pointing somewhere else now
# survives no matter which copy of this script runs or how it is called.
$shell = New-Object -ComObject WScript.Shell
$hereN = $here.TrimEnd('\')

function Owns([string]$path) {
    try { $l = $shell.CreateShortcut($path) } catch { return $false }
    foreach ($v in @($l.WorkingDirectory, $l.TargetPath, $l.Arguments, $l.IconLocation)) {
        if ($v -and $v -like "*$hereN*") { return $true }
    }
    return $false
}

$removed = 0
$skipped = @()
foreach ($n in $names) {
    foreach ($d in @($desktop, $startMenu)) {
        $lnk = Join-Path $d "$n.lnk"
        if (-not (Test-Path $lnk)) { continue }
        if (Owns $lnk) { Remove-Item $lnk -Force; $removed++ }
        else { $skipped += $lnk }
    }
}
if ((Test-Path $startMenu) -and -not (Get-ChildItem $startMenu -Force)) {
    Remove-Item $startMenu -Force
}
Say "shortcuts      removed $removed" 'Green'
if ($skipped) {
    Say "               left $($skipped.Count) alone - they point somewhere else, not at" 'DarkGray'
    Say "               $here" 'DarkGray'
}

if (Test-Path $RegKey) { Remove-Item $RegKey -Recurse -Force }
Say 'registry       Apps & features entry removed' 'Green'

# Report what is deliberately left behind, with sizes, so the choice is informed.
$snapDirs = @()
$cfg = Join-Path $here 'relab.config.ps1'
if (Test-Path $cfg) {
    . $cfg
    if ($SnapshotDir) { $snapDirs += $SnapshotDir }
}
$snapDirs += (Join-Path $here 'snapshots')

foreach ($d in ($snapDirs | Select-Object -Unique)) {
    if (Test-Path $d) {
        $snaps = @(Get-ChildItem $d -Filter *.tar -ErrorAction SilentlyContinue)
        if ($snaps) {
            $gb = [math]::Round((($snaps | Measure-Object Length -Sum).Sum) / 1GB, 1)
            Say "KEPT           $($snaps.Count) snapshot(s), $gb GB, in $d" 'Yellow'
        }
    }
}
Say 'KEPT           the WSL distro. Remove it yourself:  wsl --unregister kali-linux' 'Yellow'

if ($KeepFiles) {
    Say "files          kept (-KeepFiles): $here" 'DarkGray'
} else {
    # Delete only what Install.ps1 placed here, so a snapshots/ subdirectory or
    # anything else the user put in this folder survives a plain uninstall.
    $ours = @('launch-desktop.vbs', 'make-shortcuts.ps1', 'snapshot.ps1', 'restore.ps1',
              'relab-common.ps1', 're-lab.ico', 'ghidra.ico', 'relab.config.ps1')
    foreach ($f in $ours) {
        $p = Join-Path $here $f
        if (Test-Path $p) { Remove-Item $p -Force }
    }
    Say 'files          removed' 'Green'

    $left = @(Get-ChildItem $here -Force -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -ne 'Uninstall.ps1' })
    if ($left) {
        Say "               kept $here - it still holds: $($left.Name -join ', ')" 'DarkGray'
    }
}

Say "`nDone." 'Cyan'
