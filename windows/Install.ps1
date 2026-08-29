<#
.SYNOPSIS
    Installs the Kali RE Lab as a Windows app: shortcuts, icons, launcher, and an
    entry in Apps & features.

.DESCRIPTION
    Copies the launcher and management scripts to an install directory, creates
    Desktop and Start-menu shortcuts, and registers a per-user uninstall entry so
    the lab appears alongside ordinary applications.

    This installs the WINDOWS side only. The lab itself is a WSL distro named
    kali-linux; if it is not registered yet the installer says so and points at
    provision/rebuild-lab.sh, rather than silently producing shortcuts that open
    nothing.

    Nothing here needs administrator rights: everything is per-user.

.PARAMETER InstallDir
    Where to put the app. Defaults to %LOCALAPPDATA%\Programs\RE Lab.

.PARAMETER SnapshotDir
    Where snapshots go. Defaults to <InstallDir>\snapshots. A snapshot of this
    lab is about 16 GB, so point this at a roomy drive if the install directory
    is on a small one.

.PARAMETER NoShortcuts
    Skip shortcut creation.

.PARAMETER LinkDistro
    Move the WSL distro's disk into <InstallDir>\distro, so the app directory
    holds the machine itself rather than just a launcher pointing at one
    registered elsewhere. Back up that folder and you have backed up the lab;
    move it to another drive and the lab moves with it.

    This is a real move of the virtual disk - around 16 GB for a provisioned
    lab. Moving between drives copies every byte and takes a while; within one
    drive it is quick. The lab is shut down for the duration. Skipped
    automatically if the disk already sits under the install directory.

.EXAMPLE
    .\Install.ps1

.EXAMPLE
    .\Install.ps1 -InstallDir 'D:\re-lab' -SnapshotDir 'D:\re-lab\snapshots'
#>
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\RE Lab'),
    [string]$SnapshotDir = '',
    [switch]$NoShortcuts,
    [switch]$LinkDistro
)

$ErrorActionPreference = 'Stop'
$AppName = 'Kali RE Lab'
$RegKey  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\KaliRELab'
$Distro  = 'kali-linux'
# Single source of truth, shipped alongside the scripts. Hardcoding it here as
# well guarantees the two drift: this printed 1.1.0 from a 1.2.0 package the
# first time the release was assembled.
$Version = 'unknown'
foreach ($vf in @((Join-Path $PSScriptRoot 'VERSION'),
                  (Join-Path $PSScriptRoot '..\VERSION'))) {
    if (Test-Path $vf) { $Version = (Get-Content $vf -First 1).Trim(); break }
}

function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }

Say "$AppName $Version" 'Cyan'
Say ('-' * 40)

# --- prerequisites -----------------------------------------------------------
# Collect every problem rather than stopping at the first, so one run tells the
# user everything they need to fix.
$problems = @()

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    $problems += 'WSL is not installed. Run:  wsl --install'
} else {
    # wsl.exe writes UTF-16 to a redirected pipe. Read it as anything else and
    # every distro name arrives NUL-separated, so the membership test below
    # fails for a distro that is plainly there.
    $prev = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [Text.Encoding]::Unicode
        $distros = (wsl.exe --list --quiet) -split "`r?`n" |
                   ForEach-Object { $_.Trim() } | Where-Object { $_ }
    } finally { [Console]::OutputEncoding = $prev }

    if ($distros -notcontains $Distro) {
        $problems += "The '$Distro' distro is not registered. Install it with:"
        $problems += '    wsl --install kali-linux --no-launch'
        $problems += 'then provision it with provision/rebuild-lab.sh from this repo.'
        $problems += "Found instead: $($distros -join ', ')"
    }
}

if ($problems) {
    Say "`nCannot install yet:" 'Yellow'
    $problems | ForEach-Object { Say "  $_" 'Yellow' }
    Say "`nThis installs the Windows side only - the lab has to exist first." 'DarkGray'
    exit 1
}
Say "prerequisites  ok ($Distro registered)" 'Green'

# --- copy payload ------------------------------------------------------------
$payload = @('launch-desktop.vbs', 'make-shortcuts.ps1', 'snapshot.ps1', 'restore.ps1',
             'relab-common.ps1', 'Uninstall.ps1', 're-lab.ico', 'ghidra.ico')
# VERSION is copied too, so the installed copy can report itself accurately.
$optional = @('VERSION')

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
foreach ($f in $payload) {
    $src = Join-Path $PSScriptRoot $f
    if (-not (Test-Path $src)) { throw "Missing from this package: $f" }
    Copy-Item $src (Join-Path $InstallDir $f) -Force
}
foreach ($f in $optional) {
    $src = Join-Path $PSScriptRoot $f
    if (Test-Path $src) { Copy-Item $src (Join-Path $InstallDir $f) -Force }
}
Say "installed      $InstallDir" 'Green'

# --- snapshot location -------------------------------------------------------
$cfgPath = Join-Path $InstallDir 'relab.config.ps1'
if ($SnapshotDir) {
    New-Item -ItemType Directory -Force -Path $SnapshotDir | Out-Null
    "`$SnapshotDir = '$SnapshotDir'" | Set-Content $cfgPath -Encoding UTF8
    Say "snapshots      $SnapshotDir" 'Green'
} else {
    Remove-Item $cfgPath -ErrorAction SilentlyContinue
    $drive = (Get-Item $InstallDir).PSDrive.Name
    $free = [math]::Round((Get-PSDrive $drive).Free / 1GB, 1)
    Say "snapshots      $InstallDir\snapshots  ($free GB free on ${drive}:)" 'Green'
    if ($free -lt 40) {
        Say '               a snapshot is ~16 GB; consider -SnapshotDir on a larger drive' 'Yellow'
    }
}

# --- link the distro to this install -----------------------------------------
# Where WSL keeps a distro's virtual disk, from the registry rather than by
# guessing at a path layout that has changed between WSL versions.
function Get-DistroBasePath([string]$name) {
    Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' -ErrorAction SilentlyContinue |
        ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            if ($p.DistributionName -eq $name) { $p.BasePath }
        } | Select-Object -First 1
}

$distroTarget = Join-Path $InstallDir 'distro'
$basePath = Get-DistroBasePath $Distro
$normalised = if ($basePath) { $basePath -replace '^\\\\\?\\', '' } else { '' }

if ($LinkDistro) {
    if ($normalised -and $normalised.TrimEnd('\') -ieq $distroTarget.TrimEnd('\')) {
        Say "distro         already linked ($distroTarget)" 'Green'
    } else {
        $sizeGB = 0
        if ($normalised -and (Test-Path $normalised)) {
            $sizeGB = [math]::Round((Get-ChildItem $normalised -File -Recurse -ErrorAction SilentlyContinue |
                                     Measure-Object Length -Sum).Sum / 1GB, 1)
        }
        $sameDrive = $normalised -and
                     ((Split-Path $normalised -Qualifier) -ieq (Split-Path $distroTarget -Qualifier))
        Say "distro         moving $Distro ($sizeGB GB) into $distroTarget" 'Cyan'
        if (-not $sameDrive) {
            Say '               across drives, so every byte is copied - this takes a while' 'Yellow'
        }
        wsl.exe --terminate $Distro 2>$null | Out-Null
        New-Item -ItemType Directory -Force -Path $distroTarget | Out-Null
        wsl.exe --manage $Distro --move $distroTarget
        if ($LASTEXITCODE -ne 0) {
            # Leave the lab where it is rather than half-moved; the distro is
            # still registered and working at its old path.
            Say "               move FAILED (exit $LASTEXITCODE); distro left at $normalised" 'Red'
        } else {
            Say "distro         now lives in the app folder" 'Green'
        }
    }
} elseif ($normalised) {
    Say "distro         $normalised" 'DarkGray'
    Say '               (-LinkDistro moves it inside the app folder so the app owns it)' 'DarkGray'
}

# --- shortcuts ---------------------------------------------------------------
if ($NoShortcuts) {
    Say 'shortcuts      skipped (-NoShortcuts)' 'DarkGray'
} else {
    & (Join-Path $InstallDir 'make-shortcuts.ps1') | Out-Null
    Say "shortcuts      Desktop and Start menu -> 'RE Lab'" 'Green'
}

# --- Apps & features entry ---------------------------------------------------
# Per-user (HKCU), so no elevation is needed and nothing machine-wide is touched.
New-Item -Path $RegKey -Force | Out-Null
$props = [ordered]@{
    DisplayName     = $AppName
    DisplayVersion  = $Version
    Publisher       = 're-lab-tools'
    DisplayIcon     = (Join-Path $InstallDir 're-lab.ico')
    InstallLocation = $InstallDir
    UninstallString = "powershell -ExecutionPolicy Bypass -File `"$(Join-Path $InstallDir 'Uninstall.ps1')`""
    NoModify        = 1
    NoRepair        = 1
    EstimatedSize   = [int]((Get-ChildItem $InstallDir -File | Measure-Object Length -Sum).Sum / 1KB)
}
foreach ($k in $props.Keys) {
    $type = if ($props[$k] -is [int]) { 'DWord' } else { 'String' }
    New-ItemProperty -Path $RegKey -Name $k -Value $props[$k] -PropertyType $type -Force | Out-Null
}
Say "registered     Apps & features -> '$AppName'" 'Green'

Say "`nDone." 'Cyan'
Say "Launch from the Start menu, or:  wsl -d $Distro -- re-desktop fullscreen"
Say 'Uninstall from Apps & features, or run Uninstall.ps1 in the install folder.' 'DarkGray'
