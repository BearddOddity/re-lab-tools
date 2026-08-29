# Creates the RE lab shortcuts on the Desktop and in the Start menu.
# Re-runnable: it overwrites its own shortcuts and touches nothing else.
# -DesktopDir / -StartMenuDir exist so the installer can be exercised without
# overwriting the real shortcuts on someone's desktop.
param(
    [string]$DesktopDir = [Environment]::GetFolderPath('Desktop'),
    [string]$StartMenuDir = (Join-Path ([Environment]::GetFolderPath('Programs')) 'RE Lab')
)
$ErrorActionPreference = 'Stop'

$desktop = $DesktopDir
$startMenu = $StartMenuDir
New-Item -ItemType Directory -Force -Path $desktop | Out-Null
New-Item -ItemType Directory -Force -Path $startMenu | Out-Null

$sys = "$env:SystemRoot\System32"
$shell = New-Object -ComObject WScript.Shell

$shortcuts = @(
    # Icons live here rather than in %TEMP%\WSLDVCPlugin, where WSLg puts the
    # ones it generates - Windows cleans that up and the shortcut goes blank.
    @{ Name = 'Kali RE Lab';       Target = "$sys\wscript.exe"; Args = "`"$PSScriptRoot\launch-desktop.vbs`""; Icon = "$PSScriptRoot\re-lab.ico"; Desc = 'Kali desktop (XFCE) in a window' }
    @{ Name = 'Kali RE Lab (Fullscreen)'; Target = "$sys\wscript.exe"; Args = "`"$PSScriptRoot\launch-desktop.vbs`" fullscreen"; Icon = "$PSScriptRoot\re-lab.ico"; Desc = 'Kali desktop filling the monitor' }
    @{ Name = 'Kali RE Lab (Portrait)';   Target = "$sys\wscript.exe"; Args = "`"$PSScriptRoot\launch-desktop.vbs`" portrait";   Icon = "$PSScriptRoot\re-lab.ico"; Desc = 'Kali desktop at 1080x1920 for a rotated monitor' }
    @{ Name = 'Ghidra (RE Lab)';   Target = 'C:\Program Files\WSL\wslg.exe'; Args = '-d kali-linux --cd "~" -- /opt/ghidra_12.1.3_PUBLIC/ghidraRun'; Icon = "$PSScriptRoot\ghidra.ico"; Desc = 'Ghidra 12.1.3 with the GhidraMCP extension' }
    @{ Name = 'RE Lab - Terminal'; Target = 'wt.exe';            Args = 'wsl.exe -d kali-linux';                     Icon = "$sys\wsl.exe,0";        Desc = 'Kali shell in Windows Terminal' }
    @{ Name = 'RE Lab - Snapshot'; Target = "$sys\WindowsPowerShell\v1.0\powershell.exe"; Args = "-NoExit -ExecutionPolicy Bypass -File `"$PSScriptRoot\snapshot.ps1`""; Icon = "$sys\imageres.dll,76"; Desc = 'Save a rollback point for the lab' }
    @{ Name = 'RE Lab - Restore';  Target = "$sys\WindowsPowerShell\v1.0\powershell.exe"; Args = "-NoExit -ExecutionPolicy Bypass -File `"$PSScriptRoot\restore.ps1`"";  Icon = "$sys\imageres.dll,79"; Desc = 'Roll the lab back to a snapshot (destroys current lab)' }
    @{ Name = 'RE Lab - Shared Folder'; Target = "$sys\..\explorer.exe"; Args = 'D:\re-lab-share'; Icon = "$sys\imageres.dll,3"; Desc = 'The one folder shared between Windows and the lab' }
)

foreach ($s in $shortcuts) {
    foreach ($dir in @($desktop, $startMenu)) {
        $lnk = $shell.CreateShortcut((Join-Path $dir "$($s.Name).lnk"))
        $lnk.TargetPath = $s.Target
        $lnk.Arguments = $s.Args
        $lnk.Description = $s.Desc
        $lnk.IconLocation = $s.Icon
        $lnk.WorkingDirectory = $PSScriptRoot
        $lnk.Save()
    }
    Write-Host "created: $($s.Name)"
}

Write-Host "`nDesktop  : $desktop" -ForegroundColor Green
Write-Host "Start menu: $startMenu" -ForegroundColor Green
