# Hardens a Hyper-V VM into a malware analysis box and takes a baseline checkpoint.
#
# Run this AFTER creating the VM with Hyper-V Quick Create. Must be run elevated.
#
#   .\hyperv-setup.ps1 -VMName "Windows 11 dev environment"
#
# What it does:
#   - 8 GB static RAM, 6 vCPU
#   - REMOVES the network adapter, so the VM has no network at all
#   - turns off the guest file-copy integration service
#   - disables automatic checkpoints, sets checkpoints to Standard (memory included)
#   - takes a checkpoint named "clean-base" you can revert to after every sample
param(
    [string]$VMName = "Windows 11 dev environment",
    [int64]$MemoryBytes = 8GB,
    [int]$CpuCount = 6,
    [int64]$DiskBytes = 120GB,
    # Attach a private switch instead of removing networking. Private switches reach
    # other VMs on the same switch but never the host or the internet. Only useful
    # once you add a second VM running something like INetSim to fake the internet.
    [switch]$IsolatedNetwork
)

$ErrorActionPreference = 'Stop'

if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this in an elevated PowerShell. Hyper-V cmdlets require administrator."
}

$vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
if (-not $vm) {
    Write-Host "No VM named '$VMName'." -ForegroundColor Yellow
    Write-Host "Existing VMs:"
    Get-VM | Select-Object Name, State | Format-Table -AutoSize
    throw "Create it first with Hyper-V Quick Create, then re-run with -VMName."
}

if ($vm.State -ne 'Off') {
    Write-Host "Stopping '$VMName' so it can be reconfigured..." -ForegroundColor DarkGray
    Stop-VM -Name $VMName -Force
    while ((Get-VM -Name $VMName).State -ne 'Off') { Start-Sleep -Milliseconds 500 }
}

# --- resources -------------------------------------------------------------
Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $false -StartupBytes $MemoryBytes
Set-VMProcessor -VMName $VMName -Count $CpuCount
Write-Host "Set $([math]::Round($MemoryBytes/1GB)) GB RAM, $CpuCount vCPU" -ForegroundColor Green

# --- disk ------------------------------------------------------------------
# Growing the VHDX does not grow the partition inside Windows. After first boot,
# extend it from Disk Management in the guest, or leave it; it is only a ceiling.
$disk = Get-VMHardDiskDrive -VMName $VMName | Select-Object -First 1
if ($disk) {
    $vhd = Get-VHD -Path $disk.Path
    if ($vhd.Size -lt $DiskBytes) {
        Resize-VHD -Path $disk.Path -SizeBytes $DiskBytes
        Write-Host "Grew virtual disk to $([math]::Round($DiskBytes/1GB)) GB (extend the partition inside the guest to use it)" -ForegroundColor Green
    } else {
        Write-Host "Virtual disk already $([math]::Round($vhd.Size/1GB)) GB, left alone" -ForegroundColor DarkGray
    }
}

# --- network ---------------------------------------------------------------
# The whole point of this VM. A sample that cannot reach the network cannot phone
# home, cannot pull a second stage, and cannot attack anything else on your LAN.
if ($IsolatedNetwork) {
    $switchName = 'RE-Lab-Isolated'
    if (-not (Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue)) {
        New-VMSwitch -Name $switchName -SwitchType Private | Out-Null
        Write-Host "Created private switch '$switchName'" -ForegroundColor Green
    }
    Get-VMNetworkAdapter -VMName $VMName | Connect-VMNetworkAdapter -SwitchName $switchName
    Write-Host "Network: private switch only. No host access, no internet." -ForegroundColor Yellow
} else {
    Get-VMNetworkAdapter -VMName $VMName | Remove-VMNetworkAdapter
    Write-Host "Network: adapter REMOVED. The VM has no network at all." -ForegroundColor Green
}

# --- host/guest bridges ----------------------------------------------------
# Guest Service Interface is host-to-guest file copy. Off, so nothing crosses by
# accident. Note that Enhanced Session Mode clipboard sharing is a host-wide
# setting, not per-VM: do not copy/paste out of an infected guest.
Disable-VMIntegrationService -VMName $VMName -Name 'Guest Service Interface' -ErrorAction SilentlyContinue
Write-Host "Guest file-copy service disabled" -ForegroundColor Green

# --- checkpoints -----------------------------------------------------------
Set-VM -Name $VMName -AutomaticCheckpointsEnabled $false -CheckpointType Standard
if (-not (Get-VMSnapshot -VMName $VMName -Name 'clean-base' -ErrorAction SilentlyContinue)) {
    Checkpoint-VM -Name $VMName -SnapshotName 'clean-base'
    Write-Host "Baseline checkpoint 'clean-base' taken" -ForegroundColor Green
} else {
    Write-Host "Checkpoint 'clean-base' already exists, left alone" -ForegroundColor DarkGray
}

Write-Host "`nDone. '$VMName' is configured as an isolated analysis box." -ForegroundColor Green
Write-Host "Revert after every sample with:  .\vm-revert.ps1"
