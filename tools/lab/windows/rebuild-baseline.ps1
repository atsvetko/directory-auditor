#Requires -Version 5.1
<#
.SYNOPSIS
  Re-create the vulnerable-baseline checkpoint of a lab DC VM from scratch.
  Runs on the Hyper-V host. Use after the fixtures change or the evaluation
  licence is close to expiry.

.DESCRIPTION
  Drives provision.ps1 + populate.ps1 inside the VM over PowerShell Direct, then
  takes a fresh "vuln-baseline" checkpoint. Needs local-admin credentials for
  the VM (prompted, or passed as -VMCredential). No secret is stored here.

  This does not install Windows — start from a VM that already has a supported
  Windows Server evaluation installed and (for a first build) not yet promoted.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$VMName,
    [Parameter(Mandatory)][string]$DomainName,     # e.g. da.test
    [Parameter(Mandatory)][string]$DCAddress,      # static IP given to the DC
    [ValidateSet('Win2016','Win2025','Default')][string]$ForestMode = 'Win2016',
    [pscredential]$VMCredential = (Get-Credential -Message 'Local admin of the lab VM (pre-promotion) / DA\Administrator (post)'),
    [string]$Checkpoint = 'vuln-baseline'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module Hyper-V

if ($env:DIRAUDITOR_LAB -ne '1') { throw 'refusing: set DIRAUDITOR_LAB=1' }
$scriptDir = $PSScriptRoot
$prov = Get-Content (Join-Path $scriptDir 'provision.ps1') -Raw
$pop  = Get-Content (Join-Path $scriptDir 'populate.ps1')  -Raw

function Invoke-InVM {
    param([string]$Script, [object[]]$ArgList)
    Invoke-Command -VMName $VMName -Credential $VMCredential -ScriptBlock {
        param($code, $argList)
        $env:DIRAUDITOR_LAB = '1'
        $sb = [scriptblock]::Create($code)
        & $sb @argList
    } -ArgumentList $Script, $ArgList
}

if ($PSCmdlet.ShouldProcess($VMName, 'provision (promote to DC, reboots)')) {
    Start-VM -Name $VMName -ErrorAction SilentlyContinue | Out-Null
    Invoke-InVM -Script $prov -ArgList @('-DomainName', $DomainName, '-IPAddress', $DCAddress, '-ForestMode', $ForestMode)
    Write-Host 'waiting for the DC to reboot and come back...'
    Start-Sleep -Seconds 60
}

if ($PSCmdlet.ShouldProcess($VMName, 'populate fixtures')) {
    # Wait for LDAP, then seed.
    $deadline = (Get-Date).AddSeconds(600)
    while ((Get-Date) -lt $deadline) {
        if ((Test-NetConnection -ComputerName $DCAddress -Port 389 -WarningAction SilentlyContinue).TcpTestSucceeded) { break }
        Start-Sleep -Seconds 10
    }
    Invoke-InVM -Script $pop -ArgList @('-DomainName', $DomainName)
}

if ($PSCmdlet.ShouldProcess($VMName, "checkpoint $Checkpoint")) {
    Get-VMSnapshot -VMName $VMName -Name $Checkpoint -ErrorAction SilentlyContinue | Remove-VMSnapshot -Confirm:$false
    Checkpoint-VM -Name $VMName -SnapshotName $Checkpoint
    Write-Host "baseline checkpoint '$Checkpoint' created for $VMName"
}
