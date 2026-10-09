#Requires -Version 5.1
<#
.SYNOPSIS
  Restore a lab DC VM to its vulnerable-baseline checkpoint and wait until LDAP
  answers. Runs on the Hyper-V host (the self-hosted runner), before each scan.

.DESCRIPTION
  This is the reset step that makes the lab deterministic and low-maintenance:
  every run starts from an identical, known-weak DC, and no state accumulates.
  Read-only toward the directory; it only manages the VM.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$VMName,
    [string]$Checkpoint = 'vuln-baseline',
    [Parameter(Mandatory)][string]$DCAddress,   # IP or FQDN of the DC in the VM
    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module Hyper-V

$snap = Get-VMSnapshot -VMName $VMName -Name $Checkpoint -ErrorAction Stop
Write-Host "restoring $VMName to checkpoint '$Checkpoint'"
Restore-VMSnapshot -VMSnapshot $snap -Confirm:$false
Start-VM -Name $VMName -ErrorAction SilentlyContinue | Out-Null

Write-Host "waiting for LDAP on $DCAddress:389 (up to $TimeoutSeconds s)"
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while ((Get-Date) -lt $deadline) {
    try {
        $t = Test-NetConnection -ComputerName $DCAddress -Port 389 -WarningAction SilentlyContinue
        if ($t.TcpTestSucceeded) {
            # Give AD DS a few seconds after the port opens to finish starting.
            Start-Sleep -Seconds 10
            Write-Host "DC $DCAddress is answering LDAP"
            exit 0
        }
    } catch { }
    Start-Sleep -Seconds 5
}
Write-Error "DC $DCAddress did not answer LDAP within $TimeoutSeconds s"
exit 1
