#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  One-time preparation of a Hyper-V host for windows-lab.ps1 and samba-lab.ps1.
  Idempotent; run as administrator.

  - DA-Lab: an internal switch, host 10.55.0.1/24, no NAT and no IP forwarding on the
    host side, so lab VMs reach this host and each other but nothing beyond.
  - The lab SSH key for the Samba and scanner VMs, readable by its owner only (OpenSSH for Windows
    refuses a private key others can read).
#>
$ErrorActionPreference = 'Stop'
if ($env:DIRAUDITOR_LAB -ne '1') { throw 'refusing: set DIRAUDITOR_LAB=1' }
$LabRoot = if ($env:DA_LAB_HOME) { $env:DA_LAB_HOME } else { 'C:\DirAuditorLab' }
foreach ($d in 'iso', 'vhd', 'state', 'out', 'vm') { New-Item -ItemType Directory -Force (Join-Path $LabRoot $d) | Out-Null }

# 1. DA-Lab switch
$sw = Get-VMSwitch -Name 'DA-Lab' -ErrorAction SilentlyContinue
if (-not $sw) { $sw = New-VMSwitch -Name 'DA-Lab' -SwitchType Internal }
if ($sw.SwitchType -ne 'Internal') { throw "DA-Lab is a $($sw.SwitchType) switch; it must be Internal" }
$if = 'vEthernet (DA-Lab)'
if (-not (Get-NetIPAddress -InterfaceAlias $if -IPAddress 10.55.0.1 -ErrorAction SilentlyContinue)) {
    New-NetIPAddress -InterfaceAlias $if -IPAddress 10.55.0.1 -PrefixLength 24 | Out-Null
}
Set-NetIPInterface -InterfaceAlias $if -Forwarding Disabled
$nat = Get-NetNat -ErrorAction SilentlyContinue | Where-Object { $_.InternalIPInterfaceAddressPrefix -like '10.55.0.*' }
if ($nat) { throw "a NAT ($($nat.Name)) covers 10.55.0.0/24: the lab would have a route out" }
"DA-Lab: internal, host 10.55.0.1/24, forwarding $((Get-NetIPInterface -InterfaceAlias $if -AddressFamily IPv4).Forwarding), no NAT"

# 2. Lab SSH key (the Ubuntu VMs' cloud-init installs the public half)
$key = Join-Path $LabRoot 'state\id_ed25519'
if (-not (Test-Path $key)) { & ssh-keygen.exe -q -t ed25519 -N '""' -C 'da-lab' -f $key }
icacls $key /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
"lab key: $key (owner $env:USERNAME only)"
