#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  One-time: a GitHub Actions runner for the Hyper-V lab (labels self-hosted, windows,
  hyperv-lab) as the local user 'labrunner'. Run as administrator in an interactive
  console: it asks for labrunner's password (when the user is new) and never stores it.

  labrunner is a member of Hyper-V Administrators only: it can restore, start, stop and
  reach the lab VMs (PowerShell Direct), not administer the host. It gets write access
  to the lab's out folder and its own copy of the lab SSH key.

  Note: Hyper-V Administrators may control every VM on the host, not only the lab's.
.PARAMETER RunnerZip  actions-runner-win-x64-<version>.zip (checked against its SHA-256 first)
.PARAMETER Sha256     the published SHA-256 of that zip
.PARAMETER TokenFile  a file holding a registration token (valid one hour; deleted after use)
#>
param(
    [Parameter(Mandatory)][string]$RunnerZip,
    [Parameter(Mandatory)][string]$Sha256,
    [string]$TokenFile,
    [string]$Url = 'https://github.com/atsvetko/directory-auditor',
    [string]$RunnerDir = 'C:\actions-runner'
)
$ErrorActionPreference = 'Stop'
$LabRoot = if ($env:DA_LAB_HOME) { $env:DA_LAB_HOME } else { 'C:\DirAuditorLab' }
$user = 'labrunner'

if ((Get-FileHash $RunnerZip -Algorithm SHA256).Hash -ne $Sha256.ToUpper()) { throw "$RunnerZip does not match SHA-256 $Sha256" }

# 1. The account
$pw = $null
if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
    $pw = Read-Host -AsSecureString "password for the new local user $user"
    New-LocalUser -Name $user -Password $pw -PasswordNeverExpires -UserMayNotChangePassword `
        -Description 'GitHub Actions runner for the Directory Auditor Hyper-V lab' | Out-Null
}
if (-not (Get-LocalGroupMember -Group 'Hyper-V Administrators' -Member $user -ErrorAction SilentlyContinue)) {
    Add-LocalGroupMember -Group 'Hyper-V Administrators' -Member $user
}
"user ${user}: member of $((Get-LocalGroup | Where-Object { Get-LocalGroupMember $_ -Member $user -ErrorAction SilentlyContinue }).Name -join ', ')"

# 2. Lab folders: reports, and its own copy of the lab key (owner-only)
New-Item -ItemType Directory -Force (Join-Path $LabRoot 'out') | Out-Null
icacls (Join-Path $LabRoot 'out') /grant "${user}:(OI)(CI)M" | Out-Null
$rs = Join-Path $LabRoot "state-$user"
New-Item -ItemType Directory -Force $rs | Out-Null
Copy-Item (Join-Path $LabRoot 'state\id_ed25519*') $rs -Force
icacls $rs /inheritance:r /grant:r "${user}:(OI)(CI)F" /grant:r 'SYSTEM:(OI)(CI)F' /grant:r 'Administrators:(OI)(CI)F' | Out-Null
icacls (Join-Path $rs 'id_ed25519') /setowner $user | Out-Null
"lab key for ${user}: $rs\id_ed25519 (DA_LAB_KEY)"

# 3. The runner, as a service logged on as labrunner
if (-not (Test-Path (Join-Path $RunnerDir '.runner'))) {
    if (-not $TokenFile -or -not (Test-Path $TokenFile)) { throw 'not registered yet: pass -TokenFile with a fresh registration token' }
    New-Item -ItemType Directory -Force $RunnerDir | Out-Null
    Expand-Archive -Path $RunnerZip -DestinationPath $RunnerDir -Force
    icacls $RunnerDir /grant "${user}:(OI)(CI)M" | Out-Null
    if (-not $pw) { $pw = Read-Host -AsSecureString "password of the existing local user $user (for the service logon)" }
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw))
    $token = (Get-Content $TokenFile -Raw).Trim()
    Push-Location $RunnerDir
    try {
        & .\config.cmd --unattended --url $Url --token $token --name "hyperv-lab-$($env:COMPUTERNAME.ToLower())" `
            --labels hyperv-lab --work _work --replace --runasservice --windowslogonaccount ".\$user" --windowslogonpassword $plain
        if ($LASTEXITCODE) { throw "config.cmd failed with $LASTEXITCODE" }
    } finally { Pop-Location; $plain = $null }
    Remove-Item $TokenFile -Force
}
Get-Service 'actions.runner.*' | Format-Table Name, Status, StartType -AutoSize
"OK: runner (self-hosted, windows, hyperv-lab) runs as $user."
