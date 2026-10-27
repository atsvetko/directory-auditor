#Requires -Version 5.1
<#
.SYNOPSIS
  Samba AD DC lab on Hyper-V (switch DA-Lab). The Hyper-V counterpart of
  tools/lab/kvm/samba-lab.sh, run on the Hyper-V host itself.

    create     Generation 2 VM from the Ubuntu 24.04 cloud image (VHDX), cloud-init;
               packages through a temporary NIC on the Default Switch (NAT), which is
               removed before anything is weakened
    provision  tools/lab/samba/provision.sh + populate.sh inside the VM
    snapshot   shut down, checkpoint "baseline", start again
    reset      restore "baseline" and start Samba
    scan       scan inside the VM as the 'audit' user (pinned LDAPS via --tls auto, then
               --tls none), both with --local, verify inside the VM, and check from the
               DC side that nothing was written
    stop       power the VM off (the next reset restores the checkpoint)
    destroy    remove the VM, its checkpoint and its disk (keeps the base image)

  The host reaches the VM over SSH on DA-Lab (10.55.0.20) with the lab key from
  setup-host.ps1 and runs no lab binary itself. Env: DA_LAB_HOME (C:\DirAuditorLab), DA_LAB_KEY, DA_BIN. Needs DIRAUDITOR_LAB=1.
.EXAMPLE
  $env:DIRAUDITOR_LAB = '1'; .\samba-lab.ps1 reset; .\samba-lab.ps1 scan
#>
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('create', 'provision', 'snapshot', 'reset', 'scan', 'stop', 'destroy')]
    [string]$Command
)
. (Join-Path $PSScriptRoot 'common.ps1')

$VM       = 'da-samba-dc1'
$IP       = '10.55.0.20'
$MAC      = '00155D550020'
$MacNat   = '00155D550120'
$UserPw   = 'Lab-User-Pass-2026!'      # populate.sh default; throwaway lab value
$Out      = Join-Path $OutRoot 'samba'

function Invoke-Vm([string]$Script) { Invoke-LabSsh $IP $Script }
function Copy-ToVm([string[]]$Paths, [string]$Dest, [switch]$Recurse) { Copy-ToLab $IP $Paths $Dest -Recurse:$Recurse }
function Start-Samba {
    # provision.sh is idempotent: on an existing domain it only starts samba
    Invoke-Vm 'sudo DIRAUDITOR_LAB=1 bash ~/lab/provision.sh' | Where-Object { $_ -match '^lab:' }
}

function Cmd-Create {
    New-UbuntuLabVM -Name $VM -Hostname dc1 -IP $IP -Mac $MAC -MaxMemory 2GB -NatMac $MacNat `
        -Packages samba, samba-dsdb-modules, samba-vfs-modules, winbind, krb5-user, ldb-tools, ldap-utils
    Invoke-Vm 'samba -V'
    Close-UbuntuLabVM $VM $IP
}

function Cmd-Provision {
    if ((Get-VMNetworkAdapter -VMName $VM).SwitchName -contains $NatSwitch) { throw "$NatSwitch NIC still attached; refusing to weaken a VM with internet access" }
    Log 'copying lab scripts'
    Invoke-Vm 'rm -rf ~/lab && mkdir -p ~/lab'
    Copy-ToVm @((Join-Path $RepoRoot 'tools\lab\samba\provision.sh'), (Join-Path $RepoRoot 'tools\lab\samba\populate.sh')) 'lab/'
    # a Windows checkout may have CRLF line endings (core.autocrlf); bash refuses them
    Invoke-Vm "sed -i 's/\r`$//' ~/lab/*.sh"
    Log 'provision (weak Samba AD DC)'
    Invoke-Vm 'sudo DIRAUDITOR_LAB=1 bash ~/lab/provision.sh' | Select-Object -Last 8
    Log 'populate (weak objects)'
    Invoke-Vm 'sudo DIRAUDITOR_LAB=1 bash ~/lab/populate.sh' | Select-Object -Last 8
}

function Cmd-Snapshot {
    Log 'shutting down for checkpoint baseline'
    Stop-VM -Name $VM -Force
    Get-VMSnapshot -VMName $VM -Name baseline -ErrorAction SilentlyContinue | Remove-VMSnapshot
    Checkpoint-VM -Name $VM -SnapshotName baseline
    Start-VM -Name $VM
    Wait-LabSsh $IP
    Start-Samba
}

function Cmd-Reset {
    Log "restoring $VM to baseline"
    Restore-VMSnapshot -VMName $VM -Name baseline -Confirm:$false
    if ((Get-VM -Name $VM).State -ne 'Running') { Start-VM -Name $VM }
    Wait-LabSsh $IP
    Start-Samba
}

function Get-Usn { (Invoke-Vm "sudo ldbsearch -H /var/lib/samba/private/sam.ldb -s base -b '' highestCommittedUSN" | Where-Object { $_ -match '^highestCommittedUSN' }) -replace '^\S+:\s*', '' }
function Get-AuditState { ((Invoke-Vm "sudo ldbsearch -H /var/lib/samba/private/sam.ldb -b DC=lab,DC=example '(sAMAccountName=audit)' badPwdCount lockoutTime" | Where-Object { $_ -match '^(badPwdCount|lockoutTime)' }) | Sort-Object) -join ' ' }

function Cmd-Scan {
    $bin = Get-LabBinaries
    New-Item -ItemType Directory -Force $Out | Out-Null

    Log 'deploy binary + catalogue'
    Invoke-Vm 'rm -rf ~/scan && mkdir -p ~/scan'
    Copy-ToVm @((Join-Path $bin 'dirauditor'), (Join-Path $bin 'verify'), (Join-Path $RepoRoot 'testdata\lab\samba-expect.yaml')) 'scan/'
    Copy-ToVm @((Join-Path $RepoRoot 'catalogue')) 'scan/' -Recurse
    Invoke-Vm 'chmod +x ~/scan/dirauditor ~/scan/verify'

    # A Kerberos logon by audit can itself update the account on first use: log on
    # once (own krb5.conf: the VM's resolver does not know the lab realm) before measuring.
    Invoke-Vm @"
printf '[libdefaults]\n default_realm = LAB.EXAMPLE\n[realms]\n LAB.EXAMPLE = {\n  kdc = 127.0.0.1\n }\n' > ~/scan/krb5.conf
echo '$UserPw' | KRB5_CONFIG=~/scan/krb5.conf kinit audit@LAB.EXAMPLE >/dev/null && kdestroy
"@
    $usn0 = Get-Usn; $acct0 = Get-AuditState
    Write-Host "before: highestCommittedUSN=$usn0 audit: $acct0"

    Log 'scan 1: audit user, pinned LDAPS, local smb.conf'
    Invoke-Vm @"
cd ~/scan && PIN=`$(sudo openssl x509 -in /var/lib/samba/private/tls/cert.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')
echo '$UserPw' | sudo -E ./dirauditor scan --server dc1.lab.example --domain lab.example --user audit@lab.example --password-stdin --pin "`$PIN" --local --catalogue catalogue --packs '' --out lab-out --lang en 2>&1 | tail -12
"@
    Log 'scan 2: audit user, plain LDAP with Kerberos SASL sealing'
    Invoke-Vm @"
cd ~/scan && echo '$UserPw' | sudo -E ./dirauditor scan --server dc1.lab.example --domain lab.example --user audit@lab.example --password-stdin --tls none --local --catalogue catalogue --packs '' --out lab-seal --lang en 2>&1 | tail -5
"@
    $usn1 = Get-Usn; $acct1 = Get-AuditState
    Write-Host "after:  highestCommittedUSN=$usn1 audit: $acct1"

    Log 'fetch reports'
    Invoke-Vm 'sudo chown -R lab ~/scan/lab-out ~/scan/lab-seal'
    foreach ($d in 'lab-out', 'lab-seal') {
        Remove-Item -Recurse -Force (Join-Path $Out $d) -ErrorAction SilentlyContinue
        Copy-FromLab $IP "scan/$d" $Out
    }

    $fail = $false
    foreach ($d in 'lab-out', 'lab-seal') {
        Log "verify $d against samba-expect.yaml"
        try { Invoke-Vm "cd ~/scan && ./verify -report $d/report.json -expect samba-expect.yaml" | Out-Host }
        catch { Write-Host "FAIL: $($_.Exception.Message)"; $fail = $true }
    }
    $t = (Get-Content (Join-Path $Out 'lab-seal\report.json') -Raw | ConvertFrom-Json).inventory.transport
    Write-Host "sealed transport: $t"
    if ($t -ne 'LDAP, Kerberos-sealed (no TLS)') { Write-Host 'FAIL: transport'; $fail = $true }

    Log 'read-only check (DC side)'
    if ($usn0 -eq $usn1) { Write-Host "ok: highestCommittedUSN unchanged ($usn0)" }
    else {
        Write-Host "FAIL: highestCommittedUSN $usn0 -> $usn1; objects changed during the scan:"
        Invoke-Vm "sudo ldbsearch -H /var/lib/samba/private/sam.ldb -b DC=lab,DC=example '(uSNChanged>=$([int64]$usn0 + 1))' dn uSNChanged" | Where-Object { $_ -match '^(dn|uSNChanged):' } | Out-Host
        $fail = $true
    }
    if ($acct0 -eq $acct1) { Write-Host "ok: audit account badPwdCount/lockoutTime unchanged ($acct0)" }
    else { Write-Host "FAIL: audit account changed: '$acct0' -> '$acct1'"; $fail = $true }
    if (Get-ChildItem -Recurse -File (Join-Path $Out 'lab-out'), (Join-Path $Out 'lab-seal') | Select-String -SimpleMatch $UserPw -List) {
        Write-Host 'FAIL: password found in output'; $fail = $true
    } else { Write-Host 'ok: password not present in any report or run log' }

    Write-Host ''
    if ($fail) { Write-Host 'LAB FAIL'; exit 1 }
    Write-Host 'LAB PASS'
}

function Cmd-Destroy { Remove-LabVM $VM }

switch ($Command) {
    'create'    { Cmd-Create }
    'provision' { Cmd-Provision }
    'snapshot'  { Cmd-Snapshot }
    'reset'     { Cmd-Reset }
    'scan'      { Cmd-Scan }
    'stop'      { Log "powering off $VM"; Stop-LabVM $VM }
    'destroy'   { Cmd-Destroy }
}
