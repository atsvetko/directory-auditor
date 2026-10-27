#Requires -Version 5.1
<#
.SYNOPSIS
  Windows Server 2025 AD DC lab on Hyper-V (switch DA-Lab). The Hyper-V counterpart
  of tools/lab/kvm/windows-lab.sh, run on the Hyper-V host itself.

    create         Generation 2 VM from your Windows Server ISO, unattended, static IP
                   10.55.0.10 on DA-Lab; never has a route out (AD DS and AD CS install
                   from the ISO)
    provision      tools/lab/windows/provision.ps1 (new forest da.test, reboots) + populate.ps1
    populate       populate.ps1 again (idempotent)
    adcs           tools/lab/windows/provision-adcs.ps1 (Enterprise CA + weak templates)
    snapshot NAME  shut down, checkpoint NAME, start again   (baseline, adcs, ...)
    reset NAME     restore checkpoint NAME and wait for AD
    scanner        (re)build the scanner VM da-scan1 (Ubuntu 24.04, 10.55.0.30, no packages,
                   never a route out), checkpoint "clean"
    scan           from the scanner, restored to "clean": scan as the ordinary 'audit' user
                   (auto transport, then --tls none), verify, and check from the DC side
                   that nothing was written
    stop           power both VMs off (the next reset restores a checkpoint)
    destroy        remove both VMs, their checkpoints and their disks

  The scans run in a Linux VM, not on this host: no lab binary runs here, so a host
  with Smart App Control (which refuses unsigned executables) needs no exception.
  Everything inside the DC goes over PowerShell Direct (no SSH or WinRM in it); the
  scanner is reached over SSH with the lab key.
  Needs: Hyper-V Administrators (or Administrators), DIRAUDITOR_LAB=1, and once per
  host setup-host.ps1 (as administrator). Env also: DA_LAB_KEY. Env: DA_LAB_HOME (C:\DirAuditorLab),
  WIN_ISO, IMAGE_INDEX (2 = Standard, Desktop Experience), EXPECT, DA_BIN.
.EXAMPLE
  $env:DIRAUDITOR_LAB = '1'; .\windows-lab.ps1 reset baseline; .\windows-lab.ps1 scan
#>
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('create', 'provision', 'populate', 'adcs', 'snapshot', 'reset', 'scanner', 'scan', 'stop', 'destroy')]
    [string]$Command,
    [Parameter(Position = 1)][string]$Snapshot
)
. (Join-Path $PSScriptRoot 'common.ps1')

$VM         = 'da-win2025-dc1'
$IP         = '10.55.0.10'
$MAC        = '00155D550010'
$Domain     = 'da.test'
$DcName     = 'dc1.da.test'
$AdminPw    = 'Lab-Admin-Pass-2026!'    # throwaway lab values
$AuditPw    = 'Lab-Reader-Pass-2026!'   # populate.ps1 default
$Iso        = if ($env:WIN_ISO) { $env:WIN_ISO } else { Join-Path $LabRoot 'iso\Win2025.iso' }
$ImageIndex = if ($env:IMAGE_INDEX) { $env:IMAGE_INDEX } else { '2' }
$Expect     = if ($env:EXPECT) { $env:EXPECT } else { Join-Path $RepoRoot 'testdata\lab\windows-expect.yaml' }
$Disk       = Join-Path $LabRoot "vhd\$VM.vhdx"
$AnswerIso  = Join-Path $LabRoot "iso\$VM-answer.iso"
$Out        = Join-Path $OutRoot 'windows'
$Scanner    = 'da-scan1'
$ScanIP     = '10.55.0.30'
$ScanMAC    = '00155D550030'

function New-Cred([string]$User) { New-Object PSCredential($User, (ConvertTo-SecureString $AdminPw -AsPlainText -Force)) }
$LocalAdmin  = New-Cred 'Administrator'      # before promotion
$DomainAdmin = New-Cred 'DA\Administrator'   # after: same name and password, now the domain's

# Each PowerShell Direct connection is a new Administrator logon, which the DC records
# (lastLogon, logonCount: highestCommittedUSN moves). scan opens one session and keeps
# it, so its measurements do not disturb what they measure.
$script:DcSession = $null
function Invoke-Guest([scriptblock]$Script, [object[]]$ArgumentList = @(), [switch]$Local) {
    if ($script:DcSession -and -not $Local) { return Invoke-Command -Session $script:DcSession -ScriptBlock $Script -ArgumentList $ArgumentList }
    $c = if ($Local) { $LocalAdmin } else { $DomainAdmin }
    Invoke-Command -VMName $VM -Credential $c -ScriptBlock $Script -ArgumentList $ArgumentList
}

function Wait-AD {
    Wait-Until { (Invoke-Guest { (Get-ADDomain -ErrorAction Stop).DNSRoot }) -eq $Domain } 1800 "AD on $VM" 15
    Write-Host 'AD up'
}

function Copy-LabScripts([pscredential]$Cred) {
    $s = New-PSSession -VMName $VM -Credential $Cred
    try {
        Invoke-Command -Session $s { New-Item -ItemType Directory -Force C:\lab\windows | Out-Null }
        Copy-Item (Join-Path $RepoRoot 'tools\lab\windows\*.ps1') -Destination C:\lab\windows -ToSession $s -Force
    } finally { Remove-PSSession $s }
}

function Cmd-Create {
    if (Get-VM -Name $VM -ErrorAction SilentlyContinue) { throw "$VM already exists (destroy it first)" }
    if (-not (Test-Path $Iso)) { throw "missing Windows ISO $Iso (set WIN_ISO)" }
    if (-not (Get-VMSwitch -Name $LabSwitch -ErrorAction SilentlyContinue)) { throw "no $LabSwitch switch: run setup-host.ps1 first" }

    Log 'answer media'
    $a = Join-Path $env:TEMP "$VM-answer"
    Remove-Item -Recurse -Force $a -ErrorAction SilentlyContinue
    New-Item -ItemType Directory $a | Out-Null
    $macDashed = ($MAC -split '(..)' | Where-Object { $_ }) -join '-'
    $xml = (Get-Content (Join-Path $PSScriptRoot 'windows\autounattend.xml') -Raw).
        Replace('@ADMIN_PASSWORD@', $AdminPw).Replace('@IMAGE_INDEX@', $ImageIndex).
        Replace('@MAC@', $macDashed).Replace('@IP@', $IP)
    Set-Content -Path (Join-Path $a 'autounattend.xml') -Value $xml -Encoding UTF8
    New-IsoFile -SourceDir $a -Path $AnswerIso -Label 'ANSWER'
    Remove-Item -Recurse -Force $a

    # Static memory while Windows PE installs: PE has no dynamic-memory driver, and with
    # 1-2 GB Setup fails applying install.wim (0x80070057). Dynamic once Windows is up.
    Log "VM $VM (2 vCPU, 4 GB static for the install) on $LabSwitch $IP, no other network"
    New-VHD -Path $Disk -SizeBytes 60GB -Dynamic | Out-Null
    New-VM -Name $VM -Generation 2 -MemoryStartupBytes 4GB -VHDPath $Disk -SwitchName $LabSwitch -Path (Join-Path $LabRoot 'vm') | Out-Null
    Set-VM -Name $VM -ProcessorCount 2 -StaticMemory -AutomaticCheckpointsEnabled $false -CheckpointType Standard -AutomaticStartAction Nothing -AutomaticStopAction ShutDown
    Set-VMNetworkAdapter -VMName $VM -StaticMacAddress $MAC
    Add-VMDvdDrive -VMName $VM -Path $Iso
    Add-VMDvdDrive -VMName $VM -Path $AnswerIso
    Set-VMFirmware -VMName $VM -FirstBootDevice (Get-VMDvdDrive -VMName $VM | Where-Object Path -eq $Iso)
    Start-VM -Name $VM

    # UEFI asks "Press any key to boot from CD or DVD" for a few seconds; answer it.
    $id = (Get-VM -Name $VM).Id.Guid
    $kb = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_Keyboard | Where-Object SystemName -eq $id
    1..20 | ForEach-Object { Invoke-CimMethod -InputObject $kb -MethodName TypeKey -Arguments @{ keyCode = [uint32]13 } | Out-Null; Start-Sleep 1 }

    Log 'waiting for unattended install and first logon (20-40 min)'
    Wait-Until { Invoke-Guest -Local { Test-Path C:\lab-ready.txt } } 4800 'install + first logon' 30
    Log 'installed: ejecting media, switching to 2 GB dynamic memory (1-4 GB)'
    Stop-LabVM $VM | Out-Null
    Get-VMDvdDrive -VMName $VM | Set-VMDvdDrive -Path $null
    Set-VMFirmware -VMName $VM -FirstBootDevice (Get-VMHardDiskDrive -VMName $VM)
    Set-VM -Name $VM -DynamicMemory -MemoryStartupBytes 2GB -MemoryMinimumBytes 1GB -MemoryMaximumBytes 4GB
    Start-VM -Name $VM
    Wait-Until { Invoke-Guest -Local { $true } } 600 'boot after the install'
    Invoke-Guest -Local { '{0} {1} build {2}' -f (Get-CimInstance Win32_OperatingSystem).Caption, $env:COMPUTERNAME, [Environment]::OSVersion.Version }
}

function Cmd-Provision {
    Log 'copying tools/lab/windows'
    Copy-LabScripts $LocalAdmin
    Log "provision.ps1 (new forest $Domain; the DC reboots)"
    try {
        Invoke-Guest -Local -ArgumentList $Domain, $IP {
            param($d, $ip)
            $env:DIRAUDITOR_LAB = '1'
            & C:\lab\windows\provision.ps1 -DomainName $d -IPAddress $ip -ForestMode Win2025 -Confirm:$false
        }
    } catch { Write-Host "(session ended by the promotion reboot: $($_.Exception.Message.Split([char]10)[0]))" }
    Start-Sleep 60
    Wait-AD
    Cmd-Populate
}

function Cmd-Populate {
    Copy-LabScripts $DomainAdmin
    Log 'populate.ps1 (weak objects)'
    Invoke-Guest -ArgumentList $Domain {
        param($d)
        $env:DIRAUDITOR_LAB = '1'
        & C:\lab\windows\populate.ps1 -DomainName $d -Confirm:$false
    }
}

function Cmd-Adcs {
    if (-not (Test-Path (Join-Path $RepoRoot 'tools\lab\windows\provision-adcs.ps1'))) { throw 'no tools/lab/windows/provision-adcs.ps1 in this checkout' }
    Copy-LabScripts $DomainAdmin
    Log 'provision-adcs.ps1 (Enterprise CA + weak templates)'
    Invoke-Guest -ArgumentList $Domain {
        param($d)
        $env:DIRAUDITOR_LAB = '1'
        Set-Location C:\lab\windows
        & C:\lab\windows\provision-adcs.ps1 -DomainName $d -Confirm:$false
    }
}

function Cmd-Snapshot {
    if (-not $Snapshot) { throw 'usage: snapshot NAME' }
    Log "shutting down for checkpoint $Snapshot"
    Stop-VM -Name $VM -Force
    Get-VMSnapshot -VMName $VM -Name $Snapshot -ErrorAction SilentlyContinue | Remove-VMSnapshot
    Checkpoint-VM -Name $VM -SnapshotName $Snapshot
    Get-VMSnapshot -VMName $VM | Format-Table Name, CreationTime -AutoSize | Out-Host
    Start-VM -Name $VM
    Wait-AD
}

function Cmd-Reset {
    if (-not $Snapshot) { throw 'usage: reset NAME' }
    Log "restoring $VM to $Snapshot"
    Restore-VMSnapshot -VMName $VM -Name $Snapshot -Confirm:$false
    if ((Get-VM -Name $VM).State -ne 'Running') { Start-VM -Name $VM }
    Wait-AD
}

function Get-Usn { [int64](Invoke-Guest { (Get-ADRootDSE).highestCommittedUSN }) }
function Get-Logons { [int](Invoke-Guest { (Get-ADUser audit -Properties logonCount).logonCount }) }
function Get-AuditState { Invoke-Guest { $u = Get-ADUser audit -Properties badPwdCount, lockoutTime; "badPwdCount=$($u.badPwdCount) lockoutTime=$($u.lockoutTime)" } }

function Invoke-Scan([string]$Label, [string]$Dir, [string]$Extra = '') {
    Log "scan: $Label"
    Invoke-LabSsh $ScanIP @"
cd ~/scan && rm -rf $Dir && echo '$AuditPw' | ./dirauditor scan --server $IP --server-name $DcName --domain $Domain --user audit@$Domain --password-stdin --catalogue catalogue --packs '' --out $Dir --lang en $Extra 2>&1 | tail -12
"@ | Out-Host
}

function Cmd-Scanner {
    # disposable: rebuilt from scratch, never repaired
    if (Get-VM -Name $Scanner -ErrorAction SilentlyContinue) { Remove-LabVM $Scanner }
    New-UbuntuLabVM -Name $Scanner -Hostname scan1 -IP $ScanIP -Mac $ScanMAC -MaxMemory 1GB
    Close-UbuntuLabVM $Scanner $ScanIP
    Log "shutting down $Scanner for checkpoint clean"
    Stop-VM -Name $Scanner -Force
    Checkpoint-VM -Name $Scanner -SnapshotName clean
}

function Start-Scanner {
    if (-not (Get-VMSnapshot -VMName $Scanner -Name clean -ErrorAction SilentlyContinue)) { throw "no scanner VM: run 'windows-lab.ps1 scanner' once" }
    Log "restoring $Scanner to clean"
    Restore-VMSnapshot -VMName $Scanner -Name clean -Confirm:$false
    Start-VM -Name $Scanner
    Wait-LabSsh $ScanIP 300
}

function Cmd-Scan {
    $bin = Get-LabBinaries
    New-Item -ItemType Directory -Force $Out | Out-Null
    Start-Scanner
    Log 'deploy binaries, catalogue and expectations to the scanner'
    Invoke-LabSsh $ScanIP 'mkdir -p ~/scan'
    Copy-ToLab $ScanIP @((Join-Path $bin 'dirauditor'), (Join-Path $bin 'verify'), $Expect) 'scan/'
    Copy-ToLab $ScanIP @((Join-Path $RepoRoot 'catalogue')) 'scan/' -Recurse
    Invoke-LabSsh $ScanIP 'chmod +x ~/scan/dirauditor ~/scan/verify'
    $script:DcSession = New-PSSession -VMName $VM -Credential $DomainAdmin

    # The checkpoint predates the audit account's first logon: log on once (output
    # discarded), then let the freshly restored DC finish its own housekeeping.
    Invoke-Scan 'warm-up logon (not measured)' 'warm-up'
    for ($i = 0; $i -lt 10; $i++) {
        $a = Get-Usn; Start-Sleep 30; $b = Get-Usn
        if ($a -eq $b) { Write-Host "DC quiet at highestCommittedUSN $b"; break }
    }

    $usn0 = Get-Usn; $acct0 = Get-AuditState; $logon0 = Get-Logons
    Write-Host "before: highestCommittedUSN=$usn0 audit: $acct0"
    Invoke-Scan 'audit user, --tls auto' 'lab-out'
    Invoke-Scan 'audit user, --tls none (Kerberos sealing)' 'lab-seal' '--tls none'
    $usn1 = Get-Usn; $acct1 = Get-AuditState; $logon1 = Get-Logons
    Write-Host "after:  highestCommittedUSN=$usn1 audit: $acct1"

    $fail = $false
    $exp = Split-Path $Expect -Leaf
    foreach ($d in 'lab-out', 'lab-seal') {
        Remove-Item -Recurse -Force (Join-Path $Out $d) -ErrorAction SilentlyContinue
        try { Copy-FromLab $ScanIP "scan/$d" $Out } catch { }
        Log "verify $d against $exp"
        $report = Join-Path $Out "$d\report.json"
        if (-not (Test-Path $report)) { Write-Host 'FAIL: no report'; $fail = $true; continue }
        $inv = (Get-Content $report -Raw | ConvertFrom-Json).inventory
        Write-Host "transport: $($inv.transport) | identity: $($inv.identity)"
        try { Invoke-LabSsh $ScanIP "cd ~/scan && ./verify -report $d/report.json -expect $exp" | Out-Host }
        catch { Write-Host "FAIL: $($_.Exception.Message)"; $fail = $true }
    }

    Log 'read-only check (DC side)'
    # Every Kerberos logon makes the DC record audit's non-replicated lastLogon and
    # logonCount, which advances highestCommittedUSN without changing any object. So:
    # no object may change, and the USN may grow by exactly the number of logons.
    $changed = @(Invoke-Guest -ArgumentList $usn0 { param($u) @(Get-ADObject -IncludeDeletedObjects -Filter "uSNChanged -gt $u" -Properties uSNChanged, whenChanged) })
    if ($changed.Count -gt 0) {
        Write-Host "FAIL: $($changed.Count) object(s) changed during the scans:"
        $changed | Format-Table uSNChanged, whenChanged, DistinguishedName -AutoSize | Out-Host
        $fail = $true
    } elseif (($usn1 - $usn0) -eq ($logon1 - $logon0)) {
        Write-Host "ok: no object changed; highestCommittedUSN $usn0 -> $usn1 = $($logon1 - $logon0) logon(s) recorded for audit (logonCount $logon0 -> $logon1)"
    } else {
        Write-Host "FAIL: highestCommittedUSN $usn0 -> $usn1 but audit logged on $($logon1 - $logon0) time(s): an unexplained local write"
        $fail = $true
    }
    if ($acct0 -eq $acct1) { Write-Host "ok: audit account unchanged ($acct0)" }
    else { Write-Host "FAIL: audit account changed: '$acct0' -> '$acct1'"; $fail = $true }
    if (Get-ChildItem -Recurse -File (Join-Path $Out 'lab-out'), (Join-Path $Out 'lab-seal') -ErrorAction SilentlyContinue | Select-String -SimpleMatch $AuditPw -List) {
        Write-Host 'FAIL: password found in output'; $fail = $true
    } else { Write-Host 'ok: password not present in any report or run log' }

    Write-Host ''
    if ($fail) { Write-Host 'LAB FAIL'; exit 1 }
    Write-Host 'LAB PASS'
}

function Cmd-Destroy { Remove-LabVM $VM; Remove-LabVM $Scanner }

switch ($Command) {
    'create'    { Cmd-Create }
    'provision' { Cmd-Provision }
    'populate'  { Cmd-Populate }
    'adcs'      { Cmd-Adcs }
    'snapshot'  { Cmd-Snapshot }
    'reset'     { Cmd-Reset }
    'scanner'   { Cmd-Scanner }
    'scan'      { Cmd-Scan }
    'stop'      { Log "powering off $VM and $Scanner"; Stop-LabVM $Scanner | Out-Null; Stop-LabVM $VM }
    'destroy'   { Cmd-Destroy }
}
