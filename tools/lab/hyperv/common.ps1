# Shared helpers for the Hyper-V lab scripts (dot-sourced by windows-lab.ps1 and
# samba-lab.ps1). Keep this file ASCII: Windows PowerShell 5.1 reads a BOM-less
# script as Windows-1252.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:DIRAUDITOR_LAB -ne '1') {
    throw 'refusing: set DIRAUDITOR_LAB=1 (this builds and scans a deliberately weak directory)'
}

$LabRoot   = if ($env:DA_LAB_HOME) { $env:DA_LAB_HOME } else { 'C:\DirAuditorLab' }
$LabSwitch = 'DA-Lab'            # internal switch, host 10.55.0.1, no NAT: no route out
$NatSwitch = 'Default Switch'    # Hyper-V's NAT switch, attached only while installing packages
$RepoRoot  = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$OutRoot   = Join-Path $LabRoot 'out'
foreach ($d in 'iso', 'vhd', 'state', 'out') { New-Item -ItemType Directory -Force (Join-Path $LabRoot $d) | Out-Null }

function Log([string]$m) { Write-Host "`n== $m" }

function Wait-Until([scriptblock]$Test, [int]$Seconds, [string]$What, [int]$Every = 10) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try { if (& $Test) { return } } catch { }
        Start-Sleep $Every
    }
    throw "timed out after $Seconds s waiting for $What"
}

# An ISO 9660 + Joliet image from a folder (answer and cloud-init seed media),
# through Windows' own IMAPI2: no oscdimg or ADK needed.
function New-IsoFile([string]$SourceDir, [string]$Path, [string]$Label) {
    if (-not ('LabIsoWriter' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class LabIsoWriter {
    public static void Write(object stream, string path) {
        IStream s = (IStream)stream;
        byte[] buf = new byte[65536];
        IntPtr read = Marshal.AllocHGlobal(4);
        try {
            using (FileStream f = File.Create(path)) {
                while (true) {
                    s.Read(buf, buf.Length, read);
                    int n = Marshal.ReadInt32(read);
                    if (n <= 0) break;
                    f.Write(buf, 0, n);
                }
            }
        } finally { Marshal.FreeHGlobal(read); }
    }
}
'@
    }
    $fs = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    $fs.FileSystemsToCreate = 3        # ISO 9660 + Joliet
    $fs.VolumeName = $Label
    $fs.Root.AddTree($SourceDir, $false)
    if (Test-Path $Path) { Remove-Item $Path -Force }
    [LabIsoWriter]::Write($fs.CreateResultImage().ImageStream, $Path)
}

# dirauditor and tools/lab/verify for Linux, built from this checkout when Go is on
# PATH, else taken from $env:DA_BIN (prebuilt). Both run inside a lab VM, never on this
# host: a host with Smart App Control (or another code-integrity policy) refuses
# unsigned executables, and the lab must not depend on weakening that.
function Get-LabBinaries {
    $bin = Join-Path $OutRoot 'bin'
    New-Item -ItemType Directory -Force $bin | Out-Null
    if (Get-Command go -ErrorAction SilentlyContinue) {
        $branch = (& git -C $RepoRoot rev-parse --abbrev-ref HEAD 2>$null); $commit = (& git -C $RepoRoot rev-parse --short HEAD 2>$null)
        Log "build dirauditor + verify (linux/amd64) from $branch@$commit"
        Push-Location $RepoRoot
        try {
            $env:CGO_ENABLED = '0'; $env:GOOS = 'linux'; $env:GOARCH = 'amd64'
            & go build -trimpath -o (Join-Path $bin 'dirauditor') ./cmd/dirauditor; if ($LASTEXITCODE) { throw 'go build dirauditor failed' }
            & go build -trimpath -o (Join-Path $bin 'verify') ./tools/lab/verify; if ($LASTEXITCODE) { throw 'go build verify failed' }
        } finally {
            Remove-Item Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
            Pop-Location
        }
    } elseif ($env:DA_BIN) {
        Copy-Item (Join-Path $env:DA_BIN 'dirauditor'), (Join-Path $env:DA_BIN 'verify') $bin -Force
    } else {
        throw 'no Go on PATH and no DA_BIN with prebuilt Linux dirauditor and verify'
    }
    return $bin
}

# Power a VM off. Hyper-V's shutdown integration service works with nobody
# logged on; a hard turn-off is the last resort (the next run restores a
# checkpoint, so nothing is lost).
function Stop-LabVM([string]$Name) {
    $vm = Get-VM -Name $Name -ErrorAction SilentlyContinue
    if (-not $vm) { Write-Host "$Name does not exist"; return }
    if ($vm.State -ne 'Off') {
        try { Stop-VM -Name $Name -Force -ErrorAction Stop } catch { Stop-VM -Name $Name -TurnOff -Force }
    }
    (Get-VM -Name $Name).State
}

function Assert-NoRouteOut([scriptblock]$Probe, [string]$Name) {
    if (& $Probe) { throw "$Name still reaches the internet" }
    Write-Host "ok: $Name has no route out"
}

# --- Ubuntu lab VMs (the Samba DC and the scanner), reached over SSH on DA-Lab ---

# DA_LAB_KEY: another account's copy of the lab key (OpenSSH for Windows refuses a
# private key that anyone but its owner, SYSTEM and Administrators can read)
$LabKey   = if ($env:DA_LAB_KEY) { $env:DA_LAB_KEY } else { Join-Path $LabRoot 'state\id_ed25519' }
$LabKnown = Join-Path (Split-Path $LabKey) 'known_hosts'
$LabBase  = Join-Path $LabRoot 'vhd\noble-base.vhdx'
function Get-SshOpts { @('-i', $LabKey, '-o', "UserKnownHostsFile=$LabKnown", '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=5', '-o', 'BatchMode=yes') }

# Run a native program with its stdin, stdout and stderr on files, with a timeout.
# ssh.exe and scp.exe (Win32-OpenSSH) can hang after the remote side has exited when
# their stdout is a pipe, in a session without a console of its own (a CI runner
# service, an SSH session): PowerShell's & and Process redirection both give it pipes.
# Output comes back after the program exits: stdout, then stderr.
function Invoke-Native([string]$Exe, [string[]]$Arguments, [string]$StdIn = '', [int]$TimeoutSec = 3600) {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("da-lab-" + [guid]::NewGuid().ToString('N'))
    [IO.File]::WriteAllText("$tmp.in", $StdIn, (New-Object Text.UTF8Encoding($false)))
    $argLine = ($Arguments | ForEach-Object { if ($_ -match '[\s"]' -or $_ -eq '') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' '
    try {
        $p = Start-Process -FilePath $Exe -ArgumentList $argLine -NoNewWindow -PassThru `
            -RedirectStandardInput "$tmp.in" -RedirectStandardOutput "$tmp.out" -RedirectStandardError "$tmp.err"
        $null = $p.Handle    # keeps ExitCode readable after the process exits
        if (-not $p.WaitForExit($TimeoutSec * 1000)) { $p.Kill(); throw "$Exe timed out after $TimeoutSec s" }
        $lines = @(Get-Content "$tmp.out", "$tmp.err" -Encoding UTF8 -ErrorAction SilentlyContinue | Where-Object { $_ -ne '' })
        [pscustomobject]@{ Code = $p.ExitCode; Lines = $lines }
    } finally { Remove-Item "$tmp.in", "$tmp.out", "$tmp.err" -ErrorAction SilentlyContinue }
}

# Run a bash script in a VM. The script goes over stdin: Windows PowerShell 5.1
# mangles double quotes in native arguments, and bash must not see CRLF.
function Invoke-LabSsh([string]$IP, [string]$Script, [int]$TimeoutSec = 3600) {
    $r = Invoke-Native ssh.exe ((Get-SshOpts) + "lab@$IP" + 'bash -s') ($Script -replace "`r", '') $TimeoutSec
    # on failure, show the output before throwing: a caller's pipeline (Select-Object
    # -Last N, a variable) would never see it
    if ($r.Code) { $r.Lines | Select-Object -Last 40 | Out-Host; throw "command on $IP failed with $($r.Code)" }
    $r.Lines
}
function Test-LabSsh([string]$IP) { try { (Invoke-Native ssh.exe ((Get-SshOpts) + "lab@$IP" + 'true') '' 30).Code -eq 0 } catch { $false } }
function Wait-LabSsh([string]$IP, [int]$Seconds = 900) { Wait-Until { Test-LabSsh $IP } $Seconds "SSH to $IP" 5 }
function Copy-ToLab([string]$IP, [string[]]$Paths, [string]$Dest, [switch]$Recurse) {
    $r = if ($Recurse) { @('-r') } else { @() }
    $x = Invoke-Native scp.exe (@('-q') + $r + (Get-SshOpts) + $Paths + "lab@${IP}:$Dest") '' 600
    if ($x.Code) { $x.Lines | Out-Host; throw "scp to $IP failed" }
}
function Copy-FromLab([string]$IP, [string]$Src, [string]$Dest) {
    $x = Invoke-Native scp.exe (@('-q', '-r') + (Get-SshOpts) + "lab@${IP}:$Src" + $Dest) '' 600
    if ($x.Code) { $x.Lines | Out-Host; throw "scp from $IP failed" }
}
function ConvertTo-ColonMac([string]$Mac) { (($Mac -split '(..)' | Where-Object { $_ }) -join ':').ToLower() }

# A Generation 2 Ubuntu 24.04 VM on DA-Lab: a differencing disk over the cloud image and
# a cloud-init seed (user 'lab' with the lab key, static address). With -Packages it gets
# a second NIC on the NAT switch while cloud-init installs them; the caller removes it.
function New-UbuntuLabVM([string]$Name, [string]$Hostname, [string]$IP, [string]$Mac,
                         [int64]$MaxMemory = 2GB, [string]$NatMac, [string[]]$Packages = @()) {
    if (Get-VM -Name $Name -ErrorAction SilentlyContinue) { throw "$Name already exists (destroy it first)" }
    foreach ($f in $LabBase, $LabKey) { if (-not (Test-Path $f)) { throw "missing $f (setup-host.ps1 and the README describe it)" } }
    $disk = Join-Path $LabRoot "vhd\$Name.vhdx"
    $seedIso = Join-Path $LabRoot "iso\$Name-seed.iso"

    Log "storage and cloud-init seed for $Name"
    New-VHD -Path $disk -ParentPath $LabBase -Differencing | Out-Null
    Resize-VHD -Path $disk -SizeBytes 20GB
    $seed = Join-Path $env:TEMP "$Name-seed"
    Remove-Item -Recurse -Force $seed -ErrorAction SilentlyContinue
    New-Item -ItemType Directory $seed | Out-Null
    $pub = (Get-Content "$LabKey.pub" -Raw).Trim()
    Set-Content (Join-Path $seed 'meta-data') -Encoding Ascii -Value "instance-id: $Name`nlocal-hostname: $Hostname`n"
    $net = "version: 2`nethernets:`n  lab:`n    match: {macaddress: `"$(ConvertTo-ColonMac $Mac)`"}`n    addresses: [$IP/24]`n"
    if ($NatMac) { $net += "  nat:`n    match: {macaddress: `"$(ConvertTo-ColonMac $NatMac)`"}`n    dhcp4: true`n    optional: true`n" }
    Set-Content (Join-Path $seed 'network-config') -Encoding Ascii -Value $net
    $ud = "#cloud-config`nhostname: $Hostname`nusers:`n  - name: lab`n    sudo: ALL=(ALL) NOPASSWD:ALL`n    shell: /bin/bash`n    ssh_authorized_keys: [`"$pub`"]`nssh_pwauth: false`n"
    if ($Packages) { $ud += "package_update: true`npackages: [$($Packages -join ', ')]`n" }
    Set-Content (Join-Path $seed 'user-data') -Encoding Ascii -Value $ud
    New-IsoFile -SourceDir $seed -Path $seedIso -Label 'cidata'
    Remove-Item -Recurse -Force $seed

    $extra = if ($NatMac) { " + temporary NIC on $NatSwitch" } else { ', no other network' }
    Log "VM $Name (2 vCPU, 1-$($MaxMemory / 1GB) GB dynamic) on $LabSwitch $IP$extra"
    New-VM -Name $Name -Generation 2 -MemoryStartupBytes 1GB -VHDPath $disk -SwitchName $LabSwitch -Path (Join-Path $LabRoot 'vm') | Out-Null
    Set-VM -Name $Name -ProcessorCount 2 -DynamicMemory -MemoryMinimumBytes 512MB -MemoryMaximumBytes $MaxMemory `
        -AutomaticCheckpointsEnabled $false -CheckpointType Standard -AutomaticStartAction Nothing -AutomaticStopAction ShutDown
    Set-VMFirmware -VMName $Name -SecureBootTemplate MicrosoftUEFICertificateAuthority
    Set-VMNetworkAdapter -VMName $Name -StaticMacAddress $Mac
    if ($NatMac) { Add-VMNetworkAdapter -VMName $Name -Name nat -SwitchName $NatSwitch -StaticMacAddress $NatMac }
    Add-VMDvdDrive -VMName $Name -Path $seedIso
    Set-VMFirmware -VMName $Name -FirstBootDevice (Get-VMHardDiskDrive -VMName $Name)
    Start-VM -Name $Name

    Log 'waiting for SSH and cloud-init'
    # a new VM has a new host key: forget the address's old one
    if (Test-Path $LabKnown) {
        $keep = @(Get-Content $LabKnown | Where-Object { $_ -notmatch "^$([regex]::Escape($IP))[ ,]" })
        Set-Content -Path $LabKnown -Value $keep -Encoding Ascii
    }
    Wait-LabSsh $IP 1200
    Invoke-LabSsh $IP 'cloud-init status --wait >/dev/null; cloud-init status --long | head -3'
}

# Detach the NAT NIC and the seed, then prove the VM has no route out.
function Close-UbuntuLabVM([string]$Name, [string]$IP) {
    Log "removing any $NatSwitch NIC and the seed from $Name (no route out from here on)"
    Get-VMNetworkAdapter -VMName $Name | Where-Object SwitchName -eq $NatSwitch | Remove-VMNetworkAdapter
    Get-VMDvdDrive -VMName $Name | Remove-VMDvdDrive
    Get-VMNetworkAdapter -VMName $Name | Format-Table Name, SwitchName, MacAddress -AutoSize | Out-Host
    $out = Invoke-LabSsh $IP 'if timeout 5 bash -c "echo > /dev/tcp/1.1.1.1/443" 2>/dev/null; then echo ROUTE-OUT; else echo isolated; fi'
    Assert-NoRouteOut { $out -contains 'ROUTE-OUT' } $Name
}

function Remove-LabVM([string]$Name) {
    Stop-VM -Name $Name -TurnOff -Force -ErrorAction SilentlyContinue
    Get-VMSnapshot -VMName $Name -ErrorAction SilentlyContinue | Remove-VMSnapshot
    Remove-VM -Name $Name -Force -ErrorAction SilentlyContinue
    Remove-Item -Force (Join-Path $LabRoot "vhd\$Name.vhdx"), (Join-Path $LabRoot "iso\$Name-seed.iso"), (Join-Path $LabRoot "iso\$Name-answer.iso") -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force (Join-Path $LabRoot "vm\$Name") -ErrorAction SilentlyContinue
    Write-Host "destroyed $Name"
}
