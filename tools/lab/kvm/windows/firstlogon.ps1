# LAB ONLY. Runs once at the first Administrator logon of the KVM lab VM
# (autounattend.xml FirstLogonCommands), from the answer media's lab\ folder:
# turns on the built-in OpenSSH server with the lab's public key, makes
# PowerShell the SSH shell, and installs the virtio guest tools when the
# virtio-win media is attached. Writes C:\lab-ready.txt when done.
$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# OpenSSH server ships with Windows Server 2025; it only needs enabling.
if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
}
New-Item -ItemType Directory -Force C:\ProgramData\ssh | Out-Null
$keys = 'C:\ProgramData\ssh\administrators_authorized_keys'
Copy-Item (Join-Path $here 'authorized_keys') $keys -Force
icacls $keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
New-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -PropertyType String -Force `
    -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' | Out-Null
Set-Service sshd -StartupType Automatic
Start-Service sshd
# The lab network has no gateway, so Windows classes it as Public; allow SSH on any profile.
if (-not (Get-NetFirewallRule -Name lab-sshd -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name lab-sshd -DisplayName 'Lab SSH' -Protocol TCP -LocalPort 22 -Direction Inbound -Action Allow -Profile Any | Out-Null
}

# virtio guest tools (virtio-serial + qemu-guest-agent), if the media is attached.
$gt = Get-PSDrive -PSProvider FileSystem | ForEach-Object { Join-Path $_.Root 'virtio-win-gt-x64.msi' } | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($gt) {
    Start-Process msiexec.exe -Wait -ArgumentList '/i', "`"$gt`"", '/qn', '/norestart'
    $ga = Join-Path (Split-Path $gt) 'guest-agent\qemu-ga-x86_64.msi'
    if (Test-Path $ga) { Start-Process msiexec.exe -Wait -ArgumentList '/i', "`"$ga`"", '/qn', '/norestart' }
}

"ready $(Get-Date -Format o)" | Set-Content C:\lab-ready.txt
