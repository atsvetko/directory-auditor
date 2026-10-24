#Requires -Version 5.1
<#
.SYNOPSIS
    End-to-end AD CS validation runner for the lab. Run on the lab CA/DC built by
    tools/lab/windows/provision-adcs.ps1. It collects the tier-2 CA/DC facts,
    runs the auditor (tier-0 LDAP + the offline tier-2 ingest + the HTTP probe),
    and asserts that the expected AD CS checks fired. Prints a PASS/FAIL table
    and exits non-zero on any mismatch.

.DESCRIPTION
    Read-only against the directory and CA. Ready to run as-is on the lab DC
    (sensible defaults); override with the parameters for other layouts.

    Expected to FIRE (the lab seeds these):
      tier-0 LDAP templates : DSA-0501 ESC1, DSA-0502 ESC2, DSA-0509 ESC9, DSA-0515 ESC15
      tier-2 offline (CA/DC): DSA-0506 ESC6, DSA-0510 ESC10, DSA-0511 ESC11, DSA-0516 ESC16
      tier-1 probe (if a web-enrollment endpoint answers): DSA-0508 ESC8
    ESC7 (DSA-0507) and ESC13 (DSA-0513) are NOT seeded by provision-adcs.ps1
    and are therefore not asserted here.

.PARAMETER Auditor   Path to dirauditor.exe. Default: .\dirauditor.exe then PATH.
.PARAMETER Server    DC/CA to scan. Default: this computer.
.PARAMETER Domain    AD domain. Default: $env:USERDNSDOMAIN.
.PARAMETER User      Audit user (read-only). Default: current user @ domain.
.PARAMETER WorkDir   Where to write the collector JSON and the report. Default: a temp dir.

.EXAMPLE
    .\validate-adcs.ps1            # on the lab DC, audit user = current logon
    .\validate-adcs.ps1 -User audit@da.test
#>
[CmdletBinding()]
param(
    [string]$Auditor,
    [string]$Server = $env:COMPUTERNAME,
    [string]$Domain = $env:USERDNSDOMAIN,
    [string]$User,
    [string]$WorkDir = (Join-Path $env:TEMP ("adcs-validate-{0}" -f (Get-Date -Format yyyyMMdd-HHmmss)))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $Domain) { throw 'Domain is required (no USERDNSDOMAIN); pass -Domain.' }
if (-not $User)   { $User = "$env:USERNAME@$Domain" }
if (-not $Auditor) {
    foreach ($cand in (Join-Path $here 'dirauditor.exe'), (Join-Path (Split-Path $here) 'dirauditor.exe'), 'dirauditor.exe') {
        $c = Get-Command $cand -ErrorAction SilentlyContinue
        if ($c) { $Auditor = $c.Source; break }
    }
}
if (-not $Auditor -or -not (Get-Command $Auditor -ErrorAction SilentlyContinue)) {
    throw "dirauditor.exe not found — pass -Auditor <path> (build it with: go build -o dirauditor.exe ./cmd/dirauditor)."
}

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$offline = Join-Path $WorkDir 'adcs-tier2.json'
$outDir  = Join-Path $WorkDir 'report'
$collector = Join-Path $here 'collect-adcs-tier2.ps1'

Write-Host "== 1/3 collecting tier-2 CA/DC facts =="
# In this PowerShell: Windows Server ships 5.1 only and the collector runs on it.
& $collector -OutFile $offline
if (-not (Test-Path $offline)) { throw "collector did not produce $offline" }

Write-Host "== 2/3 scanning with the auditor (tier 0 LDAP + offline tier-2 + HTTP probe) =="
# Credentials: the audit user is prompted once; the password is piped on stdin,
# never placed on the command line.
# LAB_AUDIT_PASSWORD for unattended runs (an SSH session cannot answer Read-Host).
if ($env:LAB_AUDIT_PASSWORD) {
    $plain = $env:LAB_AUDIT_PASSWORD
} else {
    $sec = Read-Host -AsSecureString "password for $User (read-only audit account)"
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
}
$scanArgs = @(
    'scan', '--server', $Server, '--domain', $Domain, '--user', $User,
    '--password-stdin', '--tier', '2',
    '--adcs-offline', $offline, '--adcs-probe',
    '--catalogue', (Join-Path (Split-Path $here) 'catalogue'),
    '--packs', '', '--out', $outDir, '--lang', 'en'
)
$plain | & $Auditor @scanArgs
$report = Join-Path $outDir 'report.json'
if (-not (Test-Path $report)) { throw "no report at $report" }

Write-Host "== 3/3 asserting expected AD CS findings =="
$r = Get-Content -Raw $report | ConvertFrom-Json
$status = @{}
foreach ($c in $r.checks) { $status[$c.id] = $c.status }

$expectFire = [ordered]@{
    'DSA-0501' = 'ESC1  requester-named subject auth template'
    'DSA-0502' = 'ESC2  Any Purpose template'
    'DSA-0509' = 'ESC9  NO_SECURITY_EXTENSION template'
    'DSA-0515' = 'ESC15 schema-v1 supplies-subject template'
    'DSA-0506' = 'ESC6  EDITF_ATTRIBUTESUBJECTALTNAME2'
    'DSA-0510' = 'ESC10 weak DC certificate mapping'
    'DSA-0511' = 'ESC11 no RPC packet-privacy enforcement'
    'DSA-0516' = 'ESC16 SID extension disabled on CA'
}
$optionalFire = [ordered]@{ 'DSA-0508' = 'ESC8  web-enrollment NTLM/relay (needs a reachable endpoint)' }

$fail = 0
'{0,-10} {1,-7} {2}' -f 'CHECK', 'STATUS', 'MEANING' | Write-Host
foreach ($id in $expectFire.Keys) {
    $st = if ($status.ContainsKey($id)) { $status[$id] } else { '(absent)' }
    $ok = ($st -eq 'fail')   # a security finding has status "fail"
    if (-not $ok) { $fail++ }
    '{0,-10} {1,-7} {2}' -f $id, $st, (("PASS: ", "MISS: ")[[int](-not $ok)] + $expectFire[$id]) | Write-Host
}
foreach ($id in $optionalFire.Keys) {
    $st = if ($status.ContainsKey($id)) { $status[$id] } else { '(absent)' }
    '{0,-10} {1,-7} {2}' -f $id, $st, ('note: ' + $optionalFire[$id]) | Write-Host
}

Write-Host ''
if ($fail -eq 0) {
    Write-Host "RESULT: PASS — all $($expectFire.Count) seeded AD CS checks fired." -ForegroundColor Green
    exit 0
} else {
    Write-Host "RESULT: FAIL — $fail of $($expectFire.Count) expected AD CS checks did not fire. See $report." -ForegroundColor Red
    exit 1
}
