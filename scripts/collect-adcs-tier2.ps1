#requires -Version 5.1
<#
.SYNOPSIS
    Collect the out-of-band AD CS facts that the Directory Auditor tier-2 checks
    ESC6/ESC7/ESC10/ESC11/ESC16 (DSA-0506, 0507, 0510, 0511, 0516) need, into a
    JSON file for `dirauditor scan --adcs-offline <file>`.

.DESCRIPTION
    These facts do not live in LDAP; they live in the CA host registry and the
    domain-controller registry. This script READS them and writes a JSON
    document in the collector contract shape (internal/provider/ad/collect.go,
    "Out-of-band AD CS configuration snapshot"):

      - dirauditorCaConfig  per enterprise CA (run on a CA host)
          EditFlags            policy-module flag NAMES   (EDITF_*)      — ESC6
          InterfaceFlags       CA interface flag NAMES    (IF_*)         — ESC11
          DisableExtensionList disabled-extension OIDs                   — ESC16
          ManageCA             SIDs with the CA-admin role               — ESC7
          ManageCertificates   SIDs with the cert-manager role           — ESC7
      - dirauditorDcConfig  per domain controller (run on a DC)
          StrongCertificateBindingEnforcement  Kdc value 0/1/2           — ESC10
          CertificateMappingMethods            Schannel bitmask (0x-hex) — ESC10

    It is strictly READ-ONLY and idempotent: it runs `certutil -getreg ...`
    (read-only) and reads registry values with Get-ItemProperty; it changes
    nothing. Run it on the CA, on the DC, or on a box that is both; the output
    contains whatever roles the host has. Merge several hosts' files with
    --adcs-offline given more than once, or collect on each and analyse together.

.PARAMETER OutFile
    Path of the JSON file to write. Default: .\adcs-tier2-<COMPUTERNAME>.json

.PARAMETER LogFile
    Path of the run log. Default: <OutFile>.log

.EXAMPLE
    powershell -File .\collect-adcs-tier2.ps1        # Windows PowerShell 5.1 or PowerShell 7
    powershell -File .\collect-adcs-tier2.ps1 -OutFile C:\audit\ca01.json

.NOTES
    Needs local administrator rights on the CA (to read the CA Security
    descriptor and the policy-module registry) and on the DC (to read the Kdc
    and Schannel keys). Read-only; it never writes to the registry or to CertSvc.
    Field validation (on a real CA/DC) is still required — see the repository
    report. Output is UTF-8 with BOM for ru-RU Windows consoles.
#>
[CmdletBinding()]
param(
    [string]$OutFile = (Join-Path -Path (Get-Location) -ChildPath ("adcs-tier2-{0}.json" -f $env:COMPUTERNAME)),
    [string]$LogFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false  # certutil exit codes are inspected, not thrown

if (-not $LogFile) { $LogFile = "$OutFile.log" }

# ---- logging -------------------------------------------------------------
$script:LogLines = [System.Collections.Generic.List[string]]::new()
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0:yyyy-MM-ddTHH:mm:ssZ} [{1}] {2}' -f (Get-Date).ToUniversalTime(), $Level, $Message
    $script:LogLines.Add($line)
    Write-Host $line
}

# ---- read-only helpers ---------------------------------------------------

# Run certutil -getreg for the given CA config and value path; return raw text,
# or $null when certutil is missing or the value is absent.
function Invoke-CertutilGetReg {
    param([string]$CaConfig, [string]$ValuePath)
    $certutil = Get-Command certutil.exe -ErrorAction SilentlyContinue
    if (-not $certutil) { return $null }
    $cuArgs = @('-getreg', $ValuePath)
    if ($CaConfig) { $cuArgs = @('-config', $CaConfig) + $cuArgs }
    try {
        $out = & $certutil.Path @cuArgs 2>$null
    } catch { return $null }
    if ($LASTEXITCODE -ne 0) { return $null }
    return ($out -join "`n")
}

# Extract flag NAMES (e.g. EDITF_ATTRIBUTESUBJECTALTNAME2, IF_ENFORCEENCRYPTICERTREQUEST)
# that certutil prints for the bits that are set. The token names are not
# localised, so this is safe on ru-RU.
function Get-FlagNames {
    param([string]$Text, [string]$Prefix)
    if (-not $Text) { return @() }
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($m in [regex]::Matches($Text, ($Prefix + '[A-Z0-9_]+'))) {
        if (-not $names.Contains($m.Value)) { $names.Add($m.Value) }
    }
    return $names.ToArray()
}

# Minimal, documented fallback decoder used only when certutil is unavailable.
# Confirm every bit value at field validation (clean-room: facts in our words).
$script:EditFlagBits = [ordered]@{
    'EDITF_ATTRIBUTESUBJECTALTNAME2' = 0x00040000  # ESC6 — requester-supplied SAN for all templates
}
$script:InterfaceFlagBits = [ordered]@{
    'IF_ENFORCEENCRYPTICERTREQUEST'  = 0x00000200  # ESC11 — require RPC packet privacy
}
function ConvertTo-FlagNames {
    param([int]$Value, [System.Collections.Specialized.OrderedDictionary]$Map)
    $names = @()
    foreach ($k in $Map.Keys) { if ($Value -band $Map[$k]) { $names += $k } }
    return $names
}

# Read one registry value, or $null when the key or value is absent.
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch { return $null }
}

# Parse the CA security descriptor bytes into the SIDs that hold each CA role.
# CA access rights: CA_ACCESS_ADMIN = 0x1 (Manage CA), CA_ACCESS_OFFICER = 0x2
# (Manage Certificates). Confirm these masks at field validation.
function Get-CaRoleHolders {
    param([byte[]]$SecurityBytes)
    $result = @{ ManageCA = @(); ManageCertificates = @() }
    if (-not $SecurityBytes -or $SecurityBytes.Length -eq 0) { return $result }
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($SecurityBytes, 0)
    if (-not $sd.DiscretionaryAcl) { return $result }
    $ca = [System.Collections.Generic.List[string]]::new()
    $cert = [System.Collections.Generic.List[string]]::new()
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace -isnot [System.Security.AccessControl.CommonAce]) { continue }
        if ($ace.AceType -ne [System.Security.AccessControl.AceType]::AccessAllowed) { continue }
        $sid = $ace.SecurityIdentifier.Value
        if ($ace.AccessMask -band 0x1 -and -not $ca.Contains($sid)) { $ca.Add($sid) }
        if ($ace.AccessMask -band 0x2 -and -not $cert.Contains($sid)) { $cert.Add($sid) }
    }
    $result.ManageCA = $ca.ToArray()
    $result.ManageCertificates = $cert.ToArray()
    return $result
}

# When dot-sourced (e.g. by collect-adcs-tier2.Tests.ps1) stop here: only the
# parsing functions above are needed; the collection below must not run.
if ($MyInvocation.InvocationName -eq '.') { return }

# ---- collection ----------------------------------------------------------
Write-Log "collect-adcs-tier2 starting on $env:COMPUTERNAME"
$objects = [System.Collections.Generic.List[object]]::new()

# --- CA host: one dirauditorCaConfig per enterprise CA ---
$caConfigRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
if (Test-Path -LiteralPath $caConfigRoot) {
    $caKeys = @(Get-ChildItem -LiteralPath $caConfigRoot -ErrorAction SilentlyContinue)
    Write-Log ("found {0} CA configuration key(s)" -f $caKeys.Count)
    foreach ($caKey in $caKeys) {
        $caName = $caKey.PSChildName
        $caConfig = "{0}\{1}" -f $env:COMPUTERNAME, $caName
        Write-Log "reading CA '$caName'"

        # EditFlags (ESC6) — prefer certutil's name decode, fall back to the DWORD.
        $editText = Invoke-CertutilGetReg -CaConfig $caConfig -ValuePath 'policy\EditFlags'
        $editFlags = Get-FlagNames -Text $editText -Prefix 'EDITF_'
        if (-not $editFlags -or $editFlags.Count -eq 0) {
            $pmActive = Get-RegValue -Path (Join-Path $caKey.PSPath 'PolicyModules') -Name 'Active'
            if ($pmActive) {
                $dword = Get-RegValue -Path (Join-Path (Join-Path $caKey.PSPath 'PolicyModules') $pmActive) -Name 'EditFlags'
                if ($null -ne $dword) {
                    $editFlags = ConvertTo-FlagNames -Value ([int]$dword) -Map $script:EditFlagBits
                    Write-Log "  EditFlags from registry DWORD (certutil unavailable); confirm bit names at field validation" 'WARN'
                }
            }
        }

        # InterfaceFlags (ESC11).
        $ifText = Invoke-CertutilGetReg -CaConfig $caConfig -ValuePath 'ca\InterfaceFlags'
        $ifFlags = Get-FlagNames -Text $ifText -Prefix 'IF_'
        if (-not $ifFlags -or $ifFlags.Count -eq 0) {
            $dword = Get-RegValue -Path $caKey.PSPath -Name 'InterfaceFlags'
            if ($null -ne $dword) {
                $ifFlags = ConvertTo-FlagNames -Value ([int]$dword) -Map $script:InterfaceFlagBits
                Write-Log "  InterfaceFlags from registry DWORD (certutil unavailable); confirm bit names at field validation" 'WARN'
            }
        }

        # DisableExtensionList (ESC16) — OIDs.
        $delText = Invoke-CertutilGetReg -CaConfig $caConfig -ValuePath 'policy\DisableExtensionList'
        $disabled = @()
        if ($delText) {
            foreach ($m in [regex]::Matches($delText, '\b\d+(?:\.\d+){2,}\b')) { $disabled += $m.Value }
        } else {
            $pmActive = Get-RegValue -Path (Join-Path $caKey.PSPath 'PolicyModules') -Name 'Active'
            if ($pmActive) {
                $multi = Get-RegValue -Path (Join-Path (Join-Path $caKey.PSPath 'PolicyModules') $pmActive) -Name 'DisableExtensionList'
                if ($multi) { $disabled = @($multi | Where-Object { $_ -match '^\d+(\.\d+){2,}$' }) }
            }
        }
        $disabled = @($disabled | Select-Object -Unique)

        # CA security roles (ESC7).
        $secBytes = Get-RegValue -Path $caKey.PSPath -Name 'Security'
        $roles = Get-CaRoleHolders -SecurityBytes $secBytes

        $attrs = [ordered]@{ caName = $caName }
        if ($editFlags.Count) { $attrs['EditFlags'] = @($editFlags) }
        if ($ifFlags.Count)   { $attrs['InterfaceFlags'] = @($ifFlags) }
        if ($disabled.Count)  { $attrs['DisableExtensionList'] = @($disabled) }
        if ($roles.ManageCA.Count)           { $attrs['ManageCA'] = @($roles.ManageCA) }
        if ($roles.ManageCertificates.Count) { $attrs['ManageCertificates'] = @($roles.ManageCertificates) }

        $objects.Add([ordered]@{
            dn    = "cn=$caName,cn=certsvc,cn=dirauditor"
            class = 'dirauditorCaConfig'
            attrs = $attrs
        })
    }
} else {
    Write-Log "no CertSvc\Configuration key — this host is not an enterprise CA; skipping CA facts"
}

# --- DC host: one dirauditorDcConfig for this DC ---
$isDc = $false
try { $isDc = (Get-CimInstance Win32_ComputerSystem).DomainRole -in 4, 5 } catch {}
if (-not $isDc) { $isDc = Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' }
if ($isDc) {
    Write-Log "reading domain-controller certificate-mapping keys"
    $dcAttrs = [ordered]@{ dcName = $env:COMPUTERNAME }

    # StrongCertificateBindingEnforcement — ABSENT must NOT be reported as 0
    # (the ESC10 condition only fires on an explicit 0), so emit it only when set.
    $sbe = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name 'StrongCertificateBindingEnforcement'
    if ($null -ne $sbe) { $dcAttrs['StrongCertificateBindingEnforcement'] = [string]([int]$sbe) }

    # CertificateMappingMethods — emit as 0x-hex to match the snapshot convention.
    $cmm = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel' -Name 'CertificateMappingMethods'
    if ($null -ne $cmm) { $dcAttrs['CertificateMappingMethods'] = ('0x{0:x}' -f [int]$cmm) }

    $objects.Add([ordered]@{
        dn    = "cn=$($env:COMPUTERNAME),cn=kdc,cn=dirauditor"
        class = 'dirauditorDcConfig'
        attrs = $dcAttrs
    })
} else {
    Write-Log "not a domain controller; skipping DC certificate-mapping facts"
}

if ($objects.Count -eq 0) {
    Write-Log "nothing collected: this host is neither an enterprise CA nor a domain controller" 'WARN'
}

# ---- write output (UTF-8 with BOM) ---------------------------------------
$doc = [ordered]@{
    schema       = 'dirauditor-adcs-offline/1'
    generated_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    host         = $env:COMPUTERNAME
    objects      = @($objects)
}
$json = $doc | ConvertTo-Json -Depth 8
$utf8Bom = New-Object System.Text.UTF8Encoding($true)
[System.IO.File]::WriteAllText($OutFile, $json, $utf8Bom)
Write-Log "wrote $($objects.Count) object(s) to $OutFile"
[System.IO.File]::WriteAllText($LogFile, ($script:LogLines -join "`r`n"), $utf8Bom)

# ---- print the resulting state -------------------------------------------
Write-Host ""
Write-Host "==== resulting AD CS tier-2 snapshot ($OutFile) ===="
Write-Host $json
