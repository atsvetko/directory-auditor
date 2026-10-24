#Requires -Version 5.1
<#
.SYNOPSIS
    LAB ONLY. Installs an Enterprise Root CA on an already-promoted lab domain
    controller and seeds intentionally VULNERABLE AD CS configuration so the
    Directory Auditor AD CS checks (DSA-0501…0520, ESC1–ESC16) have something to
    find. Run on the DC after provision.ps1 + populate.ps1 (labctl does this for
    a windows-dc with `adcs: true`).

.DESCRIPTION
    This script WRITES state — it installs the AD CS role and creates weak
    certificate templates, CA flags and DC registry values on purpose. It must
    NEVER be run on a production or internet-joined system. It refuses to run
    unless the environment variable DIRAUDITOR_LAB=1 is set, and it is idempotent
    (re-running tops up what is missing). A log is written and the resulting CA
    configuration is printed at the end.

    What it seeds, mapped to the checks:
      ESC1  (DSA-0501)  template LabESC1   — clientAuth + ENROLLEE_SUPPLIES_SUBJECT, Authenticated Users may enroll
      ESC2  (DSA-0502)  template LabESC2   — Any Purpose EKU, Authenticated Users may enroll
      ESC9  (DSA-0509)  template LabESC9   — clientAuth + CT_FLAG_NO_SECURITY_EXTENSION
      ESC15 (DSA-0515)  template LabESC15  — schema version 1 + ENROLLEE_SUPPLIES_SUBJECT
      ESC6  (DSA-0506)  CA policy EditFlags += EDITF_ATTRIBUTESUBJECTALTNAME2
      ESC11 (DSA-0511)  CA InterfaceFlags  -= IF_ENFORCEENCRYPTICERTREQUEST
      ESC16 (DSA-0516)  CA policy DisableExtensionList += 1.3.6.1.4.1.311.25.2 (SID security extension)
      ESC10 (DSA-0510)  DC Kdc\StrongCertificateBindingEnforcement = 0
      ESC7  (DSA-0507)  best effort — see note; may need manual CA-security grant
      ESC13 (DSA-0513)  not seeded here — needs an issuance-policy OID + msDS-OIDToGroupLink (documented TODO)

    Field-validation open points (this script is NOT run or linted in CI — no
    Windows there): confirm the AD CS feature/role cmdlet names on the target
    Windows Server build, the template-duplication AD attributes, and the
    certutil -setreg value paths against a live CA. See docs/clean-room.md notes
    and the catalogue entries.

.PARAMETER DomainName
    The AD domain (e.g. da.test). Defaults to the current computer's domain.

.PARAMETER CommonName
    CA common name. Default: <NetBIOS>-LAB-CA.

.EXAMPLE
    $env:DIRAUDITOR_LAB=1; .\provision-adcs.ps1 -DomainName da.test
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$DomainName = $env:USERDNSDOMAIN,
    [string]$CommonName,
    [string]$LogFile = (Join-Path -Path (Get-Location) -ChildPath 'provision-adcs.log')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format o), $Level, $Message
    Write-Host $line
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch { }
}

if ($env:DIRAUDITOR_LAB -ne '1') {
    throw 'refusing to run: set DIRAUDITOR_LAB=1 — this script seeds VULNERABLE AD CS config and is for throwaway labs only.'
}
if (-not $DomainName) { throw 'DomainName is required (no USERDNSDOMAIN in the environment).' }

$netbios = ($DomainName -split '\.')[0].ToUpper()
if (-not $CommonName) { $CommonName = "$netbios-LAB-CA" }
Write-Log "provision-adcs starting on $env:COMPUTERNAME for domain $DomainName (CA '$CommonName')"

# ---- 1. Install the AD CS role + Enterprise Root CA (idempotent) ----------
function Install-LabCA {
    if (-not $PSCmdlet.ShouldProcess($CommonName, 'install Enterprise Root CA')) { return }
    Import-Module ServerManager -ErrorAction SilentlyContinue
    $feat = Get-WindowsFeature -Name ADCS-Cert-Authority -ErrorAction SilentlyContinue
    if ($feat -and -not $feat.Installed) {
        Write-Log 'installing ADCS-Cert-Authority feature'
        Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools | Out-Null
    }
    Import-Module ADCSDeployment -ErrorAction SilentlyContinue
    # Already configured? certutil returns the CA name when a CA is present.
    $existing = & certutil.exe 2>$null | Select-String -Pattern 'Config:' -SimpleMatch
    if ($existing) {
        Write-Log 'an Enterprise CA is already configured — skipping role configuration'
        return
    }
    Write-Log 'configuring Enterprise Root CA (this can take a minute)'
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName $CommonName `
        -HashAlgorithmName SHA256 -KeyLength 2048 -ValidityPeriod Years -ValidityPeriodUnits 5 `
        -Force -ErrorAction Stop | Out-Null
    Write-Log 'Enterprise Root CA configured'
}

# ---- certificate template helpers (dependency-free, via ADSI) --------------
# A certificate template is a pKICertificateTemplate object under
# CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration.
# We clone the built-in "User" template's AD object and override the attributes
# each ESC needs, then publish it on the CA.
function Get-ConfigNC { ([ADSI]'LDAP://RootDSE').Get('configurationNamingContext') }

function New-LabTemplate {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$Eku,                       # pKIExtendedKeyUsage OIDs; empty => Any Purpose (ESC2)
        [int]$NameFlag = 0x1,                 # msPKI-Certificate-Name-Flag (0x1 = ENROLLEE_SUPPLIES_SUBJECT)
        [int]$EnrollmentFlag = 0,             # msPKI-Enrollment-Flag (0x80000 = NO_SECURITY_EXTENSION, ESC9)
        [int]$SchemaVersion = 2               # msPKI-Template-Schema-Version (1 => ESC15)
    )
    if (-not $PSCmdlet.ShouldProcess($Name, 'create vulnerable certificate template')) { return }
    $cfg = Get-ConfigNC
    $tmplRoot = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg"
    $container = [ADSI]$tmplRoot
    $dn = "CN=$Name,CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg"
    $existing = $container.psbase.Children | Where-Object { $_.Name -eq $Name }
    if ($existing) {
        Write-Log "template $Name already exists — topping up its EKUs and Enroll right"
    } else {
    $t = $container.Create('pKICertificateTemplate', "CN=$Name")
    $t.Put('distinguishedName', "CN=$Name,CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg")
    $t.Put('displayName', $Name)
    $t.Put('revision', 100)
    $t.Put('msPKI-Template-Schema-Version', $SchemaVersion)
    $t.Put('msPKI-Template-Minor-Revision', 1)
    $t.Put('msPKI-Certificate-Name-Flag', [int]$NameFlag)      # requester supplies subject (ESC1/ESC15)
    $t.Put('msPKI-Enrollment-Flag', [int]$EnrollmentFlag)       # 0 => no manager approval; 0x80000 => NO_SECURITY_EXTENSION
    $t.Put('msPKI-RA-Signature', 0)                            # no issuance signature required
    $t.Put('pKIDefaultKeySpec', 1)
    $t.Put('msPKI-Minimal-Key-Size', 2048)
    $t.Put('pKIExpirationPeriod', [byte[]](0,0x80,0x72,0x0e,0x5d,0xc2,0xff,0xff))   # 1 year
    $t.Put('pKIOverlapPeriod',    [byte[]](0,0x80,0xa6,0x0a,0xff,0xde,0xff,0xff))   # 6 weeks
    $t.SetInfo()
    }
    # Multi-valued EKUs through the AD module: ADSI PutEx fails here with
    # "Unspecified error" on Windows Server 2025, before and after SetInfo.
    if ($Eku -and $Eku.Count) {
        Set-ADObject -Identity $dn -Replace @{ 'pKIExtendedKeyUsage' = [string[]]$Eku; 'msPKI-Certificate-Application-Policy' = [string[]]$Eku }
    }
    # ANY PURPOSE (ESC2): leave both EKU attributes unset entirely.
    Write-Log "created template $Name (schemaV=$SchemaVersion nameFlag=0x$("{0:x}" -f $NameFlag) enrollFlag=0x$("{0:x}" -f $EnrollmentFlag) eku=$($Eku -join ','))"

    # Grant Authenticated Users Enroll (extended right 0e10c968-…) so the ESC
    # checks' "enrollable outside Tier 0" predicate fires.
    try {
        $tObj = [ADSI]("LDAP://CN=$Name,CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg")
        $authUsers = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')
        $enroll = [GUID]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $authUsers, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow, $enroll)
        $tObj.psbase.ObjectSecurity.AddAccessRule($ace)
        $tObj.psbase.CommitChanges()
        Write-Log "  granted Authenticated Users Enroll on $Name"
    } catch { Write-Log "  WARN: could not grant Enroll on $Name — $_" 'WARN' }
}

function Publish-LabTemplate {
    param([Parameter(Mandatory)][string]$Name)
    if (-not $PSCmdlet.ShouldProcess($Name, 'publish template on the CA')) { return }
    try { & certutil.exe -SetCATemplates "+$Name" 2>&1 | Out-Null; Write-Log "published $Name on the CA" }
    catch { Write-Log "  WARN: could not publish $Name — $_" 'WARN' }
}

# ---- CA registry flags via certutil -setreg (ESC6/11/16) -------------------
function Set-CaReg {
    param([string]$Path, [string]$Arg, [string]$What)
    if (-not $PSCmdlet.ShouldProcess($What, 'certutil -setreg')) { return }
    try {
        & certutil.exe -setreg $Path $Arg 2>&1 | Out-Null
        Write-Log "set CA reg $Path $Arg ($What)"
    } catch { Write-Log "  WARN: certutil -setreg $Path $Arg failed — $_" 'WARN' }
}

# ---- DC registry (ESC10) ---------------------------------------------------
function Set-WeakDcMapping {
    if (-not $PSCmdlet.ShouldProcess('Kdc\StrongCertificateBindingEnforcement', 'set 0 (ESC10)')) { return }
    try {
        Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
            -Name 'StrongCertificateBindingEnforcement' -Value 0 -Type DWord
        Write-Log 'set Kdc\StrongCertificateBindingEnforcement = 0 (ESC10)'
    } catch { Write-Log "  WARN: could not set the Kdc value — $_" 'WARN' }
}

# ============================ run =========================================
try { Install-LabCA } catch { Write-Log "ERROR installing CA: $_" 'ERROR'; throw }

# ESC1: clientAuth + requester-supplied subject
New-LabTemplate -Name 'LabESC1'  -Eku '1.3.6.1.5.5.7.3.2' -NameFlag 0x1 -SchemaVersion 2
# ESC2: Any Purpose (no EKU attributes at all)
New-LabTemplate -Name 'LabESC2'  -Eku @()                 -NameFlag 0x1 -SchemaVersion 2
# ESC9: clientAuth + NO_SECURITY_EXTENSION (0x80000)
New-LabTemplate -Name 'LabESC9'  -Eku '1.3.6.1.5.5.7.3.2' -NameFlag 0x1 -EnrollmentFlag 0x80000 -SchemaVersion 2
# ESC15: schema version 1 + requester-supplied subject
New-LabTemplate -Name 'LabESC15' -Eku '1.3.6.1.5.5.7.3.2' -NameFlag 0x1 -SchemaVersion 1

foreach ($n in 'LabESC1', 'LabESC2', 'LabESC9', 'LabESC15') { Publish-LabTemplate -Name $n }

Set-CaReg -Path 'policy\EditFlags'           -Arg '+EDITF_ATTRIBUTESUBJECTALTNAME2' -What 'ESC6 requester SAN for all templates'
Set-CaReg -Path 'CA\InterfaceFlags'          -Arg '-IF_ENFORCEENCRYPTICERTREQUEST'  -What 'ESC11 drop RPC packet-privacy enforcement'
Set-CaReg -Path 'policy\DisableExtensionList' -Arg '+1.3.6.1.4.1.311.25.2'           -What 'ESC16 disable the SID security extension'
try { & certutil.exe -setreg ca\CRLPeriodUnits 1 2>&1 | Out-Null } catch { }
Write-Log 'restarting certsvc to apply CA flag changes'
try { Restart-Service certsvc -ErrorAction Stop; Write-Log 'certsvc restarted' } catch { Write-Log "WARN: could not restart certsvc — $_" 'WARN' }

Set-WeakDcMapping

Write-Log 'ESC7 (non-Tier-0 ManageCA/ManageCertificates) is NOT auto-seeded — grant it in the CA MMC or via ICertAdmin, then re-run the audit. Documented as an open point.' 'WARN'
Write-Log 'ESC13 (issuance-policy OID -> msDS-OIDToGroupLink) is NOT auto-seeded — needs an OID object and a universal group link. Documented as an open point.' 'WARN'

# ---- final self-check: print the resulting CA configuration ----------------
Write-Host ''
Write-Host '==== resulting CA configuration (evidence) ===='
try { & certutil.exe -getreg policy\EditFlags 2>&1 | Out-String | Write-Host } catch { }
try { & certutil.exe -getreg ca\InterfaceFlags 2>&1 | Out-String | Write-Host } catch { }
try { & certutil.exe -getreg policy\DisableExtensionList 2>&1 | Out-String | Write-Host } catch { }
try { & certutil.exe -CATemplates 2>&1 | Out-String | Write-Host } catch { }
try {
    $sbe = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name StrongCertificateBindingEnforcement -ErrorAction SilentlyContinue).StrongCertificateBindingEnforcement
    Write-Host "Kdc\StrongCertificateBindingEnforcement = $sbe"
} catch { }
Write-Log 'provision-adcs done'
