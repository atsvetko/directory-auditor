<#
.SYNOPSIS
    Pester tests for the parsing cores of collect-adcs-tier2.ps1.

    Run on Windows PowerShell 7 (the collector's target):
        pwsh -NoProfile -Command "Invoke-Pester -Path .\collect-adcs-tier2.Tests.ps1 -Output Detailed"

    The tests dot-source the collector (its main body is guarded so only the
    functions load) and exercise the three field-validation-sensitive parsers:
    Get-FlagNames (certutil name decode), ConvertTo-FlagNames (DWORD fallback)
    and Get-CaRoleHolders (CA security-descriptor → role-holder SIDs). The last
    one uses System.Security.AccessControl, which is Windows-only — so this
    suite is meaningful only on real Windows, which is the point of running it
    on the lab/host rather than in CI on Linux.
#>

BeforeAll {
    . (Join-Path $PSScriptRoot 'collect-adcs-tier2.ps1')
}

Describe 'Get-FlagNames (certutil -getreg name decode)' {
    It 'extracts EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6) from representative certutil text' {
        # Shape of `certutil -getreg policy\EditFlags` output: a hex value then the
        # decoded flag names, one per line, prefixed with the bit.
        $text = @'
  EditFlags REG_DWORD = 15014e (1376590)
    EDITF_REQUESTEXTENSIONLIST -- 2
    EDITF_ATTRIBUTEENDDATE -- 20 (32)
    EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 (262144)
    EDITF_ENABLEAKICRITICAL -- 100000 (1048576)
'@
        $names = Get-FlagNames -Text $text -Prefix 'EDITF_'
        $names | Should -Contain 'EDITF_ATTRIBUTESUBJECTALTNAME2'
    }

    It 'extracts IF_ENFORCEENCRYPTICERTREQUEST (ESC11) and de-duplicates' {
        $text = "IF_ENFORCEENCRYPTICERTREQUEST -- 200`nIF_ENFORCEENCRYPTICERTREQUEST -- 200`nIF_LOCKICERTREQUEST -- 800"
        $names = @(Get-FlagNames -Text $text -Prefix 'IF_')
        $names | Should -Contain 'IF_ENFORCEENCRYPTICERTREQUEST'
        ($names | Where-Object { $_ -eq 'IF_ENFORCEENCRYPTICERTREQUEST' }).Count | Should -Be 1
    }

    It 'returns empty for empty input' {
        @(Get-FlagNames -Text '' -Prefix 'EDITF_').Count | Should -Be 0
    }
}

Describe 'ConvertTo-FlagNames (DWORD fallback when certutil is absent)' {
    It 'decodes the EDITF_ATTRIBUTESUBJECTALTNAME2 bit (0x40000)' {
        $names = @(ConvertTo-FlagNames -Value 0x00040000 -Map $script:EditFlagBits)
        $names | Should -Contain 'EDITF_ATTRIBUTESUBJECTALTNAME2'
    }

    It 'does not report the SAN bit when it is clear' {
        $names = @(ConvertTo-FlagNames -Value 0x00000002 -Map $script:EditFlagBits)
        $names | Should -Not -Contain 'EDITF_ATTRIBUTESUBJECTALTNAME2'
    }

    It 'treats a missing IF_ENFORCEENCRYPTICERTREQUEST bit as absent (ESC11 finding)' {
        # InterfaceFlags without the 0x200 bit -> the flag name is NOT produced,
        # which is exactly what the ESC11 condition keys on.
        $names = @(ConvertTo-FlagNames -Value 0x00000040 -Map $script:InterfaceFlagBits)
        $names | Should -Not -Contain 'IF_ENFORCEENCRYPTICERTREQUEST'
    }
}

Describe 'Get-CaRoleHolders (CA Security descriptor -> role-holder SIDs)' {
    BeforeAll {
        # Build a real CA Security descriptor: one principal with ManageCA (0x1),
        # one with ManageCertificates (0x2), one with both, and a read-only ACE
        # that must be ignored. SDDL -> binary is the same path the collector
        # parses from the registry REG_BINARY.
        $mgrCA   = 'S-1-5-21-1111111111-2222222222-3333333333-1105'  # non-Tier-0 user
        $mgrCert = 'S-1-5-21-1111111111-2222222222-3333333333-1106'
        $both    = 'S-1-5-32-544'                                    # Administrators
        $sddl = "O:BAG:BAD:(A;;0x1;;;$mgrCA)(A;;0x2;;;$mgrCert)(A;;0x3;;;$both)(A;;0x200;;;S-1-1-0)"
        $rsd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl)
        $bytes = New-Object byte[] ($rsd.BinaryLength)
        $rsd.GetBinaryForm($bytes, 0)
        $script:roles = Get-CaRoleHolders -SecurityBytes $bytes
        $script:mgrCA = $mgrCA; $script:mgrCert = $mgrCert; $script:both = $both
    }

    It 'lists ManageCA holders (mask bit 0x1), including the both-roles principal' {
        $script:roles.ManageCA | Should -Contain $script:mgrCA
        $script:roles.ManageCA | Should -Contain $script:both
        $script:roles.ManageCA | Should -Not -Contain $script:mgrCert
    }

    It 'lists ManageCertificates holders (mask bit 0x2), including the both-roles principal' {
        $script:roles.ManageCertificates | Should -Contain $script:mgrCert
        $script:roles.ManageCertificates | Should -Contain $script:both
        $script:roles.ManageCertificates | Should -Not -Contain $script:mgrCA
    }

    It 'ignores an ACE that grants neither role bit (Everyone, read-only 0x200)' {
        $script:roles.ManageCA | Should -Not -Contain 'S-1-1-0'
        $script:roles.ManageCertificates | Should -Not -Contain 'S-1-1-0'
    }

    It 'returns empty role sets for an empty descriptor' {
        $empty = Get-CaRoleHolders -SecurityBytes @()
        @($empty.ManageCA).Count | Should -Be 0
        @($empty.ManageCertificates).Count | Should -Be 0
    }
}
