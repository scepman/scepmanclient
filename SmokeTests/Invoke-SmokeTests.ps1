#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [String[]]$ConfigPath,

    [String[]]$Scenario,

    [Switch]$ValidateOnly,

    [Switch]$StopOnFailure
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-JsonProperty {
    param(
        [AllowNull()]
        [Object]$InputObject,

        [Parameter(Mandatory)]
        [String]$Name
    )

    return $null -ne $InputObject -and $InputObject.PSObject.Properties.Name -contains $Name
}

function Get-RequiredJsonValue {
    param(
        [Parameter(Mandatory)]
        [Object]$InputObject,

        [Parameter(Mandatory)]
        [String]$Name,

        [Parameter(Mandatory)]
        [String]$Location
    )

    if (-not (Test-JsonProperty -InputObject $InputObject -Name $Name) -or [String]::IsNullOrWhiteSpace([String]$InputObject.$Name)) {
        throw "Missing required '$Name' in $Location."
    }

    return $InputObject.$Name
}

function Invoke-AzureCli {
    param(
        [Parameter(Mandatory)]
        [String[]]$Arguments,

        [Parameter(Mandatory)]
        [String]$Purpose
    )

    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw "Azure CLI is required for $Purpose, but 'az' was not found."
    }

    $Output = & az @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI failed while $Purpose`: $($Output -join [Environment]::NewLine)"
    }

    return ($Output -join [Environment]::NewLine).Trim()
}

function Get-ScenarioValue {
    param(
        [Parameter(Mandatory)]
        [Object]$Configuration,

        [Parameter(Mandatory)]
        [Object]$TestScenario,

        [Parameter(Mandatory)]
        [String]$Name
    )

    if (Test-JsonProperty -InputObject $TestScenario -Name $Name) {
        return $TestScenario.$Name
    }

    if (Test-JsonProperty -InputObject $Configuration -Name $Name) {
        return $Configuration.$Name
    }

    return $null
}

function Add-RequestParameter {
    param(
        [Parameter(Mandatory)]
        [Hashtable]$Parameters,

        [AllowNull()]
        [Object]$Request
    )

    if ($null -eq $Request) {
        return
    }

    $SwitchParameters = @('SubjectFromUserContext', 'SubjectFromHostname')
    foreach ($Name in $SwitchParameters) {
        if ((Test-JsonProperty -InputObject $Request -Name $Name) -and $Request.$Name) {
            $Parameters[$Name] = $true
        }
    }

    $ValueParameters = @(
        'Subject',
        'UPN',
        'Email',
        'DNSName',
        'URI',
        'IP',
        'SignatureAlgorithm',
        'ExtendedKeyUsage',
        'ExtendedKeyUsageOID',
        'KeyUsage',
        'ValidityPeriod',
        'ValidityPeriodUnits'
    )

    foreach ($Name in $ValueParameters) {
        if (Test-JsonProperty -InputObject $Request -Name $Name) {
            $Parameters[$Name] = $Request.$Name
        }
    }
}

function Add-EndpointParameter {
    param(
        [Parameter(Mandatory)]
        [Hashtable]$Parameters,

        [Parameter(Mandatory)]
        [Object]$Configuration,

        [Parameter(Mandatory)]
        [Object]$TestScenario
    )

    $Endpoint = Get-ScenarioValue -Configuration $Configuration -TestScenario $TestScenario -Name 'Endpoint'
    if (-not [String]::IsNullOrWhiteSpace([String]$Endpoint)) {
        $Parameters.Endpoint = $Endpoint
    }
}

function Add-BearerAuthentication {
    param(
        [Parameter(Mandatory)]
        [Hashtable]$Parameters,

        [Parameter(Mandatory)]
        [Object]$Configuration,

        [Parameter(Mandatory)]
        [Object]$TestScenario
    )

    $Authentication = Get-RequiredJsonValue -InputObject $TestScenario -Name 'Authentication' -Location "scenario '$($TestScenario.Name)'"
    $AuthenticationType = Get-RequiredJsonValue -InputObject $Authentication -Name 'Type' -Location "authentication for scenario '$($TestScenario.Name)'"

    switch ($AuthenticationType) {
        'AzContext' {
            if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
                throw "Scenario '$($TestScenario.Name)' requires an Az PowerShell context. Run Connect-AzAccount first."
            }
        }
        'AzureCli' {
            $ResourceUrl = Get-ScenarioValue -Configuration $Configuration -TestScenario $TestScenario -Name 'ResourceUrl'
            if ([String]::IsNullOrWhiteSpace([String]$ResourceUrl)) {
                throw "Scenario '$($TestScenario.Name)' requires ResourceUrl when Authentication.Type is AzureCli."
            }

            $Parameters.AccessToken = Invoke-AzureCli -Arguments @(
                'account', 'get-access-token',
                '--resource', $ResourceUrl,
                '--query', 'accessToken',
                '--output', 'tsv',
                '--only-show-errors'
            ) -Purpose "acquiring the token for scenario '$($TestScenario.Name)'"

            if ($Parameters.ContainsKey('SubjectFromUserContext')) {
                $AccountName = Invoke-AzureCli -Arguments @(
                    'account', 'show',
                    '--query', 'user.name',
                    '--output', 'tsv',
                    '--only-show-errors'
                ) -Purpose "reading the signed-in account for scenario '$($TestScenario.Name)'"

                $Parameters.Remove('SubjectFromUserContext')
                $Parameters.Subject = "CN=$AccountName"
                $Parameters.UPN = $AccountName
            }
        }
        'ServicePrincipal' {
            $Parameters.ClientId = Get-RequiredJsonValue -InputObject $Authentication -Name 'ClientId' -Location "authentication for scenario '$($TestScenario.Name)'"
            $Parameters.TenantId = Get-RequiredJsonValue -InputObject $Authentication -Name 'TenantId' -Location "authentication for scenario '$($TestScenario.Name)'"
            $Parameters.ClientSecret = Get-RequiredJsonValue -InputObject $Authentication -Name 'ClientSecret' -Location "authentication for scenario '$($TestScenario.Name)'"
            $Parameters.IgnoreExistingSession = $true
        }
        'AccessToken' {
            $Parameters.AccessToken = Get-RequiredJsonValue -InputObject $Authentication -Name 'AccessToken' -Location "authentication for scenario '$($TestScenario.Name)'"
        }
        default {
            throw "Unsupported authentication type '$AuthenticationType' in scenario '$($TestScenario.Name)'."
        }
    }

    if ($AuthenticationType -in @('AzContext', 'ServicePrincipal')) {
        $ResourceUrl = Get-ScenarioValue -Configuration $Configuration -TestScenario $TestScenario -Name 'ResourceUrl'
        if (-not [String]::IsNullOrWhiteSpace([String]$ResourceUrl)) {
            $Parameters.ResourceUrl = $ResourceUrl
        }
    }
}

function Assert-SmokeCertificate {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [Object]$TestScenario
    )

    if (-not $Certificate.HasPrivateKey) {
        throw "Scenario '$($TestScenario.Name)' returned a certificate without its private key."
    }

    if ($Certificate.NotAfter -le [DateTime]::Now) {
        throw "Scenario '$($TestScenario.Name)' returned an expired certificate."
    }

    if (-not (Test-JsonProperty -InputObject $TestScenario -Name 'Expected')) {
        return
    }

    $Expected = $TestScenario.Expected
    if ((Test-JsonProperty -InputObject $Expected -Name 'SubjectRegex') -and $Certificate.Subject -notmatch $Expected.SubjectRegex) {
        throw "Certificate subject '$($Certificate.Subject)' does not match '$($Expected.SubjectRegex)'."
    }

    if ((Test-JsonProperty -InputObject $Expected -Name 'IssuerRegex') -and $Certificate.Issuer -notmatch $Expected.IssuerRegex) {
        throw "Certificate issuer '$($Certificate.Issuer)' does not match '$($Expected.IssuerRegex)'."
    }

    if (Test-JsonProperty -InputObject $Expected -Name 'MinimumRemainingDays') {
        $MinimumExpiration = [DateTime]::Now.AddDays([Double]$Expected.MinimumRemainingDays)
        if ($Certificate.NotAfter -lt $MinimumExpiration) {
            throw "Certificate expires at '$($Certificate.NotAfter)' and has fewer than $($Expected.MinimumRemainingDays) remaining days."
        }
    }
}

function ConvertTo-WindowsMtlsCertificate {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if (-not $IsWindows) {
        return $Certificate
    }

    $PrivateKey = if ($Certificate.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1') {
        [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    } elseif ($Certificate.PublicKey.Oid.Value -eq '1.2.840.10045.2.1') {
        [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Certificate)
    }

    try {
        $IsEphemeralCngKey = (
            ($PrivateKey -is [System.Security.Cryptography.RSACng] -or $PrivateKey -is [System.Security.Cryptography.ECDsaCng]) -and
            $PrivateKey.Key.IsEphemeral
        )
    } finally {
        if ($null -ne $PrivateKey) {
            $PrivateKey.Dispose()
        }
    }

    if (-not $IsEphemeralCngKey) {
        return $Certificate
    }

    $TemporaryPassword = [Guid]::NewGuid().ToString('N')
    $Pkcs12 = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $TemporaryPassword)
    try {
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $Pkcs12,
            $TemporaryPassword,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet
        )
    } finally {
        [Array]::Clear($Pkcs12, 0, $Pkcs12.Length)
    }
}

function Invoke-SmokeScenario {
    param(
        [Parameter(Mandatory)]
        [Object]$Configuration,

        [Parameter(Mandatory)]
        [Object]$TestScenario,

        [Parameter(Mandatory)]
        [Collections.Generic.Dictionary[String, System.Security.Cryptography.X509Certificates.X509Certificate2]]$Certificates
    )

    $Protocol = Get-RequiredJsonValue -InputObject $TestScenario -Name 'Protocol' -Location "scenario '$($TestScenario.Name)'"
    $Parameters = @{}
    $TemporaryCertificate = $null

    switch ($Protocol) {
        'EST' {
            $Url = Get-ScenarioValue -Configuration $Configuration -TestScenario $TestScenario -Name 'Url'
            if ([String]::IsNullOrWhiteSpace([String]$Url)) {
                throw "Scenario '$($TestScenario.Name)' requires Url."
            }

            $Parameters.Url = $Url
            Add-RequestParameter -Parameters $Parameters -Request $TestScenario.Request
            Add-EndpointParameter -Parameters $Parameters -Configuration $Configuration -TestScenario $TestScenario
            Add-BearerAuthentication -Parameters $Parameters -Configuration $Configuration -TestScenario $TestScenario
        }
        'ManagementSearch' {
            $Url = Get-ScenarioValue -Configuration $Configuration -TestScenario $TestScenario -Name 'Url'
            if ([String]::IsNullOrWhiteSpace([String]$Url)) {
                throw "Scenario '$($TestScenario.Name)' requires Url."
            }

            $Parameters.Url = $Url
            Add-BearerAuthentication -Parameters $Parameters -Configuration $Configuration -TestScenario $TestScenario

            if (Test-JsonProperty -InputObject $TestScenario -Name 'Search') {
                foreach ($Name in @('SearchText', 'PageSize', 'CertValidity', 'CertType')) {
                    if (Test-JsonProperty -InputObject $TestScenario.Search -Name $Name) {
                        $Parameters[$Name] = $TestScenario.Search.$Name
                    }
                }
            }
        }
        'SCEP' {
            $Url = Get-ScenarioValue -Configuration $Configuration -TestScenario $TestScenario -Name 'Url'
            if ([String]::IsNullOrWhiteSpace([String]$Url)) {
                throw "Scenario '$($TestScenario.Name)' requires Url."
            }

            $Parameters.Url = $Url
            $Parameters.UseSCEPEnrollment = $true
            $Parameters.ChallengePassword = Get-RequiredJsonValue -InputObject $TestScenario -Name 'ChallengePassword' -Location "scenario '$($TestScenario.Name)'"
            Add-RequestParameter -Parameters $Parameters -Request $TestScenario.Request
            Add-EndpointParameter -Parameters $Parameters -Configuration $Configuration -TestScenario $TestScenario
        }
        { $_ -in @('ESTRenewal', 'SCEPRenewal') } {
            $SourceScenario = Get-RequiredJsonValue -InputObject $TestScenario -Name 'SourceScenario' -Location "scenario '$($TestScenario.Name)'"
            if (-not $Certificates.ContainsKey($SourceScenario)) {
                throw "Scenario '$($TestScenario.Name)' requires successful source scenario '$SourceScenario' earlier in the same config."
            }

            if ($Protocol -eq 'ESTRenewal') {
                # The preceding in-process enrollment returns an ephemeral CNG key that Windows Schannel cannot use directly.
                $Parameters.Certificate = ConvertTo-WindowsMtlsCertificate -Certificate $Certificates[$SourceScenario]
                if (-not [Object]::ReferenceEquals($Parameters.Certificate, $Certificates[$SourceScenario])) {
                    $TemporaryCertificate = $Parameters.Certificate
                }
            } else {
                $Parameters.Certificate = $Certificates[$SourceScenario]
                $Parameters.UseSCEPRenewal = $true
            }
            Add-EndpointParameter -Parameters $Parameters -Configuration $Configuration -TestScenario $TestScenario
        }
        default {
            throw "Unsupported protocol '$Protocol' in scenario '$($TestScenario.Name)'."
        }
    }

    $UsesServicePrincipal = (
        $Protocol -in @('EST', 'ManagementSearch') -and
        (Test-JsonProperty -InputObject $TestScenario -Name 'Authentication') -and
        $TestScenario.Authentication.Type -eq 'ServicePrincipal'
    )
    $OriginalContext = if ($UsesServicePrincipal) {
        Get-AzContext -ErrorAction SilentlyContinue
    }

    try {
        if ($Protocol -eq 'ManagementSearch') {
            $Response = Find-SCEPmanCertificate @Parameters
        } else {
            $Certificate = New-SCEPmanCertificate @Parameters
        }
    }
    finally {
        if ($UsesServicePrincipal -and $null -ne $OriginalContext) {
            Set-AzContext -Context $OriginalContext -Scope Process | Out-Null
        } elseif ($UsesServicePrincipal) {
            Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue | Out-Null
        }
        if ($null -ne $TemporaryCertificate) {
            $TemporaryCertificate.Dispose()
        }
    }

    if ($Protocol -eq 'ManagementSearch') {
        if (-not (Test-JsonProperty -InputObject $Response -Name 'items')) {
            throw "Scenario '$($TestScenario.Name)' returned a management response without an items collection."
        }

        return [PSCustomObject]@{
            Certificate = $null
            Subject     = "$(@($Response.items).Count) item(s)"
            Thumbprint  = $null
        }
    }

    if ($Certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
        throw "Scenario '$($TestScenario.Name)' returned '$($Certificate.GetType().FullName)' instead of an X509Certificate2."
    }

    Assert-SmokeCertificate -Certificate $Certificate -TestScenario $TestScenario
    return [PSCustomObject]@{
        Certificate = $Certificate
        Subject     = $Certificate.Subject
        Thumbprint  = $Certificate.Thumbprint
    }
}

$ModulePath = Join-Path $PSScriptRoot '..\SCEPmanClient\SCEPmanClient.psm1'
Import-Module $ModulePath -Force

$ResolvedConfigPaths = $ConfigPath | ForEach-Object {
    Resolve-Path -Path $_ -ErrorAction Stop
} | Select-Object -ExpandProperty Path -Unique

$Results = [Collections.Generic.List[Object]]::new()
$FailureCount = 0

foreach ($Path in $ResolvedConfigPaths) {
    $Configuration = Get-Content -Path $Path -Raw | ConvertFrom-Json -Depth 20
    $ConfigurationName = if (Test-JsonProperty -InputObject $Configuration -Name 'Name') {
        $Configuration.Name
    } else {
        [IO.Path]::GetFileNameWithoutExtension($Path)
    }

    if (-not (Test-JsonProperty -InputObject $Configuration -Name 'Scenarios')) {
        throw "Configuration '$Path' does not contain a Scenarios array."
    }

    $Certificates = [Collections.Generic.Dictionary[String, System.Security.Cryptography.X509Certificates.X509Certificate2]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($TestScenario in $Configuration.Scenarios) {
        $ScenarioName = Get-RequiredJsonValue -InputObject $TestScenario -Name 'Name' -Location "configuration '$ConfigurationName'"
        if ((Test-JsonProperty -InputObject $TestScenario -Name 'Enabled') -and -not $TestScenario.Enabled) {
            continue
        }
        if ($Scenario -and $ScenarioName -notin $Scenario) {
            continue
        }
        if ($ValidateOnly) {
            continue
        }

        Write-Information "[$ConfigurationName] RUN  $ScenarioName" -InformationAction Continue
        $StartedAt = [DateTime]::UtcNow

        try {
            $Outcome = Invoke-SmokeScenario -Configuration $Configuration -TestScenario $TestScenario -Certificates $Certificates
            if ($null -ne $Outcome.Certificate) {
                $Certificates[$ScenarioName] = $Outcome.Certificate
            }
            $Results.Add([PSCustomObject]@{
                Configuration = $ConfigurationName
                Scenario      = $ScenarioName
                Status        = 'Passed'
                Duration      = [DateTime]::UtcNow - $StartedAt
                Subject       = $Outcome.Subject
                Thumbprint    = $Outcome.Thumbprint
                Error         = $null
            })
            Write-Information "[$ConfigurationName] PASS $ScenarioName" -InformationAction Continue
        }
        catch {
            $FailureCount++
            $Results.Add([PSCustomObject]@{
                Configuration = $ConfigurationName
                Scenario      = $ScenarioName
                Status        = 'Failed'
                Duration      = [DateTime]::UtcNow - $StartedAt
                Subject       = $null
                Thumbprint    = $null
                Error         = $_.Exception.Message
            })
            Write-Information "[$ConfigurationName] FAIL $ScenarioName`: $($_.Exception.Message)" -InformationAction Continue

            if ($StopOnFailure) {
                break
            }
        }
    }

    if ($StopOnFailure -and $FailureCount -gt 0) {
        break
    }
}

if ($ValidateOnly) {
    Write-Information "$(@($ResolvedConfigPaths).Count) smoke test configuration(s) passed JSON and structure validation." -InformationAction Continue
    return
}

if ($Scenario -and $Results.Count -eq 0) {
    throw "No enabled scenarios matched: $($Scenario -join ', ')."
}

$Results | Format-Table Configuration, Scenario, Status, Duration, Subject -AutoSize

if ($FailureCount -gt 0) {
    $Results | Where-Object Status -eq 'Failed' | ForEach-Object {
        Write-Error "[$($_.Configuration)] $($_.Scenario): $($_.Error)" -ErrorAction Continue
    }
    throw "$FailureCount smoke test scenario(s) failed."
}

Write-Information "$($Results.Count) smoke test scenario(s) passed." -InformationAction Continue