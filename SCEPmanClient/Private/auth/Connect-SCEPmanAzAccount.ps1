<#
.SYNOPSIS
    Wrapper for Connect-AzAccount to make sure we have a valid Azure context

.DESCRIPTION
    Check for existing Azure context and connect to Azure if needed

.PARAMETER DeviceCode
    Use device code authentication to connect to Azure

.PARAMETER AppRegistrationSecret
    Use app registration with client secret to connect to Azure

.PARAMETER AppRegistrationCertificate
    Use app registration with certificate to connect to Azure

.PARAMETER IgnoreExistingSession
    Ignore existing Azure context and connect to Azure

.OUTPUTS
    None

.EXAMPLE
    Connect-SCEPmanAzAccount -DeviceCode
    Connect to Azure using device code

.EXAMPLE
    Connect-SCEPmanAzAccount -IgnoreExistingSession
    Connect to Azure using interactive login and ignore existing session
#>

Function Connect-SCEPmanAzAccount {
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    Param(
        [Parameter(ParameterSetName='DeviceCode')]
        [Switch]$DeviceCode,

        [Parameter(Mandatory, ParameterSetName='AppRegistrationSecret')]
        [Parameter(Mandatory, ParameterSetName='AppRegistrationCertificate')]
        [String]$ClientId,
        [Parameter(Mandatory, ParameterSetName='AppRegistrationSecret')]
        [Parameter(Mandatory, ParameterSetName='AppRegistrationCertificate')]
        [String]$TenantId,
        [Parameter(ParameterSetName='AppRegistrationCertificate')]
        [String]$CertificateThumbprint,
        [Parameter(ParameterSetName='AppRegistrationSecret')]
        [String]$ClientSecret,

        [Switch]$IgnoreExistingSession
    )
    # Disable warning messages
    $WarningPreferenceBackup = $WarningPreference
    $WarningPreference = 'SilentlyContinue'

    $Context = Get-AzContext

    If($Context) {
        If($IgnoreExistingSession) {
            Write-Verbose "$($MyInvocation.MyCommand): Found existing Azure context. Ignoring existing session"
            Disconnect-AzAccount -Scope Process | Out-Null
        } else {
            Write-Verbose "Connect-SCEPmanAzAccount: Found existing Azure context. Using existing session"
            Return
        }
    }

    If($PSCmdlet.ParameterSetName -eq 'DeviceCode') {
        Write-Verbose "$($MyInvocation.MyCommand): Connecting to Azure using device code"
        Connect-AzAccount -DeviceCode -WarningAction SilentlyContinue | Out-Null

    } ElseIf($PSCmdlet.ParameterSetName -eq 'AppRegistrationSecret') {
        Write-Verbose "$($MyInvocation.MyCommand): Connecting to Azure using app registration and client secret"
        Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential (New-Object PSCredential $ClientId, (ConvertTo-SecureString $ClientSecret -AsPlainText -Force)) -WarningAction SilentlyContinue | Out-Null

    } ElseIf ($PSCmdlet.ParameterSetName -eq 'AppRegistrationCertificate') {
        Write-Verbose "$($MyInvocation.MyCommand): Connecting to Azure using app registration and certificate"
        $Certificate = Get-Item -Path Cert:\CurrentUser\My\$CertificateThumbprint
        Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential (New-Object PSCredential $ClientId, $Certificate) -WarningAction SilentlyContinue | Out-Null

    } ElseIf ($PSCmdlet.ParameterSetName -eq 'Interactive') {
        Write-Verbose "$($MyInvocation.MyCommand): Connecting to Azure using interactive login"
        Connect-AzAccount -WarningAction SilentlyContinue | Out-Null

    } else {
        throw "$($MyInvocation.MyCommand): Invalid parameter set"
    }

    # Reset warning preference
    $WarningPreference = $WarningPreferenceBackup
}