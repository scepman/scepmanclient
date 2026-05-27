<#
.SYNOPSIS
    Revoke a certificate issued by SCEPman.

.DESCRIPTION
    This function revokes a certificate issued by SCEPman by calling the SCEPman revocation API.

.PARAMETER Url
    The URL of the SCEPman App Service.

.PARAMETER SerialNumber
    One or more serial numbers of the certificates to revoke.

.PARAMETER RevocationReason
    The reason for revoking the certificate.

.PARAMETER Revoker
    The identity of the person or entity revoking the certificate (e.g. admin@contoso.com). If not provided, the current Azure context account will be used.

.PARAMETER ResourceUrl
    The resource URL of the SCEPman service. If not provided, the function will try to find the Enterprise Application for the URL.

.PARAMETER IgnoreExistingSession
    Ignore existing Azure session.

.PARAMETER DeviceCode
    Use device code authentication.

.PARAMETER Identity
    Use the managed identity for authentication.

.PARAMETER ClientId
    The client ID for service principal authentication.

.PARAMETER TenantId
    The tenant ID for service principal authentication.

.PARAMETER ClientSecret
    The client secret for service principal authentication.

.EXAMPLE
    Revoke-SCEPmanCertificate -Url "https://scepman.contoso.com" -SerialNumber "1A2B3C4D" -RevocationReason KeyCompromise -Revoker "admin@contoso.com"

.EXAMPLE
    Revoke-SCEPmanCertificate -Url "https://scepman.contoso.com" -SerialNumber "1A2B3C4D","5E6F7A8B" -RevocationReason Superseded
#>

Function Revoke-SCEPmanCertificate {
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingUsernameAndPasswordParams", "", Justification="Service principal authentication requires username and password.")]
    Param(
        [Parameter(Mandatory, Position=0)]
        [Alias('AppServiceUrl')]
        [String]$Url,

        [Parameter(Mandatory, Position=1, ValueFromPipeline)]
        [String[]]$SerialNumber,

        [Parameter(Mandatory)]
        [RevocationReason]$RevocationReason,

        [String]$Revoker,

        [String]$ResourceUrl,

        [Switch]$IgnoreExistingSession,
        [Switch]$DeviceCode,
        [Switch]$Identity,
        [String]$ClientId,
        [String]$TenantId,
        [String]$ClientSecret
    )

    Begin {
        $ErrorActionPreference = 'Stop'

        Set-AzConfig -Scope Process -LoginExperienceV2 Off -DisplaySurveyMessage $false | Out-Null

        $Connect_Params = @{}

        If ($PSBoundParameters.ContainsKey('IgnoreExistingSession')) { $Connect_Params['IgnoreExistingSession'] = $true }
        If ($PSBoundParameters.ContainsKey('DeviceCode')) { $Connect_Params['DeviceCode'] = $true }
        If ($PSBoundParameters.ContainsKey('Identity')) { $Connect_Params['Identity'] = $true }
        If ($PSBoundParameters.ContainsKey('ClientId')) { $Connect_Params['ClientId'] = $ClientId }
        If ($PSBoundParameters.ContainsKey('TenantId')) { $Connect_Params['TenantId'] = $TenantId }
        If ($PSBoundParameters.ContainsKey('ClientSecret')) { $Connect_Params['ClientSecret'] = $ClientSecret }

        Connect-SCEPmanAzAccount @Connect_Params

        If (-not $PSBoundParameters.ContainsKey('ResourceUrl')) {
            Write-Verbose "$($MyInvocation.MyCommand): No resource URL provided. Trying to find Enterprise Application for URL: $Url"
            $ResourceUrl = Get-SCEPmanResourceUrl -AppServiceUrl $Url
        }

        $AccessToken = Get-SCEPmanAccessToken -ResourceUrl $ResourceUrl

        $BaseUrl = $Url.TrimEnd('/')

        $Headers = @{
            'Authorization' = "Bearer $AccessToken"
            'Content-Type'  = 'application/json'
        }

    }

    Process {
        foreach ($Serial in $SerialNumber) {
            $RequestUrl = "$BaseUrl/api/manage/revoke/$Serial"

            $Body = @{
                revocationReason = [int]$RevocationReason
                revoker          = $Revoker
            } | ConvertTo-Json

            Write-Verbose "$($MyInvocation.MyCommand): Sending revocation request to $RequestUrl"

            $Result = try {
                $null = Invoke-RestMethod -Uri $RequestUrl -Method Patch -Headers $Headers -Body $Body
                [pscustomobject]@{
                    Success      = $true
                    StatusCode   = 200
                    ErrorCode    = $null
                    ErrorMessage = $null
                }

                Write-Verbose "$($MyInvocation.MyCommand): Certificate $Serial revoked successfully."
            } catch {
                $statusCode = [int]$_.Exception.Response.StatusCode
                $errorBody = $_.ErrorDetails.Message

                $errorCode = $null
                $errorMessage = $null

                if ($errorBody) {
                    try {
                        $parsed = $errorBody | ConvertFrom-Json
                        $errorCode = $parsed.ErrorCode
                        $errorMessage = $parsed.ErrorMessage
                    }
                    catch {
                        $errorMessage = $errorBody
                    }
                }

                # If we could not retrieve the internal error code/message, throw the raw error for better visibility
                if (-not $errorCode) {
                    throw "$($MyInvocation.MyCommand): Failed to revoke certificate $Serial. Raw error: $($_)"
                }

                [pscustomobject]@{
                    Success      = $false
                    StatusCode   = $statusCode
                    ErrorCode    = $errorCode
                    ErrorMessage = $errorMessage
                }

            }

            If ($Result.Success) {
                Write-Output "$($MyInvocation.MyCommand): Certificate $Serial revoked successfully."
            } Else {
                throw "$($MyInvocation.MyCommand): Failed to revoke certificate $Serial. StatusCode: $($Result.StatusCode), ErrorCode: $($Result.ErrorCode), Message: $($Result.ErrorMessage)"
            }
        }
    }
}
