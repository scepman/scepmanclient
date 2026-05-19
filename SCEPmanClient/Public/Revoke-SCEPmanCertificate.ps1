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

        If (-not $PSBoundParameters.ContainsKey('Revoker')) {
            $Revoker = (Get-AzContext).Account.Id
            Write-Verbose "$($MyInvocation.MyCommand): No revoker provided. Using current Azure context: $Revoker"
        }
    }

    Process {
        $BaseUrl = $Url.TrimEnd('/')

        $Headers = @{
            'Authorization' = "Bearer $AccessToken"
            'Content-Type'  = 'application/json'
        }

        foreach ($Serial in $SerialNumber) {
            $RequestUrl = "$BaseUrl/api/manage/revoke/$Serial"

            $Body = @{
                revocationReason = [int]$RevocationReason
                revoker          = $Revoker
            } | ConvertTo-Json

            Write-Verbose "$($MyInvocation.MyCommand): Sending revocation request to $RequestUrl"

            try {
                $Response = Invoke-RestMethod -Uri $RequestUrl -Method Patch -Headers $Headers -Body $Body
                Write-Verbose "$($MyInvocation.MyCommand): Certificate $Serial revoked successfully."
                $Response
            } catch {
                $StatusCode = $_.Exception.Response.StatusCode.value__
                Write-Error "$($MyInvocation.MyCommand): Failed to revoke certificate $Serial. Status code: $StatusCode. Error details: $($_ | Out-String)"

                switch ($StatusCode) {
                    401 { throw "$($MyInvocation.MyCommand): Unauthorized. Authentication failed. $_" }
                    400 { throw "$($MyInvocation.MyCommand): Bad request. Check the request body for errors. $_" }
                    404 { throw "$($MyInvocation.MyCommand): Certificate not found. Verify the URL and that serial number '$Serial' exists. $_" }
                    500 { throw "$($MyInvocation.MyCommand): Server error. The certificate may have already been revoked. $_" }
                    default { throw $_ }
                }
            }
        }
    }
}
