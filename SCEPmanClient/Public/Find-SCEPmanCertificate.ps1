<#
.SYNOPSIS
    Search certificates issued by SCEPman.

.DESCRIPTION
    This function searches certificates via the SCEPman management search API.

.PARAMETER Url
    The URL of the SCEPman App Service.

.PARAMETER SearchText
    Search text used by the SCEPman API (for example an email, subject, or serial fragment).

.PARAMETER PageSize
    Number of results to return per request.

.PARAMETER CertValidity
    Certificate validity filter value expected by your SCEPman API (for example 'Any' or a numeric enum value).

.PARAMETER CertType
    Certificate type filter value expected by your SCEPman API (for example 'Any' or a numeric enum value).

.PARAMETER ContinuationToken
    Continuation token from a previous search response.

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
    Find-SCEPmanCertificate -Url "https://scepman.contoso.com" -SearchText "alice@contoso.com" -PageSize 50 -CertValidity Any -CertType Any

.EXAMPLE
    Find-SCEPmanCertificate -Url "https://scepman.contoso.com" -SearchText "alice" -ContinuationToken "next-page-token"
#>

Function Find-SCEPmanCertificate {
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingUsernameAndPasswordParams", "", Justification="Service principal authentication requires username and password.")]
    Param(
        [Parameter(Mandatory, Position=0)]
        [Alias('AppServiceUrl')]
        [String]$Url,

        [String]$SearchText,

        [ValidateRange(1, 500)]
        [Int]$PageSize = 50,

        [CertValidityType]$CertValidity = 'Any',

        [CertType]$CertType = 'Any',

        [String]$ContinuationToken,

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
    }

    Process {
        $BaseUrl = $Url.TrimEnd('/')

        $Headers = @{
            'Authorization' = "Bearer $AccessToken"
        }

        $Query = [ordered]@{
            SearchText        = $SearchText
            PageSize          = $PageSize
            CertValidity      = $CertValidity
            CertType          = $CertType
            ContinuationToken = $ContinuationToken
        }

        $QueryString = ($Query.GetEnumerator() |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Value) } |
            ForEach-Object {
                '{0}={1}' -f [uri]::EscapeDataString($_.Key), [uri]::EscapeDataString([string]$_.Value)
            }) -join '&'

        $RequestUrl = "$BaseUrl/api/manage/search"
        If (-not [string]::IsNullOrWhiteSpace($QueryString)) {
            $RequestUrl = "{0}?{1}" -f $RequestUrl, $QueryString
        }

        Write-Verbose "$($MyInvocation.MyCommand): Sending search request to $RequestUrl"

        try {
            $Response = Invoke-RestMethod -Uri $RequestUrl -Method Get -Headers $Headers
            Write-Verbose "$($MyInvocation.MyCommand): Search request successful. Found $($Response.items.count) certificate$(if($Response.items.count -ne 1) { 's' })"

            Return $Response

        } catch {
            $StatusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
            $RawErrorBody = $_.ErrorDetails.Message

            $ApiErrorCode = $null
            $ApiErrorMessage = $null

            if ($RawErrorBody) {
                try {
                    $ParsedError = $RawErrorBody | ConvertFrom-Json
                    $ApiErrorCode = $ParsedError.ErrorCode
                    $ApiErrorMessage = $ParsedError.ErrorMessage
                }
                catch {
                    $ApiErrorMessage = $RawErrorBody
                }
            }

            Write-Verbose "$($MyInvocation.MyCommand): Failed to search certificates. Status code: $StatusCode. ApiErrorCode: $ApiErrorCode. ApiErrorMessage: $ApiErrorMessage"

            switch ($ApiErrorCode) {
                4711 { throw "$($MyInvocation.MyCommand): SCEPman Enterprise is required for the manage search API." }
                default {
                    switch ($StatusCode) {
                        400 { throw "$($MyInvocation.MyCommand): Bad request. Check the request parameters for errors. $ApiErrorMessage" }
                        401 { throw "$($MyInvocation.MyCommand): Unauthorized. Authentication failed." }
                        403 { throw "$($MyInvocation.MyCommand): Forbidden. Access denied or license revoked." }
                        404 { throw "$($MyInvocation.MyCommand): Endpoint not found. Verify the URL and that the manage API endpoint exists." }
                        409 { throw "$($MyInvocation.MyCommand): Conflict. $(if ($ApiErrorMessage) { $ApiErrorMessage } else { 'Request could not be completed.' })" }
                        500 { throw "$($MyInvocation.MyCommand): Server error while searching certificates. $ApiErrorMessage" }
                        default { throw $_ }
                    }
                }
            }
        }
    }
}
