<#
.SYNOPSIS
    Sends a EST request to a EST.

.DESCRIPTION
    This function, `Invoke-ESTRequest`, sends an Enrollment over Secure Transport (EST) request to a specified Application Service URL. It constructs the request with the provided access token, endpoint, and PKCS#10 certificate request, and sends it using the `Invoke-WebRequest` cmdlet. If the response is successful, it parses the returned DER-encoded certificate into an X509Certificate2Collection object; otherwise, it throws an error with the response status code.

.PARAMETER AppServiceUrl
    The URL of the Application Service to send the EST request to.

.PARAMETER Endpoint
    The endpoint to send the EST request to. Default is '/.well-known/est/simpleenroll'.

.PARAMETER AccessToken
    The access token to authenticate the EST request.

.PARAMETER Request
    The PKCS#10 certificate request to send in the EST request.

.EXAMPLE
    # Example usage of Invoke-ESTRequest
    $AppServiceUrl = "https://example.com"
    $AccessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."  # Replace with a valid access token
    $Request = @"
    -----BEGIN CERTIFICATE REQUEST-----
    MIIBVTCBvwIBADBFMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTkMxEDAOBgNVBAcM
    B1JhbGVpZ2gxEDAOBgNVBAoMB1Rlc3QgQ28wXDANBgkqhkiG9w0BAQEFAANLADBIAkEA
    ...
    -----END CERTIFICATE REQUEST-----
    "@  # Replace with a valid PKCS#10 certificate request

    $Certificate = Invoke-ESTRequest -AppServiceUrl $AppServiceUrl -AccessToken $AccessToken -Request $Request
#>

Function Invoke-ESTRequest {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2Collection])]
    Param(
        [Parameter(Mandatory)]
        [String]$AppServiceUrl,
        [Parameter()]
        [String]$Endpoint = '/.well-known/est/simpleenroll',
        [Parameter(Mandatory)]
        [String]$Request,
        [String]$AccessToken,
        [PSCredential]$Credential
    )

    $Uri = ($AppServiceUrl -replace '/$') + $Endpoint

    $Headers = @{
        'Content-Type' = 'application/pkcs10'
    }

    If ($PSBoundParameters.ContainsKey('AccessToken')) {
        Write-Verbose "$($MyInvocation.MyCommand): Add access token to request header"
        $Headers['Authorization'] = "Bearer $AccessToken"
    }

    Write-Verbose "$($MyInvocation.MyCommand): Sending EST request to $Uri"

    $Request_Params = @{
        Uri     = $Uri
        Method  = 'POST'
        Headers = $Headers
        Body    = $Request
    }

    If ($PSBoundParameters.ContainsKey('Credential')) {
        Write-Verbose "$($MyInvocation.MyCommand): Add passed credential to request"
        $Request_Params['Credential'] = $Credential
    }

    $Response = Invoke-WebRequest @Request_Params

    If ($Response.StatusCode -eq 200) {
        $CertificateCollection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $DERCertificate = [System.Convert]::FromBase64String(($Response.Content | ConvertFrom-Bytes))
        $CertificateCollection.Import($DERCertificate)

        Return $CertificateCollection
    } Else {
        throw "$($MyInvocation.MyCommand): SCEPman EST Request failed: $($Response.StatusCode)"
    }
}