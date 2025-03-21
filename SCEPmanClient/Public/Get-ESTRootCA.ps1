<#
    .SYNOPSIS
    Get the root CA certificate from the EST server.

    .DESCRIPTION
    Get the root CA certificate from the EST server. The root CA certificate is used to verify the EST server's certificate.

    .PARAMETER Url
    The URL of the EST server.

    .PARAMETER Endpoint
    The endpoint to get the root CA certificate from. Default is '/.well-known/est/cacerts'.

    .EXAMPLE
    Get-ESTRootCA -AppServiceUrl 'https://est.example.com'

    .OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2Collection
#>

Function Get-ESTRootCA {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2Collection])]
    Param(
        [Parameter(Mandatory)]
        [Alias('AppServiceUrl')]
        [String]$Url,
        [String]$Endpoint = '/.well-known/est/cacerts'
    )

    $Uri = $Uri = ($Url -replace '/$') + $Endpoint

    Write-Verbose "$($MyInvocation.MyCommand): Getting root CA from $Uri"
    $Response = Invoke-WebRequest -Uri $Uri -Method GET

    If ($Response.StatusCode -eq 200) {
        $CertificateCollection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $DERCertificate = [System.Convert]::FromBase64String(($Response.Content | ConvertFrom-Bytes))
        $CertificateCollection.Import($DERCertificate)

        Return $CertificateCollection
    } Else {
        throw "$($MyInvocation.MyCommand): Failed to get root CA. Status code: $($Response.StatusCode)"
    }
}