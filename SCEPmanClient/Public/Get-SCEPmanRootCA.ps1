<#
    .SYNOPSIS
    Get the root CA certificate from SCEPman.

    .DESCRIPTION
    Gets the root CA certificate from the SCEPman CA endpoint.

    .PARAMETER Url
    The URL of the SCEPman service.

    .EXAMPLE
    Get-SCEPmanRootCA -AppServiceUrl 'https://scepman.example.com'

    .OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2Collection
#>

Function Get-SCEPmanRootCA {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2Collection])]
    Param(
        [Parameter(Mandatory)]
        [Alias('AppServiceUrl')]
        [String]$Url
    )

    $Uri = Join-UrlPath -Url $Url -Endpoint '/ca'

    Write-Verbose "$($MyInvocation.MyCommand): Getting root CA from $Uri"
    $Response = Invoke-WebRequest -Uri $Uri -Method GET

    If ($Response.StatusCode -eq 200) {
        $CertificateCollection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $CertificateCollection.Import($Response.Content)

        Return $CertificateCollection
    } Else {
        throw "$($MyInvocation.MyCommand): Failed to get root CA. Status code: $($Response.StatusCode)"
    }
}