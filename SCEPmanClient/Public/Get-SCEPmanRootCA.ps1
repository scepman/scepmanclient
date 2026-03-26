<#
    .SYNOPSIS
    Get the root CA certificate from SCEPman.

    .PARAMETER Url
    The URL of the SCEPman app service.

    .PARAMETER Endpoint
    The endpoint to get the root CA certificate from. Default is '/.well-known/est/cacerts'.

    .EXAMPLE
    Get-SCEPmanRootCA -AppServiceUrl 'https://scepman.contoso.com'

    .OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2Collection
#>

Function Get-SCEPmanRootCA {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2Collection])]
    Param(
        [Parameter(Mandatory)]
        [Alias('AppServiceUrl')]
        [String]$Url,
        [String]$Endpoint = '/ca'
    )

    $Uri = $Uri = ($Url -replace '/$') + $Endpoint

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