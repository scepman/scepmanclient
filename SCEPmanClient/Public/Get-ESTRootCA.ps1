Function Get-ESTRootCA {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$AppServiceUrl,
        [String]$Endpoint = '/.well-known/est/cacerts'
    )

    $Uri = $Uri = ($AppServiceUrl -replace '/$') + $Endpoint

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