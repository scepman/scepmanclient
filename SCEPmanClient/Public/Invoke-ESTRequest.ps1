Function Invoke-ESTRequest {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$AppServiceUrl,
        [Parameter()]
        [String]$Endpoint = '/.well-known/est/simpleenroll',
        [Parameter(Mandatory)]
        [String]$AccessToken,
        [Parameter(Mandatory)]
        [String]$Request
    )

    $Headers = @{
        'Authorization' = "Bearer $AccessToken"
        'Content-Type' = 'application/pkcs10'
    }

    $Uri = ($AppServiceUrl -replace '/$') + $Endpoint

    Write-Verbose "$($MyInvocation.MyCommand): Sending EST request to $Uri"
    $Response = Invoke-WebRequest -Uri $Uri -Method POST -Headers $Headers -Body $Request

    If ($Response.StatusCode -eq 200) {
        $CertificateCollection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $DERCertificate = [System.Convert]::FromBase64String(($Response.Content | ConvertFrom-Bytes))
        $CertificateCollection.Import($DERCertificate)

        Return $CertificateCollection
    } Else {
        throw "$($MyInvocation.MyCommand): SCEPman EST Request failed: $($Response.StatusCode)"
    }
}