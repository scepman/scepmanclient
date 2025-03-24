<#
.SYNOPSIS
    Extracts a certificate from a SCEP response.

.DESCRIPTION
    Extracts a certificate from a SCEP response. The SCEP response is a PKCS#7 signed data structure that contains a PKCS#7 enveloped data structure that contains the certificate.

.PARAMETER SCEPResponse
    The SCEP response as a byte array.

.PARAMETER SignerCertificate
    The certificate of the signer that signed the SCEP response.

.PARAMETER RecipientCertificate
    The certificate of the recipient that will decrypt the SCEP response.

.OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2Collection
#>

Function Get-CertificateFromSCEPResponse {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [Byte[]]$SCEPResponse,
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$SignerCertificate,
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$RecipientCertificate
    )

    Write-Verbose "$($MyInvocation.MyCommand): Extracting certificate from SCEP response"

    $SignedCms = New-Object System.Security.Cryptography.Pkcs.SignedCms
    $SignedCms.Decode($SCEPResponse)

    $SignedCms.CheckSignature($SignerCertificate, $true)

    $EnvelopedCms = New-Object System.Security.Cryptography.Pkcs.EnvelopedCms

    $EnvelopedCms.Decode($SignedCms.ContentInfo.Content)

    Write-Verbose "$($MyInvocation.MyCommand): Decrypting envelope using $($RecipientCertificate.Subject)"
    $EnvelopedCms.Decrypt($RecipientCertificate)

    $CertificateCollection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    $CertificateCollection.Import($EnvelopedCms.ContentInfo.Content)

    Return $CertificateCollection
}