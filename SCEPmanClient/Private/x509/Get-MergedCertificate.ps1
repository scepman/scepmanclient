<#
.SYNOPSIS
    Merges a certificate with a private key.

.DESCRIPTION
    Merges a certificate with a private key. The private key must be in the form of a RSACryptoServiceProvider or ECDsaCng object.

.PARAMETER Certificate
    The certificate to merge.

.PARAMETER PrivateKey
    The private key to merge.

.OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2
#>

Function Get-MergedCertificate {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)]
        $PrivateKey
    )

    $CertificateCollection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    $CertificateCollection.Import($Certificate.RawData)

    If ($PrivateKey.SignatureAlgorithm -in ('RSA', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1')) {
        Write-Verbose "$($MyInvocation.MyCommand): Merging certificate with RSA private key"
        $MergedCertificate = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($CertificateCollection[0], $PrivateKey)
    } ElseIf ($PrivateKey.SignatureAlgorithm -eq 'ECDSA') {
        Write-Verbose "$($MyInvocation.MyCommand): Merging certificate with ECDSA private key"
        $MergedCertificate = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($CertificateCollection[0], $PrivateKey)
    } Else {
        throw "Unsupported signature algorithm $($PrivateKey.SignatureAlgorithm)"
    }

    Return $MergedCertificate
}