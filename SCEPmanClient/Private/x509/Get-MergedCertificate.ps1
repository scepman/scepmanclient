<#
.SYNOPSIS
    Merges a certificate with a private key.

.DESCRIPTION
    Merges a certificate with a private key. If a certificate chain is provided, the certificate whose public key matches the private key is selected.

.PARAMETER Certificate
    The certificate to merge.

.PARAMETER PrivateKey
    The private key to merge.

.OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2
#>

Function Get-MergedCertificate {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    Param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificate,
        [Parameter(Mandatory)]
        $PrivateKey
    )

    $SignatureAlgorithm = $PrivateKey.SignatureAlgorithm
    If ($SignatureAlgorithm -notin ('RSA', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1', 'ECDSA')) {
        throw "Unsupported signature algorithm $($PrivateKey.SignatureAlgorithm)"
    }

    foreach ($Candidate in $Certificate) {
        $PublicCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Candidate.RawData)

        Try {
            If ($SignatureAlgorithm -in ('RSA', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1')) {
                Write-Verbose "$($MyInvocation.MyCommand): Trying to merge certificate $($Candidate.Thumbprint) with RSA private key"
                Return [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($PublicCertificate, $PrivateKey)
            }

            Write-Verbose "$($MyInvocation.MyCommand): Trying to merge certificate $($Candidate.Thumbprint) with ECDSA private key"
            Return [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($PublicCertificate, $PrivateKey)
        } Catch [System.ArgumentException] {
            Write-Verbose "$($MyInvocation.MyCommand): Certificate $($Candidate.Thumbprint) does not match the private key"
        }
    }

    throw "$($MyInvocation.MyCommand): None of the returned certificates matches the private key."
}