<#
.SYNOPSIS
    Creates an ephemeral self-signed certificate from a CertificateRequest for SCEP enrollment.

.DESCRIPTION
    Creates a short-lived self-signed X509Certificate2 from a CertificateRequest object.
    Used as the signer certificate for initial SCEP enrollment (PKCSReq, messageType 19)
    where no existing certificate is available.

.PARAMETER CertificateRequest
    The CertificateRequest object containing the private key.

.OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2
        A self-signed certificate with HasPrivateKey = true and 1-day validity.

.EXAMPLE
    $SelfSigned = New-SelfSignedCertificateForSCEP -CertificateRequest $Request
#>

Function New-SelfSignedCertificateForSCEP {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    Param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.CertificateRequest]$CertificateRequest
    )

    Write-Verbose "$($MyInvocation.MyCommand): Creating self-signed certificate for SCEP enrollment"

    $NotBefore = [System.DateTimeOffset]::UtcNow
    $NotAfter = $NotBefore.AddDays(1)

    $SelfSignedCert = $CertificateRequest.CreateSelfSigned($NotBefore, $NotAfter)

    Write-Verbose "$($MyInvocation.MyCommand): Created self-signed certificate: $($SelfSignedCert.Subject) (Thumbprint: $($SelfSignedCert.Thumbprint))"

    Return $SelfSignedCert
}
