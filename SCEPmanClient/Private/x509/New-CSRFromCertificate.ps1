<#
.SYNOPSIS
    Creates a new Certificate Signing Request (CSR) from a certificate.

.DESCRIPTION
    This function creates a new Certificate Signing Request (CSR) from a certificate. The CSR will have the same subject as the certificate and the same extended key usage as the certificate.

.PARAMETER Certificate
    The certificate to create the CSR from.

.PARAMETER PrivateKey
    The private key to use for the CSR.

.OUTPUTS
    System.Security.Cryptography.Pkcs.Pkcs10CertificationRequest
#>

Function New-CSRFromCertificate {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)]
        $PrivateKey
    )

    $Subject = $Certificate.Subject

    $EKUExtension = $Certificate.Extensions | Where-Object {$_.Oid.value -eq '2.5.29.37'}

    $Oid = $EKUExtension.EnhancedKeyUsages.Value

    Return New-CSR -Subject $Subject -ExtendedKeyUsageOid $Oid -PrivateKey $PrivateKey
}