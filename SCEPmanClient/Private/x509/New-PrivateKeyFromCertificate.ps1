<#
.SYNOPSIS
    Creates a new private key based on the public key of a certificate.

.DESCRIPTION
    This function creates a new private key based on the public key of a certificate. The function supports RSA and ECDSA keys.

.PARAMETER Certificate
    The certificate to create the private key from.

.OUTPUTS
    System.Security.Cryptography.RSACng or System.Security.Cryptography.ECDsaCng
#>

Function New-PrivateKeyFromCertificate {
    [Diagnostics.CodeAnalysis.SuppressMessage("PSShouldProcess", "", Justification = "Function does not change system state or interact with external systems.")]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    If ($Certificate.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1') {
        $PrivateKey = New-PrivateKey -Algorithm RSA -KeySize $Certificate.PublicKey.Key.KeySize

    } ElseIf ($Certificate.PublicKey.Oid.Value -eq '1.2.840.10045.2.1') {
        $PrivateKey = New-PrivateKey -Algorithm ECDSA -ECCurve $Certificate.PublicKey.Key.ExportParameters().Curve

    } Else {
        throw "$($MyInvocation.MyCommand): Unsupported key algorithm: $($Certificate.PublicKey.Oid.Value) ($($Certificate.PublicKey.Oid.FriendlyName))"
    }

    Return $PrivateKey
}