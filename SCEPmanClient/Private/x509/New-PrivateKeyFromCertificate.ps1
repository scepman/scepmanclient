Function New-PrivateKeyFromCertificate {
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