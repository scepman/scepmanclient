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