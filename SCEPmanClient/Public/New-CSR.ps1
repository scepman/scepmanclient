<#
.SYNOPSIS
    Create a new certificate signing request (CSR) using the specified parameters.

.DESCRIPTION
    Create a new certificate signing request (CSR) using the specified parameters.

.PARAMETER Subject
    The subject name of the certificate request.

.PARAMETER ExtendedKeyUsage
    The extended key usage of the certificate request.

.PARAMETER ExtendedKeyUsageOid
    The extended key usage OID of the certificate request.

.PARAMETER KeyUsage
    The key usage of the certificate request.

.PARAMETER KeyUsageOid
    The key usage OID of the certificate request.

.PARAMETER PrivateKey
    The private key to use for the certificate request.

.PARAMETER HashingAlgorithm
    The hashing algorithm to use for the certificate request.

.PARAMETER IPAddress
    The IP addresses to add to the Subject Alternative Name extension.

.PARAMETER DNSName
    The DNS names to add to the Subject Alternative Name extension.

.PARAMETER Email
    The email addresses to add to the Subject Alternative Name extension.

.PARAMETER URI
    The URIs to add to the Subject Alternative Name extension.

.PARAMETER UPN
    The User Principal Names to add to the Subject Alternative Name extension.

.PARAMETER Raw
    Return the raw certificate request object instead of the base64 encoded string.

.EXAMPLE
    New-CSR -Subject 'CN=Test' -PrivateKey $PrivateKey
    Create a new certificate signing request for the subject 'CN=Test' using the specified private key.

.EXAMPLE
    New-CSR -Subject 'CN=Test' -PrivateKey $PrivateKey -ExtendedKeyUsage 'ClientAuth', 'ServerAuth' -KeyUsage 'DigitalSignature', 'KeyEncipherment' -IPAddress '10.11.0.11'
    Create a new certificate signing request for the subject 'CN=Test' using the specified private key with the specified extended key usage, key usage and IP address.
#>

Function New-CSR {
    Param(
        [Parameter(Mandatory)]
        [String]$Subject,

        [ValidateSet(
            'ClientAuth',
            'ServerAuth',
            'CodeSigning',
            'EmailProtection',
            'TimeStamping',
            'OCSPSigning',
            'SmartCardLogon',
            'EncryptFileSystem',
            'IPSecIKE',
            'PSecIKEIntermediate',
            'KDCAuth',
            'IpSecurityUser'
        )]
        [String[]]$ExtendedKeyUsage,
        [String[]]$ExtendedKeyUsageOid,


        [ValidateSet(
            'DigitalSignature',
            'NonRepudiation',
            'KeyEncipherment',
            'DataEncipherment',
            'KeyAgreement',
            'KeyCertSign',
            'CRLSign',
            'EncipherOnly',
            'DecipherOnly'
        )]
        [String[]]$KeyUsage,
        [String[]]$KeyUsageOid,

        [Parameter(Mandatory)]
        $PrivateKey,

        [ValidateSet(
            'SHA256',
            'SHA384',
            'SHA512'
        )]
        [String]$HashingAlgorithm = 'SHA256',

        [String[]]$IPAddress,
        [String[]]$DNSName,
        [String[]]$Email,
        [String[]]$URI,
        [String[]]$UPN,

        [Switch]$Raw
    )

    Write-Verbose "$($MyInvocation.MyCommand): Creating certificate request for $Subject"
    If ($PrivateKey.SignatureAlgorithm -in ('RSA', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1')) {
        $UsedAlgorithm = 'RSA'
        $Request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($Subject, $PrivateKey, [System.Security.Cryptography.HashAlgorithmName]::$HashingAlgorithm, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } ElseIf ($PrivateKey.SignatureAlgorithm -eq 'ECDSA') {
        $UsedAlgorithm = 'ECDSA'
        $Request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($Subject, $PrivateKey, [System.Security.Cryptography.HashAlgorithmName]::$HashingAlgorithm)
    } Else {
        throw "$($MyInvocation.MyCommand): Unsupported signature algorithm $($PrivateKey.SignatureAlgorithm)"
    }

    If ($KeyUsage) {
        $KeyUsage | ForEach-Object {
            Write-Verbose "$($MyInvocation.MyCommand): Adding Key Usage $_"
            $KeyUsageDefinition = $constant_KUDefinition[$_]
            If($KeyUsageDefinition.KeyTypes -notcontains $UsedAlgorithm) {
                Write-Verbose "$($MyInvocation.MyCommand): Key usage $_ is not supported for algorithm $UsedAlgorithm"
            } Else {
                $Extension = New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension
                $Oid = $constant_KUDefinition[$_].Oid
                $Extension.Oid = $Oid
                $Request.CertificateExtensions.Add($Extension)
            }
        }
    }

    If ($ExtendedKeyUsage -or $ExtendedKeyUsageOid) {
        $OidCollection = New-Object System.Security.Cryptography.OidCollection

        If ($ExtendedKeyUsage) {
            $ExtendedKeyUsage | ForEach-Object {
                Write-Verbose "$($MyInvocation.MyCommand): Adding Extended Key Usage $_"
                $Oid = New-Object System.Security.Cryptography.Oid $constant_EKUDefinition[$_]
    
                $OidCollection.Add($Oid) | Out-Null
            }
        } 

        If ($ExtendedKeyUsageOid) {
            $ExtendedKeyUsageOid | ForEach-Object {
                Write-Verbose "$($MyInvocation.MyCommand): Adding Extended Key Usage OID $_"
                $Oid = New-Object System.Security.Cryptography.Oid $_
    
                $OidCollection.Add($Oid) | Out-Null
            }
        }

        $EKUExtension = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension $OidCollection, $true
        $Request.CertificateExtensions.Add($EKUExtension)
    }

    If ($IPAddress -or $DNSName -or $Email -or $URI -or $UPN) {
        $SANBuilder = New-Object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder

        If($IPAddress) {
            $HasSAN = $true
            $IPAddress | ForEach-Object {
                Write-Verbose "$($MyInvocation.MyCommand): Adding IP address $_ to Subject Alternative Name extension"
                $SANBuilder.AddIpAddress($_)
            }
        }
    
        If($DNSName) {
            $DNSName | ForEach-Object {
                Write-Verbose "$($MyInvocation.MyCommand): Adding DNS name $_ to Subject Alternative Name extension"
                $SANBuilder.AddDnsName($_)
            }
        }
    
        If($Email) {
            $Email | ForEach-Object {
                Write-Verbose "$($MyInvocation.MyCommand): Adding email address $_ to Subject Alternative Name extension"
                $SANBuilder.AddEmailAddress($_)
            }
        }
    
        If($URI) {
            $URI | ForEach-Object {
                Write-Verbose "$($MyInvocation.MyCommand): Adding URI $_ to Subject Alternative Name extension"
                $SANBuilder.AddUri($_)
            }
        }
    
        If($UPN) {
            $UPN | ForEach-Object {
                Write-Verbose "$($MyInvocation.MyCommand): Adding User Principal Name $_ to Subject Alternative Name extension"
                $SANBuilder.AddUserPrincipalName($_)
            }
        }
    
        $SANExtension = $SANBuilder.Build()
        $Request.CertificateExtensions.Add($SANExtension)

    }

    If($Raw) {
        Return $Request
    } Else {
        Return [System.Convert]::ToBase64String($Request.CreateSigningRequest())
    }
}