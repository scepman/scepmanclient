Function Save-CertificateToStore {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)]
        $PrivateKey,
        [Parameter(Mandatory)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [String]$StoreName,

        [Switch]$Exportable
    )

    Switch ($StoreName) {
        'CurrentUser' {
            Write-Verbose "$($MyInvocation.MyCommand): Preparing to save certificate to CurrentUser store"
            $KeyStorageFlag = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet
            $StorageLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        }
        'LocalMachine' {
            Write-Verbose "$($MyInvocation.MyCommand): Preparing to save certificate to LocalMachine store"
            $KeyStorageFlag = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
            $StorageLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        }
    }

    $CertificateCollection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    $CertificateCollection.Import($Certificate.RawData, $null, $KeyStorageFlag)

    If ($PrivateKey.SignatureAlgorithm -in ('RSA', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1')) {
        Write-Verbose "$($MyInvocation.MyCommand): Merging certificate with RSA private key"
        $MergedCertificate = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($CertificateCollection[0], $PrivateKey)
    } ElseIf ($PrivateKey.SignatureAlgorithm -eq 'ECDSA') {
        Write-Verbose "$($MyInvocation.MyCommand): Merging certificate with ECDSA private key"
        $MergedCertificate = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($CertificateCollection[0], $PrivateKey)        
    } Else {
        throw "Unsupported signature algorithm $($PrivateKey.SignatureAlgorithm)"
    }

    $TemporaryPassword = New-RandomPassword

    Write-Verbose "$($MyInvocation.MyCommand): Exporting certificate and private key to PFX bundle"
    $PfxBundle = $MergedCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $TemporaryPassword)

    If ($PSBoundParameters.ContainsKey('Exportable')) {
        $KeyStorageFlags = $KeyStorageFlag -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    } Else {
        $KeyStorageFlags = $KeyStorageFlag -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
    }

    $IssuedCertificateAndKey = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxBundle, $TemporaryPassword, $KeyStorageFlags)

    Write-Verbose "$($MyInvocation.MyCommand): Opening certificate store at $StorageLocation"
    $CertificateStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("My", $StorageLocation)
    $CertificateStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)

    Write-Verbose "$($MyInvocation.MyCommand): Adding certificate to store"
    $CertificateStore.Add($IssuedCertificateAndKey)

    $CertificateStore.Close()
    $CertificateStore.Dispose()
}