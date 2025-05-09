<#
.SYNOPSIS
    Saves a certificate to the Windows certificate store.

.DESCRIPTION
    Saves an X.509 certificate and its private key to the Windows certificate store, supporting both `CurrentUser` and `LocalMachine` stores. The function merges the certificate with the private key, handles RSA and ECDSA algorithms, and optionally allows the private key to be exportable. It ensures proper cryptographic handling and provides verbose output for tracing operations.

.PARAMETER Certificate
    The X.509 certificate to save to the store.

.PARAMETER PrivateKey
    The private key to merge with the certificate.

.PARAMETER StoreName
    The name of the certificate store to save the certificate to. Supported values are `CurrentUser` and `LocalMachine`.

.PARAMETER Exportable
    Indicates whether the private key should be exportable.

.PARAMETER UserProtected
    Indicates whether the private key should be user-protected. This will prompt the user for a confirmation or password when accessing the private key.

.EXAMPLE
    Save-CertificateToStore -Certificate $Certificate -PrivateKey $PrivateKey -StoreName 'CurrentUser'
    Saves the specified certificate and private key to the CurrentUser certificate store.
#>

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

        [Switch]$Exportable,
        [Switch]$UserProtected
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
        $MergedCertificate = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($CertificateCollection[0], $PrivateKey)
    } ElseIf ($PrivateKey.SignatureAlgorithm -eq 'ECDSA') {
        $MergedCertificate = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($CertificateCollection[0], $PrivateKey)
    } Else {
        throw "Unsupported signature algorithm $($PrivateKey.SignatureAlgorithm)"
    }

    $TemporaryPassword = New-RandomPassword

    $PfxBundle = $MergedCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $TemporaryPassword)

    $KeyStorageFlags = $KeyStorageFlag -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet

    If ($PSBoundParameters.ContainsKey('Exportable')) {
        $KeyStorageFlags = $KeyStorageFlags -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    }

    If ($PSBoundParameters.ContainsKey('UserProtected')) {
        $KeyStorageFlags = $KeyStorageFlags -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserProtected
    }


    $IssuedCertificateAndKey = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxBundle, $TemporaryPassword, $KeyStorageFlags)

    $CertificateStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("My", $StorageLocation)
    $CertificateStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)

    Write-Verbose "$($MyInvocation.MyCommand): Adding certificate to store"
    $CertificateStore.Add($IssuedCertificateAndKey)

    $CertificateStore.Close()
    $CertificateStore.Dispose()
}