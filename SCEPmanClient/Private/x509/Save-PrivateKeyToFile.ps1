<#
.SYNOPSIS
    Saves a private key to a file.

.DESCRIPTION
    Saves a private key to a file. The private key can be encrypted with a password.

.PARAMETER PrivateKey
    The private key to save.

.PARAMETER EncryptionAlgorithm
    The encryption algorithm to use when encrypting the private key.

.PARAMETER HashingAlgorithm
    The hashing algorithm to use when encrypting the private key.

.PARAMETER IterationCount
    The number of iterations to use when encrypting the private key.

.PARAMETER Password
    The password to use when encrypting the private key.

.PARAMETER FilePath
    The path to save the private key to.

.EXAMPLE
    Save-PrivateKeyToFile -PrivateKey $PrivateKey -FilePath 'C:\Temp\PrivateKey.pem'
    Saves the private key to 'C:\Temp\PrivateKey.pem'.
#>

Function Save-PrivateKeyToFile {
    Param (
        [Parameter(Mandatory)]
        $PrivateKey,

        [ValidateSet('Aes128Cbc', 'Aes192Cbc', 'Aes256Cbc', 'TripleDes3KeyPkcs12')]
        $EncryptionAlgorithm = 'Aes256Cbc',

        [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512')]
        $HashingAlgorithm = 'SHA256',

        $IterationCount = 20000,

        [SecureString]$Password,

        [String]$FilePath
    )

    If ($PSVersionTable.PSVersion.Major -lt 7) {
        throw "$($MyInvocation.MyCommand): Exporting certificates to file is only supported on PowerShell 7 and later"
    }

    If ($PSBoundParameters.ContainsKey('Password')) {
        Write-Verbose "$($MyInvocation.MyCommand): Exporting private key with password"
        $EncryptionAlgorithm = [System.Security.Cryptography.PbeEncryptionAlgorithm]::$EncryptionAlgorithm
        $HashingAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::$HashingAlgorithm

        $PbeParameters = [System.Security.Cryptography.PbeParameters]::new($EncryptionAlgorithm, $HashingAlgorithm, $IterationCount)

        $FileContent = $PrivateKey.ExportEncryptedPkcs8PrivateKeyPem(($Password | ConvertFrom-SecureString -AsPlainText), $PbeParameters)

    } Else {
        Write-Verbose "$($MyInvocation.MyCommand): Exporting private key without password"
        $FileContent = $PrivateKey.ExportPkcs8PrivateKeyPem()
    }

    Set-Content -Path $FilePath -Value $FileContent
    Write-Verbose "$($MyInvocation.MyCommand): Successfully saved private key to $FilePath"
}