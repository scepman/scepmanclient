<#
.SYNOPSIS
    Encrypts a message using the PKCS#7 enveloped data format.

.DESCRIPTION
    Encrypts a message using the PKCS#7 enveloped data format. The message is encrypted using the public key of the recipient certificate.

.PARAMETER RecipientCertificate
    The certificate of the recipient.

.PARAMETER Message
    The message to encrypt.

.OUTPUTS
    Byte[]
        The encrypted message.

.EXAMPLE
    $RecipientCertificate = Get-ChildItem -Path 'Cert:\CurrentUser\My' | Where-Object { $_.Subject -eq 'CN=Recipient' }
    $Message = [System.Text.Encoding]::UTF8.GetBytes('Hello, World!')
    $EncryptedMessage = New-Pkcs7EnvelopedData -RecipientCertificate $RecipientCertificate -Message $Message
#>

Function New-Pkcs7EnvelopedData {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$RecipientCertificate,
        [Parameter(Mandatory)]
        [Byte[]]$Message
    )
    Write-Verbose "$($MyInvocation.MyCommand): Encrypting message for $($RecipientCertificate.Subject)"

    $ContentInfo = [System.Security.Cryptography.Pkcs.ContentInfo]::new($Message)
    $EnvelopedCms = [System.Security.Cryptography.Pkcs.EnvelopedCms]::new($ContentInfo)

    $CmsRecipient = [System.Security.Cryptography.Pkcs.CmsRecipient]::new($RecipientCertificate)

    $EnvelopedCms.Encrypt($CmsRecipient)

    Return $EnvelopedCms.Encode()
}