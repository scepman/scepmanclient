<#
.SYNOPSIS
    Signs a message using the PKCS#7 signed data format.

.DESCRIPTION
    Signs a message using the PKCS#7 signed data format. The message is signed using the private key of the signer certificate.
    Additional attributes are added to the signed message to comply with RFC 8894 (SCEP PKIMessage).
    https://www.rfc-editor.org/rfc/rfc8894.html#name-scep-pkimessage

.PARAMETER SignerCertificate
    The certificate of the signer.

.PARAMETER Message
    The message to sign.

.OUTPUTS
    Byte[]
        The signed message.

.EXAMPLE
    $SignerCertificate = Get-ChildItem -Path 'Cert:\CurrentUser\My' | Where-Object { $_.Subject -eq 'CN=Signer' }
    $Message = [System.Text.Encoding]::UTF8.GetBytes('Hello, World!')
    $SignedMessage = New-Pkcs7SignedMessage -SignerCertificate $SignerCertificate -Message $Message
#>

Function New-Pkcs7SignedMessage {
    [Diagnostics.CodeAnalysis.SuppressMessage("PSShouldProcess", "", Justification = "Function does not change system state or interact with external systems.")]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$SignerCertificate,
        [Parameter(Mandatory)]
        [Byte[]]$Message

    )
    Write-Verbose "$($MyInvocation.MyCommand): Signing message using $($SignerCertificate.Subject)"

    $CmsSigner = [System.Security.Cryptography.Pkcs.CmsSigner]::new($SignerCertificate)
    $CmsSigner.DigestAlgorithm = $constant_MD5Oid

    $MessageTypeBody = ([System.Text.Encoding]::ASCII).GetBytes('17')
    $MessageTypeHeader = [Byte[]]@([Byte]19, [Byte]$MessageTypeBody.Length)
    $MessageTypeData = $MessageTypeHeader + $MessageTypeBody
    $MessageTypeAttribute = [System.Security.Cryptography.AsnEncodedData]::new($constant_MessageTypeOid, $MessageTypeData)

    $CmsSigner.SignedAttributes.Add($MessageTypeAttribute) | Out-Null

    $Sha = New-Object System.Security.Cryptography.SHA512Managed
    $HashedKey = $Sha.ComputeHash($SignerCertificate.GetPublicKey())
    $HashedKeyString = [System.Convert]::ToBase64String($HashedKey)

    $TransactionIdBody = ([System.Text.Encoding]::ASCII).GetBytes($HashedKeyString)
    $TransactionIdHeader = [Byte[]]@([Byte]19, [Byte]$TransactionIdBody.Length)
    $TransactionIdData = $TransactionIdHeader + $TransactionIdBody
    $TransactionIdAttribute = [System.Security.Cryptography.Pkcs.Pkcs9AttributeObject]::new($constant_TransactionIdOid, $TransactionIdData)

    $CmsSigner.SignedAttributes.Add($TransactionIdAttribute) | Out-Null

    $LastSenderNonce = New-Object Byte[] 16
    [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($LastSenderNonce)
    $SenderNonceHeader = [Byte[]]@([Byte]4, [Byte]$LastSenderNonce.Length)
    $SenderNonceData = $SenderNonceHeader + $LastSenderNonce
    $SenderNonceAttribute = [System.Security.Cryptography.Pkcs.Pkcs9AttributeObject]::new($constant_SenderNonceOid, $SenderNonceData)

    $CmsSigner.SignedAttributes.Add($SenderNonceAttribute) | Out-Null

    $SignedContentInfo = [System.Security.Cryptography.Pkcs.ContentInfo]::new($Message)
    $SignedMessage = [System.Security.Cryptography.Pkcs.SignedCms]::new($SignedContentInfo)

    $SignedMessage.ComputeSignature($CmsSigner)

    Return $SignedMessage.Encode()
}
