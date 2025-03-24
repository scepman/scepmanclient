<#
.SYNOPSIS
    Renews a certificate using SCEP.

.DESCRIPTION
    Renews a certificate using SCEP. The SCEP renewal request is a PKCS#10 certificate request that is signed and encrypted using the recipient's certificate.

.PARAMETER Url
    The URL of the SCEP server.

.PARAMETER Endpoint
    The endpoint of the SCEP server.

.PARAMETER SignerCertificate
    The certificate of the signer that signs the SCEP renewal request.

.PARAMETER RecipientCertificate
    The certificate of the recipient that will decrypt the SCEP renewal request.

.PARAMETER RawRequest
    The raw certificate request.

.OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2Collection
#>

Function Invoke-SCEPRenewal {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$Url,
        [String]$Endpoint = '/static',
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$SignerCertificate,
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$RecipientCertificate,
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.CertificateRequest]$RawRequest
    )

    $EnvelopedData = New-Pkcs7EnvelopedData -RecipientCertificate $RecipientCertificate -Message ($RawRequest.CreateSigningRequest())
    $SignedMessage = New-Pkcs7SignedMessage -SignerCertificate $SignerCertificate -Message $EnvelopedData

    $WebClient = New-Object System.Net.WebClient

    $Uri = ($Url -replace '/$') + $Endpoint

    Write-Verbose "$($MyInvocation.MyCommand): Sending SCEP renewal request to $Uri"
    $Response = $WebClient.UploadData($Uri, $SignedMessage)

    Return Get-CertificateFromSCEPResponse -SCEPResponse $Response -SignerCertificate $RecipientCertificate -RecipientCertificate $SignerCertificate
}