<#
.SYNOPSIS
    Enrolls a new certificate using SCEP (PKCSReq).

.DESCRIPTION
    Performs initial SCEP enrollment using PKCSReq (messageType 19). Unlike SCEP renewal,
    no existing certificate is needed — a self-signed certificate is created from the
    request's key pair to act as the PKCS#7 signer.

.PARAMETER Url
    The URL of the SCEP server.

.PARAMETER Endpoint
    The endpoint of the SCEP server.

.PARAMETER RecipientCertificate
    The Root CA certificate used to encrypt the SCEP request.

.PARAMETER RawRequest
    The raw certificate request (CertificateRequest object).

.OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2Collection
#>

Function Invoke-SCEPEnrollment {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$Url,
        [String]$Endpoint = '/static',
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$RecipientCertificate,
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.CertificateRequest]$RawRequest
    )

    $SelfSignedCert = New-SelfSignedCertificateForSCEP -CertificateRequest $RawRequest

    $EnvelopedData = New-Pkcs7EnvelopedData -RecipientCertificate $RecipientCertificate -Message ($RawRequest.CreateSigningRequest())
    $SignedMessage = New-Pkcs7SignedMessage -SignerCertificate $SelfSignedCert -Message $EnvelopedData -MessageType '19'

    $WebClient = New-Object System.Net.WebClient

    $Uri = ($Url -replace '/$') + $Endpoint

    Write-Verbose "$($MyInvocation.MyCommand): Sending SCEP enrollment request to $Uri"

    Try {
        $Response = $WebClient.UploadData($Uri, $SignedMessage)
    } Catch {
        Throw "$($MyInvocation.MyCommand): SCEP enrollment failed on Uri $Uri with error: $($_.Exception.Message) - Please check the SCEP endpoints configuration"
    }

    Return Get-CertificateFromSCEPResponse -SCEPResponse $Response -SignerCertificate $RecipientCertificate -RecipientCertificate $SelfSignedCert
}
