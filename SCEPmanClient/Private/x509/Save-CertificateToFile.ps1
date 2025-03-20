<#
.SYNOPSIS
    Saves a certificate to a file.

.DESCRIPTION
    Saves a certificate to a file in either DER or PEM format. If the format is PEM, the certificate is saved in the PEM format used by OpenSSL.

.PARAMETER Certificate
    The certificate to save.

.PARAMETER FilePath
    The path to save the certificate to. The file extension is automatically added based on the format.

.PARAMETER Format
    The format to save the certificate in. Supported values are 'DER' and 'PEM'. The default is 'PEM'.

.EXAMPLE
    Save-CertificateToFile -Certificate $Certificate -FilePath 'C:\path\to\certificate' -Format 'DER'
    Saves the certificate to 'C:\path\to\certificate.cer' in DER format.

.EXAMPLE
    Save-CertificateToFile -Certificate $Certificate -FilePath 'C:\path\to\certificate' -Format 'PEM'
    Saves the certificate to 'C:\path\to\certificate.pem' in PEM format.

#>

Function Save-CertificateToFile {
    Param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)]
        [String]$FilePath,
        [ValidateSet('DER', 'PEM')]
        [String]$Format = 'PEM'
    )

    If ($PSVersionTable.PSVersion.Major -lt 7 -and $Format -eq 'PEM') {
        throw "$($MyInvocation.MyCommand): Exporting certificates to PEM format is only supported on PowerShell 7 and later"
    }

    If ($Format -eq 'DER') {
        $FilePath = $FilePath + '.cer'
        $DER = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        Write-Verbose "$($MyInvocation.MyCommand): Successfully saved DER certificate to $FilePath"
        [System.IO.File]::WriteAllBytes($FilePath, $DER)
    } ElseIf ($Format -eq 'PEM') {
        $FilePath = $FilePath + '.pem'
        $PEM = $Certificate.ExportCertificatePem()
        Set-Content -Path $FilePath -Value $PEM
        Write-Verbose "$($MyInvocation.MyCommand): Successfully saved PEM certificate to $FilePath"
    } Else {
        throw "$($MyInvocation.MyCommand): Unsupported format $Format"
    }
}