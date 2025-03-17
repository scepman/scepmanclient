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