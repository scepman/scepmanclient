Function Get-AppServiceUrlFromCertificate {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    If ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Verbose "$($MyInvocation.MyCommand): PowerShell version is less than 7, extract AIA extension from certificate extensions"

        $AiaExtension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.5.5.7.1.1' }

        If ($null -eq $AiaExtension) {
            throw "$($MyInvocation.MyCommand): Certificate does not have an AIA extension to infer AppServiceUrl from."
        }

        $Encoding = New-Object System.Text.UTF8Encoding
        $AppServiceUrl = [Regex]::Match($Encoding.GetString($AiaExtension.RawData), 'https://.*?GetCACert').Value

        if ([string]::IsNullOrEmpty($AppServiceUrl)) {
            throw "$($MyInvocation.MyCommand): Certificate does not have any CA Issuers URLs in the AIA extension to infer AppServiceUrl from."
        }
    } else {
        $AiaExtension = $Certificate.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509AuthorityInformationAccessExtension] }
        if ($null -eq $AiaExtension) {
            throw "$($MyInvocation.MyCommand): Certificate does not have an AIA extension to infer AppServiceUrl from."
        }

        $CaUrls = $AiaExtension.EnumerateCAIssuersUris()
        if ($CaUrls.Count -eq 0) {
            throw "$($MyInvocation.MyCommand): Certificate does not have any CA Issuers URLs in the AIA extension to infer AppServiceUrl from."
        }

        $AppServiceUrl = $CaUrls[0]
    }

        Write-Verbose "$($MyInvocation.MyCommand): Found AIA CA URL in certificate: $AppServiceUrl"

        $AppServiceUrl = $AppServiceUrl.Substring(0, $AppServiceUrl.IndexOf('/', "https://".Length))

        Write-Verbose "$($MyInvocation.MyCommand): Inferred AppServiceUrl from AIA extension: $AppServiceUrl"

        Return $AppServiceUrl
}