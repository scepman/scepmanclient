Function Get-SCEPmanResourceUrl {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$AppServiceUrl
    )

    Write-Verbose "$($MyInvocation.MyCommand): Try to find ClientId of Enterprise Application for URL: $AppServiceUrl"

    # Strip the url from protocol and trailing slashes
    $AppServiceUrl = $AppServiceUrl -replace '/+$'
    $AppServiceUrl = $AppServiceUrl -replace '^https?://'

    Write-Verbose "$($MyInvocation.MyCommand): Stripped URL: $AppServiceUrl"

    $Application = Get-AzADApplication | Where-Object { $_.Web.HomePageUrl -match 'scepman.coni.rocks' }

    If ($Application.GetType().Name -ne 'MicrosoftGraphApplication') {
        Write-Verbose "$($MyInvocation.MyCommand): Found applications: $($Application.DisplayName)"
        throw "$($MyInvocation.MyCommand): Found multiple applications matching the AppServiceUrl: $AppServiceUrl"
    }

    Write-Verbose "$($MyInvocation.MyCommand): Found application: $($Application.DisplayName) with ClientId $($Application.AppId)"
    Return "api://$($Application.AppId)"
}