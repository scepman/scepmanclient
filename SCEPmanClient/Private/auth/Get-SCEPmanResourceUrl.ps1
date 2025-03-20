<#
.SYNOPSIS
    Get the ClientId of the Enterprise Application for the given AppServiceUrl

.DESCRIPTION
    This function queries all available Entra Enterprise Applications and returns the ClientId of the application that matches the AppServiceUrl

.PARAMETER AppServiceUrl
    The URL of the AppService that is used to find the Enterprise Application

.OUTPUTS
    System.String Get-SCEPmanResourceUrl returns the ClientId of the Enterprise Application
#>

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