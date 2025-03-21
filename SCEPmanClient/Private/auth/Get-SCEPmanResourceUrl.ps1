<#
.SYNOPSIS
    Get the ClientId of the Enterprise Application for the given AppServiceUrl

.DESCRIPTION
    This function queries all available Entra Enterprise Applications and returns the ClientId of the application that matches the AppServiceUrl

.PARAMETER Url
    The URL of the AppService that is used to find the Enterprise Application

.OUTPUTS
    System.String Get-SCEPmanResourceUrl returns the ClientId of the Enterprise Application
#>

Function Get-SCEPmanResourceUrl {
    [CmdletBinding()]
    [OutputType([String])]
    Param(
        [Parameter(Mandatory)]
        [Alias('AppServiceUrl')]
        [String]$Url
    )

    Write-Verbose "$($MyInvocation.MyCommand): Try to find ClientId of Enterprise Application for URL: $Url"

    # Strip the url from protocol and trailing slashes
    $Url = $Url -replace '/+$'
    $Url = $Url -replace '^https?://'

    Write-Verbose "$($MyInvocation.MyCommand): Stripped URL: $Url"

    $Application = Get-AzADApplication | Where-Object { $_.Web.HomePageUrl -match 'scepman.coni.rocks' }

    If (-not $Application) {
        Write-Error "$($MyInvocation.MyCommand): No application found for AppServiceUrl: $Url - Please check the Home Page URL of the app registration"
    }

    If ($Application.GetType().Name -ne 'MicrosoftGraphApplication') {
        Write-Verbose "$($MyInvocation.MyCommand): Found applications: $($Application.DisplayName)"
        throw "$($MyInvocation.MyCommand): Found multiple applications matching the AppServiceUrl: $Url"
    }

    Write-Verbose "$($MyInvocation.MyCommand): Found application: $($Application.DisplayName) with ClientId $($Application.AppId)"
    Return "api://$($Application.AppId)"
}