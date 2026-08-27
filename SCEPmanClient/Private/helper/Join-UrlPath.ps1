<#
.SYNOPSIS
    Joins a base URL and an endpoint path into a single, well-formed URI.

.DESCRIPTION
    Ensures exactly one '/' separates the base URL and the endpoint, regardless of
    whether either value already has leading/trailing slashes.

.PARAMETER Url
    The base URL.

.PARAMETER Endpoint
    The endpoint path to append to the URL.

.OUTPUTS
    A string

.EXAMPLE
    Join-UrlPath -Url 'https://contoso.com/' -Endpoint 'static/aad'
#>
Function Join-UrlPath {
    Param(
        [Parameter(Mandatory)]
        [String]$Url,
        [Parameter(Mandatory)]
        [String]$Endpoint
    )

    Return ($Url -replace '/$') + '/' + ($Endpoint -replace '^/')
}
