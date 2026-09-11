<#
.SYNOPSIS
    Joins a base URL and an endpoint path into a single, well-formed URI.

.DESCRIPTION
    Defaults scheme-less URLs to HTTPS and ensures exactly one '/' separates the
    base URL and endpoint. Explicit HTTP and HTTPS schemes are preserved.

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

    If ($Url -notmatch '^https?://') {
        $Url = 'https://' + $Url
    }

    Return ($Url -replace '/$') + '/' + ($Endpoint -replace '^/')
}
