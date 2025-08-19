<#
.SYNOPSIS
    Expand a given JWT to check its validity and extract claims.

.DESCRIPTION
    This function takes a JWT, tries to decode and validate it and extracts the claims.

.PARAMETER Token
    The JWT to expand.

.OUTPUTS
    PSCustomObject containing the payload if the token is valid and unencrypted.
    Returns $null if the token is invalid
    Returns 'JWE' if the token is encrypted
#>

Function Expand-JWT {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$Token
    )

    # According to RFC7519 Section 7.2.1
    # Validate that the JWT contains at least one period
    If ([Regex]::Count($Token, '\.') -eq 0) {
        Write-Verbose "$($MyInvocation.MyCommand): The given token does not contain any periods. Invalid"
        Return $null
    }

    # 7.2.2 - 7.2.4
    # Extract the first encoded part of the JWT, padding it if necessary and decode it
    Try {
        $JoseHeader = $Token -split '\.' | Select-Object -Index 0 | Get-PaddedBase64 | ConvertFrom-Base64 | ConvertFrom-Json
    } Catch {
        Write-Verbose "$($MyInvocation.MyCommand): Could not decode JWT header."
        Write-Verbose "$($MyInvocation.MyCommand): $($_.Exception.Message)"
        Return $null
    }

    # Check if we have a JWT or JWE (RFC 7516)
    If ($JoseHeader.PSObject.Properties.Name -contains 'enc') {
        Write-Verbose "$($MyInvocation.MyCommand): Found JWE header."
        Return $null
    }

    # Extract the payload, pad it and decode it
    # The unserialized object will be returned
    Try {
        $Payload = $Token -split '\.' | Select-Object -Index 1 | Get-PaddedBase64 | ConvertFrom-Base64 | ConvertFrom-Json
    } Catch {
        Write-Verbose "$($MyInvocation.MyCommand): Could not decode JWT payload."
        Write-Verbose "$($MyInvocation.MyCommand): $($_.Exception.Message)"
        Return $null
    }

    Return $Payload
}