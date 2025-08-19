<#
.SYNOPSIS
    Get a bearer token for the SCEPman API.

.PARAMETER ResourceUrl
    The resource URL to get the token for. Default is the SCEPman API.

.OUTPUTS
    System.String
    The bearer token for the SCEPman API.
#>

Function Get-SCEPmanAccessToken {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$ResourceUrl
    )

    Try {
        Write-Verbose "$($MyInvocation.MyCommand): Getting access token for resource $ResourceUrl"
        $Token = Get-AzAccessToken -ResourceUrl $ResourceUrl -WarningAction SilentlyContinue | Select-Object -ExpandProperty Token

        If ($Token -is [SecureString]) {
            If ($PSVersionTable.PSVersion.Major -ge 7) {
                $Token = $Token | ConvertFrom-SecureString -AsPlainText
            } Else {
                Write-Verbose "$($MyInvocation.MyCommand): PowerShell 5 - Using legacy method to convert secure string"
                $Credential = [PSCredential]::new("AccessToken", $Token)
                $Token = $Credential.GetNetworkCredential().Password
            }
        }
    }
    Catch {
        # We are not throwing the actual exception as it likely only tells the user that an interaction is required
        Throw "$($MyInvocation.MyCommand): Failed to get access token for resource $ResourceUrl - Check your assigned role in this application - Make sure to authorize 1950a258-227b-4e31-a9cf-717495945fc2 (Microsoft Azure PowerShell) to this app registration"
    }

    # Check if we can get the JWT claims
    $Claims = Expand-JWT -Token $Token

    If (-not $Claims) {
        Write-Verbose "$($MyInvocation.MyCommand): Failed to expand JWT. Returning original token."
        Return $Token
    } elseif ($Claims -eq 'JWE') {
        Write-Verbose "$($MyInvocation.MyCommand): Found JWE token. Returning original token."
        Return $Token
    }

    # Check for roles claim
    If ($Claims.PSObject.Properties.Name -notcontains 'roles') {
        Write-Verbose "$($MyInvocation.MyCommand): No roles found in JWT claims. Request might not work as intended."
        Return $Token
    }

    # Check if we have the correct roles
    If(($Claims.roles -contains 'CSR.SelfService') -or ($Claims.roles -contains 'CSR.Request.Db')) {
        Write-Verbose "$($MyInvocation.MyCommand): Found required role in $($Claims.roles)"
        Return $Token
    } else {
        Write-Verbose "$($MyInvocation.MyCommand): The token does not have the required role 'CSR.SelfService' or 'CSR.Request.Db' in $($Claims.roles). Request might not work as intended."
        Return $Token
    }
}