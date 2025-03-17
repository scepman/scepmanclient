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
        $Token = If ($PSVersionTable.PSVersion.Major -ge 7) {
            Get-AzAccessToken -ResourceUrl $ResourceUrl -AsSecureString -WarningAction SilentlyContinue | Select-Object -ExpandProperty Token | ConvertFrom-SecureString -AsPlainText
        } Else {
            Write-Verbose "$($MyInvocation.MyCommand): Using legacy method to get access token"
            Get-AzAccessToken -ResourceUrl $ResourceUrl -WarningAction SilentlyContinue | Select-Object -ExpandProperty Token
        }
    }
    Catch {
        Throw "$($MyInvocation.MyCommand): Failed to get access token for resource $ResourceUrl"
    }

    $RawPayload = $Token -split '\.' | Select-Object -Index 1

    # Add padding if needed
    While($RawPayload.Length % 4 -ne 0) {
        $RawPayload += '='
    }
    $Payload = $RawPayload | ConvertFrom-Base64 | ConvertFrom-Json

    If(($Payload.roles -contains 'CSR.SelfService') -or ($Payload.roles -contains 'CSR.Request.Db')) {
        Write-Verbose "$($MyInvocation.MyCommand): Found required role in $($Payload.roles)"
        Return $Token
    } else {
        Write-Verbose "$($MyInvocation.MyCommand): The token does not have the required role 'CSR.SelfService' or 'CSR.Request.Db' in $($Payload.roles). Request might not work as intended."
        Return $Token
    }
}