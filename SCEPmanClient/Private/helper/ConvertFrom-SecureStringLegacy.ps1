<#
.SYNOPSIS
    Converts a SecureString to a plain text string.

.DESCRIPTION
    Converts a SecureString to a plain text string. This function is used to convert SecureStrings to plain text strings for compatibility with Windows PowerShell.

.PARAMETER SecureString
    The SecureString to convert.

.OUTPUTS
    System.String
#>

function ConvertFrom-SecureStringLegacy {
    [CmdletBinding()]
    [OutputType([String])]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [SecureString]$SecureString
    )

    Process {
        [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        )
    }
}