<#
.SYNOPSIS
    Pads a given string until it is a multiple of 4 characters.

.DESCRIPTION
    Pads a given string with '=' characters until its length is a multiple of 4.

.PARAMETER String
    The input string that should be padded.

.PARAMETER PaddingChar
    The character to use for padding. Defaults to '='.

.OUTPUTS
    A string

.EXAMPLE
    Pad a Base64-encoded string:
    "SGVsbG8gV29ybGQ=" | Get-PaddedBase64
#>
Function Get-PaddedBase64 {
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [String]$String,
        [Char]$PaddingChar = '='
    )

    Process {
        While($String.Length % 4 -ne 0) {
            $String += $PaddingChar
        }

        Return $String
    }
}