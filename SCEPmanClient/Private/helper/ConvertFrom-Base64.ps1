<#
.SYNOPSIS
    Decodes a Base64-encoded string into plain text.

.DESCRIPTION
    Converts a Base64-encoded string to plain text. You can specify the encoding to use for the decoded text.

.PARAMETER String
    The Base64-encoded string to decode.

.PARAMETER Encoding
    The encoding to use for the decoded text. Defaults to UTF8.

.OUTPUTS
    An array of bytes

.EXAMPLE
    Convert a Base64-encoded string to plain text:
    "SGVsbG8gV29ybGQ=" | ConvertFrom-Base64
#>
Function ConvertFrom-Base64 {
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [String]$String,
        [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8
    )

    Process {
        $Bytes = [System.Convert]::FromBase64String($String)
        Return $Bytes | ConvertFrom-Bytes -Encoding $Encoding
    }
}