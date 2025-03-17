<#
.SYNOPSIS
    Converts a byte array to a string.

.DESCRIPTION
    Converts a byte array to a string using the specified encoding.

.PARAMETER Bytes
    The byte array to convert.

.PARAMETER Encoding
    The encoding to use for the conversion. Defaults to UTF8.

.OUTPUTS
    A string

.EXAMPLE
    Convert a byte array to a string:
    [byte[]](65, 66, 67) | ConvertFrom-Bytes
#>
Function ConvertFrom-Bytes {
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [Byte]$Bytes,
        [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8
    )

    Begin {
        $ByteArray = [System.Collections.ArrayList]@()
    }

    Process {
        $ByteArray.Add($Bytes) | Out-Null
    }

    End {
        Return $Encoding.GetString([byte[]]$ByteArray)
    }
}