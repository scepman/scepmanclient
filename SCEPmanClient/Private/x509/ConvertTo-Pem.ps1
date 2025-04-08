<#
.SYNOPSIS
    Converts a DER encoded byte array to a PEM encoded string.

.DESCRIPTION
    Converts a DER encoded byte array to a PEM encoded string according to RFC 7468.
    https://datatracker.ietf.org/doc/html/rfc7468

.PARAMETER DerBytes
    The DER encoded byte array to convert.

.PARAMETER Label
    The label to use in the PEM header and footer. If not specified, no header or footer will be added.
#>

Function ConvertTo-Pem {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [Byte[]]$DerBytes,
        [String]$Label
    )

    $StringBuilder = New-Object System.Text.StringBuilder

    If (-not [String]::IsNullOrEmpty($Label)) {
        $StringBuilder.AppendLine("-----BEGIN $($Label.ToUpper())-----") | Out-Null
    }

    $RawString = [System.Convert]::ToBase64String($DerBytes)

    for ($i = 0; $i -lt $RawString.Length; $i += 64) {
        $StringBuilder.AppendLine($RawString.Substring($i, [System.Math]::Min(64, $RawString.Length - $i))) | Out-Null
    }

    If (-not [String]::IsNullOrEmpty($Label)) {
        $StringBuilder.Append("-----END $($Label.ToUpper())-----") | Out-Null
    }

    Return $StringBuilder.ToString()
}