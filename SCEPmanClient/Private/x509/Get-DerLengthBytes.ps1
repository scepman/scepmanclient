<#
.SYNOPSIS
    Encodes a length as DER (short-form or long-form) length octets.

.DESCRIPTION
    Encodes a length as DER (short-form or long-form) length octets. Values below 128 use
    a single short-form byte, values of 128 and above use long-form encoding as required by DER.

.PARAMETER Length
    The length to encode.

.OUTPUTS
    A byte array containing the DER length octets.

.EXAMPLE
    Get-DerLengthBytes -Length 200
#>
Function Get-DerLengthBytes {
    Param(
        [Parameter(Mandatory)]
        [Int]$Length
    )

    If ($Length -lt 128) {
        Return [Byte[]]@([Byte]$Length)
    }

    $LengthBytes = [System.Collections.Generic.List[Byte]]::new()
    $Remainder = $Length
    While ($Remainder -gt 0) {
        $LengthBytes.Insert(0, [Byte]($Remainder -band 0xFF))
        $Remainder = $Remainder -shr 8
    }

    Return [Byte[]]@([Byte](0x80 -bor $LengthBytes.Count)) + $LengthBytes.ToArray()
}
