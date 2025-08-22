Function New-AsnEncodedEnrollmentKeyValuePair {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$Name,

        [Parameter(Mandatory)]
        [String]$Value
    )

    $AsnWriter = [System.Formats.Asn1.AsnWriter]::new($constant_core_Asn1EncodingRuleSet)

    $AsnWriter.PushSequence($constant_core_Asn1SequenceTag) | Out-Null
    $AsnWriter.WriteCharacterString($constant_core_Asn1BMPStringTag, $Name)
    $AsnWriter.WriteCharacterString($constant_core_Asn1BMPStringTag, $Value)
    $AsnWriter.PopSequence()

    $AsnObject = [System.Security.Cryptography.AsnEncodedData]::new($constant_core_EnrollmentKeyValuePairOid, $AsnWriter.Encode())
    $AsnWriter.Reset()

    Return $AsnObject
}