<#
.SYNOPSIS
    Create a new ASN.1 encoded enrollment key-value pair.

.DESCRIPTION
    Create a new ASN.1 encoded enrollment key-value pair using the specified parameters.

.PARAMETER Name
    The name of the enrollment key-value pair.

.PARAMETER Value
    The value of the enrollment key-value pair.

.EXAMPLE
    New-AsnEncodedEnrollmentKeyValuePair -Name 'Key1' -Value 'Value1'
    Create a new ASN.1 encoded enrollment key-value pair with the specified name and value.

.OUTPUTS
    [System.Security.Cryptography.AsnEncodedData]
    The ASN.1 encoded enrollment key-value pair.
#>

Function New-AsnEncodedEnrollmentKeyValuePair {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$Name,

        [Parameter(Mandatory)]
        [String]$Value
    )

    $Asn1EncodingRulesEnum = [System.Type]::GetType("System.Formats.Asn1.AsnEncodingRules, System.Formats.Asn1")
    $Asn1EncodingRule = [System.Enum]::Parse($Asn1EncodingRulesEnum, "DER")

    $Asn1UniversalTagEnum = [System.Type]::GetType("System.Formats.Asn1.UniversalTagNumber, System.Formats.Asn1")
    $Asn1TagBMPSTRING = [System.Enum]::Parse($Asn1UniversalTagEnum, "BMPString")

    $Asn1SequenceTag = New-Object -TypeName System.Formats.Asn1.Asn1Tag -ArgumentList 16

    $EnrollmentKeyValuePairOid = [System.Security.Cryptography.Oid]::new('1.3.6.1.4.1.311.13.2.1')

    $AsnWriter = New-Object -TypeName System.Formats.Asn1.AsnWriter -ArgumentList $Asn1EncodingRule

    $AsnWriter.PushSequence($Asn1SequenceTag) | Out-Null
    $AsnWriter.WriteCharacterString($Asn1TagBMPSTRING, $Name)
    $AsnWriter.WriteCharacterString($Asn1TagBMPSTRING, $Value)
    $AsnWriter.PopSequence()

    $AsnObject = [System.Security.Cryptography.AsnEncodedData]::new($EnrollmentKeyValuePairOid, $AsnWriter.Encode())
    $AsnWriter.Reset()

    Return $AsnObject
}