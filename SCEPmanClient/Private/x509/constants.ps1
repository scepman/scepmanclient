Set-Variable -Option Constant -Name constant_EKUDefinition -Value @{
    'ClientAuth' = '1.3.6.1.5.5.7.3.2'
    'ServerAuth' = '1.3.6.1.5.5.7.3.1'
    'CodeSigning' = '1.3.6.1.5.5.7.3.3'
    'EmailProtection' = '1.3.6.1.5.5.7.3.4'
    'TimeStamping' = '1.3.6.1.5.5.7.3.8'
    'OCSPSigning' = '1.3.6.1.5.5.7.3.9'
    'SmartCardLogon' = '1.3.6.1.4.1.311.20.2.2'
    'EncryptFileSystem' = '1.3.6.1.4.1.311.10.3.4'
    'IPSecIKE' = '1.3.6.1.5.5.7.3.17'
    'PSecIKEIntermediate' = '1.3.6.1.5.5.8.2.2'
    'KDCAuth' = '1.3.6.1.5.2.3.5'
    'IpSecurityUser' = '1.3.6.1.5.5.7.3.7'
}

Set-Variable -Option Constant -Name constant_KUDefinition -Value @{
    'DigitalSignature'       = @{ 'Oid' = '2.5.29.150'; 'KeyTypes' = @('RSA', 'ECDSA') }
    'CRLSign'                = @{ 'Oid' = '2.5.29.156'; 'KeyTypes' = @('RSA', 'ECDSA') }
    'DataEncipherment'       = @{ 'Oid' = '2.5.29.153'; 'KeyTypes' = @('RSA') }
    'DecipherOnly'           = @{ 'Oid' = '2.5.29.158'; 'KeyTypes' = @('ECDSA') }
    'EncipherOnly'           = @{ 'Oid' = '2.5.29.157'; 'KeyTypes' = @('ECDSA') }
    'KeyAgreement'           = @{ 'Oid' = '2.5.29.154'; 'KeyTypes' = @('ECDSA') }
    'KeyCertSign'            = @{ 'Oid' = '2.5.29.155'; 'KeyTypes' = @('RSA', 'ECDSA') }
    'KeyEncipherment'        = @{ 'Oid' = '2.5.29.152'; 'KeyTypes' = @('RSA') }
    'NonRepudiation'         = @{ 'Oid' = '2.5.29.151'; 'KeyTypes' = @('RSA', 'ECDSA') }
}

Set-Variable -Option Constant -Name constant_HashingAlgorithm -Value @('SHA256', 'SHA384', 'SHA512')

Set-Variable -Option Constant -Name constant_SignatureAlgorithm -Value @('RSA', 'ECDSA')

Set-Variable -Option Constant -Name constant_SCEPmanRoles -Value @('CSR.SelfService', 'CSR.Request.Db')

Set-Variable -Option Constant -Name constant_Pkcs7EncryptedDataOid -Value ([System.Security.Cryptography.Oid]::new('1.2.840.113549.1.7.6', 'envelopedData'))
Set-Variable -Option Constant -Name constant_MessageTypeOid -Value ([System.Security.Cryptography.Oid]::new('2.16.840.1.113733.1.9.2'))
Set-Variable -Option Constant -Name constant_MD5Oid -Value ([System.Security.Cryptography.Oid]::new('1.2.840.113549.2.5', 'digestAlgorithm'))
Set-Variable -Option Constant -Name constant_TransactionIdOid -Value ([System.Security.Cryptography.Oid]::new('2.16.840.1.113733.1.9.7'))
Set-Variable -Option Constant -Name constant_SenderNonceOid -Value ([System.Security.Cryptography.Oid]::new('2.16.840.1.113733.1.9.5'))

Set-Variable -Option Constant -Name constant_EnrollmentKeyValuePairOid -Value ([System.Security.Cryptography.Oid]::new('1.3.6.1.4.1.311.13.2.1'))
Set-Variable -Option Constant -Name constant_Asn1SequenceTag -Value ([System.Formats.Asn1.Asn1Tag]::new(16))
Set-Variable -Option Constant -Name constant_Asn1BMPStringTag -Value ([System.Formats.Asn1.UniversalTagNumber]::BMPString)
Set-Variable -Option Constant -Name constant_Asn1EncodingRuleSet -Value ([System.Formats.Asn1.AsnEncodingRules]::DER)
