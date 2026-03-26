BeforeAll {
	$ModuleRoot = "$PSScriptRoot\..\SCEPmanClient\"

	Import-Module "$ModuleRoot\SCEPmanClient.psm1"
}

Describe "New-Pkcs7SignedMessage" {
	It "should default to messageType 17 (renewal)" {
		InModuleScope SCEPmanClient {
			$Key = [System.Security.Cryptography.RSA]::Create(2048)
			$Request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
				"CN=Test",
				$Key,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256,
				[System.Security.Cryptography.RSASignaturePadding]::Pkcs1
			)
			$Cert = $Request.CreateSelfSigned(
				[System.DateTimeOffset]::UtcNow,
				[System.DateTimeOffset]::UtcNow.AddDays(1)
			)
			$TestMessage = [System.Text.Encoding]::UTF8.GetBytes('TestPayload')

			$Result = New-Pkcs7SignedMessage -SignerCertificate $Cert -Message $TestMessage
			$Result | Should -BeOfType [Byte]

			$SignedCms = [System.Security.Cryptography.Pkcs.SignedCms]::new()
			$SignedCms.Decode($Result)

			$MessageTypeAttr = $SignedCms.SignerInfos[0].SignedAttributes | Where-Object { $_.Oid.Value -eq '2.16.840.1.113733.1.9.2' }
			$MessageTypeAttr | Should -Not -BeNullOrEmpty

			$DecodedValue = [System.Text.Encoding]::ASCII.GetString($MessageTypeAttr.Values[0].RawData, 2, $MessageTypeAttr.Values[0].RawData.Length - 2)
			$DecodedValue | Should -Be '17'
		}
	}

	It "should use messageType 19 (PKCSReq) when specified" {
		InModuleScope SCEPmanClient {
			$Key = [System.Security.Cryptography.RSA]::Create(2048)
			$Request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
				"CN=Test",
				$Key,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256,
				[System.Security.Cryptography.RSASignaturePadding]::Pkcs1
			)
			$Cert = $Request.CreateSelfSigned(
				[System.DateTimeOffset]::UtcNow,
				[System.DateTimeOffset]::UtcNow.AddDays(1)
			)
			$TestMessage = [System.Text.Encoding]::UTF8.GetBytes('TestPayload')

			$Result = New-Pkcs7SignedMessage -SignerCertificate $Cert -Message $TestMessage -MessageType '19'
			$Result | Should -BeOfType [Byte]

			$SignedCms = [System.Security.Cryptography.Pkcs.SignedCms]::new()
			$SignedCms.Decode($Result)

			$MessageTypeAttr = $SignedCms.SignerInfos[0].SignedAttributes | Where-Object { $_.Oid.Value -eq '2.16.840.1.113733.1.9.2' }
			$MessageTypeAttr | Should -Not -BeNullOrEmpty

			$DecodedValue = [System.Text.Encoding]::ASCII.GetString($MessageTypeAttr.Values[0].RawData, 2, $MessageTypeAttr.Values[0].RawData.Length - 2)
			$DecodedValue | Should -Be '19'
		}
	}
}
