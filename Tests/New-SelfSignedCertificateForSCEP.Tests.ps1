BeforeAll {
	$ModuleRoot = "$PSScriptRoot\..\SCEPmanClient\"

	Import-Module "$ModuleRoot\SCEPmanClient.psm1"
}

Describe "New-SelfSignedCertificateForSCEP" {
	It "should create a self-signed certificate from RSA key" {
		InModuleScope SCEPmanClient {
			$Key = [System.Security.Cryptography.RSA]::Create(2048)
			$Request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
				"CN=TestRSA",
				$Key,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256,
				[System.Security.Cryptography.RSASignaturePadding]::Pkcs1
			)

			$Cert = New-SelfSignedCertificateForSCEP -CertificateRequest $Request
			$Cert | Should -BeOfType [System.Security.Cryptography.X509Certificates.X509Certificate2]
			$Cert.HasPrivateKey | Should -Be $true
			$Cert.Subject | Should -Be "CN=TestRSA"
		}
	}

	It "should create a self-signed certificate from ECDSA key" {
		InModuleScope SCEPmanClient {
			$Key = [System.Security.Cryptography.ECDsa]::Create(
				[System.Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7')
			)
			$Request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
				"CN=TestECDSA",
				$Key,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256
			)

			$Cert = New-SelfSignedCertificateForSCEP -CertificateRequest $Request
			$Cert | Should -BeOfType [System.Security.Cryptography.X509Certificates.X509Certificate2]
			$Cert.HasPrivateKey | Should -Be $true
			$Cert.Subject | Should -Be "CN=TestECDSA"
		}
	}

	It "should create a certificate with short validity" {
		InModuleScope SCEPmanClient {
			$Key = [System.Security.Cryptography.RSA]::Create(2048)
			$Request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
				"CN=TestValidity",
				$Key,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256,
				[System.Security.Cryptography.RSASignaturePadding]::Pkcs1
			)

			$Cert = New-SelfSignedCertificateForSCEP -CertificateRequest $Request
			($Cert.NotAfter - $Cert.NotBefore).TotalDays | Should -BeLessOrEqual 1.01
			($Cert.NotAfter - $Cert.NotBefore).TotalDays | Should -BeGreaterOrEqual 0.99
		}
	}
}
