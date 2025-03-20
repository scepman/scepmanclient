BeforeAll {
	$ModuleRoot = "$PSScriptRoot\..\SCEPmanClient\"

	Import-Module "$ModuleRoot\SCEPmanClient.psm1"
}

Describe "New-PrivateKey" {
	It "should return RSA key with default size" {
		$Key = New-PrivateKey
		$Key | Should -BeOfType [System.Security.Cryptography.RSA]
		$Key.KeySize | Should -Be 2048
	}

	It "should return ECDSA key with default size" {
		$Key = New-PrivateKey -Algorithm ECDSA
		$Key | Should -BeOfType [System.Security.Cryptography.ECDsa]
		$Key.KeySize | Should -Be 521
	}

	It "should return RSA key with custom size" {
		$Key = New-PrivateKey -KeySize 4096
		$Key | Should -BeOfType [System.Security.Cryptography.RSA]
		$Key.KeySize | Should -Be 4096
	}

	It "should return ECDSA key with custom size" {
		$Key = New-PrivateKey -Algorithm ECDSA -KeySize 256
		$Key | Should -BeOfType [System.Security.Cryptography.ECDsa]
		$Key.KeySize | Should -Be 256
	}

	It "should return ECDSA key with custom curve" {
		$Curve = [System.Security.Cryptography.ECCurve]::CreateFromOid('1.3.36.3.3.2.8.1.1.11')
		New-PrivateKey -Algorithm ECDSA -ECCurve $Curve | Should -BeOfType [System.Security.Cryptography.ECDsa]
	}
}