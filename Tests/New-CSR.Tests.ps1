BeforeAll {
	$ModuleRoot = "$PSScriptRoot\..\SCEPmanClient\"

	Import-Module "$ModuleRoot\SCEPmanClient.psm1"
}

Describe "New-CSR" {
	It "should return a valid CSR" {
		$Key = New-PrivateKey
		New-CSR -PrivateKey $Key -Subject "CN=Test" -Raw | Should -BeOfType [System.Security.Cryptography.X509Certificates.CertificateRequest]
	}

    It "should return a valid CSR with ECDSA key" {
        $Key = New-PrivateKey -Algorithm ECDSA
        New-CSR -PrivateKey $Key -Subject "CN=Test" -Raw | Should -BeOfType [System.Security.Cryptography.X509Certificates.CertificateRequest]
    }

    It "should return a valid CSR with custom attributes" {
        New-CSR -PrivateKey (New-PrivateKey) -Subject "CN=Test" -ExtendedKeyUsage ClientAuth, ServerAuth -KeyUsage KeyEncipherment, DigitalSignature -Raw | Should -BeOfType [System.Security.Cryptography.X509Certificates.CertificateRequest]
    }
}