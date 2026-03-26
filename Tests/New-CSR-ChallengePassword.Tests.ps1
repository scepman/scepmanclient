BeforeAll {
	$ModuleRoot = "$PSScriptRoot\..\SCEPmanClient\"

	Import-Module "$ModuleRoot\SCEPmanClient.psm1"
}

Describe "New-CSR ChallengePassword" {
	It "should return a valid CSR with ChallengePassword attribute" {
		$Key = New-PrivateKey
		$Request = New-CSR -PrivateKey $Key -Subject "CN=Test" -ChallengePassword "testpassword" -Raw

		$Request | Should -BeOfType [System.Security.Cryptography.X509Certificates.CertificateRequest]

		$ChallengeAttr = $Request.OtherRequestAttributes | Where-Object { $_.Oid.Value -eq '1.2.840.113549.1.9.7' }
		$ChallengeAttr | Should -Not -BeNullOrEmpty
	}

	It "should include the correct challenge password value" {
		$Key = New-PrivateKey
		$Password = "mySecret123"
		$Request = New-CSR -PrivateKey $Key -Subject "CN=Test" -ChallengePassword $Password -Raw

		$ChallengeAttr = $Request.OtherRequestAttributes | Where-Object { $_.Oid.Value -eq '1.2.840.113549.1.9.7' }
		# The raw data contains ASN.1 PrintableString header (0x13, length) followed by the password bytes
		$PasswordBytes = [System.Text.Encoding]::ASCII.GetBytes($Password)
		$DecodedValue = [System.Text.Encoding]::ASCII.GetString($ChallengeAttr.RawData, 2, $ChallengeAttr.RawData.Length - 2)
		$DecodedValue | Should -Be $Password
	}

	It "should work without ChallengePassword (backwards compatible)" {
		$Key = New-PrivateKey
		$Request = New-CSR -PrivateKey $Key -Subject "CN=Test" -Raw
		$Request | Should -BeOfType [System.Security.Cryptography.X509Certificates.CertificateRequest]
	}
}
