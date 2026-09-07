BeforeAll {
    $ModuleRoot = "$PSScriptRoot\..\SCEPmanClient\"

    Import-Module "$ModuleRoot\SCEPmanClient.psm1" -Force

    $script:RootKey = [System.Security.Cryptography.RSA]::Create(2048)
    $script:RootRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=Test Root CA",
        $script:RootKey,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $script:RootCertificate = $script:RootRequest.CreateSelfSigned([DateTimeOffset]::UtcNow, [DateTimeOffset]::UtcNow.AddDays(1))
    $script:BinaryCertificate = $script:RootCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
}

Describe "Get-SCEPmanRootCA" {
    It "downloads and imports the root certificate from the SCEPman CA endpoint" {
        Mock Invoke-WebRequest {
            [pscustomobject]@{ StatusCode = 200; Content = $script:BinaryCertificate }
        } -ModuleName SCEPmanClient

        $Certificate = Get-SCEPmanRootCA -Url "https://scepman.contoso.com"

        $Certificate.Thumbprint | Should -Be $script:RootCertificate.Thumbprint
        Should -Invoke Invoke-WebRequest -Times 1 -ModuleName SCEPmanClient -ParameterFilter {
            $Uri -eq "https://scepman.contoso.com/ca"
        }
    }
}

Describe "SCEP root CA retrieval" {
    BeforeEach {
        Mock Get-AppServiceUrlFromCertificate { 'https://scepman.contoso.com' } -ModuleName SCEPmanClient
        Mock New-PrivateKeyFromCertificate { $script:RootKey } -ModuleName SCEPmanClient
        Mock New-CSRfromCertificate { $script:RootRequest } -ModuleName SCEPmanClient
        Mock New-PrivateKey { $script:RootKey } -ModuleName SCEPmanClient
        Mock New-CSR { $script:RootRequest } -ModuleName SCEPmanClient
        Mock Get-SCEPmanRootCA { $script:RootCertificate } -ModuleName SCEPmanClient
        Mock Invoke-SCEPRenewal { $script:RootCertificate } -ModuleName SCEPmanClient
        Mock Invoke-SCEPEnrollment { $script:RootCertificate } -ModuleName SCEPmanClient
        Mock Get-MergedCertificate { $script:RootCertificate } -ModuleName SCEPmanClient
    }

    It "uses the SCEPman CA endpoint for renewal" {
        New-SCEPmanCertificate -Certificate $script:RootCertificate -UseSCEPRenewal | Out-Null

        Should -Invoke Get-SCEPmanRootCA -Times 1 -ModuleName SCEPmanClient -ParameterFilter {
            $Url -eq 'https://scepman.contoso.com'
        }
    }

    It "uses the SCEPman CA endpoint for initial enrollment" {
        New-SCEPmanCertificate -Url "https://scepman.contoso.com" -UseSCEPEnrollment -ChallengePassword "challenge" -Subject "CN=Test" | Out-Null

        Should -Invoke Get-SCEPmanRootCA -Times 1 -ModuleName SCEPmanClient -ParameterFilter {
            $Url -eq 'https://scepman.contoso.com'
        }
    }
}