BeforeAll {
    $ModuleRoot = "$PSScriptRoot\..\SCEPmanClient\"

    Import-Module "$ModuleRoot\SCEPmanClient.psm1"

    # A real self-signed certificate so the typed output path (Get-MergedCertificate) binds correctly
    $script:DummyRsa = [System.Security.Cryptography.RSA]::Create(2048)
    $script:DummyCertRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=Test",
        $script:DummyRsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $script:DummyCert = $script:DummyCertRequest.CreateSelfSigned([DateTimeOffset]::UtcNow, [DateTimeOffset]::UtcNow.AddDays(1))
}

Describe "New-SCEPmanCertificate" {
    BeforeEach {
        $script:ESTCalls = @()

        Mock Set-AzConfig {} -ModuleName SCEPmanClient
        Mock Connect-SCEPmanAzAccount {} -ModuleName SCEPmanClient
        Mock Get-SCEPmanResourceUrl { 'api://resource-id' } -ModuleName SCEPmanClient
        Mock Get-SCEPmanAccessToken { 'az-token' } -ModuleName SCEPmanClient

        # Avoid running real crypto for key generation / CSR building; return the shared dummy key/cert
        Mock New-PrivateKey { $script:DummyRsa } -ModuleName SCEPmanClient
        Mock New-CSR { 'dummy-csr' } -ModuleName SCEPmanClient
        Mock Get-MergedCertificate { $script:DummyCert } -ModuleName SCEPmanClient

        Mock Invoke-ESTRequest {
            param($Url, $Endpoint, $Request, $AccessToken, $Credential)

            $script:ESTCalls += [pscustomobject]@{
                Url         = $Url
                Request     = $Request
                AccessToken = $AccessToken
            }

            $script:DummyCert
        } -ModuleName SCEPmanClient
    }

    Context "DirectTokenAuth parameter set" {
        It "uses the supplied bearer token and skips Azure authentication" {
            New-SCEPmanCertificate -Url "https://scepman.contoso.com" -AccessToken "my-bearer-token" -Csr "supplied-csr" | Out-Null

            Should -Invoke Connect-SCEPmanAzAccount -Times 0 -ModuleName SCEPmanClient
            Should -Invoke Get-SCEPmanAccessToken -Times 0 -ModuleName SCEPmanClient
            Should -Invoke Get-SCEPmanResourceUrl -Times 0 -ModuleName SCEPmanClient

            Should -Invoke Invoke-ESTRequest -Times 1 -ModuleName SCEPmanClient
            $script:ESTCalls[0].AccessToken | Should -Be 'my-bearer-token'
            $script:ESTCalls[0].Url | Should -Be 'https://scepman.contoso.com'
            $script:ESTCalls[0].Request | Should -Be 'supplied-csr'
        }

        It "builds a CSR from parameters when no Csr is supplied" {
            New-SCEPmanCertificate -Url "https://scepman.contoso.com" -AccessToken "my-bearer-token" -Subject "CN=Test" | Out-Null

            Should -Invoke New-CSR -Times 1 -ModuleName SCEPmanClient
            Should -Invoke Invoke-ESTRequest -Times 1 -ModuleName SCEPmanClient
            $script:ESTCalls[0].AccessToken | Should -Be 'my-bearer-token'
        }
    }

    Context "AzAuth parameter set" {
        It "acquires a token from Azure and passes it to the EST request" {
            New-SCEPmanCertificate -Url "https://scepman.contoso.com" -Csr "supplied-csr" | Out-Null

            Should -Invoke Connect-SCEPmanAzAccount -Times 1 -ModuleName SCEPmanClient
            Should -Invoke Get-SCEPmanAccessToken -Times 1 -ModuleName SCEPmanClient

            Should -Invoke Invoke-ESTRequest -Times 1 -ModuleName SCEPmanClient
            $script:ESTCalls[0].AccessToken | Should -Be 'az-token'
        }
    }
}
