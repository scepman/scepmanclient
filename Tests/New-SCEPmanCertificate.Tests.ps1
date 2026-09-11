BeforeAll {
    $ModuleRoot = "$PSScriptRoot\..\SCEPmanClient\"

    Import-Module "$ModuleRoot\SCEPmanClient.psm1" -Force

    # A real self-signed certificate so the typed output path (Get-MergedCertificate) binds correctly
    $script:DummyRsa = [System.Security.Cryptography.RSA]::Create(2048)
    $script:DummyCertRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=Test",
        $script:DummyRsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $script:DummyCert = $script:DummyCertRequest.CreateSelfSigned([DateTimeOffset]::UtcNow, [DateTimeOffset]::UtcNow.AddDays(1))

    $script:RenewalRsa = [System.Security.Cryptography.RSA]::Create(2048)
    $script:RenewalCertRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=Test",
        $script:RenewalRsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $RenewalCertWithKey = $script:RenewalCertRequest.CreateSelfSigned([DateTimeOffset]::UtcNow, [DateTimeOffset]::UtcNow.AddDays(1))
    $script:RenewalCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $RenewalCertWithKey.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    )
}

Describe "New-SCEPmanCertificate" {
    BeforeEach {
        $script:ESTCalls = @()

        Mock Set-AzConfig {} -ModuleName SCEPmanClient
        Mock Connect-SCEPmanAzAccount {} -ModuleName SCEPmanClient
        Mock Get-SCEPmanResourceUrl { 'api://resource-id' } -ModuleName SCEPmanClient
        Mock Get-SCEPmanAccessToken { 'az-token' } -ModuleName SCEPmanClient
        Mock Get-AzContext {} -ModuleName SCEPmanClient

        # Avoid running real crypto for key generation / CSR building; return the shared dummy key/cert
        Mock New-PrivateKey { $script:DummyRsa } -ModuleName SCEPmanClient
        Mock New-CSR { 'dummy-csr' } -ModuleName SCEPmanClient

        Mock Invoke-ESTRequest {
            param($Url, $Request, $AccessToken)

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

        It "requires an Azure context when deriving the subject from the current user" {
            {
                New-SCEPmanCertificate -Url "https://scepman.contoso.com" -AccessToken "my-bearer-token" -SubjectFromUserContext
            } | Should -Throw '*SubjectFromUserContext requires an active Azure context*'

            Should -Invoke New-CSR -Times 0 -ModuleName SCEPmanClient
            Should -Invoke Invoke-ESTRequest -Times 0 -ModuleName SCEPmanClient
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

    Context "PlainTextPassword forwarding" {
        It "uses the supplied password when loading an encrypted private key" {
            $CertificatePath = Join-Path $TestDrive 'certificate.pem'
            $KeyPath = Join-Path $TestDrive 'private-key.pem'
            $PbeParameters = [System.Security.Cryptography.PbeParameters]::new(
                [System.Security.Cryptography.PbeEncryptionAlgorithm]::Aes256Cbc,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                20000
            )

            Set-Content -Path $CertificatePath -Value $script:DummyCert.ExportCertificatePem()
            Set-Content -Path $KeyPath -Value $script:DummyRsa.ExportEncryptedPkcs8PrivateKeyPem('file-password', $PbeParameters)

            Mock Read-Host { throw 'Password prompt was not expected' } -ModuleName SCEPmanClient
            Mock Get-AppServiceUrlFromCertificate { 'https://scepman.contoso.com' } -ModuleName SCEPmanClient
            Mock New-CSRFromCertificate { 'renewal-csr' } -ModuleName SCEPmanClient
            Mock Invoke-ESTmTLSRequest { $Certificate } -ModuleName SCEPmanClient

            {
                New-SCEPmanCertificate -CertificateFromFile $CertificatePath -KeyFromFile $KeyPath -PlainTextPassword 'file-password'
            } | Should -Not -Throw

            Should -Invoke Read-Host -Times 0 -ModuleName SCEPmanClient
            Should -Invoke Invoke-ESTmTLSRequest -Times 1 -ModuleName SCEPmanClient
        }

        It "uses the supplied password when exporting a PEM private key" {
            $script:SavedPrivateKeyPassword = $null
            Mock Read-Host { throw 'Password prompt was not expected' } -ModuleName SCEPmanClient
            Mock Save-CertificateToFile {} -ModuleName SCEPmanClient
            Mock Save-PrivateKeyToFile {
                param($PrivateKey, $FilePath, $Password)
                $script:SavedPrivateKeyPassword = $Password | ConvertFrom-SecureString -AsPlainText
            } -ModuleName SCEPmanClient

            New-SCEPmanCertificate -Url 'https://scepman.contoso.com' -AccessToken 'my-bearer-token' -Subject 'CN=Test' `
                -SaveToFolder $TestDrive -Format PEM -IncludeRootCA -PlainTextPassword 'export-password' | Out-Null

            Should -Invoke Read-Host -Times 0 -ModuleName SCEPmanClient
            Should -Invoke Save-PrivateKeyToFile -Times 1 -ModuleName SCEPmanClient
            $script:SavedPrivateKeyPassword | Should -Be 'export-password'
        }
    }

    Context "Certificate renewal" {
        It "rejects multiple certificates found by subject" {
            Mock Get-ChildItem { @($script:DummyCert) } -ModuleName SCEPmanClient

            {
                New-SCEPmanCertificate -CertificateBySubject 'CN=Test'
            } | Should -Throw '*Multiple certificates found with subject: CN=Test*Only one certificate can be renewed at a time*'

            Should -Invoke Get-ChildItem -Times 2 -ModuleName SCEPmanClient
        }

        It "renews from a certificate object and merges the matching certificate from the returned chain" {
            Mock Get-AppServiceUrlFromCertificate { 'https://scepman.contoso.com' } -ModuleName SCEPmanClient
            Mock New-PrivateKeyFromCertificate { $script:RenewalRsa } -ModuleName SCEPmanClient
            Mock New-CSRFromCertificate { 'renewal-csr' } -ModuleName SCEPmanClient
            Mock Invoke-ESTmTLSRequest { @($script:DummyCert, $script:RenewalCert) } -ModuleName SCEPmanClient

            $Certificate = New-SCEPmanCertificate -Certificate $script:DummyCert

            $Certificate | Should -BeOfType ([System.Security.Cryptography.X509Certificates.X509Certificate2])
            $Certificate.Thumbprint | Should -Be $script:RenewalCert.Thumbprint
            $Certificate.HasPrivateKey | Should -BeTrue
        }
    }
}
