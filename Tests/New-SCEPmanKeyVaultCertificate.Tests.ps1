BeforeAll {
    $ModuleRoot = "$PSScriptRoot\..\SCEPmanClient\"

    Import-Module "$ModuleRoot\SCEPmanClient.psm1" -Force
}

Describe "New-SCEPmanKeyVaultCertificate" {
    BeforeEach {
        Mock Get-AzContext {} -ModuleName SCEPmanClient
        Mock New-TemporaryFile {} -ModuleName SCEPmanClient
        Mock Add-AzKeyVaultCertificate {} -ModuleName SCEPmanClient
    }

    Context "DirectTokenAuth parameter set" {
        It "requires an Azure context before starting Key Vault operations" {
            {
                New-SCEPmanKeyVaultCertificate -Url "https://scepman.contoso.com" -AccessToken "my-bearer-token" -VaultName "test-vault" -Subject "CN=Test" -CertificateName "test-cert"
            } | Should -Throw '*Key Vault operations require an active Azure context*'

            Should -Invoke New-TemporaryFile -Times 0 -ModuleName SCEPmanClient
            Should -Invoke Add-AzKeyVaultCertificate -Times 0 -ModuleName SCEPmanClient
        }
    }
}