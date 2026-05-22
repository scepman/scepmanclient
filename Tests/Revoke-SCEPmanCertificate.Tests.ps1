BeforeAll {
    $ModuleRoot = "$PSScriptRoot\..\SCEPmanClient\"

    Import-Module "$ModuleRoot\SCEPmanClient.psm1" -Force
}

Describe "Revoke-SCEPmanCertificate" {
    BeforeEach {
        $script:InvokeCalls = @()

        Mock Set-AzConfig {} -ModuleName SCEPmanClient
        Mock Connect-SCEPmanAzAccount {} -ModuleName SCEPmanClient
        Mock Get-SCEPmanResourceUrl { 'api://resource-id' } -ModuleName SCEPmanClient
        Mock Get-SCEPmanAccessToken { 'test-token' } -ModuleName SCEPmanClient
        Mock Get-AzContext { [pscustomobject]@{ Account = [pscustomobject]@{ Id = 'context-user@contoso.com' } } } -ModuleName SCEPmanClient

        Mock Invoke-RestMethod {
            param($Uri, $Method, $Headers, $Body)

            $script:InvokeCalls += [pscustomobject]@{
                Uri    = $Uri
                Method = $Method
                Auth   = $Headers.Authorization
                CType  = $Headers.'Content-Type'
                Body   = $Body | ConvertFrom-Json
            }

            [pscustomobject]@{ status = 'ok' }
        } -ModuleName SCEPmanClient
    }

    It "sends a PATCH request with revocation reason and explicit revoker" {
        Revoke-SCEPmanCertificate -Url "https://scepman.contoso.com" -SerialNumber "1A2B3C4D" -RevocationReason KeyCompromise -Revoker "admin@contoso.com" -ResourceUrl "api://given-resource" | Out-Null

        Should -Invoke Get-SCEPmanResourceUrl -Times 0 -ModuleName SCEPmanClient
        Should -Invoke Get-SCEPmanAccessToken -Times 1 -ModuleName SCEPmanClient -ParameterFilter {
            $ResourceUrl -eq 'api://given-resource'
        }
        Should -Invoke Invoke-RestMethod -Times 1 -ModuleName SCEPmanClient

        $script:InvokeCalls[0].Method | Should -Be 'Patch'
        $script:InvokeCalls[0].Auth | Should -Be 'Bearer test-token'
        $script:InvokeCalls[0].CType | Should -Be 'application/json'
        $script:InvokeCalls[0].Uri | Should -Be 'https://scepman.contoso.com/api/manage/revoke/1A2B3C4D'
        $script:InvokeCalls[0].Body.revocationReason | Should -Be 1
        $script:InvokeCalls[0].Body.revoker | Should -Be 'admin@contoso.com'
    }

    It "uses Azure context account as revoker when Revoker is not provided" {
        Revoke-SCEPmanCertificate -Url "https://scepman.contoso.com/" -SerialNumber "A1B2" -RevocationReason Superseded | Out-Null

        Should -Invoke Get-SCEPmanResourceUrl -Times 1 -ModuleName SCEPmanClient
        Should -Invoke Get-AzContext -Times 1 -ModuleName SCEPmanClient
        $script:InvokeCalls[0].Body.revocationReason | Should -Be 4
        $script:InvokeCalls[0].Body.revoker | Should -Be 'context-user@contoso.com'
        $script:InvokeCalls[0].Uri | Should -Be 'https://scepman.contoso.com/api/manage/revoke/A1B2'
    }

    It "sends one request per serial number" {
        Revoke-SCEPmanCertificate -Url "https://scepman.contoso.com" -SerialNumber "1111", "2222" -RevocationReason Unspecified -Revoker "admin@contoso.com" | Out-Null

        Should -Invoke Invoke-RestMethod -Times 2 -ModuleName SCEPmanClient
        $script:InvokeCalls.Count | Should -Be 2
        $script:InvokeCalls[0].Uri | Should -Be 'https://scepman.contoso.com/api/manage/revoke/1111'
        $script:InvokeCalls[1].Uri | Should -Be 'https://scepman.contoso.com/api/manage/revoke/2222'
        $script:InvokeCalls[0].Body.revocationReason | Should -Be 0
        $script:InvokeCalls[1].Body.revocationReason | Should -Be 0
    }
}
