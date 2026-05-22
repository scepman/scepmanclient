BeforeAll {
    $ModuleRoot = "$PSScriptRoot\..\SCEPmanClient\"

    Import-Module "$ModuleRoot\SCEPmanClient.psm1" -Force
}

Describe "Find-SCEPmanCertificate" {
    BeforeEach {
        $script:LastInvokeUri = $null
        $script:LastInvokeMethod = $null
        $script:LastInvokeAuth = $null

        Mock Set-AzConfig {} -ModuleName SCEPmanClient
        Mock Connect-SCEPmanAzAccount {} -ModuleName SCEPmanClient
        Mock Get-SCEPmanResourceUrl { 'api://resource-id' } -ModuleName SCEPmanClient
        Mock Get-SCEPmanAccessToken { 'test-token' } -ModuleName SCEPmanClient
        Mock Invoke-RestMethod {
            param($Uri, $Method, $Headers)
            $script:LastInvokeUri = $Uri
            $script:LastInvokeMethod = $Method
            $script:LastInvokeAuth = $Headers.Authorization
            [pscustomobject]@{ ok = $true }
        } -ModuleName SCEPmanClient
    }

    It "builds the search query and calls the API using bearer auth" {
        Find-SCEPmanCertificate -Url "https://scepman.contoso.com" -SearchText "alice@contoso.com" -PageSize 50 -CertValidity "Any" -CertType "Any" | Out-Null

        Should -Invoke Invoke-RestMethod -Times 1 -ModuleName SCEPmanClient
        $script:LastInvokeMethod | Should -Be 'Get'
        $script:LastInvokeAuth | Should -Be 'Bearer test-token'
        $script:LastInvokeUri | Should -Match '^https://scepman\.contoso\.com/api/manage/search\?'
        $script:LastInvokeUri | Should -Match 'SearchText=alice%40contoso\.com'
        $script:LastInvokeUri | Should -Match 'PageSize=50'
        $script:LastInvokeUri | Should -Match 'CertValidity=Any'
        $script:LastInvokeUri | Should -Match 'CertType=Any'
    }

    It "omits empty continuation token and resolves resource URL when not provided" {
        Find-SCEPmanCertificate -Url "https://scepman.contoso.com" -SearchText "alice" -ContinuationToken "" | Out-Null

        Should -Invoke Get-SCEPmanResourceUrl -Times 1 -ModuleName SCEPmanClient
        Should -Invoke Invoke-RestMethod -Times 1 -ModuleName SCEPmanClient
        $script:LastInvokeUri | Should -Not -Match 'ContinuationToken='
    }

    It "does not resolve resource URL when ResourceUrl is provided" {
        Find-SCEPmanCertificate -Url "https://scepman.contoso.com" -SearchText "alice" -ResourceUrl "api://given-resource" | Out-Null

        Should -Invoke Get-SCEPmanResourceUrl -Times 0 -ModuleName SCEPmanClient
        Should -Invoke Get-SCEPmanAccessToken -Times 1 -ModuleName SCEPmanClient -ParameterFilter {
            $ResourceUrl -eq 'api://given-resource'
        }
    }
}
