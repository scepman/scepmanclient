BeforeAll {
    $ModuleRoot = "$PSScriptRoot\..\SCEPmanClient\"

    Import-Module "$ModuleRoot\SCEPmanClient.psm1" -Force
}

Describe "Join-UrlPath" {
    It "defaults a scheme-less URL to HTTPS" {
        InModuleScope SCEPmanClient {
            Join-UrlPath -Url 'scepman.contoso.com' -Endpoint '/static' |
                Should -BeExactly 'https://scepman.contoso.com/static'
        }
    }

    It "preserves an explicit HTTP scheme" {
        InModuleScope SCEPmanClient {
            Join-UrlPath -Url 'http://scepman.contoso.com/' -Endpoint 'static' |
                Should -BeExactly 'http://scepman.contoso.com/static'
        }
    }

    It "preserves an explicit HTTPS scheme" {
        InModuleScope SCEPmanClient {
            Join-UrlPath -Url 'https://scepman.contoso.com/' -Endpoint '/static' |
                Should -BeExactly 'https://scepman.contoso.com/static'
        }
    }
}