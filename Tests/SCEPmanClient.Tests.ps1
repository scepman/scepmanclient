#Requires -Modules PSScriptAnalyzer

BeforeAll {
	$ModuleRoot = "$PSScriptRoot\..\SCEPmanClient\"
}

Describe "PSScriptAnalyzer" {
	It "should show no warnings or errors." {
		$Results = Invoke-ScriptAnalyzer -Path $ModuleRoot -Recurse -ExcludeRule PSUseSingularNouns
		$Results | Out-String | Write-Host
		$Results | Should -Be $null
	}
}
