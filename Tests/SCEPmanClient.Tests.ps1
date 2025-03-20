#Requires -Modules PSScriptAnalyzer

BeforeAll {
	$ModuleRoot = "$PSScriptRoot\..\SCEPmanClient\"
}

Describe "PSScriptAnalyzer" {
	It "should show no warnings or errors." {
		$RulesToExclude = @(
			# We are not changing system state
			'PSUseShouldProcessForStateChangingFunctions',
			# As we are often use $PSBoundParameters to verify the presence of a parameter, we need to exclude this rule.
			'PSReviewUnusedParameter'
		)

		$Results = Invoke-ScriptAnalyzer -Path $ModuleRoot -Recurse -ReportSummary -ExcludeRule $RulesToExclude
		$Results | Out-String | Write-Host
		$Results | Should -Be $null
	}
}
