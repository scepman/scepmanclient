$PrivateScripts = @(Get-ChildItem $PSScriptRoot\Private\*.ps1 -Recurse)
$PublicScripts = @(Get-ChildItem $PSScriptRoot\Public\*.ps1 -Recurse)

$ScriptsToSource = $PrivateScripts + $PublicScripts

If($PSVersionTable.PSEdition -eq 'Core') {
    $PlatformSpecificScripts = @(Get-ChildItem $PSScriptRoot\PlatformSpecific\PowerShellCore\*.ps1 -Recurse)
    $ScriptsToSource += $PlatformSpecificScripts
}

# Dot source all scripts
Foreach ($Script in $ScriptsToSource)
{
    . $Script.FullName
}

Export-ModuleMember -Function $PublicScripts.BaseName
