$PrivateScripts = @(Get-ChildItem $PSScriptRoot\Private\*.ps1 -Recurse)
$PublicScripts = @(Get-ChildItem $PSScriptRoot\Public\*.ps1 -Recurse)

# Dot source all scripts
Foreach ($Script in ($PrivateScripts + $PublicScripts))
{
    . $Script.FullName
}

Export-ModuleMember -Function $PublicScripts.BaseName
