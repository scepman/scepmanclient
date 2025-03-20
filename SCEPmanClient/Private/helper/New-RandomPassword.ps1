<#
.SYNOPSIS
    Generates a random password.

.OUTPUTS
    System.Security.SecureString
#>

Function New-RandomPassword {
    $securePassword = [System.Security.SecureString]::new()
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = [byte[]]::new(16)
    $random.GetBytes($bytes)
    $bytes | ForEach-Object {
        $securePassword.AppendChar([char]$_)
    }
    return $securePassword
}