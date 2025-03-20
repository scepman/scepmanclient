<#
.SYNOPSIS
    Creates a new private key.

.DESCRIPTION
    Creates a new private key using the specified algorithm and key size.

.PARAMETER Algorithm
    The algorithm to use for the private key. Supported values are 'RSA' and 'ECDSA'.

.PARAMETER KeySize
    The size of the key to create. For RSA, supported key sizes are 1024, 2048, 3072, and 4096. For ECDSA, supported key sizes are 256, 384, and 521.

.PARAMETER ECCurve
    The curve to use for the ECDSA key. Supported values are 'NistP256', 'NistP384', and 'NistP521'.

.EXAMPLE
    New-PrivateKey -Algorithm RSA -KeySize 2048
    Creates a new RSA private key with a key size of 2048 bits.
#>

Function New-PrivateKey {
    Param(
        [Parameter()]
        [ValidateSet('RSA', 'ECDSA')]
        [String]$Algorithm = 'RSA',

        [Parameter()]
        [Int]$KeySize,

        $ECCurve
    )

    If ($PSBoundParameters.ContainsKey('KeySize')) {
        If ($Algorithm -eq 'RSA' -and (-not (@(1024, 2048, 3072, 4096) -contains $KeySize))) {
            throw "$($MyInvocation.MyCommand): Invalid key size for RSA. Supported key sizes are 1024, 2048, 3072, 4096"

        } ElseIf ($Algorithm -eq 'ECDSA' -and (-not (@(256, 384, 521) -contains $KeySize))) {
            throw "$($MyInvocation.MyCommand): Invalid key size for ECDSA. Supported key sizes are 256, 384, 521"
        }
    }

    if ($Algorithm -eq 'RSA') {
        If($KeySize) {
            Write-Verbose "$($MyInvocation.MyCommand): Setting key size to $KeySize"
        } Else {
            $KeySize = 2048
        }

        Write-Verbose "$($MyInvocation.MyCommand): Creating RSA key"
        $PrivateKey = [System.Security.Cryptography.RSA]::Create($KeySize)
    } elseif ($Algorithm -eq 'ECDSA') {
        If($ECCurve) {
            Write-Verbose "$($MyInvocation.MyCommand): Creating ECDSA key with given curve"
            $PrivateKey = [System.Security.Cryptography.ECDsa]::Create($ECCurve)
        } Else {
            Write-Verbose "$($MyInvocation.MyCommand): Creating ECDSA key"
            $PrivateKey = [System.Security.Cryptography.ECDsa]::Create()
        }

        If($KeySize) {
            Write-Verbose "$($MyInvocation.MyCommand): Setting key size to $KeySize"
            $PrivateKey.KeySize = $KeySize
        }
    }

    Return $PrivateKey
}