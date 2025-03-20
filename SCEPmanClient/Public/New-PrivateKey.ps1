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
        If ($Algorithm -eq 'RSA' -and (-not (@(1024, 2048, 3072, 4096) -contains $_))) {
            throw "$($MyInvocation.MyCommand): Invalid key size for RSA. Supported key sizes are 1024, 2048, 3072, 4096"

        } ElseIf ($Algorithm -eq 'ECDSA' -and (-not (@(256, 384, 521) -contains $_))) {
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