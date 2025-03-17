Function New-PrivateKey {
    Param(
        [Parameter()]
        [ValidateSet('RSA', 'ECDSA')]
        [String]$Algorithm = 'RSA',

        [Parameter()]
        [ValidateScript({
            If ($Algorithm -eq 'RSA') {
                If (-not (@(1024, 2048, 3072, 4096) -contains $_)) {
                    throw "$($MyInvocation.MyCommand): Invalid key size for RSA. Supported key sizes are 1024, 2048, 3072, 4096"
                }
                return $true
            } ElseIf ($Algorithm -eq 'ECDSA') {
                If (-not (@(256, 384, 521) -contains $_)) {
                    throw "$($MyInvocation.MyCommand): Invalid key size for ECDSA. Supported key sizes are 256, 384, 521"
                }
                return $true
            }
        })]
        [Int]$KeySize,

        $ECDsaCurve
    )
    
    if ($Algorithm -eq 'RSA') {
        If($KeySize) {
            Write-Verbose "$($MyInvocation.MyCommand): Setting key size to $KeySize"
        } Else {
            $KeySize = 2048
        }

        Write-Verbose "$($MyInvocation.MyCommand): Creating RSA key"
        $PrivateKey = [System.Security.Cryptography.RSA]::Create($KeySize)
    } elseif ($Algorithm -eq 'ECDSA') {
        If($ECDsaCurve) {
            Write-Verbose "$($MyInvocation.MyCommand): Creating ECDSA key with given curve"
            $PrivateKey = [System.Security.Cryptography.ECDsa]::Create($ECDsaCurve)
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