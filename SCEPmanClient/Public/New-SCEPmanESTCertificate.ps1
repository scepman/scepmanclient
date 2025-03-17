Function New-SCEPmanESTCertificate {
    [CmdletBinding(DefaultParameterSetName='AzAuth')]
    Param(
        [Parameter(
            Mandatory,
            ParameterSetName='AzAuth',
            Position=0
        )]
        [String]$AppServiceUrl,
        [Parameter(ParameterSetName='AzAuth')]
        [String]$ResourceUrl,

        [Parameter(ParameterSetName='AzAuth')]
        [Switch]$IgnoreExistingSession,
        [Parameter(ParameterSetName='AzAuth')]
        [Switch]$DeviceCode,
        [Parameter(ParameterSetName='AzAuth')]
        [String]$ClientId,
        [Parameter(ParameterSetName='AzAuth')]
        [String]$TenantId,
        [Parameter(ParameterSetName='AzAuth')]
        [String]$ClientSecret,

        [Parameter(ParameterSetName='CertAuthFromObject')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(ParameterSetName='CertAuthFromStore')]
        [String]$CertificateBySubject,
        [Parameter(ParameterSetName='CertAuthFromFile')]
        [String]$CertificateFromFile,
        [Parameter(ParameterSetName='CertAuthFromFile')]
        [String]$KeyFromFile,

        [Switch]$SubjectFromUserContext,
        [Switch]$SubjectFromHostname,

        [String]$Subject,
        [String]$UPN,
        [String]$Email,
        [String]$DNSName,
        [String]$URI,
        [String]$IP,

        [ValidateSet('RSA', 'ECDSA')]
        [String]$SignatureAlgorithm,

        [ValidateSet('ClientAuth', 'ServerAuth', 'CodeSigning', 'EmailProtection', 'TimeStamping', 'OCSPSigning', 'SmartCardLogon', 'EncryptFileSystem', 'IPSecIKE', 'PSecIKEIntermediate', 'KDCAuth', 'IpSecurityUser')]
        [String[]]$ExtendedKeyUsage,
        [String[]]$ExtendedKeyUsageOID,

        [ValidateScript({ Test-Path $_ -PathType Container })]
        [String]$SaveToFolder,
        [ValidateSet('DER', 'PEM', 'PFX')]
        [String]$Format,
        [Switch]$IncludeRootCA,

        [String]$PlainTextPassword,
        [Switch]$NoPassword,



        [ValidateSet('LocalMachine', 'CurrentUser')]
        [String]$SaveToStore,
        [Switch]$Exportable
    )

    Begin {
        $ErrorActionPreference = 'Stop'

        If(-not $PSBoundParameters.ContainsKey('Format')) {
            If ($PSVersionTable.PSVersion.Major -lt 7) {
                $Format = 'PFX'
            } ElseIf (-not $Format -and -not $IsWindows) {
                $Format = 'PEM'
            } Else {
                $Format = 'PFX'
            }
        }

        If($PSCmdlet.ParameterSetName -eq 'CertAuthFromStore') {

            If ($PSBoundParameters.ContainsKey('CertificateBySubject')) {
                Write-Verbose "$($MyInvocation.MyCommand): Trying to find certificate by subject: $CertificateBySubject"
                $AllCertificates = (Get-ChildItem Cert:\CurrentUser\My\) + (Get-ChildItem Cert:\LocalMachine\My\)

                $Certificate = $AllCertificates | Where-Object { $_.Subject -match $CertificateBySubject }

                If (-not $Certificate) {
                    throw "$($MyInvocation.MyCommand): No certificate found with subject: $CertificateBySubject"
                } ElseIf ($Certificate.Count -gt 1) {
                    Write-Verbose "$($MyInvocation.MyCommand): Multiple certificates found by subject: $CertificateBySubject"

                    $Certificate = $Certificate | Select-Object -First 1

                    Write-Verbose "$($MyInvocation.MyCommand): Select first certificate with thumbprint: $($Certificate.Thumbprint)"
                } Else {
                    Write-Verbose "$($MyInvocation.MyCommand): Found certificate by subject: $($Certificate.Subject)"
                    Write-Verbose "$($MyInvocation.MyCommand): Thumbprint: $($Certificate.Thumbprint)"
                }
            }
        }

        If($PSCmdlet.ParameterSetName -eq 'CertAuthFromFile') {
            If (-not (Test-Path $CertificateFromFile)) {
                throw "$($MyInvocation.MyCommand): Certificate file not found: $CertificateFromFile"
            }

            If (-not (Test-Path $KeyFromFile)) {
                throw "$($MyInvocation.MyCommand): Key file not found: $KeyFromFile"
            }

            Write-Verbose "$($MyInvocation.MyCommand): Loading certificate from file: $CertificateFromFile"
            
            $PEM = Get-Content -Path $CertificateFromFile -Raw
            $Key = Get-Content -Path $KeyFromFile -Raw

            If ($PSBoundParameters.ContainsKey('NoPassword')) {
                $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($PEM, $Key)
            } Else {
                $Password = Read-Host -Prompt "Enter password for private key" -AsSecureString
                $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromEncryptedPem($PEM, $Key, ($Password | ConvertFrom-SecureString -AsPlainText))
            }
        }

        If($PSCmdlet.ParameterSetName -eq 'AzAuth') {
            Set-AzConfig -Scope Process -LoginExperienceV2 Off | Out-Null

            $Connect_Params = @{}
    
            If ($PSBoundParameters.ContainsKey('IgnoreExistingSession')) { $Connect_Params['IgnoreExistingSession'] = $true }
            If ($PSBoundParameters.ContainsKey('DeviceCode')) { $Connect_Params['DeviceCode'] = $true }
            If ($PSBoundParameters.ContainsKey('ClientId')) { $Connect_Params['ClientId'] = $ClientId }
            If ($PSBoundParameters.ContainsKey('TenantId')) { $Connect_Params['TenantId'] = $TenantId }
            If ($PSBoundParameters.ContainsKey('ClientSecret')) { $Connect_Params['ClientSecret'] = $ClientSecret }
    
            Connect-SCEPmanAzAccount @Connect_Params
    
            If (-not $PSBoundParameters.ContainsKey('ResourceUrl')) {
                Write-Verbose "$($MyInvocation.MyCommand): No resource URL provided. Trying to find Enterprise Application for URL: $AppServiceUrl"
                $ResourceUrl = Get-SCEPmanResourceUrl -AppServiceUrl $AppServiceUrl
            }
            
            $AccessToken = Get-SCEPmanAccessToken -ResourceUrl $ResourceUrl
        }
    }

    Process {

        If($PSCmdlet.ParameterSetName -in 'CertAuthFromObject', 'CertAuthFromStore') {
            $AppServiceUrl = Get-AppServiceUrlFromCertificate -Certificate $Certificate
            $PrivateKey = New-PrivateKeyFromCertificate -Certificate $Certificate
            $Request = New-CSRfromCertificate -Certificate $Certificate -PrivateKey $PrivateKey

            $NewCertificate = Invoke-ESTmTLSRequest -AppServiceUrl $AppServiceUrl -Certificate $Certificate -Request $Request
        }

        If($PSCmdlet.ParameterSetName -eq 'CertAuthFromFile') {
            $AppServiceUrl = Get-AppServiceUrlFromCertificate -Certificate $Certificate
            $PrivateKey = $Certificate.PrivateKey
            $Request = New-CSRfromCertificate -Certificate $Certificate -PrivateKey $PrivateKey

            $NewCertificate = Invoke-ESTmTLSRequest -AppServiceUrl $AppServiceUrl -Certificate $Certificate -Request $Request
        }

        If($PSCmdlet.ParameterSetName -eq 'AzAuth') {
            $PrivateKey_Params = @{}
            If($PSBoundParameters.ContainsKey('SignatureAlgorithm')) { $PrivateKey_Params['Algorithm'] = $SignatureAlgorithm }
    
            $PrivateKey = New-PrivateKey @PrivateKey_Params
    
            $Request_Params = @{}
            If ($PSBoundParameters.ContainsKey('SubjectFromUserContext')) {
                Write-Verbose "$($MyInvocation.MyCommand): SubjectFromUserContext is set. Using current user context for subject"
                $Request_Params['Subject'] = "CN=$((Get-AzContext).Account.id)"
                $Request_Params['UPN'] = (Get-AzContext).Account.id
            }
            If ($PSBoundParameters.ContainsKey('SubjectFromHostname')) {
                Write-Verbose "$($MyInvocation.MyCommand): SubjectFromHostname is set. Using hostname for subject: $(hostname)"
                $Request_Params['Subject'] = "CN=$(hostname)"
            }
            If($PSBoundParameters.ContainsKey('Subject')) { $Request_Params['Subject'] = $Subject }
            If($PSBoundParameters.ContainsKey('UPN')) { $Request_Params['UPN'] = $UPN }
            If($PSBoundParameters.ContainsKey('Email')) { $Request_Params['Email'] = $Email }
            If($PSBoundParameters.ContainsKey('DNSName')) { $Request_Params['DNSName'] = $DNSName }
            If($PSBoundParameters.ContainsKey('URI')) { $Request_Params['URI'] = $URI }
            If($PSBoundParameters.ContainsKey('IP')) { $Request_Params['IP'] = $IP }
            If($PSBoundParameters.ContainsKey('ExtendedKeyUsage')) { $Request_Params['ExtendedKeyUsage'] = $ExtendedKeyUsage }
            If($PSBoundParameters.ContainsKey('ExtendedKeyUsageOid')) { $Request_Params['ExtendedKeyUsageOid'] = $ExtendedKeyUsageOid }
    
            $Request = New-CSR -PrivateKey $PrivateKey @Request_Params
    
            $NewCertificate = Invoke-ESTRequest -AppServiceUrl $AppServiceUrl -AccessToken $AccessToken -Request $Request
        }
        
        If ($PSBoundParameters.ContainsKey('SaveToStore')) {
            Write-Verbose "$($MyInvocation.MyCommand): Saving certificate to store $SaveToStore"
            $SaveToStore_Params = @{
                'Certificate' = $NewCertificate
                'PrivateKey' = $PrivateKey
                'StoreName' = $SaveToStore
            }

            If ($PSBoundParameters.ContainsKey('Exportable')) { $SaveToStore_Params['Exportable'] = $true }

            Save-CertificateToStore @SaveToStore_Params
        }

        If ($PSBoundParameters.ContainsKey('SaveToFolder')) {
            If ($Format -eq 'PFX') {
                $MergedCertificate = Get-MergedCertificate -Certificate $NewCertificate -PrivateKey $PrivateKey

                If ($PSBoundParameters.ContainsKey('PlainTextPassword')) {
                    $Password = $PlainTextPassword
                } Else {
                    $Password = (Read-Host -Prompt "Enter password for PFX" -AsSecureString) | ConvertFrom-SecureString -AsPlainText
                }

                $Pkcs12 = $MergedCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $Password)

                If ($PSVersionTable.PSVersion.Major -lt 7) {
                    $Pkcs12 | Set-Content -Path "$SaveToFolder\$($NewCertificate.Subject).pfx" -Encoding Byte
                } Else {
                    $Pkcs12 | Set-Content -Path "$SaveToFolder\$($NewCertificate.Subject).pfx" -AsByteStream
                }

                Write-Verbose "$($MyInvocation.MyCommand): Successfully saved Pkcs12 bundle to $SaveToFolder"
            } Else {
                Write-Verbose "$($MyInvocation.MyCommand): Saving certificate to folder $SaveToFolder"
                Save-CertificateToFile -Certificate $NewCertificate -FilePath "$SaveToFolder\$($NewCertificate.Subject)" -Format $Format

                If (-not $PSBoundParameters.ContainsKey('KeyFromFile')) {
                    Write-Verbose "$($MyInvocation.MyCommand): Saving private key to folder $SaveToFolder"
                    If ( -not $PSBoundParameters.ContainsKey('NoPassword')) {
                        Save-PrivateKeyToFile -PrivateKey $PrivateKey -FilePath "$SaveToFolder\$($NewCertificate.Subject).key" -Password (Read-Host -Prompt "Enter password for private key" -AsSecureString)
                    } ElseIf ($PSBoundParameters.ContainsKey('PlainTextPassword')) {
                        Save-PrivateKeyToFile -PrivateKey $PrivateKey -FilePath "$SaveToFolder\$($NewCertificate.Subject).key" -Password ($PlainTextPassword | ConvertTo-SecureString -AsPlainText -Force)
                    } Else {
                        Save-PrivateKeyToFile -PrivateKey $PrivateKey -FilePath "$SaveToFolder\$($NewCertificate.Subject).key"
                    }
                }

                If (-not $PSBoundParameters.ContainsKey('IncludeRootCA')) {
                    Write-Verbose "$($MyInvocation.MyCommand): Saving root CA certificate to folder $SaveToFolder"
                    $RootCertificate = Get-ESTRootCA -AppServiceUrl $AppServiceUrl
                    Save-CertificateToFile -Certificate $RootCertificate -FilePath "$SaveToFolder\$($RootCertificate.Subject)" -Format $Format
                }
            }
        }

        Return (Get-MergedCertificate -Certificate $NewCertificate -PrivateKey $PrivateKey)
    }
}