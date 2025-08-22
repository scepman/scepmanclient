<#
.SYNOPSIS
    Request a new certificate from SCEPman using EST.

.DESCRIPTION
    This function requests a new certificate from SCEPman using EST. The function supports different authentication methods and certificate sources.

.PARAMETER Url
    The URL of the SCEPman service.

.PARAMETER ResourceUrl
    The URL of the SCEPman service. If not provided, the function will try to find the Enterprise Application for the URL.

.PARAMETER IgnoreExistingSession
    Ignore existing Azure session.

.PARAMETER DeviceCode
    Use device code authentication.

.PARAMETER ClientId
    The client ID for service principal authentication.

.PARAMETER TenantId
    The tenant ID for service principal authentication.

.PARAMETER ClientSecret
    The client secret for service principal authentication.

.PARAMETER Certificate
    The certificate to use for authentication.

.PARAMETER CertificateBySubject
    The subject of the certificate to use for authentication. This parameter is used to find the certificate in the certificate store by matching the input of the parameter with the Subject property of the certificate using regex.

.PARAMETER CertificateFromFile
    The path to the certificate file to use for authentication.

.PARAMETER KeyFromFile
    The path to the private key file to use for authentication.

.PARAMETER Csr
    An already prepared Csr that should be sent to the EST server.

.PARAMETER UseSCEPRenewal
    Use SCEP renewal to request the certificate.

.PARAMETER SubjectFromUserContext
    Use the current user context for the subject.

.PARAMETER SubjectFromHostname
    Use the hostname for the subject.

.PARAMETER Subject
    The subject of the certificate.

.PARAMETER UPN
    User principal name to be added to the certificates subject alternative name.

.PARAMETER Email
    Email to be added to the certificates subject alternative name.

.PARAMETER DNSName
    DNS name to be added to the certificates subject alternative name.

.PARAMETER URI
    URI to be added to the certificates subject alternative name.

.PARAMETER IP
    IP address to be added to the certificates subject alternative name.

.PARAMETER SignatureAlgorithm
    The signature algorithm to use for the private key.

.PARAMETER ExtendedKeyUsage
    The extended key usage to add to the certificate.

.PARAMETER ExtendedKeyUsageOID
    The extended key usage OID to add to the certificate.

.PARAMETER SaveToFolder
    The folder to save the certificate to.

.PARAMETER Format
    The format to save the certificate in. Default is PFX. Possible values are DER, PEM, PFX.

.PARAMETER IncludeRootCA
    Include the root CA certificate if the certificate is saved to a folder.

.PARAMETER PlainTextPassword
    The password for the private key in plain text.

.PARAMETER NoPassword
    Do not use a password for the private key.

.PARAMETER SaveToKeyVault
    Import the certificate to the given Azure Key Vault.

.PARAMETER KeyVaultCertificateName
    This is the name of the certificate that should be imported to the Azure Key Vault.

.PARAMETER SaveToStore
    Save the certificate to the certificate store. Possible values are LocalMachine, CurrentUser.

.PARAMETER Exportable
    Mark the private key as exportable.

.PARAMETER UserProtected
    Indicates whether the private key should be user-protected. This will prompt the user for a confirmation or password when accessing the private key.

.PARAMETER ValidityPeriod
    The validity period of the certificate request.

.PARAMETER ValidityPeriodUnits
    The units for the validity period of the certificate request.

#>

Function New-SCEPmanCertificate {
    [CmdletBinding(DefaultParameterSetName='AzAuth')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "", Justification="The parameter PlainTextPassword is meant to be.. plain text.")]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "", Justification="The parameter PlainTextPassword is meant to be.. plain text.")]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingUsernameAndPasswordParams", "", Justification="Service principal authentication requires username and password.")]
    Param(
        [Parameter(
            Mandatory,
            ParameterSetName='AzAuth',
            Position=0
        )]
        [Alias('AppServiceUrl')]
        [String]$Url,
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

        [String]$Csr,

        [Switch]$UseSCEPRenewal,

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

        [String]$SaveToKeyVault,
        [String]$KeyVaultCertificateName,

        [ValidateSet('LocalMachine', 'CurrentUser')]
        [String]$SaveToStore,
        [Switch]$Exportable,
        [Switch]$UserProtected,

        [ValidityPeriod]$ValidityPeriod = [ValidityPeriod]::Days,
        [Int]$ValidityPeriodUnits
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
            Set-AzConfig -Scope Process -LoginExperienceV2 Off -DisplaySurveyMessage $false | Out-Null

            $Connect_Params = @{}

            If ($PSBoundParameters.ContainsKey('IgnoreExistingSession')) { $Connect_Params['IgnoreExistingSession'] = $true }
            If ($PSBoundParameters.ContainsKey('DeviceCode')) { $Connect_Params['DeviceCode'] = $true }
            If ($PSBoundParameters.ContainsKey('ClientId')) { $Connect_Params['ClientId'] = $ClientId }
            If ($PSBoundParameters.ContainsKey('TenantId')) { $Connect_Params['TenantId'] = $TenantId }
            If ($PSBoundParameters.ContainsKey('ClientSecret')) { $Connect_Params['ClientSecret'] = $ClientSecret }

            Connect-SCEPmanAzAccount @Connect_Params

            If (-not $PSBoundParameters.ContainsKey('ResourceUrl')) {
                Write-Verbose "$($MyInvocation.MyCommand): No resource URL provided. Trying to find Enterprise Application for URL: $Url"
                $ResourceUrl = Get-SCEPmanResourceUrl -AppServiceUrl $Url
            }

            $AccessToken = Get-SCEPmanAccessToken -ResourceUrl $ResourceUrl
        }
    }

    Process {

        If($PSCmdlet.ParameterSetName -in 'CertAuthFromObject', 'CertAuthFromStore') {
            $Url = Get-AppServiceUrlFromCertificate -Certificate $Certificate
            $PrivateKey = New-PrivateKeyFromCertificate -Certificate $Certificate

            If($UseSCEPRenewal) {
                $RootCertificate = Get-ESTRootCA -Url $Url
                $Request = New-CSRfromCertificate -Certificate $Certificate -PrivateKey $PrivateKey -Raw
                $NewCertificate = Invoke-SCEPRenewal -Url $Url -SignerCertificate $Certificate -RecipientCertificate $RootCertificate -RawRequest $Request
            } Else {
                $Request = New-CSRfromCertificate -Certificate $Certificate -PrivateKey $PrivateKey
                $NewCertificate = Invoke-ESTmTLSRequest -AppServiceUrl $Url -Certificate $Certificate -Request $Request
            }
        }

        If($PSCmdlet.ParameterSetName -eq 'CertAuthFromFile') {
            $Url = Get-AppServiceUrlFromCertificate -Certificate $Certificate
            $PrivateKey = $Certificate.PrivateKey

            If($UseSCEPRenewal) {
                $RootCertificate = Get-ESTRootCA -Url $Url
                $Request = New-CSRfromCertificate -Certificate $Certificate -PrivateKey $PrivateKey -Raw
                $NewCertificate = Invoke-SCEPRenewal -Url $Url -SignerCertificate $Certificate -RecipientCertificate $RootCertificate -RawRequest $Request
            } Else {
                $Request = New-CSRfromCertificate -Certificate $Certificate -PrivateKey $PrivateKey
                $NewCertificate = Invoke-ESTmTLSRequest -AppServiceUrl $Url -Certificate $Certificate -Request $Request
            }
        }

        If($PSCmdlet.ParameterSetName -eq 'AzAuth') {

            If($PSBoundParameters.ContainsKey('Csr')) {
                $Request = $Csr
            } Else {
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
                If($PSBoundParameters.ContainsKey('ValidityPeriod')) { $Request_Params['ValidityPeriod'] = $ValidityPeriod }
                If($PSBoundParameters.ContainsKey('ValidityPeriodUnits')) { $Request_Params['ValidityPeriodUnits'] = $ValidityPeriodUnits }

                $Request = New-CSR -PrivateKey $PrivateKey @Request_Params
            }

            $NewCertificate = Invoke-ESTRequest -AppServiceUrl $Url -AccessToken $AccessToken -Request $Request

        } ElseIf($PSCmdlet.ParameterSetName -in 'CertAuthFromObject', 'CertAuthFromStore', 'CertAuthFromFile') {
            $Url = Get-AppServiceUrlFromCertificate -Certificate $Certificate

            $PrivateKey = If($PSCmdlet.ParameterSetName -eq 'CertAuthFromFile') {
                $Certificate.PrivateKey
            } Else {
                New-PrivateKeyFromCertificate -Certificate $Certificate
            }

            If($UseSCEPRenewal) {
                $RootCertificate = Get-ESTRootCA -Url $Url
                $Request = New-CSRfromCertificate -Certificate $Certificate -PrivateKey $PrivateKey -Raw
                $NewCertificate = Invoke-SCEPRenewal -Url $Url -SignerCertificate $Certificate -RecipientCertificate $RootCertificate -RawRequest $Request
            } Else {
                $Request = New-CSRfromCertificate -Certificate $Certificate -PrivateKey $PrivateKey
                $NewCertificate = Invoke-ESTmTLSRequest -AppServiceUrl $Url -Certificate $Certificate -Request $Request
            }
        }

        If ($PSBoundParameters.ContainsKey('SaveToStore')) {
            Write-Verbose "$($MyInvocation.MyCommand): Saving certificate to store $SaveToStore"
            $SaveToStore_Params = @{
                'Certificate' = $NewCertificate
                'PrivateKey' = $PrivateKey
                'StoreName' = $SaveToStore
            }

            If ($PSBoundParameters.ContainsKey('Exportable')) { $SaveToStore_Params['Exportable'] = $true }
            If ($PSBoundParameters.ContainsKey('UserProtected')) { $SaveToStore_Params['UserProtected'] = $true }

            Save-CertificateToStore @SaveToStore_Params
        }

        If ($PSBoundParameters.ContainsKey('SaveToFolder')) {
            If ($Format -eq 'PFX') {
                $MergedCertificate = Get-MergedCertificate -Certificate $NewCertificate -PrivateKey $PrivateKey

                If (-not $PSBoundParameters.ContainsKey('NoPassword')) {
                    If ($PSBoundParameters.ContainsKey('PlainTextPassword')) {
                        $Password = $PlainTextPassword
                    } Else {
                        $Password = (Read-Host -Prompt "Enter password for PFX" -AsSecureString) | ConvertFrom-SecureString -AsPlainText
                    }
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
                        Save-PrivateKeyToFile -PrivateKey $PrivateKey -FilePath "$SaveToFolder\$($NewCertificate.Subject).key" -Password (Read-Host -Prompt "Enter password for private key" -AsSecureString) -Format $Format
                    } ElseIf ($PSBoundParameters.ContainsKey('PlainTextPassword')) {
                        Save-PrivateKeyToFile -PrivateKey $PrivateKey -FilePath "$SaveToFolder\$($NewCertificate.Subject).key" -Password ($PlainTextPassword | ConvertTo-SecureString -AsPlainText -Force) -Format $Format
                    } Else {
                        Save-PrivateKeyToFile -PrivateKey $PrivateKey -FilePath "$SaveToFolder\$($NewCertificate.Subject).key" -Format $Format
                    }
                }

                If (-not $PSBoundParameters.ContainsKey('IncludeRootCA')) {
                    Write-Verbose "$($MyInvocation.MyCommand): Saving root CA certificate to folder $SaveToFolder"
                    $RootCertificate = Get-ESTRootCA -AppServiceUrl $Url
                    Save-CertificateToFile -Certificate $RootCertificate -FilePath "$SaveToFolder\$($RootCertificate.Subject)" -Format $Format
                }Y
            }
        }

        If($PSBoundParameters.ContainsKey('SaveToKeyVault')) {
            Get-MergedCertificate -Certificate $NewCertificate -PrivateKey $PrivateKey | Import-AzKeyVaultCertificate -VaultName $SaveToKeyVault -Name $KeyVaultCertificateName
        }

        If($PSBoundParameters.ContainsKey('Csr')) {
            Return $NewCertificate
        } Else {
            Return (Get-MergedCertificate -Certificate $NewCertificate -PrivateKey $PrivateKey)
        }

    }
}