<#
.SYNOPSIS
    Creates a new certificate object in a given Azure Key Vault.

.DESCRIPTION
    Creates a key pair in a Key Vault and fulfills the resulting CSR by providing it to SCEPman.

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

.PARAMETER ExtendedKeyUsage
    The extended key usage to add to the certificate.

.PARAMETER ExtendedKeyUsageOID
    The extended key usage OID to add to the certificate.

.PARAMETER Url
    The URL of the SCEPman service.

.PARAMETER VaultName
    The name of the Azure Key Vault where the certificate will be stored.

.PARAMETER Subject
    The subject of the certificate to be created.

.PARAMETER CertificateName
    The name of the certificate to be created in the Key Vault.

.PARAMETER KeyVaultPolicy
    An optional Key Vault certificate policy to use when creating the certificate.

.EXAMPLE
    New-SCEPmanKeyVaultCertificate -Url 'https://scepman.contoso.com' -KeyVaultUrl 'https://kv-contoso0345.vault.azure.net/' -Subject 'CN=Test' -CertificateName 'TestCert' -ExtendedKeyUsage 'ClientAuth', 'ServerAuth'

    Creates a new certificate in the Key Vault with the specified subject and name, including client and server authentication extended key usages.
#>

Function New-SCEPmanKeyVaultCertificate {
    [CmdletBinding(DefaultParameterSetName='AzAuth')]
    Param(
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

        [ValidateSet('ClientAuth', 'ServerAuth', 'CodeSigning')]
        [String[]]$ExtendedKeyUsage = @(),
        [String[]]$ExtendedKeyUsageOID = @(),

        [Parameter(
            Mandatory,
            ParameterSetName='AzAuth',
            Position=0
        )]
        [Alias('AppServiceUrl')]
        [String]$Url,
        [Parameter(Mandatory)]
        [String]$VaultName,
        [Parameter(Mandatory)]
        [String]$Subject,
        [Parameter(Mandatory)]
        [String]$CertificateName,
        [object]$KeyVaultPolicy
    )

    Begin {
        $TempFile = New-TemporaryFile

        If($PSCmdlet.ParameterSetName -eq 'AzAuth') {
            Set-AzConfig -Scope Process -LoginExperienceV2 Off -DisplaySurveyMessage $false | Out-Null

            $Connect_Params = @{}

            If ($PSBoundParameters.ContainsKey('IgnoreExistingSession')) { $Connect_Params['IgnoreExistingSession'] = $true }
            If ($PSBoundParameters.ContainsKey('DeviceCode')) { $Connect_Params['DeviceCode'] = $true }
            If ($PSBoundParameters.ContainsKey('ClientId')) { $Connect_Params['ClientId'] = $ClientId }
            If ($PSBoundParameters.ContainsKey('TenantId')) { $Connect_Params['TenantId'] = $TenantId }
            If ($PSBoundParameters.ContainsKey('ClientSecret')) { $Connect_Params['ClientSecret'] = $ClientSecret }

            Connect-SCEPmanAzAccount @Connect_Params
        }
    }

    Process {
        If(-not $KeyVaultPolicy) {
            $EkuOids = $ExtendedKeyUsageOID + ($ExtendedKeyUsage | Foreach-Object { $constant_EKUDefinition.$_ })
            $KeyVaultPolicy = New-AzKeyVaultCertificatePolicy -SubjectName $Subject -IssuerName Unknown -Ekus $EkuOids
        }

        $ExistingCertificate = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName
        If ($ExistingCertificate) {
            Write-Verbose "$($MyInvocation.MyCommand): Certificate with name '$CertificateName' already exists in Key Vault '$VaultName'."
            Write-Verbose "$($MyInvocation.MyCommand): Skipping creation of new certificate."
            return
        }

        try {
            $CertificateObject = Add-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -CertificatePolicy $KeyVaultPolicy -ErrorAction Stop
        } catch {
            Write-Error "$($MyInvocation.MyCommand): Failed to create certificate request."
            Write-Error "$($MyInvocation.MyCommand): $_"
            return
        }

        $Certificate = New-SCEPmanCertificate $Url -CSR $CertificateObject.CertificateSigningRequest

        Set-Content -Path $TempFile -Value $Certificate.ExportCertificatePem()

        try {
            $Response = Import-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName -FilePath $TempFile
        } catch {
            Write-Error "$($MyInvocation.MyCommand): Failed to import certificate into Key Vault."
            Write-Error "$($MyInvocation.MyCommand): $_"
        }

        Write-Verbose "$($MyInvocation.MyCommand): Certificate imported into Key Vault to version $($Response.Version)"
    }

    End {
        If(Test-Path -Path $TempFile) {
            Remove-Item -Path $TempFile
        }
    }
}
