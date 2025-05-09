# Module manifest docs: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_module_manifests

@{

  RootModule = 'SCEPmanClient.psm1'
  # Version will be set in release branches
  ModuleVersion = '2.10.2'
  GUID = '4a5f64cc-e043-4d40-baa1-95cbb25ca9e3'
  Author = 'glueckkanja AG'
  Description = 'PowerShell module to interact with SCEPman EST API'
  CompanyName = 'glueckkanja AG'

  PrivateData = @{
    PSData = @{
      Tags = @('SCEPman', 'EST', 'API', 'SCEP', 'PKI', 'Certificate')
      LicenseUri = ''
      ProjectUri = 'https://scepman.com'
      IconUri = 'https://raw.githubusercontent.com/scepman/scepmanclient/main/SCEPmanClient/scepman-icon.png'
      Prerelease = 'beta'
    }
  }

  RequiredModules = @(
    @(
        'Az.Accounts',
        'Az.Resources'
    )
  )

  FunctionsToExport = @(
    'Get-ESTRootCA',
    'Invoke-ESTmTLSRequest',
    'Invoke-ESTRequest',
    'Invoke-SCEPRenewal',
    'New-CSR',
    'New-PrivateKey',
    'New-SCEPmanCertificate'
  )

}
