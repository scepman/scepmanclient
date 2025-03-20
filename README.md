# SCEPmanClient
This PowerShell module provides an interface for the Enrollment over Secure Transport (EST) protocol, facilitating secure and automated certificate enrollment and renewal. While it is designed to work with various EST servers, it offers enhanced compatibility with SCEPman.

# Prerequisites
You need to modify the existing scepman-api (default name) app registration with the following changes:

1. Add SCEPman's App Service URL:
Navigate to the `Branding & Properties` section of the app registration.
Add SCEPman's App Service URL to the Home page URL field.

2. Expose an API:
Go to the `Expose an API` section of the app registration.
Create a custom scope that can be used to authorize the client ID `1950a258-227b-4e31-a9cf-717495945fc2` (Microsoft Azure PowerShell).

# Usage

## Use Azure Authentication
### Interactive Authentication
When requesting a new certificate without specifying the authentication mechanism, the user will be authenticated interactively by default. By using the `-SubjectFromUserContext` parameter, the certificate's subject and UPN SAN will be automatically populated based on the logged-in user's context:
```powershell
New-SCEPmanESTCertificate -Url 'scepman.contoso.com' -SubjectFromUserContext -SaveToStore CurrentUser
```

### Device Login
If you want to request a new certificate on a system without any desktop environment you can use the `-DeviceCode` parameter to perform the actual authentication on another session:
```powershell
New-SCEPmanESTCertificate -Url 'scepman.contoso.com' -DeviceCode -SubjectFromUserContext -SaveToFolder /home/user/certificates
```

### Service Principal Authentication
In fully automated scenarios an App Registration can be used for authentication. Inferring the subject from the authenticated context will not be possible in this case.

Parameter splatting will also make the execution more readable:

```powershell
$Parameters = @{
    'Url'              = 'scepman.contoso.com'
    'ClientId'         = '569fbf51-aa63-4b5c-8b26-ebbcfcde2715'
    'TenantId'         = '8aa3123d-e76c-42e2-ba3c-190cabbec531'
    'ClientSecret'     = 'csa8Q~aVaWCLZTzswIBGvhxUiEvhptuqEyJugb70'
    'Subject'          = 'CN=WebServer'
    'DNSName'          = 'Webserver.domain.local'
    'ExtendedKeyUsage' = 'ServerAuth'
    'SaveToStore'      = 'LocalMachine'
}

New-SCEPmanESTCertificate @Parameters
```

## Authenticate using certificates
Once a certificate has been issued using an authenticated context we can use it to renew it without providing any context again.

### CertificateBySubject
*Interacting with keystores is only possible on Windows*

When providing the `CertificateBySubject` parameter, the module will automatically try find a suitable certificate for renewal in the *CurrentUser* and *LocalMachine* keystores.

The entered value will be regex matched against the subjects in all available certificates.

```powershell
New-SCEPmanESTCertificate -CertificateBySubject 'WebServer' -SaveToStore 'LocalMachine'
```

### Provide a specific certificate
```powershell
$Certificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object Thumbprint -eq '9B08EA68B16773CEF3C49D5D95BE50B784638984'

New-SCEPmanESTCertificate -Certificate $Certificate -SaveToStore LocalMachine
```

### CertificateFromFile
On Linux system a certificate renewal can be performed by passing the paths of the existing certificate and its private key.

```powershell
New-SCEPmanESTCertificate -CertificateFromFile '~/certs/myCert.pem' -KeyFromFile '~/certs/myKey.key' -SaveToFolder '~/certs'
```

When using an encrypted private key you will asked for the password. You can also directly pass the keys password using the `PlainTextPassword` parameter.