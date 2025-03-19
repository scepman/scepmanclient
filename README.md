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

