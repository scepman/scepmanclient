# Define this callback in C#, so it doesn't require a PowerShell runspace to run. This way, it can be called back in a different thread.
$csCodeSelectFirstCertificateCallback = @'
public static class CertificateCallbacks
{
    public static System.Security.Cryptography.X509Certificates.X509Certificate SelectFirstCertificate(
        object sender,
        string targetHost,
        System.Security.Cryptography.X509Certificates.X509CertificateCollection localCertificates,
        System.Security.Cryptography.X509Certificates.X509Certificate remoteCertificate,
        string[] acceptableIssuers)
    {
        return localCertificates[0];
    }

    public static System.Net.Security.LocalCertificateSelectionCallback SelectionCallback {
        get {
            return SelectFirstCertificate;
        }
    }
}
'@
Add-Type -TypeDefinition $csCodeSelectFirstCertificateCallback -Language CSharp


<#
.SYNOPSIS
    Sends a mTLS request to an EST endpoint.

.DESCRIPTION
    Sends a mTLS request to an EST endpoint. This function uses the HttpClientHandler in PowerShell 5 and the SocketsHttpHandler in PowerShell 7.
    The function will throw an error if the certificate does not have a private key.

.PARAMETER Url
    The URL of the EST service.

.PARAMETER Endpoint
    The endpoint of the EST service. Default is '/.well-known/est/simplereenroll'.

.PARAMETER Certificate
    The certificate to use for the mTLS request.

.PARAMETER Request
    The request to send to the EST service.

.EXAMPLE
    $Certificate = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Subject -eq "CN=ESTClient" }
    $PrivateKey = New-PrivateKeyFromCertificate -Certificate $Certificate
    $Request = New-CSRFromCertificate -Certificate $Certificate
    $Response = Invoke-ESTmTLSRequest -Url "https://est.example.com" -Certificate $Certificate -Request $Request
#>

Function Invoke-ESTmTLSRequest {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2Collection])]
    Param(
        [Parameter(Mandatory)]
        [Alias('AppServiceUrl')]
        [String]$Url,
        [Parameter()]
        [String]$Endpoint = '/.well-known/est/simplereenroll',
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)]
        [String]$Request
    )

    If (-not $Certificate.HasPrivateKey) {
        throw "$($MyInvocation.MyCommand): Certificate does not have a private key"
    }

    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Verbose "$($MyInvocation.MyCommand): Detected PowerShell 5: Using HttpClientHandler"
        Add-Type -AssemblyName System.Net.Http
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.ClientCertificates.Add($Certificate) | Out-Null
    } else {
        Write-Verbose "$($MyInvocation.MyCommand): Detected PowerShell 7: Using SocketsHttpHandler"
        $handler = New-Object System.Net.Http.SocketsHttpHandler

        # SocketsHttpHandler's ClientCertificateOptions is internal. So we need to use reflection to set it. If we leave it at 'Automatic', it would require the certificate to be in the store.
        try {
            $SocketHandlerType = $handler.GetType()
            $ClientCertificateOptionsProperty = $SocketHandlerType.GetProperty("ClientCertificateOptions", [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
            $ClientCertificateOptionsProperty.SetValue($handler, [System.Net.Http.ClientCertificateOption]::Manual)
        }
        catch {
            Write-Warning "$($MyInvocation.MyCommand): Couldn't set ClientCertificateOptions to Manual. This should cause an issue if the certificate is not in the MY store. This is probably due to a too recent .NET version (> 8.0)."
        }
        $handler.SslOptions.LocalCertificateSelectionCallback = [CertificateCallbacks]::SelectionCallback # This just selects the first certificate in the collection. We only provide a single certificate, so this suffices.
        $handler.SslOptions.ClientCertificates = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $null = $handler.SslOptions.ClientCertificates.Add($Certificate)
    }

    $Uri = ($Url -replace '/$') + $Endpoint

    $requestmessage = [System.Net.Http.HttpRequestMessage]::new()
    $requestmessage.Content = [System.Net.Http.StringContent]::new(
        $Request,
        [System.Text.Encoding]::UTF8,"application/pkcs10"
    )
    $requestmessage.Content.Headers.ContentType = "application/pkcs10"
    $requestmessage.Method = 'POST'
    $requestmessage.RequestUri = $Uri

    $client = New-Object System.Net.Http.HttpClient($handler)
    Write-Verbose "$($MyInvocation.MyCommand): Sending EST request to $Uri"

    try {
        $httpResponseMessage = $client.SendAsync($requestmessage).GetAwaiter().GetResult()
    }
    catch {
        # dump details of the exception, including InnerException
        $ex = $_.Exception
        Write-Error "$($MyInvocation.MyCommand): $($ex.GetType()): $($ex.Message)"
        while ($ex.InnerException) {
            $ex = $ex.InnerException
            Write-Error "$($MyInvocation.MyCommand): $($ex.GetType()): $($ex.Message)"
        }
    }
    If ($httpResponseMessage.StatusCode -eq 'InternalServerError') {
        throw "$($MyInvocation.MyCommand): Failed to renew certificate. Status code: $($httpResponseMessage.StatusCode) - Check if certificate renewals are allowed on this endpoint and check application logs"
    } ElseIf ($httpResponseMessage.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
        throw "$($MyInvocation.MyCommand): Failed to renew certificate. Status code: $($httpResponseMessage.StatusCode)"
    }

    $Response =  $httpResponseMessage.Content.ReadAsStringAsync().Result
    $client.Dispose()
    $handler.Dispose()

    $CertificateCollection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    $DERCertificate = [System.Convert]::FromBase64String($Response)
    $CertificateCollection.Import($DERCertificate)

    Return $CertificateCollection
}