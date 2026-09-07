# Manual smoke tests

These tests issue real certificates and call real SCEPman endpoints. They are intentionally separate from the Pester unit tests in `Tests` and run only when invoked manually.

## Covered scenarios

| Protocol | Authentication | Intended authorization |
| --- | --- | --- |
| EST self-service | Existing Azure CLI context | `CSR.SelfService` |
| EST arbitrary CSR | App registration client secret | `CSR.Request.Db` |
| EST direct token | Token in the local config | SCEPman SaaS token flow |
| EST renewal | Certificate issued by an earlier scenario | No Azure context |
| SCEP enrollment | Challenge password in the local config | Static SCEP endpoint |
| SCEP renewal | Certificate issued by an earlier scenario | No Azure context |
| Management search | App registration client secret | `Manage.All` |

The management check performs a read-only search. It does not revoke certificates.

## Configure

PowerShell 7 or later, the module dependencies, and Azure CLI are required. Sign in before running an `AzureCli` scenario:

```powershell
az login
az account show
```

Copy only the templates you need and remove `.template` from the copied file name. Local JSON files in `SmokeTests/Configs` are ignored by Git.

```powershell
Copy-Item ./SmokeTests/Configs/est.template.json ./SmokeTests/Configs/est.json
Copy-Item ./SmokeTests/Configs/scep.template.json ./SmokeTests/Configs/scep.json
```

Replace the URLs, resource/audience URI, tenant IDs, client IDs, request identities, and credential placeholders in each local file. `ResourceUrl` is the Application ID URI used as the access-token audience, not necessarily the SCEPman web URL.

Service-principal secrets use `Authentication.ClientSecret`, supplied SaaS tokens use `Authentication.AccessToken`, and SCEP challenges use `ChallengePassword`. These values are intentionally stored directly in the local JSON for convenient smoke testing. Never put real credentials into a `.template.json` file; ordinary JSON files in `SmokeTests/Configs` are ignored by Git.

For an existing Az PowerShell context instead of Azure CLI, run `Connect-AzAccount` and change the scenario's authentication type from `AzureCli` to `AzContext`. With `AzContext`, `SubjectFromUserContext` is resolved by the module. With `AzureCli`, the runner derives the subject and UPN from `az account show`.

## Run

Run one config:

```powershell
./SmokeTests/Invoke-SmokeTests.ps1 ./SmokeTests/Configs/est.json
```

Run multiple configs, which may target different servers:

```powershell
./SmokeTests/Invoke-SmokeTests.ps1 ./SmokeTests/Configs/*.json
```

Validate JSON and required top-level structure without contacting any endpoint:

```powershell
./SmokeTests/Invoke-SmokeTests.ps1 ./SmokeTests/Configs/*.json -ValidateOnly
```

Run selected scenarios by their exact names:

```powershell
./SmokeTests/Invoke-SmokeTests.ps1 ./SmokeTests/Configs/est.json `
    -Scenario 'EST arbitrary CSR using CSR.Request.Db','EST renewal without auth context'
```

Renewal scenarios reference `SourceScenario`, so the source scenario must run earlier in the same config. Include both names when filtering with `-Scenario`.

Use `-StopOnFailure` to stop after the first failed scenario. Successful certificates remain only in memory and are not installed or exported.

## Config reference

Every config contains shared `Name`, `Url`, optional `ResourceUrl`, optional `Endpoint`, and a `Scenarios` array. A scenario can override `Url`, `ResourceUrl`, or `Endpoint`.

Supported protocol values are `EST`, `ESTRenewal`, `SCEP`, `SCEPRenewal`, and `ManagementSearch`. Supported authentication types for EST and management are `AzureCli`, `AzContext`, `ServicePrincipal`, and `AccessToken`.

The optional `Expected` object supports `SubjectRegex`, `IssuerRegex`, and `MinimumRemainingDays`. Every enrollment and renewal also verifies that the returned certificate has a private key and is not expired.