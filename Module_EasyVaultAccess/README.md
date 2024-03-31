# EasyVaultAccess

EasyVaultAccess is a PowerShell module that makes starting off with, and keeping up use of, secrets managers / key vaults (particularly Azure Key Vault) easy, fast, and convenient.


## Problem Statement

Managing credentials in an automated environment presents several challenges:

- Storing passwords on disk in readable files can lead to accidental exposure.
- Entering passwords only at the time of use is secure but not suitable for automation.
- Per-device local encryption (DPAPI and exporting securestrings) is a good solution, but it raises questions about who has access, who can revoke access, and where this can be done.
- Sharing and rotating credentials can be logistically difficult, and once a credential is out, it's out.


## Solution

Using Azure Key Vault secrets fetched via an app registration certificate delegated permission, we can integrate easily into preexisting PowerShell workflows that use credentials, all the while ensuring we grant only ACCESS and not the CONTENT of such credentials.


## Prerequisites

See [Resources] section below for some helpful links related to this Azure portion.

- Azure tenant (can be personally created with no up front cost) 
- Az powershell cmdlets installed (Install-Module Az -Scope AllUsers)
- Azure Key Vault created 
- Azure app registration created
    - Azure app registration has the azure key vault delegated permissioa added
    - Azure app registration has been granted consent for these permissions by an administrator
- Azure Key Vault role-based access controls added the newly-created app registration to a role which will allow it to at minimum view secrets


## Getting started

Imagine you've completed the above and area ready to use this module. Let's assume your keyvault is named `JS-KeyVault-BP3`.

1. Run `Invoke-AppRegSelfSignedCertSetup.ps1` with your Azure data and pick a nickname for this cert. Example:
```powershell
$InvokeAppRegSelfSignedCertSetupSplat = [ordered]@{
    AppRegId = "faceb00c-17b6-424c-9e09-dd84a62bdf38"
    CertNameIdentifier = "KVBP3" #this will be important later!
    CertNamePrefix = "JS" #this is can be useful for cross-org or multiple azure tenants, etc
}
Invoke-AppRegSelfSignedCertSetup @InvokeAppRegSelfSignedCertSetupSplat
```
2. Follow the instructions on-screen and upload the .CER to the Certificates portion of the app registration. 
    
    a. Note: unless you plan to transfer this certificate around to other devices (NOT recommended), add in the app reg cert upload NOTES field who and where (computer) this certificate came from. Makes tracking down expiring-soon certs much easier!

3. Test out your newly enabled Azure Key Vault connection:
```powershell
$ConnectAzureKeyVaultSplat = [ordered]@{
    KeyVaultName = "DSR-AKV-DemoTIme"
    SubscriptionID = "a3a1428c-c179-45b1-8767-3f21b6cb7b3b"
    TenantID = "0d849965-e2cf-42ab-a66b-f33e8e26a0c5"
    AppRegID = "faceb00c-17b6-424c-9e09-dd84a62bdf38"
    CertNickname = "KVBP3"
}
```
If things are set up correctly, you'll be greeted with a successful key vault connection.

5. Next, ensure you've populated credentials in the vault (use the UI or Set-AzKeyVaultSecret). Read the docs for `Get-SecureCredential` to find the correct format to use. For now, we'll assume you have added two secrets to Azure Key Vault like so: `AKV-Teapot-Username` and `AKV-Teapot-Password`. 

6. Finally, you're ready to start fetching creds. Let's collect the credentials for the Teapot API:
```powershell
$TeapotCreds = Get-SecureCredential -APITargetName "Teapot"
```
If successful, you'll find a [pscredential] object now lives in $TeapotCreds

7. Finally, use the credential: Let's assume you have a solid network connection to an appropriate teapot. Now let's Invoke-TeapotBoil:
```powershell
Invoke-TeapotBoil -TemperatureGoalCelsius 100 -WhistleWhenDone -Credentials $TeapotCreds
```

Since you obtained the teapot creds already, sit back and relax and in about 3-4 minutes you'll be ready to make a steaming hot cuppa.


## Additional Function Info

This module provides a number of utility functions to make using Azure Key Vault a frictionless, automatic experience.

- **Invoke-AppRegSelfSignedCertSetup**: This function sets up a self-signed certificate for an Azure App Registration. This is the first step. Remember to upload the .CER as instructed to the App Registration
    - **Import-PfxCertificateAsOtherUser**: This function imports a PFX certificate as another user. It's useful when you need to drop a certificate under a different user's context. Particularly useful for service acccounts.
- **Connect-AzureKeyVault**: This function is used to establish a connection to an Azure Key Vault. It authenticates the user and returns a handle to the connected vault.
- **Get-SecureCredential**: This function retrieves a secure credential object from the Azure Key Vault. It uses the connection established by Connect-AzureKeyVault to securely fetch the credential.

    
## Resources

Further Azure reading:
 
- [Quickstart: Create a key vault using the Azure portal](https://learn.microsoft.com/en-us/azure/key-vault/general/quick-create-portal) 

- [Create an App Registration ](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/walkthrough-register-app-azure-active-directory)

- [Azure Key Vault - Setting up Role-Based Access Control](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide?tabs=azure-cli)

- [Authenticating to Azure AD as an application using certificate based client credential grant](https://goodworkaround.com/2020/07/07/authenticating-to-azure-ad-as-an-application-using-certificate-based-client-credential-grant/) (good semi-contextual overview)


## About

### Version history
- 1.0.0.1 - 2024-03-29 - Initial public release

### Misc
This has been adapted from a module I've created and used at various places over last couple of years. Adoption is accelerating and it's always great to see fewer and fewer instances or mentions of "storing that password in the script". 

If you have questions about the functions, Azure Key Vault, or how to push for a more devops-y perspective in your organization, send me a note - always happy to discuss.

