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
- Azure Key Vault created 
- Azure app registration created
    - Azure app registration has the azure key vault delegated permissioa added
    - Azure app registration has been granted consent for these permissions by an administrator
- Azure Key Vault role-based access controls added the newly-created app registration to a role which will allow it to at minimum view secrets

## Implementation

This module provides a number of utility functions to make using Azure Key Vault a frictionless, automatic experience.


- Invoke-AppRegSelfSignedCertSetup.ps1: This function sets up a self-signed certificate for an Azure App Registration. This is the first step. Remember to upload the .CER as instructed to the App Registration
    - Import-PfxCertificateAsOtherUser.ps1: This function imports a PFX certificate as another user. It's useful when you need to use a certificate under a different user context.
- Connect-AzureKeyVault: This function is used to establish a connection to an Azure Key Vault. It authenticates the user and returns a handle to the connected vault.
- Get-SecureCredential: This function retrieves a secure credential object from the Azure Key Vault. It uses the connection established by Connect-AzureKeyVault.ps1 to securely fetch the credential.

    
## Resources

Further Azure reading:

[Quickstart: Create a key vault using the Azure portal](https://learn.microsoft.com/en-us/azure/key-vault/general/quick-create-portal) 

[Create an App Registration ](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/walkthrough-register-app-azure-active-directory)

[Azure Key Vault - Setting up Role-Based Access Control](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide?tabs=azure-cli)

[Authenticating to Azure AD as an application using certificate based client credential grant](https://goodworkaround.com/2020/07/07/authenticating-to-azure-ad-as-an-application-using-certificate-based-client-credential-grant/) (good semi-contextual overview)


## Notes

Version history:
- 1.0.0.0 - Base version (skipped)
- 1.0.0.1 - First publishable release

Misc:
This has been adapted from a similar module used internally at my org for the last couple of years. Adoption is accelerating and it's always great to see fewer and fewer instances or mentions of "storing that password in the script". 

If you have questions about the functions, Azure Key Vault, or how to push for a more devops perspective organization, send me a note - always happy to discuss.

