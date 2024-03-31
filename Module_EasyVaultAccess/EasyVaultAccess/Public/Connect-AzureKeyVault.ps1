function Connect-AzureKeyVault {
    <#
    .SYNOPSIS 
    Connects to an Azure Key Vault using the provided parameters.

    .DESCRIPTION
    The Connect-AzureKeyVault function connects to an Azure Key Vault using the given KeyVaultName, SubscriptionID, AppRegID, and TenantID. If any of these are not provided, default values will be used. A ForceRefresh switch can be used to force a refresh of the global KeyVaultStore.

    .PARAMETER KeyVaultName
    [string] The name of the Azure Key Vault to connect to.

    .PARAMETER SubscriptionID
    [string] The Azure subscription ID for the Key Vault.

    .PARAMETER AppRegID
    [string] The Azure app registration ID which has been granted delegated permissions to Azure Key Vault and which is properly permissioned withing Key Vault RBAC.

    .PARAMETER TenantID
    [string] The Azure tenant ID for the Key Vault.

    .PARAMETER ForceRefresh
    Forces a refresh of the global KeyVaultStore.

    .EXAMPLE
    $ConnectAKVSplat = @{
        KeyVaultName = "MyKeyVault"
        SubscriptionID = "3f8cdea0-1111-2222-3333-98de6e0d5432"
        AppRegID = "a6c279d2-4444-5555-6666-7d8e1e6f2345"
        TenantID = "e6e8f2d8-7777-8888-9999-5a6b1c3d7654"
        CertNickname = "KV-TestA"
    }

    > Connect-AzureKeyVault @ConnectAKVSplat

    This command connects to the Azure Key Vault "MyKeyVault" using the specified SubscriptionID, AppRegID, TenantID, and CertNickname.
    Note the use of splatting to pass the parameters, a far superior method to stacking them all on the same line.
    
    .NOTES
    To use this function, you must have the appropriate Azure app registration certificate installed on your machine as well as the Az module installed.
    #>
    [Alias('Connect-AKV','CAKV')]
    [cmdletbinding()]

    param (
		[parameter(Mandatory=$true)]
        [string[]]$KeyVaultName
		,
		[parameter(Mandatory=$true)]
		[guid]$SubscriptionID
		,
		[parameter(Mandatory=$true)]
		[guid]$AppRegID
		,
		[parameter(Mandatory=$true)]
		[guid]$TenantID
        ,
        [parameter(Mandatory=$true)]
		[string]$CertNickname
        ,
        [parameter(Mandatory=$false)]
        [switch]$ForceRefresh
    )

    begin {

        $ErrorActionPreference = "Stop"

        ### bound parameter shortcuts
        foreach ($BoundParameter in $MyInvocation.BoundParameters.Keys) {
            $BPShortcut = Set-Variable -Name "BP_$BoundParameter" -Value $true -PassThru -whatif:$false
            Write-Verbose "BOUNDPARAM FOUND -- Set $($BPShortcut.Name) to $($BPShortcut.Value) -- actual value: $($MyInvocation.BoundParameters["$BoundParameter"])"
        }

        ## global key vault store check - to avoid redundancy in future checks
        if ($ForceRefresh) {
            Write-Verbose "Force refresh requested - removing vault store glob."
            $global:KeyVaultStore = $null
        }
        
        Write-Verbose "Checking for global key vault store..."
        if ($global:KeyVaultStore) {
            Write-Verbose "Global:KeyVaultStore object already initialized."
        } else {
            Write-Verbose "Global key vault store not found, initializing..."
            $global:KeyVaultStore = @{
                ObjectInitTime = Get-Date
                AppRegCertConfirmed = $null
            }
        }

        ## app reg cert check

        $AppRegCertBasename = "SSC-AppReg-$CertNickname-$($AppRegID[0..7] -join '')"

        # this is used to avoid redundancy in future checks
        if ($global:KeyVaultStore.AppRegCertConfirmed -ne $true) {
            Write-Verbose "Key vault app reg cert not yet checked - checking..."
            $AppRegCertificateMachineStore = Get-ChildItem "Cert:\localmachine\my\" | Where-Object {$_.FriendlyName -match $AppRegCertBasename} 
            $AppRegCertificateUserStore = Get-ChildItem "Cert:\currentuser\my\" | Where-Object {$_.FriendlyName -match $AppRegCertBasename} 

            # prefer machine cert, but user cert okay as well. this behavior differs from mggraph which can ONLY use user certs.
            $AppRegCertForAzConnect = if ($AppRegCertificateMachineStore) {
                $AppRegCertificateMachineStore
                Write-Verbose "Using key vault app reg cert found in machine store."
            } elseif ($AppRegCertificateUserStore) {
                $AppRegCertificateUserStore
                Write-Verbose "Using key vault app reg cert found in user store."
            } else {
                Write-Verbose "No key vault app reg cert found."
                $null
            }

            if ($AppRegCertForAzConnect) {
                $global:KeyVaultStore.AppRegCertConfirmed = $true
                $global:KeyVaultStore.AppRegCertThumbprint = $AppRegCertForAzConnect.Thumbprint
            } else {                
                throw "App reg certificate not found. Please run Initialize-AzureKeyVaultPrerequisites to get started."
            }
        }

        ## connect-az check
        if ($null -eq $global:KeyVaultStore.AzContext) {
            try {
                
                Write-Host -ForegroundColor Cyan "Importing required Az modules..."

                Import-Module Az.Accounts

                try {
                    Import-Module Az.Keyvault
                } catch [System.IO.FileLoadException] {
                    if ($PSVersionTable.PSVersion.Major -ge 7) {
                        Write-Warning "PS7+ detected and Az.KeyVault conflict detected. Loading module using PS5, this may take a bit of extra time..."
                        Import-Module Az.KeyVault -UseWindowsPowerShell
                    } else {
                        throw $_
                    }
                }

                Write-Host -ForegroundColor Cyan "Connecting to Azure via app reg certificate..."

                #Update-AzConfig -DisplayBreakingChangeWarning $false -Scope CurrentUser | Out-Null

                $ConnectSplat = @{
                    CertificateThumbprint = $global:KeyVaultStore.AppRegCertThumbprint
                    ApplicationId = $AppRegID # this is the ID of the app registration, not a secret key
                    Tenant = $TenantID # this is the Azure tenant ID, not a secret key
                    Subscription = $SubscriptionID
                    ServicePrincipal = $true
                }

                Connect-AzAccount @ConnectSplat -Verbose | Out-Null
                #Set-AzContext -Subscription $SubscriptionID | Out-Null
                $KeyVaultAzContext = Get-AZContext

                $global:KeyVaultStore.Remove("AzContext")
                $global:KeyVaultStore.Add("AzContext",$KeyVaultAzContext)
                
                Write-Host -ForegroundColor Green "AzAccount connected. Key vault connection phase ready to start."

            } catch {
                Write-Warning "Unable to connect to AzAccount!"
                throw $_
            }
        }#if-alreadyconnected

    }#begin

    process {
        foreach ($VaultName in $KeyVaultName) {
            if ($null -eq $global:KeyVaultStore.$VaultName) {
                try {

                    ### hit key vault to confirm access
                
                    $CurrentVault = Get-AzKeyVault -VaultName $VaultName -SubscriptionId $SubscriptionID -WarningAction SilentlyContinue
                
                    if ($CurrentVault) {

                        $global:KeyVaultStore.Remove($VaultName)
                        $global:KeyVaultStore.Add($VaultName,$CurrentVault)

                        Write-Host -ForegroundColor Green "Welcome to $VaultName. Connection complete."
                    } else {
                        Write-Host -ForegroundColor Yellow "Couldn't find $VaultName in Azure Key Vault. Are you still online?"
                    }


                } catch {
                    Write-Warning "Unable to connect to Azure Key Vault $VaultName"
                    throw $_
                }


            } else {
                Write-Host -ForegroundColor Green "Az already connected, '$($VaultName)' active."
            }#if-keyvaultconnected
        }#foreach
    }#process

    end {}

}#function



######

<#

$VaultName = "DSR-AKV-General01"

### fetching
$TargetName = "OpenAI-K3"
$Username = Get-AzKeyVaultSecret -InputObject $KeyVault -Name API-$TargetName-Username -AsPlainText
$Password = (Get-AzKeyVaultSecret -InputObject $KeyVault -Name API-$TargetName-Password).secretvalue
$CredentialFromKeyVault = [pscredential]::new($Username,$Password)

### setting
$TargetName = "OpenAI-K3"


$CredentialForKeyVault = Get-Credential
Set-AzKeyVaultSecret -VaultName $global:KeyVaultStore.'EE-KeyVault-Generic01'.VaultName -Name "AKV-$TargetName-Username" -SecretValue (ConvertTo-SecureString $CredentialForKeyVault.UserName -AsPlainText -Force)
Set-AzKeyVaultSecret -VaultName $global:KeyVaultStore.'EE-KeyVault-Generic01'.VaultName -Name "AKV-$TargetName-Password" -SecretValue $CredentialForKeyVault.Password

#>
