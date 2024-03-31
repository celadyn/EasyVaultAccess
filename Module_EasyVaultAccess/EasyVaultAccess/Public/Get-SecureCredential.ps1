
function Get-SecureCredential {
    <#
    .SYNOPSIS
        Gets credentials from any of many sources based on patterns. Built-in vault checks.

    .DESCRIPTION
        Retrieving credentials from vaults requires a bit of setup. This function eliminates redundancy and acts as an intelligent broker between the calling script and the credential-holding vault source. Checks all vaults in series for a specified API based on its "target name", OR checks a specified vault as indicated.

        Note that vaults/secretstores secret labels must conform to specific pattern for this to work:

        Azure Key Vault    : AKV-$APITargetName-[Username|Password] - e.g., 'AKV-Slack-Username' and 'AKV-Slack-Password'
        PSUniversal        : PSU_$APITargetName_[Username|Password] - e.g., 'PSU_Slack_Username' and 'PSU_Slack_Password'
        Task Sequence Vars : TSV-$APITargetName-[Username|Password] - e.g., 'TSV-Slack-Username' and 'TSV-Slack-Password'
        CredentialManager  : LCM-$APITargetName-[Username|Password] - e.g., 'LCM-Slack-Username' and 'LCM-Slack-Password'

        NOTE: For scope or environment specific credentials, append the environment to the APITargetName with a hyphen (e.g. "Slack-Prod" or "Slack-ReadOnly"). This will be appended to the APITargetName when checking for credentials.

        Ensuring the necessary vault connection exists PRIOR to requesting credentials is, of course, required, and must be handled separately.

    .PARAMETER APITargetName
        The target name of the API for which credentials are being requested. This is the primary identifier for the credential set.

    .PARAMETER APIEnvironment
        The environment of the API for which credentials are being requested. This is an optional parameter that can be used to specify a specific environment within the same system (e.g. prod/nonprod or read-only/read-write).

    .PARAMETER CredentialVault
        The vault or secretstore to check for the credentials. If not specified, all vaults will be checked in order. Default is all vaults. Available options are: AzureKeyVault, CredentialManager, TaskSequenceVariables, PowershellUniversal.

    .PARAMETER AzureKeyVaultName
        The name of the Azure Key Vault to check for credentials.

    .PARAMETER SuperVerbose
        Enables some extremely noisy and detailed output useful for debugging when particular "vaults" maybe questionably usable.

    .PARAMETER Username
        The username for the credential set. This is only used in manual mode. This mode only exists in case you start typing this function name and realize you really only wanted to use Get-Credential...

    .PARAMETER Password
        The password for the credential set. This is only used in manual mode.

    .EXAMPLE
        PS C:\>Get-SecureCredential -APITargetName "Slack"
        

        Checks all vaults for API with target name "Slack".

    .EXAMPLE
        ...
        
        PS C:\>$CredSplatHashtable = @{
            APITargetName   = "Slack"
            Environment     = "Prod"
            CredentialVault = "AzureKeyVault"
        }

        PS C:\>Get-SecureCredential @CredSplatHashtable
        

        Using splatting for cleanliness, requests the the specified credential from the specified vault/secretstore. Note that the Environment parameter is optional, and if used, will be appended to the APITargetName with a hyphen (e.g. "Slack-Prod"). 

    .NOTES
        Name: Get-SecureCredential
        Author: David Richmond
        Keywords: Credential,keyvault,secretstore,password,utility

        Version history:
            1.0.0.0 - 2022.08.08 - initial creation
            1.0.0.1 - 2022.08.12 - added Task Sequence Variable option and handling, and all comment-based help
            1.0.0.2 - 2022.11.23 - modified Azure Key Vault query to account for username-less creds (e.g. secret/client keys)
            1.0.0.3 - 2023-12-12 - adding support for Environment param which allows for specific picking of credentials within the same system (e.g. prod/nonprod or read-only/read-write)
            1.0.0.4 - 2024-03-27 - genericization for wider use; added handling for multiple Azure Key Vaults

    .OUTPUTS
        A [pscredential] object, or, nothing.
    
    #>


    [cmdletbinding(SupportsShouldProcess,DefaultParameterSetName="Auto")]
    param (
        [Parameter(Mandatory=$true,ParameterSetName="Auto",Position=0)]
        [Alias('Target')]
		[string]$APITargetName
		,
        [Parameter(ParameterSetName="Auto",Position=1)]
        [Alias('Env','Environment')]
		[string]$APIEnvironment
		,
        [Parameter(Mandatory=$false,ParameterSetName="Auto",Position=2)]
		[ValidateSet('AzureKeyVault','CredentialManager','TaskSequenceVariables','PowershellUniversal')]
        [ValidateNotNullOrEmpty()]
		[string[]]$CredentialVault = @('AzureKeyVault','PowershellUniversal','CredentialManager','TaskSequenceVariables')
        ,
        [Parameter(ParameterSetName="Auto")]
        $AzureKeyVaultName
        ,
        [Parameter(ParameterSetName="Auto")]
        [Parameter(ParameterSetName="Manual")]
        [Alias('vv')]
		[Switch]$SuperVerbose
		,
        [Parameter(Mandatory=$true,ParameterSetName="Manual",Position=0)]
        [ValidateNotNullOrEmpty()]
		[string]$Username
		,
        [Parameter(Mandatory=$true,ParameterSetName="Manual",Position=1)]
        [securestring]$Password
	
	)

    begin {

        $ErrorActionPreference = "Stop"

        Write-Verbose "START: Command [$($MyInvocation.MyCommand.Name)] - Module [$($MyInvocation.MyCommand.ModuleName)]"

        ### bound parameter shortcuts
        foreach ($BoundParameter in $MyInvocation.BoundParameters.Keys) {
            $BPShortcut = Set-Variable -Name "BP_$BoundParameter" -Value $true -PassThru -whatif:$false
            Write-Verbose "BOUNDPARAM FOUND -- Set $($BPShortcut.Name) to $($BPShortcut.Value) -- actual value: $($MyInvocation.BoundParameters["$BoundParameter"])"
        }

        $BaseAPITargetName = $APITargetName

        if (-not [string]::IsNullOrEmpty($APIEnvironment)) {
            $APITargetName = "$APITargetName-$APIEnvironment"
        }

        # handle the Azure Key Vault name if it's not specified by checking to see if there's only one keyvault in the global keyvaultstore, and if so, using that
        # we do this by using getenumerator() on the keyvaultstore hashtable and checking to see which of the values in there are of type [Microsoft.Azure.Commands.KeyVault.Models.PSKeyVault]
        if ([string]::isnullorempty($AzureKeyVaultName) -and $CredentialVault -contains "AzureKeyVault") {
            $LoadedKeyVaults = $global:KeyVaultStore.GetEnumerator() | Where-Object {$_.value -is [Microsoft.Azure.Commands.KeyVault.Models.PSKeyVault]} | Select-Object -ExpandProperty Value
            if ($LoadedKeyVaults.Count -eq 1) {
                $AzureKeyVaultName = $LoadedKeyVaults.VaultName
                Write-Verbose "Only one keyvault loaded, using '$AzureKeyVaultName'"
            } else {
                Write-Warning "Multiple keyvaults loaded. Will check them all!"
            }
        }

    }#begin

    process {
        
        $Credentials = switch ($PSCmdlet.ParameterSetName) {

            "Manual" {
                try {
                    $CredObject = [pscredential]::new($Username,$Password)
                    Write-Host -ForegroundColor Green "MANUAL -- Generated creds with username '$($CredObject.UserName)'"
                    $CredObject | Out-String | Write-Verbose
                    $CredObject
                } catch {
                    Write-Verbose "Unable to generate credentials."
                    $null
                    break
                }
            }#switch-manual

            "Auto" {


                #handling credential vault argument vs using the unbound-param defaults
                if ($BP_CredentialVault) {
                    $CredentialVaultOptions = @($CredentialVault)
                } else {
                    $CredentialVaultOptions = $CredentialVault
                    Write-Verbose "Credential vault not specified, trying them all in order..."
                }
        
                # the below switch checks each of the credential vault options (or the one, if specified) and attempts to return a cred object
                foreach ($Vault in $CredentialVaultOptions) {
                    Write-Verbose "Checking for creds in $Vault..."
            
                    #in check-all mode, this switch processes one by one
                    switch ($Vault) {
                        "AzureKeyVault" {
                            try {
                                foreach ($CurrentKeyVault in $LoadedKeyVaults) {
                                    if (!$global:KeyVaultStore) {throw "No keyvaults loaded. Did you forget to connect them?"}
                                    $AZKeyVaultCredentialUsername = try {Get-AzKeyVaultSecret -VaultName $CurrentKeyVault.VaultName -Name "AKV-$APITargetName-Username" -AsPlainText} catch {"not-applicable"}
                                    $AZKeyVaultCredentialPassword = (Get-AzKeyVaultSecret -VaultName $CurrentKeyVault.VaultName -Name "AKV-$APITargetName-Password").secretvalue
                                    if (!$AZKeyVaultCredentialPassword) {throw "No proper creds exist with this target name."}
                                    if ([string]::IsNullOrEmpty($AZKeyVaultCredentialUsername)) {$AZKeyVaultCredentialUsername = "IntentionallyLeftBlank"}
                                    Write-Verbose "Constructing pscredential: '$AZKeyVaultCredentialUsername'  :  '$AZKeyVaultCredentialPassword'"
                                    $CredObject = [pscredential]::new($AZKeyVaultCredentialUsername,$AZKeyVaultCredentialPassword)
                                    Write-Host -ForegroundColor Green "AUTO -- Retrieved creds from $Vault with username '$($CredObject.UserName)' for API '$BaseAPITargetName'$(if ($APIEnvironment) {" with environment '$APIEnvironment'"})"
                                    $CredObject | Out-String | Write-Verbose
                                    if ($CredObject) {break}
                                }

                                if ($CredObject) {
                                    $CredObject
                                } else {
                                    throw "Credentials not found."
                                }
                            } catch {Write-Verbose "Errors or couldn't find from $Vault.";if ($BP_SuperVerbose) {Write-Warning $_}}
                        } 
                        "PowershellUniversal" {
                            try {
                                #no unique setup required, in PSU secrets are stored as accessible variables in all sessions 
                                $PSUCredentialUsername = Get-Variable -Name "PSU_${APITargetName}_Password" -ValueOnly
                                $PSUCredentialPassword = Get-Variable -Name "PSU_${APITargetName}_Password" -ValueOnly | ConvertTo-SecureString -AsPlainText -Force
                                if (!$PSUCredentialUsername -or !$PSUCredentialPassword) {throw "No proper creds exist with this target name."}
                                $CredObject = [pscredential]::new($PSUCredentialUsername,$PSUCredentialPassword)
                                Write-Host -ForegroundColor Green "AUTO -- Retrieved creds from $Vault with username '$($CredObject.UserName)' for API '$BaseAPITargetName'$(if ($APIEnvironment) {" with environment '$APIEnvironment'"})"
                                $CredObject | Out-String | Write-Verbose
                                if ($CredObject) {$CredObject} else {throw "Credentials not found."}
                            } catch {Write-Verbose "Errors or couldn't find from $Vault.";if ($BP_SuperVerbose) {Write-Warning $_}}

                        }
                        "TaskSequenceVariables" {
                            try {
                                #uniquely, we check here for the the TS comobject
                                $TSEnvironment = New-Object -ComObject Microsoft.SMS.TSEnvironment
                        
                                $TSVCredentialUsername = $TSEnvironment.Value('TSV-$APITargetName-Username')
                                $TSVCredentialPassword = $TSEnvironment.Value('TSV-$APITargetName-Password')
                                if (!$TSVCredentialUsername -or !$TSVCredentialPassword) {throw "No proper creds exist with this target name."}
                                $CredObject = [pscredential]::new($TSVCredentialUsername,$TSVCredentialPassword)
                                Write-Host -ForegroundColor Green "AUTO -- Retrieved creds from $Vault with username '$($CredObject.UserName)' for API '$BaseAPITargetName'$(if ($APIEnvironment) {" with environment '$APIEnvironment'"})"
                                $CredObject | Out-String | Write-Verbose
                                if ($CredObject) {$CredObject} else {throw "Credentials not found."}
                            } catch {Write-Verbose "Errors or couldn't find from $Vault.";if ($BP_SuperVerbose) {Write-Warning $_}}
                        }
                        "CredentialManager" {
                            try {
                                $CredObject = Get-StoredCredential -Target $APITargetName
                                if (!$CredObject) {throw "Credentials not found."}
                                Write-Host -ForegroundColor Green "AUTO -- Retrieved creds from $Vault with username '$($CredObject.UserName)' for API '$BaseAPITargetName'$(if ($APIEnvironment) {" with environment '$APIEnvironment'"})"
                                $CredObject | Out-String | Write-Verbose
                                if ($CredObject) {$CredObject} else {throw "Credentials not found."}
                            } catch {Write-Verbose "Errors or couldn't find from $Vault.";if ($BP_SuperVerbose) {Write-Warning $_}}
                        }
                        default {
                            Write-Warning "How did you get here? This won't ever be reached in this loop."
                            #hypothetically this COULD be reached if we did not ValidateNotNullOrEmpty when 
                            #a specific credential is passed to the CredentialVault parameter. always mind your nulls or empties on strings!
                        }
                    }#switch

                    #if credentials are obtained from a vault, we BREAK out of the FOREACH - no more need to keep trying!
                    if ($CredObject) {
                        Write-Verbose "BREAK - CredObject exists"
                        break
                    }

                    Write-Verbose "FOREACH -- No credentials returned from $Vault."

                }#foreach-vault
            }#switch-auto
        }#switch-autoormanual

        #if one of the vaults (or the specified vault) contained the credentials requested, returns this; otherwise, sad news.
        if ($null -ne $Credentials) {
            $Credentials
        } else {
            throw "Unable to acquire $APITargetName credentials$(if ($APIEnvironment) {" with environment '$APIEnvironment'"}). Please check source or credentials and try again."
        }

	}#process

    end {
        Write-Verbose "END: Command [$($Myinvocation.MyCommand.Name)] - Module [$($Myinvocation.MyCommand.ModuleName)]"
    }

}