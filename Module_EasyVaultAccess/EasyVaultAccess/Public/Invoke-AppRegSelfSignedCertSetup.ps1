function Invoke-AppRegSelfSignedCertSetup {
    <# 
    .SYNOPSIS 
    Checks for and creates a self-signed certificate for an Azure app registration.

    .DESCRIPTION
    The Invoke-AppRegSelfSignedCertSetup function checks for the existence of a self-signed certificate in the local machine and current user certificate stores. If the certificate does not exist, it will create a new self-signed certificate and export it to a file for manual upload to the Azure app registration. If the certificate exists in the machine store but not the user store, it will copy the machine certificate to the user store. If the certificate exists in the user store but not the machine store, it will copy the user certificate to the machine store. If the certificate exists in both stores, it will validate that the certificate is still valid and has not expired. If the certificate is expired, it will prompt the user to regenerate the certificate. If the certificate is not expired, it will return a success message.

    .PARAMETER AppRegId
    [string] The Azure app registration ID for which the certificate is being created.

    .PARAMETER CertNameIdentifier
    [string] A unique identifier for the certificate name.

    .PARAMETER CertNamePrefix
    [string] A prefix for the certificate name.

    .PARAMETER SkipMachineCertCheck
    [switch] Skips the check for the certificate in the local machine certificate store.

    .PARAMETER SkipUserCertCheck
    [switch] Skips the check for the certificate in the current user certificate store.

    .PARAMETER ForceRegenerateCertificate
    [switch] Forces the regeneration of the certificate(s) even if they already exist. Useful during tests.

    .PARAMETER IgnoreExpiredCerts
    [switch] Ignores expired certificates and does not prompt for regeneration if they are no longer usable. [NOT IMPLEMENTED]

    .PARAMETER DontDeletePfxAfterImport
    [switch] Prevents the deletion of the PFX file after importing the certificate to the user store.

    .PARAMETER DontMakeMachineCertUnexportable
    [switch] Prevents the machine certificate from being reimported as unexpertable after being reimported, just in case you have a reason to keep it exportable.

    .PARAMETER DeleteMachineCertAfterUserImport
    [switch] Deletes the machine certificate after importing it to the user store. This is useful if you only want the user certificate to exist.

    .PARAMETER DeleteAllCerts
    [switch] Deletes all certificates matching the specified name (derived from app reg id, prefix, and nickname). Useful for cleanup.

    .EXAMPLE
    Invoke-AppRegSelfSignedCertSetup -AppRegId "f3a4801d-9a63-4d01-a87b-1e8cc56f0a69" -CertNameIdentifier "DSR" -CertNamePrefix "KVT" 

    This command will check for the existence of a self-signed certificate for the specified app registration ID and create a new certificate if it does not exist.

    .EXAMPLE
    $InvokeAppRegSelfSignedCertSetupSplat = @{
        AppRegId = "f3a4801d-9a63-4d01-a87b-1e8cc56f0a69"
        CertNameIdentifier = "DSR"
        CertNamePrefix = "KVT"
    }

    > Invoke-AppRegSelfSignedCertSetup @InvokeAppRegSelfSignedCertSetupSplat

    This command will use a splat to pass the parameters to the Invoke-AppRegSelfSignedCertSetup function. Remember: splatting is your friend!

    .NOTES
    
    
    #>
    [cmdletbinding(SupportsShouldProcess=$true,ConfirmImpact="Medium")]

    param (
		[parameter(Mandatory)]
		[ValidateScript({
            #check if cast to guid works
            try {
                [guid]$_
                $true
            } catch {
                $false
            }
        })]
        [string]$AppRegId
        ,
		[parameter()]
        $CertNameIdentifier
        ,
		[parameter()]
        $CertNamePrefix
        ,
        [parameter()]
        [switch]$SkipMachineCertCheck
        ,
        [parameter()]
        [switch]$SkipUserCertCheck
        ,
        [parameter()]
        [switch]$ForceRegenerateCertificate
        ,
        [parameter()]
        [switch]$IgnoreExpiredCerts
        ,
        [parameter()]
        [switch]$DontDeletePfxAfterImport
        ,
        [parameter()]
        [switch]$DontMakeMachineCertUnexportable
        ,
        [parameter()]
        [switch]$DeleteMachineCertAfterUserImport
        ,
        [parameter()]
        [switch]$DeleteAllCerts
    )

    begin {
        $ErrorActionPreference = "Stop"

        ### bound parameter shortcuts
        foreach ($BoundParameter in $MyInvocation.BoundParameters.Keys) {
            $BPShortcut = Set-Variable -Name "BP_$BoundParameter" -Value $true -PassThru -whatif:$false
            Write-Verbose "BOUNDPARAM FOUND -- Set $($BPShortcut.Name) to $($BPShortcut.Value) -- actual value: $($MyInvocation.BoundParameters["$BoundParameter"])"
        }
        
    }
    
    process {
        Write-Host -ForegroundColor Yellow "Checking for required certificates..."
        
        try {
            ## app reg cert setup

            # constructing the name of the app registration - this is COMMON to all similarly setup devices and useful for consistency
            # part of the name is the first 8 letters of the associated app registration for easy identification later

            # $AppRegCertBasename = "$($CertNamePrefix)SSC-AppReg-$CertNameIdentifier-$($AppRegId[0..7] -join '')" #oldschool
            # actually we need to construct this by joining the various parts with -join "-" like so (kind of messy, but... it does work nicely!):
            $AppRegCertBasename = ((   $CertNamePrefix, "SSC", "AppReg", $CertNameIdentifier, "$($AppRegId[0..7] -join '')"   ) | ? {-not [string]::IsNullOrEmpty($_)}) -join "-"
            Write-Verbose "Cert friendlyname constructed: '$AppRegCertBasename'"

            #checking for app reg certificate in cert stores...
            $AppRegCertificateMachineStore = Get-ChildItem "Cert:\localmachine\my\" | Where-Object {$_.FriendlyName -match $AppRegCertBasename} 
            $AppRegCertificateUserStore = Get-ChildItem "Cert:\currentuser\my\" | Where-Object {$_.FriendlyName -match $AppRegCertBasename} 

            if ($ForceRegenerateCertificate -or $DeleteAllCerts) {
                try {
                    Remove-Item $AppRegCertificateMachineStore.pspath -Force -Confirm:$false
                    Write-Host -ForegroundColor DarkRed "Cert found in machine store. Deleting..."
                    $AppRegCertificateMachineStore = $null
                } catch {
                    Write-Warning "No machine cert removed during force regen - it did not exist! No need to force regenerate. If you created with a different name manually, please manually delete."
                }

                try {
                    Remove-Item $AppRegCertificateUserStore.pspath -Force -Confirm:$false
                    Write-Host -ForegroundColor DarkRed "Cert found in user store. Deleting..."
                    $AppRegCertificateUserStore = $null
                } catch {
                    Write-Warning "No user cert removed during force regen - it did not exist! No need to force regenerate. If you created with a different name manually, please manually delete."
                }
            }
            
            if ($DeleteAllCerts) {
                Write-Host -ForegroundColor Red "All certs matching $AppRegCertBasename deleted. Enjoy!"
                return
            }

            # machine cert validation
            if ($SkipMachineCertCheck) {
                Write-Host -ForegroundColor Yellow "Machine cert check skipped. Not sure why you'd want to do this, but you do you."
            } else {
                if ($AppRegCertificateMachineStore) {
                    Write-Host -ForegroundColor DarkGreen "EVAL: App registration cert exists in local machine cert store == PASS"
                    $AppRegCertificate = $AppRegCertificateMachineStore
                } else {
                    try {
                        Write-Host -ForegroundColor DarkYellow "EVAL: App registration cert not found in localmachine cert store == REMEDIATE"
                        $CertificateName = "$AppRegCertBasename-$("$env:computername")"
                        
                        $NewCertSplat = @{
                            Subject = "CN=$CertificateName"
                            FriendlyName = $AppRegCertBasename 
                            CertStoreLocation = "Cert:\localmachine\My" 
                            KeyExportPolicy = "Exportable" 
                            KeySpec = "Signature" 
                            KeyLength = 2048
                            KeyAlgorithm = "RSA"
                            HashAlgorithm = "SHA256"
                        }
                        
                        $AppRegCertificateMachineStore = New-SelfSignedCertificate @NewCertSplat
                        Export-Certificate -Cert $AppRegCertificateMachineStore -FilePath "$env:temp\$CertificateName-ToUpload.cer" | Out-Null
                        Write-Host -ForegroundColor Yellow -BackgroundColor Red "!!! Action required !!!"
                        Write-Host -ForegroundColor Yellow -BackgroundColor Red "Full path of certificate just exported:"
                        Write-Host -ForegroundColor Black -BackgroundColor White "$env:temp\$CertificateName-ToUpload.cer"
                        Write-Host -ForegroundColor Yellow -BackgroundColor Red "Upload this certificate file to the App Registration with ID {$($AppRegId)}."
                        Write-Host -ForegroundColor Yellow -BackgroundColor Red "Delete the file after uploading."
                    }

                    catch {
                        Write-Warning "Aborting - could not create cert in machine store."
                        throw $_
                    }

                }#else-app reg cert not in machine store
            }


            # user cert validation
            if ($SkipUserCertStoreCheck) {
                Write-Host -ForegroundColor Yellow "User cert check skipped."
            } else {
                if ($AppRegCertificateUserStore) {
                    Write-Host -ForegroundColor DarkGreen "EVAL: App registration cert exists in current user cert storage == PASS"
                } else {
				
                    ### user cert option since some AZ cmdlets seem to... not accept the localmachine store. This is a huge nuisance.
                    Write-Host -ForegroundColor DarkYellow "EVAL: App registration cert not found in current user cert storage == REMEDIATE"
    
                    try {

                        # to move a private key from machine store to user store we need a pfx, which means a temp pw and temp file. the temp pw is made up and doesn't matter, so, ¯\_(ツ)_/¯
                        $TempPFXPasswordSecureString = ConvertTo-SecureString '[string]::isnullorempty($TheCheatIsGroundedSinceOctober2002)' -AsPlainText -Force
                        $TempPFXExportPath = "$env:TEMP\$($AppRegCertificateMachineStore.FriendlyName)-TempStoreLocationTransfer.pfx"
                        
                        # exporting and then immediately reimporting the pfx to USER store
                        Get-Item $AppRegCertificateMachineStore.pspath | Export-PfxCertificate -Password $TempPFXPasswordSecureString -FilePath $TempPFXExportPath | Out-Null
                        Import-PfxCertificate -Password $TempPFXPasswordSecureString -FilePath $TempPFXExportPath -CertStoreLocation Cert:\CurrentUser\my -Exportable:$false | Out-Null
                        
                        if ($DontMakeMachineCertUnexportable) {
                            Write-Warning "Skipping making machine cert unexportable. This is not recommended. Be sure to do so manually afterward!"
                        } else {
                            Write-Host "Removing machine cert to make it non-exportable..."
                            # now that the machine cert has been imported to user-side, we don't need to ever export it as PFX again
                            # deleting the exported pfx and reimporting will mark it nonexportable
                            Remove-Item $AppRegCertificateMachineStore.pspath
                            if (!$DeleteMachineCertAfterUserImport) {
                                Write-Host "Reimporting machine cert with non-exportable flag set..."                                
                                Import-PfxCertificate -Password $TempPFXPasswordSecureString -FilePath $TempPFXExportPath -CertStoreLocation Cert:\LocalMachine\my -Exportable:$false | Out-Null
                            } else {
                                Write-Host "Machine cert will not be reimported. Unexportable user cert will be the only one that exists."
                            }
                        }

                        Write-Host -ForegroundColor Cyan "$($AppRegCertificateMachineStore.FriendlyName) successfully copied to the user cert store."
                        Write-Host -ForegroundColor DarkGreen "EVAL: App registration cert exists in current user cert store == PASS"

                    } catch {
                        throw "Unable to add cert from machine store to local store. Please do so manually by exporting the self-signed machine cert including its private key to a PFX and then importing to the user store."
                        Write-Error $_
                    } finally {
                        if (-not $DontDeletePfxAfterImport) {
                            Remove-Item $TempPFXExportPath -ErrorAction SilentlyContinue
                        } else {
                            Write-Warning "Skipping deletion of PFX file. This is not recommended. Be sure to delete it manually afterward!"
                            Write-Warning "PFX cert at path: $TempPFXExportPath"
                            Write-Warning "PFX password in «brackets» (do not include « or »): «$([pscredential]::new("SecureStringRetrieval",$TempPFXPasswordSecureString).GetNetworkCredential().Password)»"
                        }
                    }
                }#else-app reg user cert not found
    
            }#else-skipusercertcheck

            Write-Host -ForegroundColor Green "Certificates confirmed."
        } catch {
            Write-Warning "Error occurred during cert check or remediation. Please validate your permissions and filesystem access and try again."
            throw $_
        }
    }#process

    end {}
}#function


# create a splat using the function's parameters

$InvokeAppRegSelfSignedCertSetupSplat = [ordered]@{
    AppRegId = "f3a4801d-9a63-4d01-a87b-1e8cc56f0a69"
    CertNameIdentifier = "DSR"
    CertNamePrefix = "KVT"
    SkipMachineCertCheck = $false
    SkipUserCertCheck = $false
    ForceRegenerateCertificate = $false
    IgnoreExpiredCerts = $false
    DontDeletePfxAfterImport = $false
    DontMakeMachineCertUnexportable = $false
    DeleteMachineCertAfterUserImport = $false
    DeleteAllCerts = $false
}