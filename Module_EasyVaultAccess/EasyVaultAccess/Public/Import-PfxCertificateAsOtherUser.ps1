
function Import-PfxCertificateAsOtherUser {
    
    <#
    .SYNOPSIS
    Imports a PFX certificate into the personal store of a specified user.

    .DESCRIPTION
    The Import-PfxCertificateAsOtherUser function imports a PFX certificate
    into the personal store of a specified user. The function uses a job to
    run the import process as the specified user.
    
    Remember: To use this function, you must have the other user's credentials.
    As such, it is only truly suitable for use in administrative settings
    against YOUR OWN other accounts (daily/protected actions accounts),
    OR against common-use service accounts.

    .PARAMETER FilePath
    The path to the PFX certificate file.   

    .PARAMETER CertPassword
    The password for the PFX certificate file.

    .PARAMETER CertStoreLocation
    The location to import the certificate to. Default is "Cert:\CurrentUser\My".

    .PARAMETER Exportable
    Indicates whether the private key is exportable. Default is $false.

    .PARAMETER Credential
    The credential of the user to import the certificate as.

    .PARAMETER Quiet
    Indicates whether to suppress output. Default is $false.

    .EXAMPLE
    Import-PfxCertificateAsOtherUser -FilePath "C:\certs\mycert.pfx" -CertPassword $CertPassword -Credential $Credential

    Imports the certificate located at "C:\certs\mycert.pfx" into the personal store of the user specified by the $Credential variable.

    .NOTES

    #>

    param (
        [parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [Alias('CertPath','Path','FullName')]
        [ValidateScript({
            if (-not (Test-Path $_)) {
                throw "Path not found: $_"
                $false
            } else {
                $true
            }
        })]
        $FilePath
        ,
        [parameter(Mandatory)]
        [Alias('Pw','CertPw')]
        [securestring]$CertPassword
        ,
        [parameter()]
        $CertStoreLocation = "Cert:\CurrentUser\My"
        ,
        [parameter()]
        [switch]$Exportable
        ,
        [parameter(Mandatory)]
        [pscredential]$Credential
        ,
        [switch]$Quiet
    )

    $Job = Start-Job -ScriptBlock { 
        param($FilePath, [securestring]$CertPassword, $CertStoreLocation, $Exportable)
        try {
            Import-PfxCertificate -FilePath $FilePath -Password $CertPassword -CertStoreLocation $CertStoreLocation -Exportable:$Exportable -Confirm:$false -Verbose -ErrorAction Stop
            Write-Host -ForegroundColor Cyan "Imported cert to personal store of user: '$($env:username)'."
        } catch {
            throw $_
        }
    } -Credential $Credential -ArgumentList $FilePath,$CertPassword,$CertStoreLocation,$Exportable

    if (-not $Quiet) {Write-Host "Job Pending..." -NoNewline}

    if (-not $Quiet) {
        while ((Get-Job $Job.id).state -ne "Completed") {
            Write-Host "." -NoNewline
            Start-Sleep -Milliseconds 100
        }
    }

    if (-not $Quiet) {Write-Host "Job Complete!"}

    Receive-Job $Job.id

    Remove-Job $Job.id
}
