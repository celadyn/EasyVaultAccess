param (
    [switch]$WhatIf
)

function Publish-EEModule {
    [cmdletbinding()]
    param (
        [switch]$WhatIf
    )

    $ErrorActionPreference = 'Stop'
            
    $PSD1Path = Get-ChildItem $PSScriptRoot -Recurse -Depth 1 -Filter *.psd1 | select -First 1

    $PSModulePathForPublication = $PSD1Path.Directory.BaseName

    try {
        Publish-Module -Path ".\$PSModulePathForPublication" -Repository "PSRepo" -Verbose -whatif:$WhatIf
         = True
    } catch {
         = False
        Write-Error $_
        throw $_
    }


}

Set-Location $PSScriptRoot
Publish-EEModule -WhatIf:$WhatIf
