Write-Verbose "Importing module functions from: $PSScriptRoot"
$Public = @( Get-ChildItem -Recurse -Path "$PSScriptRoot\Public\" -Filter *.ps1 )
$Private = @( Get-ChildItem -Recurse -Path "$PSScriptRoot\Private\" -Filter *.ps1 )

@($Public + $Private) | ForEach-Object {
    Try {
        Write-Host "Loading $($_.BaseName)..."
        . $_.FullName
    }
    Catch {
        Write-Error -Message "Failed to import function $($_.FullName): $_"
    }
}
