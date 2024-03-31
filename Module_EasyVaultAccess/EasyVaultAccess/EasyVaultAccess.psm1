Write-Verbose "Importing module functions from: $PSScriptRoot"
$Public = @( Get-ChildItem -Recurse -Path "$PSScriptRoot\Public\" -Filter *.ps1 -ErrorAction SilentlyContinue)
$Private = @( Get-ChildItem -Recurse -Path "$PSScriptRoot\Private\" -Filter *.ps1 -ErrorAction SilentlyContinue)

@($Public + $Private) | ForEach-Object {
    Try {
        Write-Verbose "Loading $($_.BaseName)..."
        . $_.FullName
    }
    Catch {
        Write-Warning -Message "Failed to import function $($_.FullName): $_"
    }
}

#Export-ModuleMember -Function $Private.BaseName -Verbose #uncomment this to expose private functions, perhaps for testing
Export-ModuleMember -Function $Public.BaseName
