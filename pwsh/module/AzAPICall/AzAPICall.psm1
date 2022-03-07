Get-ChildItem -path $PSScriptRoot\functions | ForEach-Object -Process {
    . $PSItem.FullName
}