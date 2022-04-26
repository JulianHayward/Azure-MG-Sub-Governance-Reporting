$allFunctionLines = foreach ($file in Get-ChildItem -path .\pwsh\dev\functions -Recurse -filter *.ps1) {
    Get-Content -LiteralPath $file.FullName
}
$functionCode = $allFunctionLines -join "`n"
$AzGovVizScriptFile = Get-Content -Path .\pwsh\dev\devAzGovVizParallel.ps1 -Raw

$newContent = @"

#region Functions
$functionCode
"@

$startIndex = $AzGovVizScriptFile.IndexOf('#region Functions')
$endIndex = $AzGovVizScriptFile.IndexOf('#endregion Functions')

$textBefore = $AzGovVizScriptFile.SubString(0, $startIndex)
$textAfter = $AzGovVizScriptFile.SubString($endIndex)

$textBefore.TrimEnd(), $newContent, $textAfter | Set-Content -Path .\pwsh\AzGovVizParallel.ps1