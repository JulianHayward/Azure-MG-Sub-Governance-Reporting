$allFunctionLines = foreach ($file in Get-ChildItem -Path .\pwsh\dev\functions -Recurse -Filter *.ps1) {
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

$versionPattern = 'ProductVersion = '
$versiontxt = (Select-String -Path .\pwsh\AzGovVizParallel.ps1 -Pattern $versionPattern) -replace ".*$versionPattern" -replace "'" -replace ','
if ($versiontxt.Count -ne 1 -or $versiontxt -notlike 'v6_major*' -or $versiontxt.length -ne 19) {
    Write-Host "version '$versiontxt' unexpected"
    throw
}
$versiontxt | Set-Content -NoNewline -Path .\version.txt

Write-Host "'AzGovVizParallel.ps1' $versiontxt created"