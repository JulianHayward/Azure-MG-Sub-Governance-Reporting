param(
    [switch]
    $skipVersionCompare
)
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
$versiontxtSplitted = $versiontxt -split '\.'
if ($versiontxt.Count -ne 1 -or $versiontxtSplitted.count -ne 3 -or $versiontxtSplitted[0] -notmatch '^\d+$' -or $versiontxtSplitted[1] -notmatch '^\d+$' -or $versiontxtSplitted[2] -notmatch '^\d+$') {
    Write-Host "version '$versiontxt' unexpected -> expected e.g. 1.0.0"
    throw
}

if (-not $skipVersionCompare) {
    try {
        $repoVersionJsonUri = 'https://raw.githubusercontent.com/JulianHayward/Azure-MG-Sub-Governance-Reporting/master/version.json'
        $getRepoVersion = Invoke-WebRequest -Uri $repoVersionJsonUri
        $repoVersion = ($getRepoVersion.Content | ConvertFrom-Json).ProductVersion
    }
    catch {
        throw "could not get the version from the repo '$repoVersionJsonUri'"
    }

    if ($repoVersion -eq $versiontxt) {
        throw "the given version $versiontxt is equal to the current version on the repository $repoVersion"
    }

    if ([System.Version]$versiontxt -lt [System.Version]$repoVersion) {
        throw "the given productVersion '$versiontxt' is lower than the current version on the repository '$repoVersion'"
    }
}

$versionJson = @{
    ProductVersion = $versiontxt
}

($versionJson | ConvertTo-Json) | Set-Content -NoNewline -Path .\version.json

Write-Host "'AzGovVizParallel.ps1' $versiontxt created"