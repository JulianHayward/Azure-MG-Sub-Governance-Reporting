function checkAzGovVizVersion {
    try {
        $getRepoVersion = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/JulianHayward/Azure-MG-Sub-Governance-Reporting/master/version.json'
        $repoVersion = ($getRepoVersion.Content | ConvertFrom-Json).ProductVersion

        $script:azGovVizNewerVersionAvailable = $false
        if ($repoVersion -ne $ProductVersion) {
            $repoVersionSplit = $repoVersion -split '\.'
            $repoVersionMajor = $repoVersionSplit[0]
            $repoVersionMinor = $repoVersionSplit[1]
            $repoVersionPatch = $repoVersionSplit[2]

            $ProductVersionSplit = $ProductVersion -split '\.'
            $ProductVersionMajor = $ProductVersionSplit[0]
            $ProductVersionMinor = $ProductVersionSplit[1]
            $ProductVersionPatch = $ProductVersionSplit[2]

            if ($repoVersionMajor -ne $ProductVersionMajor) {
                $versionDrift = 'major'
            }
            elseif ($repoVersionMinor -ne $ProductVersionMinor) {
                $versionDrift = 'minor'
            }
            elseif ($repoVersionPatch -ne $ProductVersionPatch) {
                $versionDrift = 'patch'
            }
            else {
                $versionDrift = 'unknown'
            }

            $versionDriftSummary = "$repoVersion ($versionDrift)"
            $script:azGovVizVersionOnRepositoryFull = $versionDriftSummary
            $script:azGovVizNewerVersionAvailable = $true
            $script:azGovVizNewerVersionAvailableHTML = '<span style="color:#FF5733; font-weight:bold">Get the latest Azure Governance Visualizer version ' + $azGovVizVersionOnRepositoryFull + '!</span> <a href="https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting/blob/master/history.md" target="_blank"><i class="fa fa-external-link" aria-hidden="true"></i></a>'
        }
        else {
            Write-Host "Azure Governance Visualizer version is up to date '$ProductVersion'" -ForegroundColor Green
        }
    }
    catch {
        #skip
        Write-Host 'Azure Governance Visualizer version check skipped' -ForegroundColor Magenta
    }
}