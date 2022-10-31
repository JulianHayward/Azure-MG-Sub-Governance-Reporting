function checkAzGovVizVersion {
    try {
        $getRepoVersion = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/JulianHayward/Azure-MG-Sub-Governance-Reporting/master/version.txt'
        $azGovVizVersionThis = ($ProductVersion -split '_')[2]
        $script:azGovVizVersionOnRepositoryFull = $getRepoVersion.Content -replace "`n"
        $azGovVizVersionOnRepository = ($azGovVizVersionOnRepositoryFull -split '_')[2]
        $script:azGovVizNewerVersionAvailable = $false
        if ([int]$azGovVizVersionOnRepository -gt [int]$azGovVizVersionThis) {
            $script:azGovVizNewerVersionAvailable = $true
            $script:azGovVizNewerVersionAvailableHTML = '<span style="color:#FF5733; font-weight:bold">Get the latest AzGovViz version (' + $azGovVizVersionOnRepositoryFull + ')!</span> <a href="https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting/blob/master/history.md" target="_blank"><i class="fa fa-external-link" aria-hidden="true"></i></a>'
        }
    }
    catch {
        #skip
    }
}