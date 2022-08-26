function processALZEverGreen {

    $ALZRepositoryURI = 'https://github.com/Azure/Enterprise-Scale.git'
    $workingPath = Get-Location
    Write-Host " Working directory is '$($workingPath)'"
    $ALZFolderName = "ALZ_$(get-date -Format $FileTimeStampFormat)"
    $ALZPath = "$($OutputPath)/$($ALZFolderName)"
        
    if (-not (Test-Path -LiteralPath "$($ALZPath)")) {
        Write-Host " Creating temporary directory '$($ALZPath)'"
        $null = mkdir $ALZPath
    }
    else {
        Write-Host " Unexpected: The path '$($ALZPath)' already exists"
        throw
    }

    Write-Host " Switching to temporary directory '$($ALZPath)'"
    Set-Location $ALZPath
    $ALZCloneSuccess = $false

    try {
        Write-Host " Try cloning '$($ALZRepositoryURI)'"
        git clone $ALZRepositoryURI
        if (-not (Test-Path -LiteralPath "$($ALZPath)/Enterprise-Scale" -PathType Container)) {
            $ALZCloneSuccess = $false
            Write-Host " Cloning '$($ALZRepositoryURI)' failed"
            Write-Host " Setting switch parameter '-NoALZEvergreen' to true"
            $script:NoALZEvergreen = $true
            $script:azAPICallConf['htParameters'].NoALZEvergreen = $true
            Write-Host " Switching back to working directory '$($workingPath)'"
            Set-Location $workingPath
        }
        else {
            Write-Host " Cloning '$($ALZRepositoryURI)' succeeded"
            $ALZCloneSuccess = $true
        }
    }
    catch {
        $_
        Write-Host " Cloning '$($ALZRepositoryURI)' failed"
        Write-Host " Setting switch parameter '-NoALZEvergreen' to true"
        $script:NoALZEvergreen = $true
        $script:azAPICallConf['htParameters'].NoALZEvergreen = $true
        Write-Host " Switching back to working directory '$($workingPath)'"
        Set-Location $workingPath
    }
        
    if ($ALZCloneSuccess) {
        Write-Host " Switching to directory '$($ALZPath)/Enterprise-Scale'"
        Set-Location "$($ALZPath)/Enterprise-Scale"
  
        # $htGitTrackESLZPolicies = @{}
        # $htGitTrackESLZdataPolicies = @{}
        $allESLZPolicies = @{}
        $allESLZPolicySets = @{}

        $gitHist = (git log --format="%ai`t%H`t%an`t%ae`t%s" -- ./eslzArm/managementGroupTemplates/policyDefinitions/policies.json) | ConvertFrom-Csv -Delimiter "`t" -Header ("Date", "CommitId", "Author", "Email", "Subject")
        #Write-Host $gitHist.Count
        $commitCount = 0
        Write-Host " Processing ALZ Policy and Set definitions"
        foreach ($commit in $gitHist | Sort-Object -Property Date) {
            $commitCount++
            #$commitCount

            #$dt = (([datetime]$commit.Date).ToUniversalTime()).ToString("yyyyMMddHHmmss")
            # $htGitTrackESLZPolicies.($dt) = @{}
            # $htGitTrackESLZPolicies.($dt).policies = @{}
            # $htGitTrackESLZPolicies.($dt).commitId = $commit.CommitId
            $jsonRaw = git show "$($commit.CommitId):eslzArm/managementGroupTemplates/policyDefinitions/policies.json"
            
            $jsonESLZPolicies = $jsonRaw | ConvertFrom-Json
            #Write-Host "$dt $($commit.CommitId)"
            if (($jsonESLZPolicies.variables.policies.policyDefinitions).Count -eq 0) {
                $eslzGoodToGo = $false
            }
            else {
                $eslzGoodToGo = $true

                $eslzPolicies = $jsonESLZPolicies.variables.policies.policyDefinitions
                foreach ($policyDefinition in $eslzPolicies) {
                    $policyJsonConv = ($policyDefinition | ConvertTo-Json -depth 99) -replace "\[\[", '['
                    $hash = [System.Security.Cryptography.HashAlgorithm]::Create("sha256").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($policyJsonConv))
                    $stringHash = [System.BitConverter]::ToString($hash) 
                    $policyJsonRebuild = $policyJsonConv | ConvertFrom-Json
                    # $htGitTrackESLZPolicies.($dt).policies.($policyJsonRebuild.name) = @{}
                    # $htGitTrackESLZPolicies.($dt).policies.($policyJsonRebuild.name).version = $policyJsonRebuild.properties.metadata.version
        
                    if (-not $allESLZPolicies.($policyJsonRebuild.name)) {
                        $allESLZPolicies.($policyJsonRebuild.name) = @{}
                        $allESLZPolicies.($policyJsonRebuild.name).version = [System.Collections.ArrayList]@()
                        $null = $allESLZPolicies.($policyJsonRebuild.name).version.Add($policyJsonRebuild.properties.metadata.version)
                        $allESLZPolicies.($policyJsonRebuild.name).$stringHash = $policyJsonRebuild.properties.metadata.version
                        if ($commitCount -eq $gitHist.Count) {
                            $allESLZPolicies.($policyJsonRebuild.name).status = 'prod'
                        }
                        else {
                            $allESLZPolicies.($policyJsonRebuild.name).status = 'obsolete'
                        }
                    }
                    else {
                        if ($commitCount -eq $gitHist.Count) {
                            $allESLZPolicies.($policyJsonRebuild.name).status = 'prod'
                        }
                        else {
                            $allESLZPolicies.($policyJsonRebuild.name).status = 'obsolete'
                        }
                        if ($allESLZPolicies.($policyJsonRebuild.name).version -notcontains $policyJsonRebuild.properties.metadata.version) {
                            $null = $allESLZPolicies.($policyJsonRebuild.name).version.Add($policyJsonRebuild.properties.metadata.version)
                        }
                        if (-not $allESLZPolicies.($policyJsonRebuild.name).$stringHash) {
                            $allESLZPolicies.($policyJsonRebuild.name).$stringHash = $policyJsonRebuild.properties.metadata.version
                        }
                    }
                }

                $eslzPolicySets = $jsonESLZPolicies.variables.initiatives.policySetDefinitions
                foreach ($policySetDefinition in $eslzPolicySets) {
                    $policyJsonConv = ($policySetDefinition | ConvertTo-Json -depth 99) -replace "\[\[", '['
                    $hash = [System.Security.Cryptography.HashAlgorithm]::Create("sha256").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($policyJsonConv))
                    $stringHash = [System.BitConverter]::ToString($hash) 
                    $policyJsonRebuild = $policyJsonConv | ConvertFrom-Json
                    # $htGitTrackESLZPolicies.($dt).policies.($policyJsonRebuild.name) = @{}
                    # $htGitTrackESLZPolicies.($dt).policies.($policyJsonRebuild.name).version = $policyJsonRebuild.properties.metadata.version
                    if (-not $allESLZPolicySets.($policyJsonRebuild.name)) {
                        $allESLZPolicySets.($policyJsonRebuild.name) = @{}
                        $allESLZPolicySets.($policyJsonRebuild.name).version = [System.Collections.ArrayList]@()
                        $null = $allESLZPolicySets.($policyJsonRebuild.name).version.Add($policyJsonRebuild.properties.metadata.version)
                        $allESLZPolicySets.($policyJsonRebuild.name).$stringHash = $policyJsonRebuild.properties.metadata.version
                        if ($commitCount -eq $gitHist.Count) {
                            $allESLZPolicySets.($policyJsonRebuild.name).status = 'prod'
                        }
                        else {
                            $allESLZPolicySets.($policyJsonRebuild.name).status = 'obsolete'
                        }
                    }
                    else {
                        if ($commitCount -eq $gitHist.Count) {
                            $allESLZPolicySets.($policyJsonRebuild.name).status = 'prod'
                        }
                        else {
                            $allESLZPolicySets.($policyJsonRebuild.name).status = 'obsolete'
                        }
                        if ($allESLZPolicySets.($policyJsonRebuild.name).version -notcontains $policyJsonRebuild.properties.metadata.version) {
                            $null = $allESLZPolicySets.($policyJsonRebuild.name).version.Add($policyJsonRebuild.properties.metadata.version)
                        }
                        if (-not $allESLZPolicySets.($policyJsonRebuild.name).$stringHash) {
                            $allESLZPolicySets.($policyJsonRebuild.name).$stringHash = $policyJsonRebuild.properties.metadata.version
                        }
                    }
                }
            }
        }

        Write-Host " Processing ALZ Data Policy definitions"
        $gitHist = (git log --format="%ai`t%H`t%an`t%ae`t%s" -- ./eslzArm/managementGroupTemplates/policyDefinitions/dataPolicies.json) | ConvertFrom-Csv -Delimiter "`t" -Header ("Date", "CommitId", "Author", "Email", "Subject")
        #Write-Host $gitHist.Count
        $commitCount = 0
        foreach ($commit in $gitHist | Sort-Object -Property Date) {

            $commitCount++
            #$dt = (([datetime]$commit.Date).ToUniversalTime()).ToString("yyyyMMddHHmmss")
            # $htGitTrackESLZdataPolicies.($dt) = @{}
            # $htGitTrackESLZdataPolicies.($dt).policies = @{}
            # $htGitTrackESLZdataPolicies.($dt).commitId = $commit.CommitId
            $jsonRaw = git show "$($commit.CommitId):eslzArm/managementGroupTemplates/policyDefinitions/dataPolicies.json"
            
            $jsonESLZPolicies = $jsonRaw | ConvertFrom-Json
            #Write-Host "$dt $($commit.CommitId)"
            if (($jsonESLZPolicies.variables.policies.policyDefinitions).Count -eq 0) {
                $eslzGoodToGo = $false
            }
            else {
                $eslzGoodToGo = $true
                $eslzPolicies = $jsonESLZPolicies.variables.policies.policyDefinitions
                foreach ($policyDefinition in $eslzPolicies) {
                    $policyJsonConv = ($policyDefinition | ConvertTo-Json -depth 99) -replace "\[\[", '['
                    $hash = [System.Security.Cryptography.HashAlgorithm]::Create("sha256").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($policyJsonConv))
                    $stringHash = [System.BitConverter]::ToString($hash) 
                    $policyJsonRebuild = $policyJsonConv | ConvertFrom-Json
                    # $htGitTrackESLZdataPolicies.($dt).policies.($policyJsonRebuild.name) = @{}
                    # $htGitTrackESLZdataPolicies.($dt).policies.($policyJsonRebuild.name).version = $policyJsonRebuild.properties.metadata.version
        
                    if (-not $allESLZPolicies.($policyJsonRebuild.name)) {
                        $allESLZPolicies.($policyJsonRebuild.name) = @{}
                        $allESLZPolicies.($policyJsonRebuild.name).version = [System.Collections.ArrayList]@()
                        $null = $allESLZPolicies.($policyJsonRebuild.name).version.Add($policyJsonRebuild.properties.metadata.version)
                        $allESLZPolicies.($policyJsonRebuild.name).$stringHash = $policyJsonRebuild.properties.metadata.version
                        if ($commitCount -eq $gitHist.Count) {
                            $allESLZPolicies.($policyJsonRebuild.name).status = 'prod'
                        }
                        else {
                            $allESLZPolicies.($policyJsonRebuild.name).status = 'obsolete'
                        }
                    }
                    else {
                        if ($commitCount -eq $gitHist.Count) {
                            $allESLZPolicies.($policyJsonRebuild.name).status = 'prod'
                        }
                        else {
                            $allESLZPolicies.($policyJsonRebuild.name).status = 'obsolete'
                        }
                        if ($allESLZPolicies.($policyJsonRebuild.name).version -notcontains $policyJsonRebuild.properties.metadata.version) {
                            $null = $allESLZPolicies.($policyJsonRebuild.name).version.Add($policyJsonRebuild.properties.metadata.version)
                        }
                        if (-not $allESLZPolicies.($policyJsonRebuild.name).$stringHash) {
                            $allESLZPolicies.($policyJsonRebuild.name).$stringHash = $policyJsonRebuild.properties.metadata.version
                        }
                    }
                }
            }
        }

        Write-Host " $($allESLZPolicies.Keys.Count) Policy definitions ($($allESLZPolicies.Values.where({$_.status -eq 'Prod'}).Count) productive)"
        Write-Host " $($allESLZPolicySets.Keys.Count) PolicySet definitions ($($allESLZPolicySets.Values.where({$_.status -eq 'Prod'}).Count) productive)"

        #$script:alzPolicies = @{}
        foreach ($entry in $allESLZPolicies.keys | sort-object) {
            $thisOne = $allESLZPolicies.($entry)
            $latestVersion = ([array]($thisOne.version | Sort-Object -Descending))[0]
            $script:alzPolicies.($entry) = @{}
            $script:alzPolicies.($entry).latestVersion = $latestVersion
            $script:alzPolicies.($entry).status = $thisOne.status
        }
        $script:alzPolicies.'deploy-asc-standard' = @{}
        $script:alzPolicies.'deploy-asc-standard'.latestVersion = '1.0.0'
        $script:alzPolicies.'deploy-asc-standard'.status = 'obsolete'

        #$script:alzPolicySets = @{}
        foreach ($entry in $allESLZPolicySets.keys | sort-object) {
            $thisOne = $allESLZPolicySets.($entry)
            $latestVersion = ([array]($thisOne.version | Sort-Object -Descending))[0]
            $script:alzPolicySets.($entry) = @{}
            $script:alzPolicySets.($entry).latestVersion = $latestVersion
            $script:alzPolicySets.($entry).status = $thisOne.status
        }
        $script:alzPolicySets.'Deploy-Diag-LogAnalytics' = @{}
        $script:alzPolicySets.'Deploy-Diag-LogAnalytics'.latestVersion = '1.0.0'
        $script:alzPolicySets.'Deploy-Diag-LogAnalytics'.status = 'obsolete'
        
        Write-Host " Switching back to working directory '$($workingPath)'"
        Set-Location $workingPath
        
        Write-Host " Removing temporary directory '$($ALZPath)'"
        Remove-Item -Recurse -Force $ALZPath
    }
}