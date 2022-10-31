function processALZPolicyVersionChecker {
    $start = Get-Date
    Write-Host "Processing 'Azure Landing Zones (ALZ) Policy Version Checker' base data"
    $ALZRepositoryURI = 'https://github.com/Azure/Enterprise-Scale.git'
    $workingPath = Get-Location
    Write-Host " Working directory is '$($workingPath)'"
    $ALZFolderName = "ALZ_$(Get-Date -Format $FileTimeStampFormat)"
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
            Write-Host " Setting switch parameter '-NoALZPolicyVersionChecker' to true"
            $script:NoALZPolicyVersionChecker = $true
            $script:azAPICallConf['htParameters'].NoALZPolicyVersionChecker = $true
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
        Write-Host " Setting switch parameter '-NoALZPolicyVersionChecker' to true"
        $script:NoALZPolicyVersionChecker = $true
        $script:azAPICallConf['htParameters'].NoALZPolicyVersionChecker = $true
        Write-Host " Switching back to working directory '$($workingPath)'"
        Set-Location $workingPath
    }

    if ($ALZCloneSuccess) {
        Write-Host " Switching to directory '$($ALZPath)/Enterprise-Scale'"
        Set-Location "$($ALZPath)/Enterprise-Scale"

        $allESLZPolicies = @{}
        $allESLZPolicySets = @{}
        $allESLZPolicyHashes = @{}
        $allESLZPolicySetHashes = @{}

        #Write-Host " Processing ALZ Data Policy definitions"
        $gitHist = (git log --format="%ai`t%H`t%an`t%ae`t%s" -- ./eslzArm/managementGroupTemplates/policyDefinitions/dataPolicies.json) | ConvertFrom-Csv -Delimiter "`t" -Header ('Date', 'CommitId', 'Author', 'Email', 'Subject')
        $commitCount = 0
        $processDataPolicies = $true
        foreach ($commit in $gitHist | Sort-Object -Property Date) {
            if ($processDataPolicies) {
                if ($commit.CommitId -eq '3476914f9ba9a8f3f641a25497dfb24a4efa1017') {
                    $processDataPolicies = $false
                    continue
                }
                #Write-Host "processing commit (dataPolicies) $($commit.CommitId)"
                $commitCount++
                $jsonRaw = git show "$($commit.CommitId):eslzArm/managementGroupTemplates/policyDefinitions/dataPolicies.json"

                $jsonESLZPolicies = $jsonRaw | ConvertFrom-Json
                if (($jsonESLZPolicies.variables.policies.policyDefinitions).Count -eq 0) {
                }
                else {
                    $eslzPolicies = $jsonESLZPolicies.variables.policies.policyDefinitions
                    foreach ($policyDefinition in $eslzPolicies) {
                        $policyJsonConv = ($policyDefinition | ConvertTo-Json -Depth 99) -replace '\[\[', '['
                        $policyJsonRebuild = $policyJsonConv | ConvertFrom-Json
                        $policyJsonRule = $policyJsonRebuild.properties.policyRule | ConvertTo-Json -Depth 99
                        $hash = [System.Security.Cryptography.HashAlgorithm]::Create('sha256').ComputeHash([System.Text.Encoding]::UTF8.GetBytes($policyJsonRule))
                        $stringHash = [System.BitConverter]::ToString($hash)

                        if (-not $allESLZPolicies.($policyJsonRebuild.name)) {
                            $allESLZPolicies.($policyJsonRebuild.name) = @{}
                            $allESLZPolicies.($policyJsonRebuild.name).version = [System.Collections.ArrayList]@()
                            $null = $allESLZPolicies.($policyJsonRebuild.name).version.Add($policyJsonRebuild.properties.metadata.version)
                            $allESLZPolicies.($policyJsonRebuild.name).$stringHash = $policyJsonRebuild.properties.metadata.version
                            $allESLZPolicies.($policyJsonRebuild.name).name = $policyJsonRebuild.name
                            $allESLZPolicies.($policyJsonRebuild.name).metadataSource = ''

                            $allESLZPolicies.($policyJsonRebuild.name).status = 'obsolete'
                        }
                        else {
                            $allESLZPolicies.($policyJsonRebuild.name).status = 'obsolete'

                            if ($allESLZPolicies.($policyJsonRebuild.name).version -notcontains $policyJsonRebuild.properties.metadata.version) {
                                $null = $allESLZPolicies.($policyJsonRebuild.name).version.Add($policyJsonRebuild.properties.metadata.version)
                            }
                            if (-not $allESLZPolicies.($policyJsonRebuild.name).$stringHash) {
                                $allESLZPolicies.($policyJsonRebuild.name).$stringHash = $policyJsonRebuild.properties.metadata.version
                            }
                        }

                        #hsh
                        if (-not $allESLZPolicyHashes.($stringHash)) {
                            $allESLZPolicyHashes.($stringHash) = @{}
                            $allESLZPolicyHashes.($stringHash).version = [System.Collections.ArrayList]@()
                            $null = $allESLZPolicyHashes.($stringHash).version.Add($policyJsonRebuild.properties.metadata.version)
                            $allESLZPolicyHashes.($stringHash).name = $policyJsonRebuild.name
                            $allESLZPolicyHashes.($stringHash).metadataSource = ''

                            $allESLZPolicyHashes.($stringHash).status = 'obsolete'
                        }
                        else {
                            $allESLZPolicyHashes.($stringHash).status = 'obsolete'
                            if ($allESLZPolicyHashes.($stringHash).version -notcontains $policyJsonRebuild.properties.metadata.version) {
                                $null = $allESLZPolicyHashes.($stringHash).version.Add($policyJsonRebuild.properties.metadata.version)
                            }
                            if (-not $allESLZPolicyHashes.($stringHash).($policyJsonRebuild.name)) {
                                $allESLZPolicyHashes.($stringHash).($policyJsonRebuild.name) = $policyJsonRebuild.name
                            }
                        }
                    }
                }
            }
        }

        #Write-Host " Processing ALZ Policy and Set definitions"
        $gitHist = (git log --format="%ai`t%H`t%an`t%ae`t%s" -- ./eslzArm/managementGroupTemplates/policyDefinitions/policies.json) | ConvertFrom-Csv -Delimiter "`t" -Header ('Date', 'CommitId', 'Author', 'Email', 'Subject')
        $commitCount = 0
        $doNewALZPolicyReadingApproach = $false
        foreach ($commit in $gitHist | Sort-Object -Property Date) {

            if ($commit.CommitId -eq '3476914f9ba9a8f3f641a25497dfb24a4efa1017') {
                $doNewALZPolicyReadingApproach = $true
            }
            #Write-Host "processing commit $($commit.CommitId) - doNewALZPolicyReadingApproach: $doNewALZPolicyReadingApproach"
            $commitCount++

            $jsonRaw = git show "$($commit.CommitId):eslzArm/managementGroupTemplates/policyDefinitions/policies.json"

            if ($doNewALZPolicyReadingApproach) {
                $jsonESLZPolicies = $jsonRaw -replace '\[\[', '[' | ConvertFrom-Json
                [regex]$extractVariableName = "(?<=\[variables\(')[^']+"
                $refsPolicyDefinitionsAll = $extractVariableName.Matches($jsonESLZPolicies.variables.loadPolicyDefinitions.All).Value
                $refsPolicyDefinitionsAzureCloud = $extractVariableName.Matches($jsonESLZPolicies.variables.loadPolicyDefinitions.AzureCloud).Value
                $refsPolicyDefinitionsAzureChinaCloud = $extractVariableName.Matches($jsonESLZPolicies.variables.loadPolicyDefinitions.AzureChinaCloud).Value
                $refsPolicyDefinitionsAzureUSGovernment = $extractVariableName.Matches($jsonESLZPolicies.variables.loadPolicyDefinitions.AzureUSGovernment).Value
                $refsPolicySetDefinitionsAll = $extractVariableName.Matches($jsonESLZPolicies.variables.loadPolicySetDefinitions.All).Value
                $refsPolicySetDefinitionsAzureCloud = $extractVariableName.Matches($jsonESLZPolicies.variables.loadPolicySetDefinitions.AzureCloud).Value
                $refsPolicySetDefinitionsAzureChinaCloud = $extractVariableName.Matches($jsonESLZPolicies.variables.loadPolicySetDefinitions.AzureChinaCloud).Value
                $refsPolicySetDefinitionsAzureUSGovernment = $extractVariableName.Matches($jsonESLZPolicies.variables.loadPolicySetDefinitions.AzureUSGovernment).Value
                $listPolicyDefinitionsAzureCloud = $refsPolicyDefinitionsAll + $refsPolicyDefinitionsAzureCloud
                $listPolicyDefinitionsAzureChinaCloud = $refsPolicyDefinitionsAll + $refsPolicyDefinitionsAzureChinaCloud
                $listPolicyDefinitionsAzureUSGovernment = $refsPolicyDefinitionsAll + $refsPolicyDefinitionsAzureUSGovernment
                $listPolicySetDefinitionsAzureCloud = $refsPolicySetDefinitionsAll + $refsPolicySetDefinitionsAzureCloud
                $listPolicySetDefinitionsAzureChinaCloud = $refsPolicySetDefinitionsAll + $refsPolicySetDefinitionsAzureChinaCloud
                $listPolicySetDefinitionsAzureUSGovernment = $refsPolicySetDefinitionsAll + $refsPolicySetDefinitionsAzureUSGovernment
                $policyDefinitionsAzureCloud = $listPolicyDefinitionsAzureCloud.ForEach({ $jsonESLZPolicies.variables.$_ })
                $policyDefinitionsAzureChinaCloud = $listPolicyDefinitionsAzureChinaCloud.ForEach({ $jsonESLZPolicies.variables.$_ })
                $policyDefinitionsAzureUSGovernment = $listPolicyDefinitionsAzureUSGovernment.ForEach({ $jsonESLZPolicies.variables.$_ })
                $policySetDefinitionsAzureCloud = $listPolicySetDefinitionsAzureCloud.ForEach({ $jsonESLZPolicies.variables.$_ })
                $policySetDefinitionsAzureChinaCloud = $listPolicySetDefinitionsAzureChinaCloud.ForEach({ $jsonESLZPolicies.variables.$_ })
                $policySetDefinitionsAzureUSGovernment = $listPolicySetDefinitionsAzureUSGovernment.ForEach({ $jsonESLZPolicies.variables.$_ })

                switch ($azAPICallConf['checkContext'].Environment.Name) {
                    'Azurecloud' {
                        $policyDefinitionsData = $policyDefinitionsAzureCloud
                        $policySetDefinitionsData = $policySetDefinitionsAzureCloud
                    }
                    'AzureChinaCloud' {
                        $policyDefinitionsData = $policyDefinitionsAzureChinaCloud
                        $policySetDefinitionsData = $policySetDefinitionsAzureChinaCloud
                    }
                    'AzureUSGovernment' {
                        $policyDefinitionsData = $policyDefinitionsAzureUSGovernment
                        $policySetDefinitionsData = $policySetDefinitionsAzureUSGovernment
                    }
                }

                foreach ($policyDefinition in $policyDefinitionsData) {

                    $policyJsonRebuild = $policyDefinition | ConvertFrom-Json
                    $policyJsonRule = $policyJsonRebuild.properties.policyRule | ConvertTo-Json -Depth 99
                    $hash = [System.Security.Cryptography.HashAlgorithm]::Create('sha256').ComputeHash([System.Text.Encoding]::UTF8.GetBytes($policyJsonRule))
                    $stringHash = [System.BitConverter]::ToString($hash)

                    if (-not $allESLZPolicies.($policyJsonRebuild.name)) {
                        $allESLZPolicies.($policyJsonRebuild.name) = @{}
                        $allESLZPolicies.($policyJsonRebuild.name).version = [System.Collections.ArrayList]@()
                        $null = $allESLZPolicies.($policyJsonRebuild.name).version.Add($policyJsonRebuild.properties.metadata.version)
                        $allESLZPolicies.($policyJsonRebuild.name).$stringHash = $policyJsonRebuild.properties.metadata.version
                        $allESLZPolicies.($policyJsonRebuild.name).name = $policyJsonRebuild.name
                        $allESLZPolicies.($policyJsonRebuild.name).metadataSource = $policyJsonRebuild.properties.metadata.source
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
                        $allESLZPolicies.($policyJsonRebuild.name).metadataSource = $policyJsonRebuild.properties.metadata.source
                        if ($allESLZPolicies.($policyJsonRebuild.name).version -notcontains $policyJsonRebuild.properties.metadata.version) {
                            $null = $allESLZPolicies.($policyJsonRebuild.name).version.Add($policyJsonRebuild.properties.metadata.version)
                        }
                        if (-not $allESLZPolicies.($policyJsonRebuild.name).$stringHash) {
                            $allESLZPolicies.($policyJsonRebuild.name).$stringHash = $policyJsonRebuild.properties.metadata.version
                        }
                    }

                    #hsh
                    if (-not $allESLZPolicyHashes.($stringHash)) {
                        $allESLZPolicyHashes.($stringHash) = @{}
                        $allESLZPolicyHashes.($stringHash).version = [System.Collections.ArrayList]@()
                        $null = $allESLZPolicyHashes.($stringHash).version.Add($policyJsonRebuild.properties.metadata.version)
                        $allESLZPolicyHashes.($stringHash).name = $policyJsonRebuild.name
                        $allESLZPolicyHashes.($stringHash).metadataSource = $policyJsonRebuild.properties.metadata.source
                        if ($commitCount -eq $gitHist.Count) {
                            $allESLZPolicyHashes.($stringHash).status = 'prod'
                        }
                        else {
                            $allESLZPolicyHashes.($stringHash).status = 'obsolete'
                        }
                    }
                    else {
                        if ($commitCount -eq $gitHist.Count) {
                            $allESLZPolicyHashes.($stringHash).status = 'prod'
                        }
                        else {
                            $allESLZPolicyHashes.($stringHash).status = 'obsolete'
                        }
                        $allESLZPolicyHashes.($stringHash).metadataSource = $policyJsonRebuild.properties.metadata.source
                        if ($allESLZPolicyHashes.($stringHash).version -notcontains $policyJsonRebuild.properties.metadata.version) {
                            $null = $allESLZPolicyHashes.($stringHash).version.Add($policyJsonRebuild.properties.metadata.version)
                        }
                        if (-not $allESLZPolicyHashes.($stringHash).($policyJsonRebuild.name)) {
                            $allESLZPolicyHashes.($stringHash).($policyJsonRebuild.name) = $policyJsonRebuild.name
                        }
                    }
                }

                foreach ($policySetDefinition in $policySetDefinitionsData) {

                    $policyJsonRebuild = $policySetDefinition | ConvertFrom-Json
                    $policyJsonParameters = $policyJsonRebuild.properties.parameters | ConvertTo-Json -Depth 99
                    $policyJsonPolicyDefinitions = $policyJsonRebuild.properties.policyDefinitions | ConvertTo-Json -Depth 99
                    $hashParameters = [System.Security.Cryptography.HashAlgorithm]::Create('sha256').ComputeHash([System.Text.Encoding]::UTF8.GetBytes($policyJsonParameters))
                    $stringHashParameters = [System.BitConverter]::ToString($hashParameters)
                    $hashPolicyDefinitions = [System.Security.Cryptography.HashAlgorithm]::Create('sha256').ComputeHash([System.Text.Encoding]::UTF8.GetBytes($policyJsonPolicyDefinitions))
                    $stringHashPolicyDefinitions = [System.BitConverter]::ToString($hashPolicyDefinitions)
                    $stringHash = "$($stringHashParameters)_$($stringHashPolicyDefinitions)"

                    if (-not $allESLZPolicySets.($policyJsonRebuild.name)) {
                        $allESLZPolicySets.($policyJsonRebuild.name) = @{}
                        $allESLZPolicySets.($policyJsonRebuild.name).version = [System.Collections.ArrayList]@()
                        $null = $allESLZPolicySets.($policyJsonRebuild.name).version.Add($policyJsonRebuild.properties.metadata.version)
                        $allESLZPolicySets.($policyJsonRebuild.name).$stringHash = $policyJsonRebuild.properties.metadata.version
                        $allESLZPolicySets.($policyJsonRebuild.name).name = $policyJsonRebuild.name
                        $allESLZPolicySets.($policyJsonRebuild.name).metadataSource = $policyJsonRebuild.properties.metadata.source
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
                        $allESLZPolicySets.($policyJsonRebuild.name).metadataSource = $policyJsonRebuild.properties.metadata.source
                        if ($allESLZPolicySets.($policyJsonRebuild.name).version -notcontains $policyJsonRebuild.properties.metadata.version) {
                            $null = $allESLZPolicySets.($policyJsonRebuild.name).version.Add($policyJsonRebuild.properties.metadata.version)
                        }
                        if (-not $allESLZPolicySets.($policyJsonRebuild.name).$stringHash) {
                            $allESLZPolicySets.($policyJsonRebuild.name).$stringHash = $policyJsonRebuild.properties.metadata.version
                        }
                    }

                    #hsh
                    if (-not $allESLZPolicySetHashes.($stringHash)) {
                        $allESLZPolicySetHashes.($stringHash) = @{}
                        $allESLZPolicySetHashes.($stringHash).version = [System.Collections.ArrayList]@()
                        $null = $allESLZPolicySetHashes.($stringHash).version.Add($policyJsonRebuild.properties.metadata.version)
                        $allESLZPolicySetHashes.($stringHash).name = $policyJsonRebuild.name
                        $allESLZPolicySetHashes.($stringHash).metadataSource = $policyJsonRebuild.properties.metadata.source
                        if ($commitCount -eq $gitHist.Count) {
                            $allESLZPolicySetHashes.($stringHash).status = 'prod'
                        }
                        else {
                            $allESLZPolicySetHashes.($stringHash).status = 'obsolete'
                        }
                    }
                    else {
                        if ($commitCount -eq $gitHist.Count) {
                            $allESLZPolicySetHashes.($stringHash).status = 'prod'
                        }
                        else {
                            $allESLZPolicySetHashes.($stringHash).status = 'obsolete'
                        }
                        $allESLZPolicySetHashes.($stringHash).metadataSource = $policyJsonRebuild.properties.metadata.source
                        if ($allESLZPolicySetHashes.($stringHash).version -notcontains $policyJsonRebuild.properties.metadata.version) {
                            $null = $allESLZPolicySetHashes.($stringHash).version.Add($policyJsonRebuild.properties.metadata.version)
                        }
                        if (-not $allESLZPolicySetHashes.($stringHash).($policyJsonRebuild.name)) {
                            $allESLZPolicySetHashes.($stringHash).($policyJsonRebuild.name) = $policyJsonRebuild.name
                        }
                    }
                }
            }
            else {
                $jsonESLZPolicies = $jsonRaw | ConvertFrom-Json
                if (($jsonESLZPolicies.variables.policies.policyDefinitions).Count -eq 0) {
                }
                else {

                    $eslzPolicies = $jsonESLZPolicies.variables.policies.policyDefinitions
                    foreach ($policyDefinition in $eslzPolicies) {
                        $policyJsonConv = ($policyDefinition | ConvertTo-Json -Depth 99) -replace '\[\[', '['
                        $policyJsonRebuild = $policyJsonConv | ConvertFrom-Json
                        $policyJsonRule = $policyJsonRebuild.properties.policyRule | ConvertTo-Json -Depth 99
                        $hash = [System.Security.Cryptography.HashAlgorithm]::Create('sha256').ComputeHash([System.Text.Encoding]::UTF8.GetBytes($policyJsonRule))
                        $stringHash = [System.BitConverter]::ToString($hash)

                        if (-not $allESLZPolicies.($policyJsonRebuild.name)) {
                            $allESLZPolicies.($policyJsonRebuild.name) = @{}
                            $allESLZPolicies.($policyJsonRebuild.name).version = [System.Collections.ArrayList]@()
                            $null = $allESLZPolicies.($policyJsonRebuild.name).version.Add($policyJsonRebuild.properties.metadata.version)
                            $allESLZPolicies.($policyJsonRebuild.name).$stringHash = $policyJsonRebuild.properties.metadata.version
                            $allESLZPolicies.($policyJsonRebuild.name).name = $policyJsonRebuild.name
                            $allESLZPolicies.($policyJsonRebuild.name).metadataSource = ''
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

                        #hsh
                        if (-not $allESLZPolicyHashes.($stringHash)) {
                            $allESLZPolicyHashes.($stringHash) = @{}
                            $allESLZPolicyHashes.($stringHash).version = [System.Collections.ArrayList]@()
                            $null = $allESLZPolicyHashes.($stringHash).version.Add($policyJsonRebuild.properties.metadata.version)
                            $allESLZPolicyHashes.($stringHash).name = $policyJsonRebuild.name
                            $allESLZPolicyHashes.($stringHash).metadataSource = ''
                            if ($commitCount -eq $gitHist.Count) {
                                $allESLZPolicyHashes.($stringHash).status = 'prod'
                            }
                            else {
                                $allESLZPolicyHashes.($stringHash).status = 'obsolete'
                            }
                        }
                        else {
                            if ($commitCount -eq $gitHist.Count) {
                                $allESLZPolicyHashes.($stringHash).status = 'prod'
                            }
                            else {
                                $allESLZPolicyHashes.($stringHash).status = 'obsolete'
                            }
                            if ($allESLZPolicyHashes.($stringHash).version -notcontains $policyJsonRebuild.properties.metadata.version) {
                                $null = $allESLZPolicyHashes.($stringHash).version.Add($policyJsonRebuild.properties.metadata.version)
                            }
                            if (-not $allESLZPolicyHashes.($stringHash).($policyJsonRebuild.name)) {
                                $allESLZPolicyHashes.($stringHash).($policyJsonRebuild.name) = $policyJsonRebuild.name
                            }
                        }
                    }

                    $eslzPolicySets = $jsonESLZPolicies.variables.initiatives.policySetDefinitions
                    foreach ($policySetDefinition in $eslzPolicySets) {

                        $policyJsonConv = ($policySetDefinition | ConvertTo-Json -Depth 99) -replace '\[\[', '['
                        $policyJsonRebuild = $policyJsonConv | ConvertFrom-Json
                        $policyJsonParameters = $policyJsonRebuild.properties.parameters | ConvertTo-Json -Depth 99
                        $policyJsonPolicyDefinitions = $policyJsonRebuild.properties.policyDefinitions | ConvertTo-Json -Depth 99
                        $hashParameters = [System.Security.Cryptography.HashAlgorithm]::Create('sha256').ComputeHash([System.Text.Encoding]::UTF8.GetBytes($policyJsonParameters))
                        $stringHashParameters = [System.BitConverter]::ToString($hashParameters)
                        $hashPolicyDefinitions = [System.Security.Cryptography.HashAlgorithm]::Create('sha256').ComputeHash([System.Text.Encoding]::UTF8.GetBytes($policyJsonPolicyDefinitions))
                        $stringHashPolicyDefinitions = [System.BitConverter]::ToString($hashPolicyDefinitions)
                        $stringHash = "$($stringHashParameters)_$($stringHashPolicyDefinitions)"

                        if (-not $allESLZPolicySets.($policyJsonRebuild.name)) {
                            $allESLZPolicySets.($policyJsonRebuild.name) = @{}
                            $allESLZPolicySets.($policyJsonRebuild.name).version = [System.Collections.ArrayList]@()
                            $null = $allESLZPolicySets.($policyJsonRebuild.name).version.Add($policyJsonRebuild.properties.metadata.version)
                            $allESLZPolicySets.($policyJsonRebuild.name).$stringHash = $policyJsonRebuild.properties.metadata.version
                            $allESLZPolicySets.($policyJsonRebuild.name).name = $policyJsonRebuild.name
                            $allESLZPolicySets.($policyJsonRebuild.name).metadataSource = ''
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

                        #hsh
                        if (-not $allESLZPolicySetHashes.($stringHash)) {
                            $allESLZPolicySetHashes.($stringHash) = @{}
                            $allESLZPolicySetHashes.($stringHash).version = [System.Collections.ArrayList]@()
                            $null = $allESLZPolicySetHashes.($stringHash).version.Add($policyJsonRebuild.properties.metadata.version)
                            $allESLZPolicySetHashes.($stringHash).name = $policyJsonRebuild.name
                            $allESLZPolicySetHashes.($stringHash).metadataSource = ''
                            if ($commitCount -eq $gitHist.Count) {
                                $allESLZPolicySetHashes.($stringHash).status = 'prod'
                            }
                            else {
                                $allESLZPolicySetHashes.($stringHash).status = 'obsolete'
                            }
                        }
                        else {
                            if ($commitCount -eq $gitHist.Count) {
                                $allESLZPolicySetHashes.($stringHash).status = 'prod'
                            }
                            else {
                                $allESLZPolicySetHashes.($stringHash).status = 'obsolete'
                            }
                            if ($allESLZPolicySetHashes.($stringHash).version -notcontains $policyJsonRebuild.properties.metadata.version) {
                                $null = $allESLZPolicySetHashes.($stringHash).version.Add($policyJsonRebuild.properties.metadata.version)
                            }
                            if (-not $allESLZPolicySetHashes.($stringHash).($policyJsonRebuild.name)) {
                                $allESLZPolicySetHashes.($stringHash).($policyJsonRebuild.name) = $policyJsonRebuild.name
                            }
                        }
                    }
                }
            }
        }


        Write-Host " $($allESLZPolicies.Keys.Count) Azure Landing Zones (ALZ) Policy definitions ($($allESLZPolicies.Values.where({$_.status -eq 'Prod'}).Count) productive)"
        Write-Host " $($allESLZPolicySets.Keys.Count) Azure Landing Zones (ALZ) PolicySet definitions ($($allESLZPolicySets.Values.where({$_.status -eq 'Prod'}).Count) productive)"

        $arrayObsoleteALZPolicies = @(
            'Deny-PublicEndpoint-Aks',
            'Deny-PublicEndpoint-CosmosDB',
            'Deny-PublicEndpoint-KeyVault',
            'Deny-PublicEndpoint-MySQL',
            'Deny-PublicEndpoint-PostgreSql',
            'Deny-PublicEndpoint-Sql',
            'Deny-PublicEndpoint-Storage',
            'Deploy-ASC-Standard',
            'Deploy-Diagnostics-ActivityLog',
            'Deploy-Diagnostics-AKS',
            'Deploy-Diagnostics-Batch',
            'Deploy-Diagnostics-DataLakeStore',
            'Deploy-Diagnostics-EventHub',
            'Deploy-Diagnostics-KeyVault',
            'Deploy-Diagnostics-LogicAppsWF',
            'Deploy-Diagnostics-PublicIP',
            'Deploy-Diagnostics-RecoveryVault',
            'Deploy-Diagnostics-SearchServices',
            'Deploy-Diagnostics-ServiceBus',
            'Deploy-Diagnostics-SQLDBs',
            'Deploy-Diagnostics-StreamAnalytics',
            'Deploy-DNSZoneGroup-For-Blob-PrivateEndpoint',
            'Deploy-DNSZoneGroup-For-File-PrivateEndpoint',
            'Deploy-DNSZoneGroup-For-KeyVault-PrivateEndpoint',
            'Deploy-DNSZoneGroup-For-Queue-PrivateEndpoint',
            'Deploy-DNSZoneGroup-For-Sql-PrivateEndpoint',
            'Deploy-DNSZoneGroup-For-Table-PrivateEndpoint',
            'Deploy-HUB',
            'Deploy-LA-Config',
            'Deploy-Log-Analytics',
            'Deploy-vHUB',
            'Deploy-vNet',
            'Deploy-vWAN'
        )
        foreach ($obsoleteALZPolicy in $arrayObsoleteALZPolicies) {
            if (-not $alzPolicies.($obsoleteALZPolicy)) {
                $script:alzPolicies.($obsoleteALZPolicy) = @{}
                $script:alzPolicies.($obsoleteALZPolicy).latestVersion = ''
                $script:alzPolicies.($obsoleteALZPolicy).status = 'obsolete'
                $script:alzPolicies.($obsoleteALZPolicy).policyName = $obsoleteALZPolicy
                $script:alzPolicies.($obsoleteALZPolicy).metadataSource = ''
            }
        }

        foreach ($entry in $allESLZPolicies.keys | Sort-Object) {
            $thisOne = $allESLZPolicies.($entry)
            $latestVersion = ([array]($thisOne.version | Sort-Object -Descending))[0]
            $script:alzPolicies.($entry) = @{}
            $script:alzPolicies.($entry).latestVersion = $latestVersion
            $script:alzPolicies.($entry).status = $thisOne.status
            $script:alzPolicies.($entry).policyName = $thisOne.name
            $script:alzPolicies.($entry).metadataSource = $thisOne.name
        }

        foreach ($entry in $allESLZPolicyHashes.keys | Sort-Object) {
            $thisOne = $allESLZPolicyHashes.($entry)
            $latestVersion = ([array]($thisOne.version | Sort-Object -Descending))[0]
            $script:alzPolicyHashes.($entry) = @{}
            $script:alzPolicyHashes.($entry).latestVersion = $latestVersion
            $script:alzPolicyHashes.($entry).status = $thisOne.status
            $script:alzPolicyHashes.($entry).policyName = $thisOne.name
            $script:alzPolicyHashes.($entry).metadataSource = $thisOne.metadataSource
        }

        $script:alzPolicySets.'Deploy-Diag-LogAnalytics' = @{}
        $script:alzPolicySets.'Deploy-Diag-LogAnalytics'.latestVersion = '1.0.0'
        $script:alzPolicySets.'Deploy-Diag-LogAnalytics'.status = 'obsolete'
        $script:alzPolicySets.'Deploy-Diag-LogAnalytics'.policySetName = 'Deploy-Diag-LogAnalytics'
        foreach ($entry in $allESLZPolicySets.keys | Sort-Object) {
            $thisOne = $allESLZPolicySets.($entry)
            $latestVersion = ([array]($thisOne.version | Sort-Object -Descending))[0]
            $script:alzPolicySets.($entry) = @{}
            $script:alzPolicySets.($entry).latestVersion = $latestVersion
            $script:alzPolicySets.($entry).status = $thisOne.status
            $script:alzPolicySets.($entry).policySetName = $thisOne.name
            $script:alzPolicySets.($entry).metadataSource = $thisOne.metadataSource
        }

        foreach ($entry in $allESLZPolicySetHashes.keys | Sort-Object) {
            $thisOne = $allESLZPolicySetHashes.($entry)
            $latestVersion = ([array]($thisOne.version | Sort-Object -Descending))[0]
            $script:alzPolicySetHashes.($entry) = @{}
            $script:alzPolicySetHashes.($entry).latestVersion = $latestVersion
            $script:alzPolicySetHashes.($entry).status = $thisOne.status
            $script:alzPolicySetHashes.($entry).policySetName = $thisOne.name
            $script:alzPolicySetHashes.($entry).metadataSource = $thisOne.metadataSource
        }

        Write-Host " Switching back to working directory '$($workingPath)'"
        Set-Location $workingPath

        Write-Host " Removing temporary directory '$($ALZPath)'"
        Remove-Item -Recurse -Force $ALZPath
    }

    $end = Get-Date
    Write-Host " Processing 'Azure Landing Zones (ALZ) Policy Version Checker' base data duration: $((New-TimeSpan -Start $start -End $end).TotalSeconds) seconds"
}