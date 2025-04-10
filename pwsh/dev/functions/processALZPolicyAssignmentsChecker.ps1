function processALZPolicyAssignmentsChecker {
    Write-Host "Processing 'Azure Landing Zones (ALZ) Policy Assignment Checker' base data"
    $ALZLibraryRepositoryURI = 'https://github.com/Azure/Azure-Landing-Zones-Library.git'
    $workingPath = Get-Location
    Write-Host " Working directory is '$($workingPath)'"
    $AlZLibraryFolderName = "ALZ_Library_$(Get-Date -Format $FileTimeStampFormat)"
    $ALZLibraryPath = "$($OutputPath)/$($AlZLibraryFolderName)"

    if (-not (Test-Path -LiteralPath "$($ALZLibraryPath)")) {
        Write-Host " Creating temporary directory '$($ALZLibraryPath)'"
        $null = mkdir $ALZLibraryPath
    }
    else {
        Write-Host " Unexpected: The path '$($ALZLibraryPath)' already exists"
        throw
    }

    Write-Host " Switching to temporary directory '$($ALZLibraryPath)'"
    Set-Location $ALZLibraryPath
    $ALZCloneSuccess = $false

    try {
        Write-Host " Try cloning '$($ALZLibraryRepositoryURI)'"
        git clone $ALZLibraryRepositoryURI
        if (-not (Test-Path -LiteralPath "$($ALZLibraryPath)/Azure-Landing-Zones-Library" -PathType Container)) {
            $ALZCloneSuccess = $false
            Write-Host " Cloning '$($ALZLibraryRepositoryURI)' failed"
            Write-Host " Setting switch parameter '-ALZPolicyAssignmentsChecker' to false"
            $script:ALZPolicyAssignmentsChecker = $false
            $script:azAPICallConf['htParameters'].ALZPolicyAssignmentsChecker = $false
            Write-Host " Switching back to working directory '$($workingPath)'"
            Set-Location $workingPath
        }
        else {
            Write-Host " Cloning '$($ALZLibraryRepositoryURI)' succeeded"
            $ALZCloneSuccess = $true
        }
    }
    catch {
        $_
        Write-Host " Cloning '$($ALZLibraryRepositoryURI)' failed"
        Write-Host " Setting switch parameter '-ALZPolicyAssignmentsChecker' to false"
        $script:ALZPolicyAssignmentsChecker = $false
        $script:azAPICallConf['htParameters'].ALZPolicyAssignmentsChecker = $false
        Write-Host " Switching back to working directory '$($workingPath)'"
        Set-Location $workingPath
    }

    if ($ALZCloneSuccess) {
        Write-Host " Switching to directory '$($ALZLibraryPath)/Azure-Landing-Zones-Library'"
        Set-Location "$($ALZLibraryPath)/Azure-Landing-Zones-Library"

        Write-Host ' Fetching the latest Azure Landing Zones Library releases'
        git fetch --tags
        Write-Host ' Getting the latest Azure Landing Zones Library release'
        $latestALZLibraryRelease = git tag --sort=-creatordate | Where-Object { $_ -match 'platform/alz' } | Select-Object -First 1
        $latestALZLibraryReleaseURL = "https://github.com/Azure/Azure-Landing-Zones-Library/releases/tag/$latestALZLibraryRelease"
        $latestALZLibraryCommit = git rev-parse $latestALZLibraryRelease
        Write-Host ' Checking if the latest Azure Landing Zones Library release matches to an ESLZ release'
        git config --global advice.detachedHead false
        try {
            $latestALZLibraryReleaseRequest = Invoke-WebRequest -Uri "https://api.github.com/repos/azure/azure-landing-zones-library/releases/tags/$latestALZLibraryRelease"
            $latestALZLibraryReleaseBody = ($latestALZLibraryReleaseRequest | ConvertFrom-Json).body
            if ($latestALZLibraryReleaseRequest.StatusCode -eq 200) {
                $ESLZReleasePattern = 'https://github\.com/Azure/Enterprise-Scale/releases/tag/[^\s\)]*'
                $ESLZReleaseURL = [regex]::Match($latestALZLibraryReleaseBody, $ESLZReleasePattern).Value
                if ($ESLZReleaseURL) {
                    $ESLZRelease = ([regex]::Match($latestALZLibraryReleaseBody, $ESLZReleasePattern).Value).split('/')[-1]
                }
                else {
                    $ESLZRelease = $null
                    $ESLZReleaseURL = $null
                }
                git checkout $latestALZLibraryCommit
            }
        }
        catch {
            Write-Host 'Release not found or error accessing the URL'
            $ESLZRelease = $null
            $ESLZReleaseURL = $null
            $script:ALZPolicyAssignmentsChecker = $false
            $script:azAPICallConf['htParameters'].ALZPolicyAssignmentsChecker = $false
        }

        $script:referenceALZPolicyAssignments = @{}
        $script:ALZpolicyDefinitionsTable = @{}
        $script:ALZPolicyAssignmentsPayloadFiles = @{}
        $script:ESLZRelease = $ESLZRelease
        $script:ESLZReleaseURL = $ESLZReleaseURL
        $script:latestALZLibraryReleaseURL = $latestALZLibraryReleaseURL
        $script:latestALZLibraryRelease = $latestALZLibraryRelease
        $script:latestALZLibraryCommit = $latestALZLibraryCommit
        $archetypesPath = '.\platform\alz\archetype_definitions'
        $policyAssignmentsPath = '.\platform\alz\policy_assignments'
        $archetypesDefinition = Get-ChildItem -Path $archetypesPath -Filter '*.json'

        function Test-ALZManagementGroupIds {
            param (
                [string]$managementGroupIdTobeChecked
            )
            $ALZMangementGroupFound = ($arrayEntitiesFromAPI.where( { $_.Type -eq 'Microsoft.Management/managementGroups' -and $_.id.split('/')[-1] -eq $managementGroupIdTobeChecked -and ($_.properties.parentNameChain -match $ManagementGroupId -or $managementGroupIdTobeChecked -eq $ManagementGroupId) })).id
            if ($null -eq $ALZMangementGroupFound) {
                return $false
            }
            else {
                return $true
            }

            return $ALZMangementGroupFound
        }

        try {
            # Define the variables and their default values
            $variableMap = @{
                'connectivity'   = @{ Variable = $ALZManagementGroupsIds['connectivity']; Default = 'connectivity' }
                'corp'           = @{ Variable = $ALZManagementGroupsIds['corp']; Default = 'corp' }
                'root'           = @{ Variable = $ALZManagementGroupsIds['root']; Default = 'alz' }
                'platform'       = @{ Variable = $ALZManagementGroupsIds['platform']; Default = 'platform' }
                'online'         = @{ Variable = $ALZManagementGroupsIds['online']; Default = 'online' }
                'sandbox'        = @{ Variable = $ALZManagementGroupsIds['sandbox']; Default = 'sandbox' }
                'decommissioned' = @{ Variable = $ALZManagementGroupsIds['decommissioned']; Default = 'decommissioned' }
                'management'     = @{ Variable = $ALZManagementGroupsIds['management']; Default = 'management' }
                'identity'       = @{ Variable = $ALZManagementGroupsIds['identity']; Default = 'identity' }
                'landing_zones'  = @{ Variable = $ALZManagementGroupsIds['landing_zones']; Default = 'landing_zones' }
            }

            $ALZManagementGroupsIds = $script:ALZManagementGroupsIds
            foreach ($archetype in $archetypesDefinition) {
                $key = ($archetype.BaseName -split '\.')[0]
                switch ($key) {
                    'connectivity' { if ($ALZManagementGroupsIds.containsKey('connectivity') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['connectivity'])) { $key = $ALZManagementGroupsIds['connectivity'] } else { if (Test-ALZManagementGroupIds $variableMap.connectivity.Default) { $key = $variableMap.connectivity.Default } else { $key = 'connectivity-notProvided' } } }
                    'corp' { if ($ALZManagementGroupsIds.containsKey('corp') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['corp'])) { $key = $ALZManagementGroupsIds['corp'] } else { if (Test-ALZManagementGroupIds $variableMap.corp.Default) { $key = $variableMap.corp.Default } else { $key = 'corp-notProvided' } } }
                    'root' { if ($ALZManagementGroupsIds.containsKey('root') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['root'])) { $key = $ALZManagementGroupsIds['root'] } else { if (Test-ALZManagementGroupIds $variableMap.root.Default) { $key = $variableMap.root.Default } else { $key = 'root-notProvided' } } }
                    'platform' { if ($ALZManagementGroupsIds.containsKey('platform') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['platform'])) { $key = $ALZManagementGroupsIds['platform'] } else { if (Test-ALZManagementGroupIds $variableMap.platform.Default) { $key = $variableMap.platform.Default } else { $key = 'platform-notProvided' } } }
                    'online' { if ($ALZManagementGroupsIds.containsKey('online') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['online'])) { $key = $ALZManagementGroupsIds['online'] } else { if (Test-ALZManagementGroupIds $variableMap.online.Default) { $key = $variableMap.online.Default } else { $key = 'online-notProvided' } } }
                    'sandbox' { if ($ALZManagementGroupsIds.containsKey('sandbox') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['sandbox'])) { $key = $ALZManagementGroupsIds['sandbox'] } else { if (Test-ALZManagementGroupIds $variableMap.sandbox.Default) { $key = $variableMap.sandbox.Default } else { $key = 'sandbox-notProvided' } } }
                    'decommissioned' { if ($ALZManagementGroupsIds.containsKey('decommissioned') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['decommissioned'])) { $key = $ALZManagementGroupsIds['decommissioned'] } else { if (Test-ALZManagementGroupIds $variableMap.decommissioned.Default) { $key = $variableMap.decommissioned.Default } else { $key = 'decommissioned-notProvided' } } }
                    'management' { if ($ALZManagementGroupsIds.containsKey('management') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['management'])) { $key = $ALZManagementGroupsIds['management'] } else { if (Test-ALZManagementGroupIds $variableMap.management.Default) { $key = $variableMap.management.Default } else { $key = 'management-notProvided' } } }
                    'identity' { if ($ALZManagementGroupsIds.containsKey('identity') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['identity'])) { $key = $ALZManagementGroupsIds['identity'] } else { if (Test-ALZManagementGroupIds $variableMap.identity.Default) { $key = $variableMap.identity.Default } else { $key = 'identity-notProvided' } } }
                    'landing_zones' { if ($ALZManagementGroupsIds.containsKey('landing_zones') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['landing_zones'])) { $key = $ALZManagementGroupsIds['landing_zones'] } else { if (Test-ALZManagementGroupIds $variableMap.landing_zones.Default) { $key = $variableMap.landing_zones.Default } else { $key = 'landing_zones-notProvided' } } }
                    Default {}
                }
                $content = Get-Content $archetype.FullName | ConvertFrom-Json
                if ($content.policy_assignments) {
                    $script:referenceALZPolicyAssignments[$key] = $content.policy_assignments
                    $content.policy_assignments | ForEach-Object {
                        $assignmentName = $_
                        $filename = "$assignmentName.alz_policy_assignment.json"
                        $script:ALZPolicyAssignmentsPayloadFiles[$_] = $filename
                        $PolicyContent = Get-Content -Path "$policyAssignmentsPath\$filename" | ConvertFrom-Json
                        $script:ALZpolicyDefinitionsTable[$_] = $PolicyContent.properties.policyDefinitionId
                    }
                }
            }
            # Output the result
            $script:referenceALZPolicyAssignments | ConvertTo-Json -Depth 10 | Out-File "$($OutputPath)/ALZPolicyAssignmentsChecker.json"
            Write-Host " Switching back to working directory '$($workingPath)'"
            Set-Location $workingPath

            Write-Host " Removing temporary directory '$($ALZLibraryPath)'"
            Remove-Item -Recurse -Force $ALZLibraryPath

            $currentALZPolicyAssignments = @{}
            $variableMapCalculated = @{}

            foreach ($item in $variableMap.GetEnumerator()) {
                switch ($item.Key) {
                    'connectivity' { if ($ALZManagementGroupsIds.containsKey('connectivity') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['connectivity'])) { $key = $ALZManagementGroupsIds['connectivity'] } else { if (Test-ALZManagementGroupIds $variableMap.connectivity.Default) { $key = $variableMap.connectivity.Default } else { $key = 'connectivity-notProvided' } } }
                    'corp' { if ($ALZManagementGroupsIds.containsKey('corp') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['corp'])) { $key = $ALZManagementGroupsIds['corp'] } else { if (Test-ALZManagementGroupIds $variableMap.corp.Default) { $key = $variableMap.corp.Default } else { $key = 'corp-notProvided' } } }
                    'root' { if ($ALZManagementGroupsIds.containsKey('root') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['root'])) { $key = $ALZManagementGroupsIds['root'] } else { if (Test-ALZManagementGroupIds $variableMap.root.Default) { $key = $variableMap.root.Default } else { $key = 'root-notProvided' } } }
                    'platform' { if ($ALZManagementGroupsIds.containsKey('platform') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['platform'])) { $key = $ALZManagementGroupsIds['platform'] } else { if (Test-ALZManagementGroupIds $variableMap.platform.Default) { $key = $variableMap.platform.Default } else { $key = 'platform-notProvided' } } }
                    'online' { if ($ALZManagementGroupsIds.containsKey('online') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['online'])) { $key = $ALZManagementGroupsIds['online'] } else { if (Test-ALZManagementGroupIds $variableMap.online.Default) { $key = $variableMap.online.Default } else { $key = 'online-notProvided' } } }
                    'sandbox' { if ($ALZManagementGroupsIds.containsKey('sandbox') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['sandbox'])) { $key = $ALZManagementGroupsIds['sandbox'] } else { if (Test-ALZManagementGroupIds $variableMap.sandbox.Default) { $key = $variableMap.sandbox.Default } else { $key = 'sandbox-notProvided' } } }
                    'decommissioned' { if ($ALZManagementGroupsIds.containsKey('decommissioned') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['decommissioned'])) { $key = $ALZManagementGroupsIds['decommissioned'] } else { if (Test-ALZManagementGroupIds $variableMap.decommissioned.Default) { $key = $variableMap.decommissioned.Default } else { $key = 'decommissioned-notProvided' } } }
                    'management' { if ($ALZManagementGroupsIds.containsKey('management') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['management'])) { $key = $ALZManagementGroupsIds['management'] } else { if (Test-ALZManagementGroupIds $variableMap.management.Default) { $key = $variableMap.management.Default } else { $key = 'management-notProvided' } } }
                    'identity' { if ($ALZManagementGroupsIds.containsKey('identity') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['identity'])) { $key = $ALZManagementGroupsIds['identity'] } else { if (Test-ALZManagementGroupIds $variableMap.identity.Default) { $key = $variableMap.identity.Default } else { $key = 'identity-notProvided' } } }
                    'landing_zones' { if ($ALZManagementGroupsIds.containsKey('landing_zones') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['landing_zones'])) { $key = $ALZManagementGroupsIds['landing_zones'] } else { if (Test-ALZManagementGroupIds $variableMap.landing_zones.Default) { $key = $variableMap.landing_zones.Default } else { $key = 'landing_zones-notProvided' } } }
                    Default { }
                }
                $variableMapCalculated[$item.Key] = $key
            }

            $script:ALZArchetypeMgIdReference = $variableMapCalculated

            # Populate the hashtable
            foreach ($item in $variableMap.GetEnumerator()) {
                if ($null -ne $item.Value.Variable -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds[$item.Value.Variable])) {
                    $key = $item.Value.Variable
                }
                elseif (Test-ALZManagementGroupIds $ALZManagementGroupsIds[$item.Value.Default]) {
                    $key = $item.Value.Default
                }
                else {
                    $mg = $item.Value.Default
                    $key = "$mg-notProvided"
                }
                $currentALZPolicyAssignments[$key] = @()
            }

            $htCacheAssignmentsPolicy.GetEnumerator() | ForEach-Object {
                if ($_.value.AssignmentScopeMgSubRg -eq 'Mg') {
                    $assignmentName = ($_.key).split('/')[-1]
                    $managementGroup = ($_.key).split('/')[4]
                    if ($currentALZPolicyAssignments.ContainsKey($managementGroup)) {
                        $currentALZPolicyAssignments[$managementGroup] += $assignmentName
                    }
                    else {
                        $currentALZPolicyAssignments[$managementGroup] = @($assignmentName)
                    }
                }
            }

            # Output the result
            $referenceALZPolicyAssignments = $script:referenceALZPolicyAssignments

            # Function to compare hashtables
            function Compare-ALZPolicyHashTables($array1, $array2) {
                $comparison = Compare-Object -ReferenceObject $array1 -DifferenceObject $array2 -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
                return $comparison
            }

            # Compare the hashtables and find items in reference that are not in the current environment
            $differences = @{}

            foreach ($key in $referenceALZPolicyAssignments.Keys) {
                if ($currentALZPolicyAssignments.ContainsKey($key)) {
                    $diff = Compare-ALZPolicyHashTables $currentALZPolicyAssignments[$key] $referenceALZPolicyAssignments[$key]
                    if ($diff) {
                        $differences[$key] = $diff
                    }
                }
                else {
                    # If the key doesn't exist in current environment, all items in reference are different
                    $differences[$key] = $referenceALZPolicyAssignments[$key]
                    #$differences[$key] = 'N/A'
                }
            }
            $script:ALZPolicyAssignmentsDifferences = $differences
            Remove-Item "$($OutputPath)/ALZPolicyAssignmentsChecker.json" -Force
        }
        catch {
            $script:ALZPolicyAssignmentsChecker = $false
            $script:azAPICallConf['htParameters'].ALZPolicyAssignmentsChecker = $false
        }
    }
}