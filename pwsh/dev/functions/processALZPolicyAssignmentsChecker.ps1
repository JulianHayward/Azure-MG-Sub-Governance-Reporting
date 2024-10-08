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
        $script:referenceALZPolicyAssignments = @{}
        $script:ALZpolicyDefinitionsTable = @{}
        $script:ALZPolicyAssignmentsPayloadFiles = @{}
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

        $ALZManagementGroupsIds = $script:ALZManagementGroupsIds
        foreach ($archetype in $archetypesDefinition) {
            $key = ($archetype.BaseName -split '\.')[0]
            switch ($key) {
                'connectivity' { if ($ALZManagementGroupsIds.containsKey('connectivity') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['connectivity'])) { $key = $ALZManagementGroupsIds['connectivity'] } else { $key = 'connectivity-notProvided' } }
                'corp' { if ($ALZManagementGroupsIds.containsKey('corp') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['corp'])) { $key = $ALZManagementGroupsIds['corp'] } else { $key = 'corp-notProvided' } }
                'root' { if ($ALZManagementGroupsIds.containsKey('root') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['root'])) { $key = $ALZManagementGroupsIds['root'] } else { $key = 'root-notProvided' } }
                'platform' { if ($ALZManagementGroupsIds.containsKey('platform') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['platform'])) { $key = $ALZManagementGroupsIds['platform'] } else { $key = 'platform-notProvided' } }
                'online' { if ($ALZManagementGroupsIds.containsKey('online') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['online'])) { $key = $ALZManagementGroupsIds['online'] } else { $key = 'online-notProvided' } }
                'sandboxes' { if ($ALZManagementGroupsIds.containsKey('sandboxes') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['sandboxes'])) { $key = $ALZManagementGroupsIds['sandboxes'] } else { $key = 'sandboxes-notProvided' } }
                'decommissioned' { if ($ALZManagementGroupsIds.containsKey('decommissioned') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['decommissioned'])) { $key = $ALZManagementGroupsIds['decommissioned'] } else { $key = 'decommissioned-notProvided' } }
                'management' { if ($ALZManagementGroupsIds.containsKey('management') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['management'])) { $key = $ALZManagementGroupsIds['management'] } else { $key = 'management-notProvided' } }
                'identity' { if ($ALZManagementGroupsIds.containsKey('identity') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['identity'])) { $key = $ALZManagementGroupsIds['identity'] } else { $key = 'identity-notProvided' } }
                'landing_zones' { if ($ALZManagementGroupsIds.containsKey('landing_zones') -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds['landing_zones'])) { $key = $ALZManagementGroupsIds['landing_zones'] } else { $key = 'landing_zones-notProvided' } }
                Default {}
            }
            $content = Get-Content $archetype.FullName | ConvertFrom-Json
            if ($content.policy_assignments) {
                $script:referenceALZPolicyAssignments[$key] = $content.policy_assignments
                $content.policy_assignments | ForEach-Object {
                    $assignmentName = $_ -replace '-', '_'
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

        # Define the variables and their default values
        $ALZArchetypeMgIdReference = @{
            'connectivity'   = @{ Variable = $ALZManagementGroupsIds['connectivity']; Default = 'connectivity' }
            'corp'           = @{ Variable = $ALZManagementGroupsIds['corp']; Default = 'corp' }
            'root'           = @{ Variable = $ALZManagementGroupsIds['root']; Default = 'root' }
            'platform'       = @{ Variable = $ALZManagementGroupsIds['platform']; Default = 'platform' }
            'online'         = @{ Variable = $ALZManagementGroupsIds['online']; Default = 'online' }
            'sandboxes'      = @{ Variable = $ALZManagementGroupsIds['sandboxes']; Default = 'sandboxes' }
            'decommissioned' = @{ Variable = $ALZManagementGroupsIds['decommissioned']; Default = 'decommissioned' }
            'management'     = @{ Variable = $ALZManagementGroupsIds['management']; Default = 'management' }
            'identity'       = @{ Variable = $ALZManagementGroupsIds['identity']; Default = 'identity' }
            'landingzones'   = @{ Variable = $ALZManagementGroupsIds['landing_zones']; Default = 'landing_zones' }
        }

        # Populate the hashtable
        foreach ($item in $ALZArchetypeMgIdReference.GetEnumerator()) {
            $key = if ($null -ne $item.Value.Variable -and (Test-ALZManagementGroupIds $ALZManagementGroupsIds[$item.Value.Default])) { $item.Value.Variable } else { $item.Value.Default }
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
}