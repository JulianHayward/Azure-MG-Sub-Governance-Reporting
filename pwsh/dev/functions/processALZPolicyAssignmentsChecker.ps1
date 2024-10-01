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
            Write-Host " Setting switch parameter '-ALZPolicyAssignmentsChecker' to true"
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
        Write-Host " Setting switch parameter '-ALZPolicyAssignmentsChecker' to true"
        $script:ALZPolicyAssignmentsChecker = $true
        $script:azAPICallConf['htParameters'].ALZPolicyAssignmentsChecker = $true
        Write-Host " Switching back to working directory '$($workingPath)'"
        Set-Location $workingPath
    }

    if ($ALZCloneSuccess) {
        Write-Host " Switching to directory '$($ALZLibraryPath)/Azure-Landing-Zones-Library'"
        Set-Location "$($ALZLibraryPath)/Azure-Landing-Zones-Library"
        $script:referenceALZPolicyAssignments = @{}
        $archetypesPath = '.\platform\alz\archetype_definitions'
        $archetypesDefinition = Get-ChildItem -Path $archetypesPath -Filter '*.json'

        $ALZManagementGroupsIds = $script:ALZManagementGroupsIds
        foreach ($archetype in $archetypesDefinition) {
            $key = ($archetype.BaseName -split '\.')[0]
            switch ($key) {
                'connectivity' { if ($ALZManagementGroupsIds.containsKey('connectivity')) { $key = $ALZManagementGroupsIds['connectivity'] } else { $key = 'connectivity (Id not provided)' } }
                'corp' { if ($ALZManagementGroupsIds.containsKey('corp')) { $key = $ALZManagementGroupsIds['corp'] } else { $key = 'corp (Id not provided)' } }
                'root' { if ($ALZManagementGroupsIds.containsKey('root')) { $key = $ALZManagementGroupsIds['root'] } else { $key = 'root (Id not provided)' } }
                'platform' { if ($ALZManagementGroupsIds.containsKey('platform')) { $key = $ALZManagementGroupsIds['platform'] } else { $key = 'platform (Id not provided)' } }
                'online' { if ($ALZManagementGroupsIds.containsKey('online')) { $key = $ALZManagementGroupsIds['online'] } else { $key = 'online (Id not provided)' } }
                'sandboxes' { if ($ALZManagementGroupsIds.containsKey('sandboxes')) { $key = $ALZManagementGroupsIds['sandboxes'] } else { $key = 'sandboxes (Id not provided)' } }
                'decommissioned' { if ($ALZManagementGroupsIds.containsKey('decommissioned')) { $key = $ALZManagementGroupsIds['decommissioned'] } else { $key = 'decommissioned (Id not provided)' } }
                'management' { if ($ALZManagementGroupsIds.containsKey('management')) { $key = $ALZManagementGroupsIds['management'] } else { $key = 'management (Id not provided)' } }
                'identity' { if ($ALZManagementGroupsIds.containsKey('identity')) { $key = $ALZManagementGroupsIds['identity'] } else { $key = 'identity (Id not provided)' } }
                'landing_zones' { if ($ALZManagementGroupsIds.containsKey('landing_zones')) { $key = $ALZManagementGroupsIds['landing_zones'] } else { $key = 'landing_zones (Id not provided)' } }
                Default {}
            }
            $content = Get-Content $archetype.FullName | ConvertFrom-Json
            if ($content.policy_assignments) {
                $script:referenceALZPolicyAssignments[$key] = $content.policy_assignments
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
        $variableMap = @{
            'connectivity'   = @{ Variable = $ALZManagementGroupsIds['connectivity']; Default = 'connectivity' }
            'corp'           = @{ Variable = $ALZManagementGroupsIds['corp']; Default = 'corp' }
            'root'           = @{ Variable = $ALZManagementGroupsIds['root']; Default = 'root' }
            'platform'       = @{ Variable = $ALZManagementGroupsIds['platform']; Default = 'platform' }
            'online'         = @{ Variable = $ALZManagementGroupsIds['online']; Default = 'online' }
            'sandboxes'      = @{ Variable = $ALZManagementGroupsIds['sandboxes']; Default = 'sandboxes' }
            'decommissioned' = @{ Variable = $ALZManagementGroupsIds['decommissioned']; Default = 'decommissioned' }
            'management'     = @{ Variable = $ALZManagementGroupsIds['management']; Default = 'management' }
            'identity'       = @{ Variable = $ALZManagementGroupsIds['identity']; Default = 'identity' }
            'landingzones'   = @{ Variable = $ALZManagementGroupsIds['landing_zones']; Default = 'landingzones' }
        }

        # Populate the hashtable
        foreach ($item in $variableMap.GetEnumerator()) {
            $key = if ($null -ne $item.Value.Variable) { $item.Value.Variable } else { $item.Value.Default }
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
                #$differences[$key] = $referenceALZPolicyAssignments[$key]
                $differences[$key] = 'N/A'
            }
        }
        $script:ALZPolicyAssignmentsDifferences = $differences
        Remove-Item "$($OutputPath)/ALZPolicyAssignmentsChecker.json" -Force
    }
}