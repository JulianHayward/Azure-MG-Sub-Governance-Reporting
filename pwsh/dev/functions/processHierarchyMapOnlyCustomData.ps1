function processHierarchyMapOnlyCustomData {
    Write-Host 'HierarchyMapOnly with custom data' -ForegroundColor Yellow
    Write-Host ' Parameter HierarchyMapOnly:' $HierarchyMapOnly
    Write-Host ' Check if HierarchyMapOnlyCustomDataJSON is valid JSON'
    try {
        $HierarchyMapOnlyCustomDataConvertedAsHashTable = $HierarchyMapOnlyCustomDataJSON | ConvertFrom-Json -AsHashtable
        $hierarchyMapOnlyCustomData = @{}
        foreach ($key in $HierarchyMapOnlyCustomDataConvertedAsHashTable.Keys) {
            $hierarchyMapOnlyCustomData.$key = $HierarchyMapOnlyCustomDataConvertedAsHashTable.$key | ConvertTo-Json | ConvertFrom-Json
        }
        Write-Host '  HierarchyMapOnlyCustomDataJSON is valid JSON' -ForegroundColor Green
    }
    catch {
        throw 'HierarchyMapOnlyCustomDataJSON is not valid JSON'
    }

    Write-Host ' Parameter hierarchyMapOnlyCustomData count:' $hierarchyMapOnlyCustomData.Keys.Count

    #validate
    Write-Host ' ManagementGroupId validation'
    if (-not $ManagementGroupId) {
        throw 'ManagementGroupId validation failed - please provide ManagementGroupId (parameter -ManagementGroupId)'
    }
    else {
        if ($hierarchyMapOnlyCustomData.$ManagementGroupId) {
            Write-Host "  ManagementGroupId '$ManagementGroupId' is available in 'hierarchyMapOnlyCustomData'"
        }
        else {
            throw "ManagementGroupId validation failed - Given ManagementGroupId '$ManagementGroupId' is NOT available in 'hierarchyMapOnlyCustomData'"
        }
        Write-Host "  ManagementGroupId validation passed '$ManagementGroupId'" -ForegroundColor Green
    }

    Write-Host ' CustomData validation'
    if ($hierarchyMapOnlyCustomData.Keys.Count -gt 0) {
        Write-Host '  Checking Keys (sanity check on first item)'
        $requiredKeys = @('Id', 'ParentId', 'ParentNameChain', 'ParentDisplayName', 'DisplayName', 'type')
        $firstItem = $hierarchyMapOnlyCustomData.($($hierarchyMapOnlyCustomData.Keys)[0])
        foreach ($requiredKey in $requiredKeys) {
            if (($firstitem | Get-Member -Name $requiredKey)) {
                Write-Host "   Key:$($requiredKey) exists" -ForegroundColor Green
            }
            else {
                Write-Host "  CustomData validation failed - required key:$($requiredKey) missing" -ForegroundColor DarkRed
                Write-Host "  The following keys are expected: $($requiredKeys -join ', ')"
                throw "CustomData validation failed - required key:$($requiredKey) missing"
            }
        }

        Write-Host '  Checking for existence of Management Groups'
        $HierarchyMapOnlyCustomDataHroupedByType = $hierarchyMapOnlyCustomData.values | Group-Object -Property type
        if ($HierarchyMapOnlyCustomDataHroupedByType.Name -notcontains 'Microsoft.Management/managementGroups') {
            Write-Host '   CustomData validation failed - Custom data does not contain Manangement Groups'
            throw 'CustomData validation failed - Custom data does not contain Manangement Groups'
        }
        else {
            Write-Host '   Checking for existence of Management Groups passed' -ForegroundColor Green
        }
        foreach ($type in $HierarchyMapOnlyCustomDataHroupedByType) {
            Write-Host "    Custom Data contains $($type.Count) x type: '$($type.name)'"
        }

        Write-Host ' CustomData validation passed' -ForegroundColor Green
    }
    else {
        Write-Host " CustomData validation failed - no data (`$hierarchyMapOnlyCustomData.Keys.Count: $($hierarchyMapOnlyCustomData.Keys.Count))"
        throw "CustomData validation failed - no data (`$hierarchyMapOnlyCustomData.Keys.Count: $($hierarchyMapOnlyCustomData.Keys.Count))"
    }
    $script:htEntities = $hierarchyMapOnlyCustomData
}