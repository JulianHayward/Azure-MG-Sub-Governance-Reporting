function getEntities {
    Write-Host 'Entities'
    $startEntities = Get-Date
    $currentTask = ' Getting Entities'
    Write-Host $currentTask
    #https://management.azure.com/providers/Microsoft.Management/getEntities?api-version=2020-02-01
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/getEntities?api-version=2020-02-01"
    $method = 'POST'
    $arrayEntitiesFromAPIInitial = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask
    Write-Host "  $($arrayEntitiesFromAPIInitial.Count) Entities returned"

    $script:arrayEntitiesFromAPI = [System.Collections.ArrayList]@()
    $script:htsubscriptionsFromEntitiesThatAreNotInGetSubscriptions = @{}
    foreach ($entry in $arrayEntitiesFromAPIInitial) {
        if ($entry.Type -eq '/subscriptions') {
            if ($htSubscriptionsFromOtherTenants.($entry.name)) {
                $subdetail = $htSubscriptionsFromOtherTenants.($entry.name).subdetails
                Write-Host "   Excluded Subscription '$($subDetail.displayName)' ($($entry.name)) (foreign tenantId: '$($subDetail.tenantId)')" -ForegroundColor DarkRed
                continue
            }
            if (-not $htAllSubscriptionsFromAPI.($entry.name)) {
                #not contained in subscriptions
                $script:htsubscriptionsFromEntitiesThatAreNotInGetSubscriptions.($entry.name) = $entry
                Write-Host "   Excluded Subscription '$($entry.properties.displayName)' ($($entry.name)) (contained in GetEntities, not contained in GetSubscriptions)" -ForegroundColor DarkRed
                continue
            }
            #test
            # if ($entry.name -eq '<subId>') {
            #     $script:htsubscriptionsFromEntitiesThatAreNotInGetSubscriptions.($entry.name) = $entry
            #     Write-Host "   Excluded Subscription '$($entry.properties.displayName)' ($($entry.name)) (contained in GetEntities, not contained in GetSubscriptions)" -ForegroundColor DarkRed
            #     continue
            # }
        }

        $null = $script:arrayEntitiesFromAPI.Add($entry)
    }

    Write-Host "  $($arrayEntitiesFromAPI.Count)/$($arrayEntitiesFromAPIInitial.Count) Entities relevant"

    $endEntities = Get-Date
    Write-Host " Getting Entities duration: $((New-TimeSpan -Start $startEntities -End $endEntities).TotalSeconds) seconds"

    $startEntitiesdata = Get-Date
    Write-Host ' Processing Entities data'
    $script:htSubscriptionsMgPath = @{}
    $script:htManagementGroupsMgPath = @{}
    $script:htEntities = @{}
    $script:htEntitiesPlain = @{}

    foreach ($entity in $arrayEntitiesFromAPI) {
        $script:htEntitiesPlain.($entity.Name) = @{}
        $script:htEntitiesPlain.($entity.Name) = $entity
    }

    foreach ($entity in $arrayEntitiesFromAPI) {
        if ($entity.Type -eq '/subscriptions') {
            $parent = $entity.properties.parent.Id -replace '.*/'
            $parentId = $entity.properties.parent.Id
            $script:htSubscriptionsMgPath.($entity.name) = @{}
            $script:htSubscriptionsMgPath.($entity.name).ParentNameChain = $entity.properties.parentNameChain
            $script:htSubscriptionsMgPath.($entity.name).ParentNameChainDelimited = $entity.properties.parentNameChain -join '/'
            $script:htSubscriptionsMgPath.($entity.name).Parent = $entity.properties.parent.Id -replace '.*/'
            $script:htSubscriptionsMgPath.($entity.name).ParentName = $htEntitiesPlain.($entity.properties.parent.Id -replace '.*/').properties.displayName
            $script:htSubscriptionsMgPath.($entity.name).DisplayName = $entity.properties.displayName
            $array = $entity.properties.parentNameChain
            $array += $entity.name
            $script:htSubscriptionsMgPath.($entity.name).path = $array
            $script:htSubscriptionsMgPath.($entity.name).pathDelimited = $array -join '/'
            $script:htSubscriptionsMgPath.($entity.name).level = (($entity.properties.parentNameChain).Count - 1)
        }
        if ($entity.Type -eq 'Microsoft.Management/managementGroups') {
            if ([string]::IsNullOrEmpty($entity.properties.parent.Id)) {
                $parent = '__TenantRoot__'
                $parentId = '__TenantRoot__'
            }
            else {
                $parent = $entity.properties.parent.Id -replace '.*/'
                $parentId = $entity.properties.parent.Id
            }
            $script:htManagementGroupsMgPath.($entity.name) = @{}
            $script:htManagementGroupsMgPath.($entity.name).ParentNameChain = $entity.properties.parentNameChain
            $script:htManagementGroupsMgPath.($entity.name).ParentNameChainDelimited = $entity.properties.parentNameChain -join '/'
            $script:htManagementGroupsMgPath.($entity.name).ParentNameChainCount = ($entity.properties.parentNameChain | Measure-Object).Count
            $script:htManagementGroupsMgPath.($entity.name).Parent = $parent
            $script:htManagementGroupsMgPath.($entity.name).ChildMgsAll = ($arrayEntitiesFromAPI.where( { $_.Type -eq 'Microsoft.Management/managementGroups' -and $_.properties.ParentNameChain -contains $entity.name } )).Name
            $script:htManagementGroupsMgPath.($entity.name).ChildMgsDirect = ($arrayEntitiesFromAPI.where( { $_.Type -eq 'Microsoft.Management/managementGroups' -and $_.properties.Parent.Id -replace '.*/' -eq $entity.name } )).Name
            $script:htManagementGroupsMgPath.($entity.name).DisplayName = $entity.properties.displayName
            $script:htManagementGroupsMgPath.($entity.name).Id = ($entity.name)
            $array = $entity.properties.parentNameChain
            $array += $entity.name
            $script:htManagementGroupsMgPath.($entity.name).path = $array
            $script:htManagementGroupsMgPath.($entity.name).pathDelimited = $array -join '/'
            $script:htManagementGroupsMgPath.($entity.name).level = $array.Count
        }

        $script:htEntities.($entity.name) = @{}
        $script:htEntities.($entity.name).ParentNameChain = $entity.properties.parentNameChain
        $script:htEntities.($entity.name).Parent = $parent
        $script:htEntities.($entity.name).ParentId = $parentId
        if ($parent -eq '__TenantRoot__') {
            $parentDisplayName = '__TenantRoot__'
        }
        else {
            $parentDisplayName = $htEntitiesPlain.($htEntities.($entity.name).Parent).properties.displayName
        }
        $script:htEntities.($entity.name).ParentDisplayName = $parentDisplayName
        $script:htEntities.($entity.name).DisplayName = $entity.properties.displayName
        $script:htEntities.($entity.name).Id = $entity.Name
        $script:htEntities.($entity.name).Type = $entity.Type
    }

    Write-Host "  $(($htManagementGroupsMgPath.Keys).Count) relevant Management Groups"
    Write-Host "  $(($htSubscriptionsMgPath.Keys).Count) relevant Subscriptions"

    $endEntitiesdata = Get-Date
    Write-Host " Processing Entities data duration: $((New-TimeSpan -Start $startEntitiesdata -End $endEntitiesdata).TotalSeconds) seconds"

    $script:arrayEntitiesFromAPISubscriptionsCount = ($arrayEntitiesFromAPI.where( { $_.type -eq '/subscriptions' -and $_.properties.parentNameChain -contains $ManagementGroupId } ) | Sort-Object -Property id -Unique).count
    $script:arrayEntitiesFromAPIManagementGroupsCount = ($arrayEntitiesFromAPI.where( { $_.type -eq 'Microsoft.Management/managementGroups' -and $_.properties.parentNameChain -contains $ManagementGroupId } ) | Sort-Object -Property id -Unique).count + 1

    $endEntities = Get-Date
    Write-Host "Processing Entities duration: $((New-TimeSpan -Start $startEntities -End $endEntities).TotalSeconds) seconds"
}