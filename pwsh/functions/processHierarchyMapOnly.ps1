function processHierarchyMapOnly {
    foreach ($entity in $arrayEntitiesFromAPI) {
        if ($entity.properties.parentNameChain -contains $ManagementGroupID -or $entity.Name -eq $ManagementGroupId) {
            if ($entity.type -eq '/subscriptions') {
                addRowToTable `
                    -level (($htEntities.($entity.name).ParentNameChain).Count - 1) `
                    -mgName $htEntities.(($entity.properties.parent.Id) -replace '.*/').displayName `
                    -mgId (($entity.properties.parent.Id) -replace '.*/') `
                    -mgParentId $htEntities.(($entity.properties.parent.Id) -replace '.*/').Parent `
                    -mgParentName $htEntities.(($entity.properties.parent.Id) -replace '.*/').ParentDisplayName `
                    -Subscription $htEntities.($entity.name).DisplayName `
                    -SubscriptionId $htEntities.($entity.name).Id
            }
            if ($entity.type -eq 'Microsoft.Management/managementGroups') {
                addRowToTable `
                    -level ($htEntities.($entity.name).ParentNameChain).Count `
                    -mgName $entity.properties.displayname `
                    -mgId $entity.Name `
                    -mgParentId $htEntities.($entity.name).Parent `
                    -mgParentName $htEntities.($entity.name).ParentDisplayName
            }
        }
    }
}