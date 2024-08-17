function processHierarchyMapOnly {
    foreach ($entity in $htEntities.values) {
        if ($entity.parentNameChain -contains $ManagementGroupID -or $entity.Id -eq $ManagementGroupId) {

            if ($entity.type -eq '/subscriptions') {
                $hlpEntityParent = $htEntities.(($entity.parent))
                addRowToTable `
                    -level (($entity.ParentNameChain).Count - 1) `
                    -mgName $hlpEntityParent.displayName `
                    -mgId ($entity.parent) `
                    -mgParentId $hlpEntityParent.Parent `
                    -mgParentName $hlpEntityParent.ParentDisplayName `
                    -Subscription $entity.DisplayName `
                    -SubscriptionId $entity.Id
            }
            if ($entity.type -eq 'Microsoft.Management/managementGroups') {
                addRowToTable `
                    -level ($entity.ParentNameChain).Count `
                    -mgName $entity.displayname `
                    -mgId $entity.id `
                    -mgParentId $entity.Parent `
                    -mgParentName $entity.ParentDisplayName
            }
        }
    }
}