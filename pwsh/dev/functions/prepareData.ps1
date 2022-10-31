function prepareData {
    Write-Host 'Preparing Data'
    $startPreparingArrays = Get-Date
    $script:optimizedTableForPathQuery = ($newTable | Select-Object -Property level, mg*, subscription*) | Sort-Object -Property level, mgid, subscriptionId -Unique
    $hlperOptimizedTableForPathQuery = $optimizedTableForPathQuery.where( { -not [String]::IsNullOrEmpty($_.SubscriptionId) } )
    $script:optimizedTableForPathQueryMgAndSub = ($hlperOptimizedTableForPathQuery | Select-Object -Property level, mg*, subscription*) | Sort-Object -Property level, mgid, mgname, mgparentId, mgparentName, subscriptionId, subscription -Unique
    $script:optimizedTableForPathQueryMg = ($optimizedTableForPathQuery.where( { [String]::IsNullOrEmpty($_.SubscriptionId) } ) | Select-Object -Property level, mgid, mgName, mgparentid, mgparentName) | Sort-Object -Property level, mgid, mgname, mgparentId, mgparentName -Unique
    $script:optimizedTableForPathQuerySub = ($hlperOptimizedTableForPathQuery | Select-Object -Property subscription*) | Sort-Object -Property subscriptionId -Unique

    foreach ($entry in $optimizedTableForPathQuery) {
        $script:htMgDetails.($entry.mgId) = @{}
        $mgSubs = $optimizedTableForPathQueryMgAndSub.where( { $_.mgId -eq $entry.mgId } )
        $script:htMgDetails.($entry.mgId).subscriptionsCount = $mgSubs.Count
        $script:htMgDetails.($entry.mgId).subscriptions = $mgSubs
        $script:htMgDetails.($entry.mgId).details = $entry
        $mgChildren = ($optimizedTableForPathQueryMg.where( { $_.mgParentId -eq $entry.mgId } )).MgId
        $script:htMgDetails.($entry.mgId).mgChildren = $mgChildren
        $script:htMgDetails.($entry.mgId).mgChildrenCount = $mgChildren.Count
    }

    foreach ($entry in $optimizedTableForPathQueryMgAndSub) {
        $script:htSubDetails.($entry.SubscriptionId) = @{}
        $script:htSubDetails.($entry.SubscriptionId).details = $optimizedTableForPathQueryMgAndSub.where( { $_.SubscriptionId -eq $entry.SubscriptionId } )
    }

    $script:parentMgBaseQuery = ($optimizedTableForPathQueryMg.where( { $_.MgParentId -eq $getMgParentId } ))
    $script:parentMgNamex = $parentMgBaseQuery.mgParentName | Get-Unique
    $script:parentMgIdx = $parentMgBaseQuery.mgParentId | Get-Unique

    $endPreparingArrays = Get-Date
    Write-Host "Preparing Arrays duration: $((New-TimeSpan -Start $startPreparingArrays -End $endPreparingArrays).TotalMinutes) minutes ($((New-TimeSpan -Start $startPreparingArrays -End $endPreparingArrays).TotalSeconds) seconds)"
}