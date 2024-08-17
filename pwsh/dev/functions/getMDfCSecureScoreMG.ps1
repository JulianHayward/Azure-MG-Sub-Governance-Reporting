function getMDfCSecureScoreMG {
    $start = Get-Date
    $currentTask = 'Getting Microsoft Defender for Cloud Secure Score for Management Groups'
    Write-Host $currentTask
    #ref: https://learn.microsoft.com/azure/governance/management-groups/resource-graph-samples?tabs=azure-cli#secure-score-per-management-group
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
    $method = 'POST'

    $query = @'
        SecurityResources
        | where type == 'microsoft.security/securescores'
        | project subscriptionId,
            subscriptionTotal = iff(properties.score.max == 0, 0.00, round(tolong(properties.weight) * todouble(properties.score.current)/tolong(properties.score.max),2)),
            weight = tolong(iff(properties.weight == 0, 1, properties.weight))
        | join kind=leftouter (
            ResourceContainers
            | where type == 'microsoft.resources/subscriptions' and properties.state == 'Enabled'
            | project subscriptionId, mgChain=properties.managementGroupAncestorsChain )
            on subscriptionId
        | mv-expand mg=mgChain
        | summarize sumSubs = sum(subscriptionTotal), sumWeight = sum(weight), resultsNum = count() by tostring(mg.displayName), mgId = tostring(mg.name)
        | extend secureScore = iff(tolong(resultsNum) == 0, 404.00, round(sumSubs/sumWeight*100,2))
        | project mgDisplayName=mg_displayName, mgId, sumSubs, sumWeight, resultsNum, secureScore
        | order by mgDisplayName asc
'@

    $body = @"
        {
            "query": "$($query)",
            "managementGroups":[
                "$($ManagementGroupId)"
            ]
        }
"@

    $getMgAscSecureScore = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -body $body -listenOn 'Content' -unhandledErrorAction ContinueQuiet
    if ($getMgAscSecureScore) {
        Write-Host " Retrieved 'Microsoft Defender for Cloud' SecureScore for $($getMgAscSecureScore.Count) Management Groups"
        foreach ($entry in $getMgAscSecureScore) {
            $script:htMgASCSecureScore.($entry.mgId) = @{}
            if ($entry.secureScore -eq 404) {
                $script:htMgASCSecureScore.($entry.mgId).SecureScore = 'n/a'
            }
            else {
                $script:htMgASCSecureScore.($entry.mgId).SecureScore = $entry.secureScore
            }
        }
    }
    else {
        Write-Host ' Microsoft Defender for Cloud SecureScore for Management Groups will not be available' -ForegroundColor Yellow
    }

    $end = Get-Date
    Write-Host "Getting Microsoft Defender for Cloud Secure Score for Management Groups duration: $((New-TimeSpan -Start $start -End $end).TotalMinutes) minutes ($((New-TimeSpan -Start $start -End $end).TotalSeconds) seconds)"
}