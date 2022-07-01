function getOrphanedResources {
    $start = Get-Date
    Write-Host 'Getting orphaned resources (ARG)'

    $queries = [System.Collections.ArrayList]@()
    $intent = 'clean up'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.resources/subscriptions/resourceGroups'
            query     = "ResourceContainers | where type =~ 'microsoft.resources/subscriptions/resourceGroups' | extend rgAndSub = strcat(resourceGroup, '--', subscriptionId) | join kind=leftouter (Resources | extend rgAndSub = strcat(resourceGroup, '--', subscriptionId) | summarize count() by rgAndSub) on rgAndSub | where isnull(count_) | project type, subscriptionId, Resource=id, Intent='$intent'"
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/networkSecurityGroups'
            query     = "Resources | where type =~ 'microsoft.network/networkSecurityGroups' and isnull(properties.networkInterfaces) and isnull(properties.subnets) | project type, subscriptionId, Resource=id, Intent='$intent'"
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/routeTables'
            query     = "resources | where type =~ 'microsoft.network/routeTables' | where isnull(properties.subnets) | project type, subscriptionId, Resource=id, Intent='$intent'"
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/networkInterfaces'
            query     = "Resources | where type =~ 'microsoft.network/networkInterfaces' | where isnull(properties.privateEndpoint) | where isnull(properties.privateLinkService) | where properties.hostedWorkloads == '[]' | where properties !has 'virtualmachine' | project type, subscriptionId, Resource=id, Intent='$intent'"
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.compute/disks'
            query     = "Resources | where type =~ 'microsoft.compute/disks' | extend diskState = tostring(properties.diskState) | where managedBy == '' | where not(name endswith '-ASRReplica' or name startswith 'ms-asr-') | project type, subscriptionId, Resource=id, Intent='$intent'"
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/publicIpAddresses'
            query     = "Resources | where type =~ 'microsoft.network/publicIpAddresses' | where properties.ipConfiguration == '' | project type, subscriptionId, Resource=id, Intent='$intent'"
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.compute/availabilitySets'
            query     = "Resources | where type =~ 'microsoft.compute/availabilitySets' | where properties.virtualMachines == '[]' | project type, subscriptionId, Resource=id, Intent='$intent'"
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/loadBalancers'
            query     = "Resources | where type =~ 'microsoft.network/loadBalancers' | where properties.backendAddressPools == '[]' | project type, subscriptionId, Resource=id, Intent='$intent'"
        })

    $intent = 'clean up'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.web/serverfarms'
            query     = "Resources | where type =~ 'microsoft.web/serverfarms' | where properties.numberOfSites == 0 | project type, subscriptionId, Resource=id, Intent='$intent'"
        })

    $queries | foreach-object -Parallel {
        $queryDetail = $_
        $arrayOrphanedResources = $using:arrayOrphanedResources
        $subsToProcessInCustomDataCollection = $using:subsToProcessInCustomDataCollection
        $azAPICallConf = $using:azAPICallConf

        #Batching: https://docs.microsoft.com/en-us/azure/governance/resource-graph/troubleshoot/general#toomanysubscription
        $counterBatch = [PSCustomObject] @{ Value = 0 }
        $batchSize = 1000    
        $subscriptionsBatch = $subsToProcessInCustomDataCollection | Group-Object -Property { [math]::Floor($counterBatch.Value++ / $batchSize) }

        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
        $method = "POST"
        foreach ($batch in $subscriptionsBatch) { 
            " Getting orphaned $($queryDetail.queryName) for $($batch.Group.subscriptionId.Count) Subscriptions"
            $subscriptions = '"{0}"' -f ($batch.Group.subscriptionId -join '","')
            $body = @"
{
"query": "$($queryDetail.query)",
"subscriptions": [$($subscriptions)]
}
"@

            $res = (AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -body $body -listenOn 'Content' -currentTask "Getting orphaned $($queryDetail.queryName)")
            #Write-Host '$res.count:' $res.count
            if ($res.count -gt 0) {
                foreach ($resource in $res) {
                    $null = $script:arrayOrphanedResources.Add($resource)
                }
            }
        }
    } -ThrottleLimit ($queries.Count)

    if ($arrayOrphanedResources.Count -gt 0) {
        Write-Host " Found $($arrayOrphanedResources.Count) orphaned Resources"
        Write-Host " Exporting OrphanedResources CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_ResourcesOrphaned.csv'"
        $arrayOrphanedResources | Sort-Object -Property Resource | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_ResourcesOrphaned.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
    }
    else {
        Write-Host " No orphaned Resources found"
    }

    $end = Get-Date
    Write-Host "Getting orphaned resources (ARG) processing duration: $((NEW-TIMESPAN -Start $start -End $end).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $start -End $end).TotalSeconds) seconds)"
}