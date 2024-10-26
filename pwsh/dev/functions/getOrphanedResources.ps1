function getOrphanedResources {
    $start = Get-Date
    Write-Host 'Getting orphaned/unused resources (ARG)'

    #region queries
    $queries = [System.Collections.ArrayList]@()
    $intent = 'cost savings - stopped but not deallocated VM'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.compute/virtualmachines'
            query     = @"
resources
| where type =~ 'microsoft.compute/virtualmachines'
| where properties.extended.instanceView.powerState.code =~ 'PowerState/stopped'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'clean up'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.resources/subscriptions/resourceGroups'
            query     = @"
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions/resourceGroups'
| extend rgAndSub = strcat(resourceGroup, '--', subscriptionId)
| join kind=leftouter (
    resources
    | extend rgAndSub = strcat(resourceGroup, '--', subscriptionId)
    | summarize count() by rgAndSub
) on rgAndSub
| where isnull(count_)
| order by id
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/networkSecurityGroups'
            query     = @"
resources
| where type =~ 'microsoft.network/networkSecurityGroups'
| where isnull(properties.networkInterfaces) and isnull(properties.subnets)
| order by id
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/routeTables'
            query     = @"
resources
| where type =~ 'microsoft.network/routeTables'
| where isnull(properties.subnets)
| order by id
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/networkInterfaces'
            query     = @"
resources
| where type =~ 'microsoft.network/networkInterfaces'
| where isnull(properties.privateEndpoint) and isnull(properties.privateLinkService) and properties.hostedWorkloads == '[]' and properties !has 'virtualmachine'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.compute/disks'
            query     = @"
resources
| where type has 'microsoft.compute/disks'
| where isempty(managedBy) or properties.diskState =~ 'unattached' and not(name endswith '-ASRReplica' or name startswith 'ms-asr-' or name startswith 'asrseeddisk-')
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/publicIpAddresses'
            query     = @"
resources | where type =~ 'microsoft.network/publicIpAddresses'
| where properties.ipConfiguration == '' and properties.natGateway == '' and properties.publicIPPrefix == '' and properties.publicIPAllocationMethod =~ 'Static'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/publicIpAddresses'
            query     = @"
resources | where type =~ 'microsoft.network/publicIpAddresses'
| where properties.ipConfiguration == '' and properties.natGateway == '' and properties.publicIPPrefix == '' and properties.publicIPAllocationMethod =~ 'Dynamic'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.compute/availabilitySets'
            query     = @"
resources
| where type =~ 'microsoft.compute/availabilitySets'
| where properties.virtualMachines == '[]'
| where not(name endswith '-asr')
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/loadBalancers'
            query     = @"
resources
| where type =~ 'microsoft.network/loadBalancers'
| where properties.backendAddressPools == '[]'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/applicationGateways'
            query     = @"
resources
| where type =~ 'microsoft.network/applicationgateways'
| extend backendPoolsCount = array_length(properties.backendAddressPools),SKUName= tostring(properties.sku.name), SKUTier= tostring(properties.sku.tier),SKUCapacity=properties.sku.capacity,backendPools=properties.backendAddressPools , AppGwId = tostring(id)
| project type, AppGwId, resourceGroup, location, subscriptionId, tags, name, SKUName, SKUTier, SKUCapacity
| join (
    resources
    | where type =~ 'microsoft.network/applicationgateways'
    | mvexpand backendPools = properties.backendAddressPools
    | extend backendIPCount = array_length(backendPools.properties.backendIPConfigurations)
    | extend backendAddressesCount = array_length(backendPools.properties.backendAddresses)
    | extend backendPoolName  = backendPools.properties.backendAddressPools.name
    | extend AppGwId = tostring(id)
    | summarize backendIPCount = sum(backendIPCount) ,backendAddressesCount=sum(backendAddressesCount) by AppGwId
) on AppGwId
| project-away AppGwId1
| where  (backendIPCount == 0 or isempty(backendIPCount)) and (backendAddressesCount == 0 or isempty(backendAddressesCount))
| project type, subscriptionId, Resource=AppGwId, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.web/serverfarms'
            query     = @"
resources
| where type =~ 'microsoft.web/serverfarms'
| where properties.numberOfSites == 0 and sku.tier !~ 'Free'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.web/serverfarms'
            query     = @"
resources
| where type =~ 'microsoft.web/serverfarms'
| where properties.numberOfSites == 0 and sku.tier =~ 'Free'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    #new
    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.sql/servers/elasticpools'
            query     = @"
resources
| where type =~ 'microsoft.sql/servers/elasticpools'
| project type, elasticPoolId = tolower(id), Resource = id, resourceGroup, location, subscriptionId, tags, properties, Details = pack_all(), Intent='$intent'
| join kind=leftouter (
    resources
    | where type =~ 'Microsoft.Sql/servers/databases'
    | project id, properties
    | extend elasticPoolId = tolower(properties.elasticPoolId)
) on elasticPoolId
| summarize databaseCount = countif(id != '') by type, Resource, subscriptionId, Intent
| where databaseCount == 0
| project-away databaseCount
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/trafficmanagerprofiles'
            query     = @"
resources
| where type =~ 'microsoft.network/trafficmanagerprofiles'
| where properties.endpoints == '[]'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/virtualnetworks'
            query     = @"
resources
| where type =~ 'microsoft.network/virtualnetworks'
| where properties.subnets == '[]'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/virtualnetworks/subnets'
            query     = @"
resources
| where type =~ 'microsoft.network/virtualnetworks'
| extend subnet = properties.subnets
| mv-expand subnet
| extend ipConfigurations = subnet.properties.ipConfigurations
| extend delegations = subnet.properties.delegations
| where isnull(ipConfigurations) and delegations == '[]'
| order by tostring(subnet.id)
| project type, subscriptionId, Resource=(subnet.id), Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/natgateways'
            query     = @"
resources
| where type =~ 'microsoft.network/natgateways'
| where isnull(properties.subnets)
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/ipgroups'
            query     = @"
resources
| where type =~ 'microsoft.network/ipgroups'
| where properties.firewalls == '[]' and properties.firewallPolicies == '[]'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/privatednszones'
            query     = @"
resources
| where type =~ 'microsoft.network/privatednszones'
| where properties.numberOfVirtualNetworkLinks == 0
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/privateendpoints'
            query     = @"
resources
| where type =~ 'microsoft.network/privateendpoints'
| extend connection = iff(array_length(properties.manualPrivateLinkServiceConnections) > 0, properties.manualPrivateLinkServiceConnections[0], properties.privateLinkServiceConnections[0])
| extend stateEnum = tostring(connection.properties.privateLinkServiceConnectionState.status)
| where stateEnum =~ 'Disconnected'
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/virtualnetworkgateways'
            query     = @"
resources
| where type =~ 'microsoft.network/virtualnetworkgateways'
| extend vpnClientConfiguration = properties.vpnClientConfiguration
| extend Resource = id
| join kind=leftouter (
    resources
    | where type =~ 'microsoft.network/connections'
    | mv-expand Resource = pack_array(properties.virtualNetworkGateway1.id, properties.virtualNetworkGateway2.id) to typeof(string)
    | project Resource, connectionId = id, ConnectionProperties=properties
    ) on Resource
| where isempty(vpnClientConfiguration) and isempty(connectionId)
| project type, subscriptionId, Resource, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.network/ddosprotectionplans'
            query     = @"
resources
| where type =~ 'microsoft.network/ddosprotectionplans'
| where isnull(properties.virtualNetworks)
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'misconfiguration'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.Web/connections'
            query     = @"
resources
| where type =~ 'Microsoft.Web/connections'
| project type, resourceId = id , apiName = name, subscriptionId, resourceGroup, tags, location
| join kind = leftouter (
    resources
    | where type =~ 'microsoft.logic/workflows'
    | extend resourceGroup, location, subscriptionId, properties
    | extend var_json = properties['parameters']['`$connections']['value']
    | mvexpand var_connection = var_json
    | where notnull(var_connection)
    | extend connectionId = extract('connectionId\\\":\\\"(.*?)\\\"', 1, tostring(var_connection))
    | project connectionId, name
    )
    on `$left.resourceId == `$right.connectionId
| where connectionId == ''
| project type, subscriptionId, Resource=resourceId, Intent='$intent'
"@
            intent    = $intent
        })

    $intent = 'cost savings'
    $null = $queries.Add([PSCustomObject]@{
            queryName = 'microsoft.Web/certificates'
            query     = @"
resources
| where type =~ 'microsoft.web/certificates'
| extend expiresOn = todatetime(properties.expirationDate)
| where expiresOn <= now()
| project type, subscriptionId, Resource=id, Intent='$intent'
"@
            intent    = $intent
        })
    #endregion queries

    $batchSize = [math]::ceiling($queries.Count / $azAPICallConf['htParameters'].ThrottleLimit)
    #Write-Host "Optimal batch size: $($batchSize)"
    $counterBatch = [PSCustomObject] @{ Value = 0 }
    $queriesBatch = ($queries) | Group-Object -Property { [math]::Floor($counterBatch.Value++ / $batchSize) }
    Write-Host " Processing queries in $($queriesBatch.Count) batches"

    $queriesBatch | ForEach-Object -Parallel {
        $arrayOrphanedResources = $using:arrayOrphanedResources
        $subsToProcessInCustomDataCollection = $using:subsToProcessInCustomDataCollection
        $azAPICallConf = $using:azAPICallConf
        foreach ($queryDetail in $_.Group) {
            #Batching: https://learn.microsoft.com/azure/governance/resource-graph/troubleshoot/general#toomanysubscription
            $counterBatch = [PSCustomObject] @{ Value = 0 }
            $batchSize = 1000
            $subscriptionsBatch = $subsToProcessInCustomDataCollection | Group-Object -Property { [math]::Floor($counterBatch.Value++ / $batchSize) }

            $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
            $method = 'POST'
            foreach ($batch in $subscriptionsBatch) {
                Write-Host " Getting orphaned $($queryDetail.queryName) for $($batch.Group.subscriptionId.Count) Subscriptions"
                $subscriptions = '"{0}"' -f ($batch.Group.subscriptionId -join '","')
                $body = @"
{
    "query": "$($queryDetail.query)",
    "subscriptions": [$($subscriptions)],
    "options": {
        "`$top": 1000
    }
}
"@

                $res = (AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -body $body -listenOn 'Content' -currentTask "Getting orphaned $($queryDetail.queryName)")

                if ($res.count -gt 0) {
                    foreach ($resource in $res) {
                        $null = $script:arrayOrphanedResources.Add($resource)
                    }
                }
                Write-Host "  $($res.count) orphaned $($queryDetail.queryName) found"
            }
        }
    } -ThrottleLimit ($azAPICallConf['htParameters'].ThrottleLimit)

    if ($arrayOrphanedResources.Count -gt 0) {

        if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
            $allConsumptionDataGroupedByTypeAndCurrency = $allConsumptionData | Group-Object -Property ResourceType, Currency
            $orphanedResourcesResourceTypesCostRelevant = ($queries.where({ $_.intent -like 'cost savings*' })).queryName

            $htC = @{}
            foreach ($consumptionResourceTypeAndCurrency in $allConsumptionDataGroupedByTypeAndCurrency) {
                $consumptionResourceTypeAndCurrencySplitted = $consumptionResourceTypeAndCurrency.Name.split(', ')
                #$consumptionResourceTypeAndCurrencySplitted[0]
                if ($consumptionResourceTypeAndCurrencySplitted[0] -in $orphanedResourcesResourceTypesCostRelevant ) {
                    foreach ($entry in $consumptionResourceTypeAndCurrency.Group) {
                        if (-not $htC.($entry.resourceId)) {
                            $htC.($entry.resourceId) = @{
                                cost     = $entry.PreTaxCost
                                currency = $entry.Currency
                            }

                        }
                        else {
                            $htC.($entry.resourceId).cost = $htC.($entry.resourceId).cost + $entry.PreTaxCost
                        }
                    }
                }
            }

            $costrelevantOrphanedResourcesGroupedByType = ($arrayOrphanedResources | Group-Object -Property intent).where({ $_.name -like 'cost savings*' }).group | Group-Object -Property type
            $nonCostrelevantOrphanedResourcesGroupedByType = ($arrayOrphanedResources | Group-Object -Property intent).where({ $_.name -notlike 'cost savings*' }).group | Group-Object -Property type
            $script:arrayOrphanedResources = [System.Collections.ArrayList]@()

            foreach ($costrelevantOrphanedResourceType in $costrelevantOrphanedResourcesGroupedByType) {
                foreach ($resource in $costrelevantOrphanedResourceType.Group) {
                    if ($htC.($resource.Resource)) {
                        $null = $script:arrayOrphanedResources.Add([PSCustomObject]@{
                                Type           = $costrelevantOrphanedResourceType.Name
                                Resource       = $resource.Resource
                                SubscriptionId = $resource.subscriptionId
                                Intent         = $resource.Intent
                                Cost           = $htC.($resource.Resource).cost
                                Currency       = $htC.($resource.Resource).currency
                            })
                    }
                    else {
                        $null = $script:arrayOrphanedResources.Add([PSCustomObject]@{
                                Type           = $costrelevantOrphanedResourceType.Name
                                Resource       = $resource.Resource
                                SubscriptionId = $resource.subscriptionId
                                Intent         = $resource.Intent
                                Cost           = ''
                                Currency       = ''
                            })
                    }
                }
            }

            foreach ($nonCostrelevantOrphanedResourceType in $nonCostrelevantOrphanedResourcesGroupedByType) {
                Write-Host "Processing $($nonCostrelevantOrphanedResourceType.Name)"
                foreach ($resource in $nonCostrelevantOrphanedResourceType.Group) {
                    $null = $script:arrayOrphanedResources.Add([PSCustomObject]@{
                            Type           = $nonCostrelevantOrphanedResourceType.Name
                            Resource       = $resource.Resource
                            SubscriptionId = $resource.subscriptionId
                            Intent         = $resource.Intent
                            Cost           = ''
                            Currency       = ''
                        })
                }
            }
        }

        Write-Host " Found $($arrayOrphanedResources.Count) orphaned/unused Resources"
        if (-not $NoCsvExport) {
            Write-Host " Exporting OrphanedResources CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_ResourcesCostOptimizationAndCleanup.csv'"
            $arrayOrphanedResources | Sort-Object -Property Resource | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_ResourcesCostOptimizationAndCleanup.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
        }
    }
    else {
        Write-Host ' No orphaned/unused Resources found'
    }

    $end = Get-Date
    Write-Host "Getting orphaned/unused resources (ARG) processing duration: $((New-TimeSpan -Start $start -End $end).TotalMinutes) minutes ($((New-TimeSpan -Start $start -End $end).TotalSeconds) seconds)"
}