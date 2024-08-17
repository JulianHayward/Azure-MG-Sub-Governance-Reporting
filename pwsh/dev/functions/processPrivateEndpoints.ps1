function processPrivateEndpoints {
    $start = Get-Date
    Write-Host 'Processing Private Endpoints enrichment'

    $script:arrayPrivateEndpointsEnriched = [System.Collections.ArrayList]@()

    if ($arrayPrivateEndPointsFromResourceProperties.Count -gt 0) {
        $privateEndPointsFromResourcePropertiesToProcess = ($arrayPrivateEndPointsFromResourceProperties.where({ $arrayPrivateEndPoints.id -notcontains $_.privateEndpointConnection.Properties.privateEndpoint.id }))
        $privateEndPointsFromResourcePropertiesToProcessCount = $privateEndPointsFromResourcePropertiesToProcess.Count
        Write-Host " Processing Private Endpoints enrichment for $privateEndPointsFromResourcePropertiesToProcessCount Private Endpoint(s) where the Private Endpoint was not returned from the PE API endpoint but from a resource property"
        if ($privateEndPointsFromResourcePropertiesToProcessCount -gt 0) {
            foreach ($entry in $privateEndPointsFromResourcePropertiesToProcess) {
                $peResIdSplit = $entry.privateEndpointConnection.Properties.privateEndpoint.id -split '/'
                $crossSubscriptionPE = 'n/a'
                $peSubscriptionId = $peResIdSplit[2]
                if ($peSubscriptionId -ne $entry.ResourceSubscriptionId) {
                    $crossSubscriptionPE = $true
                }
                else {
                    $crossSubscriptionPE = $false
                }

                $peMGPath = 'n/a'
                $peXTenant = 'unknown'
                if ($htSubscriptionsMgPath.($peSubscriptionId)) {
                    $peMGPath = $htSubscriptionsMgPath.($peSubscriptionId).pathDelimited
                    $peXTenant = $false
                }
                elseif ($htUnknownTenantsForSubscription.($peSubscriptionId)) {
                    $remoteTenantId = $htUnknownTenantsForSubscription.($peSubscriptionId).TenantId
                    $peMGPath = $remoteTenantId
                    if ($remoteTenantId -eq $azApiCallConf['checkcontext'].tenant.id) {
                        $peXTenant = $false
                    }
                    else {
                        $peXTenant = $true
                    }
                }
                else {
                    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($peSubscriptionId)?api-version=2020-01-01"
                    $remoteTenantId = AzAPICall -AzAPICallConfiguration $azApiCallConf -uri $uri -listenOn 'content' -currentTask "getTenantId for subscriptionId '$($peSubscriptionId)'"
                    $arrayRemoteMGPath = [System.Collections.ArrayList]@()
                    foreach ($remoteId in $remoteTenantId) {
                        $objectGuid = [System.Guid]::empty
                        if ([System.Guid]::TryParse($remoteId, [System.Management.Automation.PSReference]$ObjectGuid)) {
                            if ($remoteId -in $MSTenantIds) {
                                $null = $arrayRemoteMGPath.Add("$remoteId (MS)")
                            }
                            else {
                                $null = $arrayRemoteMGPath.Add($remoteId)
                            }
                            if ($remoteId -eq $azApiCallConf['checkcontext'].tenant.id) {
                                $peXTenant = $false
                            }
                            else {
                                $peXTenant = $true
                            }
                        }
                        $script:htUnknownTenantsForSubscription.($peSubscriptionId) = @{
                            TenantId = $arrayRemoteMGPath -join ', '
                        }
                        $peMGPath = $arrayRemoteMGPath -join ', '
                    }
                }

                $null = $script:arrayPrivateEndpointsEnriched.Add([PSCustomObject]@{
                        PEName                   = $entry.privateEndpointConnection.name
                        PEId                     = $entry.privateEndpointConnection.Properties.privateEndpoint.id
                        PELocation               = 'n/a'
                        PEResourceGroup          = $peResIdSplit[4]
                        PESubscriptionName       = 'n/a'
                        PESubscription           = $peSubscriptionId
                        PEMGPath                 = $peMGPath
                        PEConnectionType         = 'n/a'
                        PEConnectionState        = $entry.privateEndpointConnection.Properties.privateLinkServiceConnectionState.status
                        CrossSubscriptionPE      = $crossSubscriptionPE
                        CrossTenantPE            = $peXTenant

                        Resource                 = $entry.ResourceName
                        ResourceType             = $entry.ResourceType
                        ResourceId               = $entry.ResourceId
                        TargetSubresource        = 'n/a'
                        NICName                  = 'n/a'
                        FQDN                     = 'n/a'
                        ipAddresses              = 'n/a'
                        ResourceResourceGroup    = $entry.ResourceResourceGroup
                        ResourceSubscriptionName = $entry.ResourceSubscriptionName
                        ResourceSubscriptionId   = $entry.ResourceSubscriptionId
                        ResourceMGPath           = $entry.ResourceMGPath
                        ResourceCrossTenant      = 'false'

                        Subnet                   = 'n/a'
                        SubnetId                 = 'n/a'
                        SubnetVNet               = 'n/a'
                        SubnetVNetId             = 'n/a'
                        SubnetVNetLocation       = 'n/a'
                        SubnetVNetResourceGroup  = 'n/a'
                        SubnetSubscriptionName   = 'n/a'
                        SubnetSubscription       = 'n/a'
                        SubnetMGPath             = 'n/a'
                    })
            }
        }
    }

    Write-Host " Processing Private Endpoints enrichment for $($arrayPrivateEndPoints.Count) Private Endpoint(s) where the Private Endpoint was returned from the PE API endpoint"
    $htVPrivateEndPoints = @{}
    foreach ($pe in $arrayPrivateEndPoints) {
        $htVPrivateEndPoints.($pe.id) = $pe
    }

    $htVPrivateEndPoints = @{}
    foreach ($pe in $arrayPrivateEndPoints) {
        $htVPrivateEndPoints.($pe.id) = $pe
    }

    foreach ($pe in $arrayPrivateEndPoints) {

        $peIdSplit = ($pe.id -split '/')
        $subscriptionId = $peIdSplit[2]
        $resourceGroup = $peIdSplit[4]

        $subscriptionName = 'n/a'
        $MGPath = 'n/a'
        if ($htSubscriptionsMgPath.($subscriptionId)) {
            $subHelper = $htSubscriptionsMgPath.($subscriptionId)
            $subscriptionName = $subHelper.displayName
            $MGPath = $subHelper.ParentNameChainDelimited
        }

        $SubnetSubscriptionName = 'n/a'
        $SubnetSubscription = 'n/a'
        $SubnetMGPath = 'n/a'
        $SubnetVNet = 'n/a'
        $SubnetVNetId = 'n/a'
        $SubnetVNetLocation = 'n/a'
        $SubnetVNetResourceGroup = 'n/a'
        if ($htSubnets.($pe.properties.subnet.id)) {
            $hlper = $htSubnets.($pe.properties.subnet.id)
            $SubnetSubscriptionName = $hlper.SubscriptionName
            $SubnetSubscription = $hlper.Subscription
            $SubnetMGPath = $hlper.MGPath
            $SubnetVNet = $hlper.VNet
            $SubnetVNetId = $hlper.VNetId
            $SubnetVNetLocation = $hlper.Location
            $SubnetVNetResourceGroup = $hlper.ResourceGroup
        }

        $resourceSplit = $false
        if ($pe.properties.privateLinkServiceConnections.Count -gt 0) {
            $resourceId = $pe.properties.privateLinkServiceConnections.properties.privateLinkServiceId
            $targetSubresource = $pe.properties.privateLinkServiceConnections.properties.groupIds -join ', '
            $resourceSplit = $pe.properties.privateLinkServiceConnections.properties.privateLinkServiceId -split '/'
            $peConnectionType = 'direct'
            $peConnectionState = $pe.properties.privateLinkServiceConnections.properties.privateLinkServiceConnectionState.status
        }
        if ($pe.properties.manualPrivateLinkServiceConnections.Count -gt 0) {
            $resourceId = $pe.properties.manualPrivateLinkServiceConnections.properties.privateLinkServiceId
            $targetSubresource = $pe.properties.manualPrivateLinkServiceConnections.properties.groupIds -join ', '
            $resourceSplit = $pe.properties.manualPrivateLinkServiceConnections.properties.privateLinkServiceId -split '/'
            $peConnectionType = 'manual'
            $peConnectionState = $pe.properties.manualPrivateLinkServiceConnections.properties.privateLinkServiceConnectionState.status
        }

        $resourceSubscriptionId = 'n/a'
        $resource = 'n/a'
        $resourceType = 'n/a'
        $resourceResourceGroup = 'n/a'
        $resourceSubscriptionName = 'n/a'
        $resourceMGPath = 'n/a'
        $crossSubscriptionPE = 'n/a'
        $resourceXTenant = 'unknown'

        if ($resourceSplit) {
            $ObjectGuid = [System.Guid]::empty
            if ([System.Guid]::TryParse($resourceSplit[2], [System.Management.Automation.PSReference]$ObjectGuid)) {
                $resourceSubscriptionId = $resourceSplit[2]
                $resource = $resourceSplit[8]
                $resourceType = "$($resourceSplit[6])/$($resourceSplit[7])"
                $resourceResourceGroup = $resourceSplit[4]

                if ($htSubscriptionsMgPath.($resourceSubscriptionId)) {
                    $subHelper = $htSubscriptionsMgPath.($resourceSubscriptionId)
                    $resourceSubscriptionName = $subHelper.displayName
                    $resourceMGPath = $subHelper.ParentNameChainDelimited
                    $resourceXTenant = $false
                }
                else {
                    if ($htUnknownTenantsForSubscription.($resourceSubscriptionId)) {
                        $remoteTenantId = $htUnknownTenantsForSubscription.($resourceSubscriptionId).TenantId
                        $resourceMGPath = $remoteTenantId
                        if ($remoteTenantId -eq $azApiCallConf['checkcontext'].tenant.id) {
                            $resourceXTenant = $false
                        }
                        else {
                            $resourceXTenant = $true
                        }
                    }
                    else {
                        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($resourceSubscriptionId)?api-version=2020-01-01"
                        $remoteTenantId = AzAPICall -AzAPICallConfiguration $azApiCallConf -uri $uri -listenOn 'content' -currentTask "getTenantId for subscriptionId '$($resourceSubscriptionId)'"
                        $arrayRemoteMGPath = [System.Collections.ArrayList]@()
                        foreach ($remoteId in $remoteTenantId) {
                            $objectGuid = [System.Guid]::empty
                            if ([System.Guid]::TryParse($remoteId, [System.Management.Automation.PSReference]$ObjectGuid)) {
                                if ($remoteId -in $MSTenantIds) {
                                    $null = $arrayRemoteMGPath.Add("$remoteId (MS)")
                                }
                                else {
                                    $null = $arrayRemoteMGPath.Add($remoteId)
                                }
                                if ($remoteId -eq $azApiCallConf['checkcontext'].tenant.id) {
                                    $resourceXTenant = $false
                                }
                                else {
                                    $resourceXTenant = $true
                                }
                            }
                            $script:htUnknownTenantsForSubscription.($resourceSubscriptionId) = @{
                                TenantId = $arrayRemoteMGPath -join ', '
                            }
                            $resourceMGPath = $arrayRemoteMGPath -join ', '
                        }
                    }
                }

                if ($SubnetSubscription -eq $resourceSubscriptionId) {
                    $crossSubscriptionPE = $false
                }
                else {
                    $crossSubscriptionPE = $true
                }

                $crossTenantPE = $false
                if ($resourceXTenant -eq $true) {
                    $crossTenantPE = $true
                }

            }
        }

        $null = $script:arrayPrivateEndpointsEnriched.Add([PSCustomObject]@{
                PEName                   = $pe.name
                PEId                     = $pe.id
                PELocation               = $pe.location
                PEResourceGroup          = $resourceGroup
                PESubscriptionName       = $subscriptionName
                PESubscription           = ($pe.id -split '/')[2]
                PEMGPath                 = $MGPath
                PEConnectionType         = $peConnectionType
                PEConnectionState        = $peConnectionState
                CrossSubscriptionPE      = $crossSubscriptionPE
                CrossTenantPE            = $crossTenantPE

                Resource                 = $resource
                ResourceType             = $resourceType
                ResourceId               = $resourceId
                TargetSubresource        = $targetSubresource -join ', '
                NICName                  = $pe.properties.customNetworkInterfaceName
                FQDN                     = $pe.properties.customDnsConfigs.fqdn -join ', '
                ipAddresses              = $pe.properties.customDnsConfigs.ipAddresses -join ', '
                ResourceResourceGroup    = $resourceResourceGroup
                ResourceSubscriptionName = $resourceSubscriptionName
                ResourceSubscriptionId   = $resourceSubscriptionId
                ResourceMGPath           = $resourceMGPath
                ResourceCrossTenant      = $resourceXTenant

                Subnet                   = $pe.properties.subnet.id -replace '.*/'
                SubnetId                 = $pe.properties.subnet.id
                SubnetVNet               = $SubnetVNet
                SubnetVNetId             = $SubnetVNetId
                SubnetVNetLocation       = $SubnetVNetLocation
                SubnetVNetResourceGroup  = $SubnetVNetResourceGroup
                SubnetSubscriptionName   = $SubnetSubscriptionName
                SubnetSubscription       = $SubnetSubscription
                SubnetMGPath             = $SubnetMGPath
            })
    }


    $end = Get-Date
    Write-Host " Processing Private Endpoints enrichment duration: $((New-TimeSpan -Start $start -End $end).TotalSeconds) seconds"
}