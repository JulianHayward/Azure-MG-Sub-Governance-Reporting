function processPrivateEndpoints {
    $start = Get-Date
    Write-Host "Processing Private Endpoints enrichment ($($arrayPrivateEndPoints.Count) Private Endpoints)"

    $htVPrivateEndPoints = @{}
    foreach ($pe in $arrayPrivateEndPoints) {
        $htVPrivateEndPoints.($pe.id) = $pe
    }

    $script:arrayPrivateEndpointsEnriched = [System.Collections.ArrayList]@()

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

        $resourceSubscriptionId = $resourceSplit[2]
        $resourceSubscriptionName = 'n/a'
        $resourceMGPath = 'n/a'
        if ($htSubscriptionsMgPath.($resourceSubscriptionId)) {
            $subHelper = $htSubscriptionsMgPath.($resourceSubscriptionId)
            $resourceSubscriptionName = $subHelper.displayName
            $resourceMGPath = $subHelper.ParentNameChainDelimited
        }

        if ($SubnetSubscription -eq $resourceSubscriptionId) {
            $crossSubscriptionPE = $false
        }
        else {
            $crossSubscriptionPE = $true
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

                Resource                 = $resourceSplit[8]
                ResourceType             = "$($resourceSplit[6])/$($resourceSplit[7])"
                ResourceId               = $resourceId
                TargetSubresource        = $targetSubresource -join ', '
                NICName                  = $pe.properties.customNetworkInterfaceName
                FQDN                     = $pe.properties.customDnsConfigs.fqdn -join ', '
                ipAddresses              = $pe.properties.customDnsConfigs.ipAddresses -join ', '
                ResourceResourceGroup    = $resourceSplit[4]
                ResourceSubscriptionName = $resourceSubscriptionName
                ResourceSubscriptionId   = $resourceSubscriptionId
                ResourceMGPath           = $resourceMGPath

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