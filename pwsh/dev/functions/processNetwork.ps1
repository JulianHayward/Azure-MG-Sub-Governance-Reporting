function processNetwork {
    $script:arrayVirtualNetworks = [System.Collections.ArrayList]@()
    $script:arraySubnets = [System.Collections.ArrayList]@()

    $htVNets = @{}
    #$htPeerings = @{}
    foreach ($vnet in $arrayVNets) {
        $htVNets.($vnet.id) = $vnet
        if ($vnet.properties.subnets.Count -gt 0) {
            foreach ($subnet in $vnet.properties.subnets) {
                if ($subnet.properties.ipConfigurations.Count -gt 0) {
                    foreach ($ipConfiguration in $subnet.properties.ipConfigurations) {
                        #$vnet | convertto-json -depth 99
                        #$ipConfiguration.id
                        #  pause
                    }
                }
                if ($subnet.properties.networkSecurityGroup.Count -gt 0) {
                    foreach ($networkSecurityGroup in $subnet.properties.networkSecurityGroup) {
                        # $networkSecurityGroup
                    }
                }
                if ($subnet.properties.serviceEndpoints.Count -gt 0) {
                    foreach ($serviceEndpoints in $subnet.properties.serviceEndpoints) {
                        # $serviceEndpoints
                    }
                }
                if ($subnet.properties.routeTable.Count -gt 0) {
                    foreach ($routeTable in $subnet.properties.routeTable) {
                        #  $routeTable
                    }
                }
                if ($subnet.properties.delegations.Count -gt 0) {
                    foreach ($delegations in $subnet.properties.delegations) {
                        # $delegations
                    }
                }
            }
        }
        # if ($vnet.properties.virtualNetworkPeerings.Count -gt 0) {
        #     $htPeerings.($vnet.id) = $vnet.properties.virtualNetworkPeerings
        # }
    }

    foreach ($vnet in $arrayVNets) {
        #peeringsStuff

        #$vnetIdSplit = "/subscriptions/19f26644-2e08-4119-8ade-5e1e93e3dca3/resourceGroups/AzAdvertizer/providers/Microsoft.Network/virtualNetworks/azadvertizer" -split "/"
        $vnetIdSplit = ($vnet.id -split "/")
        $subscriptionId = $vnetIdSplit[2]

        $subscriptionName = 'n/a'
        $MGPath = 'n/a'
        if ($htSubscriptionsMgPath.($subscriptionId)) {
            $subHelper = $htSubscriptionsMgPath.($subscriptionId)
            $subscriptionName = $subHelper.displayName
            $MGPath = $subHelper.ParentNameChainDelimited
        }

        $vnetResourceGroup = $vnetIdSplit[4]
        if ($vnet.properties.virtualNetworkPeerings.Count -gt 0) {
            foreach ($peering in $vnet.properties.virtualNetworkPeerings) {
                $remotevnetIdSplit = ($peering.properties.remoteVirtualNetwork.id -split "/")
                $remotesubscriptionId = $remotevnetIdSplit[2]


                $remotesubscriptionName = 'n/a'
                $remoteMGPath = 'n/a'
                if ($htSubscriptionsMgPath.($subscriptionId)) {
                    $remotesubHelper = $htSubscriptionsMgPath.($remotesubscriptionId)
                    $remotesubscriptionName = $remotesubHelper.displayName
                    $remoteMGPath = $remotesubHelper.ParentNameChainDelimited
                }

                $remotevnetName = $remotevnetIdSplit[8]
                $remotevnetResourceGroup = $remotevnetIdSplit[4]

                if ($htVNets.($peering.properties.remoteVirtualNetwork.id)) {
                    $remotevnetState = 'existent'
                    $remoteLocation = $htVNets.($peering.properties.remoteVirtualNetwork.id).location
                    $remotePeeringsCount = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.virtualNetworkPeerings.Count
                    $remoteSubnetsCount = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.subnets.Count
                    $remoteSubnetsWithNSGCount = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.subnets.properties.networkSecurityGroup.Count
                    $remoteSubnetsWithRouteTable = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.subnets.properties.routeTable.Count
                    $remoteSubnetsWithDelegations = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.subnets.properties.delegations.Count
                    $remoteDhcpoptionsDnsservers = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.dhcpoptions.dnsservers
                    $remoteConnectedDevices = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.subnets.properties.ipConfigurations.id.Count
                    $remoteDdosProtection = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.enableDdosProtection
                    $remotePeering = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.virtualNetworkPeerings.where({ $_.properties.remoteVirtualNetwork.id -eq $vnet.id })
                    if ($remotePeering.count -eq 1) {
                        $remotePeeringName = $remotePeering.name
                        $remotePeeringState = $remotePeering.Properties.peeringState
                        $remotePeeringSyncLevel = $remotePeering.Properties.peeringSyncLevel
                        $remoteAllowVirtualNetworkAccess = $remotePeering.properties.allowVirtualNetworkAccess
                        $remoteAllowForwardedTraffic = $remotePeering.properties.allowForwardedTraffic
                        $remoteAllowGatewayTransit = $remotePeering.properties.allowGatewayTransit
                        $remoteUseRemoteGateways = $remotePeering.properties.useRemoteGateways
                        $remoteDoNotVerifyRemoteGateways = $remotePeering.properties.doNotVerifyRemoteGateways
                        $remotePeerCompleteVnets = $remotePeering.properties.peerCompleteVnets
                        $remoteRouteServiceVips = $remotePeering.properties.routeServiceVips
                    }
                    else{
                        $remotePeeringName = 'n/a'
                        $remotePeeringState = 'n/a'
                        $remotePeeringSyncLevel = 'n/a'
                        $remoteAllowVirtualNetworkAccess = 'n/a'
                        $remoteAllowForwardedTraffic = 'n/a'
                        $remoteAllowGatewayTransit = 'n/a'
                        $remoteUseRemoteGateways = 'n/a'
                        $remoteDoNotVerifyRemoteGateways = 'n/a'
                        $remotePeerCompleteVnets = 'n/a'
                        $remoteRouteServiceVips = 'n/a'
                    }

                }
                else {
                    if ($getMgParentName -eq 'Tenant Root') {
                        $remotevnetState = 'non-existent'
                    }
                    else {
                        $remotevnetState = 'n/a'
                    }
                    $remoteLocation = 'n/a'
                    $remotePeeringsCount = 'n/a'
                    $remoteSubnetsCount = 'n/a'
                    $remoteSubnetsWithNSGCount = 'n/a'
                    $remoteSubnetsWithRouteTable = 'n/a'
                    $remoteSubnetsWithDelegations = 'n/a'
                    $remoteDhcpoptionsDnsservers = 'n/a'
                    $remoteConnectedDevices = 'n/a'
                    $remoteDdosProtection = 'n/a'
                    $remotePeeringName = 'n/a'
                    $remotePeeringState = 'n/a'
                    $remotePeeringSyncLevel = 'n/a'
                    $remoteAllowVirtualNetworkAccess = 'n/a'
                    $remoteAllowForwardedTraffic = 'n/a'
                    $remoteAllowGatewayTransit = 'n/a'
                    $remoteUseRemoteGateways = 'n/a'
                    $remoteDoNotVerifyRemoteGateways = 'n/a'
                    $remotePeerCompleteVnets = 'n/a'
                    $remoteRouteServiceVips = 'n/a'
                }

                $null = $script:arrayVirtualNetworks.Add([PSCustomObject]@{
                        SubscriptionName                                = $subscriptionName
                        Subscription                                    = ($vnet.id -split "/")[2]
                        MGPath                                          = $MGPath
                        VNet                                            = $vnet.name
                        VNetId                                            = $vnet.id
                        VNetResourceGroup                               = $vnetResourceGroup
                        Location                                        = $vnet.location
                        AddressSpaceAddressPrefixes                     = $vnet.properties.addressSpace.addressPrefixes
                        DhcpoptionsDnsservers                           = $vnet.properties.dhcpoptions.dnsservers
                        SubnetsCount                                    = $vnet.properties.subnets.Count
                        SubnetsWithNSGCount                             = $vnet.properties.subnets.properties.networkSecurityGroup.Count
                        SubnetsWithRouteTableCount                      = $vnet.properties.subnets.properties.routeTable.Count
                        SubnetsWithDelegationsCount                     = $vnet.properties.subnets.properties.delegations.Count
                        ConnectedDevices                                = $vnet.properties.subnets.properties.ipConfigurations.id.Count
                        DdosProtection                                  = $vnet.properties.enableDdosProtection

                        PeeringsCount                                   = $vnet.properties.virtualNetworkPeerings.Count
                        PeeringName                                     = $peering.name
                        PeeringState                                    = $peering.properties.peeringState
                        PeeringSyncLevel                                = $peering.properties.peeringSyncLevel
                        AllowVirtualNetworkAccess                       = $peering.properties.allowVirtualNetworkAccess
                        AllowForwardedTraffic                           = $peering.properties.allowForwardedTraffic
                        AllowGatewayTransit                             = $peering.properties.allowGatewayTransit
                        UseRemoteGateways                               = $peering.properties.useRemoteGateways
                        DoNotVerifyRemoteGateways                       = $peering.properties.doNotVerifyRemoteGateways
                        PeerCompleteVnets                               = $peering.properties.peerCompleteVnets
                        RouteServiceVips                                = $peering.properties.routeServiceVips

                        RemotePeeringsCount                             = $remotePeeringsCount
                        RemotePeeringName                               = $remotePeeringName
                        RemotePeeringState                              = $remotePeeringState
                        RemotePeeringSyncLevel                          = $remotePeeringSyncLevel
                        RemoteAllowVirtualNetworkAccess                 = $RemoteAllowVirtualNetworkAccess
                        RemoteAllowForwardedTraffic                     = $RemoteAllowForwardedTraffic
                        RemoteAllowGatewayTransit                       = $RemoteAllowGatewayTransit
                        RemoteUseRemoteGateways                         = $RemoteUseRemoteGateways
                        RemoteDoNotVerifyRemoteGateways                 = $RemoteDoNotVerifyRemoteGateways
                        RemotePeerCompleteVnets                         = $RemotePeerCompleteVnets
                        RemoteRouteServiceVips                          = $RemoteRouteServiceVips

                        RemoteSubscriptionName                          = $remotesubscriptionName
                        RemoteSubscription                              = $remotesubscriptionId
                        RemoteMGPath                                    = $remoteMGPath
                        RemoteVNet                                      = $remotevnetName
                        RemoteVNetId                                    = $peering.properties.remoteVirtualNetwork.id
                        RemoteVNetState                                 = $remotevnetState
                        RemoteVNetResourceGroup                         = $remotevnetResourceGroup
                        RemoteVNetLocation                              = $remoteLocation
                        RemoteAddressSpaceAddressPrefixes               = $peering.properties.remoteAddressSpace.addressPrefixes
                        RemoteVirtualNetworkAddressSpaceAddressPrefixes = $peering.properties.remoteVirtualNetworkAddressSpace.addressPrefixes

                        RemoteDhcpoptionsDnsservers                     = $remoteDhcpoptionsDnsservers
                        RemoteSubnetsCount                              = $remoteSubnetsCount
                        RemoteSubnetsWithNSGCount                       = $remoteSubnetsWithNSGCount
                        RemoteSubnetsWithRouteTable                     = $remoteSubnetsWithRouteTable
                        RemoteSubnetsWithDelegations                    = $remoteSubnetsWithDelegations
                        RemoteConnectedDevices                          = $remoteConnectedDevices
                        RemoteDdosProtection                            = $remoteDdosProtection
                    })
            }

        }
        else {
            $null = $script:arrayVirtualNetworks.Add([PSCustomObject]@{
                    SubscriptionName                                = $subscriptionName
                    Subscription                                    = ($vnet.id -split "/")[2]
                    MGPath                                          = $MGPath
                    VNet                                            = $vnet.name
                    VNetId                                          = $vnet.id
                    VNetResourceGroup                               = $vnetResourceGroup
                    Location                                        = $vnet.location

                    AddressSpaceAddressPrefixes                     = $vnet.properties.addressSpace.addressPrefixes
                    DhcpoptionsDnsservers                           = $vnet.properties.dhcpoptions.dnsservers
                    SubnetsCount                                    = $vnet.properties.subnets.Count
                    SubnetsWithNSGCount                             = $vnet.properties.subnets.properties.networkSecurityGroup.Count
                    SubnetsWithRouteTableCount                      = $vnet.properties.subnets.properties.routeTable.Count
                    SubnetsWithDelegationsCount                     = $vnet.properties.subnets.properties.delegations.Count
                    ConnectedDevices                                = $vnet.properties.subnets.properties.ipConfigurations.id.Count
                    DdosProtection                                  = $vnet.properties.enableDdosProtection

                    PeeringsCount                                   = $vnet.properties.virtualNetworkPeerings.Count
                    PeeringName                                     = ''
                    PeeringState                                    = ''
                    PeeringSyncLevel                                = ''
                    AllowVirtualNetworkAccess                       = ''
                    AllowForwardedTraffic                           = ''
                    AllowGatewayTransit                             = ''
                    UseRemoteGateways                               = ''
                    DoNotVerifyRemoteGateways                       = ''
                    PeerCompleteVnets                               = ''
                    RouteServiceVips                                = ''

                    RemotePeeringsCount                             = ''
                    RemotePeeringName                               = ''
                    RemotePeeringState                              = ''
                    RemotePeeringSyncLevel                          = ''
                    RemoteAllowVirtualNetworkAccess                 = ''
                    RemoteAllowForwardedTraffic                     = ''
                    RemoteAllowGatewayTransit                       = ''
                    RemoteUseRemoteGateways                         = ''
                    RemoteDoNotVerifyRemoteGateways                 = ''
                    RemotePeerCompleteVnets                         = ''
                    RemoteRouteServiceVips                          = ''

                    RemoteSubscriptionName                          = ''
                    RemoteSubscription                              = ''
                    RemoteMGPath                                    = ''
                    RemoteVNet                                      = ''
                    RemoteVNetId                                    = ''
                    RemoteVNetState                                 = ''
                    RemoteVNetResourceGroup                         = ''
                    RemoteVNetLocation                              = ''
                    RemoteAddressSpaceAddressPrefixes               = ''
                    RemoteVirtualNetworkAddressSpaceAddressPrefixes = ''
                    RemoteDhcpoptionsDnsservers                     = ''
                    RemoteSubnetsCount                              = ''
                    RemoteSubnetsWithNSGCount                       = ''
                    RemoteSubnetsWithRouteTable                     = ''
                    RemoteSubnetsWithDelegations                    = ''
                    RemoteConnectedDevices                          = ''
                    RemoteDdosProtection                            = ''
                })
        }


        #subnetStuff
        if ($vnet.properties.subnets.Count -gt 0) {
            #"$($vnet.name) has $($vnet.properties.subnets.Count) subnets"
            foreach ($subnet in $vnet.properties.subnets) {
                #"  subnet: $($subnet.name)"
                #"  addressPrefix: $($subnet.properties.addressPrefix)"
            }
        }
    }
}