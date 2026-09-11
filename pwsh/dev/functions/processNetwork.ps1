function processNetwork {
    $start = Get-Date
    Write-Host "Processing Network enrichment ($($arrayVNets.Count) Virtual Networks)"

    $htVNets = @{}
    foreach ($vnet in $arrayVNets) {
        $htVNets.($vnet.id) = $vnet
    }

    $script:htSubnets = @{}
    $script:arrayVirtualNetworks = [System.Collections.ArrayList]@()
    $script:arraySubnets = [System.Collections.ArrayList]@()

    foreach ($vnet in $arrayVNets) {

        #region peerings
        $vnetIdSplit = ($vnet.id -split '/')
        $subscriptionId = $vnetIdSplit[2]

        $subscriptionName = 'n/a'
        $MGPath = 'n/a'
        if ($htSubscriptionsMgPath.($subscriptionId)) {
            $subHelper = $htSubscriptionsMgPath.($subscriptionId)
            $subscriptionName = $subHelper.displayName
            $MGPath = $subHelper.ParentNameChainDelimited
        }

        $subnetsWithPrivateEndPointsCount = 0
        if ($vnet.properties.subnets.properties.privateEndpoints.id.Count -gt 0) {
            $subnetsWithPrivateEndPointsCount = $vnet.properties.subnets.where({ $_.properties.privateEndpoints.id.Count -gt 0 }).Count
        }

        $subnetsWithConnectedDevicesCount = 0
        if ($vnet.properties.subnets.properties.ipConfigurations.id.Count -gt 0) {
            $subnetsWithConnectedDevicesCount = $vnet.properties.subnets.where({ $_.properties.ipConfigurations.id.Count -gt 0 }).Count
        }

        $vnetResourceGroup = $vnetIdSplit[4]
        if ($vnet.properties.virtualNetworkPeerings.id.Count -gt 0) {
            foreach ($peering in $vnet.properties.virtualNetworkPeerings) {
                $remotevnetIdSplit = ($peering.properties.remoteVirtualNetwork.id -split '/')
                $remotesubscriptionId = $remotevnetIdSplit[2]

                $remotesubscriptionName = 'n/a'
                $remoteMGPath = 'n/a'
                $peeringXTenant = 'unknown'
                if ($htSubscriptionsMgPath.($remotesubscriptionId)) {
                    $peeringXTenant = 'false'
                    $remotesubHelper = $htSubscriptionsMgPath.($remotesubscriptionId)
                    $remotesubscriptionName = $remotesubHelper.displayName
                    $remoteMGPath = $remotesubHelper.ParentNameChainDelimited
                }
                else {
                    if ($htUnknownTenantsForSubscription.($remotesubscriptionId)) {
                        $remoteTenantId = $htUnknownTenantsForSubscription.($remotesubscriptionId).TenantId
                        $remoteMGPath = $remoteTenantId
                        if ($remoteTenantId -eq $azApiCallConf['checkcontext'].tenant.id) {
                            $peeringXTenant = 'false'
                        }
                        else {
                            $peeringXTenant = 'true'
                        }
                    }
                    else {
                        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($remotesubscriptionId)?api-version=2020-01-01"
                        $remoteTenantId = AzAPICall -AzAPICallConfiguration $azApiCallConf -uri $uri -listenOn 'content' -currentTask "getTenantId for subscriptionId '$($remotesubscriptionId)'"
                        if ($remoteTenantId.id -like '/subscriptions/*') {
                            #sub actually could be resolved but not available in htSubscriptionsMgPath
                            Write-Host "SubscriptionId '$($remotesubscriptionId)' (tenantId: '$($remoteTenantId.tenantId)' (current context tenantId: '$($azapiCallConf['checkContext'].tenant.Id)')) was not captured by getSubscriptions/getEntities, however could be fully resolved with direct get call (ARM subscription API)" -ForegroundColor Magenta
                            $remoteMGPath = $remoteTenantId.tenantId
                            if ($azapiCallConf['checkContext'].tenant.Id -eq $remoteTenantId.tenantId) {
                                $peeringXTenant = 'false'
                            }
                            else {
                                $peeringXTenant = 'true'
                            }
                        }
                        else {
                            $arrayRemoteMGPath = [System.Collections.ArrayList]@()
                            foreach ($remoteId in $remoteTenantId) {
                                if ($remoteId -eq 'SubscriptionNotFound Tenant unknown') {
                                    $remoteMGPath = 'unknown'
                                    $peeringXTenant = 'n/a'
                                }
                                else {
                                    $objectGuid = [System.Guid]::empty
                                    if ([System.Guid]::TryParse($remoteId, [System.Management.Automation.PSReference]$ObjectGuid)) {
                                        if ($remoteId -in $MSTenantIds) {
                                            $null = $arrayRemoteMGPath.Add("$remoteId (MS)")
                                        }
                                        else {
                                            $null = $arrayRemoteMGPath.Add($remoteId)
                                        }
                                        if ($remoteId -eq $azApiCallConf['checkcontext'].tenant.id) {
                                            $peeringXTenant = 'false'
                                        }
                                        else {
                                            $peeringXTenant = 'true'
                                        }
                                    }
                                    $script:htUnknownTenantsForSubscription.($remotesubscriptionId) = @{
                                        TenantId = $arrayRemoteMGPath -join ', '
                                    }
                                    $remoteMGPath += $arrayRemoteMGPath -join ', '
                                }
                            }
                        }
                    }
                }

                $remotevnetName = $remotevnetIdSplit[8]
                $remotevnetResourceGroup = $remotevnetIdSplit[4]

                if ($htVNets.($peering.properties.remoteVirtualNetwork.id)) {
                    $remotevnetState = 'existent'
                    $remoteLocation = $htVNets.($peering.properties.remoteVirtualNetwork.id).location
                    $remotePeeringsCount = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.virtualNetworkPeerings.id.Count
                    $remoteDhcpoptionsDnsservers = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.dhcpoptions.dnsservers
                    $remoteSubnetsCount = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.subnets.id.Count
                    $remoteSubnetsWithNSGCount = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.subnets.properties.networkSecurityGroup.id.Count
                    $remoteSubnetsWithRouteTable = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.subnets.properties.routeTable.id.Count
                    $remoteSubnetsWithDelegations = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.subnets.properties.delegations.id.Count
                    $remotePrivateEndPoints = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.subnets.properties.privateEndpoints.id.Count
                    $remoteSubnetsWithPrivateEndPoints = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.subnets.where({ $_.properties.privateEndpoints.id.Count -gt 0 }).Count
                    $remoteConnectedDevices = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.subnets.properties.ipConfigurations.id.Count
                    $remoteSubnetsWithConnectedDevices = $htVNets.($peering.properties.remoteVirtualNetwork.id).properties.subnets.where({ $_.properties.ipConfigurations.id.Count -gt 0 }).Count
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
                    else {
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
                    $remoteDhcpoptionsDnsservers = 'n/a'
                    $remoteSubnetsCount = 'n/a'
                    $remoteSubnetsWithNSGCount = 'n/a'
                    $remoteSubnetsWithRouteTable = 'n/a'
                    $remoteSubnetsWithDelegations = 'n/a'
                    $remotePrivateEndPoints = 'n/a'
                    $remoteSubnetsWithPrivateEndPoints = 'n/a'
                    $remoteConnectedDevices = 'n/a'
                    $remoteSubnetsWithConnectedDevices = 'n/a'
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
                        Subscription                                    = ($vnet.id -split '/')[2]
                        MGPath                                          = $MGPath
                        VNet                                            = $vnet.name
                        VNetId                                          = $vnet.id
                        VNetResourceGroup                               = $vnetResourceGroup
                        Location                                        = $vnet.location
                        AddressSpaceAddressPrefixes                     = ($vnet.properties.addressSpace.addressPrefixes -join "$CsvDelimiterOpposite ")
                        DhcpoptionsDnsservers                           = ($vnet.properties.dhcpoptions.dnsservers -join "$CsvDelimiterOpposite ")
                        SubnetsCount                                    = $vnet.properties.subnets.id.Count
                        SubnetsWithNSGCount                             = $vnet.properties.subnets.properties.networkSecurityGroup.id.Count
                        SubnetsWithRouteTableCount                      = $vnet.properties.subnets.properties.routeTable.id.Count
                        SubnetsWithDelegationsCount                     = $vnet.properties.subnets.properties.delegations.id.Count
                        PrivateEndpointsCount                           = $vnet.properties.subnets.properties.privateEndpoints.id.Count
                        SubnetsWithPrivateEndPointsCount                = $subnetsWithPrivateEndPointsCount
                        ConnectedDevices                                = $vnet.properties.subnets.properties.ipConfigurations.id.Count
                        SubnetsWithConnectedDevicesCount                = $subnetsWithConnectedDevicesCount
                        DdosProtection                                  = $vnet.properties.enableDdosProtection

                        PeeringsCount                                   = $vnet.properties.virtualNetworkPeerings.id.Count
                        PeeringXTenant                                  = $peeringXTenant
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
                        RemoteMGPath                                    = $remoteMGPath -join ', '
                        RemoteVNet                                      = $remotevnetName
                        RemoteVNetId                                    = $peering.properties.remoteVirtualNetwork.id
                        RemoteVNetState                                 = $remotevnetState
                        RemoteVNetResourceGroup                         = $remotevnetResourceGroup
                        RemoteVNetLocation                              = $remoteLocation
                        RemoteAddressSpaceAddressPrefixes               = ($peering.properties.remoteAddressSpace.addressPrefixes -join "$CsvDelimiterOpposite ")
                        RemoteVirtualNetworkAddressSpaceAddressPrefixes = ($peering.properties.remoteVirtualNetworkAddressSpace.addressPrefixes -join "$CsvDelimiterOpposite ")

                        RemoteDhcpoptionsDnsservers                     = ($remoteDhcpoptionsDnsservers -join "$CsvDelimiterOpposite ")
                        RemoteSubnetsCount                              = $remoteSubnetsCount
                        RemoteSubnetsWithNSGCount                       = $remoteSubnetsWithNSGCount
                        RemoteSubnetsWithRouteTable                     = $remoteSubnetsWithRouteTable
                        RemoteSubnetsWithDelegations                    = $remoteSubnetsWithDelegations
                        RemotePrivateEndPoints                          = $remotePrivateEndPoints
                        RemoteSubnetsWithPrivateEndPoints               = $remoteSubnetsWithPrivateEndPoints
                        RemoteConnectedDevices                          = $remoteConnectedDevices
                        RemoteSubnetsWithConnectedDevices               = $remoteSubnetsWithConnectedDevices
                        RemoteDdosProtection                            = $remoteDdosProtection
                    })
            }

        }
        else {
            $null = $script:arrayVirtualNetworks.Add([PSCustomObject]@{
                    SubscriptionName                                = $subscriptionName
                    Subscription                                    = ($vnet.id -split '/')[2]
                    MGPath                                          = $MGPath
                    VNet                                            = $vnet.name
                    VNetId                                          = $vnet.id
                    VNetResourceGroup                               = $vnetResourceGroup
                    Location                                        = $vnet.location

                    AddressSpaceAddressPrefixes                     = ($vnet.properties.addressSpace.addressPrefixes -join "$CsvDelimiterOpposite ")
                    DhcpoptionsDnsservers                           = ($vnet.properties.dhcpoptions.dnsservers -join "$CsvDelimiterOpposite ")
                    SubnetsCount                                    = $vnet.properties.subnets.id.Count
                    SubnetsWithNSGCount                             = $vnet.properties.subnets.properties.networkSecurityGroup.id.Count
                    SubnetsWithRouteTableCount                      = $vnet.properties.subnets.properties.routeTable.id.Count
                    SubnetsWithDelegationsCount                     = $vnet.properties.subnets.properties.delegations.id.Count
                    PrivateEndpointsCount                           = $vnet.properties.subnets.properties.privateEndpoints.id.Count
                    SubnetsWithPrivateEndPointsCount                = $subnetsWithPrivateEndPointsCount
                    ConnectedDevices                                = $vnet.properties.subnets.properties.ipConfigurations.id.Count
                    SubnetsWithConnectedDevicesCount                = $subnetsWithConnectedDevicesCount
                    DdosProtection                                  = $vnet.properties.enableDdosProtection

                    PeeringsCount                                   = $vnet.properties.virtualNetworkPeerings.id.Count
                    PeeringXTenant                                  = 'n/a'
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
                    RemotePrivateEndPoints                          = ''
                    RemoteSubnetsWithPrivateEndPoints               = ''
                    RemoteConnectedDevices                          = ''
                    RemoteSubnetsWithConnectedDevices               = ''
                    RemoteDdosProtection                            = ''
                })
        }
        #endregion peerings

        #region subnets

        if ($vnet.properties.subnets.Count -gt 0) {
            foreach ($subnet in $vnet.properties.subnets) {

                $script:htSubnets.($subnet.id) = @{
                    SubscriptionName = $subscriptionName
                    Subscription     = ($vnet.id -split '/')[2]
                    MGPath           = $MGPath
                    VNet             = $vnet.name
                    VNetId           = $vnet.id
                    Location         = $vnet.location
                    ResourceGroup    = $vnetResourceGroup
                }

                $arrayServiceEndPoints = @()
                if ($subnet.properties.serviceEndpoints.service.Count -gt 0) {
                    $arrayServiceEndPoints = foreach ($serviceEndpoint in $subnet.properties.serviceEndpoints) {
                        "$($serviceEndpoint.service) ($(($serviceEndpoint.locations | Sort-Object) -join ', '))"
                    }
                }

                $delegation = ''
                if ($subnet.properties.delegations.Count -gt 0) {
                    $delegation = "$($subnet.properties.delegations.properties.serviceName) ($(($subnet.properties.delegations.properties.actions | Sort-Object) -join ', '))"
                }

                #region IP address usage
                #https://github.com/ElanShudnow/AzureCode/blob/242b923eada55fa795b930473a50dedf14bdc409/PowerShell/AzSubnetAvailability/AzSubnetAvailability.ps1

                #must be reset per subnet, else a subnet without an IPv4 prefix would inherit the previous subnet's values
                $AddressPrefix = $null
                $subnetNet = $null
                $subnetNetOutput = $null
                $regexIPv4Cidr = '^(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\/(\d{1}|[0-2]{1}\d{1}|3[0-2])$'

                #ignore IPv6
                if (-not [string]::IsNullOrWhiteSpace($subnet.properties.addressPrefix)) {
                    if ($subnet.properties.addressPrefix -match $regexIPv4Cidr) {
                        $AddressPrefix = $subnet.properties.addressPrefix
                        $subnetNet = $AddressPrefix -replace '/.*'
                        $subnetNetOutput = $subnetNet
                    }
                    else {
                        $subnetNetOutput = "(ignoring IPv6 $($subnet.properties.addressPrefix))"
                    }
                }

                #ignore IPv6
                if (-not [string]::IsNullOrWhiteSpace($subnet.properties.addressPrefixes)) {
                    $arr = foreach ($entry in $subnet.properties.addressPrefixes) {
                        if ($entry -match $regexIPv4Cidr) {
                            $AddressPrefix = $entry
                            $AddressPrefix -replace '/.*'
                            $subnetNet = $AddressPrefix -replace '/.*'
                        }
                        else {
                            "(ignoring IPv6 $entry)"
                        }
                    }
                    $subnetNetOutput = $arr
                }

                if ($null -eq $AddressPrefix) {
                    $subnetPrefix = 'n/a'
                    $subnetmask = 'n/a'
                    $Range = 'n/a'
                    $IPsLeft = 'n/a'
                    $usedIPAddressesPercent = 'n/a'
                    $subnetIPAddressUsageCritical = $false
                }
                else {
                    $subnetPrefix = $AddressPrefix -replace '.*/'

                    #Amount of available IP Addresses minus the 3 IPs that Azure consumes, minus net and broadcast
                    #https://learn.microsoft.com/azure/virtual-network/virtual-networks-faq#are-there-any-restrictions-on-using-ip-addresses-within-these-subnets
                    $AvailableAddresses = [Math]::Pow(2, 32 - [int]$subnetPrefix) - 5
                    if ($AvailableAddresses -lt 0) {
                        $AvailableAddresses = 0
                    }

                    if ($AvailableAddresses -eq 0) {
                        $IPsLeft = 0
                        $PercentIPsUsed = 100
                    }
                    else {
                        $IPsLeft = $AvailableAddresses - $subnet.properties.ipConfigurations.Count
                        $PercentIPsUsed = [math]::Round((($subnet.properties.ipConfigurations.Count / $AvailableAddresses) * 100), 1)
                    }
                    $usedIPAddressesPercent = "$PercentIPsUsed %"

                    $subnetIPAddressUsageCritical = $false
                    if ($PercentIPsUsed -gt $NetworkSubnetIPAddressUsageCriticalPercentage) {
                        $subnetIPAddressUsageCritical = $true
                    }

                    $subnetmask = ([IPAddress]"$([system.convert]::ToInt64(('1'*$subnetPrefix).PadRight(32,'0'),2))").IPAddressToString
                    $IPBits = [int[]]$subnetNet.Split('.')
                    $MaskBits = [int[]]$subnetmask.Split('.')
                    $NetworkIDBits = 0..3 | ForEach-Object { $IPBits[$_] -band $MaskBits[$_] }
                    $Broadcast = (0..3 | ForEach-Object { $NetworkIDBits[$_] + ($MaskBits[$_] -bxor 255) }) -join '.'
                    $Range = "$subnetNet - $Broadcast"
                }

                #endregion IP address usage

                $null = $script:arraySubnets.Add([PSCustomObject]@{
                        SubscriptionName                  = $subscriptionName
                        Subscription                      = ($vnet.id -split '/')[2]
                        MGPath                            = $MGPath
                        VNet                              = $vnet.name
                        VNetId                            = $vnet.id
                        VNetResourceGroup                 = $vnetResourceGroup
                        Location                          = $vnet.location
                        SubnetName                        = $subnet.name
                        SubnetId                          = $subnet.id
                        SubnetNet                         = $subnetNetOutput -join "$CsvDelimiterOpposite "
                        SubnetPrefix                      = $subnetPrefix
                        Subnetmask                        = $subnetmask
                        Range                             = $Range
                        ConnectedDevices                  = $subnet.properties.ipConfigurations.Count
                        AvailableIPAddresses              = $IPsLeft
                        UsedIPAddressesPercent            = $usedIPAddressesPercent
                        SubnetIPAddressUsageCritical      = $subnetIPAddressUsageCritical
                        PrivateEndpointNetworkPolicies    = $subnet.properties.privateEndpointNetworkPolicies
                        PrivateLinkServiceNetworkPolicies = $subnet.properties.privateLinkServiceNetworkPolicies
                        ServiceEndpointsCount             = $subnet.properties.serviceEndpoints.service.Count
                        ServiceEndpoints                  = $arrayServiceEndPoints -join ', '
                        Delegation                        = $delegation
                        NetworkSecurityGroup              = $subnet.properties.networkSecurityGroup.id
                        RouteTable                        = $subnet.properties.routeTable
                        NatGateway                        = ''
                        PrivateEndpoints                  = $subnet.properties.privateEndpoints.Count
                    })
            }
        }
        #endregion subnets
    }

    $end = Get-Date
    Write-Host " Processing Network enrichment duration: $((New-TimeSpan -Start $start -End $end).TotalSeconds) seconds"
}