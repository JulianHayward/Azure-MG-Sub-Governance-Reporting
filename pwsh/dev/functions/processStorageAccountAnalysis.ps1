function processStorageAccountAnalysis {
    $start = Get-Date
    Write-Host 'Processing Storage Account Analysis'
    $storageAccountsCount = $storageAccounts.count
    if ($storageAccountsCount -gt 0) {
        Write-Host " Executing Storage Account Analysis for $storageAccountsCount Storage Accounts"
        createBearerToken -AzAPICallConfiguration $azapicallconf -targetEndPoint 'Storage'

        $htSACost = @{}
        if ($DoAzureConsumption -eq $true) {
            $saConsumptionByResourceId = $allConsumptionData.where({ $_.resourceType -eq 'microsoft.storage/storageaccounts' }) | Group-Object -Property resourceid

            foreach ($sa in $saConsumptionByResourceId) {
                $htSACost.($sa.Name) = @{}
                $htSACost.($sa.Name).meterCategoryAll = ($sa.Group.MeterCategory | Sort-Object) -join ', '
                $htSACost.($sa.Name).costAll = ($sa.Group.PreTaxCost | Measure-Object -Sum).Sum #[decimal]($sa.Group.PreTaxCost | Measure-Object -Sum).Sum
                $htSACost.($sa.Name).currencyAll = ($sa.Group.Currency | Sort-Object -Unique) -join ', '
                foreach ($costentry in $sa.Group) {
                    $htSACost.($sa.Name)."cost_$($costentry.MeterCategory)" = $costentry.PreTaxCost
                    $htSACost.($sa.Name)."currency_$($costentry.MeterCategory)" = $costentry.Currency
                }
            }
        }

        $storageAccounts | ForEach-Object -Parallel {
            $storageAccount = $_
            $azAPICallConf = $using:azAPICallConf
            $arrayStorageAccountAnalysisResults = $using:arrayStorageAccountAnalysisResults
            $htAllSubscriptionsFromAPI = $using:htAllSubscriptionsFromAPI
            $htSubscriptionsMgPath = $using:htSubscriptionsMgPath
            $htSubscriptionTags = $using:htSubscriptionTags
            $CSVDelimiterOpposite = $using:CSVDelimiterOpposite
            $htSACost = $using:htSACost
            $StorageAccountAccessAnalysisSubscriptionTags = $using:StorageAccountAccessAnalysisSubscriptionTags
            $StorageAccountAccessAnalysisStorageAccountTags = $using:StorageAccountAccessAnalysisStorageAccountTags
            $listContainersSuccess = 'n/a'
            $containersCount = 'n/a'
            $arrayContainers = @()
            $arrayContainersAnonymousContainer = @()
            $arrayContainersAnonymousBlob = @()
            $staticWebsitesState = 'n/a'
            $webSiteResponds = 'n/a'

            $subscriptionId = ($storageAccount.SA.id -split '/')[2]
            $resourceGroupName = ($storageAccount.SA.id -split '/')[4]
            $subDetails = $htAllSubscriptionsFromAPI.($subscriptionId).subDetails

            Write-Host "Processing Storage Account '$($storageAccount.SA.name)' - Subscription: '$($subDetails.displayName)' ($subscriptionId) [$($subDetails.subscriptionPolicies.quotaId)]"

            if ($storageAccount.SA.Properties.primaryEndpoints.blob) {

                $urlServiceProps = "$($storageAccount.SA.Properties.primaryEndpoints.blob)?restype=service&comp=properties"
                $saProperties = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $urlServiceProps -method 'GET' -listenOn 'Content' -currentTask "$($storageAccount.SA.name) get restype=service&comp=properties" -saResourceGroupName $resourceGroupName -unhandledErrorAction Continue
                if ($saProperties) {
                    if ($saProperties -eq 'AuthorizationFailure' -or $saProperties -eq 'AuthorizationPermissionDenied' -or $saProperties -eq 'ResourceUnavailable' -or $saProperties -eq 'AuthorizationPermissionMismatch' ) {
                        if ($saProperties -eq 'ResourceUnavailable') {
                            $staticWebsitesState = $saProperties
                        }
                    }
                    else {
                        try {
                            $xmlSaProperties = [xml]([string]$saProperties -replace $saProperties.Substring(0, 3))
                            if ($xmlSaProperties.StorageServiceProperties.StaticWebsite) {
                                if ($xmlSaProperties.StorageServiceProperties.StaticWebsite.Enabled -eq $true) {
                                    $staticWebsitesState = $true
                                }
                                else {
                                    $staticWebsitesState = $false
                                }
                            }
                        }
                        catch {
                            Write-Host "XMLSAPropertiesFailed: Subscription: $($subDetails.displayName) ($subscriptionId) - Storage Account: $($storageAccount.SA.name)"
                            Write-Host $($saProperties.ForEach({ [char]$_ }) -join '') -ForegroundColor Cyan
                        }
                    }
                }

                $urlCompList = "$($storageAccount.SA.Properties.primaryEndpoints.blob)?comp=list"
                $listContainers = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $urlCompList -method 'GET' -listenOn 'Content' -currentTask "$($storageAccount.SA.name) get comp=list" -unhandledErrorAction Continue
                if ($listContainers) {
                    if ($listContainers -eq 'AuthorizationFailure' -or $listContainers -eq 'AuthorizationPermissionDenied' -or $listContainers -eq 'ResourceUnavailable' -or $listContainers -eq 'AuthorizationPermissionMismatch') {
                        if ($listContainers -eq 'ResourceUnavailable') {
                            $listContainersSuccess = $listContainers
                        }
                        else {
                            $listContainersSuccess = $false
                        }
                    }
                    else {
                        $listContainersSuccess = $true
                    }

                    if ($listContainersSuccess -eq $true) {
                        $xmlListContainers = [xml]([string]$listContainers -replace $listContainers.Substring(0, 3))
                        $containersCount = $xmlListContainers.EnumerationResults.Containers.Container.Count

                        foreach ($container in $xmlListContainers.EnumerationResults.Containers.Container) {
                            $arrayContainers += $container.Name
                            if ($container.Name -eq '$web' -and $staticWebsitesState) {
                                if ($storageAccount.SA.properties.primaryEndpoints.web) {
                                    try {
                                        $testStaticWebsiteResponse = Invoke-WebRequest -Uri $storageAccount.SA.properties.primaryEndpoints.web -Method 'HEAD'
                                        $webSiteResponds = $true
                                    }
                                    catch {
                                        $webSiteResponds = $false
                                    }
                                }
                            }

                            if ($container.Properties.PublicAccess) {
                                if ($container.Properties.PublicAccess -eq 'blob') {
                                    $arrayContainersAnonymousBlob += $container.Name
                                }
                                if ($container.Properties.PublicAccess -eq 'container') {
                                    $arrayContainersAnonymousContainer += $container.Name
                                }
                            }
                        }
                    }
                }
            }

            $allowSharedKeyAccess = $storageAccount.SA.properties.allowSharedKeyAccess
            if ([string]::IsNullOrWhiteSpace($storageAccount.SA.properties.allowSharedKeyAccess)) {
                $allowSharedKeyAccess = 'likely True'
            }
            $requireInfrastructureEncryption = $storageAccount.SA.properties.encryption.requireInfrastructureEncryption
            if ([string]::IsNullOrWhiteSpace($storageAccount.SA.properties.encryption.requireInfrastructureEncryption)) {
                $requireInfrastructureEncryption = 'likely False'
            }

            $arrayResourceAccessRules = [System.Collections.ArrayList]@()
            if ($storageAccount.SA.properties.networkAcls.resourceAccessRules) {
                if ($storageAccount.SA.properties.networkAcls.resourceAccessRules.count -gt 0) {
                    foreach ($resourceAccessRule in $storageAccount.SA.properties.networkAcls.resourceAccessRules) {

                        $resourceAccessRuleResourceIdSplitted = $resourceAccessRule.resourceId -split '/'
                        $resourceType = "$($resourceAccessRuleResourceIdSplitted[6])/$($resourceAccessRuleResourceIdSplitted[7])"

                        [regex]$regex = '\*+'
                        #$resourceAccessRule.resourceId
                        switch ($regex.matches($resourceAccessRule.resourceId).count) {
                            { $_ -eq 1 } {
                                $null = $arrayResourceAccessRules.Add([PSCustomObject]@{
                                        resourcetype = $resourceType
                                        range        = 'resourceGroup'
                                        sort         = 3
                                    })
                            }
                            { $_ -eq 2 } {
                                $null = $arrayResourceAccessRules.Add([PSCustomObject]@{
                                        resourcetype = $resourceType
                                        range        = 'subscription'
                                        sort         = 2
                                    })
                            }
                            { $_ -eq 3 } {
                                $null = $arrayResourceAccessRules.Add([PSCustomObject]@{
                                        resourcetype = $resourceType
                                        range        = 'tenant'
                                        sort         = 1
                                    })
                            }
                            default {
                                $null = $arrayResourceAccessRules.Add([PSCustomObject]@{
                                        resourcetype = $resourceType
                                        range        = 'resource'
                                        resource     = $resourceAccessRule.resourceId
                                        sort         = 0
                                    })
                            }
                        }
                    }
                }
            }
            $resourceAccessRulesCount = $arrayResourceAccessRules.count
            if ($resourceAccessRulesCount -eq 0) {
                $resourceAccessRules = ''
            }
            else {
                $ht = @{}
                foreach ($accessRulePerRange in $arrayResourceAccessRules | Group-Object -Property range | Sort-Object -Property Name -Descending) {

                    if ($accessRulePerRange.Name -eq 'resource') {
                        $arrayResources = @()
                        foreach ($resource in $accessRulePerRange.Group.resource | Sort-Object) {
                            $arrayResources += $resource
                        }
                        $ht.($accessRulePerRange.Name) = [array]($arrayResources)
                    }
                    else {
                        $arrayResourceTypes = @()
                        foreach ($resourceType in $accessRulePerRange.Group.resourceType | Sort-Object) {
                            $arrayResourceTypes += $resourceType
                        }
                        $ht.($accessRulePerRange.Name) = [array]($arrayResourceTypes)
                    }
                }
                $resourceAccessRules = $ht | ConvertTo-Json
            }

            if ([string]::IsNullOrWhiteSpace($storageAccount.SA.properties.publicNetworkAccess)) {
                $publicNetworkAccess = 'likely Enabled'
            }
            else {
                $publicNetworkAccess = $storageAccount.SA.properties.publicNetworkAccess
            }

            if ([string]::IsNullOrWhiteSpace($storageAccount.SA.properties.allowedCopyScope)) {
                $allowedCopyScope = 'From any Storage Account'
            }
            else {
                $allowedCopyScope = $storageAccount.SA.properties.allowedCopyScope
            }

            if ([string]::IsNullOrWhiteSpace($storageAccount.SA.properties.allowCrossTenantReplication)) {
                if ($allowedCopyScope -ne 'From any Storage Account') {
                    $allowCrossTenantReplication = "likely False (allowedCopyScope=$allowedCopyScope)"
                }
                else {
                    $allowCrossTenantReplication = 'likely True'
                }
            }
            else {
                $allowCrossTenantReplication = $storageAccount.SA.properties.allowCrossTenantReplication
            }

            if ($storageAccount.SA.properties.dnsEndpointType) {
                $dnsEndpointType = $storageAccount.SA.properties.dnsEndpointType
            }
            else {
                $dnsEndpointType = 'standard'
            }

            if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
                if ($htSACost.($storageAccount.SA.id)) {
                    $hlpCost = $htSACost.($storageAccount.SA.id)
                    $saCost = $hlpCost.costAll
                    $saCostCurrency = $hlpCost.currencyAll
                    $saCostMeterCategories = $hlpCost.meterCategoryAll
                }
                else {
                    $saCost = 'n/a'
                    $saCostCurrency = 'n/a'
                    $saCostMeterCategories = 'n/a'
                }
            }
            else {
                $saCost = ''
                $saCostCurrency = ''
                $saCostMeterCategories = ''
            }

            $temp = [System.Collections.ArrayList]@()
            $null = $temp.Add([PSCustomObject]@{
                    storageAccount                    = $storageAccount.SA.name
                    kind                              = $storageAccount.SA.kind
                    skuName                           = $storageAccount.SA.sku.name
                    skuTier                           = $storageAccount.SA.sku.tier
                    location                          = $storageAccount.SA.location
                    creationTime                      = $storageAccount.SA.properties.creationTime
                    allowBlobPublicAccess             = $storageAccount.SA.properties.allowBlobPublicAccess
                    publicNetworkAccess               = $publicNetworkAccess
                    SubscriptionId                    = $subscriptionId
                    SubscriptionName                  = $subDetails.displayName
                    subscriptionQuotaId               = $subDetails.subscriptionPolicies.quotaId
                    subscriptionMGPath                = $htSubscriptionsMgPath.($subscriptionId).path -join '/'
                    resourceGroup                     = $resourceGroupName
                    networkAclsdefaultAction          = $storageAccount.SA.properties.networkAcls.defaultAction
                    staticWebsitesState               = $staticWebsitesState
                    staticWebsitesResponse            = $webSiteResponds
                    containersCanBeListed             = $listContainersSuccess
                    containersCount                   = $containersCount
                    containers                        = $arrayContainers -join "$CSVDelimiterOpposite "
                    containersAnonymousContainerCount = $arrayContainersAnonymousContainer.Count
                    containersAnonymousContainer      = $arrayContainersAnonymousContainer -join "$CSVDelimiterOpposite "
                    containersAnonymousBlobCount      = $arrayContainersAnonymousBlob.Count
                    containersAnonymousBlob           = $arrayContainersAnonymousBlob -join "$CSVDelimiterOpposite "
                    ipRulesCount                      = $storageAccount.SA.properties.networkAcls.ipRules.Count
                    ipRulesIPAddressList              = ($storageAccount.SA.properties.networkAcls.ipRules.value | Sort-Object) -join "$CSVDelimiterOpposite "
                    virtualNetworkRulesCount          = $storageAccount.SA.properties.networkAcls.virtualNetworkRules.Count
                    virtualNetworkRulesList           = ($storageAccount.SA.properties.networkAcls.virtualNetworkRules.Id | Sort-Object) -join "$CSVDelimiterOpposite "
                    resourceAccessRulesCount          = $resourceAccessRulesCount
                    resourceAccessRules               = $resourceAccessRules
                    bypass                            = ($storageAccount.SA.properties.networkAcls.bypass | Sort-Object) -join "$CSVDelimiterOpposite "
                    supportsHttpsTrafficOnly          = $storageAccount.SA.properties.supportsHttpsTrafficOnly
                    minimumTlsVersion                 = $storageAccount.SA.properties.minimumTlsVersion
                    allowSharedKeyAccess              = $allowSharedKeyAccess
                    requireInfrastructureEncryption   = $requireInfrastructureEncryption
                    allowedCopyScope                  = $allowedCopyScope
                    allowCrossTenantReplication       = $allowCrossTenantReplication
                    dnsEndpointType                   = $dnsEndpointType
                    usedCapacity                      = $storageAccount.SAUsedCapacity
                    cost                              = $saCost
                    metercategory                     = $saCostMeterCategories
                    curreny                           = $saCostCurrency
                })

            if ($StorageAccountAccessAnalysisSubscriptionTags[0] -ne 'undefined' -and $StorageAccountAccessAnalysisSubscriptionTags.Count -gt 0) {
                foreach ($subTag4StorageAccountAccessAnalysis in $StorageAccountAccessAnalysisSubscriptionTags) {
                    if ($htSubscriptionTags.($subscriptionId).$subTag4StorageAccountAccessAnalysis) {
                        $temp | Add-Member -NotePropertyName "SubTag_$subTag4StorageAccountAccessAnalysis" -NotePropertyValue $($htSubscriptionTags.($subscriptionId).$subTag4StorageAccountAccessAnalysis)
                    }
                    else {
                        $temp | Add-Member -NotePropertyName "SubTag_$subTag4StorageAccountAccessAnalysis" -NotePropertyValue 'n/a'
                    }
                }
            }

            if ($StorageAccountAccessAnalysisStorageAccountTags[0] -ne 'undefined' -and $StorageAccountAccessAnalysisStorageAccountTags.Count -gt 0) {
                if ($storageAccount.SA.tags) {
                    $htAllSATags = @{}
                    foreach ($saTagName in ($storageAccount.SA.tags | Get-Member).where({ $_.MemberType -eq 'NoteProperty' }).Name) {
                        $htAllSATags.$saTagName = $storageAccount.SA.tags.$saTagName
                    }
                }
                foreach ($saTag4StorageAccountAccessAnalysis in $StorageAccountAccessAnalysisStorageAccountTags) {
                    if ($htAllSATags.$saTag4StorageAccountAccessAnalysis) {
                        $temp | Add-Member -NotePropertyName "SATag_$saTag4StorageAccountAccessAnalysis" -NotePropertyValue $($htAllSATags.$saTag4StorageAccountAccessAnalysis)
                    }
                    else {
                        $temp | Add-Member -NotePropertyName "SATag_$saTag4StorageAccountAccessAnalysis" -NotePropertyValue 'n/a'
                    }
                }
            }

            $null = $script:arrayStorageAccountAnalysisResults.AddRange($temp)

        } -ThrottleLimit $ThrottleLimit
    }
    else {
        Write-Host ' No Storage Accounts present'
    }

    $end = Get-Date
    Write-Host " Processing Storage Account Analysis duration: $((New-TimeSpan -Start $start -End $end).TotalMinutes) minutes ($((New-TimeSpan -Start $start -End $end).TotalSeconds) seconds)"
}