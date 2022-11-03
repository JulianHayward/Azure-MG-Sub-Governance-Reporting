function processStorageAccountAnalysis {
    $start = get-date
    Write-Host "Processing Storage Account Analysis"
    $storageAccountscount = $storageAccounts.count
    if ($storageAccountscount -gt 0) {
        Write-Host " Executing Storage Account Analysis for $storageAccountscount Storage Accounts"
        $script:arrayStorageAccountAnalysisResults = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        createBearerToken -AzAPICallConfiguration $azapicallconf -targetEndPoint 'Storage'

        $storageAccounts | ForEach-Object -Parallel {
            $storageAccount = $_
            $azAPICallConf = $using:azAPICallConf
            $arrayStorageAccountAnalysisResults = $using:arrayStorageAccountAnalysisResults
            $htAllSubscriptionsFromAPI = $using:htAllSubscriptionsFromAPI
            $htSubscriptionsMgPath = $using:htSubscriptionsMgPath
            $htSubscriptionTags = $using:htSubscriptionTags
            $CSVDelimiterOpposite = $using:CSVDelimiterOpposite
            $StorageAccountAccessAnalysisSubscriptionTags = $using:StorageAccountAccessAnalysisSubscriptionTags
            $StorageAccountAccessAnalysisStorageAccountTags = $using:StorageAccountAccessAnalysisStorageAccountTags
            $listContainersSuccess = 'n/a'
            $containersCount = 'n/a'
            $arrayContainers = @()
            $arrayContainersAnonymousContainer = @()
            $arrayContainersAnonymousBlob = @()
            $staticWebsitesState = 'n/a'
            $webSiteResponds = 'n/a'

            $subscriptionId = ($storageAccount.id -split '/')[2]
            $resourceGroupName = ($storageAccount.id -split '/')[4]
            $subDetails = $htAllSubscriptionsFromAPI.($subscriptionId).subDetails

            Write-Host "Processing SA; Subscription: $($subDetails.displayName) ($subscriptionId) [$($subDetails.subscriptionPolicies.quotaId)] - Storage Account: $($storageAccount.name)"

            if ($storageAccount.Properties.primaryEndpoints.blob) {

                $urlServiceProps = "$($storageAccount.Properties.primaryEndpoints.blob)?restype=service&comp=properties"
                $saProperties = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $urlServiceProps -method 'GET' -listenOn 'Content' -currentTask "$($storageAccount.name) get restype=service&comp=properties" -saResourceGroupName $resourceGroupName
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
                        Write-Host "XMLSAPropertiesFailed: Subscription: $($subDetails.displayName) ($subscriptionId) - Storage Account: $($storageAccount.name)"
                        Write-Host $($saProperties.ForEach({[char]$_}) -join '') -ForegroundColor Cyan
                    }
                }

                $urlCompList = "$($storageAccount.Properties.primaryEndpoints.blob)?comp=list"
                $listContainers = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $urlCompList -method 'GET' -listenOn 'Content' -currentTask "$($storageAccount.name) get comp=list"
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
                            if ($storageAccount.properties.primaryEndpoints.web) {
                                try {
                                    $testStaticWebsiteResponse = Invoke-WebRequest -Uri $storageAccount.properties.primaryEndpoints.web -Method 'HEAD'
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

            $allowSharedKeyAccess = $storageAccount.properties.allowSharedKeyAccess
            if ([string]::IsNullOrWhiteSpace($storageAccount.properties.allowSharedKeyAccess)) {
                $allowSharedKeyAccess = 'likely True'
            }
            $requireInfrastructureEncryption = $storageAccount.properties.encryption.requireInfrastructureEncryption
            if ([string]::IsNullOrWhiteSpace($storageAccount.properties.encryption.requireInfrastructureEncryption)) {
                $requireInfrastructureEncryption = 'likely False'
            }

            $arrayResourceAccessRules = [System.Collections.ArrayList]@()
            if ($storageAccount.properties.networkAcls.resourceAccessRules) {
                if ($storageAccount.properties.networkAcls.resourceAccessRules.count -gt 0) {
                    foreach ($resourceAccessRule in $storageAccount.properties.networkAcls.resourceAccessRules) {

                        $resourceAccessRuleResourceIdSplitted = $resourceAccessRule.resourceId -split '/'
                        $resourceType = "$($resourceAccessRuleResourceIdSplitted[6])/$($resourceAccessRuleResourceIdSplitted[7])"

                        [regex]$regex = '\*+'
                        $resourceAccessRule.resourceId
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

            if ([string]::IsNullOrWhiteSpace($storageAccount.properties.publicNetworkAccess)) {
                $publicNetworkAccess = 'likely enabled'
            }
            else {
                $publicNetworkAccess = $storageAccount.properties.publicNetworkAccess
            }

            $temp = [System.Collections.ArrayList]@()
            $null = $temp.Add([PSCustomObject]@{
                    storageAccount                    = $storageAccount.name
                    kind                              = $storageAccount.kind
                    skuName                           = $storageAccount.sku.name
                    skuTier                           = $storageAccount.sku.tier
                    location                          = $storageAccount.location
                    creationTime                      = $storageAccount.properties.creationTime
                    allowBlobPublicAccess             = $storageAccount.properties.allowBlobPublicAccess
                    publicNetworkAccess               = $publicNetworkAccess
                    SubscriptionId                    = $subscriptionId
                    SubscriptionName                  = $subDetails.displayName
                    subscriptionQuotaId               = $subDetails.subscriptionPolicies.quotaId
                    subscriptionMGPath                = $htSubscriptionsMgPath.($subscriptionId).path -join '/'
                    resourceGroup                     = $resourceGroupName
                    networkAclsdefaultAction          = $storageAccount.properties.networkAcls.defaultAction
                    staticWebsitesState               = $staticWebsitesState
                    staticWebsitesResponse            = $webSiteResponds
                    containersCanBeListed             = $listContainersSuccess
                    containersCount                   = $containersCount
                    containers                        = $arrayContainers -join "$CSVDelimiterOpposite "
                    containersAnonymousContainerCount = $arrayContainersAnonymousContainer.Count
                    containersAnonymousContainer      = $arrayContainersAnonymousContainer -join "$CSVDelimiterOpposite "
                    containersAnonymousBlobCount      = $arrayContainersAnonymousBlob.Count
                    containersAnonymousBlob           = $arrayContainersAnonymousBlob -join "$CSVDelimiterOpposite "
                    ipRulesCount                      = $storageAccount.properties.networkAcls.ipRules.Count
                    ipRulesIPAddressList              = ($storageAccount.properties.networkAcls.ipRules.value | Sort-Object) -join "$CSVDelimiterOpposite "
                    virtualNetworkRulesCount          = $storageAccount.properties.networkAcls.virtualNetworkRules.Count
                    virtualNetworkRulesList           = ($storageAccount.properties.networkAcls.virtualNetworkRules.Id | Sort-Object) -join "$CSVDelimiterOpposite "
                    resourceAccessRulesCount          = $resourceAccessRulesCount
                    resourceAccessRules               = $resourceAccessRules
                    bypass                            = ($storageAccount.properties.networkAcls.bypass | Sort-Object) -join "$CSVDelimiterOpposite "
                    supportsHttpsTrafficOnly          = $storageAccount.properties.supportsHttpsTrafficOnly
                    minimumTlsVersion                 = $storageAccount.properties.minimumTlsVersion
                    allowSharedKeyAccess              = $allowSharedKeyAccess
                    requireInfrastructureEncryption   = $requireInfrastructureEncryption
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
                if ($storageAccount.tags) {
                    $htAllSATags = @{}
                    foreach ($saTagName in ($storageAccount.tags | Get-Member).where({ $_.MemberType -eq 'NoteProperty' }).Name) {
                        $htAllSATags.$saTagName = $storageAccount.tags.$saTagName
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
        Write-Host " No Storage Accounts present"
    }

    $end = Get-Date
    Write-Host " Processing Storage Account Analysis duration: $((NEW-TIMESPAN -Start $start -End $end).TotalSeconds) seconds"
}