#region functions4DataCollection

function dataCollectionMGSecureScore {
    [CmdletBinding()]Param(
        [string]$Id
    )

    $mgAscSecureScoreResult = ''
    if ($azAPICallConf['htParameters'].NoMDfCSecureScore -eq $false) {
        if ($htMgASCSecureScore.($Id)) {
            $mgAscSecureScoreResult = $htMgASCSecureScore.($Id).SecureScore
        }
        else {
            $mgAscSecureScoreResult = 'isNullOrEmpty'
        }
    }
    return $mgAscSecureScoreResult
}
$funcDataCollectionMGSecureScore = $function:dataCollectionMGSecureScore.ToString()

function dataCollectionDefenderPlans {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $ChildMgMgPath,
        $SubscriptionQuotaId
    )

    $currentTask = "Getting Microsoft Defender for Cloud plans for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$SubscriptionQuotaId']"
    #https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Security/pricings?api-version=2018-06-01"
    $method = 'GET'
    $defenderPlansResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    if ($defenderPlansResult -eq 'SubScriptionNotRegistered' -or $defenderPlansResult -eq 'DisallowedProvider') {
        #Subscription skipped for MDfC
        $null = $script:arrayDefenderPlansSubscriptionsSkipped.Add([PSCustomObject]@{
                subscriptionId      = $scopeId
                subscriptionName    = $scopeDisplayName
                subscriptionQuotaId = $subscriptionQuotaId
                subscriptionMgPath  = $childMgMgPath
                reason              = $defenderPlansResult
            })
    }
    else {
        if ($defenderPlansResult.Count -gt 0) {
            foreach ($defenderPlanResult in $defenderPlansResult) {
                $null = $script:arrayDefenderPlans.Add([PSCustomObject]@{
                        subscriptionId     = $scopeId
                        subscriptionName   = $scopeDisplayName
                        subscriptionMgPath = $childMgMgPath
                        defenderPlan       = $defenderPlanResult.name
                        defenderPlanTier   = $defenderPlanResult.properties.pricingTier
                    })
            }
        }
    }
}
$funcDataCollectionDefenderPlans = $function:dataCollectionDefenderPlans.ToString()


function dataCollectionAdvisorScores {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $ChildMgMgPath,
        $SubscriptionQuotaId
    )

    $currentTask = "Getting Advisor Scores for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$SubscriptionQuotaId']"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Advisor/advisorScore?api-version=2020-07-01-preview"
    $method = 'GET'
    $advisorScoreResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection' -skipOnErrorCode 404

    if ($advisorScoreResult -eq 'SubScriptionNotRegistered' -or $advisorScoreResult -eq 'DisallowedProvider') {
    }
    else {
        if ($advisorScoreResult -like 'azgvzerrorMessage_*') {

        }
        else {
            if ($advisorScoreResult.Count -gt 0) {
                foreach ($entry in $advisorScoreResult) {
                    #Write-Host ($entry | ConvertTo-Json -Depth 99)
                    if ($entry.Name) {
                        $objectGuid = [System.Guid]::empty
                        if ([System.Guid]::TryParse($entry.Name, [System.Management.Automation.PSReference]$ObjectGuid)) {
                        }
                        else {
                            $null = $script:arrayAdvisorScores.Add([PSCustomObject]@{
                                    subscriptionId      = $scopeId
                                    subscriptionName    = $scopeDisplayName
                                    subscriptionQuotaId = $SubscriptionQuotaId
                                    subscriptionMgPath  = $childMgMgPath
                                    category            = $entry.Name
                                    score               = $entry.properties.lastRefreshedScore.score
                                })
                        }
                    }
                }
            }
        }
    }
}
$funcDataCollectionAdvisorScores = $function:dataCollectionAdvisorScores.ToString()

function dataCollectionDefenderEmailContacts {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $SubscriptionQuotaId
    )

    $currentTask = "Getting Microsoft Defender for Cloud Email contacts for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$SubscriptionQuotaId']"
    #https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview"
    $method = 'GET'
    $defenderSecurityContactsResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -listenOn 'Content' -currentTask $currentTask -caller 'CustomDataCollection'

    if ($defenderSecurityContactsResult -eq 'SubScriptionNotRegistered' -or $defenderSecurityContactsResult -eq 'DisallowedProvider') {
    }
    else {

        if ($defenderSecurityContactsResult -like 'azgvzerrorMessage_*') {
            $errorInfo = $defenderSecurityContactsResult -replace 'azgvzerrorMessage_'
            $script:htDefenderEmailContacts.($scopeId) = @{
                subscriptionId                    = $scopeId
                subscriptionName                  = $scopeDisplayName
                emails                            = $errorInfo
                roles                             = $errorInfo
                alertNotificationsState           = $errorInfo
                alertNotificationsminimalSeverity = $errorInfo
            }
        }
        else {
            if ($defenderSecurityContactsResult.Count -gt 0) {
                foreach ($entry in $defenderSecurityContactsResult) {

                    if ($entry.properties) {
                        if ($entry.properties.notificationsByRole.roles.count -gt 0) {
                            $roles = ($entry.properties.notificationsByRole.roles | Sort-Object) -join "$CsvDelimiterOpposite "
                        }
                        else {
                            $roles = 'none'
                        }

                        if ($entry.properties.emails) {
                            if (-not [string]::IsNullOrWhiteSpace($entry.properties.emails)) {
                                $emailsSplitted = $entry.properties.emails -split ';'
                                $arrayEmails = @()
                                foreach ($email in $emailsSplitted) {
                                    $arrayEmails += "'$email'"
                                }
                                $emails = ($arrayEmails | Sort-Object) -join "$CsvDelimiterOpposite "
                            }
                            else {
                                $emails = $entry.properties.emails
                            }
                        }
                        else {
                            $emails = 'none'
                        }

                        if ($entry.properties.alertNotifications.state) {
                            $alertNotificationsState = $entry.properties.alertNotifications.state
                        }

                        if ($entry.properties.alertNotifications.minimalSeverity) {
                            $alertNotificationsminimalSeverity = $entry.properties.alertNotifications.minimalSeverity
                        }
                    }
                    else {
                        $roles = 'n/a'
                        $emails = 'n/a'
                        $alertNotificationsState = 'n/a'
                        $alertNotificationsminimalSeverity = 'n/a'
                    }

                    $script:htDefenderEmailContacts.($scopeId) = @{
                        subscriptionId                    = $scopeId
                        subscriptionName                  = $scopeDisplayName
                        emails                            = $emails
                        roles                             = $roles
                        alertNotificationsState           = $alertNotificationsState
                        alertNotificationsminimalSeverity = $alertNotificationsminimalSeverity
                    }
                }
            }
            else {
                $script:htDefenderEmailContacts.($scopeId) = @{
                    subscriptionId                    = $scopeId
                    subscriptionName                  = $scopeDisplayName
                    emails                            = 'n/a'
                    roles                             = 'n/a'
                    alertNotificationsState           = 'n/a'
                    alertNotificationsminimalSeverity = 'n/a'
                }
            }
        }
    }
}
$funcDataCollectionDefenderEmailContacts = $function:dataCollectionDefenderEmailContacts.ToString()

function dataCollectionVNets {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $SubscriptionQuotaId
    )

    $currentTask = "Getting Virtual Networks for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$SubscriptionQuotaId']"
    #https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Network/virtualNetworks?api-version=2022-05-01"
    $method = 'GET'
    $networkResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    if ($networkResult -eq 'someError') {
    }
    else {
        if ($networkResult.Count -gt 0) {
            if ($networkResult -ne 'DisallowedProvider') {
                foreach ($vnet in $networkResult) {
                    $null = $script:arrayVNets.Add($vnet)
                }
            }
        }
    }
}
$funcDataCollectionVNets = $function:dataCollectionVNets.ToString()

function dataCollectionPrivateEndpoints {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $SubscriptionQuotaId
    )

    $currentTask = "Getting Private Endpoints for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$SubscriptionQuotaId']"
    #https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Network/privateEndpoints?api-version=2022-05-01"
    $method = 'GET'
    $privateEndpointsResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection' -unhandledErrorAction Continue

    if ($privateEndpointsResult.Count -gt 0) {
        if ($privateEndpointsResult -ne 'DisallowedProvider') {
            foreach ($pe in $privateEndpointsResult) {
                $null = $script:arrayPrivateEndPoints.Add($pe)
            }
        }
    }
}
$funcDataCollectionPrivateEndpoints = $function:dataCollectionPrivateEndpoints.ToString()

function dataCollectionDiagnosticsSub {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $ChildMgMgPath,
        $ChildMgId,
        $subscriptionQuotaId
    )

    $currentTask = "Getting Diagnostic Settings for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview"
    $method = 'GET'
    $getDiagnosticSettingsSub = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask

    if ($getDiagnosticSettingsSub.Count -eq 0) {
        $null = $script:arrayDiagnosticSettingsMgSub.Add([PSCustomObject]@{
                Scope              = 'Sub'
                ScopeName          = $scopeDisplayName
                ScopeId            = $scopeId
                ScopeMgPath        = $childMgMgPath
                SubMgParent        = $childMgId
                DiagnosticsPresent = 'false'
            })
    }
    else {
        foreach ($diagnosticSetting in $getDiagnosticSettingsSub) {
            $arrayLogs = [System.Collections.ArrayList]@()
            if ($diagnosticSetting.Properties.logs) {
                foreach ($logCategory in $diagnosticSetting.properties.logs) {
                    $null = $arrayLogs.Add([PSCustomObject]@{
                            Category = $logCategory.category
                            Enabled  = $logCategory.enabled
                        })
                }
            }

            $htLogs = @{}
            if ($diagnosticSetting.Properties.logs) {
                foreach ($logCategory in $diagnosticSetting.properties.logs) {
                    if ($logCategory.enabled) {
                        $htLogs.($logCategory.category) = 'true'
                    }
                    else {
                        $htLogs.($logCategory.category) = 'false'
                    }
                }
            }

            if ($diagnosticSetting.Properties.workspaceId) {
                $null = $script:arrayDiagnosticSettingsMgSub.Add([PSCustomObject]@{
                        Scope                  = 'Sub'
                        ScopeName              = $scopeDisplayName
                        ScopeId                = $scopeId
                        ScopeMgPath            = $childMgMgPath
                        SubMgParent            = $childMgId
                        DiagnosticsPresent     = 'true'
                        DiagnosticSettingName  = $diagnosticSetting.name
                        DiagnosticTargetType   = 'LA'
                        DiagnosticTargetId     = $diagnosticSetting.Properties.workspaceId
                        DiagnosticCategories   = $arrayLogs
                        DiagnosticCategoriesHt = $htLogs
                    })
            }
            if ($diagnosticSetting.Properties.storageAccountId) {
                $null = $script:arrayDiagnosticSettingsMgSub.Add([PSCustomObject]@{
                        Scope                  = 'Sub'
                        ScopeName              = $scopeDisplayName
                        ScopeId                = $scopeId
                        ScopeMgPath            = $childMgMgPath
                        SubMgParent            = $childMgId
                        DiagnosticsPresent     = 'true'
                        DiagnosticSettingName  = $diagnosticSetting.name
                        DiagnosticTargetType   = 'SA'
                        DiagnosticTargetId     = $diagnosticSetting.Properties.storageAccountId
                        DiagnosticCategories   = $arrayLogs
                        DiagnosticCategoriesHt = $htLogs
                    })
            }
            if ($diagnosticSetting.Properties.eventHubAuthorizationRuleId) {
                $null = $script:arrayDiagnosticSettingsMgSub.Add([PSCustomObject]@{
                        Scope                  = 'Sub'
                        ScopeName              = $scopeDisplayName
                        ScopeId                = $scopeId
                        ScopeMgPath            = $childMgMgPath
                        SubMgParent            = $childMgId
                        DiagnosticsPresent     = 'true'
                        DiagnosticSettingName  = $diagnosticSetting.name
                        DiagnosticTargetType   = 'EH'
                        DiagnosticTargetId     = $diagnosticSetting.Properties.eventHubAuthorizationRuleId
                        DiagnosticCategories   = $arrayLogs
                        DiagnosticCategoriesHt = $htLogs
                    })
            }
        }
    }
}
$funcDataCollectionDiagnosticsSub = $function:dataCollectionDiagnosticsSub.ToString()

function dataCollectionDiagnosticsMG {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName
    )

    $mgPath = $htManagementGroupsMgPath.($scopeId).pathDelimited
    $currentTask = "Getting Diagnostic Settings for Management Group: '$($scopeDisplayName)' ('$($scopeId)')"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($mgdetail.Name)/providers/microsoft.insights/diagnosticSettings?api-version=2020-01-01-preview"
    $method = 'GET'
    $getDiagnosticSettingsMg = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask

    if ($getDiagnosticSettingsMg -eq 'InvalidResourceType') {
        #skipping until supported
    }
    else {
        if ($getDiagnosticSettingsMg.Count -eq 0) {
            $null = $script:arrayDiagnosticSettingsMgSub.Add([PSCustomObject]@{
                    Scope                     = 'Mg'
                    ScopeName                 = $scopeDisplayName
                    ScopeId                   = $scopeId
                    ScopeMgPath               = $mgPath
                    DiagnosticsPresent        = 'false'
                    DiagnosticsInheritedOrnot = $false
                    DiagnosticsInheritedFrom  = 'none'
                })
        }
        else {
            foreach ($diagnosticSetting in $getDiagnosticSettingsMg) {
                $arrayLogs = [System.Collections.ArrayList]@()
                if ($diagnosticSetting.Properties.logs) {
                    foreach ($logCategory in $diagnosticSetting.properties.logs) {
                        $null = $arrayLogs.Add([PSCustomObject]@{
                                Category = $logCategory.category
                                Enabled  = $logCategory.enabled
                            })
                    }
                }

                $htLogs = @{}
                if ($diagnosticSetting.Properties.logs) {
                    foreach ($logCategory in $diagnosticSetting.properties.logs) {
                        if ($logCategory.enabled) {
                            $htLogs.($logCategory.category) = 'true'
                        }
                        else {
                            $htLogs.($logCategory.category) = 'false'
                        }
                    }
                }

                if ($diagnosticSetting.Properties.workspaceId) {
                    $null = $script:arrayDiagnosticSettingsMgSub.Add([PSCustomObject]@{
                            Scope                     = 'Mg'
                            ScopeName                 = $scopeDisplayName
                            ScopeId                   = $scopeId
                            ScopeMgPath               = $mgPath
                            DiagnosticsPresent        = 'true'
                            DiagnosticsInheritedOrnot = $false
                            DiagnosticsInheritedFrom  = 'none'
                            DiagnosticSettingName     = $diagnosticSetting.name
                            DiagnosticTargetType      = 'LA'
                            DiagnosticTargetId        = $diagnosticSetting.Properties.workspaceId
                            DiagnosticCategories      = $arrayLogs
                            DiagnosticCategoriesHt    = $htLogs
                        })
                }
                if ($diagnosticSetting.Properties.storageAccountId) {
                    $null = $script:arrayDiagnosticSettingsMgSub.Add([PSCustomObject]@{
                            Scope                     = 'Mg'
                            ScopeName                 = $scopeDisplayName
                            ScopeId                   = $scopeId
                            ScopeMgPath               = $mgPath
                            DiagnosticsPresent        = 'true'
                            DiagnosticsInheritedOrnot = $false
                            DiagnosticsInheritedFrom  = 'none'
                            DiagnosticSettingName     = $diagnosticSetting.name
                            DiagnosticTargetType      = 'SA'
                            DiagnosticTargetId        = $diagnosticSetting.Properties.storageAccountId
                            DiagnosticCategories      = $arrayLogs
                            DiagnosticCategoriesHt    = $htLogs
                        })
                }
                if ($diagnosticSetting.Properties.eventHubAuthorizationRuleId) {
                    $null = $script:arrayDiagnosticSettingsMgSub.Add([PSCustomObject]@{
                            Scope                     = 'Mg'
                            ScopeName                 = $scopeDisplayName
                            ScopeId                   = $scopeId
                            ScopeMgPath               = $mgPath
                            DiagnosticsPresent        = 'true'
                            DiagnosticsInheritedOrnot = $false
                            DiagnosticsInheritedFrom  = 'none'
                            DiagnosticSettingName     = $diagnosticSetting.name
                            DiagnosticTargetType      = 'EH'
                            DiagnosticTargetId        = $diagnosticSetting.Properties.eventHubAuthorizationRuleId
                            DiagnosticCategories      = $arrayLogs
                            DiagnosticCategoriesHt    = $htLogs
                        })
                }
            }
        }
    }
}
$funcDataCollectionDiagnosticsMG = $function:dataCollectionDiagnosticsMG.ToString()

function dataCollectionStorageAccounts {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $ChildMgMgPath,
        $ChildMgParentNameChainDelimited,
        $subscriptionQuotaId
    )

    $currentTask = "Getting Storage Accounts for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Storage/storageAccounts?api-version=2021-09-01"
    $method = 'GET'
    $storageAccountsSubscriptionResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    if ($storageAccountsSubscriptionResult -ne 'DisallowedProvider') {
        foreach ($storageAccount in $storageAccountsSubscriptionResult) {

            $dtisostart = Get-Date (Get-Date).AddHours(-1).ToUniversalTime() -UFormat '+%Y-%m-%dT%H:%M:%S.000Z'
            $dtisoend = Get-Date (Get-Date).ToUniversalTime() -UFormat '+%Y-%m-%dT%H:%M:%S.000Z'
            $currentTask = "Getting Storage Account '$($storageAccount.name)' UsedCapacity ('$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId'])"
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)$($storageAccount.id)/providers/Microsoft.Insights/metrics?timespan=$($dtisostart)/$($dtisoend)&metricnames=UsedCapacity&aggregation=Average&api-version=2021-05-01"
            $method = 'GET'
            $storageAccountUsedCapacity = $null
            $storageAccountUsedCapacity = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection' -unhandledErrorAction Continue

            $usedCapacity = 'n/a'
            if ($storageAccountUsedCapacity.Count -gt 0) {
                if (-not [string]::IsNullOrWhiteSpace($storageAccountUsedCapacity.timeseries.data.average)) {
                    $usedCapacity = [decimal]$storageAccountUsedCapacity.timeseries.data.average / 1024 / 1024 / 1024
                }
            }

            $obj = [System.Collections.ArrayList]@()
            $null = $obj.Add([PSCustomObject]@{
                    SA             = $storageAccount
                    SAUsedCapacity = $usedCapacity
                })
            $null = $script:storageAccounts.Add($obj)
        }
    }

}
$funcDataCollectionStorageAccounts = $function:dataCollectionStorageAccounts.ToString()

function dataCollectionResources {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $ChildMgMgPath,
        $ChildMgParentNameChainDelimited,
        $subscriptionQuotaId
    )

    #region resources LIST
    $currentTask = "Getting Resources for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/resources?`$expand=createdTime,changedTime,properties&api-version=2021-04-01"
    $method = 'GET'
    $resourcesSubscriptionResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'
    #Write-Host 'arm resList count:'$resourcesSubscriptionResult.Count
    #endregion resources LIST

    #region resources GET
    if ($resourcesSubscriptionResult.Count -gt 0) {
        $arrayResourcesWithProperties = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        $resourcesSubscriptionResult | ForEach-Object -Parallel {
            $resource = $_

            #region using
            $arrayResourcesWithProperties = $using:arrayResourcesWithProperties
            $htResourceProvidersRef = $using:htResourceProvidersRef
            $arrayPrivateEndPointsFromResourceProperties = $using:arrayPrivateEndPointsFromResourceProperties
            $htAvailablePrivateEndpointTypes = $using:htAvailablePrivateEndpointTypes
            $htResourcePropertiesConvertfromJSONFailed = $using:htResourcePropertiesConvertfromJSONFailed
            $scopeId = $using:scopeId
            $scopeDisplayName = $using:scopeDisplayName
            $ChildMgParentNameChainDelimited = $using:ChildMgParentNameChainDelimited
            $azAPICallConf = $using:azAPICallConf
            #$htResourcesWithProperties = $using:htResourcesWithProperties
            #endregion using

            if ($htAvailablePrivateEndpointTypes.(($resource.type).ToLower())) {
                #Write-Host "$($resource.type) in `$htAvailablePrivateEndpointTypes"
                if ($htResourceProvidersRef.($resource.type)) {
                    if ($htResourceProvidersRef.($resource.type).APIDefault) {
                        $apiVersionToUse = $htResourceProvidersRef.($resource.type).APIDefault
                        $apiRef = 'default'
                    }
                    else {
                        $apiVersionToUse = $htResourceProvidersRef.($resource.type).APILatest
                        $apiRef = 'latest'
                    }

                    $currentTask = "Getting Resource Properties API-version: '$apiVersionToUse' ($apiRef); ResourceType: '$($resource.type)'; ResourceId: '$($resource.id)'"
                    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)$($resource.id)?api-version=$apiVersionToUse"
                    $method = 'GET'
                    $resourceResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection' -listenOn Content -unhandledErrorAction Continue

                    if ($resourceResult -ne 'ResourceOrResourcegroupNotFound' -and $resourceResult -ne 'convertfromJSONError') {
                        $null = $script:arrayResourcesWithProperties.Add($resourceResult)
                        #$script:htResourcesWithProperties.($resourceResult.id) = $resourceResult
                        if ($resourceResult.properties.privateEndpointConnections.Count -gt 0) {
                            foreach ($privateEndpointConnection in $resourceResult.properties.privateEndpointConnections) {
                                $resourceResultIdSplit = $resourceResult.id -split '/'
                                $null = $script:arrayPrivateEndPointsFromResourceProperties.Add([PSCustomObject]@{
                                        ResourceName              = $resourceResult.name
                                        ResourceType              = $resourceResult.type
                                        ResourceId                = $resourceResult.id
                                        ResourceResourceGroup     = $resourceResultIdSplit[4]
                                        ResourceSubscriptionId    = $scopeId
                                        ResourceSubscriptionName  = $scopeDisplayName
                                        ResourceMGPath            = $ChildMgParentNameChainDelimited
                                        privateEndpointConnection = $privateEndpointConnection
                                    })
                            }
                        }
                    }
                    else {
                        if ($resourceResult -eq 'convertfromJSONError') {
                            $script:htResourcePropertiesConvertfromJSONFailed.($resource.id) = @{}
                        }
                    }
                }
                else {
                    Write-Host "[Azure Governance Visualizer] Please file an issue at the Azure Governance Visualizer GitHub repository (aka.ms/AzGovViz) and provide this information (scrub subscription Id and company identifyable names): No API-version matches! ResourceType: '$($resource.type)'; ResourceId: '$($resource.id)' - Thank you!" -ForegroundColor DarkRed
                }
            }
            else {
                #Write-Host "$($resource.type) not in `$htAvailablePrivateEndpointTypes"
            }

        } -ThrottleLimit $azAPICallConf['htParameters'].ThrottleLimit
    }
    #Write-Host 'arm resGet count:' $arrayResourcesWithProperties.Count
    #endregion resources GET

    # if ($resourcesSubscriptionResult.Count -ne $arrayResourcesWithProperties.Count) {
    #     Write-Host " FYI: Getting Resources for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']  - ARM list count: $($resourcesSubscriptionResult.Count); ARG get count: $($arrayResourcesWithProperties.Count)"
    # }

    #region PSRule
    if ($azAPICallConf['htParameters'].DoPSRule -eq $true) {
        if ($resourcesSubscriptionResult.Count -gt 0) {

            $startPSRule = Get-Date
            try {
                <#
                $path = (Get-Module PSRule.Rules.Azure -ListAvailable | Sort-Object Version -Descending -Top 1).ModuleBase
                Write-Host "Import-Module (Join-Path $path -ChildPath 'PSRule.Rules.Azure-nodeps.psd1')"
                Import-Module (Join-Path $path -ChildPath 'PSRule.Rules.Azure-nodeps.psd1')
                #>
                if ($azAPICallConf['htParameters'].PSRuleFailedOnly -eq $true) {
                    $psruleResults = $arrayResourcesWithProperties | Invoke-PSRule -Module psrule.rules.Azure -As Detail -Culture en-us -WarningAction Ignore -ErrorAction SilentlyContinue -Outcome Fail, Error
                }
                else {
                    $psruleResults = $arrayResourcesWithProperties | Invoke-PSRule -Module psrule.rules.Azure -As Detail -Culture en-us -WarningAction Ignore -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-Host "   Please report 'PSRule for Azure' error '$($scopeDisplayName)' ('$scopeId'): $_"
            }

            $endPSRule = Get-Date
            $durationPSRule = $((New-TimeSpan -Start $startPSRule -End $endPSRule).TotalSeconds)

            $null = $script:arrayPSRuleTracking.Add([PSCustomObject]@{
                    subscriptionId = $scopeId
                    duration       = $durationPSRule
                })

            if ($psruleResults.Count -gt 0) {
                foreach ($psRuleResult in $psRuleResults) {
                    $null = $script:arrayPSRule.Add([PSCustomObject]@{
                            resourceType   = $psRuleResult.TargetType
                            subscriptionId = $scopeId
                            mgPath         = $ChildMgParentNameChainDelimited
                            resourceId     = $psRuleResult.TargetObject.id
                            pillar         = $psRuleResult.Info.Annotations.pillar
                            category       = $psRuleResult.Info.Annotations.category
                            severity       = $psRuleResult.Info.Annotations.severity
                            rule           = $psRuleResult.Info.DisplayName
                            description    = $psRuleResult.Info.Description
                            recommendation = $psRuleResult.Info.Recommendation
                            link           = $psRuleResult.Info.Annotations.'online version'
                            result         = $psRuleResult.Outcome
                            errorMsg       = $psRuleResult.Error.Message
                        })
                }
            }
        }
    }
    #endregion PSRule

    foreach ($resourceTypeLocation in ($resourcesSubscriptionResult | Group-Object -Property type, location)) {
        $null = $script:resourcesAll.Add([PSCustomObject]@{
                subscriptionId = $scopeId
                type           = ($resourceTypeLocation.values[0]).ToLower()
                location       = ($resourceTypeLocation.values[1]).ToLower()
                count_         = $resourceTypeLocation.Count
            })
    }

    foreach ($resourceType in ($resourcesSubscriptionResult | Group-Object -Property type)) {
        if (-not $htResourceTypesUniqueResource.(($resourceType.name).ToLower())) {
            $script:htResourceTypesUniqueResource.(($resourceType.name).ToLower()) = @{}
            $script:htResourceTypesUniqueResource.(($resourceType.name).ToLower()).resourceId = $resourceType.Group.Id | Select-Object -First 1
        }
    }

    $startSubResourceIdsThis = Get-Date

    <# Build the $JSONcafResourceNaming #pending PR https://github.com/MicrosoftDocs/cloud-adoption-framework/pull/916
    $arrayCAFNamingConvention = [System.Collections.ArrayList]@()
    $htCAFNamingConvention = @{}
    #$cafNamingFromFile = Get-Content -Path .\cafNaming.md -Encoding utf8
    $CAFFileName = 'resource-abbreviations.md'
    Invoke-webrequest -OutFile .\$($CAFFileName) -URI "https://raw.githubusercontent.com/MicrosoftDocs/cloud-adoption-framework/main/docs/ready/azure-best-practices/resource-abbreviations.md"
    $cafNamingFromFile = Get-Content -Path .\$($CAFFileName) -Encoding utf8
    $cafNamingFromFile.count
    foreach ($line in $cafNamingFromFile) {
        #$line
        if ($line -match "microsoft.") {
            $tranformed = $line -replace '`' -split " \| "
            $friendlyName =  $($tranformed[0] -replace "\| ")
            $resourceType = $($tranformed[1])
            $namingConvention = $($tranformed[2] -replace " \|" -replace "\|")
            $null = $arrayCAFNamingConvention.Add([PSCustomObject]@{
                resourceType = $resourceType
                friendlyName = $friendlyName
                namingConvention = $namingConvention
            })
        }
    }

    $htCAFNamingConvention = [ordered]@{}
    $arrayCAFNamingConventionGroupedByType = $arrayCAFNamingConvention | Sort-Object -Property resourceType | Group-Object -Property resourceType
    foreach ($entry in $arrayCAFNamingConventionGroupedByType){
        $htCAFNamingConvention.($entry.name) = @{}
        $htCAFNamingConvention.($entry.name).friendlyName = $entry.group.friendlyName
        $htCAFNamingConvention.($entry.name).namingConvention = $entry.group.namingConvention
    }
    $htCAFNamingConvention | ConvertTo-Json
#>

    $JSONcafResourceNaming = @'
    {
        "Microsoft.AnalysisServices/servers": {
          "friendlyName": "Azure Analysis Services server",
          "namingConvention": "as"
        },
        "Microsoft.ApiManagement/service": {
          "friendlyName": "API management service instance",
          "namingConvention": "apim-"
        },
        "Microsoft.AppConfiguration/configurationStores": {
          "friendlyName": "App Configuration store",
          "namingConvention": "appcs-"
        },
        "Microsoft.Authorization/policyDefinitions": {
          "friendlyName": "Policy definition",
          "namingConvention": "policy-"
        },
        "Microsoft.Automation/automationAccounts": {
          "friendlyName": "Automation account",
          "namingConvention": "aa-"
        },
        "Microsoft.Blueprint/blueprints": {
          "friendlyName": "Blueprint",
          "namingConvention": "bp-"
        },
        "Microsoft.Blueprint/blueprints/artifacts": {
          "friendlyName": "Blueprint assignment",
          "namingConvention": "bpa-"
        },
        "Microsoft.Cache/Redis": {
          "friendlyName": "Azure Cache for Redis instance",
          "namingConvention": "redis-"
        },
        "Microsoft.Cdn/profiles": {
          "friendlyName": "CDN profile",
          "namingConvention": "cdnp-"
        },
        "Microsoft.Cdn/profiles/endpoints": {
          "friendlyName": "CDN endpoint",
          "namingConvention": "cdne-"
        },
        "Microsoft.CognitiveServices/accounts": {
          "friendlyName": "Azure Cognitive Services",
          "namingConvention": "cog-"
        },
        "Microsoft.Compute/availabilitySets": {
          "friendlyName": "Availability set",
          "namingConvention": "avail-"
        },
        "Microsoft.Compute/cloudServices": {
          "friendlyName": "Cloud service",
          "namingConvention": "cld-"
        },
        "Microsoft.Compute/diskEncryptionSets": {
          "friendlyName": "Disk encryption set",
          "namingConvention": "des"
        },
        "Microsoft.Compute/disks": {
          "friendlyName": [
            "Managed disk (data)",
            "Managed disk (OS)"
          ],
          "namingConvention": [
            "disk",
            "osdisk"
          ]
        },
        "Microsoft.Compute/galleries": {
          "friendlyName": "Gallery",
          "namingConvention": "gal"
        },
        "Microsoft.Compute/snapshots": {
          "friendlyName": "Snapshot",
          "namingConvention": "snap-"
        },
        "Microsoft.Compute/virtualMachines": {
          "friendlyName": "Virtual machine",
          "namingConvention": "vm"
        },
        "Microsoft.Compute/virtualMachineScaleSets": {
          "friendlyName": "Virtual machine scale set",
          "namingConvention": "vmss-"
        },
        "Microsoft.ContainerInstance/containerGroups": {
          "friendlyName": "Container instance",
          "namingConvention": "ci"
        },
        "Microsoft.ContainerRegistry/registries": {
          "friendlyName": "Container registry",
          "namingConvention": "cr"
        },
        "Microsoft.ContainerService/managedClusters": {
          "friendlyName": "AKS cluster",
          "namingConvention": "aks-"
        },
        "Microsoft.Databricks/workspaces": {
          "friendlyName": "Azure Databricks workspace",
          "namingConvention": "dbw-"
        },
        "Microsoft.DataFactory/factories": {
          "friendlyName": "Azure Data Factory",
          "namingConvention": "adf-"
        },
        "Microsoft.DataLakeAnalytics/accounts": {
          "friendlyName": "Data Lake Analytics account",
          "namingConvention": "dla"
        },
        "Microsoft.DataLakeStore/accounts": {
          "friendlyName": "Data Lake Store account",
          "namingConvention": "dls"
        },
        "Microsoft.DataMigration/services": {
          "friendlyName": "Database Migration Service instance",
          "namingConvention": "dms-"
        },
        "Microsoft.DataProtection/BackupVaults": {
          "friendlyName": "Backup vault",
          "namingConvention": "bv-"
        },
        "Microsoft.DBforMySQL/servers": {
          "friendlyName": "MySQL database",
          "namingConvention": "mysql-"
        },
        "Microsoft.DBforPostgreSQL/servers": {
          "friendlyName": "PostgreSQL database",
          "namingConvention": "psql-"
        },
        "Microsoft.Devices/IotHubs": {
          "friendlyName": "IoT hub",
          "namingConvention": "iot-"
        },
        "Microsoft.Devices/provisioningServices": {
          "friendlyName": "Provisioning services",
          "namingConvention": "provs-"
        },
        "Microsoft.Devices/provisioningServices/certificates": {
          "friendlyName": "Provisioning services certificate",
          "namingConvention": "pcert-"
        },
        "Microsoft.DocumentDB/databaseAccounts/sqlDatabases": {
          "friendlyName": "Azure Cosmos DB database",
          "namingConvention": "cosmos-"
        },
        "Microsoft.EventGrid/domains": {
          "friendlyName": "Event Grid domain",
          "namingConvention": "evgd-"
        },
        "Microsoft.EventGrid/domains/topics": {
          "friendlyName": "Event Grid topic",
          "namingConvention": "evgt-"
        },
        "Microsoft.EventGrid/eventSubscriptions": {
          "friendlyName": "Event Grid subscriptions",
          "namingConvention": "evgs-"
        },
        "Microsoft.EventHub/namespaces": {
          "friendlyName": "Event Hubs namespace",
          "namingConvention": "evhns-"
        },
        "Microsoft.EventHub/namespaces/eventHubs": {
          "friendlyName": "Event hub",
          "namingConvention": "evh-"
        },
        "Microsoft.HDInsight/clusters": {
          "friendlyName": [
            "HDInsight - Hadoop cluster",
            "HDInsight - Kafka cluster",
            "HDInsight - Spark cluster",
            "HDInsight - Storm cluster",
            "HDInsight - ML Services cluster",
            "HDInsight - HBase cluster"
          ],
          "namingConvention": [
            "hadoop-",
            "kafka-",
            "spark-",
            "storm-",
            "mls-",
            "hbase-"
          ]
        },
        "Microsoft.HybridCompute/machines": {
          "friendlyName": "Azure Arc enabled server",
          "namingConvention": "arcs-"
        },
        "Microsoft.Insights/actionGroups": {
          "friendlyName": "Azure Monitor action group",
          "namingConvention": "ag-"
        },
        "Microsoft.Insights/components": {
          "friendlyName": "Application Insights",
          "namingConvention": "appi-"
        },
        "Microsoft.KeyVault/vaults": {
          "friendlyName": "Key vault",
          "namingConvention": "kv-"
        },
        "Microsoft.Kubernetes/connectedClusters": {
          "friendlyName": "Azure Arc enabled Kubernetes cluster",
          "namingConvention": "arck"
        },
        "Microsoft.Kusto/clusters": {
          "friendlyName": "Azure Data Explorer cluster",
          "namingConvention": "dec"
        },
        "Microsoft.Kusto/clusters/databases": {
          "friendlyName": "Azure Data Explorer cluster database",
          "namingConvention": "dedb"
        },
        "Microsoft.Logic/integrationAccounts": {
          "friendlyName": "Integration account",
          "namingConvention": "ia-"
        },
        "Microsoft.Logic/workflows": {
          "friendlyName": "Logic apps",
          "namingConvention": "logic-"
        },
        "Microsoft.MachineLearningServices/workspaces": {
          "friendlyName": "Azure Machine Learning workspace",
          "namingConvention": "mlw-"
        },
        "Microsoft.ManagedIdentity/userAssignedIdentities": {
          "friendlyName": "Managed Identity",
          "namingConvention": "id-"
        },
        "Microsoft.Management/managementGroups": {
          "friendlyName": "Management group",
          "namingConvention": "mg-"
        },
        "Microsoft.Migrate/assessmentProjects": {
          "friendlyName": "Azure Migrate project",
          "namingConvention": "migr-"
        },
        "Microsoft.Network/applicationGateways": {
          "friendlyName": "Application gateway",
          "namingConvention": "agw-"
        },
        "Microsoft.Network/applicationSecurityGroups": {
          "friendlyName": "Application security group (ASG)",
          "namingConvention": "asg-"
        },
        "Microsoft.Network/azureFirewalls": {
          "friendlyName": "Firewall",
          "namingConvention": "afw-"
        },
        "Microsoft.Network/bastionHosts": {
          "friendlyName": "Bastion",
          "namingConvention": "bas-"
        },
        "Microsoft.Network/connections": {
          "friendlyName": "Connections",
          "namingConvention": "con-"
        },
        "Microsoft.Network/dnsZones": {
          "friendlyName": "DNS",
          "namingConvention": "dnsz-"
        },
        "Microsoft.Network/expressRouteCircuits": {
          "friendlyName": "ExpressRoute circuit",
          "namingConvention": "erc-"
        },
        "Microsoft.Network/firewallPolicies": {
          "friendlyName": [
            "Web Application Firewall (WAF) policy",
            "Firewall policy"
          ],
          "namingConvention": [
            "waf",
            "afwp-"
          ]
        },
        "Microsoft.Network/firewallPolicies/ruleGroups": {
          "friendlyName": "Web Application Firewall (WAF) policy rule group",
          "namingConvention": "wafrg"
        },
        "Microsoft.Network/frontDoors": {
          "friendlyName": "Front Door instance",
          "namingConvention": "fd-"
        },
        "Microsoft.Network/frontdoorWebApplicationFirewallPolicies": {
          "friendlyName": "Front Door firewall policy",
          "namingConvention": "fdfp-"
        },
        "Microsoft.Network/loadBalancers": {
          "friendlyName": [
            "Load balancer (external)",
            "Load balancer (internal)"
          ],
          "namingConvention": [
            "lbe-",
            "lbi-"
          ]
        },
        "Microsoft.Network/loadBalancers/inboundNatRules": {
          "friendlyName": "Load balancer rule",
          "namingConvention": "rule-"
        },
        "Microsoft.Network/localNetworkGateways": {
          "friendlyName": "Local network gateway",
          "namingConvention": "lgw-"
        },
        "Microsoft.Network/natGateways": {
          "friendlyName": "NAT gateway",
          "namingConvention": "ng-"
        },
        "Microsoft.Network/networkInterfaces": {
          "friendlyName": "Network interface (NIC)",
          "namingConvention": "nic-"
        },
        "Microsoft.Network/networkSecurityGroups": {
          "friendlyName": "Network security group (NSG)",
          "namingConvention": "nsg-"
        },
        "Microsoft.Network/networkSecurityGroups/securityRules": {
          "friendlyName": "Network security group (NSG) security rules",
          "namingConvention": "nsgsr-"
        },
        "Microsoft.Network/networkWatchers": {
          "friendlyName": "Network Watcher",
          "namingConvention": "nw-"
        },
        "Microsoft.Network/privateDnsZones": {
          "friendlyName": "DNS zone",
          "namingConvention": "pdnsz-"
        },
        "Microsoft.Network/privateLinkServices": {
          "friendlyName": "Private Link",
          "namingConvention": "pl-"
        },
        "Microsoft.Network/publicIPAddresses": {
          "friendlyName": "Public IP address",
          "namingConvention": "pip-"
        },
        "Microsoft.Network/publicIPPrefixes": {
          "friendlyName": "Public IP address prefix",
          "namingConvention": "ippre-"
        },
        "Microsoft.Network/routeFilters": {
          "friendlyName": "Route filter",
          "namingConvention": "rf-"
        },
        "Microsoft.Network/routeTables": {
          "friendlyName": "Route table",
          "namingConvention": "rt-"
        },
        "Microsoft.Network/routeTables/routes": {
          "friendlyName": "User defined route (UDR)",
          "namingConvention": "udr-"
        },
        "Microsoft.Network/trafficManagerProfiles": {
          "friendlyName": "Traffic Manager profile",
          "namingConvention": "traf-"
        },
        "Microsoft.Network/virtualNetworkGateways": {
          "friendlyName": "Virtual network gateway",
          "namingConvention": "vgw-"
        },
        "Microsoft.Network/virtualNetworks": {
          "friendlyName": "Virtual network",
          "namingConvention": "vnet-"
        },
        "Microsoft.Network/virtualNetworks/subnets": {
          "friendlyName": "Virtual network subnet",
          "namingConvention": "snet-"
        },
        "Microsoft.Network/virtualNetworks/virtualNetworkPeerings": {
          "friendlyName": "Virtual network peering",
          "namingConvention": "peer-"
        },
        "Microsoft.Network/virtualWans": {
          "friendlyName": "Virtual WAN",
          "namingConvention": "vwan-"
        },
        "Microsoft.Network/vpnGateways": {
          "friendlyName": "VPN Gateway",
          "namingConvention": "vpng-"
        },
        "Microsoft.Network/vpnGateways/vpnConnections": {
          "friendlyName": "VPN connection",
          "namingConvention": "vcn-"
        },
        "Microsoft.Network/vpnGateways/vpnSites": {
          "friendlyName": "VPN site",
          "namingConvention": "vst-"
        },
        "Microsoft.NotificationHubs/namespaces": {
          "friendlyName": "Notification Hubs namespace",
          "namingConvention": "ntfns-"
        },
        "Microsoft.NotificationHubs/namespaces/notificationHubs": {
          "friendlyName": "Notification Hubs",
          "namingConvention": "ntf-"
        },
        "Microsoft.OperationalInsights/workspaces": {
          "friendlyName": "Log Analytics workspace",
          "namingConvention": "log-"
        },
        "Microsoft.PowerBIDedicated/capacities": {
          "friendlyName": "Power BI Embedded",
          "namingConvention": "pbi-"
        },
        "Microsoft.Purview/accounts": {
          "friendlyName": "Azure Purview instance",
          "namingConvention": "pview-"
        },
        "Microsoft.RecoveryServices/vaults": {
          "friendlyName": "Recovery Services vault",
          "namingConvention": "rsv-"
        },
        "Microsoft.RecoveryServices/vaults/backupPolicies": {
          "friendlyName": "Recovery Services vault backup policy",
          "namingConvention": "rsvbp-"
        },
        "Microsoft.Resources/resourceGroups": {
          "friendlyName": "Resource group",
          "namingConvention": "rg-"
        },
        "Microsoft.Search/searchServices": {
          "friendlyName": "Azure Cognitive Search",
          "namingConvention": "srch-"
        },
        "Microsoft.ServiceBus/namespaces": {
          "friendlyName": "Service Bus",
          "namingConvention": "sb-"
        },
        "Microsoft.ServiceBus/namespaces/queues": {
          "friendlyName": "Service Bus queue",
          "namingConvention": "sbq-"
        },
        "Microsoft.ServiceBus/namespaces/topics": {
          "friendlyName": "Service Bus topic",
          "namingConvention": "sbt-"
        },
        "Microsoft.serviceEndPointPolicies": {
          "friendlyName": "Service endpoint",
          "namingConvention": "se-"
        },
        "Microsoft.ServiceFabric/clusters": {
          "friendlyName": "Service Fabric cluster",
          "namingConvention": "sf-"
        },
        "Microsoft.SignalRService/SignalR": {
          "friendlyName": "SignalR",
          "namingConvention": "sigr"
        },
        "Microsoft.Sql/managedInstances": {
          "friendlyName": "SQL Managed Instance",
          "namingConvention": "sqlmi-"
        },
        "Microsoft.Sql/servers": {
          "friendlyName": [
            "Azure SQL Data Warehouse",
            "Azure SQL Database server"
          ],
          "namingConvention": [
            "sqldw-",
            "sql-"
          ]
        },
        "Microsoft.Sql/servers/databases": {
          "friendlyName": [
            "SQL Server Stretch Database",
            "Azure SQL database"
          ],
          "namingConvention": [
            "sqlstrdb-",
            "sqldb-"
          ]
        },
        "Microsoft.Storage/storageAccounts": {
          "friendlyName": [
            "Storage account",
            "VM storage account"
          ],
          "namingConvention": [
            "st",
            "stvm"
          ]
        },
        "Microsoft.StorSimple/managers": {
          "friendlyName": "Azure StorSimple",
          "namingConvention": "ssimp"
        },
        "Microsoft.StreamAnalytics/cluster": {
          "friendlyName": "Azure Stream Analytics",
          "namingConvention": "asa-"
        },
        "Microsoft.Synapse/workspaces": {
          "friendlyName": [
            "Azure Synapse Analytics Workspaces",
            "Azure Synapse Analytics"
          ],
          "namingConvention": [
            "synw",
            "syn"
          ]
        },
        "Microsoft.Synapse/workspaces/sqlPools": {
          "friendlyName": [
            "Azure Synapse Analytics Spark Pool",
            "Azure Synapse Analytics SQL Dedicated Pool"
          ],
          "namingConvention": [
            "synsp",
            "syndp"
          ]
        },
        "Microsoft.TimeSeriesInsights/environments": {
          "friendlyName": "Time Series Insights environment",
          "namingConvention": "tsi-"
        },
        "Microsoft.Web/serverFarms": {
          "friendlyName": "App Service plan",
          "namingConvention": "plan-"
        },
        "Microsoft.Web/sites": {
          "friendlyName": [
            "Web app",
            "Function app",
            "App Service environment"
          ],
          "namingConvention": [
            "app-",
            "func-",
            "ase-"
          ]
        },
        "Microsoft.Web/staticSites": {
          "friendlyName": "Static web app",
          "namingConvention": "stapp-"
        }
      }
'@
    $htCAFNamingConvention = $JSONcafResourceNaming | ConvertFrom-Json

    $resourcesSubscriptionResultGroupedByType = $resourcesSubscriptionResult | Group-Object -Property type
    foreach ($entry in $resourcesSubscriptionResultGroupedByType) {

        if ($htCAFNamingConvention.($entry.Name)) {
            $doCAFResourceNamingCheck = $true
            $namingConvention = $htCAFNamingConvention.($entry.Name).namingConvention
            $namingConventionFriendlyName = $htCAFNamingConvention.($entry.Name).friendlyName
        }
        else {
            $doCAFResourceNamingCheck = $false
            $namingConvention = 'n/a'
            $namingConventionFriendlyName = 'n/a'
        }

        foreach ($resource in ($entry.Group)) {

            if ($doCAFResourceNamingCheck) {
                $cafResourceNamingCheck = 'failed'
                $applicableNaming = $namingConvention -join "$CsvDelimiterOpposite "
                foreach ($naming in $namingConvention) {
                    if (($resource.name).StartsWith($naming, 'CurrentCultureIgnoreCase')) {
                        $cafResourceNamingCheck = 'passed'
                        #$applicableNaming = $naming
                    }
                }
            }
            else {
                $cafResourceNamingCheck = 'n/a'
                $applicableNaming = 'n/a'
            }
            $null = $script:resourcesIdsAll.Add([PSCustomObject]@{
                    subscriptionId                = $scopeId
                    mgPath                        = $childMgMgPath
                    type                          = ($resource.type).ToLower()
                    id                            = ($resource.Id).ToLower()
                    name                          = ($resource.name).ToLower()
                    location                      = ($resource.location).ToLower()
                    tags                          = ($resource.tags)
                    createdTime                   = ($resource.createdTime)
                    changedTime                   = ($resource.changedTime)
                    cafResourceNamingResult       = $cafResourceNamingCheck
                    cafResourceNaming             = $applicableNaming
                    cafResourceNamingFriendlyName = $namingConventionFriendlyName -join "$CSVDelimiterOpposite "
                })

            if ($resource.identity.userAssignedIdentities) {
                $resource.identity.userAssignedIdentities.psobject.properties | ForEach-Object {
                    if ((-not [string]::IsNullOrEmpty($resource.Id)) -and (-not [string]::IsNullOrEmpty($_.Value.principalId))) {
                        $hlp = ($_.Name.split('/'))
                        $hlpMiSubId = $hlp[2]
                        if ($scopeId -eq $hlpMiSubId) {
                            $miCrossSubscription = $false
                        }
                        else {
                            $miCrossSubscription = $true
                        }
                        $null = $script:arrayUserAssignedIdentities4Resources.Add([PSCustomObject]@{
                                resourceId                = $resource.Id
                                resourceName              = $resource.name
                                resourceMgPath            = $childMgMgPath
                                resourceSubscriptionName  = $scopeDisplayName
                                resourceSubscriptionId    = $scopeId
                                resourceResourceGroupName = ($resource.Id -split ('/'))[4]
                                resourceType              = $resource.type
                                resourceLocation          = $resource.location
                                miPrincipalId             = $_.Value.principalId
                                miClientId                = $_.Value.clientId
                                miMgPath                  = $htSubscriptionsMgPath.($hlpMiSubId).pathDelimited
                                miSubscriptionName        = $htSubscriptionsMgPath.($hlpMiSubId).DisplayName
                                miSubscriptionId          = $hlpMiSubId
                                miResourceGroupName       = $hlp[4]
                                miResourceId              = $_.Name
                                miResourceName            = $_.Name -replace '.*/'
                                miCrossSubscription       = $miCrossSubscription
                            })
                    }
                }
            }
        }
    }
    $endSubResourceIdsThis = Get-Date
    $null = $script:arraySubResourcesAddArrayDuration.Add([PSCustomObject]@{
            sub         = $scopeId
            DurationSec = (New-TimeSpan -Start $startSubResourceIdsThis -End $endSubResourceIdsThis).TotalSeconds
        })


    #resourceTags
    $script:htSubscriptionTagList.($scopeId) = @{}
    $script:htSubscriptionTagList.($scopeId).Resource = @{}
    foreach ($tags in ($resourcesSubscriptionResult.where( { $_.Tags -and -not [String]::IsNullOrWhiteSpace($_.Tags) } )).Tags) {
        foreach ($tagName in $tags.PSObject.Properties.Name) {
            #resource
            if ($htSubscriptionTagList.($scopeId).Resource.ContainsKey($tagName)) {
                $script:htSubscriptionTagList.($scopeId).Resource."$tagName" += 1
            }
            else {
                $script:htSubscriptionTagList.($scopeId).Resource."$tagName" = 1
            }

            #resourceAll
            if ($htAllTagList.Resource.ContainsKey($tagName)) {
                $script:htAllTagList.Resource."$tagName" += 1
            }
            else {
                $script:htAllTagList.Resource."$tagName" = 1
            }

            #all
            if ($htAllTagList.AllScopes.ContainsKey($tagName)) {
                $script:htAllTagList.AllScopes."$tagName" += 1
            }
            else {
                $script:htAllTagList.AllScopes."$tagName" = 1
            }
        }
    }
}
$funcDataCollectionResources = $function:dataCollectionResources.ToString()

function dataCollectionResourceGroups {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $subscriptionQuotaId
    )

    #https://management.azure.com/subscriptions/{subscriptionId}/resourcegroups?api-version=2020-06-01
    $currentTask = "Getting ResourceGroups for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/resourcegroups?api-version=2021-04-01"
    $method = 'GET'
    $resourceGroupsSubscriptionResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    $null = $script:resourceGroupsAll.Add([PSCustomObject]@{
            subscriptionId = $scopeId
            count_         = ($resourceGroupsSubscriptionResult).count
        })

    #resourceGroupTags
    if ($azAPICallConf['htParameters'].NoResources -eq $true) {
        $script:htSubscriptionTagList.($scopeId) = @{}
    }

    $script:htSubscriptionTagList.($scopeId).ResourceGroup = @{}
    foreach ($tags in ($resourceGroupsSubscriptionResult.where( { $_.Tags -and -not [String]::IsNullOrWhiteSpace($_.Tags) } )).Tags) {
        foreach ($tagName in $tags.PSObject.Properties.Name) {

            #resource
            if ($htSubscriptionTagList.($scopeId).ResourceGroup.ContainsKey($tagName)) {
                $script:htSubscriptionTagList.($scopeId).ResourceGroup."$tagName" += 1
            }
            else {
                $script:htSubscriptionTagList.($scopeId).ResourceGroup."$tagName" = 1
            }

            #resourceAll
            if ($htAllTagList.ResourceGroup.ContainsKey($tagName)) {
                $script:htAllTagList.ResourceGroup."$tagName" += 1
            }
            else {
                $script:htAllTagList.ResourceGroup."$tagName" = 1
            }

            #all
            if ($htAllTagList.AllScopes.ContainsKey($tagName)) {
                $script:htAllTagList.AllScopes."$tagName" += 1
            }
            else {
                $script:htAllTagList.AllScopes."$tagName" = 1
            }
        }
    }
}
$funcDataCollectionResourceGroups = $function:dataCollectionResourceGroups.ToString()

function dataCollectionResourceProviders {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayname,
        $subscriptionQuotaId
    )

    ($script:htResourceProvidersAll).($scopeId) = @{}
    $currentTask = "Getting ResourceProviders for Subscription: '$($scopeDisplayname)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers?api-version=2019-10-01"
    $method = 'GET'
    $resProvResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    ($script:htResourceProvidersAll).($scopeId).Providers = $resProvResult | Select-Object namespace, registrationState
}
$funcDataCollectionResourceProviders = $function:dataCollectionResourceProviders.ToString()

function dataCollectionFeatures {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayname,
        [object]$MgParentNameChain,
        $subscriptionQuotaId
    )

    $currentTask = "Getting Features for Subscription: '$($scopeDisplayname)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Features/features?api-version=2021-07-01"
    $method = 'GET'
    $featuresResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    $featuresResultRegistered = $featuresResult.where({ $_.properties.state -eq 'Registered' })

    if ($featuresResultRegistered.Count -gt 0) {
        foreach ($registeredFeature in $featuresResultRegistered) {
            $null = $script:arrayFeaturesAll.Add([PSCustomObject]@{
                    subscriptionId = $registeredFeature.id.split('/')[2]
                    mgPathArray    = $MgParentNameChain
                    mgPath         = ($MgParentNameChain -join ',')
                    feature        = $registeredFeature.name
                })
        }
    }
}
$funcDataCollectionFeatures = $function:dataCollectionFeatures.ToString()

function dataCollectionResourceLocks {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayname,
        $subscriptionQuotaId
    )

    $currentTask = "Getting ResourceLocks for Subscription: '$($scopeDisplayname)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Authorization/locks?api-version=2016-09-01"
    $method = 'GET'
    $requestSubscriptionResourceLocks = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    $requestSubscriptionResourceLocksCount = ($requestSubscriptionResourceLocks).Count
    if ($requestSubscriptionResourceLocksCount -gt 0) {
        $htTemp = @{}
        $locksAnyLockSubscriptionCount = 0
        $locksCannotDeleteSubscriptionCount = 0
        $locksReadOnlySubscriptionCount = 0
        $arrayResourceGroupsAnyLock = [System.Collections.ArrayList]@()
        $arrayResourceGroupsCannotDeleteLock = [System.Collections.ArrayList]@()
        $arrayResourceGroupsReadOnlyLock = [System.Collections.ArrayList]@()
        $arrayResourcesAnyLock = [System.Collections.ArrayList]@()
        $arrayResourcesCannotDeleteLock = [System.Collections.ArrayList]@()
        $arrayResourcesReadOnlyLock = [System.Collections.ArrayList]@()
        foreach ($requestSubscriptionResourceLock in $requestSubscriptionResourceLocks) {

            $splitRequestSubscriptionResourceLockId = ($requestSubscriptionResourceLock.Id).Split('/')
            switch (($splitRequestSubscriptionResourceLockId).Count - 1) {
                #subLock
                6 {
                    $locksAnyLockSubscriptionCount++
                    if ($requestSubscriptionResourceLock.properties.level -eq 'CanNotDelete') {
                        $locksCannotDeleteSubscriptionCount++
                    }
                    if ($requestSubscriptionResourceLock.properties.level -eq 'ReadOnly') {
                        $locksReadOnlySubscriptionCount++
                    }
                }
                #rgLock
                8 {
                    $resourceGroupName = $splitRequestSubscriptionResourceLockId[0..4] -join '/'
                    $null = $arrayResourceGroupsAnyLock.Add([PSCustomObject]@{
                            rg = $resourceGroupName
                        })
                    if ($requestSubscriptionResourceLock.properties.level -eq 'CanNotDelete') {
                        $null = $arrayResourceGroupsCannotDeleteLock.Add([PSCustomObject]@{
                                rg = $resourceGroupName
                            })
                    }
                    if ($requestSubscriptionResourceLock.properties.level -eq 'ReadOnly') {
                        $null = $arrayResourceGroupsReadOnlyLock.Add([PSCustomObject]@{
                                rg = $resourceGroupName
                            })
                    }
                }
                #resLock
                12 {
                    $resourceId = $splitRequestSubscriptionResourceLockId[0..8] -join '/'
                    $null = $arrayResourcesAnyLock.Add([PSCustomObject]@{
                            res = $resourceId
                        })
                    if ($requestSubscriptionResourceLock.properties.level -eq 'CanNotDelete') {
                        $null = $arrayResourcesCannotDeleteLock.Add([PSCustomObject]@{
                                res = $resourceId
                            })
                    }
                    if ($requestSubscriptionResourceLock.properties.level -eq 'ReadOnly') {
                        $null = $arrayResourcesReadOnlyLock.Add([PSCustomObject]@{
                                res = $resourceId
                            })
                    }
                }
            }
        }

        $htTemp.SubscriptionLocksCannotDeleteCount = $locksCannotDeleteSubscriptionCount
        $htTemp.SubscriptionLocksReadOnlyCount = $locksReadOnlySubscriptionCount

        #resourceGroups
        $htTemp.ResourceGroupsLocksCannotDeleteCount = $arrayResourceGroupsCannotDeleteLock.Count
        $htTemp.ResourceGroupsLocksCannotDelete = $arrayResourceGroupsCannotDeleteLock

        $htTemp.ResourceGroupsLocksReadOnlyCount = $arrayResourceGroupsReadOnlyLock.Count
        $htTemp.ResourceGroupsLocksReadOnly = $arrayResourceGroupsReadOnlyLock

        #resources
        $htTemp.ResourcesLocksCannotDeleteCount = $arrayResourcesCannotDeleteLock.Count
        $htTemp.ResourcesLocksCannotDelete = $arrayResourcesCannotDeleteLock

        $htTemp.ResourcesLocksReadOnlyCount = $arrayResourcesReadOnlyLock.Count
        $htTemp.ResourcesLocksReadOnly = $arrayResourcesReadOnlyLock

        $script:htResourceLocks.($scopeId) = $htTemp
    }
}
$funcDataCollectionResourceLocks = $function:dataCollectionResourceLocks.ToString()

function dataCollectionTags {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $subscriptionQuotaId
    )

    $currentTask = "Getting Tags for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Resources/tags/default?api-version=2020-06-01"
    $method = 'GET'
    $requestSubscriptionTags = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -listenOn 'Content' -caller 'CustomDataCollection'

    $script:htSubscriptionTagList.($scopeId).Subscription = @{}
    if ($requestSubscriptionTags.properties.tags) {
        $subscriptionTags = @()
        ($script:htSubscriptionTags).($scopeId) = @{}
        foreach ($tag in ($requestSubscriptionTags.properties.tags).PSObject.Properties) {
            $subscriptionTags += "$($tag.Name)/$($tag.Value)"

            ($script:htSubscriptionTags).($scopeId).($tag.Name) = $tag.Value
            $tagName = $tag.Name

            #subscription
            if ($htSubscriptionTagList.($scopeId).Subscription.ContainsKey($tagName)) {
                $script:htSubscriptionTagList.($scopeId).Subscription."$tagName" += 1
            }
            else {
                $script:htSubscriptionTagList.($scopeId).Subscription."$tagName" = 1
            }

            #subscriptionAll
            if ($htAllTagList.Subscription.ContainsKey($tagName)) {
                $script:htAllTagList.Subscription."$tagName" += 1
            }
            else {
                $script:htAllTagList.Subscription."$tagName" = 1
            }

            #all
            if ($htAllTagList.AllScopes.ContainsKey($tagName)) {
                $script:htAllTagList.AllScopes."$tagName" += 1
            }
            else {
                $script:htAllTagList.AllScopes."$tagName" = 1
            }

        }
        $subscriptionTagsCount = ($subscriptionTags).Count
        $subscriptionTags = $subscriptionTags -join "$CsvDelimiterOpposite "
    }
    else {
        $subscriptionTagsCount = 0
        $subscriptionTags = 'none'
    }
    $htSubscriptionTagsReturn = @{}
    $htSubscriptionTagsReturn.subscriptionTagsCount = $subscriptionTagsCount
    $htSubscriptionTagsReturn.subscriptionTags = $subscriptionTags
    return $htSubscriptionTagsReturn
}
$funcDataCollectionTags = $function:dataCollectionTags.ToString()

function dataCollectionPolicyComplianceStates {
    [CmdletBinding()]Param(
        [string]$TargetMgOrSub,
        [string]$scopeId,
        [string]$scopeDisplayName,
        $subscriptionQuotaId
    )


    if ($TargetMgOrSub -eq 'Sub') {
        $currentTask = "Getting Policy Compliance for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
    }
    if ($TargetMgOrSub -eq 'MG') {
        $currentTask = "Getting Policy Compliance for Management Group: '$($scopeDisplayName)' ('$scopeId')"
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($scopeId)/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
    }
    $method = 'POST'
    $policyComplianceResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    if ($policyComplianceResult -eq 'ResponseTooLarge') {
        if ($TargetMgOrSub -eq 'Sub') {
            $script:htCachePolicyComplianceResponseTooLargeSUB.($scopeId) = @{}
        }
        if ($TargetMgOrSub -eq 'MG') {
            $script:htCachePolicyComplianceResponseTooLargeMG.($scopeId) = @{}
        }
    }
    elseif ($policyComplianceResult -eq 'DisallowedProvider') {
        #nothing to do
    }
    else {
        if ($TargetMgOrSub -eq 'Sub') { ($script:htCachePolicyComplianceSUB).($scopeId) = @{} }
        if ($TargetMgOrSub -eq 'MG') { ($script:htCachePolicyComplianceMG).($scopeId) = @{} }
        foreach ($policyAssignment in $policyComplianceResult.policyassignments | Sort-Object -Property policyAssignmentId) {
            $policyAssignmentIdToLower = ($policyAssignment.policyAssignmentId).ToLower()
            if ($TargetMgOrSub -eq 'Sub') { ($script:htCachePolicyComplianceSUB).($scopeId).($policyAssignmentIdToLower) = @{} }
            if ($TargetMgOrSub -eq 'MG') { ($script:htCachePolicyComplianceMG).($scopeId).($policyAssignmentIdToLower) = @{} }
            foreach ($policyComplianceState in $policyAssignment.results.policydetails) {
                if ($policyComplianceState.ComplianceState -eq 'compliant') {
                    if ($TargetMgOrSub -eq 'Sub') { ($script:htCachePolicyComplianceSUB).($scopeId).($policyAssignmentIdToLower).CompliantPolicies = $policyComplianceState.count }
                    if ($TargetMgOrSub -eq 'MG') { ($script:htCachePolicyComplianceMG).($scopeId).($policyAssignmentIdToLower).CompliantPolicies = $policyComplianceState.count }
                }
                if ($policyComplianceState.ComplianceState -eq 'noncompliant') {
                    if ($TargetMgOrSub -eq 'Sub') { ($script:htCachePolicyComplianceSUB).($scopeId).($policyAssignmentIdToLower).NonCompliantPolicies = $policyComplianceState.count }
                    if ($TargetMgOrSub -eq 'MG') { ($script:htCachePolicyComplianceMG).($scopeId).($policyAssignmentIdToLower).NonCompliantPolicies = $policyComplianceState.count }
                }
            }

            foreach ($resourceComplianceState in $policyAssignment.results.resourcedetails) {
                if ($resourceComplianceState.ComplianceState -eq 'compliant') {
                    if ($TargetMgOrSub -eq 'Sub') { ($script:htCachePolicyComplianceSUB).($scopeId).($policyAssignmentIdToLower).CompliantResources = $resourceComplianceState.count }
                    if ($TargetMgOrSub -eq 'MG') { ($script:htCachePolicyComplianceMG).($scopeId).($policyAssignmentIdToLower).CompliantResources = $resourceComplianceState.count }

                }
                if ($resourceComplianceState.ComplianceState -eq 'nonCompliant') {
                    if ($TargetMgOrSub -eq 'Sub') { ($script:htCachePolicyComplianceSUB).($scopeId).($policyAssignmentIdToLower).NonCompliantResources = $resourceComplianceState.count }
                    if ($TargetMgOrSub -eq 'MG') { ($script:htCachePolicyComplianceMG).($scopeId).($policyAssignmentIdToLower).NonCompliantResources = $resourceComplianceState.count }

                }
                if ($resourceComplianceState.ComplianceState -eq 'conflict') {
                    if ($TargetMgOrSub -eq 'Sub') { ($script:htCachePolicyComplianceSUB).($scopeId).($policyAssignmentIdToLower).ConflictingResources = $resourceComplianceState.count }
                    if ($TargetMgOrSub -eq 'MG') { ($script:htCachePolicyComplianceMG).($scopeId).($policyAssignmentIdToLower).ConflictingResources = $resourceComplianceState.count }
                }
            }
        }
    }
}
$funcDataCollectionPolicyComplianceStates = $function:dataCollectionPolicyComplianceStates.ToString()

function dataCollectionASCSecureScoreSub {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $subscriptionQuotaId
    )

    if ($azAPICallConf['htParameters'].NoMDfCSecureScore -eq $false) {
        $currentTask = "Getting Microsoft Defender for Cloud Secure Score for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Security/securescores?api-version=2020-01-01"
        $method = 'GET'
        $subASCSecureScoreResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

        if ($subASCSecureScoreResult -ne 'DisallowedProvider') {
            $subASCSecureScoreResultASCScore = ($subASCSecureScoreResult.where({ $_.name -eq 'ascScore' }))
            if ($subASCSecureScoreResultASCScore.count -gt 0) {
                $secureScorePercentageRounded = [math]::Round(($subASCSecureScoreResultASCScore.properties.score.current / $subASCSecureScoreResultASCScore.properties.score.max * 100), 2)
                $subscriptionASCSecureScore = "$($secureScorePercentageRounded)% ($($subASCSecureScoreResultASCScore.properties.score.current) of $($subASCSecureScoreResultASCScore.properties.score.max) points)"
            }
            else {
                $subscriptionASCSecureScore = 'n/a'
            }
        }
        else {
            $subscriptionASCSecureScore = 'n/a'
        }

    }
    else {
        $subscriptionASCSecureScore = "excluded (-NoMDfCSecureScore $($azAPICallConf['htParameters'].NoMDfCSecureScore))"
    }
    return $subscriptionASCSecureScore
}
$funcDataCollectionASCSecureScoreSub = $function:dataCollectionASCSecureScoreSub.ToString()

function dataCollectionBluePrintDefinitionsMG {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $hierarchyLevel,
        $mgParentId,
        $mgParentName,
        $mgAscSecureScoreResult
    )

    $currentTask = "Getting Blueprint definitions for Management Group: '$($scopeDisplayName)' ('$scopeId')"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($scopeId)/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
    $method = 'GET'
    $scopeBlueprintDefinitionResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    $addRowToTableDone = $false
    if (($scopeBlueprintDefinitionResult).count -gt 0) {
        foreach ($blueprint in $scopeBlueprintDefinitionResult) {

            if (-not $($htCacheDefinitionsBlueprint).($blueprint.Id)) {
                ($script:htCacheDefinitionsBlueprint).($blueprint.Id) = @{}
            }

            $blueprintName = $blueprint.name
            $blueprintId = $blueprint.Id
            $blueprintDisplayName = $blueprint.properties.displayName
            $blueprintDescription = $blueprint.properties.description
            $blueprintScoped = "/providers/Microsoft.Management/managementGroups/$($scopeId)"

            $addRowToTableDone = $true
            addRowToTable `
                -level $hierarchyLevel `
                -mgName $scopeDisplayName `
                -mgId $scopeId `
                -mgParentId $mgParentId `
                -mgParentName $mgParentName `
                -mgASCSecureScore $mgAscSecureScoreResult `
                -BlueprintName $blueprintName `
                -BlueprintId $blueprintId `
                -BlueprintDisplayName $blueprintDisplayName `
                -BlueprintDescription $blueprintDescription `
                -BlueprintScoped $blueprintScoped
        }
    }

    $returnObject = @{}
    if ($addRowToTableDone) {
        $returnObject.'addRowToTableDone' = @{}
    }
    return $returnObject
}
$funcDataCollectionBluePrintDefinitionsMG = $function:dataCollectionBluePrintDefinitionsMG.ToString()

function dataCollectionBluePrintDefinitionsSub {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $hierarchyLevel,
        $childMgDisplayName,
        $childMgId,
        $childMgParentId,
        $childMgParentName,
        $mgAscSecureScoreResult,
        $subscriptionQuotaId,
        $subscriptionState,
        $subscriptionASCSecureScore,
        $subscriptionTags,
        $subscriptionTagsCount
    )

    $currentTask = "Getting Blueprint definitions for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
    $method = 'GET'
    $scopeBlueprintDefinitionResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    $addRowToTableDone = $false
    if ($scopeBlueprintDefinitionResult -ne 'DisallowedProvider') {
        if (($scopeBlueprintDefinitionResult).count -gt 0) {
            foreach ($blueprint in $scopeBlueprintDefinitionResult) {

                if (-not $($htCacheDefinitionsBlueprint).($blueprint.Id)) {
                ($script:htCacheDefinitionsBlueprint).($blueprint.Id) = @{}
                }

                $blueprintName = $blueprint.name
                $blueprintId = $blueprint.Id
                $blueprintDisplayName = $blueprint.properties.displayName
                $blueprintDescription = $blueprint.properties.description
                $blueprintScoped = "/subscriptions/$($scopeId)"

                $addRowToTableDone = $true
                addRowToTable `
                    -level $hierarchyLevel `
                    -mgName $childMgDisplayName `
                    -mgId $childMgId `
                    -mgParentId $childMgParentId `
                    -mgParentName $childMgParentName `
                    -mgASCSecureScore $mgAscSecureScoreResult `
                    -Subscription $scopeDisplayName `
                    -SubscriptionId $scopeId `
                    -SubscriptionQuotaId $subscriptionQuotaId `
                    -SubscriptionState $subscriptionState `
                    -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                    -SubscriptionTags $subscriptionTags `
                    -SubscriptionTagsCount $subscriptionTagsCount `
                    -BlueprintName $blueprintName `
                    -BlueprintId $blueprintId `
                    -BlueprintDisplayName $blueprintDisplayName `
                    -BlueprintDescription $blueprintDescription `
                    -BlueprintScoped $blueprintScoped
            }
        }
    }

    $returnObject = @{}
    if ($addRowToTableDone) {
        $returnObject.'addRowToTableDone' = @{}
    }
    return $returnObject
}
$funcDataCollectionBluePrintDefinitionsSub = $function:dataCollectionBluePrintDefinitionsSub.ToString()

function dataCollectionBluePrintAssignmentsSub {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $hierarchyLevel,
        $childMgDisplayName,
        $childMgId,
        $childMgParentId,
        $childMgParentName,
        $mgAscSecureScoreResult,
        $subscriptionQuotaId,
        $subscriptionState,
        $subscriptionASCSecureScore,
        $subscriptionTags,
        $subscriptionTagsCount
    )

    $currentTask = "Getting Blueprint assignments for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Blueprint/blueprintAssignments?api-version=2018-11-01-preview"
    $method = 'GET'
    $subscriptionBlueprintAssignmentsResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    $addRowToTableDone = $false
    if ($subscriptionBlueprintAssignmentsResult -ne 'DisallowedProvider') {
        if (($subscriptionBlueprintAssignmentsResult).count -gt 0) {
            foreach ($subscriptionBlueprintAssignment in $subscriptionBlueprintAssignmentsResult) {

                if (-not ($htCacheAssignmentsBlueprint).($subscriptionBlueprintAssignment.Id)) {
                ($script:htCacheAssignmentsBlueprint).($subscriptionBlueprintAssignment.Id) = @{}
                ($script:htCacheAssignmentsBlueprint).($subscriptionBlueprintAssignment.Id) = $subscriptionBlueprintAssignment
                }

                if (($subscriptionBlueprintAssignment.properties.blueprintId) -like '/subscriptions/*') {
                    $blueprintScope = $subscriptionBlueprintAssignment.properties.blueprintId -replace '/providers/Microsoft.Blueprint/blueprints/.*', ''
                    $blueprintName = $subscriptionBlueprintAssignment.properties.blueprintId -replace '.*/blueprints/', '' -replace '/versions/.*', ''
                }
                if (($subscriptionBlueprintAssignment.properties.blueprintId) -like '/providers/Microsoft.Management/managementGroups/*') {
                    $blueprintScope = $subscriptionBlueprintAssignment.properties.blueprintId -replace '/providers/Microsoft.Blueprint/blueprints/.*', ''
                    $blueprintName = $subscriptionBlueprintAssignment.properties.blueprintId -replace '.*/blueprints/', '' -replace '/versions/.*', ''
                }

                $currentTask = "Getting Blueprint definitions related to Blueprint assignments for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
                $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/$($blueprintScope)/providers/Microsoft.Blueprint/blueprints/$($blueprintName)?api-version=2018-11-01-preview"
                $method = 'GET'
                $subscriptionBlueprintDefinitionResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -listenOn 'Content' -caller 'CustomDataCollection'

                if ($subscriptionBlueprintDefinitionResult -eq 'BlueprintNotFound') {
                    $blueprintName = 'BlueprintNotFound'
                    $blueprintId = 'BlueprintNotFound'
                    $blueprintAssignmentVersion = $subscriptionBlueprintAssignment.properties.blueprintId -replace '.*/'
                    $blueprintDisplayName = 'BlueprintNotFound'
                    $blueprintDescription = 'BlueprintNotFound'
                    $blueprintScoped = $blueprintScope
                    $blueprintAssignmentId = $subscriptionBlueprintAssignmentsResult.Id
                }
                else {
                    $blueprintName = $subscriptionBlueprintDefinitionResult.name
                    $blueprintId = $subscriptionBlueprintDefinitionResult.Id
                    $blueprintAssignmentVersion = $subscriptionBlueprintAssignment.properties.blueprintId -replace '.*/'
                    $blueprintDisplayName = $subscriptionBlueprintDefinitionResult.properties.displayName
                    $blueprintDescription = $subscriptionBlueprintDefinitionResult.properties.description
                    $blueprintScoped = $blueprintScope
                    $blueprintAssignmentId = $subscriptionBlueprintAssignmentsResult.Id
                }

                $addRowToTableDone = $true
                addRowToTable `
                    -level $hierarchyLevel `
                    -mgName $childMgDisplayName `
                    -mgId $childMgId `
                    -mgParentId $childMgParentId `
                    -mgParentName $childMgParentName `
                    -mgASCSecureScore $mgAscSecureScoreResult `
                    -Subscription $scopeDisplayName `
                    -SubscriptionId $scopeId `
                    -SubscriptionQuotaId $subscriptionQuotaId `
                    -SubscriptionState $subscriptionState `
                    -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                    -SubscriptionTags $subscriptionTags `
                    -SubscriptionTagsCount $subscriptionTagsCount `
                    -BlueprintName $blueprintName `
                    -BlueprintId $blueprintId `
                    -BlueprintDisplayName $blueprintDisplayName `
                    -BlueprintDescription $blueprintDescription `
                    -BlueprintScoped $blueprintScoped `
                    -BlueprintAssignmentVersion $blueprintAssignmentVersion `
                    -BlueprintAssignmentId $blueprintAssignmentId
            }
        }
    }

    $returnObject = @{}
    if ($addRowToTableDone) {
        $returnObject.'addRowToTableDone' = @{}
    }
    return $returnObject
}
$funcDataCollectionBluePrintAssignmentsSub = $function:dataCollectionBluePrintAssignmentsSub.ToString()

function dataCollectionPolicyExemptions {
    [CmdletBinding()]Param(
        [string]$TargetMgOrSub,
        [string]$scopeId,
        [string]$scopeDisplayName,
        $subscriptionQuotaId
    )

    if ($TargetMgOrSub -eq 'Sub') {
        $currentTask = "Getting Policy exemptions for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Authorization/policyExemptions?api-version=2020-07-01-preview"
    }
    if ($TargetMgOrSub -eq 'MG') {
        $currentTask = "Getting Policy exemptions for Management Group: '$($scopeDisplayName)' ('$scopeId')"
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($scopeId)/providers/Microsoft.Authorization/policyExemptions?api-version=2020-07-01-preview&`$filter=atScope()"
    }
    $method = 'GET'
    $requestPolicyExemptionAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    $requestPolicyExemptionAPICount = ($requestPolicyExemptionAPI).Count
    if ($requestPolicyExemptionAPICount -gt 0) {
        foreach ($exemption in $requestPolicyExemptionAPI) {
            if (-not $htPolicyAssignmentExemptions.($exemption.Id)) {
                $script:htPolicyAssignmentExemptions.($exemption.Id) = @{}
                $script:htPolicyAssignmentExemptions.($exemption.Id).exemption = $exemption
            }
        }
    }
}
$funcDataCollectionPolicyExemptions = $function:dataCollectionPolicyExemptions.ToString()

function dataCollectionPolicyDefinitions {
    [CmdletBinding()]Param(
        [string]$TargetMgOrSub,
        [string]$scopeId,
        [string]$scopeDisplayName,
        $subscriptionQuotaId
    )

    if ($TargetMgOrSub -eq 'Sub') {
        $currentTask = "Getting Policy definitions for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Authorization/policyDefinitions?api-version=2021-06-01&`$filter=policyType eq 'Custom'"
    }
    if ($TargetMgOrSub -eq 'MG') {
        $currentTask = "Getting Policy definitions for Management Group: '$($scopeDisplayName)' ('$scopeId')"
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementgroups/$($scopeId)/providers/Microsoft.Authorization/policyDefinitions?api-version=2021-06-01&`$filter=policyType eq 'Custom'"
    }
    $method = 'GET'
    $requestPolicyDefinitionAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    $scopePolicyDefinitions = $requestPolicyDefinitionAPI.where( { $_.properties.policyType -eq 'custom' } )

    if ($TargetMgOrSub -eq 'Sub') {
        $PolicyDefinitionsScopedCount = (($scopePolicyDefinitions.where( { ($_.id) -like "/subscriptions/$($scopeId)/*" } ))).count
    }
    if ($TargetMgOrSub -eq 'MG') {
        $PolicyDefinitionsScopedCount = (($scopePolicyDefinitions.where( { ($_.id) -like "/providers/Microsoft.Management/managementGroups/$($scopeId)/*" } ))).count
    }

    foreach ($scopePolicyDefinition in $scopePolicyDefinitions) {
        $hlpPolicyDefinitionId = ($scopePolicyDefinition.id).ToLower()

        $doIt = $true
        if ($TargetMgOrSub -eq 'MG') {
            $doIt = $false
            if ($hlpPolicyDefinitionId -like "/providers/Microsoft.Management/managementGroups/$($scopeId)/*" -and $hlpPolicyDefinitionId -notlike "/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)/*") {
                $doIt = $true
            }
            if ($scopeId -eq $ManagementGroupId) {
                $doIt = $true
            }
        }

        if ($doIt) {

            if (-not $script:htCacheDefinitionsPolicy.($hlpPolicyDefinitionId)) {
                if (($scopePolicyDefinition.Properties.description).length -eq 0) {
                    $policyDefinitionDescription = 'no description given'
                }
                else {
                    $policyDefinitionDescription = $scopePolicyDefinition.Properties.description
                }

                $htTemp = @{}
                $htTemp.Id = $hlpPolicyDefinitionId

                if ($hlpPolicyDefinitionId -like '/providers/Microsoft.Management/managementGroups/*') {
                    $htTemp.Scope = (($hlpPolicyDefinitionId).split('/'))[0..4] -join '/'
                    $htTemp.ScopeMgSub = 'Mg'
                    $htTemp.ScopeId = (($hlpPolicyDefinitionId).split('/'))[4]
                    $htTemp.ScopeMGLevel = $htManagementGroupsMgPath.((($hlpPolicyDefinitionId).split('/'))[4]).ParentNameChainCount
                }

                if ($hlpPolicyDefinitionId -like '/subscriptions/*') {
                    $htTemp.Scope = (($hlpPolicyDefinitionId).split('/'))[0..2] -join '/'
                    $htTemp.ScopeMgSub = 'Sub'
                    $htTemp.ScopeId = (($hlpPolicyDefinitionId).split('/'))[2]
                    $htTemp.ScopeMGLevel = $htSubscriptionsMgPath.((($hlpPolicyDefinitionId).split('/'))[2]).level
                }


                if ($azAPICallConf['htParameters'].NoALZPolicyVersionChecker -eq $false) {

                    $policyJsonRule = $scopePolicyDefinition.properties.policyRule | ConvertTo-Json -Depth 99
                    $hash = [System.Security.Cryptography.HashAlgorithm]::Create('sha256').ComputeHash([System.Text.Encoding]::UTF8.GetBytes($policyJsonRule))
                    $stringHash = [System.BitConverter]::ToString($hash)

                    if ($alzPolicies.($scopePolicyDefinition.name) -or $alzPolicyHashes.($stringHash) -or $scopePolicyDefinition.properties.metadata.source -eq 'https://github.com/Azure/Enterprise-Scale/') {

                        $policyHashMatch = $false
                        if ($alzPolicyHashes.($stringHash)) {
                            $policyHashMatch = $true
                            $htTemp.ALZ = 'true'
                            if ($alzPolicyHashes.($stringHash).metadataSource -eq 'https://github.com/Azure/Enterprise-Scale/' -and $alzPolicyHashes.($stringHash).metadataSource -eq $scopePolicyDefinition.properties.metadata.source -and $alzPolicyHashes.($stringHash).policyName -eq $scopePolicyDefinition.name) {
                                $htTemp.ALZIdentificationLevel = 'PolicyRule Hash, Policy Name, MetaData Tag'
                            }
                            elseif ($alzPolicyHashes.($stringHash).policyName -eq $scopePolicyDefinition.name) {
                                $htTemp.ALZIdentificationLevel = 'PolicyRule Hash, Policy Name'
                            }
                            else {
                                $htTemp.ALZIdentificationLevel = 'PolicyRule Hash'
                            }
                            $htTemp.ALZPolicyName = $alzPolicyHashes.($stringHash).policyName
                            $htTemp.hash = $stringHash
                            if ($alzpolicies.($alzPolicyHashes.($stringHash).policyName).status -eq 'obsolete') {
                                $htTemp.ALZState = 'obsolete'
                                $htTemp.ALZLatestVer = ''
                            }
                            else {
                                if ($scopePolicyDefinition.Properties.metadata.version) {
                                    if ($alzpolicies.($alzPolicyHashes.($stringHash).policyName).latestVersion -eq $scopePolicyDefinition.Properties.metadata.version) {
                                        $htTemp.ALZState = 'upToDate'
                                    }
                                    else {
                                        if ($alzpolicies.($alzPolicyHashes.($stringHash).policyName).latestVersion -like '*-deprecated') {
                                            $htTemp.ALZState = 'deprecated'
                                        }
                                        else {
                                            $htTemp.ALZState = 'outDated'
                                        }
                                    }
                                }
                                else {
                                    $htTemp.ALZState = 'potentiallyOutDated (no ver)'
                                }
                                $htTemp.ALZLatestVer = $alzpolicies.($alzPolicyHashes.($stringHash).policyName).latestVersion
                            }
                        }

                        $policyNameMatch = $false
                        if ($alzPolicies.($scopePolicyDefinition.name) -and -not $policyHashMatch) {
                            $policyNameMatch = $true
                            $htTemp.ALZ = 'true'
                            if ($alzPolicies.($scopePolicyDefinition.name).metadataSource -eq 'https://github.com/Azure/Enterprise-Scale/' -and $alzPolicies.($scopePolicyDefinition.name).metadataSource -eq $scopePolicyDefinition.properties.metadata.source) {
                                $htTemp.ALZIdentificationLevel = 'Policy Name, MetaData Tag'
                            }
                            else {
                                $htTemp.ALZIdentificationLevel = 'Policy Name'
                            }

                            $htTemp.ALZPolicyName = $alzPolicies.($scopePolicyDefinition.name).policyName
                            $htTemp.hash = $stringHash
                            if ($alzPolicies.($scopePolicyDefinition.name).status -eq 'obsolete') {
                                $htTemp.ALZState = 'obsolete'
                                $htTemp.ALZLatestVer = ''
                            }
                            else {
                                if ($scopePolicyDefinition.Properties.metadata.version) {
                                    if ($alzPolicies.($scopePolicyDefinition.name).latestVersion -eq $scopePolicyDefinition.Properties.metadata.version) {
                                        $htTemp.ALZState = 'upToDate'
                                    }
                                    else {
                                        if ($alzPolicies.($scopePolicyDefinition.name).latestVersion -like '*-deprecated') {
                                            $htTemp.ALZState = 'deprecated'
                                        }
                                        else {
                                            $htTemp.ALZState = 'outDated'
                                        }
                                    }
                                }
                                else {
                                    $htTemp.ALZState = 'potentiallyOutDated (no ver)'
                                }

                                $htTemp.ALZLatestVer = $alzPolicies.($scopePolicyDefinition.name).latestVersion
                            }
                        }

                        if ($scopePolicyDefinition.properties.metadata.source -eq 'https://github.com/Azure/Enterprise-Scale/' -and -not $policyHashMatch -and -not $policyNameMatch) {
                            $htTemp.ALZ = 'true'
                            $htTemp.ALZState = 'unknown'
                            $htTemp.ALZLatestVer = ''
                            $htTemp.ALZIdentificationLevel = 'MetaData Tag'
                            $htTemp.ALZPolicyName = ''
                            $htTemp.hash = $stringHash
                        }
                    }
                    else {
                        $htTemp.ALZ = 'false'
                        $htTemp.ALZState = ''
                        $htTemp.ALZLatestVer = ''
                        $htTemp.ALZIdentificationLevel = ''
                        $htTemp.ALZPolicyName = ''
                        $htTemp.hash = $stringHash
                    }
                }
                else {
                    $htTemp.ALZ = 'n/a'
                    $htTemp.ALZState = ''
                    $htTemp.ALZLatestVer = ''
                    $htTemp.ALZIdentificationLevel = ''
                    $htTemp.ALZPolicyName = ''
                    $htTemp.hash = ''
                }

                $htTemp.DisplayName = $($scopePolicyDefinition.Properties.displayname)
                $htTemp.Name = $scopePolicyDefinition.Name
                $htTemp.Description = $($policyDefinitionDescription)
                $htTemp.Type = $($scopePolicyDefinition.Properties.policyType)
                $htTemp.Category = $($scopePolicyDefinition.Properties.metadata.category)
                if ($scopePolicyDefinition.Properties.metadata.version) {
                    $htTemp.Version = $($scopePolicyDefinition.Properties.metadata.version)
                }
                else {
                    $htTemp.Version = 'n/a'
                }
                $htTemp.PolicyDefinitionId = $hlpPolicyDefinitionId
                if ($scopePolicyDefinition.Properties.metadata.deprecated -eq $true -or $scopePolicyDefinition.Properties.displayname -like "``[Deprecated``]*") {
                    $htTemp.Deprecated = $scopePolicyDefinition.Properties.metadata.deprecated
                }
                else {
                    $htTemp.Deprecated = $false
                }
                if ($scopePolicyDefinition.Properties.metadata.preview -eq $true -or $scopePolicyDefinition.Properties.displayname -like "``[*Preview``]*") {
                    $htTemp.Preview = $scopePolicyDefinition.Properties.metadata.preview
                }
                else {
                    $htTemp.Preview = $false
                }

                #region effect
                $htEffectDetected = detectPolicyEffect -policyDefinition $scopePolicyDefinition
                $htTemp.effectDefaultValue = $htEffectDetected.defaultValue
                $htTemp.effectAllowedValue = $htEffectDetected.allowedValues
                $htTemp.effectFixedValue = $htEffectDetected.fixedValue
                #endregion effect

                $htTemp.Json = $scopePolicyDefinition
                $script:htCacheDefinitionsPolicy.($hlpPolicyDefinitionId) = $htTemp
            }


            if (-not [string]::IsNullOrWhiteSpace($scopePolicyDefinition.properties.policyRule.then.details.roleDefinitionIds)) {
                $script:htCacheDefinitionsPolicy.($hlpPolicyDefinitionId).RoleDefinitionIds = $scopePolicyDefinition.properties.policyRule.then.details.roleDefinitionIds
                foreach ($roledefinitionId in $scopePolicyDefinition.properties.policyRule.then.details.roleDefinitionIds) {
                    if (-not [string]::IsNullOrEmpty($roledefinitionId)) {
                        if (-not $htRoleDefinitionIdsUsedInPolicy.($roledefinitionId)) {
                            $script:htRoleDefinitionIdsUsedInPolicy.($roledefinitionId) = @{}
                            $script:htRoleDefinitionIdsUsedInPolicy.($roledefinitionId).UsedInPolicies = [array]$hlpPolicyDefinitionId
                        }
                        else {
                            $usedInPolicies = $htRoleDefinitionIdsUsedInPolicy.($roledefinitionId).UsedInPolicies
                            $usedInPolicies += $hlpPolicyDefinitionId
                            $script:htRoleDefinitionIdsUsedInPolicy.($roledefinitionId).UsedInPolicies = $usedInPolicies
                        }
                    }
                    else {
                        Write-Host "$currentTask $($hlpPolicyDefinitionId) Finding: empty roleDefinitionId in roledefinitionIds"
                    }
                }
            }
            else {
                $script:htCacheDefinitionsPolicy.($hlpPolicyDefinitionId).RoleDefinitionIds = 'n/a'
            }

            #region namingValidation
            if (-not [string]::IsNullOrEmpty($scopePolicyDefinition.Properties.displayname)) {
                $namingValidationResult = NamingValidation -toCheck $scopePolicyDefinition.Properties.displayname
                if ($namingValidationResult.Count -gt 0) {
                    if (-not $script:htNamingValidation.Policy.($hlpPolicyDefinitionId)) {
                        $script:htNamingValidation.Policy.($hlpPolicyDefinitionId) = @{}
                    }
                    $script:htNamingValidation.Policy.($hlpPolicyDefinitionId).displayNameInvalidChars = ($namingValidationResult -join '')
                    $script:htNamingValidation.Policy.($hlpPolicyDefinitionId).displayName = $scopePolicyDefinition.Properties.displayname
                }
            }
            if (-not [string]::IsNullOrEmpty($scopePolicyDefinition.Name)) {
                $namingValidationResult = NamingValidation -toCheck $scopePolicyDefinition.Name
                if ($namingValidationResult.Count -gt 0) {
                    if (-not $script:htNamingValidation.Policy.($hlpPolicyDefinitionId)) {
                        $script:htNamingValidation.Policy.($hlpPolicyDefinitionId) = @{}
                    }
                    $script:htNamingValidation.Policy.($hlpPolicyDefinitionId).nameInvalidChars = ($namingValidationResult -join '')
                    $script:htNamingValidation.Policy.($hlpPolicyDefinitionId).name = $scopePolicyDefinition.Name
                }
            }
            #endregion namingValidation
        }
    }

    $returnObject = @{}
    $returnObject.'PolicyDefinitionsScopedCount' = $PolicyDefinitionsScopedCount
    return $returnObject
}
$funcDataCollectionPolicyDefinitions = $function:dataCollectionPolicyDefinitions.ToString()

function dataCollectionPolicySetDefinitions {
    [CmdletBinding()]Param(
        [string]$TargetMgOrSub,
        [string]$scopeId,
        [string]$scopeDisplayName,
        $subscriptionQuotaId
    )

    if ($TargetMgOrSub -eq 'Sub') {
        $currentTask = "Getting PolicySet definitions for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2021-06-01&`$filter=policyType eq 'Custom'"
    }
    if ($TargetMgOrSub -eq 'MG') {
        $currentTask = "Getting PolicySet definitions for Management Group: '$($scopeDisplayName)' ('$scopeId')"
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementgroups/$($scopeId)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2021-06-01&`$filter=policyType eq 'Custom'"
    }
    $method = 'GET'
    $requestPolicySetDefinitionAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    $scopePolicySetDefinitions = $requestPolicySetDefinitionAPI.where( { $_.properties.policyType -eq 'custom' } )
    if ($TargetMgOrSub -eq 'Sub') {
        $PolicySetDefinitionsScopedCount = ($scopePolicySetDefinitions.where( { ($_.Id) -like "/subscriptions/$($scopeId)/*" } )).count
    }
    if ($TargetMgOrSub -eq 'MG') {
        $PolicySetDefinitionsScopedCount = (($scopePolicySetDefinitions.where( { ($_.Id) -like "/providers/Microsoft.Management/managementGroups/$($scopeId)/*" } ))).count
    }

    foreach ($scopePolicySetDefinition in $scopePolicySetDefinitions) {
        $hlpPolicySetDefinitionId = ($scopePolicySetDefinition.id).ToLower()

        $doIt = $true
        if ($TargetMgOrSub -eq 'MG') {
            $doIt = $false
            if ($hlpPolicySetDefinitionId -like "/providers/Microsoft.Management/managementGroups/$($scopeId)/*" -and $hlpPolicySetDefinitionId -notlike "/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)/*") {
                $doIt = $true
            }
            if ($scopeId -eq $ManagementGroupId) {
                $doIt = $true
            }
        }

        if ($doIt) {
            if (-not $script:htCacheDefinitionsPolicySet.($hlpPolicySetDefinitionId)) {
                if (($scopePolicySetDefinition.Properties.description).length -eq 0) {
                    $policySetDefinitionDescription = 'no description given'
                }
                else {
                    $policySetDefinitionDescription = $scopePolicySetDefinition.Properties.description
                }

                $htTemp = @{}
                $htTemp.Id = $hlpPolicySetDefinitionId
                if ($scopePolicySetDefinition.Id -like '/providers/Microsoft.Management/managementGroups/*') {
                    $htTemp.Scope = (($scopePolicySetDefinition.Id).split('/'))[0..4] -join '/'
                    $htTemp.ScopeMgSub = 'Mg'
                    $htTemp.ScopeId = (($scopePolicySetDefinition.Id).split('/'))[4]
                    $htTemp.ScopeMGLevel = $htManagementGroupsMgPath.((($scopePolicySetDefinition.Id).split('/'))[4]).ParentNameChainCount
                }

                if ($scopePolicySetDefinition.Id -like '/subscriptions/*') {
                    $htTemp.Scope = (($scopePolicySetDefinition.Id).split('/'))[0..2] -join '/'
                    $htTemp.ScopeMgSub = 'Sub'
                    $htTemp.ScopeId = (($scopePolicySetDefinition.Id).split('/'))[2]
                    $htTemp.ScopeMGLevel = $htSubscriptionsMgPath.((($scopePolicySetDefinition.Id).split('/'))[2]).level
                }

                if ($azAPICallConf['htParameters'].NoALZPolicyVersionChecker -eq $false) {

                    $policyJsonParameters = $scopePolicySetDefinition.properties.parameters | ConvertTo-Json -Depth 99
                    $policyJsonPolicyDefinitions = $scopePolicySetDefinition.properties.policyDefinitions | ConvertTo-Json -Depth 99
                    $hashParameters = [System.Security.Cryptography.HashAlgorithm]::Create('sha256').ComputeHash([System.Text.Encoding]::UTF8.GetBytes($policyJsonParameters))
                    $stringHashParameters = [System.BitConverter]::ToString($hashParameters)
                    $hashPolicyDefinitions = [System.Security.Cryptography.HashAlgorithm]::Create('sha256').ComputeHash([System.Text.Encoding]::UTF8.GetBytes($policyJsonPolicyDefinitions))
                    $stringHashPolicyDefinitions = [System.BitConverter]::ToString($hashPolicyDefinitions)
                    $stringHash = "$($stringHashParameters)_$($stringHashPolicyDefinitions)"

                    if ($alzPolicySets.($scopePolicySetDefinition.name) -or $allESLZPolicySetHashes.($stringHash) -or $scopePolicySetDefinition.properties.metadata.source -eq 'https://github.com/Azure/Enterprise-Scale/') {

                        $policySetHashMatch = $false
                        if ($alzPolicySetHashes.($stringHash)) {
                            $policySetHashMatch = $true
                            $htTemp.ALZ = 'true'
                            if ($allESLZPolicySetHashes.($stringHash).metadataSource -eq 'https://github.com/Azure/Enterprise-Scale/' -and $allESLZPolicySetHashes.($stringHash).metadataSource -eq $scopePolicySetDefinition.properties.metadata.source -and $allESLZPolicySetHashes.($stringHash).policySetName -eq $scopePolicySetDefinition.name) {
                                $htTemp.ALZIdentificationLevel = 'PolicySet Hash, PolicySet Name, MetaData Tag'
                            }
                            elseif ($allESLZPolicySetHashes.($stringHash).policySetName -eq $scopePolicySetDefinition.name) {
                                $htTemp.ALZIdentificationLevel = 'PolicySet Hash, PolicySet Name'
                            }
                            else {
                                $htTemp.ALZIdentificationLevel = 'PolicySet Hash'
                            }
                            $htTemp.ALZPolicySetName = $alzPolicySetHashes.($stringHash).policySetName
                            if ($alzPolicySetHashes.($stringHash).status -eq 'obsolete') {
                                $htTemp.ALZState = 'obsolete'
                                $htTemp.ALZLatestVer = ''
                            }
                            else {
                                if ($alzPolicySetHashes.($stringHash).latestVersion -eq $scopePolicySetDefinition.Properties.metadata.version) {
                                    $htTemp.ALZState = 'upToDate'
                                }
                                else {
                                    if ($alzPolicySetHashes.($stringHash).latestVersion -like '*-deprecated') {
                                        $htTemp.ALZState = 'deprecated'
                                    }
                                    else {
                                        $htTemp.ALZState = 'outDated'
                                    }
                                }
                                $htTemp.ALZLatestVer = $alzPolicySetHashes.($stringHash).latestVersion
                            }
                        }

                        $policySetNameMatch = $false
                        if ($alzPolicySets.($scopePolicySetDefinition.name) -and -not $policySetHashMatch) {
                            $policySetNameMatch = $true
                            $htTemp.ALZ = 'true'
                            if ($alzPolicySets.($scopePolicySetDefinition.name).metadataSource -eq 'https://github.com/Azure/Enterprise-Scale/' -and $alzPolicySets.($scopePolicySetDefinition.name).metadataSource -eq $scopePolicySetDefinition.properties.metadata.source) {
                                $htTemp.ALZIdentificationLevel = 'PolicySet Name, MetaData Tag'
                            }
                            else {
                                $htTemp.ALZIdentificationLevel = 'PolicySet Name'
                            }
                            $htTemp.ALZPolicySetName = $alzPolicySets.($scopePolicySetDefinition.name).policySetName
                            if ($alzPolicySets.($scopePolicySetDefinition.name).status -eq 'obsolete') {
                                $htTemp.ALZState = 'obsolete'
                                $htTemp.ALZLatestVer = ''
                            }
                            else {
                                if ($alzPolicySets.($scopePolicySetDefinition.name).latestVersion -eq $scopePolicySetDefinition.Properties.metadata.version) {
                                    $htTemp.ALZState = 'upToDate'
                                }
                                else {
                                    if ($alzPolicySets.($scopePolicySetDefinition.name).latestVersion -like '*-deprecated') {
                                        $htTemp.ALZState = 'deprecated'
                                    }
                                    else {
                                        $htTemp.ALZState = 'outDated'
                                    }
                                }
                                $htTemp.ALZLatestVer = $alzPolicySets.($scopePolicySetDefinition.name).latestVersion
                            }
                        }

                        if ($scopePolicySetDefinition.properties.metadata.source -eq 'https://github.com/Azure/Enterprise-Scale/' -and -not $policySetHashMatch -and -not $policySetNameMatch) {
                            $htTemp.ALZ = 'true'
                            $htTemp.ALZState = 'unknown'
                            $htTemp.ALZLatestVer = ''
                            $htTemp.ALZIdentificationLevel = 'MetaData Tag'
                            $htTemp.ALZPolicyName = ''
                            $htTemp.hash = $stringHash
                        }
                    }
                    else {
                        $htTemp.ALZ = 'false'
                        $htTemp.ALZState = ''
                        $htTemp.ALZLatestVer = ''
                        $htTemp.ALZIdentificationLevel = ''
                        $htTemp.ALZPolicySetName = ''
                    }
                }
                else {
                    $htTemp.ALZ = 'n/a'
                    $htTemp.ALZState = ''
                    $htTemp.ALZLatestVer = ''
                    $htTemp.ALZIdentificationLevel = ''
                    $htTemp.ALZPolicySetName = ''
                }

                $htTemp.DisplayName = $($scopePolicySetDefinition.Properties.displayname)
                $htTemp.Name = $scopePolicySetDefinition.Name
                $htTemp.Description = $($policySetDefinitionDescription)
                $htTemp.Type = $($scopePolicySetDefinition.Properties.policyType)
                $htTemp.Category = $($scopePolicySetDefinition.Properties.metadata.category)
                if ($scopePolicySetDefinition.Properties.metadata.version) {
                    $htTemp.Version = $($scopePolicySetDefinition.Properties.metadata.version)
                }
                else {
                    $htTemp.Version = 'n/a'
                }
                $htTemp.PolicyDefinitionId = $hlpPolicySetDefinitionId
                $arrayPolicySetPolicyIdsToLower = @()
                $htPolicySetPolicyRefIds = @{}
                $arrayPolicySetPolicyIdsToLower = foreach ($policySetPolicy in $scopePolicySetDefinition.properties.policydefinitions) {
                    $($policySetPolicy.policyDefinitionId).ToLower()
                    $htPolicySetPolicyRefIds.($policySetPolicy.policyDefinitionReferenceId) = ($policySetPolicy.policyDefinitionId)
                }
                $htTemp.PolicySetPolicyIds = $arrayPolicySetPolicyIdsToLower
                $htTemp.PolicySetPolicyRefIds = $htPolicySetPolicyRefIds
                $htTemp.Json = $scopePolicySetDefinition
                if ($scopePolicySetDefinition.Properties.metadata.deprecated -eq $true -or $scopePolicySetDefinition.Properties.displayname -like "``[Deprecated``]*") {
                    $htTemp.Deprecated = $scopePolicySetDefinition.Properties.metadata.deprecated
                }
                else {
                    $htTemp.Deprecated = $false
                }
                if ($scopePolicySetDefinition.Properties.metadata.preview -eq $true -or $scopePolicySetDefinition.Properties.displayname -like "``[*Preview``]*") {
                    $htTemp.Preview = $scopePolicySetDefinition.Properties.metadata.preview
                }
                else {
                    $htTemp.Preview = $false
                }
                ($script:htCacheDefinitionsPolicySet).($hlpPolicySetDefinitionId) = $htTemp
            }
            #namingValidation
            if (-not [string]::IsNullOrEmpty($scopePolicySetDefinition.Properties.displayname)) {
                $namingValidationResult = NamingValidation -toCheck $scopePolicySetDefinition.Properties.displayname
                if ($namingValidationResult.Count -gt 0) {
                    if (-not $script:htNamingValidation.PolicySet.($scopePolicySetDefinition.Id)) {
                        $script:htNamingValidation.PolicySet.($scopePolicySetDefinition.Id) = @{}
                    }
                    $script:htNamingValidation.PolicySet.($scopePolicySetDefinition.Id).displayNameInvalidChars = ($namingValidationResult -join '')
                    $script:htNamingValidation.PolicySet.($scopePolicySetDefinition.Id).displayName = $scopePolicySetDefinition.Properties.displayname
                }
            }
            if (-not [string]::IsNullOrEmpty($scopePolicySetDefinition.Name)) {
                $namingValidationResult = NamingValidation -toCheck $scopePolicySetDefinition.Name
                if ($namingValidationResult.Count -gt 0) {
                    if (-not $script:htNamingValidation.PolicySet.($scopePolicySetDefinition.Id)) {
                        $script:htNamingValidation.PolicySet.($scopePolicySetDefinition.Id) = @{}
                    }
                    $script:htNamingValidation.PolicySet.($scopePolicySetDefinition.Id).nameInvalidChars = ($namingValidationResult -join '')
                    $script:htNamingValidation.PolicySet.($scopePolicySetDefinition.Id).name = $scopePolicySetDefinition.Name
                }
            }
        }
    }

    $returnObject = @{}
    $returnObject.'PolicySetDefinitionsScopedCount' = $PolicySetDefinitionsScopedCount
    return $returnObject
}
$funcDataCollectionPolicySetDefinitions = $function:dataCollectionPolicySetDefinitions.ToString()

function dataCollectionPolicyAssignmentsMG {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $hierarchyLevel,
        $mgParentId,
        $mgParentName,
        $mgAscSecureScoreResult,
        $PolicyDefinitionsScopedCount,
        $PolicySetDefinitionsScopedCount
    )

    $addRowToTableDone = $false
    $currentTask = "Getting Policy assignments for Management Group: '$($scopeDisplayName)' ('$($scopeId)')"
    if ($azAPICallConf['htParameters'].LargeTenant -eq $false -or $azAPICallConf['htParameters'].PolicyAtScopeOnly -eq $false) {
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementgroups/$($scopeId)/providers/Microsoft.Authorization/policyAssignments?`$filter=atscope()&api-version=2021-06-01"
    }
    else {
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementgroups/$($scopeId)/providers/Microsoft.Authorization/policyAssignments?`$filter=atExactScope()&api-version=2021-06-01"
    }
    $method = 'GET'
    $L0mgmtGroupPolicyAssignments = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    $L0mgmtGroupPolicyAssignmentsPolicyCount = (($L0mgmtGroupPolicyAssignments.where( { $_.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policyDefinitions/' } ))).count
    $L0mgmtGroupPolicyAssignmentsPolicySetCount = (($L0mgmtGroupPolicyAssignments.where( { $_.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policySetDefinitions/' } ))).count
    $L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount = (($L0mgmtGroupPolicyAssignments.where( { $_.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policyDefinitions/' -and $_.Id -match "/providers/Microsoft.Management/managementGroups/$($scopeId)" } ))).count
    $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount = (($L0mgmtGroupPolicyAssignments.where( { $_.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policySetDefinitions/' -and $_.Id -match "/providers/Microsoft.Management/managementGroups/$($scopeId)" } ))).count
    $L0mgmtGroupPolicyAssignmentsPolicyAndPolicySetAtScopeCount = ($L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount + $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount)

    if (-not $htMgAtScopePolicyAssignments.($scopeId)) {
        $script:htMgAtScopePolicyAssignments.($scopeId) = @{}
        $script:htMgAtScopePolicyAssignments.($scopeId).AssignmentsCount = $L0mgmtGroupPolicyAssignmentsPolicyAndPolicySetAtScopeCount
    }

    foreach ($L0mgmtGroupPolicyAssignment in $L0mgmtGroupPolicyAssignments) {

        $doIt = $false
        if ($L0mgmtGroupPolicyAssignment.properties.scope -eq "/providers/Microsoft.Management/managementGroups/$($scopeId)" -and $L0mgmtGroupPolicyAssignment.properties.scope -ne "/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)") {
            $doIt = $true
        }
        if ($scopeId -eq $ManagementGroupId) {
            $doIt = $true
        }

        if ($doIt) {
            $htTemp = @{}
            $htTemp.Assignment = $L0mgmtGroupPolicyAssignment
            $htTemp.AssignmentScopeMgSubRg = 'Mg'
            $splitAssignment = (($L0mgmtGroupPolicyAssignment.Id).ToLower()).Split('/')
            $htTemp.AssignmentScopeId = [string]($splitAssignment[4])
            $script:htCacheAssignmentsPolicy.(($L0mgmtGroupPolicyAssignment.Id).ToLower()) = $htTemp
        }

        #region namingValidation
        if (-not [string]::IsNullOrEmpty($L0mgmtGroupPolicyAssignment.Properties.DisplayName)) {
            $namingValidationResult = NamingValidation -toCheck $L0mgmtGroupPolicyAssignment.Properties.DisplayName
            if ($namingValidationResult.Count -gt 0) {
                if (-not $script:htNamingValidation.PolicyAssignment.($L0mgmtGroupPolicyAssignment.Id)) {
                    $script:htNamingValidation.PolicyAssignment.($L0mgmtGroupPolicyAssignment.Id) = @{}
                }
                $script:htNamingValidation.PolicyAssignment.($L0mgmtGroupPolicyAssignment.Id).displayNameInvalidChars = ($namingValidationResult -join '')
                $script:htNamingValidation.PolicyAssignment.($L0mgmtGroupPolicyAssignment.Id).displayName = $L0mgmtGroupPolicyAssignment.Properties.DisplayName
            }
        }
        if (-not [string]::IsNullOrEmpty($L0mgmtGroupPolicyAssignment.Name)) {
            $namingValidationResult = NamingValidation -toCheck $L0mgmtGroupPolicyAssignment.Name
            if ($namingValidationResult.Count -gt 0) {
                if (-not $script:htNamingValidation.PolicyAssignment.($L0mgmtGroupPolicyAssignment.Id)) {
                    $script:htNamingValidation.PolicyAssignment.($L0mgmtGroupPolicyAssignment.Id) = @{}
                }
                $script:htNamingValidation.PolicyAssignment.($L0mgmtGroupPolicyAssignment.Id).nameInvalidChars = ($namingValidationResult -join '')
                $script:htNamingValidation.PolicyAssignment.($L0mgmtGroupPolicyAssignment.Id).name = $L0mgmtGroupPolicyAssignment.Name
            }
        }
        #endregion namingValidation

        if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policyDefinitions/' -OR $L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policySetDefinitions/') {

            #policy
            if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policyDefinitions/') {
                $policyVariant = 'Policy'
                $policyDefinitionId = ($L0mgmtGroupPolicyAssignment.properties.policydefinitionid).ToLower()

                $policyDefinitionSplitted = $policyDefinitionId.split('/')
                $hlpPolicyDefinitionScope = $policyDefinitionSplitted[4]

                if ( ($policyDefinitionId -like '/providers/microsoft.management/managementgroups/*' -and $htManagementGroupsMgPath.($scopeId).path -contains ($hlpPolicyDefinitionScope)) -or $policyDefinitionId -like '/providers/microsoft.authorization/policydefinitions/*' ) {
                    $tryCounter = 0
                    do {
                        $tryCounter++
                        if (($htCacheDefinitionsPolicy).($policyDefinitionId)) {
                            $policyReturnedFromHt = $true
                            $policyDefinition = ($htCacheDefinitionsPolicy).($policyDefinitionId)

                            if ([string]::IsnullOrEmpty($policyDefinition.PolicyDefinitionId)) {
                                Write-Host "check: $policyDefinitionId"
                                $policyDefinition
                            }

                            if ($policyDefinition.Type -eq 'Custom') {
                                $policyDefintionScope = $policyDefinition.Scope
                                $policyDefintionScopeMgSub = $policyDefinition.ScopeMgSub
                                $policyDefintionScopeId = $policyDefinition.ScopeId
                            }
                            else {
                                $policyDefintionScope = 'n/a'
                                $policyDefintionScopeMgSub = 'n/a'
                                $policyDefintionScopeId = 'n/a'
                            }

                            $policyAvailability = ''
                            $policyDisplayName = ($policyDefinition).DisplayName
                            $policyDescription = ($policyDefinition).Description
                            $policyDefinitionType = ($policyDefinition).Type
                            $policyDefinitionIsALZ = ($policyDefinition).ALZ
                            $policyCategory = ($policyDefinition).Category
                            $policyDefinitionEffectDefault = ($policyDefinition).effectDefaultValue
                            $policyDefinitionEffectFixed = ($policyDefinition).effectFixedValue
                        }
                        else {
                            #test
                            Write-Host "   attention! $scopeDisplayName ($scopeId); policyAssignment '$($L0mgmtGroupPolicyAssignment.Id)' policyDefinition (Policy) could not be found: '$($policyDefinitionId)' -retry"
                            Start-Sleep -Seconds 1
                        }
                    }
                    until ($policyReturnedFromHt -or $tryCounter -gt 2)
                    if (-not $policyReturnedFromHt) {
                        Write-Host "   attention! $scopeDisplayName ($scopeId); policyAssignment '$($L0mgmtGroupPolicyAssignment.Id)' policyDefinition (Policy) could not be found: '$($policyDefinitionId)'"
                        Write-Host "   scope: $($scopeId) Policy / Custom:$($mgPolicyDefinitions.Count) CustomAtScope:$($PolicyDefinitionsScopedCount)"
                        Write-Host "   built-in PolicyDefinitions: $($($htCacheDefinitionsPolicy).Values.where({$_.Type -eq 'BuiltIn'}).Count)"
                        Write-Host "   custom PolicyDefinitions: $($($htCacheDefinitionsPolicy).Values.where({$_.Type -eq 'Custom'}).Count)"
                        Write-Host '   Listing all PolicyDefinitions:'
                        foreach ($tmpPolicyDefinitionId in ($($htCacheDefinitionsPolicy).Keys | Sort-Object)) {
                            Write-Host $tmpPolicyDefinitionId
                        }
                        Throw 'Error - Azure Governance Visualizer: check the last console output for details'
                    }
                }
                #policyDefinition Scope does not exist
                else {
                    if ($htManagementGroupsMgPath.Keys -contains $hlpPolicyDefinitionScope) {
                        Write-Host "   $scopeDisplayName ($scopeId); policyAssignment '$($L0mgmtGroupPolicyAssignment.Id)' policyDefinition (Policy) could not be found: '$($policyDefinitionId)' - the scope '$($hlpPolicyDefinitionScope)' is not contained in the '$scopeId' Management Group chain. The Policy definition scope '$hlpPolicyDefinitionScope' has MGPath: '$($htManagementGroupsMgPath.($hlpPolicyDefinitionScope).pathDelimited)'"
                    }
                    else {
                        Write-Host "   $scopeDisplayName ($scopeId); policyAssignment '$($L0mgmtGroupPolicyAssignment.Id)' policyDefinition (Policy) could not be found: '$($policyDefinitionId)' - the scope '$($hlpPolicyDefinitionScope)' could not be found"
                    }
                    $policyAvailability = 'na'

                    $policyDefintionScope = "/$($policyDefinitionSplitted[1])/$($policyDefinitionSplitted[2])/$($policyDefinitionSplitted[3])/$($hlpPolicyDefinitionScope)"
                    $policyDefintionScopeMgSub = 'Mg'
                    $policyDefintionScopeId = $hlpPolicyDefinitionScope

                    $policyDisplayName = 'unknown'
                    $policyDescription = 'unknown'
                    $policyDefinitionType = 'likely Custom'
                    $policyDefinitionIsALZ = 'unknown'
                    $policyCategory = 'unknown'
                    $policyDefinitionEffectDefault = 'unknown'
                    $policyDefinitionEffectFixed = 'unknown'
                }

                $policyAssignmentScope = $L0mgmtGroupPolicyAssignment.Properties.Scope
                $policyAssignmentId = ($L0mgmtGroupPolicyAssignment.Id).ToLower()
                $policyAssignmentName = $L0mgmtGroupPolicyAssignment.Name
                $policyAssignmentDisplayName = $L0mgmtGroupPolicyAssignment.Properties.DisplayName
                if (($L0mgmtGroupPolicyAssignment.Properties.Description).length -eq 0) {
                    $policyAssignmentDescription = 'no description given'
                }
                else {
                    $policyAssignmentDescription = $L0mgmtGroupPolicyAssignment.Properties.Description
                }

                if ($L0mgmtGroupPolicyAssignment.identity) {
                    $policyAssignmentIdentity = $L0mgmtGroupPolicyAssignment.identity.principalId
                }
                else {
                    $policyAssignmentIdentity = 'n/a'
                }

                $assignedBy = 'n/a'
                $createdBy = ''
                $createdOn = ''
                $updatedBy = ''
                $updatedOn = ''
                if ($L0mgmtGroupPolicyAssignment.properties.metadata) {
                    if ($L0mgmtGroupPolicyAssignment.properties.metadata.assignedBy) {
                        $assignedBy = $L0mgmtGroupPolicyAssignment.properties.metadata.assignedBy
                    }
                    if ($L0mgmtGroupPolicyAssignment.properties.metadata.createdBy) {
                        $createdBy = $L0mgmtGroupPolicyAssignment.properties.metadata.createdBy
                    }
                    if ($L0mgmtGroupPolicyAssignment.properties.metadata.createdOn) {
                        $createdOn = $L0mgmtGroupPolicyAssignment.properties.metadata.createdOn
                    }
                    if ($L0mgmtGroupPolicyAssignment.properties.metadata.updatedBy) {
                        $updatedBy = $L0mgmtGroupPolicyAssignment.properties.metadata.updatedBy
                    }
                    if ($L0mgmtGroupPolicyAssignment.properties.metadata.updatedOn) {
                        $updatedOn = $L0mgmtGroupPolicyAssignment.properties.metadata.updatedOn
                    }
                }

                if ($L0mgmtGroupPolicyAssignment.Properties.nonComplianceMessages.Message) {
                    $nonComplianceMessage = $L0mgmtGroupPolicyAssignment.Properties.nonComplianceMessages.Message
                }
                else {
                    $nonComplianceMessage = ''
                }

                $formatedPolicyAssignmentParameters = ''
                $hlp = $L0mgmtGroupPolicyAssignment.Properties.Parameters
                if (-not [string]::IsNullOrEmpty($hlp)) {
                    $arrayPolicyAssignmentParameters = @()
                    $arrayPolicyAssignmentParameters = foreach ($parameterName in $hlp.PSObject.Properties.Name | Sort-Object) {
                        "$($parameterName)=$($hlp.($parameterName).Value -join "$($CsvDelimiter) ")"
                    }
                    $formatedPolicyAssignmentParameters = $arrayPolicyAssignmentParameters -join "$($CsvDelimiterOpposite) "
                }

                $addRowToTableDone = $true
                addRowToTable `
                    -level $hierarchyLevel `
                    -mgName $scopeDisplayName `
                    -mgId $scopeId `
                    -mgParentId $mgParentId `
                    -mgParentName $mgParentName `
                    -mgASCSecureScore $mgAscSecureScoreResult `
                    -Policy $policyDisplayName `
                    -PolicyAvailability $policyAvailability `
                    -PolicyDescription $policyDescription `
                    -PolicyVariant $policyVariant `
                    -PolicyType $policyDefinitionType `
                    -PolicyIsALZ $policyDefinitionIsALZ `
                    -PolicyCategory $policyCategory `
                    -PolicyDefinitionIdGuid ($policyDefinitionId -replace '.*/') `
                    -PolicyDefinitionId $policyDefinitionId `
                    -PolicyDefintionScope $policyDefintionScope `
                    -PolicyDefintionScopeMgSub $policyDefintionScopeMgSub `
                    -PolicyDefintionScopeId $policyDefintionScopeId `
                    -PolicyDefinitionsScopedLimit $LimitPOLICYPolicyDefinitionsScopedManagementGroup `
                    -PolicyDefinitionsScopedCount $policyDefinitionsScopedCount `
                    -PolicySetDefinitionsScopedLimit $LimitPOLICYPolicySetDefinitionsScopedManagementGroup `
                    -PolicySetDefinitionsScopedCount $policySetDefinitionsScopedCount `
                    -PolicyDefinitionEffectDefault $policyDefinitionEffectDefault `
                    -PolicyDefinitionEffectFixed $policyDefinitionEffectFixed `
                    -PolicyAssignmentScope $policyAssignmentScope `
                    -PolicyAssignmentScopeMgSubRg 'Mg' `
                    -PolicyAssignmentScopeName ($policyAssignmentScope -replace '.*/', '') `
                    -PolicyAssignmentNotScopes $L0mgmtGroupPolicyAssignment.Properties.NotScopes `
                    -PolicyAssignmentId $policyAssignmentId `
                    -PolicyAssignmentName $policyAssignmentName `
                    -PolicyAssignmentDisplayName $policyAssignmentDisplayName `
                    -PolicyAssignmentDescription $policyAssignmentDescription `
                    -PolicyAssignmentEnforcementMode $L0mgmtGroupPolicyAssignment.Properties.EnforcementMode `
                    -PolicyAssignmentNonComplianceMessages $nonComplianceMessage `
                    -PolicyAssignmentIdentity $policyAssignmentIdentity `
                    -PolicyAssignmentLimit $LimitPOLICYPolicyAssignmentsManagementGroup `
                    -PolicyAssignmentCount $L0mgmtGroupPolicyAssignmentsPolicyCount `
                    -PolicyAssignmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount `
                    -PolicyAssignmentParameters $L0mgmtGroupPolicyAssignment.Properties.Parameters `
                    -PolicyAssignmentParametersFormated $formatedPolicyAssignmentParameters `
                    -PolicyAssignmentAssignedBy $assignedBy `
                    -PolicyAssignmentCreatedBy $createdBy `
                    -PolicyAssignmentCreatedOn $createdOn `
                    -PolicyAssignmentUpdatedBy $updatedBy `
                    -PolicyAssignmentUpdatedOn $updatedOn `
                    -PolicySetAssignmentLimit $LimitPOLICYPolicySetAssignmentsManagementGroup `
                    -PolicySetAssignmentCount $L0mgmtGroupPolicyAssignmentsPolicySetCount `
                    -PolicySetAssignmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount `
                    -PolicyAndPolicySetAssignmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicyAndPolicySetAtScopeCount
            }

            #policySet
            if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policySetDefinitions/') {
                $policyVariant = 'PolicySet'
                $policySetDefinitionId = ($L0mgmtGroupPolicyAssignment.properties.policydefinitionid).ToLower()
                $policySetDefinitionSplitted = $policySetDefinitionId.split('/')
                $hlpPolicySetDefinitionScope = $policySetDefinitionSplitted[4]

                $tryCounter = 0
                do {
                    $tryCounter++
                    if (($htCacheDefinitionsPolicySet).($policySetDefinitionId)) {
                        $policySetReturnedFromHt = $true
                        $policySetDefinition = ($htCacheDefinitionsPolicySet).($policySetDefinitionId)
                        if ($policySetDefinition.Type -eq 'Custom') {
                            $policySetDefintionScope = $policySetDefinition.Scope
                            $policySetDefintionScopeMgSub = $policySetDefinition.ScopeMgSub
                            $policySetDefintionScopeId = $policySetDefinition.ScopeId
                        }
                        else {
                            $policySetDefintionScope = 'n/a'
                            $policySetDefintionScopeMgSub = 'n/a'
                            $policySetDefintionScopeId = 'n/a'
                        }
                        $policySetDisplayName = $policySetDefinition.DisplayName
                        $policySetDescription = $policySetDefinition.Description
                        $policySetDefinitionType = $policySetDefinition.Type
                        $policySetDefinitionIsALZ = $policySetDefinition.ALZ
                        $policySetCategory = $policySetDefinition.Category
                    }
                    else {
                        #test
                        #Write-Host "pa '($L0mgmtGroupPolicyAssignment.Id)' scope: '$($scopeId)' - policySetDefinition not available: $policySetDefinitionId"
                        Start-Sleep -Seconds 1
                    }
                }
                until ($policySetReturnedFromHt -or $tryCounter -gt 2)
                if (-not $policySetReturnedFromHt) {
                    Write-Host "   $scopeDisplayName ($scopeId); policyAssignment '$($L0mgmtGroupPolicyAssignment.Id)' policyDefinition (PolicySet) could not be found: '$($policySetDefinitionId)'"
                    $policySetDefintionScope = "/$($policySetDefinitionSplitted[1])/$($policySetDefinitionSplitted[2])/$($policySetDefinitionSplitted[3])/$($hlpPolicySetDefinitionScope)"
                    $policySetDefintionScopeMgSub = 'Mg'
                    $policySetDefintionScopeId = $hlpPolicySetDefinitionScope
                    $policySetDisplayName = 'unknown'
                    $policySetDescription = 'unknown'
                    $policySetDefinitionType = 'likely Custom'
                    $policySetDefinitionIsALZ = 'unknown'
                    $policySetCategory = 'unknown'
                }

                $policyAssignmentScope = $L0mgmtGroupPolicyAssignment.Properties.Scope
                $policyAssignmentId = ($L0mgmtGroupPolicyAssignment.Id).ToLower()
                $policyAssignmentName = $L0mgmtGroupPolicyAssignment.Name
                $policyAssignmentDisplayName = $L0mgmtGroupPolicyAssignment.Properties.DisplayName
                if (($L0mgmtGroupPolicyAssignment.Properties.Description).length -eq 0) {
                    $policyAssignmentDescription = 'no description given'
                }
                else {
                    $policyAssignmentDescription = $L0mgmtGroupPolicyAssignment.Properties.Description
                }

                if ($L0mgmtGroupPolicyAssignment.identity) {
                    $policyAssignmentIdentity = $L0mgmtGroupPolicyAssignment.identity.principalId
                }
                else {
                    $policyAssignmentIdentity = 'n/a'
                }

                $assignedBy = 'n/a'
                $createdBy = ''
                $createdOn = ''
                $updatedBy = ''
                $updatedOn = ''
                if ($L0mgmtGroupPolicyAssignment.properties.metadata) {
                    if ($L0mgmtGroupPolicyAssignment.properties.metadata.assignedBy) {
                        $assignedBy = $L0mgmtGroupPolicyAssignment.properties.metadata.assignedBy
                    }
                    if ($L0mgmtGroupPolicyAssignment.properties.metadata.createdBy) {
                        $createdBy = $L0mgmtGroupPolicyAssignment.properties.metadata.createdBy
                    }
                    if ($L0mgmtGroupPolicyAssignment.properties.metadata.createdOn) {
                        $createdOn = $L0mgmtGroupPolicyAssignment.properties.metadata.createdOn
                    }
                    if ($L0mgmtGroupPolicyAssignment.properties.metadata.updatedBy) {
                        $updatedBy = $L0mgmtGroupPolicyAssignment.properties.metadata.updatedBy
                    }
                    if ($L0mgmtGroupPolicyAssignment.properties.metadata.updatedOn) {
                        $updatedOn = $L0mgmtGroupPolicyAssignment.properties.metadata.updatedOn
                    }
                }

                if (($L0mgmtGroupPolicyAssignment.Properties.nonComplianceMessages.where( { -not $_.policyDefinitionReferenceId } )).Message) {
                    $nonComplianceMessage = ($L0mgmtGroupPolicyAssignment.Properties.nonComplianceMessages.where( { -not $_.policyDefinitionReferenceId } )).Message
                }
                else {
                    $nonComplianceMessage = ''
                }

                $formatedPolicyAssignmentParameters = ''
                $hlp = $L0mgmtGroupPolicyAssignment.Properties.Parameters
                if (-not [string]::IsNullOrEmpty($hlp)) {
                    $arrayPolicyAssignmentParameters = @()
                    $arrayPolicyAssignmentParameters = foreach ($parameterName in $hlp.PSObject.Properties.Name | Sort-Object) {
                        "$($parameterName)=$($hlp.($parameterName).Value -join "$($CsvDelimiter) ")"
                    }
                    $formatedPolicyAssignmentParameters = $arrayPolicyAssignmentParameters -join "$($CsvDelimiterOpposite) "
                }

                $addRowToTableDone = $true
                addRowToTable `
                    -level $hierarchyLevel `
                    -mgName $scopeDisplayName `
                    -mgId $scopeId `
                    -mgParentId $mgParentId `
                    -mgParentName $mgParentName `
                    -mgASCSecureScore $mgAscSecureScoreResult `
                    -Policy $policySetDisplayName `
                    -PolicyDescription $policySetDescription `
                    -PolicyVariant $policyVariant `
                    -PolicyType $policySetDefinitionType `
                    -PolicyIsALZ $policySetDefinitionIsALZ `
                    -PolicyCategory $policySetCategory `
                    -PolicyDefinitionIdGuid ($policySetDefinitionId -replace '.*/') `
                    -PolicyDefinitionId $policySetDefinitionId `
                    -PolicyDefintionScope $policySetDefintionScope `
                    -PolicyDefintionScopeMgSub $policySetDefintionScopeMgSub `
                    -PolicyDefintionScopeId $policySetDefintionScopeId `
                    -PolicyDefinitionsScopedLimit $LimitPOLICYPolicyDefinitionsScopedManagementGroup `
                    -PolicyDefinitionsScopedCount $policyDefinitionsScopedCount `
                    -PolicySetDefinitionsScopedLimit $LimitPOLICYPolicySetDefinitionsScopedManagementGroup `
                    -PolicySetDefinitionsScopedCount $policySetDefinitionsScopedCount `
                    -PolicyAssignmentScope $policyAssignmentScope `
                    -PolicyAssignmentScopeMgSubRg 'Mg' `
                    -PolicyAssignmentScopeName ($policyAssignmentScope -replace '.*/', '') `
                    -PolicyAssignmentNotScopes $L0mgmtGroupPolicyAssignment.Properties.NotScopes `
                    -PolicyAssignmentId $policyAssignmentId `
                    -PolicyAssignmentName $policyAssignmentName `
                    -PolicyAssignmentDisplayName $policyAssignmentDisplayName `
                    -PolicyAssignmentDescription $policyAssignmentDescription `
                    -PolicyAssignmentEnforcementMode $L0mgmtGroupPolicyAssignment.Properties.EnforcementMode `
                    -PolicyAssignmentNonComplianceMessages $nonComplianceMessage `
                    -PolicyAssignmentIdentity $policyAssignmentIdentity `
                    -PolicyAssignmentLimit $LimitPOLICYPolicyAssignmentsManagementGroup `
                    -PolicyAssignmentCount $L0mgmtGroupPolicyAssignmentsPolicyCount `
                    -PolicyAssignmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount `
                    -PolicyAssignmentParameters $L0mgmtGroupPolicyAssignment.Properties.Parameters `
                    -PolicyAssignmentParametersFormated $formatedPolicyAssignmentParameters `
                    -PolicyAssignmentAssignedBy $assignedBy `
                    -PolicyAssignmentCreatedBy $createdBy `
                    -PolicyAssignmentCreatedOn $createdOn `
                    -PolicyAssignmentUpdatedBy $updatedBy `
                    -PolicyAssignmentUpdatedOn $updatedOn `
                    -PolicySetAssignmentLimit $LimitPOLICYPolicySetAssignmentsManagementGroup `
                    -PolicySetAssignmentCount $L0mgmtGroupPolicyAssignmentsPolicySetCount `
                    -PolicySetAssignmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount `
                    -PolicyAndPolicySetAssignmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicyAndPolicySetAtScopeCount
            }
        }
    }

    $returnObject = @{}
    if ($addRowToTableDone) {
        $returnObject.'addRowToTableDone' = @{}
    }
    return $returnObject
}
$funcDataCollectionPolicyAssignmentsMG = $function:dataCollectionPolicyAssignmentsMG.ToString()

function dataCollectionPolicyAssignmentsSub {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $hierarchyLevel,
        $childMgDisplayName,
        $childMgId,
        $childMgParentId,
        $childMgParentName,
        $mgAscSecureScoreResult,
        $subscriptionQuotaId,
        $subscriptionState,
        $subscriptionASCSecureScore,
        $subscriptionTags,
        $subscriptionTagsCount,
        $PolicyDefinitionsScopedCount,
        $PolicySetDefinitionsScopedCount
    )

    $currentTask = "Getting Policy assignments for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Authorization/policyAssignments?api-version=2021-06-01"
    $method = 'GET'

    $addRowToTableDone = $false
    if ($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy -eq $false) {
        $L1mgmtGroupSubPolicyAssignments = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

        $L1mgmtGroupSubPolicyAssignmentsPolicyCount = ($L1mgmtGroupSubPolicyAssignments.where( { $_.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policyDefinitions/' } )).count
        $L1mgmtGroupSubPolicyAssignmentsPolicySetCount = ($L1mgmtGroupSubPolicyAssignments.where( { $_.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policySetDefinitions/' } )).count
        $L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount = ($L1mgmtGroupSubPolicyAssignments.where( { $_.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policyDefinitions/' -and $_.Id -match "/subscriptions/$($scopeId)" } )).count
        $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount = ($L1mgmtGroupSubPolicyAssignments.where( { $_.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policySetDefinitions/' -and $_.Id -match "/subscriptions/$($scopeId)" } )).count
        $L1mgmtGroupSubPolicyAssignmentsQuery = $L1mgmtGroupSubPolicyAssignments
    }
    else {
        $L1mgmtGroupSubPolicyAssignments = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

        $L1mgmtGroupSubPolicyAssignmentsPolicyCount = ($L1mgmtGroupSubPolicyAssignments.where( { $_.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policyDefinitions/' -and $_.Id -notmatch "/subscriptions/$($scopeId)/resourceGroups" } )).count
        $L1mgmtGroupSubPolicyAssignmentsPolicySetCount = ($L1mgmtGroupSubPolicyAssignments.where( { $_.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policySetDefinitions/' -and $_.Id -notmatch "/subscriptions/$($scopeId)/resourceGroups" } )).count
        $L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount = ($L1mgmtGroupSubPolicyAssignments.where( { $_.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policyDefinitions/' -and $_.Id -match "/subscriptions/$($scopeId)" -and $_.Id -notmatch "/subscriptions/$($scopeId)/resourceGroups" } )).count
        $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount = ($L1mgmtGroupSubPolicyAssignments.where( { $_.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policySetDefinitions/' -and $_.Id -match "/subscriptions/$($scopeId)" -and $_.Id -notmatch "/subscriptions/$($scopeId)/resourceGroups" } )).count
        foreach ($L1mgmtGroupSubPolicyAssignment in $L1mgmtGroupSubPolicyAssignments.where( { $_.Id -match "/subscriptions/$($scopeId)/resourceGroups" } )) {
            ($script:htCacheAssignmentsPolicyOnResourceGroupsAndResources).(($L1mgmtGroupSubPolicyAssignment.Id).ToLower()) = $L1mgmtGroupSubPolicyAssignment
        }
        $L1mgmtGroupSubPolicyAssignmentsQuery = $L1mgmtGroupSubPolicyAssignments.where( { $_.Id -notmatch "/subscriptions/$($scopeId)/resourceGroups" } )
    }

    $L1mgmtGroupSubPolicyAssignmentsPolicyAndPolicySetAtScopeCount = ($L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount + $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount)

    foreach ($L1mgmtGroupSubPolicyAssignment in $L1mgmtGroupSubPolicyAssignmentsQuery ) {
        if ($L1mgmtGroupSubPolicyAssignment.Id -like "/subscriptions/$($scopeId)/*") {
            $htTemp = @{}
            $htTemp.Assignment = $L1mgmtGroupSubPolicyAssignment
            $splitAssignment = (($L1mgmtGroupSubPolicyAssignment.Id).ToLower()).Split('/')
            if (($L1mgmtGroupSubPolicyAssignment.Id).ToLower() -like "/subscriptions/$($scopeId)/resourceGroups*") {
                $htTemp.AssignmentScopeMgSubRg = 'Rg'
                $htTemp.AssignmentScopeId = "$($splitAssignment[2])/$($splitAssignment[4])"
            }
            else {
                $htTemp.AssignmentScopeMgSubRg = 'Sub'
                $htTemp.AssignmentScopeId = [string]$splitAssignment[2]
            }
            $script:htCacheAssignmentsPolicy.(($L1mgmtGroupSubPolicyAssignment.Id).ToLower()) = $htTemp
        }

        #region namingValidation
        if (-not [string]::IsNullOrEmpty($L1mgmtGroupSubPolicyAssignment.Properties.DisplayName)) {
            $namingValidationResult = NamingValidation -toCheck $L1mgmtGroupSubPolicyAssignment.Properties.DisplayName
            if ($namingValidationResult.Count -gt 0) {
                if (-not $script:htNamingValidation.PolicyAssignment.($L1mgmtGroupSubPolicyAssignment.Id)) {
                    $script:htNamingValidation.PolicyAssignment.($L1mgmtGroupSubPolicyAssignment.Id) = @{}
                }
                $script:htNamingValidation.PolicyAssignment.($L1mgmtGroupSubPolicyAssignment.Id).displayNameInvalidChars = ($namingValidationResult -join '')
                $script:htNamingValidation.PolicyAssignment.($L1mgmtGroupSubPolicyAssignment.Id).displayName = $L1mgmtGroupSubPolicyAssignment.Properties.DisplayName
            }
        }
        if (-not [string]::IsNullOrEmpty($L1mgmtGroupSubPolicyAssignment.Name)) {
            $namingValidationResult = NamingValidation -toCheck $L1mgmtGroupSubPolicyAssignment.Name
            if ($namingValidationResult.Count -gt 0) {
                if (-not $script:htNamingValidation.PolicyAssignment.($L1mgmtGroupSubPolicyAssignment.Id)) {
                    $script:htNamingValidation.PolicyAssignment.($L1mgmtGroupSubPolicyAssignment.Id) = @{}
                }
                $script:htNamingValidation.PolicyAssignment.($L1mgmtGroupSubPolicyAssignment.Id).nameInvalidChars = ($namingValidationResult -join '')
                $script:htNamingValidation.PolicyAssignment.($L1mgmtGroupSubPolicyAssignment.Id).name = $L1mgmtGroupSubPolicyAssignment.Name
            }
        }
        #endregion namingValidation

        if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policyDefinitions/' -OR $L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policySetDefinitions/') {

            #policy
            if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policyDefinitions/') {
                $policyVariant = 'Policy'
                $policyDefinitionId = ($L1mgmtGroupSubPolicyAssignment.properties.policydefinitionid).ToLower()

                if (($htCacheDefinitionsPolicy).($policyDefinitionId)) {
                    $policyAvailability = ''

                    #handling some strange scenario where the synchronized hashTable responds fragments?!
                    $tryCounter = 0
                    do {
                        $tryCounter++
                        $policyAssignmentsPolicyDefinition = ($htCacheDefinitionsPolicy).($policyDefinitionId)

                        if (($policyAssignmentsPolicyDefinition).Type -eq 'Custom' -or ($policyAssignmentsPolicyDefinition).Type -eq 'Builtin') {
                            $policyReturnedFromHt = $true

                            $policyDisplayName = ($policyAssignmentsPolicyDefinition).DisplayName
                            $policyDescription = ($policyAssignmentsPolicyDefinition).Description
                            $policyDefinitionType = ($policyAssignmentsPolicyDefinition).Type
                            $policyDefinitionIsALZ = ($policyAssignmentsPolicyDefinition).ALZ
                            $policyCategory = ($policyAssignmentsPolicyDefinition).Category
                            $policyDefinitionEffectDefault = ($policyAssignmentsPolicyDefinition).effectDefaultValue
                            $policyDefinitionEffectFixed = ($policyAssignmentsPolicyDefinition).effectFixedValue

                            if (($policyAssignmentsPolicyDefinition).Type -ne $policyDefinitionType) {
                                Write-Host "$scopeDisplayName ($scopeId) $policyVariant was processing: $policyDefinitionId"
                                Write-Host "'$(($policyAssignmentsPolicyDefinition).Type)' ne '$policyDefinitionType'"
                                Write-Host "!Please report this error: $($azAPICallConf['htParameters'].GithubRepository)" -ForegroundColor Yellow
                                throw
                            }

                            if ($policyDefinitionType -eq 'Custom') {
                                $policyDefintionScope = ($policyAssignmentsPolicyDefinition).Scope
                                $policyDefintionScopeMgSub = ($policyAssignmentsPolicyDefinition).ScopeMgSub
                                $policyDefintionScopeId = ($policyAssignmentsPolicyDefinition).ScopeId
                            }

                            if ($policyDefinitionType -eq 'Builtin') {
                                $policyDefintionScope = 'n/a'
                                $policyDefintionScopeMgSub = 'n/a'
                                $policyDefintionScopeId = 'n/a'
                            }
                        }
                        else {
                            Write-Host " **INCONSISTENCY! processing policyId:'$policyDefinitionId'; policyAss:'$($L1mgmtGroupSubPolicyAssignment.Id)'; policyAssignmentsPolicyDefinition.Type: '$($policyAssignmentsPolicyDefinition.Type)'"
                            Start-Sleep -Seconds 1
                        }
                    }
                    until($policyReturnedFromHt -or $tryCounter -gt 5)
                    if (-not $policyReturnedFromHt) {
                        Write-Host "FinalHandler - $scopeDisplayName ($scopeId) $policyVariant was processing: policyId:'$policyDefinitionId'; policyAss:'$($L1mgmtGroupSubPolicyAssignment.Id)'; policyAssignmentsPolicyDefinition.Type: '$($policyAssignmentsPolicyDefinition.Type)'"
                        Write-Host ($policyAssignmentsPolicyDefinition | ConvertTo-Json -Depth 99)
                        Write-Host "!Please report this error: $($azAPICallConf['htParameters'].GithubRepository)" -ForegroundColor Yellow
                        throw
                    }
                }
                #policyDefinition not exists!
                else {
                    $policyDefinitionSplitted = $policyDefinitionId.split('/')

                    if ($policyDefinitionId -like '/providers/microsoft.management/managementgroups/*') {
                        $hlpPolicyDefinitionScope = $policyDefinitionSplitted[4]
                        if ($htSubscriptionsMgPath.($scopeId).path -contains $hlpPolicyDefinitionScope) {
                            Write-Host "   ATTENTION: $scopeDisplayName ($scopeId); policyAssignment '$($L1mgmtGroupSubPolicyAssignment.Id)' policyDefinition (Policy) could not be found: '$($policyDefinitionId)' - the scope '$($hlpPolicyDefinitionScope)' HOWEVER IS CONTAINED in the '$scopeId' Management Group chain. The Policy definition scope '$hlpPolicyDefinitionScope' has MGPath: '$($htManagementGroupsMgPath.($hlpPolicyDefinitionScope).pathDelimited)'"
                        }
                        else {
                            if ($htManagementGroupsMgPath.($hlpPolicyDefinitionScope)) {
                                Write-Host "   $scopeDisplayName ($scopeId); policyAssignment '$($L1mgmtGroupSubPolicyAssignment.Id)' policyDefinition (Policy) could not be found: '$($policyDefinitionId)' - the scope '$($hlpPolicyDefinitionScope)' IS NOT CONTAINED in the '$scopeId' Management Group chain. The Policy definition scope '$hlpPolicyDefinitionScope' has MGPath: '$($htManagementGroupsMgPath.($hlpPolicyDefinitionScope).pathDelimited)'"
                            }
                            else {
                                Write-Host "   $scopeDisplayName ($scopeId); policyAssignment '$($L1mgmtGroupSubPolicyAssignment.Id)' policyDefinition (Policy) could not be found: '$($policyDefinitionId)' - the scope '$($hlpPolicyDefinitionScope)' IS NOT CONTAINED in the '$scopeId' Management Group chain. The Policy definition scope '$hlpPolicyDefinitionScope' could not be found"
                            }
                        }
                        $policyDefintionScope = "/$($policyDefinitionSplitted[1])/$($policyDefinitionSplitted[2])/$($policyDefinitionSplitted[3])/$($hlpPolicyDefinitionScope)"
                        $policyDefintionScopeMgSub = 'Mg'
                        $policyDefintionScopeId = $hlpPolicyDefinitionScope
                    }
                    else {
                        $hlpPolicyDefinitionScope = $policyDefinitionSplitted[2]
                        Write-Host "   $scopeDisplayName ($scopeId); policyAssignment '$($L1mgmtGroupSubPolicyAssignment.Id)' policyDefinition (Policy) could not be found: '$($policyDefinitionId)'"
                        $policyDefintionScope = "/$($policyDefinitionSplitted[1])/$($hlpPolicyDefinitionScope)"
                        $policyDefintionScopeMgSub = 'Sub'
                        $policyDefintionScopeId = $hlpPolicyDefinitionScope
                    }
                    $policyAvailability = 'na'
                    $policyDisplayName = 'unknown'
                    $policyDescription = 'unknown'
                    $policyDefinitionType = 'likely Custom'
                    $policyDefinitionIsALZ = 'unknown'
                    $policyCategory = 'unknown'
                    $policyDefinitionEffectDefault = 'unknown'
                    $policyDefinitionEffectFixed = 'unknown'
                }

                $PolicyAssignmentScope = $L1mgmtGroupSubPolicyAssignment.Properties.Scope
                if ($PolicyAssignmentScope -like '/providers/Microsoft.Management/managementGroups/*') {
                    $PolicyAssignmentScopeMgSubRg = 'Mg'
                }
                else {
                    $splitPolicyAssignmentScope = ($PolicyAssignmentScope).Split('/')
                    switch (($splitPolicyAssignmentScope).Count - 1) {
                        #sub
                        2 {
                            $PolicyAssignmentScopeMgSubRg = 'Sub'
                        }
                        4 {
                            $PolicyAssignmentScopeMgSubRg = 'Rg'
                        }
                        Default {
                            $PolicyAssignmentScopeMgSubRg = 'unknown'
                        }
                    }
                }

                $PolicyAssignmentId = ($L1mgmtGroupSubPolicyAssignment.Id).ToLower()
                $PolicyAssignmentName = $L1mgmtGroupSubPolicyAssignment.Name
                $PolicyAssignmentDisplayName = $L1mgmtGroupSubPolicyAssignment.Properties.DisplayName
                if (($L1mgmtGroupSubPolicyAssignment.Properties.Description).length -eq 0) {
                    $PolicyAssignmentDescription = 'no description given'
                }
                else {
                    $PolicyAssignmentDescription = $L1mgmtGroupSubPolicyAssignment.Properties.Description
                }

                if ($L1mgmtGroupSubPolicyAssignment.identity) {
                    $PolicyAssignmentIdentity = $L1mgmtGroupSubPolicyAssignment.identity.principalId
                }
                else {
                    $PolicyAssignmentIdentity = 'n/a'
                }

                $assignedBy = 'n/a'
                $createdBy = ''
                $createdOn = ''
                $updatedBy = ''
                $updatedOn = ''
                if ($L1mgmtGroupSubPolicyAssignment.properties.metadata) {
                    if ($L1mgmtGroupSubPolicyAssignment.properties.metadata.assignedBy) {
                        $assignedBy = $L1mgmtGroupSubPolicyAssignment.properties.metadata.assignedBy
                    }
                    if ($L1mgmtGroupSubPolicyAssignment.properties.metadata.createdBy) {
                        $createdBy = $L1mgmtGroupSubPolicyAssignment.properties.metadata.createdBy
                    }
                    if ($L1mgmtGroupSubPolicyAssignment.properties.metadata.createdOn) {
                        $createdOn = $L1mgmtGroupSubPolicyAssignment.properties.metadata.createdOn
                    }
                    if ($L1mgmtGroupSubPolicyAssignment.properties.metadata.updatedBy) {
                        $updatedBy = $L1mgmtGroupSubPolicyAssignment.properties.metadata.updatedBy
                    }
                    if ($L1mgmtGroupSubPolicyAssignment.properties.metadata.updatedOn) {
                        $updatedOn = $L1mgmtGroupSubPolicyAssignment.properties.metadata.updatedOn
                    }
                }

                if ($L1mgmtGroupSubPolicyAssignment.Properties.nonComplianceMessages.Message) {
                    $nonComplianceMessage = $L1mgmtGroupSubPolicyAssignment.Properties.nonComplianceMessages.Message
                }
                else {
                    $nonComplianceMessage = ''
                }

                $formatedPolicyAssignmentParameters = ''
                $hlp = $L1mgmtGroupSubPolicyAssignment.Properties.Parameters
                if (-not [string]::IsNullOrEmpty($hlp)) {
                    $arrayPolicyAssignmentParameters = @()
                    $arrayPolicyAssignmentParameters = foreach ($parameterName in $hlp.PSObject.Properties.Name | Sort-Object) {
                        "$($parameterName)=$($hlp.($parameterName).Value -join "$($CsvDelimiter) ")"
                    }
                    $formatedPolicyAssignmentParameters = $arrayPolicyAssignmentParameters -join "$($CsvDelimiterOpposite) "
                }

                $addRowToTableDone = $true
                addRowToTable `
                    -level $hierarchyLevel `
                    -mgName $childMgDisplayName `
                    -mgId $childMgId `
                    -mgParentId $childMgParentId `
                    -mgParentName $childMgParentName `
                    -mgASCSecureScore $mgAscSecureScoreResult `
                    -Subscription $scopeDisplayName `
                    -SubscriptionId $scopeId `
                    -SubscriptionQuotaId $subscriptionQuotaId `
                    -SubscriptionState $subscriptionState `
                    -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                    -SubscriptionTags $subscriptionTags `
                    -SubscriptionTagsCount $subscriptionTagsCount `
                    -Policy $policyDisplayName `
                    -PolicyAvailability $policyAvailability `
                    -PolicyDescription $policyDescription `
                    -PolicyVariant $policyVariant `
                    -PolicyType $policyDefinitionType `
                    -PolicyIsALZ $policyDefinitionIsALZ `
                    -PolicyCategory $policyCategory `
                    -PolicyDefinitionIdGuid ($policyDefinitionId -replace '.*/') `
                    -PolicyDefinitionId $policyDefinitionId `
                    -PolicyDefintionScope $policyDefintionScope `
                    -PolicyDefintionScopeMgSub $policyDefintionScopeMgSub `
                    -PolicyDefintionScopeId $policyDefintionScopeId `
                    -PolicyDefinitionsScopedLimit $LimitPOLICYPolicyDefinitionsScopedSubscription `
                    -PolicyDefinitionsScopedCount $PolicyDefinitionsScopedCount `
                    -PolicySetDefinitionsScopedLimit $LimitPOLICYPolicySetDefinitionsScopedSubscription `
                    -PolicySetDefinitionsScopedCount $PolicySetDefinitionsScopedCount `
                    -PolicyDefinitionEffectDefault $policyDefinitionEffectDefault `
                    -PolicyDefinitionEffectFixed $policyDefinitionEffectFixed `
                    -PolicyAssignmentScope $PolicyAssignmentScope `
                    -PolicyAssignmentScopeMgSubRg $PolicyAssignmentScopeMgSubRg `
                    -PolicyAssignmentScopeName ($PolicyAssignmentScope -replace '.*/', '') `
                    -PolicyAssignmentNotScopes $L1mgmtGroupSubPolicyAssignment.Properties.NotScopes `
                    -PolicyAssignmentId $PolicyAssignmentId `
                    -PolicyAssignmentName $PolicyAssignmentName `
                    -PolicyAssignmentDisplayName $PolicyAssignmentDisplayName `
                    -PolicyAssignmentDescription $PolicyAssignmentDescription `
                    -PolicyAssignmentEnforcementMode $L1mgmtGroupSubPolicyAssignment.Properties.EnforcementMode `
                    -PolicyAssignmentNonComplianceMessages $nonComplianceMessage `
                    -PolicyAssignmentIdentity $PolicyAssignmentIdentity `
                    -PolicyAssignmentLimit $LimitPOLICYPolicyAssignmentsSubscription `
                    -PolicyAssignmentCount $L1mgmtGroupSubPolicyAssignmentsPolicyCount `
                    -PolicyAssignmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount `
                    -PolicyAssignmentParameters $L1mgmtGroupSubPolicyAssignment.Properties.Parameters `
                    -PolicyAssignmentParametersFormated $formatedPolicyAssignmentParameters `
                    -PolicyAssignmentAssignedBy $assignedBy `
                    -PolicyAssignmentCreatedBy $createdBy `
                    -PolicyAssignmentCreatedOn $createdOn `
                    -PolicyAssignmentUpdatedBy $updatedBy `
                    -PolicyAssignmentUpdatedOn $updatedOn `
                    -PolicySetAssignmentLimit $LimitPOLICYPolicySetAssignmentsSubscription `
                    -PolicySetAssignmentCount $L1mgmtGroupSubPolicyAssignmentsPolicySetCount `
                    -PolicySetAssignmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount `
                    -PolicyAndPolicySetAssignmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicyAndPolicySetAtScopeCount
            }

            #policySet
            if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match '/providers/Microsoft.Authorization/policySetDefinitions/') {
                $policyVariant = 'PolicySet'
                $policySetDefinitionId = ($L1mgmtGroupSubPolicyAssignment.properties.policydefinitionid).ToLower()
                $policySetDefinitionSplitted = $policySetDefinitionId.split('/')

                if (($htCacheDefinitionsPolicySet).($policySetDefinitionId)) {
                    $policyAvailability = ''

                    #handling some strange behavior where the synchronized hashTable responds fragments?!
                    $tryCounter = 0
                    do {
                        $tryCounter++
                        $policyAssignmentsPolicySetDefinition = ($htCacheDefinitionsPolicySet).($policySetDefinitionId)

                        if (($policyAssignmentsPolicySetDefinition).Type -eq 'Custom' -or ($policyAssignmentsPolicySetDefinition).Type -eq 'Builtin') {
                            $policySetReturnedFromHt = $true

                            $policySetDisplayName = ($policyAssignmentsPolicySetDefinition).DisplayName
                            $policySetDescription = ($policyAssignmentsPolicySetDefinition).Description
                            $policySetDefinitionType = ($policyAssignmentsPolicySetDefinition).Type
                            $policySetDefinitionIsALZ = ($policyAssignmentsPolicySetDefinition).ALZ
                            $policySetCategory = ($policyAssignmentsPolicySetDefinition).Category

                            if (($policyAssignmentsPolicySetDefinition).Type -ne $policySetDefinitionType) {
                                Write-Host "$scopeDisplayName ($scopeId) $policyVariant was processing: $policySetDefinitionId"
                                Write-Host "'$(($policyAssignmentsPolicySetDefinition).Type)' ne '$policySetDefinitionType'"
                                Write-Host "!Please report this error: $($azAPICallConf['htParameters'].GithubRepository)" -ForegroundColor Yellow
                                throw
                            }

                            if ($policySetDefinitionType -eq 'Custom') {
                                $policySetDefintionScope = ($policyAssignmentsPolicySetDefinition).Scope
                                $policySetDefintionScopeMgSub = ($policyAssignmentsPolicySetDefinition).ScopeMgSub
                                $policySetDefintionScopeId = ($policyAssignmentsPolicySetDefinition).ScopeId
                            }
                            if ($policySetDefinitionType -eq 'Builtin') {
                                $policySetDefintionScope = 'n/a'
                                $policySetDefintionScopeMgSub = 'n/a'
                                $policySetDefintionScopeId = 'n/a'
                            }
                        }
                        else {
                            #Write-Host "TryHandler - $scopeDisplayName ($scopeId) $policyVariant was processing: policySetId:'$policySetDefinitionId'; policyAss:'$($L1mgmtGroupSubPolicyAssignment.Id)'; type:'$(($policyAssignmentsPolicySetDefinition).Type)' - sleeping '$tryCounter' seconds"
                            Start-Sleep -Seconds 1
                        }
                    }
                    until($policySetReturnedFromHt -or $tryCounter -gt 5)
                    if (-not $policySetReturnedFromHt) {
                        Write-Host "FinalHandler - $scopeDisplayName ($scopeId) $policyVariant was processing: policySetId:'$policySetDefinitionId'; policyAss:'$($L1mgmtGroupSubPolicyAssignment.Id)'"
                        Write-Host "!Please report this error: $($azAPICallConf['htParameters'].GithubRepository)" -ForegroundColor Yellow
                        throw
                    }
                }
                #policySetDefinition not exists!
                else {
                    $policyAvailability = 'na'
                    $policySetDisplayName = 'unknown'
                    $policySetDescription = 'unknown'
                    $policySetDefinitionType = 'likely Custom'
                    $policySetDefinitionIsALZ = 'unknown'
                    $policySetCategory = 'unknown'

                    if ($policySetDefinitionId -like '/providers/microsoft.management/managementgroups/*') {
                        $hlpPolicySetDefinitionScope = $policySetDefinitionSplitted[4]
                        $policySetDefintionScope = "/$($policySetDefinitionSplitted[1])/$($policySetDefinitionSplitted[2])/$($policySetDefinitionSplitted[3])/$($hlpPolicySetDefinitionScope)"
                        $policySetDefintionScopeMgSub = 'Mg'
                        $policySetDefintionScopeId = $hlpPolicySetDefinitionScope
                    }
                    else {
                        $hlpPolicySetDefinitionScope = $policySetDefinitionSplitted[2]
                        $policySetDefintionScope = "/$($policySetDefinitionSplitted[1])/$($hlpPolicySetDefinitionScope)"
                        $policySetDefintionScopeMgSub = 'Sub'
                        $policySetDefintionScopeId = $hlpPolicySetDefinitionScope

                    }
                    Write-Host "   $scopeDisplayName ($scopeId); policyAssignment '$($L1mgmtGroupSubPolicyAssignment.Id)' policyDefinition (PolicySet) could not be found: '$($policySetDefinitionId)'"
                }

                $PolicyAssignmentScope = $L1mgmtGroupSubPolicyAssignment.Properties.Scope
                if ($PolicyAssignmentScope -like '/providers/Microsoft.Management/managementGroups/*') {
                    $PolicyAssignmentScopeMgSubRg = 'Mg'
                }
                else {
                    $splitPolicyAssignmentScope = ($PolicyAssignmentScope).Split('/')
                    switch (($splitPolicyAssignmentScope).Count - 1) {
                        #sub
                        2 {
                            $PolicyAssignmentScopeMgSubRg = 'Sub'
                        }
                        4 {
                            $PolicyAssignmentScopeMgSubRg = 'Rg'
                        }
                        Default {
                            $PolicyAssignmentScopeMgSubRg = 'unknown'
                        }
                    }
                }

                $PolicyAssignmentId = ($L1mgmtGroupSubPolicyAssignment.Id).ToLower()
                $PolicyAssignmentName = $L1mgmtGroupSubPolicyAssignment.Name
                $PolicyAssignmentDisplayName = $L1mgmtGroupSubPolicyAssignment.Properties.DisplayName
                if (($L1mgmtGroupSubPolicyAssignment.Properties.Description).length -eq 0) {
                    $PolicyAssignmentDescription = 'no description given'
                }
                else {
                    $PolicyAssignmentDescription = $L1mgmtGroupSubPolicyAssignment.Properties.Description
                }

                if ($L1mgmtGroupSubPolicyAssignment.identity) {
                    $PolicyAssignmentIdentity = $L1mgmtGroupSubPolicyAssignment.identity.principalId
                }
                else {
                    $PolicyAssignmentIdentity = 'n/a'
                }

                $assignedBy = 'n/a'
                $createdBy = ''
                $createdOn = ''
                $updatedBy = ''
                $updatedOn = ''
                if ($L1mgmtGroupSubPolicyAssignment.properties.metadata) {
                    if ($L1mgmtGroupSubPolicyAssignment.properties.metadata.assignedBy) {
                        $assignedBy = $L1mgmtGroupSubPolicyAssignment.properties.metadata.assignedBy
                    }
                    if ($L1mgmtGroupSubPolicyAssignment.properties.metadata.createdBy) {
                        $createdBy = $L1mgmtGroupSubPolicyAssignment.properties.metadata.createdBy
                    }
                    if ($L1mgmtGroupSubPolicyAssignment.properties.metadata.createdOn) {
                        $createdOn = $L1mgmtGroupSubPolicyAssignment.properties.metadata.createdOn
                    }
                    if ($L1mgmtGroupSubPolicyAssignment.properties.metadata.updatedBy) {
                        $updatedBy = $L1mgmtGroupSubPolicyAssignment.properties.metadata.updatedBy
                    }
                    if ($L1mgmtGroupSubPolicyAssignment.properties.metadata.updatedOn) {
                        $updatedOn = $L1mgmtGroupSubPolicyAssignment.properties.metadata.updatedOn
                    }
                }

                if (($L1mgmtGroupSubPolicyAssignment.Properties.nonComplianceMessages.where( { -not $_.policyDefinitionReferenceId })).Message) {
                    $nonComplianceMessage = ($L1mgmtGroupSubPolicyAssignment.Properties.nonComplianceMessages.where( { -not $_.policyDefinitionReferenceId })).Message
                }
                else {
                    $nonComplianceMessage = ''
                }

                $formatedPolicyAssignmentParameters = ''
                $hlp = $L1mgmtGroupSubPolicyAssignment.Properties.Parameters
                if (-not [string]::IsNullOrEmpty($hlp)) {
                    $arrayPolicyAssignmentParameters = @()
                    $arrayPolicyAssignmentParameters = foreach ($parameterName in $hlp.PSObject.Properties.Name | Sort-Object) {
                        "$($parameterName)=$($hlp.($parameterName).Value -join "$($CsvDelimiter) ")"
                    }
                    $formatedPolicyAssignmentParameters = $arrayPolicyAssignmentParameters -join "$($CsvDelimiterOpposite) "
                }

                $addRowToTableDone = $true
                addRowToTable `
                    -level $hierarchyLevel `
                    -mgName $childMgDisplayName `
                    -mgId $childMgId `
                    -mgParentId $childMgParentId `
                    -mgParentName $childMgParentName `
                    -mgASCSecureScore $mgAscSecureScoreResult `
                    -Subscription $scopeDisplayName `
                    -SubscriptionId $scopeId `
                    -SubscriptionQuotaId $subscriptionQuotaId `
                    -SubscriptionState $subscriptionState `
                    -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                    -SubscriptionTags $subscriptionTags `
                    -SubscriptionTagsCount $subscriptionTagsCount `
                    -Policy $policySetDisplayName `
                    -PolicyAvailability $policyAvailability `
                    -PolicyDescription $policySetDescription `
                    -PolicyVariant $policyVariant `
                    -PolicyType $policySetDefinitionType `
                    -PolicyIsALZ $policySetDefinitionIsALZ `
                    -PolicyCategory $policySetCategory `
                    -PolicyDefinitionIdGuid (($policySetDefinitionId) -replace '.*/') `
                    -PolicyDefinitionId $policySetDefinitionId `
                    -PolicyDefintionScope $policySetDefintionScope `
                    -PolicyDefintionScopeMgSub $policySetDefintionScopeMgSub `
                    -PolicyDefintionScopeId $policySetDefintionScopeId `
                    -PolicyDefinitionsScopedLimit $LimitPOLICYPolicyDefinitionsScopedSubscription `
                    -PolicyDefinitionsScopedCount $PolicyDefinitionsScopedCount `
                    -PolicySetDefinitionsScopedLimit $LimitPOLICYPolicySetDefinitionsScopedSubscription `
                    -PolicySetDefinitionsScopedCount $PolicySetDefinitionsScopedCount `
                    -PolicyAssignmentScope $PolicyAssignmentScope `
                    -PolicyAssignmentScopeMgSubRg $PolicyAssignmentScopeMgSubRg `
                    -PolicyAssignmentScopeName ($PolicyAssignmentScope -replace '.*/', '') `
                    -PolicyAssignmentNotScopes $L1mgmtGroupSubPolicyAssignment.Properties.NotScopes `
                    -PolicyAssignmentId $PolicyAssignmentId `
                    -PolicyAssignmentName $PolicyAssignmentName `
                    -PolicyAssignmentDisplayName $PolicyAssignmentDisplayName `
                    -PolicyAssignmentDescription $PolicyAssignmentDescription `
                    -PolicyAssignmentEnforcementMode $L1mgmtGroupSubPolicyAssignment.Properties.EnforcementMode `
                    -PolicyAssignmentNonComplianceMessages $nonComplianceMessage `
                    -PolicyAssignmentIdentity $PolicyAssignmentIdentity `
                    -PolicyAssignmentLimit $LimitPOLICYPolicyAssignmentsSubscription `
                    -PolicyAssignmentCount $L1mgmtGroupSubPolicyAssignmentsPolicyCount `
                    -PolicyAssignmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount `
                    -PolicyAssignmentParameters $L1mgmtGroupSubPolicyAssignment.Properties.Parameters `
                    -PolicyAssignmentParametersFormated $formatedPolicyAssignmentParameters `
                    -PolicyAssignmentAssignedBy $assignedBy `
                    -PolicyAssignmentCreatedBy $createdBy `
                    -PolicyAssignmentCreatedOn $createdOn `
                    -PolicyAssignmentUpdatedBy $updatedBy `
                    -PolicyAssignmentUpdatedOn $updatedOn `
                    -PolicySetAssignmentLimit $LimitPOLICYPolicySetAssignmentsSubscription `
                    -PolicySetAssignmentCount $L1mgmtGroupSubPolicyAssignmentsPolicySetCount `
                    -PolicySetAssignmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount `
                    -PolicyAndPolicySetAssignmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicyAndPolicySetAtScopeCount
            }
        }
    }

    $returnObject = @{}
    if ($addRowToTableDone) {
        $returnObject.'addRowToTableDone' = @{}
    }
    return $returnObject
}
$funcDataCollectionPolicyAssignmentsSub = $function:dataCollectionPolicyAssignmentsSub.ToString()

function dataCollectionRoleDefinitions {
    [CmdletBinding()]Param(
        [string]$TargetMgOrSub,
        [string]$scopeId,
        [string]$scopeDisplayName,
        $subscriptionQuotaId
    )

    if ($TargetMgOrSub -eq 'Sub') {
        $currentTask = "Getting Custom Role definitions for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Authorization/roleDefinitions?api-version=2018-07-01&`$filter=type eq 'CustomRole'"
    }
    if ($TargetMgOrSub -eq 'MG') {
        $currentTask = "Getting Custom Role definitions for Management Group: '$($scopeDisplayName)' ('$scopeId')"
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($scopeId)/providers/Microsoft.Authorization/roleDefinitions?api-version=2018-07-01&`$filter=type eq 'CustomRole'"
    }
    $method = 'GET'
    $scopeCustomRoleDefinitions = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    foreach ($scopeCustomRoleDefinition in $scopeCustomRoleDefinitions) {
        if (-not $($htCacheDefinitionsRole).($scopeCustomRoleDefinition.name)) {

            if (
                (
                    $scopeCustomRoleDefinition.properties.permissions.Actions -contains 'Microsoft.Authorization/roleassignments/write' -or
                    $scopeCustomRoleDefinition.properties.permissions.Actions -contains 'Microsoft.Authorization/roleassignments/*' -or
                    $scopeCustomRoleDefinition.properties.permissions.Actions -contains 'Microsoft.Authorization/*/write' -or
                    $scopeCustomRoleDefinition.properties.permissions.Actions -contains 'Microsoft.Authorization/*' -or
                    $scopeCustomRoleDefinition.properties.permissions.Actions -contains '*/write' -or
                    $scopeCustomRoleDefinition.properties.permissions.Actions -contains '*'
                ) -and (
                    $scopeCustomRoleDefinition.properties.permissions.NotActions -notcontains 'Microsoft.Authorization/roleassignments/write' -and
                    $scopeCustomRoleDefinition.properties.permissions.NotActions -notcontains 'Microsoft.Authorization/roleassignments/*' -and
                    $scopeCustomRoleDefinition.properties.permissions.NotActions -notcontains 'Microsoft.Authorization/*/write' -and
                    $scopeCustomRoleDefinition.properties.permissions.NotActions -notcontains 'Microsoft.Authorization/*' -and
                    $scopeCustomRoleDefinition.properties.permissions.NotActions -notcontains '*/write' -and
                    $scopeCustomRoleDefinition.properties.permissions.NotActions -notcontains '*'
                )
            ) {
                $roleCapable4RoleAssignmentsWrite = $true
            }
            else {
                $roleCapable4RoleAssignmentsWrite = $false
            }

            $htTemp = @{}
            $htTemp.Id = $($scopeCustomRoleDefinition.name)
            $htTemp.Name = $($scopeCustomRoleDefinition.properties.roleName)
            $htTemp.IsCustom = $true
            $htTemp.AssignableScopes = $($scopeCustomRoleDefinition.properties.AssignableScopes)
            $htTemp.Actions = $($scopeCustomRoleDefinition.properties.permissions.Actions)
            $htTemp.NotActions = $($scopeCustomRoleDefinition.properties.permissions.NotActions)
            $htTemp.DataActions = $($scopeCustomRoleDefinition.properties.permissions.DataActions)
            $htTemp.NotDataActions = $($scopeCustomRoleDefinition.properties.permissions.NotDataActions)
            $htTemp.Json = $scopeCustomRoleDefinition
            $htTemp.RoleCanDoRoleAssignments = $roleCapable4RoleAssignmentsWrite
            ($script:htCacheDefinitionsRole).($scopeCustomRoleDefinition.name) = $htTemp

            #namingValidation
            if (-not [string]::IsNullOrEmpty($scopeCustomRoleDefinition.properties.roleName)) {
                $namingValidationResult = NamingValidation -toCheck $scopeCustomRoleDefinition.properties.roleName
                if ($namingValidationResult.Count -gt 0) {
                    $script:htNamingValidation.Role.($scopeCustomRoleDefinition.name) = @{}
                    $script:htNamingValidation.Role.($scopeCustomRoleDefinition.name).roleNameInvalidChars = ($namingValidationResult -join '')
                    $script:htNamingValidation.Role.($scopeCustomRoleDefinition.name).roleName = $scopeCustomRoleDefinition.properties.roleName
                }
            }
        }
    }
}
$funcDataCollectionRoleDefinitions = $function:dataCollectionRoleDefinitions.ToString()

function dataCollectionRoleAssignmentsMG {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $hierarchyLevel,
        $mgParentId,
        $mgParentName,
        $mgAscSecureScoreResult
    )

    $addRowToTableDone = $false
    #PIM MGRoleAssignmentScheduleInstances
    if ($htDoARMRoleAssignmentScheduleInstances.Do -eq $true) {
        $currentTask = "Getting ARM RoleAssignment ScheduleInstances for Management Group: '$($scopeDisplayName)' ('$($scopeId)')"
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($scopeId)/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01"
        $method = 'GET'
        $roleAssignmentScheduleInstancesFromAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

        if ($roleAssignmentScheduleInstancesFromAPI -eq 'RoleAssignmentScheduleInstancesError' -or $roleAssignmentScheduleInstancesFromAPI -eq 'AadPremiumLicenseRequired') {
            if ($roleAssignmentScheduleInstancesFromAPI -eq 'AadPremiumLicenseRequired') {
                Write-Host "    -> Setting 'htDoARMRoleAssignmentScheduleInstances.Do' to false (AadPremiumLicenseRequired)"
                $script:htDoARMRoleAssignmentScheduleInstances.Do = $false
            }
        }
        else {
            $roleAssignmentScheduleInstances = ($roleAssignmentScheduleInstancesFromAPI.where( { ($_.properties.roleAssignmentScheduleId -replace '.*/') -ne ($_.properties.originRoleAssignmentId -replace '.*/') }))
            $roleAssignmentScheduleInstancesCount = $roleAssignmentScheduleInstances.Count
            if ($roleAssignmentScheduleInstancesCount -gt 0) {
                #$htRoleAssignmentsPIM = @{}
                foreach ($roleAssignmentScheduleInstance in $roleAssignmentScheduleInstances) {
                    $script:htRoleAssignmentsPIM.($roleAssignmentScheduleInstance.properties.originRoleAssignmentId.tolower()) = $roleAssignmentScheduleInstance.properties
                }
            }
        }
    }

    #RoleAssignment API MG
    $currentTask = "Getting Role assignments API for Management Group: '$($scopeDisplayName)' ('$($scopeId)')"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($scopeId)/providers/Microsoft.Authorization/roleAssignments?api-version=2015-07-01"
    $method = 'GET'
    $roleAssignmentsFromAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    if ($roleAssignmentsFromAPI.Count -gt 0) {
        $principalsToResolve = @()
        $principalsToResolve = foreach ($ra in $roleAssignmentsFromAPI.properties | Sort-Object -Property principalId -Unique) {
            if (-not $htPrincipals.($ra.principalId)) {
                $ra.principalId
            }
        }

        if ($principalsToResolve.Count -gt 0) {
            ResolveObjectIds -objectIds $principalsToResolve
        }
    }

    $L0mgmtGroupRoleAssignments = $roleAssignmentsFromAPI

    $L0mgmtGroupRoleAssignmentsLimitUtilization = (($L0mgmtGroupRoleAssignments.properties.where( { $_.scope -eq "/providers/Microsoft.Management/managementGroups/$($scopeId)" } ))).count
    if (-not $htMgAtScopeRoleAssignments.($scopeId)) {
        $script:htMgAtScopeRoleAssignments.($scopeId) = @{}
        $script:htMgAtScopeRoleAssignments.($scopeId).AssignmentsCount = $L0mgmtGroupRoleAssignmentsLimitUtilization
    }

    if ($azAPICallConf['htParameters'].LargeTenant -eq $true -or $azAPICallConf['htParameters'].RBACAtScopeOnly -eq $true) {
        $L0mgmtGroupRoleAssignments = $L0mgmtGroupRoleAssignments.where( { $_.properties.scope -eq "/providers/Microsoft.Management/managementGroups/$($scopeId)" } )
    }
    else {
        #tenantLevelRoleAssignments
        if (-not $htMgAtScopeRoleAssignments.'tenantLevelRoleAssignments') {
            $tenantLevelRoleAssignmentsCount = (($L0mgmtGroupRoleAssignments.where( { $_.id -like '/providers/Microsoft.Authorization/roleAssignments/*' } ))).count
            $script:htMgAtScopeRoleAssignments.'tenantLevelRoleAssignments' = @{}
            $script:htMgAtScopeRoleAssignments.'tenantLevelRoleAssignments'.AssignmentsCount = $tenantLevelRoleAssignmentsCount
        }
    }
    foreach ($L0mgmtGroupRoleAssignment in $L0mgmtGroupRoleAssignments) {
        $roleAssignmentId = ($L0mgmtGroupRoleAssignment.id).ToLower()

        if ($htRoleAssignmentsPIM.($roleAssignmentId)) {
            $hlperPim = $htRoleAssignmentsPIM.($roleAssignmentId)
            $pim = 'true'
            $pimAssignmentType = $hlperPim.assignmentType
            $pimSlotStart = $($hlperPim.startDateTime)
            if ($hlperPim.endDateTime) {
                $pimSlotEnd = $($hlperPim.endDateTime)
            }
            else {
                $pimSlotEnd = 'eternity'
            }
        }
        else {
            $pim = 'false'
            $pimAssignmentType = ''
            $pimSlotStart = ''
            $pimSlotEnd = ''
        }

        if (-not $htRoleAssignmentsFromAPIInheritancePrevention.($roleAssignmentId -replace '.*/')) {
            $script:htRoleAssignmentsFromAPIInheritancePrevention.($roleAssignmentId -replace '.*/') = @{}
            $script:htRoleAssignmentsFromAPIInheritancePrevention.($roleAssignmentId -replace '.*/').assignment = $L0mgmtGroupRoleAssignment
        }

        $roleDefinitionId = $L0mgmtGroupRoleAssignment.properties.roleDefinitionId
        $roleDefinitionIdGuid = $roleDefinitionId -replace '.*/'

        if (-not ($htCacheDefinitionsRole).($roleDefinitionIdGuid)) {
            $roleAssignmentsRoleDefinition = ''
            $roleDefinitionName = "'This roleDefinition likely was deleted although a roleAssignment existed'"
        }
        else {
            $roleAssignmentsRoleDefinition = ($htCacheDefinitionsRole).($roleDefinitionIdGuid)
            $roleDefinitionName = $roleAssignmentsRoleDefinition.Name
        }

        $doIt = $false
        if ($L0mgmtGroupRoleAssignment.properties.scope -eq "/providers/Microsoft.Management/managementGroups/$($scopeId)" -and $L0mgmtGroupRoleAssignment.properties.scope -ne "/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)") {
            $doIt = $true
        }
        if ($scopeId -eq $ManagementGroupId) {
            $doIt = $true
        }

        if ($doIt) {
            #assignment
            $splitAssignment = ($roleAssignmentId).Split('/')
            $arrayRoleAssignment = [System.Collections.ArrayList]@()
            $null = $arrayRoleAssignment.Add([PSCustomObject]@{
                    RoleAssignmentId   = $roleAssignmentId
                    Scope              = $L0mgmtGroupRoleAssignment.properties.scope
                    DisplayName        = $htPrincipals.($L0mgmtGroupRoleAssignment.properties.principalId).displayName
                    SignInName         = $htPrincipals.($L0mgmtGroupRoleAssignment.properties.principalId).signInName
                    RoleDefinitionName = $roleDefinitionName
                    RoleDefinitionId   = $L0mgmtGroupRoleAssignment.properties.roleDefinitionId -replace '.*/'
                    ObjectId           = $L0mgmtGroupRoleAssignment.properties.principalId
                    ObjectType         = $htPrincipals.($L0mgmtGroupRoleAssignment.properties.principalId).type
                    PIM                = $pim
                })

            $htTemp = @{}
            $htTemp.Assignment = $arrayRoleAssignment

            if ($roleAssignmentId -like '/providers/Microsoft.Authorization/roleAssignments/*') {
                $htTemp.AssignmentScopeTenMgSubRgRes = 'Tenant'
                $htTemp.AssignmentScopeId = 'Tenant'
            }
            else {
                $htTemp.AssignmentScopeTenMgSubRgRes = 'Mg'
                $htTemp.AssignmentScopeId = [string]$splitAssignment[4]
            }
            ($script:htCacheAssignmentsRole).($roleAssignmentId) = $htTemp
        }

        if (($htPrincipals.($L0mgmtGroupRoleAssignment.properties.principalId).displayName).length -eq 0) {
            $roleAssignmentIdentityDisplayname = 'n/a'
        }
        else {
            if ($htPrincipals.($L0mgmtGroupRoleAssignment.properties.principalId).type -eq 'User') {
                if ($azAPICallConf['htParameters'].DoNotShowRoleAssignmentsUserData -eq $false) {
                    $roleAssignmentIdentityDisplayname = $htPrincipals.($L0mgmtGroupRoleAssignment.properties.principalId).displayName
                }
                else {
                    $roleAssignmentIdentityDisplayname = 'scrubbed'
                }
            }
            else {
                $roleAssignmentIdentityDisplayname = $htPrincipals.($L0mgmtGroupRoleAssignment.properties.principalId).displayName
            }
        }
        if (-not $htPrincipals.($L0mgmtGroupRoleAssignment.properties.principalId).signInName) {
            $roleAssignmentIdentitySignInName = 'n/a'
        }
        else {
            if ($htPrincipals.($L0mgmtGroupRoleAssignment.properties.principalId).type -eq 'User') {
                if ($azAPICallConf['htParameters'].DoNotShowRoleAssignmentsUserData -eq $false) {
                    $roleAssignmentIdentitySignInName = $htPrincipals.($L0mgmtGroupRoleAssignment.properties.principalId).signInName
                }
                else {
                    $roleAssignmentIdentitySignInName = 'scrubbed'
                }
            }
            else {
                $roleAssignmentIdentitySignInName = $htPrincipals.($L0mgmtGroupRoleAssignment.properties.principalId).signInName
            }
        }
        $roleAssignmentIdentityObjectId = $L0mgmtGroupRoleAssignment.properties.principalId
        $roleAssignmentIdentityObjectType = $htPrincipals.($L0mgmtGroupRoleAssignment.properties.principalId).type
        $roleAssignmentScope = $L0mgmtGroupRoleAssignment.properties.scope
        $roleAssignmentScopeName = $roleAssignmentScope -replace '.*/'
        $roleAssignmentScopeType = 'MG'

        $roleSecurityCustomRoleOwner = 0
        if ($roleAssignmentsRoleDefinition.Actions -eq '*' -and (($roleAssignmentsRoleDefinition.NotActions)).length -eq 0 -and $roleAssignmentsRoleDefinition.IsCustom -eq $True) {
            $roleSecurityCustomRoleOwner = 1
        }
        $roleSecurityOwnerAssignmentSP = 0
        if (($roleAssignmentsRoleDefinition.Id -eq '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' -and $roleAssignmentIdentityObjectType -eq 'ServicePrincipal') -or ($roleAssignmentsRoleDefinition.Actions -eq '*' -and (($roleAssignmentsRoleDefinition.NotActions)).length -eq 0 -and $roleAssignmentsRoleDefinition.IsCustom -eq $True -and $roleAssignmentIdentityObjectType -eq 'ServicePrincipal')) {
            $roleSecurityOwnerAssignmentSP = 1
        }

        $createdBy = ''
        $createdOn = ''
        $createdOnUnformatted = $null
        $updatedBy = ''
        $updatedOn = ''

        if ($L0mgmtGroupRoleAssignment.properties.createdBy) {
            $createdBy = $L0mgmtGroupRoleAssignment.properties.createdBy
        }
        if ($L0mgmtGroupRoleAssignment.properties.createdOn) {
            $createdOn = $L0mgmtGroupRoleAssignment.properties.createdOn
        }
        if ($L0mgmtGroupRoleAssignment.properties.updatedBy) {
            $updatedBy = $L0mgmtGroupRoleAssignment.properties.updatedBy
        }
        if ($L0mgmtGroupRoleAssignment.properties.updatedOn) {
            $updatedOn = $L0mgmtGroupRoleAssignment.properties.updatedOn
        }
        $createdOnUnformatted = $L0mgmtGroupRoleAssignment.properties.createdOn

        $addRowToTableDone = $true
        addRowToTable `
            -level $hierarchyLevel `
            -mgName $scopeDisplayName `
            -mgId $scopeId `
            -mgParentId $mgParentId `
            -mgParentName $mgParentName `
            -mgASCSecureScore $mgAscSecureScoreResult `
            -RoleDefinitionId $roleDefinitionIdGuid `
            -RoleDefinitionName $roleDefinitionName `
            -RoleIsCustom $roleAssignmentsRoleDefinition.IsCustom `
            -RoleAssignableScopes ($roleAssignmentsRoleDefinition.AssignableScopes -join "$CsvDelimiterOpposite ") `
            -RoleActions ($roleAssignmentsRoleDefinition.Actions -join "$CsvDelimiterOpposite ") `
            -RoleNotActions ($roleAssignmentsRoleDefinition.NotActions -join "$CsvDelimiterOpposite ") `
            -RoleDataActions ($roleAssignmentsRoleDefinition.DataActions -join "$CsvDelimiterOpposite ") `
            -RoleNotDataActions ($roleAssignmentsRoleDefinition.NotDataActions -join "$CsvDelimiterOpposite ") `
            -RoleCanDoRoleAssignments $roleAssignmentsRoleDefinition.RoleCanDoRoleAssignments `
            -RoleAssignmentIdentityDisplayname $roleAssignmentIdentityDisplayname `
            -RoleAssignmentIdentitySignInName $roleAssignmentIdentitySignInName `
            -RoleAssignmentIdentityObjectId $roleAssignmentIdentityObjectId `
            -RoleAssignmentIdentityObjectType $roleAssignmentIdentityObjectType `
            -RoleAssignmentId $roleAssignmentId `
            -RoleAssignmentScope $roleAssignmentScope `
            -RoleAssignmentScopeName $roleAssignmentScopeName `
            -RoleAssignmentScopeType $roleAssignmentScopeType `
            -RoleAssignmentCreatedBy $createdBy `
            -RoleAssignmentCreatedOn $createdOn `
            -RoleAssignmentCreatedOnUnformatted $createdOnUnformatted `
            -RoleAssignmentUpdatedBy $updatedBy `
            -RoleAssignmentUpdatedOn $updatedOn `
            -RoleAssignmentsLimit $LimitRBACRoleAssignmentsManagementGroup `
            -RoleAssignmentsCount $L0mgmtGroupRoleAssignmentsLimitUtilization `
            -RoleSecurityCustomRoleOwner $roleSecurityCustomRoleOwner `
            -RoleSecurityOwnerAssignmentSP $roleSecurityOwnerAssignmentSP `
            -RoleAssignmentPIM $pim `
            -RoleAssignmentPIMAssignmentType $pimAssignmentType `
            -RoleAssignmentPIMSlotStart $pimSlotStart `
            -RoleAssignmentPIMSlotEnd $pimSlotEnd
    }

    $returnObject = @{}
    if ($addRowToTableDone) {
        $returnObject.'addRowToTableDone' = @{}
    }
    return $returnObject
}
$funcDataCollectionRoleAssignmentsMG = $function:dataCollectionRoleAssignmentsMG.ToString()

function dataCollectionRoleAssignmentsSub {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $hierarchyLevel,
        $childMgDisplayName,
        $childMgId,
        $childMgParentId,
        $childMgParentName,
        $mgAscSecureScoreResult,
        $subscriptionQuotaId,
        $subscriptionState,
        $subscriptionASCSecureScore,
        $subscriptionTags,
        $subscriptionTagsCount
    )

    $addRowToTableDone = $false
    #Usage
    $currentTask = "Getting Role assignments usage metrics for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Authorization/roleAssignmentsUsageMetrics?api-version=2019-08-01-preview"
    $method = 'GET'
    $roleAssignmentsUsage = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -listenOn 'Content' -caller 'CustomDataCollection'

    $script:htSubscriptionsRoleAssignmentLimit.($scopeId) = $roleAssignmentsUsage.roleAssignmentsLimit

    #PIM SubscriptionRoleAssignmentScheduleInstances
    if ($htDoARMRoleAssignmentScheduleInstances.Do -eq $true) {
        $currentTask = "Getting ARM RoleAssignment ScheduleInstances for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01"
        $method = 'GET'
        $roleAssignmentScheduleInstancesFromAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

        if ($roleAssignmentScheduleInstancesFromAPI -eq 'RoleAssignmentScheduleInstancesError' -or $roleAssignmentScheduleInstancesFromAPI -eq 'AadPremiumLicenseRequired') {
            # this should not be required at sub level as the error would already have occured at mg level
            # if ($roleAssignmentScheduleInstancesFromAPI -eq 'AadPremiumLicenseRequired') {
            #     Write-Host " Setting 'htDoARMRoleAssignmentScheduleInstances.Do' to false (AadPremiumLicenseRequired)"
            #     $script:htDoARMRoleAssignmentScheduleInstances.Do = $false
            # }
        }
        else {
            $roleAssignmentScheduleInstances = ($roleAssignmentScheduleInstancesFromAPI.where( { ($_.properties.roleAssignmentScheduleId -replace '.*/') -ne ($_.properties.originRoleAssignmentId -replace '.*/') }))
            $roleAssignmentScheduleInstancesCount = $roleAssignmentScheduleInstances.Count
            if ($roleAssignmentScheduleInstancesCount -gt 0) {
                #$htRoleAssignmentsPIM = @{}
                foreach ($roleAssignmentScheduleInstance in $roleAssignmentScheduleInstances) {
                    $script:htRoleAssignmentsPIM.($roleAssignmentScheduleInstance.properties.originRoleAssignmentId.tolower()) = $roleAssignmentScheduleInstance.properties
                }
            }
        }
    }

    #RoleAssignment API Sub
    $currentTask = "Getting Role assignments API for Subscription: '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Authorization/roleAssignments?api-version=2015-07-01"
    $method = 'GET'
    $roleAssignmentsFromAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    $baseRoleAssignments = [System.Collections.ArrayList]@()
    if ($roleAssignmentsFromAPI.Count -gt 0) {
        foreach ($roleAssignmentFromAPI in $roleAssignmentsFromAPI) {

            if ($roleAssignmentFromAPI.id -match "/subscriptions/$($scopeId)/") {
                if (-not $htRoleAssignmentsFromAPIInheritancePrevention.($roleAssignmentFromAPI.id -replace '.*/')) {
                    $null = $baseRoleAssignments.Add($roleAssignmentFromAPI)
                }
                else {
                    $null = $baseRoleAssignments.Add($htRoleAssignmentsFromAPIInheritancePrevention.($roleAssignmentFromAPI.id -replace '.*/').assignment)
                }
            }
            else {
                $null = $baseRoleAssignments.Add($roleAssignmentFromAPI)
            }
        }
    }

    if ($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC -eq $true) {
        $relevantRAs = $baseRoleAssignments.where( { $_.id -notmatch "/subscriptions/$($scopeId)/resourcegroups/" } )
    }
    else {
        $relevantRAs = $baseRoleAssignments
    }
    if ($relevantRAs.Count -gt 0) {
        $principalsToResolve = @()
        $principalsToResolve = foreach ($ra in $relevantRAs.properties | Sort-Object -Property principalId -Unique) {
            if (-not $htPrincipals.($ra.principalId)) {
                $ra.principalId
            }
        }

        if ($principalsToResolve.Count -gt 0) {
            ResolveObjectIds -objectIds $principalsToResolve
        }
    }


    $L1mgmtGroupSubRoleAssignments = $baseRoleAssignments

    if ($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC -eq $true) {
        foreach ($L1mgmtGroupSubRoleAssignmentOnRg in $L1mgmtGroupSubRoleAssignments.where( { $_.id -match "/subscriptions/$($scopeId)/resourcegroups/" } )) {
            if (-not ($htCacheAssignmentsRBACOnResourceGroupsAndResources).($L1mgmtGroupSubRoleAssignmentOnRg.id)) {

                $roleDefinitionId = $L1mgmtGroupSubRoleAssignmentOnRg.properties.roleDefinitionId
                $roleDefinitionIdGuid = $roleDefinitionId -replace '.*/'

                if (-not ($htCacheDefinitionsRole).($roleDefinitionIdGuid)) {
                    $roleAssignmentsRoleDefinition = ''
                    $roleDefinitionName = "'This roleDefinition likely was deleted although a roleAssignment existed'"
                }
                else {
                    $roleAssignmentsRoleDefinition = ($htCacheDefinitionsRole).($roleDefinitionIdGuid)
                    $roleDefinitionName = $roleAssignmentsRoleDefinition.Name
                }

                #assignment
                $arrayRoleAssignment = [System.Collections.ArrayList]@()
                $null = $arrayRoleAssignment.Add([PSCustomObject]@{
                        RoleAssignmentId   = $L1mgmtGroupSubRoleAssignmentOnRg.id
                        Scope              = $L1mgmtGroupSubRoleAssignmentOnRg.properties.scope
                        RoleDefinitionName = $roleDefinitionName
                        RoleDefinitionId   = $L1mgmtGroupSubRoleAssignmentOnRg.properties.roleDefinitionId -replace '.*/'
                        ObjectId           = $L1mgmtGroupSubRoleAssignmentOnRg.properties.principalId
                    })

                ($script:htCacheAssignmentsRBACOnResourceGroupsAndResources).($L1mgmtGroupSubRoleAssignmentOnRg.id) = $arrayRoleAssignment
            }
        }
    }

    if ($azAPICallConf['htParameters'].LargeTenant -eq $true -or $azAPICallConf['htParameters'].RBACAtScopeOnly -eq $true) {
        if ($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC -eq $false) {
            $assignmentsScope = $L1mgmtGroupSubRoleAssignments
        }
        else {
            $assignmentsScope = $L1mgmtGroupSubRoleAssignments.where( { $_.properties.Scope -eq "/subscriptions/$($scopeId)" } )
        }
    }
    else {
        if ($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC -eq $false) {
            $assignmentsScope = $L1mgmtGroupSubRoleAssignments
        }
        else {
            $assignmentsScope = $L1mgmtGroupSubRoleAssignments.where( { $_.id -notmatch "/subscriptions/$($scopeId)/resourcegroups/" } )
        }
    }

    foreach ($L1mgmtGroupSubRoleAssignment in $assignmentsScope) {

        $roleAssignmentId = ($L1mgmtGroupSubRoleAssignment.id).ToLower()
        $roleDefinitionId = $L1mgmtGroupSubRoleAssignment.properties.roleDefinitionId
        $roleDefinitionIdGuid = $roleDefinitionId -replace '.*/'

        if (-not ($htCacheDefinitionsRole).($roleDefinitionIdGuid)) {
            $roleAssignmentsRoleDefinition = ''
            $roleDefinitionName = "'This roleDefinition likely was deleted although a roleAssignment existed'"
        }
        else {
            $roleAssignmentsRoleDefinition = ($htCacheDefinitionsRole).($roleDefinitionIdGuid)
            $roleDefinitionName = $roleAssignmentsRoleDefinition.Name
        }

        $roleAssignmentIdentityObjectId = $L1mgmtGroupSubRoleAssignment.properties.principalId
        $roleAssignmentIdentityObjectType = $htPrincipals.($L1mgmtGroupSubRoleAssignment.properties.principalId).type
        $roleAssignmentScope = $L1mgmtGroupSubRoleAssignment.properties.scope
        $roleAssignmentScopeName = $roleAssignmentScope -replace '.*/'

        if ($roleAssignmentScope -like '/subscriptions/*' -and $roleAssignmentScope -notlike '/subscriptions/*/resourcegroups/*') {
            $roleAssignmentScopeType = 'Sub'
            $roleAssignmentScopeRG = ''
            $roleAssignmentScopeRes = ''
        }
        if ($roleAssignmentScope -like '/subscriptions/*/resourcegroups/*' -and $roleAssignmentScope -notlike '/subscriptions/*/resourcegroups/*/providers*') {
            $roleAssignmentScopeType = 'RG'
            $roleAssignmentScopeSplit = $roleAssignmentScope.Split('/')
            $roleAssignmentScopeRG = $roleAssignmentScopeSplit[4]
            $roleAssignmentScopeRes = ''
        }
        if ($roleAssignmentScope -like '/subscriptions/*/resourcegroups/*/providers*') {
            $roleAssignmentScopeType = 'Res'
            $roleAssignmentScopeSplit = $roleAssignmentScope.Split('/')
            $roleAssignmentScopeRG = $roleAssignmentScopeSplit[4]
            $roleAssignmentScopeRes = $roleAssignmentScopeSplit[8]
        }

        if ($htRoleAssignmentsPIM.($roleAssignmentId)) {
            $hlperPim = $htRoleAssignmentsPIM.($roleAssignmentId)
            $pim = 'true'
            $pimAssignmentType = $hlperPim.assignmentType
            $pimSlotStart = $($hlperPim.startDateTime)
            if ($hlperPim.endDateTime) {
                $pimSlotEnd = $($hlperPim.endDateTime)
            }
            else {
                $pimSlotEnd = 'eternity'
            }
        }
        else {
            $pim = 'false'
            $pimAssignmentType = ''
            $pimSlotStart = ''
            $pimSlotEnd = ''
        }

        if ($roleAssignmentId -like "/subscriptions/$($scopeId)/*") {

            #assignment
            $splitAssignment = ($roleAssignmentId).Split('/')
            $arrayRoleAssignment = [System.Collections.ArrayList]@()
            $null = $arrayRoleAssignment.Add([PSCustomObject]@{
                    RoleAssignmentId   = $roleAssignmentId
                    Scope              = $L1mgmtGroupSubRoleAssignment.properties.scope
                    DisplayName        = $htPrincipals.($L1mgmtGroupSubRoleAssignment.properties.principalId).displayName
                    SignInName         = $htPrincipals.($L1mgmtGroupSubRoleAssignment.properties.principalId).signInName
                    RoleDefinitionName = $roleDefinitionName
                    RoleDefinitionId   = $L1mgmtGroupSubRoleAssignment.properties.roleDefinitionId -replace '.*/'
                    ObjectId           = $L1mgmtGroupSubRoleAssignment.properties.principalId
                    ObjectType         = $htPrincipals.($L1mgmtGroupSubRoleAssignment.properties.principalId).type
                    PIM                = $pim
                })

            $htTemp = @{}
            $htTemp.Assignment = $arrayRoleAssignment

            $htTemp.AssignmentScopeTenMgSubRgRes = $roleAssignmentScopeType
            if ($roleAssignmentScopeType -eq 'Sub') {
                $htTemp.AssignmentScopeId = [string]$splitAssignment[2]
            }
            if ($roleAssignmentScopeType -eq 'RG') {
                $htTemp.AssignmentScopeId = "$($splitAssignment[2])/$($splitAssignment[4])"
            }
            if ($roleAssignmentScopeType -eq 'Res') {
                $htTemp.AssignmentScopeId = "$($splitAssignment[2])/$($splitAssignment[4])/$($splitAssignment[8])"
                $htTemp.ResourceType = "$($splitAssignment[6])-$($splitAssignment[7])"
            }
            ($script:htCacheAssignmentsRole).($roleAssignmentId) = $htTemp
        }


        if (($htPrincipals.($L1mgmtGroupSubRoleAssignment.properties.principalId).displayName).length -eq 0) {
            $roleAssignmentIdentityDisplayname = 'n/a'
        }
        else {
            if ($htPrincipals.($L1mgmtGroupSubRoleAssignment.properties.principalId).type -eq 'User') {
                if ($azAPICallConf['htParameters'].DoNotShowRoleAssignmentsUserData -eq $false) {
                    $roleAssignmentIdentityDisplayname = $htPrincipals.($L1mgmtGroupSubRoleAssignment.properties.principalId).displayName
                }
                else {
                    $roleAssignmentIdentityDisplayname = 'scrubbed'
                }
            }
            else {
                $roleAssignmentIdentityDisplayname = $htPrincipals.($L1mgmtGroupSubRoleAssignment.properties.principalId).displayName
            }
        }
        if (-not $htPrincipals.($L1mgmtGroupSubRoleAssignment.properties.principalId).signInName) {
            $roleAssignmentIdentitySignInName = 'n/a'
        }
        else {
            if ($htPrincipals.($L1mgmtGroupSubRoleAssignment.properties.principalId).type -eq 'User') {
                if ($azAPICallConf['htParameters'].DoNotShowRoleAssignmentsUserData -eq $false) {
                    $roleAssignmentIdentitySignInName = $htPrincipals.($L1mgmtGroupSubRoleAssignment.properties.principalId).signInName
                }
                else {
                    $roleAssignmentIdentitySignInName = 'scrubbed'
                }
            }
            else {
                $roleAssignmentIdentitySignInName = $htPrincipals.($L1mgmtGroupSubRoleAssignment.properties.principalId).signInName
            }
        }

        $roleSecurityCustomRoleOwner = 0
        if (($htCacheDefinitionsRole).$($roleDefinitionIdGuid).Actions -eq '*' -and ((($htCacheDefinitionsRole).$($roleDefinitionIdGuid).NotActions)).length -eq 0 -and ($htCacheDefinitionsRole).$($roleDefinitionIdGuid).IsCustom -eq $True) {
            $roleSecurityCustomRoleOwner = 1
        }
        $roleSecurityOwnerAssignmentSP = 0
        if ((($htCacheDefinitionsRole).$($roleDefinitionIdGuid).Id -eq '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' -and $roleAssignmentIdentityObjectType -eq 'ServicePrincipal') -or (($htCacheDefinitionsRole).$($roleDefinitionIdGuid).Actions -eq '*' -and ((($htCacheDefinitionsRole).$($roleDefinitionIdGuid).NotActions)).length -eq 0 -and ($htCacheDefinitionsRole).$($roleDefinitionIdGuid).IsCustom -eq $True -and $roleAssignmentIdentityObjectType -eq 'ServicePrincipal')) {
            $roleSecurityOwnerAssignmentSP = 1
        }

        $createdBy = ''
        $createdOn = ''
        $createdOnUnformatted = $null
        $updatedBy = ''
        $updatedOn = ''

        if ($L1mgmtGroupSubRoleAssignment.properties.createdBy) {
            $createdBy = $L1mgmtGroupSubRoleAssignment.properties.createdBy
        }
        if ($L1mgmtGroupSubRoleAssignment.properties.createdOn) {
            $createdOn = $L1mgmtGroupSubRoleAssignment.properties.createdOn
        }
        if ($L1mgmtGroupSubRoleAssignment.properties.updatedBy) {
            $updatedBy = $L1mgmtGroupSubRoleAssignment.properties.updatedBy
        }
        if ($L1mgmtGroupSubRoleAssignment.properties.updatedOn) {
            $updatedOn = $L1mgmtGroupSubRoleAssignment.properties.updatedOn
        }
        $createdOnUnformatted = $L1mgmtGroupSubRoleAssignment.properties.createdOn

        $addRowToTableDone = $true
        addRowToTable `
            -level $hierarchyLevel `
            -mgName $childMgDisplayName `
            -mgId $childMgId `
            -mgParentId $childMgParentId `
            -mgParentName $childMgParentName `
            -mgASCSecureScore $mgAscSecureScoreResult `
            -Subscription $scopeDisplayName `
            -SubscriptionId $scopeId `
            -SubscriptionQuotaId $subscriptionQuotaId `
            -SubscriptionState $subscriptionState `
            -SubscriptionASCSecureScore $subscriptionASCSecureScore `
            -SubscriptionTags $subscriptionTags `
            -SubscriptionTagsCount $subscriptionTagsCount `
            -RoleDefinitionId $roleDefinitionIdGuid `
            -RoleDefinitionName $roleDefinitionName `
            -RoleIsCustom $roleAssignmentsRoleDefinition.IsCustom `
            -RoleAssignableScopes ($roleAssignmentsRoleDefinition.AssignableScopes -join "$CsvDelimiterOpposite ") `
            -RoleActions ($roleAssignmentsRoleDefinition.Actions -join "$CsvDelimiterOpposite ") `
            -RoleNotActions ($roleAssignmentsRoleDefinition.NotActions -join "$CsvDelimiterOpposite ") `
            -RoleDataActions ($roleAssignmentsRoleDefinition.DataActions -join "$CsvDelimiterOpposite ") `
            -RoleNotDataActions ($roleAssignmentsRoleDefinition.NotDataActions -join "$CsvDelimiterOpposite ") `
            -RoleCanDoRoleAssignments $roleAssignmentsRoleDefinition.RoleCanDoRoleAssignments `
            -RoleAssignmentIdentityDisplayname $roleAssignmentIdentityDisplayname `
            -RoleAssignmentIdentitySignInName $roleAssignmentIdentitySignInName `
            -RoleAssignmentIdentityObjectId $roleAssignmentIdentityObjectId `
            -RoleAssignmentIdentityObjectType $roleAssignmentIdentityObjectType `
            -RoleAssignmentId $roleAssignmentId `
            -RoleAssignmentScope $roleAssignmentScope `
            -RoleAssignmentScopeName $roleAssignmentScopeName `
            -RoleAssignmentScopeRG $roleAssignmentScopeRG `
            -RoleAssignmentScopeRes $roleAssignmentScopeRes `
            -RoleAssignmentScopeType $roleAssignmentScopeType `
            -RoleAssignmentCreatedBy $createdBy `
            -RoleAssignmentCreatedOn $createdOn `
            -RoleAssignmentCreatedOnUnformatted $createdOnUnformatted `
            -RoleAssignmentUpdatedBy $updatedBy `
            -RoleAssignmentUpdatedOn $updatedOn `
            -RoleAssignmentsLimit $roleAssignmentsUsage.roleAssignmentsLimit `
            -RoleAssignmentsCount $roleAssignmentsUsage.roleAssignmentsCurrentCount `
            -RoleSecurityCustomRoleOwner $roleSecurityCustomRoleOwner `
            -RoleSecurityOwnerAssignmentSP $roleSecurityOwnerAssignmentSP `
            -RoleAssignmentPIM $pim `
            -RoleAssignmentPIMAssignmentType $pimAssignmentType `
            -RoleAssignmentPIMSlotStart $pimSlotStart `
            -RoleAssignmentPIMSlotEnd $pimSlotEnd
    }

    $returnObject = @{}
    if ($addRowToTableDone) {
        $returnObject.'addRowToTableDone' = @{}
    }
    return $returnObject
}
$funcDataCollectionRoleAssignmentsSub = $function:dataCollectionRoleAssignmentsSub.ToString()

function dataCollectionClassicAdministratorsSub {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        [string]$subscriptionMgPath,
        $subscriptionQuotaId
    )

    $apiEndPoint = $azAPICallConf['azAPIEndpointUrls'].ARM
    $api = "/subscriptions/$($scopeId)/providers/Microsoft.Authorization/classicAdministrators"
    $apiVersion = '?api-version=2015-07-01'
    $uri = $apiEndPoint + $api + $apiVersion
    $azAPICallPayload = @{
        uri                    = $uri
        method                 = 'GET'
        currentTask            = "classicAdministrators '$($scopeDisplayName)' ('$scopeId') [quotaId:'$subscriptionQuotaId']"
        AzAPICallConfiguration = $azAPICallConf
    }

    $AzApiCallResult = AzAPICall @azAPICallPayload
    if ($AzApiCallResult -ne 'ClassicAdministratorListFailed') {
        $arrayClassicAdministrators = [System.Collections.ArrayList]@()
        foreach ($roleAll in $AzApiCallResult) {
            $splitPropertiesRole = $roleAll.properties.role.Split(';')
            foreach ($role in $splitPropertiesRole) {
                $null = $arrayClassicAdministrators.Add([PSCustomObject]@{
                        Subscription       = $scopeDisplayName
                        SubscriptionId     = $scopeId
                        SubscriptionMgPath = $subscriptionMgPath
                        Identity           = $roleAll.properties.emailAddress
                        Role               = $role
                        Id                 = $roleAll.id
                    })
            }
        }
        $script:htClassicAdministrators.($scopeId) = @{}
        $script:htClassicAdministrators.($scopeId).ClassicAdministrators = $arrayClassicAdministrators
    }
}
$funcDataCollectionClassicAdministratorsSub = $function:dataCollectionClassicAdministratorsSub.ToString()

#endregion functions4DataCollection
