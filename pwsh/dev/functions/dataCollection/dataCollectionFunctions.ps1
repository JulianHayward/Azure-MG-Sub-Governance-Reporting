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
        $ChildMgMgPath
    )

    $currentTask = "Getting Microsoft Defender for Cloud plans for Subscription: '$($scopeDisplayName)' ('$scopeId')"
    #https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Security/pricings?api-version=2018-06-01"
    $method = 'GET'
    $defenderPlansResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    if ($defenderPlansResult -eq 'SubScriptionNotRegistered') {
        #Subscription skipped for MDfC
        $null = $script:arrayDefenderPlansSubscriptionNotRegistered.Add([PSCustomObject]@{
                subscriptionId     = $scopeId
                subscriptionName   = $scopeDisplayName
                subscriptionMgPath = $childMgMgPath
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

function dataCollectionDiagnosticsSub {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $ChildMgMgPath,
        $ChildMgId
    )

    $currentTask = "getDiagnosticSettingsSub for Subscription: '$($scopeDisplayName)' ('$scopeId')"
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
    $currentTask = "getARMDiagnosticSettingsMg '$($scopeDisplayName)' ('$($scopeId)')"
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

function dataCollectionResources {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName,
        $ChildMgMgPath
    )
    $currentTask = "Getting ResourceTypes for Subscription: '$($scopeDisplayName)' ('$scopeId')"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/resources?`$expand=createdTime,changedTime&api-version=2021-04-01"
    $method = 'GET'
    $resourcesSubscriptionResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

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
                $psruleResults = $resourcesSubscriptionResult | Invoke-PSRule -Module psrule.rules.Azure -As Detail -Culture en-us -WarningAction Ignore -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host "   Please report 'PSRule for Azure' error '$($scopeDisplayName)' ('$scopeId'): $_"
            }
            
            $endPSRule = Get-Date
            $durationPSRule = $((NEW-TIMESPAN -Start $startPSRule -End $endPSRule).TotalSeconds)

            $null = $script:arrayPSRuleTracking.Add([PSCustomObject]@{
                    subscriptionId = $scopeId
                    duration       = $durationPSRule
                })

            if ($psruleResults.Count -gt 0) {
                $null = $script:arrayPSRule.AddRange($psRuleResults)
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
            $script:htResourceTypesUniqueResource.(($resourceType.name).ToLower()).resourceId = $resourceType.Group.Id | Select-Object -first 1
        }
    }

    $startSubResourceIdsThis = Get-Date
    foreach ($resource in ($resourcesSubscriptionResult)) {
        $null = $script:resourcesIdsAll.Add([PSCustomObject]@{
                subscriptionId = $scopeId
                mgPath         = $childMgMgPath
                type           = ($resource.type).ToLower()
                id             = ($resource.Id).ToLower()
                name           = ($resource.name).ToLower()
                location       = ($resource.location).ToLower()
                tags           = ($resource.tags)
                createdTime    = ($resource.createdTime)
                changedTime    = ($resource.changedTime)
            })

        if ($resource.identity.userAssignedIdentities) {
            $resource.identity.userAssignedIdentities.psobject.properties | ForEach-Object {
                if ((-not [string]::IsNullOrEmpty($resource.Id)) -and (-not [string]::IsNullOrEmpty($_.Value.principalId))) {
                    $hlp = ($_.Name.split('/'))
                    $hlpMiSubId = $hlp[2]
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
                        })
                }
            }
        }
    }
    $endSubResourceIdsThis = Get-Date
    $null = $script:arraySubResourcesAddArrayDuration.Add([PSCustomObject]@{
            sub         = $scopeId
            DurationSec = (NEW-TIMESPAN -Start $startSubResourceIdsThis -End $endSubResourceIdsThis).TotalSeconds
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
        [string]$scopeDisplayName
    )

    #https://management.azure.com/subscriptions/{subscriptionId}/resourcegroups?api-version=2020-06-01
    $currentTask = "Getting ResourceGroups for Subscription: '$($scopeDisplayName)' ('$scopeId')"
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
        [string]$scopeDisplayname
    )

    ($script:htResourceProvidersAll).($scopeId) = @{}
    $currentTask = "Getting ResourceProviders for Subscription: '$($scopeDisplayname)' ('$scopeId')"
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
        [object]$MgParentNameChain
    )

    $currentTask = "Getting Features for Subscription: '$($scopeDisplayname)' ('$scopeId')"
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
        [string]$scopeDisplayname
    )

    $currentTask = "Subscription ResourceLocks '$($scopeDisplayname)' ('$scopeId')"
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
        $resourceGroupsLocksCannotDeleteCount = ($arrayResourceGroupsCannotDeleteLock).Count
        $htTemp.ResourceGroupsLocksCannotDeleteCount = $resourceGroupsLocksCannotDeleteCount

        $resourceGroupsLocksReadOnlyCount = ($arrayResourceGroupsReadOnlyLock).Count
        $htTemp.ResourceGroupsLocksReadOnlyCount = $resourceGroupsLocksReadOnlyCount
        $htTemp.ResourceGroupsLocksCannotDelete = $arrayResourceGroupsCannotDeleteLock

        #resources
        $resourcesLocksCannotDeleteCount = ($arrayResourcesCannotDeleteLock).Count
        $htTemp.ResourcesLocksCannotDeleteCount = $resourcesLocksCannotDeleteCount

        $resourcesLocksReadOnlyCount = ($arrayResourcesReadOnlyLock).Count
        $htTemp.ResourcesLocksReadOnlyCount = $resourcesLocksReadOnlyCount
        $htTemp.ResourcesLocksCannotDelete = $arrayResourcesCannotDeleteLock

        $script:htResourceLocks.($scopeId) = $htTemp
    }
}
$funcDataCollectionResourceLocks = $function:dataCollectionResourceLocks.ToString()

function dataCollectionTags {
    [CmdletBinding()]Param(
        [string]$scopeId,
        [string]$scopeDisplayName
    )

    $currentTask = "Subscription Tags '$($scopeDisplayName)' ('$scopeId')"
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
        [string]$scopeDisplayName
    )

    $currentTask = "Policy Compliance $($TargetMgOrSub) '$($scopeDisplayName)' ('$scopeId')"
    if ($TargetMgOrSub -eq 'Sub') { $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01" }
    if ($TargetMgOrSub -eq 'MG') { $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($scopeId)/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01" }
    $method = 'POST'
    $policyComplianceResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    if ($policyComplianceResult -eq 'ResponseTooLarge') {
        if ($TargetMgOrSub -eq 'Sub') { ($script:htCachePolicyComplianceResponseTooLargeSUB).($scopeId) = @{} }
        if ($TargetMgOrSub -eq 'MG') {
 ($script:htCachePolicyComplianceResponseTooLargeMG).($scopeId) = @{}
        }
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
        [string]$scopeDisplayName
    )

    if ($azAPICallConf['htParameters'].NoMDfCSecureScore -eq $false) {
        $currentTask = "Microsoft Defender for Cloud Secure Score Sub: '$($scopeDisplayName)' ('$scopeId')"
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Security/securescores?api-version=2020-01-01"
        $method = 'GET'
        $subASCSecureScoreResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

        if (($subASCSecureScoreResult).count -gt 0) {
            $subscriptionASCSecureScore = "$($subASCSecureScoreResult.properties.score.current) of $($subASCSecureScoreResult.properties.score.max) points"
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

    $currentTask = "Blueprint definitions MG '$($scopeDisplayName)' ('$scopeId')"
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

    $currentTask = "Blueprint definitions Sub '$($scopeDisplayName)' ('$scopeId')"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
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

    $currentTask = "Blueprint assignments '$($scopeDisplayName)' ('$scopeId')"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Blueprint/blueprintAssignments?api-version=2018-11-01-preview"
    $method = 'GET'
    $subscriptionBlueprintAssignmentsResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    $addRowToTableDone = $false
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

            $currentTask = "   Blueprint definitions related to Blueprint assignments '$($scopeDisplayName)' ('$scopeId')"
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
        [string]$scopeDisplayName
    )

    $currentTask = "Policy exemptions $($TargetMgOrSub) '$($scopeDisplayName)' ('$scopeId')"
    if ($TargetMgOrSub -eq 'Sub') {
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Authorization/policyExemptions?api-version=2020-07-01-preview"
    }
    if ($TargetMgOrSub -eq 'MG') {
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
        [string]$scopeDisplayName
    )

    $currentTask = "Policy definitions $($TargetMgOrSub) '$($scopeDisplayName)' ('$scopeId')"
    if ($TargetMgOrSub -eq 'Sub') {
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Authorization/policyDefinitions?api-version=2021-06-01&`$filter=policyType eq 'Custom'"
    }
    if ($TargetMgOrSub -eq 'MG') {
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
            $htTemp.DisplayName = $($scopePolicyDefinition.Properties.displayname)
            $htTemp.Description = $($policyDefinitionDescription)
            $htTemp.Type = $($scopePolicyDefinition.Properties.policyType)
            $htTemp.Category = $($scopePolicyDefinition.Properties.metadata.category)
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
            #effects
            if ($scopePolicyDefinition.properties.parameters.effect.defaultvalue) {
                $htTemp.effectDefaultValue = $scopePolicyDefinition.properties.parameters.effect.defaultvalue
                if ($scopePolicyDefinition.properties.parameters.effect.allowedValues) {
                    $htTemp.effectAllowedValue = $scopePolicyDefinition.properties.parameters.effect.allowedValues -join ','
                }
                else {
                    $htTemp.effectAllowedValue = 'n/a'
                }
                $htTemp.effectFixedValue = 'n/a'
            }
            else {
                if ($scopePolicyDefinition.properties.parameters.policyEffect.defaultValue) {
                    $htTemp.effectDefaultValue = $scopePolicyDefinition.properties.parameters.policyEffect.defaultvalue
                    if ($scopePolicyDefinition.properties.parameters.policyEffect.allowedValues) {
                        $htTemp.effectAllowedValue = $scopePolicyDefinition.properties.parameters.policyEffect.allowedValues -join ','
                    }
                    else {
                        $htTemp.effectAllowedValue = 'n/a'
                    }
                    $htTemp.effectFixedValue = 'n/a'
                }
                else {
                    $htTemp.effectFixedValue = $scopePolicyDefinition.Properties.policyRule.then.effect
                    $htTemp.effectDefaultValue = 'n/a'
                    $htTemp.effectAllowedValue = 'n/a'
                }
            }
            $htTemp.Json = $scopePolicyDefinition
            ($script:htCacheDefinitionsPolicy).($hlpPolicyDefinitionId) = $htTemp


            if (-not [string]::IsNullOrWhiteSpace($scopePolicyDefinition.properties.policyRule.then.details.roleDefinitionIds)) {
                ($script:htCacheDefinitionsPolicy).($hlpPolicyDefinitionId).RoleDefinitionIds = $scopePolicyDefinition.properties.policyRule.then.details.roleDefinitionIds
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
                ($script:htCacheDefinitionsPolicy).($hlpPolicyDefinitionId).RoleDefinitionIds = 'n/a'
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
        [string]$scopeDisplayName
    )

    $currentTask = "PolicySet definitions $($TargetMgOrSub) '$($scopeDisplayName)' ('$scopeId')"
    if ($TargetMgOrSub -eq 'Sub') {
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2021-06-01&`$filter=policyType eq 'Custom'"
    }
    if ($TargetMgOrSub -eq 'MG') {
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
            $htTemp.DisplayName = $($scopePolicySetDefinition.Properties.displayname)
            $htTemp.Description = $($policySetDefinitionDescription)
            $htTemp.Type = $($scopePolicySetDefinition.Properties.policyType)
            $htTemp.Category = $($scopePolicySetDefinition.Properties.metadata.category)
            $htTemp.PolicyDefinitionId = $hlpPolicySetDefinitionId
            $arrayPolicySetPolicyIdsToLower = @()
            $arrayPolicySetPolicyIdsToLower = foreach ($policySetPolicy in $scopePolicySetDefinition.properties.policydefinitions.policyDefinitionId) {
                    ($policySetPolicy).ToLower()
            }
            $htTemp.PolicySetPolicyIds = $arrayPolicySetPolicyIdsToLower
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
    $currentTask = "Policy assignments '$($scopeDisplayName)' ('$($scopeId)')"
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
                            $policyCategory = ($policyDefinition).Category
                            $policyDefinitionEffectDefault = ($policyDefinition).effectDefaultValue
                            $policyDefinitionEffectFixed = ($policyDefinition).effectFixedValue
                        }
                        else {
                            #test
                            Write-Host "   attention! $scopeDisplayName ($scopeId); policyAssignment '$($L0mgmtGroupPolicyAssignment.Id)' policyDefinition (Policy) could not be found: '$($policyDefinitionId)' -retry"
                            start-sleep -seconds 1
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
                        Throw 'Error - AzGovViz: check the last console output for details'
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
                        $policySetCategory = $policySetDefinition.Category
                    }
                    else {
                        #test
                        #Write-Host "pa '($L0mgmtGroupPolicyAssignment.Id)' scope: '$($scopeId)' - policySetDefinition not available: $policySetDefinitionId"
                        start-sleep -seconds 1
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

    $currentTask = "Policy assignments '$($scopeDisplayName)' ('$scopeId')"
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
                            start-sleep -seconds 1
                        }
                    }
                    until($policyReturnedFromHt -or $tryCounter -gt 5)
                    if (-not $policyReturnedFromHt) {
                        Write-Host "FinalHandler - $scopeDisplayName ($scopeId) $policyVariant was processing: policyId:'$policyDefinitionId'; policyAss:'$($L1mgmtGroupSubPolicyAssignment.Id)'; policyAssignmentsPolicyDefinition.Type: '$($policyAssignmentsPolicyDefinition.Type)'"
                        Write-Host ($policyAssignmentsPolicyDefinition | ConvertTo-Json -depth 99)
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
                            start-sleep -seconds 1
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
        [string]$scopeDisplayName
    )

    $currentTask = "Custom Role definitions $($TargetMgOrSub) '$($scopeDisplayName)' ('$scopeId')"
    if ($TargetMgOrSub -eq 'Sub') {
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Authorization/roleDefinitions?api-version=2015-07-01&`$filter=type eq 'CustomRole'"
    }
    if ($TargetMgOrSub -eq 'MG') {
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($scopeId)/providers/Microsoft.Authorization/roleDefinitions?api-version=2015-07-01&`$filter=type eq 'CustomRole'"
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
    $currentTask = "getARMRoleAssignmentScheduleInstances MG '$($scopeDisplayName)' ('$($scopeId)')"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($scopeId)/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01"
    $method = 'GET'
    $roleAssignmentScheduleInstancesFromAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    if ($roleAssignmentScheduleInstancesFromAPI -eq 'ResourceNotOnboarded' -or $roleAssignmentScheduleInstancesFromAPI -eq 'TenantNotOnboarded' -or $roleAssignmentScheduleInstancesFromAPI -eq 'InvalidResourceType') {
        #Write-Host "Scope '$($scopeDisplayName)' ('$scopeId') not onboarded in PIM"
    }
    else {
        $roleAssignmentScheduleInstances = ($roleAssignmentScheduleInstancesFromAPI.where( { ($_.properties.roleAssignmentScheduleId -replace '.*/') -ne ($_.properties.originRoleAssignmentId -replace '.*/') }))
        $roleAssignmentScheduleInstancesCount = $roleAssignmentScheduleInstances.Count
        if ($roleAssignmentScheduleInstancesCount -gt 0) {
            $htRoleAssignmentsPIM = @{}
            foreach ($roleAssignmentScheduleInstance in $roleAssignmentScheduleInstances) {
                $htRoleAssignmentsPIM.($roleAssignmentScheduleInstance.properties.originRoleAssignmentId.tolower()) = $roleAssignmentScheduleInstance.properties
            }
        }
    }

    #RoleAssignment API MG
    $currentTask = "Role assignments API '$($scopeDisplayName)' ('$($scopeId)')"
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
    $currentTask = "Role assignments usage metrics '$($scopeDisplayName)' ('$scopeId')"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Authorization/roleAssignmentsUsageMetrics?api-version=2019-08-01-preview"
    $method = 'GET'
    $roleAssignmentsUsage = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -listenOn 'Content' -caller 'CustomDataCollection'

    $script:htSubscriptionsRoleAssignmentLimit.($scopeId) = $roleAssignmentsUsage.roleAssignmentsLimit

    #PIM SubscriptionRoleAssignmentScheduleInstances
    $currentTask = "getARMRoleAssignmentScheduleInstances Sub '$($scopeDisplayName)' ('$scopeId')"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($scopeId)/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01"
    $method = 'GET'
    $roleAssignmentScheduleInstancesFromAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

    if ($roleAssignmentScheduleInstancesFromAPI -eq 'ResourceNotOnboarded' -or $roleAssignmentScheduleInstancesFromAPI -eq 'TenantNotOnboarded' -or $roleAssignmentScheduleInstancesFromAPI -eq 'InvalidResourceType') {
        #Write-Host "Scope '$($scopeDisplayName)' ('$scopeId') not onboarded in PIM"
    }
    else {
        $roleAssignmentScheduleInstances = ($roleAssignmentScheduleInstancesFromAPI.where( { ($_.properties.roleAssignmentScheduleId -replace '.*/') -ne ($_.properties.originRoleAssignmentId -replace '.*/') }))
        $roleAssignmentScheduleInstancesCount = $roleAssignmentScheduleInstances.Count
        if ($roleAssignmentScheduleInstancesCount -gt 0) {
            $htRoleAssignmentsPIM = @{}
            foreach ($roleAssignmentScheduleInstance in $roleAssignmentScheduleInstances) {
                $htRoleAssignmentsPIM.($roleAssignmentScheduleInstance.properties.originRoleAssignmentId.tolower()) = $roleAssignmentScheduleInstance.properties
            }
        }
    }

    #RoleAssignment API Sub
    $currentTask = "Role assignments API '$($scopeDisplayName)' ('$scopeId')"
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
        [string]$subscriptionMgPath
    )

    $apiEndPoint = $azAPICallConf['azAPIEndpointUrls'].ARM
    $api = "/subscriptions/$($scopeId)/providers/Microsoft.Authorization/classicAdministrators"
    $apiVersion = '?api-version=2015-07-01'
    $uri = $apiEndPoint + $api + $apiVersion
    $azAPICallPayload = @{
        uri                    = $uri
        method                 = 'GET'
        currentTask            = "classicAdministrators '$($scopeDisplayName)' ('$scopeId')"
        AzAPICallConfiguration = $azAPICallConf
    }

    $AzApiCallResult = AzAPICall @azAPICallPayload
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
$funcDataCollectionClassicAdministratorsSub = $function:dataCollectionClassicAdministratorsSub.ToString()

#endregion functions4DataCollection