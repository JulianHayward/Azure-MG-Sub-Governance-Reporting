function getConsumption {

    $costManagementQueryAPIVersion = $azAPICallConf['htParameters'].APIMappingCloudEnvironment.costManagementQuery.($azAPICallConf['htParameters'].azureCloudEnvironment)

    function addToAllConsumptionData {
        [CmdletBinding()]Param(
            [Parameter(Mandatory)]
            [object]
            $consumptiondataFromAPI
        )

        foreach ($consumptionline in $consumptiondataFromAPI.properties.rows) {
            $hlper = $htSubscriptionsMgPath.($consumptionline[1])

            $null = $script:allConsumptionData.Add([PSCustomObject]@{
                    "$($consumptiondataFromAPI.properties.columns.name[0])" = [decimal]$consumptionline[0]
                    "$($consumptiondataFromAPI.properties.columns.name[1])" = $consumptionline[1]
                    SubscriptionName                                        = $hlper.DisplayName
                    SubscriptionMgPath                                      = $hlper.ParentNameChainDelimited
                    "$($consumptiondataFromAPI.properties.columns.name[2])" = $consumptionline[2]
                    "$($consumptiondataFromAPI.properties.columns.name[3])" = $consumptionline[3]
                    "$($consumptiondataFromAPI.properties.columns.name[4])" = $consumptionline[4]
                    "$($consumptiondataFromAPI.properties.columns.name[5])" = $consumptionline[5]
                    "$($consumptiondataFromAPI.properties.columns.name[6])" = $consumptionline[6]
                })
        }
    }

    $startConsumptionData = Get-Date

    #cost only for whitelisted quotaId
    if ($SubscriptionQuotaIdWhitelist[0] -ne 'undefined') {
        if ($subsToProcessInCustomDataCollectionCount -gt 0) {
            #region mgScopeWhitelisted
            #$subscriptionIdsOptimizedForBody = '"{0}"' -f ($subsToProcessInCustomDataCollection.subscriptionId -join '","')
            $currenttask = "Getting Consumption data (scope MG '$($ManagementGroupId)') for $($subsToProcessInCustomDataCollectionCount) Subscriptions (QuotaId Whitelist: '$($SubscriptionQuotaIdWhitelist -join ', ')') for $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)"
            Write-Host "$currentTask"
            #https://learn.microsoft.com/rest/api/cost-management/query/usage
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)/providers/Microsoft.CostManagement/query?api-version=$($costManagementQueryAPIVersion)&`$top=5000"
            $method = 'POST'

            $counterBatch = [PSCustomObject] @{ Value = 0 }
            $batchSize = 100
            $subscriptionsBatch = ($subsToProcessInCustomDataCollection | Sort-Object -Property subscriptionQuotaId) | Group-Object -Property { [math]::Floor($counterBatch.Value++ / $batchSize) }
            $batchCnt = 0

            foreach ($batch in $subscriptionsBatch) {
                $batchCnt++
                $subscriptionIdsOptimizedForBody = '"{0}"' -f (($batch.Group).subscriptionId -join '","')
                $currenttask = "Getting Consumption data #batch$($batchCnt)/$(($subscriptionsBatch | Measure-Object).Count) (scope MG '$($ManagementGroupId)') for $(($batch.Group).Count) Subscriptions (QuotaId Whitelist: '$($SubscriptionQuotaIdWhitelist -join ', ')') for $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)"
                Write-Host "$currentTask" -ForegroundColor Cyan

                $body = @"
{
"type": "ActualCost",
"dataset": {
    "granularity": "none",
    "filter": {
        "dimensions": {
            "name": "SubscriptionId",
            "operator": "In",
            "values": [
                $($subscriptionIdsOptimizedForBody)
            ]
        }
    },
    "aggregation": {
        "totalCost": {
            "name": "PreTaxCost",
            "function": "Sum"
        }
    },
    "grouping": [
        {
            "type": "Dimension",
            "name": "SubscriptionId"
        },
        {
            "type": "Dimension",
            "name": "ResourceId"
        },
        {
            "type": "Dimension",
            "name": "ResourceType"
        },
        {
            "type": "Dimension",
            "name": "MeterCategory"
        },
        {
            "type": "Dimension",
            "name": "ChargeType"
        }
    ]
},
"timeframe": "Custom",
"timeperiod": {
    "from": "$($azureConsumptionStartDate)",
    "to": "$($azureConsumptionEndDate)"
}
}
"@

                $mgConsumptionData = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -body $body -currentTask $currentTask -listenOn 'ContentProperties'
                #endregion mgScopeWhitelisted

                <#test
                #$mgConsumptionData = "OfferNotSupported"
                if ($batchCnt -eq 1){
                    $mgConsumptionData = "OfferNotSupported"
                }
                #>

                if ($mgConsumptionData -eq 'Unauthorized' -or $mgConsumptionData -eq 'OfferNotSupported' -or $mgConsumptionData -eq 'NoValidSubscriptions') {
                    if (-not $script:htConsumptionExceptionLog.Mg.($ManagementGroupId)) {
                        $script:htConsumptionExceptionLog.Mg.($ManagementGroupId) = @{}
                    }
                    $script:htConsumptionExceptionLog.Mg.($ManagementGroupId).($batchCnt) = @{
                        Exception     = $mgConsumptionData
                        Subscriptions = ($batch.Group).subscriptionId
                    }

                    Write-Host " Switching to 'foreach Subscription' Subscription scope mode. Getting Consumption data #batch$($batchCnt) using Management Group scope failed."
                    #region subScopewhitelisted
                    $body = @"
{
"type": "ActualCost",
"dataset": {
    "granularity": "none",
    "aggregation": {
        "totalCost": {
            "name": "PreTaxCost",
            "function": "Sum"
        }
    },
    "grouping": [
        {
            "type": "Dimension",
            "name": "SubscriptionId"
        },
        {
            "type": "Dimension",
            "name": "ResourceId"
        },
        {
            "type": "Dimension",
            "name": "ResourceType"
        },
        {
            "type": "Dimension",
            "name": "MeterCategory"
        },
        {
            "type": "Dimension",
            "name": "ChargeType"
        }
    ]
},
"timeframe": "Custom",
"timeperiod": {
    "from": "$($azureConsumptionStartDate)",
    "to": "$($azureConsumptionEndDate)"
}
}
"@
                    $funcAddToAllConsumptionData = $function:addToAllConsumptionData.ToString()
                    $batch.Group | ForEach-Object -Parallel {
                        $subIdToProcess = $_.subscriptionId
                        $subNameToProcess = $_.subscriptionName
                        $subscriptionQuotaIdToProcess = $_.subscriptionQuotaId
                        #region UsingVARs
                        $body = $using:body
                        $azureConsumptionStartDate = $using:azureConsumptionStartDate
                        $azureConsumptionEndDate = $using:azureConsumptionEndDate
                        $SubscriptionQuotaIdWhitelist = $using:SubscriptionQuotaIdWhitelist
                        #fromOtherFunctions
                        $azAPICallConf = $using:azAPICallConf
                        $scriptPath = $using:ScriptPath
                        #Array&HTs
                        $allConsumptionData = $using:allConsumptionData
                        $htSubscriptionsMgPath = $using:htSubscriptionsMgPath
                        $htAllSubscriptionsFromAPI = $using:htAllSubscriptionsFromAPI
                        $htConsumptionExceptionLog = $using:htConsumptionExceptionLog
                        #other
                        $function:addToAllConsumptionData = $using:funcAddToAllConsumptionData
                        $costManagementQueryAPIVersion = $using:costManagementQueryAPIVersion
                        #endregion UsingVARs

                        $currentTask = "  Getting Consumption data (scope Sub $($subNameToProcess) '$($subIdToProcess)' ($($subscriptionQuotaIdToProcess)) (whitelist))"
                        #test
                        Write-Host $currentTask
                        #https://learn.microsoft.com/rest/api/cost-management/query/usage
                        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($subIdToProcess)/providers/Microsoft.CostManagement/query?api-version=$($costManagementQueryAPIVersion)&`$top=5000"
                        $method = 'POST'
                        $subConsumptionData = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -body $body -currentTask $currentTask -listenOn 'ContentProperties'
                        if ($subConsumptionData -eq 'Unauthorized' -or $subConsumptionData -eq 'OfferNotSupported' -or $subConsumptionData -eq 'InvalidQueryDefinition' -or $subConsumptionData -eq 'NonValidWebDirectAIRSOfferType' -or $subConsumptionData -eq 'NotFoundNotSupported' -or $subConsumptionData -eq 'IndirectCostDisabled') {
                            Write-Host "   Failed ($subConsumptionData) - Getting Consumption data (scope Sub $($subNameToProcess) '$($subIdToProcess)' ($($subscriptionQuotaIdToProcess)) (whitelist))"
                            $hlper = $htAllSubscriptionsFromAPI.($subIdToProcess).subDetails
                            $hlper2 = $htSubscriptionsMgPath.($subIdToProcess)
                            $script:htConsumptionExceptionLog.Sub.($subIdToProcess) = @{
                                Exception        = $subConsumptionData
                                SubscriptionId   = $subIdToProcess
                                SubscriptionName = $hlper.displayName
                                QuotaId          = $hlper.subscriptionPolicies.quotaId
                                mgPath           = $hlper2.ParentNameChainDelimited
                                mgParent         = $hlper2.Parent
                            }

                            Continue
                        }
                        else {
                            Write-Host "   $($subConsumptionData.Count) Consumption data entries ((scope Sub $($subNameToProcess) '$($subIdToProcess)' ($($subscriptionQuotaIdToProcess))))"
                            if ($subConsumptionData.Count -gt 0) {
                                addToAllConsumptionData -consumptiondataFromAPI $subConsumptionData
                                <#
                                foreach ($consumptionEntry in $subConsumptionData) {
                                    if ($consumptionEntry.PreTaxCost -ne 0) {
                                        $null = $script:allConsumptionData.Add($consumptionEntry)
                                    }
                                }
                                #>

                            }
                        }
                    } -ThrottleLimit $ThrottleLimit
                    #endregion subScopewhitelisted
                }
                else {
                    Write-Host " $($mgConsumptionData.Count) Consumption data entries"
                    if ($mgConsumptionData.Count -gt 0) {
                        addToAllConsumptionData -consumptiondataFromAPI $mgConsumptionData
                        <#
                        foreach ($consumptionEntry in $mgConsumptionData) {
                            if ($consumptionEntry.PreTaxCost -ne 0) {
                                $null = $script:allConsumptionData.Add($consumptionEntry)
                            }
                        }
                        #>
                    }
                }
            }
        }
        else {
            $detailShowStopperResult = 'NoWhitelistSubscriptionsPresent'
            Write-Host ' No Subscriptions matching whitelist present, skipping Consumption data processing'
            #überprüfen
        }
    }
    else {

        if ($subsToProcessInCustomDataCollectionCount -gt 0) {
            #region mgScope
            $currenttask = "Getting Consumption data (scope MG '$($ManagementGroupId)') for $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)"
            Write-Host "$currentTask"
            #https://learn.microsoft.com/rest/api/cost-management/query/usage
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)/providers/Microsoft.CostManagement/query?api-version=$($costManagementQueryAPIVersion)&`$top=5000"
            $method = 'POST'
            $body = @"
{
    "type": "ActualCost",
    "dataset": {
        "granularity": "none",
        "aggregation": {
            "totalCost": {
                "name": "PreTaxCost",
                "function": "Sum"
            }
        },
        "grouping": [
            {
                "type": "Dimension",
                "name": "SubscriptionId"
            },
            {
                "type": "Dimension",
                "name": "ResourceId"
            },
            {
                "type": "Dimension",
                "name": "ResourceType"
            },
            {
                "type": "Dimension",
                "name": "MeterCategory"
            },
            {
                "type": "Dimension",
                "name": "ChargeType"
            }
        ]
    },
    "timeframe": "Custom",
    "timeperiod": {
        "from": "$($azureConsumptionStartDate)",
        "to": "$($azureConsumptionEndDate)"
    }
}
"@
            #$script:allConsumptionData = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -body $body -currentTask $currentTask -listenOn 'ContentProperties'
            $allConsumptionDataAPIResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -body $body -currentTask $currentTask -listenOn 'ContentProperties'
            #endregion mgScope

            #test
            #$allConsumptionData = "OfferNotSupported"

            if ($allConsumptionDataAPIResult -eq 'AccountCostDisabled' <#-or $allConsumptionDataAPIResult -eq 'NoValidSubscriptions'#>) {
                if ($allConsumptionDataAPIResult -eq 'AccountCostDisabled') {
                    $detailShowStopperResult = $allConsumptionDataAPIResult
                }
                <#if ($allConsumptionDataAPIResult -eq 'NoValidSubscriptions') {
                    $detailShowStopperResult = $allConsumptionDataAPIResult
                }#>
            }
            else {
                if ($allConsumptionDataAPIResult -eq 'Unauthorized' -or $allConsumptionDataAPIResult -eq 'OfferNotSupported' -or $allConsumptionDataAPIResult -eq 'NoValidSubscriptions' -or $allConsumptionDataAPIResult -eq 'tooManySubscriptions') {
                    $script:htConsumptionExceptionLog.Mg.($ManagementGroupId) = @{
                        Exception = $allConsumptionDataAPIResult
                    }
                    Write-Host " Switching to 'foreach Subscription' mode. Getting Consumption data using Management Group scope failed."
                    #region subScope
                    $body = @"
{
    "type": "ActualCost",
    "dataset": {
        "granularity": "none",
        "aggregation": {
            "totalCost": {
                "name": "PreTaxCost",
                "function": "Sum"
            }
        },
        "grouping": [
            {
                "type": "Dimension",
                "name": "SubscriptionId"
            },
            {
                "type": "Dimension",
                "name": "ResourceId"
            },
            {
                "type": "Dimension",
                "name": "ResourceType"
            },
            {
                "type": "Dimension",
                "name": "MeterCategory"
            },
            {
                "type": "Dimension",
                "name": "ChargeType"
            }
        ]
    },
    "timeframe": "Custom",
    "timeperiod": {
        "from": "$($azureConsumptionStartDate)",
        "to": "$($azureConsumptionEndDate)"
    }
}
"@

                    $funcAddToAllConsumptionData = $function:addToAllConsumptionData.ToString()
                    $subsToProcessInCustomDataCollection | ForEach-Object -Parallel {
                        $subIdToProcess = $_.subscriptionId
                        $subNameToProcess = $_.subscriptionName
                        $subscriptionQuotaIdToProcess = $_.subscriptionQuotaId
                        #region UsingVARs
                        $body = $using:body
                        $azureConsumptionStartDate = $using:azureConsumptionStartDate
                        $azureConsumptionEndDate = $using:azureConsumptionEndDate
                        #fromOtherFunctions
                        $azAPICallConf = $using:azAPICallConf
                        $scriptPath = $using:ScriptPath
                        #Array&HTs
                        $htSubscriptionsMgPath = $using:htSubscriptionsMgPath
                        $htAllSubscriptionsFromAPI = $using:htAllSubscriptionsFromAPI
                        $allConsumptionData = $using:allConsumptionData
                        $htConsumptionExceptionLog = $using:htConsumptionExceptionLog
                        #other
                        $function:addToAllConsumptionData = $using:funcAddToAllConsumptionData
                        $costManagementQueryAPIVersion = $using:costManagementQueryAPIVersion
                        #endregion UsingVARs

                        $currentTask = "  Getting Consumption data (scope Sub $($subNameToProcess) '$($subIdToProcess)' ($($subscriptionQuotaIdToProcess)))"
                        #test
                        Write-Host $currentTask
                        #https://learn.microsoft.com/rest/api/cost-management/query/usage
                        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($subIdToProcess)/providers/Microsoft.CostManagement/query?api-version=$($costManagementQueryAPIVersion)&`$top=5000"
                        $method = 'POST'
                        $subConsumptionData = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -body $body -currentTask $currentTask -listenOn 'ContentProperties'
                        if ($subConsumptionData -eq 'Unauthorized' -or $subConsumptionData -eq 'OfferNotSupported' -or $subConsumptionData -eq 'InvalidQueryDefinition' -or $subConsumptionData -eq 'NonValidWebDirectAIRSOfferType' -or $subConsumptionData -eq 'NotFoundNotSupported' -or $subConsumptionData -eq 'IndirectCostDisabled') {
                            Write-Host "   Failed ($subConsumptionData) - Getting Consumption data (scope Sub $($subNameToProcess) '$($subIdToProcess)' ($($subscriptionQuotaIdToProcess)))"
                            $hlper = $htAllSubscriptionsFromAPI.($subIdToProcess).subDetails
                            $hlper2 = $htSubscriptionsMgPath.($subIdToProcess)
                            $script:htConsumptionExceptionLog.Sub.($subIdToProcess) = @{
                                Exception        = $subConsumptionData
                                SubscriptionId   = $subIdToProcess
                                SubscriptionName = $hlper.displayName
                                QuotaId          = $hlper.subscriptionPolicies.quotaId
                                mgPath           = $hlper2.ParentNameChainDelimited
                                mgParent         = $hlper2.Parent
                            }

                            Continue
                        }
                        else {
                            Write-Host "   $($subConsumptionData.Count) Consumption data entries (scope Sub $($subNameToProcess) '$($subIdToProcess)' ($($subscriptionQuotaIdToProcess)))"
                            if ($subConsumptionData.Count -gt 0) {
                                addToAllConsumptionData -consumptiondataFromAPI $subConsumptionData
                                <#
                            foreach ($consumptionEntry in $subConsumptionData) {
                                if ($consumptionEntry.PreTaxCost -ne 0) {
                                    $null = $script:allConsumptionData.Add($consumptionEntry)
                                }
                            }
                            #>
                            }
                        }
                    } -ThrottleLimit $ThrottleLimit
                    #endregion subScope
                }
                else {
                    Write-Host " $($allConsumptionDataAPIResult.properties.rows.Count) Consumption data entries"
                    if ($allConsumptionDataAPIResult.properties.rows.Count -gt 0) {
                        addToAllConsumptionData -consumptiondataFromAPI $allConsumptionDataAPIResult
                    }
                }
            }
        }
        else {
            $detailShowStopperResult = 'NoSubscriptionsPresent'
            Write-Host ' No Subscriptions present, skipping Consumption data processing'
        }
    }

    if ($detailShowStopperResult -eq 'AccountCostDisabled' -or $detailShowStopperResult -eq 'NoValidSubscriptions' -or $detailShowStopperResult -eq 'NoWhitelistSubscriptionsPresent' -or $detailShowStopperResult -eq 'NoSubscriptionsPresent') {
        if ($detailShowStopperResult -eq 'AccountCostDisabled') {
            Write-Host ' Seems Access to cost data has been disabled for this Account - skipping CostManagement'
        }
        if ($detailShowStopperResult -eq 'NoValidSubscriptions') {
            Write-Host ' Seems there are no valid Subscriptions present - skipping CostManagement'
        }
        if ($detailShowStopperResult -eq 'NoWhitelistSubscriptionsPresent') {
            Write-Host " Seems there are no Subscriptions present that match the whitelist ($($SubscriptionQuotaIdWhitelist -join ', ')) - skipping CostManagement"
        }
        if ($detailShowStopperResult -eq 'NoSubscriptionsPresent') {
            Write-Host ' Seems there are no Subscriptions present - skipping CostManagement'
        }
        Write-Host " Action: Setting switch parameter 'DoAzureConsumption' to false"
        $azAPICallConf['htParameters'].DoAzureConsumption = $false
    }
    else {
        Write-Host ' Checking returned Consumption data'
        $script:allConsumptionDataCount = $allConsumptionData.Count

        if ($allConsumptionDataCount -gt 0) {

            $script:allConsumptionData = $allConsumptionData.where( { $_.PreTaxCost -ne 0 } )
            $script:allConsumptionDataCount = $allConsumptionData.Count

            if ($allConsumptionDataCount -gt 0) {
                Write-Host "  $($allConsumptionDataCount) relevant Consumption data entries"

                $script:consumptionData = $allConsumptionData
                $script:consumptionDataGroupedByCurrency = $consumptionData | Group-Object -Property Currency

                foreach ($currency in $consumptionDataGroupedByCurrency) {

                    #subscriptions
                    $groupAllConsumptionDataPerCurrencyBySubscriptionId = $currency.group | Group-Object -Property SubscriptionId
                    foreach ($subscriptionId in $groupAllConsumptionDataPerCurrencyBySubscriptionId) {

                        $subTotalCost = ($subscriptionId.Group.PreTaxCost | Measure-Object -Sum).Sum
                        $script:htAzureConsumptionSubscriptions.($subscriptionId.Name) = @{
                            ConsumptionData = $subscriptionId.group
                            TotalCost       = $subTotalCost
                            Currency        = $currency.Name
                        }

                        $resourceTypes = $subscriptionId.Group.ResourceType | Sort-Object -Unique

                        foreach ($parentMg in $htSubscriptionsMgPath.($subscriptionId.Name).ParentNameChain) {

                            if (-not $htManagementGroupsCost.($parentMg)) {
                                $script:htManagementGroupsCost.($parentMg) = @{
                                    currencies                                         = $currency.Name
                                    "mgTotalCost_$($currency.Name)"                    = $subTotalCost #[decimal]$subTotalCost
                                    "resourcesThatGeneratedCost_$($currency.Name)"     = ($subscriptionId.Group.ResourceId | Sort-Object -Unique | Measure-Object).Count
                                    resourcesThatGeneratedCostCurrencyIndependent      = ($subscriptionId.Group.ResourceId | Sort-Object -Unique | Measure-Object).Count
                                    "subscriptionsThatGeneratedCost_$($currency.Name)" = 1
                                    subscriptionsThatGeneratedCostCurrencyIndependent  = 1
                                    "resourceTypesThatGeneratedCost_$($currency.Name)" = $resourceTypes
                                    resourceTypesThatGeneratedCostCurrencyIndependent  = $resourceTypes
                                    "consumptionDataSubscriptions_$($currency.Name)"   = $subscriptionId.group
                                    consumptionDataSubscriptions                       = $subscriptionId.group
                                }

                            }
                            else {
                                $newMgTotalCost = $htManagementGroupsCost.($parentMg)."mgTotalCost_$($currency.Name)" + $subTotalCost #[decimal]$subTotalCost
                                $script:htManagementGroupsCost.($parentMg)."mgTotalCost_$($currency.Name)" = $newMgTotalCost #[decimal]$newMgTotalCost

                                $currencies = [array]$htManagementGroupsCost.($parentMg).currencies
                                if ($currencies -notcontains $currency.Name) {
                                    $currencies += $currency.Name
                                    $script:htManagementGroupsCost.($parentMg).currencies = $currencies
                                }

                                #currency based
                                $resourcesThatGeneratedCost = $htManagementGroupsCost.($parentMg)."resourcesThatGeneratedCost_$($currency.Name)" + ($subscriptionId.Group.ResourceId | Sort-Object -Unique | Measure-Object).Count
                                $script:htManagementGroupsCost.($parentMg)."resourcesThatGeneratedCost_$($currency.Name)" = $resourcesThatGeneratedCost

                                $subscriptionsThatGeneratedCost = $htManagementGroupsCost.($parentMg)."subscriptionsThatGeneratedCost_$($currency.Name)" + 1
                                $script:htManagementGroupsCost.($parentMg)."subscriptionsThatGeneratedCost_$($currency.Name)" = $subscriptionsThatGeneratedCost

                                $consumptionDataSubscriptions = $htManagementGroupsCost.($parentMg)."consumptionDataSubscriptions_$($currency.Name)" += $subscriptionId.group
                                $script:htManagementGroupsCost.($parentMg)."consumptionDataSubscriptions_$($currency.Name)" = $consumptionDataSubscriptions

                                $resourceTypesThatGeneratedCost = $htManagementGroupsCost.($parentMg)."resourceTypesThatGeneratedCost_$($currency.Name)"
                                foreach ($resourceType in $resourceTypes) {
                                    if ($resourceTypesThatGeneratedCost -notcontains $resourceType) {
                                        $resourceTypesThatGeneratedCost += $resourceType
                                    }
                                }
                                $script:htManagementGroupsCost.($parentMg)."resourceTypesThatGeneratedCost_$($currency.Name)" = $resourceTypesThatGeneratedCost

                                #currencyIndependent
                                $resourcesThatGeneratedCostCurrencyIndependent = $htManagementGroupsCost.($parentMg).resourcesThatGeneratedCostCurrencyIndependent + ($subscriptionId.Group.ResourceId | Sort-Object -Unique | Measure-Object).Count
                                $script:htManagementGroupsCost.($parentMg).resourcesThatGeneratedCostCurrencyIndependent = $resourcesThatGeneratedCostCurrencyIndependent

                                $subscriptionsThatGeneratedCostCurrencyIndependent = $htManagementGroupsCost.($parentMg).subscriptionsThatGeneratedCostCurrencyIndependent + 1
                                $script:htManagementGroupsCost.($parentMg).subscriptionsThatGeneratedCostCurrencyIndependent = $subscriptionsThatGeneratedCostCurrencyIndependent

                                $consumptionDataSubscriptionsCurrencyIndependent = $htManagementGroupsCost.($parentMg).consumptionDataSubscriptions += $subscriptionId.group
                                $script:htManagementGroupsCost.($parentMg).consumptionDataSubscriptions = $consumptionDataSubscriptionsCurrencyIndependent

                                $resourceTypesThatGeneratedCostCurrencyIndependent = $htManagementGroupsCost.($parentMg).resourceTypesThatGeneratedCostCurrencyIndependent
                                foreach ($resourceType in $resourceTypes) {
                                    if ($resourceTypesThatGeneratedCostCurrencyIndependent -notcontains $resourceType) {
                                        $resourceTypesThatGeneratedCostCurrencyIndependent += $resourceType
                                    }
                                }
                                $script:htManagementGroupsCost.($parentMg).resourceTypesThatGeneratedCostCurrencyIndependent = $resourceTypesThatGeneratedCostCurrencyIndependent
                            }
                        }
                    }

                    $totalCost = 0
                    $script:tenantSummaryConsumptionDataGrouped = $currency.group | Group-Object -Property ResourceType, ChargeType, MeterCategory
                    $subsCount = ($tenantSummaryConsumptionDataGrouped.group.subscriptionId | Sort-Object -Unique | Measure-Object).Count
                    $consumedServiceCount = ($tenantSummaryConsumptionDataGrouped.group.ResourceType | Sort-Object -Unique | Measure-Object).Count
                    $resourceCount = ($tenantSummaryConsumptionDataGrouped.group.ResourceId | Sort-Object -Unique | Measure-Object).Count
                    foreach ($consumptionline in $tenantSummaryConsumptionDataGrouped) {

                        $costConsumptionLine = ($consumptionline.group.PreTaxCost | Measure-Object -Sum).Sum

                        if ([math]::Round($costConsumptionLine, 2) -eq 0) {
                            $cost = $costConsumptionLine.ToString('0.0000')
                        }
                        else {
                            $cost = [math]::Round($costConsumptionLine, 2).ToString('0.00')
                        }

                        $null = $script:arrayConsumptionData.Add([PSCustomObject]@{
                                ResourceType                 = ($consumptionline.name).split(', ')[0]
                                ConsumedServiceChargeType    = ($consumptionline.name).split(', ')[1]
                                ConsumedServiceCategory      = ($consumptionline.name).split(', ')[2]
                                ConsumedServiceInstanceCount = $consumptionline.Count
                                ConsumedServiceCost          = $cost #[decimal]$cost
                                ConsumedServiceSubscriptions = ($consumptionline.group.SubscriptionId | Sort-Object -Unique).Count
                                ConsumedServiceCurrency      = $currency.Name
                            })

                        $totalCost = $totalCost + $costConsumptionLine

                    }
                    if ([math]::Round($totalCost, 2) -eq 0) {
                        $totalCost = $totalCost
                    }
                    else {
                        $totalCost = [math]::Round($totalCost, 2).ToString('0.00')
                    }
                    $script:arrayTotalCostSummary += "$($totalCost) $($currency.Name) generated by $($resourceCount) Resources ($($consumedServiceCount) ResourceTypes) in $($subsCount) Subscriptions"
                }
            }
            else {
                Write-Host '  No relevant consumption data entries (0)'
            }
        }

        #region BuildConsumptionCSV
        if (-not $NoCsvExport) {
            if (-not $NoAzureConsumptionReportExportToCSV) {
                Write-Host " Exporting Consumption CSV $($outputPath)$($DirectorySeparatorChar)$($fileName)_Consumption.csv"
                $startBuildConsumptionCSV = Get-Date
                if ($CsvExportUseQuotesAsNeeded) {
                    $allConsumptionData | Sort-Object -Property ResourceId | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_Consumption.csv" -Delimiter "$csvDelimiter" -NoTypeInformation -UseQuotes AsNeeded
                }
                else {
                    $allConsumptionData | Sort-Object -Property ResourceId | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_Consumption.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
                }
                $endBuildConsumptionCSV = Get-Date
                Write-Host " Exporting Consumption CSV total duration: $((New-TimeSpan -Start $startBuildConsumptionCSV -End $endBuildConsumptionCSV).TotalMinutes) minutes ($((New-TimeSpan -Start $startBuildConsumptionCSV -End $endBuildConsumptionCSV).TotalSeconds) seconds)"
            }
        }
        #endregion BuildConsumptionCSV
    }
    $endConsumptionData = Get-Date
    Write-Host "Getting Consumption data duration: $((New-TimeSpan -Start $startConsumptionData -End $endConsumptionData).TotalSeconds) seconds"
}