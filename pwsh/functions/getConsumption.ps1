function getConsumption {

    #region dataprocessingConsumption
    $startConsumptionData = Get-Date

    #cost only for whitelisted quotaId
    if ($SubscriptionQuotaIdWhitelist[0] -ne 'undefined') {
        if ($subsToProcessInCustomDataCollectionCount -gt 0) {
            #region mgScopeWhitelisted
            #$subscriptionIdsOptimizedForBody = '"{0}"' -f ($subsToProcessInCustomDataCollection.subscriptionId -join '","')
            #$currenttask = "Getting Consumption data (scope MG '$($ManagementGroupId)') for $($subsToProcessInCustomDataCollectionCount) Subscriptions (QuotaId Whitelist: '$($SubscriptionQuotaIdWhitelist -join ", ")') for period $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)"
            #Write-Host "$currentTask"
            #https://docs.microsoft.com/en-us/rest/api/cost-management/query/usage
            $uri = "$($Configuration['htAzureEnvironmentRelatedUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)/providers/Microsoft.CostManagement/query?api-version=2019-11-01&`$top=5000"
            $method = 'POST'

            $counterBatch = [PSCustomObject] @{ Value = 0 }
            $batchSize = 100
            $subscriptionsBatch = ($subsToProcessInCustomDataCollection | Sort-Object -Property subscriptionQuotaId) | Group-Object -Property { [math]::Floor($counterBatch.Value++ / $batchSize) }
            $batchCnt = 0
            $script:allConsumptionData = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

            foreach ($batch in $subscriptionsBatch) {
                $batchCnt++
                $subscriptionIdsOptimizedForBody = '"{0}"' -f (($batch.Group).subscriptionId -join '","')
                $currenttask = "Getting Consumption data #batch$($batchCnt)/$(($subscriptionsBatch | Measure-Object).Count) (scope MG '$($ManagementGroupId)') for $(($batch.Group).Count) Subscriptions (QuotaId Whitelist: '$($SubscriptionQuotaIdWhitelist -join ', ')') for period $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)"
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
            "name": "ConsumedService"
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

                $mgConsumptionData = AzAPICall -AzAPICallConfiguration $Configuration -uri $uri -method $method -body $body -currentTask $currentTask -listenOn 'ContentProperties'
                #endregion mgScopeWhitelisted

                <#test
                #$mgConsumptionData = "OfferNotSupported"
                if ($batchCnt -eq 1){
                    $mgConsumptionData = "OfferNotSupported"
                }
                #>

                if ($mgConsumptionData -eq 'Unauthorized' -or $mgConsumptionData -eq 'OfferNotSupported') {
                    if (-not $script:htConsumptionExceptionLog.Mg.($ManagementGroupId)) {
                        $script:htConsumptionExceptionLog.Mg.($ManagementGroupId) = @{}
                    }
                    $script:htConsumptionExceptionLog.Mg.($ManagementGroupId).($batchCnt) = @{}
                    $script:htConsumptionExceptionLog.Mg.($ManagementGroupId).($batchCnt).Exception = $mgConsumptionData
                    $script:htConsumptionExceptionLog.Mg.($ManagementGroupId).($batchCnt).Subscriptions = ($batch.Group).subscriptionId
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
            "name": "ConsumedService"
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
                        $Configuration = $using:Configuration
                        #Array&HTs
                        $allConsumptionData = $using:allConsumptionData
                        $htSubscriptionsMgPath = $using:htSubscriptionsMgPath
                        $htAllSubscriptionsFromAPI = $using:htAllSubscriptionsFromAPI
                        $htConsumptionExceptionLog = $using:htConsumptionExceptionLog
                        #Functions
                        $function:AzAPICall = $using:functions.funcAzAPICall
                        $function:createBearerToken = $using:functions.funcCreateBearerToken
                        $function:GetJWTDetails = $using:functions.funcGetJWTDetails
                        #endregion UsingVARs

                        $currentTask = "  Getting Consumption data (scope Sub $($subNameToProcess) '$($subIdToProcess)' ($($subscriptionQuotaIdToProcess)) (whitelist))"
                        #test
                        write-host $currentTask
                        #https://docs.microsoft.com/en-us/rest/api/cost-management/query/usage
                        $uri = "$($Configuration['htAzureEnvironmentRelatedUrls'].ARM)/subscriptions/$($subIdToProcess)/providers/Microsoft.CostManagement/query?api-version=2019-11-01&`$top=5000"
                        $method = 'POST'
                        $subConsumptionData = AzAPICall -AzAPICallConfiguration $Configuration -uri $uri -method $method -body $body -currentTask $currentTask -listenOn 'ContentProperties'
                        if ($subConsumptionData -eq 'Unauthorized' -or $subConsumptionData -eq 'OfferNotSupported' -or $subConsumptionData -eq 'InvalidQueryDefinition' -or $subConsumptionData -eq 'NonValidWebDirectAIRSOfferType' -or $subConsumptionData -eq 'NotFoundNotSupported' -or $subConsumptionData -eq 'IndirectCostDisabled') {
                            Write-Host "   Failed ($subConsumptionData) - Getting Consumption data (scope Sub $($subNameToProcess) '$($subIdToProcess)' ($($subscriptionQuotaIdToProcess)) (whitelist))"
                            $hlper = $htAllSubscriptionsFromAPI.($subIdToProcess).subDetails
                            $hlper2 = $htSubscriptionsMgPath.($subIdToProcess)
                            $script:htConsumptionExceptionLog.Sub.($subIdToProcess) = @{}
                            $script:htConsumptionExceptionLog.Sub.($subIdToProcess).Exception = $subConsumptionData
                            $script:htConsumptionExceptionLog.Sub.($subIdToProcess).SubscriptionId = $subIdToProcess
                            $script:htConsumptionExceptionLog.Sub.($subIdToProcess).SubscriptionName = $hlper.displayName
                            $script:htConsumptionExceptionLog.Sub.($subIdToProcess).QuotaId = $hlper.subscriptionPolicies.quotaId
                            $script:htConsumptionExceptionLog.Sub.($subIdToProcess).mgPath = $hlper2.ParentNameChainDelimited
                            $script:htConsumptionExceptionLog.Sub.($subIdToProcess).mgParent = $hlper2.Parent
                            Continue
                        }
                        else {
                            Write-Host "   $($subConsumptionData.Count) Consumption data entries ((scope Sub $($subNameToProcess) '$($subIdToProcess)' ($($subscriptionQuotaIdToProcess))))"
                            if ($subConsumptionData.Count -gt 0) {
                                foreach ($consumptionEntry in $subConsumptionData) {
                                    if ($consumptionEntry.PreTaxCost -ne 0) {
                                        $null = $script:allConsumptionData.Add($consumptionEntry)
                                    }
                                }

                            }
                        }
                    } -ThrottleLimit $ThrottleLimit
                    #endregion subScopewhitelisted
                }
                else {
                    Write-Host " $($mgConsumptionData.Count) Consumption data entries"
                    if ($mgConsumptionData.Count -gt 0) {
                        foreach ($consumptionEntry in $mgConsumptionData) {
                            if ($consumptionEntry.PreTaxCost -ne 0) {
                                $null = $script:allConsumptionData.Add($consumptionEntry)
                            }
                        }
                    }
                }
            }
        }
        else {
            $script:allConsumptionData = 'NoWhitelistSubscriptionsPresent'
            Write-Host ' No Subscriptions matching whitelist present, skipping Consumption data processing'
        }
    }
    else {

        if ($subsToProcessInCustomDataCollectionCount -gt 0) {
            #region mgScope
            $currenttask = "Getting Consumption data (scope MG '$($ManagementGroupId)') for period $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)"
            Write-Host "$currentTask"
            #https://docs.microsoft.com/en-us/rest/api/cost-management/query/usage
            $uri = "$($Configuration['htAzureEnvironmentRelatedUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)/providers/Microsoft.CostManagement/query?api-version=2019-11-01&`$top=5000"
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
                "name": "ConsumedService"
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
            $script:allConsumptionData = AzAPICall -AzAPICallConfiguration $Configuration -uri $uri -method $method -body $body -currentTask $currentTask -listenOn 'ContentProperties'
            #endregion mgScope

            #test
            #$allConsumptionData = "OfferNotSupported"

            if ($allConsumptionData -eq 'Unauthorized' -or $allConsumptionData -eq 'OfferNotSupported') {
                $script:htConsumptionExceptionLog.Mg.($ManagementGroupId) = @{}
                $script:htConsumptionExceptionLog.Mg.($ManagementGroupId).Exception = $allConsumptionData
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
                "name": "ConsumedService"
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
                #$subIdsToProcess = ($arrayEntitiesFromAPI.where( { $_.properties.parentNameChain -contains $ManagementGroupID -and $_.type -eq "/subscriptions" } ) | Sort-Object -Property id -Unique).name
                $script:allConsumptionData = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
                $subsToProcessInCustomDataCollection | ForEach-Object -Parallel {
                    $subIdToProcess = $_.subscriptionId
                    $subNameToProcess = $_.subscriptionName
                    $subscriptionQuotaIdToProcess = $_.subscriptionQuotaId
                    #region UsingVARs
                    $body = $using:body
                    $azureConsumptionStartDate = $using:azureConsumptionStartDate
                    $azureConsumptionEndDate = $using:azureConsumptionEndDate
                    #fromOtherFunctions
                    $Configuration = $using:Configuration
                    #Array&HTs
                    $htSubscriptionsMgPath = $using:htSubscriptionsMgPath
                    $htAllSubscriptionsFromAPI = $using:htAllSubscriptionsFromAPI
                    $allConsumptionData = $using:allConsumptionData
                    $htConsumptionExceptionLog = $using:htConsumptionExceptionLog
                    #Functions
                    $function:AzAPICall = $using:functions.funcAzAPICall
                    $function:createBearerToken = $using:functions.funcCreateBearerToken
                    $function:GetJWTDetails = $using:functions.funcGetJWTDetails
                    #endregion UsingVARs

                    $currentTask = "  Getting Consumption data (scope Sub $($subNameToProcess) '$($subIdToProcess)' ($($subscriptionQuotaIdToProcess)))"
                    #test
                    write-host $currentTask
                    #https://docs.microsoft.com/en-us/rest/api/cost-management/query/usage
                    $uri = "$($Configuration['htAzureEnvironmentRelatedUrls'].ARM)/subscriptions/$($subIdToProcess)/providers/Microsoft.CostManagement/query?api-version=2019-11-01&`$top=5000"
                    $method = 'POST'
                    $subConsumptionData = AzAPICall -AzAPICallConfiguration $Configuration -uri $uri -method $method -body $body -currentTask $currentTask -listenOn 'ContentProperties'
                    if ($subConsumptionData -eq 'Unauthorized' -or $subConsumptionData -eq 'OfferNotSupported' -or $subConsumptionData -eq 'InvalidQueryDefinition' -or $subConsumptionData -eq 'NonValidWebDirectAIRSOfferType' -or $subConsumptionData -eq 'NotFoundNotSupported' -or $subConsumptionData -eq 'IndirectCostDisabled') {
                        Write-Host "   Failed ($subConsumptionData) - Getting Consumption data (scope Sub $($subNameToProcess) '$($subIdToProcess)' ($($subscriptionQuotaIdToProcess)))"
                        $hlper = $htAllSubscriptionsFromAPI.($subIdToProcess).subDetails
                        $hlper2 = $htSubscriptionsMgPath.($subIdToProcess)
                        $script:htConsumptionExceptionLog.Sub.($subIdToProcess) = @{}
                        $script:htConsumptionExceptionLog.Sub.($subIdToProcess).Exception = $subConsumptionData
                        $script:htConsumptionExceptionLog.Sub.($subIdToProcess).SubscriptionId = $subIdToProcess
                        $script:htConsumptionExceptionLog.Sub.($subIdToProcess).SubscriptionName = $hlper.displayName
                        $script:htConsumptionExceptionLog.Sub.($subIdToProcess).QuotaId = $hlper.subscriptionPolicies.quotaId
                        $script:htConsumptionExceptionLog.Sub.($subIdToProcess).mgPath = $hlper2.ParentNameChainDelimited
                        $script:htConsumptionExceptionLog.Sub.($subIdToProcess).mgParent = $hlper2.Parent
                        Continue
                    }
                    else {
                        Write-Host "   $($subConsumptionData.Count) Consumption data entries (scope Sub $($subNameToProcess) '$($subIdToProcess)' ($($subscriptionQuotaIdToProcess)))"
                        if ($subConsumptionData.Count -gt 0) {
                            foreach ($consumptionEntry in $subConsumptionData) {
                                if ($consumptionEntry.PreTaxCost -ne 0) {
                                    $null = $script:allConsumptionData.Add($consumptionEntry)
                                }
                            }
                        }
                    }
                } -ThrottleLimit $ThrottleLimit
                #endregion subScope
            }
            else {
                Write-Host " $($allConsumptionData.Count) Consumption data entries"
            }
        }
        else {
            $script:allConsumptionData = 'NoSubscriptionsPresent'
            Write-Host ' No Subscriptions present, skipping Consumption data processing'
        }
    }

    if ($allConsumptionData -eq 'AccountCostDisabled' -or $allConsumptionData -eq 'NoValidSubscriptions' -or $allConsumptionData -eq 'NoWhitelistSubscriptionsPresent' -or $allConsumptionData -eq 'NoSubscriptionsPresent') {
        if ($allConsumptionData -eq 'AccountCostDisabled') {
            Write-Host ' Seems Access to cost data has been disabled for this Account - skipping CostManagement'
        }
        if ($allConsumptionData -eq 'NoValidSubscriptions') {
            Write-Host ' Seems there are no valid Subscriptions present - skipping CostManagement'
        }
        if ($allConsumptionData -eq 'NoWhitelistSubscriptionsPresent') {
            Write-Host " Seems there are no Subscriptions present that match the whitelist ($($SubscriptionQuotaIdWhitelist -join ', ')) - skipping CostManagement"
        }
        if ($allConsumptionData -eq 'NoSubscriptionsPresent') {
            Write-Host ' Seems there are no Subscriptions present - skipping CostManagement'
        }
        Write-Host " Action: Setting switch parameter 'DoAzureConsumption' to false"
        $Configuration['htParameters'].DoAzureConsumption = $false
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
                $script:consumptionDataGroupedByCurrency = $consumptionData | Group-Object -property Currency

                foreach ($currency in $consumptionDataGroupedByCurrency) {

                    #subscriptions
                    $groupAllConsumptionDataPerCurrencyBySubscriptionId = $currency.group | Group-Object -Property SubscriptionId
                    foreach ($subscriptionId in $groupAllConsumptionDataPerCurrencyBySubscriptionId) {

                        $subTotalCost = ($subscriptionId.Group.PreTaxCost | Measure-Object -Sum).Sum
                        $script:htAzureConsumptionSubscriptions.($subscriptionId.Name) = @{}
                        $script:htAzureConsumptionSubscriptions.($subscriptionId.Name).ConsumptionData = $subscriptionId.group
                        $script:htAzureConsumptionSubscriptions.($subscriptionId.Name).TotalCost = $subTotalCost
                        $script:htAzureConsumptionSubscriptions.($subscriptionId.Name).Currency = $currency.Name
                        $resourceTypes = $subscriptionId.Group.ConsumedService | Sort-Object -Unique

                        foreach ($parentMg in $htSubscriptionsMgPath.($subscriptionId.Name).ParentNameChain) {

                            if (-not $htManagementGroupsCost.($parentMg)) {
                                $script:htManagementGroupsCost.($parentMg) = @{}
                                $script:htManagementGroupsCost.($parentMg).currencies = $currency.Name
                                $script:htManagementGroupsCost.($parentMg)."mgTotalCost_$($currency.Name)" = $subTotalCost #[decimal]$subTotalCost
                                $script:htManagementGroupsCost.($parentMg)."resourcesThatGeneratedCost_$($currency.Name)" = ($subscriptionId.Group.ResourceId | Sort-Object -Unique | Measure-Object).Count
                                $script:htManagementGroupsCost.($parentMg).resourcesThatGeneratedCostCurrencyIndependent = ($subscriptionId.Group.ResourceId | Sort-Object -Unique | Measure-Object).Count
                                $script:htManagementGroupsCost.($parentMg)."subscriptionsThatGeneratedCost_$($currency.Name)" = 1
                                $script:htManagementGroupsCost.($parentMg).subscriptionsThatGeneratedCostCurrencyIndependent = 1
                                $script:htManagementGroupsCost.($parentMg)."resourceTypesThatGeneratedCost_$($currency.Name)" = $resourceTypes
                                $script:htManagementGroupsCost.($parentMg).resourceTypesThatGeneratedCostCurrencyIndependent = $resourceTypes
                                $script:htManagementGroupsCost.($parentMg)."consumptionDataSubscriptions_$($currency.Name)" = $subscriptionId.group
                                $script:htManagementGroupsCost.($parentMg).consumptionDataSubscriptions = $subscriptionId.group
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
                    $script:tenantSummaryConsumptionDataGrouped = $currency.group | Group-Object -property ConsumedService, ChargeType, MeterCategory
                    $subsCount = ($tenantSummaryConsumptionDataGrouped.group.subscriptionId | Sort-Object -Unique | Measure-Object).Count
                    $consumedServiceCount = ($tenantSummaryConsumptionDataGrouped.group.consumedService | Sort-Object -Unique | Measure-Object).Count
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
                                ConsumedService              = ($consumptionline.name).split(', ')[0]
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
        if (-not $NoAzureConsumptionReportExportToCSV) {
            Write-Host " Exporting Consumption CSV $($outputPath)$($DirectorySeparatorChar)$($fileName)_Consumption.csv"
            $startBuildConsumptionCSV = Get-Date
            if ($CsvExportUseQuotesAsNeeded) {
                $allConsumptionData | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_Consumption.csv" -Delimiter "$csvDelimiter" -NoTypeInformation -UseQuotes AsNeeded
            }
            else {
                $allConsumptionData | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_Consumption.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
            }
            $endBuildConsumptionCSV = Get-Date
            Write-Host " Exporting Consumption CSV total duration: $((NEW-TIMESPAN -Start $startBuildConsumptionCSV -End $endBuildConsumptionCSV).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startBuildCSV -End $endBuildCSV).TotalSeconds) seconds)"
        }
        #endregion BuildConsumptionCSV
    }
    $endConsumptionData = Get-Date
    Write-Host "Getting Consumption data duration: $((NEW-TIMESPAN -Start $startConsumptionData -End $endConsumptionData).TotalSeconds) seconds"
    #endregion dataprocessingConsumption
}