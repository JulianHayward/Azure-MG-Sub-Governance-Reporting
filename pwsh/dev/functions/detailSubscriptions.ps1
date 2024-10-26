function detailSubscriptions {
    $start = Get-Date
    Write-Host 'Subscription picking'
    #API in rare cases returns duplicates, therefor sorting unique (id)
    $childrenSubscriptions = $arrayEntitiesFromAPI.where( { $_.properties.parentNameChain -contains $ManagementGroupID -and $_.type -eq '/subscriptions' } ) | Sort-Object -Property id -Unique
    $script:childrenSubscriptionsCount = ($childrenSubscriptions).Count
    $script:subsToProcessInCustomDataCollection = [System.Collections.ArrayList]@()

    if ($htSubscriptionsFromOtherTenants.keys.count -gt 0) {
        foreach ($subscriptionExludedOtherTenant in $htSubscriptionsFromOtherTenants.keys) {
            $subscriptionExludedOtherTenantDetail = $htSubscriptionsFromOtherTenants.($subscriptionExludedOtherTenant).subDetails
            $null = $script:outOfScopeSubscriptions.Add([PSCustomObject]@{
                    subscriptionId      = $subscriptionExludedOtherTenantDetail.subscriptionId
                    subscriptionName    = $subscriptionExludedOtherTenantDetail.displayName
                    outOfScopeReason    = "Foreign tenant: Id: $($subscriptionExludedOtherTenantDetail.tenantId)"
                    ManagementGroupId   = ''
                    ManagementGroupName = ''
                    Level               = ''
                })
        }
    }

    if ($htsubscriptionsFromEntitiesThatAreNotInGetSubscriptions.keys.count -gt 0) {
        foreach ($subscriptionExludedInEntitiesNotInSubscriptions in $htsubscriptionsFromEntitiesThatAreNotInGetSubscriptions.keys) {
            $subscriptionExludedInEntitiesNotInSubscriptionsDetail = $htsubscriptionsFromEntitiesThatAreNotInGetSubscriptions.($subscriptionExludedInEntitiesNotInSubscriptions)
            $null = $script:outOfScopeSubscriptions.Add([PSCustomObject]@{
                    subscriptionId      = $subscriptionExludedInEntitiesNotInSubscriptions
                    subscriptionName    = $subscriptionExludedInEntitiesNotInSubscriptionsDetail.properties.displayName
                    outOfScopeReason    = 'Sub in GetEntities, not in GetSubscriptions'
                    ManagementGroupId   = ''
                    ManagementGroupName = ''
                    Level               = ''
                })
        }
    }

    foreach ($childrenSubscription in $childrenSubscriptions) {
        if ($SubscriptionIdWhitelist[0] -ne 'undefined' -and $SubscriptionIdWhitelist -notcontains $childrenSubscription.name) {
            $null = $script:outOfScopeSubscriptions.Add([PSCustomObject]@{
                    subscriptionId      = $childrenSubscription.name
                    subscriptionName    = $childrenSubscription.properties.displayName
                    outOfScopeReason    = "SubscriptionId: '$($childrenSubscription.name)' not in Whitelist"
                    ManagementGroupId   = $htSubscriptionsMgPath.($childrenSubscription.name).Parent
                    ManagementGroupName = $htSubscriptionsMgPath.($childrenSubscription.name).ParentName
                    Level               = $htSubscriptionsMgPath.($childrenSubscription.name).level
                })
            continue
        }
        $sub = $htAllSubscriptionsFromAPI.($childrenSubscription.name)
        if ($null -eq $sub.subDetails.subscriptionPolicies.quotaId) {
            $null = $script:outOfScopeSubscriptions.Add([PSCustomObject]@{
                    subscriptionId      = $childrenSubscription.name
                    subscriptionName    = $childrenSubscription.properties.displayName
                    outOfScopeReason    = 'QuotaId: null'
                    ManagementGroupId   = $htSubscriptionsMgPath.($childrenSubscription.name).Parent
                    ManagementGroupName = $htSubscriptionsMgPath.($childrenSubscription.name).ParentName
                    Level               = $htSubscriptionsMgPath.($childrenSubscription.name).level
                })
        }
        else {
            if ($sub.subDetails.subscriptionPolicies.quotaId.startswith('AAD_', 'CurrentCultureIgnoreCase') -or $sub.subDetails.state -ne 'Enabled') {
                if (($sub.subDetails.subscriptionPolicies.quotaId).startswith('AAD_', 'CurrentCultureIgnoreCase')) {
                    $null = $script:outOfScopeSubscriptions.Add([PSCustomObject]@{
                            subscriptionId      = $childrenSubscription.name
                            subscriptionName    = $childrenSubscription.properties.displayName
                            outOfScopeReason    = "QuotaId: AAD_ (State: $($sub.subDetails.state))"
                            ManagementGroupId   = $htSubscriptionsMgPath.($childrenSubscription.name).Parent
                            ManagementGroupName = $htSubscriptionsMgPath.($childrenSubscription.name).ParentName
                            Level               = $htSubscriptionsMgPath.($childrenSubscription.name).level
                        })
                }
                if ($sub.subDetails.state -ne 'Enabled') {
                    $null = $script:outOfScopeSubscriptions.Add([PSCustomObject]@{
                            subscriptionId      = $childrenSubscription.name
                            subscriptionName    = $childrenSubscription.properties.displayName
                            outOfScopeReason    = "State: $($sub.subDetails.state)"
                            ManagementGroupId   = $htSubscriptionsMgPath.($childrenSubscription.name).Parent
                            ManagementGroupName = $htSubscriptionsMgPath.($childrenSubscription.name).ParentName
                            Level               = $htSubscriptionsMgPath.($childrenSubscription.name).level
                        })
                }
            }
            else {
                if ($SubscriptionQuotaIdWhitelist[0] -ne 'undefined') {
                    $whitelistMatched = 'unknown'
                    foreach ($subscriptionQuotaIdWhitelistQuotaId in $SubscriptionQuotaIdWhitelist) {
                        if (($sub.subDetails.subscriptionPolicies.quotaId).startswith($subscriptionQuotaIdWhitelistQuotaId, 'CurrentCultureIgnoreCase')) {
                            $whitelistMatched = 'inWhitelist'
                        }
                    }

                    if ($whitelistMatched -eq 'inWhitelist') {
                        #write-host "$($childrenSubscription.properties.displayName) in whitelist"
                        $null = $script:subsToProcessInCustomDataCollection.Add([PSCustomObject]@{
                                subscriptionId      = $childrenSubscription.name
                                subscriptionName    = $childrenSubscription.properties.displayName
                                subscriptionQuotaId = $sub.subDetails.subscriptionPolicies.quotaId
                            })
                    }
                    else {
                        #Write-Host " preCustomDataCollection: $($childrenSubscription.properties.displayName) ($($childrenSubscription.name)) Subscription Quota Id: $($sub.subDetails.subscriptionPolicies.quotaId) is out of scope for Azure Governance Visualizer (not in Whitelist)"
                        $null = $script:outOfScopeSubscriptions.Add([PSCustomObject]@{
                                subscriptionId      = $childrenSubscription.name
                                subscriptionName    = $childrenSubscription.properties.displayName
                                outOfScopeReason    = "QuotaId: '$($sub.subDetails.subscriptionPolicies.quotaId)' not in Whitelist"
                                ManagementGroupId   = $htSubscriptionsMgPath.($childrenSubscription.name).Parent
                                ManagementGroupName = $htSubscriptionsMgPath.($childrenSubscription.name).ParentName
                                Level               = $htSubscriptionsMgPath.($childrenSubscription.name).level
                            })
                    }
                }
                else {
                    $null = $script:subsToProcessInCustomDataCollection.Add([PSCustomObject]@{
                            subscriptionId      = $childrenSubscription.name
                            subscriptionName    = $childrenSubscription.properties.displayName
                            subscriptionQuotaId = $sub.subDetails.subscriptionPolicies.quotaId
                        })
                }
            }
        }
    }

    if ($subsToProcessInCustomDataCollection.Count -lt $childrenSubscriptionsCount) {
        Write-Host " $($subsToProcessInCustomDataCollection.Count) of $($childrenSubscriptionsCount) Subscriptions picked for processing" -ForegroundColor yellow
    }
    else {
        Write-Host " $($subsToProcessInCustomDataCollection.Count) of $($childrenSubscriptionsCount) Subscriptions picked for processing"
    }


    if ($outOfScopeSubscriptions.Count -gt 0) {
        Write-Host " $($outOfScopeSubscriptions.Count) Subscriptions excluded" -ForegroundColor yellow
        $outOfScopeSubscriptionsGroupedByOutOfScopeReason = $outOfScopeSubscriptions | Group-Object -Property outOfScopeReason
        foreach ($exclusionreason in $outOfScopeSubscriptionsGroupedByOutOfScopeReason) {
            Write-Host "   $($exclusionreason.Count): $($exclusionreason.Name) ($($exclusionreason.Group.subscriptionId -join ', '))"
        }

        foreach ($outOfScopeSubscription in $outOfScopeSubscriptions) {
            $script:htOutOfScopeSubscriptions.($outOfScopeSubscription.subscriptionId) = @{
                subscriptionId      = $outOfScopeSubscription.subscriptionId
                subscriptionName    = $outOfScopeSubscription.subscriptionName
                outOfScopeReason    = $outOfScopeSubscription.outOfScopeReason
                ManagementGroupId   = $outOfScopeSubscription.ManagementGroupId
                ManagementGroupName = $outOfScopeSubscription.ManagementGroupName
                Level               = $outOfScopeSubscription.Level
            }
        }
    }
    else {
        Write-Host " $($outOfScopeSubscriptions.Count) Subscriptions excluded"
    }
    $script:subsToProcessInCustomDataCollectionCount = ($subsToProcessInCustomDataCollection).Count

    $end = Get-Date
    Write-Host "Subscription picking duration: $((New-TimeSpan -Start $start -End $end).TotalSeconds) seconds"
}