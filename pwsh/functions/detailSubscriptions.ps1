function detailSubscriptions {
    #API in rare cases returns duplicates, therefor sorting unique (id)
    $childrenSubscriptions = $arrayEntitiesFromAPI.where( { $_.properties.parentNameChain -contains $ManagementGroupID -and $_.type -eq '/subscriptions' } ) | Sort-Object -Property id -Unique
    $script:childrenSubscriptionsCount = ($childrenSubscriptions).Count
    $script:subsToProcessInCustomDataCollection = [System.Collections.ArrayList]@()
    foreach ($childrenSubscription in $childrenSubscriptions) {

        $sub = $htAllSubscriptionsFromAPI.($childrenSubscription.name)
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
                    #Write-Host " preCustomDataCollection: $($childrenSubscription.properties.displayName) ($($childrenSubscription.name)) Subscription Quota Id: $($sub.subDetails.subscriptionPolicies.quotaId) is out of scope for AzGovViz (not in Whitelist)"
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
    $script:subsToProcessInCustomDataCollectionCount = ($subsToProcessInCustomDataCollection).Count
}