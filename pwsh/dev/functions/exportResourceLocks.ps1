function exportResourceLocks {
    $arrayResourceLocks4CSV = [System.Collections.ArrayList]@()
    foreach ($sub in $htResourceLocks.Keys) {
        $hlper = $htSubscriptionsMgPath.($sub)
        $subscriptionDisplayName = $hlper.DisplayName
        $mgPath = $hlper.ParentNameChainDelimited
        #sub
        if ($htResourceLocks.($sub).SubscriptionLocksCannotDeleteCount -eq 1) {
            $null = $arrayResourceLocks4CSV.Add([PSCustomObject]@{
                    SubscriptionId   = $sub
                    SubscriptionName = $subscriptionDisplayName
                    MGPath           = $mgPath
                    ScopeType        = 'Subscription'
                    Lock             = 'CannotDelete'
                    Id               = "/subscriptions/$sub"
                    ResourceType     = 'Microsoft.Resources/subscriptions'
                })
        }
        if ($htResourceLocks.($sub).SubscriptionLocksReadOnlyCount -eq 1) {
            $null = $arrayResourceLocks4CSV.Add([PSCustomObject]@{
                    SubscriptionId   = $sub
                    SubscriptionName = $subscriptionDisplayName
                    MGPath           = $mgPath
                    ScopeType        = 'Subscription'
                    Lock             = 'ReadOnly'
                    Id               = "/subscriptions/$sub"
                    ResourceType     = 'Microsoft.Resources/subscriptions'
                })
        }
        #rg
        if ($htResourceLocks.($sub).ResourceGroupsLocksCannotDeleteCount -gt 0) {
            foreach ($res in $htResourceLocks.($sub).ResourceGroupsLocksCannotDelete) {
                $null = $arrayResourceLocks4CSV.Add([PSCustomObject]@{
                        SubscriptionId   = $sub
                        SubscriptionName = $subscriptionDisplayName
                        MGPath           = $mgPath
                        ScopeType        = 'ResourceGroup'
                        Lock             = 'CannotDelete'
                        Id               = $res.rg
                        ResourceType     = 'Microsoft.Resources/subscriptions/resourceGroups'
                    })
            }
        }
        if ($htResourceLocks.($sub).ResourceGroupsLocksReadOnlyCount -gt 0) {
            foreach ($res in $htResourceLocks.($sub).ResourceGroupsLocksReadOnly) {
                $null = $arrayResourceLocks4CSV.Add([PSCustomObject]@{
                        SubscriptionId   = $sub
                        SubscriptionName = $subscriptionDisplayName
                        MGPath           = $mgPath
                        ScopeType        = 'ResourceGroup'
                        Lock             = 'ReadOnly'
                        Id               = $res.rg
                        ResourceType     = 'Microsoft.Resources/subscriptions/resourceGroups'
                    })
            }
        }
        #res
        if ($htResourceLocks.($sub).ResourcesLocksCannotDeleteCount -gt 0) {
            foreach ($res in $htResourceLocks.($sub).ResourcesLocksCannotDelete) {
                $resSplit = ($res.res -split '/')
                $null = $arrayResourceLocks4CSV.Add([PSCustomObject]@{
                        SubscriptionId   = $sub
                        SubscriptionName = $subscriptionDisplayName
                        MGPath           = $mgPath
                        ScopeType        = 'Resource'
                        Lock             = 'CannotDelete'
                        Id               = $res.res
                        ResourceType     = "$($resSplit[6])/$($resSplit[7])"
                    })
            }
        }
        if ($htResourceLocks.($sub).ResourcesLocksReadOnlyCount -gt 0) {
            foreach ($res in $htResourceLocks.($sub).ResourcesLocksReadOnly) {
                $resSplit = ($res.res -split '/')
                $null = $arrayResourceLocks4CSV.Add([PSCustomObject]@{
                        SubscriptionId   = $sub
                        SubscriptionName = $subscriptionDisplayName
                        MGPath           = $mgPath
                        ScopeType        = 'Resource'
                        Lock             = 'ReadOnly'
                        Id               = $res.res
                        ResourceType     = "$($resSplit[6])/$($resSplit[7])"
                    })
            }
        }
    }
    if ($arrayResourceLocks4CSV.count -gt 0) {
        if (-not $NoCsvExport) {
            Write-Host "Exporting ResourceLocks CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_ResourceLocks.csv'"
            $arrayResourceLocks4CSV | Sort-Object -Property ScopeType, Lock, SubscriptionId, Id | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_ResourceLocks.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
        }
    }
}