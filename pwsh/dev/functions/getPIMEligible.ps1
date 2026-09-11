function getPIMEligible {
    $start = Get-Date

    Write-Host 'Get PIM Eligible assignments'

    #the ARM API has no equivalent for the retired Graph 'PIM onboarded resources' list, therefore every in scope Management Group and Subscription is queried
    $scopesToIterate = [System.Collections.ArrayList]@()
    $scopeLimited = (-not $PIMEligibilityIgnoreScope -and ($azAPICallConf['checkContext']).Tenant.Id -ne $ManagementGroupId)

    foreach ($mgId in $htManagementGroupsMgPath.Keys) {
        if ($scopeLimited) {
            #ancestors are included so that 'inherited from' can be reported
            if ($htManagementGroupsMgPath.($ManagementGroupId).ParentNameChain -notcontains $mgId -and $htManagementGroupsMgPath.($mgId).path -notcontains $ManagementGroupId) {
                continue
            }
        }
        $null = $scopesToIterate.Add([PSCustomObject]@{
                type     = 'managementgroup'
                scopeId  = $mgId
                armScope = "/providers/Microsoft.Management/managementGroups/$($mgId)"
            })
    }

    $relevantSubscriptionIds = $subsToProcessInCustomDataCollection.subscriptionId

    foreach ($subscriptionId in $htSubscriptionsMgPath.Keys) {
        if ($scopeLimited) {
            if ($htSubscriptionsMgPath.($subscriptionId).ParentNameChain -notcontains $ManagementGroupId) {
                continue
            }
        }
        if (-not $PIMEligibilityIgnoreScope) {
            if ($htOutOfScopeSubscriptions.($subscriptionId)) {
                Write-Host "excluding subscription $($subscriptionId) (outOfScopeSubscription -> $($htOutOfScopeSubscriptions.($subscriptionId).outOfScopeReason)) (`$PIMEligibilityIgnoreScope=$PIMEligibilityIgnoreScope)"
                continue
            }
        }
        if ($subscriptionId -notin $relevantSubscriptionIds) {
            continue
        }
        $null = $scopesToIterate.Add([PSCustomObject]@{
                type     = 'subscription'
                scopeId  = $subscriptionId
                armScope = "/subscriptions/$($subscriptionId)"
            })
    }

    $scopesToIterateGrouped = $scopesToIterate | Group-Object -Property type
    foreach ($entry in $scopesToIterateGrouped) {
        Write-Host " Processing $($entry.Count) $($entry.Name)s"
    }

    if ($scopesToIterate.Count -gt 0) {

        $batchSize = [math]::ceiling($scopesToIterate.Count / $ThrottleLimit)
        Write-Host "Optimal batch size: $($batchSize)"
        $counterBatch = [PSCustomObject] @{ Value = 0 }
        $scopesToIterateBatch = ($scopesToIterate) | Group-Object -Property { [math]::Floor($counterBatch.Value++ / $batchSize) }
        Write-Host "Processing data in $($scopesToIterateBatch.Count) batches"

        $scopesToIterateBatch | ForEach-Object -Parallel {
            $azAPICallConf = $using:azAPICallConf
            $arrayPIMEligible = $using:arrayPIMEligible
            $htPrincipals = $using:htPrincipals
            $htUserTypesGuest = $using:htUserTypesGuest
            $htServicePrincipals = $using:htServicePrincipals
            $htManagementGroupsMgPath = $using:htManagementGroupsMgPath
            $htSubscriptionsMgPath = $using:htSubscriptionsMgPath
            $function:resolveObjectIds = $using:funcResolveObjectIds
            $function:testGuid = $using:funcTestGuid

            foreach ($scope in $_.Group) {

                $currentTask = "Get Eligible assignments for Scope $($scope.type): $($scope.scopeId)"
                #atScope() returns the eligibilities effective at this scope (direct plus inherited from ancestors) and excludes those of child scopes
                $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)$($scope.armScope)/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&`$filter=atScope()"
                $resx = AzAPICall -AzAPICallConfiguration $azapicallConf -currentTask $currentTask -uri $uri

                if ($resx.Count -gt 0) {

                    $users = $resx.where({ $_.properties.principalType -eq 'User' })
                    if ($users.Count -gt 0) {
                        ResolveObjectIds -objectIds $users.properties.principalId -showActivity
                    }

                    foreach ($entry in $resx) {
                        $entryProperties = $entry.properties
                        $scopeId = $scope.scopeId
                        if ($scope.type -eq 'managementgroup') {
                            $ScopeType = 'MG'
                            $ManagementGroupId = $scopeId
                            $SubscriptionId = ''
                            $SubscriptionDisplayName = ''
                            if ($htManagementGroupsMgPath.($scopeId)) {
                                $MgDetails = $htManagementGroupsMgPath.($scopeId)
                                $ManagementGroupDisplayName = $MgDetails.DisplayName
                                $ScopeDisplayName = $MgDetails.DisplayName
                                $MgPath = $MgDetails.path
                                $MgLevel = $MgDetails.level
                            }
                            else {
                                $ManagementGroupDisplayName = 'notAccessible'
                                $ScopeDisplayName = 'notAccessible'
                                $MgPath = 'notAccessible'
                                $MgLevel = 'notAccessible'
                            }
                        }
                        if ($scope.type -eq 'subscription') {
                            $ScopeType = 'Sub'
                            $SubscriptionId = $scopeId
                            if ($htSubscriptionsMgPath.($scopeId)) {
                                $MgDetails = $htSubscriptionsMgPath.($scopeId)
                                $SubscriptionDisplayName = $MgDetails.DisplayName
                                $ScopeDisplayName = $MgDetails.DisplayName
                                $MgPath = $MgDetails.path
                                $MgLevel = $MgDetails.level
                                $ManagementGroupId = $MgDetails.Parent
                                $ManagementGroupDisplayName = $MgDetails.ParentName
                            }
                            else {
                                $SubscriptionDisplayName = 'notAccessible'
                                $ScopeDisplayName = 'notAccessible'
                                $MgPath = 'notAccessible'
                                $MgLevel = 'notAccessible'
                            }
                        }

                        $PIMInheritedFromClear = ''
                        $PIMInheritedFrom = ''
                        if ($entryProperties.memberType -eq 'Inherited') {
                            $inheritedFromScopeId = $entryProperties.expandedProperties.scope.id -replace '.*/'
                            $PIMInheritedFromClear = $inheritedFromScopeId
                            if ($htManagementGroupsMgPath.($inheritedFromScopeId)) {
                                $inheritedFromDetails = $htManagementGroupsMgPath.($inheritedFromScopeId)
                                $inheritedFromDisplayName = $inheritedFromDetails.DisplayName
                                $inheritedFromLevel = $inheritedFromDetails.level
                            }
                            else {
                                $inheritedFromDisplayName = 'notAccessible'
                                $inheritedFromLevel = 'notAccessible'
                            }
                            if ($inheritedFromScopeId -eq $inheritedFromDisplayName) {
                                $PIMInheritedFrom = "$($inheritedFromScopeId) [Level $($inheritedFromLevel)]"
                            }
                            else {
                                $PIMInheritedFrom = "$($inheritedFromDisplayName) ($($inheritedFromScopeId)) [Level $($inheritedFromLevel)]"
                            }
                        }

                        $identityDisplayName = $entryProperties.expandedProperties.principal.displayName
                        $identityPrincipalName = $entryProperties.expandedProperties.principal.email
                        if ($entryProperties.principalType -eq 'User') {
                            if ($htPrincipals.($entryProperties.principalId)) {
                                $userDetail = $htPrincipals.($entryProperties.principalId)
                                $principalType = "$($userDetail.type) $($userDetail.userType)"
                                #Microsoft Graph is authoritative for displayName and userPrincipalName
                                $identityDisplayName = $userDetail.displayName
                                $identityPrincipalName = $userDetail.signInName
                            }
                            else {
                                $principalType = $entryProperties.principalType
                            }
                        }
                        else {
                            $principalType = $entryProperties.principalType
                        }

                        $roleType = 'undefined'
                        if ($entryProperties.expandedProperties.roleDefinition.type -eq 'BuiltInRole') { $roleType = 'Builtin' }
                        if ($entryProperties.expandedProperties.roleDefinition.type -eq 'CustomRole') { $roleType = 'Custom' }

                        $null = $script:arrayPIMEligible.Add([PSCustomObject]@{
                                ScopeType                  = $ScopeType
                                ScopeId                    = $scopeId
                                ScopeDisplayName           = $ScopeDisplayName
                                ManagementGroupId          = $ManagementGroupId
                                ManagementGroupDisplayName = $ManagementGroupDisplayName
                                SubscriptionId             = $SubscriptionId
                                SubscriptionDisplayName    = $SubscriptionDisplayName
                                MgPath                     = $MgPath
                                MgLevel                    = $MgLevel
                                RoleId                     = $entryProperties.roleDefinitionId
                                RoleIdGuid                 = $entryProperties.roleDefinitionId -replace '.*/'
                                RoleType                   = $roleType
                                RoleName                   = $entryProperties.expandedProperties.roleDefinition.displayName
                                IdentityObjectId           = $entryProperties.principalId
                                IdentityType               = $principalType
                                IdentityDisplayName        = $identityDisplayName
                                IdentityPrincipalName      = $identityPrincipalName
                                PIMId                      = $entry.name
                                PIMInheritance             = $entryProperties.memberType
                                PIMInheritedFromClear      = $PIMInheritedFromClear
                                PIMInheritedFrom           = $PIMInheritedFrom
                                PIMStartDateTime           = $entryProperties.startDateTime
                                PIMEndDateTime             = $entryProperties.endDateTime
                            })
                    }
                }
            }

        } -ThrottleLimit $ThrottleLimit
    }

    $script:arrayPIMEligibleGrouped = $arrayPIMEligible | Group-Object -Property ScopeType
    foreach ($entry in $arrayPIMEligibleGrouped) {
        Write-Host " Found $($entry.Count) PIM Eligible assignments for $($entry.Name)s"
    }

    $end = Get-Date
    Write-Host "Getting PIM Eligible assignments processing duration: $((New-TimeSpan -Start $start -End $end).TotalMinutes) minutes ($((New-TimeSpan -Start $start -End $end).TotalSeconds) seconds)"
}
