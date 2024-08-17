function getPIMEligible {
    $start = Get-Date

    $currentTask = 'Get PIM onboarded Subscriptions and Management Groups'
    Write-Host $currentTask
    $uriExt = "&`$expand=parent&`$filter=(type eq 'subscription' or type eq 'managementgroup')"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/beta/privilegedAccess/azureResources/resources?`$select=id,displayName,type,externalId" + $uriExt
    $res = AzAPICall -AzAPICallConfiguration $azapicallConf -uri $uri -currentTask $currentTask
    if ($res.Count -gt 0) {

        $scopesToIterate = [System.Collections.ArrayList]@()
        if (-not $PIMEligibilityIgnoreScope) {
            if (($azAPICallConf['checkContext']).Tenant.Id -ne $ManagementGroupId) {
                foreach ($entry in $res) {
                    $entryIdGuid = $entry.externalId -replace '.*/'
                    if ($entry.type -eq 'managementGroup') {
                        if ($htManagementGroupsMgPath.($ManagementGroupId).ParentNameChain -contains ($entryIdGuid) -or $htManagementGroupsMgPath.($entryIdGuid).path -contains $ManagementGroupId) {
                            $null = $scopesToIterate.Add($entry)
                        }
                    }
                    if ($entry.type -eq 'subscription') {
                        if ($htSubscriptionsMgPath.($entryIdGuid).ParentNameChain -contains $ManagementGroupId) {
                            if ($htOutOfScopeSubscriptions.($entryIdGuid)) {
                                Write-Host "excluding subscription $($entryIdGuid) (outOfScopeSubscription -> $($htOutOfScopeSubscriptions.($entryIdGuid).outOfScopeReason)) (`$PIMEligibilityIgnoreScope=$PIMEligibilityIgnoreScope)"
                            }
                            else {
                                $null = $scopesToIterate.Add($entry)
                            }
                        }
                    }
                }
            }
            else {
                foreach ($entry in $res) {
                    $entryIdGuid = $entry.externalId -replace '.*/'
                    if ($htOutOfScopeSubscriptions.($entryIdGuid)) {
                        Write-Host "excluding subscription $($entryIdGuid) (outOfScopeSubscription -> $($htOutOfScopeSubscriptions.($entryIdGuid).outOfScopeReason)) (`$PIMEligibilityIgnoreScope=$PIMEligibilityIgnoreScope)"
                    }
                    else {
                        $null = $scopesToIterate.Add($entry)
                    }
                }
            }
        }
        else {
            foreach ($entry in $res) {
                $null = $scopesToIterate.Add($entry)
            }
        }

        $PIMOnboardedGrouped = $scopesToIterate | Group-Object -Property type
        foreach ($entry in $PIMOnboardedGrouped) {
            Write-Host " Found $($entry.Count) PIM onboarded $($entry.Name)s"
        }

        $htPIMEligibleDirect = [System.Collections.Hashtable]::Synchronized(@{})
        $relevantSubscriptionIds = $subsToProcessInCustomDataCollection.subscriptionId

        if ($scopesToIterate.Count -gt 0) {

            $batchSize = [math]::ceiling($scopesToIterate.Count / $ThrottleLimit)
            Write-Host "Optimal batch size: $($batchSize)"
            $counterBatch = [PSCustomObject] @{ Value = 0 }
            $scopesToIterateBatch = ($scopesToIterate) | Group-Object -Property { [math]::Floor($counterBatch.Value++ / $batchSize) }
            Write-Host "Processing data in $($scopesToIterateBatch.Count) batches"

            $scopesToIterateBatch | ForEach-Object -Parallel {
                $scope = $_
                $azAPICallConf = $using:azAPICallConf
                $arrayPIMEligible = $using:arrayPIMEligible
                $htPIMEligibleDirect = $using:htPIMEligibleDirect
                $htPrincipals = $using:htPrincipals
                $htUserTypesGuest = $using:htUserTypesGuest
                $htServicePrincipals = $using:htServicePrincipals
                $relevantSubscriptionIds = $using:relevantSubscriptionIds
                $function:resolveObjectIds = $using:funcResolveObjectIds
                $function:testGuid = $using:funcTestGuid

                foreach ($scope in $_.Group) {
                    if ($scope.type -eq 'managementgroup') { $htManagementGroupsMgPath = $using:htManagementGroupsMgPath }
                    if ($scope.type -eq 'subscription') { $htSubscriptionsMgPath = $using:htSubscriptionsMgPath }

                    $processThisScope = $true
                    if ($scope.type -eq 'subscription') {
                        if (($scope.externalId -replace '.*/') -notin $relevantSubscriptionIds) {
                            Write-Host "  Non relevant subscriptionId '$(($scope.externalId -replace '.*/'))' /skipping this subscription as it is not contained in the 'Relevant Subscriptions' collection (needs investigation)" -ForegroundColor DarkRed
                            $processThisScope = $false
                        }
                    }

                    if ($processThisScope -eq $true) {
                        $currentTask = "Get Eligible assignments for Scope $($scope.type): $($scope.externalId -replace '.*/')"
                        $extUri = "?`$expand=linkedEligibleRoleAssignment,subject,roleDefinition(`$expand=resource)&`$count=true&`$filter=(roleDefinition/resource/id eq '$($scope.id)')+and+(assignmentState eq 'Eligible')&`$top=100"
                        $uri = "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/beta/privilegedAccess/azureResources/roleAssignments" + $extUri
                        $resx = AzAPICall -AzAPICallConfiguration $azapicallConf -currentTask $currentTask -uri $uri

                        if ($resx.Count -gt 0) {

                            $users = $resx.where({ $_.subject.type -eq 'user' })
                            if ($users.Count -gt 0) {
                                ResolveObjectIds -objectIds $users.subject.id -showActivity
                            }

                            foreach ($entry in $resx) {
                                $scopeId = $scope.externalId -replace '.*/'
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

                                    if ($entry.memberType -eq 'direct') {
                                        $script:htPIMEligibleDirect.($entry.id) = @{}
                                        $script:htPIMEligibleDirect.($entry.id).clear = $scopeId
                                        if ($scopeId -eq $ManagementGroupDisplayName) {
                                            $script:htPIMEligibleDirect.($entry.id).enriched = "$($scopeId) [Level $($MgLevel)]"
                                        }
                                        else {
                                            $script:htPIMEligibleDirect.($entry.id).enriched = "$($ManagementGroupDisplayName) ($($scopeId)) [Level $($MgLevel)]"
                                        }
                                    }
                                }
                                if ($scope.type -eq 'subscription') {
                                    $ScopeType = 'Sub'
                                    #$ManagementGroupId = ''
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
                                    #$ManagementGroupDisplayName = ''

                                }

                                if ($entry.subject.type -eq 'user') {
                                    if ($htPrincipals.($entry.subject.id)) {
                                        $userDetail = $htPrincipals.($entry.subject.id)
                                        $principalType = "$($userDetail.type) $($userDetail.userType)"
                                    }
                                    else {
                                        $principalType = $entry.subject.type
                                    }
                                }
                                else {
                                    $principalType = $entry.subject.type
                                }

                                $roleType = 'undefined'
                                if ($entry.roleDefinition.type -eq 'BuiltInRole') { $roleType = 'Builtin' }
                                if ($entry.roleDefinition.type -eq 'CustomRole') { $roleType = 'Custom' }

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
                                        RoleId                     = $entry.roleDefinition.externalId
                                        RoleIdGuid                 = $entry.roleDefinition.externalId -replace '.*/'
                                        RoleType                   = $roleType
                                        RoleName                   = $entry.roleDefinition.displayName
                                        IdentityObjectId           = $entry.subject.id
                                        IdentityType               = $principalType
                                        IdentityDisplayName        = $entry.subject.displayName
                                        IdentityPrincipalName      = $entry.subject.principalName
                                        PIMId                      = $entry.id
                                        PIMInheritance             = $entry.memberType
                                        PIMInheritedFromClear      = ''
                                        PIMInheritedFrom           = ''
                                        PIMStartDateTime           = $entry.startDateTime
                                        PIMEndDateTime             = $entry.endDateTime
                                    })
                            }
                        }
                    }
                }

            } -ThrottleLimit $ThrottleLimit
        }

        foreach ($entry in $arrayPIMEligible) {
            if ($entry.PIMInheritance -eq 'inherited') {
                $entry.PIMInheritedFromClear = $htPIMEligibleDirect.($entry.PIMId).clear
                $entry.PIMInheritedFrom = $htPIMEligibleDirect.($entry.PIMId).enriched
            }
        }

        $script:arrayPIMEligibleGrouped = $arrayPIMEligible | Group-Object -Property ScopeType
        foreach ($entry in $arrayPIMEligibleGrouped) {
            Write-Host " Found $($entry.Count) PIM Eligible assignments for $($entry.Name)s"
        }
    }

    $end = Get-Date
    Write-Host "Getting PIM Eligible assignments processing duration: $((New-TimeSpan -Start $start -End $end).TotalMinutes) minutes ($((New-TimeSpan -Start $start -End $end).TotalSeconds) seconds)"
}