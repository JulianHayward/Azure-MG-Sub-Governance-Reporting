function getPIMEligible {
    $start = Get-Date
        
    $currentTask = "Get PIM onboarded Subscriptions and Management Groups"
    Write-Host $currentTask
    $uriExt = "&`$expand=parent&`$filter=(type eq 'subscription' or type eq 'managementgroup')"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/beta/privilegedAccess/azureResources/resources?`$select=id,displayName,type,externalId" + $uriExt
    $res = AzAPICall -AzAPICallConfiguration $azapicallConf -uri $uri -currentTask $currentTask
    if ($res.Count -gt 0) {

        $scopesToIterate = [System.Collections.ArrayList]@()
        if (-not $PIMEligibilityIgnoreScope) {
            if (($azAPICallConf['checkContext']).Tenant.Id -ne $ManagementGroupId) {
                foreach ($entry in $res) {
                    if ($entry.type -eq 'managementGroup') {
                        if ($htManagementGroupsMgPath.($ManagementGroupId).ParentNameChain -contains ($entry.externalId -replace '.*/') -or $htManagementGroupsMgPath.($entry.externalId -replace '.*/').path -contains $ManagementGroupId) {
                            $null = $scopesToIterate.Add($entry)
                        }
                    }
                    if ($entry.type -eq 'subscription') {
                        if ($htSubscriptionsMgPath.($entry.externalId -replace '.*/').ParentNameChain -contains $ManagementGroupId) {
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
        }
        else {
            foreach ($entry in $res) {
                $null = $scopesToIterate.Add($entry)
            }
        }


        $htPIMEligibleDirect = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
        $scopesToIterate | ForEach-Object -parallel {
            $scope = $_
            $azAPICallConf = $using:azAPICallConf
            $arrayPIMEligible = $using:arrayPIMEligible
            $htPIMEligibleDirect = $using:htPIMEligibleDirect
            if ($scope.type -eq 'managementgroup') { $htManagementGroupsMgPath = $using:htManagementGroupsMgPath }
            if ($scope.type -eq 'subscription') { $htSubscriptionsMgPath = $using:htSubscriptionsMgPath }
            $htPrincipals = $using:htPrincipals
            $function:resolveObjectIds = $using:funcResolveObjectIds
            $function:testGuid = $using:funcTestGuid
            #Write-Host "$($scope.type) $($scope.externalId -replace '.*/') - $($scope.id)"
    
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
                        $SubscriptionDisplayName = ''


                        if ($entry.memberType -eq 'direct') {
                            if ($scopeId -eq $ManagementGroupDisplayName) {
                                $script:htPIMEligibleDirect.($entry.id) = "$($scopeId) [Level $($MgLevel)]"
                            }
                            else {
                                $script:htPIMEligibleDirect.($entry.id) = "$($ManagementGroupDisplayName) ($($scopeId)) [Level $($MgLevel)]"
                            }
                        }
                    }
                    if ($scope.type -eq 'subscription') {
                        $ScopeType = 'Sub'
                        $ManagementGroupId = ''
                        $SubscriptionId = $scopeId
                        if ($htSubscriptionsMgPath.($scopeId)) {
                            $MgDetails = $htSubscriptionsMgPath.($scopeId)
                            $SubscriptionDisplayName = $MgDetails.DisplayName
                            $ScopeDisplayName = $MgDetails.DisplayName
                            $MgPath = $MgDetails.path
                            $MgLevel = $MgDetails.level 
                        }
                        else {
                            $SubscriptionDisplayName = 'notAccessible'
                            $ScopeDisplayName = 'notAccessible'
                            $MgPath = 'notAccessible'
                            $MgLevel = 'notAccessible'
                        }
                        $ManagementGroupDisplayName = ''

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
                            RoleType                   = $entry.roleDefinition.type
                            RoleName                   = $entry.roleDefinition.displayName
                            IdentityObjectId           = $entry.subject.id
                            IdentityType               = $principalType
                            IdentityDisplayName        = $entry.subject.displayName
                            IdentityPrincipalName      = $entry.subject.principalName
                            PIMId                      = $entry.id
                            PIMInheritance             = $entry.memberType
                            PIMInheritedFrom           = ''
                        })
                }
            }
        } -ThrottleLimit $ThrottleLimit

        foreach ($entry in $arrayPIMEligible) {
            if ($entry.PIMInheritance -eq 'inherited') {
                $entry.PIMInheritedFrom = $htPIMEligibleDirect.($entry.PIMId)
            }
        }

        $script:arrayPIMEligibleGrouped = $arrayPIMEligible | Group-Object -Property ScopeType
        foreach ($entry in $arrayPIMEligibleGrouped) {
            Write-Host " Found $($entry.Count) PIM onboarded $($entry.Name)s"
        }
    }

    $end = Get-Date
    Write-Host "Getting PIM Eligible assignments processing duration: $((NEW-TIMESPAN -Start $start -End $end).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $start -End $end).TotalSeconds) seconds)"
}