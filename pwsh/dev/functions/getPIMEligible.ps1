function getPIMEligible {
    $start = Get-Date
        
    $currentTask = "Get PIM onboarded Subscriptions and Management Groups"
    Write-Host $currentTask
    $uriExt = "&`$expand=parent&`$filter=(type eq 'subscription' or type eq 'managementgroup')"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/beta/privilegedAccess/azureResources/resources?`$select=id,displayName,type,externalId" + $uriExt
    $res = AzAPICall -AzAPICallConfiguration $azapicallConf -uri $uri -currentTask $currentTask

    if ($res.Count -gt 0) {
        $res | ForEach-Object -parallel {
            $scope = $_
            $azAPICallConf = $using:azAPICallConf
            $arrayPIMEligible = $using:arrayPIMEligible
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
                    ResolveObjectIds -objectIds $users.subject.id
                }

                foreach ($entry in $resx) {
                    $scopeId = $scope.externalId -replace '.*/'
                    if ($scope.type -eq 'managementgroup') {
                        $ScopeType = 'MG'
                        $ManagementGroupId = $scopeId
                        $SubscriptionId = ''
                        $MgDetails = $htManagementGroupsMgPath.($scopeId)
                        $ManagementGroupDisplayName = $MgDetails.DisplayName
                        $SubscriptionDisplayName = ''
                        $ScopeDisplayName = $MgDetails.DisplayName
                        $MgPath = $MgDetails.path
                        $MgLevel = $MgDetails.level 
                    }
                    if ($scope.type -eq 'subscription') {
                        $ScopeType = 'Sub'
                        $ManagementGroupId = ''
                        $SubscriptionId = $scopeId
                        $MgDetails = $htSubscriptionsMgPath.($scopeId)
                        $ManagementGroupDisplayName = ''
                        $SubscriptionDisplayName = $MgDetails.DisplayName
                        $ScopeDisplayName = $MgDetails.DisplayName
                        $MgPath = $MgDetails.path[0..(($MgDetails.path.Count) - 2)]
                        $MgLevel = $MgDetails.level 
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
                            IdentityObjectId           = $entry.subject.id
                            IdentityType               = $principalType
                            IdentityDisplayName        = $entry.subject.displayName
                            IdentityPrincipalName      = $entry.subject.principalName
                            RoleId                     = $entry.roleDefinition.externalId
                            RoleIdGuid                 = $entry.roleDefinition.externalId -replace '.*/'
                            RoleType                   = $entry.roleDefinition.type
                            RoleName                   = $entry.roleDefinition.displayName
                            Eligibility                = 'direct'
                        })
                    #Write-Host "  - eligible: $($scope.externalId -replace '.*/') $($entry.subject.id) $($entry.subject.displayName) ($($entry.subject.type)) -> $($entry.roleDefinition.displayName)"
                }
            }
        } -ThrottleLimit $ThrottleLimit

        $script:arrayPIMEligibleGrouped = $arrayPIMEligible | Group-Object -Property ScopeType
        foreach ($entry in $arrayPIMEligibleGrouped) {
            Write-Host " $($entry.Name)s: $($entry.Count)"
        }
    }

    $end = Get-Date
    Write-Host "Getting PIM Eligible assignments processing duration: $((NEW-TIMESPAN -Start $start -End $end).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $start -End $end).TotalSeconds) seconds)"
}