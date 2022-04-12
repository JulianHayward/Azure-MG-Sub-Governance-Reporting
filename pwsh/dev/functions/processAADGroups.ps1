function processAADGroups {
    Write-Host 'Resolving AAD Groups (for which a RBAC Role assignment exists)'
    Write-Host " Users known as Guest count: $($htUserTypesGuest.Keys.Count) (before Resolving AAD Groups)"
    $startAADGroupsResolveMembers = Get-Date

    $optimizedTableForAADGroupsQuery = ($roleAssignmentsUniqueById.where( { $_.RoleAssignmentIdentityObjectType -eq 'Group' } ) | Select-Object -Property RoleAssignmentIdentityObjectId, RoleAssignmentIdentityDisplayname) | Sort-Object -Property RoleAssignmentIdentityObjectId -Unique
    $aadGroupsCount = ($optimizedTableForAADGroupsQuery).Count

    if ($aadGroupsCount -gt 0) {

        switch ($aadGroupsCount) {
            { $_ -gt 0 } { $indicator = 1 }
            { $_ -gt 10 } { $indicator = 5 }
            { $_ -gt 50 } { $indicator = 10 }
            { $_ -gt 100 } { $indicator = 20 }
            { $_ -gt 250 } { $indicator = 25 }
            { $_ -gt 500 } { $indicator = 50 }
            { $_ -gt 1000 } { $indicator = 100 }
            { $_ -gt 10000 } { $indicator = 250 }
        }

        Write-Host " processing $($aadGroupsCount) AAD Groups with Role assignments (indicating progress in steps of $indicator)"

        $optimizedTableForAADGroupsQuery | ForEach-Object -Parallel {
            $aadGroupIdWithRoleAssignment = $_
            #region UsingVARs
            #fromOtherFunctions
            $AADGroupMembersLimit = $using:AADGroupMembersLimit
            $azAPICallConf = $using:azAPICallConf
            #Array&HTs
            $htAADGroupsDetails = $using:htAADGroupsDetails
            $arrayGroupRoleAssignmentsOnServicePrincipals = $using:arrayGroupRoleAssignmentsOnServicePrincipals
            $arrayGroupRequestResourceNotFound = $using:arrayGroupRequestResourceNotFound
            $arrayProgressedAADGroups = $using:arrayProgressedAADGroups
            $htAADGroupsExeedingMemberLimit = $using:htAADGroupsExeedingMemberLimit
            $indicator = $using:indicator
            $htUserTypesGuest = $using:htUserTypesGuest
            $htServicePrincipals = $using:htServicePrincipals
            #Functions
            #AzAPICall
            $function:AzAPICall = $using:AzAPICallFunctions.funcAzAPICall
            $function:createBearerToken = $using:AzAPICallFunctions.funcCreateBearerToken
            $function:GetJWTDetails = $using:AzAPICallFunctions.funcGetJWTDetails
            $function:Logging = $using:AzAPICallFunctions.funcLogging
            #other
            $function:getGroupmembers = $using:funcGetGroupmembers
            #endregion UsingVARs

            $rndom = Get-Random -Minimum 10 -Maximum 750
            start-sleep -Millisecond $rndom

            $uri = "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/beta/groups/$($aadGroupIdWithRoleAssignment.RoleAssignmentIdentityObjectId)/transitiveMembers/`$count"
            $method = 'GET'
            $aadGroupMembersCount = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask "getGroupMembersCountTransitive $($aadGroupIdWithRoleAssignment.RoleAssignmentIdentityObjectId)" -listenOn 'Content' -consistencyLevel 'eventual'

            if ($aadGroupMembersCount -eq 'Request_ResourceNotFound') {
                $null = $script:arrayGroupRequestResourceNotFound.Add([PSCustomObject]@{
                        groupId = $aadGroupIdWithRoleAssignment.RoleAssignmentIdentityObjectId
                    })
            }
            else {
                if ($aadGroupMembersCount -gt $AADGroupMembersLimit) {
                    Write-Host "  Group exceeding limit ($($AADGroupMembersLimit)); memberCount: $aadGroupMembersCount; Group: $($aadGroupIdWithRoleAssignment.RoleAssignmentIdentityDisplayname) ($($aadGroupIdWithRoleAssignment.RoleAssignmentIdentityObjectId)); Members will not be resolved adjust the limit using parameter -AADGroupMembersLimit"
                    $script:htAADGroupsDetails.($aadGroupIdWithRoleAssignment.RoleAssignmentIdentityObjectId) = @{}
                    $script:htAADGroupsDetails.($aadGroupIdWithRoleAssignment.RoleAssignmentIdentityObjectId).MembersAllCount = $aadGroupMembersCount
                    $script:htAADGroupsDetails.($aadGroupIdWithRoleAssignment.RoleAssignmentIdentityObjectId).MembersUsersCount = 'n/a'
                    $script:htAADGroupsDetails.($aadGroupIdWithRoleAssignment.RoleAssignmentIdentityObjectId).MembersGroupsCount = 'n/a'
                    $script:htAADGroupsDetails.($aadGroupIdWithRoleAssignment.RoleAssignmentIdentityObjectId).MembersServicePrincipalsCount = 'n/a'
                }
                else {
                    getGroupmembers -aadGroupId $aadGroupIdWithRoleAssignment.RoleAssignmentIdentityObjectId -aadGroupDisplayName $aadGroupIdWithRoleAssignment.RoleAssignmentIdentityDisplayname
                }
            }

            $null = $script:arrayProgressedAADGroups.Add($aadGroupIdWithRoleAssignment.RoleAssignmentIdentityObjectId)
            $processedAADGroupsCount = $null
            $processedAADGroupsCount = ($arrayProgressedAADGroups).Count
            if ($processedAADGroupsCount) {
                if ($processedAADGroupsCount % $indicator -eq 0) {
                    Write-Host " $processedAADGroupsCount AAD Groups processed"
                }
            }
        } -ThrottleLimit ($ThrottleLimit * 2)
        #[System.GC]::Collect()
    }
    else {
        Write-Host " processing $($aadGroupsCount) AAD Groups with Role assignments"
    }

    $arrayGroupRequestResourceNotFoundCount = ($arrayGroupRequestResourceNotFound).Count
    if ($arrayGroupRequestResourceNotFoundCount -gt 0) {
        Write-Host "$arrayGroupRequestResourceNotFoundCount Groups could not be checked for Memberships"
    }

    Write-Host " Collected $($arrayProgressedAADGroups.Count) AAD Groups"
    $endAADGroupsResolveMembers = Get-Date
    Write-Host "Resolving AAD Groups duration: $((NEW-TIMESPAN -Start $startAADGroupsResolveMembers -End $endAADGroupsResolveMembers).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startAADGroupsResolveMembers -End $endAADGroupsResolveMembers).TotalSeconds) seconds)"
    Write-Host " Users known as Guest count: $($htUserTypesGuest.Keys.Count) (after Resolving AAD Groups)"
}