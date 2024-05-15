function processAADGroups {
    if ($NoPIMEligibility) {
        Write-Host 'Resolving Microsoft Entra groups (for which a RBAC role assignment exists)'
    }
    else {
        Write-Host 'Resolving Microsoft Entra groups (for which a RBAC role assignment or PIM eligibility exists)'
    }

    Write-Host " Users known as Guest count: $($htUserTypesGuest.Keys.Count) (before resolving Microsoft Entra groups)"
    $startAADGroupsResolveMembers = Get-Date

    $roleAssignmentsforGroups = ($roleAssignmentsUniqueById.where( { $_.RoleAssignmentIdentityObjectType -eq 'Group' } ) | Select-Object -Property RoleAssignmentIdentityObjectId, RoleAssignmentIdentityDisplayname) | Sort-Object -Property RoleAssignmentIdentityObjectId -Unique
    $optimizedTableForAADGroupsQuery = [System.Collections.ArrayList]@()
    if ($roleAssignmentsforGroups.Count -gt 0) {
        foreach ($roleAssignmentforGroups in $roleAssignmentsforGroups) {
            $null = $optimizedTableForAADGroupsQuery.Add($roleAssignmentforGroups)
        }
    }

    $aadGroupsCount = ($optimizedTableForAADGroupsQuery).Count
    Write-Host " $aadGroupsCount Groups from RoleAssignments"

    if (-not $NoPIMEligibility) {
        $PIMEligibleGroups = $arrayPIMEligible.where({ $_.IdentityType -eq 'Group' }) | Select-Object IdentityObjectId, IdentityDisplayName | Sort-Object -Property IdentityObjectId -Unique
        $cntPIMEligibleGroupsTotal = 0
        $cntPIMEligibleGroupsNotCoveredFromRoleAssignments = 0
        foreach ($PIMEligibleGroup in  $PIMEligibleGroups) {
            $cntPIMEligibleGroupsTotal++
            if ($optimizedTableForAADGroupsQuery.RoleAssignmentIdentityObjectId -notcontains $PIMEligibleGroup.IdentityObjectId) {
                $cntPIMEligibleGroupsNotCoveredFromRoleAssignments++
                $null = $optimizedTableForAADGroupsQuery.Add([PSCustomObject]@{
                        RoleAssignmentIdentityObjectId    = $PIMEligibleGroup.IdentityObjectId
                        RoleAssignmentIdentityDisplayname = $PIMEligibleGroup.IdentityDisplayName
                    })
            }
        }
        Write-Host " $cntPIMEligibleGroupsTotal groups from PIM eligibility; $cntPIMEligibleGroupsNotCoveredFromRoleAssignments groups added ($($cntPIMEligibleGroupsTotal - $cntPIMEligibleGroupsNotCoveredFromRoleAssignments) already covered in role assignments)"
        $aadGroupsCount = ($optimizedTableForAADGroupsQuery).Count
        Write-Host " $aadGroupsCount groups from role assignments and PIM eligibility"
    }

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

        Write-Host " processing $($aadGroupsCount) Microsoft Entra groups (indicating progress in steps of $indicator)"

        $ThrottleLimitThis = $ThrottleLimit * 2
        $batchSize = [math]::ceiling($optimizedTableForAADGroupsQuery.Count / $ThrottleLimitThis)
        Write-Host "Optimal batch size: $($batchSize)"
        $counterBatch = [PSCustomObject] @{ Value = 0 }
        $optimizedTableForAADGroupsQueryBatch = ($optimizedTableForAADGroupsQuery) | Group-Object -Property { [math]::Floor($counterBatch.Value++ / $batchSize) }
        Write-Host "Processing data in $($optimizedTableForAADGroupsQueryBatch.Count) batches"

        $optimizedTableForAADGroupsQueryBatch | ForEach-Object -Parallel {
            #$aadGroupIdWithRoleAssignment = $_
            #region UsingVARs
            #fromOtherFunctions
            $AADGroupMembersLimit = $using:AADGroupMembersLimit
            $azAPICallConf = $using:azAPICallConf
            $scriptPath = $using:ScriptPath
            #Array&HTs
            $htAADGroupsDetails = $using:htAADGroupsDetails
            $arrayGroupRoleAssignmentsOnServicePrincipals = $using:arrayGroupRoleAssignmentsOnServicePrincipals
            $arrayGroupRequestResourceNotFound = $using:arrayGroupRequestResourceNotFound
            $arrayProgressedAADGroups = $using:arrayProgressedAADGroups
            $htAADGroupsExeedingMemberLimit = $using:htAADGroupsExeedingMemberLimit
            $indicator = $using:indicator
            $htUserTypesGuest = $using:htUserTypesGuest
            $htServicePrincipals = $using:htServicePrincipals
            #other
            $function:getGroupmembers = $using:funcGetGroupmembers
            #endregion UsingVARs

            foreach ($aadGroupIdWithRoleAssignment in $_.Group) {

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
                        $script:htAADGroupsDetails.($aadGroupIdWithRoleAssignment.RoleAssignmentIdentityObjectId) = @{
                            MembersAllCount               = $aadGroupMembersCount
                            MembersUsersCount             = 'n/a'
                            MembersGroupsCount            = 'n/a'
                            MembersServicePrincipalsCount = 'n/a'
                        }

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
                        Write-Host " $processedAADGroupsCount Microsoft Entra groups processed"
                    }
                }
            }
        } -ThrottleLimit ($ThrottleLimitThis)
    }
    else {
        Write-Host " processing $($aadGroupsCount) Microsoft Entra groups"
    }

    $arrayGroupRequestResourceNotFoundCount = ($arrayGroupRequestResourceNotFound).Count
    if ($arrayGroupRequestResourceNotFoundCount -gt 0) {
        Write-Host "$arrayGroupRequestResourceNotFoundCount Groups could not be checked for Memberships"
    }

    Write-Host " processed $($arrayProgressedAADGroups.Count) Microsoft Entra groups"
    $endAADGroupsResolveMembers = Get-Date
    Write-Host "Resolving Microsoft Entra groups duration: $((New-TimeSpan -Start $startAADGroupsResolveMembers -End $endAADGroupsResolveMembers).TotalMinutes) minutes ($((New-TimeSpan -Start $startAADGroupsResolveMembers -End $endAADGroupsResolveMembers).TotalSeconds) seconds)"
    Write-Host " Users known as Guest count: $($htUserTypesGuest.Keys.Count) (after resolving Microsoft Entra groups)"
}