function processTenantSummary() {
    Write-Host ' Building TenantSummary'
    showMemoryUsage
    if ($getMgParentName -eq 'Tenant Root') {
        $scopeNamingSummary = 'Tenant wide'
    }
    else {
        $scopeNamingSummary = "ManagementGroup '$ManagementGroupId' and descendants wide"
    }

    #region tenantSummaryPre
    $startRoleAssignmentsAllPre = Get-Date
    $roleAssignmentsallCount = ($rbacBaseQuery).count
    Write-Host "  processing (pre) TenantSummary RoleAssignments (all $roleAssignmentsallCount)"

    #region RelatedPolicyAssignments
    $startRelatedPolicyAssignmentsAll = Get-Date
    $htRoleAssignmentRelatedPolicyAssignments = @{}
    $htOrphanedSPMI = @{}
    foreach ($roleAssignmentIdUnique in $roleAssignmentsUniqueById) {

        $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId) = @{}

        if ($htManagedIdentityForPolicyAssignment.($roleAssignmentIdUnique.RoleAssignmentIdentityObjectId)) {
            $hlpPolicyAssignmentId = ($htManagedIdentityForPolicyAssignment.($roleAssignmentIdUnique.RoleAssignmentIdentityObjectId).policyAssignmentId).ToLower()
            if (-not $htCacheAssignmentsPolicy.($hlpPolicyAssignmentId)) {
                if ($ManagementGroupId -eq $azAPICallConf['checkContext'].Tenant.Id) {
                    if ($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy) {
                        if (-not ($htCacheAssignmentsPolicyOnResourceGroupsAndResources).($hlpPolicyAssignmentId)) {
                            Write-Host "   !Relict detected: SP MI: $($roleAssignmentIdUnique.RoleAssignmentIdentityObjectId) - PolicyAssignmentId: $hlpPolicyAssignmentId"
                            if (-not $htOrphanedSPMI.($roleAssignmentIdUnique.RoleAssignmentIdentityObjectId)) {
                                $htOrphanedSPMI.($roleAssignmentIdUnique.RoleAssignmentIdentityObjectId) = @{}
                            }
                        }
                    }
                    else {
                        Write-Host "   !Relict detected: SP MI: $($roleAssignmentIdUnique.RoleAssignmentIdentityObjectId) - PolicyAssignmentId: $hlpPolicyAssignmentId"
                        if (-not $htOrphanedSPMI.($roleAssignmentIdUnique.RoleAssignmentIdentityObjectId)) {
                            $htOrphanedSPMI.($roleAssignmentIdUnique.RoleAssignmentIdentityObjectId) = @{}
                        }
                    }
                }
            }
            else {
                $temp0000000000 = $htCacheAssignmentsPolicy.($hlpPolicyAssignmentId)
                $policyAssignmentId = ($temp0000000000.Assignment.id).Tolower()
                $policyDefinitionId = ($temp0000000000.Assignment.properties.policyDefinitionId).Tolower()


                #builtin
                if ($policyDefinitionId -like '/providers/Microsoft.Authorization/policy*') {
                    #policy
                    if ($policyDefinitionId -like '/providers/Microsoft.Authorization/policyDefinitions/*') {
                        $LinkOrNotLinkToAzAdvertizer = ($htCacheDefinitionsPolicy).($policyDefinitionId).LinkToAzAdvertizer
                    }
                    #policySet
                    if ($policyDefinitionId -like '/providers/Microsoft.Authorization/policySetDefinitions/*') {
                        $LinkOrNotLinkToAzAdvertizer = ($htCacheDefinitionsPolicySet).($policyDefinitionId).LinkToAzAdvertizer
                    }
                }
                else {
                    #policy
                    if ($policyDefinitionId -like '*/providers/Microsoft.Authorization/policyDefinitions/*') {
                        $policyDisplayName = ($htCacheDefinitionsPolicy).($policyDefinitionId).DisplayName

                    }
                    #policySet
                    if ($policyDefinitionId -like '*/providers/Microsoft.Authorization/policySetDefinitions/*') {
                        $policyDisplayName = ($htCacheDefinitionsPolicySet).($policyDefinitionId).DisplayName

                    }

                    $LinkOrNotLinkToAzAdvertizer = "<b>$($policyDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</b>"
                }
                $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).relatedPolicyAssignment = "$($policyAssignmentId) ($LinkOrNotLinkToAzAdvertizer)"
                $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).relatedPolicyAssignmentClear = "$($policyAssignmentId) ($policyDisplayName)"
            }
        }
        else {
            $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).relatedPolicyAssignment = 'none'
            $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).relatedPolicyAssignmentClear = 'none'
        }

        if ($roleAssignmentIdUnique.RoleIsCustom -eq 'FALSE') {
            $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).roleType = 'Builtin'
            $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer = ($htCacheDefinitionsRole).($roleAssignmentIdUnique.RoleDefinitionId).LinkToAzAdvertizer
            $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).roleClear = $roleAssignmentIdUnique.RoleDefinitionName
        }
        else {

            if ($roleAssigned.RoleSecurityCustomRoleOwner -eq 1) {
                $roletype = "<abbr title=`"Custom 'Owner' Role definitions should not exist`"><i class=`"fa fa-exclamation-triangle yellow`" aria-hidden=`"true`"></i></abbr> <a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/10ee2ea2-fb4d-45b8-a7e9-a2e770044cd9.html`" target=`"_blank`" rel=`"noopener`">Custom</a>"
            }
            else {
                $roleType = 'Custom'
            }

            $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).roleType = $roleType
            $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer = $roleAssignmentIdUnique.RoleDefinitionName
            $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).roleClear = $roleAssignmentIdUnique.RoleDefinitionName
        }
    }
    $endRelatedPolicyAssignmentsAll = Get-Date
    Write-Host "   RelatedPolicyAssignmentsAll duration: $((New-TimeSpan -Start $startRelatedPolicyAssignmentsAll -End $endRelatedPolicyAssignmentsAll).TotalMinutes) minutes ($((New-TimeSpan -Start $startRelatedPolicyAssignmentsAll -End $endRelatedPolicyAssignmentsAll).TotalSeconds) seconds)"
    #endregion RelatedPolicyAssignments

    #region createRBACAll
    $cnter = 0
    $script:rbacAll = [System.Collections.ArrayList]@()
    $startCreateRBACAll = Get-Date
    foreach ($rbac in $rbacBaseQuery) {
        $cnter++
        if ($cnter % 1000 -eq 0) {
            $etappeRoleAssignmentsAll = Get-Date
            Write-Host "   $cnter of $roleAssignmentsallCount RoleAssignments processed; $((New-TimeSpan -Start $startRoleAssignmentsAllPre -End $etappeRoleAssignmentsAll).TotalSeconds) seconds"
        }
        $scope = $null

        if ($rbac.RoleAssignmentPIM -eq 'true') {
            $pim = $true
            $pimAssignmentType = $rbac.RoleAssignmentPIMAssignmentType
            $pimSlotStart = [string]$($rbac.RoleAssignmentPIMSlotStart)
            $pimSlotEnd = [string]$($rbac.RoleAssignmentPIMSlotEnd)
        }
        else {
            $pim = $false
            $pimAssignmentType = ''
            $pimSlotStart = ''
            $pimSlotEnd = ''
        }

        if ($rbac.RoleAssignmentId -like '/providers/Microsoft.Management/managementGroups/*') {
            $scopeTenOrMgOrSubOrRGOrRes = 'Mg'
            if (-not [String]::IsNullOrEmpty($rbac.SubscriptionId)) {
                $scope = "inherited $($rbac.RoleAssignmentScopeName)"
            }
            else {
                if (($rbac.RoleAssignmentScopeName) -eq $rbac.MgId) {
                    $scope = 'thisScope MG'
                }
                else {
                    $scope = "inherited $($rbac.RoleAssignmentScopeName)"
                }
            }
        }

        if ($rbac.RoleAssignmentId -like '/subscriptions/*') {
            $scope = 'thisScope Sub'
            $scopeTenOrMgOrSubOrRGOrRes = 'Sub'
        }

        if ($rbac.RoleAssignmentId -like '/subscriptions/*/resourcegroups/*') {
            $scope = 'thisScope Sub RG'
            $scopeTenOrMgOrSubOrRGOrRes = 'RG'
        }

        if ($rbac.RoleAssignmentId -like '/subscriptions/*/resourcegroups/*/providers/*/providers/*') {
            $scope = 'thisScope Sub RG Res'
            $scopeTenOrMgOrSubOrRGOrRes = 'Res'
        }

        if ($rbac.RoleAssignmentId -like '/providers/Microsoft.Authorization/roleAssignments/*') {
            $scope = 'inherited Tenant'
            $scopeTenOrMgOrSubOrRGOrRes = 'Ten'
        }

        $objectTypeUserType = ''
        if ($rbac.RoleAssignmentIdentityObjectType -eq 'User') {
            if ($htUserTypesGuest.($rbac.RoleAssignmentIdentityObjectId)) {
                $objectTypeUserType = 'Guest'
            }
            else {
                $objectTypeUserType = 'Member'
            }
        }

        if (-not [string]::IsNullOrEmpty($rbac.RoleDataActions) -or -not [string]::IsNullOrEmpty($rbac.RoleNotDataActions)) {
            $roleManageData = 'true'
        }
        else {
            $roleManageData = 'false'
        }

        $hlpRoleAssignmentRelatedPolicyAssignments = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId)

        if (-not $NoAADGroupsResolveMembers) {
            if ($rbac.RoleAssignmentIdentityObjectType -eq 'Group') {

                $grpHlpr = $htAADGroupsDetails.($rbac.RoleAssignmentIdentityObjectId)
                $null = $script:rbacAll.Add([PSCustomObject]@{
                        Level                                = $rbac.Level
                        RoleAssignmentId                     = $rbac.RoleAssignmentId
                        RoleAssignmentPIMRelated             = $pim
                        RoleAssignmentPIMAssignmentType      = $pimAssignmentType
                        RoleAssignmentPIMAssignmentSlotStart = $pimSlotStart
                        RoleAssignmentPIMAssignmentSlotEnd   = $pimSlotEnd
                        CreatedBy                            = $rbac.RoleAssignmentCreatedBy
                        CreatedOn                            = $rbac.RoleAssignmentCreatedOn
                        UpdatedBy                            = $rbac.RoleAssignmentUpdatedBy
                        UpdatedOn                            = $rbac.RoleAssignmentUpdatedOn
                        MgId                                 = $rbac.MgId
                        MgName                               = $rbac.MgName
                        MgParentId                           = $rbac.MgParentId
                        MgParentName                         = $rbac.MgParentName
                        SubscriptionId                       = $rbac.SubscriptionId
                        SubscriptionName                     = $rbac.Subscription
                        Scope                                = $scope
                        ScopeTenOrMgOrSubOrRGOrRes           = $scopeTenOrMgOrSubOrRGOrRes
                        RoleAssignmentScopeName              = $rbac.RoleAssignmentScopeName
                        RoleAssignmentScopeRG                = $rbac.RoleAssignmentScopeRG
                        RoleAssignmentScopeRes               = $rbac.RoleAssignmentScopeRes
                        Role                                 = $hlpRoleAssignmentRelatedPolicyAssignments.roleWithWithoutLinkToAzAdvertizer
                        RoleClear                            = $hlpRoleAssignmentRelatedPolicyAssignments.roleClear
                        RoleId                               = $rbac.RoleDefinitionId
                        RoleType                             = $hlpRoleAssignmentRelatedPolicyAssignments.roleType
                        RoleDataRelated                      = $roleManageData
                        AssignmentType                       = 'direct'
                        AssignmentInheritFrom                = ''
                        GroupMembersCount                    = "$($grpHlpr.MembersAllCount) (Usr: $($grpHlpr.MembersUsersCount)$($CsvDelimiterOpposite) Grp: $($grpHlpr.MembersGroupsCount)$($CsvDelimiterOpposite) SP: $($grpHlpr.MembersServicePrincipalsCount))"
                        ObjectDisplayName                    = $rbac.RoleAssignmentIdentityDisplayname
                        ObjectSignInName                     = $rbac.RoleAssignmentIdentitySignInName
                        ObjectId                             = $rbac.RoleAssignmentIdentityObjectId
                        ObjectType                           = $rbac.RoleAssignmentIdentityObjectType
                        RbacRelatedPolicyAssignment          = $hlpRoleAssignmentRelatedPolicyAssignments.relatedPolicyAssignment
                        RbacRelatedPolicyAssignmentClear     = $hlpRoleAssignmentRelatedPolicyAssignments.relatedPolicyAssignmentClear
                        RoleSecurityCustomRoleOwner          = $rbac.RoleSecurityCustomRoleOwner
                        RoleSecurityOwnerAssignmentSP        = $rbac.RoleSecurityOwnerAssignmentSP
                        RoleCanDoRoleAssignments             = $rbac.RoleCanDoRoleAssignments
                    })


                if ($grpHlpr.MembersAllCount -gt 0) {

                    if ($htAADGroupsDetails.($rbac.RoleAssignmentIdentityObjectId).MembersAllCount -le $AADGroupMembersLimit) {

                        foreach ($groupmember in $htAADGroupsDetails.($rbac.RoleAssignmentIdentityObjectId).MembersAll) {
                            if ($groupmember.'@odata.type' -eq '#microsoft.graph.user') {
                                if ($azAPICallConf['htParameters'].DoNotShowRoleAssignmentsUserData -eq $true) {
                                    $grpMemberDisplayName = 'scrubbed'
                                    $grpMemberSignInName = 'scrubbed'
                                }
                                else {
                                    $grpMemberDisplayName = $groupmember.displayName
                                    $grpMemberSignInName = $groupmember.userPrincipalName
                                }
                                $grpMemberId = $groupmember.Id
                                $grpMemberType = 'User'
                                $grpMemberUserType = ''

                                if ($htUserTypesGuest.($grpMemberId)) {
                                    $grpMemberUserType = 'Guest'
                                }
                                else {
                                    $grpMemberUserType = 'Member'
                                }

                                $identityTypeFull = "$grpMemberType $grpMemberUserType"
                            }
                            if ($groupmember.'@odata.type' -eq '#microsoft.graph.group') {
                                $grpMemberDisplayName = $groupmember.displayName
                                $grpMemberSignInName = 'n/a'
                                $grpMemberId = $groupmember.Id
                                $grpMemberType = 'Group'
                                $grpMemberUserType = ''
                                $identityTypeFull = "$grpMemberType"
                            }
                            if ($groupmember.'@odata.type' -eq '#microsoft.graph.servicePrincipal') {
                                $grpMemberDisplayName = $groupmember.appDisplayName
                                $grpMemberSignInName = 'n/a'
                                $grpMemberId = $groupmember.Id
                                $grpMemberType = 'ServicePrincipal'
                                $grpMemberUserType = ''
                                $identityType = $htServicePrincipals.($grpMemberId).spTypeConcatinated
                                $identityTypeFull = "$identityType"
                            }

                            $null = $script:rbacAll.Add([PSCustomObject]@{
                                    Level                                = $rbac.Level
                                    RoleAssignmentId                     = $rbac.RoleAssignmentId
                                    RoleAssignmentPIMRelated             = $pim
                                    RoleAssignmentPIMAssignmentType      = $pimAssignmentType
                                    RoleAssignmentPIMAssignmentSlotStart = $pimSlotStart
                                    RoleAssignmentPIMAssignmentSlotEnd   = $pimSlotEnd
                                    CreatedBy                            = $rbac.RoleAssignmentCreatedBy
                                    CreatedOn                            = $rbac.RoleAssignmentCreatedOn
                                    UpdatedBy                            = $rbac.RoleAssignmentUpdatedBy
                                    UpdatedOn                            = $rbac.RoleAssignmentUpdatedOn
                                    MgId                                 = $rbac.MgId
                                    MgName                               = $rbac.MgName
                                    MgParentId                           = $rbac.MgParentId
                                    MgParentName                         = $rbac.MgParentName
                                    SubscriptionId                       = $rbac.SubscriptionId
                                    SubscriptionName                     = $rbac.Subscription
                                    Scope                                = $scope
                                    ScopeTenOrMgOrSubOrRGOrRes           = $scopeTenOrMgOrSubOrRGOrRes
                                    RoleAssignmentScopeName              = $rbac.RoleAssignmentScopeName
                                    RoleAssignmentScopeRG                = $rbac.RoleAssignmentScopeRG
                                    RoleAssignmentScopeRes               = $rbac.RoleAssignmentScopeRes
                                    Role                                 = $hlpRoleAssignmentRelatedPolicyAssignments.roleWithWithoutLinkToAzAdvertizer
                                    RoleClear                            = $hlpRoleAssignmentRelatedPolicyAssignments.roleClear
                                    RoleId                               = $rbac.RoleDefinitionId
                                    RoleType                             = $hlpRoleAssignmentRelatedPolicyAssignments.roleType
                                    RoleDataRelated                      = $roleManageData
                                    AssignmentType                       = 'indirect'
                                    AssignmentInheritFrom                = "$($rbac.RoleAssignmentIdentityDisplayname) ($($rbac.RoleAssignmentIdentityObjectId))"
                                    GroupMembersCount                    = "$($grpHlpr.MembersAllCount) (Usr: $($grpHlpr.MembersUsersCount)$($CsvDelimiterOpposite) Grp: $($grpHlpr.MembersGroupsCount)$($CsvDelimiterOpposite) SP: $($grpHlpr.MembersServicePrincipalsCount))"
                                    ObjectDisplayName                    = $grpMemberDisplayName
                                    ObjectSignInName                     = $grpMemberSignInName
                                    ObjectId                             = $grpMemberId
                                    ObjectType                           = $identityTypeFull
                                    RbacRelatedPolicyAssignment          = $hlpRoleAssignmentRelatedPolicyAssignments.relatedPolicyAssignment
                                    RbacRelatedPolicyAssignmentClear     = $hlpRoleAssignmentRelatedPolicyAssignments.relatedPolicyAssignmentClear
                                    RoleSecurityCustomRoleOwner          = $rbac.RoleSecurityCustomRoleOwner
                                    RoleSecurityOwnerAssignmentSP        = $rbac.RoleSecurityOwnerAssignmentSP
                                    RoleCanDoRoleAssignments             = $rbac.RoleCanDoRoleAssignments
                                })
                        }
                    }
                    else {
                        $null = $script:rbacAll.Add([PSCustomObject]@{
                                Level                                = $rbac.Level
                                RoleAssignmentId                     = $rbac.RoleAssignmentId
                                RoleAssignmentPIMRelated             = $pim
                                RoleAssignmentPIMAssignmentType      = $pimAssignmentType
                                RoleAssignmentPIMAssignmentSlotStart = $pimSlotStart
                                RoleAssignmentPIMAssignmentSlotEnd   = $pimSlotEnd
                                CreatedBy                            = $rbac.RoleAssignmentCreatedBy
                                CreatedOn                            = $rbac.RoleAssignmentCreatedOn
                                UpdatedBy                            = $rbac.RoleAssignmentUpdatedBy
                                UpdatedOn                            = $rbac.RoleAssignmentUpdatedOn
                                MgId                                 = $rbac.MgId
                                MgName                               = $rbac.MgName
                                MgParentId                           = $rbac.MgParentId
                                MgParentName                         = $rbac.MgParentName
                                SubscriptionId                       = $rbac.SubscriptionId
                                SubscriptionName                     = $rbac.Subscription
                                Scope                                = $scope
                                ScopeTenOrMgOrSubOrRGOrRes           = $scopeTenOrMgOrSubOrRGOrRes
                                RoleAssignmentScopeName              = $rbac.RoleAssignmentScopeName
                                RoleAssignmentScopeRG                = $rbac.RoleAssignmentScopeRG
                                RoleAssignmentScopeRes               = $rbac.RoleAssignmentScopeRes
                                Role                                 = $hlpRoleAssignmentRelatedPolicyAssignments.roleWithWithoutLinkToAzAdvertizer
                                RoleClear                            = $hlpRoleAssignmentRelatedPolicyAssignments.roleClear
                                RoleId                               = $rbac.RoleDefinitionId
                                RoleType                             = $hlpRoleAssignmentRelatedPolicyAssignments.roleType
                                RoleDataRelated                      = $roleManageData
                                AssignmentType                       = 'indirect'
                                AssignmentInheritFrom                = "$($rbac.RoleAssignmentIdentityDisplayname) ($($rbac.RoleAssignmentIdentityObjectId))"
                                GroupMembersCount                    = "$($grpHlpr.MembersAllCount) (Usr: $($grpHlpr.MembersUsersCount)$($CsvDelimiterOpposite) Grp: $($grpHlpr.MembersGroupsCount)$($CsvDelimiterOpposite) SP: $($grpHlpr.MembersServicePrincipalsCount))"
                                ObjectDisplayName                    = "Azure Governance Visualizer:TooManyMembers ($($htAADGroupsDetails.($rbac.RoleAssignmentIdentityObjectId).MembersAllCount))"
                                ObjectSignInName                     = "Azure Governance Visualizer:TooManyMembers ($($htAADGroupsDetails.($rbac.RoleAssignmentIdentityObjectId).MembersAllCount))"
                                ObjectId                             = "Azure Governance Visualizer:TooManyMembers ($($htAADGroupsDetails.($rbac.RoleAssignmentIdentityObjectId).MembersAllCount))"
                                ObjectType                           = 'unresolved'
                                RbacRelatedPolicyAssignment          = $hlpRoleAssignmentRelatedPolicyAssignments.relatedPolicyAssignment
                                RbacRelatedPolicyAssignmentClear     = $hlpRoleAssignmentRelatedPolicyAssignments.relatedPolicyAssignmentClear
                                RoleSecurityCustomRoleOwner          = $rbac.RoleSecurityCustomRoleOwner
                                RoleSecurityOwnerAssignmentSP        = $rbac.RoleSecurityOwnerAssignmentSP
                                RoleCanDoRoleAssignments             = $rbac.RoleCanDoRoleAssignments
                            })
                    }
                }

            }
            else {

                if ($rbac.RoleAssignmentIdentityObjectType -eq 'ServicePrincipal') {
                    $identityType = $htServicePrincipals.($rbac.RoleAssignmentIdentityObjectId).spTypeConcatinated
                    $identityTypeFull = $identityType
                }
                elseif ($rbac.RoleAssignmentIdentityObjectType -eq 'Unknown') {
                    $identityTypeFull = 'Unknown'
                }
                else {
                    #user
                    $identityType = $rbac.RoleAssignmentIdentityObjectType
                    $identityTypeFull = "$identityType $objectTypeUserType"
                }

                $null = $script:rbacAll.Add([PSCustomObject]@{
                        Level                                = $rbac.Level
                        RoleAssignmentId                     = $rbac.RoleAssignmentId
                        RoleAssignmentPIMRelated             = $pim
                        RoleAssignmentPIMAssignmentType      = $pimAssignmentType
                        RoleAssignmentPIMAssignmentSlotStart = $pimSlotStart
                        RoleAssignmentPIMAssignmentSlotEnd   = $pimSlotEnd
                        CreatedBy                            = $rbac.RoleAssignmentCreatedBy
                        CreatedOn                            = $rbac.RoleAssignmentCreatedOn
                        UpdatedBy                            = $rbac.RoleAssignmentUpdatedBy
                        UpdatedOn                            = $rbac.RoleAssignmentUpdatedOn
                        MgId                                 = $rbac.MgId
                        MgName                               = $rbac.MgName
                        MgParentId                           = $rbac.MgParentId
                        MgParentName                         = $rbac.MgParentName
                        SubscriptionId                       = $rbac.SubscriptionId
                        SubscriptionName                     = $rbac.Subscription
                        Scope                                = $scope
                        ScopeTenOrMgOrSubOrRGOrRes           = $scopeTenOrMgOrSubOrRGOrRes
                        RoleAssignmentScopeName              = $rbac.RoleAssignmentScopeName
                        RoleAssignmentScopeRG                = $rbac.RoleAssignmentScopeRG
                        RoleAssignmentScopeRes               = $rbac.RoleAssignmentScopeRes
                        Role                                 = $hlpRoleAssignmentRelatedPolicyAssignments.roleWithWithoutLinkToAzAdvertizer
                        RoleClear                            = $hlpRoleAssignmentRelatedPolicyAssignments.roleClear
                        RoleId                               = $rbac.RoleDefinitionId
                        RoleType                             = $hlpRoleAssignmentRelatedPolicyAssignments.roleType
                        RoleDataRelated                      = $roleManageData
                        AssignmentType                       = 'direct'
                        AssignmentInheritFrom                = ''
                        GroupMembersCount                    = ''
                        ObjectDisplayName                    = $rbac.RoleAssignmentIdentityDisplayname
                        ObjectSignInName                     = $rbac.RoleAssignmentIdentitySignInName
                        ObjectId                             = $rbac.RoleAssignmentIdentityObjectId
                        ObjectType                           = $identityTypeFull
                        RbacRelatedPolicyAssignment          = $hlpRoleAssignmentRelatedPolicyAssignments.relatedPolicyAssignment
                        RbacRelatedPolicyAssignmentClear     = $hlpRoleAssignmentRelatedPolicyAssignments.relatedPolicyAssignmentClear
                        RoleSecurityCustomRoleOwner          = $rbac.RoleSecurityCustomRoleOwner
                        RoleSecurityOwnerAssignmentSP        = $rbac.RoleSecurityOwnerAssignmentSP
                        RoleCanDoRoleAssignments             = $rbac.RoleCanDoRoleAssignments
                    })
            }
        }
        else {

            if ($rbac.RoleAssignmentIdentityObjectType -eq 'ServicePrincipal') {
                $identityType = $htServicePrincipals.($rbac.RoleAssignmentIdentityObjectId).spTypeConcatinated
                $identityTypeFull = $identityType
            }
            elseif ($rbac.RoleAssignmentIdentityObjectType -eq 'Unknown') {
                $identityTypeFull = 'Unknown'
            }
            elseif ($rbac.RoleAssignmentIdentityObjectType -eq 'Group') {
                $identityTypeFull = 'Group'
            }
            else {
                #user
                $identityType = $rbac.RoleAssignmentIdentityObjectType
                $identityTypeFull = "$identityType $objectTypeUserType"
            }

            #noaadgroupmemberresolve
            $null = $script:rbacAll.Add([PSCustomObject]@{
                    Level                                = $rbac.Level
                    RoleAssignmentId                     = $rbac.RoleAssignmentId
                    RoleAssignmentPIMRelated             = $pim
                    RoleAssignmentPIMAssignmentType      = $pimAssignmentType
                    RoleAssignmentPIMAssignmentSlotStart = $pimSlotStart
                    RoleAssignmentPIMAssignmentSlotEnd   = $pimSlotEnd
                    CreatedBy                            = $rbac.RoleAssignmentCreatedBy
                    CreatedOn                            = $rbac.RoleAssignmentCreatedOn
                    UpdatedBy                            = $rbac.RoleAssignmentUpdatedBy
                    UpdatedOn                            = $rbac.RoleAssignmentUpdatedOn
                    MgId                                 = $rbac.MgId
                    MgName                               = $rbac.MgName
                    MgParentId                           = $rbac.MgParentId
                    MgParentName                         = $rbac.MgParentName
                    SubscriptionId                       = $rbac.SubscriptionId
                    SubscriptionName                     = $rbac.Subscription
                    Scope                                = $scope
                    ScopeTenOrMgOrSubOrRGOrRes           = $scopeTenOrMgOrSubOrRGOrRes
                    RoleAssignmentScopeName              = $rbac.RoleAssignmentScopeName
                    RoleAssignmentScopeRG                = $rbac.RoleAssignmentScopeRG
                    RoleAssignmentScopeRes               = $rbac.RoleAssignmentScopeRes
                    Role                                 = $hlpRoleAssignmentRelatedPolicyAssignments.roleWithWithoutLinkToAzAdvertizer
                    RoleClear                            = $hlpRoleAssignmentRelatedPolicyAssignments.roleClear
                    RoleId                               = $rbac.RoleDefinitionId
                    RoleType                             = $hlpRoleAssignmentRelatedPolicyAssignments.roleType
                    RoleDataRelated                      = $roleManageData
                    AssignmentType                       = 'direct'
                    AssignmentInheritFrom                = ''
                    GroupMembersCount                    = ''
                    ObjectDisplayName                    = $rbac.RoleAssignmentIdentityDisplayname
                    ObjectSignInName                     = $rbac.RoleAssignmentIdentitySignInName
                    ObjectId                             = $rbac.RoleAssignmentIdentityObjectId
                    ObjectType                           = $identityTypeFull
                    RbacRelatedPolicyAssignment          = $hlpRoleAssignmentRelatedPolicyAssignments.relatedPolicyAssignment
                    RbacRelatedPolicyAssignmentClear     = $hlpRoleAssignmentRelatedPolicyAssignments.relatedPolicyAssignmentClear
                    RoleSecurityCustomRoleOwner          = $rbac.RoleSecurityCustomRoleOwner
                    RoleSecurityOwnerAssignmentSP        = $rbac.RoleSecurityOwnerAssignmentSP
                    RoleCanDoRoleAssignments             = $rbac.RoleCanDoRoleAssignments
                })
        }
    }
    #endregion createRBACAll

    #region PIMEligible
    if (-not $NoPIMEligibility) {
        $startPIMEnrichment = Get-Date
        Write-Host '   Processing PIMEnrichment'
        $PIMEligibleEnriched = [System.Collections.ArrayList]@()
        #$tfCountCnt = 0
        foreach ($PIMEligible in $arrayPIMEligible) {
            #$tfCountCnt++
            if ($PIMEligible.RoleType -eq 'BuiltInRole') {
                $roleName = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azrolesadvertizer/$($PIMEligible.RoleIdGuid).html`" target=`"_blank`" rel=`"noopener`">$($PIMEligible.RoleName)</a>"
            }
            else {
                $roleName = $PIMEligible.RoleName
            }
            $null = $PIMEligibleEnriched.Add([PSCustomObject]@{
                    Scope                            = $PIMEligible.ScopeType
                    ScopeId                          = $PIMEligible.ScopeId
                    ScopeName                        = $PIMEligible.ScopeDisplayName
                    ManagementGroupId                = $PIMEligible.ManagementGroupId
                    ManagementGroupDisplayName       = $PIMEligible.ManagementGroupDisplayName
                    SubscriptionId                   = $PIMEligible.SubscriptionId
                    SubscriptionDisplayName          = $PIMEligible.SubscriptionDisplayName
                    MgPath                           = $PIMEligible.MgPath -join '/'
                    MgLevel                          = $PIMEligible.MgLevel
                    Role                             = $roleName
                    RoleClear                        = $PIMEligible.RoleName
                    RoleId                           = $PIMEligible.RoleId
                    RoleIdGuid                       = $PIMEligible.RoleIdGuid
                    RoleType                         = $PIMEligible.RoleType
                    IdentityObjectId                 = $PIMEligible.IdentityObjectId
                    IdentityDisplayName              = $PIMEligible.IdentityDisplayName
                    IdentitySignInName               = $PIMEligible.IdentityPrincipalName
                    IdentityType                     = $PIMEligible.IdentityType
                    IdentityApplicability            = 'direct'
                    AppliesThrough                   = ''
                    PIMEligibilityId                 = $PIMEligible.PIMId
                    PIMEligibility                   = $PIMEligible.PIMInheritance
                    PIMEligibilityInheritedFrom      = $PIMEligible.PIMInheritedFrom
                    PIMEligibilityInheritedFromClear = $PIMEligible.PIMInheritedFromClear
                    PIMEligibilityStartDateTime      = [string]$PIMEligible.PIMStartDateTime
                    PIMEligibilityEndDateTime        = [string]$PIMEligible.PIMEndDateTime
                })

            if (-not $NoAADGroupsResolveMembers) {
                if ($PIMEligible.IdentityType -eq 'Group') {
                    if ($htAADGroupsDetails.($PIMEligible.IdentityObjectId)) {
                        foreach ($groupMemberUser in $htAADGroupsDetails.($PIMEligible.IdentityObjectId).MembersUsers) {
                            #$tfCountCnt++
                            $null = $PIMEligibleEnriched.Add([PSCustomObject]@{
                                    Scope                            = $PIMEligible.ScopeType
                                    ScopeId                          = $PIMEligible.ScopeId
                                    ScopeName                        = $PIMEligible.ScopeDisplayName
                                    ManagementGroupId                = $PIMEligible.ManagementGroupId
                                    ManagementGroupDisplayName       = $PIMEligible.ManagementGroupDisplayName
                                    SubscriptionId                   = $PIMEligible.SubscriptionId
                                    SubscriptionDisplayName          = $PIMEligible.SubscriptionDisplayName
                                    MgPath                           = $PIMEligible.MgPath -join '/'
                                    MgLevel                          = $PIMEligible.MgLevel
                                    Role                             = $roleName
                                    RoleClear                        = $PIMEligible.RoleName
                                    RoleId                           = $PIMEligible.RoleId
                                    RoleIdGuid                       = $PIMEligible.RoleIdGuid
                                    RoleType                         = $PIMEligible.RoleType
                                    IdentityObjectId                 = $groupMemberUser.id
                                    IdentityDisplayName              = $groupMemberUser.displayName
                                    IdentitySignInName               = $groupMemberUser.userPrincipalName
                                    IdentityType                     = "User $($groupMemberUser.userType)"
                                    IdentityApplicability            = 'nested'
                                    AppliesThrough                   = "$($PIMEligible.IdentityDisplayName) ($($PIMEligible.IdentityObjectId))"
                                    PIMEligibilityId                 = $PIMEligible.PIMId
                                    PIMEligibility                   = $PIMEligible.PIMInheritance
                                    PIMEligibilityInheritedFrom      = $PIMEligible.PIMInheritedFrom
                                    PIMEligibilityInheritedFromClear = $PIMEligible.PIMInheritedFromClear
                                    PIMEligibilityStartDateTime      = [string]$PIMEligible.PIMStartDateTime
                                    PIMEligibilityEndDateTime        = [string]$PIMEligible.PIMEndDateTime
                                })
                        }
                    }
                    else {
                        Write-Host "!! Unexpected: Group $($PIMEligible.IdentityDisplayName) ($($PIMEligible.IdentityObjectId)) not found in `$htAADGroupsDetails - please report back!"
                    }
                }
            }
        }
        $endPIMEnrichment = Get-Date
        Write-Host "    PIMEnrichment duration: $((New-TimeSpan -Start $startPIMEnrichment -End $endPIMEnrichment).TotalMinutes) minutes ($((New-TimeSpan -Start $startPIMEnrichment -End $endPIMEnrichment).TotalSeconds) seconds)"

        if (-not $NoPIMEligibilityIntegrationRoleAssignmentsAll) {
            $startPIMEnrichmentToRBACAll = Get-Date
            Write-Host '   Processing PIMEnrichment to RBACAll'
            foreach ($PIMEligibleRoleAssignment in $PIMEligibleEnriched) {
                if ($PIMEligibleRoleAssignment.PIMEligibility -eq 'Inherited') {
                    $scope = "inherited $($PIMEligibleRoleAssignment.PIMEligibilityInheritedFromClear)"
                }
                else {
                    $scope = "thisScope $($PIMEligibleRoleAssignment.Scope)"
                }

                if (-not [string]::IsNullOrEmpty($htCacheDefinitionsRole.($PIMEligibleRoleAssignment.RoleId).RoleDataActions) -or -not [string]::IsNullOrEmpty($htCacheDefinitionsRole.($PIMEligibleRoleAssignment.RoleId).RoleNotDataActions)) {
                    $roleManageData = 'true'
                }
                else {
                    $roleManageData = 'false'
                }

                $roleCanDoRoleAssignments = $false
                if ($htCacheDefinitionsRole.($PIMEligibleRoleAssignment.RoleId).RoleCanDoRoleAssignments) {
                    $roleCanDoRoleAssignments = 'true'
                }

                $null = $script:rbacAll.Add([PSCustomObject]@{
                        Level                                = $PIMEligibleRoleAssignment.MgLevel
                        RoleAssignmentId                     = ''
                        RoleAssignmentPIMRelated             = $true
                        RoleAssignmentPIMAssignmentType      = 'Eligible'
                        RoleAssignmentPIMAssignmentSlotStart = $PIMEligibleRoleAssignment.PIMEligibilityStartDateTime
                        RoleAssignmentPIMAssignmentSlotEnd   = $PIMEligibleRoleAssignment.PIMEligibilityEndDateTime
                        CreatedBy                            = ''
                        CreatedOn                            = ''
                        UpdatedBy                            = $rbac.RoleAssignmentUpdatedBy
                        UpdatedOn                            = $rbac.RoleAssignmentUpdatedOn
                        MgId                                 = $PIMEligibleRoleAssignment.ManagementGroupId
                        MgName                               = $PIMEligibleRoleAssignment.ManagementGroupDisplayName
                        MgParentId                           = '' #check
                        MgParentName                         = '' #check
                        SubscriptionId                       = $PIMEligibleRoleAssignment.SubscriptionId
                        SubscriptionName                     = $PIMEligibleRoleAssignment.SubscriptionDisplayName
                        Scope                                = $scope
                        ScopeTenOrMgOrSubOrRGOrRes           = $PIMEligibleRoleAssignment.Scope
                        RoleAssignmentScopeName              = $PIMEligibleRoleAssignment.Scope
                        RoleAssignmentScopeRG                = ''
                        RoleAssignmentScopeRes               = ''
                        Role                                 = $PIMEligibleRoleAssignment.Role
                        RoleClear                            = $PIMEligibleRoleAssignment.RoleClear
                        RoleId                               = $PIMEligibleRoleAssignment.RoleIdGuid
                        RoleType                             = $PIMEligibleRoleAssignment.RoleType
                        RoleDataRelated                      = $roleManageData #check
                        AssignmentType                       = $PIMEligibleRoleAssignment.IdentityApplicability
                        AssignmentInheritFrom                = $PIMEligibleRoleAssignment.AppliesThrough
                        GroupMembersCount                    = ''
                        ObjectDisplayName                    = $PIMEligibleRoleAssignment.IdentityDisplayName
                        ObjectSignInName                     = $PIMEligibleRoleAssignment.IdentitySignInName
                        ObjectId                             = $PIMEligibleRoleAssignment.IdentityObjectId
                        ObjectType                           = $PIMEligibleRoleAssignment.IdentityType
                        RbacRelatedPolicyAssignment          = ''
                        RbacRelatedPolicyAssignmentClear     = ''
                        RoleSecurityCustomRoleOwner          = '' #check $rbac.RoleSecurityCustomRoleOwner
                        RoleSecurityOwnerAssignmentSP        = '' #check $rbac.RoleSecurityOwnerAssignmentSP
                        RoleCanDoRoleAssignments             = $roleCanDoRoleAssignments
                    })
            }
            $endPIMEnrichmentToRBACAll = Get-Date
            Write-Host "    PIMEnrichment to RBACAll duration: $((New-TimeSpan -Start $startPIMEnrichmentToRBACAll -End $endPIMEnrichmentToRBACAll).TotalMinutes) minutes ($((New-TimeSpan -Start $startPIMEnrichmentToRBACAll -End $endPIMEnrichmentToRBACAll).TotalSeconds) seconds)"
        }
    }
    #endregion PIMEligible

    Write-Host '   Processing unresoved Identities (createdBy)'
    $startUnResolvedIdentitiesCreatedBy = Get-Date
    #prep prepUnresoledIdentities
    #region identitiesThatCreatedRoleAssignmentsButDontHaveARoleAssignmentThemselve
    $script:htIdentitiesWithRoleAssignmentsUnique = @{}
    $identitiesWithRoleAssignmentsUnique = $rbacAll.where( { $_.ObjectType -ne 'Unknown' } ) | Sort-Object -Property ObjectId -Unique | Select-Object ObjectType, ObjectDisplayName, ObjectSignInName, ObjectId
    foreach ($identityWithRoleAssignment in $identitiesWithRoleAssignmentsUnique | Sort-Object -Property objectType) {

        if (-not $htIdentitiesWithRoleAssignmentsUnique.($identityWithRoleAssignment.ObjectId)) {
            $script:htIdentitiesWithRoleAssignmentsUnique.($identityWithRoleAssignment.ObjectId) = @{}

            $arr = @()
            $ht = [ordered]@{}
            $identityWithRoleAssignment.psobject.properties | ForEach-Object {
                if ($_.Value) {
                    $value = $_.Value
                }
                else {
                    $value = 'n/a'
                }
                $arr += "$($_.Name): $value"
                $ht.($_.Name) = $value
            }

            $script:htIdentitiesWithRoleAssignmentsUnique.($identityWithRoleAssignment.ObjectId).details = $arr -join "$CsvDelimiterOpposite "
            $script:htIdentitiesWithRoleAssignmentsUnique.($identityWithRoleAssignment.ObjectId).detailsJson = $ht
        }
    }
    #endregion identitiesThatCreatedRoleAssignmentsButDontHaveARoleAssignmentThemselve

    #enrich rbacAll with createdBy and UpdatedBy identity information
    #region enrichrbacAll
    $htNonResolvedIdentities = @{}
    foreach ($rbac in $rbacAll) {
        $createdBy = $rbac.createdBy
        if (-not [string]::IsNullOrEmpty($createdBy)) {
            if ($htIdentitiesWithRoleAssignmentsUnique.($createdBy)) {
                $createdBy = $htIdentitiesWithRoleAssignmentsUnique.($createdBy).details
                $rbac.CreatedBy = $createdBy
            }
            else {
                if (-not $htNonResolvedIdentities.($rbac.createdBy)) {
                    $htNonResolvedIdentities.($rbac.createdBy) = @{}
                }
            }
        }

        $updatedBy = $rbac.updatedBy
        if (-not [string]::IsNullOrEmpty($updatedBy)) {
            if ($htIdentitiesWithRoleAssignmentsUnique.($updatedBy)) {
                $updatedBy = $htIdentitiesWithRoleAssignmentsUnique.($updatedBy).details
                $rbac.UpdatedBy = $updatedBy
            }
            else {
                if (-not $htNonResolvedIdentities.($rbac.updatedBy)) {
                    $htNonResolvedIdentities.($rbac.updatedBy) = @{}
                }
            }
        }
    }
    #endregion enrichrbacAll

    #region nonResolvedIdentities
    $htNonResolvedIdentitiesCount = $htNonResolvedIdentities.Count
    if ($htNonResolvedIdentitiesCount -gt 0) {
        Write-Host "    $htNonResolvedIdentitiesCount unresolved identities that created a RBAC Role assignment (createdBy)"
        $arrayUnresolvedIdentities = @()
        $arrayUnresolvedIdentities = foreach ($unresolvedIdentity in $htNonResolvedIdentities.keys) {
            if (-not [string]::IsNullOrEmpty($unresolvedIdentity)) {
                $unresolvedIdentity
            }
        }
        $arrayUnresolvedIdentitiesCount = $arrayUnresolvedIdentities.Count
        Write-Host "    $arrayUnresolvedIdentitiesCount unresolved identities that have a value"
        if ($arrayUnresolvedIdentitiesCount -gt 0) {

            $counterBatch = [PSCustomObject] @{ Value = 0 }
            $batchSize = 1000
            $ObjectBatch = $arrayUnresolvedIdentities | Group-Object -Property { [math]::Floor($counterBatch.Value++ / $batchSize) }
            $ObjectBatchCount = ($ObjectBatch | Measure-Object).Count
            $batchCnt = 0

            $script:htResolvedIdentities = @{}

            foreach ($batch in $ObjectBatch) {
                $batchCnt++

                $nonResolvedIdentitiesToCheck = '"{0}"' -f ($batch.Group.where({ testGuid $_ }) -join '","')
                Write-Host "     IdentitiesToCheck: Batch #$batchCnt/$($ObjectBatchCount) ($(($batch.Group).Count))"
                $uri = "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/directoryObjects/getByIds"
                $method = 'POST'
                $body = @"
                    {
                        "ids":[$($nonResolvedIdentitiesToCheck)]
                    }
"@

                function resolveIdentitiesRBAC($currentTask) {
                    $resolvedIdentities = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -body $body -currentTask $currentTask
                    $resolvedIdentitiesCount = $resolvedIdentities.Count
                    Write-Host "    $resolvedIdentitiesCount identities resolved"
                    if ($resolvedIdentitiesCount -gt 0) {

                        foreach ($resolvedIdentity in $resolvedIdentities) {

                            if (-not $htResolvedIdentities.($resolvedIdentity.id)) {

                                $script:htResolvedIdentities.($resolvedIdentity.id) = @{}
                                if ($resolvedIdentity.'@odata.type' -eq '#microsoft.graph.servicePrincipal' -or $resolvedIdentity.'@odata.type' -eq '#microsoft.graph.user') {
                                    if ($resolvedIdentity.'@odata.type' -eq '#microsoft.graph.servicePrincipal') {
                                        if ($resolvedIdentity.servicePrincipalType -eq 'ManagedIdentity') {
                                            $miType = 'unknown'
                                            foreach ($altName in $resolvedIdentity.alternativeNames) {
                                                if ($altName -like 'isExplicit=*') {
                                                    $splitAltName = $altName.split('=')
                                                    if ($splitAltName[1] -eq 'true') {
                                                        $miType = 'Usr'
                                                    }
                                                    if ($splitAltName[1] -eq 'false') {
                                                        $miType = 'Sys'
                                                    }
                                                }
                                            }
                                            $sptype = "MI $miType"
                                            $custObjectType = "ObjectType: SP $sptype, ObjectDisplayName: $($resolvedIdentity.displayName), ObjectSignInName: n/a, ObjectId: $($resolvedIdentity.id) (r)"
                                            $ht = @{}
                                            $ht.'ObjectType' = "SP $sptype"
                                            $ht.'ObjectDisplayName' = $($resolvedIdentity.displayName)
                                            $ht.'ObjectSignInName' = 'n/a'
                                            $ht.'ObjectId' = $resolvedIdentity.id
                                        }
                                        else {
                                            if ($resolvedIdentity.servicePrincipalType -eq 'Application') {
                                                $sptype = 'App'
                                                if ($resolvedIdentity.appOwnerOrganizationId -eq $azAPICallConf['checkContext'].Tenant.Id) {
                                                    $custObjectType = "ObjectType: SP $sptype INT, ObjectDisplayName: $($resolvedIdentity.displayName), ObjectSignInName: n/a, ObjectId: $($resolvedIdentity.id) (r)"
                                                    $ht = @{}
                                                    $ht.'ObjectType' = "SP $sptype INT"
                                                    $ht.'ObjectDisplayName' = $($resolvedIdentity.displayName)
                                                    $ht.'ObjectSignInName' = 'n/a'
                                                    $ht.'ObjectId' = $resolvedIdentity.id
                                                }
                                                else {
                                                    $custObjectType = "ObjectType: SP $sptype EXT, ObjectDisplayName: $($resolvedIdentity.displayName), ObjectSignInName: n/a, ObjectId: $($resolvedIdentity.id) (r)"
                                                    $ht = @{}
                                                    $ht.'ObjectType' = "SP $sptype EXT"
                                                    $ht.'ObjectDisplayName' = $($resolvedIdentity.displayName)
                                                    $ht.'ObjectSignInName' = 'n/a'
                                                    $ht.'ObjectId' = $resolvedIdentity.id
                                                }
                                            }
                                            else {
                                                Write-Host "* * * Unexpected IdentityType $($resolvedIdentity.servicePrincipalType)"
                                            }
                                        }
                                        $script:htResolvedIdentities.($resolvedIdentity.id).custObjectType = $custObjectType
                                        $script:htResolvedIdentities.($resolvedIdentity.id).obj = $resolvedIdentity
                                    }

                                    if ($resolvedIdentity.'@odata.type' -eq '#microsoft.graph.user') {
                                        if ($htParamteters.DoNotShowRoleAssignmentsUserData) {
                                            $hlpObjectDisplayName = 'scrubbed'
                                            $hlpObjectSigninName = 'scrubbed'
                                        }
                                        else {
                                            $hlpObjectDisplayName = $resolvedIdentity.displayName
                                            $hlpObjectSigninName = $resolvedIdentity.userPrincipalName
                                        }
                                        $custObjectType = "ObjectType: User, ObjectDisplayName: $hlpObjectDisplayName, ObjectSignInName: $hlpObjectSigninName, ObjectId: $($resolvedIdentity.id) (r)"
                                        $ht = @{}
                                        $ht.'ObjectType' = 'User'
                                        $ht.'ObjectDisplayName' = $hlpObjectDisplayName
                                        $ht.'ObjectSignInName' = $hlpObjectSigninName
                                        $ht.'ObjectId' = $resolvedIdentity.id

                                        $script:htResolvedIdentities.($resolvedIdentity.id).custObjectType = $custObjectType
                                        $script:htResolvedIdentities.($resolvedIdentity.id).obj = $resolvedIdentity
                                    }
                                    if (-not $htIdentitiesWithRoleAssignmentsUnique.($resolvedIdentity.id)) {
                                        $script:htIdentitiesWithRoleAssignmentsUnique.($resolvedIdentity.id) = @{}
                                        $script:htIdentitiesWithRoleAssignmentsUnique.($resolvedIdentity.id).details = $custObjectType
                                        $script:htIdentitiesWithRoleAssignmentsUnique.($resolvedIdentity.id).detailsJson = $ht
                                    }
                                }

                                if ($resolvedIdentity.'@odata.type' -ne '#microsoft.graph.user' -and $resolvedIdentity.'@odata.type' -ne '#microsoft.graph.servicePrincipal') {
                                    Write-Host "!!! * * * IdentityType '$($resolvedIdentity.'@odata.type')' was not considered by Azure Governance Visualizer - if you see this line, please file an issue on GitHub - thank you." -ForegroundColor Yellow
                                }
                            }
                        }
                    }
                }
                resolveIdentitiesRBAC -currentTask '    resolveObjectbyId RoleAssignment'
            }

            foreach ($rbac in $rbacAll.where( { $_.CreatedBy -notlike 'ObjectType*' -or $_.UpdatedBy -notlike 'ObjectType*' })) {
                if ($rbac.CreatedBy -notlike 'ObjectType*') {
                    if ($htResolvedIdentities.($rbac.CreatedBy)) {
                        $rbac.CreatedBy = $htResolvedIdentities.($rbac.CreatedBy).custObjectType
                    }
                    else {
                        if ($rbac.RoleAssignmentPIMAssignmentType -eq 'Eligible') {
                            $rbac.CreatedBy = ''
                        }
                        else {
                            if ([string]::IsNullOrEmpty($rbac.CreatedBy)) {
                                $rbac.CreatedBy = 'IsNullOrEmpty'
                            }
                            else {
                                $rbac.CreatedBy = "$($rbac.CreatedBy)"
                            }
                        }
                    }
                }
                if ($rbac.UpdatedBy -notlike 'ObjectType*') {
                    if ($htResolvedIdentities.($rbac.UpdatedBy)) {
                        $rbac.UpdatedBy = $htResolvedIdentities.($rbac.UpdatedBy).custObjectType
                    }
                    else {
                        if ($rbac.RoleAssignmentPIMAssignmentType -eq 'Eligible') {
                            $rbac.UpdatedBy = ''
                        }
                        else {
                            if ([string]::IsNullOrEmpty($rbac.UpdatedBy)) {
                                $rbac.UpdatedBy = 'IsNullOrEmpty'
                            }
                            else {
                                $rbac.UpdatedBy = "$($rbac.UpdatedBy)"
                            }
                        }
                    }
                }
            }
        }
    }
    $endUnResolvedIdentitiesCreatedBy = Get-Date
    Write-Host "   UnresolvedIdentities (createdBy) duration: $((New-TimeSpan -Start $startUnResolvedIdentitiesCreatedBy -End $endUnResolvedIdentitiesCreatedBy).TotalMinutes) minutes ($((New-TimeSpan -Start $startUnResolvedIdentitiesCreatedBy -End $endUnResolvedIdentitiesCreatedBy).TotalSeconds) seconds)"
    #endregion nonResolvedIdentities

    $startRBACAllGrouping = Get-Date
    $script:rbacAllGroupedBySubscription = $rbacAll | Group-Object -Property SubscriptionId
    $script:rbacAllGroupedByManagementGroup = $rbacAll | Group-Object -Property MgId
    $endRBACAllGrouping = Get-Date
    Write-Host "   RBACAll Grouping duration: $((New-TimeSpan -Start $startRBACAllGrouping -End $endRBACAllGrouping).TotalMinutes) minutes ($((New-TimeSpan -Start $startRBACAllGrouping -End $endRBACAllGrouping).TotalSeconds) seconds)"
    $endCreateRBACAll = Get-Date
    Write-Host "   CreateRBACAll duration: $((New-TimeSpan -Start $startCreateRBACAll -End $endCreateRBACAll).TotalMinutes) minutes ($((New-TimeSpan -Start $startCreateRBACAll -End $endCreateRBACAll).TotalSeconds) seconds)"
    #endregion tenantSummaryPre

    showMemoryUsage

    #region tenantSummaryPolicy
    $htmlTenantSummary = [System.Text.StringBuilder]::new()
    [void]$htmlTenantSummary.AppendLine(@'
<button type="button" class="collapsible" id="tenantSummaryPolicy"><hr class="hr-textPolicy" data-content="Policy" /></button>
<div class="content TenantSummaryContent">
<i class="padlx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Anything which can help you learn Azure Policy</span> <a class="externallink" href="https://github.com/globalbao/awesome-azure-policy" target="_blank" rel="noopener">GitHub <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
'@)

    #region SUMMARYcustompolicies
    $startCustPolLoop = Get-Date
    Write-Host '  processing TenantSummary Custom Policy definitions'

    $script:customPoliciesDetailed = [System.Collections.ArrayList]@()
    $script:tenantPoliciesDetailed = [System.Collections.ArrayList]@()
    foreach ($tenantPolicy in (($htCacheDefinitionsPolicy).Values | Sort-Object @{Expression = { $_.DisplayName } }, @{Expression = { $_.PolicyDefinitionId } })) {

        #uniqueAssignments
        $policyUniqueAssignments = $null
        if ($htPolicyWithAssignmentsBase.($tenantPolicy.PolicyDefinitionId)) {
            $policyUniqueAssignments = $htPolicyWithAssignmentsBase.($tenantPolicy.PolicyDefinitionId).Assignments | Sort-Object
            $policyUniqueAssignmentsCount = ($policyUniqueAssignments).count
        }
        else {
            $policyUniqueAssignmentsCount = 0
        }

        $uniqueAssignments = $null
        if ($policyUniqueAssignmentsCount -gt 0) {
            $policyUniqueAssignmentsList = "($($policyUniqueAssignments -join "$CsvDelimiterOpposite "))"
            $uniqueAssignments = "$policyUniqueAssignmentsCount $policyUniqueAssignmentsList"
        }
        else {
            $uniqueAssignments = $policyUniqueAssignmentsCount
        }

        #PolicyUsedInPolicySet
        $usedInPolicySet4JSON = $null
        $usedInPolicySet = 0
        $usedInPolicySet4CSV = ''
        $usedInPolicySetCount = 0
        if (($htPoliciesUsedInPolicySets).($tenantPolicy.PolicyDefinitionId)) {
            $hlpPolicySetUsed = ($htPoliciesUsedInPolicySets).($tenantPolicy.PolicyDefinitionId)
            $usedInPolicySet4JSON = $hlpPolicySetUsed.PolicySetIdOnly | Sort-Object
            $usedInPolicySet = "$(($hlpPolicySetUsed.PolicySet | Sort-Object) -join "$CsvDelimiterOpposite ")"
            $usedInPolicySet4CSV = "$(($hlpPolicySetUsed.PolicySet4CSV | Sort-Object) -join "$CsvDelimiterOpposite ")"
            $usedInPolicySetCount = ($hlpPolicySetUsed.PolicySet).Count
        }

        #policyEffect
        if ($tenantPolicy.effectDefaultValue -ne 'n/a') {
            $effect = "Default: $($tenantPolicy.effectDefaultValue); Allowed: $($tenantPolicy.effectAllowedValue)"
        }
        elseif ($tenantPolicy.effectFixedValue -ne 'n/a') {
            $effect = "Fixed: $($tenantPolicy.effectFixedValue)"
        }
        else {
            $effect = 'n/a'
        }

        if (($tenantPolicy.RoleDefinitionIds) -ne 'n/a') {
            $policyRoleDefinitionsArray = @()
            $policyRoleDefinitionsArray = foreach ($roleDefinitionId in $tenantPolicy.RoleDefinitionIds | Sort-Object) {
                if (($htCacheDefinitionsRole).($roleDefinitionId -replace '.*/').LinkToAzAdvertizer) {
                    ($htCacheDefinitionsRole).($roleDefinitionId -replace '.*/').LinkToAzAdvertizer
                }
                else {
                    ($htCacheDefinitionsRole).($roleDefinitionId -replace '.*/').Name -replace '<', '&lt;' -replace '>', '&gt;'
                }
            }
            $policyRoleDefinitionsClearArray = @()
            $policyRoleDefinitionsClearArray = foreach ($roleDefinitionId in $tenantPolicy.RoleDefinitionIds | Sort-Object) {
                ($htCacheDefinitionsRole).($roleDefinitionId -replace '.*/').Name
            }
            $policyRoleDefinitions = $policyRoleDefinitionsArray -join "$CsvDelimiterOpposite "
            $policyRoleDefinitionsClear = $policyRoleDefinitionsClearArray -join "$CsvDelimiterOpposite "
        }
        else {
            $policyRoleDefinitions = 'n/a'
            $policyRoleDefinitionsClear = 'n/a'
        }

        # if ($tenantPolicy.Json.properties.metadata.version) {
        #     $policyVersion = $tenantPolicy.Json.properties.metadata.version
        # }
        # else {
        #     $policyVersion = 'n/a'
        # }

        if ($tenantPolicy.Type -eq 'Custom') {

            $createdOn = ''
            $createdBy = ''
            $createdByJson = ''
            $updatedOn = ''
            $updatedBy = ''
            $updatedByJson = ''
            if ($tenantPolicy.Json.properties.metadata.createdOn) {
                $createdOn = $tenantPolicy.Json.properties.metadata.createdOn
            }
            if ($tenantPolicy.Json.properties.metadata.createdBy) {
                $createdBy = $tenantPolicy.Json.properties.metadata.createdBy
                $createdByJson = $createdBy
                if ($createdBy -ne 'n/a') {
                    if ($htIdentitiesWithRoleAssignmentsUnique.($createdBy)) {
                        $createdByJson = $htIdentitiesWithRoleAssignmentsUnique.($createdBy).detailsJson
                        $createdBy = $htIdentitiesWithRoleAssignmentsUnique.($createdBy).details

                    }
                }
            }
            if ($tenantPolicy.Json.properties.metadata.updatedOn) {
                $updatedOn = $tenantPolicy.Json.properties.metadata.updatedOn
            }
            if ($tenantPolicy.Json.properties.metadata.updatedBy) {
                $updatedBy = $tenantPolicy.Json.properties.metadata.updatedBy
                $updatedByJson = $updatedBy
                if ($updatedBy -ne 'n/a') {
                    if ($htIdentitiesWithRoleAssignmentsUnique.($updatedBy)) {
                        $updatedByJson = $htIdentitiesWithRoleAssignmentsUnique.($updatedBy).detailsJson
                        $updatedBy = $htIdentitiesWithRoleAssignmentsUnique.($updatedBy).details

                    }
                }
            }

            $null = $script:customPoliciesDetailed.Add([PSCustomObject]@{
                    Type                   = 'Custom'
                    ScopeMGLevel           = $tenantPolicy.ScopeMGLevel
                    Scope                  = $tenantPolicy.ScopeMgSub
                    ScopeId                = $tenantPolicy.ScopeId
                    PolicyDisplayName      = $tenantPolicy.DisplayName
                    PolicyDefinitionName   = $tenantPolicy.Name
                    PolicyDefinitionId     = $tenantPolicy.PolicyDefinitionId
                    PolicyVersion          = $tenantPolicy.Version
                    PolicyEffect           = $effect
                    PolicyCategory         = $tenantPolicy.Category
                    RoleDefinitions        = $policyRoleDefinitions
                    RoleDefinitionsClear   = $policyRoleDefinitionsClear
                    UniqueAssignments      = $uniqueAssignments
                    UsedInPolicySetsCount  = $usedInPolicySetCount
                    UsedInPolicySets       = $usedInPolicySet
                    UsedInPolicySet4CSV    = $usedInPolicySet4CSV
                    CreatedOn              = $createdOn
                    CreatedBy              = $createdBy
                    UpdatedOn              = $updatedOn
                    UpdatedBy              = $updatedBy
                    ALZ                    = $tenantPolicy.ALZ
                    ALZState               = $tenantPolicy.ALZState
                    ALZLatestVer           = $tenantPolicy.ALZLatestVer
                    ALZIdentificationLevel = $tenantPolicy.ALZIdentificationLevel
                    ALZPolicyName          = $tenantPolicy.ALZPolicyName
                    #Json                  = [string]($tenantPolicy.Json | ConvertTo-Json -Depth 99 -EnumsAsStrings)
                })

            $null = $script:tenantPoliciesDetailed.Add([PSCustomObject]@{
                    Type                   = 'Custom'
                    ScopeMGLevel           = $tenantPolicy.ScopeMGLevel
                    Scope                  = $tenantPolicy.ScopeMgSub
                    ScopeId                = $tenantPolicy.ScopeId
                    PolicyDisplayName      = $tenantPolicy.DisplayName
                    PolicyDefinitionName   = $tenantPolicy.Name
                    PolicyDefinitionId     = $tenantPolicy.PolicyDefinitionId
                    PolicyVersion          = $tenantPolicy.Version
                    PolicyEffect           = $effect
                    PolicyCategory         = $tenantPolicy.Category
                    UniqueAssignmentsCount = $policyUniqueAssignmentsCount
                    UniqueAssignments      = $policyUniqueAssignments
                    UsedInPolicySetsCount  = $usedInPolicySetCount
                    UsedInPolicySets       = $usedInPolicySet
                    UsedInPolicySet4CSV    = $usedInPolicySet4CSV
                    UsedInPolicySet4JSON   = $usedInPolicySet4JSON
                    CreatedOn              = $createdOn
                    CreatedBy              = $createdBy
                    CreatedByJson          = $createdByJson
                    UpdatedOn              = $updatedOn
                    UpdatedBy              = $updatedBy
                    UpdatedByJson          = $updatedByJson
                    #Json                  = [string]($tenantPolicy.Json | ConvertTo-Json -Depth 99 -EnumsAsStrings)
                    Json                   = $tenantPolicy.Json
                    ALZ                    = $tenantPolicy.ALZ
                    ALZState               = $tenantPolicy.ALZState
                    ALZLatestVer           = $tenantPolicy.ALZLatestVer
                    ALZIdentificationLevel = $tenantPolicy.ALZIdentificationLevel
                    ALZPolicyName          = $tenantPolicy.ALZPolicyName
                })
        }
        else {
            $null = $script:tenantPoliciesDetailed.Add([PSCustomObject]@{
                    Type                   = $tenantPolicy.Type
                    ScopeMGLevel           = $null
                    Scope                  = $null
                    ScopeId                = $null
                    PolicyDisplayName      = $tenantPolicy.DisplayName
                    PolicyDefinitionName   = $tenantPolicy.Name
                    PolicyDefinitionId     = $tenantPolicy.PolicyDefinitionId
                    PolicyVersion          = $tenantPolicy.Version
                    PolicyEffect           = $effect
                    PolicyCategory         = $tenantPolicy.Category
                    UniqueAssignmentsCount = $policyUniqueAssignmentsCount
                    UniqueAssignments      = $policyUniqueAssignments
                    UsedInPolicySetsCount  = $usedInPolicySetCount
                    UsedInPolicySets       = $usedInPolicySet
                    UsedInPolicySet4CSV    = $usedInPolicySet4CSV
                    UsedInPolicySet4JSON   = $usedInPolicySet4JSON
                    CreatedOn              = $null
                    CreatedBy              = $null
                    CreatedByJson          = $null
                    UpdatedOn              = $null
                    UpdatedBy              = $null
                    UpdatedByJson          = $null
                    #Json                  = [string]($tenantPolicy.Json | ConvertTo-Json -Depth 99 -EnumsAsStrings)
                    Json                   = $tenantPolicy.Json
                    ALZ                    = $tenantPolicy.ALZ
                    ALZState               = $tenantPolicy.ALZState
                    ALZLatestVer           = $tenantPolicy.ALZLatestVer
                    ALZIdentificationLevel = $tenantPolicy.ALZIdentificationLevel
                    ALZPolicyName          = $tenantPolicy.ALZPolicyName
                })
        }
    }

    if (-not $NoCsvExport) {
        $csvFilename = "$($filename)_PolicyDefinitions"
        Write-Host "   Exporting PolicyDefinitions CSV '$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv'"
        $tenantPoliciesDetailed | Sort-Object -Property Type, Scope, PolicyDefinitionId | Select-Object -ExcludeProperty UniqueAssignments, UsedInPolicySets, UsedInPolicySet4JSON, CreatedByJson, UpdatedByJson, Json | Export-Csv -Encoding utf8 -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter $csvDelimiter -NoTypeInformation
    }

    if ($getMgParentName -eq 'Tenant Root') {

        if ($tenantCustomPoliciesCount -gt 0) {
            $tfCount = $tenantCustomPoliciesCount
            $htmlTableId = 'TenantSummary_customPolicies'
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_customPolicies"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policy definitions ($scopeNamingSummary)</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>Scope Id</th>
<th>Policy DisplayName</th>
<th>Policy Name</th>
<th>PolicyId</th>
<th>Category</th>
<th>ALZ</th>
<th>Effect</th>
<th>Role definitions</th>
<th>Unique assignments</th>
<th>Used in PolicySets</th>
<th>CreatedOn</th>
<th>CreatedBy</th>
<th>UpdatedOn</th>
<th>UpdatedBy</th>
</tr>
</thead>
<tbody>
"@)
            $htmlSUMMARYcustompolicies = $null
            $htmlSUMMARYcustompolicies = foreach ($customPolicy in ($customPoliciesDetailed | Sort-Object @{Expression = { $_.PolicyDisplayName } }, @{Expression = { $_.PolicyDefinitionId } })) {
                if ($custompolicy.UsedInPolicySetsCount -gt 0) {
                    $customPolicyUsedInPolicySets = "$($customPolicy.UsedInPolicySetsCount) ($($customPolicy.UsedInPolicySets))"
                }
                else {
                    $customPolicyUsedInPolicySets = $($customPolicy.UsedInPolicySetsCount)
                }
                @"
<tr>
<td class="breakwordall">$($customPolicy.Scope)</td>
<td class="breakwordall">$($customPolicy.ScopeId)</td>
<td class="breakwordall">$($customPolicy.PolicyDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($customPolicy.PolicyDefinitionName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($customPolicy.PolicyDefinitionId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($customPolicy.PolicyCategory -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($customPolicy.ALZ)</td>
<td class="breakwordall">$($customPolicy.PolicyEffect)</td>
<td class="breakwordall">$($customPolicy.RoleDefinitions)</td>
<td class="breakwordall">$($customPolicy.UniqueAssignments -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($customPolicyUsedInPolicySets)</td>
<td class="breakwordall">$($customPolicy.CreatedOn)</td>
<td class="breakwordall">$($customPolicy.CreatedBy)</td>
<td class="breakwordall">$($customPolicy.UpdatedOn)</td>
<td class="breakwordall">$($customPolicy.UpdatedBy)</td>
</tr>
"@
            }

            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYcustompolicies)
            $htmlTenantSummary | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
            $htmlTenantSummary = [System.Text.StringBuilder]::new()
            [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100
            },
            no_results_message: true,
            col_widths: ['', '150px', '150px', '150px', '250px', '150px', '', '150px', '150px', '150px', '250px', '', '150px', '', '150px'],
            col_0: 'select',
            col_6: 'select',
            locale: 'en-US',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'date',
                'caseinsensitivestring',
                'date',
                'caseinsensitivestring'
            ],
            extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@"
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $tenantCustomPoliciesCount Custom Policy definitions ($scopeNamingSummary)</p>
"@)
        }
    }
    #SUMMARY NOT tenant total custom policy definitions
    else {
        $faimage = "<i class=`"fa fa-check-circle`" aria-hidden=`"true`"></i>"

        if ($tenantCustomPoliciesCount -gt 0) {
            $tfCount = $tenantCustomPoliciesCount
            $customPoliciesInScopeArray = [System.Collections.ArrayList]@()
            foreach ($customPolicy in ($tenantCustomPolicies | Sort-Object @{Expression = { $_.DisplayName } }, @{Expression = { $_.PolicyDefinitionId } })) {
                if (($customPolicy.PolicyDefinitionId) -like '/providers/Microsoft.Management/managementGroups/*') {
                    $policyScopedMgSub = $customPolicy.PolicyDefinitionId -replace '/providers/Microsoft.Management/managementGroups/', '' -replace '/.*'
                    if ($mgsAndSubs.MgId -contains ($policyScopedMgSub)) {
                        $null = $customPoliciesInScopeArray.Add($customPolicy)
                    }
                }

                if (($customPolicy.PolicyDefinitionId) -like '/subscriptions/*') {
                    $policyScopedMgSub = $customPolicy.PolicyDefinitionId -replace '/subscriptions/', '' -replace '/.*'
                    if ($mgsAndSubs.SubscriptionId -contains ($policyScopedMgSub)) {
                        $null = $customPoliciesInScopeArray.Add($customPolicy)
                    }
                    else {
                        #Write-Host "$policyScopedMgSub NOT in Scope"
                    }
                }
            }
            $customPoliciesFromSuperiorMGs = $tenantCustomPoliciesCount - (($customPoliciesInScopeArray).count)
        }
        else {
            $customPoliciesFromSuperiorMGs = '0'
        }

        if ($tenantCustomPoliciesCount -gt 0) {
            $tfCount = $tenantCustomPoliciesCount
            $htmlTableId = 'TenantSummary_customPolicies'
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_customPolicies"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policy definitions $scopeNamingSummary ($customPoliciesFromSuperiorMGs from superior scopes)</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>Scope Id</th>
<th>Policy DisplayName</th>
<th>Policy Name</th>
<th>PolicyId</th>
<th>Category</th>
<th>ALZ</th>
<th>Policy Effect</th>
<th>Role definitions</th>
<th>Unique assignments</th>
<th>Used in PolicySets</th>
<th>CreatedOn</th>
<th>CreatedBy</th>
<th>UpdatedOn</th>
<th>UpdatedBy</th>
</tr>
</thead>
<tbody>
"@)
            $htmlSUMMARYcustompolicies = $null
            $htmlSUMMARYcustompolicies = foreach ($customPolicy in ($customPoliciesDetailed | Sort-Object @{Expression = { $_.PolicyDisplayName } }, @{Expression = { $_.PolicyDefinitionId } })) {
                if ($custompolicy.UsedInPolicySetsCount -gt 0) {
                    $customPolicyUsedInPolicySets = "$($customPolicy.UsedInPolicySetsCount) ($($customPolicy.UsedInPolicySets))"
                }
                else {
                    $customPolicyUsedInPolicySets = $($customPolicy.UsedInPolicySetsCount)
                }
                @"
<tr>
<td class="breakwordall">$($customPolicy.Scope)</td>
<td class="breakwordall">$($customPolicy.ScopeId)</td>
<td class="breakwordall">$($customPolicy.PolicyDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($customPolicy.PolicyDefinitionName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($customPolicy.PolicyDefinitionId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($customPolicy.PolicyCategory -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($customPolicy.ALZ)</td>
<td class="breakwordall">$($customPolicy.PolicyEffect)</td>
<td class="breakwordall">$($customPolicy.RoleDefinitions)</td>
<td class="breakwordall">$($customPolicy.UniqueAssignments -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($customPolicyUsedInPolicySets)</td>
<td class="breakwordall">$($customPolicy.CreatedOn)</td>
<td class="breakwordall">$($customPolicy.CreatedBy)</td>
<td class="breakwordall">$($customPolicy.UpdatedOn)</td>
<td class="breakwordall">$($customPolicy.UpdatedBy)</td>
</tr>
"@
            }
            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYcustompolicies)
            [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: { delay: 1100 },
            no_results_message: true,
            col_widths: ['50px', '150px', '150px', '150px', '250px', '150px', '50px', '150px', '150px', '150px', '250px', '75px', '150px', '75px', '150px'],
            col_0: 'select',
            col_6: 'select',
            locale: 'en-US',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'date',
                'caseinsensitivestring',
                'date',
                'caseinsensitivestring'
            ],
            extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@"
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $tenantCustomPoliciesCount Custom Policy definitions ($scopeNamingSummary)</p>
"@)
        }
    }
    $endCustPolLoop = Get-Date
    Write-Host "   Custom Policy processing duration: $((New-TimeSpan -Start $startCustPolLoop -End $endCustPolLoop).TotalMinutes) minutes ($((New-TimeSpan -Start $startCustPolLoop -End $endCustPolLoop).TotalSeconds) seconds)"
    #endregion SUMMARYcustompolicies

    $startcustpolorph = Get-Date
    #region SUMMARYCustomPoliciesOrphandedTenantRoot
    Write-Host '  processing TenantSummary Custom Policy definitions orphaned'
    if ($getMgParentName -eq 'Tenant Root') {
        $customPoliciesOrphaned = [System.Collections.ArrayList]@()
        foreach ($customPolicyAll in $tenantCustomPolicies) {
            if (($policyPolicyBaseQueryUniqueCustomDefinitions).count -eq 0) {
                $null = $customPoliciesOrphaned.Add($customPolicyAll)
            }
            else {
                if ($policyPolicyBaseQueryUniqueCustomDefinitions -notcontains ($customPolicyAll.PolicyDefinitionId)) {
                    $null = $customPoliciesOrphaned.Add($customPolicyAll)
                }
            }
        }

        $arrayCustomPoliciesOrphanedFinal = [System.Collections.ArrayList]@()
        foreach ($customPolicyOrphaned in $customPoliciesOrphaned) {
            if ($customPolicyOrphaned.Id) {
                if (-not $htPoliciesUsedInPolicySets.($customPolicyOrphaned.Id)) {
                    $null = $arrayCustomPoliciesOrphanedFinal.Add($customPolicyOrphaned)
                }
            }
            else {
                Write-Host '!!!!!!!!!!!!!!!!!!!!!  no Id'
                Write-Host '## all:'
                $customPoliciesOrphaned
                Write-Host '## customPolicyOrphaned no Id:'
                $customPolicyOrphaned
            }
        }

        #rgchange
        $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()
        foreach ($customPolicyOrphanedFinal in $arrayCustomPoliciesOrphanedFinal) {
            if (($htCacheAssignmentsPolicyOnResourceGroupsAndResources).values.properties.PolicyDefinitionId -notcontains $customPolicyOrphanedFinal.PolicyDefinitionId) {
                $null = $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups.Add($customPolicyOrphanedFinal)
            }
        }

        if (($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups).count -gt 0) {
            $tfCount = ($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups).count
            $htmlTableId = 'TenantSummary_customPoliciesOrphaned'
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_customPoliciesOrphaned"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups).count) Orphaned Custom Policy definitions ($scopeNamingSummary)</span> <abbr title="Policy is not used in a PolicySet &#13;AND &#13;Policy has no assignments (including ResourceGroups)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Policy DisplayName</th>
<th>PolicyId</th>
</tr>
</thead>
<tbody>
"@)
            $htmlSUMMARYCustomPoliciesOrphandedTenantRoot = $null
            $htmlSUMMARYCustomPoliciesOrphandedTenantRoot = foreach ($customPolicyOrphaned in $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | Sort-Object @{Expression = { $_.PolicyDefinitionId } }, @{Expression = { $_.DisplayName } }) {
                @"
<tr>
<td>$($customPolicyOrphaned.DisplayName)</td>
<td>$($customPolicyOrphaned.PolicyDefinitionId)</td>
</tr>
"@
            }
            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYCustomPoliciesOrphandedTenantRoot)
            [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@"
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $(($customPoliciesOrphaned).count) Orphaned Custom Policy definitions ($scopeNamingSummary)</p>
"@)
        }
    }
    #SUMMARY Custom Policy definitions Orphanded NOT TenantRoot
    else {
        $customPoliciesOrphaned = [System.Collections.ArrayList]@()
        foreach ($customPolicyAll in $tenantCustomPolicies) {
            if (($policyPolicyBaseQueryUniqueCustomDefinitions).count -eq 0) {
                $null = $customPoliciesOrphaned.Add($customPolicyAll)
            }
            else {
                if ($policyPolicyBaseQueryUniqueCustomDefinitions -notcontains ($customPolicyAll.PolicyDefinitionId)) {
                    $null = $customPoliciesOrphaned.Add($customPolicyAll)
                }
            }
        }

        $customPoliciesOrphanedInScopeArray = [System.Collections.ArrayList]@()
        foreach ($customPolicyOrphaned in  $customPoliciesOrphaned) {
            $hlpOrphanedInScope = $customPolicyOrphaned
            if (($hlpOrphanedInScope.PolicyDefinitionId) -like '/providers/Microsoft.Management/managementGroups/*') {
                $policyScopedMgSub = $hlpOrphanedInScope.PolicyDefinitionId -replace '/providers/Microsoft.Management/managementGroups/' -replace '/.*'
                if ($mgsAndSubs.MgId -contains ($policyScopedMgSub)) {
                    $null = $customPoliciesOrphanedInScopeArray.Add($hlpOrphanedInScope)
                }
            }
            if (($hlpOrphanedInScope.PolicyDefinitionId) -like '/subscriptions/*') {
                $policyScopedMgSub = $hlpOrphanedInScope.PolicyDefinitionId -replace '/subscriptions/' -replace '/.*'
                if ($mgsAndSubs.SubscriptionId -contains ($policyScopedMgSub)) {
                    $null = $customPoliciesOrphanedInScopeArray.Add($hlpOrphanedInScope)
                }
            }
        }

        $arrayCustomPoliciesOrphanedFinal = [System.Collections.ArrayList]@()
        foreach ($customPolicyOrphanedInScopeArray in $customPoliciesOrphanedInScopeArray) {
            if (-not $htPoliciesUsedInPolicySets.($customPolicyOrphanedInScopeArray.Id)) {
                $null = $arrayCustomPoliciesOrphanedFinal.Add($customPolicyOrphanedInScopeArray)
            }
        }

        $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()
        foreach ($customPolicyOrphanedFinal in $arrayCustomPoliciesOrphanedFinal) {
            if (($htCacheAssignmentsPolicyOnResourceGroupsAndResources).values.properties.PolicyDefinitionId -notcontains $customPolicyOrphanedFinal.PolicyDefinitionId) {
                $null = $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups.Add($customPolicyOrphanedFinal)
            }
        }

        if (($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups).count -gt 0) {
            $tfCount = ($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups).count
            $htmlTableId = 'TenantSummary_customPoliciesOrphaned'
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_customPoliciesOrphaned"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups).count) Orphaned Custom Policy definitions ($scopeNamingSummary)</span> <abbr title="Policy is not used in a PolicySet &#13;AND &#13;Policy has no assignments (including ResourceGroups) &#13;Note: Policies from superior scopes are not evaluated"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Policy DisplayName</th>
<th>PolicyId</th>
</tr>
</thead>
<tbody>
"@)
            $htmlSUMMARYCustomPoliciesOrphandedTenantRoot = $null
            $htmlSUMMARYCustomPoliciesOrphandedTenantRoot = foreach ($customPolicyOrphaned in $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | Sort-Object @{Expression = { $_.PolicyDefinitionId } }, @{Expression = { $_.DisplayName } }) {
                @"
<tr>
<td>$($customPolicyOrphaned.DisplayName)</td>
<td>$($customPolicyOrphaned.PolicyDefinitionId)</td>
</tr>
"@
            }
            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYCustomPoliciesOrphandedTenantRoot)
            [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@"
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups.count) Orphaned Custom Policy definitions ($scopeNamingSummary)</p>
"@)
        }
    }
    #endregion SUMMARYCustomPoliciesOrphandedTenantRoot
    $endcustpolorph = Get-Date
    Write-Host "   processing TenantSummary Custom Policy definitions orphaned duration: $((New-TimeSpan -Start $startcustpolorph -End $endcustpolorph).TotalSeconds) seconds"

    #region SUMMARYtenanttotalcustompolicySets
    $startCustPolSetLoop = Get-Date
    Write-Host '  processing TenantSummary Custom PolicySet definitions'
    $script:customPolicySetsDetailed = [System.Collections.ArrayList]@()
    $script:tenantPolicySetsDetailed = [System.Collections.ArrayList]@()
    $custompolicySetsInScopeArray = [System.Collections.ArrayList]@()
    foreach ($tenantPolicySet in ($tenantAllPolicySets)) {

        $policySetUniqueAssignments = $policyPolicySetBaseQueryUniqueAssignments.where( { $_.PolicyDefinitionId -eq $tenantPolicySet.Id }).PolicyAssignmentId
        $policySetUniqueAssignmentsArray = [System.Collections.ArrayList]@()
        foreach ($policySetUniqueAssignment in $policySetUniqueAssignments) {
            $null = $policySetUniqueAssignmentsArray.Add($policySetUniqueAssignment)
        }
        $policySetUniqueAssignmentsCount = ($policySetUniqueAssignments).count
        if ($policySetUniqueAssignmentsCount -gt 0) {
            $policySetUniqueAssignmentsList = "($($policySetUniqueAssignmentsArray -join "$CsvDelimiterOpposite "))"
            $policySetUniqueAssignment = "$policySetUniqueAssignmentsCount $policySetUniqueAssignmentsList"
        }
        else {
            $policySetUniqueAssignment = $policySetUniqueAssignmentsCount
        }

        $policySetPoliciesArray = [System.Collections.ArrayList]@()
        $policySetPoliciesArrayClean = [System.Collections.ArrayList]@()
        $policySetPoliciesArrayIdOnly = [System.Collections.ArrayList]@()
        $policySetPoliciesBuiltinArrayIdOnlyCSV = [System.Collections.ArrayList]@()
        $policySetPoliciesStaticArrayIdOnlyCSV = [System.Collections.ArrayList]@()
        $policySetPoliciesCustomArrayIdOnlyCSV = [System.Collections.ArrayList]@()
        foreach ($policyPolicySet in $tenantPolicySet.PolicySetPolicyIds) {
            $hlpPolicyDef = ($htCacheDefinitionsPolicy).($policyPolicySet)

            if ($hlpPolicyDef.Type -eq 'Builtin' -or $hlpPolicyDef.Type -eq 'Static') {
                $null = $policySetPoliciesArray.Add("$($hlpPolicyDef.LinkToAzAdvertizer) ($policyPolicySet)")
                if ($hlpPolicyDef.Type -eq 'Builtin') {
                    $null = $policySetPoliciesBuiltinArrayIdOnlyCSV.Add($policyPolicySet -replace '/providers/microsoft.authorization/policydefinitions/')
                }
                if ($hlpPolicyDef.Type -eq 'Static') {
                    $null = $policySetPoliciesStaticArrayIdOnlyCSV.Add($policyPolicySet -replace '/providers/microsoft.authorization/policydefinitions/')
                }
            }
            else {
                $null = $policySetPoliciesCustomArrayIdOnlyCSV.Add($policyPolicySet)
                if ($hlpPolicyDef.DisplayName) {
                    if ([string]::IsNullOrEmpty($hlpPolicyDef.DisplayName)) {
                        $displayName = 'noDisplayNameGiven'
                    }
                    else {
                        $displayName = $hlpPolicyDef.DisplayName
                    }
                }
                else {
                    $displayName = 'noDisplayNameGiven'
                }
                $null = $policySetPoliciesArray.Add("<b>$($displayName -replace '<', '&lt;' -replace '>', '&gt;')</b> ($policyPolicySet)")
            }

            if ($hlpPolicyDef.DisplayName) {
                if ([string]::IsNullOrEmpty($hlpPolicyDef.DisplayName)) {
                    $displayName = 'noDisplayNameGiven'
                }
                else {
                    $displayName = $hlpPolicyDef.DisplayName
                }
            }
            else {
                $displayName = 'noDisplayNameGiven'
            }

            $null = $policySetPoliciesArrayClean.Add("$($displayName) ($policyPolicySet)")
            $null = $policySetPoliciesArrayIdOnly.Add($policyPolicySet)
        }

        if ($policySetPoliciesArrayIdOnly.Count -eq 0) {
            $policySetPoliciesArrayIdOnly = $null
        }

        if ($policySetPoliciesBuiltinArrayIdOnlyCSV.Count -eq 0) {
            $policySetPoliciesBuiltinArrayIdOnlyCSV = $null
        }
        if ($policySetPoliciesStaticArrayIdOnlyCSV.Count -eq 0) {
            $policySetPoliciesStaticArrayIdOnlyCSV = $null
        }
        if ($policySetPoliciesCustomArrayIdOnlyCSV.Count -eq 0) {
            $policySetPoliciesCustomArrayIdOnlyCSV = $null
        }

        $policySetPoliciesCount = ($policySetPoliciesArray).count
        if ($policySetPoliciesCount -gt 0) {
            $policiesUsed = "$policySetPoliciesCount ($(($policySetPoliciesArray | Sort-Object) -join "$CsvDelimiterOpposite "))"
            $policiesUsedClean = "$policySetPoliciesCount ($(($policySetPoliciesArrayClean | Sort-Object) -join "$CsvDelimiterOpposite "))"
        }
        else {
            $policiesUsed = '0 really?'
            $policiesUsedClean = '0 really?'
        }

        if ($tenantPolicySet.Json.properties.metadata.version) {
            $policySetVersion = $tenantPolicySet.Json.properties.metadata.version
        }
        else {
            $policySetVersion = 'n/a'
        }

        if ($tenantPolicySet.Type -eq 'Custom') {
            #inscopeOrNot
            if ($getMgParentName -ne 'Tenant Root') {
                if ($mgsAndSubs.MgId -contains ($tenantPolicySet.ScopeId)) {
                    $null = $custompolicySetsInScopeArray.Add($tenantPolicySet)
                }
                if ($mgsAndSubs.SubscriptionId -contains ($tenantPolicySet.ScopeId)) {
                    $null = $custompolicySetsInScopeArray.Add($tenantPolicySet)
                }
            }

            $createdOn = ''
            $createdBy = ''
            $createdByJson = ''
            $updatedOn = ''
            $updatedBy = ''
            $updatedByJson = ''
            if ($tenantPolicySet.Json.properties.metadata.createdOn) {
                $createdOn = $tenantPolicySet.Json.properties.metadata.createdOn
            }
            if ($tenantPolicySet.Json.properties.metadata.createdBy) {
                $createdBy = $tenantPolicySet.Json.properties.metadata.createdBy
                $createdByJson = $createdBy
                if ($htIdentitiesWithRoleAssignmentsUnique.($createdBy)) {
                    $createdByJson = $htIdentitiesWithRoleAssignmentsUnique.($createdBy).detailsJson
                    $createdBy = $htIdentitiesWithRoleAssignmentsUnique.($createdBy).details
                }
            }
            if ($tenantPolicySet.Json.properties.metadata.updatedOn) {
                $updatedOn = $tenantPolicySet.Json.properties.metadata.updatedOn
            }
            if ($tenantPolicySet.Json.properties.metadata.updatedBy) {
                $updatedBy = $tenantPolicySet.Json.properties.metadata.updatedBy
                $updatedByJson = $updatedBy
                if ($htIdentitiesWithRoleAssignmentsUnique.($updatedBy)) {
                    $updatedByJson = $htIdentitiesWithRoleAssignmentsUnique.($updatedBy).detailsJson
                    $updatedBy = $htIdentitiesWithRoleAssignmentsUnique.($updatedBy).details

                }
            }

            $null = $script:customPolicySetsDetailed.Add([PSCustomObject]@{
                    Type                    = 'Custom'
                    ScopeMGLevel            = $tenantPolicySet.ScopeMGLevel
                    Scope                   = $tenantPolicySet.ScopeMgSub
                    ScopeId                 = $tenantPolicySet.ScopeId
                    PolicySetDisplayName    = $tenantPolicySet.DisplayName
                    PolicySetDefinitionName = $tenantPolicySet.Name
                    PolicySetDefinitionId   = $tenantPolicySet.PolicyDefinitionId
                    PolicySetCategory       = $tenantPolicySet.Category
                    UniqueAssignments       = $policySetUniqueAssignment
                    PoliciesUsed            = $policiesUsed
                    PoliciesUsedClean       = $policiesUsedClean
                    CreatedOn               = $createdOn
                    CreatedBy               = $createdBy
                    UpdatedOn               = $updatedOn
                    UpdatedBy               = $updatedBy
                    #Json                  = [string]($tenantPolicySet.Json | ConvertTo-Json -Depth 99 -EnumsAsStrings)
                    ALZ                     = $tenantPolicySet.ALZ
                    ALZState                = $tenantPolicySet.ALZState
                    ALZLatestVer            = $tenantPolicySet.ALZLatestVer
                    ALZIdentificationLevel  = $tenantPolicySet.ALZIdentificationLevel
                    ALZPolicySetName        = $tenantPolicySet.ALZPolicySetName
                })

            $null = $script:tenantPolicySetsDetailed.Add([PSCustomObject]@{
                    Type                     = 'Custom'
                    ScopeMGLevel             = $tenantPolicySet.ScopeMGLevel
                    Scope                    = $tenantPolicySet.ScopeMgSub
                    ScopeId                  = $tenantPolicySet.ScopeId
                    PolicySetDisplayName     = $tenantPolicySet.DisplayName
                    PolicySetDescription     = $tenantPolicySet.Description
                    PolicySetDefinitionName  = $tenantPolicySet.Name
                    PolicySetDefinitionId    = $tenantPolicySet.PolicyDefinitionId
                    PolicySetCategory        = $tenantPolicySet.Category
                    PolicySetVersion         = $tenantPolicySet.Version
                    UniqueAssignmentsCount   = $policySetUniqueAssignmentsCount
                    UniqueAssignments        = $policySetUniqueAssignments
                    PoliciesUsedCount        = $policySetPoliciesCount
                    PoliciesUsedBuiltinCount = $policySetPoliciesBuiltinArrayIdOnlyCSV.Count
                    PoliciesUsedStaticCount  = $policySetPoliciesStaticArrayIdOnlyCSV.Count
                    PoliciesUsedCustomCount  = $policySetPoliciesCustomArrayIdOnlyCSV.Count
                    PoliciesUsed             = $policySetPoliciesArrayClean
                    PoliciesUsed4JSON        = $policySetPoliciesArrayIdOnly
                    PoliciesUsedBuiltin      = $policySetPoliciesBuiltinArrayIdOnlyCSV -join "$CsvDelimiterOpposite "
                    PoliciesUsedStatic       = $policySetPoliciesStaticArrayIdOnlyCSV -join "$CsvDelimiterOpposite "
                    PoliciesUsedCustom       = $policySetPoliciesCustomArrayIdOnlyCSV -join "$CsvDelimiterOpposite "
                    CreatedOn                = $createdOn
                    CreatedBy                = $createdBy
                    CreatedByJson            = $createdByJson
                    UpdatedOn                = $updatedOn
                    UpdatedBy                = $updatedBy
                    UpdatedByJson            = $updatedByJson
                    #Json                  = [string]($tenantPolicySet.Json | ConvertTo-Json -Depth 99 -EnumsAsStrings)
                    Json                     = $tenantPolicySet.Json
                    ALZ                      = $tenantPolicySet.ALZ
                    ALZState                 = $tenantPolicySet.ALZState
                    ALZLatestVer             = $tenantPolicySet.ALZLatestVer
                    ALZIdentificationLevel   = $tenantPolicySet.ALZIdentificationLevel
                    ALZPolicySetName         = $tenantPolicySet.ALZPolicySetName
                })

        }
        else {
            $null = $script:tenantPolicySetsDetailed.Add([PSCustomObject]@{
                    Type                     = 'BuiltIn'
                    ScopeMGLevel             = $null
                    Scope                    = $null
                    ScopeId                  = $null
                    PolicySetDisplayName     = $tenantPolicySet.DisplayName
                    PolicySetDescription     = $tenantPolicySet.Description
                    PolicySetDefinitionName  = $tenantPolicySet.Name
                    PolicySetDefinitionId    = $tenantPolicySet.PolicyDefinitionId
                    PolicySetCategory        = $tenantPolicySet.Category
                    PolicySetVersion         = $tenantPolicySet.Version
                    UniqueAssignmentsCount   = $policySetUniqueAssignmentsCount
                    UniqueAssignments        = $policySetUniqueAssignments
                    PoliciesUsedCount        = $policySetPoliciesCount
                    PoliciesUsedBuiltinCount = $policySetPoliciesBuiltinArrayIdOnlyCSV.Count
                    PoliciesUsedStaticCount  = $policySetPoliciesStaticArrayIdOnlyCSV.Count
                    PoliciesUsedCustomCount  = $policySetPoliciesCustomArrayIdOnlyCSV.Count
                    PoliciesUsed             = $policySetPoliciesArrayClean
                    PoliciesUsed4JSON        = $policySetPoliciesArrayIdOnly
                    PoliciesUsedBuiltin      = $policySetPoliciesBuiltinArrayIdOnlyCSV -join "$CsvDelimiterOpposite "
                    PoliciesUsedStatic       = $policySetPoliciesStaticArrayIdOnlyCSV -join "$CsvDelimiterOpposite "
                    PoliciesUsedCustom       = $policySetPoliciesCustomArrayIdOnlyCSV -join "$CsvDelimiterOpposite "
                    CreatedOn                = ''
                    CreatedBy                = ''
                    CreatedByJson            = $null
                    UpdatedOn                = ''
                    UpdatedBy                = ''
                    UpdatedByJson            = $null
                    #Json                  = [string]($tenantPolicySet.Json | ConvertTo-Json -Depth 99 -EnumsAsStrings)
                    Json                     = $tenantPolicySet.Json
                    ALZ                      = $tenantPolicySet.ALZ
                    ALZState                 = $tenantPolicySet.ALZState
                    ALZLatestVer             = $tenantPolicySet.ALZLatestVer
                    ALZIdentificationLevel   = $tenantPolicySet.ALZIdentificationLevel
                    ALZPolicySetName         = $tenantPolicySet.ALZPolicySetName
                })
        }
    }

    if (-not $NoCsvExport) {
        $csvFilename = "$($filename)_PolicySetDefinitions"
        Write-Host "   Exporting PolicySetDefinitions CSV '$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv'"
        $tenantPolicySetsDetailed | Select-Object -ExcludeProperty UniqueAssignments, PoliciesUsed, PoliciesUsed4JSON, CreatedByJson, UpdatedByJson, Json | Sort-Object -Property Type, Scope, PolicySetDefinitionId | Export-Csv -Encoding utf8 -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter $csvDelimiter -NoTypeInformation
    }

    if ($getMgParentName -eq 'Tenant Root') {
        if ($tenantCustompolicySetsCount -gt $LimitPOLICYPolicySetDefinitionsScopedTenant * ($LimitCriticalPercentage / 100)) {
            $faimage = "<i class=`"padlx fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
        }
        else {
            $faimage = "<i class=`"padlx fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
        }

        if ($tenantCustompolicySetsCount -gt 0) {
            $tfCount = $tenantCustompolicySetsCount
            $htmlTableId = 'TenantSummary_customPolicySets'
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_customPolicySets">$faimage <span class="valignMiddle">$tenantCustompolicySetsCount Custom PolicySet definitions ($scopeNamingSummary) (Limit: $tenantCustompolicySetsCount/$LimitPOLICYPolicySetDefinitionsScopedTenant)</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>ScopeId</th>
<th>PolicySet DisplayName</th>
<th>PolicySet Name</th>
<th>PolicySetId</th>
<th>Category</th>
<th>ALZ</th>
<th>Unique assignments</th>
<th>Policies used in PolicySet</th>
<th>CreatedOn</th>
<th>CreatedBy</th>
<th>UpdatedOn</th>
<th>UpdatedBy</th>
</tr>
</thead>
<tbody>
"@)
            $htmlSUMMARYtenanttotalcustompolicySets = $null
            $htmlSUMMARYtenanttotalcustompolicySets = foreach ($customPolicySet in $customPolicySetsDetailed | Sort-Object @{Expression = { $_.Scope } }, @{Expression = { $_.PolicySetDisplayName } }, @{Expression = { $_.PolicySetDefinitionId } }) {
                @"
<tr>
<td>$($customPolicySet.Scope)</td>
<td>$($customPolicySet.ScopeId)</td>
<td>$($customPolicySet.PolicySetDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($customPolicySet.PolicySetDefinitionName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($customPolicySet.PolicySetDefinitionId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($customPolicySet.PolicySetCategory -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($customPolicySet.ALZ)</td>
<td class="breakwordall">$($customPolicySet.UniqueAssignments -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($customPolicySet.PoliciesUsed)</td>
<td>$($customPolicySet.CreatedOn)</td>
<td>$($customPolicySet.CreatedBy)</td>
<td>$($customPolicySet.UpdatedOn)</td>
<td>$($customPolicySet.UpdatedBy)</td>
</tr>
"@
            }
            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYtenanttotalcustompolicySets)
            [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
            col_6: 'select',
            locale: 'en-US',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'date',
                'caseinsensitivestring',
                'date',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@"
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $tenantCustomPolicySetsCount Custom PolicySet definitions ($scopeNamingSummary)</p>
"@)
        }
    }
    #SUMMARY NOT tenant total custom policySet definitions
    else {
        $faimage = "<i class=`"fa fa-check-circle`" aria-hidden=`"true`"></i>"
        if ($tenantCustompolicySetsCount -gt $LimitPOLICYPolicySetDefinitionsScopedTenant * ($LimitCriticalPercentage / 100)) {
            $faimage = "<i class=`"padlx fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
        }
        else {
            $faimage = "<i class=`"padlx fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
        }

        if ($tenantCustompolicySetsCount -gt 0) {
            $custompolicySetsFromSuperiorMGs = $tenantCustompolicySetsCount - (($custompolicySetsInScopeArray).count)
        }
        else {
            $custompolicySetsFromSuperiorMGs = '0'
        }

        if ($tenantCustompolicySetsCount -gt 0) {
            $tfCount = $tenantCustompolicySetsCount
            $htmlTableId = 'TenantSummary_customPolicySets'
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_customPolicySets">$faimage <span class="valignMiddle">$tenantCustomPolicySetsCount Custom PolicySet definitions $scopeNamingSummary ($custompolicySetsFromSuperiorMGs from superior scopes) (Limit: $tenantCustompolicySetsCount/$LimitPOLICYPolicySetDefinitionsScopedTenant)</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>Scope Id</th>
<th>PolicySet DisplayName</th>
<th>PolicySet Name</th>
<th>PolicySetId</th>
<th>Category</th>
<th>ALZ</th>
<th>Unique assignments</th>
<th>Policies used in PolicySet</th>
<th>CreatedOn</th>
<th>CreatedBy</th>
<th>UpdatedOn</th>
<th>UpdatedBy</th>
</tr>
</thead>
<tbody>
"@)
            $htmlSUMMARYtenanttotalcustompolicySets = $null
            $htmlSUMMARYtenanttotalcustompolicySets = foreach ($customPolicySet in $customPolicySetsDetailed | Sort-Object @{Expression = { $_.Scope } }, @{Expression = { $_.PolicySetDisplayName } }, @{Expression = { $_.PolicySetDefinitionId } }) {
                @"
<tr>
<td class="breakwordall">$($customPolicySet.Scope)</td>
<td class="breakwordall">$($customPolicySet.ScopeId)</td>
<td>$($customPolicySet.PolicySetDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($customPolicySet.PolicySetDefinitionName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($customPolicySet.PolicySetDefinitionId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($customPolicySet.PolicySetCategory -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($customPolicySet.ALZ)</td>
<td class="breakwordall">$($customPolicySet.UniqueAssignments -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($customPolicySet.PoliciesUsed)</td>
<td>$($customPolicySet.CreatedOn)</td>
<td>$($customPolicySet.CreatedBy)</td>
<td>$($customPolicySet.UpdatedOn)</td>
<td>$($customPolicySet.UpdatedBy)</td>
</tr>
"@
            }
            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYtenanttotalcustompolicySets)
            [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
            col_6: 'select',
            locale: 'en-US',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'date',
                'caseinsensitivestring',
                'date',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@"
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $tenantCustomPolicySetsCount Custom PolicySet definitions ($scopeNamingSummary)</p>
"@)
        }
    }
    $endCustPolSetLoop = Get-Date
    Write-Host "   Custom PolicySet processing duration: $((New-TimeSpan -Start $startCustPolSetLoop -End $endCustPolSetLoop).TotalMinutes) minutes ($((New-TimeSpan -Start $startCustPolSetLoop -End $endCustPolSetLoop).TotalSeconds) seconds)"
    #endregion SUMMARYtenanttotalcustompolicySets

    #region SUMMARYCustompolicySetOrphandedTenantRoot
    Write-Host '  processing TenantSummary Custom PolicySet definitions orphaned'
    if ($getMgParentName -eq 'Tenant Root') {
        $custompolicySetSetsOrphaned = [System.Collections.ArrayList]@()
        foreach ($custompolicySetAll in $tenantCustomPolicySets) {
            if (($policyPolicySetBaseQueryUniqueCustomDefinitions).count -eq 0) {
                $null = $custompolicySetSetsOrphaned.Add($custompolicySetAll)
            }
            else {
                if ($policyPolicySetBaseQueryUniqueCustomDefinitions -notcontains ($custompolicySetAll.Id)) {
                    $null = $custompolicySetSetsOrphaned.Add($custompolicySetAll)
                }
            }
        }

        $arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()
        foreach ($customPolicySetOrphaned in $custompolicySetSetsOrphaned) {
            if (($htCacheAssignmentsPolicyOnResourceGroupsAndResources).values.properties.PolicyDefinitionId -notcontains $customPolicySetOrphaned.PolicyDefinitionId) {
                $null = $arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups.Add($customPolicySetOrphaned)
            }
        }

        if (($arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups).count -gt 0) {
            $tfCount = ($arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups).count
            $htmlTableId = 'TenantSummary_customPolicySetsOrphaned'
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_custompolicySetsOrphaned"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups).count) Orphaned Custom PolicySet definitions ($scopeNamingSummary)</span> <abbr title="PolicySet has no assignments (including ResourceGroups)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
</tr>
</thead>
<tbody>
"@)
            $htmlSUMMARYCustompolicySetOrphandedTenantRoot = $null
            $htmlSUMMARYCustompolicySetOrphandedTenantRoot = foreach ($custompolicySetOrphaned in $arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups | Sort-Object @{Expression = { $_.PolicyDefinitionId } }, @{Expression = { $_.DisplayName } }) {
                @"
<tr>
<td>$($custompolicySetOrphaned.DisplayName)</td>
<td>$($custompolicySetOrphaned.PolicyDefinitionId)</td>
</tr>
"@
            }
            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYCustompolicySetOrphandedTenantRoot)
            [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@"
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $(($arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups).count) Orphaned Custom PolicySet definitions ($scopeNamingSummary)</p>
"@)
        }
    }
    #SUMMARY Custom policySetSets Orphanded NOT TenantRoot
    else {
        $arraycustompolicySetsOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()
        foreach ($custompolicySetAll in $tenantCustomPolicySets) {
            $isOrphaned = 'unknown'
            if (($policyPolicySetBaseQueryUniqueCustomDefinitions).count -eq 0) {
                $isOrphaned = 'potentially'
            }
            else {
                if ($policyPolicySetBaseQueryUniqueCustomDefinitions -notcontains $custompolicySetAll.Id) {
                    $isOrphaned = 'potentially'
                }
            }

            if ($isOrphaned -eq 'potentially') {
                $isInScope = 'unknown'
                if ($custompolicySetAll.PolicyDefinitionId -like '/providers/Microsoft.Management/managementGroups/*') {
                    $policySetScopedMgSub = $custompolicySetAll.PolicyDefinitionId -replace '/providers/Microsoft.Management/managementGroups/', '' -replace '/.*'
                    if ($mgsAndSubs.MgId -contains ($policySetScopedMgSub)) {
                        $isInScope = 'inScope'
                    }
                }
                elseif ($custompolicySetAll.PolicyDefinitionId -like '/subscriptions/*') {
                    $policySetScopedMgSub = $custompolicySetAll.PolicyDefinitionId -replace '/subscriptions/', '' -replace '/.*'
                    if ($mgsAndSubs.SubscriptionId -contains ($policySetScopedMgSub)) {
                        $isInScope = 'inScope'
                    }
                }
                else {
                    Write-Host 'unexpected'
                }

                if ($isInScope -eq 'inScope') {
                    if (($htCacheAssignmentsPolicyOnResourceGroupsAndResources).values.properties.PolicyDefinitionId -notcontains $custompolicySetAll.PolicyDefinitionId) {
                        $null = $arraycustompolicySetsOrphanedFinalIncludingResourceGroups.Add($custompolicySetAll)
                    }
                }
            }
        }

        if (($arraycustompolicySetsOrphanedFinalIncludingResourceGroups).count -gt 0) {
            $tfCount = ($arraycustompolicySetsOrphanedFinalIncludingResourceGroups).count
            $htmlTableId = 'TenantSummary_customPolicySetsOrphaned'
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_custompolicySetsOrphaned"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arraycustompolicySetsOrphanedFinalIncludingResourceGroups).count) Orphaned Custom PolicySet definitions ($scopeNamingSummary)</span> <abbr title="PolicySet has no assignments (including ResourceGroups) &#13;Note: PolicySets from superior scopes are not evaluated"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
</tr>
</thead>
<tbody>
"@)
            $htmlSUMMARYCustompolicySetOrphandedTenantRoot = $null
            $htmlSUMMARYCustompolicySetOrphandedTenantRoot = foreach ($custompolicySetOrphaned in $arraycustompolicySetsOrphanedFinalIncludingResourceGroups | Sort-Object @{Expression = { $_.PolicyDefinitionId } }, @{Expression = { $_.DisplayName } }) {
                @"
<tr>
<td>$($custompolicySetOrphaned.DisplayName)</td>
<td>$($custompolicySetOrphaned.policyDefinitionId)</td>
</tr>
"@
            }
            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYCustompolicySetOrphandedTenantRoot)
            [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@"
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $(($arraycustompolicySetsOrphanedFinalIncludingResourceGroups).count) Orphaned Custom PolicySet definitions ($scopeNamingSummary)</p>
"@)
        }
    }
    #endregion SUMMARYCustompolicySetOrphandedTenantRoot

    #region SUMMARYPolicyParityCustomBuiltIn
    Write-Host '  processing TenantSummary Policy parity custom built-in'

    if ($arrayCustomBuiltInPolicyParity.Count -gt 0) {
        $tfCount = $arrayCustomBuiltInPolicyParity.Count
        $htmlTableId = 'TenantSummary_PolicyCustomBuiltInParity'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_PolicyCustomBuiltInParity"><i class="padlx fa fa-files-o" aria-hidden="true" style="color:#0078df"></i> <span class="valignMiddle">$($arrayCustomBuiltInPolicyParity.Count) custom Policy definition(s) built-in Policy rule parity</span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Policy Name</th>
<th>Policy DisplayName</th>
<th>Policy Category</th>
<th>Policy Id</th>
<th># match built-in</th>
<th>Built-In Policy</th>
</tr>
</thead>
<tbody>
"@)

        $htmlSUMMARYPolicyCustomBuiltInParity = $null
        $htmlSUMMARYPolicyCustomBuiltInParity = foreach ($entry in $arrayCustomBuiltInPolicyParity | Sort-Object -Property CustomPolicyId) {
            $arrayBuiltinsRef = @()
            foreach ($builtInPolicyId in $entry.BuiltInPolicyId) {
                $arrayBuiltinsRef += "<a class=`"externallink`" rel=`"noopener`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/$($builtInPolicyId -replace '.*/').html`" target=`"_blank`">$($htCacheDefinitionsPolicy.($builtInPolicyId).DisplayName) <i class=`"fa fa-external-link`" aria-hidden=`"true`"></i></a> ($($builtInPolicyId -replace '.*/'))"
            }
            $builtInPolicyAzA = $arrayBuiltinsRef -join ', '
            @"
<tr>
<td>$($entry.CustomPolicyName)</td>
<td>$($entry.CustomPolicyDisplayName)</td>
<td>$($entry.CustomPolicyCategory)</td>
<td>$($entry.CustomPolicyId)</td>
<td>$($entry.MatchBuiltinPolicyCount)</td>
<td>$($builtInPolicyAzA)</td>
</tr>
"@
        }

        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYPolicyCustomBuiltInParity)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_2: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@'
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No custom Policy definition(s) built-in Policy rule parity</p>
'@)
    }
    #endregion SUMMARYPolicyParityCustomBuiltIn

    #region SUMMARYALZPolicies
    Write-Host '  processing TenantSummary ALZPolicies'

    if (-not $NoALZPolicyVersionChecker) {

        $alzPoliciesInTenant = [System.Collections.ArrayList]@()
        #policies
        foreach ($policy in ($htCacheDefinitionsPolicy).Values.where({ $_.ALZ -eq $true })) {
            if ($policy.ALZState -ne 'obsolete' -and $policy.ALZState -ne 'unknown') {
                $ALZVersion = $alzPolicies.($policy.ALZPolicyName).latestVersion
                $azAdvertizerUrl = "https://www.azadvertizer.net/azpolicyadvertizer/$($policy.ALZPolicyName).html"
            }
            else {
                $ALZVersion = ''
                $azAdvertizerUrl = ''
            }
            $null = $alzPoliciesInTenant.Add([PSCustomObject]@{
                    Type            = 'Policy'
                    PolicyName      = $policy.Name
                    PolicyId        = $policy.PolicyDefinitionId
                    PolicyVersion   = $policy.Version
                    PolicyScope     = $policy.ScopeMgSub
                    PolicyScopeId   = $policy.ScopeId
                    ALZPolicyName   = $policy.ALZPolicyName
                    ALZVersion      = $ALZVersion
                    ALZState        = $policy.ALZState
                    InTenant        = $true
                    DetectedBy      = $policy.ALZIdentificationLevel
                    AzAdvertizerUrl = $azAdvertizerUrl
                })
        }
        foreach ($alzPolicy in $alzPolicies.keys) {
            if ($alzPolicies.($alzPolicy).status -eq 'Prod') {
                if ($alzPoliciesInTenant.PolicyName -notcontains $alzPolicy) {
                    $null = $alzPoliciesInTenant.Add([PSCustomObject]@{
                            Type            = 'Policy'
                            PolicyName      = 'n/a'
                            PolicyId        = 'n/a'
                            PolicyVersion   = 'n/a'
                            PolicyScope     = 'n/a'
                            PolicyScopeId   = 'n/a'
                            ALZPolicyName   = $alzPolicy
                            ALZVersion      = $alzPolicies.($alzPolicy).latestVersion
                            ALZState        = ''
                            InTenant        = $false
                            DetectedBy      = 'ALZ GitHub repository'
                            AzAdvertizerUrl = "https://www.azadvertizer.net/azpolicyadvertizer/$($alzPolicy).html"
                        })
                }
            }
        }

        #policysets
        foreach ($policySet in ($htCacheDefinitionsPolicySet).Values.where({ $_.ALZ -eq $true })) {

            if ($policySet.ALZState -ne 'obsolete' -and $policySet.ALZState -ne 'unknown') {
                $ALZVersion = $alzPolicySets.($policySet.ALZPolicySetName).latestVersion
                $azAdvertizerUrl = "https://www.azadvertizer.net/azpolicyinitiativesadvertizer/$($policySet.ALZPolicySetName).html"
            }
            else {
                $ALZVersion = ''
                $azAdvertizerUrl = ''
            }
            $null = $alzPoliciesInTenant.Add([PSCustomObject]@{
                    Type            = 'PolicySet'
                    PolicyName      = $policySet.Name
                    PolicyId        = $policySet.PolicyDefinitionId
                    PolicyVersion   = $policySet.Version
                    PolicyScope     = $policySet.ScopeMgSub
                    PolicyScopeId   = $policySet.ScopeId
                    ALZPolicyName   = $policySet.ALZPolicySetName
                    ALZVersion      = $ALZVersion
                    ALZState        = $policySet.ALZState
                    InTenant        = $true
                    DetectedBy      = $policySet.ALZIdentificationLevel
                    AzAdvertizerUrl = $azAdvertizerUrl
                })
        }

        foreach ($alzPolicySet in $alzPolicySets.keys) {
            if ($alzPolicySets.($alzPolicySet).status -eq 'Prod') {
                if ($alzPoliciesInTenant.PolicyName -notcontains $alzPolicySet) {
                    $null = $alzPoliciesInTenant.Add([PSCustomObject]@{
                            Type            = 'PolicySet'
                            PolicyName      = 'n/a'
                            PolicyId        = 'n/a'
                            PolicyVersion   = 'n/a'
                            PolicyScope     = 'n/a'
                            PolicyScopeId   = 'n/a'
                            ALZPolicyName   = $alzPolicySet
                            ALZVersion      = $alzPolicySets.($alzPolicySet).latestVersion
                            ALZState        = ''
                            InTenant        = $false
                            DetectedBy      = 'ALZ GitHub repository'
                            AzAdvertizerUrl = "https://www.azadvertizer.net/azpolicyinitiativesadvertizer/$($alzPolicySet).html"
                        })
                }
            }
        }

        if ($alzPoliciesInTenant.Count -gt 0) {
            $tfCount = $alzPoliciesInTenant.Count
            $htmlTableId = 'TenantSummary_ALZPolicies'
            $abbrALZ = " <abbr title=`"obsolete: this policy is no longer ALZ maintained by ALZ&#13;outDated: a new version of the policy available&#13;unknown: ALZ related policy could not be mapped&#13;upToDate: policy matches with latest ALZ policy`"><i class=`"fa fa-question-circle`" aria-hidden=`"true`"></i></abbr>"
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_ALZPolicies"><i class="padlx fa fa-retweet" aria-hidden="true" style="color:#23C632"></i> <span class="valignMiddle">Azure Landing Zones (ALZ) Policy Version Checker</span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Azure Landing Zones (ALZ)</span> <a class="externallink" href="https://github.com/Azure/Enterprise-Scale/blob/main/docs/ESLZ-Policies.md" target="_blank" rel="noopener">GitHub <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Type</th>
<th>Policy Name (Id)</th>
<th>Policy Version</th>
<th>Policy Scope</th>
<th>Policy Scope Id</th>
<th class="uamiresaltbgc">ALZ Policy Name (Id)</th>
<th class="uamiresaltbgc">ALZ Policy Version</th>
<th class="uamiresaltbgc">ALZ State$($abbrALZ)</th>
<th>Exists in tenant</th>
<th>Detection method</th>
<th>AzAdvertizer Link</th>
</tr>
</thead>
<tbody>
"@)

            $htmlSUMMARYALZPolicyVersionChecker = $null
            $exemptionData4CSVExport = [System.Collections.ArrayList]@()
            $alzPoliciesInTenantSorted = $alzPoliciesInTenant | Sort-Object -Property PolicyName, PolicyId, ALZPolicyName, Type
            $htmlSUMMARYALZPolicyVersionChecker = foreach ($entry in $alzPoliciesInTenantSorted) {
                if ([string]::IsNullOrWhiteSpace($entry.AzAdvertizerUrl)) {
                    $link = ''
                }
                else {
                    $link = "<a class=`"externallink`" href=`"$($entry.AzAdvertizerUrl)`" target=`"_blank`" rel=`"noopener`">AzA Link <i class=`"fa fa-external-link`" aria-hidden=`"true`"></i></a>"
                }
                @"
<tr>
<td>$($entry.Type)</td>
<td>$($entry.PolicyName)</td>
<td>$($entry.PolicyVersion)</td>
<td>$($entry.PolicyScope)</td>
<td>$($entry.PolicyScopeId)</td>
<td>$($entry.ALZPolicyName)</td>
<td>$($entry.ALZVersion)</td>
<td>$($entry.ALZState)</td>
<td>$($entry.InTenant)</td>
<td>$($entry.DetectedBy)</td>
<td>$link</td>
</tr>
"@
            }

            if (-not $NoCsvExport) {
                Write-Host "Exporting 'Azure Landing Zones (ALZ) Policy Version Checker' CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_ALZPolicyVersionChecker.csv'"
                $alzPoliciesInTenantSorted | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_ALZPolicyVersionChecker.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
            }

            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYALZPolicyVersionChecker)
            [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
            col_3: 'select',
            col_7: 'multiple',
            col_8: 'select',
            col_9: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> Azure Landing Zones (ALZ) Policy Version Checker</p>
'@)
        }
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> Azure Landing Zones (ALZ) Policy Version Checker (parameter -NoALZPolicyVersionChecker = $NoALZPolicyVersionChecker)</p>
"@)
    }
    #endregion SUMMARYALZPolicies

    $startcustpolsetdeprpol = Get-Date
    #region SUMMARYPolicySetsDeprecatedPolicy
    Write-Host '  processing TenantSummary Custom PolicySet definitions using deprected Policy'
    $policySetsDeprecated = [System.Collections.ArrayList]@()
    $customPolicySetsCount = ($tenantCustomPolicySets).count
    if ($customPolicySetsCount -gt 0) {
        foreach ($polSetDef in $tenantCustomPolicySets) {
            foreach ($polsetPolDefId in $polSetDef.PolicySetPolicyIds) {
                $hlpDeprecatedPolicySet = (($htCacheDefinitionsPolicy).($polsetPolDefId))
                if ($hlpDeprecatedPolicySet.Type -eq 'BuiltIn') {
                    if ($hlpDeprecatedPolicySet.Deprecated -eq $true -or ($hlpDeprecatedPolicySet.DisplayName).StartsWith('[Deprecated]', 'CurrentCultureIgnoreCase')) {
                        $null = $policySetsDeprecated.Add([PSCustomObject]@{
                                PolicySetDisplayName  = $polSetDef.DisplayName
                                PolicySetDefinitionId = $polSetDef.PolicyDefinitionId
                                PolicyDisplayName     = $hlpDeprecatedPolicySet.DisplayName
                                PolicyId              = $hlpDeprecatedPolicySet.Id
                                DeprecatedProperty    = $hlpDeprecatedPolicySet.Deprecated
                            })
                    }
                }
            }
        }
    }

    if (($policySetsDeprecated).count -gt 0) {
        $tfCount = ($policySetsDeprecated).count
        $htmlTableId = 'TenantSummary_policySetsDeprecated'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_policySetsDeprecated"><i class="padlx fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($policySetsDeprecated).count) Custom PolicySet definitions / deprecated built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] &#13;OR &#13;Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
<th>Policy DisplayName</th>
<th>PolicyId</th>
<th>Deprecated Property</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYPolicySetsDeprecatedPolicy = $null
        $htmlSUMMARYPolicySetsDeprecatedPolicy = foreach ($policySetDeprecated in $policySetsDeprecated | Sort-Object @{Expression = { $_.PolicySetDisplayName } }, @{Expression = { $_.PolicySetDefinitionId } }) {

            if ($policySetDeprecated.DeprecatedProperty -eq $true) {
                $deprecatedProperty = 'true'
            }
            else {
                $deprecatedProperty = 'false'
            }
            @"
<tr>
<td>$($policySetDeprecated.PolicySetDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policySetDeprecated.PolicySetDefinitionId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policySetDeprecated.PolicyDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policySetDeprecated.PolicyId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$deprecatedProperty</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYPolicySetsDeprecatedPolicy)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $(($policySetsDeprecated).count) PolicySets / deprecated built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] &#13;OR &#13;Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></p>
"@)
    }
    #endregion SUMMARYPolicySetsDeprecatedPolicy
    $endcustpolsetdeprpol = Get-Date
    Write-Host "   processing PolicySetsDeprecatedPolicy duration: $((New-TimeSpan -Start $startcustpolsetdeprpol -End $endcustpolsetdeprpol).TotalSeconds) seconds"

    $startcustpolassdeprpol = Get-Date
    #region SUMMARYPolicyAssignmentsDeprecatedPolicy
    Write-Host '  processing TenantSummary PolicyAssignments using deprecated Policy'
    $policyAssignmentsDeprecated = [System.Collections.ArrayList]@()
    foreach ($policyAssignmentAll in ($htCacheAssignmentsPolicy).Values) {

        $hlpAssignmentDeprecatedPolicy = $policyAssignmentAll.Assignment
        $hlpPolicyDefinitionId = ($hlpAssignmentDeprecatedPolicy.properties.policyDefinitionId).ToLower()
        #policySet
        if ($($htCacheDefinitionsPolicySet).(($hlpPolicyDefinitionId))) {
            foreach ($polsetPolDefId in $($htCacheDefinitionsPolicySet).(($hlpPolicyDefinitionId)).PolicySetPolicyIds) {
                $hlpDeprecatedAssignment = (($htCacheDefinitionsPolicy).(($polsetPolDefId)))
                if ($hlpDeprecatedAssignment.type -eq 'BuiltIn') {
                    if ($hlpDeprecatedAssignment.Deprecated -eq $true) {
                        $null = $policyAssignmentsDeprecated.Add([PSCustomObject]@{
                                PolicyAssignmentDisplayName = $hlpAssignmentDeprecatedPolicy.properties.displayName
                                PolicyAssignmentId          = ($hlpAssignmentDeprecatedPolicy.id).Tolower()
                                PolicyDisplayName           = $hlpDeprecatedAssignment.DisplayName
                                PolicyId                    = $hlpDeprecatedAssignment.Id
                                PolicySetDisplayName        = ($htCacheDefinitionsPolicySet).(($hlpPolicyDefinitionId)).DisplayName
                                PolicySetId                 = ($htCacheDefinitionsPolicySet).(($hlpPolicyDefinitionId)).PolicyDefinitionId
                                PolicyType                  = 'PolicySet'
                                DeprecatedProperty          = $hlpDeprecatedAssignment.Deprecated
                            })
                    }
                }
            }
        }

        #Policy
        $hlpDeprecatedAssignmentPol = ($htCacheDefinitionsPolicy).(($hlpPolicyDefinitionId))
        if ($hlpDeprecatedAssignmentPol) {
            if ($hlpDeprecatedAssignmentPol.type -eq 'BuiltIn') {
                if ($hlpDeprecatedAssignmentPol.Deprecated -eq $true) {
                    $null = $policyAssignmentsDeprecated.Add([PSCustomObject]@{
                            PolicyAssignmentDisplayName = $hlpAssignmentDeprecatedPolicy.properties.displayName
                            PolicyAssignmentId          = ($hlpAssignmentDeprecatedPolicy.id).Tolower()
                            PolicyDisplayName           = $hlpDeprecatedAssignmentPol.DisplayName
                            PolicyId                    = $hlpDeprecatedAssignmentPol.Id
                            PolicyType                  = 'Policy'
                            DeprecatedProperty          = $hlpDeprecatedAssignmentPol.Deprecated
                            PolicySetDisplayName        = 'n/a'
                            PolicySetId                 = 'n/a'
                        })
                }
            }
        }
    }


    if (($policyAssignmentsDeprecated).count -gt 0) {
        $tfCount = ($policyAssignmentsDeprecated).count
        $htmlTableId = 'TenantSummary_policyAssignmentsDeprecated'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_policyAssignmentsDeprecated"><i class="padlx fa fa-exclamation-triangle orange" aria-hidden="true"></i> <span class="valignMiddle">$(($policyAssignmentsDeprecated).count) Policy assignments / deprecated built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] &#13;OR &#13;Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Policy Assignment DisplayName</th>
<th>Policy AssignmentId</th>
<th>Policy/PolicySet</th>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
<th>Policy DisplayName</th>
<th>PolicyId</th>
<th>Deprecated Property</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYPolicyAssignmentsDeprecatedPolicy = $null
        $htmlSUMMARYPolicyAssignmentsDeprecatedPolicy = foreach ($policyAssignmentDeprecated in $policyAssignmentsDeprecated | Sort-Object @{Expression = { $_.PolicyAssignmentDisplayName } }, @{Expression = { $_.PolicyAssignmentId } }) {
            @"
<tr>
<td>$($policyAssignmentDeprecated.PolicyAssignmentDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($policyAssignmentDeprecated.PolicyAssignmentId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policyAssignmentDeprecated.PolicyType)</td>
<td>$($policyAssignmentDeprecated.PolicySetDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($policyAssignmentDeprecated.PolicySetId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policyAssignmentDeprecated.PolicyDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($policyAssignmentDeprecated.PolicyId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policyAssignmentDeprecated.DeprecatedProperty)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYPolicyAssignmentsDeprecatedPolicy)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_2: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $(($policyAssignmentsDeprecated).count) Policy assignments / deprecated built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] &#13;OR &#13;Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></p>
"@)
    }
    #endregion SUMMARYPolicyAssignmentsDeprecatedPolicy
    $endcustpolassdeprpol = Get-Date
    Write-Host "   processing PolicyAssignmentsDeprecatedPolicy duration: $((New-TimeSpan -Start $startcustpolassdeprpol -End $endcustpolassdeprpol).TotalSeconds) seconds"

    #region SUMMARYPolicyExemptions
    Write-Host '  processing TenantSummary Policy exemptions'
    $policyExemptionsCount = ($htPolicyAssignmentExemptions.Keys).Count

    if ($policyExemptionsCount -gt 0) {
        $tfCount = $policyExemptionsCount
        $htmlTableId = 'TenantSummary_policyExemptions'

        $expiredExemptionsCount = ($htPolicyAssignmentExemptions.Keys | Where-Object { $htPolicyAssignmentExemptions.($_).exemption.properties.expiresOn -and $htPolicyAssignmentExemptions.($_).exemption.properties.expiresOn -lt (Get-Date).ToUniversalTime() } | Measure-Object).count

        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_policyExemptions"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$($policyExemptionsCount) Policy exemptions | Expired: $($expiredExemptionsCount)</span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>Management Group Id</th>
<th>Management Group Name</th>
<th>SubscriptionId</th>
<th>Subscription Name</th>
<th>ResourceGroup</th>
<th>ResourceName / ResourceType</th>
<th>Exemption name</th>
<th>Exemption description</th>
<th>Category</th>
<th>ExpiresOn (UTC)</th>
<th>Exemption Id</th>
<th>Policy AssignmentId</th>
<th>Policy Type</th>
<th>Policy</th>
<th>Exempted Set Policies</th>
<th>CreatedBy</th>
<th>CreatedAt</th>
<th>LastModifiedBy</th>
<th>LastModifiedAt</th>
</tr>
</thead>
<tbody>
"@)

        $htmlSUMMARYPolicyExemptions = $null
        $exemptionData4CSVExport = [System.Collections.ArrayList]@()
        $htmlSUMMARYPolicyExemptions = foreach ($policyExemption in $htPolicyAssignmentExemptions.Keys | Sort-Object) {
            $exemption = $htPolicyAssignmentExemptions.$policyExemption.exemption
            if ($exemption.properties.expiresOn) {
                $exemptionExpiresOnFormated = (($exemption.properties.expiresOn))
                if ($exemption.properties.expiresOn -gt (Get-Date).ToUniversalTime()) {
                    $exemptionExpiresOn = $exemptionExpiresOnFormated
                }
                else {
                    $exemptionExpiresOn = "expired $($exemptionExpiresOnFormated)"
                }
            }
            else {
                $exemptionExpiresOn = 'n/a'
            }

            $splitExemptionId = ($exemption.Id).Split('/')
            if (($exemption.Id) -like '/subscriptions/*') {

                switch (($splitExemptionId).Count - 1) {
                    #sub
                    6 {
                        $exemptionScope = 'Sub'
                        $subId = $splitExemptionId[2]
                        $subdetails = $htSubDetails.($subId).details
                        $mgId = $subdetails.MgId
                        $mgName = $subdetails.MgName
                        $subName = $subdetails.Subscription
                        $rgName = ''
                        $resName = ''
                    }

                    #rg
                    8 {
                        $exemptionScope = 'RG'
                        $subId = $splitExemptionId[2]
                        $subdetails = $htSubDetails.($subId).details
                        $mgId = $subdetails.MgId
                        $mgName = $subdetails.MgName
                        $subName = $subdetails.Subscription
                        $rgName = $splitExemptionId[4]
                        $resName = ''
                    }

                    #res
                    12 {
                        $exemptionScope = 'Res'
                        $subId = $splitExemptionId[2]
                        $subdetails = $htSubDetails.($subId).details
                        $mgId = $subdetails.MgId
                        $mgName = $subdetails.MgName
                        $subName = $subdetails.Subscription
                        $rgName = $splitExemptionId[4]
                        $resName = "$($splitExemptionId[8]) / $($splitExemptionId[6..7] -join '/')"
                    }
                }
            }
            else {
                $exemptionScope = 'MG'
                $mgId = $splitExemptionId[4]
                $mgdetails = $htMgDetails.($mgId).details
                $mgName = $mgdetails.MgName
                $subId = ''
                $subName = ''
                $rgName = ''
                $resName = ''
            }

            $policyType = 'unknown'
            $policy = 'unknown'
            $arrayExemptedPolicies = @()
            $arrayExemptedPoliciesCSV = @()
            $policiesExempted = $null
            $policiesExemptedCSV = $null
            $policiesExemptedCSVCount = $null
            $policiesTotalCount = $null
            if ($htCacheAssignmentsPolicy.(($exemption.properties.policyAssignmentId).tolower()).Assignment.properties.policyDefinitionId) {
                $policyDefinitionId = $htCacheAssignmentsPolicy.(($exemption.properties.policyAssignmentId).tolower()).Assignment.properties.policyDefinitionId

                if ($policyDefinitionId -like '*/providers/Microsoft.Authorization/policyDefinitions/*') {
                    $policyType = 'Policy'
                    if ($htCacheDefinitionsPolicy.($policyDefinitionId.tolower())) {
                        $policyDetail = $htCacheDefinitionsPolicy.($policyDefinitionId.tolower())
                        if ($policyDetail.Type -eq 'BuiltIn') {
                            $policy = $policyDetail.LinkToAzAdvertizer
                        }
                        else {
                            $policy = "$($policyDetail.DisplayName) ($($policyDetail.Id))"
                        }
                        $policiesExempted = $null
                        $policyClear = "$($policyDetail.DisplayName) ($($policyDetail.Id))"
                    }
                }

                if ($policyDefinitionId -like '*/providers/Microsoft.Authorization/policySetDefinitions/*') {
                    $policyType = 'PolicySet'
                    if ($htCacheDefinitionsPolicySet.($policyDefinitionId.tolower())) {
                        $policyDetail = $htCacheDefinitionsPolicySet.($policyDefinitionId.tolower())
                        if ($policyDetail.Type -eq 'BuiltIn') {
                            $policy = $policyDetail.LinkToAzAdvertizer
                        }
                        else {
                            $policy = "$($policyDetail.DisplayName) ($($policyDetail.Id))"
                        }
                        $policiesTotalCount = $htCacheDefinitionsPolicySet.($policyDefinitionId.tolower()).PolicySetPolicyRefIds.Count
                        if ($exemption.properties.policyDefinitionReferenceIds.Count -gt 0) {
                            foreach ($exemptedRefId in $exemption.properties.policyDefinitionReferenceIds) {
                                $policyExempted = 'unknown'
                                $policyExemptedCSV = 'unknown'
                                if ($htCacheDefinitionsPolicySet.($policyDefinitionId.tolower()).PolicySetPolicyRefIds.($exemptedRefId)) {
                                    $exemptedPolicyId = $htCacheDefinitionsPolicySet.($policyDefinitionId.tolower()).PolicySetPolicyRefIds.($exemptedRefId)
                                    if ($htCacheDefinitionsPolicy.($exemptedPolicyId.tolower())) {
                                        $policyExemptedDetail = $htCacheDefinitionsPolicy.($exemptedPolicyId.tolower())
                                        if ($policyExemptedDetail.Type -eq 'BuiltIn') {
                                            $policyExempted = $policyExemptedDetail.LinkToAzAdvertizer
                                        }
                                        else {
                                            $policyExempted = "$($policyExemptedDetail.DisplayName) ($($policyExemptedDetail.Id))"
                                        }
                                        $policyExemptedCSV = "$($policyExemptedDetail.DisplayName) ($($policyExemptedDetail.Id))"

                                    }
                                }
                                $arrayExemptedPolicies += $policyExempted
                                $arrayExemptedPoliciesCSV += $policyExemptedCSV
                            }

                            $policiesExempted = "$($arrayExemptedPolicies.Count)/$($policiesTotalCount) (<br>$(($arrayExemptedPolicies | Sort-Object) -join '<br>'))"
                            $policiesExemptedCSV = ($arrayExemptedPoliciesCSV | Sort-Object) -join "$CsvDelimiterOpposite "
                            $policiesExemptedCSVCount = $arrayExemptedPoliciesCSV.Count
                        }
                        else {
                            $policiesExempted = "all $policiesTotalCount"
                            $policiesExemptedCSV = "all $policiesTotalCount"
                            $policiesExemptedCSVCount = $policiesTotalCount
                        }

                        $policyClear = "$($policyDetail.DisplayName) ($($policyDetail.Id))"
                    }
                }

            }

            if (-not $NoCsvExport) {
                $null = $exemptionData4CSVExport.Add([PSCustomObject]@{
                        Scope                     = $exemptionScope
                        ManagementGroupId         = $mgId
                        ManagementGroupName       = $mgName
                        SubscriptionId            = $subId
                        SubscriptionName          = $subName
                        ResourceGroup             = $rgName
                        ResourceName_ResourceType = $resName
                        ExemptionName             = $exemption.properties.DisplayName
                        ExemptionDescription      = $exemption.properties.Description
                        Category                  = $exemption.properties.exemptionCategory
                        ExpiresOn_UTC             = $exemptionExpiresOn
                        ExemptionId               = $exemption.Id
                        PolicyAssignmentId        = $exemption.properties.policyAssignmentId
                        PolicyType                = $policyType
                        Policy                    = $policyClear
                        PoliciesTotalCount        = $policiesTotalCount
                        PoliciesExemptedCount     = $policiesExemptedCSVCount
                        PoliciesExempted          = $policiesExemptedCSV
                        CreatedBy                 = "$($exemption.systemData.createdBy) ($($exemption.systemData.createdByType))"
                        CreatedAt                 = $exemption.systemData.createdAt.ToString('yyyy-MM-dd HH:mm:ss')
                        LastModifiedBy            = "$($exemption.systemData.lastModifiedBy) ($($exemption.systemData.lastModifiedByType))"
                        LastModifiedAt            = $exemption.systemData.lastModifiedAt.ToString('yyyy-MM-dd HH:mm:ss')
                    })
            }

            @"
<tr>
<td>$($exemptionScope)</td>
<td>$($mgId)</td>
<td>$($mgName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($subId)</td>
<td>$($subName)</td>
<td>$($rgName)</td>
<td>$($resName)</td>
<td>$($exemption.properties.DisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($exemption.properties.Description -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($exemption.properties.exemptionCategory -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($exemptionExpiresOn)</td>
<td class="breakwordall">$($exemption.Id)</td>
<td class="breakwordall">$($exemption.properties.policyAssignmentId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policyType)</td>
<td class="breakwordall">$($policy)</td>
<td class="breakwordall">$($policiesExempted)</td>
<td>$($exemption.systemData.createdBy) ($($exemption.systemData.createdByType))</td>
<td>$($exemption.systemData.createdAt.ToString('yyyy-MM-dd HH:mm:ss'))</td>
<td>$($exemption.systemData.lastModifiedBy) ($($exemption.systemData.lastModifiedByType))</td>
<td>$($exemption.systemData.lastModifiedAt.ToString('yyyy-MM-dd HH:mm:ss'))</td>
</tr>
"@
        }

        if (-not $NoCsvExport) {
            Write-Host "Exporting PolicyExemptions CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_PolicyExemptions.csv'"
            $exemptionData4CSVExport | Sort-Object -Property PolicyAssignmentId, Id | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_PolicyExemptions.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
        }

        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYPolicyExemptions)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
            col_9: 'select',
            col_13: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'date',
                'caseinsensitivestring',
                'date'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $($policyExemptionsCount) Policy exemptions</p>
"@)
    }
    #endregion SUMMARYPolicyExemptions

    #region SUMMARYPolicyAssignmentsOrphaned
    Write-Host '  processing TenantSummary PolicyAssignments orphaned'

    if ($policyAssignmentsOrphanedCount -gt 0) {
        $tfCount = $policyAssignmentsOrphanedCount
        $htmlTableId = 'TenantSummary_policyAssignmentsOrphaned'

        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_policyAssignmentsOrphaned"><i class="padlx fa fa-exclamation-triangle orange" aria-hidden="true"></i> <span class="valignMiddle">$($policyAssignmentsOrphanedCount) Policy assignments orphaned <abbr title="Policy definition not available &#13;(likely a Management Group scoped Policy definition / Management Group deleted)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Policy AssignmentId</th>
<th>Policy/Set definition</th>
</tr>
</thead>
<tbody>
"@)

        $htmlSUMMARYPolicyassignmentsOrphaned = $null
        $htmlSUMMARYPolicyassignmentsOrphaned = foreach ($orphanedPolicyAssignment in $policyAssignmentsOrphaned | Sort-Object -Property PolicyAssignmentId) {
            @"
<tr>
<td>$($orphanedPolicyAssignment.policyAssignmentId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($orphanedPolicyAssignment.PolicyDefinitionId -replace '<', '&lt;' -replace '>', '&gt;')</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYPolicyassignmentsOrphaned)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $($policyAssignmentsOrphanedCount) Policy assignments orphaned <abbr title="Policy definition not available &#13;(likely a Management Group scoped Policy definition / Management Group deleted)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></p>
"@)
    }
    #endregion SUMMARYPolicyAssignmentsOrphaned

    #region SUMMARYPolicyAssignmentsAll
    $startSummaryPolicyAssignmentsAll = Get-Date
    $allPolicyAssignments = ($policyBaseQuery).count
    Write-Host "  processing TenantSummary PolicyAssignments (all $allPolicyAssignments)"

    $script:arrayPolicyAssignmentsEnriched = [System.Collections.ArrayList]@()
    $cnter = 0

    #region PolicyAssignmentsRoleAssignmentMapping
    $startPolicyAssignmentsRoleAssignmentMapping = Get-Date
    Write-Host '   processing PolicyAssignmentsRoleAssignmentMapping'
    $script:htPolicyAssignmentRoleAssignmentMapping = @{}
    foreach ($roleassignmentId in ($htCacheAssignmentsRole).keys | Sort-Object) {
        $roleAssignment = ($htCacheAssignmentsRole).($roleassignmentId).Assignment

        if ($htManagedIdentityForPolicyAssignment.($roleAssignment.ObjectId)) {
            $mi = $htManagedIdentityForPolicyAssignment.($roleAssignment.ObjectId)

            #this
            if (-not $htPolicyAssignmentRoleAssignmentMapping.(($mi.policyAssignmentId).ToLower())) {
                $script:htPolicyAssignmentRoleAssignmentMapping.(($mi.policyAssignmentId).ToLower()) = @{}
            }

            if (($htCacheDefinitionsRole).($roleAssignment.RoleDefinitionId).IsCustom) {
                $roleDefinitionType = 'custom'
            }
            else {
                $roleDefinitionType = 'builtin'
            }

            $array = [System.Collections.ArrayList]@()
            $null = $array.Add([PSCustomObject]@{
                    roleassignmentId   = $roleassignmentId
                    roleDefinitionId   = $roleAssignment.RoleDefinitionId
                    roleDefinitionName = $roleAssignment.RoleDefinitionName
                    roleDefinitionType = $roleDefinitionType
                })

            #this
            if ($htPolicyAssignmentRoleAssignmentMapping.(($mi.policyAssignmentId).ToLower()).roleassignments) {
                $script:htPolicyAssignmentRoleAssignmentMapping.(($mi.policyAssignmentId).ToLower()).roleassignments += $array
            }
            else {
                $script:htPolicyAssignmentRoleAssignmentMapping.(($mi.policyAssignmentId).ToLower()).roleassignments = $array
            }
        }
    }

    if ($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC) {
        foreach ($roleassignmentId in ($htCacheAssignmentsRBACOnResourceGroupsAndResources).keys | Sort-Object) {
            $roleAssignment = ($htCacheAssignmentsRBACOnResourceGroupsAndResources).($roleassignmentId)

            if ($htManagedIdentityForPolicyAssignment.($roleAssignment.ObjectId)) {
                $mi = $htManagedIdentityForPolicyAssignment.($roleAssignment.ObjectId)

                #this
                if (-not $htPolicyAssignmentRoleAssignmentMapping.(($mi.policyAssignmentId).ToLower())) {
                    $script:htPolicyAssignmentRoleAssignmentMapping.(($mi.policyAssignmentId).ToLower()) = @{}
                }

                if (($htCacheDefinitionsRole).($roleAssignment.RoleDefinitionId).IsCustom) {
                    $roleDefinitionType = 'custom'
                }
                else {
                    $roleDefinitionType = 'builtin'
                }

                $array = [System.Collections.ArrayList]@()
                $null = $array.Add([PSCustomObject]@{
                        roleassignmentId   = $roleassignmentId
                        roleDefinitionId   = $roleAssignment.RoleDefinitionId
                        roleDefinitionName = $roleAssignment.RoleDefinitionName
                        roleDefinitionType = $roleDefinitionType
                    })

                #this
                if ($htPolicyAssignmentRoleAssignmentMapping.(($mi.policyAssignmentId).ToLower()).roleassignments) {
                    $script:htPolicyAssignmentRoleAssignmentMapping.(($mi.policyAssignmentId).ToLower()).roleassignments += $array
                }
                else {
                    $script:htPolicyAssignmentRoleAssignmentMapping.(($mi.policyAssignmentId).ToLower()).roleassignments = $array
                }
            }
        }
    }
    $htPolicyAssignmentRoleAssignmentMappingCount = ($htPolicyAssignmentRoleAssignmentMapping.keys).Count
    $endPolicyAssignmentsRoleAssignmentMapping = Get-Date
    Write-Host "   PolicyAssignmentsRoleAssignmentMapping processing duration: $((New-TimeSpan -Start $startPolicyAssignmentsRoleAssignmentMapping -End $endPolicyAssignmentsRoleAssignmentMapping).TotalMinutes) minutes ($((New-TimeSpan -Start $startPolicyAssignmentsRoleAssignmentMapping -End $endPolicyAssignmentsRoleAssignmentMapping).TotalSeconds) seconds)"
    #endregion PolicyAssignmentsRoleAssignmentMapping

    #region PolicyAssignmentsUniqueRelations
    $startPolicyAssignmnetsUniqueRelations = Get-Date
    Write-Host '   processing PolicyAssignmnetsUniqueRelations'
    $htPolicyAssignmentRelatedRoleAssignments = @{}
    $htPolicyAssignmentRelatedExemptions = @{}

    foreach ($policyAssignmentIdUnique in $policyBaseQueryUniqueAssignments) {

        #region relatedRoleAssignments
        $relatedRoleAssignmentsArray = @()
        $relatedRoleAssignmentsArrayClear = @()
        if ($htPolicyAssignmentRoleAssignmentMappingCount -gt 0) {
            if ($htPolicyAssignmentRoleAssignmentMapping.($policyAssignmentIdUnique.PolicyAssignmentId)) {
                foreach ($entry in $htPolicyAssignmentRoleAssignmentMapping.($policyAssignmentIdUnique.PolicyAssignmentId).roleassignments) {
                    if ($entry.roleDefinitionType -eq 'builtin') {
                        $relatedRoleAssignmentsArray += "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azrolesadvertizer/$($entry.roleDefinitionId).html`" target=`"_blank`" rel=`"noopener`">$($entry.roleDefinitionName)</a> ($($entry.roleAssignmentId))"
                    }
                    else {
                        $relatedRoleAssignmentsArray += "<b>$($entry.roleDefinitionName -replace '<', '&lt;' -replace '>', '&gt;')</b> ($($entry.roleAssignmentId))"
                    }
                    $relatedRoleAssignmentsArrayClear += "$($entry.roleDefinitionName) ($($entry.roleAssignmentId))"
                }
            }
        }

        $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId) = @{}
        if (($relatedRoleAssignmentsArray).count -gt 0) {
            $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId).relatedRoleAssignments = ($relatedRoleAssignmentsArray | Sort-Object) -join "$CsvDelimiterOpposite "
            $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId).relatedRoleAssignmentsClear = ($relatedRoleAssignmentsArrayClear | Sort-Object) -join "$CsvDelimiterOpposite "
        }
        else {
            $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId).relatedRoleAssignments = 'none'
            $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId).relatedRoleAssignmentsClear = 'none'
        }
        #endregion relatedRoleAssignments

        #region exemptions
        $arrayExemptions = @()
        foreach ($exemptionId in $htPolicyAssignmentExemptions.keys) {
            if ($htPolicyAssignmentExemptions.($exemptionId).exemption.properties.policyAssignmentId -eq $policyAssignmentIdUnique.PolicyAssignmentId) {
                $arrayExemptions += $htPolicyAssignmentExemptions.($exemptionId).exemption
                if (-not $htPolicyAssignmentRelatedExemptions.($policyAssignmentIdUnique.PolicyAssignmentId)) {
                    $htPolicyAssignmentRelatedExemptions.($policyAssignmentIdUnique.PolicyAssignmentId) = @{}
                    $htPolicyAssignmentRelatedExemptions.($policyAssignmentIdUnique.PolicyAssignmentId).exemptionsCount = 1
                    $htPolicyAssignmentRelatedExemptions.($policyAssignmentIdUnique.PolicyAssignmentId).exemptions = $arrayExemptions
                }
                else {
                    $htPolicyAssignmentRelatedExemptions.($policyAssignmentIdUnique.PolicyAssignmentId).exemptionsCount += 1
                    $htPolicyAssignmentRelatedExemptions.($policyAssignmentIdUnique.PolicyAssignmentId).exemptions = $arrayExemptions
                }
            }
        }
        #endregion exemptions
    }
    $endPolicyAssignmnetsUniqueRelations = Get-Date
    Write-Host "   PolicyAssignmnetsUniqueRelations processing duration: $((New-TimeSpan -Start $startPolicyAssignmnetsUniqueRelations -End $endPolicyAssignmnetsUniqueRelations).TotalMinutes) minutes ($((New-TimeSpan -Start $startPolicyAssignmnetsUniqueRelations -End $endPolicyAssignmnetsUniqueRelations).TotalSeconds) seconds)"
    #endregion PolicyAssignmentsUniqueRelations

    #region PolicyAssignmentsAllCreateEnriched
    $startPolicyAssignmentsAllCreateEnriched = Get-Date
    Write-Host '   processing PolicyAssignmentsAllCreateEnriched'
    foreach ($policyAssignmentAll in $policyBaseQuery) {

        $cnter++
        if ($cnter % 1000 -eq 0) {
            $etappeSummaryPolicyAssignmentsAll = Get-Date
            Write-Host "    $cnter of $allPolicyAssignments PolicyAssignments processed: $((New-TimeSpan -Start $startSummaryPolicyAssignmentsAll -End $etappeSummaryPolicyAssignmentsAll).TotalSeconds) seconds"
        }

        #region AzAdvertizerLinkOrNot
        if ($policyAssignmentAll.PolicyType -eq 'builtin') {
            if ($policyAssignmentAll.PolicyVariant -eq 'Policy') {
                $azaLinkOrNot = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/$(($policyAssignmentAll.PolicyDefinitionIdGuid)).html`" target=`"_blank`" rel=`"noopener`">$($policyAssignmentAll.Policy)</a>"
            }
            else {
                $azaLinkOrNot = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyinitiativesadvertizer/$(($policyAssignmentAll.PolicyDefinitionIdGuid)).html`" target=`"_blank`" rel=`"noopener`">$($policyAssignmentAll.Policy)</a>"
            }
        }
        else {
            $azaLinkOrNot = $policyAssignmentAll.Policy
        }
        #endregion AzAdvertizerLinkOrNot

        #region excludedScope
        $excludedScope = 'false'
        if (($policyAssignmentAll.PolicyAssignmentNotScopes).count -gt 0) {
            foreach ($policyAssignmentNotScope in $policyAssignmentAll.PolicyAssignmentNotScopes) {
                if (-not [String]::IsNullOrEmpty($policyAssignmentAll.subscriptionId)) {
                    if ($htSubscriptionsMgPath.($policyAssignmentAll.subscriptionId).path -contains ($($policyAssignmentNotScope -replace '/subscriptions/' -replace '/providers/Microsoft.Management/managementGroups/'))) {
                        $excludedScope = 'true'
                    }
                }
                else {
                    if ($htManagementGroupsMgPath.($policyAssignmentAll.MgId).path -contains ($($policyAssignmentNotScope -replace '/providers/Microsoft.Management/managementGroups/'))) {
                        $excludedScope = 'true'
                    }
                }
            }
        }
        #endregion excludedScope

        #region exemptions
        $exemptionScope = 'false'
        if ($htPolicyAssignmentRelatedExemptions.($policyAssignmentAll.PolicyAssignmentId)) {
            foreach ($exemption in $htPolicyAssignmentRelatedExemptions.($policyAssignmentAll.PolicyAssignmentId).exemptions) {
                if ($exemption.properties.expiresOn) {
                    if ($exemption.properties.expiresOn -gt (Get-Date).ToUniversalTime()) {
                        if (-not [String]::IsNullOrEmpty($policyAssignmentAll.subscriptionId)) {
                            if ($htSubscriptionsMgPath.($policyAssignmentAll.subscriptionId).path -contains ($(($exemption.Id -split '/providers/Microsoft.Authorization/policyExemptions/')[0] -replace '/subscriptions/' -replace '/providers/Microsoft.Management/managementGroups/'))) {
                                $exemptionScope = 'true'
                            }
                        }
                        else {
                            if ($htManagementGroupsMgPath.($policyAssignmentAll.MgId).path -contains ($(($exemption.Id -split '/providers/Microsoft.Authorization/policyExemptions/')[0] -replace '/subscriptions/' -replace '/providers/Microsoft.Management/managementGroups/'))) {
                                $exemptionScope = 'true'
                            }
                        }
                    }
                    else {
                        #Write-Host "$($exemption.Id) $($exemption.properties.expiresOn) $((Get-Date).ToUniversalTime()) expired"
                    }
                }
                else {
                    #same code as above / function?
                    if (-not [String]::IsNullOrEmpty($policyAssignmentAll.subscriptionId)) {
                        if ($htSubscriptionsMgPath.($policyAssignmentAll.subscriptionId).path -contains ($(($exemption.Id -split '/providers/Microsoft.Authorization/policyExemptions/')[0] -replace '/subscriptions/' -replace '/providers/Microsoft.Management/managementGroups/'))) {
                            $exemptionScope = 'true'
                        }
                    }
                    else {
                        if ($htManagementGroupsMgPath.($policyAssignmentAll.MgId).path -contains ($(($exemption.Id -split '/providers/Microsoft.Authorization/policyExemptions/')[0] -replace '/subscriptions/' -replace '/providers/Microsoft.Management/managementGroups/'))) {
                            $exemptionScope = 'true'
                        }
                    }
                }
            }
        }
        #endregion exemptions

        #region inheritance
        if ($policyAssignmentAll.PolicyAssignmentId -like '/providers/Microsoft.Management/managementGroups/*') {
            if (-not [String]::IsNullOrEmpty($policyAssignmentAll.SubscriptionId)) {
                $scope = "inherited $($policyAssignmentAll.PolicyAssignmentScope -replace '.*/')"
            }
            else {
                if (($policyAssignmentAll.PolicyAssignmentScope -replace '.*/') -eq $policyAssignmentAll.MgId) {
                    $scope = 'thisScope Mg'
                }
                else {
                    $scope = "inherited $($policyAssignmentAll.PolicyAssignmentScope -replace '.*/')"
                }
            }
        }

        if ($policyAssignmentAll.PolicyAssignmentId -like '/subscriptions/*' -and $policyAssignmentAll.PolicyAssignmentId -notlike '/subscriptions/*/resourcegroups/*') {
            $scope = 'thisScope Sub'
        }

        if ($policyAssignmentAll.PolicyAssignmentId -like '/subscriptions/*/resourcegroups/*') {
            $scope = 'thisScope Sub RG'
        }
        #endregion inheritance

        #region effect
        $effect = 'unknown'
        if ($policyAssignmentAll.PolicyVariant -eq 'Policy') {

            $test0 = $policyAssignmentAll.PolicyAssignmentParameters.effect.value
            if ($test0) {
                $effect = $test0
            }
            else {
                $test1 = $policyAssignmentAll.PolicyDefinitionEffectDefault
                if ($test1 -ne 'n/a') {
                    $effect = $test1
                }
                $test2 = $policyAssignmentAll.PolicyDefinitionEffectFixed
                if ($test2 -ne 'n/a') {
                    $effect = $test2
                }
            }
        }
        else {
            $effect = 'n/a'
        }
        #endregion effect

        #region mgOrSubOrRG
        if ([String]::IsNullOrEmpty($policyAssignmentAll.SubscriptionId)) {
            $mgOrSubOrRG = 'Mg'
        }
        else {
            if ($scope -like '*RG') {
                $mgOrSubOrRG = 'RG'
            }
            else {
                $mgOrSubOrRG = 'Sub'
            }
        }
        #endregion mgOrSubOrRG

        #region category
        if ([string]::IsNullOrEmpty($policyAssignmentAll.PolicyCategory)) {
            $policyCategory = 'n/a'
        }
        else {
            $policyCategory = $policyAssignmentAll.PolicyCategory
        }
        #endregion category

        #region createdByUpdatedBy
        #createdBy
        if ($policyAssignmentAll.PolicyAssignmentCreatedBy) {
            $createdBy = $policyAssignmentAll.PolicyAssignmentCreatedBy
            if ($htIdentitiesWithRoleAssignmentsUnique.($createdBy)) {
                $createdBy = $htIdentitiesWithRoleAssignmentsUnique.($createdBy).details
            }
        }
        else {
            $createdBy = ''
        }

        #UpdatedBy
        if ($policyAssignmentAll.PolicyAssignmentUpdatedBy) {
            $updatedBy = $policyAssignmentAll.PolicyAssignmentUpdatedBy
            if ($htIdentitiesWithRoleAssignmentsUnique.($updatedBy)) {
                $updatedBy = $htIdentitiesWithRoleAssignmentsUnique.($updatedBy).details
            }
        }
        else {
            $updatedBy = ''
        }
        #endregion createdByUpdatedBy

        #region policyAssignmentNotScopes
        if ($policyAssignmentAll.PolicyAssignmentNotScopes) {
            $policyAssignmentNotScopes = $policyAssignmentAll.PolicyAssignmentNotScopes -join $CsvDelimiterOpposite
        }
        else {
            $policyAssignmentNotScopes = 'n/a'
        }
        #endregion policyAssignmentNotScopes

        #region
        $policyAssignmentMI = ''
        if ($htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentAll.PolicyAssignmentId)) {
            $hlp = $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentAll.PolicyAssignmentId)
            $relatedRoleAssignments = $hlp.relatedRoleAssignments
            $relatedRoleAssignmentsClear = $hlp.relatedRoleAssignmentsClear
            if ($htManagedIdentityDisplayName.("$($policyAssignmentAll.PolicyAssignmentId -replace '.*/')_$($policyAssignmentAll.PolicyAssignmentId)")) {
                $hlp = $htManagedIdentityDisplayName.("$($policyAssignmentAll.PolicyAssignmentId -replace '.*/')_$($policyAssignmentAll.PolicyAssignmentId)")
                $policyAssignmentMI = "$($hlp.displayname) (SPObjId: $($hlp.id))"
            }
        }
        #endregion

        if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {
            #region policyCompliance
            $policyAssignmentIdToLower = ($policyAssignmentAll.policyAssignmentId).ToLower()

            #mg
            if ([String]::IsNullOrEmpty($policyAssignmentAll.subscriptionId)) {
                if (($htCachePolicyComplianceResponseTooLargeMG).($policyAssignmentAll.MgId)) {
                    $NonCompliantPolicies = 'skipped'
                    $CompliantPolicies = 'skipped'
                    $NonCompliantResources = 'skipped'
                    $CompliantResources = 'skipped'
                    $ConflictingResources = 'skipped'
                }
                else {
                    $compliance = ($htCachePolicyComplianceMG).($policyAssignmentAll.MgId).($policyAssignmentIdToLower)
                    $NonCompliantPolicies = $compliance.NonCompliantPolicies
                    $CompliantPolicies = $compliance.CompliantPolicies
                    $NonCompliantResources = $compliance.NonCompliantResources
                    $CompliantResources = $compliance.CompliantResources
                    $ConflictingResources = $compliance.ConflictingResources

                    if (!$NonCompliantPolicies) {
                        $NonCompliantPolicies = 0
                    }
                    if (!$CompliantPolicies) {
                        $CompliantPolicies = 0
                    }
                    if (!$NonCompliantResources) {
                        $NonCompliantResources = 0
                    }
                    if (!$CompliantResources) {
                        $CompliantResources = 0
                    }
                    if (!$ConflictingResources) {
                        $ConflictingResources = 0
                    }
                }
            }

            #sub/rg
            if (-not [String]::IsNullOrEmpty($policyAssignmentAll.subscriptionId)) {
                if (($htCachePolicyComplianceResponseTooLargeSUB).($policyAssignmentAll.SubscriptionId)) {
                    $NonCompliantPolicies = 'skipped'
                    $CompliantPolicies = 'skipped'
                    $NonCompliantResources = 'skipped'
                    $CompliantResources = 'skipped'
                    $ConflictingResources = 'skipped'
                }
                else {
                    $compliance = ($htCachePolicyComplianceSUB).($policyAssignmentAll.SubscriptionId).($policyAssignmentIdToLower)
                    $NonCompliantPolicies = $compliance.NonCompliantPolicies
                    $CompliantPolicies = $compliance.CompliantPolicies
                    $NonCompliantResources = $compliance.NonCompliantResources
                    $CompliantResources = $compliance.CompliantResources
                    $ConflictingResources = $compliance.ConflictingResources

                    if (!$NonCompliantPolicies) {
                        $NonCompliantPolicies = 0
                    }
                    if (!$CompliantPolicies) {
                        $CompliantPolicies = 0
                    }
                    if (!$NonCompliantResources) {
                        $NonCompliantResources = 0
                    }
                    if (!$CompliantResources) {
                        $CompliantResources = 0
                    }
                    if (!$ConflictingResources) {
                        $ConflictingResources = 0
                    }
                }
            }
            #endregion policyCompliance

            $null = $script:arrayPolicyAssignmentsEnriched.Add([PSCustomObject]@{
                    Level                                 = $policyAssignmentAll.Level
                    MgId                                  = $policyAssignmentAll.MgId
                    MgName                                = $policyAssignmentAll.MgName
                    MgParentId                            = $policyAssignmentAll.MgParentId
                    MgParentName                          = $policyAssignmentAll.MgParentName
                    subscriptionId                        = $policyAssignmentAll.SubscriptionId
                    subscriptionName                      = $policyAssignmentAll.Subscription
                    PolicyAssignmentId                    = (($policyAssignmentAll.PolicyAssignmentId).ToLower())
                    PolicyAssignmentScopeName             = $policyAssignmentAll.PolicyAssignmentScopeName
                    PolicyAssignmentDisplayName           = $policyAssignmentAll.PolicyAssignmentDisplayName
                    PolicyAssignmentDescription           = $policyAssignmentAll.PolicyAssignmentDescription
                    PolicyAssignmentEnforcementMode       = $policyAssignmentAll.PolicyAssignmentEnforcementMode
                    PolicyAssignmentNonComplianceMessages = $policyAssignmentAll.PolicyAssignmentNonComplianceMessages
                    PolicyAssignmentNotScopes             = $policyAssignmentNotScopes
                    PolicyAssignmentParameters            = $policyAssignmentAll.PolicyAssignmentParametersFormated
                    PolicyAssignmentMI                    = $policyAssignmentMI
                    AssignedBy                            = $policyAssignmentAll.PolicyAssignmentAssignedBy
                    CreatedOn                             = $policyAssignmentAll.PolicyAssignmentCreatedOn
                    CreatedBy                             = $createdBy
                    UpdatedOn                             = $policyAssignmentAll.PolicyAssignmentUpdatedOn
                    UpdatedBy                             = $updatedBy
                    Effect                                = $effect
                    PolicyName                            = $azaLinkOrNot
                    PolicyNameClear                       = $policyAssignmentAll.Policy
                    PolicyAvailability                    = $policyAssignmentAll.PolicyAvailability
                    PolicyDescription                     = $policyAssignmentAll.PolicyDescription
                    PolicyId                              = $policyAssignmentAll.PolicyDefinitionId
                    PolicyVariant                         = $policyAssignmentAll.PolicyVariant
                    PolicyType                            = $policyAssignmentAll.PolicyType
                    PolicyIsALZ                           = $policyAssignmentAll.PolicyIsALZ
                    PolicyCategory                        = $policyCategory
                    Inheritance                           = $scope
                    ExcludedScope                         = $excludedScope
                    RelatedRoleAssignments                = $relatedRoleAssignments
                    RelatedRoleAssignmentsClear           = $relatedRoleAssignmentsClear
                    mgOrSubOrRG                           = $mgOrSubOrRG
                    NonCompliantPolicies                  = $NonCompliantPolicies
                    CompliantPolicies                     = $CompliantPolicies
                    NonCompliantResources                 = $NonCompliantResources
                    CompliantResources                    = $CompliantResources
                    ConflictingResources                  = $ConflictingResources
                    ExemptionScope                        = $exemptionScope
                })
        }
        else {
            $null = $script:arrayPolicyAssignmentsEnriched.Add([PSCustomObject]@{
                    Level                                 = $policyAssignmentAll.Level
                    MgId                                  = $policyAssignmentAll.MgId
                    MgName                                = $policyAssignmentAll.MgName
                    MgParentId                            = $policyAssignmentAll.MgParentId
                    MgParentName                          = $policyAssignmentAll.MgParentName
                    subscriptionId                        = $policyAssignmentAll.SubscriptionId
                    subscriptionName                      = $policyAssignmentAll.Subscription
                    PolicyAssignmentId                    = (($policyAssignmentAll.PolicyAssignmentId).ToLower())
                    PolicyAssignmentScopeName             = $policyAssignmentAll.PolicyAssignmentScopeName
                    PolicyAssignmentDisplayName           = $policyAssignmentAll.PolicyAssignmentDisplayName
                    PolicyAssignmentDescription           = $policyAssignmentAll.PolicyAssignmentDescription
                    PolicyAssignmentEnforcementMode       = $policyAssignmentAll.PolicyAssignmentEnforcementMode
                    PolicyAssignmentNonComplianceMessages = $policyAssignmentAll.PolicyAssignmentNonComplianceMessages
                    PolicyAssignmentNotScopes             = $policyAssignmentNotScopes
                    PolicyAssignmentParameters            = $policyAssignmentAll.PolicyAssignmentParametersFormated
                    PolicyAssignmentMI                    = $policyAssignmentMI
                    AssignedBy                            = $policyAssignmentAll.PolicyAssignmentAssignedBy
                    CreatedOn                             = $policyAssignmentAll.PolicyAssignmentCreatedOn
                    CreatedBy                             = $createdBy
                    UpdatedOn                             = $policyAssignmentAll.PolicyAssignmentUpdatedOn
                    UpdatedBy                             = $updatedBy
                    Effect                                = $effect
                    PolicyName                            = $azaLinkOrNot
                    PolicyNameClear                       = $policyAssignmentAll.Policy
                    PolicyAvailability                    = $policyAssignmentAll.PolicyAvailability
                    PolicyDescription                     = $policyAssignmentAll.PolicyDescription
                    PolicyId                              = $policyAssignmentAll.PolicyDefinitionId
                    PolicyVariant                         = $policyAssignmentAll.PolicyVariant
                    PolicyType                            = $policyAssignmentAll.PolicyType
                    PolicyIsALZ                           = $policyAssignmentAll.PolicyIsALZ
                    PolicyCategory                        = $policyCategory
                    Inheritance                           = $scope
                    ExcludedScope                         = $excludedScope
                    RelatedRoleAssignments                = $relatedRoleAssignments
                    RelatedRoleAssignmentsClear           = $relatedRoleAssignmentsClear
                    mgOrSubOrRG                           = $mgOrSubOrRG
                    ExemptionScope                        = $exemptionScope
                })
        }
    }
    $EndPolicyAssignmentsAllCreateEnriched = Get-Date
    Write-Host "   PolicyAssignmentsAllCreateEnriched processing duration: $((New-TimeSpan -Start $startPolicyAssignmentsAllCreateEnriched -End $EndPolicyAssignmentsAllCreateEnriched).TotalMinutes) minutes ($((New-TimeSpan -Start $startPolicyAssignmentsAllCreateEnriched -End $EndPolicyAssignmentsAllCreateEnriched).TotalSeconds) seconds)"
    #endregion PolicyAssignmentsAllCreateEnriched

    #region PolicyAssignmentsAllResolveIdentities
    Write-Host '   processing unresoved Identities (createdBy/updatedBy)'
    $startUnResolvedIdentitiesCreatedByUpdatedByPolicy = Get-Date

    $createdByNotResolved = ($arrayPolicyAssignmentsEnriched.where( { -not [string]::IsNullOrEmpty($_.CreatedBy) -and $_.CreatedBy -notlike 'ObjectType:*' })).CreatedBy | Sort-Object -Unique
    $updatedByNotResolved = ($arrayPolicyAssignmentsEnriched.where( { -not [string]::IsNullOrEmpty($_.UpdatedBy) -and $_.UpdatedBy -notlike 'ObjectType:*' })).UpdatedBy | Sort-Object -Unique

    $htNonResolvedIdentitiesPolicy = @{}
    foreach ($createdByNotResolvedEntry in $createdByNotResolved) {
        if (-not $htNonResolvedIdentitiesPolicy.($createdByNotResolvedEntry)) {
            $htNonResolvedIdentitiesPolicy.($createdByNotResolvedEntry) = @{}
        }
    }
    foreach ($updatedByNotResolvedEntry in $updatedByNotResolved) {
        if (-not $htNonResolvedIdentitiesPolicy.($updatedByNotResolvedEntry)) {
            $htNonResolvedIdentitiesPolicy.($updatedByNotResolvedEntry) = @{}
        }
    }

    $htNonResolvedIdentitiesPolicyCount = $htNonResolvedIdentitiesPolicy.Count
    if ($htNonResolvedIdentitiesPolicyCount -gt 0) {
        Write-Host "     $htNonResolvedIdentitiesPolicyCount unresolved identities that created/updated a Policy assignment (createdBy/updatedBy)"
        $arrayUnresolvedIdentities = @()
        $arrayUnresolvedIdentities = foreach ($unresolvedIdentity in  $htNonResolvedIdentitiesPolicy.keys) {
            if (-not [string]::IsNullOrEmpty($unresolvedIdentity)) {
                $unresolvedIdentity
            }
        }
        $arrayUnresolvedIdentitiesCount = $arrayUnresolvedIdentities.Count
        Write-Host "     $arrayUnresolvedIdentitiesCount unresolved identities that have a value"
        if ($arrayUnresolvedIdentitiesCount.Count -gt 0) {
            $counterBatch = [PSCustomObject] @{ Value = 0 }
            $batchSize = 1000
            $ObjectBatch = $arrayUnresolvedIdentities | Group-Object -Property { [math]::Floor($counterBatch.Value++ / $batchSize) }
            $ObjectBatchCount = ($ObjectBatch | Measure-Object).Count
            $batchCnt = 0

            $script:htResolvedIdentitiesPolicy = @{}

            foreach ($batch in $ObjectBatch) {
                $batchCnt++

                $nonResolvedIdentitiesToCheck = '"{0}"' -f ($batch.Group.where({ testGuid $_ }) -join '","')
                Write-Host "     IdentitiesToCheck: Batch #$batchCnt/$($ObjectBatchCount) ($(($batch.Group).Count))"
                $uri = "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/directoryObjects/getByIds"
                $method = 'POST'
                $body = @"
                    {
                        "ids":[$($nonResolvedIdentitiesToCheck)]
                    }
"@

                function resolveIdentitiesPolicy($currentTask) {
                    $resolvedIdentities = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -body $body -currentTask $currentTask
                    $resolvedIdentitiesCount = $resolvedIdentities.Count
                    Write-Host "     $resolvedIdentitiesCount identities resolved"
                    if ($resolvedIdentitiesCount -gt 0) {
                        foreach ($resolvedIdentity in $resolvedIdentities) {
                            if (-not $htResolvedIdentitiesPolicy.($resolvedIdentity.id)) {
                                $script:htResolvedIdentitiesPolicy.($resolvedIdentity.id) = @{}
                                if ($resolvedIdentity.'@odata.type' -eq '#microsoft.graph.servicePrincipal') {
                                    if ($resolvedIdentity.servicePrincipalType -eq 'ManagedIdentity') {
                                        $miType = 'unknown'
                                        foreach ($altName in $resolvedIdentity.alternativeNames) {
                                            if ($altName -like 'isExplicit=*') {
                                                $splitAltName = $altName.split('=')
                                                if ($splitAltName[1] -eq 'true') {
                                                    $miType = 'Usr'
                                                }
                                                if ($splitAltName[1] -eq 'false') {
                                                    $miType = 'Sys'
                                                }
                                            }
                                        }
                                        $sptype = "MI $miType"
                                        $custObjectType = "ObjectType: SP $sptype, ObjectDisplayName: $($resolvedIdentity.displayName), ObjectSignInName: n/a, ObjectId: $($resolvedIdentity.id) (rp)"
                                    }
                                    else {
                                        if ($resolvedIdentity.servicePrincipalType -eq 'Application') {
                                            $sptype = 'App'
                                            if ($resolvedIdentity.appOwnerOrganizationId -eq $azAPICallConf['checkContext'].Tenant.Id) {
                                                $custObjectType = "ObjectType: SP $sptype INT, ObjectDisplayName: $($resolvedIdentity.displayName), ObjectSignInName: n/a, ObjectId: $($resolvedIdentity.id) (rp)"
                                            }
                                            else {
                                                $custObjectType = "ObjectType: SP $sptype EXT, ObjectDisplayName: $($resolvedIdentity.displayName), ObjectSignInName: n/a, ObjectId: $($resolvedIdentity.id) (rp)"
                                            }
                                        }
                                        else {
                                            Write-Host "* * * Unexpected IdentityType $($resolvedIdentity.servicePrincipalType)"
                                        }
                                    }
                                    $script:htResolvedIdentitiesPolicy.($resolvedIdentity.id).custObjectType = $custObjectType
                                    $script:htResolvedIdentitiesPolicy.($resolvedIdentity.id).obj = $resolvedIdentity
                                }

                                if ($resolvedIdentity.'@odata.type' -eq '#microsoft.graph.user') {
                                    if ($azAPICallConf['htParameters'].DoNotShowRoleAssignmentsUserData) {
                                        $hlpObjectDisplayName = 'scrubbed'
                                        $hlpObjectSigninName = 'scrubbed'
                                    }
                                    else {
                                        $hlpObjectDisplayName = $resolvedIdentity.displayName
                                        $hlpObjectSigninName = $resolvedIdentity.userPrincipalName
                                    }
                                    $custObjectType = "ObjectType: User, ObjectDisplayName: $hlpObjectDisplayName, ObjectSignInName: $hlpObjectSigninName, ObjectId: $($resolvedIdentity.id) (rp)"

                                    $script:htResolvedIdentitiesPolicy.($resolvedIdentity.id).custObjectType = $custObjectType
                                    $script:htResolvedIdentitiesPolicy.($resolvedIdentity.id).obj = $resolvedIdentity
                                }

                                if ($resolvedIdentity.'@odata.type' -ne '#microsoft.graph.user' -and $resolvedIdentity.'@odata.type' -ne '#microsoft.graph.servicePrincipal') {
                                    Write-Host "!!! * * * IdentityType '$($resolvedIdentity.'@odata.type')' was not considered by Azure Governance Visualizer - if you see this line, please file an issue on GitHub - thank you." -ForegroundColor Yellow
                                }
                            }
                        }
                    }
                }
                resolveIdentitiesPolicy -currentTask 'resolveObjectbyId PolicyAssignment #1'
            }

            foreach ($policyAssignment in $script:arrayPolicyAssignmentsEnriched.where( { -not [string]::IsNullOrEmpty($_.CreatedBy) -and $_.CreatedBy -notlike 'ObjectType*' })) {
                if ($htResolvedIdentitiesPolicy.($policyAssignment.CreatedBy)) {
                    $policyAssignment.CreatedBy = $htResolvedIdentitiesPolicy.($policyAssignment.CreatedBy).custObjectType
                }
            }

            foreach ($policyAssignment in $script:arrayPolicyAssignmentsEnriched.where( { -not [string]::IsNullOrEmpty($_.UpdatedBy) -and $_.UpdatedBy -notlike 'ObjectType*' })) {
                if ($htResolvedIdentitiesPolicy.($policyAssignment.UpdatedBy)) {
                    $policyAssignment.UpdatedBy = $htResolvedIdentitiesPolicy.($policyAssignment.UpdatedBy).custObjectType
                }
            }
        }
    }

    $endUnResolvedIdentitiesCreatedByUpdatedByPolicy = Get-Date
    Write-Host "    UnresolvedIdentities (createdBy/updatedBy) duration: $((New-TimeSpan -Start $startUnResolvedIdentitiesCreatedByUpdatedByPolicy -End $endUnResolvedIdentitiesCreatedByUpdatedByPolicy).TotalMinutes) minutes ($((New-TimeSpan -Start $startUnResolvedIdentitiesCreatedByUpdatedByPolicy -End $endUnResolvedIdentitiesCreatedByUpdatedByPolicy).TotalSeconds) seconds)"
    #endregion PolicyAssignmentsAllResolveIdentities

    $script:arrayPolicyAssignmentsEnrichedGroupedBySubscription = $arrayPolicyAssignmentsEnriched | Group-Object -Property subscriptionId
    $script:arrayPolicyAssignmentsEnrichedGroupedByManagementGroup = $arrayPolicyAssignmentsEnriched | Group-Object -Property MgId

    #region policyAssignmentsAllHTML
    Write-Host '   processing SummaryPolicyAssignmentsAllHTML'
    $startSummaryPolicyAssignmentsAllHTML = Get-Date
    if (($arrayPolicyAssignmentsEnriched).count -gt 0) {

        if (-not $NoCsvExport) {
            $csvFilename = "$($filename)_PolicyAssignments"
            Write-Host "    Exporting PolicyAssignments CSV '$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv'"
            if ($CsvExportUseQuotesAsNeeded) {
                $arrayPolicyAssignmentsEnriched | Sort-Object -Property Level, MgId, SubscriptionId, PolicyAssignmentId | Select-Object -ExcludeProperty PolicyName, RelatedRoleAssignments | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter "$csvDelimiter" -NoTypeInformation -UseQuotes AsNeeded
            }
            else {
                $arrayPolicyAssignmentsEnriched | Sort-Object -Property Level, MgId, SubscriptionId, PolicyAssignmentId | Select-Object -ExcludeProperty PolicyName, RelatedRoleAssignments | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter "$csvDelimiter" -NoTypeInformation
            }
        }

        $policyAssignmentsUniqueCount = ($arrayPolicyAssignmentsEnriched | Sort-Object -Property PolicyAssignmentId -Unique).count
        if ($azAPICallConf['htParameters'].LargeTenant -or $azAPICallConf['htParameters'].PolicyAtScopeOnly) {
            $policyAssignmentsCount = $policyAssignmentsUniqueCount
            $tfCount = $policyAssignmentsCount
        }
        else {
            $policyAssignmentsCount = ($arrayPolicyAssignmentsEnriched).count
            $tfCount = $policyAssignmentsCount
        }

        if ($tfCount -gt $HtmlTableRowsLimit) {
            Write-Host "   !Skipping TenantSummary PolicyAssignments HTML processing as $tfCount lines is exceeding the critical rows limit of $HtmlTableRowsLimit" -ForegroundColor Yellow
            [void]$htmlTenantSummary.AppendLine(@"
            <button type="button" class="collapsible" id="buttonTenantSummary_policyAssignmentsAll_largeDataSet">
                <i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$($policyAssignmentsCount) Policy assignments ($policyAssignmentsUniqueCount unique)</span>
            </button>
            <div class="content TenantSummary padlxx">
                <i class="fa fa-exclamation-triangle orange" aria-hidden="true"></i><span style="color:#ff0000"> Output of $tfCount lines would exceed the html rows limit of $HtmlTableRowsLimit (html file potentially would become unresponsive). Work with the CSV file <i>$($csvFilename).csv</i> | Note: the CSV file will only exist if you did NOT use parameter <i>-NoCsvExport</i></span><br>
                <span style="color:#ff0000">You can adjust the html row limit by using parameter <i>-HtmlTableRowsLimit</i></span><br>
                <span style="color:#ff0000">You can reduce the number of lines by using parameter <i>-LargeTenant</i> and/or <i>-DoNotIncludeResourceGroupsAndResourcesOnRBAC</i></span><br>
                <span style="color:#ff0000">Check the parameters documentation</span> <a class="externallink" href="https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting#parameters" target="_blank" rel="noopener">Azure Governance Visualizer docs <i class="fa fa-external-link" aria-hidden="true"></i></a>
            </div>
"@)
        }
        else {

            $htmlTableId = 'TenantSummary_policyAssignmentsAll'
            $noteOrNot = ''

            [void]$htmlTenantSummary.AppendLine(@"
        <button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_policyAssignmentsAll"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$($policyAssignmentsCount) Policy assignments ($policyAssignmentsUniqueCount unique)</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a><br>
<span class="padlxx hintTableSize">*Depending on the number of rows and your computer´s performance the table may respond with delay, download the csv for better filtering experience</span>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>Management Group Id</th>
<th>Management Group Name</th>
<th>SubscriptionId</th>
<th>Subscription Name</th>
<th>Inheritance</th>
<th>ScopeExcluded</th>
<th>Exemption applies</th>
<th>Policy/Set DisplayName</th>
<th>Policy/Set Description</th>
<th>Policy/SetId</th>
<th>Policy/Set</th>
<th>Type</th>
<th>Category</th>
<th>ALZ</th>
<th>Effect</th>
<th>Parameters</th>
<th>Enforcement</th>
<th>NonCompliance Message</th>
"@)

            if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {
                [void]$htmlTenantSummary.AppendLine(@'
<th>Policies NonCmplnt</th>
<th>Policies Compliant</th>
<th>Resources NonCmplnt</th>
<th>Resources Compliant</th>
<th>Resources Conflicting</th>
'@)
            }

            [void]$htmlTenantSummary.AppendLine(@"
<th>Role/Assignment $noteOrNot</th>
<th>Managed Identity</th>
<th>Assignment DisplayName</th>
<th>Assignment Description</th>
<th>AssignmentId</th>
<th>AssignedBy</th>
<th>CreatedOn</th>
<th>CreatedBy</th>
<th>UpdatedOn</th>
<th>UpdatedBy</th>
</tr>
</thead>
<tbody>
"@)

            $htmlTenantSummary | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
            $htmlTenantSummary = [System.Text.StringBuilder]::new()
            $htmlSummaryPolicyAssignmentsAll = $null
            $startloop = Get-Date

            $htmlSummaryPolicyAssignmentsAll = foreach ($policyAssignment in $arrayPolicyAssignmentsEnriched | Sort-Object -Property Level, MgName, MgId, SubscriptionName, SubscriptionId, PolicyAssignmentId) {
                if ($azAPICallConf['htParameters'].LargeTenant -or $azAPICallConf['htParameters'].PolicyAtScopeOnly) {
                    if ($policyAssignment.Inheritance -like 'inherited *' -and $policyAssignment.MgParentId -ne "'upperScopes'") {
                        continue
                    }
                }
                if ($policyAssignment.PolicyType -eq 'Custom') {
                    $policyName = ($policyAssignment.PolicyName -replace '<', '&lt;' -replace '>', '&gt;')
                }
                else {
                    $policyName = $policyAssignment.PolicyName
                }
                @"
<tr>
<td>$($policyAssignment.mgOrSubOrRG)</td>
<td>$($policyAssignment.MgId)</td>
<td>$($policyAssignment.MgName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policyAssignment.SubscriptionId)</td>
<td>$($policyAssignment.SubscriptionName)</td>
<td>$($policyAssignment.Inheritance)</td>
<td>$($policyAssignment.ExcludedScope)</td>
<td>$($policyAssignment.ExemptionScope)</td>
<td>$($policyName)</td>
<td>$($policyAssignment.PolicyDescription -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($policyAssignment.PolicyId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policyAssignment.PolicyVariant)</td>
<td>$($policyAssignment.PolicyType)</td>
<td>$($policyAssignment.PolicyCategory -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policyAssignment.PolicyIsALZ)</td>
<td>$($policyAssignment.Effect)</td>
<td>$($policyAssignment.PolicyAssignmentParameters)</td>
<td>$($policyAssignment.PolicyAssignmentEnforcementMode)</td>
<td>$($policyAssignment.PolicyAssignmentNonComplianceMessages -replace '<', '&lt;' -replace '>', '&gt;')</td>
"@

                if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {
                    @"
<td>$($policyAssignment.NonCompliantPolicies)</td>
<td>$($policyAssignment.CompliantPolicies)</td>
<td>$($policyAssignment.NonCompliantResources)</td>
<td>$($policyAssignment.CompliantResources)</td>
<td>$($policyAssignment.ConflictingResources)</td>
"@
                }

                @"
<td class="breakwordall">$($policyAssignment.RelatedRoleAssignments)</td>
<td>$($policyAssignment.PolicyAssignmentMI)</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentDescription -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policyAssignment.AssignedBy)</td>
<td>$($policyAssignment.CreatedOn)</td>
<td>$($policyAssignment.CreatedBy)</td>
<td>$($policyAssignment.UpdatedOn)</td>
<td>$($policyAssignment.UpdatedBy)</td>
</tr>
"@
            }

            $endloop = Get-Date
            Write-Host "    html foreach loop duration: $((New-TimeSpan -Start $startloop -End $endloop).TotalSeconds) seconds"

            $start = Get-Date
            [void]$htmlTenantSummary.AppendLine($htmlSummaryPolicyAssignmentsAll)
            $htmlTenantSummary | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
            $htmlTenantSummary = [System.Text.StringBuilder]::new()
            $end = Get-Date
            Write-Host "    html append file duration: $((New-TimeSpan -Start $start -End $end).TotalSeconds) seconds"

            [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
        paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@'
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100
            },
            no_results_message: true,
            linked_filters: true,
            col_0: 'select',
            col_6: 'select',
            col_7: 'select',
            col_11: 'select',
            col_12: 'select',
            col_14: 'select',
            col_16: 'select',
            col_17: 'select',
            locale: 'en-US',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
'@)

            if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {
                [void]$htmlTenantSummary.AppendLine(@'
                'number',
                'number',
                'number',
                'number',
                'number',
'@)
            }

            [void]$htmlTenantSummary.AppendLine(@'
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'date',
                'caseinsensitivestring',
                'date',
                'caseinsensitivestring'
            ],
'@)

            if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {
                [void]$htmlTenantSummary.AppendLine(@'
            watermark: ['', '', '', 'try [nonempty]', '', 'thisScope', '', '', '', '', '', '', '','', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
'@)
            }
            else {
                [void]$htmlTenantSummary.AppendLine(@'
            watermark: ['', '', '', 'try [nonempty]', '', 'thisScope', '', '', '', '', '', '', '','', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
'@)
            }

            [void]$htmlTenantSummary.AppendLine(@'
            extensions: [
                {
                    name: 'colsVisibility',
'@)

            if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {
                [void]$htmlTenantSummary.AppendLine(@'
                    at_start: [9, 26, 27],
'@)
            }
            else {
                [void]$htmlTenantSummary.AppendLine(@'
                    at_start: [9, 21, 22],
'@)
            }

            [void]$htmlTenantSummary.AppendLine(@"
                    text: 'Columns: ',
                    enable_tick_all: true
                },
                { name: 'sort'
                }
            ]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
        }
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $(($arrayPolicyAssignmentsEnriched).count) Policy assignments</p>
"@)
    }
    $endSummaryPolicyAssignmentsAllHTML = Get-Date
    Write-Host "   SummaryPolicyAssignmentsAllHTML duration: $((New-TimeSpan -Start $startSummaryPolicyAssignmentsAllHTML -End $endSummaryPolicyAssignmentsAllHTML).TotalMinutes) minutes ($((New-TimeSpan -Start $startSummaryPolicyAssignmentsAllHTML -End $endSummaryPolicyAssignmentsAllHTML).TotalSeconds) seconds)"
    #endregion policyAssignmentsAllHTML
    $endSummaryPolicyAssignmentsAll = Get-Date
    Write-Host "   SummaryPolicyAssignmentsAll duration: $((New-TimeSpan -Start $startSummaryPolicyAssignmentsAll -End $endSummaryPolicyAssignmentsAll).TotalMinutes) minutes ($((New-TimeSpan -Start $startSummaryPolicyAssignmentsAll -End $endSummaryPolicyAssignmentsAll).TotalSeconds) seconds)"
    #endregion SUMMARYPolicyAssignmentsAll

    #region SUMMARYPolicyRemediation
    Write-Host '  processing TenantSummary Policy Remediation'

    if ($arrayRemediatable.Count -gt 0) {
        $tfCount = $arrayRemediatable.Count
        $nonCompliantResourcesTotal = ($arrayRemediatable.nonCompliantResourcesCount | Measure-Object -Sum).Sum
        $htmlTableId = 'TenantSummary_PolicyRemediation'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_PolicyRemediation"><i class="padlx fa fa-wrench" aria-hidden="true" style="color:#0078df"></i> <span class="valignMiddle">$($arrayRemediatable.Count) Policies to remediate ($($nonCompliantResourcesTotal) nonCompliant resources)</span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Assignment Scope Type</th>
<th>Assignment Scope</th>
<th>Assignment Id</th>
<th>Assignment DisplayName</th>
<th>Assignment Policy/Set</th>
<th>Effect</th>
<th>Policy definition id</th>
<th>Policy definition displayName</th>
<th>Policy definition type</th>
<th>Policy definition refId</th>
<th>PolicySet definition id</th>
<th>PolicySet definition displayName</th>
<th>PolicySet definition type</th>
<th>NonCompliant resources</th>
</tr>
</thead>
<tbody>
"@)

        $htmlSUMMARYPolicyRemediation = $null
        $arrayRemediatableSorted = $arrayRemediatable | Sort-Object -Property nonCompliantResourcesCount, policySetPolicyDefinitionReferenceId, policyDefinitionId, policyAssignmentId -Descending
        if (-not $NoCsvExport) {
            $csvFilename = "$($filename)_PolicyRemediation"
            Write-Host "   Exporting PolicyRemediation CSV '$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv'"
            $arrayRemediatableSorted | Export-Csv -Encoding utf8 -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter $csvDelimiter -NoTypeInformation
        }
        $htmlSUMMARYPolicyRemediation = foreach ($entry in $arrayRemediatableSorted) {

            if ($entry.policyDefinitionType -eq 'builtin') {
                $pd = "<a class=`"externallink`" rel=`"noopener`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/$($entry.policyDefinitionName).html`" target=`"_blank`">$($entry.policyDefinitionDisplayName) <i class=`"fa fa-external-link`" aria-hidden=`"true`"></i></a> ($($entry.policyDefinitionName))"
            }
            else {
                $pd = "$($entry.policyDefinitionDisplayName) ($($entry.policyDefinitionName))"
            }

            if ($entry.policySetDefinitionType -ne 'n/a') {
                if ($entry.policySetDefinitionType -eq 'builtIn') {
                    $psd = "<a class=`"externallink`" rel=`"noopener`" href=`"https://www.azadvertizer.net/azpolicyinitiativesadvertizer/$($entry.policySetDefinitionName).html`" target=`"_blank`">$($entry.policySetDefinitionDisplayName) <i class=`"fa fa-external-link`" aria-hidden=`"true`"></i></a> ($($entry.policySetDefinitionName))"
                }
                else {
                    $psd = "$($entry.policySetDefinitionDisplayName) ($($entry.policySetDefinitionName))"
                }
            }
            else {
                $psd = $entry.policySetDefinitionType
            }

            @"
<tr>
<td>$($entry.policyAssignmentScopeType)</td>
<td>$($entry.policyAssignmentScope)</td>
<td class="breakwordall">$($entry.policyAssignmentId)</td>
<td>$($entry.policyAssignmentDisplayName)</td>
<td>$($entry.policyAssignmentPolicyOrPolicySet)</td>
<td>$($entry.effect)</td>
<td class="breakwordall">$($entry.policyDefinitionId)</td>
<td>$($pd)</td>
<td>$($entry.policyDefinitionType)</td>
<td>$($entry.policySetPolicyDefinitionReferenceId)</td>
<td class="breakwordall">$($entry.policySetDefinitionId)</td>
<td>$($psd)</td>
<td>$($entry.policySetDefinitionType)</td>
<td>$($entry.nonCompliantResourcesCount)</td>
</tr>
"@
        }

        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYPolicyRemediation)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
            col_4: 'select',
            col_5: 'select',
            col_8: 'select',
            col_12: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@'
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No Policies to remediate</p>
'@)
    }
    #endregion SUMMARYPolicyRemediation

    [void]$htmlTenantSummary.AppendLine(@'
    </div>
'@)
    #endregion tenantSummaryPolicy

    showMemoryUsage

    #region tenantSummaryRBAC
    [void]$htmlTenantSummary.AppendLine(@'
<button type="button" class="collapsible" id="tenantSummaryRBAC"><hr class="hr-textRBAC" data-content="RBAC" /></button>
<div class="content TenantSummaryContent">
'@)

    #region SUMMARYtenanttotalcustomroles
    Write-Host '  processing TenantSummary Custom Roles'
    if ($tenantCustomRolesCount -gt $LimitRBACCustomRoleDefinitionsTenant * ($LimitCriticalPercentage / 100)) {
        $faimage = "<i class=`"padlx fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
    }
    else {
        $faimage = "<i class=`"padlx fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
    }

    if ($tenantCustomRolesCount -gt 0) {
        $tfCount = $tenantCustomRolesCount
        $htmlTableId = 'TenantSummary_customRoles'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_customRoles">$faimage <span class="valignMiddle">$tenantCustomRolesCount Custom Role definitions ($scopeNamingSummary) (Limit: $tenantCustomRolesCount/$LimitRBACCustomRoleDefinitionsTenant)</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Assignable Scopes</th>
<th>Data</th>
<th>CreatedOn</th>
<th>CreatedBy</th>
<th>UpdatedOn</th>
<th>UpdatedBy</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYtenanttotalcustomroles = $null
        $htmlSUMMARYtenanttotalcustomroles = foreach ($tenantCustomRole in $tenantCustomRoles | Sort-Object @{Expression = { $_.Name } }, @{Expression = { $_.Id } }) {
            $cachedTenantCustomRole = ($htCacheDefinitionsRole).($tenantCustomRole.Id)
            if (-not [string]::IsNullOrEmpty($cachedTenantCustomRole.DataActions) -or -not [string]::IsNullOrEmpty($cachedTenantCustomRole.NotDataActions)) {
                $roleManageData = 'true'
            }
            else {
                $roleManageData = 'false'
            }

            if (-not [string]::IsNullOrEmpty($cachedTenantCustomRole.Json.properties.createdBy)) {
                $createdBy = $cachedTenantCustomRole.Json.properties.createdBy
                if ($htIdentitiesWithRoleAssignmentsUnique.($createdBy)) {
                    $createdBy = $htIdentitiesWithRoleAssignmentsUnique.($createdBy).details
                }
            }
            else {
                $createdBy = 'IsNullOrEmpty'
            }

            $createdOn = $cachedTenantCustomRole.Json.properties.createdOn
            $createdOnFormated = $createdOn
            $updatedOn = $cachedTenantCustomRole.Json.properties.updatedOn
            if ($updatedOn -eq $createdOn) {
                $updatedOnFormated = ''
                $updatedByRemoveNoiseOrNot = ''
            }
            else {
                $updatedOnFormated = $updatedOn
                if (-not [string]::IsNullOrEmpty($cachedTenantCustomRole.Json.properties.updatedBy)) {
                    $updatedByRemoveNoiseOrNot = $cachedTenantCustomRole.Json.properties.updatedBy
                    if ($htIdentitiesWithRoleAssignmentsUnique.($updatedByRemoveNoiseOrNot)) {
                        $updatedByRemoveNoiseOrNot = $htIdentitiesWithRoleAssignmentsUnique.($updatedByRemoveNoiseOrNot).details
                    }
                }
                else {
                    $updatedByRemoveNoiseOrNot = 'IsNullOrEmpty'
                }
            }
            @"
<tr>
<td>$($cachedTenantCustomRole.Name -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($cachedTenantCustomRole.Id)</td>
<td>$(($cachedTenantCustomRole.AssignableScopes).count) ($($cachedTenantCustomRole.AssignableScopes -join "$CsvDelimiterOpposite "))</td>
<td>$($roleManageData)</td>
<td>$createdOnFormated</td>
<td>$createdBy</td>
<td>$updatedOnFormated</td>
<td>$updatedByRemoveNoiseOrNot</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYtenanttotalcustomroles)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_3: 'select',
            locale: 'en-US',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'select',
                'date',
                'caseinsensitivestring',
                'date',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $tenantCustomRolesCount Custom Role definitions ($scopeNamingSummary)</p>
"@)
    }
    #endregion SUMMARYtenanttotalcustomroles

    #region SUMMARYOrphanedCustomRoles
    $startSUMMARYOrphanedCustomRoles = Get-Date
    Write-Host '  processing TenantSummary Custom Roles orphaned'
    if ($getMgParentName -eq 'Tenant Root') {
        $arrayCustomRolesOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()

        if (($tenantCustomRoles).count -gt 0) {
            $mgSubRoleAssignmentsArrayRoleDefinitionIdUnique = $mgSubRoleAssignmentsArrayFromHTValues.RoleDefinitionId | Sort-Object -Unique
            if ($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC) {
                $rgResRoleAssignmentsArrayRoleDefinitionIdUnique = $rgResRoleAssignmentsArrayFromHTValues.RoleDefinitionId | Sort-Object -Unique
            }
            foreach ($customRoleAll in $tenantCustomRoles) {
                $roleIsUsed = $false
                if (($mgSubRoleAssignmentsArrayRoleDefinitionIdUnique) -contains ($customRoleAll.Id)) {
                    $roleIsUsed = $true
                }

                if ($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC) {
                    if ($roleIsUsed -eq $false) {
                        if (($rgResRoleAssignmentsArrayRoleDefinitionIdUnique) -contains ($customRoleAll.Id)) {
                            $roleIsUsed = $true
                        }
                    }
                }

                #role used in a policyDef (rule roledefinitionIds)
                if ($htRoleDefinitionIdsUsedInPolicy.Keys -contains "/providers/Microsoft.Authorization/roleDefinitions/$($customRoleAll.Id)") {
                    $roleIsUsed = $true
                }

                if ($roleIsUsed -eq $false) {
                    $null = $arrayCustomRolesOrphanedFinalIncludingResourceGroups.Add($customRoleAll)
                }
            }
        }

        if (($arrayCustomRolesOrphanedFinalIncludingResourceGroups).count -gt 0) {
            $tfCount = ($arrayCustomRolesOrphanedFinalIncludingResourceGroups).count
            $htmlTableId = 'TenantSummary_customRolesOrphaned'
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_customRolesOrphaned"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomRolesOrphanedFinalIncludingResourceGroups).count) Orphaned Custom Role definitions ($scopeNamingSummary) <abbr title="Role has no assignments (including ResourceGroups and Resources) &#13;AND &#13;Role is not used in a Policy definition´s rule (roleDefinitionIds)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Assignable Scopes</th>
</tr>
</thead>
<tbody>
"@)
            $htmlSUMMARYOrphanedCustomRoles = $null
            $htmlSUMMARYOrphanedCustomRoles = foreach ($customRoleOrphaned in $arrayCustomRolesOrphanedFinalIncludingResourceGroups | Sort-Object @{Expression = { $_.Name } }) {
                @"
<tr>
<td>$($customRoleOrphaned.Name -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($customRoleOrphaned.Id)</td>
<td>$(($customRoleOrphaned.AssignableScopes).count) ($($customRoleOrphaned.AssignableScopes -join "$CsvDelimiterOpposite "))</td>
</tr>
"@
            }
            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYOrphanedCustomRoles)
            [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@"
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $(($arrayCustomRolesOrphanedFinalIncludingResourceGroups).count) Orphaned Custom Role definitions ($scopeNamingSummary)</p>
"@)
        }
        #not renant root
    }
    else {
        $mgs = (($optimizedTableForPathQueryMg.where( { $_.mgId -ne '' -and $_.Level -ne '0' })) | Select-Object MgId -Unique)
        $arrayCustomRolesOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()

        $mgSubRoleAssignmentsArrayRoleDefinitionIdUnique = $mgSubRoleAssignmentsArrayFromHTValues.RoleDefinitionId | Sort-Object -Unique
        if ($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC) {
            $rgResRoleAssignmentsArrayRoleDefinitionIdUnique = $rgResRoleAssignmentsArrayFromHTValues.RoleDefinitionId | Sort-Object -Unique
        }
        if (($tenantCustomRoles).count -gt 0) {
            foreach ($customRoleAll in $tenantCustomRoles) {
                $roleIsUsed = $false
                $customRoleAssignableScopes = $customRoleAll.AssignableScopes
                foreach ($customRoleAssignableScope in $customRoleAssignableScopes) {
                    if (($customRoleAssignableScope) -like '/providers/Microsoft.Management/managementGroups/*') {
                        $roleAssignableScopeMg = $customRoleAssignableScope -replace '/providers/Microsoft.Management/managementGroups/', ''
                        if ($mgs.MgId -notcontains ($roleAssignableScopeMg)) {
                            #assignableScope outside of the ManagementGroupId Scope
                            $roleIsUsed = $true
                            Continue
                        }
                    }
                }
                if ($roleIsUsed -eq $false) {
                    if (($mgSubRoleAssignmentsArrayRoleDefinitionIdUnique) -contains ($customRoleAll.Id)) {
                        $roleIsUsed = $true
                    }
                }
                if ($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC) {
                    if ($roleIsUsed -eq $false) {
                        if (($rgResRoleAssignmentsArrayRoleDefinitionIdUnique) -contains ($customRoleAll.Id)) {
                            $roleIsUsed = $true
                        }
                    }
                }

                #role used in a policyDef (rule roledefinitionIds)
                if ($htRoleDefinitionIdsUsedInPolicy.Keys -contains "/providers/Microsoft.Authorization/roleDefinitions/$($customRoleAll.Id)") {
                    $roleIsUsed = $true
                }

                if ($roleIsUsed -eq $false) {
                    $null = $arrayCustomRolesOrphanedFinalIncludingResourceGroups.Add($customRoleAll)
                }
            }
        }

        if (($arrayCustomRolesOrphanedFinalIncludingResourceGroups).count -gt 0) {
            $tfCount = ($arrayCustomRolesOrphanedFinalIncludingResourceGroups).count
            $htmlTableId = 'TenantSummary_customRolesOrphaned'
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_customRolesOrphaned"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomRolesOrphanedFinalIncludingResourceGroups).count) Orphaned Custom Role definitions ($scopeNamingSummary) <abbr title="Role has no assignments (including ResourceGroups and Resources) &#13;AND &#13;Role is not used in a Policy definition´s rule (roleDefinitionIds) &#13;(Roles where assignableScopes contains MG Id from superior scopes are not evaluated)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Role Assignable Scopes</th>
</tr>
</thead>
<tbody>
"@)
            $htmlSUMMARYOrphanedCustomRoles = $null
            $htmlSUMMARYOrphanedCustomRoles = foreach ($inScopeCustomRole in $arrayCustomRolesOrphanedFinalIncludingResourceGroups | Sort-Object @{Expression = { $_.Name } }) {
                @"
<tr>
<td>$($inScopeCustomRole.Name -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($inScopeCustomRole.Id)</td>
<td>$(($inScopeCustomRole.AssignableScopes).count) ($($inScopeCustomRole.AssignableScopes -join "$CsvDelimiterOpposite "))</td>
</tr>
"@
            }
            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYOrphanedCustomRoles)
            [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@"
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $(($arrayCustomRolesOrphanedFinalIncludingResourceGroups).count) Orphaned Custom Role definitions ($scopeNamingSummary)</p>
"@)
        }
    }
    $endSUMMARYOrphanedCustomRoles = Get-Date
    Write-Host "   SUMMARYOrphanedCustomRoles duration: $((New-TimeSpan -Start $startSUMMARYOrphanedCustomRoles -End $endSUMMARYOrphanedCustomRoles).TotalMinutes) minutes ($((New-TimeSpan -Start $startSUMMARYOrphanedCustomRoles -End $endSUMMARYOrphanedCustomRoles).TotalSeconds) seconds)"

    #endregion SUMMARYOrphanedCustomRoles

    #region SUMMARYOrphanedRoleAssignments
    Write-Host '  processing TenantSummary RoleAssignments orphaned'
    $roleAssignmentsOrphanedAll = ($rbacBaseQuery.where( { $_.RoleAssignmentIdentityObjectType -eq 'Unknown' })) | Sort-Object -Property RoleAssignmentId
    $roleAssignmentsOrphanedUnique = $roleAssignmentsOrphanedAll | Sort-Object -Property RoleAssignmentId -Unique

    if (($roleAssignmentsOrphanedUnique).count -gt 0) {
        $tfCount = ($roleAssignmentsOrphanedUnique).count
        $htmlTableId = 'TenantSummary_roleAssignmentsOrphaned'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_roleAssignmentsOrphaned"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOrphanedUnique).count) Orphaned Role assignments ($scopeNamingSummary) <abbr title="Role definition was deleted although and assignment existed &#13;OR &#13;Target identity (User, Group, ServicePrincipal) was deleted &#13;OR &#13;Target Resource was moved"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Role AssignmentId</th>
<th>Role Name</th>
<th>RoleId</th>
<th>Impacted Mg/Sub</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYOrphanedRoleAssignments = $null
        foreach ($roleAssignmentOrphanedUnique in $roleAssignmentsOrphanedUnique) {
            $hlpRoleAssignmentsAll = $roleAssignmentsOrphanedAll.where( { $_.RoleAssignmentId -eq $roleAssignmentOrphanedUnique.RoleAssignmentId })
            $impactedMgs = $hlpRoleAssignmentsAll.where( { [String]::IsNullOrEmpty($_.SubscriptionId) }) | Sort-Object -Property MgId
            $impactedSubs = $hlpRoleAssignmentsAll.where( { -not [String]::IsNullOrEmpty($_.SubscriptionId) }) | Sort-Object -Property SubscriptionId
            $htmlSUMMARYOrphanedRoleAssignments += @"
<tr>
<td>$($roleAssignmentOrphanedUnique.RoleAssignmentId)</td>
<td>$($roleAssignmentOrphanedUnique.RoleDefinitionName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($roleAssignmentOrphanedUnique.RoleDefinitionId)</td>
<td>Mg: $(($impactedMgs).count); Sub: $(($impactedSubs).count)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYOrphanedRoleAssignments)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $(($roleAssignmentsOrphanedUnique).count) Orphaned Role assignments ($scopeNamingSummary)</p>
"@)
    }
    #endregion SUMMARYOrphanedRoleAssignments

    #region SUMMARYClassicAdministrators
    Write-Host '  processing TenantSummary ClassicAdministrators'

    if ($htClassicAdministrators.Keys.Count -gt 0) {
        $tfCount = $htClassicAdministrators.Values.ClassicAdministrators.Count
        $htmlTableId = 'TenantSummary_ClassicAdministrators'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_ClassicAdministrators"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$($tfCount) Classic Administrators</span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>MgPath</th>
<th>Role</th>
<th>Identity</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYClassicAdministrators = $null
        $classicAdministrators = $htClassicAdministrators.Values.ClassicAdministrators | Sort-Object -Property Subscription, Role, Identity
        if (-not $NoCsvExport) {
            $csvFilename = "$($filename)_ClassicAdministrators"
            Write-Host "   Exporting ClassicAdministrators CSV '$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv'"
            $classicAdministrators | Select-Object -ExcludeProperty Id | Sort-Object -Property Subscription, SubscriptionId, Role | Export-Csv -Encoding utf8 -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter $csvDelimiter -NoTypeInformation
        }
        $htmlSUMMARYClassicAdministrators = foreach ($classicAdministrator in $classicAdministrators) {
            @"
<tr>
<td>$($classicAdministrator.Subscription)</td>
<td>$($classicAdministrator.SubscriptionId)</td>
<td>$($classicAdministrator.SubscriptionMgPath)</td>
<td>$($classicAdministrator.Role)</td>
<td>$($classicAdministrator.Identity)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYClassicAdministrators)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_3: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@'
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No ClassicAdministrators</p>
'@)
    }
    #endregion SUMMARYClassicAdministrators

    #region SUMMARYRoleAssignmentsAll
    $startRoleAssignmentsAll = Get-Date
    Write-Host '  processing TenantSummary RoleAssignments'

    $startCreateRBACAllHTMLbeforeForeach = Get-Date

    if ($azAPICallConf['htParameters'].LargeTenant -or $azAPICallConf['htParameters'].RBACAtScopeOnly) {
        $rbacAllAtScope = ($rbacAll.where( { ((-not [string]::IsNullOrEmpty($_.SubscriptionId) -and $_.scope -notlike 'inherited *')) -or ([string]::IsNullOrEmpty($_.SubscriptionId)) }))
        $rbacAllCount = $rbacAllAtScope.Count
        $rbacAllUniqueCount = ($rbacAllAtScope.where({ $_.roleAssignmentId }).RoleAssignmentId | Sort-Object -Unique).count
    }
    else {
        $rbacAllCount = $rbacAll.Count
        $rbacAllUniqueCount = ($rbacAll.where({ $_.roleAssignmentId }).RoleAssignmentId | Sort-Object -Unique).count
    }

    if ($rbacAllCount -gt 0) {
        $uniqueRoleAssignmentsCount = ($rbacAll.RoleAssignmentId | Sort-Object -Unique).count
        $tfCount = $rbacAllCount

        if (-not $NoCsvExport) {
            $startCreateRBACAllCSV = Get-Date

            $csvFilename = "$($filename)_RoleAssignments"
            Write-Host "   Exporting RoleAssignments CSV '$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv'"
            if ($CsvExportUseQuotesAsNeeded) {
                if ($azAPICallConf['htParameters'].LargeTenant -or $azAPICallConf['htParameters'].RBACAtScopeOnly) {
                    $rbacAllAtScope | Sort-Object -Property Level, RoleAssignmentId, MgId, SubscriptionId, RoleClear, ObjectId | Select-Object -ExcludeProperty Role, RbacRelatedPolicyAssignment | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter "$csvDelimiter" -NoTypeInformation -UseQuotes AsNeeded
                }
                else {
                    $rbacAll | Sort-Object -Property Level, RoleAssignmentId, MgId, SubscriptionId, RoleClear, ObjectId | Select-Object -ExcludeProperty Role, RbacRelatedPolicyAssignment | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter "$csvDelimiter" -NoTypeInformation -UseQuotes AsNeeded
                }
            }
            else {
                if ($azAPICallConf['htParameters'].LargeTenant -or $azAPICallConf['htParameters'].RBACAtScopeOnly) {
                    $rbacAllAtScope | Sort-Object -Property Level, RoleAssignmentId, MgId, SubscriptionId, RoleClear, ObjectId | Select-Object -ExcludeProperty Role, RbacRelatedPolicyAssignment | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter "$csvDelimiter" -NoTypeInformation
                }
                else {
                    $rbacAll | Sort-Object -Property Level, RoleAssignmentId, MgId, SubscriptionId, RoleClear, ObjectId | Select-Object -ExcludeProperty Role, RbacRelatedPolicyAssignment | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter "$csvDelimiter" -NoTypeInformation
                }
            }

            $endCreateRBACAllCSV = Get-Date
            Write-Host "   CreateRBACAll CSV duration: $((New-TimeSpan -Start $startCreateRBACAllCSV -End $endCreateRBACAllCSV).TotalMinutes) minutes ($((New-TimeSpan -Start $startCreateRBACAllCSV -End $endCreateRBACAllCSV).TotalSeconds) seconds)"
        }

        if ($tfCount -gt $HtmlTableRowsLimit) {
            Write-Host "   !Skipping TenantSummary RoleAssignments HTML processing as $tfCount lines is exceeding the critical rows limit of $HtmlTableRowsLimit" -ForegroundColor Yellow
            [void]$htmlTenantSummary.AppendLine(@"
            <button type="button" class="collapsible" id="buttonTenantSummary_roleAssignmentsAll_largeDataSet">
                <i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$($rbacAllCount) Role assignments ($uniqueRoleAssignmentsCount unique)</span>
            </button>
            <div class="content TenantSummary padlxx">
                <i class="fa fa-exclamation-triangle orange" aria-hidden="true"></i><span style="color:#ff0000"> Output of $tfCount lines would exceed the html rows limit of $HtmlTableRowsLimit (html file potentially would become unresponsive). Work with the CSV file <i>$($csvFilename).csv</i> | Note: the CSV file will only exist if you did NOT use parameter <i>-NoCsvExport</i></span><br>
                <span style="color:#ff0000">You can adjust the html row limit by using parameter <i>-HtmlTableRowsLimit</i></span><br>
                <span style="color:#ff0000">You can reduce the number of lines by using parameter <i>-LargeTenant</i> and/or <i>-DoNotIncludeResourceGroupsAndResourcesOnRBAC</i></span><br>
                <span style="color:#ff0000">Check the parameters documentation</span> <a class="externallink" href="https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting#parameters" target="_blank" rel="noopener">Azure Governance Visualizer docs <i class="fa fa-external-link" aria-hidden="true"></i></a>
            </div>
"@)
        }
        else {

            $roleAssignmentsInfo = @()
            #all
            $roleAssignmentsInfo += "All: $($rbacAllUniqueCount)"
            #static
            $roleAssignmentsInfo += "Standing: $((($rbacAll.where({ $_.RoleAssignmentPIMRelated -eq $false })).roleAssignmentId | Sort-Object -Unique).count)"
            #PIM
            foreach ($pimAssignmentInfo in ($rbacAll.where({ $_.RoleAssignmentPIMRelated -and $_.Scope -notlike 'inherited*' })) | Group-Object -Property RoleAssignmentPIMAssignmentType) {
                $roleAssignmentsInfo += "PIM-$($pimAssignmentInfo.Name): $($pimAssignmentInfo.Count)"
            }

            $htmlTableId = 'TenantSummary_roleAssignmentsAll'
            $noteOrNot = ''
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_roleAssignmentsAll"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$($rbacAllCount) Role assignment related entries (unique -> $($roleAssignmentsInfo -join ', '))</span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a><br>
<span class="padlxx hintTableSize">*Depending on the number of rows and your computer´s performance the table may respond with delay, download the csv for better filtering experience</span>
"@)


            [void]$htmlTenantSummary.AppendLine(@"
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>Management Group Id</th>
<th>Management Group Name</th>
<th>SubscriptionId</th>
<th>Subscription Name</th>
<th>Assignment Scope</th>
<th>Role</th>
<th>Role Id</th>
<th>Role Type</th>
<th>Data</th>
<th>Can do Role assignment</th>
<th>Identity Displayname</th>
<th>Identity SignInName</th>
<th>Identity ObjectId</th>
<th>Identity Type</th>
<th>Applicability</th>
<th>Applies through membership <abbr title="Note: the identity might not be a direct member of the group it could also be member of a nested group"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></th>
<th>Group Details</th>
<th class="uamiresaltbgc">PIM</th>
<th class="uamiresaltbgc">PIM assignment type</th>
<th class="uamiresaltbgc">PIM start</th>
<th class="uamiresaltbgc">PIM end</th>
<th>Role AssignmentId</th>
<th>Related Policy Assignment $noteOrNot</th>
<th>CreatedOn</th>
<th>CreatedBy</th>
</tr>
</thead>
<tbody>
"@)
            $cnter = 0
            $roleAssignmentsAllCount = $rbacAllCount
            $htmlSummaryRoleAssignmentsAll = $null
            $htmlTenantSummary | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
            $htmlTenantSummary = [System.Text.StringBuilder]::new()

            $endCreateRBACAllHTMLbeforeForeach = Get-Date
            Write-Host "   CreateRBACAll HTML before Foreach duration: $((New-TimeSpan -Start $startCreateRBACAllHTMLbeforeForeach -End $endCreateRBACAllHTMLbeforeForeach).TotalMinutes) minutes ($((New-TimeSpan -Start $startCreateRBACAllHTMLbeforeForeach -End $endCreateRBACAllHTMLbeforeForeach).TotalSeconds) seconds)"

            $startSortRBACAll = Get-Date
            if ($azAPICallConf['htParameters'].LargeTenant -or $azAPICallConf['htParameters'].RBACAtScopeOnly) {
                $rbacAllSorted = $rbacAllAtScope | Sort-Object -Property Level, MgName, MgId, SubscriptionName, SubscriptionId, Scope, Role, RoleId, ObjectId, RoleAssignmentId
            }
            else {
                $rbacAllSorted = $rbacAll | Sort-Object -Property Level, MgName, MgId, SubscriptionName, SubscriptionId, Scope, Role, RoleId, ObjectId, RoleAssignmentId
            }

            $endSortRBACAll = Get-Date
            Write-Host "   Sort RBACAll duration: $((New-TimeSpan -Start $startSortRBACAll -End $endSortRBACAll).TotalMinutes) minutes ($((New-TimeSpan -Start $startSortRBACAll -End $endSortRBACAll).TotalSeconds) seconds)"

            $startCreateRBACAllHTMLForeach = Get-Date
            $htmlSummaryRoleAssignmentsAll = [System.Text.StringBuilder]::new()
            foreach ($roleAssignment in $rbacAllSorted) {
                $cnter++
                if ($cnter % 1000 -eq 0) {
                    Write-Host "    create HTML $cnter of $rbacAllCount RoleAssignments processed"
                    if ($cnter % 5000 -eq 0) {
                        Write-Host '     appending..'
                        $htmlSummaryRoleAssignmentsAll | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
                        $htmlSummaryRoleAssignmentsAll = [System.Text.StringBuilder]::new()
                    }
                }

                if ($roleAssignment.RoleType -eq 'Custom') {
                    $roleName = ($roleAssignment.Role -replace '<', '&lt;' -replace '>', '&gt;')
                }
                else {
                    $roleName = $roleAssignment.Role
                }

                [void]$htmlSummaryRoleAssignmentsAll.AppendFormat(
                    @'
<tr>
<td style="width:40px">{0}</td>
<td>{1}</td>
<td>{2}</td>
<td>{3}</td>
<td>{4}</td>
<td>{5}</td>
<td>{6}</td>
<td>{7}</td>
<td>{8}</td>
<td>{9}</td>
<td>{10}</td>
<td class="breakwordall">{11}</td>
<td class="breakwordall">{12}</td>
<td class="breakwordall">{13}</td>
<td style="width:76px" class="breakwordnone">{14}</td>
<td>{15}</td>
<td>{16}</td>
<td>{17}</td>
<td>{18}</td>
<td>{19}</td>
<td>{20}</td>
<td>{21}</td>
<td class="breakwordall">{22}</td>
<td class="breakwordall">{23}</td>
<td class="breakwordall">{24}</td>
<td class="breakwordall">{25}</td>
</tr>
'@, $roleAssignment.ScopeTenOrMgOrSubOrRGOrRes,
                    $roleAssignment.MgId,
                    ($roleAssignment.MgName -replace '<', '&lt;' -replace '>', '&gt;'),
                    $roleAssignment.SubscriptionId,
                    $roleAssignment.SubscriptionName,
                    $roleAssignment.Scope,
                    $roleName,
                    $roleAssignment.RoleId,
                    $roleAssignment.RoleType,
                    $roleAssignment.RoleDataRelated,
                    $roleAssignment.RoleCanDoRoleAssignments,
                    $roleAssignment.ObjectDisplayName,
                    $roleAssignment.ObjectSignInName,
                    $roleAssignment.ObjectId,
                    $roleAssignment.ObjectType,
                    $roleAssignment.AssignmentType,
                    $roleAssignment.AssignmentInheritFrom,
                    $roleAssignment.GroupMembersCount,
                    $roleAssignment.RoleAssignmentPIMRelated,
                    $roleAssignment.RoleAssignmentPIMAssignmentType,
                    $roleAssignment.RoleAssignmentPIMAssignmentSlotStart,
                    $roleAssignment.RoleAssignmentPIMAssignmentSlotEnd,
                    $roleAssignment.RoleAssignmentId,
                    ($roleAssignment.RbacRelatedPolicyAssignment),
                    $roleAssignment.CreatedOn,
                    $roleAssignment.CreatedBy
                )

            }
            $start = Get-Date
            [void]$htmlTenantSummary.AppendLine($htmlSummaryRoleAssignmentsAll)

            $htmlTenantSummary | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
            $htmlSummaryRoleAssignmentsAll = $null #cleanup
            $htmlTenantSummary = [System.Text.StringBuilder]::new()
            $end = Get-Date

            $endCreateRBACAllHTMLForeach = Get-Date
            Write-Host "   CreateRBACAll HTML Foreach duration: $((New-TimeSpan -Start $startCreateRBACAllHTMLForeach -End $endCreateRBACAllHTMLForeach).TotalMinutes) minutes ($((New-TimeSpan -Start $startCreateRBACAllHTMLForeach -End $endCreateRBACAllHTMLForeach).TotalSeconds) seconds)"

            [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            //linked_filters: true,
            col_0: 'multiple',
            col_8: 'select',
            col_9: 'select',
            col_10: 'select',
            col_14: 'multiple',
            col_15: 'select',
            col_18: 'select',
            col_19: 'select',
            locale: 'en-US',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'date',
                'date',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'date',
                'caseinsensitivestring'
            ],
            watermark: ['', '', '', 'try [nonempty]', '', 'thisScope', 'try owner||reader', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
            extensions: [{ name: 'colsVisibility', text: 'Columns: ', enable_tick_all: true },{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)

        }
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $($rbacAllCount) Role assignments</p>
"@)
    }

    $endRoleAssignmentsAll = Get-Date
    Write-Host "   SummaryRoleAssignmentsAll duration: $((New-TimeSpan -Start $startRoleAssignmentsAll -End $endRoleAssignmentsAll).TotalMinutes) minutes ($((New-TimeSpan -Start $startRoleAssignmentsAll -End $endRoleAssignmentsAll).TotalSeconds) seconds)"
    #endregion SUMMARYRoleAssignmentsAll

    #region SUMMARYPIMEligibility
    if (-not $NoPIMEligibility) {
        $startPIMEligibility = Get-Date
        Write-Host '  processing TenantSummary PIMEligibility'

        if ($arrayPIMEligible.Count -gt 0) {
            $tfCount = $arrayPIMEligible.Count
            $htmlTableId = 'TenantSummary_PIMEligibility'
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_PIMEligibility"><i class="padlx fa fa-universal-access" aria-hidden="true"></i> <span class="valignMiddle">$($tfCount) direct PIM Eligible assignments</span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>ScopeId</th>
<th>ScopeName</th>
<th>MgPath</th>
<th>MgLevel</th>
<th>Role</th>
<th>Role Id</th>
<th>Role type</th>
<th>Identity ObjectId</th>
<th>Identity DisplayName</th>
<th>Identity SignInName</th>
<th>Identity Type</th>
<th>Identity Applicability</th>
<th>Applies through (AAD Grp)</th>
<th class="uamiresaltbgc">PIM Eligibility</th>
<th class="uamiresaltbgc">PIM Eligibility inhherted (MG)</th>
<th class="uamiresaltbgc">PIM start</th>
<th class="uamiresaltbgc">PIM end</th>
<th class="uamiresaltbgc">PIM Eligibility Id</th>
</tr>
</thead>
<tbody>
"@)
            $htmlSUMMARYPIMEligibility = $null
            $PIMEligibleEnrichedSorted = $PIMEligibleEnriched | Sort-Object -Property Scope, MgLevel, ScopeName, IdentityDisplayName, PIMEligibilityId
            $tfCountCnt = $PIMEligibleEnrichedSorted.Count
            $htmlSUMMARYPIMEligibility = foreach ($PIMEligible in $PIMEligibleEnrichedSorted) {
                @"
<tr>
<td>$($PIMEligible.Scope)</td>
<td>$($PIMEligible.ScopeId)</td>
<td>$($PIMEligible.ScopeName)</td>
<td>$($PIMEligible.MgPath -join '/')</td>
<td>$($PIMEligible.MgLevel)</td>
<td>$($PIMEligible.Role)</td>
<td>$($PIMEligible.RoleIdGuid)</td>
<td>$($PIMEligible.RoleType)</td>
<td>$($PIMEligible.IdentityObjectId)</td>
<td>$($PIMEligible.IdentityDisplayName)</td>
<td>$($PIMEligible.IdentitySignInName)</td>
<td>$($PIMEligible.IdentityType)</td>
<td>$($PIMEligible.IdentityApplicability)</td>
<td>$($PIMEligible.AppliesThrough)</td>
<td>$($PIMEligible.PIMEligibility)</td>
<td>$($PIMEligible.PIMEligibilityInheritedFrom)</td>
<td>$($PIMEligible.PIMEligibilityStartDateTime)</td>
<td>$($PIMEligible.PIMEligibilityEndDateTime)</td>
<td>$($PIMEligible.PIMEligibilityId)</td>
</tr>
"@
            }

            if (-not $NoCsvExport) {
                $csvFilename = "$($filename)_PIMEligibility"
                Write-Host "   Exporting PIMEligibility CSV '$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv'"
                $PIMEligibleEnrichedSorted | Select-Object -ExcludeProperty RoleClear | Export-Csv -Encoding utf8 -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter $csvDelimiter -NoTypeInformation
            }

            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYPIMEligibility)
            [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCountCnt -gt 10) {
                $spectrum = "10, $tfCountCnt"
                if ($tfCountCnt -gt 50) {
                    $spectrum = "10, 25, 50, $tfCountCnt"
                }
                if ($tfCountCnt -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCountCnt"
                }
                if ($tfCountCnt -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCountCnt"
                }
                if ($tfCountCnt -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCountCnt"
                }
                if ($tfCountCnt -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCountCnt"
                }
                if ($tfCountCnt -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCountCnt"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
            col_4: 'select',
            col_7: 'select',
            col_11: 'select',
            col_12: 'select',
            col_14: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'date',
                'date',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No PIM Eligibility</p>
'@)
        }

        $endPIMEligibility = Get-Date
        Write-Host "   TenantSummary PIMEligibility duration: $((New-TimeSpan -Start $startPIMEligibility -End $endPIMEligibility).TotalMinutes) minutes ($((New-TimeSpan -Start $startPIMEligibility -End $endPIMEligibility).TotalSeconds) seconds)"
    }
    else {
        if ($azAPICallConf['htParameters'].accountType -ne 'User' -and $NoPIMEligibility) {
            [void]$htmlTenantSummary.AppendLine(@"
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No PIM Eligibility - </span><span class="info valignMiddle">parameter -NoPIMEligibility = $NoPIMEligibility</p>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No PIM Eligibility - </span><span class="info valignMiddle">run Azure Governance Visualizer with a Service Principal to get PIM Eligibility insights</p>
'@)
        }
    }
    #endregion SUMMARYPIMEligibility

    #region SUMMARYSecurityCustomRoles
    Write-Host '  processing TenantSummary Custom Roles security (owner permissions)'
    $customRolesOwnerAll = ($rbacBaseQuery.where( { $_.RoleSecurityCustomRoleOwner -eq 1 })) | Sort-Object -Property RoleDefinitionId
    $customRolesOwnerHtAll = $tenantCustomRoles.where( { $_.Actions -eq '*' -and ($_.NotActions).length -eq 0 })
    if (($customRolesOwnerHtAll).count -gt 0) {
        $tfCount = ($customRolesOwnerHtAll).count
        $htmlTableId = 'TenantSummary_CustomRoleOwner'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_CustomRoleOwner"><i class="padlx fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($customRolesOwnerHtAll).count) Custom Role definitions Owner permissions ($scopeNamingSummary) <abbr title="Custom 'Owner' Role definitions should not exist"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Role assignments</th>
<th>Assignable Scopes</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYSecurityCustomRoles = $null
        foreach ($customRole in ($customRolesOwnerHtAll | Sort-Object -Property Name, Id)) {
            $customRoleOwnersAllAssignmentsCount = ((($customRolesOwnerAll.where( { $_.RoleDefinitionId -eq $customRole.Id })).RoleAssignmentId | Sort-Object -Unique)).count
            if ($customRoleOwnersAllAssignmentsCount -gt 0) {
                $customRoleRoleAssignmentsArray = [System.Collections.ArrayList]@()
                $customRoleRoleAssignmentIds = ($customRolesOwnerAll.where( { $_.RoleDefinitionId -eq $customRole.Id })).RoleAssignmentId | Sort-Object -Unique
                foreach ($customRoleRoleAssignmentId in $customRoleRoleAssignmentIds) {
                    $null = $customRoleRoleAssignmentsArray.Add($customRoleRoleAssignmentId)
                }
                $customRoleRoleAssignmentsOutput = "$customRoleOwnersAllAssignmentsCount ($($customRoleRoleAssignmentsArray -join "$CsvDelimiterOpposite "))"
            }
            else {
                $customRoleRoleAssignmentsOutput = "$customRoleOwnersAllAssignmentsCount"
            }
            $htmlSUMMARYSecurityCustomRoles += @"
<tr>
<td>$($customRole.Name -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($customRole.Id)</td>
<td>$($customRoleRoleAssignmentsOutput)</td>
<td>$(($customRole.AssignableScopes).count) ($($customRole.AssignableScopes -join "$CsvDelimiterOpposite "))</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYSecurityCustomRoles)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $(($customRolesOwnerHtAll).count) Custom Role definitions Owner permissions ($scopeNamingSummary)</p>
"@)
    }
    #endregion SUMMARYSecurityCustomRoles

    #region SUMMARYSecurityRolesCanDoRoleAssignments
    Write-Host '  processing TenantSummary Roles security (can apply Role assignments)'
    if ($tenantAllRolesCanDoRoleAssignmentsCount -gt 0) {

        #$roleAssignments4RolesCanDoRoleAssignments = (($rbacBaseQuery.where( { $_.RoleCanDoRoleAssignments -eq $true })) | Sort-Object -Property RoleAssignmentId -Unique) | Select-Object RoleAssignmentId, RoleDefinitionId
        $roleAssignments4RolesCanDoRoleAssignments = (($rbacBaseQuery | Sort-Object -Property RoleAssignmentId -Unique).where( { $_.RoleCanDoRoleAssignments -eq $true })) | Select-Object RoleAssignmentId, RoleDefinitionId
        $htRoleAssignments4RolesCanDoRoleAssignments = @{}
        foreach ($roleAssignment4RolesCanDoRoleAssignments in $roleAssignments4RolesCanDoRoleAssignments) {
            if (-not $htRoleAssignments4RolesCanDoRoleAssignments.($roleAssignment4RolesCanDoRoleAssignments.RoleDefinitionId)) {
                $htRoleAssignments4RolesCanDoRoleAssignments.($roleAssignment4RolesCanDoRoleAssignments.RoleDefinitionId) = @{}
                $htRoleAssignments4RolesCanDoRoleAssignments.($roleAssignment4RolesCanDoRoleAssignments.RoleDefinitionId).roleAssignments = [System.Collections.ArrayList]@()
            }
            $null = $htRoleAssignments4RolesCanDoRoleAssignments.($roleAssignment4RolesCanDoRoleAssignments.RoleDefinitionId).roleAssignments.Add($roleAssignment4RolesCanDoRoleAssignments.RoleAssignmentId)
        }

        $tfCount = $tenantAllRolesCanDoRoleAssignmentsCount
        $htmlTableId = 'TenantSummary_RolesCanDoRoleAssignments'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_RolesCanDoRoleAssignments"><i class="padlx fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$($tenantAllRolesCanDoRoleAssignmentsCount) Role definitions can apply Role assignments</span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Type</th>
<th>Role assignments</th>
<th>Assignable Scopes</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYSecurityRolesCanDoRoleAssignments = $null
        foreach ($role in ($tenantAllRolesCanDoRoleAssignments | Sort-Object -Property Name)) {
            if ($role.IsCustom) {
                $roleType = 'Custom'
                $roleAssignableScopes = "$(($role.AssignableScopes).count) ($($role.AssignableScopes -join "$CsvDelimiterOpposite "))"
            }
            else {
                $roleType = 'BuiltIn'
                $roleAssignableScopes = ''
            }

            if ($htRoleAssignments4RolesCanDoRoleAssignments.($role.Id).roleAssignments.Count -gt 0) {
                $roleAssignments = "$($htRoleAssignments4RolesCanDoRoleAssignments.($role.Id).roleAssignments.Count) ($($htRoleAssignments4RolesCanDoRoleAssignments.($role.Id).roleAssignments -join ', '))"
            }
            else {
                $roleAssignments = 0
            }

            $htmlSUMMARYSecurityRolesCanDoRoleAssignments += @"
<tr>
<td>$($role.Name -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($role.Id)</td>
<td>$($roleType)</td>
<td>$($roleAssignments)</td>
<td>$($roleAssignableScopes)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYSecurityRolesCanDoRoleAssignments)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_2: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $($tenantAllRolesCanDoRoleAssignmentsCount) Role definitions can apply Role assignments</p>
"@)
    }
    #endregion SUMMARYSecurityRolesCanDoRoleAssignments

    #region SUMMARYSecurityOwnerAssignmentSP
    $startSUMMARYSecurityOwnerAssignmentSP = Get-Date
    Write-Host '  processing TenantSummary RoleAssignments security (owner SP)'
    $roleAssignmentsOwnerAssignmentSPAll = ($rbacBaseQuery.where( { $_.RoleSecurityOwnerAssignmentSP -eq 1 })) | Sort-Object -Property RoleAssignmentId
    $roleAssignmentsOwnerAssignmentSP = $roleAssignmentsOwnerAssignmentSPAll | Sort-Object -Property RoleAssignmentId -Unique
    if (($roleAssignmentsOwnerAssignmentSP).count -gt 0) {
        $tfCount = ($roleAssignmentsOwnerAssignmentSP).count
        $htmlTableId = 'TenantSummary_roleAssignmentsOwnerAssignmentSP'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_roleAssignmentsOwnerAssignmentSP"><i class="padlx fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentSP).count) Owner permission assignments to ServicePrincipal ($scopeNamingSummary) <abbr title="Owner permissions on Service Principals should be treated exceptional"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Role Assignment</th>
<th>ServicePrincipal (ObjId)</th>
<th>Impacted Mg/Sub</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYSecurityOwnerAssignmentSP = $null
        $htmlSUMMARYSecurityOwnerAssignmentSP = foreach ($roleAssignmentOwnerAssignmentSP in ($roleAssignmentsOwnerAssignmentSP)) {
            $hlpRoleAssignmentsAll = $roleAssignmentsOwnerAssignmentSPAll.where( { $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentSP.RoleAssignmentId })
            $impactedMgs = $hlpRoleAssignmentsAll.where( { [String]::IsNullOrEmpty($_.SubscriptionId) })
            $impactedSubs = $hlpRoleAssignmentsAll.where( { -not [String]::IsNullOrEmpty($_.SubscriptionId) })
            $servicePrincipal = $roleAssignmentsOwnerAssignmentSP.where( { $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentSP.RoleAssignmentId }) | Get-Unique
            @"
<tr>
<td>$($roleAssignmentOwnerAssignmentSP.RoleDefinitionName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($roleAssignmentOwnerAssignmentSP.RoleDefinitionId)</td>
<td>$($roleAssignmentOwnerAssignmentSP.RoleAssignmentId)</td>
<td>$($servicePrincipal.RoleAssignmentIdentityDisplayname) ($($servicePrincipal.RoleAssignmentIdentityObjectId))</td>
<td>Mg: $(($impactedMgs.mgid | Sort-Object -Unique).count); Sub: $(($impactedSubs.subscriptionId | Sort-Object -Unique).count)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYSecurityOwnerAssignmentSP)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $(($roleAssignmentsOwnerAssignmentSP).count) Owner permission assignments to ServicePrincipal ($scopeNamingSummary)</p>
"@)
    }
    $endSUMMARYSecurityOwnerAssignmentSP = Get-Date
    Write-Host "   TenantSummary RoleAssignments security (owner SP) duration: $((New-TimeSpan -Start $startSUMMARYSecurityOwnerAssignmentSP -End $endSUMMARYSecurityOwnerAssignmentSP).TotalMinutes) minutes ($((New-TimeSpan -Start $startSUMMARYSecurityOwnerAssignmentSP -End $endSUMMARYSecurityOwnerAssignmentSP).TotalSeconds) seconds)"
    #endregion SUMMARYSecurityOwnerAssignmentSP

    #region SUMMARYSecurityOwnerAssignmentNotGroup
    Write-Host '  processing TenantSummary RoleAssignments security (owner notGroup)'
    $startSUMMARYSecurityOwnerAssignmentNotGroup = Get-Date

    $roleAssignmentsOwnerAssignmentNotGroup = $rbacBaseQueryArrayListNotGroupOwner | Sort-Object -Property RoleAssignmentId -Unique
    $roleAssignmentsOwnerAssignmentNotGroupGrouped = ($rbacBaseQueryArrayListNotGroupOwner | Group-Object -Property roleassignmentId)

    if (($roleAssignmentsOwnerAssignmentNotGroup).count -gt 0) {
        $tfCount = ($roleAssignmentsOwnerAssignmentNotGroup).count
        $htmlTableId = 'TenantSummary_roleAssignmentsOwnerAssignmentNotGroup'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_roleAssignmentsOwnerAssignmentNotGroup"><i class="padlx fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentNotGroup).count) Owner permission assignments to notGroup ($scopeNamingSummary)</span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Role Assignment</th>
<th>Obj Type</th>
<th>Obj DisplayName</th>
<th>Obj SignInName</th>
<th>ObjId</th>
<th>Impacted Mg/Sub</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYSecurityOwnerAssignmentNotGroup = $null
        $htmlSUMMARYSecurityOwnerAssignmentNotGroup = foreach ($roleAssignmentOwnerAssignmentNotGroup in ($roleAssignmentsOwnerAssignmentNotGroup)) {
            $impactedMgSubBaseQuery = $roleAssignmentsOwnerAssignmentNotGroupGrouped.where( { $_.Name -eq $roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentId })
            $impactedMgs = $impactedMgSubBaseQuery.Group.where( { [String]::IsNullOrEmpty($_.SubscriptionId) })
            $impactedSubs = $impactedMgSubBaseQuery.Group.where( { -not [String]::IsNullOrEmpty($_.SubscriptionId) })
            @"
<tr>
<td>$($roleAssignmentOwnerAssignmentNotGroup.RoleDefinitionName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($roleAssignmentOwnerAssignmentNotGroup.RoleDefinitionId)</td>
<td class="breakwordall">$($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentId)</td>
<td>$($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentIdentityObjectType)</td>
<td>$($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentIdentityDisplayname)</td>
<td class="breakwordall">$($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentIdentitySignInName)</td>
<td class="breakwordall">$($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentIdentityObjectId)</td>
<td>Mg: $(($impactedMgs.mgid | Sort-Object -Unique).count); Sub: $(($impactedSubs.subscriptionId | Sort-Object -Unique).count)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYSecurityOwnerAssignmentNotGroup)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }

            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_3: 'multiple',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $(($roleAssignmentsOwnerAssignmentNotGroup).count) Owner permission assignments to notGroup ($scopeNamingSummary)</p>
"@)
    }
    $endSUMMARYSecurityOwnerAssignmentNotGroup = Get-Date
    Write-Host "   TenantSummary RoleAssignments security (owner notGroup) duration: $((New-TimeSpan -Start $startSUMMARYSecurityOwnerAssignmentNotGroup -End $endSUMMARYSecurityOwnerAssignmentNotGroup).TotalMinutes) minutes ($((New-TimeSpan -Start $startSUMMARYSecurityOwnerAssignmentNotGroup -End $endSUMMARYSecurityOwnerAssignmentNotGroup).TotalSeconds) seconds)"
    #endregion SUMMARYSecurityOwnerAssignmentNotGroup

    #region SUMMARYSecurityUserAccessAdministratorAssignmentNotGroup
    $startSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup = Get-Date
    Write-Host '  processing TenantSummary RoleAssignments security (userAccessAdministrator notGroup)'
    $roleAssignmentsUserAccessAdministratorAssignmentNotGroup = $rbacBaseQueryArrayListNotGroupUserAccessAdministrator | Sort-Object -Property RoleAssignmentId -Unique
    $roleAssignmentsUserAccessAdministratorAssignmentNotGroupGrouped = ($rbacBaseQueryArrayListNotGroupUserAccessAdministrator | Group-Object -Property roleassignmentId)

    if (($roleAssignmentsUserAccessAdministratorAssignmentNotGroup).count -gt 0) {
        $tfCount = ($roleAssignmentsUserAccessAdministratorAssignmentNotGroup).count
        $htmlTableId = 'TenantSummary_roleAssignmentsUserAccessAdministratorAssignmentNotGroup'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_roleAssignmentsUserAccessAdministratorAssignmentNotGroup"><i class="padlx fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsUserAccessAdministratorAssignmentNotGroup).count) UserAccessAdministrator permission assignments to notGroup ($scopeNamingSummary)</span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Role Assignment</th>
<th>Obj Type</th>
<th>Obj DisplayName</th>
<th>Obj SignInName</th>
<th>ObjId</th>
<th>Impacted Mg/Sub</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup = $null
        $htmlSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup = foreach ($roleAssignmentUserAccessAdministratorAssignmentNotGroup in ($roleAssignmentsUserAccessAdministratorAssignmentNotGroup)) {
            $impactedMgSubBaseQuery = $roleAssignmentsUserAccessAdministratorAssignmentNotGroupGrouped.where( { $_.Name -eq $roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId })
            $impactedMgs = $impactedMgSubBaseQuery.Group.where( { [String]::IsNullOrEmpty($_.SubscriptionId) })
            $impactedSubs = $impactedMgSubBaseQuery.Group.where( { -not [String]::IsNullOrEmpty($_.SubscriptionId) })
            @"
<tr>
<td>$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleDefinitionName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleDefinitionId)</td>
<td class="breakwordall">$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId)</td>
<td>$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentIdentityObjectType)</td>
<td>$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentIdentityDisplayname)</td>
<td class="breakwordall">$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentIdentitySignInName)</td>
<td class="breakwordall">$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentIdentityObjectId)</td>
<td>Mg: $(($impactedMgs.mgid | Sort-Object -Unique).count); Sub: $(($impactedSubs.subscriptionId | Sort-Object -Unique).count)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_3: 'multiple',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $(($roleAssignmentsUserAccessAdministratorAssignmentNotGroup).count) UserAccessAdministrator permission assignments to notGroup ($scopeNamingSummary)</p>
"@)
    }
    $endSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup = Get-Date
    Write-Host "   TenantSummary RoleAssignments security (userAccessAdministrator notGroup) duration: $((New-TimeSpan -Start $startSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup -End $endSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup).TotalMinutes) minutes ($((New-TimeSpan -Start $startSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup -End $endSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup).TotalSeconds) seconds)"
    #endregion SUMMARYSecurityUserAccessAdministratorAssignmentNotGroup

    #region SUMMARYSecurityGuestUserHighPriviledgesAssignments

    $startSUMMARYSecurityGuestUserHighPriviledgesAssignments = Get-Date
    Write-Host '  processing TenantSummary RoleAssignments security (high privileged Guest User)'
    $highPrivilegedGuestUserRoleAssignments = $rbacAll.where( { ($_.RoleId -eq '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' -or $_.RoleId -eq '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9') -and $_.ObjectType -eq 'User Guest' }) | Sort-Object -Property RoleAssignmentId, ObjectId -Unique
    $highPrivilegedGuestUserRoleAssignmentsCount = ($highPrivilegedGuestUserRoleAssignments).Count
    if ($highPrivilegedGuestUserRoleAssignmentsCount -gt 0) {
        $tfCount = $highPrivilegedGuestUserRoleAssignmentsCount
        $htmlTableId = 'TenantSummary_SecurityGuestUserHighPriviledgesAssignments'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_SecurityGuestUserHighPriviledgesAssignments"><i class="padlx fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$($highPrivilegedGuestUserRoleAssignmentsCount) Guest Users with high permissions ($scopeNamingSummary)</span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Role Assignment</th>
<th>Obj Type</th>
<th>Obj DisplayName</th>
<th>Obj SignInName</th>
<th>ObjId</th>
<th>Assignment direct/indirect</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYSecurityGuestUserHighPriviledgesAssignments = $null
        $htmlSUMMARYSecurityGuestUserHighPriviledgesAssignments = foreach ($highPrivilegedGuestUserRoleAssignment in ($highPrivilegedGuestUserRoleAssignments)) {
            if ($highPrivilededGuestUserRoleAssignment.AssignmentType -eq 'indirect') {
                $assignmentInfo = "indirect / AAD Group Membership '$($highPrivilededGuestUserRoleAssignment.AssignmentInheritFrom)'"
            }
            else {
                $assignmentInfo = 'direct'
            }
            @"
<tr>
<td>$($highPrivilegedGuestUserRoleAssignment.Role <#-replace "<", "&lt;" -replace ">", "&gt;"#>)</td>
<td>$($highPrivilegedGuestUserRoleAssignment.RoleId)</td>
<td class="breakwordall">$($highPrivilegedGuestUserRoleAssignment.RoleAssignmentId)</td>
<td>$($highPrivilegedGuestUserRoleAssignment.ObjectType)</td>
<td>$($highPrivilegedGuestUserRoleAssignment.ObjectDisplayName)</td>
<td class="breakwordall">$($highPrivilegedGuestUserRoleAssignment.ObjectSignInName)</td>
<td class="breakwordall">$($highPrivilegedGuestUserRoleAssignment.ObjectId)</td>
<td>$assignmentInfo</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYSecurityGuestUserHighPriviledgesAssignments)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $($highPrivilegedGuestUserRoleAssignmentsCount) Guest Users with high permissions ($scopeNamingSummary)</p>
"@)
    }
    $endSUMMARYSecurityGuestUserHighPriviledgesAssignments = Get-Date
    Write-Host "   TenantSummary RoleAssignments security (high privileged Guest User) duration: $((New-TimeSpan -Start $startSUMMARYSecurityGuestUserHighPriviledgesAssignments -End $endSUMMARYSecurityGuestUserHighPriviledgesAssignments).TotalMinutes) minutes ($((New-TimeSpan -Start $startSUMMARYSecurityGuestUserHighPriviledgesAssignments -End $endSUMMARYSecurityGuestUserHighPriviledgesAssignments).TotalSeconds) seconds)"
    #endregion SUMMARYSecurityGuestUserHighPriviledgesAssignments


    [void]$htmlTenantSummary.AppendLine(@'
    </div>
'@)
    #endregion tenantSummaryRBAC

    showMemoryUsage

    #region tenantSummaryBlueprints
    [void]$htmlTenantSummary.AppendLine(@'
<button type="button" class="collapsible" id="tenantSummaryBlueprints"><hr class="hr-textBlueprints" data-content="Blueprints" /></button>
<div class="content TenantSummaryContent">
'@)

    #region SUMMARYBlueprintDefinitions
    Write-Host '  processing TenantSummary Blueprints'
    $blueprintDefinitions = ($blueprintBaseQuery | Where-Object { [String]::IsNullOrEmpty($_.BlueprintAssignmentId) })
    $blueprintDefinitionsCount = ($blueprintDefinitions).count
    if ($blueprintDefinitionsCount -gt 0) {
        $htmlTableId = 'TenantSummary_BlueprintDefinitions'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_BlueprintDefinitions"><p><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> $blueprintDefinitionsCount Blueprint definitions</p></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th class="widthCustom">Blueprint Name</th>
<th>Blueprint DisplayName</th>
<th>Blueprint Description</th>
<th>BlueprintId</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYBlueprintDefinitions = $null
        $htmlSUMMARYBlueprintDefinitions = foreach ($blueprintDefinition in $blueprintDefinitions | Sort-Object -Property BlueprintName, BlueprintDisplayName) {
            @"
<tr>
<td>$($blueprintDefinition.BlueprintName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintDefinition.BlueprintDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintDefinition.BlueprintDescription -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintDefinition.BlueprintId -replace '<', '&lt;' -replace '>', '&gt;')</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYBlueprintDefinitions)
        [void]$htmlTenantSummary.AppendLine(@"
                </tbody>
            </table>
        </div>
        <script>
            function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
                window.helpertfConfig4$htmlTableId =1;
                var tfConfig4$htmlTableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
                col_types: [
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring'
                ],
extensions: [{ name: 'sort' }]
            };
            var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
            tf.init();}}
        </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $blueprintDefinitionsCount Blueprint definitions</p>
"@)
    }
    #endregion SUMMARYBlueprintDefinitions

    #region SUMMARYBlueprintAssignments
    Write-Host '  processing TenantSummary BlueprintAssignments'
    $blueprintAssignments = ($blueprintBaseQuery | Where-Object { -not [String]::IsNullOrEmpty($_.BlueprintAssignmentId) })
    $blueprintAssignmentsCount = ($blueprintAssignments).count

    if ($blueprintAssignmentsCount -gt 0) {
        $htmlTableId = 'TenantSummary_BlueprintAssignments'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_BlueprintAssignments"><p><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> $blueprintAssignmentsCount Blueprint assignments</p></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th class="widthCustom">Blueprint Name</th>
<th>Blueprint DisplayName</th>
<th>Blueprint Description</th>
<th>BlueprintId</th>
<th>Blueprint Version</th>
<th>Blueprint AssignmentId</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYBlueprintAssignments = $null
        $htmlSUMMARYBlueprintAssignments = foreach ($blueprintAssignment in $blueprintAssignments | Sort-Object -Property level, BlueprintAssignmentId) {
            @"
<tr>
<td>$($blueprintAssignment.BlueprintName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintAssignment.BlueprintDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintAssignment.BlueprintDescription -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintAssignment.BlueprintId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintAssignment.BlueprintAssignmentVersion)</td>
<td>$($blueprintAssignment.BlueprintAssignmentId -replace '<', '&lt;' -replace '>', '&gt;')</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYBlueprintAssignments)
        [void]$htmlTenantSummary.AppendLine(@"
                </tbody>
            </table>
        </div>
        <script>
            function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
                window.helpertfConfig4$htmlTableId =1;
                var tfConfig4$htmlTableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
                col_types: [
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring'
                ],
extensions: [{ name: 'sort' }]
            };
            var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
            tf.init();}}
        </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $blueprintAssignmentsCount Blueprint assignments</p>
"@)
    }
    #endregion SUMMARYBlueprintAssignments

    #region SUMMARYBlueprintsOrphaned
    Write-Host '  processing TenantSummary Blueprint definitions orphaned'
    $blueprintDefinitionsOrphanedArray = @()
    if ($blueprintDefinitionsCount -gt 0) {
        if ($blueprintAssignmentsCount -gt 0) {
            $blueprintDefinitionsOrphanedArray += foreach ($blueprintDefinition in $blueprintDefinitions) {
                if (($blueprintAssignments.BlueprintId) -notcontains ($blueprintDefinition.BlueprintId)) {
                    $blueprintDefinition
                }
            }
        }
        else {
            $blueprintDefinitionsOrphanedArray += foreach ($blueprintDefinition in $blueprintDefinitions) {
                $blueprintDefinition
            }
        }
    }
    $blueprintDefinitionsOrphanedCount = ($blueprintDefinitionsOrphanedArray).count

    if ($blueprintDefinitionsOrphanedCount -gt 0) {

        $htmlTableId = 'TenantSummary_BlueprintsOrphaned'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_BlueprintsOrphaned"><p><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> $blueprintDefinitionsOrphanedCount Orphaned Blueprints</p></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th class="widthCustom">Blueprint Name</th>
<th>Blueprint DisplayName</th>
<th>Blueprint Description</th>
<th>BlueprintId</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYBlueprintsOrphaned = $null
        $htmlSUMMARYBlueprintsOrphaned = foreach ($blueprintDefinition in $blueprintDefinitionsOrphanedArray | Sort-Object -Property BlueprintId) {
            @"
<tr>
<td>$($blueprintDefinition.BlueprintName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintDefinition.BlueprintDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintDefinition.BlueprintDescription -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintDefinition.BlueprintId -replace '<', '&lt;' -replace '>', '&gt;')</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYBlueprintsOrphaned)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $blueprintDefinitionsOrphanedCount Orphaned Blueprint definitions</p>
"@)
    }
    #endregion SUMMARYBlueprintsOrphaned

    [void]$htmlTenantSummary.AppendLine(@'
    </div>
'@)
    #endregion tenantSummaryBlueprints

    showMemoryUsage

    #region tenantSummaryManagementGroups
    [void]$htmlTenantSummary.AppendLine(@'
<button type="button" class="collapsible" id="tenantSummaryManagementGroups"><hr class="hr-textManagementGroups" data-content="Management Groups" /></button>
<div class="content TenantSummaryContent">
'@)

    #region SUMMARYMGs
    $startSUMMARYMGs = Get-Date
    Write-Host '  processing TenantSummary ManagementGroups'

    $summaryManagementGroups = $optimizedTableForPathQueryMg | Sort-Object -Property Level, mgid, mgParentId
    $summaryManagementGroupsCount = ($summaryManagementGroups).Count
    if ($summaryManagementGroupsCount -gt 0) {
        $tfCount = $summaryManagementGroupsCount
        $htmlTableId = 'TenantSummary_ManagementGroups'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_Subs"><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> <span class="valignMiddle">$($summaryManagementGroupsCount) Management Groups</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Level</th>
<th>ManagementGroup</th>
<th>ManagementGroup Id</th>
<th>Mg children (total)</th>
<th>Mg children (direct)</th>
<th>Sub children (total)</th>
<th>Sub children (direct)</th>
"@)
        if ($azAPICallConf['htParameters'].NoMDfCSecureScore -eq $false) {
            [void]$htmlTenantSummary.AppendLine(@'
<th>MG MDfC Score</th>
'@)
        }
        if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
            [void]$htmlTenantSummary.AppendLine(@"
<th>Cost ($($AzureConsumptionPeriod)d)</th>
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@'
<th>Path</th>
</tr>
</thead>
<tbody>
'@)
        $htmlSUMMARYManagementGroups = $null
        $cnter = 0
        $htmlSUMMARYManagementGroups = foreach ($summaryManagementGroup in $summaryManagementGroups) {

            $mgPath = $htManagementGroupsMgPath.($summaryManagementGroup.mgId).pathDelimited

            if ($summaryManagementGroup.mgid -eq $mgSubPathTopMg -and ($azAPICallConf['checkContext']).Tenant.Id -ne $ManagementGroupId) {
                $pathhlper = "$($mgPath)"
                $arrayTotalCostSummaryMgSummary = 'n/a'
                $mgAllChildMgsCountTotal = 'n/a'
                $mgAllChildMgsCountDirect = 'n/a'
                $mgAllChildSubscriptionsCountTotal = 'n/a'
                $mgAllChildSubscriptionsCountDirect = 'n/a'
                $mgSecureScore = 'n/a'
            }
            else {

                if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
                    if ($allConsumptionDataCount -gt 0) {
                        $arrayTotalCostSummaryMgSummary = @()
                        if ($htManagementGroupsCost.($summaryManagementGroup.mgid)) {
                            foreach ($currency in $htManagementGroupsCost.($summaryManagementGroup.mgid).currencies) {
                                $hlper = $htManagementGroupsCost.($summaryManagementGroup.mgid)
                                $totalCost = $hlper."mgTotalCost_$($currency)"
                                if ([math]::Round($totalCost, 2) -eq 0) {
                                    $totalCost = $totalCost.ToString('0.0000')
                                }
                                else {
                                    $totalCost = [math]::Round($totalCost, 2).ToString('0.00')
                                }
                                $totalCostGeneratedByResourceTypes = ($hlper."resourceTypesThatGeneratedCost_$($currency)").Count
                                $totalCostGeneratedByResources = $hlper."resourcesThatGeneratedCost_$($currency)"
                                $totalCostGeneratedBySubscriptions = $hlper."subscriptionsThatGeneratedCost_$($currency)"
                                $arrayTotalCostSummaryMgSummary += "$($totalCost) $($currency) generated by $($totalCostGeneratedByResources) Resources ($($totalCostGeneratedByResourceTypes) ResourceTypes) in $($totalCostGeneratedBySubscriptions) Subscriptions"
                            }
                        }
                        else {
                            $arrayTotalCostSummaryMgSummary = 'no consumption data available'
                        }
                    }
                    else {
                        $arrayTotalCostSummaryMgSummary = 'no consumption data available'
                    }
                }
                $pathhlper = "<a href=`"#hierarchy_$($summaryManagementGroup.mgId)`"><i class=`"fa fa-eye`" aria-hidden=`"true`"></i></a> $($mgPath)"

                #childrenMgInfo
                $mgAllChildMgs = [System.Collections.ArrayList]@()
                foreach ($entry in $htManagementGroupsMgPath.keys) {
                    if (($htManagementGroupsMgPath.($entry).path) -contains $($summaryManagementGroup.mgid)) {
                        $null = $mgAllChildMgs.Add($entry)
                    }
                }
                $mgAllChildMgsCountTotal = (($mgAllChildMgs).Count - 1)
                $mgAllChildMgsCountDirect = $htMgDetails.($summaryManagementGroup.mgid).mgChildrenCount

                $mgAllChildSubscriptions = [System.Collections.ArrayList]@()
                $mgDirectChildSubscriptions = [System.Collections.ArrayList]@()
                foreach ($entry in $htSubscriptionsMgPath.keys) {
                    if (($htSubscriptionsMgPath.($entry).path) -contains $($summaryManagementGroup.mgid)) {
                        $null = $mgAllChildSubscriptions.Add($entry)
                    }
                    if (($htSubscriptionsMgPath.($entry).parent) -eq $($summaryManagementGroup.mgid)) {
                        $null = $mgDirectChildSubscriptions.Add($entry)
                    }
                }

                $mgAllChildSubscriptionsCountTotal = (($mgAllChildSubscriptions).Count)
                $mgAllChildSubscriptionsCountDirect = (($mgDirectChildSubscriptions).Count)

                if ($htMgASCSecureScore.($summaryManagementGroup.mgId).SecureScore) {
                    if ([string]::IsNullOrEmpty($htMgASCSecureScore.($summaryManagementGroup.mgId).SecureScore) -or [string]::IsNullOrWhiteSpace($htMgASCSecureScore.($summaryManagementGroup.mgId).SecureScore)) {
                        $mgSecureScore = 'n/a'
                    }
                    else {
                        $mgSecureScore = $htMgASCSecureScore.($summaryManagementGroup.mgId).SecureScore
                    }
                }
                else {
                    $mgSecureScore = 'n/a'
                }
            }

            @"
<tr>
<td>$($summaryManagementGroup.level)</td>
<td>$($summaryManagementGroup.mgName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($summaryManagementGroup.mgId)</td>
<td>$($mgAllChildMgsCountTotal)</td>
<td>$($mgAllChildMgsCountDirect)</td>
<td>$($mgAllChildSubscriptionsCountTotal)</td>
<td>$($mgAllChildSubscriptionsCountDirect)</td>
"@
            if ($azAPICallConf['htParameters'].NoMDfCSecureScore -eq $false) {
                @"
<td>$($mgSecureScore)</td>
"@
            }
            if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
                @"
<td>$($arrayTotalCostSummaryMgSummary -join ', ')</td>
"@
            }
            @"
<td>$($pathhlper)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYManagementGroups)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@'
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
            col_types: [
                'number',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number',
                'number',
                'number',
                'number',
'@)
        if ($azAPICallConf['htParameters'].NoMDfCSecureScore -eq $false) {
            [void]$htmlTenantSummary.AppendLine(@'
                'caseinsensitivestring',
'@)
        }
        if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
            [void]$htmlTenantSummary.AppendLine(@'
                'caseinsensitivestring',
'@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>

"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
    <p><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> <span class="valignMiddle">$($summaryManagementGroupsCount) Management Groups</span></p>
"@)
    }
    $endSUMMARYMGs = Get-Date
    Write-Host "   SUMMARYMGs duration: $((New-TimeSpan -Start $startSUMMARYMGs -End $endSUMMARYMGs).TotalMinutes) minutes ($((New-TimeSpan -Start $startSUMMARYMGs -End $endSUMMARYMGs).TotalSeconds) seconds)"
    #endregion SUMMARYMGs

    #region SUMMARYMGdefault
    Write-Host '  processing TenantSummary ManagementGroups - default Management Group'
    [void]$htmlTenantSummary.AppendLine(@"
    <p><img class="padlx imgSubTree defaultMG" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> Hierarchy Settings | Default Management Group Id: '<b>$($defaultManagementGroupId)</b>' <a class="externallink" href="https://docs.microsoft.com/en-us/azure/governance/management-groups/how-to/protect-resource-hierarchy#setting---default-management-group" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@)
    #endregion SUMMARYMGdefault

    #region SUMMARYMGRequireAuthorizationForGroupCreation
    Write-Host '  processing TenantSummary ManagementGroups - requireAuthorizationForGroupCreation Management Group'
    [void]$htmlTenantSummary.AppendLine(@"
    <p><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> Hierarchy Settings | Require authorization for Management Group creation: '<b>$($requireAuthorizationForGroupCreation)</b>' <a class="externallink" href="https://docs.microsoft.com/en-us/azure/governance/management-groups/how-to/protect-resource-hierarchy#setting---require-authorization" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@)
    #endregion SUMMARYMGRequireAuthorizationForGroupCreation

    [void]$htmlTenantSummary.AppendLine(@'
    </div>
'@)
    #endregion tenantSummaryManagementGroups

    showMemoryUsage

    #region tenantSummarySubscriptionsResourceDefenderPSRule
    [void]$htmlTenantSummary.AppendLine(@'
<button type="button" class="collapsible" id="tenantSummarySubscriptions"><hr class="hr-textSubscriptions" data-content="Subscriptions, Resources & Defender" /></button>
<div class="content TenantSummaryContent">
'@)

    #region SUMMARYSubs
    $startSUMMARYSubs = Get-Date
    Write-Host '  processing TenantSummary Subscriptions'
    $summarySubscriptions = $optimizedTableForPathQueryMgAndSub | Sort-Object -Property Subscription
    $summarySubscriptionsCount = ($summarySubscriptions).Count

    $arrayPIMEligibleGroupedBySubscription = $arrayPIMEligible.where({ $_.ScopeType -eq 'Sub' }) | Group-Object -Property ScopeId

    if ($summarySubscriptionsCount -gt 0) {

        $advisorScoreCategories = $arrayAdvisorScores.category | Sort-Object -Unique
        $htAdvisorScoresSubscriptions = @{}
        if ($advisorScoreCategories.Count -gt 0) {
            $arrayAdvisorScoresGroupedBySubscriptionId = $arrayAdvisorScores | Group-Object -Property subscriptionId
            foreach ($subEntry in $arrayAdvisorScoresGroupedBySubscriptionId) {
                $htAdvisorScoresSubscriptions.($subEntry.Name) = @{}
                foreach ($possibleCategory in $advisorScoreCategories) {
                    if ($subEntry.Group.category -eq $possibleCategory) {
                        $htAdvisorScoresSubscriptions.($subEntry.Name).($possibleCategory) = $subEntry.Group.where({ $_.category -eq $possibleCategory }).score
                    }
                }
            }
        }

        $tfCount = $summarySubscriptionsCount
        $htmlTableId = 'TenantSummary_subs'
        $abbr = " <abbr title=`"indirect: members of an AAD group where RBAC was assigned`"><i class=`"fa fa-question-circle`" aria-hidden=`"true`"></i></abbr>"
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_Subs"><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle">$($summarySubscriptionsCount) Subscriptions (state: enabled)</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Supported Microsoft Azure offers</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/cost-management-billing/costs/understand-cost-mgt-data#supported-microsoft-azure-offers" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Understand Microsoft Defender for Cloud Secure Score</span> <a class="externallink" href="https://www.youtube.com/watch?v=2EMnzxdqDhA" target="_blank" rel="noopener">Video <i class="fa fa-external-link" aria-hidden="true"></i></a>, <a class="externallink" href="https://techcommunity.microsoft.com/t5/azure-security-center/security-controls-in-azure-security-center-enable-endpoint/ba-p/1624653" target="_blank" rel="noopener">Blog <i class="fa fa-external-link" aria-hidden="true"></i></a>, <a class="externallink" href="https://docs.microsoft.com/en-us/azure/security-center/secure-score-security-controls#how-your-secure-score-is-calculated" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>QuotaId</th>
<th>Role assignment limit</th>
<th>Tags</th>
<th>Owner (at Scope) direct</th>
<th>Owner (at Scope) indirect$($abbr)</th>
<th>Owner (PIM eligible at scope)</th>
<th>User Access Administrator (at Scope) direct</th>
<th>User Access Administrator (at Scope) indirect$($abbr)</th>
<th>User Access Administrator (PIM eligible at scope)</th>
<th>MDfC Score</th>
<th>MDfC 'Email notifications' state</th>
<th>MDfC 'Email notifications' severity</th>
<th>MDfC 'Email notifications' roles</th>
<th>MDfC 'Email notifications' emails</th>
"@)

        foreach ($possibleCategory in $advisorScoreCategories) {
            if ($possibleCategory -eq 'Advisor') {
                [void]$htmlTenantSummary.AppendLine(@"
                <th>$possibleCategory score</th>
"@)
            }
            else {
                [void]$htmlTenantSummary.AppendLine(@"
        <th>Advisor $possibleCategory score</th>
"@)
            }
        }

        if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
            [void]$htmlTenantSummary.AppendLine(@"
<th>Cost ($($AzureConsumptionPeriod)d)</th>
<th>Currency</th>
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@'
<th>Management Group Path</th>
</tr>
</thead>
<tbody>
'@)

        if (-not $ManagementGroupsOnly) {
            if (-not $NoCsvExport) {
                Write-Host " Exporting MDfC Email Notifications CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_MDfCEmailNotifications.csv'"
                $htDefenderEmailContacts.values | Sort-Object -Property subscriptionName | Select-Object -Property subscriptionId, subscriptionName, alertNotificationsState, alertNotificationsminimalSeverity, roles, emails | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_MDfCEmailNotifications.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
            }
        }

        $subscriptionDetails4CSVExport = [System.Collections.ArrayList]@()
        $htmlSUMMARYSubs = $null
        $htmlSUMMARYSubs = foreach ($summarySubscription in $summarySubscriptions) {
            $subPath = $htSubscriptionsMgPath.($summarySubscription.subscriptionId).ParentNameChainDelimited
            $subscriptionTagsArray = [System.Collections.ArrayList]@()
            foreach ($tag in ($htSubscriptionTags).($summarySubscription.subscriptionId).keys) {
                $null = $subscriptionTagsArray.Add("'$($tag)':'$(($htSubscriptionTags).$($summarySubscription.subscriptionId).$tag)'")
            }

            if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
                if ($htAzureConsumptionSubscriptions.($summarySubscription.subscriptionId)) {
                    if ([math]::Round($htAzureConsumptionSubscriptions.($summarySubscription.subscriptionId).TotalCost, 2) -eq 0) {
                        $totalCost = $htAzureConsumptionSubscriptions.($summarySubscription.subscriptionId).TotalCost.ToString('0.0000')
                    }
                    else {
                        $totalCost = (([math]::Round($htAzureConsumptionSubscriptions.($summarySubscription.subscriptionId).TotalCost, 2))).ToString('0.00')
                    }
                    $currency = $htAzureConsumptionSubscriptions.($summarySubscription.subscriptionId).Currency
                }
                else {
                    $totalCost = '0'
                    $currency = 'n/a'
                }
            }
            else {
                $totalCost = 'n/a'
                $currency = 'n/a'
            }

            if ($htDefenderEmailContacts.($summarySubscription.subscriptionId)) {
                $hlpDefenderEmailContacts = $htDefenderEmailContacts.($summarySubscription.subscriptionId)
                $MDfCEmailNotificationsState = $hlpDefenderEmailContacts.alertNotificationsState
                $MDfCEmailNotificationsSeverity = $hlpDefenderEmailContacts.alertNotificationsminimalSeverity
                $MDfCEmailNotificationsRoles = $hlpDefenderEmailContacts.roles
                $MDfCEmailNotificationsEmails = $hlpDefenderEmailContacts.emails
            }
            else {
                $MDfCEmailNotificationsState = ''
                $MDfCEmailNotificationsSeverity = ''
                $MDfCEmailNotificationsRoles = ''
                $MDfCEmailNotificationsEmails = ''
            }

            #rbac assignments owner and userAccountAdministrator
            $rbacAtScopeForThisSubscription = ($rbacAllGroupedBySubscription.where( { $_.name -eq $summarySubscription.subscriptionId } )).group

            $rbacOwnersAtScopeForThisSubscription = ($rbacAtScopeForThisSubscription.where({ $_.Scope -eq 'thisScope Sub' -and $_.RoleId -eq '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' }))
            $rbacOwnersAtScopeForThisSubscriptionDirectCount = ($rbacOwnersAtScopeForThisSubscription.where( { $_.AssignmentType -eq 'direct' } )).Count
            $rbacOwnersAtScopeForThisSubscriptionInDirectCount = $rbacOwnersAtScopeForThisSubscription.Count - $rbacOwnersAtScopeForThisSubscriptionDirectCount

            $rbacUAAsAtScopeForThisSubscription = ($rbacAtScopeForThisSubscription.where({ $_.Scope -eq 'thisScope Sub' -and $_.RoleId -eq '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' }))
            $rbacUAAsAtScopeForThisSubscriptionDirectCount = ($rbacUAAsAtScopeForThisSubscription.where( { $_.AssignmentType -eq 'direct' } )).Count
            $rbacUAAsAtScopeForThisSubscriptionInDirectCount = $rbacUAAsAtScopeForThisSubscription.Count - $rbacUAAsAtScopeForThisSubscriptionDirectCount

            #pim eligibility owner and userAccountAdministrator
            $pimEligibleOwnersAtScopeForThisSubscriptionCount = ''
            $pimEligibleUAAsAtScopeForThisSubscriptionCount = ''
            if (-not $NoPIMEligibility) {
                $pimEligibleAtScopeForThisSubscription = ($arrayPIMEligibleGroupedBySubscription.where( { $_.name -eq $summarySubscription.subscriptionId } )).group
                $pimEligibleOwnersAtScopeForThisSubscriptionCount = ($pimEligibleAtScopeForThisSubscription.where( { $_.RoleIdGuid -eq '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' } )).Count
                $pimEligibleUAAsAtScopeForThisSubscriptionCount = ($pimEligibleAtScopeForThisSubscription.where( { $_.RoleIdGuid -eq '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' } )).Count
            }

            $htColl = [ordered]@{}
            @"
<tr>
<td>$($summarySubscription.subscription -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($summarySubscription.MgId)">$($summarySubscription.subscriptionId)</a></span></td>
<td>$($summarySubscription.SubscriptionQuotaId)</td>
<td>$($htSubscriptionsRoleAssignmentLimit.($summarySubscription.subscriptionId))</td>
<td>$(($subscriptionTagsArray | Sort-Object) -join "$CsvDelimiterOpposite ")</td>
<td>$($rbacOwnersAtScopeForThisSubscriptionDirectCount)</td>
<td>$($rbacOwnersAtScopeForThisSubscriptionInDirectCount)</td>
<td>$($pimEligibleOwnersAtScopeForThisSubscriptionCount)</td>
<td>$($rbacUAAsAtScopeForThisSubscriptionDirectCount)</td>
<td>$($rbacUAAsAtScopeForThisSubscriptionInDirectCount)</td>
<td>$($pimEligibleUAAsAtScopeForThisSubscriptionCount)</td>
<td>$($summarySubscription.SubscriptionASCSecureScore)</td>
<td>$($MDfCEmailNotificationsState)</td>
<td>$($MDfCEmailNotificationsSeverity)</td>
<td>$($MDfCEmailNotificationsRoles)</td>
<td>$($MDfCEmailNotificationsEmails)</td>
"@

            $htColl.Subscription = $summarySubscription.subscription
            $htColl.SubscriptionId = $summarySubscription.subscriptionId
            $htColl.QuotaId = $summarySubscription.SubscriptionQuotaId
            $htColl.ManagementGroupPath = $subPath
            $htColl.RoleAssignmentLimit = $htSubscriptionsRoleAssignmentLimit.($summarySubscription.subscriptionId)
            $htColl.Tags = ($subscriptionTagsArray | Sort-Object) -join "$CsvDelimiterOpposite "
            $htColl.'Owner(atScope)Direct' = $rbacOwnersAtScopeForThisSubscriptionDirectCount
            $htColl.'Owner(atScope)Indirect' = $rbacOwnersAtScopeForThisSubscriptionInDirectCount
            $htColl.'Owner(PIMEligibleAtScope)' = $pimEligibleOwnersAtScopeForThisSubscriptionCount
            $htColl.'UserAccessAdministrator(atScope)Direct' = $rbacUAAsAtScopeForThisSubscriptionDirectCount
            $htColl.'UserAccessAdministrator(atScope)Indirect' = $rbacUAAsAtScopeForThisSubscriptionInDirectCount
            $htColl.'UserAccessAdministrator(PIMEligibleAtScope)' = $pimEligibleUAAsAtScopeForThisSubscriptionCount
            $htColl.MDfCScore = $summarySubscription.SubscriptionASCSecureScore
            $htColl.MDfCEmailNotificationsState = $MDfCEmailNotificationsState
            $htColl.MDfCEmailNotificationsSeverity = $MDfCEmailNotificationsSeverity
            $htColl.MDfCEmailNotificationsRoles = $MDfCEmailNotificationsRoles
            $htColl.MDfCEmailNotificationsEmails = $MDfCEmailNotificationsEmails

            foreach ($possibleCategory in $advisorScoreCategories) {
                if ($htAdvisorScoresSubscriptions.($summarySubscription.subscriptionId).($possibleCategory)) {
                    @"
        <td>$([math]::Round(($htAdvisorScoresSubscriptions.($summarySubscription.subscriptionId).($possibleCategory)), 2))</td>
"@
                    if ($possibleCategory -eq 'Advisor') {
                        $htColl.("$($possibleCategory)Score") = $htAdvisorScoresSubscriptions.($summarySubscription.subscriptionId).($possibleCategory)
                    }
                    else {
                        $htColl.("Advisor$($possibleCategory)Score") = $htAdvisorScoresSubscriptions.($summarySubscription.subscriptionId).($possibleCategory)
                    }
                }
                else {
                    @'
        <td>n/a</td>
'@
                    $htColl.($possibleCategory) = 'n/a'
                }
            }

            if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
                @"
<td>$totalCost</td>
<td>$currency</td>
"@
                $htColl."Cost($($AzureConsumptionPeriod)d)" = $totalCost
                $htColl.Currency = $currency
            }
            @"
<td><a href="#hierarchySub_$($summarySubscription.MgId)"><i class="fa fa-eye" aria-hidden="true"></i></a> $subPath</td>
</tr>
"@
            if (-not $NoCsvExport) {
                $null = $subscriptionDetails4CSVExport.Add($htColl)
            }
        }

        if (-not $ManagementGroupsOnly) {
            if (-not $NoCsvExport) {
                Write-Host " Exporting SubscriptionDetails CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_SubscriptionDetails.csv'"
                $subscriptionDetails4CSVExport | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_SubscriptionDetails.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
            }
        }

        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYSubs)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@'
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_2: 'select',
            col_3: 'select',
            col_12: 'select',
            col_13: 'select',
            col_14: 'select',
'@)
        if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
            [void]$htmlTenantSummary.AppendLine(@"
            col_$(17 + $advisorScoreCategories.Count): 'multiple',
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@'
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number',
                'caseinsensitivestring',
                'number',
                'number',
                'number',
                'number',
                'number',
                'number',
                'number',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
'@)
        foreach ($possibleCategory in $advisorScoreCategories) {
            [void]$htmlTenantSummary.AppendLine(@'
    'number',
'@)
        }

        if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
            [void]$htmlTenantSummary.AppendLine(@'
                'number',
                'caseinsensitivestring',
'@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
                'caseinsensitivestring'
            ],
            watermark: ['', '', '', '', '', 'try: >1'],
            extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>

"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
    <p><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle">$($summarySubscriptionsCount) Subscriptions</span></p>
"@)
    }

    $endSUMMARYSubs = Get-Date
    Write-Host "   SUMMARYSubs duration: $((New-TimeSpan -Start $startSUMMARYSubs -End $endSUMMARYSubs).TotalMinutes) minutes ($((New-TimeSpan -Start $startSUMMARYSubs -End $endSUMMARYSubs).TotalSeconds) seconds)"
    #endregion SUMMARYSubs

    #region SUMMARYOutOfScopeSubscriptions
    Write-Host '  processing TenantSummary Subscriptions (out-of-scope)'
    $outOfScopeSubscriptionsCount = ($outOfScopeSubscriptions).Count
    if ($outOfScopeSubscriptionsCount -gt 0) {
        $tfCount = $outOfScopeSubscriptionsCount
        $htmlTableId = 'TenantSummary_outOfScopeSubscriptions'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_outOfScopeSubscriptions"><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg"> <span class="valignMiddle">$outOfScopeSubscriptionsCount Subscriptions out-of-scope</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription Name</th>
<th>SubscriptionId</th>
<th>out-of-scope reason</th>
<th>Management Group</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYOutOfScopeSubscriptions = $null
        $htmlSUMMARYOutOfScopeSubscriptions = foreach ($outOfScopeSubscription in $outOfScopeSubscriptions) {
            @"
<tr>
<td>$($outOfScopeSubscription.SubscriptionName)</td>
<td>$($outOfScopeSubscription.SubscriptionId)</td>
<td>$($outOfScopeSubscription.outOfScopeReason)</td>
<td><a href="#hierarchy_$($outOfScopeSubscription.ManagementGroupId)"><i class="fa fa-eye" aria-hidden="true"></i></a> $($outOfScopeSubscription.ManagementGroupName -replace '<', '&lt;' -replace '>', '&gt;') ($($outOfScopeSubscription.ManagementGroupId))</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYOutOfScopeSubscriptions)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,

"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
    <p><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg"> $outOfScopeSubscriptionsCount Subscriptions out-of-scope</p>
"@)
    }
    #endregion SUMMARYOutOfScopeSubscriptions

    #region SUMMARYTagNameUsage
    Write-Host '  processing TenantSummary TagsUsage'
    $tagsUsageCount = ($arrayTagList).Count
    if ($tagsUsageCount -gt 0) {
        $tagNamesUniqueCount = ($arrayTagList | Sort-Object -Property TagName -Unique).Count
        $tagNamesUsedInScopes = ($arrayTagList.where( { $_.Scope -ne 'AllScopes' }) | Sort-Object -Property Scope -Unique).scope -join "$($CsvDelimiterOpposite) "
        $tfCount = $tagsUsageCount
        $htmlTableId = 'TenantSummary_tagsUsage'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_tagsUsage"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Tag Name Usage ($tagNamesUniqueCount unique Tag Names applied at $($tagNamesUsedInScopes))</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Resource naming and tagging decision guide</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/cloud-adoption-framework/decision-guides/resource-tagging" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>TagName</th>
<th>Count</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYtagsUsage = $null
        $htmlSUMMARYtagsUsage = foreach ($tagEntry in $arrayTagList | Sort-Object -Property Scope, TagName -CaseSensitive) {
            @"
<tr>
<td>$($tagEntry.Scope)</td>
<td>$($tagEntry.TagName)</td>
<td>$($tagEntry.TagCount)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYtagsUsage)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,

"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'multiple',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> Tag Name Usage ($tagsUsageCount Tags) <a class="externallink" href="https://docs.microsoft.com/en-us/azure/cloud-adoption-framework/decision-guides/resource-tagging" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@)
    }
    #endregion SUMMARYTagNameUsage

    if ($azAPICallConf['htParameters'].NoResources -eq $false) {
        #region SUMMARYResources
        $startSUMMARYResources = Get-Date
        Write-Host '  processing TenantSummary Subscriptions Resources'
        if (($resourcesAll).count -gt 0) {
            $resourcesAllGroupedByType = $resourcesAll | Select-Object -Property type, count_ | Group-Object type
            $resourcesTotal = ($resourcesAll.count_ | Measure-Object -Sum).Sum
            $resourcesResourceTypeCount = ($resourcesAll.type | Sort-Object -Unique).Count

            if ($resourcesResourceTypeCount -gt 0) {
                $tfCount = ($resourcesAllGroupedByType | Measure-Object).Count
                $htmlTableId = 'TenantSummary_resources'
                [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_resources"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resources ($resourcesResourceTypeCount ResourceTypes) ($resourcesTotal Resources) ($scopeNamingSummary)</span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>ResourceType</th>
<th>Resource Count</th>
</tr>
</thead>
<tbody>
"@)
                $htmlSUMMARYResources = $null
                $htmlSUMMARYResources = foreach ($resourceAllSummarized in $resourcesAllGroupedByType) {
                    $type = $resourceAllSummarized.Name
                    $script:htDailySummary."ResourceType_$($resourceAllSummarized.Name)" = ($resourceAllSummarized.group.count_ | Measure-Object -Sum).Sum
                    @"
<tr>
<td>$($type)</td>
<td>$(($resourceAllSummarized.group.count_ | Measure-Object -Sum).Sum)</td>
</tr>
"@

                }
                [void]$htmlTenantSummary.AppendLine($htmlSUMMARYResources)
                [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
                if ($tfCount -gt 10) {
                    $spectrum = "10, $tfCount"
                    if ($tfCount -gt 50) {
                        $spectrum = "10, 25, 50, $tfCount"
                    }
                    if ($tfCount -gt 100) {
                        $spectrum = "10, 30, 50, 100, $tfCount"
                    }
                    if ($tfCount -gt 500) {
                        $spectrum = "10, 30, 50, 100, 250, $tfCount"
                    }
                    if ($tfCount -gt 1000) {
                        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                    }
                    if ($tfCount -gt 2000) {
                        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                    }
                    if ($tfCount -gt 3000) {
                        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                    }
                    [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
                }
                [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_types: [
            'caseinsensitivestring',
            'number'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>
"@)
            }
            else {
                [void]$htmlTenantSummary.AppendLine(@"
                    <p><i class="padlx fa fa-ban" aria-hidden="true"></i> Resources ($resourcesResourceTypeCount ResourceTypes)</p>
"@)
            }

        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> Resources (0 ResourceTypes)</p>
'@)
        }
        $endSUMMARYResources = Get-Date
        Write-Host "   SUMMARY Resources processing duration: $((New-TimeSpan -Start $startSUMMARYResources -End $endSUMMARYResources).TotalMinutes) minutes ($((New-TimeSpan -Start $startSUMMARYResources -End $endSUMMARYResources).TotalSeconds) seconds)"
        #endregion SUMMARYResources

        #region SUMMARYResourcesByLocation
        $startSUMMARYResources = Get-Date
        Write-Host '  processing TenantSummary Subscriptions Resources by Location'
        if (($resourcesAll | Measure-Object).count -gt 0) {
            $resourcesAllGroupedByTypeLocation = $resourcesAll | Select-Object -Property type, location, count_ | Group-Object type, location
            $resourcesTotal = ($resourcesAll.count_ | Measure-Object -Sum).Sum
            $resourcesResourceTypeCount = ($resourcesAll.type | Sort-Object -Unique).Count
            $resourcesLocationCount = ($resourcesAll.location | Sort-Object -Unique).Count

            if ($resourcesResourceTypeCount -gt 0) {
                $tfCount = ($resourcesAllGroupedByTypeLocation | Measure-Object).Count
                $htmlTableId = 'TenantSummary_resourcesByLocation'
                [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_resourcesByLocation"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resources byLocation ($resourcesResourceTypeCount ResourceTypes) ($resourcesTotal Resources) in $resourcesLocationCount Locations ($scopeNamingSummary)</span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>ResourceType</th>
<th>Location</th>
<th>Resource Count</th>
</tr>
</thead>
<tbody>
"@)
                $htmlSUMMARYResources = $null
                $htmlSUMMARYResources = foreach ($resourceAllSummarized in $resourcesAllGroupedByTypeLocation) {
                    $typeLocation = $resourceAllSummarized.Name.Split(', ')
                    $type = $typeLocation[0]
                    $location = $typeLocation[1]
                    @"
<tr>
<td>$($type)</td>
<td>$($location)</td>
<td>$(($resourceAllSummarized.group.count_ | Measure-Object -Sum).Sum)</td>
</tr>
"@

                }
                [void]$htmlTenantSummary.AppendLine($htmlSUMMARYResources)
                [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
                if ($tfCount -gt 10) {
                    $spectrum = "10, $tfCount"
                    if ($tfCount -gt 50) {
                        $spectrum = "10, 25, 50, $tfCount"
                    }
                    if ($tfCount -gt 100) {
                        $spectrum = "10, 30, 50, 100, $tfCount"
                    }
                    if ($tfCount -gt 500) {
                        $spectrum = "10, 30, 50, 100, 250, $tfCount"
                    }
                    if ($tfCount -gt 1000) {
                        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                    }
                    if ($tfCount -gt 2000) {
                        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                    }
                    if ($tfCount -gt 3000) {
                        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                    }
                    [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
                }
                [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'number'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>
"@)
            }
            else {
                [void]$htmlTenantSummary.AppendLine(@"
                    <p><i class="padlx fa fa-ban" aria-hidden="true"></i> Resources ($resourcesResourceTypeCount ResourceTypes)</p>
"@)
            }

        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> Resources (0 ResourceTypes)</p>
'@)
        }
        $endSUMMARYResources = Get-Date
        Write-Host "   SUMMARY Resources ByLocation processing duration: $((New-TimeSpan -Start $startSUMMARYResources -End $endSUMMARYResources).TotalMinutes) minutes ($((New-TimeSpan -Start $startSUMMARYResources -End $endSUMMARYResources).TotalSeconds) seconds)"
        #endregion SUMMARYResourcesByLocation

        #region SUMMARYResourceFluctuation
        $startSUMMARYResourceFluctuation = Get-Date
        Write-Host '  processing TenantSummary Resource fluctuation'
        if (($arrayResourceFluctuationFinal).count -gt 0) {
            $resourceTypesCount = ($arrayResourceFluctuationFinal | Group-Object -Property ResourceType | Measure-Object).Count
            $addedCount = ($arrayResourceFluctuationFinal.where({ $_.Event -eq 'Added' }).'Resource count' | Measure-Object -Sum).Sum
            $removedCount = ($arrayResourceFluctuationFinal.where({ $_.Event -eq 'Removed' }).'Resource count' | Measure-Object -Sum).Sum

            $tfCount = ($arrayResourceFluctuationFinal).count
            $htmlTableId = 'TenantSummary_resourceFluctuation'
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_resourceFluctuation"><i class="padlx fa fa-history" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">Resource fluctuation - $resourceTypesCount Resource types (Resources: $addedCount added, $removedCount removed)</span>
</button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Event</th>
<th>ResourceType</th>
<th>Resource count</th>
<th>Subscription count</th>
</tr>
</thead>
<tbody>
"@)
            $htmlSUMMARYResourceFluctuation = $null
            $htmlSUMMARYResourceFluctuation = foreach ($entry in $arrayResourceFluctuationFinal | Sort-Object -Property ResourceType, Event) {
                @"
<tr>
<td>$($entry.Event)</td>
<td>$($entry.ResourceType)</td>
<td>$($entry.'Resource count')</td>
<td>$($entry.'Subscription count')</td>
</tr>
"@

            }
            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYResourceFluctuation)
            [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_0: 'select',
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'number',
            'number'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No Resource fluctuation since last run</p>
'@)
        }
        $endSUMMARYResourceFluctuation = Get-Date
        Write-Host "   SUMMARY Resource fluctuation processing duration: $((New-TimeSpan -Start $startSUMMARYResourceFluctuation -End $endSUMMARYResourceFluctuation).TotalMinutes) minutes ($((New-TimeSpan -Start $startSUMMARYResourceFluctuation -End $endSUMMARYResourceFluctuation).TotalSeconds) seconds)"
        #endregion SUMMARYResourceFluctuation

        #region SUMMARYCAFResourceNamingALL
        $startSUMMARYCAFResourceNamingALL = Get-Date
        Write-Host '  processing TenantSummary CAFResourceNamingALL'
        $script:resourcesIdsAllCAFNamingRelevant = $resourcesIdsAll.where({ $_.cafResourceNamingResult -ne 'n/a' })
        $resourcesIdsAllCAFNamingRelevantGroupedByType = $resourcesIdsAllCAFNamingRelevant | Group-Object -Property type
        $resourcesIdsAllCAFNamingRelevantGroupedByTypeCount = ($resourcesIdsAllCAFNamingRelevantGroupedByType | Measure-Object).Count

        if ($resourcesIdsAllCAFNamingRelevantGroupedByTypeCount -gt 0) {

            $tfCount = $resourcesIdsAllCAFNamingRelevantGroupedByTypeCount
            $htmlTableId = 'TenantSummary_CAFResourceNamingALL'
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_CAFResourceNamingALL"><i class="padlx fa fa-star-o" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">CAF Naming Recommendation Compliance</span>
</button>
<div class="content TenantSummary">
<span class="padlxx info"><i class="fa fa-lightbulb-o" aria-hidden="true"></i> CAF - Recommended abbreviations for Azure resource types</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<span class="padlxx"><i class="fa fa-lightbulb-o" aria-hidden="true"></i> Resource details can be found in the CSV output *_ResourcesAll.csv</span><br>
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>ResourceType</th>
<th>Recommendation</th>
<th>ResourceFriendlyName</th>
<th>passed</th>
<th>failed</th>
<th>passed percentage</th>
</tr>
</thead>
<tbody>
"@)

            $htmlSUMMARYCAFResourceNamingALL = $null
            $htmlSUMMARYCAFResourceNamingALL = foreach ($entry in $resourcesIdsAllCAFNamingRelevantGroupedByType) {

                $resourceTypeGroupedByCAFResourceNamingResult = $entry.Group | Group-Object -Property cafResourceNamingResult, cafResourceNaming
                if ($entry.Group.cafResourceNaming.Count -gt 1) {
                    $namingConvention = ($entry.Group.cafResourceNaming)[0]
                    $namingConventionFriendlyName = ($entry.Group.cafResourceNamingFriendlyName)[0]
                }
                else {
                    $namingConvention = $entry.Group.cafResourceNaming
                    $namingConventionFriendlyName = $entry.Group.cafResourceNamingFriendlyName
                }

                $passed = 0
                $failed = 0
                foreach ($result in $resourceTypeGroupedByCAFResourceNamingResult) {
                    $resultNameSplitted = $result.Name -split ', '
                    if ($resultNameSplitted[0] -eq 'passed') {
                        $passed = $result.Count
                    }

                    if ($resultNameSplitted[0] -eq 'failed') {
                        $failed = $result.Count
                    }
                }

                if ($passed -gt 0) {
                    $percentage = [math]::Round(($passed / ($passed + $failed) * 100), 2)
                }
                else {
                    $percentage = 0
                }

                @"
<tr>
<td>$($entry.Name)</td>
<td>$($namingConvention)</td>
<td>$($namingConventionFriendlyName)</td>
<td>$($passed)</td>
<td>$($failed)</td>
<td>$($percentage)%</td>
</tr>
"@

            }
            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYCAFResourceNamingALL)
            [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'number',
            'number',
            'number'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No CAF Naming Recommendation Compliance data</p>
'@)
        }
        $endSUMMARYCAFResourceNamingALL = Get-Date
        Write-Host "   SUMMARY CAFResourceNamingALL processing duration: $((New-TimeSpan -Start $startSUMMARYCAFResourceNamingALL -End $endSUMMARYCAFResourceNamingALL).TotalMinutes) minutes ($((New-TimeSpan -Start $startSUMMARYCAFResourceNamingALL -End $endSUMMARYCAFResourceNamingALL).TotalSeconds) seconds)"
        #endregion SUMMARYCAFResourceNamingALL
    }

    #region SUMMARYOrphanedResources
    $startSUMMARYOrphanedResources = Get-Date
    Write-Host '  processing TenantSummary Orphaned/unused Resources'
    if ($arrayOrphanedResources.count -gt 0) {
        $script:arrayOrphanedResourcesSlim = $arrayOrphanedResources | Sort-Object -Property type


        if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
            $orphanedIncludingCost = $true
            $hintTableTH = " ($($AzureConsumptionPeriod) days)"

            $arrayOrphanedResourcesGroupedByType = $arrayOrphanedResourcesSlim | Group-Object type, currency
            $orphanedResourceTypesCount = ($arrayOrphanedResourcesGroupedByType | Measure-Object).Count
            $orphanedResourceTypesCountUnique = ($arrayOrphanedResourcesSlim.type | Sort-Object -Unique).Count
        }
        else {
            $orphanedIncludingCost = $false
            $hintTableTH = ''

            $arrayOrphanedResourcesGroupedByType = $arrayOrphanedResourcesSlim | Group-Object type
            $orphanedResourceTypesCount = ($arrayOrphanedResourcesGroupedByType | Measure-Object).Count
            $orphanedResourceTypesCountUnique = ($arrayOrphanedResourcesSlim.type | Sort-Object -Unique).Count
        }

        $tfCount = $orphanedResourceTypesCount
        $htmlTableId = 'TenantSummary_orphanedResources'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_orphanedResources"><i class="padlx fa fa-trash-o" aria-hidden="true" style="color: #0078df"></i>=<i class="fa fa-usd" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">Cost optimization & cleanup - $($arrayOrphanedResources.count) Resources, $orphanedResourceTypesCountUnique Resource Types</span>
</button>
<div class="content TenantSummary">
<span class="padlxx info"><i class="fa fa-lightbulb-o" aria-hidden="true"></i> 'Azure Orphan Resources' ARG queries and workbooks</span> <a class="externallink" href="https://github.com/dolevshor/azure-orphan-resources" target="_blank" rel="noopener">GitHub <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<span class="padlxx"><i class="fa fa-lightbulb-o" aria-hidden="true"></i> Resource details can be found in the CSV output *_ResourcesCostOptimizationAndCleanup.csv</span><br>
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>ResourceType</th>
<th>Resource count</th>
<th>Subscriptions count</th>
<th>Intent</th>
<th>Cost$($hintTableTH)</th>
<th>Currency</th>
</tr>
</thead>
<tbody>
"@)

        $htmlSUMMARYOrphanedResources = $null
        $htmlSUMMARYOrphanedResources = foreach ($orphanedResourceType in $arrayOrphanedResourcesGroupedByType | Sort-Object -Property Name) {
            $script:htDailySummary."OrpanedResourceType_$($orphanedResourceType.Name)" = ($orphanedResourceType.count)
            if ($orphanedIncludingCost) {
                if (($orphanedResourceType.Group[0].Intent) -like 'cost savings*') {
                    $orphCost = ($orphanedResourceType.Group.Cost | Measure-Object -Sum).Sum
                    if ($orphCost -eq 0) {
                        $orphCost = ''
                    }
                    $orphCurrency = $orphanedResourceType.Group[0].Currency
                    $script:htDailySummary."OrpanedResourceType_$($orphanedResourceType.Name)_Costs" = $orphCost
                    $script:htDailySummary."OrpanedResourceType_$($orphanedResourceType.Name)_Costs_ConsumptionPeriodInDays" = $AzureConsumptionPeriod
                }
                else {
                    $orphCost = ''
                    $orphCurrency = ''
                }

            }
            else {
                if (($orphanedResourceType.Group.Intent | Get-Unique) -like 'cost savings*') {
                    $orphCost = "<span class=`"info`">use parameter <b>-DoAzureConsumption</b> to show potential savings</span>"
                    $orphCurrency = ''
                }
                else {
                    $orphCost = ''
                    $orphCurrency = ''
                }
            }

            @"
<tr>
<td>$(($orphanedResourceType.Name -split ',')[0])</td>
<td>$($orphanedResourceType.count)</td>
<td>$(($orphanedResourceType.Group.SubscriptionId | Sort-Object -Unique).Count)</td>
<td>$($orphanedResourceType.Group[0].Intent)</td>
<td>$($orphCost)</td>
<td>$($orphCurrency)</td>
</tr>
"@

        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYOrphanedResources)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_0: 'multiple',
        col_3: 'select',
        col_5: 'select',
        col_types: [
            'caseinsensitivestring',
            'number',
            'number',
            'caseinsensitivestring',
            'number',
            'caseinsensitivestring'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@'
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No cost optimization & cleanup</p>
'@)
    }
    $endSUMMARYOrphanedResources = Get-Date
    Write-Host "   SUMMARY Orphaned/unused Resources processing duration: $((New-TimeSpan -Start $startSUMMARYOrphanedResources -End $endSUMMARYOrphanedResources).TotalMinutes) minutes ($((New-TimeSpan -Start $startSUMMARYOrphanedResources -End $endSUMMARYOrphanedResources).TotalSeconds) seconds)"
    #endregion SUMMARYOrphanedResources

    #region SUMMARYSubResourceProviders
    if ($azAPICallConf['htParameters'].NoResourceProvidersAtAll -eq $false) {
        $startSUMMARYSubResourceProviders = Get-Date
        Write-Host '  processing TenantSummary Subscriptions Resource Providers'
        $resourceProvidersAllCount = (($htResourceProvidersAll).Keys | Measure-Object).count
        if ($resourceProvidersAllCount -gt 0) {
            $grped = (($htResourceProvidersAll).values.Providers) | Sort-Object -Property namespace, registrationState | Group-Object namespace
            $htResProvSummary = @{}
            foreach ($grp in $grped) {
                $htResProvSummary.($grp.name) = @{}
                $regstates = ($grp.group | Sort-Object -Property registrationState -Unique).registrationstate
                foreach ($regstate in $regstates) {
                    $htResProvSummary.($grp.name).$regstate = (($grp.group).where( { $_.registrationstate -eq $regstate }) | Measure-Object).count
                }
            }
            $providerSummary = [System.Collections.ArrayList]@()
            foreach ($provider in $htResProvSummary.keys) {
                $hlperProvider = $htResProvSummary.$provider
                if ($hlperProvider.registered) {
                    $registered = $hlperProvider.registered
                }
                else {
                    $registered = '0'
                }

                if ($hlperProvider.registering) {
                    $registering = $hlperProvider.registering
                }
                else {
                    $registering = '0'
                }

                if ($hlperProvider.notregistered) {
                    $notregistered = $hlperProvider.notregistered
                }
                else {
                    $notregistered = '0'
                }

                if ($hlperProvider.unregistering) {
                    $unregistering = $hlperProvider.unregistering
                }
                else {
                    $unregistering = '0'
                }

                $null = $providerSummary.Add([PSCustomObject]@{
                        Provider      = $provider
                        Registered    = $registered
                        NotRegistered = $notregistered
                        Registering   = $registering
                        Unregistering = $unregistering
                    })
            }

            $uniqueNamespaces = (($htResourceProvidersAll).values.Providers) | Sort-Object -Property namespace -Unique
            $uniqueNamespacesCount = ($uniqueNamespaces | Measure-Object).count
            $uniqueNamespaceRegistrationState = (($htResourceProvidersAll).values.Providers) | Sort-Object -Property namespace, registrationState -Unique
            $providersRegistered = ($uniqueNamespaceRegistrationState.where( { $_.registrationState -eq 'registered' -or $_.registrationState -eq 'registering' }) | Sort-Object namespace -Unique).namespace
            $providersRegisteredCount = ($providersRegistered | Measure-Object).count

            $providersNotRegisteredUniqueCount = 0
            foreach ($uniqueNamespace in $uniqueNamespaces) {
                if ($providersRegistered -notcontains ($uniqueNamespace.namespace)) {
                    $providersNotRegisteredUniqueCount++
                }
            }
            $tfCount = $uniqueNamespacesCount
            $htmlTableId = 'TenantSummary_SubResourceProviders'
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_SubResourceProviders"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Providers Total: $uniqueNamespacesCount Registered/Registering: $providersRegisteredCount NotRegistered/Unregistering: $providersNotRegisteredUniqueCount</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Provider</th>
<th>Registered</th>
<th>Registering</th>
<th>NotRegistered</th>
<th>Unregistering</th>
</tr>
</thead>
<tbody>
"@)
            $htmlSUMMARYSubResourceProviders = $null
            $htmlSUMMARYSubResourceProviders = foreach ($provider in ($providerSummary | Sort-Object -Property Provider)) {
                @"
<tr>
<td>$($provider.Provider)</td>
<td>$($provider.Registered)</td>
<td>$($provider.Registering)</td>
<td>$($provider.NotRegistered)</td>
<td>$($provider.Unregistering)</td>
</tr>
"@
            }
            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYSubResourceProviders)
            [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'number',
                'number',
                'number',
                'number'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $resourceProvidersAllCount Resource Providers</p>
"@)
        }
        $endSUMMARYSubResourceProviders = Get-Date
        Write-Host "   TenantSummary Subscriptions Resource Providers duration: $((New-TimeSpan -Start $startSUMMARYSubResourceProviders -End $endSUMMARYSubResourceProviders).TotalMinutes) minutes ($((New-TimeSpan -Start $startSUMMARYSubResourceProviders -End $endSUMMARYSubResourceProviders).TotalSeconds) seconds)"
    }
    #endregion SUMMARYSubResourceProviders

    #region SUMMARYSubResourceProvidersDetailed
    if ($azAPICallConf['htParameters'].NoResourceProvidersAtAll -eq $false) {
        if ($azAPICallConf['htParameters'].NoResourceProvidersDetailed -eq $false) {

            Write-Host '  processing TenantSummary Subscriptions Resource Providers detailed'
            $startsumRPDetailed = Get-Date
            $resourceProvidersAllCount = (($htResourceProvidersAll).Keys).count
            if ($resourceProvidersAllCount -gt 0) {
                $tfCount = ($htResourceProvidersAll).values.Providers.Count
                if ($tfCount -lt $HtmlTableRowsLimit) {
                    $htmlTableId = 'TenantSummary_SubResourceProvidersDetailed'
                    [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_SubResourceProvidersDetailed"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Providers Detailed</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>Subscription MG path
<th>Provider</th>
<th>State</th>
</tr>
</thead>
<tbody>
"@)

                }
                else {
                    Write-Host "   !Skipping TenantSummary ResourceProvidersDetailed HTML processing as $tfCount lines is exceeding the critical rows limit of $HtmlTableRowsLimit" -ForegroundColor Yellow
                }
                $cnter = 0
                $startResProvDetailed = Get-Date
                $htmlSUMMARYSubResourceProvidersDetailed = $null

                $arrayResourceProvidersDetailedForCSVExport = [System.Collections.ArrayList]@()
                $htmlSUMMARYSubResourceProvidersDetailed = foreach ($subscriptionResProv in (($htResourceProvidersAll).Keys | Sort-Object)) {
                    $subscriptionResProvDetails = $htSubscriptionsMgPath.($subscriptionResProv)
                    foreach ($provider in ($htResourceProvidersAll).($subscriptionResProv).Providers | Sort-Object @{Expression = { $_.namespace } }) {
                        $cnter++
                        if ($cnter % 1000 -eq 0) {
                            $etappeResProvDetailed = Get-Date
                            Write-Host "   $cnter ResProv processed; $((New-TimeSpan -Start $startResProvDetailed -End $etappeResProvDetailed).TotalSeconds) seconds"
                        }

                        #array for exportCSV
                        if (-not $NoCsvExport) {
                            $null = $arrayResourceProvidersDetailedForCSVExport.Add([PSCustomObject]@{
                                    Subscription       = $subscriptionResProvDetails.DisplayName
                                    SubscriptionId     = $subscriptionResProv
                                    SubscriptionMGpath = $subscriptionResProvDetails.pathDelimited
                                    Provider           = $provider.namespace
                                    State              = $provider.registrationState
                                })
                        }

                        @"
<tr>
<td>$($subscriptionResProvDetails.DisplayName)</td>
<td>$($subscriptionResProv)</td>
<td>$($subscriptionResProvDetails.pathDelimited)</td>
<td>$($provider.namespace)</td>
<td>$($provider.registrationState)</td>
</tr>
"@
                    }
                }

                #region exportCSV
                if (-not $NoCsvExport) {
                    $csvFilename = "$($filename)_ResourceProviders"
                    Write-Host "   Exporting ResourceProviders CSV '$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv'"
                    $arrayResourceProvidersDetailedForCSVExport | Export-Csv -Encoding utf8 -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter $csvDelimiter -NoTypeInformation
                    $arrayResourceProvidersDetailedForCSVExport = $null
                }
                #endregion exportCSV

                if ($tfCount -lt $HtmlTableRowsLimit) {
                    [void]$htmlTenantSummary.AppendLine($htmlSUMMARYSubResourceProvidersDetailed)
                    [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,

"@)
                    if ($tfCount -gt 10) {
                        $spectrum = "10, $tfCount"
                        if ($tfCount -gt 50) {
                            $spectrum = "10, 25, 50, $tfCount"
                        }
                        if ($tfCount -gt 100) {
                            $spectrum = "10, 30, 50, 100, $tfCount"
                        }
                        if ($tfCount -gt 500) {
                            $spectrum = "10, 30, 50, 100, 250, $tfCount"
                        }
                        if ($tfCount -gt 1000) {
                            $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                        }
                        if ($tfCount -gt 2000) {
                            $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                        }
                        if ($tfCount -gt 3000) {
                            $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                        }
                        [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
                    }
                    [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_4: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
                }
                else {
                    [void]$htmlTenantSummary.AppendLine(@"
            <button type="button" class="collapsible" id="buttonTenantSummary_SubResourceProvidersDetailed"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Providers Detailed</span></button>
                <div class="content TenantSummary padlxx">
                    <i class="fa fa-exclamation-triangle orange" aria-hidden="true"></i><span style="color:#ff0000"> Output of $tfCount lines would exceed the html rows limit of $HtmlTableRowsLimit (html file potentially would become unresponsive). Work with the CSV file <i>$($csvFilename).csv</i> | Note: the CSV file will only exist if you did NOT use parameter <i>-NoCsvExport</i></span><br>
                    <span style="color:#ff0000">You can adjust the html row limit by using parameter <i>-HtmlTableRowsLimit</i></span><br>
                    <span style="color:#ff0000">Check the parameters documentation</span> <a class="externallink" href="https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting#parameters" target="_blank" rel="noopener">Azure Governance Visualizer docs <i class="fa fa-external-link" aria-hidden="true"></i></a>
                </div>
"@)
                }
            }
            else {
                [void]$htmlTenantSummary.AppendLine(@"
                    <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $resourceProvidersAllCount Resource Providers</p>
"@)
            }
            $endsumRPDetailed = Get-Date
            Write-Host "   RP detailed processing duration: $((New-TimeSpan -Start $startsumRPDetailed -End $endsumRPDetailed).TotalMinutes) minutes ($((New-TimeSpan -Start $startsumRPDetailed -End $endsumRPDetailed).TotalSeconds) seconds)"
        }
    }
    #endregion SUMMARYSubResourceProvidersDetailed

    #region SUMMARYSubFeatures
    Write-Host '  processing TenantSummary Subscriptions Features'
    $startSubFeatures = Get-Date
    $subFeaturesAllCount = $arrayFeaturesAll.count
    if ($subFeaturesAllCount -gt 0) {

        #region exportCSV
        if (-not $NoCsvExport) {
            $csvFilename = "$($filename)_SubscriptionsFeatures"
            Write-Host "   Exporting SubscriptionsFeatures CSV '$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv'"
            ($arrayFeaturesAll | Select-Object -ExcludeProperty mgPathArray | Sort-Object -Property feature, subscriptionId) | Export-Csv -Encoding utf8 -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter $csvDelimiter -NoTypeInformation
        }
        #endregion exportCSV

        $subFeaturesGroupedByFeature = $arrayFeaturesAll | Group-Object -Property feature
        $tfCount = ($subFeaturesGroupedByFeature | Measure-Object).Count
        $htmlTableId = 'TenantSummary_SubFeatures'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_SubFeatures"><i class="padlx fa fa-cube" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">$tfCount enabled Subscriptions Features</span></button>
<div class="content TenantSummary">
<span class="padlxx info"><i class="fa fa-lightbulb-o" aria-hidden="true"></i> Set up preview features in Azure subscription</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/preview-features" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Feature</th>
<th>Subscriptions</th>
</tr>
</thead>
<tbody>
"@)


        $cnter = 0
        $startResProvDetailed = Get-Date
        $htmlSUMMARYSubFeatures = $null
        $htmlSUMMARYSubFeatures = foreach ($feature in $subFeaturesGroupedByFeature | Sort-Object -Property name) {
            @"
<tr>
<td>$($feature.name)</td>
<td>$($feature.Count)</td>
</tr>
"@
        }

        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYSubFeatures)
        [void]$htmlTenantSummary.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,

"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'number'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)

    }
    else {
        [void]$htmlTenantSummary.AppendLine(@'
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No enabled Subscriptions Features <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/preview-features" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
'@)
    }
    $endSubFeatures = Get-Date
    Write-Host "   Subscriptions Features processing duration: $((New-TimeSpan -Start $startSubFeatures -End $endSubFeatures).TotalMinutes) minutes ($((New-TimeSpan -Start $startSubFeatures -End $endSubFeatures).TotalSeconds) seconds)"
    #endregion SUMMARYSubFeatures

    #region SUMMARYSubResourceLocks
    Write-Host '  processing TenantSummary Subscriptions Resource Locks'
    $tfCount = 6
    $startResourceLocks = Get-Date

    if (($htResourceLocks.keys | Measure-Object).Count -gt 0) {
        $htmlTableId = 'TenantSummary_ResourceLocks'

        $subscriptionLocksCannotDeleteCount = ($htResourceLocks.Keys.where( { $htResourceLocks.($_).SubscriptionLocksCannotDeleteCount -gt 0 } )).Count
        $subscriptionLocksReadOnlyCount = ($htResourceLocks.Keys.where( { $htResourceLocks.($_).SubscriptionLocksReadOnlyCount -gt 0 } )).Count

        $resourceGroupsLocksCannotDeleteCount = ($htResourceLocks.Keys.where( { $htResourceLocks.($_).ResourceGroupsLocksCannotDeleteCount -gt 0 } )).Count
        $resourceGroupsLocksReadOnlyCount = ($htResourceLocks.Keys.where({ $htResourceLocks.($_).ResourceGroupsLocksReadOnlyCount -gt 0 } )).Count

        $resourcesLocksCannotDeleteCount = ($htResourceLocks.Keys.where( { $htResourceLocks.($_).ResourcesLocksCannotDeleteCount -gt 0 } )).Count
        $resourcesLocksReadOnlyCount = ($htResourceLocks.Keys.where( { $htResourceLocks.($_).ResourcesLocksReadOnlyCount -gt 0 } )).Count

        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_ResourceLocks"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Locks</span></button>
<div class="content TenantSummary">
<span class="padlxx info"><i class="fa fa-lightbulb-o" aria-hidden="true"></i> Considerations before applying locks</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources#considerations-before-applying-locks" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<span class="padlxx info"><i class="fa fa-lightbulb-o" aria-hidden="true"></i> Note: Detailed information on Resource Locks is provided in the *_ResourceLocks.csv</span>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Lock scope</th>
<th>Lock type</th>
<th>presence</th>
</tr>
</thead>
<tbody>
<tr><td>Subscription</td><td>CannotDelete</td><td>$($subscriptionLocksCannotDeleteCount) of $totalSubCount Subscriptions</td></tr>
<tr><td>Subscription</td><td>ReadOnly</td><td>$($subscriptionLocksReadOnlyCount) of $totalSubCount Subscriptions</td></tr>
<tr><td>ResourceGroup</td><td>CannotDelete</td><td>$($resourceGroupsLocksCannotDeleteCount) of $totalSubCount Subscriptions (total: $(($htResourceLocks.Values.ResourceGroupsLocksCannotDeleteCount | Measure-Object -Sum).Sum))</td></tr>
<tr><td>ResourceGroup</td><td>ReadOnly</td><td>$($resourceGroupsLocksReadOnlyCount) of $totalSubCount Subscriptions (total: $(($htResourceLocks.Values.ResourceGroupsLocksReadOnlyCount | Measure-Object -Sum).Sum))</td></tr>
<tr><td>Resource</td><td>CannotDelete</td><td>$($resourcesLocksCannotDeleteCount) of $totalSubCount Subscriptions (total: $(($htResourceLocks.Values.ResourcesLocksCannotDeleteCount | Measure-Object -Sum).Sum))</td></tr>
<tr><td>Resource</td><td>ReadOnly</td><td>$($resourcesLocksReadOnlyCount) of $totalSubCount Subscriptions (total: $(($htResourceLocks.Values.ResourcesLocksReadOnlyCount | Measure-Object -Sum).Sum))</td></tr>
</tbody>
</table>
<script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            linked_filters: true,
            col_0: 'select',
            col_1: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
</div>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@'
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No Resource Locks at all <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources#considerations-before-applying-locks" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
'@)
    }
    $endResourceLocks = Get-Date
    Write-Host "   ResourceLocks processing duration: $((New-TimeSpan -Start $startResourceLocks -End $endResourceLocks).TotalMinutes) minutes ($((New-TimeSpan -Start $startResourceLocks -End $endResourceLocks).TotalSeconds) seconds)"
    #endregion SUMMARYSubResourceLocks

    #SUMMARYSubDefenderPlansSubscriptionsSkipped
    if ($arrayDefenderPlansSubscriptionsSkipped.Count -gt 0) {
        #region SUMMARYSubDefenderPlansSubscriptionsSkipped
        Write-Host '  processing TenantSummary Subscriptions Microsoft Defender for Cloud plans SubscriptionsSkipped'

        $tfCount = $defenderPlansGroupedByPlanCount
        $startDefenderPlans = Get-Date

        $htmlTableId = 'TenantSummary_DefenderPlansSubscriptionsSkipped'

        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_DefenderPlansSubscriptionsSkipped"><i class="padlx fa fa-shield" aria-hidden="true"></i> <span class="valignMiddle">Microsoft Defender for Cloud plans - Subscriptions skipped</span></button>
<div class="content TenantSummary">
<span class="padlxx info"><i class="fa fa-lightbulb-o" aria-hidden="true"></i> Register Resource Provider 'Microsoft.Security'</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/resource-providers-and-types#register-resource-provider" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<span class="padlxx info"><i class="fa fa-lightbulb-o" aria-hidden="true"></i> Microsoft Defender for Cloud's enhanced security features</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/defender-for-cloud/enhanced-security-features-overview" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription Name</th>
<th>Subscription Id</th>
<th>Subscription QuotaId</th>
<th>Subscription MG path</th>
<th>reason</th>
</tr>
</thead>
<tbody>
"@)

        foreach ($subscription in $arrayDefenderPlansSubscriptionsSkipped | Sort-Object -Property subscriptionName) {
            [void]$htmlTenantSummary.AppendLine(@"
                <tr>
                <td>$($subscription.subscriptionName)</td>
                <td>$($subscription.subscriptionId)</td>
                <td>$($subscription.subscriptionQuotaId)</td>
                <td>$($subscription.subscriptionMgPath)</td>
                <td>$($subscription.reason)</td>
                </tr>
"@)
        }

        [void]$htmlTenantSummary.AppendLine(@"
</tbody>
</table>
<script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
            btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
            extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
</div>
"@)

        $endDefenderPlans = Get-Date
        Write-Host "   Microsoft Defender for Cloud plans SubscriptionsSkipped processing duration: $((New-TimeSpan -Start $startDefenderPlans -End $endDefenderPlans).TotalMinutes) minutes ($((New-TimeSpan -Start $startDefenderPlans -End $endDefenderPlans).TotalSeconds) seconds)"
        #endregion SUMMARYSubDefenderPlansSubscriptionsSkipped
    }

    #region SUMMARYSubDefenderPlansByPlan
    Write-Host '  processing TenantSummary Subscriptions Microsoft Defender for Cloud plans by plan'

    $tfCount = $defenderPlansGroupedByPlanCount
    $startDefenderPlans = Get-Date

    if ($defenderPlansGroupedByPlanCount -gt 0) {
        $htmlTableId = 'TenantSummary_DefenderPlans'

        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_DefenderPlans"><i class="padlx fa fa-shield" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">Microsoft Defender for Cloud plans (by plan)</span></button>
<div class="content TenantSummary">
"@)

        if ($defenderPlanDeprecatedContainerRegistry) {
            [void]$htmlTenantSummary.AppendLine(@'
        <span class="padlxx"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> Using deprecated plan 'Container registries'</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/defender-for-cloud/release-notes#microsoft-defender-for-containers-plan-released-for-general-availability-ga" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
'@)
        }
        if ($defenderPlanDeprecatedKubernetesService) {
            [void]$htmlTenantSummary.AppendLine(@'
        <span class="padlxx"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i>  Using deprecated plan 'Kubernetes'</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/defender-for-cloud/release-notes#microsoft-defender-for-containers-plan-released-for-general-availability-ga" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
'@)
        }

        [void]$htmlTenantSummary.AppendLine(@"
<span class="padlxx info"><i class="fa fa-lightbulb-o" aria-hidden="true"></i> Microsoft Defender for Cloud's enhanced security features</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/defender-for-cloud/enhanced-security-features-overview" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Plan/Tier</th>
<th>Subscription Count</th>
</tr>
</thead>
<tbody>
"@)

        foreach ($defenderCapabilityAndTier in $defenderPlansGroupedByPlan | Sort-Object -Property Name) {
            if ($defenderCapabilityAndTier.Name -eq 'ContainerRegistry, Standard' -or $defenderCapabilityAndTier.Name -eq 'KubernetesService, Standard') {
                $thisDefenderPlan = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i> $($defenderCapabilityAndTier.Name)"
            }
            else {
                $thisDefenderPlan = $defenderCapabilityAndTier.Name
            }
            [void]$htmlTenantSummary.AppendLine(@"
                <tr>
                <td>$($thisDefenderPlan)</td>
                <td>$($defenderCapabilityAndTier.Count)</td>
                </tr>
"@)
        }

        [void]$htmlTenantSummary.AppendLine(@"
</tbody>
</table>
<script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
            btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'number'
            ],
            extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
</div>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@'
    <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No Microsoft Defender for Cloud plans at all</p>
'@)
    }
    $endDefenderPlans = Get-Date
    Write-Host "   Microsoft Defender for Cloud plans by plan processing duration: $((New-TimeSpan -Start $startDefenderPlans -End $endDefenderPlans).TotalMinutes) minutes ($((New-TimeSpan -Start $startDefenderPlans -End $endDefenderPlans).TotalSeconds) seconds)"
    #endregion SUMMARYSubDefenderPlansByPlan

    #region SUMMARYSubDefenderPlansBySubscription
    Write-Host '  processing TenantSummary Subscriptions Microsoft Defender for Cloud plans by Subscription'
    $tfCount = $subsDefenderPlansCount
    $startDefenderPlans = Get-Date

    if (($arrayDefenderPlans).Count -gt 0) {
        $htmlTableId = 'TenantSummary_DefenderPlansBySubscription'

        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_DefenderPlansBySubscription"><i class="padlx fa fa-shield" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">Microsoft Defender for Cloud plans (by Subscription)</span></button>
<div class="content TenantSummary">
"@)

        if ($defenderPlanDeprecatedContainerRegistry) {
            [void]$htmlTenantSummary.AppendLine(@'
        <span class="padlxx"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> Using deprecated plan 'Container registries'</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/defender-for-cloud/release-notes#microsoft-defender-for-containers-plan-released-for-general-availability-ga" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
'@)
        }
        if ($defenderPlanDeprecatedKubernetesService) {
            [void]$htmlTenantSummary.AppendLine(@'
        <span class="padlxx"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i>  Using deprecated plan 'Kubernetes'</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/defender-for-cloud/release-notes#microsoft-defender-for-containers-plan-released-for-general-availability-ga" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
'@)
        }

        [void]$htmlTenantSummary.AppendLine(@"
<span class="padlxx info"><i class="fa fa-lightbulb-o" aria-hidden="true"></i> Microsoft Defender for Cloud's enhanced security features</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/defender-for-cloud/enhanced-security-features-overview" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>Subscription MG path</th>
"@)

        foreach ($defenderCapability in $defenderCapabilities) {
            if (($defenderPlanDeprecatedContainerRegistry -and $defenderCapability -eq 'ContainerRegistry') -or ($defenderPlanDeprecatedKubernetesService -and $defenderCapability -eq 'KubernetesService')) {
                $thisDefenderCapability = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i> $($defenderCapability)"
            }
            else {
                $thisDefenderCapability = $defenderCapability
            }
            [void]$htmlTenantSummary.AppendLine(@"
            <th>$($thisDefenderCapability)</th>
"@)

        }

        [void]$htmlTenantSummary.AppendLine(@'
</tr>
</thead>
<tbody>
'@)

        foreach ($sub in $defenderPlansGroupedBySub) {
            $nameSplit = $sub.Name.split(', ')
            [void]$htmlTenantSummary.AppendLine(@"
            <tr>
            <td>$($nameSplit[0])</td>
            <td>$($nameSplit[1])</td>
            <td>$($nameSplit[2])</td>

"@)

            foreach ($plan in $sub.Group | Sort-Object -Property defenderPlan) {
                [void]$htmlTenantSummary.AppendLine(@"
                <td>$($plan.defenderPlanTier)</td>
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@'
            </tr>
'@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
</tbody>
</table>
<script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@'
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            linked_filters: true,
'@)
        $cnt = 2
        foreach ($defenderCapability in $defenderCapabilities) {
            $cnt++
            [void]$htmlTenantSummary.AppendLine(@"
                    col_$($cnt): 'select',
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@'
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
'@)
        $cnt = 0
        foreach ($defenderCapability in $defenderCapabilities) {
            $cnt++
            if ($cnt -ne $defenderCapabilitiesCount) {
                [void]$htmlTenantSummary.AppendLine(@'
                'caseinsensitivestring',
'@)
            }
            else {
                [void]$htmlTenantSummary.AppendLine(@'
                'caseinsensitivestring'
'@)
            }

        }
        [void]$htmlTenantSummary.AppendLine(@"
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
</div>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@'
    <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No Microsoft Defender for Cloud plans at all</p>
'@)
    }
    $endDefenderPlans = Get-Date
    Write-Host "   Microsoft Defender for Cloud plans by Subscription processing duration: $((New-TimeSpan -Start $startDefenderPlans -End $endDefenderPlans).TotalMinutes) minutes ($((New-TimeSpan -Start $startDefenderPlans -End $endDefenderPlans).TotalSeconds) seconds)"
    #endregion SUMMARYSubDefenderPlansBySubscription

    if ($azAPICallConf['htParameters'].NoResources -eq $false) {
        #region SUMMARYSubUserAssignedIdentities4Resources
        Write-Host '  processing TenantSummary Subscriptions UserAssigned Managed Identities assigned to Resources'
        $arrayUserAssignedIdentities4ResourcesCount = $arrayUserAssignedIdentities4Resources.Count
        $tfCount = $arrayUserAssignedIdentities4ResourcesCount
        $startUserAssignedIdentities4Resources = Get-Date

        if ($arrayUserAssignedIdentities4ResourcesCount -gt 0) {

            $script:htUserAssignedIdentitiesAssignedResources = @{}
            $script:htResourcesAssignedUserAssignedIdentities = @{}
            foreach ($entry in $arrayUserAssignedIdentities4Resources) {
                #UserAssignedIdentities
                if (-not $htUserAssignedIdentitiesAssignedResources.($entry.miPrincipalId)) {
                    $script:htUserAssignedIdentitiesAssignedResources.($entry.miPrincipalId) = @{}
                    $script:htUserAssignedIdentitiesAssignedResources.($entry.miPrincipalId).ResourcesCount = 1
                }
                else {
                    $script:htUserAssignedIdentitiesAssignedResources.($entry.miPrincipalId).ResourcesCount++
                }
                #Resources
                if (-not $htResourcesAssignedUserAssignedIdentities.(($entry.resourceId).tolower())) {
                    $script:htResourcesAssignedUserAssignedIdentities.(($entry.resourceId).tolower()) = @{}
                    $script:htResourcesAssignedUserAssignedIdentities.(($entry.resourceId).tolower()).UserAssignedIdentitiesCount = 1
                }
                else {
                    $script:htResourcesAssignedUserAssignedIdentities.(($entry.resourceId).tolower()).UserAssignedIdentitiesCount++
                }
            }

            $htmlTableId = 'TenantSummary_UserAssignedIdentities4Resources'

            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_UserAssignedIdentities4Resources"><i class="padlx fa fa-user-circle-o" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">UserAssigned Managed Identities assigned to Resources / vice versa</span></button>
<div class="content TenantSummary">
<span class="padlxx info"><i class="fa fa-lightbulb-o" aria-hidden="true"></i> Managed identity 'user-assigned' vs 'system-assigned'</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview#managed-identity-types" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>MI Name</th>
<th>MI MgPath</th>
<th>MI Subscription Name</th>
<th>MI Subscription Id</th>
<th>MI ResourceGroup</th>
<th>MI ResourceId</th>
<th>MI AAD SP objectId</th>
<th>MI AAD SP applicationId</th>
<th>MI count Res assignments</th>
<th>MI used cross subscription</th>
<th class="uamiresaltbgc">Res Name</th>
<th class="uamiresaltbgc">Res Type</th>
<th class="uamiresaltbgc">Res MgPath</th>
<th class="uamiresaltbgc">Res Subscription Name</th>
<th class="uamiresaltbgc">Res Subscription Id</th>
<th class="uamiresaltbgc">Res ResourceGroup</th>
<th class="uamiresaltbgc">Res Id</th>
<th class="uamiresaltbgc">Res count assigned MIs</th>
"@)

            [void]$htmlTenantSummary.AppendLine(@'
</tr>
</thead>
<tbody>
'@)

            $userAssignedIdentities4Resources4CSVExport = [System.Collections.ArrayList]@()
            foreach ($miResEntry in $arrayUserAssignedIdentities4Resources | Sort-Object -Property miResourceId, resourceId) {
                [void]$htmlTenantSummary.AppendLine(@"
                    <tr>
                        <td>$($miResEntry.miResourceName)</td>
                        <td class="breakwordall">$($miResEntry.miMgPath)</td>
                        <td>$($miResEntry.miSubscriptionName)</td>
                        <td>$($miResEntry.miSubscriptionId)</td>
                        <td>$($miResEntry.miResourceGroupName)</td>
                        <td class="breakwordall">$($miResEntry.miResourceId)</td>
                        <td>$($miResEntry.miPrincipalId)</td>
                        <td>$($miResEntry.miClientId)</td>
                        <td>$($htUserAssignedIdentitiesAssignedResources.($miResEntry.miPrincipalId).ResourcesCount)</td>
                        <td>$($miResEntry.miCrossSubscription)</td>
                        <td>$($miResEntry.resourceName)</td>
                        <td class="breakwordall">$($miResEntry.resourceType)</td>
                        <td>$($miResEntry.resourceMgPath)</td>
                        <td>$($miResEntry.resourceSubscriptionName)</td>
                        <td>$($miResEntry.resourceSubscriptionId)</td>
                        <td>$($miResEntry.resourceResourceGroupName)</td>
                        <td class="breakwordall">$($miResEntry.resourceId)</td>
                        <td>$($htResourcesAssignedUserAssignedIdentities.(($miResEntry.resourceId).tolower()).UserAssignedIdentitiesCount)</td>
                    </tr>
"@)

                if (-not $NoCsvExport) {
                    $null = $userAssignedIdentities4Resources4CSVExport.Add([PSCustomObject]@{
                            MIName                = $miResEntry.miResourceName
                            MIMgPath              = $miResEntry.miMgPath
                            MISubscriptionName    = $miResEntry.miSubscriptionName
                            MISubscriptionId      = $miResEntry.miSubscriptionId
                            MIResourceGroup       = $miResEntry.miResourceGroupName
                            MIResourceId          = $miResEntry.miResourceId
                            MIAADSPObjectId       = $miResEntry.miPrincipalId
                            MIAADSPApplicationId  = $miResEntry.miClientId
                            MICountResAssignments = $htUserAssignedIdentitiesAssignedResources.($miResEntry.miPrincipalId).ResourcesCount
                            MICrossSubscription   = $miResEntry.miCrossSubscription
                            ResName               = $miResEntry.resourceName
                            ResType               = $miResEntry.resourceType
                            ResMgPath             = $miResEntry.resourceMgPath
                            ResSubscriptionName   = $miResEntry.resourceSubscriptionName
                            ResSubscriptionId     = $miResEntry.resourceSubscriptionId
                            ResResourceGroup      = $miResEntry.resourceResourceGroupName
                            ResId                 = $miResEntry.resourceId
                            ResCountAssignedMIs   = $htResourcesAssignedUserAssignedIdentities.(($miResEntry.resourceId).tolower()).UserAssignedIdentitiesCount
                        })
                }

            }

            if (-not $NoCsvExport) {
                Write-Host "   Exporting UserAssignedIdentities4Resources CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_UserAssignedIdentities4Resources.csv'"
                $userAssignedIdentities4Resources4CSVExport | Sort-Object -Property MIResourceId, ResId | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_UserAssignedIdentities4Resources.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
            }

            [void]$htmlTenantSummary.AppendLine(@"
</tbody>
</table>
<script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            linked_filters: true,
            col_9: 'select',
            col_11: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number'
            ],
            extensions: [{ name: 'colsVisibility', text: 'Columns: ', enable_tick_all: true },{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
</div>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
    <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No UserAssigned Managed Identities assigned to Resources / vice versa - at all</p>
'@)
        }
        $endUserAssignedIdentities4Resources = Get-Date
        Write-Host "   UserAssigned Managed Identities assigned to Resources processing duration: $((New-TimeSpan -Start $startUserAssignedIdentities4Resources -End $endUserAssignedIdentities4Resources).TotalMinutes) minutes ($((New-TimeSpan -Start $startUserAssignedIdentities4Resources -End $endUserAssignedIdentities4Resources).TotalSeconds) seconds)"
        #endregion SUMMARYSubUserAssignedIdentities4Resources

        #region SUMMARYPSRule
        if ($azAPICallConf['htParameters'].DoPSRule -eq $true) {
            $startPSRule = Get-Date
            Write-Host '  processing TenantSummary PSRule'
            $arrayPSRuleCount = $arrayPsRule.Count

            if ($arrayPSRuleCount -gt 0) {

                if (-not $NoCsvExport) {
                    $PSRuleCSVPath = "$($outputPath)$($DirectorySeparatorChar)$($fileName)_PSRule.csv"
                    Write-Host "   Exporting 'PSRule for Azure' CSV '$PSRuleCSVPath'"
                    $arrayPsRule | Sort-Object -Property resourceId, pillar, category, severity, rule, recommendation | Export-Csv -Path $PSRuleCSVPath -Delimiter "$csvDelimiter" -NoTypeInformation

                    if ($azAPICallConf['htParameters'].onGitHubActions -eq $true) {
                        $exportCSVPSRuleFileSize = (Get-Item -Path $PSRuleCSVPath).length / 1MB
                        if ($exportCSVPSRuleFileSize -gt 100) {
                            Write-Host "   The exported 'PSRule for Azure' CSV '$PSRuleCSVPath' exceeds the GitHub file limit of 100MB"
                            Write-Host '   more info: https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github#file-size-limits'
                            Write-Host '   ! ---> Hint: Consider using additional parameter -PSRuleFailedOnly / results will only include failed resources'
                            Write-Host "   Re-Exporting 'PSRule for Azure' CSV '$PSRuleCSVPath' excluding column 'description'"
                            $arrayPsRule | Select-Object -ExcludeProperty description | Sort-Object -Property resourceId, pillar, category, severity, rule, recommendation | Export-Csv -Path "$PSRuleCSVPath" -Delimiter "$csvDelimiter" -NoTypeInformation

                            $exportCSVPSRuleFileSize = (Get-Item -Path $PSRuleCSVPath).length / 1MB
                            if ($exportCSVPSRuleFileSize -gt 100) {
                                Write-Host "   The exported 'PSRule for Azure' CSV '$PSRuleCSVPath' still exceeds the GitHub file limit of 100MB"
                                Write-Host "   Re-Exporting 'PSRule for Azure' CSV '$PSRuleCSVPath' excluding column 'description', 'recommendation'"
                                $arrayPsRule | Select-Object -ExcludeProperty description, recommendation | Sort-Object -Property resourceId, pillar, category, severity, rule | Export-Csv -Path "$PSRuleCSVPath" -Delimiter "$csvDelimiter" -NoTypeInformation
                            }

                            $exportCSVPSRuleFileSize = (Get-Item -Path $PSRuleCSVPath).length / 1MB
                            if ($exportCSVPSRuleFileSize -gt 100) {
                                Write-Host "   The exported 'PSRule for Azure' CSV '$PSRuleCSVPath' still exceeds the GitHub file limit of 100MB"
                                Write-Host "   Deleting 'PSRule for Azure' CSV '$PSRuleCSVPath' in order to prevent the workflow from failing at push to repo"
                                Remove-Item -Path $PSRuleCSVPath
                            }
                        }
                        else {
                            Write-Host "   Info: The exported 'PSRule for Azure' CSV '$PSRuleCSVPath' does not exceed the GitHub file limit of 100MB"
                        }
                    }
                }

                $grpPSRuleAll = $arrayPsRule | Group-Object -Property resourceType, pillar, category, severity, rule, result
                $tfCount = $grpPSRuleAll.Name.Count

                $htmlTableId = 'TenantSummary_PSRule'

                [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_PSRule"><i class="padlx fa fa-check-square-o" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">$tfCount PSRule for Azure results</span></button>
<div class="content TenantSummary">
<span class="padlxx info"><i class="fa fa-lightbulb-o" aria-hidden="true"></i> Learn about </span> <a class="externallink" href="https://azure.github.io/PSRule.Rules.Azure" target="_blank" rel="noopener">PSRule for Azure <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Resource Type</th>
<th>Resource Count</th>
<th>Subscription Count</th>
<th>Pillar</th>
<th>Category</th>
<th>Severity</th>
<th>Rule</th>
<th>Recommendation</th>
<th>lnk</th>
<th>State</th>
</tr>
</thead>
<tbody>
"@)

                foreach ($result in $grpPSRuleAll | Sort-Object -Property Name) {
                    $resultNameSplit = $result.Name.split(', ')
                    [void]$htmlTenantSummary.AppendLine(@"
                        <tr>
                            <td>$($resultNameSplit[0])</td>
                            <td>$($result.Group.Count)</td>
                            <td>$(($result.Group.subscriptionId | Sort-Object -Unique).Count)</td>
                            <td>$($resultNameSplit[1])</td>
                            <td>$($resultNameSplit[2])</td>
                            <td>$($resultNameSplit[3])</td>
                            <td>$(($result.Group[0].rule))</td>
                            <td>$(($result.Group[0].recommendation))</td>
                            <td><a href=`"$(($result.Group[0].link))`" target=`"_blank`"><i class="fa fa-external-link" aria-hidden="true"></i></a></td>
                            <td>$($resultNameSplit[5])</td>
                        </tr>
"@)

                }

                [void]$htmlTenantSummary.AppendLine(@"
</tbody>
</table>
<script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
                if ($tfCount -gt 10) {
                    $spectrum = "10, $tfCount"
                    if ($tfCount -gt 50) {
                        $spectrum = "10, 25, 50, $tfCount"
                    }
                    if ($tfCount -gt 100) {
                        $spectrum = "10, 30, 50, 100, $tfCount"
                    }
                    if ($tfCount -gt 500) {
                        $spectrum = "10, 30, 50, 100, 250, $tfCount"
                    }
                    if ($tfCount -gt 1000) {
                        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                    }
                    if ($tfCount -gt 2000) {
                        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                    }
                    if ($tfCount -gt 3000) {
                        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                    }
                    [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
                }
                [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            linked_filters: true,
            col_3: 'select',
            col_4: 'select',
            col_5: 'select',
            col_9: 'select',
            col_types: [
                'caseinsensitivestring',
                'number',
                'number',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
            extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
</div>
"@)
            }
            else {
                [void]$htmlTenantSummary.AppendLine(@'
    <p><i class="padlx fa fa-shield" aria-hidden="true"></i> <span class="valignMiddle">No PSRule for Azure results</span></p>
'@)
            }
            $endPSRule = Get-Date
            Write-Host "   PSRule for Azure processing duration: $((New-TimeSpan -Start $startPSRule -End $endPSRule).TotalMinutes) minutes ($((New-TimeSpan -Start $startPSRule -End $endPSRule).TotalSeconds) seconds)"
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
            <i class="padlx fa fa-ban" aria-hidden="true"></i> PSRule for Azure - <span class="info">integration paused - <a class="externallink" href="https://azure.github.io/PSRule.Rules.Azure/integrations" target="_blank" rel="noopener">PSRule for Azure <i class="fa fa-external-link" aria-hidden="true"></i></a>
'@)
        }
        #endregion SUMMARYPSRule
    }

    #region SUMMARYStorageAccountAnalysis
    if ($azAPICallConf['htParameters'].NoStorageAccountAccessAnalysis -eq $false) {
        $startStorageAccountAnalysis = Get-Date
        Write-Host '  processing TenantSummary Storage Account Access Analysis'

        $arrayStorageAccountAnalysisResultsCount = $arrayStorageAccountAnalysisResults.Count
        if ($arrayStorageAccountAnalysisResultsCount -gt 0) {

            if (-not $NoCsvExport) {
                $storageAccountAccessAnalysisCSVPath = "$($outputPath)$($DirectorySeparatorChar)$($fileName)_StorageAccountAccessAnalysis.csv"
                Write-Host "   Exporting 'Storage Account Access Analysis' CSV '$storageAccountAccessAnalysisCSVPath'"
                $arrayStorageAccountAnalysisResults | Sort-Object -Property StorageAccount | Export-Csv -Path $storageAccountAccessAnalysisCSVPath -Delimiter "$csvDelimiter" -NoTypeInformation
            }

            $saAnonymousAccessCount = ($arrayStorageAccountAnalysisResults.where({ $_.containersAnonymousContainerCount -gt 0 -or $_.containersAnonymousBlobCount -gt 0 })).Count
            $saStaticWebsitesEnabledCount = ($arrayStorageAccountAnalysisResults.where({ $_.staticWebsitesState -eq $true })).Count

            $htmlTableId = 'TenantSummary_StorageAccountAccessAnalysis'
            $tfCount = $arrayStorageAccountAnalysisResultsCount

            if ($DoAzureConsumption -eq $true) {
                $costDays = " ($($AzureConsumptionPeriod)d)"
            }
            else {
                $costDays = " (<i>-DoAzureConsumption</i> = <span style=`"color:orange`">$DoAzureConsumption</span>)"
            }

            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_StorageAccountAccessAnalysis"><i class="padlx fa fa-user-secret" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">$tfCount Storage Accounts Access Analysis results - Anonymous Access Container/Blob: $saAnonymousAccessCount, Static Website enabled: $saStaticWebsitesEnabledCount</span></button>
<div class="content TenantSummary">
<span class="padlxx info"><i class="fa fa-lightbulb-o" aria-hidden="true"></i> Check this article by Elli Shlomo (MVP) </span> <a class="externallink" href="https://misconfig.io/azure-blob-container-threats-attacks/" target="_blank" rel="noopener">Azure Blob Container Threats & Attacks <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<span class="padlxx info"><i class="fa fa-lightbulb-o" aria-hidden="true"></i> If you enabled the parameters <i>StorageAccountAccessAnalysisSubscriptionTags or StorageAccountAccessAnalysisStorageAccountTags</i> these are integrated in the CSV output *_StorageAccountAccessAnalysis.csv</span><br>
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>StorageAccount</th>
<th>Kind</th>
<th>SkuName</th>
<th>SkuTier</th>
<th>Location</th>
<th>Subscription</th>
<th>Subscription MGPath</th>
<th>ResourceGroup</th>
<th>Allow Blob Public Access</th>
<th>Public Network Access</th>
<th>NetworkAcls defaultAction</th>
<th>StaticWebsites State</th>
<th>StaticWebsites Response</th>
<th>Containers CanBeListed</th>
<th>Containers Count</th>
<th>Containers Anonymous Container Count</th>
<th>Containers Anonymous Blob Count</th>
<th>IpRules Count</th>
<th>IpRules IPAddress List</th>
<th>VirtualNetwork Rules Count</th>
<th>ResourceAccess Rules Count</th>
<th>ResourceAccess Rules</th>
<th>Bypass</th>
<th>Supports Https Traffic Only</th>
<th>Minimum Tls Version</th>
<th>Allow SharedKey Access</th>
<th>Require Infrastructure Encryption</th>
<th>Allowed Copy Scope</th>
<th>Allow Cross Tenant Replication</th>
<th>DNS Endpoint Type</th>
<th>Used Capacity (GB)</th>
<th>Cost$costDays</th>
<th>Currency</th>
<th>Cost categories</th>
</tr>
</thead>
<tbody>
"@)

            foreach ($result in $arrayStorageAccountAnalysisResults | Sort-Object -Property storageAccount) {

                [void]$htmlTenantSummary.AppendLine(@"
                        <tr>
                        <td>$($result.storageAccount)</td>
                        <td>$($result.kind)</td>
                        <td>$($result.skuName)</td>
                        <td>$($result.skuTier)</td>
                        <td>$($result.location)</td>
                        <td>$($result.SubscriptionName)</td>
                        <td>$($result.subscriptionMGPath)</td>
                        <td>$($result.resourceGroup)</td>
                        <td>$($result.allowBlobPublicAccess)</td>
                        <td>$($result.publicNetworkAccess)</td>
                        <td>$($result.networkAclsdefaultAction)</td>
                        <td>$($result.staticWebsitesState)</td>
                        <td>$($result.staticWebsitesResponse)</td>
                        <td>$($result.containersCanBeListed)</td>
                        <td>$($result.containersCount)</td>
                        <td>$($result.containersAnonymousContainerCount)</td>
                        <td>$($result.containersAnonymousBlobCount)</td>
                        <td>$($result.ipRulesCount)</td>
                        <td>$($result.ipRulesIPAddressList)</td>
                        <td>$($result.virtualNetworkRulesCount)</td>
                        <td>$($result.resourceAccessRulesCount)</td>
                        <td>$($result.resourceAccessRules)</td>
                        <td>$($result.bypass)</td>
                        <td>$($result.supportsHttpsTrafficOnly)</td>
                        <td>$($result.minimumTlsVersion)</td>
                        <td>$($result.allowSharedKeyAccess)</td>
                        <td>$($result.requireInfrastructureEncryption)</td>
                        <td>$($result.allowedCopyScope)</td>
                        <td>$($result.allowCrossTenantReplication)</td>
                        <td>$($result.dnsEndpointType)</td>
                        <td>$($result.usedCapacity)</td>
                        <td>$($result.cost)</td>
                        <td>$($result.curreny)</td>
                        <td>$($result.metercategory)</td>
                        </tr>
"@)

            }

            [void]$htmlTenantSummary.AppendLine(@"
</tbody>
</table>
<script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            linked_filters: true,
            col_1: 'select',
            col_2: 'select',
            col_3: 'select',
            col_4: 'select',
            col_8: 'select',
            col_9: 'select',
            col_10: 'select',
            col_11: 'select',
            col_12: 'select',
            col_13: 'select',
            col_22: 'select',
            col_23: 'select',
            col_24: 'select',
            col_25: 'select',
            col_26: 'select',
            col_27: 'select',
            col_28: 'select',
            col_29: 'select',
            col_32: 'select',
            col_33: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number',
                'number',
                'number',
                'number',
                'caseinsensitivestring',
                'number',
                'number',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number',
                'number',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
            extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
</div>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No Storage Accounts found</p>
'@)
        }
        $endStorageAccountAnalysis = Get-Date
        Write-Host "   Storage Account Analysis processing duration: $((New-TimeSpan -Start $startStorageAccountAnalysis -End $endStorageAccountAnalysis).TotalMinutes) minutes ($((New-TimeSpan -Start $startStorageAccountAnalysis -End $endStorageAccountAnalysis).TotalSeconds) seconds)"
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> Storage Account Access Analysis disabled - <span class="info">parameter -NoStorageAccountAccessAnalysis = $($azAPICallConf['htParameters'].NoStorageAccountAccessAnalysis)</span></p>
"@)
    }
    #endregion SUMMARYStorageAccountAnalysis

    [void]$htmlTenantSummary.AppendLine(@'
    </div>
'@)
    #endregion tenantSummarySubscriptionsResourceDefenderPSRule

    #region tenantSummaryNetwork
    [void]$htmlTenantSummary.AppendLine(@'
    <button type="button" class="collapsible" id="tenantSummaryNetwork"><hr class="hr-textNetwork" data-content="Network" /></button>
    <div class="content TenantSummaryContent">
'@)

    #region SUMMARYVNets
    if ($azAPICallConf['htParameters'].NoNetwork -eq $false) {
        $startVNets = Get-Date
        Write-Host '  processing TenantSummary VNets'
        $Vnets = $arrayVirtualNetworks | Sort-Object -Property SubscriptionName, VNet, VNetId -Unique | Select-Object SubscriptionName, Subscription, MGPath, VNet, VNetResourceGroup, Location, AddressSpaceAddressPrefixes, DhcpoptionsDnsservers, SubnetsCount, SubnetsWithNSGCount, SubnetsWithRouteTableCount, SubnetsWithDelegationsCount, PrivateEndpointsCount, SubnetsWithPrivateEndPointsCount, ConnectedDevices, SubnetsWithConnectedDevicesCount, DdosProtection, PeeringsCount
        $VNetsCount = $Vnets.Count

        if (-not $NoCsvExport) {
            $virtualNetworksCSVPath = "$($outputPath)$($DirectorySeparatorChar)$($fileName)_VirtualNetworks.csv"
            Write-Host "   Exporting VirtaulNetworks CSV '$virtualNetworksCSVPath'"
            $Vnets | Export-Csv -Path $virtualNetworksCSVPath -Delimiter "$csvDelimiter" -NoTypeInformation
        }

        if ($VNetsCount -gt 0) {

            $htmlTableId = 'TenantSummary_VNets'
            $tfCount = $VNetsCount
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_VNets"><i class="padlx fa fa-arrows" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">$tfCount Virtual Networks</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription Name</th>
<th>Subscription</th>
<th>MGPath</th>
<th>VNet</th>
<th>VNet Resource Group</th>
<th>Location</th>
<th>Address Prefixes</th>
<th>DNS Servers</th>
<th>Subnets</th>
<th>Subnets with NSG</th>
<th>Subnets with RouteTable</th>
<th>Subnets with Delegation</th>
<th>Private Endpoints</th>
<th>Subnets with Private Endpoints</th>
<th>Connected device</th>
<th>Subnets with connected device</th>
<th>DDoS</th>
<th>Peerings Count</th>
</tr>
</thead>
<tbody>
"@)

            foreach ($result in $Vnets) {

                [void]$htmlTenantSummary.AppendLine(@"
                        <tr>
                        <td>$($result.SubscriptionName)</td>
                        <td>$($result.Subscription)</td>
                        <td>$($result.MGPath)</td>
                        <td>$($result.VNet)</td>
                        <td>$($result.VNetResourceGroup)</td>
                        <td>$($result.Location)</td>
                        <td>$($result.AddressSpaceAddressPrefixes)</td>
                        <td>$($result.DhcpoptionsDnsservers)</td>
                        <td>$($result.SubnetsCount)</td>
                        <td>$($result.SubnetsWithNSGCount)</td>
                        <td>$($result.SubnetsWithRouteTableCount)</td>
                        <td>$($result.SubnetsWithDelegationsCount)</td>
                        <td>$($result.PrivateEndpointsCount)</td>
                        <td>$($result.SubnetsWithPrivateEndPointsCount)</td>
                        <td>$($result.ConnectedDevices)</td>
                        <td>$($result.SubnetsWithConnectedDevicesCount)</td>
                        <td>$($result.DdosProtection)</td>
                        <td>$($result.PeeringsCount)</td>
                        </tr>
"@)

            }

            [void]$htmlTenantSummary.AppendLine(@"
</tbody>
</table>
<script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            linked_filters: true,
            col_5: 'select',
            col_16: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number',
                'number',
                'number',
                'number',
                'number',
                'number',
                'number',
                'number',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
            extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
</div>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No Virtual Networks</p>
'@)
        }
        $endVNets = Get-Date
        Write-Host "   VNets processing duration: $((New-TimeSpan -Start $startVNets -End $endVNets).TotalMinutes) minutes ($((New-TimeSpan -Start $startVNets -End $endVNets).TotalSeconds) seconds)"
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> Virtual Networks - Network Analysis disabled - <span class="info">parameter -NoNetwork = $($azAPICallConf['htParameters'].NoNetwork)</span></p>
"@)
    }
    #endregion SUMMARYVNets

    #region SUMMARYSubnets
    if ($azAPICallConf['htParameters'].NoNetwork -eq $false) {
        $startSubnets = Get-Date
        Write-Host '  processing TenantSummary Subnets'
        $subnets = $arraySubnets | Sort-Object -Property SubscriptionName, VNet, VNetId, SubnetName
        $subnetsCount = $subnets.Count

        if (-not $NoCsvExport) {
            $subnetsCSVPath = "$($outputPath)$($DirectorySeparatorChar)$($fileName)_VirtualNetworkSubnets.csv"
            Write-Host "   Exporting Subnets CSV '$subnetsCSVPath'"
            $subnets | Export-Csv -Path $subnetsCSVPath -Delimiter "$csvDelimiter" -NoTypeInformation
        }

        if ($subnetsCount -gt 0) {

            $subnetIPAddressUsageCriticalCount = ($subnets.where({ $_.SubnetIPAddressUsageCritical -eq $true })).Count
            $criticalUsageText = ''
            if ($subnetIPAddressUsageCriticalCount -gt 0) {
                $criticalUsageText = " ($subnetIPAddressUsageCriticalCount > $($NetworkSubnetIPAddressUsageCriticalPercentage)% IP addresses used)"
            }

            $htmlTableId = 'TenantSummary_Subnets'
            $tfCount = $subnetsCount
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_Subnets"><i class="padlx fa fa-arrows-h" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">$tfCount Subnets$($criticalUsageText)</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription Name</th>
<th>Subscription</th>
<th>MGPath</th>
<th>VNet</th>
<th>VNet Resource Group</th>
<th>Location</th>
<th>Name</th>
<th>Id</th>
<th>Subnet</th>
<th>Prefix</th>
<th>Mask</th>
<th>Range</th>
<th>Connected devices</th>
<th>Free IP addresses</th>
<th>Used IP addresses %</th>
<th>Private Endpoint Network Policies</th>
<th>Private Link Service Network Policies</th>
<th>Service Endpoints count</th>
<th>Service Endpoints</th>
<th>Delegation</th>
<th>NSG</th>
<th>Route Table</th>
<th>Nat Gateway</th>
<th>Private Endpoints</th>
</tr>
</thead>
<tbody>
"@)

            foreach ($result in $subnets) {

                [void]$htmlTenantSummary.AppendLine(@"
                        <tr>
                        <td>$($result.SubscriptionName)</td>
                        <td>$($result.Subscription)</td>
                        <td style="min-width: 150px" class="breakwordall">$($result.MGPath)</td>
                        <td>$($result.VNet)</td>
                        <td>$($result.VNetResourceGroup)</td>
                        <td>$($result.Location)</td>
                        <td>$($result.SubnetName)</td>
                        <td style="min-width: 200px" class="breakwordall">$($result.SubnetId)</td>
                        <td>$($result.SubnetNet)</td>
                        <td>$($result.SubnetPrefix)</td>
                        <td>$($result.Subnetmask)</td>
                        <td>$($result.Range)</td>
                        <td>$($result.ConnectedDevices)</td>
                        <td>$($result.AvailableIPAddresses)</td>
                        <td>$($result.UsedIPAddressesPercent)</td>
                        <td>$($result.PrivateEndpointNetworkPolicies)</td>
                        <td>$($result.PrivateLinkServiceNetworkPolicies)</td>
                        <td>$($result.ServiceEndpointsCount)</td>
                        <td>$($result.ServiceEndpoints)</td>
                        <td>$($result.Delegation)</td>
                        <td style="min-width: 200px" class="breakwordall">$($result.NetworkSecurityGroup)</td>
                        <td style="min-width: 200px" class="breakwordall">$($result.RouteTable)</td>
                        <td>$($result.NatGateway)</td>
                        <td>$($result.PrivateEndpoints)</td>
                        </tr>
"@)

            }

            [void]$htmlTenantSummary.AppendLine(@"
</tbody>
</table>
<script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            linked_filters: true,
            col_5: 'select',
            col_9: 'select',
            col_10: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number',
                'number',
                'number',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
            extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
</div>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No Subnets</p>
'@)
        }
        $endSubnets = Get-Date
        Write-Host "   Subnets processing duration: $((New-TimeSpan -Start $startSubnets -End $endSubnets).TotalMinutes) minutes ($((New-TimeSpan -Start $startSubnets -End $endSubnets).TotalSeconds) seconds)"
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> Subnets - Network Analysis disabled - <span class="info">parameter -NoNetwork = $($azAPICallConf['htParameters'].NoNetwork)</span></p>
"@)
    }
    #endregion SUMMARYSubnets

    #region SUMMARYVNetPeerings
    if ($azAPICallConf['htParameters'].NoNetwork -eq $false) {
        $startVNetPeerings = Get-Date
        Write-Host '  processing TenantSummary VNet Peerings'
        $vnetPeerings = $arrayVirtualNetworks.where({ $_.PeeringsCount -gt 0 }) | Sort-Object -Property SubscriptionName, VNet, VNetId
        $VNetsPeeringsCount = $vnetPeerings.Count

        if (-not $NoCsvExport) {
            $virtualNetworkPeeringsCSVPath = "$($outputPath)$($DirectorySeparatorChar)$($fileName)_VirtualNetworkPeerings.csv"
            Write-Host "   Exporting VirtaulNetworks CSV '$virtualNetworkPeeringsCSVPath'"
            $vnetPeerings | Export-Csv -Path $virtualNetworkPeeringsCSVPath -Delimiter "$csvDelimiter" -NoTypeInformation
        }

        if ($VNetsPeeringsCount -gt 0) {
            $vnetPeeringsGroupedByPeeringState = $vnetPeerings | Group-Object -Property PeeringState
            $arrayPeeringState = foreach ($peeringState in $vnetPeeringsGroupedByPeeringState) {
                "$($peeringState.Name): $($peeringState.Count)"
            }

            $xTenantPeeringsCount = $vnetPeerings.where({ $_.PeeringXTenant -eq 'true' }).Count

            $htmlTableId = 'TenantSummary_VNetPeerings'
            $tfCount = $VNetsPeeringsCount
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_TenantSummary_VNetPeerings"><i class="padlx fa fa-exchange" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">$VNetsPeeringsCount Virtual Network Peerings - ($($arrayPeeringState -join "$CSVDelimiterOpposite ")) (Cross Tenant: $($xTenantPeeringsCount))</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription Name</th>
<th>Subscription</th>
<th>MGPath</th>
<th>VNet</th>
<th>VNet Resource Group</th>
<th>Location</th>
<th>Address Prefixes</th>
<th>DNS Servers</th>
<th>Subnets</th>
<th>Subnets with NSG</th>
<th>Subnets with RouteTable</th>
<th>Subnets with Delegation</th>
<th>Private Endpoints</th>
<th>Subnets with Private Endpoints</th>
<th>Connected device</th>
<th>Subnets with connected device</th>
<th>DDoS</th>
<th class="uamiresaltbgc">Peerings Count</th>
<th class="uamiresaltbgc">Peering Cross Tenant</th>
<th class="uamiresaltbgc">Peering Name</th>
<th class="uamiresaltbgc">Peering State</th>
<th class="uamiresaltbgc">Peering Sync Level</th>
<th class="uamiresaltbgc">Allow Virtual Network Access</th>
<th class="uamiresaltbgc">Allow Forwarded Traffic</th>
<th class="uamiresaltbgc">Allow Gateway Transit</th>
<th class="uamiresaltbgc">Use Remote Gateways</th>
<th class="uamiresaltbgc">Do Not Verify Remote Gateways</th>
<th class="uamiresaltbgc">Peer Complete Vnets</th>
<th class="uamiresaltbgc">Route Service Vips</th>

<th class="uamiresaltbgc"><b>Remote</b> Peerings Count</th>
<th class="uamiresaltbgc"><b>Remote</b> Peering Name</th>
<th class="uamiresaltbgc"><b>Remote</b> Peering State</th>
<th class="uamiresaltbgc"><b>Remote</b> Peering Sync Level</th>
<th class="uamiresaltbgc"><b>Remote</b> Allow Virtual Network Access</th>
<th class="uamiresaltbgc"><b>Remote</b> Allow Forwarded Traffic</th>
<th class="uamiresaltbgc"><b>Remote</b> Allow Gateway Transit</th>
<th class="uamiresaltbgc"><b>Remote</b> Use Remote Gateways</th>
<th class="uamiresaltbgc"><b>Remote</b> Do Not Verify Remote Gateways</th>
<th class="uamiresaltbgc"><b>Remote</b> Peer Complete Vnets</th>
<th class="uamiresaltbgc"><b>Remote</b> Route Service Vips</th>

<th class="uamiresaltbgc"><b>Remote</b> Subscription Name</th>
<th class="uamiresaltbgc"><b>Remote</b> Subscription</th>
<th class="uamiresaltbgc"><b>Remote</b> MGPath</th>
<th class="uamiresaltbgc"><b>Remote</b> VNet</th>
<th class="uamiresaltbgc"><b>Remote</b> VNet State</th>
<th class="uamiresaltbgc"><b>Remote</b> VNet Resource Group</th>
<th class="uamiresaltbgc"><b>Remote</b> Location</th>
<th class="uamiresaltbgc"><b>Remote</b> Address Space Address Prefixes</th>
<th class="uamiresaltbgc"><b>Remote</b> Virtual Network AddressSpace Address Prefixes</th>

<th class="uamiresaltbgc"><b>Remote</b> DNS Servers</th>
<th class="uamiresaltbgc"><b>Remote</b> Subnets</th>
<th class="uamiresaltbgc"><b>Remote</b> Subnets with NSG</th>
<th class="uamiresaltbgc"><b>Remote</b> Subnets with RouteTable</th>
<th class="uamiresaltbgc"><b>Remote</b> Subnets with Delegation</th>
<th class="uamiresaltbgc"><b>Remote</b> Private Endpoints</th>
<th class="uamiresaltbgc"><b>Remote</b> Subnets with Private Endpoints</th>
<th class="uamiresaltbgc"><b>Remote</b> Connected devices</th>
<th class="uamiresaltbgc"><b>Remote</b> Subnets with connected devices</th>
<th class="uamiresaltbgc"><b>Remote</b> DDoS</th>

</tr>
</thead>
<tbody>
"@)

            foreach ($result in $vnetPeerings) {

                [void]$htmlTenantSummary.AppendLine(@"
                        <tr>
                        <td>$($result.SubscriptionName)</td>
                        <td>$($result.Subscription)</td>
                        <td>$($result.MGPath)</td>
                        <td>$($result.VNet)</td>
                        <td>$($result.VNetResourceGroup)</td>
                        <td>$($result.Location)</td>
                        <td>$($result.AddressSpaceAddressPrefixes)</td>
                        <td>$($result.DhcpoptionsDnsservers)</td>
                        <td>$($result.SubnetsCount)</td>
                        <td>$($result.SubnetsWithNSGCount)</td>
                        <td>$($result.SubnetsWithRouteTableCount)</td>
                        <td>$($result.SubnetsWithDelegationsCount)</td>
                        <td>$($result.PrivateEndpointsCount)</td>
                        <td>$($result.SubnetsWithPrivateEndPointsCount)</td>
                        <td>$($result.ConnectedDevices)</td>
                        <td>$($result.SubnetsWithConnectedDevicesCount)</td>
                        <td>$($result.DdosProtection)</td>
                        <td>$($result.PeeringsCount)</td>
                        <td>$($result.PeeringXTenant)</td>
                        <td>$($result.PeeringName)</td>
                        <td>$($result.PeeringState)</td>
                        <td>$($result.PeeringSyncLevel)</td>
                        <td>$($result.AllowVirtualNetworkAccess)</td>
                        <td>$($result.AllowForwardedTraffic)</td>
                        <td>$($result.AllowGatewayTransit)</td>
                        <td>$($result.UseRemoteGateways)</td>
                        <td>$($result.DoNotVerifyRemoteGateways)</td>
                        <td>$($result.PeerCompleteVnets)</td>
                        <td>$($result.RouteServiceVips)</td>

                        <td>$($result.RemotePeeringsCount)</td>
                        <td>$($result.RemotePeeringName)</td>
                        <td>$($result.RemotePeeringState)</td>
                        <td>$($result.RemotePeeringSyncLevel)</td>
                        <td>$($result.RemoteAllowVirtualNetworkAccess)</td>
                        <td>$($result.RemoteAllowForwardedTraffic)</td>
                        <td>$($result.RemoteAllowGatewayTransit)</td>
                        <td>$($result.RemoteUseRemoteGateways)</td>
                        <td>$($result.RemoteDoNotVerifyRemoteGateways)</td>
                        <td>$($result.RemotePeerCompleteVnets)</td>
                        <td>$($result.RemoteRouteServiceVips)</td>

                        <td>$($result.RemoteSubscriptionName)</td>
                        <td>$($result.RemoteSubscription)</td>
                        <td>$($result.RemoteMGPath)</td>
                        <td>$($result.RemoteVNet)</td>
                        <td>$($result.RemoteVNetState)</td>
                        <td>$($result.RemoteVNetResourceGroup)</td>
                        <td>$($result.RemoteVNetLocation)</td>
                        <td>$($result.RemoteAddressSpaceAddressPrefixes)</td>
                        <td>$($result.RemoteVirtualNetworkAddressSpaceAddressPrefixes)</td>
                        <td>$($result.RemoteDhcpoptionsDnsservers)</td>
                        <td>$($result.RemoteSubnetsCount)</td>
                        <td>$($result.RemoteSubnetsWithNSGCount)</td>
                        <td>$($result.RemoteSubnetsWithRouteTable)</td>
                        <td>$($result.RemoteSubnetsWithDelegations)</td>
                        <td>$($result.RemotePrivateEndPoints)</td>
                        <td>$($result.RemoteSubnetsWithPrivateEndPoints)</td>
                        <td>$($result.RemoteConnectedDevices)</td>
                        <td>$($result.RemoteSubnetsWithConnectedDevices)</td>
                        <td>$($result.RemoteDdosProtection)</td>
                        </tr>
"@)

            }

            [void]$htmlTenantSummary.AppendLine(@"
</tbody>
</table>
<script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            linked_filters: true,
            col_5: 'select',
            col_16: 'select',
            col_18: 'select',

            col_20: 'select',
            col_21: 'select',
            col_22: 'select',
            col_23: 'select',
            col_24: 'select',
            col_25: 'select',
            col_26: 'select',
            col_27: 'select',
            col_28: 'select',


            col_31: 'select',
            col_32: 'select',
            col_33: 'select',
            col_34: 'select',
            col_35: 'select',
            col_36: 'select',
            col_37: 'select',
            col_38: 'select',
            col_39: 'select',

            col_43: 'select',
            col_45: 'select',
            col_58: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number',
                'number',
                'number',
                'number',
                'number',
                'number',
                'number',
                'number',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number',
                'number',
                'number',
                'number',
                'number',
                'number',
                'number',
                'number',
                'caseinsensitivestring'
            ],
            extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
</div>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No Virtual Network Peerings</p>
'@)
        }
        $endVNetPeerings = Get-Date
        Write-Host "   VNet Peerings processing duration: $((New-TimeSpan -Start $startVNetPeerings -End $endVNetPeerings).TotalMinutes) minutes ($((New-TimeSpan -Start $startVNetPeerings -End $endVNetPeerings).TotalSeconds) seconds)"
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> Virtual Network Peerings - Network Analysis disabled - <span class="info">parameter -NoNetwork = $($azAPICallConf['htParameters'].NoNetwork)</span></p>
"@)
    }
    #endregion SUMMARYVNetPeerings

    #region SUMMARYPrivateEndpoints
    if ($azAPICallConf['htParameters'].NoNetwork -eq $false) {
        $startPrivateEndpoints = Get-Date
        Write-Host '  processing TenantSummary PrivateEndpoints'
        $privateEndPoints = $arrayPrivateEndpointsEnriched | Sort-Object -Property PESubscriptionName, PEName
        $privateEndPointsCount = $privateEndPoints.Count

        if (-not $NoCsvExport) {
            $peCSVPath = "$($outputPath)$($DirectorySeparatorChar)$($fileName)_PrivateEndpoints.csv"
            Write-Host "   Exporting PrivateEndpoints CSV '$peCSVPath'"
            $privateEndPoints | Export-Csv -Path $peCSVPath -Delimiter "$csvDelimiter" -NoTypeInformation
        }

        if ($privateEndPointsCount -gt 0) {

            $crossSubPECount = ($privateEndPoints.where({ $_.crossSubscriptionPE -eq $true })).Count
            $crossSubPEText = ''
            if ($crossSubPECount -gt 0) {
                $crossSubPEText = " ($crossSubPECount cross Subscription)"
            }
            $crossTenantPECount = ($privateEndPoints.where({ $_.crossTenantPE -eq $true })).Count
            $crossTenantPEText = ''
            if ($crossTenantPECount -gt 0) {
                $crossTenantPEText = " ($crossTenantPECount cross Tenant)"
            }

            $htmlTableId = 'TenantSummary_PrivateEndpoints'
            $tfCount = $privateEndPointsCount
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_PrivateEndpoints"><i class="padlx fa fa-map-pin" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">$tfCount Private Endpoints$($crossSubPEText)$($crossTenantPEText)</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>

<th>PE Name</th>
<th>PE Id</th>
<th>PE Location</th>
<th>PE Resource Group</th>
<th>PE Subscription Name</th>
<th>PE Subscription</th>
<th>PE MGPath</th>
<th>PE Type</th>
<th>PE State</th>
<th>Cross Subscription PE</th>
<th>Cross Tenant PE</th>

<th class="uamiresaltbgc">Resource</th>
<th class="uamiresaltbgc">Resource Type</th>
<th class="uamiresaltbgc">Resource Id</th>
<th class="uamiresaltbgc">Target Subresource</th>
<th class="uamiresaltbgc">NIC Name</th>
<th class="uamiresaltbgc">FQDN</th>
<th class="uamiresaltbgc">IP addresses</th>
<th class="uamiresaltbgc">Resource Resource Group</th>
<th class="uamiresaltbgc">Resource Subscription Name</th>
<th class="uamiresaltbgc">Resource Subscription Id</th>
<th class="uamiresaltbgc">Resource MGPath</th>
<th class="uamiresaltbgc">Resource Cross Tenant</th>

<th>Subnet</th>
<th>Subnet Id</th>
<th>VNet</th>
<th>VNet Id</th>
<th>VNet Location</th>
<th>VNet Resource Group</th>
<th>Subnet Subscription Name</th>
<th>Subnet Subscription Id</th>
<th>Subnet MGPath</th>
</tr>
</thead>
<tbody>
"@)

            foreach ($result in $privateEndPoints) {

                [void]$htmlTenantSummary.AppendLine(@"
                        <tr>
                        <td>$($result.PEName)</td>
                        <td style="min-width: 200px" class="breakwordall">$($result.PEId)</td>
                        <td>$($result.PELocation)</td>
                        <td>$($result.PEResourceGroup)</td>
                        <td>$($result.PESubscriptionName)</td>
                        <td>$($result.PESubscription)</td>
                        <td style="min-width: 150px" class="breakwordall">$($result.PEMGPath)</td>
                        <td>$($result.PEConnectionType)</td>
                        <td>$($result.PEConnectionState)</td>
                        <td>$($result.CrossSubscriptionPE)</td>
                        <td>$($result.CrossTenantPE)</td>

                        <td>$($result.Resource)</td>
                        <td>$($result.ResourceType)</td>
                        <td style="min-width: 200px" class="breakwordall">$($result.ResourceId)</td>
                        <td>$($result.TargetSubresource)</td>
                        <td>$($result.NICName)</td>
                        <td>$($result.FQDN)</td>
                        <td>$($result.ipAddresses)</td>
                        <td>$($result.ResourceResourceGroup)</td>
                        <td>$($result.ResourceSubscriptionName)</td>
                        <td>$($result.ResourceSubscriptionId)</td>
                        <td style="min-width: 150px" class="breakwordall">$($result.ResourceMGPath)</td>
                        <td>$($result.ResourceCrossTenant)</td>

                        <td>$($result.Subnet)</td>
                        <td style="min-width: 200px" class="breakwordall">$($result.SubnetId)</td>
                        <td>$($result.SubnetVNet)</td>
                        <td style="min-width: 200px" class="breakwordall">$($result.SubnetVNetId)</td>
                        <td>$($result.SubnetVNetLocation)</td>
                        <td>$($result.SubnetVNetResourceGroup)</td>
                        <td>$($result.SubnetSubscriptionName)</td>
                        <td>$($result.SubnetSubscription)</td>
                        <td style="min-width: 150px" class="breakwordall">$($result.SubnetMGPath)</td>
                        </tr>
"@)

            }

            [void]$htmlTenantSummary.AppendLine(@"
</tbody>
</table>
<script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            linked_filters: true,
            col_2: 'select',
            col_7: 'select',
            col_8: 'select',
            col_9: 'select',
            col_10: 'select',
            col_12: 'select',
            col_14: 'select',
            col_22: 'select',
            col_27: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
            extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
</div>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No Private Endpoints</p>
'@)
        }
        $endPrivateEndpoints = Get-Date
        Write-Host "   PrivateEndpoints processing duration: $((New-TimeSpan -Start $startPrivateEndpoints -End $endPrivateEndpoints).TotalMinutes) minutes ($((New-TimeSpan -Start $startPrivateEndpoints -End $endPrivateEndpoints).TotalSeconds) seconds)"
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> Private Endpoints - Network Analysis disabled - <span class="info">parameter -NoNetwork = $($azAPICallConf['htParameters'].NoNetwork)</span></p>
"@)
    }
    #endregion SUMMARYPrivateEndpoints

    [void]$htmlTenantSummary.AppendLine(@'
    </div>
'@)
    #endregion tenantSummaryNetwork

    showMemoryUsage

    #region tenantSummaryDiagnostics
    [void]$htmlTenantSummary.AppendLine(@'
    <button type="button" class="collapsible" id="tenantSummaryDiagnostics"><hr class="hr-textDiagnostics" data-content="Diagnostics" /></button>
    <div class="content TenantSummaryContent">
'@)

    [void]$htmlTenantSummary.AppendLine( @'
<p><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> <span class="valignMiddle"><b>Management Groups</b></span></p>
'@)

    #region SUMMARYDiagnosticsManagementGroups
    Write-Host '  processing TenantSummary Diagnostics Management Groups'

    #hasDiag
    if ($diagnosticSettingsMgCount -gt 0) {
        $tfCount = $diagnosticSettingsMgCount
        $htmlTableId = 'TenantSummary_DiagnosticsManagementGroups'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_DiagnosticsManagementGroups"><i class="padlxx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$diagnosticSettingsMgManagementGroupsCount ($mgsDiagnosticsApplicableCount) Management Groups configured for Diagnostic settings ($diagnosticSettingsMgCount settings)</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Management Group Diagnostic Settings - Create Or Update - REST API</span> <a class="externallink" href="https://docs.microsoft.com/en-us/rest/api/monitor/managementgroupdiagnosticsettings/createorupdate" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Management Group Name</th>
<th>Management Group Id</th>
<th>Diagnostic setting</th>
<th>Inheritance</th>
<th>Inherited from</th>
<th>Target</th>
<th>TargetId</th>
"@)

        foreach ($logCategory in $diagnosticSettingsMgCategories) {
            [void]$htmlTenantSummary.AppendLine(@"
<th>$logCategory</th>
"@)
        }

        [void]$htmlTenantSummary.AppendLine(@'
</tr>
</thead>
<tbody>
'@)
        $htmlSUMMARYDiagnosticsManagementGroups = $null
        $htmlSUMMARYDiagnosticsManagementGroups = foreach ($entry in $diagnosticSettingsMg | Sort-Object -Property ScopeMgPath, DiagnosticsInheritedFrom, DiagnosticSettingName, DiagnosticTargetType, DiagnosticTargetId) {

            @"
<tr>
<td>$($entry.ScopeName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($entry.ScopeId)</td>
<td>$($entry.DiagnosticSettingName)</td>
<td>$($entry.DiagnosticsInheritedOrnot)</td>
<td>$($entry.DiagnosticsInheritedFrom)</td>
<td>$($entry.DiagnosticTargetType)</td>
<td>$($entry.DiagnosticTargetId)</td>
"@
            foreach ($logCategory in $diagnosticSettingsMgCategories) {
                if ($entry.DiagnosticCategoriesHt.($logCategory)) {
                    @"
                    <td>$($entry.DiagnosticCategoriesHt.($logCategory))</td>
"@
                }
                else {
                    @'
                    <td>n/a</td>
'@
                }
            }
            @'
</tr>
'@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYDiagnosticsManagementGroups)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@'
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            linked_filters: true,
            col_3: 'select',
            col_5: 'select',
'@)
        $cnt = 6
        foreach ($logCategory in $diagnosticSettingsMgCategories) {
            $cnt++
            [void]$htmlTenantSummary.AppendLine(@"
                col_$($cnt): 'select',
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@'
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
'@)
        $cnt = 0
        foreach ($logCategory in $diagnosticSettingsMgCategories) {
            $cnt++
            if ($diagnosticSettingsMgCategories.Count -eq $cnt) {
                [void]$htmlTenantSummary.AppendLine(@'
                    'caseinsensitivestring'
'@)
            }
            else {
                [void]$htmlTenantSummary.AppendLine(@'
                    'caseinsensitivestring',
'@)
            }
        }
        [void]$htmlTenantSummary.AppendLine(@"
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>
"@)
    }
    else {

        [void]$htmlTenantSummary.AppendLine(@'
            <p><i class="padlxx fa fa-ban" aria-hidden="true"></i> No Management Groups configured for Diagnostic settings <a class="externallink" href="https://docs.microsoft.com/en-us/rest/api/monitor/managementgroupdiagnosticsettings/createorupdate" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
'@)
    }

    #hasNoDiag
    if ($arrayMgsWithoutDiagnosticsCount -gt 0) {
        $tfCount = $arrayMgsWithoutDiagnosticsCount
        $htmlTableId = 'TenantSummary_NoDiagnosticsManagementGroups'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_NoDiagnosticsManagementGroups"><i class="padlxx fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$arrayMgsWithoutDiagnosticsCount Management Groups NOT configured for Diagnostic settings</span> <a class="externallink" href="https://docs.microsoft.com/en-us/rest/api/monitor/managementgroupdiagnosticsettings/createorupdate" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Management Group Diagnostic Settings - Create Or Update - REST API</span> <a class="externallink" href="https://docs.microsoft.com/en-us/rest/api/monitor/managementgroupdiagnosticsettings/createorupdate" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Management Group Name</th>
<th>Management Group Id</th>
<th>Management Group path</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYNoDiagnosticsManagementGroups = $null
        $htmlSUMMARYNoDiagnosticsManagementGroups = foreach ($entry in $arrayMgsWithoutDiagnostics | Sort-Object -Property ScopeMgPath) {

            @"
<tr>
<td>$($entry.ScopeName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($entry.ScopeId)</td>
<td>$($entry.ScopeMgPath)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYNoDiagnosticsManagementGroups)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>
"@)
    }
    else {

        [void]$htmlTenantSummary.AppendLine(@'
            <p><i class="padlxx fa fa-ban" aria-hidden="true"></i> All Management Groups are configured for Diagnostic settings <a class="externallink" href="https://docs.microsoft.com/en-us/rest/api/monitor/managementgroupdiagnosticsettings/createorupdate" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
'@)
    }
    #endregion SUMMARYDiagnosticsManagementGroups

    #region subscriptions
    [void]$htmlTenantSummary.AppendLine( @'
<p><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle"><b>Subscriptions</b></span></p>
'@)

    #region SUMMARYDiagnosticsSubscriptions
    Write-Host '  processing TenantSummary Diagnostics Subscriptions'

    #hasDiag
    if ($diagnosticSettingsSubCount -gt 0) {
        $tfCount = $diagnosticSettingsSubCount
        $htmlTableId = 'TenantSummary_DiagnosticsSubscriptions'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_DiagnosticsSubscriptions"><i class="padlxx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$diagnosticSettingsSubSubscriptionsCount Subscriptions configured for Diagnostic settings ($diagnosticSettingsSubCount settings)</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Create diagnostic setting</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/quick-collect-activity-log-portal#create-diagnostic-setting" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>Path</th>
<th>Diagnostic setting</th>
<th>Target</th>
<th>TargetId</th>
"@)

        foreach ($logCategory in $diagnosticSettingsSubCategories) {
            [void]$htmlTenantSummary.AppendLine(@"
<th>$logCategory</th>
"@)
        }

        [void]$htmlTenantSummary.AppendLine(@'
</tr>
</thead>
<tbody>
'@)
        $htmlSUMMARYDiagnosticsSubscriptions = $null
        $htmlSUMMARYDiagnosticsSubscriptions = foreach ($entry in $diagnosticSettingsSub | Sort-Object -Property ScopeName, DiagnosticTargetType, DiagnosticSettingName) {

            @"
<tr>
<td>$($entry.ScopeName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($entry.ScopeId)</td>
<td><a href="#hierarchySub_$($entry.SubMgParent)"><i class="fa fa-eye" aria-hidden="true"></i></a> $($entry.ScopeMgPath)</td>
<td>$($entry.DiagnosticSettingName)</td>
<td>$($entry.DiagnosticTargetType)</td>
<td>$($entry.DiagnosticTargetId)</td>
"@
            foreach ($logCategory in $diagnosticSettingsSubCategories) {
                if ($entry.DiagnosticCategoriesHt.($logCategory)) {
                    @"
                    <td>$($entry.DiagnosticCategoriesHt.($logCategory))</td>
"@
                }
                else {
                    @'
                    <td>n/a</td>
'@
                }
            }
            @'
</tr>
'@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYDiagnosticsSubscriptions)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@'
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            linked_filters: true,
            col_4: 'select',
'@)
        $cnt = 5
        foreach ($logCategory in $diagnosticSettingsSubCategories) {
            $cnt++
            [void]$htmlTenantSummary.AppendLine(@"
                col_$($cnt): 'select',
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@'
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
'@)
        $cnt = 0
        foreach ($logCategory in $diagnosticSettingsSubCategories) {
            $cnt++
            if ($diagnosticSettingsSubCategories.Count -eq $cnt) {
                [void]$htmlTenantSummary.AppendLine(@'
                    'caseinsensitivestring'
'@)
            }
            else {
                [void]$htmlTenantSummary.AppendLine(@'
                    'caseinsensitivestring',
'@)
            }
        }
        [void]$htmlTenantSummary.AppendLine(@"
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>
"@)
    }
    else {

        [void]$htmlTenantSummary.AppendLine(@'
            <p><i class="padlxx fa fa-ban" aria-hidden="true"></i> No Subscriptions configured for Diagnostic settings <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/quick-collect-activity-log-portal#create-diagnostic-setting" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
'@)
    }

    #hasNoDiag
    if ($diagnosticSettingsSubNoDiagCount -gt 0) {
        $tfCount = $diagnosticSettingsSubNoDiagCount
        $htmlTableId = 'TenantSummary_NoDiagnosticsSubscriptions'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_NoDiagnosticsSubscriptions"><i class="padlxx fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$diagnosticSettingsSubNoDiagCount Subscriptions NOT configured for Diagnostic settings</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Create diagnostic setting</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/quick-collect-activity-log-portal#create-diagnostic-setting" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>Subscription Id</th>
<th>Subscription Mg path</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYNoDiagnosticsSubscriptions = $null
        $htmlSUMMARYNoDiagnosticsSubscriptions = foreach ($entry in $diagnosticSettingsSubNoDiag | Sort-Object -Property ScopeMgPath) {

            @"
<tr>
<td>$($entry.ScopeName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($entry.ScopeId)</td>
<td>$($entry.ScopeMgPath)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYNoDiagnosticsSubscriptions)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>
"@)
    }
    else {

        [void]$htmlTenantSummary.AppendLine(@'
            <p><i class="padlxx fa fa-ban" aria-hidden="true"></i> All Subscriptions are configured for Diagnostic settings <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/quick-collect-activity-log-portal#create-diagnostic-setting" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
'@)
    }
    #endregion SUMMARYDiagnosticsSubscriptions

    #endregion subscriptions

    if ($azAPICallConf['htParameters'].NoResources -eq $false) {
        #region resources
        [void]$htmlTenantSummary.AppendLine( @'
<p><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/10001-icon-service-All-Resources.svg"> <span class="valignMiddle"><b>Resources</b></span></p>
'@)

        #region SUMMARYResourcesDiagnosticsCapable
        Write-Host '  processing TenantSummary Diagnostics Resources Diagnostics Capable (1st party only)'
        $resourceTypesDiagnosticsArraySorted = $resourceTypesDiagnosticsArray | Sort-Object -Property ResourceType, ResourceCount, Metrics, Logs, LogCategories
        $resourceTypesDiagnosticsArraySortedCount = ($resourceTypesDiagnosticsArraySorted | Measure-Object).count
        $resourceTypesDiagnosticsMetricsTrueCount = ($resourceTypesDiagnosticsArray.where( { $_.Metrics -eq $True }) | Measure-Object).count
        $resourceTypesDiagnosticsLogsTrueCount = ($resourceTypesDiagnosticsArray.where( { $_.Logs -eq $True }) | Measure-Object).count
        $resourceTypesDiagnosticsMetricsLogsTrueCount = ($resourceTypesDiagnosticsArray.where( { $_.Metrics -eq $True -or $_.Logs -eq $True }) | Measure-Object).count
        if ($resourceTypesDiagnosticsArraySortedCount -gt 0) {
            $tfCount = $resourceTypesDiagnosticsArraySortedCount
            $htmlTableId = 'TenantSummary_ResourcesDiagnosticsCapable'
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_ResourcesDiagnosticsCapable"><i class="padlxx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resources (1st party) Diagnostics capable $resourceTypesDiagnosticsMetricsLogsTrueCount/$resourceTypesDiagnosticsArraySortedCount ResourceTypes ($resourceTypesDiagnosticsMetricsTrueCount Metrics, $resourceTypesDiagnosticsLogsTrueCount Logs)</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Create Custom Policies for Azure ResourceTypes that support Diagnostics Logs and Metrics</span> <a class="externallink" href="https://github.com/JimGBritt/AzurePolicy/blob/master/AzureMonitor/Scripts/README.md#overview-of-create-azdiagpolicyps1" target="_blank" rel="noopener">Create-AzDiagPolicy <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Supported categories for Azure Resource Logs</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-monitor/platform/resource-logs-categories" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>ResourceType</th>
<th>Resource Count</th>
<th>Diagnostics capable</th>
<th>Metrics</th>
<th>Logs</th>
<th>LogCategories</th>
</tr>
</thead>
<tbody>
"@)
            $htmlSUMMARYResourcesDiagnosticsCapable = $null
            $htmlSUMMARYResourcesDiagnosticsCapable = foreach ($resourceType in $resourceTypesDiagnosticsArraySorted) {
                if ($resourceType.Metrics -eq $true -or $resourceType.Logs -eq $true) {
                    $diagnosticsCapable = $true
                }
                else {
                    if ($resourceType.Metrics -eq 'n/a - resourcesMeanwhileDeleted' -or $resourceType.Logs -eq 'n/a - resourcesMeanwhileDeleted') {
                        $diagnosticsCapable = 'n/a'
                    }
                    else {
                        $diagnosticsCapable = $false
                    }
                }
                @"
<tr>
<td>$($resourceType.ResourceType)</td>
<td>$($resourceType.ResourceCount)</td>
<td>$diagnosticsCapable</td>
<td>$($resourceType.Metrics)</td>
<td>$($resourceType.Logs)</td>
<td>$($resourceType.LogCategories -join "$CsvDelimiterOpposite ")</td>
</tr>
"@
            }
            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYResourcesDiagnosticsCapable)
            [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        linked_filters: true,
        col_2: 'select',
        col_3: 'select',
        col_4: 'select',
        col_types: [
            'caseinsensitivestring',
            'number',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>
"@)
        }
        else {

            [void]$htmlTenantSummary.AppendLine(@'
                <p><i class="padlxx fa fa-ban" aria-hidden="true"></i> No Resources (1st party) Diagnostics capable</p>
'@)
        }
        #endregion SUMMARYResourcesDiagnosticsCapable

        #region SUMMARYDiagnosticsPolicyLifecycle
        if (-not $NoResourceDiagnosticsPolicyLifecycle) {
            Write-Host '  processing TenantSummary Diagnostics Resource Diagnostics Policy Lifecycle'
            $startsumDiagLifecycle = Get-Date

            if ($tenantCustomPoliciesCount -gt 0) {
                $policiesThatDefineDiagnostics = $tenantCustomPolicies.where( { $_.Type -eq 'custom' -and $_.Json.properties.policyrule.then.details.type -eq 'Microsoft.Insights/diagnosticSettings' -and $_.Json.properties.policyrule.then.details.deployment.properties.template.resources.type -match '/providers/diagnosticSettings' } )

                $policiesThatDefineDiagnosticsCount = ($policiesThatDefineDiagnostics).count
                if ($policiesThatDefineDiagnosticsCount -gt 0) {

                    $diagnosticsPolicyAnalysis = @()
                    $diagnosticsPolicyAnalysis = [System.Collections.ArrayList]@()
                    foreach ($policy in $policiesThatDefineDiagnostics) {

                        if (
                            (($policy).Json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match '/providers/diagnosticSettings' }).properties.workspaceId -or
                            (($policy).Json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match '/providers/diagnosticSettings' }).properties.eventHubAuthorizationRuleId -or
                            (($policy).Json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match '/providers/diagnosticSettings' }).properties.storageAccountId
                        ) {
                            if ( (($policy).Json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match '/providers/diagnosticSettings' }).properties.workspaceId) {
                                $diagnosticsDestination = 'LA'
                            }
                            if ( (($policy).Json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match '/providers/diagnosticSettings' }).properties.eventHubAuthorizationRuleId) {
                                $diagnosticsDestination = 'EH'
                            }
                            if ( (($policy).Json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match '/providers/diagnosticSettings' }).properties.storageAccountId) {
                                $diagnosticsDestination = 'SA'
                            }

                            if ( (($policy).Json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match '/providers/diagnosticSettings' }).properties.logs ) {

                                $resourceType = ( (($policy).Json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match '/providers/diagnosticSettings' }).type -replace '/providers/diagnosticSettings')

                                $resourceTypeCountFromResourceTypesSummarizedArray = ($resourceTypesSummarizedArray.where( { $_.ResourceType -eq $resourceType })).ResourceCount
                                if ($resourceTypeCountFromResourceTypesSummarizedArray) {
                                    $resourceCount = $resourceTypeCountFromResourceTypesSummarizedArray
                                }
                                else {
                                    $resourceCount = '0'
                                }
                                $supportedLogs = $resourceTypesDiagnosticsArray | Where-Object { $_.ResourceType -eq ( (($policy).Json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match '/providers/diagnosticSettings' }).type -replace '/providers/diagnosticSettings') }

                                $diagnosticsLogCategoriesSupported = $supportedLogs.LogCategories
                                if (($supportedLogs | Measure-Object).count -gt 0) {
                                    $logsSupported = 'yes'
                                }
                                else {
                                    $logsSupported = 'no'
                                }

                                $roleDefinitionIdsArray = [System.Collections.ArrayList]@()
                                foreach ($roleDefinitionId in ($policy).Json.properties.policyrule.then.details.roleDefinitionIds) {
                                    if (($htCacheDefinitionsRole).($roleDefinitionId -replace '.*/')) {
                                        $null = $roleDefinitionIdsArray.Add("<b>$(($htCacheDefinitionsRole).($roleDefinitionId -replace '.*/').Name)</b> ($($roleDefinitionId -replace '.*/'))")
                                    }
                                    else {
                                        Write-Host "  DiagnosticsLifeCycle: unknown RoleDefinition '$roleDefinitionId'"
                                        $null = $roleDefinitionIdsArray.Add("unknown RoleDefinition: '$roleDefinitionId'")
                                    }
                                }

                                $policyHasPolicyAssignments = $policyBaseQuery | Where-Object { $_.PolicyDefinitionId -eq $policy.Id } | Sort-Object -Property PolicyDefinitionId, PolicyAssignmentId -Unique
                                $policyHasPolicyAssignmentCount = ($policyHasPolicyAssignments | Measure-Object).count
                                if ($policyHasPolicyAssignmentCount -gt 0) {
                                    $policyAssignmentsArray = @()
                                    $policyAssignmentsArray += foreach ($policyAssignment in $policyHasPolicyAssignments) {
                                        "$($policyAssignment.PolicyAssignmentId) (<b>$($policyAssignment.PolicyAssignmentDisplayName)</b>)"
                                    }
                                    $policyAssignmentsCollCount = ($policyAssignmentsArray).count
                                    $policyAssignmentsColl = $policyAssignmentsCollCount
                                }
                                else {
                                    $policyAssignmentsColl = 0
                                }

                                #PolicyUsedinPolicySet
                                $policySetAssignmentsColl = 0
                                $policySetAssignmentsArray = @()
                                $policyUsedinPolicySets = 'n/a'

                                $usedInPolicySetArray = [System.Collections.ArrayList]@()
                                foreach ($customPolicySet in $tenantCustomPolicySets) {
                                    if ($customPolicySet.Type -eq 'Custom') {
                                        $hlpCustomPolicySet = ($customPolicySet)
                                        if (($hlpCustomPolicySet.PolicySetPolicyIds) -contains ($policy.Id)) {
                                            $null = $usedInPolicySetArray.Add("$($hlpCustomPolicySet.Id) (<b>$($hlpCustomPolicySet.DisplayName)</b>)")

                                            #PolicySetHasAssignments
                                            $policySetAssignments = ($htCacheAssignmentsPolicy).Values.where( { $_.Assignment.properties.policyDefinitionId -eq ($hlpCustomPolicySet.Id) } )
                                            $policySetAssignmentsCount = ($policySetAssignments).count
                                            if ($policySetAssignmentsCount -gt 0) {
                                                $policySetAssignmentsArray += foreach ($policySetAssignment in $policySetAssignments) {
                                                    "$(($policySetAssignment.Assignment.id).Tolower()) (<b>$($policySetAssignment.Assignment.properties.displayName)</b>)"
                                                }
                                                $policySetAssignmentsCollCount = ($policySetAssignmentsArray).Count
                                                $policySetAssignmentsColl = "$policySetAssignmentsCollCount [$($policySetAssignmentsArray -join "$CsvDelimiterOpposite ")]"
                                            }

                                        }
                                    }
                                }

                                if (($usedInPolicySetArray | Measure-Object).count -gt 0) {
                                    $policyUsedinPolicySets = "$(($usedInPolicySetArray | Measure-Object).count) [$($usedInPolicySetArray -join "$CsvDelimiterOpposite ")]"
                                }
                                else {
                                    $policyUsedinPolicySets = "$(($usedInPolicySetArray | Measure-Object).count)"
                                }

                                if ($recommendation -eq 'review the policy and add the missing categories as required') {
                                    if ($policyAssignmentsColl -gt 0 -or $policySetAssignmentsColl -gt 0) {
                                        $priority = '1-High'
                                    }
                                    else {
                                        $priority = '3-MediumLow'
                                    }
                                }
                                else {
                                    $priority = '4-Low'
                                }

                                $diagnosticsLogCategoriesCoveredByPolicy = (($policy).Json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match '/providers/diagnosticSettings' }).properties.logs
                                if (($diagnosticsLogCategoriesCoveredByPolicy.category | Measure-Object).count -gt 0) {

                                    if (($supportedLogs | Measure-Object).count -gt 0) {
                                        $actionItems = @()
                                        $actionItems += foreach ($supportedLogCategory in $supportedLogs.LogCategories) {
                                            if ($diagnosticsLogCategoriesCoveredByPolicy.category -notcontains ($supportedLogCategory)) {
                                                $supportedLogCategory
                                            }
                                        }
                                        if (($actionItems | Measure-Object).count -gt 0) {
                                            $diagnosticsLogCategoriesNotCoveredByPolicy = $actionItems
                                            $recommendation = 'review the policy and add the missing categories as required'
                                        }
                                        else {
                                            $diagnosticsLogCategoriesNotCoveredByPolicy = 'all OK'
                                            $recommendation = 'no recommendation'
                                        }
                                    }
                                    else {
                                        $status = 'Azure Governance Visualizer did not detect the resourceType'
                                        $diagnosticsLogCategoriesSupported = 'n/a'
                                        $diagnosticsLogCategoriesNotCoveredByPolicy = 'n/a'
                                        $recommendation = 'no recommendation as this resourceType seems not existing'
                                        $logsSupported = 'unknown'
                                    }

                                    $null = $diagnosticsPolicyAnalysis.Add([PSCustomObject]@{
                                            Priority                    = $priority
                                            PolicyId                    = ($policy).Id
                                            PolicyCategory              = ($policy).Category
                                            PolicyName                  = ($policy).DisplayName
                                            PolicyDeploysRoles          = $roleDefinitionIdsArray -join "$CsvDelimiterOpposite "
                                            PolicyForResourceTypeExists = $true
                                            ResourceType                = $resourceType
                                            ResourceTypeCount           = $resourceCount
                                            Status                      = $status
                                            LogsSupported               = $logsSupported
                                            LogCategoriesInPolicy       = ($diagnosticsLogCategoriesCoveredByPolicy.category | Sort-Object) -join "$CsvDelimiterOpposite "
                                            LogCategoriesSupported      = ($diagnosticsLogCategoriesSupported | Sort-Object) -join "$CsvDelimiterOpposite "
                                            LogCategoriesDelta          = ($diagnosticsLogCategoriesNotCoveredByPolicy | Sort-Object) -join "$CsvDelimiterOpposite "
                                            Recommendation              = $recommendation
                                            DiagnosticsTargetType       = $diagnosticsDestination
                                            PolicyAssignments           = $policyAssignmentsColl
                                            PolicyUsedInPolicySet       = $policyUsedinPolicySets
                                            PolicySetAssignments        = $policySetAssignmentsColl
                                        })

                                }
                                else {
                                    $status = 'no categories defined'
                                    $priority = '5-Low'
                                    $recommendation = 'Review the policy - the definition has key for categories, but there are none categories defined'
                                    $null = $diagnosticsPolicyAnalysis.Add([PSCustomObject]@{
                                            Priority                    = $priority
                                            PolicyId                    = ($policy).Id
                                            PolicyCategory              = ($policy).Category
                                            PolicyName                  = ($policy).DisplayName
                                            PolicyDeploysRoles          = $roleDefinitionIdsArray -join "$CsvDelimiterOpposite "
                                            PolicyForResourceTypeExists = $true
                                            ResourceType                = $resourceType
                                            ResourceTypeCount           = $resourceCount
                                            Status                      = $status
                                            LogsSupported               = $logsSupported
                                            LogCategoriesInPolicy       = 'none'
                                            LogCategoriesSupported      = ($diagnosticsLogCategoriesSupported | Sort-Object) -join "$CsvDelimiterOpposite "
                                            LogCategoriesDelta          = ($diagnosticsLogCategoriesSupported | Sort-Object) -join "$CsvDelimiterOpposite "
                                            Recommendation              = $recommendation
                                            DiagnosticsTargetType       = $diagnosticsDestination
                                            PolicyAssignments           = $policyAssignmentsColl
                                            PolicyUsedInPolicySet       = $policyUsedinPolicySets
                                            PolicySetAssignments        = $policySetAssignmentsColl
                                        })
                                }
                            }
                            else {
                                if (-not (($policy).Json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match '/providers/diagnosticSettings' }).properties.metrics ) {
                                    Write-Host "  DiagnosticsLifeCycle check?!: $($policy.DisplayName) ($($policy.Id)) - something unexpected, no Logs and no Metrics defined"
                                }
                            }
                        }
                        else {
                            Write-Host "   DiagnosticsLifeCycle check?!: $($policy.DisplayName) ($($policy.Id)) - something unexpected - not EH, LA, SA"
                        }
                    }
                    #where no Policy exists
                    $diagnosticsPolicyAnalysisCount = ($diagnosticsPolicyAnalysis).count
                    if ($diagnosticsPolicyAnalysisCount -gt 0) {
                        foreach ($resourceTypeDiagnosticsCapable in $resourceTypesDiagnosticsArray | Where-Object { $_.Logs -eq $true }) {
                            if (($diagnosticsPolicyAnalysis.ResourceType).ToLower() -notcontains ( ($resourceTypeDiagnosticsCapable.ResourceType).ToLower() )) {
                                $supportedLogs = ($resourceTypesDiagnosticsArray | Where-Object { $_.ResourceType -eq $resourceTypeDiagnosticsCapable.ResourceType }).LogCategories
                                $logsSupported = 'yes'
                                $resourceTypeCountFromResourceTypesSummarizedArray = ($resourceTypesSummarizedArray | Where-Object { $_.ResourceType -eq $resourceTypeDiagnosticsCapable.ResourceType }).ResourceCount
                                if ($resourceTypeCountFromResourceTypesSummarizedArray) {
                                    $resourceCount = $resourceTypeCountFromResourceTypesSummarizedArray
                                }
                                else {
                                    $resourceCount = '0'
                                }
                                $recommendation = "Create diagnostics policy for this ResourceType. To verify GA check <a class=`"externallink`" href=`"https://docs.microsoft.com/en-us/azure/azure-monitor/platform/resource-logs-categories`" target=`"_blank`" rel=`"noopener`">docs <i class=`"fa fa-external-link`" aria-hidden=`"true`"></i></a>"
                                $null = $diagnosticsPolicyAnalysis.Add([PSCustomObject]@{
                                        Priority                    = '2-Medium'
                                        PolicyId                    = 'n/a'
                                        PolicyCategory              = 'n/a'
                                        PolicyName                  = 'n/a'
                                        PolicyDeploysRoles          = 'n/a'
                                        ResourceType                = $resourceTypeDiagnosticsCapable.ResourceType
                                        ResourceTypeCount           = $resourceCount
                                        Status                      = 'n/a'
                                        LogsSupported               = $logsSupported
                                        LogCategoriesInPolicy       = 'n/a'
                                        LogCategoriesSupported      = $supportedLogs -join "$CsvDelimiterOpposite "
                                        LogCategoriesDelta          = 'n/a'
                                        Recommendation              = $recommendation
                                        DiagnosticsTargetType       = 'n/a'
                                        PolicyForResourceTypeExists = $false
                                        PolicyAssignments           = 'n/a'
                                        PolicyUsedInPolicySet       = 'n/a'
                                        PolicySetAssignments        = 'n/a'
                                    })
                            }
                        }
                    }

                    $diagnosticsPolicyAnalysisCount = ($diagnosticsPolicyAnalysis).count

                    if ($diagnosticsPolicyAnalysisCount -gt 0) {
                        $tfCount = $diagnosticsPolicyAnalysisCount

                        $htmlTableId = 'TenantSummary_DiagnosticsLifecycle'
                        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_DiagnosticsLifecycle"><i class="padlxx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">ResourceDiagnostics for Logs - Policy Lifecycle recommendations</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Create Custom Policies for Azure ResourceTypes that support Diagnostics Logs and Metrics</span> <a class="externallink" href="https://github.com/JimGBritt/AzurePolicy/blob/master/AzureMonitor/Scripts/README.md#overview-of-create-azdiagpolicyps1" target="_blank" rel="noopener">Create-AzDiagPolicy <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Supported categories for Azure Resource Logs</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-monitor/platform/resource-logs-categories" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Priority</th>
<th>Recommendation</th>
<th>ResourceType</th>
<th>Resource Count</th>
<th>Diagnostics capable (logs)</th>
<th>Policy Id</th>
<th>Policy DisplayName</th>
<th>Role definitions</th>
<th>Target</th>
<th>Log Categories not covered by Policy</th>
<th>Policy assignments</th>
<th>Policy used in PolicySet</th>
<th>PolicySet assignments</th>
</tr>
</thead>
<tbody>
"@)

                        foreach ($diagnosticsFinding in $diagnosticsPolicyAnalysis | Sort-Object -Property @{Expression = { $_.Priority } }, @{Expression = { $_.Recommendation } }, @{Expression = { $_.ResourceType } }, @{Expression = { $_.PolicyName } }, @{Expression = { $_.PolicyId } }) {
                            [void]$htmlTenantSummary.AppendLine(@"
            <tr>
                <td>
                    $($diagnosticsFinding.Priority)
                </td>
                <td>
                    $($diagnosticsFinding.Recommendation)
                </td>
                <td>
                    <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-monitor/platform/resource-logs-categories#$(($diagnosticsFinding.ResourceType -replace '\.','' -replace '/','').ToLower())" target="_blank" rel="noopener">$($diagnosticsFinding.ResourceType)</a>
                </td>
                <td>
                    $($diagnosticsFinding.ResourceTypeCount)
                </td>
                <td>
                    $($diagnosticsFinding.LogsSupported)
                </td>
                <td class="breakwordall">
                    $($diagnosticsFinding.PolicyId)
                </td>
                <td class="breakwordall">
                    $($diagnosticsFinding.PolicyName)
                </td>
                <td class="breakwordall">
                    $($diagnosticsFinding.PolicyDeploysRoles)
                </td>
                <td>
                    $($diagnosticsFinding.DiagnosticsTargetType)
                </td>
                <td>
                    $($diagnosticsFinding.LogCategoriesDelta)
                </td>
                <td>
                    $($diagnosticsFinding.PolicyAssignments)
                </td>
                <td class="breakwordall">
                    $($diagnosticsFinding.PolicyUsedInPolicySet)
                </td>
                <td class="breakwordall">
                    $($diagnosticsFinding.PolicySetAssignments)
                </td>
            </tr>
"@)
                        }
                        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
                        if ($tfCount -gt 10) {
                            $spectrum = "10, $tfCount"
                            if ($tfCount -gt 50) {
                                $spectrum = "10, 25, 50, $tfCount"
                            }
                            if ($tfCount -gt 100) {
                                $spectrum = "10, 30, 50, 100, $tfCount"
                            }
                            if ($tfCount -gt 500) {
                                $spectrum = "10, 30, 50, 100, 250, $tfCount"
                            }
                            if ($tfCount -gt 1000) {
                                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                            }
                            if ($tfCount -gt 2000) {
                                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                            }
                            if ($tfCount -gt 3000) {
                                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                            }

                            [void]$htmlTenantSummary.AppendLine(@"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            /*state: { types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
                        }
                        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_0: 'select',
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'number',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'number',
            'number',
            'number'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>
"@)
                    }
                    else {
                        [void]$htmlTenantSummary.AppendLine(@'
                            <p><i class="padlxx fa fa-ban" aria-hidden="true"></i> No ResourceDiagnostics Policy Lifecycle recommendations</p>
'@)
                    }
                }
                else {
                    [void]$htmlTenantSummary.AppendLine(@'
                        <p><i class="padlxx fa fa-ban" aria-hidden="true"></i> No ResourceDiagnostics Policy Lifecycle recommendations</p>
'@)
                }
            }
            else {
                [void]$htmlTenantSummary.AppendLine(@'
                    <p><i class="padlxx fa fa-ban" aria-hidden="true"></i> No ResourceDiagnostics Policy Lifecycle recommendations</p>
'@)
            }
            $endsumDiagLifecycle = Get-Date
            Write-Host "   Resource Diagnostics Policy Lifecycle processing duration: $((New-TimeSpan -Start $startsumDiagLifecycle -End $endsumDiagLifecycle).TotalSeconds) seconds"
        }
        #endregion SUMMARYDiagnosticsPolicyLifecycle

        #endregion resources
    }

    [void]$htmlTenantSummary.AppendLine(@'
    </div>
'@)

    #endregion tenantSummaryDiagnostics

    showMemoryUsage

    #region tenantSummaryLimits
    [void]$htmlTenantSummary.AppendLine(@"
<button type="button" class="collapsible" id="tenantSummaryLimits"><hr class="hr-textLimits" data-content="Limits | $($LimitCriticalPercentage)%" /></button>
<div class="content TenantSummaryContent">
"@)

    #region tenantSummaryLimitsTenant
    [void]$htmlTenantSummary.AppendLine( @'
<p><i class="padlx fa fa-home" aria-hidden="true"></i> Tenant</p>
'@)

    #policySets
    if ($tenantCustompolicySetsCount -gt (($LimitPOLICYPolicySetDefinitionsScopedTenant * $LimitCriticalPercentage) / 100)) {
        [void]$htmlTenantSummary.AppendLine(@"
    <p><i class="padlxx fa fa-exclamation-triangle" aria-hidden="true"></i> PolicySet definitions: $tenantCustompolicySetsCount/$LimitPOLICYPolicySetDefinitionsScopedTenant <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-policy-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
    <p><i class="padlxx fa fa-check green" aria-hidden="true"></i> PolicySet definitions: $tenantCustompolicySetsCount/$LimitPOLICYPolicySetDefinitionsScopedTenant <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-policy-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@)
    }

    #CustomRoleDefinitions
    if ($tenantCustomRolesCount -gt (($LimitRBACCustomRoleDefinitionsTenant * $LimitCriticalPercentage) / 100)) {
        [void]$htmlTenantSummary.AppendLine(@"
    <p><i class="padlxx fa fa-check green" aria-hidden="true"></i> Custom Role definitions: $tenantCustomRolesCount/$LimitRBACCustomRoleDefinitionsTenant <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-rbac-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
    <p><i class="padlxx fa fa-check green" aria-hidden="true"></i> Custom Role definitions: $tenantCustomRolesCount/$LimitRBACCustomRoleDefinitionsTenant <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-rbac-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@)
    }

    #endregion tenantSummaryLimitsTenant

    #region tenantSummaryLimitsManagementGroups
    [void]$htmlTenantSummary.AppendLine( @'
<p><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> Management Groups</p>
'@)

    #region SUMMARYMgsapproachingLimitsPolicyAssignments
    Write-Host '  processing TenantSummary ManagementGroups Limit PolicyAssignments'
    $mgsApproachingLimitPolicyAssignments = (($policyBaseQueryManagementGroups.where( { [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.PolicyAndPolicySetAssignmentAtScopeCount -gt 0 -and (($_.PolicyAndPolicySetAssignmentAtScopeCount -gt ($LimitPOLICYPolicyAssignmentsManagementGroup * ($LimitCriticalPercentage / 100)))) })) | Select-Object MgId, MgName, PolicyAssignmentAtScopeCount, PolicySetAssignmentAtScopeCount, PolicyAndPolicySetAssignmentAtScopeCount, PolicyAssignmentLimit -Unique)
    if (($mgsApproachingLimitPolicyAssignments | Measure-Object).count -gt 0) {
        $tfCount = ($mgsApproachingLimitPolicyAssignments | Measure-Object).count
        $htmlTableId = 'TenantSummary_MgsapproachingLimitsPolicyAssignments'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_MgsapproachingLimitsPolicyAssignments"><i class="padlxx fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicyAssignments | Measure-Object).count) Management Groups approaching Limit ($LimitPOLICYPolicyAssignmentsManagementGroup) for PolicyAssignment</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Azure Policy Limits</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-policy-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Management Group Name</th>
<th>Management Group Id</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYMgsapproachingLimitsPolicyAssignments = $null
        $htmlSUMMARYMgsapproachingLimitsPolicyAssignments = foreach ($mgApproachingLimitPolicyAssignments in $mgsApproachingLimitPolicyAssignments) {
            @"
<tr>
<td><span class="valignMiddle">$($mgApproachingLimitPolicyAssignments.MgName -replace '<', '&lt;' -replace '>', '&gt;')</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($mgApproachingLimitPolicyAssignments.MgId)">$($mgApproachingLimitPolicyAssignments.MgId)</a></span></td>
<td>$(($mgApproachingLimitPolicyAssignments.PolicyAndPolicySetAssignmentAtScopeCount/$LimitPOLICYPolicyAssignmentsManagementGroup).tostring('P')) ($($mgApproachingLimitPolicyAssignments.PolicyAndPolicySetAssignmentAtScopeCount)/$($LimitPOLICYPolicyAssignmentsManagementGroup)) ($($mgApproachingLimitPolicyAssignments.PolicyAssignmentAtScopeCount) Policy assignments, $($mgApproachingLimitPolicyAssignments.PolicySetAssignmentAtScopeCount) PolicySet assignments)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYMgsapproachingLimitsPolicyAssignments)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
    <p><i class="padlxx fa fa-check green" aria-hidden="true"></i> $(($mgsApproachingLimitPolicyAssignments | Measure-Object).count) Management Groups approaching Limit ($LimitPOLICYPolicyAssignmentsManagementGroup) for PolicyAssignment <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-policy-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@)
    }
    #endregion SUMMARYMgsapproachingLimitsPolicyAssignments

    #region SUMMARYMgsapproachingLimitsPolicyScope
    Write-Host '  processing TenantSummary ManagementGroups Limit PolicyScope'
    $mgsApproachingLimitPolicyScope = (($policyBaseQueryManagementGroups.where( { [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.PolicyDefinitionsScopedCount -gt 0 -and (($_.PolicyDefinitionsScopedCount -gt ($LimitPOLICYPolicyDefinitionsScopedManagementGroup * ($LimitCriticalPercentage / 100)))) })) | Select-Object MgId, MgName, PolicyDefinitionsScopedCount, PolicyDefinitionsScopedLimit -Unique)
    if (($mgsApproachingLimitPolicyScope | Measure-Object).count -gt 0) {
        $tfCount = ($mgsApproachingLimitPolicyScope | Measure-Object).count
        $htmlTableId = 'TenantSummary_MgsapproachingLimitsPolicyScope'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_MgsapproachingLimitsPolicyScope"><i class="padlxx fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicyScope | Measure-Object).count) Management Groups approaching Limit ($LimitPOLICYPolicyDefinitionsScopedManagementGroup) for Policy Scope</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Azure Policy Limits</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-policy-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Management Group Name</th>
<th>Management Group Id</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYMgsapproachingLimitsPolicyScope = $null
        $htmlSUMMARYMgsapproachingLimitsPolicyScope = foreach ($mgApproachingLimitPolicyScope in $mgsApproachingLimitPolicyScope) {
            @"
<tr>
<td><span class="valignMiddle">$($mgApproachingLimitPolicyScope.MgName -replace '<', '&lt;' -replace '>', '&gt;')</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($mgApproachingLimitPolicyScope.MgId)">$($mgApproachingLimitPolicyScope.MgId)</a></span></td>
<td>$(($mgApproachingLimitPolicyScope.PolicyDefinitionsScopedCount/$LimitPOLICYPolicyDefinitionsScopedManagementGroup).tostring('P')) $($mgApproachingLimitPolicyScope.PolicyDefinitionsScopedCount)/$($LimitPOLICYPolicyDefinitionsScopedManagementGroup)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYMgsapproachingLimitsPolicyScope)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
<p><i class="padlxx fa fa-check green" aria-hidden="true"></i> $($mgsApproachingLimitPolicyScope.count) Management Groups approaching Limit ($LimitPOLICYPolicyDefinitionsScopedManagementGroup) for Policy Scope <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-policy-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@)
    }
    #endregion SUMMARYMgsapproachingLimitsPolicyScope

    #region SUMMARYMgsapproachingLimitsPolicySetScope
    Write-Host '  processing TenantSummary ManagementGroups Limit PolicySetScope'
    $mgsApproachingLimitPolicySetScope = (($policyBaseQueryManagementGroups.where( { [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.PolicySetDefinitionsScopedCount -gt 0 -and (($_.PolicySetDefinitionsScopedCount -gt ($LimitPOLICYPolicySetDefinitionsScopedManagementGroup * ($LimitCriticalPercentage / 100)))) })) | Select-Object MgId, MgName, PolicySetDefinitionsScopedCount, PolicySetDefinitionsScopedLimit -Unique)
    if ($mgsApproachingLimitPolicySetScope.count -gt 0) {
        $tfCount = ($mgsApproachingLimitPolicySetScope | Measure-Object).count
        $htmlTableId = 'TenantSummary_MgsapproachingLimitsPolicySetScope'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_MgsapproachingLimitsPolicySetScope"><i class="padlxx fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicySetScope | Measure-Object).count) Management Groups approaching Limit ($LimitPOLICYPolicySetDefinitionsScopedManagementGroup) for PolicySet Scope</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Azure Policy Limits</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-policy-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Management Group Name</th>
<th>Management Group Id</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYMgsapproachingLimitsPolicySetScope = $null
        $htmlSUMMARYMgsapproachingLimitsPolicySetScope = foreach ($mgApproachingLimitPolicySetScope in $mgsApproachingLimitPolicySetScope) {
            @"
<tr>
<td><span class="valignMiddle">$($mgApproachingLimitPolicySetScope.MgName -replace '<', '&lt;' -replace '>', '&gt;')</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($mgApproachingLimitPolicySetScope.MgId)">$($mgApproachingLimitPolicySetScope.MgId)</a></span></td>
<td>$(($mgApproachingLimitPolicySetScope.PolicySetDefinitionsScopedCount/$LimitPOLICYPolicySetDefinitionsScopedManagementGroup).tostring('P')) ($($mgApproachingLimitPolicySetScope.PolicySetDefinitionsScopedCount)/$($LimitPOLICYPolicySetDefinitionsScopedManagementGroup))</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYMgsapproachingLimitsPolicySetScope)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
<p><i class="padlxx fa fa-check green" aria-hidden="true"></i> $(($mgsApproachingLimitPolicySetScope | Measure-Object).count) Management Groups approaching Limit ($LimitPOLICYPolicySetDefinitionsScopedManagementGroup) for PolicySet Scope <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-policy-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@)
    }
    #endregion SUMMARYMgsapproachingLimitsPolicySetScope

    #region SUMMARYMgsapproachingLimitsRoleAssignment
    Write-Host '  processing TenantSummary ManagementGroups Limit RoleAssignments'
    $mgsApproachingRoleAssignmentLimit = $rbacBaseQuery.where( { [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.RoleAssignmentsCount -gt ($LimitRBACRoleAssignmentsManagementGroup * $LimitCriticalPercentage / 100) }) | Sort-Object -Property MgId -Unique | Select-Object -Property MgId, MgName, RoleAssignmentsCount, RoleAssignmentsLimit

    if (($mgsApproachingRoleAssignmentLimit).count -gt 0) {
        $tfCount = ($mgsApproachingRoleAssignmentLimit).count
        $htmlTableId = 'TenantSummary_MgsapproachingLimitsRoleAssignment'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_MgsapproachingLimitsRoleAssignment"><i class="padlxx fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingRoleAssignmentLimit | Measure-Object).count) Management Groups approaching Limit ($LimitRBACRoleAssignmentsManagementGroup) for RoleAssignment</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Azure RBAC Limits</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-rbac-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Management Group Name</th>
<th>Management Group Id</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYMgsapproachingLimitsRoleAssignment = $null
        $htmlSUMMARYMgsapproachingLimitsRoleAssignment = foreach ($mgApproachingRoleAssignmentLimit in $mgsApproachingRoleAssignmentLimit) {
            @"
<tr>
<td><span class="valignMiddle">$($mgApproachingRoleAssignmentLimit.MgName -replace '<', '&lt;' -replace '>', '&gt;')</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($mgApproachingRoleAssignmentLimit.MgId)">$($mgApproachingRoleAssignmentLimit.MgId)</a></span></td>
<td>$(($mgApproachingRoleAssignmentLimit.RoleAssignmentsCount/$LimitRBACRoleAssignmentsManagementGroup).tostring('P')) ($($mgApproachingRoleAssignmentLimit.RoleAssignmentsCount)/$($LimitRBACRoleAssignmentsManagementGroup))</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYMgsapproachingLimitsRoleAssignment)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
    <p><i class="padlxx fa fa-check green" aria-hidden="true"></i> $(($mgApproachingRoleAssignmentLimit | Measure-Object).count) Management Groups approaching Limit ($LimitRBACRoleAssignmentsManagementGroup) for RoleAssignment <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-rbac-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@)
    }
    #endregion SUMMARYMgsapproachingLimitsRoleAssignment

    #endregion tenantSummaryLimitsManagementGroups

    #region tenantSummaryLimitsSubscriptions
    [void]$htmlTenantSummary.AppendLine( @'
<p><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> Subscriptions</p>
'@)

    #region SUMMARYSubsapproachingLimitsResourceGroups
    Write-Host '  processing TenantSummary Subscriptions Limit Resource Groups'
    $subscriptionsApproachingLimitFromResourceGroupsAll = $resourceGroupsAll.where( { $_.count_ -gt ($LimitResourceGroups * ($LimitCriticalPercentage / 100)) })
    if (($subscriptionsApproachingLimitFromResourceGroupsAll | Measure-Object).count -gt 0) {
        $tfCount = ($subscriptionsApproachingLimitFromResourceGroupsAll | Measure-Object).count
        $htmlTableId = 'TenantSummary_SubsapproachingLimitsResourceGroups'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_SubsapproachingLimitsResourceGroups"><i class="padlxx fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitFromResourceGroupsAll | Measure-Object).count) Subscriptions approaching Limit ($LimitResourceGroups) for ResourceGroups</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Azure Subscription Resource Group Limit</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#subscription-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYSubsapproachingLimitsResourceGroups = $null
        $htmlSUMMARYSubsapproachingLimitsResourceGroups = foreach ($subscriptionApproachingLimitFromResourceGroupsAll in $subscriptionsApproachingLimitFromResourceGroupsAll) {
            $subscriptionData = $htSubDetails.($subscriptionApproachingLimitFromResourceGroupsAll.subscriptionId).details
            @"
<tr>
<td><span class="valignMiddle">$($subscriptionData.subscription -replace '<', '&lt;' -replace '>', '&gt;')</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionData.MgId)">$($subscriptionData.subscriptionId)</a></span></td>
<td>$(($subscriptionApproachingLimitFromResourceGroupsAll.count_/$LimitResourceGroups).tostring('P')) ($($subscriptionApproachingLimitFromResourceGroupsAll.count_)/$($LimitResourceGroups))</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYSubsapproachingLimitsResourceGroups)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
    <p"><i class="padlxx fa fa-check green" aria-hidden="true"></i> $(($subscriptionsApproachingLimitFromResourceGroupsAll | Measure-Object).count) Subscriptions approaching Limit ($LimitResourceGroups) for ResourceGroups <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#subscription-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@)
    }
    #endregion SUMMARYSubsapproachingLimitsResourceGroups

    #region SUMMARYSubsapproachingLimitsSubscriptionTags
    Write-Host '  processing TenantSummary Subscriptions Limit Subscription Tags'
    $subscriptionsApproachingLimitTags = ($optimizedTableForPathQueryMgAndSub.where( { (($_.SubscriptionTagsCount -gt ($LimitTagsSubscription * ($LimitCriticalPercentage / 100)))) }))
    if (($subscriptionsApproachingLimitTags | Measure-Object).count -gt 0) {
        $tfCount = ($subscriptionsApproachingLimitTags | Measure-Object).count
        $htmlTableId = 'TenantSummary_SubsapproachingLimitsSubscriptionTags'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_SubsapproachingLimitsSubscriptionTags"><i class="padlxx fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitTags | Measure-Object).count) Subscriptions approaching Limit ($LimitTagsSubscription) for Tags</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Azure Subscription Tag Limit</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#subscription-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYSubsapproachingLimitsSubscriptionTags = $null
        $htmlSUMMARYSubsapproachingLimitsSubscriptionTags = foreach ($subscriptionApproachingLimitTags in $subscriptionsApproachingLimitTags) {
            @"
<tr>
<td><span class="valignMiddle">$($subscriptionApproachingLimitTags.subscription -replace '<', '&lt;' -replace '>', '&gt;')</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingLimitTags.MgId)">$($subscriptionApproachingLimitTags.subscriptionId)</a></span></td>
<td>$(($subscriptionApproachingLimitTags.SubscriptionTagsCount/$LimitTagsSubscription).tostring('P')) ($($subscriptionApproachingLimitTags.SubscriptionTagsCount)/$($LimitTagsSubscription))</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYSubsapproachingLimitsSubscriptionTags)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
    <p><i class="padlxx fa fa-check green" aria-hidden="true"></i> $($subscriptionsApproachingLimitTags.count) Subscriptions approaching Limit ($LimitTagsSubscription) for Tags <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#subscription-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@)
    }
    #endregion SUMMARYSubsapproachingLimitsSubscriptionTags

    #region SUMMARYSubsapproachingLimitsPolicyAssignments
    Write-Host '  processing TenantSummary Subscriptions Limit PolicyAssignments'
    $subscriptionsApproachingLimitPolicyAssignments = (($policyBaseQuerySubscriptions.where( { -not [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.PolicyAndPolicySetAssignmentAtScopeCount -gt 0 -and (($_.PolicyAndPolicySetAssignmentAtScopeCount -gt ($_.PolicyAssignmentLimit * ($LimitCriticalPercentage / 100)))) })) | Select-Object MgId, Subscription, SubscriptionId, PolicyAssignmentAtScopeCount, PolicySetAssignmentAtScopeCount, PolicyAndPolicySetAssignmentAtScopeCount, PolicyAssignmentLimit -Unique)
    if ($subscriptionsApproachingLimitPolicyAssignments.count -gt 0) {
        $tfCount = ($subscriptionsApproachingLimitPolicyAssignments | Measure-Object).count
        $htmlTableId = 'TenantSummary_SubsapproachingLimitsPolicyAssignments'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_SubsapproachingLimitsPolicyAssignments"><i class="padlxx fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyAssignments | Measure-Object).count) Subscriptions approaching Limit ($LimitPOLICYPolicyAssignmentsSubscription) for PolicyAssignment</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Azure Policy Limits</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-policy-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYSubsapproachingLimitsPolicyAssignments = $null
        $htmlSUMMARYSubsapproachingLimitsPolicyAssignments = foreach ($subscriptionApproachingLimitPolicyAssignments in $subscriptionsApproachingLimitPolicyAssignments) {
            @"
<tr>
<td><span class="valignMiddle">$($subscriptionApproachingLimitPolicyAssignments.subscription -replace '<', '&lt;' -replace '>', '&gt;')</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingLimitPolicyAssignments.MgId)">$($subscriptionApproachingLimitPolicyAssignments.subscriptionId)</a></span></td>
<td>$(($subscriptionApproachingLimitPolicyAssignments.PolicyAndPolicySetAssignmentAtScopeCount/$subscriptionApproachingLimitPolicyAssignments.PolicyAssignmentLimit).tostring('P')) ($($subscriptionApproachingLimitPolicyAssignments.PolicyAndPolicySetAssignmentAtScopeCount)/$($subscriptionApproachingLimitPolicyAssignments.PolicyAssignmentLimit)) ($($subscriptionApproachingLimitPolicyAssignments.PolicyAssignmentAtScopeCount) Policy assignments, $($subscriptionApproachingLimitPolicyAssignments.PolicySetAssignmentAtScopeCount) PolicySet assignments)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYSubsapproachingLimitsPolicyAssignments)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
    <p><i class="padlxx fa fa-check green" aria-hidden="true"></i> $(($subscriptionsApproachingLimitPolicyAssignments | Measure-Object).count) Subscriptions approaching Limit ($LimitPOLICYPolicyAssignmentsSubscription) for PolicyAssignment <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-policy-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@)
    }
    #endregion SUMMARYSubsapproachingLimitsPolicyAssignments

    #region SUMMARYSubsapproachingLimitsPolicyScope
    Write-Host '  processing TenantSummary Subscriptions Limit PolicyScope'
    $subscriptionsApproachingLimitPolicyScope = (($policyBaseQuerySubscriptions.where( { -not [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.PolicyDefinitionsScopedCount -gt 0 -and (($_.PolicyDefinitionsScopedCount -gt ($_.PolicyDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) })) | Select-Object MgId, Subscription, SubscriptionId, PolicyDefinitionsScopedCount, PolicyDefinitionsScopedLimit -Unique)
    if (($subscriptionsApproachingLimitPolicyScope | Measure-Object).count -gt 0) {
        $tfCount = ($subscriptionsApproachingLimitPolicyScope | Measure-Object).count
        $htmlTableId = 'TenantSummary_SubsapproachingLimitsPolicyScope'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_SubsapproachingLimitsPolicyScope"><i class="padlxx fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyScope | Measure-Object).count) Subscriptions approaching Limit ($LimitPOLICYPolicyDefinitionsScopedSubscription) for Policy Scope</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Azure Policy Limits</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-policy-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYSubsapproachingLimitsPolicyScope = $null
        $htmlSUMMARYSubsapproachingLimitsPolicyScope = foreach ($subscriptionApproachingLimitPolicyScope in $subscriptionsApproachingLimitPolicyScope) {
            @"
<tr>
<td><span class="valignMiddle">$($subscriptionApproachingLimitPolicyScope.subscription -replace '<', '&lt;' -replace '>', '&gt;')</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingLimitPolicyScope.MgId)">$($subscriptionApproachingLimitPolicyScope.subscriptionId)</a></span></td>
<td>$(($subscriptionApproachingLimitPolicyScope.PolicyDefinitionsScopedCount/$subscriptionApproachingLimitPolicyScope.PolicyDefinitionsScopedLimit).tostring('P')) ($($subscriptionApproachingLimitPolicyScope.PolicyDefinitionsScopedCount)/$($subscriptionApproachingLimitPolicyScope.PolicyDefinitionsScopedLimit))</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYSubsapproachingLimitsPolicyScope)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
    <p><i class="padlxx fa fa-check green" aria-hidden="true"></i> $($subscriptionsApproachingLimitPolicyScope.count) Subscriptions approaching Limit ($LimitPOLICYPolicyDefinitionsScopedSubscription) for Policy Scope <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-policy-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@)
    }
    #endregion SUMMARYSubsapproachingLimitsPolicyScope

    #region SUMMARYSubsapproachingLimitsPolicySetScope
    Write-Host '  processing TenantSummary Subscriptions Limit PolicySetScope'
    $subscriptionsApproachingLimitPolicySetScope = (($policyBaseQuerySubscriptions.where( { -not [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.PolicySetDefinitionsScopedCount -gt 0 -and (($_.PolicySetDefinitionsScopedCount -gt ($_.PolicySetDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) })) | Select-Object MgId, Subscription, SubscriptionId, PolicySetDefinitionsScopedCount, PolicySetDefinitionsScopedLimit -Unique)
    if ($subscriptionsApproachingLimitPolicySetScope.count -gt 0) {
        $tfCount = ($subscriptionsApproachingLimitPolicySetScope | Measure-Object).count
        $htmlTableId = 'TenantSummary_SubsapproachingLimitsPolicySetScope'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_SubsapproachingLimitsPolicySetScope"><i class="padlxx fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyScope | Measure-Object).count) Subscriptions approaching Limit ($LimitPOLICYPolicySetDefinitionsScopedSubscription) for PolicySet Scope</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Azure Policy Limits</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-policy-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYSubsapproachingLimitsPolicySetScope = $null
        $htmlSUMMARYSubsapproachingLimitsPolicySetScope = foreach ($subscriptionApproachingLimitPolicySetScope in $subscriptionsApproachingLimitPolicySetScope) {
            @"
<tr>
<td><span class="valignMiddle">$($subscriptionApproachingLimitPolicySetScope.subscription -replace '<', '&lt;' -replace '>', '&gt;')</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingLimitPolicySetScope.MgId)">$($subscriptionApproachingLimitPolicySetScope.subscriptionId)</a></span></td>
<td>$(($subscriptionApproachingLimitPolicySetScope.PolicySetDefinitionsScopedCount/$subscriptionApproachingLimitPolicySetScope.PolicySetDefinitionsScopedLimit).tostring('P')) ($($subscriptionApproachingLimitPolicySetScope.PolicySetDefinitionsScopedCount)/$($subscriptionApproachingLimitPolicySetScope.PolicySetDefinitionsScopedLimit))</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYSubsapproachingLimitsPolicySetScope)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
    <p><i class="padlxx fa fa-check green" aria-hidden="true"></i> $(($subscriptionsApproachingLimitPolicyScope | Measure-Object).count) Subscriptions approaching Limit ($LimitPOLICYPolicySetDefinitionsScopedSubscription) for PolicySet Scope <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-policy-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@)
    }
    #endregion SUMMARYSubsapproachingLimitsPolicySetScope

    #region SUMMARYSubsapproachingLimitsRoleAssignment
    Write-Host '  processing TenantSummary Subscriptions Limit RoleAssignments'
    $subscriptionsApproachingRoleAssignmentLimit = $rbacBaseQuery.where( { -not [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.RoleAssignmentsCount -gt ($_.RoleAssignmentsLimit * $LimitCriticalPercentage / 100) }) | Sort-Object -Property SubscriptionId -Unique | Select-Object -Property MgId, SubscriptionId, Subscription, RoleAssignmentsCount, RoleAssignmentsLimit

    $availableSubscriptionsRoleAssignmentLimits = ($htSubscriptionsRoleAssignmentLimit.values | Sort-Object -Unique) -join ' | '

    if (($subscriptionsApproachingRoleAssignmentLimit).count -gt 0) {
        $tfCount = ($subscriptionsApproachingRoleAssignmentLimit).count
        $htmlTableId = 'TenantSummary_SubsapproachingLimitsRoleAssignment'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_SubsapproachingLimitsRoleAssignment"><i class="padlxx fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingRoleAssignmentLimit | Measure-Object).count) Subscriptions approaching Limit ($($availableSubscriptionsRoleAssignmentLimits)) for RoleAssignment</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Azure RBAC Limits</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-rbac-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYSubsapproachingLimitsRoleAssignment = $null
        $htmlSUMMARYSubsapproachingLimitsRoleAssignment = foreach ($subscriptionApproachingRoleAssignmentLimit in $subscriptionsApproachingRoleAssignmentLimit) {
            @"
<tr>
<td><span class="valignMiddle">$($subscriptionApproachingRoleAssignmentLimit.subscription -replace '<', '&lt;' -replace '>', '&gt;')</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingRoleAssignmentLimit.MgId)">$($subscriptionApproachingRoleAssignmentLimit.subscriptionId)</a></span></td>
<td>$(($subscriptionApproachingRoleAssignmentLimit.RoleAssignmentsCount/$subscriptionApproachingRoleAssignmentLimit.RoleAssignmentsLimit).tostring('P')) ($($subscriptionApproachingRoleAssignmentLimit.RoleAssignmentsCount)/$($subscriptionApproachingRoleAssignmentLimit.RoleAssignmentsLimit))</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYSubsapproachingLimitsRoleAssignment)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
    <p"><i class="padlxx fa fa-check green" aria-hidden="true"></i> $(($subscriptionsApproachingRoleAssignmentLimit | Measure-Object).count) Subscriptions approaching Limit ($availableSubscriptionsRoleAssignmentLimits) for RoleAssignment <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-rbac-limits" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@)
    }
    #endregion SUMMARYSubsapproachingLimitsRoleAssignment

    #endregion tenantSummaryLimitsSubscriptions

    [void]$htmlTenantSummary.AppendLine(@'
</div>
'@)
    #endregion tenantSummaryLimits

    showMemoryUsage

    #region tenantSummaryAAD
    [void]$htmlTenantSummary.AppendLine(@'
<button type="button" class="collapsible" id="tenantSummaryAAD"><hr class="hr-textAAD" data-content="Azure Active Directory" /></button>
<div class="content TenantSummaryContent">
<i class="padlx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Check out <b>AzADServicePrincipalInsights</b></span> <a class="externallink" href="https://aka.ms/azadserviceprincipalinsights" target="_blank" rel="noopener">GitHub <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Demystifying Service Principals - Managed Identities</span> <a class="externallink" href="https://devblogs.microsoft.com/devops/demystifying-service-principals-managed-identities/" target="_blank" rel="noopener">devBlogs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
<i class="padlx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">John Savill - Azure AD App Registrations, Enterprise Apps and Service Principals</span> <a class="externallink" href="https://www.youtube.com/watch?v=WVNvoiA_ktw" target="_blank" rel="noopener">YouTube <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
'@)

    #region AADSPNotFound
    Write-Host '  processing TenantSummary AAD ServicePrincipals - not found'

    if ($servicePrincipalRequestResourceNotFoundCount -gt 0) {
        $tfCount = $servicePrincipalRequestResourceNotFoundCount
        $htmlTableId = 'TenantSummary_AADSPNotFound'

        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_AADSPNotFound"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$($servicePrincipalRequestResourceNotFoundCount) AAD ServicePrincipals 'Request_ResourceNotFound'</span> <abbr title="API return: Request_ResourceNotFound"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content TenantSummary">
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Service Principal Object Id</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYAADSPNotFound = $null
        $htmlSUMMARYAADSPNotFound = foreach ($serviceprincipal in $arrayServicePrincipalRequestResourceNotFound | Sort-Object) {

            @"
<tr>
<td>$($serviceprincipal)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYAADSPNotFound)
        [void]$htmlTenantSummary.AppendLine(@"
    </tbody>
</table>
</div>
<script>
function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
    window.helpertfConfig4$htmlTableId =1;
    var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
    col_types: [
        'caseinsensitivestring'
    ],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@'
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No ServicePrincipals where the API returned 'Request_ResourceNotFound'</p>
'@)
    }
    #endregion AADSPNotFound

    #region AADAppNotFound
    Write-Host '  processing TenantSummary AAD Applications - not found'

    if ($applicationRequestResourceNotFoundCount -gt 0) {
        $tfCount = $applicationRequestResourceNotFoundCount
        $htmlTableId = 'TenantSummary_AADAppNotFound'

        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_AADAppNotFound"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$($applicationRequestResourceNotFoundCount) AAD Applications 'Request_ResourceNotFound'</span> <abbr title="API return: Request_ResourceNotFound"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content TenantSummary">
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Application (Client) Id</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYAADAppNotFound = $null
        $htmlSUMMARYAADAppNotFound = foreach ($app in $arrayApplicationRequestResourceNotFound | Sort-Object) {

            @"
<tr>
<td>$($app)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYAADAppNotFound)
        [void]$htmlTenantSummary.AppendLine(@"
    </tbody>
</table>
</div>
<script>
function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
    window.helpertfConfig4$htmlTableId =1;
    var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
    col_types: [
        'caseinsensitivestring'
    ],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@'
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No Applications where the API returned 'Request_ResourceNotFound'</p>
'@)
    }
    #endregion AADAppNotFound

    #region AADSPManagedIdentity
    $startAADSPManagedIdentityLoop = Get-Date
    Write-Host '  processing TenantSummary AAD SP Managed Identities'

    if ($servicePrincipalsOfTypeManagedIdentityCount -gt 0) {
        $tfCount = $servicePrincipalsOfTypeManagedIdentityCount
        $htmlTableId = 'TenantSummary_AADSPManagedIdentities'

        if ($htOrphanedSPMI.keys.Count -gt 0) {
            $orphanedSPMIPresent = $true
        }

        $abbr = " <abbr title=`"Relevant for UserAssigned MI's &#13;Check 'TenantSummary/Subscription, Resources & Defender/UserAssigned Managed Identities assigned to Resources' for more details`"><i class=`"fa fa-question-circle`" aria-hidden=`"true`"></i></abbr>"
        $abbrOrphanedSPMI = " <abbr title=`"Policy assignment related Managed Identities &#13;The related Policy assignment does not exist`"><i class=`"fa fa-question-circle`" aria-hidden=`"true`"></i></abbr>"
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_AADSPManagedIdentities"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$($servicePrincipalsOfTypeManagedIdentityCount) AAD ServicePrincipals type=ManagedIdentity</span> <abbr title="ServicePrincipals where a Role assignment exists &#13;(including ResourceGroups and Resources)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>ApplicationId</th>
<th>DisplayName</th>
<th>SP ObjectId</th>
<th>Type</th>
<th>Usage</th>
<th>Usage info</th>
<th>Policy assignment details</th>
<th>Role assignments</th>
<th>Assigned to resources$($abbr)</th>
<th>Orphaned$($abbrOrphanedSPMI)</td>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYAADSPManagedIdentities = $null
        $htmlSUMMARYAADSPManagedIdentities = foreach ($serviceprincipalMI in $servicePrincipalsOfTypeManagedIdentity | Sort-Object) {

            $serviceprincipalMIDetailed = $htServicePrincipals.($serviceprincipalMI)
            $miRoleAssignments = 'n/a'
            $miType = 'unknown'
            $userMiAssignedToResourcesCount = ''
            foreach ($altName in $serviceprincipalMIDetailed.alternativeNames) {
                if ($altName -like 'isExplicit=*') {
                    $splitAltName = $altName.split('=')
                    if ($splitAltName[1] -eq 'true') {
                        $miType = 'User assigned'
                        if ($htUserAssignedIdentitiesAssignedResources.($serviceprincipalMI)) {
                            $userMiAssignedToResourcesCount = $htUserAssignedIdentitiesAssignedResources.($serviceprincipalMI).ResourcesCount
                        }
                    }
                    if ($splitAltName[1] -eq 'false') {
                        $miType = 'System assigned'
                    }
                }
                else {
                    $s1 = $altName -replace '.*/providers/'; $rm = $s1 -replace '.*/'; $resourceType = $s1 -replace "/$($rm)"
                    $miAlternativeName = $altname
                    $miResourceType = $resourceType
                }
            }

            if ($miResourceType -eq 'Microsoft.Authorization/policyAssignments') {
                $policyAssignmentId = $miAlternativeName.ToLower()
                if ($policyAssignmentId -like '/providers/Microsoft.Management/managementGroups/*') {
                    if (-not ($htCacheAssignmentsPolicy).($policyAssignmentId)) {
                        $assignmentInfo = 'n/a'
                    }
                    else {
                        $assignmentInfo = ($htCacheAssignmentsPolicy).($policyAssignmentId).Assignment
                    }
                }
                else {
                    #sub
                    if (((($policyAssignmentId).Split('/') | Measure-Object).Count - 1) -eq 6) {
                        if (-not ($htCacheAssignmentsPolicy).($policyAssignmentId)) {
                            $assignmentInfo = 'n/a'
                        }
                        else {
                            $assignmentInfo = ($htCacheAssignmentsPolicy).($policyAssignmentId).Assignment
                        }
                    }
                    else {
                        #rg
                        if ($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy) {
                            if (-not ($htCacheAssignmentsPolicyOnResourceGroupsAndResources).($policyAssignmentId)) {
                                $assignmentInfo = 'n/a'
                            }
                            else {
                                $assignmentInfo = ($htCacheAssignmentsPolicyOnResourceGroupsAndResources).($policyAssignmentId)
                            }
                        }
                        else {
                            if (-not ($htCacheAssignmentsPolicy).($policyAssignmentId)) {
                                $assignmentInfo = 'n/a'
                            }
                            else {
                                $assignmentInfo = ($htCacheAssignmentsPolicy).($policyAssignmentId).Assignment
                            }
                        }
                    }
                }

                if ($assignmentinfo -ne 'n/a') {

                    if ($assignmentinfo.id -like '/subscriptions/*/resourcegroups/*') {

                        if ($assignmentInfo.properties.policyDefinitionId -like '*/providers/Microsoft.Authorization/policyDefinitions/*') {
                            $policyAssignmentsPolicyVariant = 'Policy'
                            $policyAssignmentsPolicyVariant4ht = 'policy'
                        }

                        if ($assignmentInfo.properties.policyDefinitionId -like '*/providers/Microsoft.Authorization/policySetDefinitions/*') {
                            $policyAssignmentsPolicyVariant = 'PolicySet'
                            $policyAssignmentsPolicyVariant4ht = 'policySet'
                        }

                        if ($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy) {
                            $policyAssignmentsPolicyDefinitionId = ($assignmentInfo.properties.policyDefinitionId).ToLower()
                            $policyAssignmentspolicyDefinitionIdGuid = $policyAssignmentsPolicyDefinitionId -replace '.*/'

                            if ($policyAssignmentsPolicyVariant4ht -eq 'policy') {
                                if (($htCacheDefinitionsPolicy).($policyAssignmentsPolicyDefinitionId)) {
                                    $definitionInfo = ($htCacheDefinitionsPolicy).($policyAssignmentsPolicyDefinitionId)
                                }
                                else {
                                    $definitionInfo = 'unknown'
                                }
                            }
                            if ($policyAssignmentsPolicyVariant4ht -eq 'policySet') {
                                if (($htCacheDefinitionsPolicySet).($policyAssignmentsPolicyDefinitionId)) {
                                    $definitionInfo = ($htCacheDefinitionsPolicySet).($policyAssignmentsPolicyDefinitionId)
                                }
                                else {
                                    $definitionInfo = 'unknown'
                                }
                            }

                        }
                        else {
                            $policyAssignmentsPolicyDefinitionId = ($assignmentInfo.properties.policyDefinitionId).ToLower()
                            $policyAssignmentspolicyDefinitionIdGuid = $policyAssignmentsPolicyDefinitionId -replace '.*/'

                            if ($policyAssignmentsPolicyVariant4ht -eq 'policy') {
                                if (($htCacheDefinitionsPolicy).($policyAssignmentsPolicyDefinitionId)) {
                                    $definitionInfo = ($htCacheDefinitionsPolicy).($policyAssignmentsPolicyDefinitionId)
                                }
                                else {
                                    $definitionInfo = 'unknown'
                                }
                            }
                            if ($policyAssignmentsPolicyVariant4ht -eq 'policySet') {
                                if (($htCacheDefinitionsPolicySet).($policyAssignmentsPolicyDefinitionId)) {
                                    $definitionInfo = ($htCacheDefinitionsPolicySet).($policyAssignmentsPolicyDefinitionId)
                                }
                                else {
                                    $definitionInfo = 'unknown'
                                }
                            }
                        }
                    }
                    else {
                        if ($assignmentInfo.properties.policyDefinitionId -like '*/providers/Microsoft.Authorization/policyDefinitions/*') {
                            $policyAssignmentsPolicyVariant = 'Policy'
                            $policyAssignmentsPolicyVariant4ht = 'policy'
                        }
                        if ($assignmentInfo.properties.policyDefinitionId -like '*/providers/Microsoft.Authorization/policySetDefinitions/*') {
                            $policyAssignmentsPolicyVariant = 'PolicySet'
                            $policyAssignmentsPolicyVariant4ht = 'policySet'
                        }

                        $policyAssignmentsPolicyDefinitionId = ($assignmentInfo.properties.policyDefinitionId).Tolower()
                        $policyAssignmentspolicyDefinitionIdGuid = $policyAssignmentsPolicyDefinitionId -replace '.*/'

                        if ($policyAssignmentsPolicyVariant4ht -eq 'policy') {
                            if (($htCacheDefinitionsPolicy).($policyAssignmentsPolicyDefinitionId)) {
                                $definitionInfo = ($htCacheDefinitionsPolicy).($policyAssignmentsPolicyDefinitionId)
                            }
                            else {
                                $definitionInfo = 'unknown'
                            }
                        }
                        if ($policyAssignmentsPolicyVariant4ht -eq 'policySet') {
                            if (($htCacheDefinitionsPolicySet).($policyAssignmentsPolicyDefinitionId)) {
                                $definitionInfo = ($htCacheDefinitionsPolicySet).($policyAssignmentsPolicyDefinitionId)
                            }
                            else {
                                $definitionInfo = 'unknown'
                            }
                        }
                    }

                    if ($definitionInfo -eq 'unknown') {
                        $policyAssignmentMoreInfo = "unknown definition ($($policyAssignmentsPolicyDefinitionId))"
                    }
                    else {
                        if ($definitionInfo.type -eq 'BuiltIn') {
                            $policyAssignmentMoreInfo = "$($definitionInfo.Type) $($policyAssignmentsPolicyVariant): $($definitionInfo.LinkToAzAdvertizer) ($policyAssignmentspolicyDefinitionIdGuid)"
                        }
                        else {
                            $policyAssignmentMoreInfo = "$($definitionInfo.Type) $($policyAssignmentsPolicyVariant): <b>$($definitionInfo.DisplayName -replace '<', '&lt;' -replace '>', '&gt;')</b> ($($policyAssignmentsPolicyDefinitionId))"
                        }
                    }
                }
                else {
                    $policyAssignmentMoreInfo = 'n/a'
                }

            }
            else {
                $policyAssignmentMoreInfo = 'n/a'
            }

            if ($htRoleAssignmentsForServicePrincipals.($serviceprincipalMI)) {

                $arrayMiRoleAssignments = @()
                $helperMiRoleAssignments = $htRoleAssignmentsForServicePrincipals.($serviceprincipalMI).RoleAssignments

                foreach ($roleAssignment in $helperMiRoleAssignments) {
                    if ($roleAssignment.RoleIsCustom -eq 'False') {
                        $arrayMiRoleAssignments += "$(($htCacheDefinitionsRole).($roleAssignment.roleDefinitionId).LinkToAzAdvertizer) ($($roleAssignment.roleassignmentId))"
                    }
                    else {
                        $arrayMiRoleAssignments += "<b>$($roleAssignment.roleDefinitionName -replace '<', '&lt;' -replace '>', '&gt;')</b>; $($roleAssignment.roleDefinitionId) ($($roleAssignment.roleassignmentId))"
                    }
                }
                $miRoleAssignments = "$(($arrayMiRoleAssignments).Count) ($($arrayMiRoleAssignments -join ', '))"
            }

            $orphanedMI = ''
            if ($miResourceType -eq 'Microsoft.Authorization/policyAssignments') {
                $orphanedMI = 'false'
                if ($htOrphanedSPMI.($serviceprincipalMI)) {
                    $orphanedMI = 'true'
                }
            }

            @"
<tr>
<td>$($serviceprincipalMIDetailed.appId)</td>
<td>$($serviceprincipalMIDetailed.displayName)</td>
<td class="breakwordall">$($serviceprincipalMI)</td>
<td>$miType</td>
<td>$miResourceType</td>
<td class="breakwordall">$($serviceprincipalMIDetailed.alternativeNames -join ', ')</td>
<td class="breakwordall">$($policyAssignmentMoreInfo)</td>
<td class="breakwordall">$($miRoleAssignments)</td>
<td>$userMiAssignedToResourcesCount</td>
<td>$orphanedMI</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYAADSPManagedIdentities)
        [void]$htmlTenantSummary.AppendLine(@"
    </tbody>
</table>
</div>
<script>
function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
    window.helpertfConfig4$htmlTableId =1;
    var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
    col_3: 'select',
    col_4: 'select',
    col_9: 'select',
    col_types: [
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'number',
        'caseinsensitivestring'
    ],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $servicePrincipalsOfTypeManagedIdentityCount AAD ServicePrincipals type=ManagedIdentity</p>
"@)
    }

    $endAADSPManagedIdentityLoop = Get-Date
    Write-Host "   TenantSummary AAD SP Managed Identities processing duration: $((New-TimeSpan -Start $startAADSPManagedIdentityLoop -End $endAADSPManagedIdentityLoop).TotalMinutes) minutes ($((New-TimeSpan -Start $startAADSPManagedIdentityLoop -End $endAADSPManagedIdentityLoop).TotalSeconds) seconds)"
    #endregion AADSPManagedIdentity

    #region AADSPCredExpiry
    if (-not $skipApplications) {
        $startAADSPCredExpiryLoop = Get-Date
        Write-Host '  processing TenantSummary AAD SP Apps CredExpiry'

        $servicePrincipalsOfTypeApplicationCount = ($servicePrincipalsOfTypeApplication).Count

        if ($servicePrincipalsOfTypeApplicationCount -gt 0) {
            $tfCount = $servicePrincipalsOfTypeApplicationCount
            $htmlTableId = 'TenantSummary_AADSPCredExpiry'

            $servicePrincipalsOfTypeApplicationSecretsExpiring = $servicePrincipalsOfTypeApplication.where( { $htAppDetails.($_).appPasswordCredentialsGracePeriodExpiryCount -gt 0 } )
            $servicePrincipalsOfTypeApplicationSecretsExpiringCount = ($servicePrincipalsOfTypeApplicationSecretsExpiring).Count
            $servicePrincipalsOfTypeApplicationCertificatesExpiring = $servicePrincipalsOfTypeApplication.where( { $htAppDetails.($_).appKeyCredentialsGracePeriodExpiryCount -gt 0 } )
            $servicePrincipalsOfTypeApplicationCertificatesExpiringCount = ($servicePrincipalsOfTypeApplicationCertificatesExpiring).Count
            if ($servicePrincipalsOfTypeApplicationSecretsExpiringCount -gt 0 -or $servicePrincipalsOfTypeApplicationCertificatesExpiringCount -gt 0) {
                $warningOrNot = "<i class=`"padlx fa fa-exclamation-triangle yellow`" aria-hidden=`"true`"></i>"
            }
            else {
                $warningOrNot = "<i class=`"padlx fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
            }
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_AADSPCredExpiry">$warningOrNot <span class="valignMiddle">$($servicePrincipalsOfTypeApplicationCount) AAD ServicePrincipals type=Application | $servicePrincipalsOfTypeApplicationSecretsExpiringCount Secrets expire < $($AADServicePrincipalExpiryWarningDays)d | $servicePrincipalsOfTypeApplicationCertificatesExpiringCount Certificates expire < $($AADServicePrincipalExpiryWarningDays)d</span> <abbr title="ServicePrincipals where a Role assignment exists &#13;(including ResourceGroups and Resources)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>ApplicationId</th>
<th>DisplayName</th>
<th>Notes</th>
<th>SP ObjectId</th>
<th>App ObjectId</th>
<th>Secrets</th>
<th>Secrets expired</th>
<th>Secrets expiry<br><$($AADServicePrincipalExpiryWarningDays)d</th>
<th>Secrets expiry<br>>$($AADServicePrincipalExpiryWarningDays)d & <2y</th>
<th>Secrets expiry<br>>2y</th>
<th>Certs</th>
<th>Certs expired</th>
<th>Certs expiry<br><$($AADServicePrincipalExpiryWarningDays)d</th>
<th>Certs expiry<br>>$($AADServicePrincipalExpiryWarningDays)d & <2y</th>
<th>Certs expiry<br>>2y</th>
</tr>
</thead>
<tbody>
"@)
            $htmlSUMMARYAADSPCredExpiry = $null
            $htmlSUMMARYAADSPCredExpiry = foreach ($serviceprincipalApp in $servicePrincipalsOfTypeApplication | Sort-Object) {
                @"
<tr>
<td>$($htAppDetails.$serviceprincipalApp.spGraphDetails.appId)</td>
<td>$($htAppDetails.$serviceprincipalApp.spGraphDetails.displayName)</td>
<td>$($htAppDetails.$serviceprincipalApp.spGraphDetails.notes)</td>
<td>$($htAppDetails.$serviceprincipalApp.spGraphDetails.Id)</td>
<td>$($htAppDetails.$serviceprincipalApp.appGraphDetails.Id)</td>
"@
                if ($htAppDetails.$serviceprincipalApp.appPasswordCredentialsCount) {
                    @"
<td>$($htAppDetails.$serviceprincipalApp.appPasswordCredentialsCount)</td>
<td>$($htAppDetails.$serviceprincipalApp.appPasswordCredentialsExpiredCount)</td>
<td>$($htAppDetails.$serviceprincipalApp.appPasswordCredentialsGracePeriodExpiryCount)</td>
<td>$($htAppDetails.$serviceprincipalApp.appPasswordCredentialsExpiryOKCount)</td>
<td>$($htAppDetails.$serviceprincipalApp.appPasswordCredentialsExpiryOKMoreThan2YearsCount)</td>
"@
                }
                else {
                    @'
<td>0</td>
<td>0</td>
<td>0</td>
<td>0</td>
<td>0</td>
'@
                }

                if ($htAppDetails.$serviceprincipalApp.appKeyCredentialsCount) {
                    @"
<td>$($htAppDetails.$serviceprincipalApp.appKeyCredentialsCount)</td>
<td>$($htAppDetails.$serviceprincipalApp.appKeyCredentialsExpiredCount)</td>
<td>$($htAppDetails.$serviceprincipalApp.appKeyCredentialsGracePeriodExpiryCount)</td>
<td>$($htAppDetails.$serviceprincipalApp.appKeyCredentialsExpiryOKCount)</td>
<td>$($htAppDetails.$serviceprincipalApp.appKeyCredentialsExpiryOKMoreThan2YearsCount)</td>
"@
                }
                else {
                    @'
<td>0</td>
<td>0</td>
<td>0</td>
<td>0</td>
<td>0</td>
'@
                }

                @'
</tr>
'@
            }
            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYAADSPCredExpiry)
            [void]$htmlTenantSummary.AppendLine(@"
    </tbody>
</table>
</div>
<script>
function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
    window.helpertfConfig4$htmlTableId =1;
    var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
    col_types: [
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number'
    ],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@"
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $servicePrincipalsOfTypeApplicationCount AAD ServicePrincipals type=Application</p>
"@)
        }

        $endAADSPCredExpiryLoop = Get-Date
        Write-Host "   TenantSummary AAD SP Apps CredExpiry processing duration: $((New-TimeSpan -Start $startAADSPCredExpiryLoop -End $endAADSPCredExpiryLoop).TotalMinutes) minutes ($((New-TimeSpan -Start $startAADSPCredExpiryLoop -End $endAADSPCredExpiryLoop).TotalSeconds) seconds)"
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@'
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No information on AAD ServicePrincipals type=Application as Guest account does not have enough permissions</p>
'@)
    }
    #endregion AADSPCredExpiry

    #region AADSPExternalSP
    Write-Host '  processing TenantSummary AAD External ServicePrincipals'
    $startAADSPExternalSP = Get-Date

    $htRoleAssignmentsForServicePrincipalsRgRes = @{}
    $roleAssignmentsForServicePrincipalsRgRes = (((($htCacheAssignmentsRBACOnResourceGroupsAndResources).values).where( { $_.ObjectType -eq 'ServicePrincipal' })) | Sort-Object -Property RoleAssignmentId -Unique)
    foreach ($spWithRoleAssignment in $roleAssignmentsForServicePrincipalsRgRes | Group-Object -Property ObjectId) {
        if (-not $htRoleAssignmentsForServicePrincipalsRgRes.($spWithRoleAssignment.Name)) {
            $htRoleAssignmentsForServicePrincipalsRgRes.($spWithRoleAssignment.Name) = @{}
            $htRoleAssignmentsForServicePrincipalsRgRes.($spWithRoleAssignment.Name).RoleAssignments = $spWithRoleAssignment.group
        }
    }

    $appsWithOtherOrgId = $htServicePrincipals.Keys.where( { $htServicePrincipals.($_).servicePrincipalType -eq 'Application' -and $htServicePrincipals.($_).appOwnerOrganizationId -ne $azAPICallConf['checkContext'].Tenant.Id } )
    $appsWithOtherOrgIdCount = ($appsWithOtherOrgId).Count

    if ($appsWithOtherOrgIdCount -gt 0) {
        $tfCount = $appsWithOtherOrgIdCount
        $htmlTableId = 'TenantSummary_AADSPExternal'

        if ($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC) {
            $abbr = " <abbr title=`"Lists only RoleAssignmentIds for scope RG/Resource &#13;Check TenantSummary/RBAC to find the RoleAssignmentIds for MG/Sub scopes`"><i class=`"fa fa-question-circle`" aria-hidden=`"true`"></i></abbr>"
        }
        else {
            $abbr = ''
        }
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_AADSPExternal"><i class="padlx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$($appsWithOtherOrgIdCount) External (appOwnerOrganizationId) AAD ServicePrincipals type=Application</span> <abbr title="External (appOwnerOrganizationId != $($azAPICallConf['checkContext'].Subscription.TenantId)) ServicePrincipals where a Role assignment exists &#13;(including ResourceGroups and Resources)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>ApplicationId</th>
<th>DisplayName</th>
<th>SP ObjectId</th>
<th>OrganizationId</th>
<th>Role assignments$($abbr)</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYAADSPExternal = $null
        $htmlSUMMARYAADSPExternal = foreach ($serviceprincipalApp in $appsWithOtherOrgId | Sort-Object) {
            $arrayRoleAssignments4ExternalApp = [System.Collections.ArrayList]@()
            $roleAssignmentsMgSub = $htRoleAssignmentsForServicePrincipals.($serviceprincipalApp).RoleAssignments
            $roleAssignmentsMgSubCount = ($roleAssignmentsMgSub).Count
            $roleAssignments4ExternalApp = 'n/a'
            if ($roleAssignmentsMgSubCount -gt 0) {
                $roleAssignments4ExternalApp = $roleAssignmentsMgSubCount
            }
            $roleAssignmentsRgRes = $htRoleAssignmentsForServicePrincipalsRgRes.($serviceprincipalApp).RoleAssignments
            $roleAssignmentsRgResCount = ($roleAssignmentsRgRes).Count
            if ($roleAssignmentsRgResCount -gt 0) {
                foreach ($roleAssignmentRgRes in $roleAssignmentsRgRes) {
                    $null = $arrayRoleAssignments4ExternalApp.Add([PSCustomObject]@{
                            roleAssignmentId = $roleAssignmentRgRes.RoleAssignmentId
                        })
                }
                $roleAssignments4ExternalApp = "$roleAssignmentsRgResCount ($($arrayRoleAssignments4ExternalApp.roleAssignmentId -join ', '))"
            }

            @"
<tr>
<td>$($htServicePrincipals.($serviceprincipalApp).appId)</td>
<td>$($htServicePrincipals.($serviceprincipalApp).displayName)</td>
<td>$($htServicePrincipals.($serviceprincipalApp).id)</td>
<td>$($htServicePrincipals.($serviceprincipalApp).appOwnerOrganizationId)</td>
<td>$roleAssignments4ExternalApp</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYAADSPExternal)
        [void]$htmlTenantSummary.AppendLine(@"
    </tbody>
</table>
</div>
<script>
function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
    window.helpertfConfig4$htmlTableId =1;
    var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
    col_types: [
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring'
    ],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> $appsWithOtherOrgIdCount External (appOwnerOrganizationId) AAD ServicePrincipals type=Application</p>
"@)
    }

    $endAADSPExternalSP = Get-Date
    Write-Host "   TenantSummary AAD External ServicePrincipals processing duration: $((New-TimeSpan -Start $startAADSPExternalSP -End $endAADSPExternalSP).TotalMinutes) minutes ($((New-TimeSpan -Start $startAADSPExternalSP -End $endAADSPExternalSP).TotalSeconds) seconds)"
    #endregion AADSPExternalSP

    [void]$htmlTenantSummary.AppendLine(@'
</div>
'@)
    #endregion tenantSummaryAAD

    showMemoryUsage

    #region tenantSummaryConsumption
    [void]$htmlTenantSummary.AppendLine(@'
    <button type="button" class="collapsible" id="tenantSummaryConsumption"><hr class="hr-textConsumption" data-content="Consumption" /></button>
    <div class="content TenantSummaryContent">
    <i class="padlx fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Customize your Azure environment optimizations (Cost, Reliability & more) with</span> <a class="externallink" href="https://github.com/helderpinto/AzureOptimizationEngine" target="_blank" rel="noopener">Azure Optimization Engine (AOE) <i class="fa fa-external-link" aria-hidden="true"></i></a>
'@)

    if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
        $startConsumption = Get-Date
        Write-Host '  processing TenantSummary Consumption'

        if (($arrayConsumptionData | Measure-Object).Count -gt 0) {
            $tfCount = ($arrayConsumptionData | Measure-Object).Count
            $htmlTableId = 'TenantSummary_Consumption'
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_Consumption"><i class="padlx fa fa-credit-card blue" aria-hidden="true"></i> <span class="valignMiddle">Total cost $($arrayTotalCostSummary -join "$CsvDelimiterOpposite ") last $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>ChargeType</th>
<th>ResourceType</th>
<th>Category</th>
<th>ResourceCount</th>
<th>Cost ($($AzureConsumptionPeriod)d)</th>
<th>Currency</th>
<th>Subscriptions</th>
</tr>
</thead>
<tbody>
"@)
            $htmlSUMMARYConsumption = $null
            $htmlSUMMARYConsumption = foreach ($consumptionLine in $arrayConsumptionData) {
                @"
<tr>
<td>$($consumptionLine.ConsumedServiceChargeType)</td>
<td>$($consumptionLine.ResourceType)</td>
<td>$($consumptionLine.ConsumedServiceCategory)</td>
<td>$($consumptionLine.ConsumedServiceInstanceCount)</td>
<td>$($consumptionLine.ConsumedServiceCost)</td>
<td>$($consumptionLine.ConsumedServiceCurrency)</td>
<td>$($consumptionLine.ConsumedServiceSubscriptions)</td>
</tr>
"@
            }
            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYConsumption)
            [void]$htmlTenantSummary.AppendLine(@"
</tbody>
</table>
</div>
<script>
function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
window.helpertfConfig4$htmlTableId =1;
var tfConfig4$htmlTableId = {
base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
col_5: 'select',
col_types: [
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'number',
    'number',
    'caseinsensitivestring',
    'number'
],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
                <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No information on Consumption</p>
'@)
        }

        $endConsumption = Get-Date
        Write-Host "   TenantSummary Consumption processing duration: $((New-TimeSpan -Start $startConsumption -End $endConsumption).TotalMinutes) minutes ($((New-TimeSpan -Start $startConsumption -End $endConsumption).TotalSeconds) seconds)"

    }
    else {
        [void]$htmlTenantSummary.AppendLine(@'
            <p><i class="padlx fa fa-ban" aria-hidden="true"></i> No information on Consumption as switch parameter -DoAzureConsumption was not applied</p>
'@)
    }

    [void]$htmlTenantSummary.AppendLine(@'
</div>
'@)
    #endregion tenantSummaryConsumption

    showMemoryUsage

    #region tenantSummaryChangeTracking
    Write-Host '  processing TenantSummary ChangeTracking'
    $startChangeTracking = Get-Date
    $xdaysAgo = (Get-Date).AddDays(-$ChangeTrackingDays)

    #region ctpolicydata
    Write-Host '   processing Policy'
    $customPolicyCreatedOrUpdated = ($customPoliciesDetailed.where( { (-not [string]::IsNullOrEmpty($_.CreatedOn) -and [datetime]$_.CreatedOn -gt $xdaysAgo) -or (-not [string]::IsNullOrEmpty($_.UpdatedOn) -and [datetime]$_.UpdatedOn -gt $xdaysAgo) }))
    $customPolicyCreatedOrUpdatedCount = $customPolicyCreatedOrUpdated.Count
    $customPolicyCreatedMgSub = ($customPolicyCreatedOrUpdated.where( { -not [string]::IsNullOrEmpty($_.CreatedOn) -and [datetime]$_.CreatedOn -gt $xdaysAgo }))
    $customPolicyCreatedMg = ($customPolicyCreatedMgSub.where( { $_.Scope -eq 'Mg' }))
    $customPolicyCreatedMgCount = ($customPolicyCreatedMg).count
    $customPolicyCreatedSub = ($customPolicyCreatedMgSub.where( { $_.Scope -eq 'Sub' }))
    $customPolicyCreatedSubCount = ($customPolicyCreatedSub).count

    $customPolicyUpdatedMgSub = ($customPolicyCreatedOrUpdated.where( { -not [string]::IsNullOrEmpty($_.UpdatedOn) -and [datetime]$_.UpdatedOn -gt $xdaysAgo }))
    $customPolicyUpdatedMg = ($customPolicyUpdatedMgSub.where( { $_.Scope -eq 'Mg' }))
    $customPolicyUpdatedMgCount = ($customPolicyUpdatedMg).count
    $customPolicyUpdatedSub = ($customPolicyUpdatedMgSub.where( { $_.Scope -eq 'Sub' }))
    $customPolicyUpdatedSubCount = ($customPolicyUpdatedSub).count
    #endregion ctpolicydata

    #region ctpolicySetdata
    Write-Host '   processing PolicySet'
    $customPolicySetCreatedOrUpdated = ($customPolicySetsDetailed.where( { (-not [string]::IsNullOrEmpty($_.CreatedOn) -and [datetime]$_.CreatedOn -gt $xdaysAgo) -or (-not [string]::IsNullOrEmpty($_.UpdatedOn) -and [datetime]$_.UpdatedOn -gt $xdaysAgo) }))
    $customPolicySetCreatedOrUpdatedCount = $customPolicySetCreatedOrUpdated.Count

    $customPolicySetCreatedMgSub = ($customPolicySetCreatedOrUpdated.where( { -not [string]::IsNullOrEmpty($_.CreatedOn) -and [datetime]$_.CreatedOn -gt $xdaysAgo }))
    $customPolicySetCreatedMg = ($customPolicySetCreatedMgSub.where( { $_.Scope -eq 'Mg' }))
    $customPolicySetCreatedMgCount = ($customPolicySetCreatedMg).count
    $customPolicySetCreatedSub = ($customPolicySetCreatedMgSub.where( { $_.Scope -eq 'Sub' }))
    $customPolicySetCreatedSubCount = ($customPolicySetCreatedSub).count

    $customPolicySetUpdatedMgSub = ($customPolicySetCreatedOrUpdated.where( { -not [string]::IsNullOrEmpty($_.UpdatedOn) -and [datetime]$_.UpdatedOn -gt $xdaysAgo }))
    $customPolicySetUpdatedMg = ($customPolicySetUpdatedMgSub.where( { $_.Scope -eq 'Mg' }))
    $customPolicySetUpdatedMgCount = ($customPolicySetUpdatedMg).count
    $customPolicySetUpdatedSub = ($customPolicySetUpdatedMgSub.where( { $_.Scope -eq 'Sub' }))
    $customPolicySetUpdatedSubCount = ($customPolicySetUpdatedSub).count
    #endregion ctpolicySetdata

    #region ctpolicyAssignmentsData
    Write-Host '   processing Policy assignment'
    $policyAssignmentsCreatedOrUpdated = (($arrayPolicyAssignmentsEnriched.where( { $_.Inheritance -notlike 'inherited*' } )).where( { (-not [string]::IsNullOrEmpty($_.CreatedOn) -and [datetime]$_.CreatedOn -gt $xdaysAgo) -or (-not [string]::IsNullOrEmpty($_.UpdatedOn) -and [datetime]$_.UpdatedOn -gt $xdaysAgo) }))
    $policyAssignmentsCreatedOrUpdatedCount = $policyAssignmentsCreatedOrUpdated.Count

    $policyAssignmentsCreatedMgSub = $policyAssignmentsCreatedOrUpdated.where( { (-not [string]::IsNullOrEmpty($_.CreatedOn) -and [datetime]$_.CreatedOn -gt $xdaysAgo) })
    $policyAssignmentsCreatedMg = ($policyAssignmentsCreatedMgSub.where( { $_.mgOrSubOrRG -eq 'Mg' }))
    $policyAssignmentsCreatedMgCount = ($policyAssignmentsCreatedMg).count
    $policyAssignmentsCreatedSub = ($policyAssignmentsCreatedMgSub.where( { $_.mgOrSubOrRG -eq 'Sub' }))
    $policyAssignmentsCreatedSubCount = ($policyAssignmentsCreatedSub).count
    if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy) {
        $policyAssignmentsCreatedRg = ($policyAssignmentsUpdatedMgSub.where( { $_.mgOrSubOrRG -eq 'RG' }))
        $policyAssignmentsCreatedRgCount = ($policyAssignmentsCreatedRg).count
    }

    $policyAssignmentsUpdatedMgSub = $policyAssignmentsCreatedOrUpdated.where( { (-not [string]::IsNullOrEmpty($_.UpdatedOn) -and [datetime]$_.UpdatedOn -gt $xdaysAgo) })
    $policyAssignmentsUpdatedMg = ($policyAssignmentsUpdatedMgSub.where( { $_.mgOrSubOrRG -eq 'Mg' }))
    $policyAssignmentsUpdatedMgCount = ($policyAssignmentsUpdatedMg).count
    $policyAssignmentsUpdatedSub = ($policyAssignmentsUpdatedMgSub.where( { $_.mgOrSubOrRG -eq 'Sub' }))
    $policyAssignmentsUpdatedSubCount = ($policyAssignmentsUpdatedSub).count
    if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy) {
        $policyAssignmentsUpdatedRg = ($policyAssignmentsUpdatedMgSub.where( { $_.mgOrSubOrRG -eq 'RG' }))
        $policyAssignmentsUpdatedRgCount = ($policyAssignmentsUpdatedRg).count
    }


    if ($customPolicyCreatedOrUpdatedCount -gt 0 -or $customPolicySetCreatedOrUpdatedCount -gt 0 -or $policyAssignmentsCreatedOrUpdatedCount -gt 0) {
        $ctContenIndicatorPolicy = 'ctContenPolicyTrue'
        if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy) {
            $policyAssignmentSummaryCt = "(Mg: C:$($policyAssignmentsCreatedMgCount), U:$($policyAssignmentsUpdatedMgCount); Sub: C:$($policyAssignmentsCreatedSubCount), U:$($policyAssignmentsUpdatedSubCount)); RG: C:$($policyAssignmentsCreatedRgCount), U:$($policyAssignmentsUpdatedRgCount)"
        }
        else {
            $policyAssignmentSummaryCt = "(Mg: C:$($policyAssignmentsCreatedMgCount), U:$($policyAssignmentsUpdatedMgCount); Sub: C:$($policyAssignmentsCreatedSubCount), U:$($policyAssignmentsUpdatedSubCount))"
        }

    }
    else {
        $ctContenIndicatorPolicy = 'ctContenPolicyFalse'
        $policyAssignmentSummaryCt = ''
    }
    #endregion ctpolicyAssignmentsData

    ##RBAC
    #region ctRbacData
    #rbac defs
    Write-Host '   processing RBAC'
    $customRoleDefinitionsCreatedOrUpdated = $tenantCustomRoles.where( { $_.IsCustom -eq $true -and $_.Json.properties.createdOn -gt $xdaysAgo -or $_.Json.properties.updatedOn -gt $xdaysAgo })
    $customRoleDefinitionsCreatedOrUpdatedCount = $customRoleDefinitionsCreatedOrUpdated.Count

    #rbac defs created
    Write-Host '   processing RBAC Role definition created'
    $customRoleDefinitionsCreated = $customRoleDefinitionsCreatedOrUpdated.where( { $_.Json.properties.createdOn -gt $xdaysAgo })
    $customRoleDefinitionsCreatedCount = $customRoleDefinitionsCreated.Count

    #rbac defs updated
    Write-Host '   processing RBAC Role definition updated'
    $customRoleDefinitionsUpdated = $customRoleDefinitionsCreatedOrUpdated.where( { $_.Json.properties.updatedOn -ne $_.Json.properties.createdOn -and $_.Json.properties.updatedOn -gt $xdaysAgo })
    $customRoleDefinitionsUpdatedCount = $customRoleDefinitionsUpdated.Count
    #endregion ctRbacData

    #region ctrbacassignments
    #rbac roleassignments
    Write-Host '   processing RBAC Role assignments'
    $roleAssignmentsCreated = ($rbacAll | Sort-Object -Property RoleAssignmentId, ObjectId -Unique).where( { -not [string]::IsNullOrEmpty($_.CreatedOn) -and [datetime]$_.CreatedOn -gt $xdaysAgo })
    $roleAssignmentsCreatedUnique = ($roleAssignmentsCreated | Sort-Object -Property RoleAssignmentId -Unique)
    $roleAssignmentsCreatedCount = ($roleAssignmentsCreated | Sort-Object -Property RoleAssignmentId -Unique).Count
    $roleAssignmentsCreatedImpactedIdentitiesCount = $roleAssignmentsCreated.Count

    #rbac assignments createdMg
    $roleAssignmentsCreatedMg = $roleAssignmentsCreatedUnique.where( { $_.ScopeTenOrMgOrSubOrRGOrRes -eq 'MG' -or $_.ScopeTenOrMgOrSubOrRGOrRes -eq 'Ten' })
    $roleAssignmentsCreatedMgCount = $roleAssignmentsCreatedMg.Count
    #rbac assignments createdSub
    $roleAssignmentsCreatedSub = $roleAssignmentsCreatedUnique.where( { $_.ScopeTenOrMgOrSubOrRGOrRes -eq 'Sub' })
    $roleAssignmentsCreatedSubCount = $roleAssignmentsCreatedSub.Count
    if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC) {
        $roleAssignmentsCreatedSubRg = $roleAssignmentsCreatedUnique.where( { $_.ScopeTenOrMgOrSubOrRGOrRes -eq 'RG' })
        $roleAssignmentsCreatedSubRgCount = $roleAssignmentsCreatedSubRg.Count
        $roleAssignmentsCreatedSubRgRes = $roleAssignmentsCreatedUnique.where( { $_.ScopeTenOrMgOrSubOrRGOrRes -eq 'Res' })
        $roleAssignmentsCreatedSubRgResCount = $roleAssignmentsCreatedSubRgRes.Count
    }

    if ($customRoleDefinitionsCreatedOrUpdatedCount -gt 0 -or $roleAssignmentsCreatedCount -gt 0) {
        $ctContenIndicatorRBAC = 'ctContenRBACTrue'
        if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC) {
            $rbacAssignmentSummaryCt = "(Mg: $roleAssignmentsCreatedMgCount; Sub: $roleAssignmentsCreatedSubCount; RG: $roleAssignmentsCreatedSubRgCount; Res: $roleAssignmentsCreatedSubRgResCount)"
        }
        else {
            $rbacAssignmentSummaryCt = "(Mg: $roleAssignmentsCreatedMgCount; Sub: $roleAssignmentsCreatedSubCount)"
        }
    }
    else {
        $ctContenIndicatorRBAC = 'ctContenRBACFalse'
        $rbacAssignmentSummaryCt = ''
    }
    #endregion ctrbacassignments


    if ($azAPICallConf['htParameters'].NoResources -eq $false) {
        #region ctresources
        Write-Host '   processing Resources'
        $resourcesCreatedOrChanged = $resourcesIdsAll.where( { $_.createdTime -gt $xdaysAgo -or $_.changedTime -gt $xdaysAgo })
        $resourcesCreatedOrChangedCount = $resourcesCreatedOrChanged.Count

        $resourcesCreatedAndChanged = $resourcesIdsAll.where( { $_.createdTime -gt $xdaysAgo -and $_.changedTime -gt $xdaysAgo })
        $resourcesCreatedAndChangedCount = $resourcesCreatedAndChanged.Count

        $resourcesCreated = $resourcesCreatedOrChanged.where( { $_.createdTime -gt $xdaysAgo })
        $resourcesCreatedCount = $resourcesCreated.Count
        $resourcesChanged = $resourcesCreatedOrChanged.where( { $_.changedTime -gt $xdaysAgo })
        $resourcesChangedCount = $resourcesChanged.Count

        if ($resourcesCreatedOrChangedCount -gt 0) {
            $ctContenIndicatorResources = 'ctContenResourcesTrue'
            $resourcesCreatedOrChangedGrouped = $resourcesCreatedOrChanged | Group-Object -Property type
            $resourcesCreatedOrChangedGroupedCount = ($resourcesCreatedOrChangedGrouped | Measure-Object).Count
        }
        else {
            $ctContenIndicatorResources = 'ctContenResourcesFalse'
        }
        #endregion ctresources
    }



    [void]$htmlTenantSummary.AppendLine(@"
    <button type="button" class="collapsible" id="tenantSummaryChangeTracking"><hr class="hr-textChangeTracking" data-content="Change tracking | last $($ChangeTrackingDays) days; after $($xdaysAgo.ToString('dd-MMM-yyyy HH:mm:ss'))" /></button>
    <div class="content TenantSummaryContent">
"@)

    #region ctpolicy
    [void]$htmlTenantSummary.AppendLine(@"
    <button type="button" class="collapsible" id="tenantSummaryChangeTrackingPolicy"><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/10316-icon-service-Policy.svg"> <span class="$ctContenIndicatorPolicy">Policy</span></button>
    <div class="content TenantSummaryContent">
"@)

    #region ChangeTrackingCustomPolicy
    if ($customPolicyCreatedOrUpdatedCount -gt 0) {
        $tfCount = $customPolicyCreatedOrUpdatedCount
        $htmlTableId = 'TenantSummary_ChangeTrackingCustomPolicy'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_ChangeTrackingCustomPolicy"><i class="padlxx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle"> $customPolicyCreatedOrUpdatedCount Created/Updated custom Policy definitions (Mg: C:$($customPolicyCreatedMgCount), U:$($customPolicyUpdatedMgCount); Sub: C:$($customPolicyCreatedSubCount), U:$($customPolicyUpdatedSubCount))</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>Scope Id</th>
<th>Policy DisplayName</th>
<th>PolicyId</th>
<th>Category</th>
<th>Effect</th>
<th>Role definitions</th>
<th>Unique assignments</th>
<th>Used in PolicySets</th>
<th>Created/Updated</th>
<th>CreatedOn</th>
<th>CreatedBy</th>
<th>UpdatedOn</th>
<th>UpdatedBy</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYChangeTrackingCustomPolicy = $null
        $htmlSUMMARYChangeTrackingCustomPolicy = foreach ($entry in $customPolicyCreatedOrUpdated | Sort-Object -Property CreatedOn, UpdatedOn -Descending) {
            $createdOnGt = $false
            if ($entry.CreatedOn -ne '') {
                $createdOn = ($entry.CreatedOn)
                if ([datetime]($entry.CreatedOn) -gt $xdaysAgo) {
                    $createdOnGt = $true
                }
            }
            else {
                $createdOn = ''
            }

            $updatedOnGt = $false
            if ($entry.updatedOn -ne '') {
                $updatedOn = ($entry.UpdatedOn)
                if ([datetime]($entry.UpdatedOn) -gt $xdaysAgo) {
                    $updatedOnGt = $true
                }
                $updatedOnGt = $true
            }
            else {
                $updatedOn = ''
            }

            $createOnUpdatedOn = $null
            if ($createdOnGt) {
                $createOnUpdatedOn = 'Created'
            }
            if ($updatedOnGt) {
                $createOnUpdatedOn = 'Updated'
            }
            if ($createdOnGt -and $updatedOnGt) {
                $createOnUpdatedOn = 'Created&Updated'
            }

            if ($entry.UsedInPolicySetsCount -gt 0) {
                $customPolicyUsedInPolicySets = "$($entry.UsedInPolicySetsCount) ($($entry.UsedInPolicySets))"
            }
            else {
                $customPolicyUsedInPolicySets = $($entry.UsedInPolicySetsCount)
            }

            @"
<tr>
<td>$($entry.Scope)</td>
<td>$($entry.ScopeId)</td>
<td>$($entry.PolicyDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($entry.PolicyDefinitionId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($entry.PolicyCategory -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($entry.PolicyEffect)</td>
<td>$($entry.RoleDefinitions)</td>
<td class="breakwordall">$($entry.UniqueAssignments -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($customPolicyUsedInPolicySets)</td>
<td>$createOnUpdatedOn</td>
<td>$($entry.CreatedOn)</td>
<td>$($entry.CreatedBy)</td>
<td>$($entry.UpdatedOn)</td>
<td>$($entry.UpdatedBy)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYChangeTrackingCustomPolicy)
        [void]$htmlTenantSummary.AppendLine(@"
</tbody>
</table>
</div>
<script>
function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
window.helpertfConfig4$htmlTableId =1;
var tfConfig4$htmlTableId = {
base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
linked_filters: true,
col_0: 'select',
col_9: 'multiple',
locale: 'en-US',
col_types: [
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'date',
    'caseinsensitivestring',
    'date',
    'caseinsensitivestring'
],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlxx fa fa-ban" aria-hidden="true"></i> $customPolicyCreatedOrUpdatedCount Created/Updated custom Policy definitions</p>
"@)
    }
    #endregion ChangeTrackingCustomPolicy

    #region ChangeTrackingCustomPolicySet
    if ($customPolicySetCreatedOrUpdatedCount -gt 0) {
        $tfCount = $customPolicySetCreatedOrUpdatedCount
        $htmlTableId = 'TenantSummary_ChangeTrackingCustomPolicySet'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_ChangeTrackingCustomPolicySet"><i class="padlxx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle"> $customPolicySetCreatedOrUpdatedCount Created/Updated custom PolicySet definitions (Mg: C:$($customPolicySetCreatedMgCount), U:$($customPolicySetUpdatedMgCount); Sub: C:$($customPolicySetCreatedSubCount), U:$($customPolicySetUpdatedSubCount))</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>ScopeId</th>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
<th>Category</th>
<th>Unique assignments</th>
<th>Policies used in PolicySet</th>
<th>Created/Updated</th>
<th>CreatedOn</th>
<th>CreatedBy</th>
<th>UpdatedOn</th>
<th>UpdatedBy</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYChangeTrackingCustomPolicySet = $null
        $htmlSUMMARYChangeTrackingCustomPolicySet = foreach ($entry in $customPolicySetCreatedOrUpdated | Sort-Object -Property CreatedOn, UpdatedOn -Descending) {
            $createdOnGt = $false
            if ($entry.CreatedOn -ne '') {
                $createdOn = ($entry.CreatedOn)
                if ([datetime]($entry.CreatedOn) -gt $xdaysAgo) {
                    $createdOnGt = $true
                }
            }
            else {
                $createdOn = ''
            }

            $updatedOnGt = $false
            if ($entry.updatedOn -ne '') {
                $updatedOn = ($entry.UpdatedOn)
                if ([datetime]($entry.UpdatedOn) -gt $xdaysAgo) {
                    $updatedOnGt = $true
                }
                $updatedOnGt = $true
            }
            else {
                $updatedOn = ''
            }

            $createOnUpdatedOn = $null
            if ($createdOnGt) {
                $createOnUpdatedOn = 'Created'
            }
            if ($updatedOnGt) {
                $createOnUpdatedOn = 'Updated'
            }
            if ($createdOnGt -and $updatedOnGt) {
                $createOnUpdatedOn = 'Created&Updated'
            }

            @"
<tr>
<td>$($entry.Scope)</td>
<td>$($entry.ScopeId)</td>
<td>$($entry.PolicySetDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($entry.PolicySetDefinitionId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($entry.PolicySetCategory -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($entry.UniqueAssignments -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($entry.PoliciesUsed)</td>
<td>$createOnUpdatedOn</td>
<td>$($entry.CreatedOn)</td>
<td>$($entry.CreatedBy)</td>
<td>$($entry.UpdatedOn)</td>
<td>$($entry.UpdatedBy)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYChangeTrackingCustomPolicySet)
        [void]$htmlTenantSummary.AppendLine(@"
</tbody>
</table>
</div>
<script>
function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
window.helpertfConfig4$htmlTableId =1;
var tfConfig4$htmlTableId = {
base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
linked_filters: true,
col_0: 'select',
col_7: 'multiple',
locale: 'en-US',
col_types: [
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'date',
    'caseinsensitivestring',
    'date',
    'caseinsensitivestring'
],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlxx fa fa-ban" aria-hidden="true"></i> $customPolicySetCreatedOrUpdatedCount Created/Updated custom PolicySet definitions</p>
"@)
    }
    #endregion ChangeTrackingCustomPolicySet

    #region ChangeTrackingPolicyAssignments
    if ($policyAssignmentsCreatedOrUpdatedCount -gt 0) {
        $tfCount = $policyAssignmentsCreatedOrUpdatedCount
        $htmlTableId = 'TenantSummary_ChangeTrackingPolicyAssignments'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_ChangeTrackingPolicyAssignments"><i class="padlxx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle"> $policyAssignmentsCreatedOrUpdatedCount Created/Updated Policy assignments ($policyAssignmentSummaryCt)</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>Management Group Id</th>
<th>Management Group Name</th>
<th>SubscriptionId</th>
<th>Subscription Name</th>
<th>Inheritance</th>
<th>ScopeExcluded</th>
<th>Exemption applies</th>
<th>Policy/Set DisplayName</th>
<th>Policy/Set Description</th>
<th>Policy/SetId</th>
<th>Policy/Set</th>
<th>Type</th>
<th>Category</th>
<th>Effect</th>
<th>Parameters</th>
<th>Enforcement</th>
<th>NonCompliance Message</th>
"@)

        if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {
            [void]$htmlTenantSummary.AppendLine(@'
<th>Policies NonCmplnt</th>
<th>Policies Compliant</th>
<th>Resources NonCmplnt</th>
<th>Resources Compliant</th>
<th>Resources Conflicting</th>
'@)
        }

        [void]$htmlTenantSummary.AppendLine(@"
<th>Role/Assignment $noteOrNot</th>
<th>Assignment DisplayName</th>
<th>Assignment Description</th>
<th>AssignmentId</th>
<th>Created/Updated</th>
<th>AssignedBy</th>
<th>CreatedOn</th>
<th>CreatedBy</th>
<th>UpdatedOn</th>
<th>UpdatedBy</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYChangeTrackingPolicyAssignments = $null
        $htmlSUMMARYChangeTrackingPolicyAssignments = foreach ($policyAssignment in $policyAssignmentsCreatedOrUpdated | Sort-Object -Property CreatedOn, UpdatedOn -Descending) {
            $createdOnGt = $false
            if ($policyAssignment.CreatedOn -ne '') {
                $createdOn = ($policyAssignment.CreatedOn)
                if ([datetime]($policyAssignment.CreatedOn) -gt $xdaysAgo) {
                    $createdOnGt = $true
                }
            }
            else {
                $createdOn = ''
            }

            $updatedOnGt = $false
            if ($policyAssignment.updatedOn -ne '') {
                $updatedOn = ($policyAssignment.UpdatedOn)
                if ([datetime]($policyAssignment.UpdatedOn) -gt $xdaysAgo) {
                    $updatedOnGt = $true
                }
                $updatedOnGt = $true
            }
            else {
                $updatedOn = ''
            }

            $createOnUpdatedOn = $null
            if ($createdOnGt) {
                $createOnUpdatedOn = 'Created'
            }
            if ($updatedOnGt) {
                $createOnUpdatedOn = 'Updated'
            }
            if ($createdOnGt -and $updatedOnGt) {
                $createOnUpdatedOn = 'Created&Updated'
            }

            if ($policyAssignment.PolicyType -eq 'Custom') {
                $policyName = ($policyAssignment.PolicyName -replace '<', '&lt;' -replace '>', '&gt;')
            }
            else {
                $policyName = $policyAssignment.PolicyName
            }

            @"
<tr>
<td>$($policyAssignment.mgOrSubOrRG)</td>
<td>$($policyAssignment.MgId)</td>
<td>$($policyAssignment.MgName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policyAssignment.SubscriptionId)</td>
<td>$($policyAssignment.SubscriptionName)</td>
<td>$($policyAssignment.Inheritance)</td>
<td>$($policyAssignment.ExcludedScope)</td>
<td>$($policyAssignment.ExemptionScope)</td>
<td>$($policyName)</td>
<td>$($policyAssignment.PolicyDescription -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($policyAssignment.PolicyId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policyAssignment.PolicyVariant)</td>
<td>$($policyAssignment.PolicyType)</td>
<td>$($policyAssignment.PolicyCategory -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policyAssignment.Effect)</td>
<td>$($policyAssignment.PolicyAssignmentParameters)</td>
<td>$($policyAssignment.PolicyAssignmentEnforcementMode)</td>
<td>$($policyAssignment.PolicyAssignmentNonComplianceMessages)</td>
"@

            if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {
                @"
<td>$($policyAssignment.NonCompliantPolicies)</td>
<td>$($policyAssignment.CompliantPolicies)</td>
<td>$($policyAssignment.NonCompliantResources)</td>
<td>$($policyAssignment.CompliantResources)</td>
<td>$($policyAssignment.ConflictingResources)</td>
"@
            }

            @"
<td class="breakwordall">$($policyAssignment.RelatedRoleAssignments)</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentDescription -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$createOnUpdatedOn</td>
<td>$($policyAssignment.AssignedBy)</td>
<td>$($policyAssignment.CreatedOn)</td>
<td>$($policyAssignment.CreatedBy)</td>
<td>$($policyAssignment.UpdatedOn)</td>
<td>$($policyAssignment.UpdatedBy)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYChangeTrackingPolicyAssignments)
        [void]$htmlTenantSummary.AppendLine(@"
</tbody>
</table>
</div>
<script>
function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
window.helpertfConfig4$htmlTableId =1;
var tfConfig4$htmlTableId = {
base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@'
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
linked_filters: true,
col_0: 'select',
            col_6: 'select',
            col_7: 'select',
            col_11: 'select',
            col_12: 'select',
            col_14: 'select',
            col_16: 'select',
'@)
        if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {
            [void]$htmlTenantSummary.AppendLine(@'
                col_27: 'multiple',
'@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
                col_22: 'multiple',
'@)
        }
        [void]$htmlTenantSummary.AppendLine(@'
            locale: 'en-US',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
'@)

        if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {
            [void]$htmlTenantSummary.AppendLine(@'
                'number',
                'number',
                'number',
                'number',
                'number',
'@)
        }

        [void]$htmlTenantSummary.AppendLine(@'
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'date',
                'caseinsensitivestring',
                'date',
                'caseinsensitivestring'
            ],
'@)

        if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {
            [void]$htmlTenantSummary.AppendLine(@'
            watermark: ['', '', '', 'try [nonempty]', '', 'thisScope', '', '', '', '', '', '','', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
'@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
            watermark: ['', '', '', 'try [nonempty]', '', 'thisScope', '', '', '', '', '', '','', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
'@)
        }

        [void]$htmlTenantSummary.AppendLine(@'
        extensions: [
            {
                name: 'colsVisibility',
'@)

        if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {
            [void]$htmlTenantSummary.AppendLine(@'
                at_start: [9, 23, 24],
'@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@'
                at_start: [9, 18, 19],
'@)
        }

        [void]$htmlTenantSummary.AppendLine(@"
                text: 'Columns: ',
                enable_tick_all: true
            },
            { name: 'sort'
            }
        ]
    };
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlxx fa fa-ban" aria-hidden="true"></i> $policyAssignmentsCreatedOrUpdatedCount Created/Updated Policy assignments</p>
"@)
    }
    #endregion ChangeTrackingPolicyAssignments

    [void]$htmlTenantSummary.AppendLine(@'
</div>
'@)

    #endregion ctpolicy

    #region ctrbac
    [void]$htmlTenantSummary.AppendLine(@"
<button type="button" class="collapsible" id="tenantSummaryChangeTrackingRBAC"><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/rbacrole.svg"> <span class="$ctContenIndicatorRBAC">RBAC</span></button>
<div class="content TenantSummaryContent">
"@)

    #region ChangeTrackingCustomRoles
    if ($customRoleDefinitionsCreatedOrUpdatedCount -gt 0) {
        $tfCount = $customRoleDefinitionsCreatedOrUpdatedCount
        $htmlTableId = 'TenantSummary_ChangeTrackingCustomRoles'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_ChangeTrackingCustomRoles"><i class="padlxx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle"> $customRoleDefinitionsCreatedOrUpdatedCount Created/Updated custom Role definitions (Created: $customRoleDefinitionsCreatedCount; Updated: $customRoleDefinitionsUpdatedCount)</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Assignable Scopes</th>
<th>Data</th>
<th>Created/Updated</th>
<th>CreatedOn</th>
<th>CreatedBy</th>
<th>UpdatedOn</th>
<th>UpdatedBy</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYChangeTrackingCustomRoles = $null
        $htmlSUMMARYChangeTrackingCustomRoles = foreach ($entry in $customRoleDefinitionsCreatedOrUpdated | Sort-Object @{Expression = { $_.Json.properties.createdOn } }, @{Expression = { $_.Json.properties.updatedOn } } -Descending) {
            $createdBy = $entry.Json.properties.createdBy
            if ($htIdentitiesWithRoleAssignmentsUnique.($createdBy)) {
                $createdBy = $htIdentitiesWithRoleAssignmentsUnique.($createdBy).details
            }

            $createdOn = $entry.Json.properties.createdOn
            $createdOnFormated = $createdOn
            $createdOnUpdatedOn = 'Created'

            $updatedOn = $entry.Json.properties.updatedOn
            if ($updatedOn -eq $createdOn) {
                $updatedOnFormated = ''
                $updatedByRemoveNoiseOrNot = ''
            }
            else {
                if ($createdOn -gt $xdaysAgo) {
                    $createdOnUpdatedOn = 'Created&Updated'
                }
                else {
                    $createdOnUpdatedOn = 'Updated'
                }
                $updatedOnFormated = $updatedOn
                $updatedByRemoveNoiseOrNot = $entry.Json.properties.updatedBy
                if ($htIdentitiesWithRoleAssignmentsUnique.($updatedByRemoveNoiseOrNot)) {
                    $updatedByRemoveNoiseOrNot = $htIdentitiesWithRoleAssignmentsUnique.($updatedByRemoveNoiseOrNot).details
                }
            }

            @"
<tr>
<td>$($entry.Name -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($entry.Id)</td>
<td>$(($entry.AssignableScopes | Measure-Object).count) ($($entry.AssignableScopes -join "$CsvDelimiterOpposite "))</td>
<td>$($roleManageData)</td>
<td>$createdOnUpdatedOn</td>
<td>$createdOnFormated</td>
<td>$createdBy</td>
<td>$updatedOnFormated</td>
<td>$updatedByRemoveNoiseOrNot</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYChangeTrackingCustomRoles)
        [void]$htmlTenantSummary.AppendLine(@"
</tbody>
</table>
</div>
<script>
function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
window.helpertfConfig4$htmlTableId =1;
var tfConfig4$htmlTableId = {
base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
linked_filters: true,
col_3: 'select',
col_4: 'select',
locale: 'en-US',
col_types: [
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'date',
    'caseinsensitivestring',
    'date',
    'caseinsensitivestring'
],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlxx fa fa-ban" aria-hidden="true"></i> $customRoleDefinitionsCreatedOrUpdatedCount Created/Updated custom Role definitions</p>
"@)
    }
    #endregion ChangeTrackingCustomRoles

    #region ChangeTrackingRoleAssignments
    if ($roleAssignmentsCreatedCount -gt 0) {
        $tfCount = $roleAssignmentsCreatedCount
        $htmlTableId = 'TenantSummary_ChangeTrackingRoleAssignments'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_ChangeTrackingRoleAssignments"><i class="padlxx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle"> $roleAssignmentsCreatedCount Created Role assignments $rbacAssignmentSummaryCt (impacted identities: $roleAssignmentsCreatedImpactedIdentitiesCount)</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>Role</th>
<th>Role Id</th>
<th>Role Type</th>
<th>Data</th>
<th>Identity Displayname</th>
<th>Identity SignInName</th>
<th>Identity ObjectId</th>
<th>Identity Type</th>
<th>Applicability</th>
<th>Applies through membership <abbr title="Note: the identity might not be a direct member of the group it could also be member of a nested group"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></th>
<th>Group Details</th>
<th>PIM</th>
<th>PIM assignment type</th>
<th>PIM start</th>
<th>PIM end</th>
<th>Role AssignmentId</th>
<th>Related Policy Assignment $noteOrNot</th>
<th>CreatedOn</th>
<th>CreatedBy</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYChangeTrackingRoleAssignments = $null
        $htmlSUMMARYChangeTrackingRoleAssignments = [System.Text.StringBuilder]::new()
        foreach ($entry in $roleAssignmentsCreated | Sort-Object -Property CreatedOn -Descending) {
            if ($entry.RoleType -eq 'Custom') {
                $roleName = ($entry.Role -replace '<', '&lt;' -replace '>', '&gt;')
            }
            else {
                $roleName = $entry.Role
            }
            [void]$htmlSUMMARYChangeTrackingRoleAssignments.AppendFormat(
                @'
<tr>
<td>{0}</td>
<td>{1}</td>
<td>{2}</td>
<td>{3}</td>
<td>{4}</td>
<td class="breakwordall">{5}</td>
<td class="breakwordall">{6}</td>
<td class="breakwordall">{7}</td>
<td>{8}</td>
<td>{9}</td>
<td>{10}</td>
<td>{11}</td>
<td>{12}</td>
<td>{13}</td>
<td>{14}</td>
<td>{15}</td>
<td class="breakwordall">{16}</td>
<td class="breakwordall">{17}</td>
<td class="breakwordall">{18}</td>
<td class="breakwordall">{19}</td>
</tr>
'@, $entry.ScopeTenOrMgOrSubOrRGOrRes,
                $roleName,
                $entry.RoleId,
                $entry.RoleType,
                $entry.RoleDataRelated,
                $entry.ObjectDisplayName,
                $entry.ObjectSignInName,
                $entry.ObjectId,
                $entry.ObjectType,
                $entry.AssignmentType,
                $entry.AssignmentInheritFrom,
                $entry.GroupMembersCount,
                $entry.RoleAssignmentPIMRelated,
                $entry.RoleAssignmentPIMAssignmentType,
                $entry.RoleAssignmentPIMAssignmentSlotStart,
                $entry.RoleAssignmentPIMAssignmentSlotEnd,
                $entry.RoleAssignmentId,
                #($entry.RbacRelatedPolicyAssignment -replace '<', '&lt;' -replace '>', '&gt;'),
                $entry.RbacRelatedPolicyAssignment,
                $entry.CreatedOn,
                $entry.CreatedBy
            )
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYChangeTrackingRoleAssignments)
        [void]$htmlTenantSummary.AppendLine(@"
</tbody>
</table>
</div>
<script>
function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
window.helpertfConfig4$htmlTableId =1;
var tfConfig4$htmlTableId = {
base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
linked_filters: true,
col_0: 'select',
col_3: 'select',
col_4: 'select',
col_8: 'multiple',
col_9: 'select',
col_12: 'select',
col_13: 'select',
locale: 'en-US',
col_types: [
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'date',
    'date',
    'caseinsensitivestring',
    'caseinsensitivestring',
    'date',
    'caseinsensitivestring'
],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
            <p><i class="padlxx fa fa-ban" aria-hidden="true"></i> $customRoleDefinitionsCreatedOrUpdatedCount Created/Updated custom Role definitions</p>
"@)
    }
    #endregion ChangeTrackingRoleAssignments

    [void]$htmlTenantSummary.AppendLine(@'
</div>
'@)

    #endregion ctrbac

    if ($azAPICallConf['htParameters'].NoResources -eq $false) {
        #region ctresources
        [void]$htmlTenantSummary.AppendLine(@"
<button type="button" class="collapsible" id="tenantSummaryChangeTrackingResources"><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/10001-icon-service-All-Resources.svg"> <span class="$ctContenIndicatorResources">Resources</span></button>
<div class="content TenantSummaryContent">
"@)

        #region ChangeTrackingResources
        if ($resourcesCreatedOrChangedCount -gt 0) {
            $tfCount = $resourcesCreatedOrChangedGroupedCount
            $htmlTableId = 'TenantSummary_ChangeTrackingResources'
            [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_ChangeTrackingResources"><i class="padlxx fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle"> $resourcesCreatedOrChangedCount Created/Changed Resources ($resourcesCreatedOrChangedGroupedCount ResourceTypes) (Created&Changed: $resourcesCreatedAndChangedCount; Created: $resourcesCreatedCount; Changed: $resourcesChangedCount)</span></button>
<div class="content TenantSummary">
<i class="padlxxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>ResourceType</th>
<th>Resource Count</th>
<th>Created&Changed</th>
<th>Created&Changed Subs</th>
<th>Created</th>
<th>Created Subs</th>
<th>Changed</th>
<th>Changed Subs</th>
</tr>
</thead>
<tbody>
"@)
            $htmlSUMMARYChangeTrackingResources = $null
            $htmlSUMMARYChangeTrackingResources = foreach ($entry in $resourcesCreatedOrChangedGrouped) {
                $createdAndChanged = $entry.group.where( { $_.createdTime -gt $xdaysAgo -and $_.changedTime -gt $xdaysAgo })
                $createdAndChangedCount = $createdAndChanged.Count
                $createdAndChangedInSubscriptionsCount = ($createdAndChanged | Group-Object -Property subscriptionId | Measure-Object).Count

                $created = $entry.group.where( { $_.createdTime -gt $xdaysAgo })
                $createdCount = $created.Count
                $createdInSubscriptionsCount = ($created | Group-Object -Property subscriptionId | Measure-Object).Count

                $changed = $entry.group.where( { $_.changedTime -gt $xdaysAgo })
                $changedCount = $changed.Count
                $changedInSubscriptionsCount = ($changed | Group-Object -Property subscriptionId | Measure-Object).Count

                @"
<tr>
<td>$($entry.Name)</td>
<td>$($entry.Count)</td>
<td>$($createdAndChangedCount)</td>
<td>$($createdAndChangedInSubscriptionsCount)</td>
<td>$($createdCount)</td>
<td>$($createdInSubscriptionsCount)</td>
<td>$($changedCount)</td>
<td>$($changedInSubscriptionsCount)</td>
</tr>
"@
            }
            [void]$htmlTenantSummary.AppendLine($htmlSUMMARYChangeTrackingResources)
            [void]$htmlTenantSummary.AppendLine(@"
</tbody>
</table>
</div>
<script>
function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
window.helpertfConfig4$htmlTableId =1;
var tfConfig4$htmlTableId = {
base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
col_types: [
    'caseinsensitivestring',
    'number',
    'number',
    'number',
    'number',
    'number',
    'number',
    'number'
],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
"@)
        }
        else {
            [void]$htmlTenantSummary.AppendLine(@"
                <p><i class="padlxx fa fa-ban" aria-hidden="true"></i> $resourcesCreatedOrChangedCount Created/Changed Resources</p>
"@)
        }
        #endregion ChangeTrackingResources

        [void]$htmlTenantSummary.AppendLine(@'
</div>
'@)

        #endregion ctresources
    }

    [void]$htmlTenantSummary.AppendLine(@'
</div>
'@)

    $endChangeTracking = Get-Date
    Write-Host "   ChangeTracking duration: $((New-TimeSpan -Start $startChangeTracking -End $endChangeTracking).TotalMinutes) minutes ($((New-TimeSpan -Start $startChangeTracking -End $endChangeTracking).TotalSeconds) seconds)"
    #endregion tenantSummaryChangeTracking

    showMemoryUsage

    #region tenantSummaryNaming
    [void]$htmlTenantSummary.AppendLine(@'
    <button type="button" class="collapsible" id="tenantSummaryFindings"><hr class="hr-textFindings" data-content="Findings" /></button>
    <div class="content TenantSummaryContent">
'@)

    $startSUMMARYNaming = Get-Date
    Write-Host '  processing TenantSummary Findings'


    $namingPolicyCount = $htNamingValidation.Policy.values.count
    if ($namingPolicyCount -gt 0) {
        $tfCount = $namingPolicyCount
        $htmlTableId = 'TenantSummary_NamingPolicy'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_NamingPolicy"><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/policydefinition.svg"> <span class="valignMiddle">Policy $($namingPolicyCount) Naming findings</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Id</th>
<th>Name</th>
<th>Name Invalid chars</th>
<th>DisplayName</th>
<th>DisplayName Invalid chars</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYNamingPolicy = $null
        $cnter = 0
        $htmlSUMMARYNamingPolicy = foreach ($key in $htNamingValidation.Policy.Keys | Sort-Object) {
            $id = $key -replace '<', '&lt;' -replace '>', '&gt;'
            if ($htNamingValidation.Policy.($key).name) {
                $name = $htNamingValidation.Policy.($key).name -replace '<', '&lt;' -replace '>', '&gt;'
                $nameInvalidChars = $htNamingValidation.Policy.($key).nameInvalidChars -replace '<', '&lt;' -replace '>', '&gt;'
            }
            else {
                $name = ''
                $nameInvalidChars = ''
            }

            if ($htNamingValidation.Policy.($key).displayName) {
                $displayName = $htNamingValidation.Policy.($key).displayName -replace '<', '&lt;' -replace '>', '&gt;'
                $displayNameInvalidChars = $htNamingValidation.Policy.($key).displayNameInvalidChars -replace '<', '&lt;' -replace '>', '&gt;'
            }
            else {
                $displayName = ''
                $displayNameInvalidChars = ''
            }


            @"
<tr>
<td>$($id)</td>
<td>$($name)</td>
<td>$($nameInvalidChars)</td>
<td>$($displayName)</td>
<td>$($displayNameInvalidChars)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYNamingPolicy)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_0: 'select',
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>

"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
<p><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/policydefinition.svg"> Policy $($namingPolicyCount) Naming findings</p>
"@)
    }

    $namingPolicySetCount = $htNamingValidation.PolicySet.values.count
    if ($namingPolicySetCount -gt 0) {
        $tfCount = $namingPolicySetCount
        $htmlTableId = 'TenantSummary_NamingPolicySet'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_NamingPolicySet"><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/policysetdefinition.svg"> <span class="valignMiddle">PolicySet $($namingPolicySetCount) Naming findings</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Id</th>
<th>Name</th>
<th>Name Invalid chars</th>
<th>DisplayName</th>
<th>DisplayName Invalid chars</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYNamingPolicySet = $null
        $cnter = 0
        $htmlSUMMARYNamingPolicySet = foreach ($key in $htNamingValidation.PolicySet.Keys | Sort-Object) {
            $id = $key -replace '<', '&lt;' -replace '>', '&gt;'
            if ($htNamingValidation.PolicySet.($key).name) {
                $name = $htNamingValidation.PolicySet.($key).name -replace '<', '&lt;' -replace '>', '&gt;'
                $nameInvalidChars = $htNamingValidation.PolicySet.($key).nameInvalidChars -replace '<', '&lt;' -replace '>', '&gt;'
            }
            else {
                $name = ''
                $nameInvalidChars = ''
            }

            if ($htNamingValidation.PolicySet.($key).displayName) {
                $displayName = $htNamingValidation.PolicySet.($key).displayName -replace '<', '&lt;' -replace '>', '&gt;'
                $displayNameInvalidChars = $htNamingValidation.PolicySet.($key).displayNameInvalidChars -replace '<', '&lt;' -replace '>', '&gt;'
            }
            else {
                $displayName = ''
                $displayNameInvalidChars = ''
            }


            @"
<tr>
<td>$($id)</td>
<td>$($name)</td>
<td>$($nameInvalidChars)</td>
<td>$($displayName)</td>
<td>$($displayNameInvalidChars)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYNamingPolicySet)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>

"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
<p><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/policysetdefinition.svg"> PolicySet $($namingPolicySetCount) Naming findings</p>
"@)
    }

    $namingPolicyAssignmentCount = $htNamingValidation.PolicyAssignment.values.count
    if ($namingPolicyAssignmentCount -gt 0) {
        $tfCount = $namingPolicyAssignmentCount
        $htmlTableId = 'TenantSummary_NamingPolicyAssignment'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_NamingPolicyAssignment"><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/policyassignment.svg"> <span class="valignMiddle">Policy assignment $($namingPolicyAssignmentCount) Naming findings</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Id</th>
<th>Name</th>
<th>Name Invalid chars</th>
<th>DisplayName</th>
<th>DisplayName Invalid chars</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYNamingPolicyAssignment = $null
        $cnter = 0
        $htmlSUMMARYNamingPolicyAssignment = foreach ($key in $htNamingValidation.PolicyAssignment.Keys | Sort-Object) {
            $id = $key -replace '<', '&lt;' -replace '>', '&gt;'
            if ($htNamingValidation.PolicyAssignment.($key).name) {
                $name = $htNamingValidation.PolicyAssignment.($key).name -replace '<', '&lt;' -replace '>', '&gt;'
                $nameInvalidChars = $htNamingValidation.PolicyAssignment.($key).nameInvalidChars -replace '<', '&lt;' -replace '>', '&gt;'
            }
            else {
                $name = ''
                $nameInvalidChars = ''
            }

            if ($htNamingValidation.PolicyAssignment.($key).displayName) {
                $displayName = $htNamingValidation.PolicyAssignment.($key).displayName -replace '<', '&lt;' -replace '>', '&gt;'
                $displayNameInvalidChars = $htNamingValidation.PolicyAssignment.($key).displayNameInvalidChars -replace '<', '&lt;' -replace '>', '&gt;'
            }
            else {
                $displayName = ''
                $displayNameInvalidChars = ''
            }


            @"
<tr>
<td>$($id)</td>
<td>$($name)</td>
<td>$($nameInvalidChars)</td>
<td>$($displayName)</td>
<td>$($displayNameInvalidChars)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYNamingPolicyAssignment)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>

"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
<p><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/policyassignment.svg"> Policy assignment $($namingPolicyAssignmentCount) Naming findings</p>
"@)
    }

    $namingManagementGroupCount = $htNamingValidation.ManagementGroup.values.count
    if ($namingManagementGroupCount -gt 0) {
        $tfCount = $namingManagementGroupCount
        $htmlTableId = 'TenantSummary_NamingManagementGroup'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_NamingManagementGroup"><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> <span class="valignMiddle">Management Group $($namingManagementGroupCount) Naming findings</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Id</th>
<th>Name</th>
<th>Name Invalid chars</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYNamingManagementGroup = $null
        $cnter = 0
        $htmlSUMMARYNamingManagementGroup = foreach ($key in $htNamingValidation.ManagementGroup.Keys | Sort-Object) {
            $id = $key -replace '<', '&lt;' -replace '>', '&gt;'
            if ($htNamingValidation.ManagementGroup.($key).name) {
                $name = $htNamingValidation.ManagementGroup.($key).name -replace '<', '&lt;' -replace '>', '&gt;'
                $nameInvalidChars = $htNamingValidation.ManagementGroup.($key).nameInvalidChars -replace '<', '&lt;' -replace '>', '&gt;'
            }
            else {
                $name = ''
                $nameInvalidChars = ''
            }

            @"
<tr>
<td>$($id)</td>
<td>$($name)</td>
<td>$($nameInvalidChars)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYNamingManagementGroup)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>

"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
<p><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> Management Group $($namingManagementGroupCount) Naming findings</p>
"@)
    }


    $namingSubscriptionCount = $htNamingValidation.Subscription.values.count
    if ($namingSubscriptionCount -gt 0) {
        $tfCount = $namingSubscriptionCount
        $htmlTableId = 'TenantSummary_NamingSubscription'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_NamingSubscription"><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle">Subscription $($namingSubscriptionCount) Naming findings</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Id</th>
<th>DisplayName</th>
<th>DisplayName Invalid chars</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYNamingSubscription = $null
        $htmlSUMMARYNamingSubscription = foreach ($key in $htNamingValidation.Subscription.Keys | Sort-Object) {

            if ($htNamingValidation.Subscription.($key).displayName) {
                $displayName = $htNamingValidation.Subscription.($key).displayName -replace '<', '&lt;' -replace '>', '&gt;'
                $displayNameInvalidChars = $htNamingValidation.Subscription.($key).displayNameInvalidChars -replace '<', '&lt;' -replace '>', '&gt;'
            }
            else {
                $displayName = ''
                $displayNameInvalidChars = ''
            }

            @"
<tr>
<td>$($key)</td>
<td>$($displayName)</td>
<td>$($displayNameInvalidChars)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYNamingSubscription)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>

"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
<p><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> Subscription $($namingSubscriptionCount) Naming findings</p>
"@)
    }


    $namingRoleCount = $htNamingValidation.Role.values.count
    if ($namingRoleCount -gt 0) {
        $tfCount = $namingRoleCount
        $htmlTableId = 'TenantSummary_NamingRole'
        [void]$htmlTenantSummary.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible" id="buttonTenantSummary_NamingRole"><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/rbacrole.svg"> <span class="valignMiddle">RBAC $($namingRoleCount) Naming findings</span></button>
<div class="content TenantSummary">
<i class="padlxx fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Id</th>
<th>Name</th>
<th>Name Invalid chars</th>
</tr>
</thead>
<tbody>
"@)
        $htmlSUMMARYNamingRole = $null
        $htmlSUMMARYNamingRole = foreach ($key in $htNamingValidation.Role.Keys | Sort-Object) {

            if ($htNamingValidation.Role.($key).roleName) {
                $roleName = $htNamingValidation.Role.($key).roleName -replace '<', '&lt;' -replace '>', '&gt;'
                $roleNameInvalidChars = $htNamingValidation.Role.($key).roleNameInvalidChars -replace '<', '&lt;' -replace '>', '&gt;'
            }
            else {
                $roleName = ''
                $roleNameInvalidChars = ''
            }

            @"
<tr>
<td>$($key)</td>
<td>$($roleName)</td>
<td>$($roleNameInvalidChars)</td>
</tr>
"@
        }
        [void]$htmlTenantSummary.AppendLine($htmlSUMMARYNamingRole)
        [void]$htmlTenantSummary.AppendLine(@"
        </tbody>
    </table>
</div>
<script>
    function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@)
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            [void]$htmlTenantSummary.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlTenantSummary.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();}}
</script>

"@)
    }
    else {
        [void]$htmlTenantSummary.AppendLine(@"
<p><img class="padlx imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/rbacrole.svg"> RBAC $($namingRoleCount) Naming Findings</p>
"@)
    }

    $endSUMMARYNaming = Get-Date
    Write-Host "   SUMMARYMGs duration: $((New-TimeSpan -Start $startSUMMARYNaming -End $endSUMMARYNaming).TotalMinutes) minutes ($((New-TimeSpan -Start $startSUMMARYNaming -End $endSUMMARYNaming).TotalSeconds) seconds)"

    [void]$htmlTenantSummary.AppendLine(@'
</div>
'@)
    #endregion tenantSummaryNaming

    $script:html += $htmlTenantSummary
    $htmlTenantSummary = $null
    $script:html | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
    $script:html = $null
}