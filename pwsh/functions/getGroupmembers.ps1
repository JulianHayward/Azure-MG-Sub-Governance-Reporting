
function getGroupmembers($aadGroupId, $aadGroupDisplayName) {
    if (-not $htAADGroupsDetails.($aadGroupId)) {
        $script:htAADGroupsDetails.$aadGroupId = @{}
        $script:htAADGroupsDetails.($aadGroupId).Id = $aadGroupId
        $script:htAADGroupsDetails.($aadGroupId).displayname = $aadGroupDisplayName
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/beta/groups/$($aadGroupId)/transitiveMembers"
        $method = 'GET'
        $aadGroupMembers = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask "getGroupmembers $($aadGroupId)"

        if ($aadGroupMembers -eq 'Request_ResourceNotFound') {
            $null = $script:arrayGroupRequestResourceNotFound.Add([PSCustomObject]@{
                    groupId = $aadGroupId
                })
        }

        $aadGroupMembersAll = ($aadGroupMembers)
        $aadGroupMembersUsers = $aadGroupMembers.where( { $_.'@odata.type' -eq '#microsoft.graph.user' } )
        $aadGroupMembersGroups = $aadGroupMembers.where( { $_.'@odata.type' -eq '#microsoft.graph.group' } )
        $aadGroupMembersServicePrincipals = $aadGroupMembers.where( { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' } )

        $aadGroupMembersAllCount = $aadGroupMembersAll.count
        $aadGroupMembersUsersCount = $aadGroupMembersUsers.count
        $aadGroupMembersGroupsCount = $aadGroupMembersGroups.count
        $aadGroupMembersServicePrincipalsCount = $aadGroupMembersServicePrincipals.count
        #for SP stuff
        if ($aadGroupMembersServicePrincipalsCount -gt 0) {
            foreach ($identity in $aadGroupMembersServicePrincipals) {
                $arrayIdentityObject = [System.Collections.ArrayList]@()
                if ($identity.servicePrincipalType -eq 'Application') {
                    if ($identity.appOwnerOrganizationId -eq $azAPICallConf['checkContext'].Tenant.Id) {
                        $null = $arrayIdentityObject.Add([PSCustomObject]@{
                                type                   = 'ServicePrincipal'
                                spTypeConcatinated     = 'SP APP INT'
                                servicePrincipalType   = $identity.servicePrincipalType
                                id                     = $identity.id
                                appid                  = $identity.appId
                                displayName            = $identity.displayName
                                appOwnerOrganizationId = $identity.appOwnerOrganizationId
                                alternativeNames       = $identity.alternativeNames
                            })
                    }
                    else {
                        $null = $arrayIdentityObject.Add([PSCustomObject]@{
                                type                   = 'ServicePrincipal'
                                spTypeConcatinated     = 'SP APP EXT'
                                servicePrincipalType   = $identity.servicePrincipalType
                                id                     = $identity.id
                                appid                  = $identity.appId
                                displayName            = $identity.displayName
                                appOwnerOrganizationId = $identity.appOwnerOrganizationId
                                alternativeNames       = $identity.alternativeNames
                            })
                    }
                }
                elseif ($identity.servicePrincipalType -eq 'ManagedIdentity') {
                    $miType = 'unknown'
                    if ($identity.alternativeNames) {
                        foreach ($altName in $identity.alternativeNames) {
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
                    }
                    $null = $arrayIdentityObject.Add([PSCustomObject]@{
                            type                   = 'ServicePrincipal'
                            spTypeConcatinated     = "SP MI $miType"
                            servicePrincipalType   = $identity.servicePrincipalType
                            id                     = $identity.id
                            appid                  = $identity.appId
                            displayName            = $identity.displayName
                            appOwnerOrganizationId = $identity.appOwnerOrganizationId
                            alternativeNames       = $identity.alternativeNames
                        })
                }
                else {
                    $null = $arrayIdentityObject.Add([PSCustomObject]@{
                            type                   = 'servicePrincipal'
                            spTypeConcatinated     = "SP $($identity.servicePrincipalType)"
                            servicePrincipalType   = $identity.servicePrincipalType
                            id                     = $identity.id
                            appid                  = $identity.appId
                            displayName            = $identity.displayName
                            appOwnerOrganizationId = $identity.appOwnerOrganizationId
                            alternativeNames       = $identity.alternativeNames
                        })
                }
                if (-not $htServicePrincipals.($identity.id)) {
                    #Write-Host "$($identity.displayName) $($identity.id) added - - - - - - - - "
                    $script:htServicePrincipals.($identity.id) = @{}
                    $script:htServicePrincipals.($identity.id) = $arrayIdentityObject
                }
            }
        }

        #guests
        if ($aadGroupMembersUsersCount -gt 0) {
            $cntx = 0
            $cnty = 0
            foreach ($aadGroupMembersUser in $aadGroupMembersUsers | Sort-Object -Property id -Unique) {
                $cntx++
                if ($aadGroupMembersUser.userType -eq 'Guest') {
                    if (-not $htUserTypesGuest.($aadGroupMembersUser.id)) {
                        $cnty++
                        #Write-Host "$($aadGroupMembersUser.id) is Guest"
                        $script:htUserTypesGuest.($aadGroupMembersUser.id) = @{}
                        $script:htUserTypesGuest.($aadGroupMembersUser.id).userType = 'Guest'
                    }
                    else {
                        #Write-Host "$($aadGroupMembersUser.id) already known as Guest"
                    }
                }
            }
        }

        $script:htAADGroupsDetails.($aadGroupId).MembersAllCount = $aadGroupMembersAllCount
        $script:htAADGroupsDetails.($aadGroupId).MembersUsersCount = $aadGroupMembersUsersCount
        $script:htAADGroupsDetails.($aadGroupId).MembersGroupsCount = $aadGroupMembersGroupsCount
        $script:htAADGroupsDetails.($aadGroupId).MembersServicePrincipalsCount = $aadGroupMembersServicePrincipalsCount

        if ($aadGroupMembersAllCount -gt 0) {
            $script:htAADGroupsDetails.($aadGroupId).MembersAll = $aadGroupMembersAll

            if ($aadGroupMembersUsersCount -gt 0) {
                $script:htAADGroupsDetails.($aadGroupId).MembersUsers = $aadGroupMembersUsers
            }
            if ($aadGroupMembersGroupsCount -gt 0) {
                $script:htAADGroupsDetails.($aadGroupId).MembersGroups = $aadGroupMembersGroups
            }
            if ($aadGroupMembersServicePrincipalsCount -gt 0) {
                $script:htAADGroupsDetails.($aadGroupId).MembersServicePrincipals = $aadGroupMembersServicePrincipals
            }
        }
    }
}