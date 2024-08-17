function ResolveObjectIds {
    [CmdletBinding()]Param(
        [object]
        $objectIds,

        [switch]
        $showActivity
    )

    $arrayObjectIdsToCheck = @()
    $arrayObjectIdsToCheck = foreach ($objectToCheckIfAlreadyResolved in $objectIds) {
        if (-not $htPrincipals.($objectToCheckIfAlreadyResolved)) {
            $objectToCheckIfAlreadyResolved
        }
        else {
            #Write-Host "$objectToCheckIfAlreadyResolved already resolved"
        }
    }

    if ($arrayObjectIdsToCheck.Count -gt 0) {

        $counterBatch = [PSCustomObject] @{ Value = 0 }
        $batchSize = 1000
        $ObjectBatch = $arrayObjectIdsToCheck | Group-Object -Property { [math]::Floor($counterBatch.Value++ / $batchSize) }
        $ObjectBatchCount = ($ObjectBatch | Measure-Object).Count
        $batchCnt = 0

        foreach ($batch in $ObjectBatch) {
            $batchCnt++
            $objectsToProcess = '"{0}"' -f ($batch.Group.where({ testGuid $_ }) -join '","')
            $currentTask = " Resolving ObjectIds - Batch #$batchCnt/$($ObjectBatchCount) ($(($batch.Group).Count))"
            if ($showActivity) {
                Write-Host $currentTask
            }
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/beta/directoryObjects/getByIds"
            $method = 'POST'
            $body = @"
        {
            "ids":[$($objectsToProcess)]
        }
"@
            $resolveObjectIds = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -body $body -currentTask $currentTask

            foreach ($identity in $resolveObjectIds) {
                if (-not $htPrincipals.($identity.id)) {
                    $arrayIdentityObject = [System.Collections.ArrayList]@()
                    if ($identity.'@odata.type' -eq '#microsoft.graph.user') {
                        if ($identity.userType -eq 'Guest') {
                            $script:htUserTypesGuest.($identity.id) = @{
                                userType = 'Guest'
                            }
                        }
                        $null = $arrayIdentityObject.Add([PSCustomObject]@{
                                type        = 'User'
                                userType    = $identity.userType
                                id          = $identity.id
                                displayName = $identity.displayName
                                signInName  = $identity.userPrincipalName
                            })
                    }
                    if ($identity.'@odata.type' -eq '#microsoft.graph.group') {
                        $null = $arrayIdentityObject.Add([PSCustomObject]@{
                                type        = 'Group'
                                id          = $identity.id
                                displayName = $identity.displayName
                            })
                    }
                    if ($identity.'@odata.type' -eq '#microsoft.graph.servicePrincipal') {
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
                            #$script:htServicePrincipals.($identity.id) = @{}
                            $script:htServicePrincipals.($identity.id) = $arrayIdentityObject
                        }
                    }
                    if (-not $htPrincipals.($identity.id)) {
                        $script:htPrincipals.($identity.id) = $arrayIdentityObject
                    }
                }
            }
            if ($batch.Group.Count -ne $resolveObjectIds.Count) {
                foreach ($objectId in $batch.Group) {
                    if ($resolveObjectIds.id -notcontains $objectId) {
                        if (-not $htPrincipals.($objectId)) {
                            $arrayIdentityObject = [System.Collections.ArrayList]@()
                            $null = $arrayIdentityObject.Add([PSCustomObject]@{
                                    type = 'Unknown'
                                    id   = $objectId
                                })
                            $script:htPrincipals.($objectId) = $arrayIdentityObject
                        }
                        else {
                            #Write-Host "$($objectId) was already collected"
                        }
                    }
                }
            }
        }
    }
}