function buildJSON {
    #$fileTimestamp  = Get-Date -Format "yyyyMM-dd HHmmss"
    $startJSON = Get-Date
    $startBuildHt = Get-Date

    Write-Host 'Create Hierarchy JSON'
    Write-Host ' Create ht for JSON'

    $htJSON = [ordered]@{}
    $htJSON.ManagementGroups = [ordered]@{}

    $MgIds = ($optimizedTableForPathQuery) | Select-Object -Property level, MgId, MgName, mgParentId, mgParentName | Sort-Object -Property level, MgId -Unique
    #Group-Object -AsHashTable returns $null if the pipeline input is empty
    $grpScopePolicyDefinitionsCustom = (($htCacheDefinitionsPolicy).values).where( { $_.Type -eq 'Custom' }) | Group-Object ScopeMgSub
    $grpMgScopePolicyDefinitionsCustom = ($grpScopePolicyDefinitionsCustom.where( { $_.Name -eq 'Mg' }).Group | Sort-Object -Property PolicyDefinitionId | Group-Object ScopeId -AsHashTable -AsString) ?? @{}
    $grpSubScopePolicyDefinitionsCustom = ($grpScopePolicyDefinitionsCustom.where( { $_.Name -eq 'Sub' }).Group | Sort-Object -Property PolicyDefinitionId | Group-Object ScopeId -AsHashTable -AsString) ?? @{}

    $grpScopePolicySetDefinitionsCustom = (($htCacheDefinitionsPolicySet).values).where( { $_.Type -eq 'Custom' }) | Group-Object ScopeMgSub
    $grpMgScopePolicySetDefinitionsCustom = ($grpScopePolicySetDefinitionsCustom.where( { $_.Name -eq 'Mg' }).Group | Sort-Object -Property PolicyDefinitionId | Group-Object ScopeId -AsHashTable -AsString) ?? @{}
    $grpSubScopePolicySetDefinitionsCustom = ($grpScopePolicySetDefinitionsCustom.where( { $_.Name -eq 'Sub' }).Group | Sort-Object -Property PolicyDefinitionId | Group-Object ScopeId -AsHashTable -AsString) ?? @{}

    $grpScopePolicyAssignments = ($htCacheAssignmentsPolicy).values | Group-Object -Property AssignmentScopeMgSubRg
    $grpMgScopePolicyAssignments = ($grpScopePolicyAssignments.where( { $_.Name -eq 'Mg' }).Group | Sort-Object @{Expression = { $_.Assignment.Id } } | Group-Object -Property AssignmentScopeId -AsHashTable -AsString) ?? @{}
    $grpSubScopePolicyAssignments = ($grpScopePolicyAssignments.where( { $_.Name -eq 'Sub' }).Group | Sort-Object @{Expression = { $_.Assignment.Id } } | Group-Object -Property AssignmentScopeId -AsHashTable -AsString) ?? @{}

    if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy) {
        if (-not $JsonExportExcludeResourceGroups) {
            $grpRGScopePolicyAssignments = $grpScopePolicyAssignments.where( { $_.Name -eq 'RG' }).Group | Sort-Object @{Expression = { $_.Assignment.Id } } | Group-Object -Property AssignmentScopeId
            $htSubRGPolicyAssignments = @{}
            foreach ($rgpa in $grpRGScopePolicyAssignments) {
                $subId = ($rgpa.Name).split('/')[0]
                if (-not $htSubRGPolicyAssignments[$subId]) {
                    $htSubRGPolicyAssignments[$subId] = @{}
                }
                if (-not $htSubRGPolicyAssignments[$subId].PolicyAssignments) {
                    $htSubRGPolicyAssignments[$subId].PolicyAssignments = [System.Collections.ArrayList]@()
                }
                foreach ($rgpafg in $rgpa.group) {
                    $null = $htSubRGPolicyAssignments[$subId].PolicyAssignments.Add($rgpafg)
                }
            }
        }
    }

    $grpScopeRoleAssignments = ($htCacheAssignmentsRole).values | Group-Object -Property AssignmentScopeTenMgSubRgRes
    $grpTenantScopeRoleAssignments = $grpScopeRoleAssignments.where( { $_.Name -eq 'Tenant' }).Group | Group-Object -Property AssignmentScopeId
    $grpMgScopeRoleAssignments = ($grpScopeRoleAssignments.where( { $_.Name -eq 'Mg' }).Group | Sort-Object @{Expression = { $_.Assignment.RoleAssignmentId } } | Group-Object -Property AssignmentScopeId -AsHashTable -AsString) ?? @{}
    $grpSubScopeRoleAssignments = ($grpScopeRoleAssignments.where( { $_.Name -eq 'Sub' }).Group | Sort-Object @{Expression = { $_.Assignment.RoleAssignmentId } } | Group-Object -Property AssignmentScopeId -AsHashTable -AsString) ?? @{}

    if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC) {
        if (-not $JsonExportExcludeResourceGroups) {
            $grpRGScopeRoleAssignments = $grpScopeRoleAssignments.where( { $_.Name -eq 'RG' }).Group | Sort-Object @{Expression = { $_.Assignment.RoleAssignmentId } } | Group-Object -Property AssignmentScopeId
            $htSubRGRoleAssignments = @{}
            foreach ($rgra in $grpRGScopeRoleAssignments) {
                $subId = ($rgra.Name).split('/')[0]
                if (-not $htSubRGRoleAssignments[$subId]) {
                    $htSubRGRoleAssignments[$subId] = @{}
                }
                if (-not $htSubRGRoleAssignments[$subId].RoleAssignments) {
                    $htSubRGRoleAssignments[$subId].RoleAssignments = [System.Collections.ArrayList]@()
                }
                foreach ($rgrafg in $rgra.group) {
                    $null = $htSubRGRoleAssignments[$subId].RoleAssignments.Add($rgrafg)
                }
            }

            #res
            if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC) {
                if (-not $JsonExportExcludeResources) {
                    $grpResScopeRoleAssignments = $grpScopeRoleAssignments.where( { $_.Name -eq 'Res' }).Group | Sort-Object @{Expression = { $_.Assignment.RoleAssignmentId } } | Group-Object -Property AssignmentScopeId
                    $htSubResRoleAssignments = @{}
                    foreach ($resra in $grpResScopeRoleAssignments.Group) {
                        $raSplit = ($resra.Assignment.RoleAssignmentId).split('/')
                        $splitSubId = $raSplit[2]
                        $splitRg = $raSplit[4]
                        $htSubResRoleAssignmentsSubNode = $htSubResRoleAssignments[$splitSubId]
                        if (-not $htSubResRoleAssignmentsSubNode) {
                            $htSubResRoleAssignmentsSubNode = @{}
                            $htSubResRoleAssignments[$splitSubId] = $htSubResRoleAssignmentsSubNode
                        }
                        $htSubResRoleAssignmentsRgNode = $htSubResRoleAssignmentsSubNode.($splitRg)
                        if (-not $htSubResRoleAssignmentsRgNode) {
                            $htSubResRoleAssignmentsRgNode = @{}
                            $htSubResRoleAssignmentsSubNode.($splitRg) = $htSubResRoleAssignmentsRgNode
                        }

                        $resourceName = $resra.AssignmentScopeId.split('/')[2]
                        $resKey = "$($resra.ResourceType)_$($resourceName)"
                        $htSubResRoleAssignmentsResNode = $htSubResRoleAssignmentsRgNode.($resKey)
                        if (-not $htSubResRoleAssignmentsResNode) {
                            $htSubResRoleAssignmentsResNode = @{}
                            $htSubResRoleAssignmentsRgNode.($resKey) = $htSubResRoleAssignmentsResNode
                        }
                        if (-not $htSubResRoleAssignmentsResNode.RoleAssignments) {
                            $htSubResRoleAssignmentsResNode.RoleAssignments = [ordered]@{}
                        }
                        $htSubResRoleAssignmentsResNode.RoleAssignments.($resra.Assignment.RoleAssignmentId) = $resra.Assignment
                    }
                }
            }
        }

    }

    $bluePrintsAssignmentsAtScope = ($htCacheAssignmentsBlueprint).keys | Sort-Object
    $bluePrintDefinitions = ($htCacheDefinitionsBlueprint).Keys | Sort-Object
    $subscriptions = ($optimizedTableForPathQuery.where( { -not [string]::IsNullOrEmpty($_.subscriptionId) })) | Select-Object mgId, Subscription* | Sort-Object -Property subscriptionId -Unique
    $subscriptionsGroupedByMgId = ($subscriptions | Group-Object -Property MgId -AsHashTable -AsString) ?? @{}
    foreach ($mg in $MgIds) {

        $htJSONMg = [ordered]@{}
        $htJSON.ManagementGroups[$mg.MgId] = $htJSONMg
        $htJSONMg.MgId = $mg.MgId
        $htJSONMg.MgName = $mg.MgName
        $htJSONMg.mgParentId = $mg.mgParentId
        $htJSONMg.mgParentName = $mg.mgParentName
        $htJSONMg.level = $mg.level
        $htJSONMg.PolicyDefinitionsCustom = [ordered]@{}
        $htJSONMg.PolicySetDefinitionsCustom = [ordered]@{}
        $htJSONMg.BlueprintDefinitions = [ordered]@{}
        $htJSONMg.PolicyAssignments = [ordered]@{}
        $htJSONMg.RoleAssignments = [ordered]@{}
        $htJSONMg.DiagnosticSettings = [ordered]@{}
        $htJSONMg.Subscriptions = [ordered]@{}

        foreach ($PolDef in $grpMgScopePolicyDefinitionsCustom[$mg.MgId]) {
            $htJSONMg.PolicyDefinitionsCustom.($PolDef.Id) = $PolDef.Json
        }

        foreach ($PolSetDef in $grpMgScopePolicySetDefinitionsCustom[$mg.MgId]) {
            $htJSONMg.PolicySetDefinitionsCustom.($PolSetDef.Id) = $PolSetDef.Json
        }

        foreach ($PolAssignment in $grpMgScopePolicyAssignments[$mg.MgId]) {
            $htJSONMg.PolicyAssignments.($PolAssignment.Assignment.id) = $PolAssignment.Assignment
        }

        foreach ($RoleAssignment in $grpMgScopeRoleAssignments[$mg.MgId]) {
            $htJSONMg.RoleAssignments.($RoleAssignment.Assignment.RoleAssignmentId) = $RoleAssignment.Assignment
        }

        foreach ($BlueprintDefinition in ($bluePrintDefinitions).where( { $_ -like "/providers/Microsoft.Management/managementGroups/$($mg.MgId)/*" })) {
            $htJSONMg.BlueprintDefinitions.($BlueprintDefinition) = $BlueprintDefinition
        }

        $htDiagnosticSettingsMgScope = ($htDiagnosticSettingsMgSub).mg.($mg.MgId)
        if ($htDiagnosticSettingsMgScope) {
            foreach ($entry in $htDiagnosticSettingsMgScope.keys | Sort-Object) {
                $htJSONMgDiagnosticSetting = [ordered]@{}
                $htJSONMg.DiagnosticSettings.($entry) = $htJSONMgDiagnosticSetting
                $htDiagnosticSettingsMgScopeEntry = $htDiagnosticSettingsMgScope.$entry
                foreach ($diagset in $htDiagnosticSettingsMgScopeEntry.keys | Sort-Object) {
                    $htDiagnosticSettingsMgScopeEntryDiagset = $htDiagnosticSettingsMgScopeEntry.$diagset
                    $htJSONMgDiagnosticSetting.Name = ($htDiagnosticSettingsMgScopeEntryDiagset.DiagnosticSettingName)
                    $htJSONMgDiagnosticSetting.Type = ($htDiagnosticSettingsMgScopeEntryDiagset.DiagnosticTargetType)
                    $htJSONMgDiagnosticSetting.TargetId = ($htDiagnosticSettingsMgScopeEntryDiagset.DiagnosticTargetId)
                    $htJSONMgDiagnosticSetting.Settings = ($htDiagnosticSettingsMgScopeEntryDiagset.DiagnosticCategories)
                }
            }
        }

        foreach ($subscription in $subscriptionsGroupedByMgId.($mg.MgId)) {
            if ($subscription.MgId -eq $mg.MgId) {

                $htJSONSub = [ordered]@{}
                $htJSONMg.Subscriptions[$subscription.subscriptionId] = $htJSONSub
                $htJSONSub.SubscriptionName = [ordered]@{}
                $htJSONSub.SubscriptionQuotaId = [ordered]@{}
                $htJSONSub.SubscriptionState = [ordered]@{}
                $htJSONSub.SubscriptionTags = [ordered]@{}
                $htJSONSub.SubscriptionName = $subscription.Subscription
                $htJSONSub.SubscriptionQuotaId = $subscription.SubscriptionQuotaId
                $htJSONSub.SubscriptionState = $subscription.SubscriptionState
                if ($htSubscriptionTags[$subscription.SubscriptionId]) {
                    $htJSONSub.SubscriptionTags = $htSubscriptionTags[$subscription.SubscriptionId].getEnumerator() | Sort-Object Key -CaseSensitive
                }
                $htJSONSub.PolicyDefinitionsCustom = [ordered]@{}
                $htJSONSub.PolicySetDefinitionsCustom = [ordered]@{}
                $htJSONSub.BlueprintDefinitions = [ordered]@{}
                $htJSONSub.PolicyAssignments = [ordered]@{}
                $htJSONSub.RoleAssignments = [ordered]@{}
                $htJSONSub.BlueprintAssignments = [ordered]@{}
                $htJSONSub.DiagnosticSettings = [ordered]@{}

                foreach ($PolDef in $grpSubScopePolicyDefinitionsCustom[$subscription.subscriptionId]) {
                    $htJSONSub.PolicyDefinitionsCustom.($PolDef.Id) = $PolDef.Json
                }

                foreach ($PolSetDef in $grpSubScopePolicySetDefinitionsCustom[$subscription.subscriptionId]) {
                    $htJSONSub.PolicySetDefinitionsCustom.($PolSetDef.Id) = $PolSetDef.Json
                }

                foreach ($PolAssignment in $grpSubScopePolicyAssignments[$subscription.subscriptionId]) {
                    $htJSONSub.PolicyAssignments.($PolAssignment.Assignment.id) = $PolAssignment.Assignment
                }

                foreach ($RoleAssignment in $grpSubScopeRoleAssignments[$subscription.subscriptionId]) {
                    $htJSONSub.RoleAssignments.($RoleAssignment.Assignment.RoleAssignmentId) = $RoleAssignment.Assignment
                }

                foreach ($BlueprintDefinition in ($bluePrintDefinitions).where( { $_ -like "/subscriptions/$($subscription.subscriptionId)/*" })) {
                    $htJSONSub.BlueprintDefinitions.($BlueprintDefinition) = $BlueprintDefinition
                }

                foreach ($BlueprintsAssignment in ($blueprintsAssignmentsAtScope).where( { $_ -like "/subscriptions/$($subscription.subscriptionId)/*" })) {
                    $htJSONSub.BlueprintAssignments.($BlueprintsAssignment) = $BlueprintsAssignment
                }

                $htDiagnosticSettingsSubScope = ($htDiagnosticSettingsMgSub).sub.($subscription.subscriptionId)
                if ($htDiagnosticSettingsSubScope) {
                    foreach ($entry in $htDiagnosticSettingsSubScope.keys | Sort-Object) {
                        $htJSONSubDiagnosticSetting = [ordered]@{}
                        $htJSONSub.DiagnosticSettings.($entry) = $htJSONSubDiagnosticSetting
                        $htDiagnosticSettingsSubScopeEntry = $htDiagnosticSettingsSubScope.$entry
                        foreach ($diagset in $htDiagnosticSettingsSubScopeEntry.keys | Sort-Object) {
                            $htDiagnosticSettingsSubScopeEntryDiagset = $htDiagnosticSettingsSubScopeEntry.$diagset
                            $htJSONSubDiagnosticSetting.Name = ($htDiagnosticSettingsSubScopeEntryDiagset.DiagnosticSettingName)
                            $htJSONSubDiagnosticSetting.Type = ($htDiagnosticSettingsSubScopeEntryDiagset.DiagnosticTargetType)
                            $htJSONSubDiagnosticSetting.TargetId = ($htDiagnosticSettingsSubScopeEntryDiagset.DiagnosticTargetId)
                            $htJSONSubDiagnosticSetting.Settings = ($htDiagnosticSettingsSubScopeEntryDiagset.DiagnosticCategories)
                        }
                    }
                }


                if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy) {
                    if (-not $JsonExportExcludeResourceGroups) {
                        $htTemp = @{}
                        if (-not $htTemp.ResourceGroups) {
                            $htTemp.ResourceGroups = @{}
                        }

                        if ($htSubRGPolicyAssignments[$subscription.subscriptionId]) {
                            foreach ($rgpa in $htSubRGPolicyAssignments[$subscription.subscriptionId].PolicyAssignments) {
                                $rgName = ($rgpa.AssignmentScopeId).split('/')[1]
                                if (-not $htTemp.ResourceGroups.($rgName)) {
                                    $htTemp.ResourceGroups.($rgName) = [ordered]@{}
                                }
                                if (-not $htTemp.ResourceGroups.($rgName).PolicyAssignments) {
                                    $htTemp.ResourceGroups.($rgName).PolicyAssignments = [ordered]@{}
                                }
                                $htTemp.ResourceGroups.($rgName).PolicyAssignments.($rgpa.Assignment.id) = $rgpa.Assignment
                            }
                        }
                    }
                }

                if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC) {
                    if (-not $JsonExportExcludeResourceGroups) {
                        if (-not $htTemp) {
                            $htTemp = @{}
                        }
                        if (-not $htTemp.ResourceGroups) {
                            $htTemp.ResourceGroups = @{}
                        }
                        if ($htSubRGRoleAssignments[$subscription.subscriptionId]) {
                            foreach ($rgra in $htSubRGRoleAssignments[$subscription.subscriptionId].RoleAssignments) {
                                $rgName = ($rgra.AssignmentScopeId).split('/')[1]
                                if (-not $htTemp.ResourceGroups.($rgName)) {
                                    $htTemp.ResourceGroups.($rgName) = [ordered]@{}
                                }
                                if (-not $htTemp.ResourceGroups.($rgName).RoleAssignments) {
                                    $htTemp.ResourceGroups.($rgName).RoleAssignments = [ordered]@{}
                                }
                                $htTemp.ResourceGroups.($rgName).RoleAssignments.($rgra.Assignment.RoleAssignmentId) = $rgra.Assignment
                            }
                        }
                        #
                        if (-not $JsonExportExcludeResources) {
                            if (-not $htTemp.ResourceGroups) {
                                $htTemp.ResourceGroups = @{}
                            }
                            $htSubResRoleAssignmentsSub = $htSubResRoleAssignments[$subscription.subscriptionId]
                            if ($htSubResRoleAssignmentsSub) {
                                foreach ($rg in $htSubResRoleAssignmentsSub.keys) {
                                    $htSubResRoleAssignmentsSubRg = $htSubResRoleAssignmentsSub.($rg)
                                    foreach ($res in $htSubResRoleAssignmentsSubRg.Keys | Sort-Object) {
                                        $rgName = ($resra.AssignmentScopeId).split('/')[1]
                                        if (-not $htTemp.ResourceGroups.($rg)) {
                                            $htTemp.ResourceGroups.($rg) = [ordered]@{}
                                        }
                                        $htTempResourceGroupsRg = $htTemp.ResourceGroups.($rg)
                                        if (-not $htTempResourceGroupsRg.Resources) {
                                            $htTempResourceGroupsRg.Resources = [ordered]@{}
                                        }
                                        if (-not $htTempResourceGroupsRg.Resources.($res)) {
                                            $htTempResourceGroupsRg.Resources.($res) = [ordered]@{}
                                        }
                                        $htTempResourceGroupsRg.Resources.($res).RoleAssignments = $htSubResRoleAssignmentsSubRg.($res).RoleAssignments
                                    }
                                }
                            }
                        }
                    }
                }

                if ($htTemp) {
                    $sortedHt = [ordered]@{}
                    foreach ($key in ($htTemp.ResourceGroups.keys | Sort-Object)) {
                        $sortedHt.($key) = $htTemp.ResourceGroups.($key)
                    }
                    $htJSONSub.ResourceGroups = $sortedHt
                    $htTemp = $null
                    $sortedHt = $null
                }
            }
        }
    }

    if ($azAPICallConf['htParameters'].onAzureDevOpsOrGitHubActions) {
        if ($ManagementGroupsOnly) {
            $JSONPath = "JSON_ManagementGroupsOnly_$($ManagementGroupId)"
        }
        else {
            $JSONPath = "JSON_$($ManagementGroupId)"
        }

        if (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($JSONPath)") {
            if (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($JSONPath)$($DirectorySeparatorChar)Definitions") {
                $createDefinitionsLegacyAndNew = $true
            }
            Write-Host ' Cleaning old state (Pipeline only)'
            Remove-Item -Recurse -Force "$($outputPath)$($DirectorySeparatorChar)$($JSONPath)"
        }
    }
    else {
        if ($ManagementGroupsOnly) {
            $JSONPath = "JSON_ManagementGroupsOnly_$($ManagementGroupId)_$($fileTimestamp)"
        }
        else {
            $JSONPath = "JSON_$($ManagementGroupId)_$($fileTimestamp)"
        }
        Write-Host " Creating new state ($($JSONPath)) (local only))"
    }

    $null = New-Item -Name $JSONPath -ItemType directory -Path $outputPath

    if ($azAPICallConf['htParameters'].onAzureDevOpsOrGitHubActions) {
        "The directory '$($JSONPath)' will be rebuilt during the AzDO Pipeline run. __Do not save any files in this directory, files and folders will be deleted!__" | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($JSONPath)$($DirectorySeparatorChar)ReadMe_important.md" -Encoding utf8
    }

    $null = New-Item -Name "$($JSONPath)$($DirectorySeparatorChar)Definitions" -ItemType directory -Path $outputPath
    $null = New-Item -Name "$($JSONPath)$($DirectorySeparatorChar)Definitions_tracking" -ItemType directory -Path $outputPath




    $htJSON.RoleDefinitions = [ordered]@{}
    $pathRoleDefinitions = "$($JSONPath)$($DirectorySeparatorChar)Definitions$($DirectorySeparatorChar)RoleDefinitions"
    if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathRoleDefinitions)")) {
        $null = New-Item -Name $pathRoleDefinitions -ItemType directory -Path $outputPath
        $pathRoleDefinitionCustom = "$($pathRoleDefinitions)$($DirectorySeparatorChar)Custom"
        $pathRoleDefinitionBuiltIn = "$($pathRoleDefinitions)$($DirectorySeparatorChar)BuiltIn"
        $null = New-Item -Name "$($pathRoleDefinitionCustom)" -ItemType directory -Path $outputPath
        $null = New-Item -Name "$($pathRoleDefinitionBuiltIn)" -ItemType directory -Path $outputPath
    }
    $pathRoleDefinitionsTracking = "$($JSONPath)$($DirectorySeparatorChar)Definitions_tracking$($DirectorySeparatorChar)RoleDefinitions"
    if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathRoleDefinitionsTracking)")) {
        $null = New-Item -Name $pathRoleDefinitionsTracking -ItemType directory -Path $outputPath
        $pathRoleDefinitionCustomTracking = "$($pathRoleDefinitionsTracking)$($DirectorySeparatorChar)Custom"
        $pathRoleDefinitionBuiltInTracking = "$($pathRoleDefinitionsTracking)$($DirectorySeparatorChar)BuiltIn"
        $null = New-Item -Name "$($pathRoleDefinitionCustomTracking)" -ItemType directory -Path $outputPath
        $null = New-Item -Name "$($pathRoleDefinitionBuiltInTracking)" -ItemType directory -Path $outputPath
    }

    if (($htCacheDefinitionsRole).Keys.Count -gt 0) {
        foreach ($roleDefinition in ($htCacheDefinitionsRole).Keys.where( { $htCacheDefinitionsRole[$_].IsCustom }) | Sort-Object) {
            $htJSON.RoleDefinitions.($roleDefinition) = $htCacheDefinitionsRole[$roleDefinition].Json.properties
            $jsonConverted = $htCacheDefinitionsRole[$roleDefinition].Json.properties | ConvertTo-Json -Depth 99
            $jsonConverted | writeJsonFile -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathRoleDefinitionCustom)$($DirectorySeparatorChar)$(removeInvalidFileNameChars $htCacheDefinitionsRole[$roleDefinition].Name) ($($htCacheDefinitionsRole[$roleDefinition].Id)).json"

            #if a custom role has multiple assignable scopes, the definition id may vary depending which scope AzGovViz retrieved the definition from, therefore for better change tracking we pack assignablescopes, sort them and use the first entry as id

            if ($htCacheDefinitionsRole[$roleDefinition].Json.properties.assignableScopes.Count -gt 1) {
                $jsonAdjustment4Tracking = ($htCacheDefinitionsRole[$roleDefinition].Json).psobject.copy()
                $arrayAssignableScopes = [System.Collections.ArrayList]@()
                foreach ($assignableScope in $jsonAdjustment4Tracking.properties.assignableScopes) {
                    if ($assignableScope -like '/subscriptions/*') {
                        $null = $arrayAssignableScopes.Add("$($assignableScope)/providers/Microsoft.Authorization/roleDefinitions/$($jsonAdjustment4Tracking.name)")
                    }
                    else {
                        $null = $arrayAssignableScopes.Add("/providers/Microsoft.Authorization/roleDefinitions/$($jsonAdjustment4Tracking.name)")
                    }
                }
                $jsonAdjustment4Tracking.id = ($arrayAssignableScopes | Sort-Object)[0]
                $jsonConvertedTracking = $jsonAdjustment4Tracking | ConvertTo-Json -Depth 99
            }
            else {
                $jsonConvertedTracking = $htCacheDefinitionsRole[$roleDefinition].Json | ConvertTo-Json -Depth 99
            }
            $jsonConvertedTracking | writeJsonFile -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathRoleDefinitionCustomTracking)$($DirectorySeparatorChar)$($htCacheDefinitionsRole[$roleDefinition].Id).json"
        }
        foreach ($roleDefinition in ($htCacheDefinitionsRole).Keys.where( { -not $htCacheDefinitionsRole[$_].IsCustom })) {
            $jsonConverted = $htCacheDefinitionsRole[$roleDefinition].Json.properties | ConvertTo-Json -Depth 99
            $jsonConverted | writeJsonFile -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathRoleDefinitionBuiltIn)$($DirectorySeparatorChar)$(removeInvalidFileNameChars $htCacheDefinitionsRole[$roleDefinition].Name ) ($($htCacheDefinitionsRole[$roleDefinition].Id)).json"
            $jsonConvertedTracking = $htCacheDefinitionsRole[$roleDefinition].Json | ConvertTo-Json -Depth 99
            $jsonConvertedTracking | writeJsonFile -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathRoleDefinitionBuiltInTracking)$($DirectorySeparatorChar)$($htCacheDefinitionsRole[$roleDefinition].Id).json"
        }
    }

    $pathPolicyDefinitions = "$($JSONPath)$($DirectorySeparatorChar)Definitions$($DirectorySeparatorChar)PolicyDefinitions"
    if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathPolicyDefinitions)")) {
        $null = New-Item -Name $pathPolicyDefinitions -ItemType directory -Path $outputPath
        $pathPolicyDefinitionBuiltIn = "$($pathPolicyDefinitions)$($DirectorySeparatorChar)BuiltIn"
        $null = New-Item -Name "$($pathPolicyDefinitionBuiltIn)" -ItemType directory -Path $outputPath
    }
    $pathPolicyDefinitionsTracking = "$($JSONPath)$($DirectorySeparatorChar)Definitions_tracking$($DirectorySeparatorChar)PolicyDefinitions"
    if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathPolicyDefinitionsTracking)")) {
        $null = New-Item -Name $pathPolicyDefinitionsTracking -ItemType directory -Path $outputPath
        $pathPolicyDefinitionBuiltInTracking = "$($pathPolicyDefinitionsTracking)$($DirectorySeparatorChar)BuiltIn"
        $null = New-Item -Name "$($pathPolicyDefinitionBuiltInTracking)" -ItemType directory -Path $outputPath
    }
    if (($htCacheDefinitionsPolicy).Keys.Count -gt 0) {
        foreach ($policyDefinition in ($htCacheDefinitionsPolicy).Keys.where( { $htCacheDefinitionsPolicy[$_].Type -eq 'BuiltIn' })) {
            $jsonConverted = $htCacheDefinitionsPolicy[$policyDefinition].Json.properties | ConvertTo-Json -Depth 99
            $jsonConverted | writeJsonFile -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathPolicyDefinitionBuiltIn)$($DirectorySeparatorChar)$(removeInvalidFileNameChars $htCacheDefinitionsPolicy[$policyDefinition].displayName) ($($htCacheDefinitionsPolicy[$policyDefinition].Json.name)).json"
            $jsonConvertedTracking = $htCacheDefinitionsPolicy[$policyDefinition].Json | ConvertTo-Json -Depth 99
            $jsonConvertedTracking | writeJsonFile -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathPolicyDefinitionBuiltInTracking)$($DirectorySeparatorChar)$($htCacheDefinitionsPolicy[$policyDefinition].Json.name).json"
        }
    }

    $pathPolicySetDefinitions = "$($JSONPath)$($DirectorySeparatorChar)Definitions$($DirectorySeparatorChar)PolicySetDefinitions"
    if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathPolicySetDefinitions)")) {
        $null = New-Item -Name $pathPolicySetDefinitions -ItemType directory -Path $outputPath
        $pathPolicySetDefinitionBuiltIn = "$($pathPolicySetDefinitions)$($DirectorySeparatorChar)BuiltIn"
        $null = New-Item -Name "$($pathPolicySetDefinitionBuiltIn)" -ItemType directory -Path $outputPath
    }
    $pathPolicySetDefinitionsTracking = "$($JSONPath)$($DirectorySeparatorChar)Definitions_tracking$($DirectorySeparatorChar)PolicySetDefinitions"
    if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathPolicySetDefinitionsTracking)")) {
        $null = New-Item -Name $pathPolicySetDefinitionsTracking -ItemType directory -Path $outputPath
        $pathPolicySetDefinitionBuiltInTracking = "$($pathPolicySetDefinitionsTracking)$($DirectorySeparatorChar)BuiltIn"
        $null = New-Item -Name "$($pathPolicySetDefinitionBuiltInTracking)" -ItemType directory -Path $outputPath
    }
    if (($htCacheDefinitionsPolicySet).Keys.Count -gt 0) {
        foreach ($policySetDefinition in ($htCacheDefinitionsPolicySet).Keys.where( { $htCacheDefinitionsPolicySet[$_].Type -eq 'BuiltIn' })) {
            $jsonConverted = $htCacheDefinitionsPolicySet[$policySetDefinition].Json.properties | ConvertTo-Json -Depth 99
            $jsonConverted | writeJsonFile -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathPolicySetDefinitionBuiltIn)$($DirectorySeparatorChar)$(removeInvalidFileNameChars $htCacheDefinitionsPolicySet[$policySetDefinition].displayName) ($($htCacheDefinitionsPolicySet[$policySetDefinition].Json.name)).json"
            $jsonConverted = $htCacheDefinitionsPolicySet[$policySetDefinition].Json | ConvertTo-Json -Depth 99
            $jsonConverted | writeJsonFile -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathPolicySetDefinitionBuiltInTracking)$($DirectorySeparatorChar)$($htCacheDefinitionsPolicySet[$policySetDefinition].Json.name).json"
        }
    }

    $endBuildHt = Get-Date
    Write-Host " ht for JSON creation duration: $((New-TimeSpan -Start $startBuildHt -End $endBuildHt).TotalSeconds) seconds"

    $startBuildJSON = Get-Date
    Write-Host ' Build JSON'


    $null = New-Item -Name "$($JSONPath)$($DirectorySeparatorChar)Tenant" -ItemType directory -Path $outputPath

    $htTree = [ordered]@{}
    $htTree.'Tenant' = [ordered] @{}
    $htTree.Tenant.TenantId = $azAPICallConf['checkContext'].Tenant.Id
    $htTree.Tenant.RoleAssignments = [ordered]@{}
    foreach ($RoleAssignment in ($grpTenantScopeRoleAssignments).Group | Sort-Object @{Expression = { $_.Assignment.RoleAssignmentId } }) {

        $htTree.Tenant.RoleAssignments.$($RoleAssignment.Assignment.RoleAssignmentId) = [ordered]@{}
        $htTree.Tenant.RoleAssignments.$($RoleAssignment.Assignment.RoleAssignmentId) = $RoleAssignment.Assignment

        if ($RoleAssignment.Assignment.PIM -eq 'true') {
            $pim = 'PIM_'
        }
        else {
            $pim = ''
        }
        $jsonConverted = ($RoleAssignment.Assignment | Select-Object -ExcludeProperty PIM) | ConvertTo-Json -Depth 99
        $jsonConverted | writeJsonFile -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($JSONPath)$($DirectorySeparatorChar)Tenant$($DirectorySeparatorChar)ra_$($RoleAssignment.Assignment.ObjectType)_$($pim)$($RoleAssignment.Assignment.RoleAssignmentId -replace '.*/').json"
        $path = "$($JSONPath)$($DirectorySeparatorChar)Assignments$($DirectorySeparatorChar)RoleAssignments$($DirectorySeparatorChar)Tenant"
        if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)")) {
            $null = New-Item -Name $path -ItemType directory -Path $outputPath
        }
        $jsonConverted | writeJsonFile -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)$($DirectorySeparatorChar)$($RoleAssignment.Assignment.ObjectType)_$($pim)$($RoleAssignment.Assignment.RoleAssignmentId -replace '.*/').json"

        $pathTracking = "$($JSONPath)$($DirectorySeparatorChar)Assignments_tracking$($DirectorySeparatorChar)RoleAssignments$($DirectorySeparatorChar)Tenant"
        if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathTracking)")) {
            $null = New-Item -Name $pathTracking -ItemType directory -Path $outputPath
        }
        $jsonConverted | writeJsonFile -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathTracking)$($DirectorySeparatorChar)$($RoleAssignment.Assignment.ObjectType)_$($pim)$($RoleAssignment.Assignment.RoleAssignmentId -replace '.*/').json"
    }

    $htTree.'Tenant'.'ManagementGroups' = [ordered] @{}
    $json = $htTree.'Tenant'

    if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($JSONPath)$($DirectorySeparatorChar)Assignments")) {
        $null = New-Item -Name "$($JSONPath)$($DirectorySeparatorChar)Assignments" -ItemType directory -Path $outputPath
    }
    if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($JSONPath)$($DirectorySeparatorChar)Assignments_tracking")) {
        $null = New-Item -Name "$($JSONPath)$($DirectorySeparatorChar)Assignments_tracking" -ItemType directory -Path $outputPath
    }

    buildTree -mgId $ManagementGroupId -json $json -prnt "$($JSONPath)$($DirectorySeparatorChar)Tenant"

    $htTree.'Tenant'.'CustomRoleDefinitions' = $htJSON.RoleDefinitions
    #the tree references what is still needed, holding the parallel structure through the serialize doubles the peak
    $htJSON = $null

    Write-Host " Exporting Tenant JSON '$($outputPath)$($DirectorySeparatorChar)$($JSONPath)$($DirectorySeparatorChar)$($fileName).json'"

    #the hierarchy is written node by node - a single ConvertTo-Json over the whole tree peaks at a multiple of the document size
    function writeTreeNodeJson {
        param(
            [System.IO.StreamWriter]$streamWriter,
            $node,
            #indentation of the object's closing brace
            [string]$indent
        )
        if ($node.Keys.Count -eq 0) {
            $streamWriter.Write('{}')
            return
        }
        $streamWriter.Write('{')
        $propertyIndent = "$($indent)  "
        $isFirstProperty = $true
        foreach ($nodeKey in $node.Keys) {
            if (-not $isFirstProperty) {
                $streamWriter.Write(',')
            }
            $isFirstProperty = $false
            $streamWriter.Write("`n$($propertyIndent)$($nodeKey | ConvertTo-Json): ")

            if ($nodeKey -eq 'ManagementGroups') {
                $childManagementGroups = $node[$nodeKey]
                if ($childManagementGroups.Keys.Count -eq 0) {
                    $streamWriter.Write('{}')
                }
                else {
                    $streamWriter.Write('{')
                    $isFirstChild = $true
                    foreach ($childKey in $childManagementGroups.Keys) {
                        if (-not $isFirstChild) {
                            $streamWriter.Write(',')
                        }
                        $isFirstChild = $false
                        $streamWriter.Write("`n$($propertyIndent)  $($childKey | ConvertTo-Json): ")
                        writeTreeNodeJson -streamWriter $streamWriter -node $childManagementGroups[$childKey] -indent "$($propertyIndent)  "
                    }
                    $streamWriter.Write("`n$($propertyIndent)}")
                }
            }
            else {
                #every line but the first is shifted to the indentation the value has inside the document
                $streamWriter.Write(((($node[$nodeKey] | ConvertTo-Json -Depth 99) -split '\r?\n') -join "`n$($propertyIndent)"))
            }
        }
        $streamWriter.Write("`n$($indent)}")
    }

    $treeStreamWriter = [System.IO.StreamWriter]::new("$($outputPath)$($DirectorySeparatorChar)$($JSONPath)$($DirectorySeparatorChar)$($fileName).json", $false, [System.Text.UTF8Encoding]::new($false))
    try {
        $treeStreamWriter.Write("{`n  `"Tenant`": ")
        writeTreeNodeJson -streamWriter $treeStreamWriter -node $htTree.Tenant -indent '  '
        $treeStreamWriter.Write("`n}`n")
    }
    finally {
        $treeStreamWriter.Dispose()
    }
    $htTree = $null
    $json = $null

    $endBuildJSON = Get-Date
    Write-Host " Building JSON duration: $((New-TimeSpan -Start $startBuildJSON -End $endBuildJSON).TotalSeconds) seconds"

    $endJSON = Get-Date
    Write-Host "Creating Hierarchy JSON duration: $((New-TimeSpan -Start $startJSON -End $endJSON).TotalSeconds) seconds"
}