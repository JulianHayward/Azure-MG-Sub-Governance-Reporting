function buildJSON {
    #$fileTimestamp  = Get-Date -Format "yyyyMM-dd HHmmss"
    $startJSON = Get-Date
    $startBuildHt = Get-Date

    Write-Host 'Create Hierarchy JSON'
    Write-Host ' Create ht for JSON'

    $htJSON = [ordered]@{}
    $htJSON.ManagementGroups = [ordered]@{}

    $MgIds = ($optimizedTableForPathQuery) | Select-Object -Property level, MgId, MgName, mgParentId, mgParentName | Sort-Object -Property level, MgId -Unique
    $grpScopePolicyDefinitionsCustom = (($htCacheDefinitionsPolicy).values).where( { $_.Type -eq 'Custom' }) | Group-Object ScopeMgSub
    $grpMgScopePolicyDefinitionsCustom = ($grpScopePolicyDefinitionsCustom.where( { $_.Name -eq 'Mg' }).Group | Sort-Object -Property PolicyDefinitionId | Group-Object ScopeId)
    $grpSubScopePolicyDefinitionsCustom = ($grpScopePolicyDefinitionsCustom.where( { $_.Name -eq 'Sub' }).Group | Sort-Object -Property PolicyDefinitionId | Group-Object ScopeId)

    $grpScopePolicySetDefinitionsCustom = (($htCacheDefinitionsPolicySet).values).where( { $_.Type -eq 'Custom' }) | Group-Object ScopeMgSub
    $grpMgScopePolicySetDefinitionsCustom = $grpScopePolicySetDefinitionsCustom.where( { $_.Name -eq 'Mg' }).Group | Sort-Object -Property PolicyDefinitionId | Group-Object ScopeId
    $grpSubScopePolicySetDefinitionsCustom = $grpScopePolicySetDefinitionsCustom.where( { $_.Name -eq 'Sub' }).Group | Sort-Object -Property PolicyDefinitionId | Group-Object ScopeId

    $grpScopePolicyAssignments = ($htCacheAssignmentsPolicy).values | Group-Object -Property AssignmentScopeMgSubRg
    $grpMgScopePolicyAssignments = $grpScopePolicyAssignments.where( { $_.Name -eq 'Mg' }).Group | Sort-Object @{Expression = { $_.Assignment.Id } } | Group-Object -Property AssignmentScopeId
    $grpSubScopePolicyAssignments = $grpScopePolicyAssignments.where( { $_.Name -eq 'Sub' }).Group | Sort-Object @{Expression = { $_.Assignment.Id } } | Group-Object -Property AssignmentScopeId

    if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy) {
        if (-not $JsonExportExcludeResourceGroups) {
            $grpRGScopePolicyAssignments = $grpScopePolicyAssignments.where( { $_.Name -eq 'RG' }).Group | Sort-Object @{Expression = { $_.Assignment.Id } } | Group-Object -Property AssignmentScopeId
            $htSubRGPolicyAssignments = @{}
            foreach ($rgpa in $grpRGScopePolicyAssignments) {
                $subId = ($rgpa.Name).split('/')[0]
                if (-not $htSubRGPolicyAssignments.($subId)) {
                    $htSubRGPolicyAssignments.($subId) = @{}
                }
                if (-not $htSubRGPolicyAssignments.($subId).PolicyAssignments) {
                    $htSubRGPolicyAssignments.($subId).PolicyAssignments = [System.Collections.ArrayList]@()
                }
                foreach ($rgpafg in $rgpa.group) {
                    $null = $htSubRGPolicyAssignments.($subId).PolicyAssignments.Add($rgpafg)
                }
            }
        }
    }

    $grpScopeRoleAssignments = ($htCacheAssignmentsRole).values | Group-Object -Property AssignmentScopeTenMgSubRgRes
    $grpTenantScopeRoleAssignments = $grpScopeRoleAssignments.where( { $_.Name -eq 'Tenant' }).Group | Group-Object -Property AssignmentScopeId
    $grpMgScopeRoleAssignments = $grpScopeRoleAssignments.where( { $_.Name -eq 'Mg' }).Group | Sort-Object @{Expression = { $_.Assignment.RoleAssignmentId } } | Group-Object -Property AssignmentScopeId
    $grpSubScopeRoleAssignments = $grpScopeRoleAssignments.where( { $_.Name -eq 'Sub' }).Group | Sort-Object @{Expression = { $_.Assignment.RoleAssignmentId } } | Group-Object -Property AssignmentScopeId

    if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC) {
        if (-not $JsonExportExcludeResourceGroups) {
            $grpRGScopeRoleAssignments = $grpScopeRoleAssignments.where( { $_.Name -eq 'RG' }).Group | Sort-Object @{Expression = { $_.Assignment.RoleAssignmentId } } | Group-Object -Property AssignmentScopeId
            $htSubRGRoleAssignments = @{}
            foreach ($rgra in $grpRGScopeRoleAssignments) {
                $subId = ($rgra.Name).split('/')[0]
                if (-not $htSubRGRoleAssignments.($subId)) {
                    $htSubRGRoleAssignments.($subId) = @{}
                }
                if (-not $htSubRGRoleAssignments.($subId).RoleAssignments) {
                    $htSubRGRoleAssignments.($subId).RoleAssignments = [System.Collections.ArrayList]@()
                }
                foreach ($rgrafg in $rgra.group) {
                    $null = $htSubRGRoleAssignments.($subId).RoleAssignments.Add($rgrafg)
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
                        if (-not $htSubResRoleAssignments.($splitSubId)) {
                            $htSubResRoleAssignments.($splitSubId) = @{}
                        }
                        if (-not $htSubResRoleAssignments.($splitSubId).($splitRg)) {
                            $htSubResRoleAssignments.($splitSubId).($splitRg) = @{}

                        }

                        $resourceName = $resra.AssignmentScopeId.split('/')[2]
                        if (-not $htSubResRoleAssignments.($splitSubId).($splitRg).("$($resra.ResourceType)_$($resourceName)")) {
                            $htSubResRoleAssignments.($splitSubId).($splitRg).("$($resra.ResourceType)_$($resourceName)") = @{}

                        }
                        if (-not $htSubResRoleAssignments.($splitSubId).($splitRg).("$($resra.ResourceType)_$($resourceName)").RoleAssignments) {
                            $htSubResRoleAssignments.($splitSubId).($splitRg).("$($resra.ResourceType)_$($resourceName)").RoleAssignments = [ordered]@{}

                        }
                        ($htSubResRoleAssignments.($splitSubId).($splitRg).("$($resra.ResourceType)_$($resourceName)").RoleAssignments.($resra.Assignment.RoleAssignmentId)) = $resra.Assignment
                    }
                }
            }
        }

    }

    $bluePrintsAssignmentsAtScope = ($htCacheAssignmentsBlueprint).keys | Sort-Object
    $bluePrintDefinitions = ($htCacheDefinitionsBlueprint).Keys | Sort-Object
    $subscriptions = ($optimizedTableForPathQuery.where( { -not [string]::IsNullOrEmpty($_.subscriptionId) })) | Select-Object mgId, Subscription* | Sort-Object -Property subscriptionId -Unique
    foreach ($mg in $MgIds) {

        $htJSON.ManagementGroups.($mg.MgId) = [ordered]@{}
        $htJSON.ManagementGroups.($mg.MgId).MgId = $mg.MgId
        $htJSON.ManagementGroups.($mg.MgId).MgName = $mg.MgName
        $htJSON.ManagementGroups.($mg.MgId).mgParentId = $mg.mgParentId
        $htJSON.ManagementGroups.($mg.MgId).mgParentName = $mg.mgParentName
        $htJSON.ManagementGroups.($mg.MgId).level = $mg.level
        $htJSON.ManagementGroups.($mg.MgId).PolicyDefinitionsCustom = [ordered]@{}
        $htJSON.ManagementGroups.($mg.MgId).PolicySetDefinitionsCustom = [ordered]@{}
        $htJSON.ManagementGroups.($mg.MgId).BlueprintDefinitions = [ordered]@{}
        $htJSON.ManagementGroups.($mg.MgId).PolicyAssignments = [ordered]@{}
        $htJSON.ManagementGroups.($mg.MgId).RoleAssignments = [ordered]@{}
        $htJSON.ManagementGroups.($mg.MgId).DiagnosticSettings = [ordered]@{}
        $htJSON.ManagementGroups.($mg.MgId).Subscriptions = [ordered]@{}

        foreach ($PolDef in (($grpMgScopePolicyDefinitionsCustom).where( { $_.Name -eq $mg.MgId })).group) {
            $htJSON.ManagementGroups.($mg.MgId).PolicyDefinitionsCustom.($PolDef.Id) = [ordered]@{}
            $htJSON.ManagementGroups.($mg.MgId).PolicyDefinitionsCustom.($PolDef.Id) = $PolDef.Json
        }

        foreach ($PolSetDef in (($grpMgScopePolicySetDefinitionsCustom).where( { $_.Name -eq $mg.MgId })).group) {
            $htJSON.ManagementGroups.($mg.MgId).PolicySetDefinitionsCustom.($PolSetDef.Id) = [ordered]@{}
            $htJSON.ManagementGroups.($mg.MgId).PolicySetDefinitionsCustom.($PolSetDef.Id) = $PolSetDef.Json
        }

        foreach ($PolAssignment in ($grpMgScopePolicyAssignments).where( { $_.Name -eq $mg.MgId }).group) {
            $htJSON.ManagementGroups.($mg.MgId).PolicyAssignments.($PolAssignment.Assignment.id) = [ordered]@{}
            $htJSON.ManagementGroups.($mg.MgId).PolicyAssignments.($PolAssignment.Assignment.id) = $PolAssignment.Assignment
        }

        foreach ($RoleAssignment in ($grpMgScopeRoleAssignments).where( { $_.Name -eq $mg.MgId }).group) {
            $htJSON.ManagementGroups.($mg.MgId).RoleAssignments.($RoleAssignment.Assignment.RoleAssignmentId) = [ordered]@{}
            $htJSON.ManagementGroups.($mg.MgId).RoleAssignments.($RoleAssignment.Assignment.RoleAssignmentId) = $RoleAssignment.Assignment
        }

        foreach ($BlueprintDefinition in ($bluePrintDefinitions).where( { $_ -like "/providers/Microsoft.Management/managementGroups/$($mg.MgId)/*" })) {
            $htJSON.ManagementGroups.($mg.MgId).BlueprintDefinitions.($BlueprintDefinition) = [ordered]@{}
            $htJSON.ManagementGroups.($mg.MgId).BlueprintDefinitions.($BlueprintDefinition) = $BlueprintDefinition
        }

        if (($htDiagnosticSettingsMgSub).mg.($mg.MgId)) {
            foreach ($entry in ($htDiagnosticSettingsMgSub).mg.($mg.MgId).keys | Sort-Object) {
                $htJSON.ManagementGroups.($mg.MgId).DiagnosticSettings.($entry) = [ordered]@{}
                foreach ($diagset in ($htDiagnosticSettingsMgSub).mg.($mg.MgId).$entry.keys | Sort-Object) {
                    $htJSON.ManagementGroups.($mg.MgId).DiagnosticSettings.($entry).Name = (($htDiagnosticSettingsMgSub).mg.($mg.MgId).$entry.$diagset.DiagnosticSettingName)
                    $htJSON.ManagementGroups.($mg.MgId).DiagnosticSettings.($entry).Type = (($htDiagnosticSettingsMgSub).mg.($mg.MgId).$entry.$diagset.DiagnosticTargetType)
                    $htJSON.ManagementGroups.($mg.MgId).DiagnosticSettings.($entry).TargetId = (($htDiagnosticSettingsMgSub).mg.($mg.MgId).$entry.$diagset.DiagnosticTargetId)
                    $htJSON.ManagementGroups.($mg.MgId).DiagnosticSettings.($entry).Settings = (($htDiagnosticSettingsMgSub).mg.($mg.MgId).$entry.$diagset.DiagnosticCategories)
                }
            }
        }

        foreach ($subscription in $subscriptions) {
            if ($subscription.MgId -eq $mg.MgId) {

                $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId) = [ordered]@{}
                $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).SubscriptionName = [ordered]@{}
                $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).SubscriptionQuotaId = [ordered]@{}
                $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).SubscriptionState = [ordered]@{}
                $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).SubscriptionTags = [ordered]@{}
                $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).SubscriptionName = $subscription.Subscription
                $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).SubscriptionQuotaId = $subscription.SubscriptionQuotaId
                $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).SubscriptionState = $subscription.SubscriptionState
                if ($htSubscriptionTags.($subscription.SubscriptionId)) {
                    $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).SubscriptionTags = $htSubscriptionTags.($subscription.SubscriptionId).getEnumerator() | Sort-Object Key -CaseSensitive
                }
                $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).PolicyDefinitionsCustom = [ordered]@{}
                $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).PolicySetDefinitionsCustom = [ordered]@{}
                $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).BlueprintDefinitions = [ordered]@{}
                $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).PolicyAssignments = [ordered]@{}
                $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).RoleAssignments = [ordered]@{}
                $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).BlueprintAssignments = [ordered]@{}
                $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).DiagnosticSettings = [ordered]@{}

                foreach ($PolDef in (($grpSubScopePolicyDefinitionsCustom).where( { $_.Name -eq $subscription.subscriptionId })).group) {
                    $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).PolicyDefinitionsCustom.($PolDef.Id) = [ordered]@{}
                    $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).PolicyDefinitionsCustom.($PolDef.Id) = $PolDef.Json
                }

                foreach ($PolSetDef in (($grpSubScopePolicySetDefinitionsCustom).where( { $_.Name -eq $subscription.subscriptionId })).group) {
                    $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).PolicySetDefinitionsCustom.($PolSetDef.Id) = [ordered]@{}
                    $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).PolicySetDefinitionsCustom.($PolSetDef.Id) = $PolSetDef.Json
                }

                foreach ($PolAssignment in ($grpSubScopePolicyAssignments).where( { $_.Name -eq $subscription.subscriptionId }).group) {
                    $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).PolicyAssignments.($PolAssignment.Assignment.id) = [ordered]@{}
                    $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).PolicyAssignments.($PolAssignment.Assignment.id) = $PolAssignment.Assignment
                }

                foreach ($RoleAssignment in ($grpSubScopeRoleAssignments).where( { $_.Name -eq $subscription.subscriptionId }).group) {
                    $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).RoleAssignments.($RoleAssignment.Assignment.RoleAssignmentId) = [ordered]@{}
                    $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).RoleAssignments.($RoleAssignment.Assignment.RoleAssignmentId) = $RoleAssignment.Assignment
                }

                foreach ($BlueprintDefinition in ($bluePrintDefinitions).where( { $_ -like "/subscriptions/$($subscription.subscriptionId)/*" })) {
                    $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).BlueprintDefinitions.($BlueprintDefinition) = [ordered]@{}
                    $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).BlueprintDefinitions.($BlueprintDefinition) = $BlueprintDefinition
                }

                foreach ($BlueprintsAssignment in ($blueprintsAssignmentsAtScope).where( { $_ -like "/subscriptions/$($subscription.subscriptionId)/*" })) {
                    $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).BlueprintAssignments.($BlueprintsAssignment) = [ordered]@{}
                    $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).BlueprintAssignments.($BlueprintsAssignment) = $BlueprintsAssignment
                }

                if (($htDiagnosticSettingsMgSub).sub.($subscription.subscriptionId)) {
                    foreach ($entry in ($htDiagnosticSettingsMgSub).sub.($subscription.subscriptionId).keys | Sort-Object) {
                        $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).DiagnosticSettings.($entry) = [ordered]@{}
                        foreach ($diagset in ($htDiagnosticSettingsMgSub).sub.($subscription.subscriptionId).$entry.keys | Sort-Object) {
                            $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).DiagnosticSettings.($entry).Name = (($htDiagnosticSettingsMgSub).sub.($subscription.subscriptionId).$entry.$diagset.DiagnosticSettingName)
                            $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).DiagnosticSettings.($entry).Type = (($htDiagnosticSettingsMgSub).sub.($subscription.subscriptionId).$entry.$diagset.DiagnosticTargetType)
                            $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).DiagnosticSettings.($entry).TargetId = (($htDiagnosticSettingsMgSub).sub.($subscription.subscriptionId).$entry.$diagset.DiagnosticTargetId)
                            $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).DiagnosticSettings.($entry).Settings = (($htDiagnosticSettingsMgSub).sub.($subscription.subscriptionId).$entry.$diagset.DiagnosticCategories)
                        }
                    }
                }


                if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy) {
                    if (-not $JsonExportExcludeResourceGroups) {
                        $htTemp = @{}
                        if (-not $htTemp.ResourceGroups) {
                            $htTemp.ResourceGroups = @{}
                        }

                        if ($htSubRGPolicyAssignments.($subscription.subscriptionId)) {
                            foreach ($rgpa in $htSubRGPolicyAssignments.($subscription.subscriptionId).PolicyAssignments) {
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
                        if ($htSubRGRoleAssignments.($subscription.subscriptionId)) {
                            foreach ($rgra in $htSubRGRoleAssignments.($subscription.subscriptionId).RoleAssignments) {
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
                            if ($htSubResRoleAssignments.($subscription.subscriptionId)) {
                                foreach ($rg in $htSubResRoleAssignments.($subscription.subscriptionId).keys) {
                                    foreach ($res in $htSubResRoleAssignments.($subscription.subscriptionId).($rg).Keys | Sort-Object) {
                                        $rgName = ($resra.AssignmentScopeId).split('/')[1]
                                        if (-not $htTemp.ResourceGroups.($rg)) {
                                            $htTemp.ResourceGroups.($rg) = [ordered]@{}
                                        }
                                        if (-not $htTemp.ResourceGroups.($rg).Resources) {
                                            $htTemp.ResourceGroups.($rg).Resources = [ordered]@{}
                                        }
                                        if (-not $htTemp.ResourceGroups.($rg).Resources.($res)) {
                                            $htTemp.ResourceGroups.($rg).Resources.($res) = [ordered]@{}
                                        }
                                        if (-not $htTemp.ResourceGroups.($rg).Resources.($res).RoleAssignments) {
                                            $htTemp.ResourceGroups.($rg).Resources.($res).RoleAssignments = [ordered]@{}
                                        }
                                        $htTemp.ResourceGroups.($rg).Resources.($res).RoleAssignments = $htSubResRoleAssignments.($subscription.subscriptionId).($rg).($res).RoleAssignments
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
                    $htJSON.ManagementGroups.($mg.MgId).Subscriptions.($subscription.subscriptionId).ResourceGroups = $sortedHt
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
        foreach ($roleDefinition in ($htCacheDefinitionsRole).Keys.where( { ($htCacheDefinitionsRole).($_).IsCustom }) | Sort-Object) {
            $htJSON.RoleDefinitions.($roleDefinition) = ($htCacheDefinitionsRole).($roleDefinition).Json.properties
            $jsonConverted = ($htCacheDefinitionsRole).($roleDefinition).Json.properties | ConvertTo-Json -Depth 99
            $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathRoleDefinitionCustom)$($DirectorySeparatorChar)$(removeInvalidFileNameChars ($htCacheDefinitionsRole).($roleDefinition).Name) ($(($htCacheDefinitionsRole).($roleDefinition).Id)).json" -Encoding utf8

            #if a custom role has multiple assignable scopes, the definition id may vary depending which scope AzGovViz retrieved the definition from, therefore for better change tracking we pack assignablescopes, sort them and use the first entry as id

            if (($htCacheDefinitionsRole).($roleDefinition).Json.properties.assignableScopes.Count -gt 1) {
                $jsonAdjustment4Tracking = (($htCacheDefinitionsRole).($roleDefinition).Json).psobject.copy()
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
                $jsonConvertedTracking = ($htCacheDefinitionsRole).($roleDefinition).Json | ConvertTo-Json -Depth 99
            }
            $jsonConvertedTracking | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathRoleDefinitionCustomTracking)$($DirectorySeparatorChar)$(($htCacheDefinitionsRole).($roleDefinition).Id).json" -Encoding utf8
        }
        foreach ($roleDefinition in ($htCacheDefinitionsRole).Keys.where( { -not ($htCacheDefinitionsRole).($_).IsCustom })) {
            $jsonConverted = ($htCacheDefinitionsRole).($roleDefinition).Json.properties | ConvertTo-Json -Depth 99
            $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathRoleDefinitionBuiltIn)$($DirectorySeparatorChar)$(removeInvalidFileNameChars ($htCacheDefinitionsRole).($roleDefinition).Name ) ($(($htCacheDefinitionsRole).($roleDefinition).Id)).json" -Encoding utf8
            $jsonConvertedTracking = ($htCacheDefinitionsRole).($roleDefinition).Json | ConvertTo-Json -Depth 99
            $jsonConvertedTracking | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathRoleDefinitionBuiltInTracking)$($DirectorySeparatorChar)$(($htCacheDefinitionsRole).($roleDefinition).Id).json" -Encoding utf8
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
        foreach ($policyDefinition in ($htCacheDefinitionsPolicy).Keys.where( { ($htCacheDefinitionsPolicy).($_).Type -eq 'BuiltIn' })) {
            $jsonConverted = ($htCacheDefinitionsPolicy).($policyDefinition).Json.properties | ConvertTo-Json -Depth 99
            $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathPolicyDefinitionBuiltIn)$($DirectorySeparatorChar)$(removeInvalidFileNameChars ($htCacheDefinitionsPolicy).($policyDefinition).displayName) ($(($htCacheDefinitionsPolicy).($policyDefinition).Json.name)).json" -Encoding utf8
            $jsonConvertedTracking = ($htCacheDefinitionsPolicy).($policyDefinition).Json | ConvertTo-Json -Depth 99
            $jsonConvertedTracking | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathPolicyDefinitionBuiltInTracking)$($DirectorySeparatorChar)$(($htCacheDefinitionsPolicy).($policyDefinition).Json.name).json" -Encoding utf8
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
        foreach ($policySetDefinition in ($htCacheDefinitionsPolicySet).Keys.where( { ($htCacheDefinitionsPolicySet).($_).Type -eq 'BuiltIn' })) {
            $jsonConverted = ($htCacheDefinitionsPolicySet).($policySetDefinition).Json.properties | ConvertTo-Json -Depth 99
            $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathPolicySetDefinitionBuiltIn)$($DirectorySeparatorChar)$(removeInvalidFileNameChars ($htCacheDefinitionsPolicySet).($policySetDefinition).displayName) ($(($htCacheDefinitionsPolicySet).($policySetDefinition).Json.name)).json" -Encoding utf8
            $jsonConverted = ($htCacheDefinitionsPolicySet).($policySetDefinition).Json | ConvertTo-Json -Depth 99
            $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathPolicySetDefinitionBuiltInTracking)$($DirectorySeparatorChar)$(($htCacheDefinitionsPolicySet).($policySetDefinition).Json.name).json" -Encoding utf8
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
        $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($JSONPath)$($DirectorySeparatorChar)Tenant$($DirectorySeparatorChar)ra_$($RoleAssignment.Assignment.ObjectType)_$($pim)$($RoleAssignment.Assignment.RoleAssignmentId -replace '.*/').json" -Encoding utf8
        $path = "$($JSONPath)$($DirectorySeparatorChar)Assignments$($DirectorySeparatorChar)RoleAssignments$($DirectorySeparatorChar)Tenant"
        if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)")) {
            $null = New-Item -Name $path -ItemType directory -Path $outputPath
        }
        $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($path)$($DirectorySeparatorChar)$($RoleAssignment.Assignment.ObjectType)_$($pim)$($RoleAssignment.Assignment.RoleAssignmentId -replace '.*/').json" -Encoding utf8

        $pathTracking = "$($JSONPath)$($DirectorySeparatorChar)Assignments_tracking$($DirectorySeparatorChar)RoleAssignments$($DirectorySeparatorChar)Tenant"
        if (-not (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathTracking)")) {
            $null = New-Item -Name $pathTracking -ItemType directory -Path $outputPath
        }
        $jsonConverted | Set-Content -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($pathTracking)$($DirectorySeparatorChar)$($RoleAssignment.Assignment.ObjectType)_$($pim)$($RoleAssignment.Assignment.RoleAssignmentId -replace '.*/').json" -Encoding utf8
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

    Write-Host " Exporting Tenant JSON '$($outputPath)$($DirectorySeparatorChar)$($JSONPath)$($DirectorySeparatorChar)$($fileName).json'"
    $htTree | ConvertTo-Json -Depth 99 | Set-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($JSONPath)$($DirectorySeparatorChar)$($fileName).json" -Encoding utf8 -Force

    $endBuildJSON = Get-Date
    Write-Host " Building JSON duration: $((New-TimeSpan -Start $startBuildJSON -End $endBuildJSON).TotalSeconds) seconds"

    $endJSON = Get-Date
    Write-Host "Creating Hierarchy JSON duration: $((New-TimeSpan -Start $startJSON -End $endJSON).TotalSeconds) seconds"
}