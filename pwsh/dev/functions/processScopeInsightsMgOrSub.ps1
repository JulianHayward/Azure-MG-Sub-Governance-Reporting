function processScopeInsightsMgOrSub($mgOrSub, $mgChild, $subscriptionId, $subscriptionsMgId) {
    $script:scopescnter++
    $htmlScopeInsights = $null
    $htmlScopeInsights = [System.Text.StringBuilder]::new()
    #region ScopeInsightsBaseCollection
    if ($mgOrSub -eq 'mg') {
        #$startScopeInsightsPreQueryMg = Get-Date
        #BLUEPRINT
        $blueprintReleatedQuery = $blueprintBaseQuery.where( { $_.MgId -eq $mgChild -and [String]::IsNullOrEmpty($_.SubscriptionId) -and [String]::IsNullOrEmpty($_.BlueprintAssignmentId) } )
        $blueprintsScoped = $blueprintReleatedQuery
        $blueprintsScopedCount = ($blueprintsScoped).count
        #Resources
        $mgAllChildSubscriptions = [System.Collections.ArrayList]@()
        $mgAllChildSubscriptions = foreach ($entry in $htSubscriptionsMgPath.keys) {
            if (($htSubscriptionsMgPath.($entry).ParentNameChain) -contains $mgchild) {
                $entry
            }
        }
        if ($azAPICallConf['htParameters'].NoResources -eq $false) {
            $resourcesAllChildSubscriptions = [System.Collections.ArrayList]@()
            foreach ($mgAllChildSubscription in $mgAllChildSubscriptions) {
                foreach ($resource in ($resourcesAllGroupedBySubcriptionId.where( { $_.name -eq $mgAllChildSubscription } )).group | Sort-Object -Property type, location) {
                    $null = $resourcesAllChildSubscriptions.Add($resource)
                }

            }
            $resourcesAllChildSubscriptionsArray = [System.Collections.ArrayList]@()
            $grp = $resourcesAllChildSubscriptions | Group-Object -Property type, location
            foreach ($resLoc in $grp) {
                $cnt = 0
                $ResoureTypeAndLocation = $resLoc.Name.split(',')
                $resLoc.Group.count_ | ForEach-Object { $cnt += $_ }
                $null = $resourcesAllChildSubscriptionsArray.Add([PSCustomObject]@{
                        ResourceType  = $ResoureTypeAndLocation[0]
                        Location      = $ResoureTypeAndLocation[1]
                        ResourceCount = $cnt
                    })
            }
            $resourcesAllChildSubscriptions.count_ | ForEach-Object { $resourcesAllChildSubscriptionTotal += $_ }
            $resourcesAllChildSubscriptionResourceTypeCount = (($resourcesAllChildSubscriptions | Sort-Object -Property type -Unique) | Measure-Object).count
            $resourcesAllChildSubscriptionLocationCount = (($resourcesAllChildSubscriptions | Sort-Object -Property location -Unique) | Measure-Object).count
        }
        #childrenMgInfo
        $mgAllChildMgs = [System.Collections.ArrayList]@()
        $mgAllChildMgs = foreach ($entry in $htManagementGroupsMgPath.keys) {
            if (($htManagementGroupsMgPath.($entry).path) -contains $mgchild) {
                $entry
            }
        }

        $arrayPolicyAssignmentsEnrichedForThisManagementGroup = ($arrayPolicyAssignmentsEnrichedGroupedByManagementGroup.where( { $_.name -eq $mgChild } )).group
        $arrayPolicyAssignmentsEnrichedForThisManagementGroupGroupedByPolicyVariant = $arrayPolicyAssignmentsEnrichedForThisManagementGroup | Group-Object -Property PolicyVariant
        $arrayPolicyAssignmentsEnrichedForThisManagementGroupVariantPolicy = ($arrayPolicyAssignmentsEnrichedForThisManagementGroupGroupedByPolicyVariant.where( { $_.name -eq 'Policy' } )).group
        $arrayPolicyAssignmentsEnrichedForThisManagementGroupVariantPolicySet = ($arrayPolicyAssignmentsEnrichedForThisManagementGroupGroupedByPolicyVariant.where( { $_.name -eq 'PolicySet' } )).group

        if ($azAPICallConf['htParameters'].NoMDfCSecureScore -eq $false) {
            if ([string]::IsNullOrEmpty(($htMgASCSecureScore).($mgChild).SecureScore) -or [string]::IsNullOrWhiteSpace(($htMgASCSecureScore).($mgChild).SecureScore)) {
                $managementGroupASCPoints = 'n/a'
            }
            else {
                $managementGroupASCPoints = ($htMgASCSecureScore).($mgChild).SecureScore
            }
        }
        else {
            $managementGroupASCPoints = "excluded (-NoMDfCSecureScore $($azAPICallConf['htParameters'].NoMDfCSecureScore))"
        }

        $cssClass = 'mgDetailsTable'

        #$endScopeInsightsPreQueryMg = Get-Date
        #Write-Host "   ScopeInsights MG PreQuery processing duration: $((NEW-TIMESPAN -Start $startScopeInsightsPreQueryMg -End $endScopeInsightsPreQueryMg).TotalSeconds) seconds"
    }
    if ($mgOrSub -eq 'sub') {
        #$startScopeInsightsPreQuerySub = Get-Date
        #BLUEPRINT
        $blueprintReleatedQuery = $blueprintBaseQuery.where( { $_.SubscriptionId -eq $subscriptionId -and -not [String]::IsNullOrEmpty($_.BlueprintName) } )
        $blueprintsAssigned = $blueprintReleatedQuery.where( { -not [String]::IsNullOrEmpty($_.BlueprintAssignmentId) } )
        $blueprintsAssignedCount = ($blueprintsAssigned).count
        $blueprintsScoped = $blueprintReleatedQuery.where( { $_.BlueprintScoped -eq "/subscriptions/$subscriptionId" -and [String]::IsNullOrEmpty($_.BlueprintAssignmentId) } )
        $blueprintsScopedCount = ($blueprintsScoped).count
        #SubscriptionDetails
        $subPath = $htSubscriptionsMgPath.($subscriptionId).pathDelimited
        $subscriptionDetailsReleatedQuery = $htSubDetails.($subscriptionId).details
        $subscriptionState = ($subscriptionDetailsReleatedQuery).SubscriptionState
        $subscriptionQuotaId = ($subscriptionDetailsReleatedQuery).SubscriptionQuotaId
        $subscriptionResourceGroupsCount = ($resourceGroupsAll.where( { $_.subscriptionId -eq $subscriptionId } )).count_
        if (-not $subscriptionResourceGroupsCount) {
            $subscriptionResourceGroupsCount = 0
        }
        $subscriptionASCPoints = ($subscriptionDetailsReleatedQuery).SubscriptionASCSecureScore

        if ($azAPICallConf['htParameters'].NoResources -eq $false) {
            #Resources
            $resourcesSubscription = [System.Collections.ArrayList]@()
            foreach ($resource in ($resourcesAllGroupedBySubcriptionId.where( { $_.name -eq $subscriptionId } )).group | Sort-Object -Property type, location) {
                $null = $resourcesSubscription.Add($resource)
            }

            $resourcesSubscriptionTotal = 0
            $resourcesSubscription.count_ | ForEach-Object { $resourcesSubscriptionTotal += $_ }
            $resourcesSubscriptionResourceTypeCount = (($resourcesSubscription | Sort-Object -Property type -Unique)).count
            $resourcesSubscriptionLocationCount = (($resourcesSubscription | Sort-Object -Property location -Unique)).count
        }

        $arrayPolicyAssignmentsEnrichedForThisSubscription = ($arrayPolicyAssignmentsEnrichedGroupedBySubscription.where( { $_.name -eq $subscriptionId } )).group
        $arrayPolicyAssignmentsEnrichedForThisSubscriptionGroupedByPolicyVariant = $arrayPolicyAssignmentsEnrichedForThisSubscription | Group-Object -Property PolicyVariant
        $arrayPolicyAssignmentsEnrichedForThisSubscriptionVariantPolicy = ($arrayPolicyAssignmentsEnrichedForThisSubscriptionGroupedByPolicyVariant.where( { $_.name -eq 'Policy' } )).group
        $arrayPolicyAssignmentsEnrichedForThisSubscriptionVariantPolicySet = ($arrayPolicyAssignmentsEnrichedForThisSubscriptionGroupedByPolicyVariant.where( { $_.name -eq 'PolicySet' } )).group

        $arrayDefenderPlansSubscription = $defenderPlansGroupedBySub.where( { $_.Name -like "*$($subscriptionId)*" } )

        $arrayUserAssignedIdentities4ResourcesSubscription = $arrayUserAssignedIdentities4Resources.where( { $_.resourceSubscriptionId -eq $subscriptionId -or $_.miSubscriptionId -eq $subscriptionId } )
        $arrayUserAssignedIdentities4ResourcesSubscriptionCount = $arrayUserAssignedIdentities4ResourcesSubscription.Count

        if ($subFeaturesGroupedBySubscription) {
            $subscriptionFeatures = $subFeaturesGroupedBySubscription.where({ $_.name -eq $subscriptionId })
        }

        $cssClass = 'subDetailsTable'

        #$endScopeInsightsPreQuerySub = Get-Date
        #Write-Host "   ScopeInsights SUB PreQuery processing duration: $((NEW-TIMESPAN -Start $startScopeInsightsPreQuerySub -End $endScopeInsightsPreQuerySub).TotalSeconds) seconds"
    }
    #endregion ScopeInsightsBaseCollection

    if ($mgOrSub -eq 'sub') {

        if ($htDefenderEmailContacts.($subscriptionDetailsReleatedQuery.subscriptionId)) {
            $hlpDefenderEmailContacts = $htDefenderEmailContacts.($subscriptionDetailsReleatedQuery.subscriptionId)
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

        [void]$htmlScopeInsights.AppendLine(@"
<tr><td class="detailstd">Subscription Name: <b>$($subscriptionDetailsReleatedQuery.subscription -replace '<', '&lt;' -replace '>', '&gt;')</b></td></tr>
<tr><td class="detailstd">Subscription Id: <b>$($subscriptionDetailsReleatedQuery.subscriptionId)</b></td></tr>
<tr><td class="detailstd">Subscription Path: $subPath</td></tr>
<tr><td class="detailstd">State: $subscriptionState</td></tr>
<tr><td class="detailstd">QuotaId: $subscriptionQuotaId</td></tr>
<tr><td class="detailstd"><i class="fa fa-shield" aria-hidden="true"></i> Microsoft Defender for Cloud Secure Score: $subscriptionASCPoints <a class="externallink" href="https://www.youtube.com/watch?v=2EMnzxdqDhA" target="_blank" rel="noopener" rel="noopener">Video <i class="fa fa-external-link" aria-hidden="true"></i></a>, <a class="externallink" href="https://techcommunity.microsoft.com/t5/azure-security-center/security-controls-in-azure-security-center-enable-endpoint/ba-p/1624653" target="_blank" rel="noopener" rel="noopener">Blog <i class="fa fa-external-link" aria-hidden="true"></i></a>, <a class="externallink" href="https://docs.microsoft.com/en-us/azure/security-center/secure-score-security-controls#how-your-secure-score-is-calculated" target="_blank" rel="noopener" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></td></tr>
<tr><td class="detailstd"><i class="fa fa-shield" aria-hidden="true"></i> Microsoft Defender for Cloud 'Email notifications' state: $MDfCEmailNotificationsState</td></tr>
<tr><td class="detailstd"><i class="fa fa-shield" aria-hidden="true"></i> Microsoft Defender for Cloud 'Email notifications' severity: $MDfCEmailNotificationsSeverity</td></tr>
<tr><td class="detailstd"><i class="fa fa-shield" aria-hidden="true"></i> Microsoft Defender for Cloud 'Email notifications' roles: $MDfCEmailNotificationsRoles</td></tr>
<tr><td class="detailstd"><i class="fa fa-shield" aria-hidden="true"></i> Microsoft Defender for Cloud 'Email notifications' emails: $MDfCEmailNotificationsEmails</td></tr>
<tr><td class="detailstd">
"@)

        #region ScopeInsightsDefenderPlans
        if ($arrayDefenderPlansSubscription) {

            $defenderPlanSubscriptionDeprecatedContainerRegistry = $false
            $defenderPlanSubscriptionDeprecatedKubernetesService = $false

            $containerRegistryStandardCount = ($arrayDefenderPlansSubscription.Group.where( { $_.defenderPlan -eq 'ContainerRegistry' -and $_.defenderPlanTier -eq 'Standard' } )).Count
            $kubernetesServiceStandardCount = ($arrayDefenderPlansSubscription.Group.where( { $_.defenderPlan -eq 'KubernetesService' -and $_.defenderPlanTier -eq 'Standard' } )).Count
            if ($containerRegistryStandardCount -gt 0) {
                $defenderPlanSubscriptionDeprecatedContainerRegistry = $true
            }
            if ($kubernetesServiceStandardCount -gt 0) {
                $defenderPlanSubscriptionDeprecatedKubernetesService = $true
            }

            $defenderCapabilitiesSubscription = ($arrayDefenderPlansSubscription.group.defenderPlan | Sort-Object -Unique)
            $tfCount = 1
            $htmlTableId = "ScopeInsights_DefenderPlans_$($subscriptionId -replace '-','_')"
            $randomFunctionName = "func_$htmlTableId"
            [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-shield" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">Microsoft Defender for Cloud plans</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/defender-for-cloud/enhanced-security-features-overview" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></button>
<div class="content contentSISub">
"@)

            if ($defenderPlanSubscriptionDeprecatedContainerRegistry) {
                [void]$htmlScopeInsights.AppendLine(@'
        &nbsp;&nbsp;<i class="fa fa-exclamation-triangle" aria-hidden="true"></i> Using deprecated plan 'Container registries' <a class="externallink" href="https://docs.microsoft.com/en-us/azure/defender-for-cloud/release-notes#microsoft-defender-for-containers-plan-released-for-general-availability-ga" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
'@)
            }
            if ($defenderPlanSubscriptionDeprecatedKubernetesService) {
                [void]$htmlScopeInsights.AppendLine(@'
        &nbsp;&nbsp;<i class="fa fa-exclamation-triangle" aria-hidden="true"></i>  Using deprecated plan 'Kubernetes' <a class="externallink" href="https://docs.microsoft.com/en-us/azure/defender-for-cloud/release-notes#microsoft-defender-for-containers-plan-released-for-general-availability-ga" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
'@)
            }

            [void]$htmlScopeInsights.AppendLine(@"
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Plan</th>
<th>Tier</th>
</tr>
</thead>
<tbody>

"@)

            foreach ($plan in $arrayDefenderPlansSubscription.Group | Sort-Object -Property defenderPlan) {
                if (($plan.defenderPlan -eq 'ContainerRegistry' -and $plan.defenderPlanTier -eq 'Standard') -or ($plan.defenderPlan -eq 'KubernetesService' -and $plan.defenderPlanTier -eq 'Standard')) {
                    $thisDefenderPlan = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i> $($plan.defenderPlan)"
                }
                else {
                    $thisDefenderPlan = $plan.defenderPlan
                }
                [void]$htmlScopeInsights.AppendLine(@"
                    <tr>
                    <td>$($thisDefenderPlan)</td>
                    <td>$($plan.defenderPlanTier)</td>
                    </tr>
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@"

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
                [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@'
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
col_1: 'select',
col_types: [
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
'@)
            $cnt = 0
            foreach ($defenderCapability in $defenderCapabilitiesSubscription) {
                $cnt++
                if ($defenderCapabilitiesSubscription.Count -eq $cnt) {
                    [void]$htmlScopeInsights.AppendLine(@'
    'caseinsensitivestring'
'@)
                }
                else {
                    [void]$htmlScopeInsights.AppendLine(@'
    'caseinsensitivestring',
'@)
                }
            }
            [void]$htmlScopeInsights.AppendLine(@"
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
            $subscriptionSkippedMDfC = $arrayDefenderPlansSubscriptionsSkipped.where( { $_.subscriptionId -eq $subscriptionId } )
            if ($subscriptionSkippedMDfC.Count -gt 0) {
                if ($subscriptionSkippedMDfC.reason -eq 'SubScriptionNotRegistered') {
                    [void]$htmlScopeInsights.AppendLine(@"
                    <i class=`"fa fa-shield`" aria-hidden=`"true`"></i> Microsoft Defender for Cloud plans - Subscription skipped ($($subscriptionSkippedMDfC.reason)) (ResourceProvider: Microsoft.Security) <a class=`"externallink`" href=`"https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/resource-providers-and-types#register-resource-provider`" target=`"_blank`" rel=`"noopener`">docs <i class=`"fa fa-external-link`" aria-hidden=`"true`"></i></a>
"@)
                }
                else {
                    [void]$htmlScopeInsights.AppendLine(@"
                    <i class=`"fa fa-shield`" aria-hidden=`"true`"></i> Microsoft Defender for Cloud plans - Subscription skipped ($($subscriptionSkippedMDfC.reason))
"@)
                }

            }
            else {
                [void]$htmlScopeInsights.AppendLine(@'
<i class="fa fa-shield" aria-hidden="true"></i> No Microsoft Defender for Cloud plans <a class="externallink" href="https://docs.microsoft.com/en-us/azure/defender-for-cloud/enhanced-security-features-overview" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a>
'@)
            }
        }
        [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><!--y--><td class="detailstd"><!--y-->
'@)
        #endregion ScopeInsightsDefenderPlans

        #region ScopeInsightsDiganosticsSubscription
        if (($htDiagnosticSettingsMgSub).sub.($subscriptionId)) {
            $diagnosticsSubCount = (($htDiagnosticSettingsMgSub).sub.($subscriptionId).Values.Count)
            $tfCount = $diagnosticsSubCount
            $htmlTableId = "ScopeInsights_DiagnosticsSub_$($subscriptionId -replace '-','_')"
            $randomFunctionName = "func_$htmlTableId"
            [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$diagnosticsSubCount Subscription Diagnostic settings</span></button>
<div class="content contentSISub">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Diagnostic setting</th>
<th>Target</th>
<th>Target Id</th>
"@)
            foreach ($logCategory in $diagnosticSettingsSubCategories) {
                [void]$htmlScopeInsights.AppendLine(@"
<th>$logCategory</th>
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@'
</tr>
</thead>
<tbody>
'@)
            $htmlScopeInsightsDiagnosticsSub = $null
            $htmlScopeInsightsDiagnosticsSub = foreach ($entry in ($htDiagnosticSettingsMgSub).sub.($subscriptionId).keys | Sort-Object) {
                foreach ($diagset in ($htDiagnosticSettingsMgSub).sub.($subscriptionId).$entry.keys | Sort-Object) {
                    @"
<tr>
<td>$(($htDiagnosticSettingsMgSub).sub.($subscriptionId).$entry.$diagset.DiagnosticSettingName)</td>
<td>$(($htDiagnosticSettingsMgSub).sub.($subscriptionId).$entry.$diagset.DiagnosticTargetType)</td>
<td>$(($htDiagnosticSettingsMgSub).sub.($subscriptionId).$entry.$diagset.DiagnosticTargetId)</td>
"@
                    foreach ($logCategory in $diagnosticSettingsSubCategories) {
                        if (($htDiagnosticSettingsMgSub).sub.($subscriptionId).$entry.$diagset.DiagnosticCategoriesHt.($logCategory)) {
                            @"
<td>$(($htDiagnosticSettingsMgSub).sub.($subscriptionId).$entry.$diagset.DiagnosticCategoriesHt.($logCategory))</td>
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
            }

            [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsDiagnosticsSub)
            [void]$htmlScopeInsights.AppendLine(@"
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
                [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@'
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            linked_filters: true,
            col_1: 'select',
'@)
            $cnt = 2
            foreach ($logCategory in $diagnosticSettingsSubCategories) {
                $cnt++
                [void]$htmlScopeInsights.AppendLine(@"
                col_$($cnt): 'select',
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@'
col_types: [
    'caseinsensitivestring',
    'caseinsensitivestring',
    'caseinsensitivestring',
'@)
            $cnt = 0
            foreach ($logCategory in $diagnosticSettingsSubCategories) {
                $cnt++
                if ($diagnosticSettingsSubCategories.Count -eq $cnt) {
                    [void]$htmlScopeInsights.AppendLine(@'
    'caseinsensitivestring'
'@)
                }
                else {
                    [void]$htmlScopeInsights.AppendLine(@'
    'caseinsensitivestring',
'@)
                }
            }
            [void]$htmlScopeInsights.AppendLine(@"
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
            [void]$htmlScopeInsights.AppendLine(@'
<i class="fa fa-ban" aria-hidden="true"></i> No Subscription Diagnostic settings <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/quick-collect-activity-log-portal#create-diagnostic-setting" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a>
'@)
        }
        [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><!--y--><td class="detailstd"><!--y-->
'@)
        #endregion ScopeInsightsDiganosticsSubscription

        #Tags
        #region ScopeInsightsTags
        $tagsSubscriptionCount = ($htSubscriptionTags.$subscriptionId.Keys).count
        if ($tagsSubscriptionCount -gt 0) {
            $tfCount = $tagsSubscriptionCount
            $htmlTableId = "ScopeInsights_Tags_$($subscriptionId -replace '-','_')"
            $randomFunctionName = "func_$htmlTableId"
            [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible">
<i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tagsSubscriptionCount Subscription Tags | Limit: ($tagsSubscriptionCount/$LimitTagsSubscription)</span></button>
<div class="content contentSISub">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">Tag Name</th>
<th>Tag Value</th>
</tr>
</thead>
<tbody>
"@)
            $htmlScopeInsightsTags = $null
            $htmlScopeInsightsTags = foreach ($tag in (($htSubscriptionTags).($subscriptionId)).keys | Sort-Object) {
                @"
<tr>
<td>$tag</td>
<td>$($htSubscriptionTags.$subscriptionId[$tag])</td>
</tr>
"@
            }
            [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsTags)
            [void]$htmlScopeInsights.AppendLine(@"
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
                [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@"
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
    </div>
"@)
        }
        else {
            [void]$htmlScopeInsights.AppendLine(@"
            <i class="fa fa-ban" aria-hidden="true"></i> $tagsSubscriptionCount Subscription Tags
"@)
        }
        [void]$htmlScopeInsights.AppendLine(@'
        </td></tr>
        <tr><!--y--><td class="detailstd"><!--y-->
'@)
        #endregion ScopeInsightsTags

        #TagNameUsage
        #region ScopeInsightsTagNameUsage
        $arrayTagListSubscription = [System.Collections.ArrayList]@()
        foreach ($tagScope in $htSubscriptionTagList.($subscriptionId).keys) {
            foreach ($tagScopeTagName in $htSubscriptionTagList.($subscriptionId).$tagScope.keys) {
                $null = $arrayTagListSubscription.Add([PSCustomObject]@{
                        Scope    = $tagScope
                        TagName  = ($tagScopeTagName)
                        TagCount = $htSubscriptionTagList.($subscriptionId).($tagScope).($tagScopeTagName)
                    })
            }
        }
        $tagsUsageCount = ($arrayTagListSubscription).Count

        if ($tagsUsageCount -gt 0) {
            $tagNamesUniqueCount = ($arrayTagListSubscription | Sort-Object -Property TagName -Unique).Count
            $tagNamesUsedInScopes = ($arrayTagListSubscription | Sort-Object -Property Scope -Unique).scope -join "$($CsvDelimiterOpposite) "
            $tfCount = $tagsUsageCount
            $htmlTableId = "ScopeInsights_TagNameUsage_$($subscriptionId -replace '-','_')"
            $randomFunctionName = "func_$htmlTableId"
            [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible">
<i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Tag Name Usage ($tagNamesUniqueCount unique Tag Names applied at $($tagNamesUsedInScopes)</span></button>
<div class="content contentSISub">
&nbsp;&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Resource naming and tagging decision guide</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/cloud-adoption-framework/decision-guides/resource-tagging" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Scope</th>
<th>TagName</th>
<th>Count</th>
</tr>
</thead>
<tbody>
"@)
            $htmlScopeInsightsTagsUsage = $null
            $htmlScopeInsightsTagsUsage = foreach ($tagEntry in $arrayTagListSubscription | Sort-Object Scope, TagName -CaseSensitive) {
                @"
<tr>
<td>$($tagEntry.Scope)</td>
<td>$($tagEntry.TagName)</td>
<td>$($tagEntry.TagCount)</td>
</tr>
"@
            }
            [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsTagsUsage)
            [void]$htmlScopeInsights.AppendLine(@"
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
                [void]$htmlScopeInsights.AppendLine(@"
            paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@"
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
    </div>
"@)
        }
        else {
            [void]$htmlScopeInsights.AppendLine(@"
            <i class="fa fa-ban" aria-hidden="true"></i> Tag Name Usage ($tagsUsageCount Tags) <a class="externallink" href="https://docs.microsoft.com/en-us/azure/cloud-adoption-framework/decision-guides/resource-tagging" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a>
"@)
        }
        [void]$htmlScopeInsights.AppendLine(@'
        </td></tr>
        <tr><!--y--><td class="detailstd"><!--y-->
'@)
        #endregion ScopeInsightsTagNameUsage

        #Consumption
        #$startScopeInsightsConsumptionSub = Get-Date
        #region ScopeInsightsConsumptionSub
        if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {

            if ($htAzureConsumptionSubscriptions.($subscriptionId).ConsumptionData) {
                $consumptionData = $htAzureConsumptionSubscriptions.($subscriptionId).ConsumptionData

                $arrayTotalCostSummarySub = @()
                $arrayConsumptionData = [System.Collections.ArrayList]@()

                $totalCost = 0

                $currency = $htAzureConsumptionSubscriptions.($subscriptionId).Currency
                $consumedServiceCount = ($consumptionData.ResourceType | Sort-Object -Unique | Measure-Object).Count
                $resourceCount = ($consumptionData.ResourceId | Sort-Object -Unique | Measure-Object).Count
                $subConsumptionDataGrouped = $consumptionData | Group-Object -Property ResourceType, ChargeType, MeterCategory

                foreach ($consumptionline in $subConsumptionDataGrouped) {

                    $costConsumptionLine = ($consumptionline.group.PreTaxCost | Measure-Object -Sum).Sum
                    if ([math]::Round($costConsumptionLine, 2) -eq 0) {
                        $cost = $costConsumptionLine.ToString('0.0000')
                    }
                    else {
                        $cost = [math]::Round($costConsumptionLine, 2).ToString('0.00')
                    }

                    $null = $arrayConsumptionData.Add([PSCustomObject]@{
                            ResourceType                 = ($consumptionline.name).split(', ')[0]
                            ConsumedServiceChargeType    = ($consumptionline.name).split(', ')[1]
                            ConsumedServiceCategory      = ($consumptionline.name).split(', ')[2]
                            ConsumedServiceInstanceCount = $consumptionline.Count
                            ConsumedServiceCost          = $cost #[decimal]$cost
                            ConsumedServiceCurrency      = $currency
                        })

                    $totalCost = $htAzureConsumptionSubscriptions.($subscriptionId).TotalCost

                }
                if ([math]::Round($totalCost, 2) -eq 0) {
                    $totalCost = $totalCost
                }
                else {
                    $totalCost = [math]::Round($totalCost, 2).ToString('0.00')
                }
                $arrayTotalCostSummarySub += "$($totalCost) $($currency) generated by $($resourceCount) Resources ($($consumedServiceCount) ResourceTypes)"

                $tfCount = ($arrayConsumptionData | Measure-Object).Count
                $htmlTableId = "ScopeInsights_Consumption_$($subscriptionId -replace '-','_')"
                $randomFunctionName = "func_$htmlTableId"
                [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-credit-card blue" aria-hidden="true"></i> <span class="valignMiddle">Total cost $($arrayTotalCostSummarySub -join ', ') last $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)</span></button>
<div class="content contentSISub">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>ChargeType</th>
<th>ResourceType</th>
<th>Category</th>
<th>ResourceCount</th>
<th>Cost ($($AzureConsumptionPeriod)d)</th>
<th>Currency</th>
</tr>
</thead>
<tbody>
"@)
                $htmlScopeInsightsConsumptionSub = $null
                $htmlScopeInsightsConsumptionSub = foreach ($consumptionLine in $arrayConsumptionData) {
                    @"
<tr>
<td>$($consumptionLine.ConsumedServiceChargeType)</td>
<td>$($consumptionLine.ResourceType)</td>
<td>$($consumptionLine.ConsumedServiceCategory)</td>
<td>$($consumptionLine.ConsumedServiceInstanceCount)</td>
<td>$($consumptionLine.ConsumedServiceCost)</td>
<td>$($currency)</td>
</tr>
"@
                }
                [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsConsumptionSub)
                [void]$htmlScopeInsights.AppendLine(@"
</tbody>
</table>
</div>
<script>
function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
window.helpertfConfig4$htmlTableId=1;
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
                    [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
                }
                [void]$htmlScopeInsights.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
    col_types: [
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'number',
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
                [void]$htmlScopeInsights.AppendLine(@'
<i class="fa fa-credit-card" aria-hidden="true"></i> No Consumption data available
'@)
            }
        }
        else {
            [void]$htmlScopeInsights.AppendLine(@'
<i class="fa fa-credit-card" aria-hidden="true"></i> No Consumption data available as switch parameter -DoAzureConsumption was not applied
'@)
        }

        [void]$htmlScopeInsights.AppendLine(@'
        </td></tr>
        <tr><td class="detailstd">
'@)
        #endregion ScopeInsightsConsumptionSub
        #$endScopeInsightsConsumptionSub = Get-Date
        #Write-Host "  **ScopeInsightsConsumptionSub data duration: $((NEW-TIMESPAN -Start $startScopeInsightsConsumptionSub -End $endScopeInsightsConsumptionSub).TotalSeconds) seconds"

        #ResourceGroups
        #region ScopeInsightsResourceGroups
        if ($subscriptionResourceGroupsCount -gt 0) {
            [void]$htmlScopeInsights.AppendLine(@"
    <i class="fa fa-check-circle" aria-hidden="true"></i> $subscriptionResourceGroupsCount Resource Groups | Limit: ($subscriptionResourceGroupsCount/$LimitResourceGroups)
"@)
        }
        else {
            [void]$htmlScopeInsights.AppendLine(@"
    <i class="fa fa-ban" aria-hidden="true"></i> $subscriptionResourceGroupsCount Resource Groups
"@)
        }
        [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><td class="detailstd">
'@)
        #endregion ScopeInsightsResourceGroups

        #ResourceProvider
        #region ScopeInsightsResourceProvidersDetailed
        if ($azAPICallConf['htParameters'].NoResourceProvidersAtAll -eq $false) {
            if ($azAPICallConf['htParameters'].NoResourceProvidersDetailed -eq $false) {
                if (($htResourceProvidersAll).($subscriptionId)) {
                    $tfCount = ($htResourceProvidersAll).($subscriptionId).Providers.Count
                    $htmlTableId = "ScopeInsights_ResourceProvider_$($subscriptionId -replace '-','_')"
                    $randomFunctionName = "func_$htmlTableId"
                    [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Providers Detailed</span></button>
<div class="content contentSISub">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Provider</th>
<th>State</th>
</tr>
</thead>
<tbody>
"@)
                    $htmlScopeInsightsResourceProvidersDetailed = $null
                    $htmlScopeInsightsResourceProvidersDetailed = foreach ($provider in ($htResourceProvidersAll).($subscriptionId).Providers) {
                        @"
<tr>
<td>$($provider.namespace)</td>
<td>$($provider.registrationState)</td>
</tr>
"@
                    }
                    [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsResourceProvidersDetailed)
                    [void]$htmlScopeInsights.AppendLine(@"
            </tbody>
        </table>
    </div>
    <script>
        function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
            window.helpertfConfig4$htmlTableId=1;
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
                        [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
                    }
                    [void]$htmlScopeInsights.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_1: 'select',
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
                    [void]$htmlScopeInsights.AppendLine(@"
    <i class="fa fa-ban" aria-hidden="true"></i> $(($htResourceProvidersAll.Keys).count) Resource Providers
"@)
                }
                [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><td class="detailstd">
'@)
            }
        }
        #endregion ScopeInsightsResourceProvidersDetailed

        #region ScopeInsightsSubscriptionFeatures
        if ($subscriptionFeatures) {
            $subscriptionFeaturesCount = $subscriptionFeatures.Group.Count

            $tfCount = $subscriptionFeaturesCount
            $htmlTableId = "ScopeInsights_SubscriptionFeatures_$($subscriptionId -replace '-','_')"
            $randomFunctionName = "func_$htmlTableId"

            [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible">
<i class="fa fa-cube" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">$tfCount enabled Subscription Features</span></button>
<div class="content contentSISub">
&nbsp;&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Set up preview features in Azure subscription</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/preview-features" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Feature</th>
</tr>
</thead>
<tbody>
"@)

            foreach ($feature in $subscriptionFeatures.Group | Sort-Object -Property feature) {
                [void]$htmlScopeInsights.AppendLine(@"
    <tr><td>$($feature.feature)</td></tr>
"@)
            }


            [void]$htmlScopeInsights.AppendLine(@"
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
                [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            linked_filters: true,
            col_types: [
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
            [void]$htmlScopeInsights.AppendLine(@'
            <i class="fa fa-ban" aria-hidden="true"></i> 0 enabled Subscription Features <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/preview-features" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a>
'@)
        }
        [void]$htmlScopeInsights.AppendLine(@'
        </td></tr>
        <tr><!--y--><td class="detailstd"><!--y-->
'@)
        #endregion ScopeInsightsSubscriptionFeatures

        #ResourceLocks
        #region ScopeInsightsResourceLocks
        if ($htResourceLocks.($subscriptionId)) {
            $tfCount = 6
            $htmlTableId = "ScopeInsights_ResourceLocks_$($subscriptionId -replace '-','_')"
            $randomFunctionName = "func_$htmlTableId"

            $subscriptionLocksCannotDeleteCount = $htResourceLocks.($subscriptionId).SubscriptionLocksCannotDeleteCount
            $subscriptionLocksReadOnlyCount = $htResourceLocks.($subscriptionId).SubscriptionLocksReadOnlyCount
            $resourceGroupsLocksCannotDeleteCount = $htResourceLocks.($subscriptionId).ResourceGroupsLocksCannotDeleteCount
            $resourceGroupsLocksReadOnlyCount = $htResourceLocks.($subscriptionId).ResourceGroupsLocksReadOnlyCount
            $resourcesLocksCannotDeleteCount = $htResourceLocks.($subscriptionId).ResourcesLocksCannotDeleteCount
            $resourcesLocksReadOnlyCount = $htResourceLocks.($subscriptionId).ResourcesLocksReadOnlyCount

            [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible">
<i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Locks</span></button>
<div class="content contentSISub">
&nbsp;&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Considerations before applying locks</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources#considerations-before-applying-locks" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Lock scope</th>
<th>Lock type</th>
<th>presence</th>
</tr>
</thead>
<tbody>
<tr><td>Subscription</td><td>CannotDelete</td><td>$($subscriptionLocksCannotDeleteCount)</td></tr>
<tr><td>Subscription</td><td>ReadOnly</td><td>$($subscriptionLocksReadOnlyCount)</td></tr>
<tr><td>ResourceGroup</td><td>CannotDelete</td><td>$($resourceGroupsLocksCannotDeleteCount)</td></tr>
<tr><td>ResourceGroup</td><td>ReadOnly</td><td>$($resourceGroupsLocksReadOnlyCount)</td></tr>
<tr><td>Resource</td><td>CannotDelete</td><td>$($resourcesLocksCannotDeleteCount)</td></tr>
<tr><td>Resource</td><td>ReadOnly</td><td>$($resourcesLocksReadOnlyCount)</td></tr>
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
                [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@"
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
            [void]$htmlScopeInsights.AppendLine(@'
            <i class="fa fa-ban" aria-hidden="true"></i> 0 Resource Locks <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources#considerations-before-applying-locks" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a>
'@)
        }
        [void]$htmlScopeInsights.AppendLine(@'
        </td></tr>
        <tr><!--y--><td class="detailstd"><!--y-->
'@)
        #endregion ScopeInsightsResourceLocks

    }

    #MgChildInfo
    #region ScopeInsightsManagementGroups
    if ($mgOrSub -eq 'mg') {

        [void]$htmlScopeInsights.AppendLine(@"
<tr><td class="detailstd">$(($mgAllChildMgs).count -1) ManagementGroups below this scope</td></tr>
<tr><td class="detailstd">$(($mgAllChildSubscriptions).count) Subscriptions below this scope</td></tr>
<tr><td class="detailstd"><i class="fa fa-shield" aria-hidden="true"></i> Microsoft Defender for Cloud Secure Score: $managementGroupASCPoints <a class="externallink" href="https://www.youtube.com/watch?v=2EMnzxdqDhA" target="_blank" rel="noopener">Video <i class="fa fa-external-link" aria-hidden="true"></i></a>, <a class="externallink" href="https://techcommunity.microsoft.com/t5/azure-security-center/security-controls-in-azure-security-center-enable-endpoint/ba-p/1624653" target="_blank" rel="noopener">Blog <i class="fa fa-external-link" aria-hidden="true"></i></a>, <a class="externallink" href="https://docs.microsoft.com/en-us/azure/security-center/secure-score-security-controls#how-your-secure-score-is-calculated" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></td></tr>
<tr><td class="detailstd">
"@)

        #region ScopeInsightsDiagnosticsMg
        if (($htDiagnosticSettingsMgSub).mg.($mgChild)) {
            $diagnosticsMgCount = (($htDiagnosticSettingsMgSub).mg.($mgChild).Values.Count)
            $tfCount = $diagnosticsMgCount
            $htmlTableId = "ScopeInsights_DiagnosticsMg_$($mgChild -replace '\(','_' -replace '\)','_' -replace '-','_' -replace '\.','_')"
            $randomFunctionName = "func_$htmlTableId"
            [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$diagnosticsMgCount Management Group Diagnostic settings</span></button>
<div class="content contentSIMG">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Diagnostic setting</th>
<th>Target</th>
<th>Target Id</th>
"@)
            foreach ($logCategory in $diagnosticSettingsMgCategories) {
                [void]$htmlScopeInsights.AppendLine(@"
<th>$logCategory</th>
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@'
</tr>
</thead>
<tbody>
'@)
            $htmlScopeInsightsDiagnosticsMg = $null
            $htmlScopeInsightsDiagnosticsMg = foreach ($entry in ($htDiagnosticSettingsMgSub).mg.($mgChild).keys | Sort-Object) {
                foreach ($diagset in ($htDiagnosticSettingsMgSub).mg.($mgChild).$entry.keys | Sort-Object) {
                    @"
<tr>
<td>$(($htDiagnosticSettingsMgSub).mg.($mgChild).$entry.$diagset.DiagnosticSettingName)</td>
<td>$(($htDiagnosticSettingsMgSub).mg.($mgChild).$entry.$diagset.DiagnosticTargetType)</td>
<td>$(($htDiagnosticSettingsMgSub).mg.($mgChild).$entry.$diagset.DiagnosticTargetId)</td>
"@
                    foreach ($logCategory in $diagnosticSettingsMgCategories) {
                        if (($htDiagnosticSettingsMgSub).mg.($mgChild).$entry.$diagset.DiagnosticCategoriesHt.($logCategory)) {
                            @"
<td>$(($htDiagnosticSettingsMgSub).mg.($mgChild).$entry.$diagset.DiagnosticCategoriesHt.($logCategory))</td>
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
            }

            [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsDiagnosticsMg)
            [void]$htmlScopeInsights.AppendLine(@"
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
                [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@'
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            linked_filters: true,
            col_1: 'select',
'@)
            $cnt = 2
            foreach ($logCategory in $diagnosticSettingsMgCategories) {
                $cnt++
                [void]$htmlScopeInsights.AppendLine(@"
                col_$($cnt): 'select',
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@'
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
'@)
            $cnt = 0
            foreach ($logCategory in $diagnosticSettingsMgCategories) {
                $cnt++
                if ($diagnosticSettingsMgCategories.Count -eq $cnt) {
                    [void]$htmlScopeInsights.AppendLine(@'
            'caseinsensitivestring'
'@)
                }
                else {
                    [void]$htmlScopeInsights.AppendLine(@'
            'caseinsensitivestring',
'@)
                }
            }
            [void]$htmlScopeInsights.AppendLine(@"
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
            [void]$htmlScopeInsights.AppendLine(@'
    <i class="fa fa-ban" aria-hidden="true"></i> No Management Group Diagnostic settings <a class="externallink" href="https://docs.microsoft.com/en-us/rest/api/monitor/managementgroupdiagnosticsettings/createorupdate" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a>
'@)
        }
        #endregion ScopeInsightsDiagnosticsMg

        [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><td class="detailstd">
'@)

        #$startScopeInsightsConsumptionMg = Get-Date
        #region ScopeInsightsConsumptionMg
        if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
            if ($allConsumptionDataCount -gt 0) {

                $consumptionData = $htManagementGroupsCost.($mgchild).consumptionDataSubscriptions
                if (($consumptionData | Measure-Object).Count -gt 0) {
                    $arrayTotalCostSummaryMg = @()
                    $arrayConsumptionData = [System.Collections.ArrayList]@()
                    $consumptionDataGroupedByCurrency = $consumptionData | Group-Object -Property Currency
                    foreach ($currency in $consumptionDataGroupedByCurrency) {
                        $totalCost = 0
                        $tenantSummaryConsumptionDataGrouped = $currency.group | Group-Object -Property ResourceType, ChargeType, MeterCategory
                        $subsCount = ($tenantSummaryConsumptionDataGrouped.group.subscriptionId | Sort-Object -Unique).Count
                        $consumedServiceCount = ($tenantSummaryConsumptionDataGrouped.group.ResourceType | Sort-Object -Unique).Count
                        $resourceCount = ($tenantSummaryConsumptionDataGrouped.group.ResourceId | Sort-Object -Unique).Count
                        foreach ($consumptionline in $tenantSummaryConsumptionDataGrouped) {

                            $costConsumptionLine = ($consumptionline.group.PreTaxCost | Measure-Object -Sum).Sum
                            if ([math]::Round($costConsumptionLine, 2) -eq 0) {
                                $cost = $costConsumptionLine.ToString('0.0000')
                            }
                            else {
                                $cost = [math]::Round($costConsumptionLine, 2).ToString('0.00')
                            }

                            $null = $arrayConsumptionData.Add([PSCustomObject]@{
                                    ResourceType                 = ($consumptionline.name).split(', ')[0]
                                    ConsumedServiceChargeType    = ($consumptionline.name).split(', ')[1]
                                    ConsumedServiceCategory      = ($consumptionline.name).split(', ')[2]
                                    ConsumedServiceInstanceCount = $consumptionline.Count
                                    ConsumedServiceCost          = $cost #[decimal]$cost
                                    ConsumedServiceSubscriptions = ($consumptionline.group.SubscriptionId | Sort-Object -Unique).Count
                                    ConsumedServiceCurrency      = $currency.Name
                                })

                            $totalCost = $totalCost + $costConsumptionLine
                        }
                        if ([math]::Round($totalCost, 2) -eq 0) {
                            $totalCost = $totalCost.ToString('0.0000')
                        }
                        else {
                            $totalCost = [math]::Round($totalCost, 2).ToString('0.00')
                        }
                        $arrayTotalCostSummaryMg += "$($totalCost) $($currency.Name) generated by $($resourceCount) Resources ($($consumedServiceCount) ResourceTypes) in $($subsCount) Subscriptions"
                    }

                    $tfCount = ($arrayConsumptionData).Count
                    $htmlTableId = "ScopeInsights_Consumption_$($mgChild -replace '\(','_' -replace '\)','_' -replace '-','_' -replace '\.','_')"
                    $randomFunctionName = "func_$htmlTableId"
                    [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-credit-card blue" aria-hidden="true"></i> <span class="valignMiddle">Total cost $($arrayTotalCostSummaryMg -join "$CsvDelimiterOpposite ") last $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)</span></button>
<div class="content contentSIMG">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV
<a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> |
<a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
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
                    $htmlScopeInsightsConsumptionMg = $null
                    $htmlScopeInsightsConsumptionMg = foreach ($consumptionLine in $arrayConsumptionData) {
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
                    [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsConsumptionMg)
                    [void]$htmlScopeInsights.AppendLine(@"
</tbody>
</table>
</div>
<script>
function loadtf$("func_$htmlTableId")() { if (window.helpertfConfig4$htmlTableId !== 1) {
window.helpertfConfig4$htmlTableId=1;
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
                        [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
                    }
                    [void]$htmlScopeInsights.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
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
                    [void]$htmlScopeInsights.AppendLine(@'
<i class="fa fa-credit-card" aria-hidden="true"></i> No Consumption data available for Subscriptions under this ManagementGroup
'@)
                }
            }
            else {
                [void]$htmlScopeInsights.AppendLine(@'
<i class="fa fa-credit-card" aria-hidden="true"></i> No Consumption data available
'@)
            }

            [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><td class="detailstd">
'@)
        }
        else {
            [void]$htmlScopeInsights.AppendLine(@'
<i class="fa fa-credit-card" aria-hidden="true"></i> <span class="valignMiddle">No Consumption data available as switch parameter -DoAzureConsumption was not applied</span>
'@)
        }
        #endregion ScopeInsightsConsumptionMg
        #$endScopeInsightsConsumptionMg = Get-Date
        #Write-Host "   ++ScopeInsightsConsumptionMg duration:  ($((NEW-TIMESPAN -Start $startScopeInsightsConsumptionMg -End $endScopeInsightsConsumptionMg).TotalSeconds) seconds)"


    }
    #endregion ScopeInsightsManagementGroups

    #ScopeInsightsResources
    if ($azAPICallConf['htParameters'].NoResources -eq $false) {
        #resources
        #region ScopeInsightsResources
        if ($mgOrSub -eq 'mg') {
            if ($resourcesAllChildSubscriptionLocationCount -gt 0) {
                $tfCount = ($resourcesAllChildSubscriptionsArray).count
                $htmlTableId = "ScopeInsights_Resources_$($mgChild -replace '\(','_' -replace '\)','_' -replace '-','_' -replace '\.','_')"
                $randomFunctionName = "func_$htmlTableId"
                [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$resourcesAllChildSubscriptionResourceTypeCount ResourceTypes ($resourcesAllChildSubscriptionTotal Resources) in $resourcesAllChildSubscriptionLocationCount Locations (all Subscriptions below this scope)</span></button>
<div class="content contentSIMG">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">ResourceType</th>
<th>Location</th>
<th>Count</th>
</tr>
</thead>
<tbody>
"@)
                $htmlScopeInsightsResources = $null
                $htmlScopeInsightsResources = foreach ($resourceAllChildSubscriptionResourceTypePerLocation in $resourcesAllChildSubscriptionsArray | Sort-Object @{Expression = { $_.ResourceType } }, @{Expression = { $_.location } }) {
                    @"
<tr>
<td>$($resourceAllChildSubscriptionResourceTypePerLocation.ResourceType)</td>
<td>$($resourceAllChildSubscriptionResourceTypePerLocation.location)</td>
<td>$($resourceAllChildSubscriptionResourceTypePerLocation.ResourceCount)</td>
</tr>
"@
                }
                [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsResources)
                [void]$htmlScopeInsights.AppendLine(@"
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
                    [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
                }
                [void]$htmlScopeInsights.AppendLine(@"
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
    </div>
"@)
            }
            else {
                [void]$htmlScopeInsights.AppendLine(@"
            <i class="fa fa-ban" aria-hidden="true"></i> $resourcesAllChildSubscriptionResourceTypeCount ResourceTypes (all Subscriptions below this scope)
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><td class="detailstd">
'@)
        }

        if ($mgOrSub -eq 'sub') {
            if ($resourcesSubscriptionResourceTypeCount -gt 0) {
                $tfCount = ($resourcesSubscription).Count
                $htmlTableId = "ScopeInsights_Resources_$($subscriptionId -replace '-','_')"
                $randomFunctionName = "func_$htmlTableId"
                [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$resourcesSubscriptionResourceTypeCount ResourceTypes ($resourcesSubscriptionTotal Resources) in $resourcesSubscriptionLocationCount Locations</span></button>
<div class="content contentSISub">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">ResourceType</th>
<th>Location</th>
<th>Count</th>
</tr>
</thead>
<tbody>
"@)
                $htmlScopeInsightsResources = $null
                $htmlScopeInsightsResources = foreach ($resourceSubscriptionResourceTypePerLocation in $resourcesSubscription | Sort-Object @{Expression = { $_.type } }, @{Expression = { $_.location } }, @{Expression = { $_.count_ } }) {
                    @"
<tr>
<td>$($resourceSubscriptionResourceTypePerLocation.type)</td>
<td>$($resourceSubscriptionResourceTypePerLocation.location)</td>
<td>$($resourceSubscriptionResourceTypePerLocation.count_)</td>
</tr>
"@
                }
                [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsResources)
                [void]$htmlScopeInsights.AppendLine(@"
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
                    [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
                }
                [void]$htmlScopeInsights.AppendLine(@"
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
    </div>
"@)
            }
            else {
                [void]$htmlScopeInsights.AppendLine(@"
            <i class="fa fa-ban" aria-hidden="true"></i> $resourcesSubscriptionResourceTypeCount ResourceTypes
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><td class="detailstd">
'@)
        }
        #endregion ScopeInsightsResources
    }

    if ($azAPICallConf['htParameters'].NoResources -eq $false) {
        #region ScopeInsightsCAFResourceNamingALL
        if ($mgOrSub -eq 'sub') {
            $resourcesIdsAllCAFNamingRelevantThisSubscription = $resourcesIdsAllCAFNamingRelevantGroupedBySubscription.where({ $_.Name -eq $subscriptionId })
            if ($resourcesIdsAllCAFNamingRelevantThisSubscription) {
                $resourcesIdsAllCAFNamingRelevantThisSubscriptionGroupedByType = $resourcesIdsAllCAFNamingRelevantThisSubscription.Group | Group-Object -Property type
                $resourcesIdsAllCAFNamingRelevantThisSubscriptionGroupedByTypeCount = ($resourcesIdsAllCAFNamingRelevantThisSubscriptionGroupedByType | Measure-Object).Count

                $tfCount = $resourcesIdsAllCAFNamingRelevantThisSubscriptionGroupedByTypeCount
                $htmlTableId = "ScopeInsights_CAFResourceNamingALL_$($subscriptionId -replace '-','_')"
                $randomFunctionName = "func_$htmlTableId"
                [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-star-o" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">CAF Naming Recommendation Compliance</span></button>
<div class="content contentSISub">
&nbsp;&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">CAF - Recommended abbreviations for Azure resource types</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
&nbsp;&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true"></i> Resource details can be found in the CSV output *_ResourcesAll.csv<br>
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
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
                $htmlScopeInsightsCAFResourceNamingALL = $null
                $htmlScopeInsightsCAFResourceNamingALL = foreach ($entry in $resourcesIdsAllCAFNamingRelevantThisSubscriptionGroupedByType) {

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
                [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsCAFResourceNamingALL)
                [void]$htmlScopeInsights.AppendLine(@"
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
                    [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
                }
                [void]$htmlScopeInsights.AppendLine(@"
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
    </div>
"@)
            }
            else {
                [void]$htmlScopeInsights.AppendLine(@'
                <i class="fa fa-ban" aria-hidden="true"></i> No CAF Naming Recommendation Compliance data available
'@)
            }

            [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><td class="detailstd">
'@)
        }
        #endregion ScopeInsightsCAFResourceNamingALL
    }

    #region ScopeInsightsOrphanedResources
    if ($mgOrSub -eq 'sub') {
        if ($arrayOrphanedResourcesGroupedBySubscription) {
            $orphanedResourcesThisSubscription = $arrayOrphanedResourcesGroupedBySubscription.where({ $_.Name -eq $subscriptionId })
            if ($orphanedResourcesThisSubscription) {
                $orphanedResourcesThisSubscriptionCount = $orphanedResourcesThisSubscription.Group.count

                if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
                    $orphanedIncludingCost = $true
                    $hintTableTH = " ($($AzureConsumptionPeriod) days)"

                    $orphanedResourcesThisSubscriptionGroupedByType = $orphanedResourcesThisSubscription.Group | Group-Object -Property type, currency
                    $orphanedResourcesThisSubscriptionGroupedByTypeCount = ($orphanedResourcesThisSubscriptionGroupedByType | Measure-Object).Count
                }
                else {
                    $orphanedIncludingCost = $false
                    $hintTableTH = ''

                    $orphanedResourcesThisSubscriptionGroupedByType = $orphanedResourcesThisSubscription.Group | Group-Object -Property type
                    $orphanedResourcesThisSubscriptionGroupedByTypeCount = ($orphanedResourcesThisSubscriptionGroupedByType | Measure-Object).Count
                }

                $tfCount = $orphanedResourcesThisSubscriptionGroupedByTypeCount
                $htmlTableId = "ScopeInsights_OrphanedResources_$($subscriptionId -replace '-','_')"
                $randomFunctionName = "func_$htmlTableId"
                [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-trash-o" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">$orphanedResourcesThisSubscriptionCount Cost optimization & cleanup ($orphanedResourcesThisSubscriptionGroupedByTypeCount ResourceTypes)</span></button>
<div class="content contentSISub">
&nbsp;&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">'Azure Orphan Resources' ARG queries and workbooks</span> <a class="externallink" href="https://github.com/dolevshor/azure-orphan-resources" target="_blank" rel="noopener">GitHub <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
&nbsp;&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true"></i> Resource details can be found in the CSV output *_ResourcesCostOptimizationAndCleanup.csv<br>
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>ResourceType</th>
<th>Resource count</th>
<th>Intent</th>
<th>Cost$($hintTableTH)</th>
<th>Currency</th>
</tr>
</thead>
<tbody>
"@)
                $htmlScopeInsightsOrphanedResources = $null
                $htmlScopeInsightsOrphanedResources = foreach ($resourceType in $orphanedResourcesThisSubscriptionGroupedByType | Sort-Object -Property Name) {

                    if ($orphanedIncludingCost) {
                        if (($resourceType.Group[0].Intent) -like 'cost savings*') {
                            $orphCost = ($resourceType.Group.Cost | Measure-Object -Sum).Sum
                            if ($orphCost -eq 0) {
                                $orphCost = ''
                            }
                            $orphCurrency = $resourceType.Group[0].Currency
                        }
                        else {
                            $orphCost = ''
                            $orphCurrency = ''
                        }
                    }
                    else {
                        if (($resourceType.Group.Intent | Get-Unique) -like 'cost savings*') {
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
<td>$(($resourceType.Name -split ',')[0])</td>
<td>$($resourceType.Group.Count)</td>
<td>$($resourceType.Group[0].Intent)</td>
<td>$($orphCost)</td>
<td>$($orphCurrency)</td>
</tr>
"@
                }
                [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsOrphanedResources)
                [void]$htmlScopeInsights.AppendLine(@"
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
                    [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
                }
                [void]$htmlScopeInsights.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
                col_0: 'multiple',
                col_2: 'select',
                col_4: 'select',
                col_types: [
                    'caseinsensitivestring',
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
    </div>
"@)
            }
            else {
                [void]$htmlScopeInsights.AppendLine(@'
                <i class="fa fa-ban" aria-hidden="true"></i> No cost optimization & cleanup
'@)
            }
        }
        else {
            [void]$htmlScopeInsights.AppendLine(@'
            <i class="fa fa-ban" aria-hidden="true"></i> No cost optimization & cleanup
'@)
        }
        [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><td class="detailstd">
'@)
    }
    #endregion ScopeInsightsOrphanedResources

    #ScopeInsightsDiagnosticsCapable
    if ($azAPICallConf['htParameters'].NoResources -eq $false) {
        #resourcesDiagnosticsCapable
        #region ScopeInsightsDiagnosticsCapable
        if ($mgOrSub -eq 'mg') {
            $resourceTypesUnique = ($resourcesAllChildSubscriptions | Select-Object type -Unique).type
            $resourceTypesSummarizedArray = [System.Collections.ArrayList]@()
            foreach ($resourceTypeUnique in $resourceTypesUnique) {
                $resourcesTypeCountTotal = 0
                ($resourcesAllChildSubscriptions.where( { $_.type -eq $resourceTypeUnique } )).count_ | ForEach-Object { $resourcesTypeCountTotal += $_ }
                $dataFromResourceTypesDiagnosticsArray = $resourceTypesDiagnosticsArray.where( { $_.ResourceType -eq $resourceTypeUnique } )
                if ($dataFromResourceTypesDiagnosticsArray.Metrics -eq $true -or $dataFromResourceTypesDiagnosticsArray.Logs -eq $true) {
                    $resourceDiagnosticscapable = $true
                }
                else {
                    $resourceDiagnosticscapable = $false
                }
                $null = $resourceTypesSummarizedArray.Add([PSCustomObject]@{
                        ResourceType       = $resourceTypeUnique
                        ResourceCount      = $resourcesTypeCountTotal
                        DiagnosticsCapable = $resourceDiagnosticscapable
                        Metrics            = $dataFromResourceTypesDiagnosticsArray.Metrics
                        Logs               = $dataFromResourceTypesDiagnosticsArray.Logs
                        LogCategories      = ($dataFromResourceTypesDiagnosticsArray.LogCategories -join "$CsvDelimiterOpposite ")
                    })
            }
            $subscriptionResourceTypesDiagnosticsCapableMetricsCount = ($resourceTypesSummarizedArray.where( { $_.Metrics -eq $true } )).count
            $subscriptionResourceTypesDiagnosticsCapableLogsCount = ($resourceTypesSummarizedArray.where( { $_.Logs -eq $true } )).count
            $subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount = ($resourceTypesSummarizedArray.where( { $_.Metrics -eq $true -or $_.Logs -eq $true } )).count

            if ($resourcesAllChildSubscriptionResourceTypeCount -gt 0) {
                $tfCount = $resourcesAllChildSubscriptionResourceTypeCount
                $htmlTableId = "ScopeInsights_resourcesDiagnosticsCapable_$($mgchild -replace '\(','_' -replace '\)','_' -replace '-','_' -replace '\.','_')"
                $randomFunctionName = "func_$htmlTableId"
                [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount/$resourcesAllChildSubscriptionResourceTypeCount ResourceTypes (1st party) Diagnostics capable ($subscriptionResourceTypesDiagnosticsCapableMetricsCount Metrics, $subscriptionResourceTypesDiagnosticsCapableLogsCount Logs) (all Subscriptions below this scope)</span></button>
<div class="content contentSIMG">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">ResourceType</th>
<th>Resource Count</th>
<th>Diagnostics capable</th>
<th>Metrics</th>
<th>Logs</th>
<th>LogCategories</th>
</tr>
</thead>
<tbody>
"@)
                $htmlScopeInsightsDiagnosticsCapable = $null
                $htmlScopeInsightsDiagnosticsCapable = foreach ($resourceSubscriptionResourceType in $resourceTypesSummarizedArray | Sort-Object @{Expression = { $_.ResourceType } }) {
                    @"
<tr>
<td>$($resourceSubscriptionResourceType.ResourceType)</td>
<td>$($resourceSubscriptionResourceType.ResourceCount)</td>
<td>$($resourceSubscriptionResourceType.DiagnosticsCapable)</td>
<td>$($resourceSubscriptionResourceType.Metrics)</td>
<td>$($resourceSubscriptionResourceType.Logs)</td>
<td>$($resourceSubscriptionResourceType.LogCategories)</td>
</tr>
"@
                }
                [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsDiagnosticsCapable)
                [void]$htmlScopeInsights.AppendLine(@"
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
                    [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
                }
                [void]$htmlScopeInsights.AppendLine(@"
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
    </div>
"@)
            }
            else {
                [void]$htmlScopeInsights.AppendLine(@"
            <i class="fa fa-ban" aria-hidden="true"></i> $resourcesAllChildSubscriptionResourceTypeCount ResourceTypes (1st party) Diagnostics capable (all Subscriptions below this scope)
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><td class="detailstd">
'@)
        }

        if ($mgOrSub -eq 'sub') {
            $resourceTypesUnique = ($resourcesSubscription | Select-Object type -Unique).type
            $resourceTypesSummarizedArray = [System.Collections.ArrayList]@()
            foreach ($resourceTypeUnique in $resourceTypesUnique) {
                $resourcesTypeCountTotal = 0
                ($resourcesSubscription.where( { $_.type -eq $resourceTypeUnique } )).count_ | ForEach-Object { $resourcesTypeCountTotal += $_ }
                $dataFromResourceTypesDiagnosticsArray = $resourceTypesDiagnosticsArray.where( { $_.ResourceType -eq $resourceTypeUnique } )
                if ($dataFromResourceTypesDiagnosticsArray.Metrics -eq $true -or $dataFromResourceTypesDiagnosticsArray.Logs -eq $true) {
                    $resourceDiagnosticscapable = $true
                }
                else {
                    $resourceDiagnosticscapable = $false
                }
                $null = $resourceTypesSummarizedArray.Add([PSCustomObject]@{
                        ResourceType       = $resourceTypeUnique
                        ResourceCount      = $resourcesTypeCountTotal
                        DiagnosticsCapable = $resourceDiagnosticscapable
                        Metrics            = $dataFromResourceTypesDiagnosticsArray.Metrics
                        Logs               = $dataFromResourceTypesDiagnosticsArray.Logs
                        LogCategories      = ($dataFromResourceTypesDiagnosticsArray.LogCategories -join "$CsvDelimiterOpposite ")
                    })
            }

            $subscriptionResourceTypesDiagnosticsCapableMetricsCount = ($resourceTypesSummarizedArray.where( { $_.Metrics -eq $true } )).count
            $subscriptionResourceTypesDiagnosticsCapableLogsCount = ($resourceTypesSummarizedArray.where( { $_.Logs -eq $true } )).count
            $subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount = ($resourceTypesSummarizedArray.where( { $_.Metrics -eq $true -or $_.Logs -eq $true } )).count

            if ($resourcesSubscriptionResourceTypeCount -gt 0) {
                $tfCount = $resourcesSubscriptionResourceTypeCount
                $htmlTableId = "ScopeInsights_resourcesDiagnosticsCapable_$($subscriptionId -replace '-','_')"
                $randomFunctionName = "func_$htmlTableId"
                [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount/$resourcesSubscriptionResourceTypeCount ResourceTypes (1st party) Diagnostics capable ($subscriptionResourceTypesDiagnosticsCapableMetricsCount Metrics, $subscriptionResourceTypesDiagnosticsCapableLogsCount Logs)</span></button>
<div class="content contentSISub">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">ResourceType</th>
<th>Resource Count</th>
<th>Diagnostics capable</th>
<th>Metrics</th>
<th>Logs</th>
<th>LogCategories</th>
</tr>
</thead>
<tbody>
"@)
                $htmlScopeInsightsDiagnosticsCapable = $null
                $htmlScopeInsightsDiagnosticsCapable = foreach ($resourceSubscriptionResourceType in $resourceTypesSummarizedArray | Sort-Object @{Expression = { $_.ResourceType } }) {
                    @"
<tr>
<td>$($resourceSubscriptionResourceType.ResourceType)</td>
<td>$($resourceSubscriptionResourceType.ResourceCount)</td>
<td>$($resourceSubscriptionResourceType.DiagnosticsCapable)</td>
<td>$($resourceSubscriptionResourceType.Metrics)</td>
<td>$($resourceSubscriptionResourceType.Logs)</td>
<td>$($resourceSubscriptionResourceType.LogCategories)</td>
</tr>
"@
                }
                [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsDiagnosticsCapable)
                [void]$htmlScopeInsights.AppendLine(@"
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
                    [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
                }
                [void]$htmlScopeInsights.AppendLine(@"
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
    </div>
"@)
            }
            else {
                [void]$htmlScopeInsights.AppendLine(@"
            <i class="fa fa-ban" aria-hidden="true"></i> $resourcesSubscriptionResourceTypeCount ResourceTypes (1st party) Diagnostics capable
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><td class="detailstd">
'@)
        }
        #endregion ScopeInsightsDiagnosticsCapable
    }

    #ScopeInsightsUserAssignedIdentities4Resources
    if ($azAPICallConf['htParameters'].NoResources -eq $false) {
        if ($mgOrSub -eq 'sub') {
            #region ScopeInsightsUserAssignedIdentities4Resources
            if ($arrayUserAssignedIdentities4ResourcesSubscriptionCount -gt 0) {
                $tfCount = $arrayUserAssignedIdentities4ResourcesSubscriptionCount
                $htmlTableId = "ScopeInsights_UserAssignedIdentities4Resources_$($subscriptionId -replace '-','_')"
                $randomFunctionName = "func_$htmlTableId"
                [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible">
<i class="fa fa-user-circle-o" aria-hidden="true"></i> <span class="valignMiddle">UserAssigned Managed Identities assigned to Resources / vice versa</span></button>
<div class="content contentSISub">
&nbsp;&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Managed identity 'user-assigned' vs 'system-assigned'</span> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview#managed-identity-types" target="_blank" rel="noopener">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
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
</tr>
</thead>
<tbody>
"@)
                $htmlScopeInsightsUserAssignedIdentities4Resource = $null
                $htmlScopeInsightsUserAssignedIdentities4Resource = foreach ($miResEntry in $arrayUserAssignedIdentities4ResourcesSubscription | Sort-Object -Property miResourceId, resourceId) {
                    @"
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
"@
                }
                [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsUserAssignedIdentities4Resource)
                [void]$htmlScopeInsights.AppendLine(@"
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
                    [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
                }
                [void]$htmlScopeInsights.AppendLine(@"
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
                [void]$htmlScopeInsights.AppendLine(@'
            <i class="fa fa-ban" aria-hidden="true"></i> No UserAssigned Managed Identities assigned to Resources / vice versa - at all
'@)
            }
            [void]$htmlScopeInsights.AppendLine(@'
        </td></tr>
        <tr><!--y--><td class="detailstd"><!--y-->
'@)
            #endregion ScopeInsightsUserAssignedIdentities4Resources
        }
    }

    #ScopeInsightsPSRule
    if ($azAPICallConf['htParameters'].NoResources -eq $false) {
        if ($azAPICallConf['htParameters'].DoPSRule -eq $true) {
            #region ScopeInsightsPSRule

            if ($mgOrSub -eq 'mg') {

                $allPSRuleResultsUnderThisMg = [system.collections.ArrayList]@()
                foreach ($mg in $grpPSRuleManagementGroups) {
                    if ($htManagementGroupsMgPath.($mg.name -replace '.*/').path -contains $mgchild) {
                        $allPSRuleResultsUnderThisMg.AddRange($mg.Group)
                    }
                }

                $grpThisManagementGroup = $allPSRuleResultsUnderThisMg | Group-Object -Property resourceType, pillar, category, severity, rule, result

                if ($grpThisManagementGroup) {
                    $grpThisManagementGroupCount = $grpThisManagementGroup.Count
                    $tfCount = $grpThisManagementGroupCount
                    $htmlTableId = "ScopeInsights_PSRule_$($mgchild -replace '\(','_' -replace '\)','_' -replace '-','_' -replace '\.','_')"
                    $randomFunctionName = "func_$htmlTableId"
                    [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible">
<i class="fa fa-check-square-o" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">$grpThisManagementGroupCount 'PSRule for Azure' results</span></button>
<div class="content contentSIMG">
&nbsp;&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Learn about</span> <a class="externallink" href="https://azure.github.io/PSRule.Rules.Azure" target="_blank" rel="noopener">PSRule for Azure <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
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
                    $htmlScopeInsightsPSRuleMG = $null
                    $htmlScopeInsightsPSRuleMG = foreach ($result in $grpThisManagementGroup) {
                        $resultNameSplit = $result.Name.split(', ')
                        @"
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
"@
                    }
                    [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsPSRuleMG)
                    [void]$htmlScopeInsights.AppendLine(@"
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
                        [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
                    }
                    [void]$htmlScopeInsights.AppendLine(@"
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
                    [void]$htmlScopeInsights.AppendLine(@'
                    <i class="fa fa-ban" aria-hidden="true"></i> No PSRule for Azure results
'@)
                }
                [void]$htmlScopeInsights.AppendLine(@'
                </td></tr>
                <tr><!--y--><td class="detailstd"><!--y-->
'@)
            }

            if ($mgOrSub -eq 'sub') {
                $grpThisSubscription = $grpPSRuleSubscriptions.where({ $_.Name -eq $subscriptionId })
                $grpThisSubscriptionGrouped = $grpThisSubscription.Group | Group-Object -Property resourceType, pillar, category, severity, rule, result

                if ($grpThisSubscriptionGrouped) {
                    $grpThisSubscriptionGroupedCount = $grpThisSubscriptionGrouped.Count
                    $tfCount = $grpThisSubscriptionGroupedCount
                    $htmlTableId = "ScopeInsights_PSRule_$($subscriptionId -replace '-','_')"
                    $randomFunctionName = "func_$htmlTableId"
                    [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible">
<i class="fa fa-check-square-o" aria-hidden="true"></i> <span class="valignMiddle">$grpThisSubscriptionGroupedCount PSRule for Azure results</span></button>
<div class="content contentSISub">
&nbsp;&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true"></i> <span class="info">Learn about</span> <a class="externallink" href="https://azure.github.io/PSRule.Rules.Azure" target="_blank" rel="noopener">PSRule for Azure <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Resource Type</th>
<th>Resource Count</th>
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
                    $htmlScopeInsightsPSRuleSub = $null
                    $htmlScopeInsightsPSRuleSub = foreach ($result in $grpThisSubscriptionGrouped) {
                        $resultNameSplit = $result.Name.split(', ')
                        @"
                        <tr>
                            <td>$($resultNameSplit[0])</td>
                            <td>$($result.Group.Count)</td>
                            <td>$($resultNameSplit[1])</td>
                            <td>$($resultNameSplit[2])</td>
                            <td>$($resultNameSplit[3])</td>
                            <td>$(($result.Group[0].rule))</td>
                            <td>$(($result.Group[0].recommendation))</td>
                            <td><a href=`"$(($result.Group[0].link))`" target=`"_blank`"><i class="fa fa-external-link" aria-hidden="true"></i></a></td>
                            <td>$($resultNameSplit[5])</td>
                        </tr>
"@
                    }
                    [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsPSRuleSub)
                    [void]$htmlScopeInsights.AppendLine(@"
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
                        [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
                    }
                    [void]$htmlScopeInsights.AppendLine(@"
                btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
                linked_filters: true,
                col_2: 'select',
                col_3: 'select',
                col_4: 'select',
                col_8: 'select',
                col_types: [
                    'caseinsensitivestring',
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
                    [void]$htmlScopeInsights.AppendLine(@'
                    <i class="fa fa-ban" aria-hidden="true"></i> No PSRule results
'@)
                }
                [void]$htmlScopeInsights.AppendLine(@'
                </td></tr>
                <tr><!--y--><td class="detailstd"><!--y-->
'@)
            }
            #endregion ScopeInsightsPSRule
        }
        else {
            [void]$htmlScopeInsights.AppendLine(@'
            <i class="fa fa-check-square-o" aria-hidden="true"></i> PSRule for Azure - <span class="info">integration paused - <a class="externallink" href="https://azure.github.io/PSRule.Rules.Azure/integrations" target="_blank" rel="noopener">PSRule for Azure <i class="fa fa-external-link" aria-hidden="true"></i></a>
'@)
        }
    }

    #PolicyAssignments
    #region ScopeInsightsPolicyAssignments
    if ($mgOrSub -eq 'mg') {
        $SIDivContentClass = 'contentSIMG'
        $htmlTableIdentifier = $mgChild

        $policiesAssigned = [System.Collections.ArrayList]@()
        $policiesCount = 0
        $policiesCountBuiltin = 0
        $policiesCountCustom = 0
        $policiesAssignedAtScope = 0
        $policiesInherited = 0
        foreach ($policyAssignment in $arrayPolicyAssignmentsEnrichedForThisManagementGroupVariantPolicy) {
            if ([String]::IsNullOrEmpty($policyAssignment.subscriptionId)) {
                $null = $policiesAssigned.Add($policyAssignment)
                $policiesCount++
                if ($policyAssignment.PolicyType -eq 'BuiltIn') {
                    $policiesCountBuiltin++
                }
                if ($policyAssignment.PolicyType -eq 'Custom') {
                    $policiesCountCustom++
                }
                if ($policyAssignment.Inheritance -like 'this*') {
                    $policiesAssignedAtScope++
                }
                if ($policyAssignment.Inheritance -notlike 'this*') {
                    $policiesInherited++
                }
            }
        }
    }
    if ($mgOrSub -eq 'sub') {
        $SIDivContentClass = 'contentSISub'
        $htmlTableIdentifier = $subscriptionId

        $policiesAssigned = [System.Collections.ArrayList]@()
        $policiesCount = 0
        $policiesCountBuiltin = 0
        $policiesCountCustom = 0
        $policiesAssignedAtScope = 0
        $policiesInherited = 0
        foreach ($policyAssignment in $arrayPolicyAssignmentsEnrichedForThisSubscriptionVariantPolicy) {
            $null = $policiesAssigned.Add($policyAssignment)
            $policiesCount++
            if ($policyAssignment.PolicyType -eq 'BuiltIn') {
                $policiesCountBuiltin++
            }
            if ($policyAssignment.PolicyType -eq 'Custom') {
                $policiesCountCustom++
            }
            if ($policyAssignment.Inheritance -like 'this*') {
                $policiesAssignedAtScope++
            }
            if ($policyAssignment.Inheritance -notlike 'this*') {
                $policiesInherited++
            }
        }
    }

    if (($policiesAssigned).count -gt 0) {
        $tfCount = ($policiesAssigned).count
        $htmlTableId = "ScopeInsights_PolicyAssignments_$($htmlTableIdentifier -replace '\(','_' -replace '\)','_' -replace '-','_' -replace '\.','_')"
        $randomFunctionName = "func_$htmlTableId"
        $noteOrNot = ''
        [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$policiesCount Policy assignments ($policiesAssignedAtScope at scope, $policiesInherited inherited) (Builtin: $policiesCountBuiltin | Custom: $policiesCountCustom)</span></button>
<div class="content $SIDivContentClass">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a><br>
&nbsp;&nbsp;<span class="hintTableSize">*Depending on the number of rows and your computer´s performance the table may respond with delay, download the csv for better filtering experience</span>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Inheritance</th>
<th>ScopeExcluded</th>
<th>Exemption applies</th>
<th>Policy DisplayName</th>
<th>PolicyId</th>
<th>Type</th>
<th>Category</th>
<th>ALZ</th>
<th>Effect</th>
<th>Parameters</th>
<th>Enforcement</th>
<th>NonCompliance Message</th>
"@)

        if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {

            [void]$htmlScopeInsights.AppendLine(@'
<th>Policies NonCmplnt</th>
<th>Policies Compliant</th>
<th>Resources NonCmplnt</th>
<th>Resources Compliant</th>
<th>Resources Conflicting</th>
'@)
        }

        [void]$htmlScopeInsights.AppendLine(@"
<th>Role/Assignment $noteOrNot</th>
<th>Managed Identity</th>
<th>Assignment DisplayName</th>
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
        $htmlScopeInsightsPolicyAssignments = $null
        $htmlScopeInsightsPolicyAssignments = foreach ($policyAssignment in $policiesAssigned | Sort-Object @{Expression = { $_.Level } }, @{Expression = { $_.MgName } }, @{Expression = { $_.MgId } }, @{Expression = { $_.SubscriptionName } }, @{Expression = { $_.SubscriptionId } }, @{Expression = { $_.PolicyAssignmentId } }) {

            if ($policyAssignment.PolicyType -eq 'Custom') {
                $policyName = ($policyAssignment.PolicyName -replace '<', '&lt;' -replace '>', '&gt;')
            }
            else {
                $policyName = $policyAssignment.PolicyName
            }
            @"
<tr>
<td>$($policyAssignment.Inheritance)</td>
<td>$($policyAssignment.ExcludedScope)</td>
<td>$($policyAssignment.ExemptionScope)</td>
<td class="breakwordall">$($policyName)</td>
<td class="breakwordall">$($policyAssignment.PolicyId)</td>
<td>$($policyAssignment.PolicyType)</td>
<td>$($policyAssignment.PolicyCategory -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policyAssignment.PolicyIsALZ)</td>
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
<td>$($policyAssignment.PolicyAssignmentMI)</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policyAssignment.AssignedBy)</td>
<td>$($policyAssignment.CreatedOn)</td>
<td>$($policyAssignment.CreatedBy)</td>
<td>$($policyAssignment.UpdatedOn)</td>
<td>$($policyAssignment.UpdatedBy)</td>
</tr>
"@
        }
        [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsPolicyAssignments)
        [void]$htmlScopeInsights.AppendLine(@"
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
            [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlScopeInsights.AppendLine(@'
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            linked_filters: true,
            col_1: 'select',
            col_2: 'select',
            col_5: 'select',
            col_7: 'select',
            col_8: 'select',
            col_10: 'select',
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
'@)

        if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {

            [void]$htmlScopeInsights.AppendLine(@'

                'number',
                'number',
                'number',
                'number',
                'number',
'@)
        }
        [void]$htmlScopeInsights.AppendLine(@"
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
            watermark: ['try: thisScope'],
            extensions: [{ name: 'colsVisibility', text: 'Columns: ', enable_tick_all: true },{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlScopeInsights.AppendLine(@"
    <i class="fa fa-ban" aria-hidden="true"></i> $(($policiesAssigned).count) Policy assignments
"@)
    }
    [void]$htmlScopeInsights.AppendLine(@'
        </td></tr>
        <tr><!--y--><td class="detailstd"><!--y-->
'@)
    #endregion ScopeInsightsPolicyAssignments

    #PolicySetAssignments
    #region ScopeInsightsPolicySetAssignments
    if ($mgOrSub -eq 'mg') {
        $SIDivContentClass = 'contentSIMG'
        $htmlTableIdentifier = $mgChild

        $policySetsAssigned = [System.Collections.ArrayList]@()
        $policySetsCount = 0
        $policySetsCountBuiltin = 0
        $policySetsCountCustom = 0
        $policySetsAssignedAtScope = 0
        $policySetsInherited = 0
        foreach ($policySetAssignment in $arrayPolicyAssignmentsEnrichedForThisManagementGroupVariantPolicySet) {
            if ([String]::IsNullOrEmpty($policySetAssignment.subscriptionId)) {
                $null = $policySetsAssigned.Add($policySetAssignment)
                $policySetsCount++
                if ($policySetAssignment.PolicyType -eq 'BuiltIn') {
                    $policySetsCountBuiltin++
                }
                if ($policySetAssignment.PolicyType -eq 'Custom') {
                    $policySetsCountCustom++
                }
                if ($policySetAssignment.Inheritance -like 'this*') {
                    $policySetsAssignedAtScope++
                }
                if ($policySetAssignment.Inheritance -notlike 'this*') {
                    $policySetsInherited++
                }
            }
        }
    }
    if ($mgOrSub -eq 'sub') {
        $SIDivContentClass = 'contentSISub'
        $htmlTableIdentifier = $subscriptionId

        $policySetsAssigned = [System.Collections.ArrayList]@()
        $policySetsCount = 0
        $policySetsCountBuiltin = 0
        $policySetsCountCustom = 0
        $policySetsAssignedAtScope = 0
        $policySetsInherited = 0
        foreach ($policySetAssignment in $arrayPolicyAssignmentsEnrichedForThisSubscriptionVariantPolicySet) {
            $null = $policySetsAssigned.Add($policySetAssignment)
            $policySetsCount++
            if ($policySetAssignment.PolicyType -eq 'BuiltIn') {
                $policySetsCountBuiltin++
            }
            if ($policySetAssignment.PolicyType -eq 'Custom') {
                $policySetsCountCustom++
            }
            if ($policySetAssignment.Inheritance -like 'this*') {
                $policySetsAssignedAtScope++
            }
            if ($policySetAssignment.Inheritance -notlike 'this*') {
                $policySetsInherited++
            }
        }
    }

    if (($policySetsAssigned).count -gt 0) {
        $tfCount = ($policiesAssigned).count
        $htmlTableId = "ScopeInsights_PolicySetAssignments_$($htmlTableIdentifier -replace '\(','_' -replace '\)','_' -replace '-','_' -replace '\.','_')"
        $randomFunctionName = "func_$htmlTableId"
        $noteOrNot = ''
        [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$policySetsCount PolicySet assignments ($policySetsAssignedAtScope at scope, $policySetsInherited inherited) (Builtin: $policySetsCountBuiltin | Custom: $policySetsCountCustom)</span></button>
<div class="content $SIDivContentClass">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Inheritance</th>
<th>ScopeExcluded</th>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
<th>Type</th>
<th>Category</th>
<th>ALZ</th>
<th>Parameters</th>
<th>Enforcement</th>
<th>NonCompliance Message</th>
"@)

        if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {

            [void]$htmlScopeInsights.AppendLine(@'
<th>Policies NonCmplnt</th>
<th>Policies Compliant</th>
<th>Resources NonCmplnt</th>
<th>Resources Compliant</th>
<th>Resources Conflicting</th>
'@)
        }

        [void]$htmlScopeInsights.AppendLine(@"
<th>Role/Assignment $noteOrNot</th>
<th>Managed Identity</th>
<th>Assignment DisplayName</th>
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
        $htmlScopeInsightsPolicySetAssignments = $null
        $htmlScopeInsightsPolicySetAssignments = foreach ($policyAssignment in $policySetsAssigned | Sort-Object -Property Level, PolicyAssignmentId) {
            if ($policyAssignment.PolicyType -eq 'Custom') {
                $policyName = ($policyAssignment.PolicyName -replace '<', '&lt;' -replace '>', '&gt;')
            }
            else {
                $policyName = $policyAssignment.PolicyName
            }
            @"
<tr>
<td>$($policyAssignment.Inheritance)</td>
<td>$($policyAssignment.ExcludedScope)</td>
<td class="breakwordall">$($policyName)</td>
<td class="breakwordall">$($policyAssignment.PolicyId)</td>
<td>$($policyAssignment.PolicyType)</td>
<td>$($policyAssignment.PolicyCategory -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policyAssignment.PolicyIsALZ)</td>
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
<td>$($policyAssignment.PolicyAssignmentMI)</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($policyAssignment.AssignedBy)</td>
<td>$($policyAssignment.CreatedOn)</td>
<td>$($policyAssignment.CreatedBy)</td>
<td>$($policyAssignment.UpdatedOn)</td>
<td>$($policyAssignment.UpdatedBy)</td>
</tr>
"@
        }
        [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsPolicySetAssignments)
        [void]$htmlScopeInsights.AppendLine(@"
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
            [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlScopeInsights.AppendLine(@'
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            linked_filters: true,
            col_1: 'select',
            col_4: 'select',
            col_7: 'select',
            col_8: 'select',
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
'@)

        if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {
            [void]$htmlScopeInsights.AppendLine(@'
                'number',
                'number',
                'number',
                'number',
                'number',
'@)
        }
        [void]$htmlScopeInsights.AppendLine(@"
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
            watermark: ['try: thisScope'],
            extensions: [{ name: 'colsVisibility', text: 'Columns: ', enable_tick_all: true },{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlScopeInsights.AppendLine(@"
    <i class="fa fa-ban" aria-hidden="true"></i> $(($policySetsAssigned).count) PolicySet assignments
"@)
    }
    [void]$htmlScopeInsights.AppendLine(@'
        </td></tr>
        <tr><!--y--><td class="detailstd"><!--y-->
'@)
    #endregion ScopeInsightsPolicySetAssignments

    #PolicyAssignmentsLimit (Policy+PolicySet)
    #region ScopeInsightsPolicyAssignmentsLimit
    if ($mgOrSub -eq 'mg') {
        $limit = $LimitPOLICYPolicyAssignmentsManagementGroup
    }
    if ($mgOrSub -eq 'sub') {
        $limit = $LimitPOLICYPolicyAssignmentsSubscription
    }

    if ($policiesAssignedAtScope -eq 0 -and $policySetsAssignedAtScope -eq 0) {
        $faimage = "<i class=`"fa fa-ban`" aria-hidden=`"true`"></i>"

        [void]$htmlScopeInsights.AppendLine(@"
            $faImage Policy Assignment Limit: 0/$limit
"@)
    }
    else {
        if ($mgOrSub -eq 'mg') {
            $scopePolicyAssignmentsLimit = $policyPolicyBaseQueryScopeInsights.where( { [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.MgId -eq $mgChild } )
        }
        if ($mgOrSub -eq 'sub') {
            $scopePolicyAssignmentsLimit = $policyPolicyBaseQueryScopeInsights.where( { $_.SubscriptionId -eq $subscriptionId } )
        }

        if ($scopePolicyAssignmentsLimit.PolicyAndPolicySetAssignmentAtScopeCount -gt (($limit) * $LimitCriticalPercentage / 100)) {
            $faImage = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
        }
        else {
            $faimage = "<i class=`"fa fa-check-circle`" aria-hidden=`"true`"></i>"
        }
        [void]$htmlScopeInsights.AppendLine(@"
            $faImage Policy Assignment Limit: $($scopePolicyAssignmentsLimit.PolicyAndPolicySetAssignmentAtScopeCount)/$($limit)
"@)
    }
    [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><td class="detailstd">
'@)
    #endregion ScopeInsightsPolicyAssignmentsLimit

    #ScopedPolicies
    #region ScopeInsightsScopedPolicies
    if ($mgOrSub -eq 'mg') {
        $SIDivContentClass = 'contentSIMG'
        $htmlTableIdentifier = $mgChild
        $scopePolicies = $customPoliciesDetailed.where( { $_.PolicyDefinitionId -like "*/providers/Microsoft.Management/managementGroups/$mgChild/*" } )
        $scopePoliciesCount = ($scopePolicies).count
    }
    if ($mgOrSub -eq 'sub') {
        $SIDivContentClass = 'contentSISub'
        $htmlTableIdentifier = $subscriptionId
        $scopePolicies = $customPoliciesDetailed.where( { $_.PolicyDefinitionId -like "*/subscriptions/$subscriptionId/*" } )
        $scopePoliciesCount = ($scopePolicies).count
    }

    if ($scopePoliciesCount -gt 0) {
        $tfCount = $scopePoliciesCount
        $htmlTableId = "ScopeInsights_ScopedPolicies_$($htmlTableIdentifier -replace '\(','_' -replace '\)','_' -replace '-','_' -replace '\.','_')"
        $randomFunctionName = "func_$htmlTableId"
        if ($mgOrSub -eq 'mg') {
            $LimitPOLICYPolicyScoped = $LimitPOLICYPolicyDefinitionsScopedManagementGroup
            if ($scopePoliciesCount -gt (($LimitPOLICYPolicyScoped * $LimitCriticalPercentage) / 100)) {
                $faIcon = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
            }
            else {
                $faIcon = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
            }
        }
        if ($mgOrSub -eq 'sub') {
            $LimitPOLICYPolicyScoped = $LimitPOLICYPolicyDefinitionsScopedSubscription
            if ($scopePoliciesCount -gt (($LimitPOLICYPolicyScoped * $LimitCriticalPercentage) / 100)) {
                $faIcon = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
            }
            else {
                $faIcon = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
            }
        }

        [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible">$faIcon <span class="valignMiddle">$scopePoliciesCount Custom Policy definitions scoped | Limit: ($scopePoliciesCount/$LimitPOLICYPolicyScoped)</span></button>
<div class="content $SIDivContentClass">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">Policy DisplayName</th>
<th>PolicyId</th>
<th>Category</th>
<th>ALZ</th>
<th>Policy effect</th>
<th>Role definitions</th>
<th>Unique assignments</th>
<th>Used in PolicySets</th>
</tr>
</thead>
<tbody>
"@)
        $htmlScopeInsightsScopedPolicies = $null
        $htmlScopeInsightsScopedPolicies = foreach ($custompolicy in $scopePolicies | Sort-Object @{Expression = { $_.PolicyDisplayName } }, @{Expression = { $_.PolicyDefinitionId } }) {
            if ($custompolicy.UsedInPolicySetsCount -gt 0) {
                $customPolicyUsedInPolicySets = "$($customPolicy.UsedInPolicySetsCount) ($($customPolicy.UsedInPolicySets))"
            }
            else {
                $customPolicyUsedInPolicySets = $($customPolicy.UsedInPolicySetsCount)
            }
            @"
<tr>
<td>$($customPolicy.PolicyDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($customPolicy.PolicyDefinitionId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($customPolicy.PolicyCategory -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($customPolicy.ALZ)</td>
<td>$($customPolicy.PolicyEffect)</td>
<td>$($customPolicy.RoleDefinitions)</td>
<td class="breakwordall">$($customPolicy.UniqueAssignments -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td class="breakwordall">$($customPolicyUsedInPolicySets)</td>
</tr>
"@
        }
        [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsScopedPolicies)
        [void]$htmlScopeInsights.AppendLine(@"
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
            [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlScopeInsights.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
                col_3: 'select',
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
        [void]$htmlScopeInsights.AppendLine(@"
                    <i class="fa fa-ban" aria-hidden="true"></i> $scopePoliciesCount Custom Policy definitions scoped
"@)
    }
    [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><td class="detailstd">
'@)
    #endregion ScopeInsightsScopedPolicies

    #ScopedPolicySets
    #region ScopeInsightsScopedPolicySets
    if ($mgOrSub -eq 'mg') {
        $SIDivContentClass = 'contentSIMG'
        $htmlTableIdentifier = $mgChild
        $scopePolicySets = $customPolicySetsDetailed.where( { $_.PolicySetDefinitionId -like "*/providers/Microsoft.Management/managementGroups/$mgChild/*" } )
        $scopePolicySetsCount = ($scopePolicySets).count
    }
    if ($mgOrSub -eq 'sub') {
        $SIDivContentClass = 'contentSISub'
        $htmlTableIdentifier = $subscriptionId
        $scopePolicySets = $customPolicySetsDetailed.where( { $_.PolicySetDefinitionId -like "*/subscriptions/$subscriptionId/*" } )
        $scopePolicySetsCount = ($scopePolicySets).count
    }

    if ($scopePolicySetsCount -gt 0) {
        $tfCount = $scopePolicySetsCount
        $htmlTableId = "ScopeInsights_ScopedPolicySets_$($htmlTableIdentifier -replace '\(','_' -replace '\)','_' -replace '-','_' -replace '\.','_')"
        $randomFunctionName = "func_$htmlTableId"
        if ($mgOrSub -eq 'mg') {
            $LimitPOLICYPolicySetScoped = $LimitPOLICYPolicySetDefinitionsScopedManagementGroup
            if ($scopePolicySetsCount -gt (($LimitPOLICYPolicySetScoped * $LimitCriticalPercentage) / 100)) {
                $faIcon = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
            }
            else {
                $faIcon = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
            }
        }
        if ($mgOrSub -eq 'sub') {
            $LimitPOLICYPolicySetScoped = $LimitPOLICYPolicySetDefinitionsScopedSubscription
            if ($scopePolicySetsCount -gt (($LimitPOLICYPolicySetScoped * $LimitCriticalPercentage) / 100)) {
                $faIcon = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
            }
            else {
                $faIcon = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
            }
        }
        [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible">$faIcon <span class="valignMiddle">$scopePolicySetsCount Custom PolicySet definitions scoped | Limit: ($scopePolicySetsCount/$LimitPOLICYPolicySetScoped)</span></button>
<div class="content $SIDivContentClass">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">PolicySet DisplayName</th>
<th>PolicySetId</th>
<th>Category</th>
<th>ALZ</th>
<th>Unique assignments</th>
<th>Policies Used</th>
</tr>
</thead>
<tbody>
"@)
        $htmlScopeInsightsScopedPolicySets = $null
        $htmlScopeInsightsScopedPolicySets = foreach ($custompolicySet in $scopePolicySets | Sort-Object @{Expression = { $_.PolicySetDisplayName } }, @{Expression = { $_.PolicySetDefinitionId } }) {
            @"
<tr>
<td>$($custompolicySet.PolicySetDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($custompolicySet.PolicySetDefinitionId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($custompolicySet.PolicySetCategory -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($custompolicySet.ALZ)</td>
<td>$($custompolicySet.UniqueAssignments -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($custompolicySet.PoliciesUsed)</td>
</tr>
"@
        }
        [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsScopedPolicySets)
        [void]$htmlScopeInsights.AppendLine(@"
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
            [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlScopeInsights.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
                col_3: 'select',
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
        [void]$htmlScopeInsights.AppendLine(@"
                    <i class="fa fa-ban" aria-hidden="true"></i> $scopePolicySetsCount Custom PolicySet definitions scoped
"@)
    }
    [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><td class="detailstd">
'@)
    #endregion ScopeInsightsScopedPolicySets

    #BlueprintAssignments
    #region ScopeInsightsBlueprintAssignments
    if ($mgOrSub -eq 'sub') {
        if ($blueprintsAssignedCount -gt 0) {

            if ($mgOrSub -eq 'mg') {
                $htmlTableIdentifier = $mgChild
            }
            if ($mgOrSub -eq 'sub') {
                $htmlTableIdentifier = $subscriptionId
            }
            $htmlTableId = "ScopeInsights_BlueprintAssignment_$($htmlTableIdentifier -replace '\(','_' -replace '\)','_' -replace '-','_' -replace '\.','_')"
            $randomFunctionName = "func_$htmlTableId"
            [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$blueprintsAssignedCount Blueprints assigned</span></button>
<div class="content contentSISub">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
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
            $htmlScopeInsightsBlueprintAssignments = $null
            $htmlScopeInsightsBlueprintAssignments = foreach ($blueprintAssigned in $blueprintsAssigned) {
                @"
<tr>
<td>$($blueprintAssigned.BlueprintName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintAssigned.BlueprintDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintAssigned.BlueprintDescription -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintAssigned.BlueprintId -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintAssigned.BlueprintAssignmentVersion -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintAssigned.BlueprintAssignmentId -replace '<', '&lt;' -replace '>', '&gt;')</td>
</tr>
"@
            }
            [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsBlueprintAssignments)
            [void]$htmlScopeInsights.AppendLine(@"
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
                [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@"
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
            [void]$htmlScopeInsights.AppendLine(@"
                    <i class="fa fa-ban" aria-hidden="true"></i> $blueprintsAssignedCount Blueprints assigned
"@)
        }
        [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><td class="detailstd">
'@)
    }
    #endregion ScopeInsightsBlueprintAssignments

    #BlueprintsScoped
    #region ScopeInsightsBlueprintsScoped
    if ($blueprintsScopedCount -gt 0) {
        $tfCount = $blueprintsScopedCount
        if ($mgOrSub -eq 'mg') {
            $SIDivContentClass = 'contentSIMG'
            $htmlTableIdentifier = $mgChild
        }
        if ($mgOrSub -eq 'sub') {
            $SIDivContentClass = 'contentSISub'
            $htmlTableIdentifier = $subscriptionId
        }
        $htmlTableId = "ScopeInsights_BlueprintScoped_$($htmlTableIdentifier -replace '\(','_' -replace '\)','_' -replace '-','_' -replace '\.','_')"
        $randomFunctionName = "func_$htmlTableId"
        [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$blueprintsScopedCount Blueprints scoped</span></button>
<div class="content $SIDivContentClass">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
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
        $htmlScopeInsightsBlueprintsScoped = $null
        $htmlScopeInsightsBlueprintsScoped = foreach ($blueprintScoped in $blueprintsScoped) {
            @"
<tr>
<td>$($blueprintScoped.BlueprintName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintScoped.BlueprintDisplayName -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintScoped.BlueprintDescription -replace '<', '&lt;' -replace '>', '&gt;')</td>
<td>$($blueprintScoped.BlueprintId -replace '<', '&lt;' -replace '>', '&gt;')</td>
</tr>
"@
        }
        [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsBlueprintsScoped)
        [void]$htmlScopeInsights.AppendLine(@"
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
            [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlScopeInsights.AppendLine(@"
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
        [void]$htmlScopeInsights.AppendLine(@"
                    <i class="fa fa-ban" aria-hidden="true"></i> $blueprintsScopedCount Blueprints scoped
"@)
    }
    [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><td class="detailstd">
'@)
    #endregion ScopeInsightsBlueprintsScoped

    if ($mgOrSub -eq 'sub') {
        #region ScopeInsightsClassicAdministrators
        if ($htClassicAdministrators.($subscriptionId).ClassicAdministrators.Count -gt 0) {
            $tfCount = $htClassicAdministrators.($subscriptionId).ClassicAdministrators.Count
            $htmlTableId = "ScopeInsights_ClassicAdministrators_$($subscriptionId -replace '\(','_' -replace '\)','_' -replace '-','_' -replace '\.','_')"
            $randomFunctionName = "func_$htmlTableId"
            [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tfCount Classic Administrators</span></button>
<div class="content $SIDivContentClass">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Role</th>
<th>Identity</th>
</tr>
</thead>
<tbody>
"@)
            $htmlScopeInsightsClassicAdministrators = $null
            $htmlScopeInsightsClassicAdministrators = foreach ($classicAdministrator in $htClassicAdministrators.($subscriptionId).ClassicAdministrators | Sort-Object -Property Role, Identity) {
                @"
<tr>
<td>$($classicAdministrator.Role)</td>
<td>$($classicAdministrator.Identity)</td>
</tr>
"@
            }
            [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsClassicAdministrators)
            [void]$htmlScopeInsights.AppendLine(@"
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
                [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
            }
            [void]$htmlScopeInsights.AppendLine(@"
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
            [void]$htmlScopeInsights.AppendLine(@'
                    <i class="fa fa-ban" aria-hidden="true"></i> No Classic Administrators
'@)
        }
        [void]$htmlScopeInsights.AppendLine(@'
</td></tr>
<tr><td class="detailstd">
'@)
        #endregion ScopeInsightsClassicAdministrators
    }

    #RoleAssignments
    #region ScopeInsightsRoleAssignments
    if ($mgOrSub -eq 'mg') {
        $SIDivContentClass = 'contentSIMG'
        $htmlTableIdentifier = $mgChild
        $LimitRoleAssignmentsScope = $LimitRBACRoleAssignmentsManagementGroup

        $rolesAssigned = [System.Collections.ArrayList]@()
        $rolesAssignedCount = 0
        $rolesAssignedInheritedCount = 0
        $rolesAssignedUser = 0
        $rolesAssignedGroup = 0
        $rolesAssignedServicePrincipal = 0
        $rolesAssignedUnknown = 0
        $roleAssignmentsRelatedToPolicyCount = 0
        $roleSecurityFindingCustomRoleOwner = 0
        $roleSecurityFindingOwnerAssignmentSP = 0
        $rbacForThisManagementGroup = ($rbacAllGroupedByManagementGroup.where( { $_.name -eq $mgChild } )).group
        foreach ($roleAssignment in $rbacForThisManagementGroup) {
            if ([String]::IsNullOrEmpty($roleAssignment.subscriptionId)) {
                $null = $rolesAssigned.Add($roleAssignment)
                $rolesAssignedCount++
                if ($roleAssignment.Scope -notlike 'this*') {
                    $rolesAssignedInheritedCount++
                }
                if ($roleAssignment.ObjectType -like 'User*') {
                    $rolesAssignedUser++
                }
                if ($roleAssignment.ObjectType -eq 'Group') {
                    $rolesAssignedGroup++
                }
                if ($roleAssignment.ObjectType -like 'SP*') {
                    $rolesAssignedServicePrincipal++
                }
                if ($roleAssignment.ObjectType -eq 'Unknown') {
                    $rolesAssignedUnknown++
                }
                if ($roleAssignment.RbacRelatedPolicyAssignment -ne 'none') {
                    $roleAssignmentsRelatedToPolicyCount++
                }
                if ($roleAssignment.RoleSecurityCustomRoleOwner -eq 1) {
                    $roleSecurityFindingCustomRoleOwner++
                }
                if ($roleAssignment.RoleSecurityOwnerAssignmentSP -eq 1) {
                    $roleSecurityFindingOwnerAssignmentSP++
                }
            }
        }
    }
    if ($mgOrSub -eq 'sub') {
        $SIDivContentClass = 'contentSISub'
        $htmlTableIdentifier = $subscriptionId
        $LimitRoleAssignmentsScope = $htSubscriptionsRoleAssignmentLimit.($subscriptionId)

        $rolesAssigned = [System.Collections.ArrayList]@()
        $rolesAssignedCount = 0
        $rolesAssignedInheritedCount = 0
        $rolesAssignedUser = 0
        $rolesAssignedGroup = 0
        $rolesAssignedServicePrincipal = 0
        $rolesAssignedUnknown = 0
        $roleAssignmentsRelatedToPolicyCount = 0
        $roleSecurityFindingCustomRoleOwner = 0
        $roleSecurityFindingOwnerAssignmentSP = 0
        $rbacForThisSubscription = ($rbacAllGroupedBySubscription.where( { $_.name -eq $subscriptionId } )).group
        $rolesAssigned = foreach ($roleAssignment in $rbacForThisSubscription) {

            $roleAssignment
            $rolesAssignedCount++
            if ($roleAssignment.Scope -notlike 'this*') {
                $rolesAssignedInheritedCount++
            }
            if ($roleAssignment.ObjectType -like 'User*') {
                $rolesAssignedUser++
            }
            if ($roleAssignment.ObjectType -eq 'Group') {
                $rolesAssignedGroup++
            }
            if ($roleAssignment.ObjectType -like 'SP*') {
                $rolesAssignedServicePrincipal++
            }
            if ($roleAssignment.ObjectType -eq 'Unknown') {
                $rolesAssignedUnknown++
            }
            if ($roleAssignment.RbacRelatedPolicyAssignment -ne 'none') {
                $roleAssignmentsRelatedToPolicyCount++
            }
            if ($roleAssignment.RoleSecurityCustomRoleOwner -eq 1) {
                $roleSecurityFindingCustomRoleOwner++
            }
            if ($roleAssignment.RoleSecurityOwnerAssignmentSP -eq 1) {
                $roleSecurityFindingOwnerAssignmentSP++
            }
        }
    }

    $rolesAssignedAtScopeCount = $rolesAssignedCount - $rolesAssignedInheritedCount

    if (($rolesAssigned).count -gt 0) {
        $tfCount = ($rolesAssigned).count
        $htmlTableId = "ScopeInsights_RoleAssignments_$($htmlTableIdentifier -replace '\(','_' -replace '\)','_' -replace '-','_' -replace '\.','_')"
        $randomFunctionName = "func_$htmlTableId"
        $noteOrNot = ''
        [void]$htmlScopeInsights.AppendLine(@"
<button onclick="loadtf$("func_$htmlTableId")()" type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$rolesAssignedCount Role assignments ($rolesAssignedInheritedCount inherited) (User: $rolesAssignedUser | Group: $rolesAssignedGroup | ServicePrincipal: $rolesAssignedServicePrincipal | Orphaned: $rolesAssignedUnknown) ($($roleSecurityFindingCustomRoleOwnerImg)CustomRoleOwner: $roleSecurityFindingCustomRoleOwner, $($RoleSecurityFindingOwnerAssignmentSPImg)OwnerAssignmentSP: $roleSecurityFindingOwnerAssignmentSP) (Policy related: $roleAssignmentsRelatedToPolicyCount) | Limit: ($rolesAssignedAtScopeCount/$LimitRoleAssignmentsScope)</span></button>
<div class="content $SIDivContentClass">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a><br>
&nbsp;&nbsp;<span class="hintTableSize">*Depending on the number of rows and your computer´s performance the table may respond with delay, download the csv for better filtering experience</span>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Scope</th>
<th>Role</th>
<th>RoleId</th>
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
<th>Role AssignmentId</th>
<th>Related Policy Assignment $noteOrNot</th>
<th>CreatedOn</th>
<th>CreatedBy</th>
</tr>
</thead>
<tbody>
"@)
        $htmlScopeInsightsRoleAssignments = $null
        $htmlScopeInsightsRoleAssignments = foreach ($roleAssignment in ($rolesAssigned | Sort-Object -Property Level, MgName, MgId, SubscriptionName, SubscriptionId, Scope, Role, RoleId, ObjectId, RoleAssignmentId)) {
            @"
<tr>
<td>$($roleAssignment.Scope)</td>
<td>$($roleAssignment.Role)</td>
<td>$($roleAssignment.RoleId)</td>
<td>$($roleAssignment.RoleType)</td>
<td>$($roleAssignment.RoleDataRelated)</td>
<td>$($roleAssignment.RoleCanDoRoleAssignments)</td>
<td class="breakwordall">$($roleAssignment.ObjectDisplayName)</td>
<td class="breakwordall">$($roleAssignment.ObjectSignInName)</td>
<td class="breakwordall">$($roleAssignment.ObjectId)</td>
<td style="width:76px" class="breakwordnone">$($roleAssignment.ObjectType)</td>
<td>$($roleAssignment.AssignmentType)</td>
<td>$($roleAssignment.AssignmentInheritFrom)</td>
<td>$($roleAssignment.GroupMembersCount)</td>
<td class="breakwordall">$($roleAssignment.RoleAssignmentId)</td>
<td class="breakwordall">$($roleAssignment.rbacRelatedPolicyAssignment)</td>
<td>$($roleAssignment.CreatedOn)</td>
<td>$($roleAssignment.CreatedBy)</td>
</tr>
"@
        }
        [void]$htmlScopeInsights.AppendLine($htmlScopeInsightsRoleAssignments)
        [void]$htmlScopeInsights.AppendLine(@"
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
            [void]$htmlScopeInsights.AppendLine(@"
paging: {results_per_page: ['Records: ', [$spectrum]]},/*state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},*/
"@)
        }
        [void]$htmlScopeInsights.AppendLine(@"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            linked_filters: true,
            col_3: 'select',
            col_4: 'select',
            col_5: 'select',
            col_9: 'multiple',
            col_10: 'select',
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
                'date',
                'caseinsensitivestring'
            ],
            watermark: ['', 'try owner||reader', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
            extensions: [{ name: 'colsVisibility', text: 'Columns: ', enable_tick_all: true },{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@)
    }
    else {
        [void]$htmlScopeInsights.AppendLine(@"
    <i class="fa fa-ban" aria-hidden="true"></i> $(($rbacAll).count) Role assignments

"@)
    }

    [void]$htmlScopeInsights.AppendLine(@'
    </td></tr><!--rsi-->
'@)
    #endregion ScopeInsightsRoleAssignments


    if (-not $NoScopeInsights) {
        $script:html += $htmlScopeInsights
    }

    if (-not $NoSingleSubscriptionOutput) {
        if ($mgOrSub -eq 'sub') {
            $htmlThisSubSingleOutput = $htmlSubscriptionOnlyStart
            $htmlThisSubSingleOutput += $htmlScopeInsights
            $htmlThisSubSingleOutput += $htmlSubscriptionOnlyEnd
            $htmlThisSubSingleOutput | Set-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($HTMLPath)$($DirectorySeparatorChar)$($fileName)_$($subscriptionId).html" -Encoding utf8 -Force
            $htmlThisSubSingleOutput = $null
        }
    }

    if (-not $NoScopeInsights) {
        if ($scopescnter % 50 -eq 0) {
            $script:scopescnter = 0
            Write-Host '   append file duration: '(Measure-Command { $script:html | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force }).TotalSeconds 'seconds'
            $script:html = $null
        }
    }

    if ($scopescnter % 50 -eq 0) {
        showMemoryUsage
    }

}