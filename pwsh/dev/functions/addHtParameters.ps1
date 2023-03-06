function addHtParameters {
    Write-Host 'Add Azure Governance Visualizer htParameters'
    if ($LargeTenant -eq $true) {
        $script:NoScopeInsights = $true
        $NoResourceProvidersAtAll = $true
        $PolicyAtScopeOnly = $true
        $RBACAtScopeOnly = $true
    }

    if ($ManagementGroupsOnly) {
        $script:NoSingleSubscriptionOutput = $true
    }

    if ($HierarchyMapOnly) {
        $NoJsonExport = $true
    }

    $script:azAPICallConf['htParameters'] += [ordered]@{
        DoAzureConsumption                           = [bool]$DoAzureConsumption
        DoNotIncludeResourceGroupsOnPolicy           = [bool]$DoNotIncludeResourceGroupsOnPolicy
        DoNotIncludeResourceGroupsAndResourcesOnRBAC = [bool]$DoNotIncludeResourceGroupsAndResourcesOnRBAC
        DoNotShowRoleAssignmentsUserData             = [bool]$DoNotShowRoleAssignmentsUserData
        HierarchyMapOnly                             = [bool]$HierarchyMapOnly
        LargeTenant                                  = [bool]$LargeTenant
        ManagementGroupsOnly                         = [bool]$ManagementGroupsOnly
        NoJsonExport                                 = [bool]$NoJsonExport
        NoMDfCSecureScore                            = [bool]$NoMDfCSecureScore
        NoResourceProvidersDetailed                  = [bool]$NoResourceProvidersDetailed
        NoResourceProvidersAtAll                     = [bool]$NoResourceProvidersAtAll
        NoPolicyComplianceStates                     = [bool]$NoPolicyComplianceStates
        NoResources                                  = [bool]$NoResources
        ProductVersion                               = $ProductVersion
        PolicyAtScopeOnly                            = [bool]$PolicyAtScopeOnly
        RBACAtScopeOnly                              = [bool]$RBACAtScopeOnly
        DoPSRule                                     = [bool]$DoPSRule
        PSRuleFailedOnly                             = [bool]$PSRuleFailedOnly
        NoALZPolicyVersionChecker                    = [bool]$NoALZPolicyVersionChecker
        NoStorageAccountAccessAnalysis               = [bool]$NoStorageAccountAccessAnalysis
        GitHubActionsOIDC                            = [bool]$GitHubActionsOIDC
        NoNetwork                                    = [bool]$NoNetwork
        ThrottleLimit                                = $ThrottleLimit
    }
    Write-Host 'htParameters:'
    $azAPICallConf['htParameters'] | Format-Table -AutoSize | Out-String
    Write-Host 'Add Azure Governance Visualizer htParameters succeeded' -ForegroundColor Green
}