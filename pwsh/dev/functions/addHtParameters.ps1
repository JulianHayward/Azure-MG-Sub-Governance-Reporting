function addHtParameters {
    Write-Host 'Add AzGovViz htParameters'
    if ($LargeTenant -eq $true) {
        $script:NoScopeInsights = $true
        $NoResourceProvidersDetailed = $true
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
        NoPolicyComplianceStates                     = [bool]$NoPolicyComplianceStates
        NoResources                                  = [bool]$NoResources
        ProductVersion                               = $ProductVersion
        PolicyAtScopeOnly                            = [bool]$PolicyAtScopeOnly
        RBACAtScopeOnly                              = [bool]$RBACAtScopeOnly
        DoPSRule                                     = [bool]$DoPSRule
    }
    Write-Host 'htParameters:'
    $azAPICallConf['htParameters'] | format-table -AutoSize | Out-String
    Write-Host 'Add AzGovViz htParameters succeeded' -ForegroundColor Green
}