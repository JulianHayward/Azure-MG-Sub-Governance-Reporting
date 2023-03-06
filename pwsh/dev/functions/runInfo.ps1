function runInfo {
    #region RunInfo
    Write-Host 'Run Info:'
    if ($HierarchyMapOnly) {
        Write-Host ' Creating HierarchyMap only' -ForegroundColor Green
    }
    else {
        $script:paramsUsed = $Null
        $startTimeUTC = ((Get-Date).ToUniversalTime()).ToString('dd-MMM-yyyy HH:mm:ss')
        $script:paramsUsed += "Date: $startTimeUTC (UTC); Version: $ProductVersion &#13;"

        if ($azAPICallConf['htParameters'].accountType -eq 'ServicePrincipal') {
            $script:paramsUsed += "ExecutedBy: $($azAPICallConf['checkContext'].Account.Id) (App/ClientId) ($($azAPICallConf['htParameters'].accountType)) &#13;"
        }
        elseif ($azAPICallConf['htParameters'].accountType -eq 'ManagedService') {
            $script:paramsUsed += "ExecutedBy: $($azAPICallConf['checkContext'].Account.Id) (Id) ($($azAPICallConf['htParameters'].accountType)) &#13;"
        }
        elseif ($azAPICallConf['htParameters'].accountType -eq 'ClientAssertion') {
            $script:paramsUsed += "ExecutedBy: $($azAPICallConf['checkContext'].Account.Id) (App/ClientId) ($($azAPICallConf['htParameters'].accountType)) &#13;"
        }
        else {
            $script:paramsUsed += "ExecutedBy: $($azAPICallConf['checkContext'].Account.Id) ($($azAPICallConf['htParameters'].accountType), $($azAPICallConf['htParameters'].userType)) &#13;"
        }
        #$script:paramsUsed += "ManagementGroupId: $($ManagementGroupId) &#13;"
        $script:paramsUsed += 'HierarchyMapOnly: false &#13;'
        Write-Host " Creating HierarchyMap, TenantSummary, DefinitionInsights and ScopeInsights - use parameter: '-HierarchyMapOnly' to only create the HierarchyMap" -ForegroundColor Yellow

        if ($azAPICallConf['htParameters'].ManagementGroupsOnly) {
            Write-Host " Management Groups only = $($azAPICallConf['htParameters'].ManagementGroupsOnly)" -ForegroundColor Green
        }
        else {
            Write-Host " Management Groups only = $($azAPICallConf['htParameters'].ManagementGroupsOnly) - use parameter -ManagementGroupsOnly to only collect data for Management Groups" -ForegroundColor Yellow
        }

        if (($SubscriptionQuotaIdWhitelist).count -eq 1 -and $SubscriptionQuotaIdWhitelist[0] -eq 'undefined') {
            Write-Host " Subscription Whitelist disabled - use parameter: '-SubscriptionQuotaIdWhitelist' to whitelist QuotaIds" -ForegroundColor Yellow
            $script:paramsUsed += 'SubscriptionQuotaIdWhitelist: false &#13;'
        }
        else {
            Write-Host ' Subscription Whitelist enabled. Azure Governance Visualizer will only process Subscriptions where QuotaId startswith one of the following strings:' -ForegroundColor Green
            foreach ($quotaIdFromSubscriptionQuotaIdWhitelist in $SubscriptionQuotaIdWhitelist) {
                Write-Host "  - $($quotaIdFromSubscriptionQuotaIdWhitelist)" -ForegroundColor Green
            }
            foreach ($whiteListEntry in $SubscriptionQuotaIdWhitelist) {
                if ($whiteListEntry -eq 'undefined') {
                    Write-Host "When defining the 'SubscriptionQuotaIdWhitelist' make sure to remove the 'undefined' entry from the array :)" -ForegroundColor Red
                    Throw 'Error - Azure Governance Visualizer: check the last console output for details'
                }
            }
            $script:paramsUsed += "SubscriptionQuotaIdWhitelist: $($SubscriptionQuotaIdWhitelist -join ', ') &#13;"
        }

        if ($azAPICallConf['htParameters'].NoMDfCSecureScore -eq $true) {
            Write-Host " Microsoft Defender for Cloud Secure Score disabled (-NoMDfCSecureScore = $($azAPICallConf['htParameters'].NoMDfCSecureScore))" -ForegroundColor Green
            $script:paramsUsed += 'NoMDfCSecureScore: true &#13;'
        }
        else {
            Write-Host " Microsoft Defender for Cloud Secure Score enabled - use parameter: '-NoMDfCSecureScore' to disable" -ForegroundColor Yellow
            $script:paramsUsed += 'NoMDfCSecureScore: false &#13;'
        }

        if ($azAPICallConf['htParameters'].DoNotShowRoleAssignmentsUserData -eq $true) {
            Write-Host " Scrub Identity information for identityType='User' enabled (-DoNotShowRoleAssignmentsUserData = $($azAPICallConf['htParameters'].DoNotShowRoleAssignmentsUserData))" -ForegroundColor Green
            $script:paramsUsed += 'DoNotShowRoleAssignmentsUserData: true &#13;'
        }
        else {
            Write-Host " Scrub Identity information for identityType='User' disabled - use parameter: '-DoNotShowRoleAssignmentsUserData' to scrub information such as displayName and signInName (email) for identityType='User'" -ForegroundColor Yellow
            $script:paramsUsed += 'DoNotShowRoleAssignmentsUserData: false &#13;'
        }

        if ($LimitCriticalPercentage -eq 80) {
            Write-Host " ARM Limits warning set to 80% (default) - use parameter: '-LimitCriticalPercentage' to set warning level accordingly" -ForegroundColor Yellow
            #$script:paramsUsed += "LimitCriticalPercentage: 80% (default) &#13;"
        }
        else {
            Write-Host " ARM Limits warning set to $($LimitCriticalPercentage)% (custom)" -ForegroundColor Green
            #$script:paramsUsed += "LimitCriticalPercentage: $($LimitCriticalPercentage)% &#13;"
        }

        if ($azAPICallConf['htParameters'].NoPolicyComplianceStates -eq $false) {
            Write-Host " Policy States enabled - use parameter: '-NoPolicyComplianceStates' to disable Policy States" -ForegroundColor Yellow
            $script:paramsUsed += 'NoPolicyComplianceStates: false &#13;'
        }
        else {
            Write-Host " Policy States disabled (-NoPolicyComplianceStates = $($azAPICallConf['htParameters'].NoPolicyComplianceStates))" -ForegroundColor Green
            $script:paramsUsed += 'NoPolicyComplianceStates: true &#13;'
        }

        if (-not $NoResourceDiagnosticsPolicyLifecycle) {
            Write-Host " Resource Diagnostics Policy Lifecycle recommendations enabled - use parameter: '-NoResourceDiagnosticsPolicyLifecycle' to disable Resource Diagnostics Policy Lifecycle recommendations" -ForegroundColor Yellow
            $script:paramsUsed += 'NoResourceDiagnosticsPolicyLifecycle: false &#13;'
        }
        else {
            Write-Host " Resource Diagnostics Policy Lifecycle disabled (-NoResourceDiagnosticsPolicyLifecycle = $($NoResourceDiagnosticsPolicyLifecycle))" -ForegroundColor Green
            $script:paramsUsed += 'NoResourceDiagnosticsPolicyLifecycle: true &#13;'
        }

        if (-not $NoAADGroupsResolveMembers) {
            Write-Host " AAD Groups resolve members enabled (honors parameter -DoNotShowRoleAssignmentsUserData) - use parameter: '-NoAADGroupsResolveMembers' to disable resolving AAD Group memberships" -ForegroundColor Yellow
            $script:paramsUsed += 'NoAADGroupsResolveMembers: false &#13;'
            if ($AADGroupMembersLimit -eq 500) {
                Write-Host " AADGroupMembersLimit = $AADGroupMembersLimit" -ForegroundColor Yellow
                $script:paramsUsed += "AADGroupMembersLimit: $AADGroupMembersLimit &#13;"
            }
            else {
                Write-Host " AADGroupMembersLimit = $AADGroupMembersLimit" -ForegroundColor Green
                $script:paramsUsed += "AADGroupMembersLimit: $AADGroupMembersLimit &#13;"
            }
        }
        else {
            Write-Host " AAD Groups resolve members disabled (-NoAADGroupsResolveMembers = $($NoAADGroupsResolveMembers))" -ForegroundColor Green
            $script:paramsUsed += 'NoAADGroupsResolveMembers: true &#13;'
        }

        Write-Host " AADServicePrincipalExpiryWarningDays: $AADServicePrincipalExpiryWarningDays" -ForegroundColor Yellow
        #$script:paramsUsed += "AADServicePrincipalExpiryWarningDays: $AADServicePrincipalExpiryWarningDays &#13;"

        if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
            if (-not $AzureConsumptionPeriod -is [int]) {
                Write-Host 'parameter -AzureConsumptionPeriod must be an integer'
                Throw 'Error - Azure Governance Visualizer: check the last console output for details'
            }
            elseif ($AzureConsumptionPeriod -eq 0) {
                Write-Host 'parameter -AzureConsumptionPeriod must be gt 0'
                Throw 'Error - Azure Governance Visualizer: check the last console output for details'
            }
            else {
                #$azureConsumptionStartDate = ((Get-Date).AddDays( - ($($AzureConsumptionPeriod)))).ToString("yyyy-MM-dd")
                #$azureConsumptionEndDate = ((Get-Date).AddDays(-1)).ToString("yyyy-MM-dd")

                if ($AzureConsumptionPeriod -eq 1) {
                    Write-Host " Azure Consumption reporting enabled: $AzureConsumptionPeriod days (default) ($azureConsumptionStartDate - $azureConsumptionEndDate) - use parameter: '-AzureConsumptionPeriod' to define the period (days)" -ForegroundColor Yellow
                }
                else {
                    Write-Host " Azure Consumption reporting enabled: $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)" -ForegroundColor Green
                }

                if (-not $NoAzureConsumptionReportExportToCSV) {
                    Write-Host " Azure Consumption report export to CSV enabled - use parameter: '-NoAzureConsumptionReportExportToCSV' to disable" -ForegroundColor Yellow
                }
                else {
                    Write-Host " Azure Consumption report export to CSV disabled (-NoAzureConsumptionReportExportToCSV = $($NoAzureConsumptionReportExportToCSV))" -ForegroundColor Green
                }
                $script:paramsUsed += "DoAzureConsumption: true ($AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate))&#13;"
                $script:paramsUsed += "NoAzureConsumptionReportExportToCSV: $NoAzureConsumptionReportExportToCSV &#13;"
            }
        }
        else {
            Write-Host " Azure Consumption reporting disabled (-DoAzureConsumption = $($azAPICallConf['htParameters'].DoAzureConsumption))" -ForegroundColor Green
            $script:paramsUsed += 'DoAzureConsumption: false &#13;'
        }

        if ($NoScopeInsights) {
            Write-Host " ScopeInsights will not be created (-NoScopeInsights = $($NoScopeInsights))" -ForegroundColor Green
            $script:paramsUsed += 'NoScopeInsights: true &#13;'
        }
        else {
            Write-Host " ScopeInsights will be created (-NoScopeInsights = $($NoScopeInsights)) Q: Why would you not want to show ScopeInsights? A: In larger tenants ScopeInsights may blow up the html file (up to unusable due to html file size)" -ForegroundColor Yellow
            $script:paramsUsed += 'NoScopeInsights: false &#13;'
        }

        if ($NoSingleSubscriptionOutput) {
            Write-Host " No single Subscription output will not be created (-NoSingleSubscriptionOutput = $($NoSingleSubscriptionOutput))" -ForegroundColor Green
            $script:paramsUsed += 'NoSingleSubscriptionOutput: true &#13;'
        }
        else {
            Write-Host " Single Subscription output will be created (-NoSingleSubscriptionOutput = $($NoSingleSubscriptionOutput))" -ForegroundColor Yellow
            $script:paramsUsed += 'NoSingleSubscriptionOutput: false &#13;'
        }

        if ($azAPICallConf['htParameters'].NoResourceProvidersDetailed -eq $true) {
            Write-Host " ResourceProvider Detailed for TenantSummary disabled (-NoResourceProvidersDetailed = $($azAPICallConf['htParameters'].NoResourceProvidersDetailed))" -ForegroundColor Green
            $script:paramsUsed += "NoResourceProvidersDetailed: $($azAPICallConf['htParameters'].NoResourceProvidersDetailed) &#13;"
        }
        else {
            Write-Host " ResourceProvider Detailed for TenantSummary enabled - use parameter: '-NoResourceProvidersDetailed' to disable" -ForegroundColor Yellow
            $script:paramsUsed += "NoResourceProvidersDetailed: $($azAPICallConf['htParameters'].NoResourceProvidersDetailed) &#13;"
        }

        if ($azAPICallConf['htParameters'].NoResourceProvidersAtAll -eq $true) {
            Write-Host " ResourceProvider collection disabled (NoResourceProvidersAtAll = $($azAPICallConf['htParameters'].NoResourceProvidersAtAll))" -ForegroundColor Green
            $script:paramsUsed += "NoResourceProvidersAtAll: $($azAPICallConf['htParameters'].NoResourceProvidersAtAll) &#13;"
        }
        else {
            Write-Host " ResourceProvider collection enabled - use parameter: 'NoResourceProvidersAtAll' to disable" -ForegroundColor Yellow
            $script:paramsUsed += "NoResourceProvidersAtAll: $($azAPICallConf['htParameters'].NoResourceProvidersAtAll) &#13;"
        }

        if ($azAPICallConf['htParameters'].LargeTenant -or $azAPICallConf['htParameters'].PolicyAtScopeOnly -or $azAPICallConf['htParameters'].RBACAtScopeOnly) {
            if ($azAPICallConf['htParameters'].LargeTenant) {
                Write-Host " TenantSummary Policy assignments and Role assignments will not include assignment information on scopes where assignment is inherited, ScopeInsights will not be created, ResourceProvidersDetailed will not be created (-LargeTenant = $($azAPICallConf['htParameters'].LargeTenant))" -ForegroundColor Green
                $script:paramsUsed += "LargeTenant: $($azAPICallConf['htParameters'].LargeTenant) &#13;"
                $script:paramsUsed += "LargeTenant -> PolicyAtScopeOnly: $($azAPICallConf['htParameters'].PolicyAtScopeOnly) &#13;"
                $script:paramsUsed += "LargeTenant -> RBACAtScopeOnly: $($azAPICallConf['htParameters'].RBACAtScopeOnly) &#13;"
                $script:paramsUsed += "LargeTenant -> NoScopeInsights: $($NoScopeInsights) &#13;"
                $script:paramsUsed += "LargeTenant -> NoResourceProvidersDetailed: $($azAPICallConf['htParameters'].NoResourceProvidersDetailed) &#13;"
            }
            else {
                Write-Host " TenantSummary LargeTenant disabled (-LargeTenant = $($azAPICallConf['htParameters'].LargeTenant)) Q: Why would you not want to enable -LargeTenant? A: In larger tenants showing the inheritance on each scope may blow up the html file (up to unusable due to html file size)" -ForegroundColor Yellow
                $script:paramsUsed += "LargeTenant: $($azAPICallConf['htParameters'].LargeTenant) &#13;"

                if ($azAPICallConf['htParameters'].PolicyAtScopeOnly) {
                    Write-Host " TenantSummary Policy assignments will not include assignment information on scopes where assignment is inherited (PolicyAtScopeOnly = $($azAPICallConf['htParameters'].PolicyAtScopeOnly))" -ForegroundColor Green
                    $script:paramsUsed += "PolicyAtScopeOnly: $($azAPICallConf['htParameters'].PolicyAtScopeOnly) &#13;"
                }
                else {
                    Write-Host " TenantSummary Policy assignments will include assignment information on scopes where assignment is inherited (PolicyAtScopeOnly = $($azAPICallConf['htParameters'].PolicyAtScopeOnly))" -ForegroundColor Yellow
                    $script:paramsUsed += "PolicyAtScopeOnly: $($azAPICallConf['htParameters'].PolicyAtScopeOnly) &#13;"
                }

                if ($azAPICallConf['htParameters'].RBACAtScopeOnly) {
                    Write-Host " TenantSummary Role assignments will not include assignment information on scopes where assignment is inherited (RBACAtScopeOnly = $($azAPICallConf['htParameters'].RBACAtScopeOnly))" -ForegroundColor Green
                    $script:paramsUsed += "RBACAtScopeOnly: $($azAPICallConf['htParameters'].RBACAtScopeOnly) &#13;"
                }
                else {
                    Write-Host " TenantSummary Role assignments will include assignment information on scopes where assignment is inherited (RBACAtScopeOnly = $($azAPICallConf['htParameters'].RBACAtScopeOnly))" -ForegroundColor Yellow
                    $script:paramsUsed += "RBACAtScopeOnly: $($azAPICallConf['htParameters'].RBACAtScopeOnly) &#13;"
                }
            }
        }
        else {
            Write-Host " TenantSummary LargeTenant disabled (-LargeTenant = $($azAPICallConf['htParameters'].LargeTenant)) Q: Why would you not want to enable -LargeTenant? A: In larger tenants showing the inheritance on each scope may blow up the html file (up to unusable due to html file size)" -ForegroundColor Yellow
            $script:paramsUsed += "LargeTenant: $($azAPICallConf['htParameters'].LargeTenant) &#13;"

            if ($azAPICallConf['htParameters'].PolicyAtScopeOnly) {
                Write-Host " TenantSummary Policy assignments will not include assignment information on scopes where assignment is inherited (PolicyAtScopeOnly = $($azAPICallConf['htParameters'].PolicyAtScopeOnly))" -ForegroundColor Green
                $script:paramsUsed += "PolicyAtScopeOnly: $($azAPICallConf['htParameters'].PolicyAtScopeOnly) &#13;"
            }
            else {
                Write-Host " TenantSummary Policy assignments will include assignment information on scopes where assignment is inherited (PolicyAtScopeOnly = $($azAPICallConf['htParameters'].PolicyAtScopeOnly))" -ForegroundColor Yellow
                $script:paramsUsed += "PolicyAtScopeOnly: $($azAPICallConf['htParameters'].PolicyAtScopeOnly) &#13;"
            }

            if ($azAPICallConf['htParameters'].RBACAtScopeOnly) {
                Write-Host " TenantSummary Role assignments will not include assignment information on scopes where assignment is inherited (RBACAtScopeOnly = $($azAPICallConf['htParameters'].RBACAtScopeOnly))" -ForegroundColor Green
                $script:paramsUsed += "RBACAtScopeOnly: $($azAPICallConf['htParameters'].RBACAtScopeOnly) &#13;"
            }
            else {
                Write-Host " TenantSummary Role assignments will include assignment information on scopes where assignment is inherited (RBACAtScopeOnly = $($azAPICallConf['htParameters'].RBACAtScopeOnly))" -ForegroundColor Yellow
                $script:paramsUsed += "RBACAtScopeOnly: $($azAPICallConf['htParameters'].RBACAtScopeOnly) &#13;"
            }
        }

        if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy) {
            Write-Host " TenantSummary Policy assignments will also include assignments on ResourceGroups (DoNotIncludeResourceGroupsOnPolicy = $($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy))" -ForegroundColor Yellow
            $script:paramsUsed += 'DoNotIncludeResourceGroupsOnPolicy: false &#13;'
        }
        else {
            Write-Host " TenantSummary Policy assignments will not include assignments on ResourceGroups (DoNotIncludeResourceGroupsOnPolicy = $($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy))" -ForegroundColor Green
            $script:paramsUsed += 'DoNotIncludeResourceGroupsOnPolicy: true &#13;'
        }

        if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC) {
            Write-Host " TenantSummary RBAC Role assignments will also include assignments on ResourceGroups and Resources (DoNotIncludeResourceGroupsAndResourcesOnRBAC = $($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC))" -ForegroundColor Yellow
            $script:paramsUsed += 'DoNotIncludeResourceGroupsAndResourcesOnRBAC: false &#13;'
        }
        else {
            Write-Host " TenantSummary RBAC Role assignments will not include assignments on ResourceGroups and Resources (DoNotIncludeResourceGroupsAndResourcesOnRBAC = $($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC))" -ForegroundColor Green
            $script:paramsUsed += 'DoNotIncludeResourceGroupsAndResourcesOnRBAC: true &#13;'
        }

        if (-not $NoCsvExport) {
            Write-Host " CSV Export enabled: enriched 'Role assignments' data, enriched 'Policy assignments' data and 'all resources' (subscriptionId, mgPath, resourceType, id, name, location, tags, createdTime, changedTime) (-NoCsvExport = $($NoCsvExport))" -ForegroundColor Yellow
            $script:paramsUsed += 'NoCsvExport: false &#13;'
        }
        else {
            Write-Host " CSV Export disabled: enriched 'Role assignments' data, enriched 'Policy assignments' data and 'all resources' (subscriptionId, mgPath, resourceType, id, name, location, tags, createdTime, changedTime) (-NoCsvExport = $($NoCsvExport))" -ForegroundColor Green
            $script:paramsUsed += 'NoCsvExport: true &#13;'
        }

        if (-not $azAPICallConf['htParameters'].NoJsonExport) {
            Write-Host " JSON Export enabled: export of ManagementGroup Hierarchy including all MG/Sub Policy/RBAC definitions, Policy/RBAC assignments and some more relevant information to JSON (-NoJsonExport = $($azAPICallConf['htParameters'].NoJsonExport))" -ForegroundColor Yellow
            $script:paramsUsed += 'NoJsonExport: false &#13;'
            if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy) {
                if (-not $JsonExportExcludeResourceGroups) {
                    Write-Host " JSON Export will also include Policy assignments on ResourceGroups (JsonExportExcludeResourceGroups = $($JsonExportExcludeResourceGroups))" -ForegroundColor Yellow
                    $script:paramsUsed += "JsonExportExcludeResourceGroups Policy: $($JsonExportExcludeResourceGroups) &#13;"
                }
                else {
                    Write-Host " JSON Export will not include Policy assignments on ResourceGroups (JsonExportExcludeResourceGroups = $($JsonExportExcludeResourceGroups))" -ForegroundColor Green
                    $script:paramsUsed += "JsonExportExcludeResourceGroups Policy: $($JsonExportExcludeResourceGroups) &#13;"
                }
            }
            if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC) {
                if (-not $JsonExportExcludeResourceGroups) {
                    Write-Host " JSON Export will also include Role assignments on ResourceGroups (JsonExportExcludeResourceGroups = $($JsonExportExcludeResourceGroups))" -ForegroundColor Yellow
                    $script:paramsUsed += "JsonExportExcludeResourceGroups RBAC: $($JsonExportExcludeResourceGroups) &#13;"

                }
                else {
                    Write-Host " JSON Export will not include Role assignments on ResourceGroups (JsonExportExcludeResourceGroups = $($JsonExportExcludeResourceGroups))" -ForegroundColor Green
                    $script:paramsUsed += "JsonExportExcludeResourceGroups RBAC: $($JsonExportExcludeResourceGroups) &#13;"
                }
                if (-not $JsonExportExcludeResources) {
                    Write-Host " JSON Export will also include Role assignments on Resources (JsonExportExcludeResources = $($JsonExportExcludeResources))" -ForegroundColor Yellow
                    $script:paramsUsed += "JsonExportExcludeResources RBAC: $($JsonExportExcludeResources) &#13;"
                }
                else {
                    Write-Host " JSON Export will not include Role assignments on Resources (JsonExportExcludeResources = $($JsonExportExcludeResources))" -ForegroundColor Green
                    $script:paramsUsed += "JsonExportExcludeResources RBAC: $($JsonExportExcludeResources) &#13;"
                }
            }
        }
        else {
            Write-Host " JSON Export disabled: export of ManagementGroup Hierarchy including all MG/Sub Policy/RBAC definitions, Policy/RBAC assignments and some more relevant information to JSON (-NoJsonExport = $($azAPICallConf['htParameters'].NoJsonExport))" -ForegroundColor Green
            $script:paramsUsed += 'NoJsonExport: true &#13;'
        }

        if ($ThrottleLimit -eq 10) {
            Write-Host " ThrottleLimit = $ThrottleLimit" -ForegroundColor Yellow
            #$script:paramsUsed += "ThrottleLimit: $ThrottleLimit &#13;"
        }
        else {
            Write-Host " ThrottleLimit = $ThrottleLimit" -ForegroundColor Green
            #$script:paramsUsed += "ThrottleLimit: $ThrottleLimit &#13;"
        }


        if ($ChangeTrackingDays -eq 14) {
            Write-Host " ChangeTrackingDays = $ChangeTrackingDays" -ForegroundColor Yellow
            #$script:paramsUsed += "ChangeTrackingDays: $ChangeTrackingDays &#13;"
        }
        else {
            Write-Host " ChangeTrackingDays = $ChangeTrackingDays" -ForegroundColor Green
            #$script:paramsUsed += "ChangeTrackingDays: $ChangeTrackingDays &#13;"
        }

        if ($azAPICallConf['htParameters'].NoResources) {
            Write-Host " NoResources = $($azAPICallConf['htParameters'].NoResources)" -ForegroundColor Green
            $script:paramsUsed += "NoResources: $($azAPICallConf['htParameters'].NoResources) &#13;"
        }
        else {
            Write-Host " NoResources = $($azAPICallConf['htParameters'].NoResources)" -ForegroundColor Yellow
            $script:paramsUsed += "NoResources: $($azAPICallConf['htParameters'].NoResources) &#13;"
        }

        if ($ShowMemoryUsage) {
            Write-Host " ShowMemoryUsage = $($ShowMemoryUsage)" -ForegroundColor Green
            #$script:paramsUsed += "ShowMemoryUsage: $($ShowMemoryUsage) &#13;"
        }
        else {
            Write-Host " ShowMemoryUsage = $($ShowMemoryUsage)" -ForegroundColor Yellow
            #$script:paramsUsed += "ShowMemoryUsage: $($ShowMemoryUsage) &#13;"
        }

        if ($CriticalMemoryUsage -ne 99) {
            Write-Host " CriticalMemoryUsage = $($CriticalMemoryUsage)%" -ForegroundColor green
            #$script:paramsUsed += "ShowMemoryUsage: $($ShowMemoryUsage) &#13;"
        }
        else {
            Write-Host " CriticalMemoryUsage = $($CriticalMemoryUsage)%" -ForegroundColor Yellow
            #$script:paramsUsed += "ShowMemoryUsage: $($ShowMemoryUsage) &#13;"
        }

        if ($azAPICallConf['htParameters'].DoPSRule) {
            Write-Host " DoPSRule = $($azAPICallConf['htParameters'].DoPSRule)" -ForegroundColor Green
            $script:paramsUsed += "DoPSRule: $($azAPICallConf['htParameters'].DoPSRule) &#13;"

            if ($azAPICallConf['htParameters'].PSRuleFailedOnly) {
                Write-Host " PSRuleFailedOnly = $($azAPICallConf['htParameters'].PSRuleFailedOnly)" -ForegroundColor Green
                $script:paramsUsed += "PSRuleFailedOnly: $($azAPICallConf['htParameters'].PSRuleFailedOnly) &#13;"
            }
            else {
                Write-Host " PSRuleFailedOnly = $($azAPICallConf['htParameters'].PSRuleFailedOnly)" -ForegroundColor Yellow
                $script:paramsUsed += "PSRuleFailedOnly: $($azAPICallConf['htParameters'].PSRuleFailedOnly) &#13;"
            }
        }
        else {
            Write-Host " DoPSRule = $($azAPICallConf['htParameters'].DoPSRule)" -ForegroundColor Yellow
            $script:paramsUsed += "DoPSRule: $($azAPICallConf['htParameters'].DoPSRule) &#13;"
        }

        if ($NoPIMEligibility) {
            Write-Host " NoPIMEligibility = $($NoPIMEligibility)" -ForegroundColor Green
            $script:paramsUsed += "NoPIMEligibility: $($NoPIMEligibility) &#13;"
        }
        else {
            Write-Host " NoPIMEligibility = $($NoPIMEligibility)" -ForegroundColor Yellow
            $script:paramsUsed += "NoPIMEligibility: $($NoPIMEligibility) &#13;"
        }

        if ($PIMEligibilityIgnoreScope) {
            Write-Host " PIMEligibilityIgnoreScope = $($PIMEligibilityIgnoreScope)" -ForegroundColor Green
            #$script:paramsUsed += "PIMEligibilityIgnoreScope: $($PIMEligibilityIgnoreScope) &#13;"
        }
        else {
            Write-Host " PIMEligibilityIgnoreScope = $($PIMEligibilityIgnoreScope)" -ForegroundColor Yellow
            #$script:paramsUsed += "PIMEligibilityIgnoreScope: $($PIMEligibilityIgnoreScope) &#13;"
        }

        if ($NoPIMEligibilityIntegrationRoleAssignmentsAll) {
            Write-Host " NoPIMEligibilityIntegrationRoleAssignmentsAll = $($NoPIMEligibilityIntegrationRoleAssignmentsAll)" -ForegroundColor Green
            #$script:paramsUsed += "NoPIMEligibilityIntegrationRoleAssignmentsAll: $($NoPIMEligibilityIntegrationRoleAssignmentsAll) &#13;"
        }
        else {
            Write-Host " NoPIMEligibilityIntegrationRoleAssignmentsAll = $($NoPIMEligibilityIntegrationRoleAssignmentsAll)" -ForegroundColor Yellow
            #$script:paramsUsed += "NoPIMEligibilityIntegrationRoleAssignmentsAll: $($NoPIMEligibilityIntegrationRoleAssignmentsAll) &#13;"
        }

        if ($NoDefinitionInsightsDedicatedHTML) {
            Write-Host " NoDefinitionInsightsDedicatedHTML = $($NoDefinitionInsightsDedicatedHTML)" -ForegroundColor Green
            #$script:paramsUsed += "NoDefinitionInsightsDedicatedHTML: $($NoDefinitionInsightsDedicatedHTML) &#13;"
        }
        else {
            Write-Host " NoDefinitionInsightsDedicatedHTML = $($NoDefinitionInsightsDedicatedHTML)" -ForegroundColor Yellow
            #$script:paramsUsed += "NoDefinitionInsightsDedicatedHTML: $($NoDefinitionInsightsDedicatedHTML) &#13;"
        }

        if ($NoALZPolicyVersionChecker) {
            Write-Host " NoALZPolicyVersionChecker = $($NoALZPolicyVersionChecker)" -ForegroundColor Green
            #$script:paramsUsed += "NoALZPolicyVersionChecker: $($NoALZPolicyVersionChecker) &#13;"
        }
        else {
            Write-Host " NoALZPolicyVersionChecker = $($NoALZPolicyVersionChecker)" -ForegroundColor Yellow
            #$script:paramsUsed += "NoALZPolicyVersionChecker: $($NoALZPolicyVersionChecker) &#13;"
        }

        if ($NoStorageAccountAccessAnalysis) {
            Write-Host " NoStorageAccountAccessAnalysis = $($NoStorageAccountAccessAnalysis)" -ForegroundColor Green
            #$script:paramsUsed += "NoStorageAccountAccessAnalysis: $($NoStorageAccountAccessAnalysis) &#13;"
        }
        else {
            Write-Host " NoStorageAccountAccessAnalysis = $($NoStorageAccountAccessAnalysis)" -ForegroundColor Yellow
            #$script:paramsUsed += "NoStorageAccountAccessAnalysis: $($NoStorageAccountAccessAnalysis) &#13;"
            if ($StorageAccountAccessAnalysisSubscriptionTags[0] -ne 'undefined' -and $StorageAccountAccessAnalysisSubscriptionTags.Count -gt 0) {
                Write-Host "   StorageAccountAccessAnalysisSubscriptionTags: $($StorageAccountAccessAnalysisSubscriptionTags -join ', ')" -ForegroundColor Green
            }
            if ($StorageAccountAccessAnalysisStorageAccountTags[0] -ne 'undefined' -and $StorageAccountAccessAnalysisStorageAccountTags.Count -gt 0) {
                Write-Host "   StorageAccountAccessAnalysisStorageAccountTags: $($StorageAccountAccessAnalysisStorageAccountTags -join ', ')" -ForegroundColor Green
            }
        }

        if ($NoNetwork) {
            Write-Host " NoNetwork = $($NoNetwork)" -ForegroundColor Green
            #$script:paramsUsed += "NoNetwork: $($NoNetwork) &#13;"
        }
        else {
            Write-Host " NoNetwork = $($NoNetwork)" -ForegroundColor Yellow
            #$script:paramsUsed += "NoNetwork: $($NoNetwork) &#13;"

            if ($NetworkSubnetIPAddressUsageCriticalPercentage -ne 80) {
                Write-Host " NetworkSubnetIPAddressUsageCriticalPercentage = $($NetworkSubnetIPAddressUsageCriticalPercentage)" -ForegroundColor Green
                #$script:paramsUsed += "NetworkSubnetIPAddressUsageCriticalPercentage: $($NetworkSubnetIPAddressUsageCriticalPercentage) &#13;"
            }
            else {
                Write-Host " NoNetwork = $($NetworkSubnetIPAddressUsageCriticalPercentage)" -ForegroundColor Yellow
                #$script:paramsUsed += "NetworkSubnetIPAddressUsageCriticalPercentage: $($NetworkSubnetIPAddressUsageCriticalPercentage) &#13;"
            }
        }

        if ($GitHubActionsOIDC) {
            Write-Host " GitHubActionsOIDC = $($GitHubActionsOIDC)" -ForegroundColor Green
            #$script:paramsUsed += "GitHubActionsOIDC: $($GitHubActionsOIDC) &#13;"
        }
        else {
            Write-Host " GitHubActionsOIDC = $($GitHubActionsOIDC)" -ForegroundColor Yellow
            #$script:paramsUsed += "GitHubActionsOIDC: $($GitHubActionsOIDC) &#13;"
        }

    }
    #endregion RunInfo
}