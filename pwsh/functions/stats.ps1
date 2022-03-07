function stats {
    #region Stats
    if (-not $StatsOptOut) {

        if ($htParameters.onAzureDevOps) {
            if ($env:BUILD_REPOSITORY_ID) {
                $hashTenantIdOrRepositoryId = [string]($env:BUILD_REPOSITORY_ID)
            }
            else {
                $hashTenantIdOrRepositoryId = [string]($checkContext.Tenant.Id)
            }
        }
        else {
            $hashTenantIdOrRepositoryId = [string]($checkContext.Tenant.Id)
        }

        $hashAccId = [string]($checkContext.Account.Id)

        $hasher384 = [System.Security.Cryptography.HashAlgorithm]::Create('sha384')
        $hasher512 = [System.Security.Cryptography.HashAlgorithm]::Create('sha512')

        $hashTenantIdOrRepositoryIdSplit = $hashTenantIdOrRepositoryId.split('-')
        $hashAccIdSplit = $hashAccId.split('-')

        if (($hashTenantIdOrRepositoryIdSplit[0])[0] -match '[a-z]') {
            $hashTenantIdOrRepositoryIdUse = "$(($hashTenantIdOrRepositoryIdSplit[0]).substring(2))$($hashAccIdSplit[2])"
            $hashTenantIdOrRepositoryIdUse = $hasher512.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hashTenantIdOrRepositoryIdUse))
            $hashTenantIdOrRepositoryIdUse = "$(([System.BitConverter]::ToString($hashTenantIdOrRepositoryIdUse)) -replace '-')"
        }
        else {
            $hashTenantIdOrRepositoryIdUse = "$(($hashTenantIdOrRepositoryIdSplit[4]).substring(6))$($hashAccIdSplit[1])"
            $hashTenantIdOrRepositoryIdUse = $hasher384.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hashTenantIdOrRepositoryIdUse))
            $hashTenantIdOrRepositoryIdUse = "$(([System.BitConverter]::ToString($hashTenantIdOrRepositoryIdUse)) -replace '-')"
        }

        if (($hashAccIdSplit[0])[0] -match '[a-z]') {
            $hashAccIdUse = "$($hashAccIdSplit[0].substring(2))$($hashTenantIdOrRepositoryIdSplit[2])"
            $hashAccIdUse = $hasher512.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hashAccIdUse))
            $hashAccIdUse = "$(([System.BitConverter]::ToString($hashAccIdUse)) -replace '-')"
            $hashUse = "$($hashAccIdUse)$($hashTenantIdOrRepositoryIdUse)"
        }
        else {
            $hashAccIdUse = "$($hashAccIdSplit[4].substring(6))$($hashTenantIdOrRepositoryIdSplit[1])"
            $hashAccIdUse = $hasher384.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hashAccIdUse))
            $hashAccIdUse = "$(([System.BitConverter]::ToString($hashAccIdUse)) -replace '-')"
            $hashUse = "$($hashTenantIdOrRepositoryIdUse)$($hashAccIdUse)"
        }

        $identifierBase = $hasher512.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hashUse))
        $identifier = "$(([System.BitConverter]::ToString($identifierBase)) -replace '-')"

        $accountInfo = "$($accountType)$($htParameters.userType)"
        if ($accountType -eq 'ServicePrincipal' -or $accountType -eq 'ManagedService' -or $accountType -eq 'ClientAssertion') {
            $accountInfo = $accountType
        }

        $scopeUsage = 'childManagementGroup'
        if ($ManagementGroupId -eq $checkContext.Tenant.Id) {
            $scopeUsage = 'rootManagementGroup'
        }

        $statsCountSubscriptions = 'less than 100'
        if (($htSubscriptionsMgPath.Keys).Count -ge 100) {
            $statsCountSubscriptions = 'more than 100'
        }


        $tryCounter = 0
        do {
            if ($tryCounter -gt 0) {
                start-sleep -seconds ($tryCounter * 3)
            }
            $tryCounter++
            $statsSuccess = $true
            try {
                $statusBody = @"
{
    "name": "Microsoft.ApplicationInsights.Event",
    "time": "$((Get-Date).ToUniversalTime())",
    "iKey": "ffcd6b2e-1a5e-429f-9495-e3492decfe06",
    "data": {
        "baseType": "EventData",
        "baseData": {
            "name": "$($Product)",
            "ver": 2,
            "properties": {
                "accType": "$($accountInfo)",
                "azCloud": "$($checkContext.Environment.Name)",
                "identifier": "$($identifier)",
                "platform": "$($htParameters.CodeRunPlatform)",
                "productVersion": "$($ProductVersion)",
                "psAzAccountsVersion": "$($resolvedAzModuleVersion)",
                "psVersion": "$($PSVersionTable.PSVersion)",
                "scopeUsage": "$($scopeUsage)",
                "statsCountErrors": "$($Error.Count)",
                "statsCountSubscriptions": "$($statsCountSubscriptions)",
                "statsParametersDoNotIncludeResourceGroupsAndResourcesOnRBAC": "$($htParameters.DoNotIncludeResourceGroupsAndResourcesOnRBAC)",
                "statsParametersDoNotIncludeResourceGroupsOnPolicy": "$($htParameters.DoNotIncludeResourceGroupsOnPolicy)",
                "statsParametersDoNotShowRoleAssignmentsUserData": "$($htParameters.DoNotShowRoleAssignmentsUserData)",
                "statsParametersHierarchyMapOnly": "$($htParameters.HierarchyMapOnly)",
                "statsParametersManagementGroupsOnly": "$($htParameters.ManagementGroupsOnly)",
                "statsParametersLargeTenant": "$($htParameters.LargeTenant)",
                "statsParametersNoASCSecureScore": "$($htParameters.NoMDfCSecureScore)",
                "statsParametersDoAzureConsumption": "$($htParameters.DoAzureConsumption)",
                "statsParametersNoJsonExport": "$($htParameters.NoJsonExport)",
                "statsParametersNoScopeInsights": "$($NoScopeInsights)",
                "statsParametersNoSingleSubscriptionOutput": "$($NoSingleSubscriptionOutput)",
                "statsParametersNoPolicyComplianceStates": "$($htParameters.NoPolicyComplianceStates)",
                "statsParametersNoResourceProvidersDetailed": "$($htParameters.NoResourceProvidersDetailed)",
                "statsParametersNoResources": "$($htParameters.NoResources)",
                "statsParametersPolicyAtScopeOnly": "$($htParameters.PolicyAtScopeOnly)",
                "statsParametersRBACAtScopeOnly": "$($htParameters.RBACAtScopeOnly)",
                "statsTry": "$($tryCounter)"
            }
        }
    }
}
"@
                $stats = Invoke-WebRequest -Uri 'https://dc.services.visualstudio.com/v2/track' -Method 'POST' -body $statusBody
            }
            catch {
                $statsSuccess = $false
            }
        }
        until($statsSuccess -eq $true -or $tryCounter -gt 5)
    }
    else {
        #noStats
        $identifier = (New-Guid).Guid
        $tryCounter = 0
        do {
            if ($tryCounter -gt 0) {
                start-sleep -seconds ($tryCounter * 3)
            }
            $tryCounter++
            $statsSuccess = $true
            try {
                $statusBody = @"
{
    "name": "Microsoft.ApplicationInsights.Event",
    "time": "$((Get-Date).ToUniversalTime())",
    "iKey": "ffcd6b2e-1a5e-429f-9495-e3492decfe06",
    "data": {
        "baseType": "EventData",
        "baseData": {
            "name": "$($Product)",
            "ver": 2,
            "properties": {
                "identifier": "$($identifier)",
                "statsTry": "$($tryCounter)"
            }
        }
    }
}
"@
                $stats = Invoke-WebRequest -Uri 'https://dc.services.visualstudio.com/v2/track' -Method 'POST' -body $statusBody
            }
            catch {
                $statsSuccess = $false
            }
        }
        until($statsSuccess -eq $true -or $tryCounter -gt 5)
    }
    #endregion Stats
}