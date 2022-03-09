function stats {
    #region Stats
    if (-not $StatsOptOut) {

        if ($Configuration['htParameters'].onAzureDevOps) {
            if ($env:BUILD_REPOSITORY_ID) {
                $hashTenantIdOrRepositoryId = [string]($env:BUILD_REPOSITORY_ID)
            }
            else {
                $hashTenantIdOrRepositoryId = [string]($Configuration['checkContext'].Tenant.Id)
            }
        }
        else {
            $hashTenantIdOrRepositoryId = [string]($Configuration['checkContext'].Tenant.Id)
        }

        $hashAccId = [string]($Configuration['checkContext'].Account.Id)

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

        $accountInfo = "$($Configuration['accountType'])$($Configuration['htParameters'].userType)"
        if ($Configuration['accountType'] -eq 'ServicePrincipal' -or $Configuration['accountType'] -eq 'ManagedService' -or $Configuration['accountType'] -eq 'ClientAssertion') {
            $accountInfo = $Configuration['accountType']
        }

        $scopeUsage = 'childManagementGroup'
        if ($ManagementGroupId -eq $Configuration['checkContext'].Tenant.Id) {
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
                "azCloud": "$($Configuration['checkContext'].Environment.Name)",
                "identifier": "$($identifier)",
                "platform": "$($Configuration['htParameters'].CodeRunPlatform)",
                "productVersion": "$($ProductVersion)",
                "psAzAccountsVersion": "$($resolvedAzModuleVersion)",
                "psVersion": "$($PSVersionTable.PSVersion)",
                "scopeUsage": "$($scopeUsage)",
                "statsCountErrors": "$($Error.Count)",
                "statsCountSubscriptions": "$($statsCountSubscriptions)",
                "statsParametersDoNotIncludeResourceGroupsAndResourcesOnRBAC": "$($Configuration['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC)",
                "statsParametersDoNotIncludeResourceGroupsOnPolicy": "$($Configuration['htParameters'].DoNotIncludeResourceGroupsOnPolicy)",
                "statsParametersDoNotShowRoleAssignmentsUserData": "$($Configuration['htParameters'].DoNotShowRoleAssignmentsUserData)",
                "statsParametersHierarchyMapOnly": "$($Configuration['htParameters'].HierarchyMapOnly)",
                "statsParametersManagementGroupsOnly": "$($Configuration['htParameters'].ManagementGroupsOnly)",
                "statsParametersLargeTenant": "$($Configuration['htParameters'].LargeTenant)",
                "statsParametersNoASCSecureScore": "$($Configuration['htParameters'].NoMDfCSecureScore)",
                "statsParametersDoAzureConsumption": "$($Configuration['htParameters'].DoAzureConsumption)",
                "statsParametersNoJsonExport": "$($Configuration['htParameters'].NoJsonExport)",
                "statsParametersNoScopeInsights": "$($NoScopeInsights)",
                "statsParametersNoSingleSubscriptionOutput": "$($NoSingleSubscriptionOutput)",
                "statsParametersNoPolicyComplianceStates": "$($Configuration['htParameters'].NoPolicyComplianceStates)",
                "statsParametersNoResourceProvidersDetailed": "$($Configuration['htParameters'].NoResourceProvidersDetailed)",
                "statsParametersNoResources": "$($Configuration['htParameters'].NoResources)",
                "statsParametersPolicyAtScopeOnly": "$($Configuration['htParameters'].PolicyAtScopeOnly)",
                "statsParametersRBACAtScopeOnly": "$($Configuration['htParameters'].RBACAtScopeOnly)",
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