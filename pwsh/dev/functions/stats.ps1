function stats {
    #region Stats
    if (-not $StatsOptOut) {

        $dur = 0
        if ($durationProduct.TotalMinutes -lt 5) {
            $dur = 5
        }

        if ($azAPICallConf['htParameters'].onAzureDevOps) {
            if ($env:BUILD_REPOSITORY_ID) {
                $hashTenantIdOrRepositoryId = [string]($env:BUILD_REPOSITORY_ID)
            }
            else {
                $hashTenantIdOrRepositoryId = [string]($azAPICallConf['checkContext'].Tenant.Id)
            }
        }
        else {
            $hashTenantIdOrRepositoryId = [string]($azAPICallConf['checkContext'].Tenant.Id)
        }

        $hashAccId = [string]($azAPICallConf['checkContext'].Account.Id)

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
        $script:statsIdentifier = "$(([System.BitConverter]::ToString($identifierBase)) -replace '-')"

        $accountInfo = "$($azAPICallConf['htParameters'].accountType)$($azAPICallConf['htParameters'].userType)"
        if ($azAPICallConf['htParameters'].accountType -eq 'ServicePrincipal' -or $azAPICallConf['htParameters'].accountType -eq 'ManagedService' -or $azAPICallConf['htParameters'].accountType -eq 'ClientAssertion') {
            $accountInfo = $azAPICallConf['htParameters'].accountType
        }

        $scopeUsage = 'childManagementGroup'
        if ($ManagementGroupId -eq $azAPICallConf['checkContext'].Tenant.Id) {
            $scopeUsage = 'rootManagementGroup'
        }

        $statsCountSubscriptions = 'less than 100'
        if (($htSubscriptionsMgPath.Keys).Count -ge 100) {
            $statsCountSubscriptions = 'more than 100'
        }

        $tryCounter = 0
        do {
            if ($tryCounter -gt 0) {
                Start-Sleep -Seconds ($tryCounter * 3)
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
                "azCloud": "$($azAPICallConf['checkContext'].Environment.Name)",
                "identifier": "$($statsIdentifier)",
                "platform": "$($azAPICallConf['htParameters'].CodeRunPlatform)",
                "productVersion": "$($ProductVersion)",
                "AzAPICallVersion": "$($AzAPICallVersion)",
                "psAzAccountsVersion": "$($azAPICallConf['htParameters'].AzAccountsVersion)",
                "psVersion": "$($PSVersionTable.PSVersion)",
                "scopeUsage": "$($scopeUsage)",
                "statsCountErrors": "$($Error.Count)",
                "statsCountSubscriptions": "$($statsCountSubscriptions)",
                "statsParametersDoNotIncludeResourceGroupsAndResourcesOnRBAC": "$($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC)",
                "statsParametersDoNotIncludeResourceGroupsOnPolicy": "$($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy)",
                "statsParametersDoNotShowRoleAssignmentsUserData": "$($azAPICallConf['htParameters'].DoNotShowRoleAssignmentsUserData)",
                "statsParametersHierarchyMapOnly": "$HierarchyMapOnly",
                "statsParametersManagementGroupsOnly": "$($azAPICallConf['htParameters'].ManagementGroupsOnly)",
                "statsParametersLargeTenant": "$($azAPICallConf['htParameters'].LargeTenant)",
                "statsParametersNoASCSecureScore": "$($azAPICallConf['htParameters'].NoMDfCSecureScore)",
                "statsParametersDoAzureConsumption": "$($azAPICallConf['htParameters'].DoAzureConsumption)",
                "statsParametersNoJsonExport": "$($azAPICallConf['htParameters'].NoJsonExport)",
                "statsParametersNoScopeInsights": "$($NoScopeInsights)",
                "statsParametersNoSingleSubscriptionOutput": "$($NoSingleSubscriptionOutput)",
                "statsParametersNoPolicyComplianceStates": "$($azAPICallConf['htParameters'].NoPolicyComplianceStates)",
                "statsParametersNoResourceProvidersDetailed": "$($azAPICallConf['htParameters'].NoResourceProvidersDetailed)",
                "statsParametersNoResourceProvidersAtAll": "$($azAPICallConf['htParameters'].NoResourceProvidersAtAll)",
                "statsParametersNoResources": "$($azAPICallConf['htParameters'].NoResources)",
                "statsParametersPolicyAtScopeOnly": "$($azAPICallConf['htParameters'].PolicyAtScopeOnly)",
                "statsParametersRBACAtScopeOnly": "$($azAPICallConf['htParameters'].RBACAtScopeOnly)",
                "statsParametersDoPSRule": "$($azAPICallConf['htParameters'].DoPSRule)",
                "statsParametersNoPIMEligibility": "$($NoPIMEligibility)",
                "statsParametersNoALZPolicyVersionChecker": "$($NoALZPolicyVersionChecker)",
                "statsParametersNoStorageAccountAccessAnalysis": "$($NoStorageAccountAccessAnalysis)",
                "statsParametersNoNetwork": "$($NoNetwork)",
                "statsTry": "$($tryCounter)",
                "statsDurationProduct": "$($dur)"
            }
        }
    }
}
"@
                $stats = Invoke-WebRequest -Uri 'https://dc.services.visualstudio.com/v2/track' -Method 'POST' -Body $statusBody
            }
            catch {
                $statsSuccess = $false
            }
        }
        until($statsSuccess -eq $true -or $tryCounter -gt 5)
    }
    else {
        #noStats
        $script:statsIdentifier = (New-Guid).Guid
        $tryCounter = 0
        do {
            if ($tryCounter -gt 0) {
                Start-Sleep -Seconds ($tryCounter * 3)
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
                "identifier": "$($statsIdentifier)",
                "statsTry": "$($tryCounter)"
            }
        }
    }
}
"@
                $stats = Invoke-WebRequest -Uri 'https://dc.services.visualstudio.com/v2/track' -Method 'POST' -Body $statusBody
            }
            catch {
                $statsSuccess = $false
            }
        }
        until($statsSuccess -eq $true -or $tryCounter -gt 5)
    }
    #endregion Stats
}