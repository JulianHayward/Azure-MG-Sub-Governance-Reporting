function getTenantDetails {
    $currentTask = 'Get Tenant details'
    Write-Host $currentTask
    $uri = "$($Configuration['htAzureEnvironmentRelatedUrls'].ARM)/tenants?api-version=2020-01-01"
    $method = 'GET'
    $tenantDetailsResult = AzAPICall -AzAPICallConfiguration $Configuration -uri $uri -method $method -currentTask $currentTask

    if (($tenantDetailsResult).count -gt 0) {
        $tenantDetails = $tenantDetailsResult | Where-Object { $_.tenantId -eq ($Configuration['checkContext']).Tenant.Id }
        if ($tenantDetails.displayName) {
            $script:tenantDisplayName = $tenantDetails.displayName
            Write-Host " Tenant DisplayName: $tenantDisplayName"
        }
        else {
            Write-Host ' Tenant DisplayName: could not be retrieved'
        }

        if ($tenantDetails.defaultDomain) {
            $script:tenantDefaultDomain = $tenantDetails.defaultDomain
        }
    }
    else {
        Write-Host ' something unexpected'
    }
}