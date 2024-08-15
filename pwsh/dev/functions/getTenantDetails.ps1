function getTenantDetails {
    $currentTask = 'Get Tenant details'
    Write-Host $currentTask
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/tenants?api-version=2020-01-01"
    $method = 'GET'
    $tenantDetailsResult = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask

    if (($tenantDetailsResult).count -gt 0) {
        $tenantDetails = $tenantDetailsResult.where({ $_.tenantId -eq ($azAPICallConf['checkContext']).Tenant.Id })
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