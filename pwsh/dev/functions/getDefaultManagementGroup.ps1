function getDefaultManagementGroup {
    $currentTask = 'Get Default Management Group'
    Write-Host $currentTask
    #https://docs.microsoft.com/en-us/azure/governance/management-groups/how-to/protect-resource-hierarchy#setting---default-management-group
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($azAPICallConf['checkContext'].Tenant.Id)/settings?api-version=2020-02-01"
    $method = 'GET'
    $settingsMG = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask

    if (($settingsMG).count -gt 0) {
        Write-Host " default ManagementGroup Id: $($settingsMG.properties.defaultManagementGroup)"
        $script:defaultManagementGroupId = $settingsMG.properties.defaultManagementGroup
        Write-Host " requireAuthorizationForGroupCreation: $($settingsMG.properties.requireAuthorizationForGroupCreation)"
        $script:requireAuthorizationForGroupCreation = $settingsMG.properties.requireAuthorizationForGroupCreation
    }
    else {
        Write-Host " default ManagementGroup: $(($azAPICallConf['checkContext']).Tenant.Id) (Tenant Root)"
        $script:defaultManagementGroupId = ($azAPICallConf['checkContext']).Tenant.Id
        $script:requireAuthorizationForGroupCreation = $false
    }
}