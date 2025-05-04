function getDefaultManagementGroup {
    $currentTask = 'Get Default Management Group'
    Write-Host $currentTask
    #https://learn.microsoft.com/azure/governance/management-groups/how-to/protect-resource-hierarchy#setting---default-management-group
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($azAPICallConf['checkContext'].Tenant.Id)/settings?api-version=2023-04-01"
    $method = 'GET'
    #fix https://github.com/Azure/Azure-Governance-Visualizer/issues/53
    $settingsMG = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -skipOnErrorCode 403

    if ($settingsMG) {
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
    else {
        Write-Host " default ManagementGroup: could not be determined, flagging default ManagementGroup as 'unknown.'"
        $script:defaultManagementGroupId = 'unknown.'
        $script:requireAuthorizationForGroupCreation = 'unknown.'
    }

}