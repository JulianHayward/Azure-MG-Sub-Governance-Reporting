function getDefaultManagementGroup {
    Write-Host 'Get Default Management Group'
    #test 
    Write-Host $Configuration['htAzureEnvironmentRelatedUrls'].ARM
    $currentTask = 'Get Default Management Group'
    #https://docs.microsoft.com/en-us/azure/governance/management-groups/how-to/protect-resource-hierarchy#setting---default-management-group
    $uri = "$($Configuration['htAzureEnvironmentRelatedUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($Configuration['checkContext'].Tenant.Id)/settings?api-version=2020-02-01"
    $method = 'GET'
    $settingsMG = AzAPICall -AzAPICallConfiguration $Configuration -uri $uri -method $method -currentTask $currentTask

    if (($settingsMG).count -gt 0) {
        write-host " default ManagementGroup Id: $($settingsMG.properties.defaultManagementGroup)"
        $script:defaultManagementGroupId = $settingsMG.properties.defaultManagementGroup
        write-host " requireAuthorizationForGroupCreation: $($settingsMG.properties.requireAuthorizationForGroupCreation)"
        $script:requireAuthorizationForGroupCreation = $settingsMG.properties.requireAuthorizationForGroupCreation
    }
    else {
        write-host " default ManagementGroup: $(($Configuration['checkContext']).Tenant.Id) (Tenant Root)"
        $script:defaultManagementGroupId = ($Configuration['checkContext']).Tenant.Id
        $script:requireAuthorizationForGroupCreation = $false
    }
}