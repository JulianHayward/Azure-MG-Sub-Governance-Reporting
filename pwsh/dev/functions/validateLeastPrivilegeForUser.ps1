function validateLeastPrivilegeForUser {
    $currentTask = "Validate least priviledge (Azure Resource side) for executing user $($azapicallConf['htParameters'].userObjectId)"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId eq '$($azapicallConf['htParameters'].userObjectId)'"
    $method = 'GET'
    $getRoleAssignmentsForExecutingUserAtManagementGroupId = AzAPICall -AzAPICallConfiguration $azapicallConf -uri $uri
    $nonReaderRolesAssigned = ($getRoleAssignmentsForExecutingUserAtManagementGroupId.properties.RoleDefinitionId | Sort-object -Unique).where({$_ -notlike '*acdd72a7-3385-48ef-bd42-f606fba81ae7'})
    if ($nonReaderRolesAssigned.Count -gt 0) {
        Write-Host "* * * LEAST PRIVILEGE ADVICE" -ForegroundColor DarkRed
        Write-Host "The Azure Governance Visualizer script is executed with more permissions than required."
        Write-Host "The executing identity '$($azapicallConf['checkContext'].Account.Id)' ($($azapicallConf['checkContext'].Account.Type)) Id: '$($azapicallConf['htparameters'].userObjectId)' has the following RBAC Role(s) assigned at Management Group scope '$ManagementGroupId':"
        foreach ($nonReaderRoleAssigned in $nonReaderRolesAssigned) {
            $currentTask = "Get RBAC Role definition '$nonReaderRoleAssigned'"
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)$($nonReaderRoleAssigned)?api-version=2022-04-01"
            $method = 'GET'
            $getRole = AzAPICall -AzAPICallConfiguration $azapicallConf -uri $uri -listenOn Content

            if ($getRole.properties.roleName -eq 'owner' -or $getRole.properties.roleName -eq 'contributor') {
                Write-Host " - $($getRole.properties.roleName) ($($getRole.properties.type)) !!!"
            }
            else{
                Write-Host " - $($getRole.properties.roleName) ($($getRole.properties.type))"
            }
        }
        Write-Host "The required Azure RBAC role at Management Group scope '$ManagementGroupId' is 'Reader' (acdd72a7-3385-48ef-bd42-f606fba81ae7)."
        Write-Host "Recommendation: consider executing the script in context of a Service Principal with least privilege. Review the Azure Governance Visualizer Setup Guide at 'https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting/blob/master/setup.md'"
        Write-Host ' * * * * * * * * * * * * * * * * * * * * * *' -ForegroundColor DarkRed
        pause
    }
    else {
        Write-Host "Azure Governance Visualizer Least Privilege check (Azure Resource side) for executing identity '$($azapicallConf['checkContext'].Account.Id)' ($($azapicallConf['checkContext'].Account.Type)) Id: '$($azapicallConf['htparameters'].userObjectId)' succeeded" -ForegroundColor Green
    }
}