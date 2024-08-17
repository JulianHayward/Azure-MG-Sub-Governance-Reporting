function validateAccess {
    #region validationAccess
    #validation / check 'Microsoft Graph API' Access
    $permissionCheckResults = @()
    if ($azAPICallConf['htParameters'].onAzureDevOpsOrGitHubActions -eq $true -or $azAPICallConf['htParameters'].accountType -eq 'ServicePrincipal' -or $azAPICallConf['htParameters'].accountType -eq 'ManagedService' -or $azAPICallConf['htParameters'].accountType -eq 'ClientAssertion') {

        Write-Host "Checking $($azAPICallConf['htParameters'].accountType) permissions"

        $permissionsCheckFailed = $false

        $currentTask = 'Test MSGraph Users Read permission'
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/users?`$count=true&`$top=1"
        $method = 'GET'
        $res = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -consistencyLevel 'eventual' -validateAccess
        if ($res -eq 'failed') {
            $permissionCheckResults += "MSGraph API 'Users Read' permission - check FAILED"
            $permissionsCheckFailed = $true
        }
        else {
            $permissionCheckResults += "MSGraph API 'Users Read' permission - check PASSED"
        }

        $currentTask = 'Test MSGraph Groups Read permission'
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/groups?`$count=true&`$top=1"
        $method = 'GET'
        $res = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -consistencyLevel 'eventual' -validateAccess
        if ($res -eq 'failed') {
            $permissionCheckResults += "MSGraph API 'Groups Read' permission - check FAILED"
            $permissionsCheckFailed = $true
        }
        else {
            $permissionCheckResults += "MSGraph API 'Groups Read' permission - check PASSED"
        }

        $currentTask = 'Test MSGraph ServicePrincipals Read permission'
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/servicePrincipals?`$count=true&`$top=1"
        $method = 'GET'
        $res = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -consistencyLevel 'eventual' -validateAccess
        if ($res -eq 'failed') {
            $permissionCheckResults += "MSGraph API 'ServicePrincipals Read' permission - check FAILED"
            $permissionsCheckFailed = $true
        }
        else {
            $permissionCheckResults += "MSGraph API 'ServicePrincipals Read' permission - check PASSED"
        }

        if (-not $NoPIMEligibility) {
            $currentTask = 'Test MSGraph PrivilegedAccess.Read.AzureResources permission'
            $uriExt = "&`$expand=parent&`$filter=(type eq 'subscription' or type eq 'managementgroup')&`$top=1"
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/beta/privilegedAccess/azureResources/resources?`$select=id,displayName,type,externalId" + $uriExt
            $res = AzAPICall -AzAPICallConfiguration $azapicallConf -uri $uri -currentTask $currentTask -validateAccess
            if ($res -eq 'failed') {
                $permissionCheckResults += "MSGraph API 'PrivilegedAccess.Read.AzureResources' permission - check FAILED - if you cannot grant this permission or you do not have a Microsoft Entra ID P2 license, then use parameter -NoPIMEligibility"
                $permissionsCheckFailed = $true
            }
            else {
                $permissionCheckResults += "MSGraph API 'PrivilegedAccess.Read.AzureResources' permission - check PASSED"
            }
        }
    }
    #endregion validationAccess

    #ManagementGroup helper
    #region managementGroupHelper
    if (-not $ManagementGroupId) {
        #$catchResult = "letscheck"
        $currentTask = 'Getting all Management Groups'
        #Write-Host $currentTask
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups?api-version=2020-05-01"
        $method = 'GET'
        $getAzManagementGroups = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -validateAccess

        if ($getAzManagementGroups -eq 'failed') {
            $permissionCheckResults += "RBAC 'Reader' permissions on Management Group - check FAILED (use Id, not displayName)"
            $permissionsCheckFailed = $true
        }
        else {
            $permissionCheckResults += "RBAC 'Reader' permissions on Management Group - check PASSED"
        }

        Write-Host 'Permission check results'
        foreach ($permissionCheckResult in $permissionCheckResults) {
            if ($permissionCheckResult -like '*PASSED*') {
                Write-Host $permissionCheckResult -ForegroundColor Green
            }
            else {
                Write-Host $permissionCheckResult -ForegroundColor DarkRed
            }
        }
        if ($permissionsCheckFailed -eq $true) {
            Write-Host "Please consult the documentation: https://$($GithubRepository)#required-permissions-in-azure"
            Throw 'Error - Azure Governance Visualizer: check the last console output for details'
        }

        if ($getAzManagementGroups.Count -eq 0) {
            Write-Host 'Management Groups count returned null'
            Throw 'Error - Azure Governance Visualizer: check the last console output for details'
        }
        else {
            Write-Host "Detected $($getAzManagementGroups.Count) Management Groups"
        }

        [array]$MgtGroupArray = addIndexNumberToArray -array ($getAzManagementGroups)
        if (-not $MgtGroupArray) {
            Write-Host 'Seems you do not have access to any Management Group. Please make sure you have the required RBAC role [Reader] assigned on at least one Management Group' -ForegroundColor Red
            Throw 'Error - Azure Governance Visualizer: check the last console output for details'
        }

        selectMg

        if ($($MgtGroupArray[$SelectedMG - 1].Name)) {
            $script:ManagementGroupId = $($MgtGroupArray[$SelectedMG - 1].name)
            $script:ManagementGroupName = $($MgtGroupArray[$SelectedMG - 1].properties.displayName)
        }
        else {
            Write-Host 's.th. unexpected happened' -ForegroundColor Red
            return
        }
        Write-Host "Selected Management Group: #$($SelectedMG) $ManagementGroupName (Id: $ManagementGroupId)" -ForegroundColor Green
        Write-Host '_______________________________________'
    }
    else {
        $currentTask = "Checking permissions for ManagementGroup '$ManagementGroupId'"
        Write-Host $currentTask
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)?api-version=2020-05-01"
        $method = 'GET'
        $selectedManagementGroupId = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -listenOn 'Content' -validateAccess

        if ($selectedManagementGroupId -eq 'failed') {
            $permissionCheckResults += "RBAC 'Reader' permissions on Management Group '$($ManagementGroupId)' - check FAILED (use Id, not displayName)"
            $permissionsCheckFailed = $true
        }
        else {
            $permissionCheckResults += "RBAC 'Reader' permissions on Management Group '$($ManagementGroupId)' - check PASSED"
            $script:ManagementGroupId = $selectedManagementGroupId.Name
            $script:ManagementGroupName = $selectedManagementGroupId.properties.displayName
        }

        Write-Host 'Permission check results'
        foreach ($permissionCheckResult in $permissionCheckResults) {
            if ($permissionCheckResult -like '*PASSED*') {
                Write-Host $permissionCheckResult -ForegroundColor Green
            }
            else {
                Write-Host $permissionCheckResult -ForegroundColor DarkRed
            }
        }

        if ($permissionsCheckFailed -eq $true) {
            Write-Host "Please consult the documentation for permission requirements: https://$($GithubRepository)#technical-documentation"
            Throw 'Error - Azure Governance Visualizer: check the last console output for details'
        }
    }
    #endregion managementGroupHelper

    if ($azAPICallConf['htParameters'].accountType -eq 'User') {
        validateLeastPrivilegeForUser
    }
}
