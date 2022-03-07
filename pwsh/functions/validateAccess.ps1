function validateAccess {
    #region validationAccess
    #validation / check 'Microsoft Graph API' Access
    $permissionCheckResults = @()
    if ($htParameters.onAzureDevOpsOrGitHubActions -eq $true -or $accountType -eq 'ServicePrincipal' -or $accountType -eq 'ManagedService' -or $accountType -eq 'ClientAssertion') {

        Write-Host "Checking $accountType permissions"

        $permissionsCheckFailed = $false

        $currentTask = 'Test MSGraph Users Read permission'
        $uri = "$(($htAzureEnvironmentRelatedUrls).MicrosoftGraph)/v1.0/users?`$count=true&`$top=1"
        $method = 'GET'
        $res = AzAPICall -uri $uri -method $method -currentTask $currentTask -consistencyLevel 'eventual' -validateAccess -noPaging

        if ($res -eq 'failed') {
            $permissionCheckResults += "MSGraph API 'Users Read' permission - check FAILED"
            $permissionsCheckFailed = $true
        }
        else {
            $permissionCheckResults += "MSGraph API 'Users Read' permission - check PASSED"
        }

        $currentTask = 'Test MSGraph Groups Read permission'
        $uri = "$(($htAzureEnvironmentRelatedUrls).MicrosoftGraph)/v1.0/groups?`$count=true&`$top=1"
        $method = 'GET'
        $res = AzAPICall -uri $uri -method $method -currentTask $currentTask -consistencyLevel 'eventual' -validateAccess -noPaging

        if ($res -eq 'failed') {
            $permissionCheckResults += "MSGraph API 'Groups Read' permission - check FAILED"
            $permissionsCheckFailed = $true
        }
        else {
            $permissionCheckResults += "MSGraph API 'Groups Read' permission - check PASSED"
        }

        $currentTask = 'Test MSGraph ServicePrincipals Read permission'
        $uri = "$(($htAzureEnvironmentRelatedUrls).MicrosoftGraph)/v1.0/servicePrincipals?`$count=true&`$top=1"
        $method = 'GET'
        $res = AzAPICall -uri $uri -method $method -currentTask $currentTask -consistencyLevel 'eventual' -validateAccess -noPaging

        if ($res -eq 'failed') {
            $permissionCheckResults += "MSGraph API 'ServicePrincipals Read' permission - check FAILED"
            $permissionsCheckFailed = $true
        }
        else {
            $permissionCheckResults += "MSGraph API 'ServicePrincipals' Read permission - check PASSED"
        }
    }
    #endregion validationAccess

    #ManagementGroup helper
    #region managementGroupHelper
    #thx @Jim Britt https://github.com/JimGBritt/AzurePolicy/tree/master/AzureMonitor/Scripts Create-AzDiagPolicy.ps1
    if (-not $ManagementGroupId) {
        #$catchResult = "letscheck"
        $currentTask = 'Getting all Management Groups'
        #Write-Host $currentTask
        $uri = "$(($htAzureEnvironmentRelatedUrls).ARM)/providers/Microsoft.Management/managementGroups?api-version=2020-05-01"
        $method = 'GET'
        $getAzManagementGroups = AzAPICall -uri $uri -method $method -currentTask $currentTask -validateAccess -noPaging

        if ($getAzManagementGroups -eq 'failed') {
            $permissionCheckResults += "'Reader' permissions on Management Group - check FAILED"
            $permissionsCheckFailed = $true
        }
        else {
            $permissionCheckResults += "'Reader' permissions on Management Group - check PASSED"
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
            Throw 'Error - AzGovViz: check the last console output for details'
        }

        if ($getAzManagementGroups.Count -eq 0) {
            Write-Host 'Management Groups count returned null'
            Throw 'Error - AzGovViz: check the last console output for details'
        }
        else {
            Write-Host "Detected $($getAzManagementGroups.Count) Management Groups"
        }

        [array]$MgtGroupArray = addIndexNumberToArray -array ($getAzManagementGroups)
        if (-not $MgtGroupArray) {
            Write-Host 'Seems you do not have access to any Management Group. Please make sure you have the required RBAC role [Reader] assigned on at least one Management Group' -ForegroundColor Red
            Throw 'Error - AzGovViz: check the last console output for details'
        }

        selectMg

        if ($($MgtGroupArray[$SelectedMG - 1].Name)) {
            $script:ManagementGroupId = $($MgtGroupArray[$SelectedMG - 1].Name)
            $script:ManagementGroupName = $($MgtGroupArray[$SelectedMG - 1].DisplayName)
        }
        else {
            Write-Host 's.th. unexpected happened' -ForegroundColor Red
            return
        }
        Write-Host "Selected Management Group: $ManagementGroupName (Id: $ManagementGroupId)" -ForegroundColor Green
        Write-Host '_______________________________________'
    }
    else {
        $currentTask = "Checking permissions for ManagementGroup '$ManagementGroupId'"
        Write-Host $currentTask
        $uri = "$(($htAzureEnvironmentRelatedUrls).ARM)/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)?api-version=2020-05-01"
        $method = 'GET'
        $selectedManagementGroupId = AzAPICall -uri $uri -method $method -currentTask $currentTask -listenOn 'Content' -validateAccess -noPaging

        if ($selectedManagementGroupId -eq 'failed') {
            $permissionCheckResults += "'Reader' permissions on Management Group '$($ManagementGroupId)' - check FAILED"
            $permissionsCheckFailed = $true
        }
        else {
            $permissionCheckResults += "'Reader' permissions on Management Group '$($ManagementGroupId)' - check PASSED"
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
            Write-Host "Please consult the documentation: https://$($GithubRepository)#required-permissions-in-azure"
            Throw 'Error - AzGovViz: check the last console output for details'
        }

    }
    #endregion managementGroupHelper
}