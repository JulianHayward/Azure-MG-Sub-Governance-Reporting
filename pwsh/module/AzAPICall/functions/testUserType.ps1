function testUserType {
    param(
        [Parameter(Mandatory = $True)]
        [object]
        $AzAPICallConfiguration
    )

    $userType = 'n/a'
    if ($AzAPICallConfiguration['accountType'] -eq 'User') {
        $currentTask = 'Check AAD UserType'
        Write-Host " $currentTask"
        $uri = $AzAPICallConfiguration['htAzureEnvironmentRelatedUrls'].MicrosoftGraph + '/v1.0/me?$select=userType'
        $method = 'GET'
        $checkUserType = AzAPICall -AzAPICallConfiguration $AzAPICallConfiguration -uri $uri -method $method -listenOn 'Content' -currentTask $currentTask

        if ($checkUserType -eq 'unknown') {
            $userType = $checkUserType
        }
        else {
            $userType = $checkUserType.UserType
        }
        Write-Host "  AAD UserType: $($userType)" -ForegroundColor Yellow
        Write-Host '  AAD UserType check succeeded' -ForegroundColor Green
    }
    Write-Output $userType
}