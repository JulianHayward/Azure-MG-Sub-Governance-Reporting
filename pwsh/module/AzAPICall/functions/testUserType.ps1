function testUserType {
    $userType = 'n/a'
    if ($accountType -eq 'User') {
        $currentTask = 'Check AAD UserType'
        Write-Host " $currentTask"
        $uri = ($htAzureEnvironmentRelatedUrls).MicrosoftGraph + '/v1.0/me?$select=userType'
        $method = 'GET'
        $checkUserType = AzAPICall -uri $uri -method $method -listenOn 'Content' -currentTask $currentTask

        if ($checkUserType -eq 'unknown') {
            $userType = $checkUserType
        }
        else {
            $userType = $checkUserType.UserType
        }
        Write-Host "  AAD UserType: $($userType)" -ForegroundColor Yellow
        Write-Host '  AAD UserType check succeeded' -ForegroundColor Green
    }
    $global:htParameters.UserType = $userType
}