function getSubscriptions {
    $startGetSubscriptions = Get-Date
    $currentTask = 'Getting all Subscriptions'
    Write-Host "$currentTask"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions?api-version=2020-01-01"
    $method = 'GET'
    $requestAllSubscriptionsAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask

    Write-Host " $($requestAllSubscriptionsAPI.Count) Subscriptions returned"
    foreach ($subscription in $requestAllSubscriptionsAPI) {
        $script:htAllSubscriptionsFromAPI.($subscription.subscriptionId) = @{}
        $script:htAllSubscriptionsFromAPI.($subscription.subscriptionId).subDetails = $subscription
    }

    $endGetSubscriptions = Get-Date
    Write-Host "Getting all Subscriptions duration: $((NEW-TIMESPAN -Start $startGetSubscriptions -End $endGetSubscriptions).TotalSeconds) seconds"
}