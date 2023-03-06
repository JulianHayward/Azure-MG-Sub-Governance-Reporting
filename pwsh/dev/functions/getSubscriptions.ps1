function getSubscriptions {
    $startGetSubscriptions = Get-Date
    $currentTask = 'Getting all Subscriptions'
    Write-Host "$currentTask"
    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions?api-version=2020-01-01"
    $method = 'GET'
    $requestAllSubscriptionsAPI = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask

    $script:htAllSubscriptionsFromAPI = @{}
    $script:htSubscriptionsFromOtherTenants = @{}

    Write-Host " $($requestAllSubscriptionsAPI.Count) Subscriptions returned"
    foreach ($subscription in $requestAllSubscriptionsAPI) {

        if ($subscription.tenantId -ne $azAPICallConf['checkcontext'].tenant.id) {
            Write-Host "  Finding: $($subscription.displayName) ($($subscription.subscriptionId)) belongs to foreign tenant '$($subscription.tenantId)' - Azure Governance Visualizer: excluding this Subscripion" -ForegroundColor DarkRed
            $script:htSubscriptionsFromOtherTenants.($subscription.subscriptionId) = @{}
            $script:htSubscriptionsFromOtherTenants.($subscription.subscriptionId).subDetails = $subscription
        }
        else {
            $script:htAllSubscriptionsFromAPI.($subscription.subscriptionId) = @{}
            $script:htAllSubscriptionsFromAPI.($subscription.subscriptionId).subDetails = $subscription
        }
    }
    Write-Host " $($htAllSubscriptionsFromAPI.Keys.Count) Subscriptions relevant"

    $endGetSubscriptions = Get-Date
    Write-Host "Getting all Subscriptions duration: $((New-TimeSpan -Start $startGetSubscriptions -End $endGetSubscriptions).TotalSeconds) seconds"
}