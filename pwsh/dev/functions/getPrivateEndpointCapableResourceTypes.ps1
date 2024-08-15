function getPrivateEndpointCapableResourceTypes {
    $startGetAvailablePrivateEndpointTypes = Get-Date
    $privateEndpointAvailabilityCheckCompleted = $false
    $subsToProcessForGettingPrivateEndpointTypes = [System.Collections.ArrayList]@()
    $prioCounter = 0
    foreach ($subscription in $subsToProcessInCustomDataCollection) {
        $prioCounter++
        if ($subscription.subscriptionId -eq $azAPICallConf['checkcontext'].Subscription.Id) {
            $null = $subsToProcessForGettingPrivateEndpointTypes.Add([PSCustomObject]@{
                    subscriptionInfo = $subscription
                    prio             = 0
                })
        }
        else {
            $null = $subsToProcessForGettingPrivateEndpointTypes.Add([PSCustomObject]@{
                    subscriptionInfo = $subscription
                    prio             = $prioCounter
                })
        }
    }

    foreach ($subscription in $subsToProcessForGettingPrivateEndpointTypes | Sort-Object -Property prio) {

        if ($privateEndpointAvailabilityCheckCompleted) {
            continue
        }

        $subscriptionId = $subscription.subscriptionInfo.subscriptionId
        $subscriptionName = $subscription.subscriptionInfo.subscriptionName

        $armLocationsFromAzAPICall = $azAPICallConf['htParameters'].ARMLocations

        Write-Host "Getting 'Available Private Endpoint Types' for Subscription '$($subscriptionName)' ($($subscriptionId)) for $($armLocationsFromAzAPICall.Count) physical locations"

        $batchSize = [math]::ceiling($armLocationsFromAzAPICall.Count / $ThrottleLimit)
        Write-Host "Optimal batch size: $($batchSize)"
        $counterBatch = [PSCustomObject] @{ Value = 0 }
        $locationsBatch = ($armLocationsFromAzAPICall) | Group-Object -Property { [math]::Floor($counterBatch.Value++ / $batchSize) }
        Write-Host "Processing data in $($locationsBatch.Count) batches"

        $locationsBatch | ForEach-Object -Parallel {

            $subscriptionId = $using:subscriptionId
            $azAPICallConf = $using:azAPICallConf
            $htAvailablePrivateEndpointTypes = $using:htAvailablePrivateEndpointTypes

            foreach ($location in $_.Group) {
                $currentTask = "Getting 'Available Private Endpoint Types' for location $($location)"
                #Write-Host $currentTask
                $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($subscriptionId)/providers/Microsoft.Network/locations/$($location)/availablePrivateEndpointTypes?api-version=2022-07-01"
                $method = 'GET'
                $availablePrivateEndpointTypes = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -skipOnErrorCode 400, 409
                Write-Host " Returned $($availablePrivateEndpointTypes.Count) 'Available Private Endpoint Types' for location $($location)"
                foreach ($availablePrivateEndpointType in $availablePrivateEndpointTypes) {
                    if (-not $htAvailablePrivateEndpointTypes.(($availablePrivateEndpointType.resourceName).ToLower())) {
                        $script:htAvailablePrivateEndpointTypes.(($availablePrivateEndpointType.resourceName).ToLower()) = @{}
                    }
                }
            }
        } -ThrottleLimit $ThrottleLimit

        if ($htAvailablePrivateEndpointTypes.Keys.Count -gt 0) {
            #Write-Host " Created ht for $($htAvailablePrivateEndpointTypes.Keys.Count) 'Available Private Endpoint Types'"
            $privateEndpointAvailabilityCheckCompleted = $true
        }
        else {
            Write-Host " $($htAvailablePrivateEndpointTypes.Keys.Count) 'Available Private Endpoint Types' - likely the Resource Provider 'Microsoft.Network' is not registered - trying next available subscription"
            $privateEndpointAvailabilityCheckCompleted = $false
        }
    }

    if ($htAvailablePrivateEndpointTypes.Keys.Count -gt 0) {
        Write-Host " Created ht for $($htAvailablePrivateEndpointTypes.Keys.Count) 'Available Private Endpoint Types'"
    }
    else {
        $throwmsg = "$($htAvailablePrivateEndpointTypes.Keys.Count) 'Available Private Endpoint Types' - Checked for $($subsToProcessForGettingPrivateEndpointTypes.Count) Subscriptions with no success. Make sure that for at least one Subscription the Resource Provider 'Microsoft.Network' is registered. Once you registered the Resource Provider for Subscription 'subscriptionEnabled' it may be a good idea to use the parameter: -SubscriptionId4AzContext '<subscriptionId of subscriptionEnabled>'"
        Write-Host $throwmsg -ForegroundColor DarkRed
        Throw $throwmsg
    }

    $endGetAvailablePrivateEndpointTypes = Get-Date
    Write-Host "Getting 'Available Private Endpoint Types' duration: $((New-TimeSpan -Start $startGetAvailablePrivateEndpointTypes -End $endGetAvailablePrivateEndpointTypes).TotalMinutes) minutes ($((New-TimeSpan -Start $startGetAvailablePrivateEndpointTypes -End $endGetAvailablePrivateEndpointTypes).TotalSeconds) seconds)"
    #endregion Getting Available Private Endpoint Types
}