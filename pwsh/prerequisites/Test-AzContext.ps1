#check AzContext
#Region checkAzContext (FUNCTION)
$checkContext = Get-AzContext -ErrorAction Stop
Write-Host "Checking Az Context"
if (-not $checkContext) {
    Write-Host " Context test failed: No context found. Please connect to Azure (run: Connect-AzAccount) and re-run the script" -ForegroundColor Red
    Throw "Error - check the last console output for details"
}
else {
    $accountType = $checkContext.Account.Type
    $accountId = $checkContext.Account.Id
    Write-Host " Context AccountId: '$($accountId)'" -ForegroundColor Yellow
    Write-Host " Context AccountType: '$($accountType)'" -ForegroundColor Yellow

    if ($SubscriptionId4AzContext -ne "undefined") {
        if ($checkContext.Subscription.Id -ne $SubscriptionId4AzContext) {
            Write-Host " Setting AzContext to SubscriptionId: '$SubscriptionId4AzContext'" -ForegroundColor Yellow
            try {
                $null = Set-AzContext -SubscriptionId $SubscriptionId4AzContext -ErrorAction Stop
            }
            catch {
                Throw "Error - check the last console output for details"
            }
            $checkContext = Get-AzContext -ErrorAction Stop
            Write-Host " AzContext: $($checkContext.Subscription.Name) ($($checkContext.Subscription.Id))" -ForegroundColor Green
        }
        else {
            Write-Host " AzContext: $($checkContext.Subscription.Name) ($($checkContext.Subscription.Id))" -ForegroundColor Green
        }
    }

    if (-not $checkContext.Subscription) {
        $checkContext
        Write-Host " Context test failed: Context is not set to any Subscription. Set your context to a subscription by running: Set-AzContext -subscription <subscriptionId> (run Get-AzSubscription to get the list of available Subscriptions). When done re-run the script" -ForegroundColor Red
        Throw "Error - check the last console output for details"
    }
    else {
        Write-Host " Context test passed: Context OK" -ForegroundColor Green
    }
}
#EndRegion checkAzContext