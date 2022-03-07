function initAzAPICall {

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $False)][switch]$DebugAzAPICall,
        [Parameter(Mandatory = $False)][string]$SubscriptionId4AzContext,
        [Parameter(Mandatory = $False)][switch]$NoPsParallelization,
        [Parameter(Mandatory = $False)][string]$GithubRepository
    )

    $global:htParameters = $null
    $global:htParameters = setHtParameters
    Write-Host '  AzAPICall htParameters:'
    $htParameters | format-table -AutoSize
    Write-Host '  Create htParameters succeeded' -ForegroundColor Green

    if ($NoPsParallelization) {
        Write-Host ' PowerShell parallelization: false' -ForegroundColor Yellow
        $global:arrayAPICallTracking = [System.Collections.ArrayList]@()
        $global:htBearerAccessToken = @{}
    }
    else {
        Write-Host ' PowerShell parallelization: true' -ForegroundColor Yellow
        $global:funcAzAPICall = $function:AzAPICall.ToString()
        $global:funcCreateBearerToken = $function:createBearerToken.ToString()
        $global:funcGetJWTDetails = $function:getJWTDetails.ToString()

        $global:arrayAPICallTracking = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        $global:htBearerAccessToken = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))

        testPowerShellVersion
    }

    testAzModules

    Write-Host ' Get Az context'
    try {
        $global:checkContext = Get-AzContext -ErrorAction Stop
    }
    catch {
        $_
        Write-Host '  Get Az context failed'
        Throw 'Error - check the last console output for details'
    }
    if (-not $checkContext) {
        Write-Host '  Get Az context failed: No context found. Please connect to Azure (run: Connect-AzAccount -tenantId <tenantId>) and re-run the script'
        Throw 'Error - check the last console output for details'
    }
    Write-Host '  Get Az context succeeded' -ForegroundColor Green

    setAzureEnvironment

    Write-Host ' Check Az context'
    $global:accountType = $checkContext.Account.Type
    $global:accountId = $checkContext.Account.Id
    Write-Host "  Az context AccountId: '$($accountId)'" -ForegroundColor Yellow
    Write-Host "  Az context AccountType: '$($accountType)'" -ForegroundColor Yellow

    Write-Host "  Parameter -SubscriptionId4AzContext: '$SubscriptionId4AzContext'"
    if ($SubscriptionId4AzContext -ne 'undefined') {
        if ($checkContext.Subscription.Id -ne $SubscriptionId4AzContext) {

            testSubscription -SubscriptionId4Test $SubscriptionId4AzContext

            Write-Host "  Setting Az context to SubscriptionId: '$SubscriptionId4AzContext'"
            try {
                $null = Set-AzContext -SubscriptionId $SubscriptionId4AzContext -ErrorAction Stop
            }
            catch {
                Write-Host $_
                Throw 'Error - check the last console output for details'
            }
            $global:checkContext = Get-AzContext -ErrorAction Stop
            Write-Host "  New Az context: $($checkContext.Subscription.Name) ($($checkContext.Subscription.Id))"
        }
        else {
            Write-Host "  Stay with current Az context: $($checkContext.Subscription.Name) ($($checkContext.Subscription.Id))"
        }
    }
    else {
        testSubscription -SubscriptionId4Test $checkContext.Subscription.Id
    }

    if (-not $checkContext.Subscription) {
        $checkContext
        Write-Host '  Check Az context failed: Az context is not set to any Subscription'
        Write-Host '  Set Az context to a subscription by running: Set-AzContext -subscription <subscriptionId> (run Get-AzSubscription to get the list of available Subscriptions). When done re-run the script'
        Write-Host '  OR'
        Write-Host '  Use parameter -SubscriptionId4Test - e.g. .\AzGovVizParallel.ps1 -SubscriptionId4Test <subscriptionId>'
        Throw 'Error - check the last console output for details'
    }
    else {
        Write-Host '  Az context check succeeded' -ForegroundColor Green
    }

    testUserType
}
