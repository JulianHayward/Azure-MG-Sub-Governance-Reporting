function initAzAPICall {

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $False)][switch]$DebugAzAPICall,
        [Parameter(Mandatory = $False)][string]$SubscriptionId4AzContext,
        [Parameter(Mandatory = $False)][switch]$NoPsParallelization,
        [Parameter(Mandatory = $False)][string]$GithubRepository
    )

    $AzAPICallConfiguration = @{

    }
    $AzAPICallConfiguration['htParameters'] = $null
    $AzAPICallConfiguration['htParameters'] = setHtParameters
    Write-Host '  AzAPICall htParameters:'
    Write-Host ($AzAPICallConfiguration['htParameters'] | format-table -AutoSize | Out-String)
    Write-Host '  Create htParameters succeeded' -ForegroundColor Green

    $AzAPICallConfiguration['arrayAPICallTracking'] = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $AzAPICallConfiguration['htBearerAccessToken'] = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))

    if ($NoPsParallelization) {
        Write-Host ' PowerShell parallelization: false' -ForegroundColor Yellow
        # $AzAPICallConfiguration['arrayAPICallTracking'] = [System.Collections.ArrayList]@()
    }
    else {
        Write-Host ' PowerShell parallelization: true' -ForegroundColor Yellow
        # $AzAPICallConfiguration['funcAzAPICall'] = $function:AzAPICall.ToString()
        # $AzAPICallConfiguration['funcCreateBearerToken'] = $function:createBearerToken.ToString()
        # $AzAPICallConfiguration['funcGetJWTDetails'] = $function:getJWTDetails.ToString()

        testPowerShellVersion
    }

    testAzModules

    Write-Host ' Get Az context'
    try {
        $AzAPICallConfiguration['checkContext'] = Get-AzContext -ErrorAction Stop
        # $checkContext = Get-AzContext -ErrorAction Stop
    }
    catch {
        $_
        Write-Host '  Get Az context failed'
        Throw 'Error - check the last console output for details'
    }
    if (-not $AzAPICallConfiguration['checkContext']) {
        Write-Host '  Get Az context failed: No context found. Please connect to Azure (run: Connect-AzAccount -tenantId <tenantId>) and re-run the script'
        Throw 'Error - check the last console output for details'
    }
    Write-Host '  Get Az context succeeded' -ForegroundColor Green

    $AzAPICallConfiguration = setAzureEnvironment -AzAPICallConfiguration $AzAPICallConfiguration

    Write-Host ' Check Az context'
    $AzAPICallConfiguration['accountType'] = $AzAPICallConfiguration['checkContext'].Account.Type
    $AzAPICallConfiguration['accountId'] = $AzAPICallConfiguration['checkContext'].Account.Id
    Write-Host "  Az context AccountId: '$($AzAPICallConfiguration['accountId'] )'" -ForegroundColor Yellow
    Write-Host "  Az context AccountType: '$($AzAPICallConfiguration['accountType'])'" -ForegroundColor Yellow

    Write-Host "  Parameter -SubscriptionId4AzContext: '$SubscriptionId4AzContext'"
    if ($SubscriptionId4AzContext -ne 'undefined') {
        if ($AzAPICallConfiguration['checkContext'].Subscription.Id -ne $SubscriptionId4AzContext) {

            testSubscription -SubscriptionId4Test $SubscriptionId4AzContext -AzAPICallConfiguration $AzAPICallConfiguration

            Write-Host "  Setting Az context to SubscriptionId: '$SubscriptionId4AzContext'"
            try {
                # $AzAPICallConfiguration['checkContext'].Subscription = $SubscriptionId4AzContext
                $null = Set-AzContext -SubscriptionId $SubscriptionId4AzContext -ErrorAction Stop
            }
            catch {
                Write-Host $_
                Throw 'Error - check the last console output for details'
            }
            $AzAPICallConfiguration['checkContext'] = Get-AzContext -ErrorAction Stop
            Write-Host "  New Az context: $($AzAPICallConfiguration['checkContext'].Subscription.Name) ($($AzAPICallConfiguration['checkContext'].Subscription.Id))"
        }
        else {
            Write-Host "  Stay with current Az context: $($AzAPICallConfiguration['checkContext'].Subscription.Name) ($($AzAPICallConfiguration['checkContext'].Subscription.Id))"
        }
    }
    else {
        testSubscription -SubscriptionId4Test $AzAPICallConfiguration['checkContext'].Subscription.Id -AzAPICallConfiguration $AzAPICallConfiguration
    }

    if (-not $AzAPICallConfiguration['checkContext'].Subscription) {
        $AzAPICallConfiguration['checkContext']
        Write-Host '  Check Az context failed: Az context is not set to any Subscription'
        Write-Host '  Set Az context to a subscription by running: Set-AzContext -subscription <subscriptionId> (run Get-AzSubscription to get the list of available Subscriptions). When done re-run the script'
        Write-Host '  OR'
        Write-Host '  Use parameter -SubscriptionId4Test - e.g. .\AzGovVizParallel.ps1 -SubscriptionId4Test <subscriptionId>'
        Throw 'Error - check the last console output for details'
    }
    else {
        Write-Host '  Az context check succeeded' -ForegroundColor Green
    }

    $AzAPICallConfiguration['UserType'] = testUserType

    Write-Output $AzAPICallConfiguration
}
