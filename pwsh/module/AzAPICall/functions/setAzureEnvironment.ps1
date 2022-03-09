function setAzureEnvironment {
    param(
        [Parameter(Mandatory = $True)]
        [object]
        $AzAPICallConfiguration
    )
    #Region Test-Environment
    Write-Host ' Set environment endPoint url mapping'

    function testAvailable {
        [CmdletBinding()]Param(
            [string]$EndpointUrl,
            [string]$Endpoint,
            [string]$EnvironmentKey
        )
        Write-Host "  Check endpoint: '$($Endpoint)'; endpoint url: '$($EndpointUrl)'"
        if ([string]::IsNullOrWhiteSpace($EndpointUrl)) {
            if ($Endpoint -eq 'MicrosoftGraph') {
                Write-Host "  Older Az.Accounts version in use (`$AzApiCallConfiguration.checkContext.Environment.$($EnvironmentKey) not existing). AzureEnvironmentRelatedUrls -> Setting static Microsoft Graph Url 'https://graph.microsoft.com'"
                return 'https://graph.microsoft.com'
            }
            else {
                Write-Host "  Cannot read '$($Endpoint)' endpoint from current context (`$AzApiCallConfiguration.checkContext.Environment.$($EnvironmentKey))"
                Write-Host "  Please check current context (Subglobalion criteria: quotaId notLike 'AAD*'; state = enabled); Install latest Az.Accounts version"
                Write-Host ($checkContext | Format-List | Out-String)
                Throw 'Error - check the last console output for details'
            }
        }
        else {
            return ($EndpointUrl -replace '\/$')
        }
    }

    #AzureEnvironmentRelatedUrls
    $AzAPICallConfiguration['htAzureEnvironmentRelatedUrls'] = @{ }
    $AzAPICallConfiguration['htAzureEnvironmentRelatedUrls'].ARM = (testAvailable -Endpoint 'ARM' -EnvironmentKey 'ResourceManagerUrl' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.ResourceManagerUrl)
    $AzAPICallConfiguration['htAzureEnvironmentRelatedUrls'].KeyVault = (testAvailable -Endpoint 'KeyVault' -EnvironmentKey 'AzureKeyVaultServiceEndpointResourceId' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.AzureKeyVaultServiceEndpointResourceId)
    $AzAPICallConfiguration['htAzureEnvironmentRelatedUrls'].LogAnalytics = (testAvailable -Endpoint 'LogAnalytics' -EnvironmentKey 'AzureOperationalInsightsEndpointResourceId' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.AzureOperationalInsightsEndpointResourceId)
    $AzAPICallConfiguration['htAzureEnvironmentRelatedUrls'].MicrosoftGraph = (testAvailable -Endpoint 'MicrosoftGraph' -EnvironmentKey 'ExtendedProperties.MicrosoftGraphUrl' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.ExtendedProperties.MicrosoftGraphUrl)

    #AzureEnvironmentRelatedTargetEndpoints
    $AzAPICallConfiguration['htAzureEnvironmentRelatedTargetEndpoints'] = @{ }
    $AzAPICallConfiguration['htAzureEnvironmentRelatedTargetEndpoints'].(($AzApiCallConfiguration['htAzureEnvironmentRelatedUrls'].ARM -split '/')[2]) = 'ARM'
    $AzAPICallConfiguration['htAzureEnvironmentRelatedTargetEndpoints'].(($AzApiCallConfiguration['htAzureEnvironmentRelatedUrls'].KeyVault -split '/')[2]) = 'KeyVault'
    $AzAPICallConfiguration['htAzureEnvironmentRelatedTargetEndpoints'].(($AzApiCallConfiguration['htAzureEnvironmentRelatedUrls'].LogAnalytics -split '/')[2]) = 'LogAnalytics'
    $AzAPICallConfiguration['htAzureEnvironmentRelatedTargetEndpoints'].(($AzApiCallConfiguration['htAzureEnvironmentRelatedUrls'].MicrosoftGraph -split '/')[2]) = 'MicrosoftGraph'

    Write-Host '  Set environment endPoint url mapping succeeded' -ForegroundColor Green
    Write-Output $AzApiCallConfiguration
}