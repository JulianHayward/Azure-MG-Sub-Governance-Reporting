function setAzureEnvironment {
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
                Write-Host "  Older Az.Accounts version in use (`$checkContext.Environment.$($EnvironmentKey) not existing). AzureEnvironmentRelatedUrls -> Setting static Microsoft Graph Url 'https://graph.microsoft.com'"
                return 'https://graph.microsoft.com'
            }
            else {
                Write-Host "  Cannot read '$($Endpoint)' endpoint from current context (`$checkContext.Environment.$($EnvironmentKey))"
                Write-Host "  Please check current context (Subglobalion criteria: quotaId notLike 'AAD*'; state = enabled); Install latest Az.Accounts version"
                $checkContext | Format-List
                Throw 'Error - check the last console output for details'
            }
        }
        else {
            return ($EndpointUrl -replace '\/$')
        }
    }

    #AzureEnvironmentRelatedUrls
    $global:htAzureEnvironmentRelatedUrls = @{ }
    $global:htAzureEnvironmentRelatedUrls.ARM = (testAvailable -Endpoint 'ARM' -EnvironmentKey 'ResourceManagerUrl' -EndpointUrl $checkContext.Environment.ResourceManagerUrl)
    $global:htAzureEnvironmentRelatedUrls.KeyVault = (testAvailable -Endpoint 'KeyVault' -EnvironmentKey 'AzureKeyVaultServiceEndpointResourceId' -EndpointUrl $checkContext.Environment.AzureKeyVaultServiceEndpointResourceId)
    $global:htAzureEnvironmentRelatedUrls.LogAnalytics = (testAvailable -Endpoint 'LogAnalytics' -EnvironmentKey 'AzureOperationalInsightsEndpointResourceId' -EndpointUrl $checkContext.Environment.AzureOperationalInsightsEndpointResourceId)
    $global:htAzureEnvironmentRelatedUrls.MicrosoftGraph = (testAvailable -Endpoint 'MicrosoftGraph' -EnvironmentKey 'ExtendedProperties.MicrosoftGraphUrl' -EndpointUrl $checkContext.Environment.ExtendedProperties.MicrosoftGraphUrl)

    #AzureEnvironmentRelatedTargetEndpoints
    $global:htAzureEnvironmentRelatedTargetEndpoints = @{ }
    $global:htAzureEnvironmentRelatedTargetEndpoints.(($htAzureEnvironmentRelatedUrls.ARM -split '/')[2]) = 'ARM'
    $global:htAzureEnvironmentRelatedTargetEndpoints.(($htAzureEnvironmentRelatedUrls.KeyVault -split '/')[2]) = 'KeyVault'
    $global:htAzureEnvironmentRelatedTargetEndpoints.(($htAzureEnvironmentRelatedUrls.LogAnalytics -split '/')[2]) = 'LogAnalytics'
    $global:htAzureEnvironmentRelatedTargetEndpoints.(($htAzureEnvironmentRelatedUrls.MicrosoftGraph -split '/')[2]) = 'MicrosoftGraph'

    Write-Host '  Set environment endPoint url mapping succeeded' -ForegroundColor Green
}