#Region Test-Environment
($htAzureEnvironmentRelatedUrls) = @{ }
($htAzureEnvironmentRelatedUrls).ARM = $checkContext.Environment.ResourceManagerUrl
($htAzureEnvironmentRelatedUrls).KeyVault = $checkContext.Environment.AzureKeyVaultServiceEndpointResourceId
($htAzureEnvironmentRelatedUrls).LogAnalytics = $checkContext.Environment.AzureOperationalInsightsEndpointResourceId
if ([string]::IsNullOrEmpty($checkContext.Environment.ExtendedProperties.MicrosoftGraphUrl)) {
    Write-Host "Older Az.Accounts version. AzureEnvironmentRelatedUrls -> Setting static Microsoft Graph Url 'https://graph.microsoft.com'"
    ($htAzureEnvironmentRelatedUrls).MicrosoftGraph = "https://graph.microsoft.com"
}
else { 
    ($htAzureEnvironmentRelatedUrls).MicrosoftGraph = $checkContext.Environment.ExtendedProperties.MicrosoftGraphUrl 
}

($htAzureEnvironmentRelatedTargetEndpoints) = @{ }
($htAzureEnvironmentRelatedTargetEndpoints).((($checkContext.Environment.ResourceManagerUrl) -split "/")[2]) = 'ARM'
($htAzureEnvironmentRelatedTargetEndpoints).((($checkContext.Environment.AzureKeyVaultServiceEndpointResourceId) -split "/")[2]) = 'KeyVault'
($htAzureEnvironmentRelatedTargetEndpoints).((($checkContext.Environment.AzureOperationalInsightsEndpointResourceId) -split "/")[2]) = 'LogAnalytics'

if ([string]::Isnullorempty($checkContext.Environment.ExtendedProperties.MicrosoftGraphUrl)) {
    Write-Host "Older Az.Accounts version. AzureEnvironmentRelatedTargetEndpoints -> Setting static Microsoft Graph Url identifier 'graph.microsoft.com'"
    ($htAzureEnvironmentRelatedTargetEndpoints).'graph.microsoft.com' = 'MicrosoftGraph'
}
else { 
    ($htAzureEnvironmentRelatedTargetEndpoints).((($checkContext.Environment.ExtendedProperties.MicrosoftGraphUrl) -split "/")[2]) = 'MicrosoftGraph'
}
#EndRegion Test-Environment