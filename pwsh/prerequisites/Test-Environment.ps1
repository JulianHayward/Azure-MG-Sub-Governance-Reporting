#Region Test-Environment
($htAzureEnvironmentRelatedUrls) = @{ }
($htAzureEnvironmentRelatedUrls).ARM = $checkContext.Environment.ResourceManagerUrl
($htAzureEnvironmentRelatedUrls).KeyVault = $checkContext.Environment.AzureKeyVaultServiceEndpointResourceId
($htAzureEnvironmentRelatedUrls).LogAnalytics = $checkContext.Environment.AzureOperationalInsightsEndpointResourceId
($htAzureEnvironmentRelatedUrls).MicrosoftGraph = $checkContext.Environment.ExtendedProperties.MicrosoftGraphUrl

($htAzureEnvironmentRelatedTargetEndpoints) = @{ }
($htAzureEnvironmentRelatedTargetEndpoints).((($checkContext.Environment.ResourceManagerUrl) -split "/")[2]) = 'ARM'
($htAzureEnvironmentRelatedTargetEndpoints).((($checkContext.Environment.AzureKeyVaultServiceEndpointResourceId) -split "/")[2]) = 'KeyVault'
($htAzureEnvironmentRelatedTargetEndpoints).((($checkContext.Environment.AzureOperationalInsightsEndpointResourceId) -split "/")[2]) = 'LogAnalytics'
($htAzureEnvironmentRelatedTargetEndpoints).((($checkContext.Environment.ExtendedProperties.MicrosoftGraphUrl) -split "/")[2]) = 'MicrosoftGraph'
#EndRegion Test-Environment
