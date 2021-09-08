param repositoryUrl string = 'https://dev.azure.com/shaneneff0440/MS-AzGovViz/_git'
param repositoryBranch string = 'main'

param location string = 'eastus2'
param skuName string = 'Free'
param skuTier string = 'Free'

param appName string = 'shanetest3'

resource staticWebApp 'Microsoft.Web/staticSites@2020-12-01' = {
  name: 'shanestest3'
  location: location
  sku: {
    name: skuName
    tier: skuTier
  }
  properties: {
    provider: 'DevOps'
    repositoryUrl: 'https://dev.azure.com/shaneneff0440/MS-AzGovViz/_git'
    branch: 'main'
    buildProperties: {
      skipGithubActionWorkflowGeneration: true
    }
  }
}

output deployment_token string = listSecrets(staticWebApp.id, staticWebApp.apiVersion).properties.apiKey 
