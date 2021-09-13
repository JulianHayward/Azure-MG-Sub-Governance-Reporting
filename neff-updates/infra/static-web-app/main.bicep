param repositoryUrl string = <repository URL>
param repositoryBranch string = 'main'

param location string = '<location>'
param skuName string = '<skuName>'
param skuTier string = '<sku tier>'

param appName string = '<app Name>'

resource staticWebApp 'Microsoft.Web/staticSites@2020-12-01' = {
  name: 'name of site>'
  location: location
  sku: {
    name: skuName
    tier: skuTier
  }
  properties: {
    provider: 'DevOps'
    repositoryUrl: repositoryUrl
    branch: repositoryBranch
    buildProperties: {
      skipGithubActionWorkflowGeneration: true
    }
  }
}

output deployment_token string = listSecrets(staticWebApp.id, staticWebApp.apiVersion).properties.apiKey 
