param repositoryUrl string = '<URL of repository .git>'
param repositoryBranch string = 'main'

param location string = '<location>'
param skuName string = '<sku>'
param skuTier string = '<tier>'

param appName string = '<app name>'

resource staticWebApp 'Microsoft.Web/staticSites@2020-12-01' = {
  name: '<app name'
  location: location
  sku: {
    name: skuName
    tier: skuTier
  }
  properties: {
    provider: 'DevOps'
    repositoryUrl: '<URL of repository .git>'
    branch: 'main'
    buildProperties: {
      skipGithubActionWorkflowGeneration: true
    }
  }
}

output deployment_token string = listSecrets(staticWebApp.id, staticWebApp.apiVersion).properties.apiKey 
