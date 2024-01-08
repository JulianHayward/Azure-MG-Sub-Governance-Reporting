
# Configure and run Azure Governance Visualizer from GitHub

Also, most steps have both **portal based** ( :computer_mouse: ) and **PowerShell based** ( :keyboard: ) instructions. Use whichever you feel is appropriate for your situation, they both will produce the same results.

## Create GitHub repository

Create a 'private' repository

## Import Code

Click on 'Import code'

Use '<https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting.git>' as clone URL

Click on 'Begin import'

Navigate to your newly created repository
In the folder `./github/workflows` two worklows are available:

1. [AzGovViz.yml](#azgovviz-yaml)
Use this workflow if you want to store your Application (App registration) secret in GitHub

2. [AzGovViz_OIDC.yml](#azgovviz-oidc-yaml)
Use this workflow if you want leverage the [OIDC (Open ID Connect) feature](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-azure) - no secret stored in GitHub

## Azure Governance Visualizer YAML

For the GitHub Actiom to authenticate and connect to Azure we need to create Service Principal (Application)

In the Azure Portal navigate to 'Microsoft Entra ID (AAD)'

* Click on '**App registrations**'
* Click on '**New registration**'
* Name your application (e.g. 'AzureGovernanceVisualizer_SC')
* Click '**Register**'
* Your App registration has been created, in the '**Overview**' copy the '**Application (client) ID**' as we will need it later to setup the secrets in GitHub
* Under '**Manage**' click on '**Certificates & Secrets**'
* Click on '**New client secret**'
* Provide a good description and choose the expiry time based on your need and click '**Add**'
* A new client secret has been created, copy the secret´s value as we will need it later to setup the secrets in GitHub

### Store the credentials in GitHub (Azure Governance Visualizer YAML)

In GitHub navigate to 'Settings'

* Click on 'Secrets'
* Click on 'Actions'
* Click 'New repository secret'
  * Name: CREDS
  * Value:  

```
{
   "tenantId": "<GUID>",
   "subscriptionId": "<GUID>",
   "clientId": "<GUID>",
   "clientSecret": "<GUID>"
}
```

### Workflow permissions

In GitHub navigate to 'Settings'  

* Click on 'Actions'  
* Click on 'General'  
* Under 'Workflow permissions' select '**Read and write permissions**'  
* Click 'Save'

### Edit the workflow YAML file (Azure Governance Visualizer YAML)

* In the folder `./github/workflows` edit the YAML file `AzGovViz.yml`
* In the `env` section enter you Management Group ID
* If you want to continuously run Azure Governance Visualizer then enable the `schedule` in the `on` section

### Run Azure Governance Visualizer in GitHub Actions (Azure Governance Visualizer YAML)

In GitHub navigate to 'Actions'

* Click 'Enable GitHub Actions on this repository'
* Select the Azure Governance Visualizer workflow
* Click 'Run workflow'

## Azure Governance Visualizer OIDC YAML

For the GitHub Actiom to authenticate and connect to Azure we need to create Service Principal (Application). Using OIDC we will not have the requirement to create a secret, nore store it in GitHub - awesome :)

* Navigate to 'Microsoft Entra ID (AAD)'
* Click on '**App registrations**'
* Click on '**New registration**'
* Name your application (e.g. 'AzureGovernanceVisualizer_SC')
* Click '**Register**'
* Your App registration has been created, in the '**Overview**' copy the '**Application (client) ID**' as we will need it later to setup the secrets in GitHub
* Under '**Manage**' click on '**Certificates & Secrets**'
* Click on '**Federated credentials**'
* Click 'Add credential'
* Select Federation credential scenario 'GitHub Actions deploying Azure Resources'
* Fill the field 'Organization' with your GitHub Organization name
* Fill the field 'Repository' with your GitHub repository name
* For the entity type select 'Branch'
* Fill the field 'GitHub branch name' with your branch name (default is 'master' if you imported the Azure Governance Visualizer repository)
* Fill the field 'Name' with a name (e.g. AzureGovernanceVisualizer_GitHub_Actions)
* Click 'Add'

### Store the credentials in GitHub (Azure Governance Visualizer OIDC YAML)

In GitHub navigate to 'Settings'

* Click on 'Secrets'  
* Click on 'Actions'  
* Click 'New repository secret'  
* Create the following three secrets:  
  * Name: CLIENT_ID  
      Value: `Application (client) ID`  
  * Name: TENANT_ID  
      Value: `Tenant ID`  
  * Name: SUBSCRIPTION_ID  
      Value: `Subscription ID`  

### Workflow permissions

In GitHub navigate to 'Settings'  

* Click on 'Actions'  
* Click on 'General'  
* Under 'Workflow permissions' select '**Read and write permissions**'  
* Click 'Save'

### Edit the workflow YAML file (Azure Governance Visualizer OIDC YAML)

* In the folder `./github/workflows` edit the YAML file `AzGovViz_OIDC.yml`
* In the `env` section enter you Management Group ID
* If you want to continuously run Azure Governance Visualizer then enable the `schedule` in the `on` section

### Run Azure Governance Visualizer in GitHub Actions (Azure Governance Visualizer OIDC YAML)

In GitHub navigate to 'Actions'

* Click 'Enable GitHub Actions on this repository'
* Select the AzGovViz_OIDC workflow
* Click 'Run workflow'

# Azure Governance Visualizer GitHub Codespaces

Note: Codespaces is available for organizations using GitHub Team or GitHub Enterprise Cloud. [Quickstart for Codespaces](https://docs.github.com/en/codespaces/getting-started/quickstart)

![alt text](img/codespaces0.png "Azure Governance Visualizer GitHub Codespaces")

![alt text](img/codespaces1.png "Azure Governance Visualizer GitHub Codespaces")

![alt text](img/codespaces2.png "Azure Governance Visualizer GitHub Codespaces")

![alt text](img/codespaces3.png "Azure Governance Visualizer GitHub Codespaces")

![alt text](img/codespaces4.png "Azure Governance Visualizer GitHub Codespaces")

## Optional Publishing the Azure Governance Visualizer HTML to a Azure Web App

There are instances where you may want to publish the HTML output to a webapp so that anybody in the business can see up to date status of the Azure governance.

There are a few models to do this, the option below is one way to get you started.

### Prerequisites

* Deploy a simple webapp on Azure. This can be the smallest SKU or a FREE SKU. It doesn't matter whether you choose Windows or Linux as the platform  
![alt text](img/webapp_create.png "Web App Create")
* Step through the configuration. I typically use the Code for the publish and then select the Runtime stack that you standardize on
![alt text](img/webapp_configure.png "Web App Configure")
* No need to configure anything, unless your organization policies require you to do so  
NOTE: it is a good practice to tag your resource for operational and finance reasons
* In the webapp _Configuration_ add the name of the HTML output file to the _Default Documents_  
![alt text](img/webapp_defaultdocs.png "Web App Default documents")
* Make sure to configure Authentication!  
![alt text](img/webapp_authentication.png "Web App Authentication")

### Configure

* Assign the Service Principal used in GitHub with RBAC Role **Website Contributor** on the Azure Web App
* Edit the `.github/workflows/AzGovViz_OIDC.yml` or `.github/workflows/AzGovViz.yml` file  
![alt text](img/webapp_GitHub_yml.png "GitHub YAML variables")
