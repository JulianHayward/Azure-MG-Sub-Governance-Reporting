# Optional Publishing the Azure Governance Visualizer HTML to a Azure Web App

There are instances where you may want to publish the HTML output to a webapp so that anybody in the business can see up to date status of the Azure governance.

You can either setup the azure Web App [manually](#manual-setup) or deploy [code based](#code-based-setup) using the Azure Governance Visualizer accelerator.

## Manual setup

### Prerequisites 
* Deploy a simple webapp on Azure. This can be the smallest SKU or a FREE SKU. It doesn't matter whether you choose Windows or Linux as the platform  
![alt text](../img/webapp_create.png "Azure Web App Create")
* Step through the configuration. I typically use the Code for the publish and then select the Runtime stack that you standardize on 
![alt text](../img/webapp_configure.png "Azure Web App Configure")
* No need to configure anything, unless your organization policies require you to do so  
NOTE: it is a good practice to tag your resource for operational and finance reasons
* In the webapp _Configuration_ add the name of the HTML output file to the _Default Documents_  
![alt text](../img/webapp_defaultdocs.png "Azure Web App Default documents")
* Make sure to configure Authentication!  
![alt text](../img/webapp_authentication.png "Azure Web App Authentication")

### Azure DevOps

* Assign the Azure DevOps Service Connection´s Service Principal with RBAC Role __Website Contributor__ on the Azure Web App
* Edit the `.azuredevops/AzGovViz.variables.yml` file  
![alt text](../img/webapp_AzDO_yml.png "Azure DevOps YAML variables")

### GitHub Actions

* Assign the Service Principal used in GitHub with RBAC Role __Website Contributor__ on the Azure Web App
* Edit the `.github/workflows/AzGovViz_OIDC.yml` or `.github/workflows/AzGovViz.yml` file  
![alt text](../img/webapp_GitHub_yml.png "GitHub YAML variables")

## Code based setup
Use the [Azure Governance Visualizer accelerator](https://github.com/Azure/Azure-Governance-Visualizer-Accelerator) to deploy the Azure Web App per code.