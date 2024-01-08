# Configure and run Azure Governance Visualizer from Azure DevOps

Also, most steps have both **portal based** ( :computer_mouse: ) and **PowerShell based** ( :keyboard: ) instructions. Use whichever you feel is appropriate for your situation, they both will produce the same results.

## Create AzDO Project

[Create a project](https://docs.microsoft.com/en-us/azure/devops/organizations/projects/create-project?view=azure-devops&tabs=preview-page#create-a-project)

## Import Azure Governance Visualizer GitHub repository

Azure Governance Visualizer Clone URL: `https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting.git`

[Import into a new repo](https://docs.microsoft.com/en-us/azure/devops/repos/git/import-git-repository?view=azure-devops#import-into-a-new-repo)

Note: the Azure Governance Visualizer GitHub repository is public - no authorization required

## Create AzDO Service Connection

For the pipeline to authenticate and connect to Azure we need to create an AzDO Service Connection which basically is a Service Principal (Application)
There are two options to create the Service Connection:

* Options
  * **Option 1** Create Service Connection´s Service Principal in the Azure Portal
  * **Option 2** Create Service Connection in AzDO

### Create AzDO Service Connection - Option 1 - Create Service Connections Service Principal in the Azure Portal

#### AzDO supports Open ID Connect - OIDC

Using OIDC we will not have the requirement to create a secret, nore store it in AzDO - awesome :)

Quick guide for an app registration:

**AzDO:**

* Click on '**Project settings**' (located on the bottom left)
* Under '**Pipelines**' click on '**Service Connections**'
* Click on '**New service connection**' and select the connection/service type '**Azure Resource Manager**' and click '**Next**'
* Select Authentication method **Workload Identity federation (manual)**

![alt text](img/azdo_oidc_0.jpg "Microsoft Entra ID (AAD) Federated credentials")

Copy away:

* value of **Issuer**
* value of **Subject identifier**

![alt text](img/azdo_oidc_1.jpg "Microsoft Entra ID (AAD) Federated credentials; issuer, subject identifier")

**Microsoft Entra ID (AAD):**

* In the Azure Portal navigate to 'Microsoft Entra ID (AAD)'
* Click on '**App registrations**'
* Click on '**New registration**'
* Name your application (e.g. 'AzureGovernanceVisualizer_SC')
* Click '**Register**'
* Your App registration has been created
* Under '**Manage**' click on '**Certificates & Secrets**'
* Click on '**Federated credentials**' and '**Add credential**'

![alt text](img/azdo_aad_oidc_0.jpg "Microsoft Entra ID (AAD) Federated credentials")

Paste the just copied off

* value for **Issuer**
* value for **Subject identifier**

![alt text](img/azdo_aad_oidc_1.jpg "Microsoft Entra ID (AAD) Federated credentials; issuer, subject identifier")

#### Azure Portal

* Navigate to 'Microsoft Entra ID (AAD)'
* Click on '**App registrations**'
* Click on '**New registration**'
* Name your application (e.g. 'AzureGovernanceVisualizer_SC')
* Click '**Register**'
* Your App registration has been created, in the '**Overview**' copy the '**Application (client) ID**' as we will need it later to setup the Service Connection in AzDO
* Under '**Manage**' click on '**Certificates & Secrets**'
* Click on '**New client secret**'
* Provide a good description and choose the expiry time based on your need and click '**Add**'
* A new client secret has been created, copy the secret´s value as we will need it later to setup the Service Connection in AzDO

**Note:** if you do not assign the RBAC 'Reader' role to the Management group at this stage then the '**Verify**' step in [Azure DevOps](#azure-devops) will fail.

* In the portal proceed to '**Management Groups**', select the scope at which Azure Governance Visualizer will run, usually **Tenant Root Group**
* Go to '**Access Control (IAM)**', '**Grant Access**' and '**Add Role Assignment**', select '**Reader**', click '**Next**'
* Now '**Select Member**', this will be the name of the Application you created above (e.g. 'AzureGovernanceVisualizer_SC').
* Select '**Next**', '**Review + Assign**'  

#### Azure DevOps

* Click on '**Project settings**' (located on the bottom left)
* Under '**Pipelines**' click on '**Service Connections**'
* Click on '**New service connection**' and select the connection/service type '**Azure Resource Manager**' and click '**Next**'
* For the authentication method select '**Service principal (manual)**' and click '**Next**'
* For the '**Scope level**' select '**Management Group**'
  * In the field '**Management Group Id**' enter the target Management Group Id
  * In the field '**Management Group Name**' enter the target Management Group Name
* Under '**Authentication**' in the field '**Service Principal Id**' enter the '**Application (client) ID**' that you copied away earlier
* For the '**Credential**' select '**Service principal key**', in the field '**Service principal key**' enter the secret that you copied away earlier
* For '**Tenant ID**' enter your Tenant Id
* Click on '**Verify**'
* Under '**Details**' provide your Service Connection with a name and copy away the name as we will need that later when editing the Pipeline YAML file
* For '**Security**' leave the 'Grant access permissions to all pipelines' option checked (optional)
* Click on '**Verify and save**'

### Create AzDO Service Connection - Option 2 - Create Service Connection in AzDO

* Click on '**Project settings**' (located on the bottom left)
* Under '**Pipelines**' click on '**Service connections**'
* Click on '**New service connection**' and select the connection/service type '**Azure Resource Manager**' and click '**Next**'
* For the authentication method select '**Service principal (automatic)**' and click '**Next**'
* For the '**Scope level**' select '**Management Group**', in the Management Group dropdown select the target Management Group (here the Management Group´s display names will be shown), in the '**Details**' section apply a Service Connection name and optional give it a description and click '**Save**'
* A new window will open, authenticate with your administrative account
* Now the Service Connection has been created

**Important!** In Azure on the target Management Group scope an '**Owner**' RBAC Role assignment for the Service Connection´s Service Principal has been created automatically (we do however only require a '**Reader**' RBAC Role assignment! we will take corrective action in the next steps)

## Grant permissions in Azure

* Requirements
  * To assign roles, you must have '**Microsoft.Authorization/roleAssignments/write**' permissions on the target Management Group scope (such as the built-in RBAC Role '**User Access Administrator**' or '**Owner**')

Create a '**Reader**' RBAC Role assignment on the target Management Group scope for the AzDO Service Connection´s Service Principal

* PowerShell

```powershell
$objectId = "<objectId of the AzDO Service Connection´s Service Principal>"
$role = "Reader"
$managementGroupId = "<managementGroupId>"

New-AzRoleAssignment `
-ObjectId $objectId `
-RoleDefinitionName $role `
-Scope /providers/Microsoft.Management/managementGroups/$managementGroupId
```

* Azure Portal
[Assign Azure roles using the Azure portal](https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal)

**Important!** If you have created the AzDO Service Connection in AzDO (Option 2) then you SHOULD remove the automatically created '**Owner**' RBAC Role assignment for the AzDO Service Connection´s Service Principal from the target Management Group

## Grant permissions in Microsoft Entra ID

### API permissions

* Requirements
  * To grant API permissions and grant admin consent for the directory, you must have '**Privileged Role Administrator**' or '**Global Administrator**' role assigned ([Assign Azure AD roles to users](https://docs.microsoft.com/en-us/azure/active-directory/roles/manage-roles-portal))

Grant API permissions for the Service Principal´s Application that we created earlier

* Navigate to 'Microsoft Entra ID (AAD)'
* Click on '**App registrations**'
* Search for the Application that we created earlier and click on it
* Under '**Manage**' click on '**API permissions**'
  * Click on '**Add a permissions**'
  * Click on '**Microsoft Graph**'
  * Click on '**Application permissions**'
  * Select the following set of permissions and click '**Add permissions**'
    * **Application / Application.Read.All**
    * **Group / Group.Read.All**
    * **User / User.Read.All**
    * **PrivilegedAccess / PrivilegedAccess.Read.AzureResources**
  * Click on 'Add a permissions'
  * Back in the main '**API permissions**' menu you will find the permissions with status 'Not granted for...'. Click on '**Grant admin consent for _TenantName_**' and confirm by click on '**Yes**'
  * Now you will find the permissions with status '**Granted for _TenantName_**'

Permissions in Microsoft Entra ID (AAD) for App registration:
![alt text](img/aadpermissionsportal_4.jpg "Permissions in Microsoft Entra ID (AAD)")

## Grant permissions on Azure Governance Visualizer AzDO repository

When the AzDO pipeline executes the Azure Governance Visualizer script the outputs should be pushed back to the Azure Governance Visualizer AzDO repository, in order to do this we need to grant the AzDO Project´s Build Service account with 'Contribute' permissions on the repository

* Grant permissions on the Azure Governance Visualizer AzDO repository
  * In AzDO click on '**Project settings**' (located on the bottom left), under '**Repos**' open the '**Repositories**' page
  * Click on the Azure Governance Visualizer AzDO Repository and select the tab '**Security**'
  * On the right side search for the Build Service account
     **%Project name% Build Service (%Organization name%)** and grant it with '**Contribute**' permissions by selecting '**Allow**' (no save button available)

## OPTION 1 (legacy) - Edit AzDO YAML file (.pipelines folder)

* Click on '**Repos**'
* Navigate to the Azure Governance Visualizer Repository
* In the folder '**pipeline**' click on '**AzGovViz.yml**' and click '**Edit**'
* Under the variables section
  * Enter the Service Connection name that you copied earlier (ServiceConnection)
  * Enter the Management Group Id (ManagementGroupId)
* Click '**Commit**'

## OPTION 1 (legacy) - Create AzDO Pipeline (.pipelines folder)

* Click on '**Pipelines**'
* Click on '**New pipeline**'
* Select '**Azure Repos Git**'
* Select the Azure Governance Visualizer repository
* Click on '**Existing Azure Pipelines YAML file**'
* Under '**Path**' select '**/.pipelines/AzGovViz.yml**' (the YAML file we edited earlier)
* Click ' **Save**'

## OPTION 2 (new) - Edit AzDO Variables YAML file (.azuredevops folder)

>For the '**parameters**' and '**variables**' sections, details about each parameter or variable is documented inline.

* Click on '**Repos**'
* Navigate to the Azure Governance Visualizer repository
* In the folder '**/.azuredevops/pipelines**' click on '**AzGovViz.variables.yml**' and click '**Edit**'
* If needed, modify the '**parameters**' section:
  * For more information about [parameters](https://docs.microsoft.com/en-us/azure/devops/pipelines/process/runtime-parameters)
  * [Optional] Update the '**ExcludedResourceTypesDiagnosticsCapableParameters**'
  * [Optional] Update the '**SubscriptionQuotaIdWhitelistParameters**'
* Update the '**Required Variables**' section:
  * Replace `<YourServiceConnection>` with the Service connection name you copied earlier (ServiceConnection)
  * Replace `<YourManagementGroupId>` with the Management Group Id (ManagementGroupId)
* If needed, update the '**Default Variables**' section
* If needed, update the '**Optional Variables**' section

### OPTION 2 (new) Create AzDO Pipeline (.azuredevops folder)

* Click on '**Pipelines**'
* Click on '**New pipeline**'
* Select '**Azure Repos Git**'
* Select the Azure Governance Visualizer repository
* Click on '**Existing Azure Pipelines YAML file**'
* Under '**Path**' select '**/.azuredevops/pipelines/AzGovViz.pipeline.yml**'
* Click ' **Save**'

## Run the AzDO Pipeline

* Click on '**Pipelines**'
* Select the Azure Governance Visualizer pipeline
* Click '**Run pipeline**'

Note: Before the pipeline kicks off it may require you to approve the run (only first time run)

## Create AzDO Wiki (WikiAsCode)

Once the pipeline has executed successfully we can setup our Wiki (WikiAsCode)

* Click on '**Overview**'
* Click on '**Wiki**'
* Click on '**Publish code as wiki**'
* Select the Azure Governance Visualizer repository
* Select the folder '**wiki**' and click '**OK**'
* Enter a name for the Wiki
* Click '**Publish**'

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

* Assign the Azure DevOps Service Connection´s Service Principal with RBAC Role **Website Contributor** on the Azure Web App
* Edit the `.azuredevops/AzGovViz.variables.yml` file  
![alt text](img/webapp_AzDO_yml.png "Azure DevOps YAML variables")
