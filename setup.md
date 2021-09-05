# AzGovViz - Azure Governance Visualizer - Setup

This guide will help you to setup and run AzGovViz.
* Abbreviations:
    * Azure Active Directory - AAD
    * Azure DevOps - AzDO

## Table of contents
* [__AzGovViz from Console__](#azgovviz-from-console)
    * Grant permissions in Azure
    * Clone the AzGovViz repository
    * Option 1 - Execute as a Tenant Member User
        * Run AzGovViz
    * Option 2 - Execute as a Tenant Guest User
        * Grant permissions in AAD
        * Run AzGovViz
    * Option 3 - Execute as Service Principal
        * Grant permissions in AAD
            * Option 1 - API permissions
            * Option 2 - AAD Role
        * Run AzGovViz
    
* [__AzGovViz in Azure DevOps (AzDO)__](#azgovviz-in-azure-devops)
    * Create AzDO Project
    * Import AzGovViz Github repository
    * Create AzDO Service Connection
      * Option 1 - Create Service Connection in AzDO
      * Option 2 - Create Service Connection´s Service Principal in the Azure Portal
    * Grant permissions in Azure
    * Grant permissions in AAD
      * Option 1 - API permissions
      * Option 2 - AAD Role
    * Grant permissions on AzGovViz AzDO repository
    * Edit AzDO YAML file
    * Create AzDO Pipeline
    * Run the AzDO Pipeline
    * Create AzDO Wiki - WikiAsCode

# AzGovViz from Console

## Grant permissions in Azure

* Requirements
    * To assign roles, you must have Microsoft.Authorization/roleAssignments/write permissions, such as RBAC Role 'User Access Administrator' or 'Owner' on the target Management Group scope

Create a 'Reader' RBAC Role assignment on the target Management Group scope for the identity that shall run AzGovViz

* PowerShell
```powershell
$objectId = "<objectId of the identity that shall run AzGovViz>"
$role = "Reader"
$managementGroupId = "<managementGroupId>"

New-AzRoleAssignment `  
-ObjectId $objectId `  
-RoleDefinitionName $role `  
-Scope /providers/Microsoft.Management/managementGroups/$managementGroupId
```

* Azure Portal  
[Assign Azure roles using the Azure portal](https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal)

## Clone the AzGovViz repository

* Requirements
    * To clone the AzGovViz Github repository you need to have GIT installed
    * Install Git: https://git-scm.com/download/win

* PowerShell
```powershell 
Set-Location "c:\Git"  
git clone "https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting.git"
```

## Option 1 - Execute as a Tenant Member User

Proceed with step [__Run AzGovViz from Console__](#run-azgovviz-from-console)

## Option 2 - Execute as a Tenant Guest User

A Tenant Guest User by default has less permissions in AAD than a Tenant Member User ([Compare member and guest default permissions](https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/fundamentals/users-default-permissions.md#compare-member-and-guest-default-permissions)), therefore we need to grant additional permissions in AAD by assigning AAD Role 'Directory Reader' for the Guest User.

### Option 2 - Execute as a Tenant Guest User - Grant permissions in AAD

* Requirements
    * To assign roles, you must have 'Privileged Role Administrator' or 'Global Administrator' role assigned [Assign Azure AD roles to users](https://docs.microsoft.com/en-us/azure/active-directory/roles/manage-roles-portal)

Assign the AAD Role 'Directory Reader' for the Guest User that shall run AzGovViz (work with the Guest User´s display name)  
* Azure Portal
    * [Assign a role](https://docs.microsoft.com/en-us/azure/active-directory/roles/manage-roles-portal#assign-a-role)

Proceed with step [__Run AzGovViz from Console__](#run-azgovviz-from-console)

## Option 3 - Execute as Service Principal

A Service Principal by default has no read permissions on Identities, Groups and other Service Principals (Applications, Managed Identities), therefore we need to grant additional permissions in AAD.

### Option 3 - Execute as Service Principal - Grant permissions in AAD

There are two options to grant the Service Principal the required permissions
* Options
    * __Option 1__ API permissions (recommended)
    * __Option 2__ AAD Role

#### Option 3 - Execute as Service Principal - Grant permissions in AAD - Option 1 - API permissions

* Requirements
    * To grant API permissions and grant admin consent for the directory, you must have 'Privileged Role Administrator' or 'Global Administrator' role assigned [Assign Azure AD roles to users](https://docs.microsoft.com/en-us/azure/active-directory/roles/manage-roles-portal)

Proceed with step [__Run AzGovViz from Console__](#run-azgovviz-from-console)

#### Option 3 - Execute as Service Principal - Grant permissions in AAD - Option 2 - AAD Role

* Requirements
    * To assign roles, you must have 'Privileged Role Administrator' or 'Global Administrator' role assigned [Assign Azure AD roles to users](https://docs.microsoft.com/en-us/azure/active-directory/roles/manage-roles-portal)

Assign the AAD Role 'Directory Reader' for the Service Principal that shall run AzGovViz (work with the Service Principal´s display name)  
* Azure Portal
    * [Assign a role](https://docs.microsoft.com/en-us/azure/active-directory/roles/manage-roles-portal#assign-a-role)

Proceed with step [__Run AzGovViz from Console__](#run-azgovviz-from-console)

## Run AzGovViz from Console

### PowerShell & Azure PowerShell modules

* Requirements
    * Requires PowerShell 7 (minimum supported version 7.0.3)
        * [Get PowerShell](https://github.com/PowerShell/PowerShell#get-powershell)
        * [Installing PowerShell on Windows](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-windows)
        * [Installing PowerShell on Linux](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux)
    * Requires PowerShell Az Modules
        * Az.Accounts
        * Az.Resources
        * [Install the Azure Az PowerShell module](https://docs.microsoft.com/en-us/powershell/azure/install-az-ps)

### Connecting to Azure as User (Member or Guest)

* PowerShell
```powershell
Connect-AzAccount -TenantId <TenantId> -UseDeviceAuthentication
```

### Connecting to Azure using Service Principal

Have the 'Application (client) ID' of the App registration OR 'Application ID' of the Service Principal (Enterprise Application) and the secret of the App registration at hand.

* PowerShell
```powershell 
$pscredential = Get-Credential    
Connect-AzAccount -ServicePrincipal -TenantId <TenantId> -Credential $pscredential
```
User: Enter 'Application (client) ID' of the App registration OR 'Application ID' of the Service Principal (Enterprise Application)  
Password for user \<Id\>: Enter App registration´s secret 

### Run AzGovViz

Familiarize yourself with the available [parameters](https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting#usage) for AzGovViz

* PowerShell
```powershell
c:\Git\Azure-MG-Sub-Governance-Reporting\pwsh\AzGovVizParallel.ps1 -ManagementGroupId <target Management Group Id>
```

Note if not using the `-OutputPath` parameter, all outputs will be created in the current directory. The following example will create the outputs in directory c:\AzGovViz-Output (directory must exist)

* PowerShell
```powershell
c:\Git\Azure-MG-Sub-Governance-Reporting\pwsh\AzGovVizParallel.ps1 -ManagementGroupId <target Management Group Id> -OutPath "c:\AzGovViz-Output"
```

# AzGovViz in Azure DevOps

## Create AzDO Project

[Create a project](https://docs.microsoft.com/en-us/azure/devops/organizations/projects/create-project?view=azure-devops&tabs=preview-page#create-a-project)

## Import AzGovViz Github repository

AzGovViz Clone URL: `https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting.git`

[Import into a new repo](https://docs.microsoft.com/en-us/azure/devops/repos/git/import-git-repository?view=azure-devops#import-into-a-new-repo)

Note: the AzGovViz GitHub repository is public - no authorization required

## Create AzDO Service Connection

For the pipeline to authenticate and connect to Azure we need to create an AzDO Service Connection which basically is a Service Principal (Application).  
There are two options to create the Service Connection.

* Options
    * __Option 1__ Create Service Connection´s Service Principal in the Azure Portal (recommended)
    * __Option 2__ Create Service Connection in AzDO

### Create AzDO Service Connection - Option 1 - Create Service Connection´s Service Principal in the Azure Portal

Azure Portal
* Navigate to 'Azure Active Directory'
* Click on 'App registrations'
* Click on 'New registration'
* Name your application (e.g. 'AzGovViz_SC')
* Click 'Register'
* Your App registration has been created, in the 'Overview' copy the 'Application (client) ID' as we will need it later to setup the Service Connection in AzDO
* Under 'Manage' click on 'Certificates & Secrets'
* Click on 'New client secret'
* Provide a good description and choose the expiry time based on your need and click 'Add'
* A new client secret has been created, copy the secret´s value as we will need it later to setup the Service Connection in AzDO

Azure DevOps (AzDO)
* Click on 'Project settings' (located on the bottom left)
* Under 'Pipelines' click on 'Service Connections'
* Click on 'New service connection' and select the connection/service type 'Azure Resource Manager' and click Next
* For the authentication method select 'Service principal (manual)' and click Next
* For the 'Scope level' select 'Management Group'
    * In the field 'Management Group Id' enter the target Management Group Id 
    * In the field 'Management Group Name' enter the target Management Group Name
* Under 'Authentication' in the field 'Service Principal Id' enter the 'Application (client) ID' that you copied earlier
* For the 'Credential' select 'Service principal key', in the field 'Service principal key' enter the secret that you copied earlier
* For 'Tenant ID' enter your Tenant Id
* Click on 'Verify'
* Under 'Details' provide your Service Connection with a name and copy the name as we will need that later when editing the Pipeline YAML file
* For 'Security' leave the 'Grant access permissions to all pipelines' option checked
* Click on 'Verify and save'

### Create AzDO Service Connection - Option 2 - Create Service Connection in AzDO

* Click on 'Project settings' (located on the bottom left)
* Under 'Pipelines' click on 'Service connections'
* Click on 'New service connection' and select the connection/service type 'Azure Resource Manager' and click Next
* For the authentication method select 'Service principal (automatic)' and click Next
* For the 'Scope level' select 'Management Group', in the Management Group dropdown select the target Management Group (here the Management Group´s display names will be shown), in the 'Details' section apply a Service Connection name and optional give it a description and click Save
* A new window will open, authenticate with your administrative account
* Now the Service Connection has been created 
* __Important!__ In Azure on the target Management Group scope a 'Owner' RBAC Role assignment for the Service Connection´s Service Principal has been created automatically (we do however only require a 'Reader' RBAC Role assignment! we will take corrective action in the next steps)

## Grant permissions in Azure

* Requirements
    * To assign roles, you must have Microsoft.Authorization/roleAssignments/write permissions, such as RBAC Role 'User Access Administrator' or 'Owner' on the target Management Group scope

Create a 'Reader' RBAC Role assignment on the target Management Group scope for the AzDO Service Connection´s Service Principal

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

__Important!__ If you have created the AzDO Service Connection in AzDO (Option 2) then you SHOULD remove the automatically created 'Owner' RBAC Role assignment for the AzDO Service Connection´s Service Principal from the target Management Group

## Grant permissions in AAD

There are two options to grant the AzDO Service Connection´s Service Principal the required permissions
* Options
    * __Option 1__ API permissions (recommended)
    * __Option 2__ AAD Role

### Grant permissions in AAD - Option 1 - API permissions

* Requirements
    * To grant API permissions and grant admin consent for the directory, you must have 'Privileged Role Administrator' or 'Global Administrator' role assigned ([Assign Azure AD roles to users](https://docs.microsoft.com/en-us/azure/active-directory/roles/manage-roles-portal))

Grant API permissions for the Application that we created earlier
* Navigate to 'Azure Active Directory'
* Click on 'App registrations'
* Search for the Application that we created earlier and click on it
* Under 'Manage' click on 'API permissions'
    * Click on 'Add a permissions'
    * Click on '__Microsoft Graph__'
    * Click on 'Application permissions'
    * Select the following set of permissions and click 'Add permissions'
        * Application / Application.Read.All
        * Group / Group.Read.All
        * User / User.Read.All
    * Click on 'Add a permissions'
    * Click on '__Azure Active Directory Graph__'
    * Click on 'Application permissions'
    * Select the following set of permissions and click 'Add permissions'
        * Directory / Read.All
    * Back in the main 'API permissions' menu you will find the 4 permissions with status 'Not granted for...'. Click on 'Grant admin consent for _TenantName_' and confirm by click on 'Yes'
    * Now you will find the 4 permissions with status 'Granted for _TenantName_'

### Grant permissions in AAD - Option 2 - AAD Role

* Requirements
    * To assign roles, you must have 'Privileged Role Administrator' or 'Global Administrator' role assigned ([Assign Azure AD roles to users](https://docs.microsoft.com/en-us/azure/active-directory/roles/manage-roles-portal))

Assign the AAD Role 'Directory Reader' for the AzDO Service Connection´s Service Principal (work with the Service Principal´s display name)  
* Azure Portal
    * [Assign AAD role](https://docs.microsoft.com/en-us/azure/active-directory/roles/manage-roles-portal#assign-a-role)

## Grant permissions on AzGovViz AzDO repository

When the AzDO pipeline executes the AzGovViz script the outputs should be pushed back to the AzGovViz AzDO repository, in order to do this we need to grant the AzDO Project´s Build Service account with 'Contribute' permissions on the repository

* Grant permissions on the AzGovViz AzDO repository
    * In AzDO click on 'Project settings' (located on the bottom left), under 'Repos' open the 'Repositories' page
    * Click on the AzGovViz AzDO Repository and select the tab 'Security'
    * On the right side search for the Build Service account  
     __%Project name% Build Service (%Organization name%)__ and grant it with 'Contribute' permissions by selecting 'Allow' (no save button available)

## Edit AzDO YAML file

* Click on 'Repos'
* Navigate to the AzGovViz Repository
* In the folder 'pipeline' click on 'AzGovViz.yml' and click 'Edit'
* Under the variables section 
    * Enter the Service Connection name that you copied earlier (ServiceConnection)
    * Enter the Management Group Id (ManagementGroupId)
* Click 'Commit'

## Create AzDO Pipeline

* Click on 'Pipelines'
* Click on 'New pipeline'
* Select 'Azure Repos Git'
* Select the AzGovViz repository
* Click on 'Existing Azure Pipelines YAML file'
* Under 'Path' select '/pipeline/AzGovViz.yml' (the YAML file we edited earlier)
* Click ' Continue'

## Run the AzDO Pipeline

* Click on 'Pipelines'
* Select the AzGovViz pipeline
* Click 'Run pipeline'

## Create AzDO Wiki (WikiAsCode)

Once the pipeline has executed successfully we can setup our Wiki (WikiAsCode)

* Click on 'Overview'
* Click on 'Wiki'
* Click on 'Publish code as wiki'
* Select the AzGovViz repository
* Select the folder 'wiki' and click 'OK'
* Enter a name for the Wiki
* Click 'Publish'
