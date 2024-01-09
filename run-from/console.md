
# Configure and run Azure Governance Visualizer from the console

When trying out Azure Governance Visualizer for the first time or simply as a one-time evaluation of an Azure tenant, the quickest way to get results is to run it directly from the console. These instructions will get you up and running from a terminal.

Some steps have both **portal based** ( :computer_mouse: ) and **PowerShell based** ( :keyboard: ) instructions. Use whichever you feel is appropriate for your situation, they both will produce the same results.

## Prerequisites

The following must be installed on the workstation that will be used to run the scripts:

- [Git](https://git-scm.com/downloads)
- [PowerShell 7](https://github.com/PowerShell/PowerShell#get-powershell) (minimum supported version 7.0.3)
- [Azure PowerShell](https://learn.microsoft.com/powershell/azure/install-azure-powershell)
- [AzAPICall](https://github.com/JulianHayward/AzAPICall#get--set-azapicall-powershell-module)

## 1. Validate Microsoft Graph permissions for your user

:arrow_forward: If your user is a tenant _member user_ and you plan on running the script as yourself, then no additional setup is necessary. This is the most common. You can :arrow_down_small: continue with [**2. Validate Azure permissions for your user**](#2-validate-azure-permissions-for-your-user).

_- or -_

:arrow_forward: However, if your user is tenant _guest user_ and you plan on running the script as yourself, continue to [Set up to execute as a tenant _guest user_](#set-up-to-execute-as-a-tenant-guest-user) to ensure your user is configured properly. You will likely need support from the Microsoft Entra ID administrator of the tenant you are a guest in.

_- or -_

:arrow_forward: If instead you are planning on executing the script as a pre-existing service principal instead of as your user, see [Set up to execute as a _service principal_](#set-up-to-execute-as-a-service-principal) to ensure it is configured properly.

### Set up to execute as a tenant _guest user_

Your user is a [guest user](https://learn.microsoft.com/entra/fundamentals/users-default-permissions#compare-member-and-guest-default-permissions) in the tenant or there are other [hardened restrictions](https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-permissions) on the tenant, then your user must first be assigned the Microsoft Entra ID role '**Directory readers**'. Work with the Microsoft Entra administrator for the tenant you are a guest in to have them assign the '**Directory readers**' [role to your guest account](https://learn.microsoft.com/entra/identity/role-based-access-control/manage-roles-portal).

:arrow_down_small: Once that is configured, continue with [**2. Validate Azure permissions for your user**](#2-validate-azure-permissions-for-your-user).

### Set up to execute as a _service principal_

You are planning on executing the script as a service principal instead of as your user. A service principal, by default, has no read permissions on users, groups, and other service principals, therefore you'll need to work with a Microsoft Entra ID administrator to grant additional permissions to the service principal. The following Microsoft Graph API permissions, with admin consent, need to be granted:

- '**Application / Application.Read.All**'
- '**Group / Group.Read.All**'
- '**User / User.Read.All**'
- '**PrivilegedAccess / PrivilegedAccess.Read.AzureResources**'

#### Assign Microsoft Graph permissions, if needed

**:computer_mouse: Use the Microsoft Entra admin center to assign permissions to the service principal:**

> To grant API permissions and admin consent for the directory, the user performing the following steps must have '**Privileged Role Administrator**' or '**Global Administrator**' role assigned in Microsoft Entra ID.

1. Navigate to the [Microsoft Entra admin center](https://entra.microsoft.com/).
1. Click on '**App registrations**'
1. Search for the existing application (service principal)
1. Under '**Manage**' click on '**API permissions**'
1. Click on '**Add a permissions**'
1. Click on '**Microsoft Graph**'
1. Click on '**Application permissions**'
1. Select the following set of permissions and click '**Add permissions**'
   - **Application / Application.Read.All**
   - **Group / Group.Read.All**
   - **User / User.Read.All**
   - **PrivilegedAccess / PrivilegedAccess.Read.AzureResources**
1. Click on 'Add a permissions'
1. Back in the main '**API permissions**' menu you will find permissions with status 'Not granted for...'. Click on '**Grant admin consent for _TenantName_**' and confirm by click on '**Yes**'
   - Now you will find the permissions with status '**Granted for _TenantName_**'

Permissions and admin consent granted in Microsoft Entra ID for the service principal (App Registration):

![Permissions in Microsoft Entra ID](../img/aadpermissionsportal_4.jpg)

## 2. Validate Azure permissions for your user

The identity executing the script (your user or the service principal) needs to have the '**Reader**' Azure RBAC role assignment on the **target management group**.

### Assign Azure permissions, if needed

If that permission is not yet assigned to your user or the service principal, a user with '**Microsoft.Authorization/roleAssignments/write**' permissions on the target management group scope (such as the built-in Azure RBAC role '**User Access Administrator**' or '**Owner**') is required to make the required permission changes.

**:computer_mouse: Use the Azure portal to validate and assign the role:**

Follow the instructions at [Assign Azure roles using the Azure portal](https://learn.microsoft.com/azure/role-based-access-control/role-assignments-portal) to grant Azure RBAC '**Reader**' role to the management group.

**:keyboard: Use PowerShell to assign the role:**

```powershell
$objectId = "<objectId of the identity that will execute Azure Governance Visualizer>"
$managementGroupId = "<managementGroupId>"

New-AzRoleAssignment `
-ObjectId $objectId `
-RoleDefinitionName "Reader" `
-Scope /providers/Microsoft.Management/managementGroups/$managementGroupId
```

## 3. Clone the Azure Governance Visualizer repository

You'll need a copy of this repository on your workstation.

```powershell
git clone "https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting.git"
Set-Location "Azure-MG-Sub-Governance-Reporting"
```

## 4. Authenticate to Azure

**As your user:**

```powershell
Connect-AzAccount -TenantId <TenantId> -UseDeviceAuthentication
```

_- or -_

**As the service principal:**

Have the '**Application (client) ID**' of the app registration OR '**Application ID**' of the service principal (Enterprise application) and the secret of the app registration at hand.

```powershell
$pscredential = Get-Credential
Connect-AzAccount -ServicePrincipal -TenantId <TenantId> -Credential $pscredential
```

User: Enter '**Application (client) ID**' of the App registration OR '**Application ID**' of the service principal (Enterprise application)

Password for user \<Id\>: Enter App registration's secret

## 5. Run the Azure Governance Visualizer

Familiarize yourself with the available [parameters](../README.md#parameters) for Azure Governance Visualizer. The following example will create the output in directory **c:\AzGovViz-Output** (directory must exist)

```powershell
.\pwsh\AzGovVizParallel.ps1 -ManagementGroupId <target Management Group Id> -OutputPath "c:\AzGovViz-Output"
```

## 6. View the results

Open the generated HTML in your default browser.

```powershell
Set-Location -Path "c:\AzGovViz-Output"
Get-ChildItem
Invoke-Item ".\AzGovViz*.html"
```

There is also a markdown version available as well in the output directory.

## Next steps

Consider a solution that automates the execution of this process to have regular snapshots of this data available for review. This repo has instructions available to automate using [Azure DevOps](azure-devops.md) or [GitHub](github.md). For report hosting, consider using the [Azure Governance Visualizer accelerator](https://github.com/Azure/Azure-Governance-Visualizer-Accelerator) which will give you an example on how to host the output on Azure Web Apps in conjunction with the automation.
