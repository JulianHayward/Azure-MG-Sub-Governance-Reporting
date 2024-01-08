
# Configure and run Azure Governance Visualizer from the console

When trying out Azure Governance Visualizer for the first time or simply as a one-time evaluation of an Azure tenant, the quickest way to get results is to run it directly from the console. These instructions will get you up and running from a terminal.

Some steps have both **portal based** ( :computer_mouse: ) and **PowerShell based** ( :keyboard: ) instructions. Use whichever you feel is appropriate for your situation, they both will produce the same results.

The identity executing this script will need read access on the target management group and some basic Microsoft Entra ID permissions. Follow the instructions below based on the type of user you're executing this as.

----

- Requirements
  
Create a '**Reader**' RBAC Role assignment on the target Management Group scope for the identity that shall run Azure Governance Visualizer

- PowerShell

```powershell
$objectId = "<objectId of the identity that shall run Azure Governance Visualizer>"
$managementGroupId = "<managementGroupId>"

New-AzRoleAssignment `
-ObjectId $objectId `
-RoleDefinitionName "Reader" `
-Scope /providers/Microsoft.Management/managementGroups/$managementGroupId
```

- Azure Portal
[Assign Azure roles using the Azure portal](https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal)

---

## Prerequisites

The following must be installed on the workstation that will be used to run the scripts:

- [Git](https://git-scm.com/downloads)
- [PowerShell 7](https://github.com/PowerShell/PowerShell#get-powershell) (minimum supported version 7.0.3)
- [Azure PowerShell](https://learn.microsoft.com/powershell/azure/install-azure-powershell)
- [AzAPICall](https://github.com/JulianHayward/AzAPICall#get--set-azapicall-powershell-module)

## 1. Validate permissions on user

:arrow_forward: If your user is a tenant _member user_ and you use your user to complete these instructions, then no additional setup is necessary. This is the most common. And you can :arrow_down_small: continue with [**2. Clone the Azure Governance Visualizer repository**](#2-clone-the-azure-governance-visualizer-repository).

_- or -_

:arrow_forward: However, if your user is tenant _guest user_ and you use your user to complete these instructions, continue to [Set up to execute as a tenant _guest user_](#set-up-to-execute-as-a-tenant-guest-user) to ensure your user is configured properly.

_- or -_

:arrow_forward: If instead you are planning on executing the script as a pre-existing service principal instead of as your user, see [Set up to execute as a _service principal_](#set-up-to-execute-as-a-service-principal) to ensure it is configured properly.

### Set up to execute as a tenant _guest user_

Your user is a guest user in the tenant or there are other hardened restrictions on the tenant, then your user must first be assigned the Microsoft Entra ID role '**Directory readers**'.

:bulb: [Compare member and guest default permissions](https://learn.microsoft.com/entra/fundamentals/users-default-permissions#compare-member-and-guest-default-permissions)

:bulb: [Restrict guest access permissions in Microsoft Entra ID](https://docs.microsoft.com/azure/active-directory/enterprise-users/users-restrict-guest-permissions)

Work with your Microsoft Entra '**Privileged Role Administrator**' or '**Global Administrator**' to assign the '**Directory readers**' [role to your guest account](https://learn.microsoft.com/entra/identity/role-based-access-control/manage-roles-portal).

:arrow_down_small: Continue with [**2. Clone the Azure Governance Visualizer repository**](#2-clone-the-azure-governance-visualizer-repository).

### Set up to execute as a _service principal_

You are planning on executing the script as a service principal instead of as your user. A service principal, by default, has no read permissions on users, groups, and other service principals, therefore you'll need to work with a Microsoft Entra ID administrator to grant additional permissions to the service principal. The following Microsoft Graph API permissions, with admin consent, need to be added:

- **Application / Application.Read.All**
- **Group / Group.Read.All**
- **User / User.Read.All**
- **PrivilegedAccess / PrivilegedAccess.Read.AzureResources**

**:computer_mouse: Use the Microsoft Entra admin center to assign permissions to the service principal:**

To grant API permissions and grant admin consent for the directory, the user performing the following steps must have '**Privileged Role Administrator**' or '**Global Administrator**' role assigned in Microsoft Entra ID.

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

## 2. Clone the Azure Governance Visualizer repository

```powershell
Set-Location "c:\Git"
git clone "https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting.git"
```

## 2. Authenticate to Azure

**As your user:**

```powershell
Connect-AzAccount -TenantId <TenantId> -UseDeviceAuthentication
```

**As the configured service principal:**

Have the '**Application (client) ID**' of the app registration OR '**Application ID**' of the service principal (Enterprise application) and the secret of the app registration at hand.

```powershell
$pscredential = Get-Credential
Connect-AzAccount -ServicePrincipal -TenantId <TenantId> -Credential $pscredential
```

User: Enter '**Application (client) ID**' of the App registration OR '**Application ID**' of the service principal (Enterprise application)

Password for user \<Id\>: Enter App registration's secret

## 3. Run the Azure Governance Visualizer

Familiarize yourself with the available [parameters](../README.md#parameters) for Azure Governance Visualizer.

```powershell
c:\Git\Azure-MG-Sub-Governance-Reporting\pwsh\AzGovVizParallel.ps1 -ManagementGroupId <target Management Group Id>
```

If not using the `-OutputPath` parameter, all output will be created in the current directory. The following example will create the output in directory c:\AzGovViz-Output (directory must exist)

```powershell
c:\Git\Azure-MG-Sub-Governance-Reporting\pwsh\AzGovVizParallel.ps1 -ManagementGroupId <target Management Group Id> -OutputPath "c:\AzGovViz-Output"
```
