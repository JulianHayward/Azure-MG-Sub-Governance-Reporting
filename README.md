# Azure-MG-Sub-Governance-Reporting aka AzGovViz

..want to have visibility on your Management Group hierarchy, document it in markdown? This script iterates Management Group hierachy down to Subscription level. It captures all RBAC Role assignments and Policy assignments and creates a visible hierachy.

You can run the script either for your Management Group Root or any other Management Group that you have read access on. Thanks to [javierjeronimo](https://github.com/javierjeronimo) for initiating this update.

### Outputs

* detailed csv file
  * Management Groups, Subscriptions, Policy, Policy Initiative, RBAC
* detailed html file
  * Management Groups, Subscriptions, Policy, Policy Initiative, RBAC
* basic markdown file for use with Azure DevOps Wiki leveraging the [Mermaid](https://docs.microsoft.com/en-us/azure/devops/release-notes/2019/sprint-158-update#mermaid-diagram-support-in-wiki) plugin
  * Management Groups, Subscriptions

### Required permissions in Azure on the target Management Group

* RBAC: _Management Group Reader_
* RBAC: _Reader_
* API permissions: If you run the script in Azure Automation or Azure DevOps hosted agent you will need to grant API permissions in Azure Active Directory (get-AzRoleAssignment cmdlet). The Automation Account App registration must be granted with: Azure Active Directory API | Application | Directory | Read.All

### Powershell

* Requires: PowerShell Az/AzureRm Modules
* Usage:  
  * `.\mg-sub-hierachy.ps1 -managementGroupId <your Management Group Id>`
* Passed tests: Powershell Core on Windows
* Passed tests: Powershell Core on Linux Ubuntu 18.04 LTS

### Screenshots

detailed html file

![alt text](img/mg-sub-governance-reporting.jpg "example output")

basic markdown in Azure DevOps Wiki

![alt text](img/mg-sub-governance-reporting_md.jpg "example output")

note: there is some fixing ongoing at the mermaid project to optimize the graphical experience:

<https://github.com/mermaid-js/mermaid/issues/1289>

<https://github.com/mermaid-js/mermaid/issues/1177>

## AzAdvertizer

Also check <https://www.azadvertizer.net> to keep up with the pace on Azure Governance capabilities such as Azure Policies, Policy Initiatives, Policy Aliases and RBAC Roles
