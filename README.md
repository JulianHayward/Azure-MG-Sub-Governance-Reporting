# Azure-MG-Sub-Governance-Reporting aka AzGovViz

..want to have visibility on your Management Group hierarchy, document it in markdown? This script iterates Management Group hierarchy down to Subscription level. It captures all RBAC Role assignments and Policy assignments and creates a visible hierarchy.

You can run the script either for your Management Group Root or any other Management Group that you have read access on.

### Screenshots

detailed html file

![alt text](img/mg-sub-governance-reporting.jpg "example output")

basic markdown in Azure DevOps Wiki

![alt text](img/mg-sub-governance-reporting_md.jpg "example output")

### Outputs

* csv file
  * Management Groups, Subscriptions, Policy, Policy Initiative, RBAC
* html file
  * Management Groups, Subscriptions, Policy, Policy Initiative, RBAC. The html file uses Java Script and CSS files which are hosted on various CDNs (Content Delivery Network). For details review the BuildHTML region in the AzGovViz.ps1 script file.
* markdown file for use with Azure DevOps Wiki leveraging the [Mermaid](https://docs.microsoft.com/en-us/azure/devops/release-notes/2019/sprint-158-update#mermaid-diagram-support-in-wiki) plugin
  * Management Groups, Subscriptions

> note: there is some fixing ongoing at the mermaid project to optimize the graphical experience:  
 <https://github.com/mermaid-js/mermaid/issues/1289>  
 <https://github.com/mermaid-js/mermaid/issues/1177>

### Required permissions in Azure

* RBAC: _Management Group Reader_ on Management Group
* RBAC: _Reader_ on Management Group
* API permissions: If you run the script in Azure Automation or on Azure DevOps hosted agent you will need to grant API permissions in Azure Active Directory (get-AzRoleAssignment cmdlet requirements?!). The Automation Account´s App registration must be granted with: Azure Active Directory API | Application | Directory | Read.All

### Usage

#### PowerShell

* Requires: PowerShell Az/AzureRm Modules
* Usage:  
  * `.\AzGovViz.ps1 -managementGroupId <your-Management-Group-Id>`
* Passed tests: Powershell Core on Windows
* Passed tests: Powershell Core on Linux Ubuntu 18.04 LTS

#### Azure DevOps Pipeline

The provided example Pipeline is configured to run based on a [shedule](https://docs.microsoft.com/en-us/azure/devops/pipelines/build/triggers?view=azure-devops&tabs=yaml#scheduled-triggers) (every 6 hours). It will push the AzGovViz markdown output file to the wikiRepo which will feed your Wiki.

1. In Azure DevOps make sure to [enable](https://docs.microsoft.com/en-us/azure/devops/project/navigation/preview-features?view=azure-devops&tabs=new-account-enabled) the Multistage Pipelines feature <https://docs.microsoft.com/en-us/azure/devops/pipelines/get-started/multi-stage-pipelines-experience?view=azure-devops>
2. Clone the AzGovViz Repo.
3. Create an additional Repo 'wikiRepo' (hosting AzGovViz outputs).
4. Create Wiki by choosing [Publish Code as Wiki](https://docs.microsoft.com/en-us/azure/devops/project/wiki/publish-repo-to-wiki?view=azure-devops&tabs=browser), define the Repo 'wikiRepo' as source.
5. Create Pipeline, configure your pipeline selecting __Existing Azure Pipelines YAML file__, select the AzGovViz YAML from the AzGovViz (Azure-MG-Sub-Governance-Reporting) Repo.
6. Permissions: In order to allow the pipeline to push files to our wikiRepo the __Project Collection Build Service(%USERNAME%)__ must be granted __Contribute__ and __Create Branch__ permissions.

> The __Project Collection Build Service(%USERNAME%)__ seems only to become available after at least one pipeline has run - so just trigger the pipeline, expect an error and after the run grant the permissions as pointed out in 6.  
> Make sure your Service Connection has the required permissions (see __Required permissions in Azure__)

## Contributions

Thanks to [javierjeronimo](https://github.com/javierjeronimo) for initiating the update to define any Management Group / before the tenantId was used.

Thanks to [Fred](https://github.com/FriedrichWeinmann) for his help to optimize the PowerShell code.

## AzAdvertizer

Also check <https://www.azadvertizer.net> to keep up with the pace on Azure Governance capabilities such as Azure Policies, Policy Initiatives, Policy Aliases and RBAC Roles
