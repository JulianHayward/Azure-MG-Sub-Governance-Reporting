# AzGovViz - Azure Governance Visualizer

## AzGovViz version history

### AzGovViz version 5

__Changes__ (2021-Aug-22 / Major)

* Bugfix - indirect Role assignments (applied through AAD group membership); switched to Graph beta endpoint as v1.0 only resolves users and groups, whilst we´re also interested in Service Principals - [List group transitive members](https://docs.microsoft.com/en-us/graph/api/group-list-transitivemembers)

__Changes__ (2021-Aug-18 / Major)

* Added ASC Secure Score for Management Groups
* Policy Compliance - if API returns 'ResponseTooLarge' then flag Policy Compliance entries with 'skipped' for given scope
* Added [demo-output](demo-output) folder containing all outputs (html, csv, md, json, log)
* Bugfixes

__Changes__ (2021-Aug-06 / Major)

* Enriched Policy assignments with list of used parameters
* Enriched Role assignments on Groups with Group member count
* Optimize JSON outputs
* CSP scenario error handling
* Bugfixes
* Performance optimization

__Changes__ (2021-July-28 / Major)

* As demanded by the community reactivated parameters `-PolicyAtScopeOnly` and `-RBACAtScopeOnly`
* New paramter `-AADGroupMembersLimit`. Defines the limit (default=500) of AAD Group members; For AAD Groups that have more members than the defined limit Group members will not be resolved 
* New parameter `-JsonExportExcludeResourceGroups` - JSON Export will not include ResourceGroups (Policy & Role assignments)
* New parameter `-JsonExportExcludeResources`- JSON Export will not include Resources (Role assignments)
* Bugfixes
* Performance optimization

__Changes__ (2021-July-22 / Major)

* Full blown JSON definition output. Leveraging Git with this new capability you can easily track any changes that occurred in between the previous and last AzGovViz run.  
![newBuiltInRoleDefinition](img/gitdiff600.jpg)  
_* a new BuiltIn RBAC Role definition was added_
* Renamed parameter `-PolicyIncludeResourceGroups` to , `-DoNotIncludeResourceGroupsOnPolicy` (from now Policy assignments on ResourceGroups will be included by default)
* Renamed parameter `-RBACIncludeResourceGroupsAndResources` to , `-DoNotIncludeResourceGroupsAndResourcesOnRBAC` (from now Role assignments on ResourceGroups and Resources will be included by default)
* New parameter `-HtmlTableRowsLimit`. Although the parameter `-LargeTenant` was introduced recently, still the html output may become too large to be processed properly. The new parameter defines the limit of rows - if for the html processing part the limit is reached then the html table will not be created (csv and json output will still be created). Default rows limit is 40.000
* Added NonCompliance Message for Policy assignments
* Cosmetics
* Bugfixes
* Performance optimization

__Changes__ (2021-July-07 / Major)

* Replaced parameters ~~`-NoScopeInsights`,~~ `-RBACAtScopeOnly` and `-PolicyAtScopeOnly` with `-LargeTenant`. A large tenant is a tenant with more than ~500 Subscriptions - the HTML output for large tenants simply becomes too big, therefore will not create __ScopeInsights__ and will not show inheritance for Policy and Role assignments in the __TenantSummary__ (html) output
* Add Tenant to __HierarchyMap__ including count of Role assignments
* Executing against any child Management Group will show all parent Management Groups in __HierarchyMap__
* Cosmetics / Icons
* Bugfixes
* Performance optimization - optimized data collection to reduce memory utilization -> __big, fat 'Thank You'__ to Tim Wanierke and Brooks Vaughn

__Changes__ (2021-June-16 / Minor)

* added detailed [Setup](setup.md) instructions

__Changes__ (2021-June-07 / Major)

* Breaking Changes
  * Changed parameter `-CsvExport` to `-NoCsvExport` - You will need to explicitly deny CSV export using `-NoCsvExport`
  * Changed parameter `-JsonExport` to `-NoJsonExport` - You will need to explicitly deny JSON export using `-NoJsonExport`
* __HierarchyMap__ enrich Management Groups with counts on Policy assignments, scoped Policy definitions and Role assignments
* Enhanced Management Group and Subscription Diagnostic settings / list Management Groups and Subscriptions that do not have Diagnostic settings applied
* Updated API error codes / throttle handling
* Bugfixes

__Changes__ (2021-June-01 / Feature)

* Added Management Group and Subscription Diagnostic settings
* Restructure __TenantSummary__ - 'Diagnostics' gets its own section

__Changes__ (2021-May-19)

* Removed Azure PowerShell module requirement Az.ResourceGraph 
* __TenantSummary__ 'Change tracking' section. Tracks newly created and updated custom Policy, PolicySet and RBAC Role definitions, Policy/RBAC Role assignments and Resources that occured within the last 14 days (period can be adjusted using new parameter `-ChangeTrackingDays`)
* New parameters `-PolicyIncludeResourceGroups` and `-RBACIncludeResourceGroupsAndResources` - include Policy assignments on ResourceGroups, include Role assignments on ResourceGroups and Resources
* New parameters `-PolicyAtScopeOnly` and `-RBACAtScopeOnly` - removing 'inherited' lines in the HTML file; use this parameter if you run against a larger tenants
* New parameter `-CsvExport` - export enriched data for 'Role assignments', 'Policy assignments' data and 'all resources' (subscriptionId, managementGroup path, resourceType, id, name, location, tags, createdTime, changedTime)
* !_experimental_ New parameter `-JsonExport`- export of ManagementGroup Hierarchy including all MG/Sub Policy/RBAC definitions, Policy/RBAC assignments and some more relevant information to JSON
* Added ClassicAdministrators Role assignment information
* Restructure __TenantSummary__ - Limits gets its own section
* Added sytem metadata for Policy/RBAC definitions and assignments
* New parameter `-FileTimeStampFormat`- define the time format for the output files (default is `yyyyMMdd_HHmmss`)
* Updated API error codes
* Cosmetics / Icons
* Bugfixes
* Performance optimization

__Changes__ (2021-Mar-26)

* Code adaption to prevent billing related errors in sovereign cloud __AzureChinaCloud__ (.Billing n/a)
* New parameter `-SubscriptionId4AzContext` - Define the Subscription Id to use for AzContext (default is to use a random Subscription Id)
* New parameter `-AzureDevOpsWikiHierarchyDirection` - Azure DevOps Markdown Management Group hierarchy tree direction. Use 'TD' for Top->Down, use 'LR' for Left->Right (default is 'TD'; use 'LR' for larger Management Group hierarchies)
* Bugfixes
* Performance optimization

__Breaking Changes__ (2021-Feb-28)

* When granting __Azure Active Directory Graph__ API permissions in the background an AAD Role assignment for AAD Group __Directory readers__ was triggered automatically - since January/February 2021 this is no longer the case. Review the updated [__AzGovViz technical documentation__](#azgovviz-technical-documentation) section for detailed permission requirements.

__Let´s accellerate by going parallel!__  (2021-Feb-14)

* Support for PowerShell Core ONLY! No support for PowerShell version < 7.0.3
* New section __DefinitionInsights__ - Insights on all built-in and custom Policy, PolicySet and RBAC Role definitions
* New parameter `-NoScopeInsights` - Q: Why would you want to do this? A: In larger tenants the ScopeInsights section blows up the html file (up to unusable due to html file size)
* New parameter `-ThrottleLimit` - Leveraging PowerShell Core´s parallel capability you can define the ThrottleLimit (default=5)
* New parameter `DoTranscript` - Log the console output
* Parameter `SubscriptionQuotaIdWhitelist` now expects an array
* Renamed parameter `-NoServicePrincipalResolve` to `-NoAADServicePrincipalResolve`
* Renamed parameter `-ServicePrincipalExpiryWarningDays` to `-AADServicePrincipalExpiryWarningDays`
* Bugfixes

__Note:__ In order to run AzGovViz Version 5 in Azure DevOps you also must use the v5 pipeline YAML.

### AzGovViz version 4

Updates 2021-Jan-26
* Role Assigments indicate if User is Member/Guest
* Enrich information for Policy assignment related ServicePrincipal/Managed Identity (Policy assignment details on policy/set definition and Role assignments)
* Preloading of <a href="https://www.tablefilter.com/" target="_blank">TableFilter</a> removed for __TenantSummary__ PolicyAssignmentsAll and RoleAssignmentsAll (on poor hardware loading the HTML file took quite long)
* Fix 'Orphaned Custom Roles' bug - thanks to Tim Wanierke
* More bugfixes
* Performance optimization

Updates 2021-Jan-18
* Feature: __Policy Exemptions__
* Feature: __ResourceLocks__
* Feature: __Tag Name Usage__
* Feature: __Cost Management / Consumption Reporting__ - use another API
* Bugfixes

Updates 2021-Jan-08
* Feature: __Cost Management / Consumption Reporting__ - Changed AzureConsumptionPeriod default to 1 day  
![Consumption](img/consumption.png)
* Bugfixes

Updates 2021-Jan-06 - Happy New Year
* Feature: Resolve __Azure Active Directory Group memberships__ for Role assignment with identity type 'Group' leveraging Microsoft Graph. With this capability AzGovViz can ultimately provide holistic insights on permissions granted for Management Groups and Subscriptions (honors parameter `-DoNotShowRoleAssignmentsUserData`). Use parameter `-NoAADGroupsResolveMembers` to disable the feature  
![AADGroupMembers](img/aad850.png)
* Feature: New __TenantSummary__ section '__Azure Active Directory__' -> Check all Azure Active Directory Service Principals (type=Application that have a Role assignment) for Secret/Certificate expiry. Mark all Service Principals (type=ManagedIdentity) that are related to a Policy assignments. Use parameter `-NoServicePrincipalResolve` to disable this feature
* Feature: __Cost Management / Consumption Reporting__ for Subscriptions including aggregation at Management Group level. Use parameter `-NoAzureConsumption` to disable this feature.  
__Note__: Per default the consumption query will request consumption data for the last full 1 day (if you run it today, will capture the cost for yesterday), use the parameter `-AzureConsumptionPeriod` to define a favored time period  e.g. `-AzureConsumptionPeriod 7` (for 7 days) 
* Removed parameter `-Experimental`. 'Resource Diagnostics Policy Lifecycle' enabled by default. Use `-NoResourceDiagnosticsPolicyLifecycle` to disable the feature.
* Renamed parameter `-DisablePolicyComplianceStates` to `-NoPolicyComplianceStates` for better consistency
* Optimize 'Get Resource Types capability for Resource Diagnostics' query - thanks Brooks Vaughn
* Update Pipeline to honor [master/main change](https://devblogs.microsoft.com/devops/azure-repos-default-branch-name)
* Add info to HTML file on parameters used
* Performance optimization

Updates 2020-Dec-17
* Now supporting > 5000 entities (Subscriptions/Management Groups) :) thanks Brooks Vaughn

Updates 2020-Dec-15
* Pipeline `azurePowerShellVersion: latestVersion` / ensures compatibility with latest [Az.ResourceGraph 0.8.0 Release](https://github.com/Azure/azure-powershell/releases/tag/Az.ResourceGraph-v0.8.0)
* Error handling optimization / API
* Fix 'deprecated Policy assignments'
* Fix 'orphaned Custom Role definitions'

Updates 2020-Nov-30
* New parameter ~~`-DisablePolicyComplianceStates`~~ `-NoPolicyComplianceStates` (see [__Parameters__](#powerShell))
* Error handling optimization / API

Updates 2020-Nov-25
* Highlight default Management Group
* Add AzAPICall debugging parameter `-DebugAzAPICall`
* Fix for using parameter `-HierarchyMapOnly`

Updates 2020-Nov-19
* New parameter `-Experimental` (see [__Parameters__](#powerShell))
* Performance optimization
* Error handling optimization / API
* Azure DevOps pipeline worker changed from 'ubuntu-latest' to 'ubuntu-18.04' (see [Azure Pipelines - Sprint 177 Update](https://docs.microsoft.com/en-us/azure/devops/release-notes/2020/pipelines/sprint-177-update#ubuntu-latest-pipelines-will-soon-use-ubuntu-2004), [Ubuntu-latest workflows will use Ubuntu-20.04 #1816](https://github.com/actions/virtual-environments/issues/1816))

Updates 2020-Nov-08
* Re-model Bearer token handling (Az PowerShell Module Az.Accounts > 1.9.5 no longer provides access to the tokenCache [GitHub issue](https://github.com/Azure/azure-powershell/issues/13337))
* Adding Scope information for Custom Policy definitions and Custom PolicySet definitions sections in __TenantSummary__
* Cosmetics and User Experience enhancement
* New [__demo__](#demo)

Updates 2020-Nov-01
* Error handling optimization
* Enhanced read-permission validation
* Toggle capabilities in __TenantSummary__ (avoiding information overload)

Updates 2020-Oct-12
* Adding option to download HTML tables to csv  
![Download CSV](img/downloadcsv450.png)
* Preloading of <a href="https://www.tablefilter.com/" target="_blank">TableFilter</a> removed for __ScopeInsights__ (on poor hardware loading the HTML file took quite long)
* Added column un-select option for some HTML tables
* Performance optimization

Release v4
* Resource information for Management Groups (Resources in all child Subscriptions) in the __ScopeInsights__ section
* Excluded Subscriptions information (whitelisted, disabled, AAD_ QuotaId)
* Bugfixes, Bugfixes, Bugfixes
* Cosmetics and User Experience enhancement
* Performance optimization
* API error handling / retry optimization
* New Parameters `-NoASCSecureScore`, `-NoResourceProvidersDetailed` (see [__Parameters__](#powerShell))

### AzGovViz version 3

* HTML filterable tables
* Resource Types Diagnostics capability check
* ResourceDiagnostics Policy Lifecycle recommendations (experimental)
* Resource Diagnostics Policy Findings
* Resource Provider details
* Policy assignments filter excluded scopes
* Use of deprecated uilt-in Policy definitions
* Subscription QuotaId Whitelist

### AzGovViz version 2

* Optimized user experience for the HTML output
* __TenantSummary__ / selected Management Group scope
* Reflect Tenant, ManagementGroup and Subscription Limits for Azure Governance capabilities
* Some security related best practice highlighting
* More details: Management Groups, Subscriptions, Policy definitions, PolicySet definitions (Initiatives), orphaned Policy definitions, RBAC and Policy related RBAC (DINE MI), orphaned Role definitions, orphaned Role assignments, Blueprints, Subscription State, Subscription QuotaId, Subscription Tags, Azure Scurity Center Secure Score, ResourceGroups count, Resource types and count by region, Limits, Security findings
* Resources / leveraging Azure Resource Graph
* Parameter based output (hierarchy only, 'srubbed' user information and more..)
* HTML version check