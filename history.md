# AzGovViz - Azure Governance Visualizer

go to [AzGovViz Repository](https://github.com/julianhayward/azure-mg-sub-governance-reporting)

## AzGovViz version history

### AzGovViz version 4

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
* preloading of <a href="https://www.tablefilter.com/" target="_blank">TableFilter</a> removed for __ScopeInsights__ (on poor hardware loading the HTML file took quite long)
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