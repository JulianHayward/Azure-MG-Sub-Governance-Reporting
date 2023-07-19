<#
.SYNOPSIS
    This script creates the following files to help better understand and audit your governance setup
    csv file
        Management Groups, Subscriptions, Policy, PolicySet (Initiative), RBAC
    html file
        Management Groups, Subscriptions, Policy, PolicySet (Initiative), RBAC
        The html file uses Java Script and CSS files which are hosted on various CDNs (Content Delivery Network). For details review the BuildHTML region in this script.
    markdown file for use with Azure DevOps Wiki leveraging the Mermaid plugin
        Management Groups, Subscriptions

.DESCRIPTION
    Do you want to get granular insights on your technical Azure Governance implementation? - document it in csv, html and markdown? Azure Governance Visualizer is a PowerShell based script that iterates your Azure Tenants Management Group hierarchy down to Subscription level. It captures most relevant Azure governance capabilities such as Azure Policy, RBAC and Blueprints and a lot more. From the collected data Azure Governance Visualizer provides visibility on your Hierarchy Map, creates a Tenant Summary and builds granular Scope Insights on Management Groups and Subscriptions. The technical requirements as well as the required permissions are minimal.

.PARAMETER ManagementGroupId
    Define the Management Group Id for which the outputs/files should be generated

.PARAMETER CsvDelimiter
    The script outputs a csv file depending on your delimit defaults choose semicolon or comma

.PARAMETER OutputPath
    Full- or relative path

.PARAMETER DoNotShowRoleAssignmentsUserData
    default is to capture the DisplayName and SignInName for RoleAssignments on ObjectType=User; for data protection and security reasons this may not be acceptable

.PARAMETER HierarchyMapOnly
    default is to query all Management groups and Subscription for Governance capabilities, if you use the parameter -HierarchyMapOnly then only the HierarchyMap will be created

.PARAMETER NoMDfCSecureScore
    default is to query all Subscriptions for Azure Microsoft Defender for Cloud Secure Score and summarize Secure Score for Management Groups.

.PARAMETER LimitCriticalPercentage
    default is 80%, this parameter defines the warning level for approaching Limits (e.g. 80% of Role Assignment limit reached) change as per your preference

.PARAMETER SubscriptionQuotaIdWhitelist
    default is 'undefined', this parameter defines the QuotaIds the subscriptions must match so that Azure Governance Visualizer processes them. The script checks if the QuotaId startswith the string that you have put in. Separate multiple strings with comma e.g. MSDN_,EnterpriseAgreement_

.PARAMETER NoPolicyComplianceStates
    use this parameter if policy compliance states should not be queried

.PARAMETER NoResourceDiagnosticsPolicyLifecycle
    use this parameter if Resource Diagnostics Policy Lifecycle recommendations should not be created

.PARAMETER NoAADGroupsResolveMembers
    use this parameter if Azure Active Directory Group memberships should not be resolved for Role assignments where identity type is 'Group'

.PARAMETER AADServicePrincipalExpiryWarningDays
    define Service Principal Secret and Certificate grace period (lifetime below the defined will be marked for warning / default is 14 days)

.PARAMETER NoAzureConsumption
    #obsolete
    use this parameter if Azure Consumption data should not be reported

.PARAMETER DoAzureConsumption
    use this parameter if Azure Consumption data should be reported

.PARAMETER AzureConsumptionPeriod
    use this parameter to define for which time period Azure Consumption data should be gathered; default is 1 day

.PARAMETER NoAzureConsumptionReportExportToCSV
    use this parameter if Azure Consumption data should not be exported (CSV)

.PARAMETER ThrottleLimit
    Leveraging PowerShell Core´s parallel capability you can define the ThrottleLimit (default=5)

.PARAMETER DoTranscript
    Log the console output

.PARAMETER MermaidDirection
    Define the direction the Mermaid based HierarchyMap should be built TD (default) = TopDown (Horizontal), LR = LeftRight (Vertical)

.PARAMETER SubscriptionId4AzContext
    Define the Subscription Id to use for AzContext (default is to use a random Subscription Id)

.PARAMETER NoCsvExport
    Export enriched 'Role assignments' data, enriched 'Policy assignments' data and 'all resources' (subscriptionId, mgPath, resourceType, id, name, location, tags, createdTime, changedTime)

.PARAMETER DoNotIncludeResourceGroupsOnPolicy
    Do not include Policy assignments on ResourceGroups

.PARAMETER DoNotIncludeResourceGroupsAndResourcesOnRBAC
    Do not include Role assignments on ResourceGroups and Resources

.PARAMETER ChangeTrackingDays
    Define the period for Change tracking on newly created and updated custom Policy, PolicySet and RBAC Role definitions and Policy/RBAC Role assignments (default is '14')

.PARAMETER FileTimeStampFormat
    Ddefine the time format for the output files (default is `yyyyMMdd_HHmmss`)

.PARAMETER NoJsonExport
    Enable export of ManagementGroup Hierarchy including all MG/Sub Policy/RBAC definitions, Policy/RBAC assignments and some more relevant information to JSON

.PARAMETER JsonExportExcludeResourceGroups
    JSON Export will not include ResourceGroups (Policy & Role assignments)

.PARAMETER JsonExportExcludeResources
    JSON Export will not include Resources (Role assignments)

.PARAMETER LargeTenant
    A large tenant is a tenant with more than ~500 Subscriptions - the HTML output for large tenants simply becomes too big.
    If the parameter switch is true then the following parameters will be set:
    -PolicyAtScopeOnly $true
    -RBACAtScopeOnly $true
    -NoResourceProvidersAtAll $true
    -NoScopeInsights $true

.PARAMETER PolicyAtScopeOnly
    Removing 'inherited' lines in the HTML file; use this parameter if you run against a larger tenants

.PARAMETER RBACAtScopeOnly
    Removing 'inherited' lines in the HTML file; use this parameter if you run against a larger tenants

.PARAMETER NoResourceProvidersDetailed
    default is to output all ResourceProvider states for all Subscriptions in the TenantSummary. In large Tenants this can become time consuming and may blow off the html file.

.PARAMETER NoResourceProvidersAtAll
    Note if you use parameter -LargeTenant then parameter NoResourceProvidersAtAll will be set to true
    Resource Provider states will not be collected


.PARAMETER NoScopeInsights
    Note if you use parameter -LargeTenant then parameter -NoScopeInsights will be set to true
    Q: Why would you want to do this? A: In larger tenants the ScopeInsights section blows up the html file (up to unusable due to html file size)

.PARAMETER AADGroupMembersLimit
    Defines the limit (default=500) of AAD Group members; For AAD Groups that have more members than the defined limit Group members will not be resolved

.PARAMETER NoResources
    Will speed up the processing time but information like Resource diagnostics capability, resource type stats, UserAssigned Identities assigned to Resources is excluded (featured for large tenants)

.PARAMETER StatsOptOut
    Will opt-out sending stats

.PARAMETER NoSingleSubscriptionOutput
    Single Scope Insights output per Subscription should not be created

.PARAMETER HtmlTableRowsLimit
    Although the parameter -LargeTenant was introduced recently, still the html output may become too large to be processed properly. The new parameter defines the limit of rows - if for the html processing part the limit is reached then the html table will not be created (csv and json output will still be created). Default rows limit is 20.000

.PARAMETER ManagementGroupsOnly
    Collect data only for Management Groups (Subscription data such as e.g. Policy assignments etc. will not be collected)

.PARAMETER ExcludedResourceTypesDiagnosticsCapable
    Resource Types to be excluded from processing analysis for diagnostic settings capability (default: microsoft.web/certificates)

.PARAMETER NoPIMEligibility
    Do not report on PIM (Privileged Identity Management) eligible Role assignments
    Note: this feature requires you to execute as Service Principal with `Application` API permission `PrivilegedAccess.Read.AzureResources`

.PARAMETER PIMEligibilityIgnoreScope
    Ignore the current scope (ManagementGrouId) and get all PIM (Privileged Identity Management) eligible Role assignments
    By default will only report for PIM Elibility for the scope (ManagementGroupId) that was provided. If you use the new switch parameter then PIM Eligibility for all onboarded scopes (Management Groups and Subscriptions) will be reported

.PARAMETER NoPIMEligibilityIntegrationRoleAssignmentsAll
    Prevent integration of PIM eligible assignments with RoleAssignmentsAll (HTML, CSV)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoPIMEligibilityIntegrationRoleAssignmentsAll

.PARAMETER NoALZPolicyVersionChecker
    'Azure Landing Zones (ALZ) Policy Version Checker' for Policy and Set definitions. Azure Governance Visualizer will clone the ALZ GitHub repository and collect the ALZ policy and set definitions history. The ALZ data will be compared with the data from your tenant so that you can get lifecycle management recommendations for ALZ policy and set definitions that already exist in your tenant plus a list of ALZ policy and set definitions that do not exist in your tenant. The 'Azure Landing Zones (ALZ) Policy Version Checker' results will be displayed in the TenantSummary and a CSV export `*_ALZPolicyVersionChecker.csv` will be provided.
    If you do not want to execute the 'Azure Landing Zones (ALZ) Policy Version Checker' feature then use this parameter
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoALZPolicyVersionChecker

.PARAMETER NoDefinitionInsightsDedicatedHTML
    DefinitionInsights will be written to a separate HTML file `*_DefinitionInsights.html`. If you want to keep DefinitionInsights in the main html file then use this parameter
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoDefinitionInsightsDedicatedHTML

.PARAMETER NoStorageAccountAccessAnalysis
    Analysis on Storage Accounts, specially focused on anonymous access.
    If you do not want to execute this feature then use this parameter
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoStorageAccountAccessAnalysis

.PARAMETER StorageAccountAccessAnalysisSubscriptionTags
    If the Storage Account Access Analysis feature is executed with this parameter you can define the subscription tags that should be added to the CSV output
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -StorageAccountAccessAnalysisSubscriptionTags @('Responsible', 'TeamEmail')

.PARAMETER StorageAccountAccessAnalysisStorageAccountTags
    If the Storage Account Access Analysis feature is executed with this parameter you can define the Storage Account (resource) tags that should be added to the CSV output
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -StorageAccountAccessAnalysisStorageAccountTags @('SAResponsible', 'DataOfficer')

.PARAMETER NoNetwork
    Network analysis / Virtual Network, Subnets, Virtual Network Peerings and Private Endpoints
    If you do not want to execute this feature then use this parameter
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoNetwork

.PARAMETER NetworkSubnetIPAddressUsageCriticalPercentage
    Define warning level when ceratin percentage of IP addresses is used (default = 90%)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NetworkSubnetIPAddressUsageCriticalPercentage 96

.EXAMPLE
    Define the ManagementGroup ID
    PS C:\> .\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id>

    Define how the CSV output should be delimited. Valid input is ; or , (semicolon is default)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -CsvDelimiter ","

    Define the outputPath (must exist)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -OutputPath 123

    Define if User information should be scrubbed (default prints Userinformation to the CSV and HTML output)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -DoNotShowRoleAssignmentsUserData

    Define if only the HierarchyMap output should be created. Will ignore the parameters 'LimitCriticalPercentage' and 'DoNotShowRoleAssignmentsUserData' (default queries for Governance capabilities such as policy-, role-, blueprints assignments and more)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -HierarchyMapOnly

    Define if Microsoft Defender for Cloud SecureScore should be queried for Subscriptions and Management Groups
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoMDfCSecureScore

    Define when limits should be highlighted as warning (default is 80 percent)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -LimitCriticalPercentage 90

    Define the QuotaId whitelist by providing strings separated by a comma
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -SubscriptionQuotaIdWhitelist MSDN_,EnterpriseAgreement_

    Define if policy compliance states should be queried
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoPolicyComplianceStates

    Define if Resource Diagnostics Policy Lifecycle recommendations should not be created
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoResourceDiagnosticsPolicyLifecycle

    Define if Azure Active Directory Group memberships should not be resolved for Role assignments where identity type is 'Group'
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoAADGroupsResolveMembers

    Define Service Principal Secret and Certificate grace period (lifetime below the defined will be marked for warning / default is 14 days)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -AADServicePrincipalExpiryWarningDays 30

    #obsolete Define if Azure Consumption data should not be reported
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoAzureConsumption

    Define if Azure Consumption data should be reported
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -DoAzureConsumption

    Define for which time period (days) Azure Consumption data should be gathered; e.g. 14 days; default is 1 day
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -AzureConsumptionPeriod 14

    Define the number of script blocks running in parallel. Leveraging PowerShell Core´s parallel capability you can define the ThrottleLimit (default=5)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -ThrottleLimit 10

    Define if you want to log the console output
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -DoTranscript

    Define the direction the Mermaid based HierarchyMap should be built in Markdown TD = TopDown (Horizontal), LR = LeftRight (Vertical)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -MermaidDirection "LR"

    Define the Subscription Id to use for AzContext (default is to use a random Subscription Id)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -SubscriptionId4AzContext "<your-Subscription-Id>"

    Do not Export enriched 'Role assignments' data, enriched 'Policy assignments' data and 'all resources' (subscriptionId, mgPath, resourceType, id, name, location, tags, createdTime, changedTime)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoCsvExport

    Do not include Policy assignments on ResourceGroups
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -DoNotIncludeResourceGroupsOnPolicy

    Do not include Role assignments on ResourceGroups and Resources
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -DoNotIncludeResourceGroupsAndResourcesOnRBAC

    Define the period for Change tracking on newly created and updated custom Policy, PolicySet and RBAC Role definitions and Policy/RBAC Role assignments (default is '14')
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -ChangeTrackingDays 30

    Define the time format for the output files (default is `yyyyMMdd_HHmmss`)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -FileTimeStampFormat "yyyyMM-dd_HHmm" (default is `yyyyMMdd_HHmmss`)

    Do not enable export of ManagementGroup Hierarchy including all MG/Sub Policy/RBAC definitions, Policy/RBAC assignments and some more relevant information to JSON
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoJsonExport

    JSON Export will not include ResourceGroups (Policy & Role assignments)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -JsonExportExcludeResourceGroups

    JSON Export will not include Resources (Role assignments)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -JsonExportExcludeResources

    A large tenant is a tenant with more than ~500 Subscriptions - the HTML output for large tenants simply becomes too big.
    If the parameter switch is true then the following parameters will be set:
    -PolicyAtScopeOnly $true
    -RBACAtScopeOnly $true
    - NoResourceProvidersAtAll $true
    -NoScopeInsights $true
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -LargeTenant

    Removing 'inherited' lines in the HTML file for 'Policy Assignments'; use this parameter if you run against a larger tenants
    Note if you use parameter -LargeTenant then parameter -PolicyAtScopeOnly will be set to true
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -PolicyAtScopeOnly

    Removing 'inherited' lines in the HTML file for 'Role Assignments'; use this parameter if you run against a larger tenants
    Note if you use parameter -LargeTenant then parameter -RBACAtScopeOnly will be set to true
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -RBACAtScopeOnly

    Define if a detailed summary on Resource Provider states per Subscription should be created in the TenantSummary section
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoResourceProvidersDetailed

    Define if Resource Provider states should be collected
    Note if you use parameter -LargeTenant then parameter -NoResourceProvidersAtAll will be set to true
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoResourceProvidersAtAll

    Define if ScopeInsights should be created or not. Q: Why would you want to do this? A: In larger tenants the ScopeInsights section blows up the html file (up to unusable due to html file size)
    Note if you use parameter -LargeTenant then parameter -NoScopeInsights will be set to true
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoScopeInsights

    Defines the limit (default=500) of AAD Group members; For AAD Groups that have more members than the defined limit Group members will not be resolved
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -AADGroupMembersLimit 750

    Will speed up the processing time but information like Resource diagnostics capability, resource type stats, UserAssigned Identities assigned to Resources is excluded (featured for large tenants)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoResources

    Will opt-out sending stats
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -StatsOptOut

    Will not create a single Scope Insights output per Subscription
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoSingleSubscriptionOutput

    Although the parameter -LargeTenant was introduced recently, still the html output may become too large to be processed properly. The new parameter defines the limit of rows - if for the html processing part the limit is reached then the html table will not be created (csv and json output will still be created). Default rows limit is 20.000
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -HtmlTableRowsLimit 23077

    Define if data should be collected for Management Groups only (Subscription data such as e.g. Policy assignments etc. will not be collected)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -ManagementGroupsOnly

    Define Resource Types to be excluded from processing analysis for diagnostic settings capability (default: microsoft.web/certificates)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -ExcludedResourceTypesDiagnosticsCapable @('microsoft.web/certificates')

    Define if report on PIM (Privileged Identity Management) eligible Role assignments should be created. Note: this feature requires you to execute as Service Principal with `Application` API permission `PrivilegedAccess.Read.AzureResources`
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoPIMEligibility

    Define if the current scope (ManagementGroupId) should be ignored and therefore and get all PIM (Privileged Identity Management) eligible Role assignments. Note: this feature requires you to execute as Service Principal with `Application` API permission `PrivilegedAccess.Read.AzureResources`
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -PIMEligibilityIgnoreScope

    Define if PIM Eligible assignments should not be integrated with RoleAssignmentsAll outputs (HTML, CSV)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoPIMEligibilityIntegrationRoleAssignmentsAll

    Define if the 'Azure Landing Zones (ALZ) Policy Version Checker' feature should not be executed
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoALZPolicyVersionChecker

    Define if DefinitionInsights should not be written to a seperate html file (*_DefinitionInsights.html)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoDefinitionInsightsDedicatedHTML

    Define if Storage Account Access Analysis (focus on anonymous access) should be executed
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoStorageAccountAccessAnalysis
    Additionally you can define Subscription and/or Storage Account Tag names that should be added to the CSV output per Storage Account
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> --StorageAccountAccessAnalysisSubscriptionTags @('Responsible', 'TeamEmail') -StorageAccountAccessAnalysisStorageAccountTags @('SAResponsible', 'DataOfficer')

    Define if Network analysis / Virtual Network and Virtual Network Peerings should not be executed
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NoNetwork

    Define warning level when ceratin percentage of IP addresses is used (default = 90%)
    PS C:\>.\AzGovVizParallel.ps1 -ManagementGroupId <your-Management-Group-Id> -NetworkSubnetIPAddressUsageCriticalPercentage 96

.NOTES
    AUTHOR: Julian Hayward - Customer Engineer - Customer Success Unit | Azure Infrastucture/Automation/Devops/Governance | Microsoft

.LINK
    https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting (aka.ms/AzGovViz)
    https://github.com/microsoft/CloudAdoptionFramework/tree/master/govern/AzureGovernanceVisualizer
    Please note that while being developed by a Microsoft employee, Azure Governance Visualizer is not a Microsoft service or product. Azure Governance Visualizer is a personal/community driven project, there are none implicit or explicit obligations related to this project, it is provided 'as is' with no warranties and confer no rights.
#>

[CmdletBinding()]
Param
(
    [string]
    $Product = 'AzGovViz',

    [string]
    $AzAPICallVersion = '1.1.72',

    [string]
    $ProductVersion = '6.3.0',

    [string]
    $GithubRepository = 'aka.ms/AzGovViz',

    [string]
    $ScriptPath = 'pwsh', #e.g. 'myfolder\pwsh'

    [string]
    $ManagementGroupId,

    [switch]
    $AzureDevOpsWikiAsCode, #deprecated - Based on environment variables the script will detect the code run platform

    [switch]
    $DebugAzAPICall,

    [switch]
    $NoCsvExport,

    [string]
    [parameter(ValueFromPipeline)][ValidateSet(';', ',')][string]$CsvDelimiter = ';',

    [switch]
    $CsvExportUseQuotesAsNeeded,

    [string]
    $OutputPath,

    [switch]
    $DoNotShowRoleAssignmentsUserData,

    [switch]
    $HierarchyMapOnly,

    [string]
    $HierarchyMapOnlyCustomDataJSON,

    [Alias('NoASCSecureScore')]
    [switch]
    $NoMDfCSecureScore,

    [switch]
    $NoResourceProvidersDetailed,

    [switch]
    $NoResourceProvidersAtAll,

    [int]
    $LimitCriticalPercentage = 80,

    [array]
    $SubscriptionQuotaIdWhitelist = @('undefined'),

    [switch]
    $NoPolicyComplianceStates,

    [switch]
    $NoResourceDiagnosticsPolicyLifecycle,

    [switch]
    $NoAADGroupsResolveMembers,

    [int]
    $AADServicePrincipalExpiryWarningDays = 14,

    [switch]
    $NoAzureConsumption, #obsolete

    [switch]
    $DoAzureConsumption,

    [int]
    $AzureConsumptionPeriod = 1,

    [switch]
    $NoAzureConsumptionReportExportToCSV,

    [switch]
    $DoTranscript,

    [int]
    $HtmlTableRowsLimit = 20000, #HTML TenantSummary may become unresponsive depending on client device performance. A recommendation will be shown to use the CSV file instead of opening the TF table

    [int]
    $ThrottleLimit = 10,

    [Alias('ExludedResourceTypesDiagnosticsCapable')]
    [array]
    $ExcludedResourceTypesDiagnosticsCapable = @('microsoft.web/certificates', 'microsoft.chaos/chaosexperiments'),

    [switch]
    $DoNotIncludeResourceGroupsOnPolicy,

    [switch]
    $DoNotIncludeResourceGroupsAndResourcesOnRBAC,

    [Alias('AzureDevOpsWikiHierarchyDirection')]
    [parameter(ValueFromPipeline)][ValidateSet('TD', 'LR')][string]$MermaidDirection = 'TD',

    [string]
    $SubscriptionId4AzContext = 'undefined',

    [int]
    $ChangeTrackingDays = 14,

    [string]
    $FileTimeStampFormat = 'yyyyMMdd_HHmmss',

    [switch]
    $NoJsonExport,

    [switch]
    $JsonExportExcludeResourceGroups,

    [switch]
    $JsonExportExcludeResources,

    [switch]
    $LargeTenant,

    [switch]
    $NoScopeInsights,

    [int]
    $AADGroupMembersLimit = 500,

    [switch]
    $PolicyAtScopeOnly,

    [switch]
    $RBACAtScopeOnly,

    [switch]
    $NoResources,

    [switch]
    $StatsOptOut,

    [switch]
    $NoSingleSubscriptionOutput,

    [switch]
    $ManagementGroupsOnly,

    [string]
    $DirectorySeparatorChar = [IO.Path]::DirectorySeparatorChar,

    [switch]
    $ShowMemoryUsage,

    [int]
    $CriticalMemoryUsage = 99,

    [switch]
    $DoPSRule,

    [switch]
    $PSRuleFailedOnly,

    [string]
    $PSRuleVersion,

    [switch]
    $NoPIMEligibility,

    [switch]
    $PIMEligibilityIgnoreScope,

    [switch]
    $NoPIMEligibilityIntegrationRoleAssignmentsAll,

    [switch]
    $NoALZPolicyVersionChecker,

    [switch]
    $NoDefinitionInsightsDedicatedHTML,

    [switch]
    $NoStorageAccountAccessAnalysis,

    [array]
    $StorageAccountAccessAnalysisSubscriptionTags = @('undefined'),

    [array]
    $StorageAccountAccessAnalysisStorageAccountTags = @('undefined'),

    [switch]
    $GitHubActionsOIDC,

    [switch]
    $NoNetwork,

    [int]
    $NetworkSubnetIPAddressUsageCriticalPercentage = 80,

    [switch]
    $ShowRunIdentifier,

    #https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#role-based-access-control-limits
    [int]
    $LimitRBACCustomRoleDefinitionsTenant = 5000,

    [int]
    $LimitRBACRoleAssignmentsManagementGroup = 500,

    #https://docs.microsoft.com/en-us/azure/governance/policy/overview#maximum-count-of-azure-policy-objects
    [int]
    $LimitPOLICYPolicyAssignmentsManagementGroup = 200,

    [int]
    $LimitPOLICYPolicyAssignmentsSubscription = 200,

    [int]
    $LimitPOLICYPolicyDefinitionsScopedManagementGroup = 500,

    [int]
    $LimitPOLICYPolicyDefinitionsScopedSubscription = 500,

    [int]
    $LimitPOLICYPolicySetAssignmentsManagementGroup = 200,

    [int]
    $LimitPOLICYPolicySetAssignmentsSubscription = 200,

    [int]
    $LimitPOLICYPolicySetDefinitionsScopedTenant = 2500,

    [int]
    $LimitPOLICYPolicySetDefinitionsScopedManagementGroup = 200,

    [int]
    $LimitPOLICYPolicySetDefinitionsScopedSubscription = 200,

    #https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#subscription-limits
    [int]
    $LimitResourceGroups = 980,

    [int]
    $LimitTagsSubscription = 50,

    [array]
    $MSTenantIds = @('2f4a9838-26b7-47ee-be60-ccc1fdec5953', '33e01921-4d64-4f8c-a055-5bdaffd5e33d'),

    [array]
    $ValidPolicyEffects = @('append', 'audit', 'auditIfNotExists', 'deny', 'deployIfNotExists', 'modify', 'manual', 'disabled', 'EnforceRegoPolicy', 'enforceSetting')
)

$Error.clear()
$ErrorActionPreference = 'Stop'
#removeNoise
$ProgressPreference = 'SilentlyContinue'
Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings 'true'

#start
$startAzGovViz = Get-Date
$startTime = Get-Date -Format 'dd-MMM-yyyy HH:mm:ss'
Write-Host "Start Azure Governance Visualizer $($startTime) (#$($ProductVersion))"

if ($ManagementGroupId -match ' ') {
    Write-Host "Provided Management Group ID: '$($ManagementGroupId)'" -ForegroundColor Yellow
    Write-Host 'The Management Group ID may not contain spaces - provide the Management Group ID, not the displayName.' -ForegroundColor DarkRed
    throw 'Management Group ID validation failed!'
}

#region Functions
. ".\$($ScriptPath)\functions\validateLeastPrivilegeForUser.ps1"
. ".\$($ScriptPath)\functions\getPolicyRemediation.ps1"
. ".\$($ScriptPath)\functions\getPolicyHash.ps1"
. ".\$($ScriptPath)\functions\detectPolicyEffect.ps1"
. ".\$($ScriptPath)\functions\exportResourceLocks.ps1"
. ".\$($ScriptPath)\functions\processHierarchyMapOnlyCustomData.ps1"
. ".\$($ScriptPath)\functions\processPrivateEndpoints.ps1"
. ".\$($ScriptPath)\functions\processNetwork.ps1"
. ".\$($ScriptPath)\functions\processStorageAccountAnalysis.ps1"
. ".\$($ScriptPath)\functions\processALZPolicyVersionChecker.ps1"
. ".\$($ScriptPath)\functions\getPIMEligible.ps1"
. ".\$($ScriptPath)\functions\testGuid.ps1"
. ".\$($ScriptPath)\functions\apiCallTracking.ps1"
. ".\$($ScriptPath)\functions\addRowToTable.ps1"
. ".\$($ScriptPath)\functions\testPowerShellVersion.ps1"
. ".\$($ScriptPath)\functions\setOutput.ps1"
. ".\$($ScriptPath)\functions\setTranscript.ps1"
. ".\$($ScriptPath)\functions\verifyModules3rd.ps1"
. ".\$($ScriptPath)\functions\checkAzGovVizVersion.ps1"
. ".\$($ScriptPath)\functions\handleCloudEnvironment.ps1"
. ".\$($ScriptPath)\functions\addHtParameters.ps1"
. ".\$($ScriptPath)\functions\selectMg.ps1"
. ".\$($ScriptPath)\functions\validateAccess.ps1"
. ".\$($ScriptPath)\functions\getEntities.ps1"
. ".\$($ScriptPath)\functions\setBaseVariablesMG.ps1"
. ".\$($ScriptPath)\functions\getTenantDetails.ps1"
. ".\$($ScriptPath)\functions\getDefaultManagementGroup.ps1"
. ".\$($ScriptPath)\functions\runInfo.ps1"
. ".\$($ScriptPath)\functions\processHierarchyMapOnly.ps1"
. ".\$($ScriptPath)\functions\getSubscriptions.ps1"
. ".\$($ScriptPath)\functions\detailSubscriptions.ps1"
. ".\$($ScriptPath)\functions\getOrphanedResources.ps1"
. ".\$($ScriptPath)\functions\getMDfCSecureScoreMG.ps1"
. ".\$($ScriptPath)\functions\getConsumption.ps1"
. ".\$($ScriptPath)\functions\cacheBuiltIn.ps1"
. ".\$($ScriptPath)\functions\prepareData.ps1"
. ".\$($ScriptPath)\functions\getGroupmembers.ps1"
. ".\$($ScriptPath)\functions\processAADGroups.ps1"
. ".\$($ScriptPath)\functions\processApplications.ps1"
. ".\$($ScriptPath)\functions\processManagedIdentities.ps1"
. ".\$($ScriptPath)\functions\createTagList.ps1"
. ".\$($ScriptPath)\functions\getResourceDiagnosticsCapability.ps1"
. ".\$($ScriptPath)\functions\getFileNaming.ps1"
. ".\$($ScriptPath)\functions\resolveObjectIds.ps1"
. ".\$($ScriptPath)\functions\namingValidation.ps1"
. ".\$($ScriptPath)\functions\removeInvalidFileNameChars.ps1"
. ".\$($ScriptPath)\functions\addIndexNumberToArray.ps1"
. ".\$($ScriptPath)\functions\processDiagramMermaid.ps1"
. ".\$($ScriptPath)\functions\buildMD.ps1"
. ".\$($ScriptPath)\functions\buildTree.ps1"
. ".\$($ScriptPath)\functions\buildJSON.ps1"
. ".\$($ScriptPath)\functions\buildPolicyAllJSON.ps1"
. ".\$($ScriptPath)\functions\stats.ps1"
#Region dataCollectionFunctions
. ".\$($ScriptPath)\functions\dataCollection\dataCollectionFunctions.ps1"
. ".\$($ScriptPath)\functions\processDataCollection.ps1"
. ".\$($ScriptPath)\functions\exportBaseCSV.ps1"
. ".\$($ScriptPath)\functions\html\htmlFunctions.ps1"
. ".\$($ScriptPath)\functions\processTenantSummary.ps1"
. ".\$($ScriptPath)\functions\processDefinitionInsights.ps1"
. ".\$($ScriptPath)\functions\processScopeInsightsMgOrSub.ps1"
. ".\$($ScriptPath)\functions\showMemoryUsage.ps1"
#EndRegion dataCollectionFunctions
#endregion Functions

$funcAddRowToTable = $function:addRowToTable.ToString()
$funcGetGroupmembers = $function:GetGroupmembers.ToString()
$funcResolveObjectIds = $function:ResolveObjectIds.ToString()
$funcNamingValidation = $function:NamingValidation.ToString()
$funcTestGuid = $function:testGuid.ToString()
$funcDetectPolicyEffect = $function:detectPolicyEffect.ToString()
$funcGetPolicyHash = $function:getPolicyHash.ToString()

if ($HierarchyMapOnly -and $HierarchyMapOnlyCustomDataJSON) {
    processHierarchyMapOnlyCustomData
    Write-Host 'Skipping PowerShell version check /Using custom data (`$HierarchyMapOnlyCustomDataJSON)'
}
else {
    testPowerShellVersion
}

showMemoryUsage

$outputPathGiven = $OutputPath
setOutput
if ($DoTranscript) {
    setTranscript
}

#region PSRule paused
if ($DoPSRule) {
    Write-Host ''
    Write-Host ' * * * CHANGE: PSRule for Azure * * *' -ForegroundColor Magenta
    Write-Host 'PSRule integration has been paused'
    Write-Host 'Azure Governance Visualizer leveraged the Invoke-PSRule cmdlet, but there are certain [resource types](https://github.com/Azure/PSRule.Rules.Azure/blob/ab0910359c1b9826d8134041d5ca997f6195fc58/src/PSRule.Rules.Azure/PSRule.Rules.Azure.psm1#L1582) where also child resources need to be queried to achieve full rule evaluation.'
    $DoPSRule = $false
    Write-Host ' * * * * * * * * * * * * * * * * * * * * * *' -ForegroundColor Magenta
    Write-Host ''
}
#endregion PSRule paused

#region verifyModules3rd
$modules = [System.Collections.ArrayList]@()
$null = $modules.Add([PSCustomObject]@{
        ModuleName         = 'AzAPICall'
        ModuleVersion      = $AzAPICallVersion
        ModuleProductName  = 'AzAPICall'
        ModulePathPipeline = 'AzAPICallModule'
    })

if ($DoPSRule) {

    <#temporary workaround / PSRule/Azure DevOps Az.Resources module requirements
    if ($env:SYSTEM_TEAMPROJECTID -and $env:BUILD_REPOSITORY_ID) {
        $PSRuleVersion = '1.14.3'
        Write-Host "Running in Azure DevOps; enforce PSRule version '$PSRuleVersion' (Az.Resources dependency on latest PSRule)"
    }
    #>

    $null = $modules.Add([PSCustomObject]@{
            ModuleName         = 'PSRule.Rules.Azure'
            ModuleVersion      = $PSRuleVersion
            ModuleProductName  = 'PSRule'
            ModulePathPipeline = 'PSRuleModule'
        })
}
verifyModules3rd -modules $modules
#endregion verifyModules3rd

#Region initAZAPICall
Write-Host "Initialize 'AzAPICall'"
$parameters4AzAPICallModule = @{
    DebugAzAPICall           = $DebugAzAPICall
    SubscriptionId4AzContext = $SubscriptionId4AzContext
    GithubRepository         = $GithubRepository
}
$azAPICallConf = initAzAPICall @parameters4AzAPICallModule
Write-Host " Initialize 'AzAPICall' succeeded" -ForegroundColor Green
#EndRegion initAZAPICall

#region required AzAPICall version
if (-not ([System.Version]"$($azapicallConf['htParameters'].azAPICallModuleVersion)" -ge [System.Version]'1.1.72')) {
    Write-Host 'AzAPICall version check failed -> https://aka.ms/AzAPICall; https://www.powershellgallery.com/packages/AzAPICall'
    throw 'This version of Azure Governance Visualizer requires AzAPICall module version 1.1.72 or greater'
}
else {
    Write-Host "AzAPICall module version requirement check succeeded: 1.1.72 or greater - current: $($azapicallConf['htParameters'].azAPICallModuleVersion) " -ForegroundColor Green
}
#endregion required AzAPICall version

checkAzGovVizVersion

#region promptNewAzGovVizVersionAvailable
if ($azGovVizNewerVersionAvailable) {
    if (-not $azAPICallConf['htParameters'].onAzureDevOpsOrGitHubActions) {
        Write-Host ''
        Write-Host " * * * This Azure Governance Visualizer version ($ProductVersion) is not up to date. Get the latest Azure Governance Visualizer version ($azGovVizVersionOnRepositoryFull)! * * *" -ForegroundColor Green
        Write-Host 'Check the Azure Governance Visualizer history: https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting/blob/master/history.md'
        Write-Host ' * * * * * * * * * * * * * * * * * * * * * *' -ForegroundColor Green
        Pause
    }
}
#endregion promptNewAzGovVizVersionAvailable

if (-not $HierarchyMapOnly) {
    handleCloudEnvironment
}

if (-not $HierarchyMapOnly) {
    <# PSRule paused
    #region recommendPSRule
    if (-not $azAPICallConf['htParameters'].onAzureDevOpsOrGitHubActions) {
        if (-not $DoPSRule) {
            Write-Host ''
            Write-Host ' * * * RECOMMENDATION: PSRule for Azure * * *' -ForegroundColor Magenta
            Write-Host "Parameter -DoPSRule == '$DoPSRule'"
            Write-Host "'PSRule for Azure' based ouputs provide aggregated Microsoft Azure Well-Architected Framework (WAF) aligned resource analysis results including guidance for remediation."
            Write-Host 'Consider running Azure Governance Visualizer with the parameter -DoPSRule (example: .\pwsh\AzGovVizParallel.ps1 -DoPSRule)'
            Write-Host ' * * * * * * * * * * * * * * * * * * * * * *' -ForegroundColor Magenta
            Pause
        }
    }
    #endregion recommendPSRule
    #>

    #region hintPIMEligibility
    if ($azAPICallConf['htParameters'].accountType -eq 'User') {
        if (-not $NoPIMEligibility) {
            Write-Host ''
            Write-Host ' * * * HINT: PIM (Privileged Identity Management) Eligibility reporting * * *' -ForegroundColor DarkBlue
            Write-Host "Parameter -NoPIMEligibility == '$NoPIMEligibility'"
            Write-Host "Executing principal accountType: '$($azAPICallConf['htParameters'].accountType)'"
            Write-Host "PIM Eligibility reporting requires to execute the script as ServicePrincipal. API Permission 'PrivilegedAccess.Read.AzureResources' is required"
            Write-Host "For this run we switch the parameter -NoPIMEligibility from '$NoPIMEligibility' to 'True'"
            $NoPIMEligibility = $true
            Write-Host "Parameter -NoPIMEligibility == '$NoPIMEligibility'"
            Write-Host ' * * * * * * * * * * * * * * * * * * * * * *' -ForegroundColor DarkBlue
            Pause
        }
    }
    #endregion hintPIMEligibility
}

#region delimiterOpposite
if ($CsvDelimiter -eq ';') {
    $CsvDelimiterOpposite = ','
}
if ($CsvDelimiter -eq ',') {
    $CsvDelimiterOpposite = ';'
}
#endregion delimiterOpposite

#region runDataCollection

#run
if ($HierarchyMapOnly -and $HierarchyMapOnlyCustomDataJSON) {
    Write-Host 'Skipping Access validation /Using custom data (`$HierarchyMapOnlyCustomDataJSON)'
    Write-Host 'Skipping addHtParameters /Using custom data (`$HierarchyMapOnlyCustomDataJSON)'
}
else {
    addHtParameters
    validateAccess
}

getFileNaming

Write-Host "Running Azure Governance Visualizer for ManagementGroupId: '$ManagementGroupId'" -ForegroundColor Yellow

$newTable = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$htMgDetails = @{}
$htSubDetails = @{}

if (-not $HierarchyMapOnly) {
    #helper ht / collect results /save some time
    $htCacheDefinitionsPolicy = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{} #[System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htCacheDefinitionsPolicySet = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{} #[System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htCacheDefinitionsRole = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{} #[System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htCacheDefinitionsBlueprint = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{} #[System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htRoleDefinitionIdsUsedInPolicy = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htRoleAssignmentsPIM = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{} #[System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htPoliciesUsedInPolicySets = @{}
    $htSubscriptionTags = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htCacheAssignmentsPolicyOnResourceGroupsAndResources = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htCacheAssignmentsRole = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htCacheAssignmentsRBACOnResourceGroupsAndResources = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htCacheAssignmentsBlueprint = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htCacheAssignmentsPolicy = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htCachePolicyComplianceMG = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htCachePolicyComplianceSUB = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htCachePolicyComplianceResponseTooLargeMG = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htCachePolicyComplianceResponseTooLargeSUB = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $outOfScopeSubscriptions = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $htOutOfScopeSubscriptions = @{}
    if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
        $htManagementGroupsCost = @{}
        $htAzureConsumptionSubscriptions = @{}
        $arrayConsumptionData = [System.Collections.ArrayList]@()
        $arrayTotalCostSummary = @()
        $azureConsumptionStartDate = ((Get-Date).AddDays( - ($($AzureConsumptionPeriod)))).ToString('yyyy-MM-dd')
        $azureConsumptionEndDate = ((Get-Date).AddDays(-1)).ToString('yyyy-MM-dd')
    }
    $customDataCollectionDuration = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $htResourceLocks = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htAllTagList = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htAllTagList.AllScopes = @{} #[System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htAllTagList.Subscription = @{} #[System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htAllTagList.ResourceGroup = @{} #[System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htAllTagList.Resource = @{} #[System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $arrayTagList = [System.Collections.ArrayList]@()
    $htSubscriptionTagList = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htPolicyAssignmentExemptions = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htUserTypesGuest = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $resourcesAll = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $resourcesIdsAll = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $resourceGroupsAll = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $htResourceProvidersAll = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $arrayFeaturesAll = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $htResourceTypesUniqueResource = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $arrayDataCollectionProgressMg = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $arrayDataCollectionProgressSub = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $arraySubResourcesAddArrayDuration = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $arrayDiagnosticSettingsMgSub = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $htDiagnosticSettingsMgSub = @{}
    $htDiagnosticSettingsMgSub.mg = @{}
    $htDiagnosticSettingsMgSub.sub = @{}
    $htMgAtScopePolicyAssignments = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htMgAtScopePoliciesScoped = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htMgAtScopeRoleAssignments = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htMgASCSecureScore = @{}
    $htConsumptionExceptionLog = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htConsumptionExceptionLog.Mg = @{} #[System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htConsumptionExceptionLog.Sub = @{} #[System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htRoleAssignmentsFromAPIInheritancePrevention = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htNamingValidation = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htNamingValidation.PolicyAssignment = @{} #[System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htNamingValidation.Policy = @{} #[System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htNamingValidation.PolicySet = @{} #[System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htNamingValidation.Role = @{} #[System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htNamingValidation.Subscription = @{} #[System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htNamingValidation.ManagementGroup = @{} #[System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htPrincipals = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htServicePrincipals = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htDailySummary = @{}
    $arrayDefenderPlans = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $arrayDefenderPlansSubscriptionsSkipped = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $arrayUserAssignedIdentities4Resources = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $htSubscriptionsRoleAssignmentLimit = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    if ($azAPICallConf['htParameters'].NoMDfCSecureScore -eq $false) {
        $htMgASCSecureScore = @{}
    }
    $htManagedIdentityForPolicyAssignment = @{}
    $htPolicyAssignmentManagedIdentity = @{}
    $htManagedIdentityDisplayName = @{}
    $htAppDetails = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    if (-not $NoAADGroupsResolveMembers) {
        $htAADGroupsDetails = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
        $htAADGroupsExeedingMemberLimit = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
        $arrayGroupRoleAssignmentsOnServicePrincipals = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        $arrayGroupRequestResourceNotFound = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        $arrayProgressedAADGroups = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    }
    if ($DoAzureConsumption) {
        $allConsumptionData = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    }
    $arrayPsRule = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $arrayPSRuleTracking = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $htClassicAdministrators = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $arrayOrphanedResources = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $arrayPIMEligible = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $alzPolicies = @{}
    $alzPolicySets = @{}
    $alzPolicyHashes = @{}
    $alzPolicySetHashes = @{}
    $htDoARMRoleAssignmentScheduleInstances = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htDoARMRoleAssignmentScheduleInstances.Do = $true
    $storageAccounts = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $arrayStorageAccountAnalysisResults = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $htDefenderEmailContacts = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $arrayVNets = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $arrayPrivateEndPoints = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $arrayPrivateEndPointsFromResourceProperties = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $htUnknownTenantsForSubscription = @{}
    $htResourcePropertiesConvertfromJSONFailed = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    #$htResourcesWithProperties = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $htResourceProvidersRef = @{}
    $htAvailablePrivateEndpointTypes = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $arrayAdvisorScores = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $htHashesBuiltInPolicy = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable)) #@{}
    $arrayCustomBuiltInPolicyParity = [System.Collections.ArrayList]@()
    $arrayRemediatable = [System.Collections.ArrayList]@()
}

if (-not $HierarchyMapOnly) {
    if (-not $NoALZPolicyVersionChecker) {
        switch ($azAPICallConf['checkContext'].Environment.Name) {
            'Azurecloud' {
                Write-Host "'Azure Landing Zones (ALZ) Policy Version Checker' feature supported for Cloud environment '$($azAPICallConf['checkContext'].Environment.Name)'"
                processALZPolicyVersionChecker
            }
            'AzureChinaCloud' {
                Write-Host "'Azure Landing Zones (ALZ) Policy Version Checker' feature supported for Cloud environment '$($azAPICallConf['checkContext'].Environment.Name)'"
                processALZPolicyVersionChecker
            }
            'AzureUSGovernment' {
                Write-Host "'Azure Landing Zones (ALZ) Policy Version Checker' feature supported for Cloud environment '$($azAPICallConf['checkContext'].Environment.Name)'"
                processALZPolicyVersionChecker
            }
            Default {
                Write-Host "'Azure Landing Zones (ALZ) Policy Version Checker' feature NOT supported for Cloud environment '$($azAPICallConf['checkContext'].Environment.Name)'"
                Write-Host "Setting parameter -NoALZPolicyVersionChecker to 'true'"
                $NoALZPolicyVersionChecker = $true
            }
        }
    }
    else {
        #Write-Host "Skipping 'Azure Landing Zones (ALZ) Policy Version Checker' (parameter -NoALZPolicyVersionChecker = $NoALZPolicyVersionChecker)"
    }
}

if ($HierarchyMapOnly -and $HierarchyMapOnlyCustomDataJSON) {
    $script:hierarchyLevel = -1
    $script:mgSubPathTopMg = "$ManagementGroupId"
    $script:getMgParentId = "'$ManagementGroupId'"
    $script:getMgParentName = 'Tenant Root'
    $script:mermaidprnts = "'$getMgParentId',$getMgParentId"
}
else {
    getSubscriptions
    getEntities
    showMemoryUsage
    setBaseVariablesMG
}

if ($HierarchyMapOnly -and $HierarchyMapOnlyCustomDataJSON) {
}
else {
    if ($azAPICallConf['htParameters'].accountType -eq 'User') {
        getTenantDetails
    }

    getDefaultManagementGroup
}

runInfo

if (-not $HierarchyMapOnly) {

    #getSubscriptions
    detailSubscriptions
    showMemoryUsage

    if ($azAPICallConf['htParameters'].NoMDfCSecureScore -eq $false) {
        getMDfCSecureScoreMG
    }

    if ($azAPICallConf['htParameters'].DoAzureConsumption -eq $true) {
        getConsumption
    }

    getOrphanedResources
    showMemoryUsage
    cacheBuiltIn
    showMemoryUsage

    if (-not $ManagementGroupsOnly) {
        #region Getting Tenant Resource Providers
        $startGetRPs = Get-Date
        $currentTask = 'Getting Tenant Resource Providers'
        Write-Host $currentTask
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers?api-version=2021-04-01"
        $method = 'GET'
        $resourceProviders = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -caller 'CustomDataCollection'

        Write-Host " Returned $($resourceProviders.Count) Resource Provider namespaces"
        foreach ($resourceProvider in $resourceProviders) {
            foreach ($resourceProviderResourceType in $resourceProvider.resourceTypes) {
                $APIs = $resourceProviderResourceType.apiVersions | Sort-Object -Descending
                $htResourceProvidersRef.("$($resourceProvider.nameSpace)/$($resourceProviderResourceType.resourceType)") = @{}
                $htResourceProvidersRef.("$($resourceProvider.nameSpace)/$($resourceProviderResourceType.resourceType)").APILatest = $APIs | Select-Object -First 1
                $htResourceProvidersRef.("$($resourceProvider.nameSpace)/$($resourceProviderResourceType.resourceType)").APIs = $APIs
                if (-not [string]::IsNullOrWhiteSpace($resourceProviderResourceType.defaultApiVersion)) {
                    $htResourceProvidersRef.("$($resourceProvider.nameSpace)/$($resourceProviderResourceType.resourceType)").APIDefault = $resourceProviderResourceType.defaultApiVersion
                }
            }
        }
        Write-Host " Created ht for $($htResourceProvidersRef.Keys.Count) Resource/sub types"
        $endGetRPs = Get-Date
        Write-Host "Getting Tenant Resource Providers duration: $((New-TimeSpan -Start $startGetRPs -End $endGetRPs).TotalMinutes) minutes ($((New-TimeSpan -Start $startGetRPs -End $endGetRPs).TotalSeconds) seconds)"
        #endregion Getting Tenant Resource Providers

        #region Getting Available Private Endpoint Types
        $startGetAvailablePrivateEndpointTypes = Get-Date

        $currentTask = 'Getting Locations'
        Write-Host $currentTask
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($azAPICallConf['checkcontext'].Subscription.Id)/locations?api-version=2020-01-01"
        $method = 'GET'
        $getLocations = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask
        Write-Host " Returned $($getLocations.Count) locations"

        Write-Host "Getting 'Available Private Endpoint Types' for $($getLocations.Count) locations"
        $getLocations | ForEach-Object -Parallel {
            $location = $_
            $azAPICallConf = $using:azAPICallConf
            $htAvailablePrivateEndpointTypes = $using:htAvailablePrivateEndpointTypes
            $currentTask = "Getting 'Available Private Endpoint Types' for location $($location.name)"
            #Write-Host $currentTask
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($azAPICallConf['checkcontext'].Subscription.Id)/providers/Microsoft.Network/locations/$($location.name)/availablePrivateEndpointTypes?api-version=2022-07-01"
            $method = 'GET'
            $availablePrivateEndpointTypes = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask -skipOnErrorCode 400, 409
            Write-Host " Returned $($availablePrivateEndpointTypes.Count) 'Available Private Endpoint Types' for location $($location.name)"
            foreach ($availablePrivateEndpointType in $availablePrivateEndpointTypes) {
                if (-not $htAvailablePrivateEndpointTypes.(($availablePrivateEndpointType.resourceName).ToLower())) {
                    $script:htAvailablePrivateEndpointTypes.(($availablePrivateEndpointType.resourceName).ToLower()) = @{}
                }
            }
        } -ThrottleLimit $ThrottleLimit

        if ($htAvailablePrivateEndpointTypes.Keys.Count -gt 0) {
            Write-Host " Created ht for $($htAvailablePrivateEndpointTypes.Keys.Count) 'Available Private Endpoint Types'"
        }
        else {
            $throwmsg = "$($htAvailablePrivateEndpointTypes.Keys.Count) 'Available Private Endpoint Types' - Please use another Subscription for the AzContext (current subscriptionId: '$($azAPICallConf['checkcontext'].Subscription.Id)') -> use parameter: -SubscriptionId4AzContext '<subscriptionId>'"
            Write-Host $throwmsg -ForegroundColor DarkRed
            Throw $throwmsg
        }

        $endGetAvailablePrivateEndpointTypes = Get-Date
        Write-Host "Getting 'Available Private Endpoint Types' duration: $((New-TimeSpan -Start $startGetAvailablePrivateEndpointTypes -End $endGetAvailablePrivateEndpointTypes).TotalMinutes) minutes ($((New-TimeSpan -Start $startGetAvailablePrivateEndpointTypes -End $endGetAvailablePrivateEndpointTypes).TotalSeconds) seconds)"
        #endregion Getting Available Private Endpoint Types
    }

    Write-Host 'Collecting custom data'
    $startDataCollection = Get-Date

    processDataCollection -mgId $ManagementGroupId

    if (-not $ManagementGroupsOnly) {
        exportResourceLocks
    }

    getPolicyRemediation

    if ($arrayAdvisorScores.Count -gt 0) {
        if (-not $NoCsvExport) {
            Write-Host "Exporting AdvisorScores CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_AdvisorScores.csv'"
            $arrayAdvisorScores | Sort-Object -Property subscriptionName, subscriptionId, category | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_AdvisorScores.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
        }
    }

    showMemoryUsage

    if (-not $NoPIMEligibility) {
        getPIMEligible
        showMemoryUsage
    }

    $endDataCollection = Get-Date
    Write-Host "Collecting custom data duration: $((New-TimeSpan -Start $startDataCollection -End $endDataCollection).TotalMinutes) minutes ($((New-TimeSpan -Start $startDataCollection -End $endDataCollection).TotalSeconds) seconds)"

    exportBaseCSV
}
else {
    processHierarchyMapOnly
    exportBaseCSV
}

prepareData
showMemoryUsage

if (-not $HierarchyMapOnly) {

    $rbacBaseQuery = $newTable.where({ -not [String]::IsNullOrEmpty($_.RoleDefinitionName) } ) | Sort-Object -Property RoleIsCustom, RoleDefinitionName | Select-Object -Property Level, Role*, mg*, Subscription*
    $roleAssignmentsUniqueById = $rbacBaseQuery | Sort-Object -Property RoleAssignmentId -Unique

    if (-not $NoAADGroupsResolveMembers) {
        processAADGroups
        showMemoryUsage
    }

    processApplications
    showMemoryUsage

    processManagedIdentities
    showMemoryUsage
    if (-not $ManagementGroupsOnly) {
        createTagList
        showMemoryUsage
    }

    if ($azAPICallConf['htParameters'].NoStorageAccountAccessAnalysis -eq $false) {
        if (-not $ManagementGroupsOnly) {
            processStorageAccountAnalysis
            showMemoryUsage
        }
    }

    if ($azAPICallConf['htParameters'].NoResources -eq $false) {
        if (-not $ManagementGroupsOnly) {
            getResourceDiagnosticsCapability
        }
        showMemoryUsage
    }
}
#endregion runDataCollection

#region createoutputs

#region BuildHTML
$startBuildHTML = Get-Date
Write-Host 'Building HTML'
$html = $null

#getFileNaming

if (-not $HierarchyMapOnly) {
    #region preQueries
    Write-Host ' Building preQueries'
    $startPreQueries = Get-Date

    #region Create Policy/Set helper hash table
    Write-Host '  Create Policy/Set helper hash table'
    $startHelperHt = Get-Date
    $tenantAllPolicySets = ($htCacheDefinitionsPolicySet).Values
    $tenantAllPolicySetsCount = ($tenantAllPolicySets).count
    if ($tenantAllPolicySetsCount -gt 0) {
        foreach ($policySet in $tenantAllPolicySets) {
            $PolicySetPolicyIds = $policySet.PolicySetPolicyIds
            foreach ($PolicySetPolicyId in $PolicySetPolicyIds) {

                if ($policySet.LinkToAzAdvertizer) {
                    $hlperDisplayNameWithOrWithoutLinkToAzAdvertizer = "$($policySet.LinkToAzAdvertizer) ($($policySet.PolicyDefinitionId))"
                }
                else {
                    $hlperDisplayNameWithOrWithoutLinkToAzAdvertizer = "$($policySet.DisplayName) ($($policySet.PolicyDefinitionId))"
                }
                $hlper4CSVOutput = "$($policySet.DisplayName) ($($policySet.PolicyDefinitionId))"
                if (-not $htPoliciesUsedInPolicySets.($PolicySetPolicyId)) {
                    $htPoliciesUsedInPolicySets.($PolicySetPolicyId) = @{}
                    # $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySet = [array]$hlperDisplayNameWithOrWithoutLinkToAzAdvertizer
                    # $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySet4CSV = [array]$hlper4CSVOutput
                    # $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySetIdOnly = [array]($policySet.PolicyDefinitionId)
                    $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySet = [System.Collections.ArrayList]@()
                    $null = $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySet.Add($hlperDisplayNameWithOrWithoutLinkToAzAdvertizer)
                    $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySet4CSV = [System.Collections.ArrayList]@()
                    $null = $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySet4CSV.Add($hlper4CSVOutput)
                    $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySetIdOnly = [System.Collections.ArrayList]@()
                    $null = $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySetIdOnly.Add($policySet.PolicyDefinitionId)
                }
                else {
                    # $array = $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySet
                    # $array += $hlperDisplayNameWithOrWithoutLinkToAzAdvertizer
                    # $arrayCSV = $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySet4CSV
                    # $arrayCSV += $hlper4CSVOutput
                    # $arrayIdOnly = $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySetIdOnly
                    # $arrayIdOnly += $policySet.PolicyDefinitionId
                    # $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySet = $array
                    # $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySet4CSV = $arrayCSV
                    # $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySetIdOnly = $arrayIdOnly

                    $null = $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySet.Add($hlperDisplayNameWithOrWithoutLinkToAzAdvertizer)
                    $null = $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySet4CSV.Add($hlper4CSVOutput)
                    $null = $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySetIdOnly.Add($policySet.PolicyDefinitionId)
                }
            }
        }
    }
    $endHelperHt = Get-Date
    Write-Host "  Create Policy/Set helper hash table duration: $((New-TimeSpan -Start $startHelperHt -End $endHelperHt).TotalSeconds) seconds"
    #endregion Create Policy/Set helper hash table

    #region PreQueriesPolicyRelated
    $startPreQueriesPolicyRelated = Get-Date
    if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy) {
        $policyBaseQuery = $newTable.where({ -not [String]::IsNullOrEmpty($_.PolicyVariant) } ) | Sort-Object -Property PolicyType, Policy | Select-Object -Property Level, Policy*, mg*, Subscription*
    }
    else {
        $policyBaseQuery = $newTable.where({ -not [String]::IsNullOrEmpty($_.PolicyVariant) -and ($_.PolicyAssignmentScopeMgSubRg -eq 'Mg' -or $_.PolicyAssignmentScopeMgSubRg -eq 'Sub') } ) | Sort-Object -Property PolicyType, Policy | Select-Object -Property Level, Policy*, mg*, Subscription*
    }

    $policyBaseQuerySubscriptions = $policyBaseQuery.where({ -not [String]::IsNullOrEmpty($_.SubscriptionId) } )
    $policyBaseQueryManagementGroups = $policyBaseQuery.where({ [String]::IsNullOrEmpty($_.SubscriptionId) } )
    $policyPolicyBaseQueryScopeInsights = ($policyBaseQuery | Select-Object Mg*, Subscription*, PolicyAssignmentAtScopeCount, PolicySetAssignmentAtScopeCount, PolicyAndPolicySetAssignmentAtScopeCount, PolicyAssignmentLimit -Unique)
    $policyBaseQueryUniqueAssignments = $policyBaseQuery | Sort-Object -Property PolicyAssignmentId -Unique | Select-Object -Property Policy*
    $policyAssignmentsOrphaned = $policyBaseQuery.where({ $_.PolicyAvailability -eq 'na' } ) | Sort-Object -Property PolicyAssignmentId -Unique
    $policyAssignmentsOrphanedCount = $policyAssignmentsOrphaned.Count
    Write-Host "  $policyAssignmentsOrphanedCount orphaned Policy assignments found"

    $htPolicyWithAssignmentsBase = @{}
    foreach ($policyAssignment in $policyBaseQueryUniqueAssignments) {
        if ($policyAssignment.PolicyVariant -eq 'Policy') {
            if (-not $htPolicyWithAssignmentsBase.($policyAssignment.PolicyDefinitionId)) {
                $htPolicyWithAssignmentsBase.($policyAssignment.PolicyDefinitionId) = @{}
                $htPolicyWithAssignmentsBase.($policyAssignment.PolicyDefinitionId).Assignments = [array]$policyAssignment.PolicyAssignmentId
            }
            else {
                $usedInAssignments = $htPolicyWithAssignmentsBase.($policyAssignment.PolicyDefinitionId).Assignments
                $usedInAssignments += $policyAssignment.PolicyAssignmentId
                $htPolicyWithAssignmentsBase.($policyAssignment.PolicyDefinitionId).Assignments = $usedInAssignments
            }
        }
    }

    $policyPolicySetBaseQueryUniqueAssignments = $policyBaseQueryUniqueAssignments.where({ $_.PolicyVariant -eq 'PolicySet' } )
    #$policyBaseQueryUniqueCustomDefinitions = ($policyBaseQuery.where({ $_.PolicyType -eq 'Custom' } )) | Select-Object PolicyVariant, PolicyDefinitionId -Unique
    $policyBaseQueryUniqueCustomDefinitions = ($policyBaseQuery.where({ $_.PolicyType -eq 'Custom' } )) | Sort-Object -Property PolicyVariant, PolicyDefinitionId -Unique | Select-Object PolicyVariant, PolicyDefinitionId
    $policyPolicyBaseQueryUniqueCustomDefinitions = ($policyBaseQueryUniqueCustomDefinitions.where({ $_.PolicyVariant -eq 'Policy' } )).PolicyDefinitionId
    $policyPolicySetBaseQueryUniqueCustomDefinitions = ($policyBaseQueryUniqueCustomDefinitions.where({ $_.PolicyVariant -eq 'PolicySet' } )).PolicyDefinitionId

    #region create array Policy definitions
    $tenantAllPoliciesCount = (($htCacheDefinitionsPolicy).Values).count
    $tenantBuiltInPolicies = (($htCacheDefinitionsPolicy).Values).where({ $_.Type -eq 'BuiltIn' } )
    $tenantBuiltInPoliciesCount = ($tenantBuiltInPolicies).count
    $tenantCustomPolicies = (($htCacheDefinitionsPolicy).Values).where({ $_.Type -eq 'Custom' } )
    $tenantCustomPoliciesCount = ($tenantCustomPolicies).count

    #hashes for parity builtin/custom
    Write-Host 'Processing Policy custom/built-In parity check'
    $startPolicyCustomBuiltInParity = Get-Date
    foreach ($customPolicy in $tenantCustomPolicies) {
        $policyRuleHash = getPolicyHash -json ($customPolicy.Json.properties.policyRule | ConvertTo-Json -Depth 99)
        if ($htHashesBuiltInPolicy.($policyRuleHash)) {
            $null = $arrayCustomBuiltInPolicyParity.Add([PSCustomObject]@{
                    CustomPolicyName        = $customPolicy.Name
                    CustomPolicyDisplayName = $customPolicy.DisplayName
                    CustomPolicyCategory    = $customPolicy.Category
                    CustomPolicyId          = $customPolicy.Id
                    MatchBuiltinPolicyCount = $htHashesBuiltInPolicy.($policyRuleHash).Policies.Count
                    BuiltInPolicyId         = ($htHashesBuiltInPolicy.($policyRuleHash).Policies | Sort-Object) -join "$CsvDelimiterOpposite "
                })
        }
    }
    if ($arrayCustomBuiltInPolicyParity.Count -gt 0) {
        Write-Host " $($arrayCustomBuiltInPolicyParity.Count) custom Policy definition(s) found that have parity with built-In Policy definition Policy rule"
        if (-not $NoCsvExport) {
            Write-Host " Exporting PolicyCustomBuiltInParity CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_PolicyCustomBuiltInParity.csv'"
            $arrayCustomBuiltInPolicyParity | Sort-Object -Property CustomPolicyId | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_PolicyCustomBuiltInParity.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
        }
    }
    else {
        Write-Host ' No custom Policy definition found that have parity with built-In Policy definition Policy rule'
    }
    $endPolicyCustomBuiltInParity = Get-Date
    Write-Host " Policy custom/built-In parity check duration: $((New-TimeSpan -Start $startPolicyCustomBuiltInParity -End $endPolicyCustomBuiltInParity).TotalMinutes) minutes ($((New-TimeSpan -Start $startPolicyCustomBuiltInParity -End $endPolicyCustomBuiltInParity).TotalSeconds) seconds)"
    #endregion create array Policy definitions

    #region create array PolicySet definitions
    $tenantBuiltInPolicySets = $tenantAllPolicySets.where({ $_.Type -eq 'Builtin' } )
    $tenantBuiltInPolicySetsCount = ($tenantBuiltInPolicySets).count
    $tenantCustomPolicySets = $tenantAllPolicySets.where({ $_.Type -eq 'Custom' } )
    $tenantCustompolicySetsCount = ($tenantCustomPolicySets).count
    #endregion create array PolicySet definitions

    $endPreQueriesPolicyRelated = Get-Date
    Write-Host "  PreQueriesPolicyRelated duration: $((New-TimeSpan -Start $startPreQueriesPolicyRelated -End $endPreQueriesPolicyRelated).TotalSeconds) seconds"
    #endregion PreQueriesPolicyRelated

    #region PreQueriesRBACRelated
    $startPreQueriesRBACRelated = Get-Date
    $rbacBaseQueryArrayListNotGroupOwner = $rbacBaseQuery.where({ $_.RoleAssignmentIdentityObjectType -ne 'Group' -and $_.RoleDefinitionName -eq 'Owner' }) | Select-Object -Property mgid, SubscriptionId, RoleAssignmentId, RoleDefinitionName, RoleDefinitionId, RoleAssignmentIdentityObjectType, RoleAssignmentIdentityDisplayname, RoleAssignmentIdentitySignInName, RoleAssignmentIdentityObjectId, RoleAssignmentScopeType
    $rbacBaseQueryArrayListNotGroupUserAccessAdministrator = $rbacBaseQuery.where({ $_.RoleAssignmentIdentityObjectType -ne 'Group' -and $_.RoleDefinitionName -eq 'User Access Administrator' }) | Select-Object -Property mgid, SubscriptionId, RoleAssignmentId, RoleDefinitionName, RoleDefinitionId, RoleAssignmentIdentityObjectType, RoleAssignmentIdentityDisplayname, RoleAssignmentIdentitySignInName, RoleAssignmentIdentityObjectId, RoleAssignmentScopeType
    $roleAssignmentsForServicePrincipals = (($roleAssignmentsUniqueById.where({ $_.RoleAssignmentIdentityObjectType -eq 'ServicePrincipal' })))
    $htRoleAssignmentsForServicePrincipals = @{}
    foreach ($spWithRoleAssignment in $roleAssignmentsForServicePrincipals | Group-Object -Property RoleAssignmentIdentityObjectId) {
        if (-not $htRoleAssignmentsForServicePrincipals.($spWithRoleAssignment.Name)) {
            $htRoleAssignmentsForServicePrincipals.($spWithRoleAssignment.Name) = @{}
            $htRoleAssignmentsForServicePrincipals.($spWithRoleAssignment.Name).RoleAssignments = $spWithRoleAssignment.group
        }
    }

    #region assignmentRgRes
    $htPoliciesWithAssignmentOnRgRes = @{}
    foreach ($policyAssignmentRgRes in ($htCacheAssignmentsPolicyOnResourceGroupsAndResources).values | Sort-Object -Property id -Unique) {
        $hlperPolDefId = (($policyAssignmentRgRes.properties.policyDefinitionId).ToLower())
        if (-not $htPoliciesWithAssignmentOnRgRes.($hlperPolDefId)) {
            $pscustomObj = [System.Collections.ArrayList]@()
            $null = $pscustomObj.Add([PSCustomObject]@{
                    PolicyAssignmentId          = ($policyAssignmentRgRes.Id).ToLower()
                    PolicyAssignmentDisplayName = $policyAssignmentRgRes.properties.displayName
                })
            $htPoliciesWithAssignmentOnRgRes.($hlperPolDefId) = @{}
            $htPoliciesWithAssignmentOnRgRes.($hlperPolDefId).Assignments = [array](($pscustomObj))
        }
        else {
            $pscustomObj = [System.Collections.ArrayList]@()
            $null = $pscustomObj.Add([PSCustomObject]@{
                    PolicyAssignmentId          = ($policyAssignmentRgRes.Id).ToLower()
                    PolicyAssignmentDisplayName = $policyAssignmentRgRes.properties.displayName
                })
            $array = @()
            $array += $htPoliciesWithAssignmentOnRgRes.($hlperPolDefId).Assignments
            $array += (($pscustomObj))
            $htPoliciesWithAssignmentOnRgRes.($hlperPolDefId).Assignments = $array
        }
    }
    #endregion assignmentRgRes

    $tenantAllRoles = ($htCacheDefinitionsRole).Values
    $tenantAllRolesCount = ($tenantAllRoles).Count
    $tenantCustomRoles = $tenantAllRoles.where({ $_.IsCustom -eq $True } )
    $tenantCustomRolesCount = ($tenantCustomRoles).Count
    $tenantAllRolesCanDoRoleAssignments = $tenantAllRoles.where({ $_.RoleCanDoRoleAssignments -eq $True } )
    $tenantAllRolesCanDoRoleAssignmentsCount = $tenantAllRolesCanDoRoleAssignments.Count

    $mgSubRoleAssignmentsArrayFromHTValues = ($htCacheAssignmentsRole).Values.Assignment
    if ($azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC) {
        $rgResRoleAssignmentsArrayFromHTValues = ($htCacheAssignmentsRBACOnResourceGroupsAndResources).Values
    }

    $endPreQueriesRBACRelated = Get-Date
    Write-Host "  PreQueriesRBACRelated duration: $((New-TimeSpan -Start $startPreQueriesRBACRelated -End $endPreQueriesRBACRelated).TotalSeconds) seconds"
    #endregion PreQueriesRBACRelated

    $blueprintBaseQuery = ($newTable.where({ -not [String]::IsNullOrEmpty($_.BlueprintName) } )) | Select-Object mgid, SubscriptionId, Blueprint*
    $mgsAndSubs = (($optimizedTableForPathQuery.where({ $_.mgId -ne '' -and $_.Level -ne '0' } )) | Sort-Object -Property MgId, SubscriptionId -Unique | Select-Object MgId, SubscriptionId)


    #region PreQueriesDiagnosticsRelated
    $startPreQueriesDiagnosticsRelated = Get-Date
    $diagnosticSettingsMg = $arrayDiagnosticSettingsMgSub.where({ $_.Scope -eq 'Mg' -and $_.DiagnosticsPresent -eq 'true' })
    $diagnosticSettingsMgCount = $diagnosticSettingsMg.Count
    $diagnosticSettingsMgCategories = ($diagnosticSettingsMg.DiagnosticCategories | Group-Object -Property Category).Name
    $diagnosticSettingsMgGrouped = $diagnosticSettingsMg | Group-Object -Property ScopeId
    $diagnosticSettingsMgManagementGroupsCount = ($diagnosticSettingsMgGrouped | Measure-Object).Count

    foreach ($entry in $diagnosticSettingsMgGrouped) {
        $dsgrouped = $entry.group | Group-Object -Property DiagnosticSettingName

        foreach ($ds in $dsgrouped) {
            $targetTypegrouped = $ds.group | Group-Object -Property DiagnosticTargetType
            foreach ($tt in $targetTypegrouped) {
                if (-not ($htDiagnosticSettingsMgSub).mg.($entry.Name)) {
                ($htDiagnosticSettingsMgSub).mg.($entry.Name) = @{}
                }
                if (-not ($htDiagnosticSettingsMgSub).mg.($entry.Name).($ds.Name)) {
                ($htDiagnosticSettingsMgSub).mg.($entry.Name).($ds.Name) = @{}
                }
                if (-not ($htDiagnosticSettingsMgSub).mg.($entry.Name).($ds.Name).($tt.Name)) {
                ($htDiagnosticSettingsMgSub).mg.($entry.Name).($ds.Name).($tt.Name) = $tt.group
                }
            }
        }
    }

    foreach ($mg in $htManagementGroupsMgPath.Values) {
        foreach ($mgWithDiag in ($htDiagnosticSettingsMgSub).mg.keys) {
            if ($mg.ParentNameChain -contains $mgWithDiag) {
                foreach ($diagSet in ($htDiagnosticSettingsMgSub).mg.($mgWithDiag).keys) {
                    foreach ($tt in ($htDiagnosticSettingsMgSub).mg.($mgWithDiag).($diagset).keys) {
                        foreach ($tid in ($htDiagnosticSettingsMgSub).mg.($mgWithDiag).($diagset).($tt)) {
                            $null = $script:diagnosticSettingsMg.Add([PSCustomObject]@{
                                    Scope                     = 'Mg'
                                    ScopeName                 = $mg.displayName
                                    ScopeId                   = $mg.Id
                                    ScopeMgPath               = $htManagementGroupsMgPath.($mg.Id).pathDelimited
                                    DiagnosticsInheritedOrnot = $true
                                    DiagnosticsInheritedFrom  = $mgWithDiag
                                    DiagnosticsPresent        = 'true'
                                    DiagnosticSettingName     = $diagSet
                                    DiagnosticTargetType      = $tt
                                    DiagnosticTargetId        = $tid.DiagnosticTargetId
                                    DiagnosticCategories      = $tid.DiagnosticCategories
                                    DiagnosticCategoriesHt    = $tid.DiagnosticCategoriesHt
                                })
                        }
                    }
                }
            }
        }
    }
    $mgsDiagnosticsApplicableCount = $diagnosticSettingsMg.Count

    $arrayMgsWithoutDiagnostics = [System.Collections.ArrayList]@()
    foreach ($mg in $htManagementGroupsMgPath.Values) {
        if ($diagnosticSettingsMg.ScopeId -notcontains $mg.Id) {
            $null = $arrayMgsWithoutDiagnostics.Add([PSCustomObject]@{
                    ScopeName   = $mg.DisplayName
                    ScopeId     = $mg.Id
                    ScopeMgPath = $mg.pathDelimited
                })
        }
    }
    $arrayMgsWithoutDiagnosticsCount = $arrayMgsWithoutDiagnostics.Count

    $diagnosticSettingsSub = $arrayDiagnosticSettingsMgSub.where({ $_.Scope -eq 'Sub' -and $_.DiagnosticsPresent -eq 'true' })
    $diagnosticSettingsSubCount = $diagnosticSettingsSub.Count
    $diagnosticSettingsSubNoDiag = $arrayDiagnosticSettingsMgSub.where({ $_.Scope -eq 'Sub' -and $_.DiagnosticsPresent -eq 'false' })
    $diagnosticSettingsSubNoDiagCount = $diagnosticSettingsSubNoDiag.Count
    $diagnosticSettingsSubCategories = ($diagnosticSettingsSub.DiagnosticCategories | Group-Object -Property Category).Name
    $diagnosticSettingsSubGrouped = $diagnosticSettingsSub | Group-Object -Property ScopeId
    $diagnosticSettingsSubSubscriptionsCount = ($diagnosticSettingsSubGrouped | Measure-Object).Count

    foreach ($entry in $diagnosticSettingsSubGrouped) {
        $dsgrouped = $entry.group | Group-Object -Property DiagnosticSettingName

        foreach ($ds in $dsgrouped) {
            $targetTypegrouped = $ds.group | Group-Object -Property DiagnosticTargetType
            foreach ($tt in $targetTypegrouped) {
                if (-not ($htDiagnosticSettingsMgSub).sub.($entry.Name)) {
                ($htDiagnosticSettingsMgSub).sub.($entry.Name) = @{}
                }
                if (-not ($htDiagnosticSettingsMgSub).sub.($entry.Name).($ds.Name)) {
                ($htDiagnosticSettingsMgSub).sub.($entry.Name).($ds.Name) = @{}
                }
                if (-not ($htDiagnosticSettingsMgSub).sub.($entry.Name).($ds.Name).($tt.Name)) {
                ($htDiagnosticSettingsMgSub).sub.($entry.Name).($ds.Name).($tt.Name) = $tt.group
                }
            }
        }
    }
    $endPreQueriesDiagnosticsRelated = Get-Date
    Write-Host "  PreQueriesDiagnosticsRelated duration: $((New-TimeSpan -Start $startPreQueriesDiagnosticsRelated -End $endPreQueriesDiagnosticsRelated).TotalSeconds) seconds"
    #endregion PreQueriesDiagnosticsRelated

    #region PreQueriesDefenderRelated
    $startPreQueriesDefenderRelated = Get-Date
    $defenderPlansGroupedBySub = $arrayDefenderPlans | Sort-Object -Property subscriptionName | Group-Object -Property subscriptionName, subscriptionId, subscriptionMgPath
    $subsDefenderPlansCount = ($defenderPlansGroupedBySub | Measure-Object).Count
    $defenderCapabilities = ($arrayDefenderPlans.defenderPlan | Sort-Object -Unique)
    $defenderCapabilitiesCount = $defenderCapabilities.Count
    $defenderPlansGroupedByPlan = $arrayDefenderPlans | Group-Object -Property defenderPlan, defenderPlanTier
    $defenderPlansGroupedByPlanCount = ($defenderPlansGroupedByPlan | Measure-Object).Count
    if ($defenderPlansGroupedByPlan.Name -contains 'ContainerRegistry, Standard' -or $defenderPlansGroupedByPlan.Name -contains 'KubernetesService, Standard') {
        if ($defenderPlansGroupedByPlan.Name -contains 'ContainerRegistry, Standard') {
            $defenderPlanDeprecatedContainerRegistry = $true
        }
        if ($defenderPlansGroupedByPlan.Name -contains 'KubernetesService, Standard') {
            $defenderPlanDeprecatedKubernetesService = $true
        }
    }
    $endPreQueriesDefenderRelated = Get-Date
    Write-Host "  PreQueriesDefenderRelated duration: $((New-TimeSpan -Start $startPreQueriesDefenderRelated -End $endPreQueriesDefenderRelated).TotalSeconds) seconds"
    #endregion PreQueriesDefenderRelated

    $endPreQueries = Get-Date
    Write-Host " Pre Queries duration: $((New-TimeSpan -Start $startPreQueries -End $endPreQueries).TotalMinutes) minutes ($((New-TimeSpan -Start $startPreQueries -End $endPreQueries).TotalSeconds) seconds)"
    showMemoryUsage
    #endregion preQueries

    #region summarizeDataCollectionResults
    $startSummarizeDataCollectionResults = Get-Date
    Write-Host 'Summary data collection'
    #$mgsDetails = ($optimizedTableForPathQueryMg | Select-Object Level, MgId -Unique)
    $mgsDetails = ($optimizedTableForPathQueryMg | Sort-Object -Property Level, MgId -Unique | Select-Object Level, MgId)
    $mgDepth = ($mgsDetails.Level | Measure-Object -Maximum).Maximum
    $totalMgCount = ($mgsDetails).count
    $totalSubCount = ($optimizedTableForPathQuerySub).count
    $totalSubOutOfScopeCount = ($outOfScopeSubscriptions).count
    $totalSubIncludedAndExcludedCount = $totalSubCount + $totalSubOutOfScopeCount
    $totalResourceCount = $($resourcesIdsAll.Count)

    $totalPolicyAssignmentsCount = (($htCacheAssignmentsPolicy).keys).count

    $policyAssignmentsMg = (($htCacheAssignmentsPolicy).Values.where({ $_.AssignmentScopeMgSubRg -eq 'Mg' } ))
    $totalPolicyAssignmentsCountMg = $policyAssignmentsMg.Count

    $totalPolicyAssignmentsCountSub = (($htCacheAssignmentsPolicy).Values.where({ $_.AssignmentScopeMgSubRg -eq 'Sub' } )).count

    if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsOnPolicy) {
        $totalPolicyAssignmentsCountRg = (($htCacheAssignmentsPolicy).Values.where({ $_.AssignmentScopeMgSubRg -eq 'Rg' -or $_.AssignmentScopeMgSubRg -eq 'Res' } )).count
    }
    else {
        $totalPolicyAssignmentsCountRg = (($htCacheAssignmentsPolicyOnResourceGroupsAndResources).values).count
        $totalPolicyAssignmentsCount = $totalPolicyAssignmentsCount + $totalPolicyAssignmentsCountRg
    }

    $totalRoleAssignmentsCount = (($htCacheAssignmentsRole).keys).count
    $totalRoleAssignmentsCountTen = (($htCacheAssignmentsRole).keys.where({ ($htCacheAssignmentsRole).($_).AssignmentScopeTenMgSubRgRes -eq 'Tenant' } )).count
    $totalRoleAssignmentsCountMG = (($htCacheAssignmentsRole).keys.where({ ($htCacheAssignmentsRole).($_).AssignmentScopeTenMgSubRgRes -eq 'MG' } )).count
    $totalRoleAssignmentsCountSub = (($htCacheAssignmentsRole).keys.where({ ($htCacheAssignmentsRole).($_).AssignmentScopeTenMgSubRgRes -eq 'Sub' } )).count
    if (-not $azAPICallConf['htParameters'].DoNotIncludeResourceGroupsAndResourcesOnRBAC) {
        $totalRoleAssignmentsCountRG = (($htCacheAssignmentsRole).keys.where({ ($htCacheAssignmentsRole).($_).AssignmentScopeTenMgSubRgRes -eq 'RG' } )).count
        $totalRoleAssignmentsCountRes = (($htCacheAssignmentsRole).keys.where({ ($htCacheAssignmentsRole).($_).AssignmentScopeTenMgSubRgRes -eq 'Res' } )).count
        $totalRoleAssignmentsResourceGroupsAndResourcesCount = $totalRoleAssignmentsCountRG + $totalRoleAssignmentsCountRes
    }
    else {
        $totalRoleAssignmentsResourceGroupsAndResourcesCount = (($htCacheAssignmentsRBACOnResourceGroupsAndResources).values).count
        $totalRoleAssignmentsCount = $totalRoleAssignmentsCount + $totalRoleAssignmentsResourceGroupsAndResourcesCount
    }

    $totalRoleDefinitionsCustomCount = ((($htCacheDefinitionsRole).keys.where({ ($htCacheDefinitionsRole).($_).IsCustom -eq $True } ))).count
    $totalBlueprintDefinitionsCount = ((($htCacheDefinitionsBlueprint).keys)).count
    $totalBlueprintAssignmentsCount = (($htCacheAssignmentsBlueprint).keys).count
    $totalResourceTypesCount = ($resourceTypesDiagnosticsArray).Count

    Write-Host " Total Management Groups: $totalMgCount (depth $mgDepth)"
    $htDailySummary.'ManagementGroups' = $totalMgCount
    Write-Host " Total Subscriptions: $totalSubIncludedAndExcludedCount ($totalSubCount included; $totalSubOutOfScopeCount out-of-scope)"
    $htDailySummary.'Subscriptions' = $totalSubCount

    $subscriptionsGroupedByQuotaId = $optimizedTableForPathQuerySub | Group-Object -Property SubscriptionQuotaId
    if ($subscriptionsGroupedByQuotaId.Count -gt 0) {
        foreach ($quotaId in $subscriptionsGroupedByQuotaId) {
            $htDailySummary."Subscriptions_$($quotaId.Name)" = $quotaId.Count
        }
    }

    $htDailySummary.'SubscriptionsOutOfScope' = $totalSubOutOfScopeCount
    Write-Host " Total BuiltIn Policy definitions: $tenantBuiltInPoliciesCount"
    $htDailySummary.'PolicyDefinitionsBuiltIn' = $tenantBuiltInPoliciesCount
    Write-Host " Total Custom Policy definitions: $tenantCustomPoliciesCount"
    $htDailySummary.'PolicyDefinitionsCustom' = $tenantCustomPoliciesCount
    Write-Host " Total BuiltIn PolicySet definitions: $tenantBuiltInPolicySetsCount"
    $htDailySummary.'PolicySetDefinitionsBuiltIn' = $tenantBuiltInPolicySetsCount
    Write-Host " Total Custom PolicySet definitions: $tenantCustompolicySetsCount"
    $htDailySummary.'PolicySetDefinitionsCustom' = $tenantCustompolicySetsCount
    Write-Host " Total Policy assignments: $($totalPolicyAssignmentsCount)"
    $htDailySummary.'PolicyAssignments' = $totalPolicyAssignmentsCount
    Write-Host " Total Policy assignments ManagementGroups $($totalPolicyAssignmentsCountMg)"
    $htDailySummary.'PolicyAssignments_ManagementGroups' = $totalPolicyAssignmentsCountMg
    Write-Host " Total Policy assignments Subscriptions $($totalPolicyAssignmentsCountSub)"
    $htDailySummary.'PolicyAssignments_Subscriptions' = $totalPolicyAssignmentsCountSub
    Write-Host " Total Policy assignments ResourceGroups: $($totalPolicyAssignmentsCountRg)"
    $htDailySummary.'PolicyAssignments_ResourceGroups' = $totalPolicyAssignmentsCountRg
    Write-Host " Total Custom Role definitions: $totalRoleDefinitionsCustomCount"
    $htDailySummary.'RoleDefinitionsCustom' = $totalRoleDefinitionsCustomCount
    Write-Host " Total Role assignments: $totalRoleAssignmentsCount"
    $htDailySummary.'TotalRoleAssignments' = $totalRoleAssignmentsCount
    Write-Host " Total Role assignments (Tenant): $totalRoleAssignmentsCountTen"
    $htDailySummary.'TotalRoleAssignments_Tenant' = $totalRoleAssignmentsCountTen
    Write-Host " Total Role assignments (ManagementGroups): $totalRoleAssignmentsCountMG"
    $htDailySummary.'TotalRoleAssignments_ManagementGroups' = $totalRoleAssignmentsCountMG
    Write-Host " Total Role assignments (Subscriptions): $totalRoleAssignmentsCountSub"
    $htDailySummary.'TotalRoleAssignments_Subscriptions' = $totalRoleAssignmentsCountSub
    Write-Host " Total Role assignments (ResourceGroups and Resources): $totalRoleAssignmentsResourceGroupsAndResourcesCount"
    $htDailySummary.'TotalRoleAssignments_RgRes' = $totalRoleAssignmentsResourceGroupsAndResourcesCount
    Write-Host " Total Blueprint definitions: $totalBlueprintDefinitionsCount"
    $htDailySummary.'Blueprints' = $totalBlueprintDefinitionsCount
    Write-Host " Total Blueprint assignments: $totalBlueprintAssignmentsCount"
    $htDailySummary.'BlueprintAssignments' = $totalBlueprintAssignmentsCount
    Write-Host " Total Resources: $totalResourceCount"
    $htDailySummary.'Resources' = $totalResourceCount
    Write-Host " Total Resource Types: $totalResourceTypesCount"
    $htDailySummary.'ResourceTypes' = $totalResourceTypesCount

    $rbacUnique = $rbacAll | Sort-Object -Property RoleAssignmentId -Unique
    $rbacUniqueObjectIds = $rbacUnique | Sort-Object -Property ObjectId -Unique
    $rbacUniqueObjectIdsNonPIM = $rbacUnique.where({ $_.RoleAssignmentPIMRelated -eq $false } ) | Sort-Object -Property ObjectId -Unique
    $rbacUniqueObjectIdsPIM = $rbacUnique.where({ $_.RoleAssignmentPIMRelated -eq $true } ) | Sort-Object -Property ObjectId -Unique

    if ($rbacUniqueObjectIds.Count -gt 0) {
        $rbacUniqueObjectIdsGrouped = $rbacUniqueObjectIds | Group-Object -Property ObjectType
        foreach ($principalType in $rbacUniqueObjectIdsGrouped) {
            $htDailySummary."TotalUniquePrincipalWithPermission_$($principalType.Name)" = $principalType.Count
        }
        $htDailySummary.'TotalUniquePrincipalWithPermission_SP' = $rbacUniqueObjectIds.where({ $_.ObjectType -like 'SP*' } ).count
        $htDailySummary.'TotalUniquePrincipalWithPermission_User' = $rbacUniqueObjectIds.where({ $_.ObjectType -like 'User*' } ).count
    }

    if ($rbacUniqueObjectIdsNonPIM.Count -gt 0) {
        $rbacUniqueObjectIdsNonPIMGrouped = $rbacUniqueObjectIdsNonPIM | Group-Object -Property ObjectType
        foreach ($principalType in $rbacUniqueObjectIdsNonPIMGrouped) {
            $htDailySummary."TotalUniquePrincipalWithPermissionStatic_$($principalType.Name)" = $principalType.Count
        }
        $htDailySummary.'TotalUniquePrincipalWithPermissionStatic_SP' = $rbacUniqueObjectIdsNonPIM.where({ $_.ObjectType -like 'SP*' } ).count
        $htDailySummary.'TotalUniquePrincipalWithPermissionStatic_User' = $rbacUniqueObjectIdsNonPIM.where({ $_.ObjectType -like 'User*' } ).count
    }

    if ($rbacUniqueObjectIdsPIM.Count -gt 0) {
        $rbacUniqueObjectIdsPIMGrouped = $rbacUniqueObjectIdsPIM | Group-Object -Property ObjectType
        foreach ($principalType in $rbacUniqueObjectIdsPIMGrouped) {
            $htDailySummary."TotalUniquePrincipalWithPermissionPIM_$($principalType.Name)" = $principalType.Count
        }
        $htDailySummary.'TotalUniquePrincipalWithPermissionPIM_SP' = $rbacUniqueObjectIdsPIM.where({ $_.ObjectType -like 'SP*' } ).count
        $htDailySummary.'TotalUniquePrincipalWithPermissionPIM_User' = $rbacUniqueObjectIdsPIM.where({ $_.ObjectType -like 'User*' } ).count
    }


    # if ($arrayAdvisorScores.Count -gt 0) {
    #     $arrayAdvisorScoresGroupedByCategory = $arrayAdvisorScores | Group-Object -Property category
    #     foreach ($entry in $arrayAdvisorScoresGroupedByCategory) {
    #         $htDailySummary."Advisor_$($entry.Name)" = ($entry.Group.Score | Measure-Object -Sum).Sum / $entry.Group.Count
    #     }
    # }

    if ($htMgASCSecureScore.Keys.Count -gt 0) {
        foreach ($mgASCSecureScore in $htMgASCSecureScore.Keys) {
            $htDailySummary."MDfCSecureScore_$($mgASCSecureScore)" = $htMgASCSecureScore.($mgASCSecureScore).SecureScore
        }
    }

    $endSummarizeDataCollectionResults = Get-Date
    Write-Host " Summary data collection duration: $((New-TimeSpan -Start $startSummarizeDataCollectionResults -End $endSummarizeDataCollectionResults).TotalSeconds) seconds"
    showMemoryUsage
    #endregion summarizeDataCollectionResults
}

$html = @"
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
    <meta http-equiv="Pragma" content="no-cache" />
    <meta http-equiv="Expires" content="0" />
    <title>Azure Governance Visualizer aka AzGovViz</title>
    <script type="text/javascript">
        var link = document.createElement( "link" );
        rand = Math.floor(Math.random() * 99999);
        link.href = "https://www.azadvertizer.net/azgovvizv4/css/azgovvizversion.css?rnd=" + rand;
        link.type = "text/css";
        link.rel = "stylesheet";
        link.media = "screen,print";
        document.getElementsByTagName( "head" )[0].appendChild( link );
    </script>
    <link rel="stylesheet" type="text/css" href="https://www.azadvertizer.net/azgovvizv4/css/azgovvizmain_004_052.css">
    <script src="https://www.azadvertizer.net/azgovvizv4/js/jquery-3.6.0.min.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv4/js/jquery-ui-1.13.0.min.js"></script>
    <script type="text/javascript" src="https://www.azadvertizer.net/azgovvizv4/js/highlight_v004_002.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv4/js/fontawesome-0c0b5cbde8.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv4/tablefilter/tablefilter.js"></script>
    <link rel="stylesheet" href="https://www.azadvertizer.net/azgovvizv4/css/highlight-10.5.0.min.css">
    <script src="https://www.azadvertizer.net/azgovvizv4/js/highlight-10.5.0.min.js"></script>
    <script>hljs.initHighlightingOnLoad();</script>
    <link rel="stylesheet" type="text/css" href="https://www.azadvertizer.net/azgovvizv4/css/jsonviewer_v01.css">
    <script type="text/javascript" src="https://www.azadvertizer.net/azgovvizv4/js/jsonviewer_v02.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv4/js/dom-to-image.min.js"></script>
    <script>
        `$(window).on('load', function () {
            // Animate loader off screen
            `$(".se-pre-con").fadeOut("slow");;
        });
    </script>

    <script>
    // Quick and simple export target #table_id into a csv
    function download_table_as_csv_semicolon(table_id) {
        // Select rows from table_id
        var rows = document.querySelectorAll('table#' + table_id + ' tr');
        // Construct csv
        var csv = [];
        if (window.helpertfConfig4TenantSummary_roleAssignmentsAll !== 1){
            for (var i = 0; i < rows.length; i++) {
                var row = [], cols = rows[i].querySelectorAll('td, th');
                for (var j = 0; j < cols.length; j++) {
                    // Clean innertext to remove multiple spaces and jumpline (break csv)
                    var data = cols[j].innerText.replace(/(\r\n|\n|\r)/gm, '').replace(/(\s\s)/gm, ' ')
                    // Escape double-quote with double-double-quote (see https://stackoverflow.com/questions/17808511/properly-escape-a-double-quote-in-csv)
                    data = data.replace(/"/g, '""');
                    // Push escaped string
                    row.push('"' + data + '"');
                }
                csv.push(row.join(';'));
            }
        }
        else{
            for (var i = 1; i < rows.length; i++) {
                var row = [], cols = rows[i].querySelectorAll('td, th');
                for (var j = 0; j < cols.length; j++) {
                    // Clean innertext to remove multiple spaces and jumpline (break csv)
                    var data = cols[j].innerText.replace(/(\r\n|\n|\r)/gm, '').replace(/(\s\s)/gm, ' ')
                    // Escape double-quote with double-double-quote (see https://stackoverflow.com/questions/17808511/properly-escape-a-double-quote-in-csv)
                    data = data.replace(/"/g, '""');
                    // Push escaped string
                    row.push('"' + data + '"');
                }
                csv.push(row.join(';'));
            }
        }
        var csv_string = csv.join('\n');
        // Download it
        var filename = 'export_' + table_id + '_' + new Date().toLocaleDateString('en-CA') + '.csv';
        var link = document.createElement('a');
        link.style.display = 'none';
        link.setAttribute('target', '_blank');
        link.setAttribute('href', 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv_string));
        link.setAttribute('download', filename);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }
    </script>

    <script>
    // Quick and simple export target #table_id into a csv
    function download_table_as_csv_comma(table_id) {
        // Select rows from table_id
        var rows = document.querySelectorAll('table#' + table_id + ' tr');
        // Construct csv
        var csv = [];
        if (window.helpertfConfig4TenantSummary_roleAssignmentsAll !== 1){
            for (var i = 0; i < rows.length; i++) {
                var row = [], cols = rows[i].querySelectorAll('td, th');
                for (var j = 0; j < cols.length; j++) {
                    // Clean innertext to remove multiple spaces and jumpline (break csv)
                    var data = cols[j].innerText.replace(/(\r\n|\n|\r)/gm, '').replace(/(\s\s)/gm, ' ')
                    // Escape double-quote with double-double-quote (see https://stackoverflow.com/questions/17808511/properly-escape-a-double-quote-in-csv)
                    data = data.replace(/"/g, '""');
                    // Push escaped string
                    row.push('"' + data + '"');
                }
                csv.push(row.join(','));
            }
        }
        else{
            for (var i = 1; i < rows.length; i++) {
                var row = [], cols = rows[i].querySelectorAll('td, th');
                for (var j = 0; j < cols.length; j++) {
                    // Clean innertext to remove multiple spaces and jumpline (break csv)
                    var data = cols[j].innerText.replace(/(\r\n|\n|\r)/gm, '').replace(/(\s\s)/gm, ' ')
                    // Escape double-quote with double-double-quote (see https://stackoverflow.com/questions/17808511/properly-escape-a-double-quote-in-csv)
                    data = data.replace(/"/g, '""');
                    // Push escaped string
                    row.push('"' + data + '"');
                }
                csv.push(row.join(','));
            }
        }
        var csv_string = csv.join('\n');
        // Download it
        var filename = 'export_' + table_id + '_' + new Date().toLocaleDateString('en-CA') + '.csv';
        var link = document.createElement('a');
        link.style.display = 'none';
        link.setAttribute('target', '_blank');
        link.setAttribute('href', 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv_string));
        link.setAttribute('download', filename);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }
    </script>
</head>
"@

if (-not $HierarchyMapOnly) {

    if (-not $NoDefinitionInsightsDedicatedHTML) {
        $htmlDefinitionInsightsDedicatedStart = $html
        $htmlDefinitionInsightsDedicatedStart += @'
    <body>
        <div class="se-pre-con"></div>

        <div class="hierprnt" id="hierprnt">
            <div class="definitioninsightsprnt" id="definitioninsightsprnt" style="width:100%;height:100%;overflow-y:auto;resize: none;">
                <div class="definitioninsights" id="definitioninsights"><p class="pbordered">DefinitionInsights</p>

'@

        $htmlDefinitionInsightsDedicatedEnd = @"
                </div><!--definitionInsights-->
            </div><!--definitionInsightsprnt-->

        </div>
        <div class="footer">
            <div class="VersionDiv VersionLatest"></div>
            <div class="VersionDiv VersionThis"></div>
            <div class="VersionAlert"></div>
        </div>
        <script src="https://www.azadvertizer.net/azgovvizv4/js/toggle_v004_004.js"></script>
        <script src="https://www.azadvertizer.net/azgovvizv4/js/collapsetable_v004_001.js"></script>
        <script src="https://www.azadvertizer.net/azgovvizv4/js/fitty_v004_001.min.js"></script>
        <script src="https://www.azadvertizer.net/azgovvizv4/js/version_v004_004.js"></script>
        <script src="https://www.azadvertizer.net/azgovvizv4/js/autocorrectOff_v004_001.js"></script>
        <script>
            fitty('#fitme', {
                minSize: 7,
                maxSize: 10
            });
        </script>
        <script>
            `$("#getImage").on('click', function () {

            element = document.getElementById('saveAsImageArea')
            var images = element.getElementsByTagName('img');
            var l = images.length;
            for (var i = 0; i < l; i++) {
                images[0].parentNode.removeChild(images[0]);
            }

            var scale = 3;
            domtoimage.toPng(element, { quality: 0.95 , width: element.clientWidth * scale,
                height: element.clientHeight * scale,
                style: {
                    transform: 'scale('+scale+')',
                    transformOrigin: 'top left'
            }})
                .then(function (dataUrl) {
                var link = document.createElement('a');
                link.download = '$($fileName).png';
                link.href = dataUrl;
                link.click();
            });

            })
        </script>
    </body>
</html>
"@
    }
    if (-not $NoSingleSubscriptionOutput) {

        if ($azAPICallConf['htParameters'].onAzureDevOpsOrGitHubActions) {
            $HTMLPath = "HTML-Subscriptions_$($ManagementGroupId)"
            if (Test-Path -LiteralPath "$($outputPath)$($DirectorySeparatorChar)$($HTMLPath)") {
                Write-Host ' Cleaning old state (Pipeline only)'
                Remove-Item -Recurse -Force "$($outputPath)$($DirectorySeparatorChar)$($HTMLPath)"
            }
        }
        else {
            $HTMLPath = "HTML-Subscriptions_$($ManagementGroupId)_$($fileTimestamp)"
            Write-Host " Creating new state ($($HTMLPath)) (local only))"
        }

        $null = New-Item -Name $HTMLPath -ItemType directory -Path $outputPath

        $htmlSubscriptionOnlyStart = $html
        $htmlSubscriptionOnlyStart += @'
    <body>
        <div class="se-pre-con"></div>

        <div class="hierprnt" id="hierprnt">
            <div class="hierarchyTables" id="hierarchyTables">
                <p class="pbordered">ScopeInsights</p>
                <table class="subTable">
'@

        $htmlSubscriptionOnlyEnd = @"
            </table>
        </div>
        </div>
        <div class="footer">
            <div class="VersionDiv VersionLatest"></div>
            <div class="VersionDiv VersionThis"></div>
            <div class="VersionAlert"></div>
        </div>
        <script src="https://www.azadvertizer.net/azgovvizv4/js/toggle_v004_004.js"></script>
        <script src="https://www.azadvertizer.net/azgovvizv4/js/collapsetable_v004_001.js"></script>
        <script src="https://www.azadvertizer.net/azgovvizv4/js/fitty_v004_001.min.js"></script>
        <script src="https://www.azadvertizer.net/azgovvizv4/js/version_v004_004.js"></script>
        <script src="https://www.azadvertizer.net/azgovvizv4/js/autocorrectOff_v004_001.js"></script>
        <script>
            fitty('#fitme', {
                minSize: 7,
                maxSize: 10
            });
        </script>
        <script>
            `$("#getImage").on('click', function () {

            element = document.getElementById('saveAsImageArea')
            var images = element.getElementsByTagName('img');
            var l = images.length;
            for (var i = 0; i < l; i++) {
                images[0].parentNode.removeChild(images[0]);
            }

            var scale = 3;
            domtoimage.toPng(element, { quality: 0.95 , width: element.clientWidth * scale,
                height: element.clientHeight * scale,
                style: {
                    transform: 'scale('+scale+')',
                    transformOrigin: 'top left'
            }})
                .then(function (dataUrl) {
                var link = document.createElement('a');
                link.download = '$($fileName).png';
                link.href = dataUrl;
                link.click();
            });

            })
        </script>
    </body>
</html>
"@
    }

    $htmlShowHideScopeInfo =
    @"
<p>
    <button id="showHideScopeInfo">Hide<br>ScopeInfo</button><br>
    <a id="getImage" href="#"><button>save image</button></a>
    <script>
        `$("#showHideScopeInfo").click(function() {
            if (`$(this).html() == "Hide<br>ScopeInfo") {
                `$(this).html("Show<br>ScopeInfo");
                jQuery('.extraInfoContent').hide();
            } else {
                `$(this).html("Hide<br>ScopeInfo");
                jQuery('.extraInfoContent').show();
            };
        });
    </script>
</p>
"@
}
else {
    $htmlShowHideScopeInfo = '<p><a id="getImage" href="#"><button>save image</button></a></p>'
}

$html += @"
<body>
    <div class="se-pre-con"></div>
    <div class="tree">
        <div class="hierarchyTree" id="hierarchyTree">
            <div class="treeFeatureSel">
                <p class="pbordered pborderedspecial">HierarchyMap</p>
                $($htmlShowHideScopeInfo)
            </div>
"@

$html += @'
<ul>
    <div id="saveAsImageArea">
    <li id="first" style="background-color:white">
'@

if ($tenantDisplayName) {
    $tenantDetailsDisplay = "$tenantDisplayName<br>$tenantDefaultDomain<br>$($azAPICallConf['checkContext'].Tenant.Id)"
}
else {
    if ($HierarchyMapOnly -and $HierarchyMapOnlyCustomDataJSON) {
        $tenantDetailsDisplay = $ManagementGroupId
    }
    else {
        $tenantDetailsDisplay = "$($azAPICallConf['checkContext'].Tenant.Id)"
    }
}

$tenantRoleAssignmentCount = 0
if ($htMgAtScopeRoleAssignments.tenantLevelRoleAssignments) {
    $tenantRoleAssignmentCount = $htMgAtScopeRoleAssignments.tenantLevelRoleAssignments.AssignmentsCount
}
$html += @'
                        <a class="tenant">
                            <div class="main">

                                <div class="extraInfo">
                                    <div class="extraInfoContent">
                                    <div class="extraInfoPlchldr"></div>
'@

$html += @'
                                            </div>
                                            <div class="treeMgLogo">
                                                <img class="imgTreeLogoTenant" src="https://www.azadvertizer.net/azgovvizv4/icon/Azurev2.png">
                                            </div>
                                            <div class="extraInfoContent">
'@
if ($tenantRoleAssignmentCount -gt 0) {
    $html += @"
                                            <div class="extraInfoRoleAss">
                                                <abbr class="abbrTree" title="$($tenantRoleAssignmentCount) Role assignments">$($tenantRoleAssignmentCount)</abbr>
                                            </div>
"@
}
else {
    $html += @'
    <div class="extraInfoPlchldr"></div>
'@
}
$html += @"
                                    </div>
                                </div>

                                <div class="fitme" id="fitme">$($tenantDetailsDisplay)
                                </div>
                            </div>
                        </a>

"@

if ($getMgParentName -eq 'Tenant Root') {
    $html += @'

            <ul>
'@
}
else {
    if ($parentMgNamex -eq $parentMgIdx) {
        $mgNameAndOrId = $parentMgNamex
    }
    else {
        $mgNameAndOrId = "$parentMgNamex<br><i>$parentMgIdx</i>"
    }

    if ($tenantDisplayName) {
        $tenantDetailsDisplay = "$tenantDisplayName<br>$tenantDefaultDomain<br>"
    }
    else {
        $tenantDetailsDisplay = ''
    }

    $policiesMgScoped = ($htCacheDefinitionsPolicy).values.where({ $_.ScopeMgSub -eq 'Mg' })
    $policySetsMgScoped = ($htCacheDefinitionsPolicySet).values.where({ $_.ScopeMgSub -eq 'Mg' })
    $roleAssignmentsMg = (($htCacheAssignmentsRole).values.where({ $_.AssignmentScopeTenMgSubRgRes -eq 'Mg' }))

    foreach ($parentMgId in $htManagementGroupsMgPath.($ManagementGroupId).ParentNameChain) {
        if ($parentMgId -eq $defaultManagementGroupId) {
            $classdefaultMG = 'defaultMG'
        }
        else {
            $classdefaultMG = ''
        }

        $mgPolicyAssignmentCount = ($totalPolicyAssignmentsMg.where({ $_.AssignmentScopeId -eq $parentMgId })).Count
        $mgPolicyPolicySetScopedCount = ($policiesMgScoped.where({ $_.ScopeId -eq $parentMgId }).Count) + ($policySetsMgScoped.where({ $_.ScopeId -eq $parentMgId }).Count)
        $mgIdRoleAssignmentCount = $roleAssignmentsMg.where({ $_.AssignmentScopeId -eq $parentMgId }).Count

        $html += @"
        <ul>

                        <li><a class="mgnonradius parentmgnotaccessible $($classdefaultMG)">
                        <div class="main">

                        <div class="extraInfo">
                            <div class="extraInfoContent">
"@
        if ($mgPolicyAssignmentCount -gt 0 -or $mgPolicyPolicySetScopedCount -gt 0) {
            if ($mgPolicyAssignmentCount -gt 0 -and $mgPolicyPolicySetScopedCount -gt 0) {
                $html += @"
                                <div class="extraInfoPolicyAss1">
                                    <abbr class="abbrTree" title="$($mgPolicyAssignmentCount) Policy assignments">$($mgPolicyAssignmentCount)</abbr>
                                </div>
                                <div class="extraInfoPolicyScoped1">
                                    <abbr class="abbrTree" title="$($mgPolicyPolicySetScopedCount) Policy/PolicySet definitions scoped">$($mgPolicyPolicySetScopedCount)</abbr>
                                </div>
"@
            }
            else {
                if ($mgPolicyAssignmentCount -gt 0) {
                    $html += @"
                                    <div class="extraInfoPolicyAss0">
                                        <abbr class="abbrTree" title="$($mgPolicyAssignmentCount) Policy assignments">$($mgPolicyAssignmentCount)</abbr>
                                    </div>
"@
                }
                if ($mgPolicyPolicySetScopedCount -gt 0) {
                    $html += @"
                                    <div class="extraInfoPolicyScoped0">
                                        <abbr class="abbrTree" title="$($mgPolicyPolicySetScopedCount) Policy/PolicySet definitions scoped">$($mgPolicyPolicySetScopedCount)</abbr>
                                    </div>
"@
                }
            }
        }
        else {
            $html += @'
<div class="extraInfoPlchldr"></div>
'@
        }
        $html += @'
                                    </div>
                                    <div class="treeMgLogo">
                                        <img class="imgTreeLogo" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg">
                                    </div>
                                    <div class="extraInfoContent">
'@
        if ($mgIdRoleAssignmentCount -gt 0) {
            $html += @"
                                    <div class="extraInfoRoleAss">
                                        <abbr class="abbrTree" title="$($mgIdRoleAssignmentCount) Role assignments">$($mgIdRoleAssignmentCount)</abbr>
                                    </div>
"@
        }
        else {
            $html += @'
<div class="extraInfoPlchldr"></div>
'@
        }
        $html += @"
                            </div>
                        </div>

                        <div class="fitme" id="fitme">$($parentMgId)
                        </div>
                    </div>
                </a>
"@
    }
    $html += @'
<ul>
'@

}

$starthierarchyMap = Get-Date
Write-Host ' Building HierarchyMap'

HierarchyMgHTML -mgChild $ManagementGroupId
showMemoryUsage

$endhierarchyMap = Get-Date
Write-Host " Building HierarchyMap duration: $((New-TimeSpan -Start $starthierarchyMap -End $endhierarchyMap).TotalMinutes) minutes ($((New-TimeSpan -Start $starthierarchyMap -End $endhierarchyMap).TotalSeconds) seconds)"

if ($getMgParentName -eq 'Tenant Root') {
    $html += @'
                    </ul>
                </li>
            </ul>
        </div>
    </div>
'@
}
else {
    $html += @'
                            </ul>
                        </li>
                    </ul>
                </li>
                </div>
            </ul>
        </div>
    </div>
'@
}

if (-not $HierarchyMapOnly) {

    $html += @'
    <div class="summprnt" id="summprnt">
    <div class="summary" id="summary"><p class="pbordered">TenantSummary</p>
'@

    $html | Set-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
    $html = $null

    $startSummary = Get-Date

    if (-not $azAPICallConf['htParameters'].NoNetwork) {
        if (-not $ManagementGroupsOnly) {
            processNetwork
            processPrivateEndpoints
        }
    }

    processTenantSummary
    showMemoryUsage

    #region BuildDailySummaryCSV
    if (-not $NoCsvExport) {
        $dailySummary4ExportToCSV = [System.Collections.ArrayList]@()
        foreach ($entry in $htDailySummary.keys | Sort-Object) {
            $null = $dailySummary4ExportToCSV.Add([PSCustomObject]@{
                    capability = $entry
                    count      = $htDailySummary.($entry)
                })
        }
        Write-Host " Exporting DailySummary CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_DailySummary.csv'"
        $dailySummary4ExportToCSV | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_DailySummary.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
    }

    #endregion BuildDailySummaryCSV

    $endSummary = Get-Date
    Write-Host " Building TenantSummary duration: $((New-TimeSpan -Start $startSummary -End $endSummary).TotalMinutes) minutes ($((New-TimeSpan -Start $startSummary -End $endSummary).TotalSeconds) seconds)"

    $html += @'
    </div><!--summary-->
    </div><!--summprnt-->

    <div class="definitioninsightsprnt" id="definitioninsightsprnt">
    <div class="definitioninsights" id="definitioninsights"><p class="pbordered">DefinitionInsights</p>
'@
    $html | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
    $html = $null

    processDefinitionInsights
    showMemoryUsage

    $html += @'
    </div><!--definitionInsights-->
    </div><!--definitionInsightsprnt-->
'@

    if ((-not $NoScopeInsights) -or (-not $NoSingleSubscriptionOutput)) {

        if ((-not $NoScopeInsights)) {
            $html += @'
    <div class="hierprnt" id="hierprnt">
        <div class="hierarchyTables" id="hierarchyTables"><p class="pbordered">ScopeInsights</p>
'@
            $html | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
            $html = $null
            Write-Host ' Building ScopeInsights'
        }

        $startHierarchyTable = Get-Date
        $script:scopescnter = 0
        if ($azAPICallConf['htParameters'].NoResources -eq $false) {
            if ($azAPICallConf['htParameters'].DoPSRule -eq $true) {
                $grpPSRuleSubscriptions = $arrayPsRule | Group-Object -Property subscriptionId
                $grpPSRuleManagementGroups = $arrayPsRule | Group-Object -Property mgPath
            }
        }
        if ($arrayFeaturesAll.Count -gt 0) {
            $script:subFeaturesGroupedBySubscription = $arrayFeaturesAll | Group-Object -Property subscriptionId
        }
        if ($arrayOrphanedResourcesSlim.Count -gt 0) {
            $arrayOrphanedResourcesGroupedBySubscription = $arrayOrphanedResourcesSlim | Group-Object subscriptionId
        }
        $resourcesIdsAllCAFNamingRelevantGroupedBySubscription = $resourcesIdsAllCAFNamingRelevant | Group-Object -Property subscriptionId

        processScopeInsights -mgChild $ManagementGroupId -mgChildOf $getMgParentId
        showMemoryUsage

        $endHierarchyTable = Get-Date
        Write-Host " Building ScopeInsights duration: $((New-TimeSpan -Start $startHierarchyTable -End $endHierarchyTable).TotalMinutes) minutes ($((New-TimeSpan -Start $startHierarchyTable -End $endHierarchyTable).TotalSeconds) seconds)"

        if ((-not $NoScopeInsights)) {
            $html += @'
        </div>
    </div>
'@
        }
    }
}

$html += @'
    <div class="footer">
    <div class="VersionDiv VersionLatest"></div>
    <div class="VersionDiv VersionThis"></div>
    <div class="VersionAlert"></div>
'@
if (-not $HierarchyMapOnly) {
    $endAzGovVizHTML = Get-Date
    $AzGovVizHTMLDuration = (New-TimeSpan -Start $startAzGovViz -End $endAzGovVizHTML).TotalMinutes
    $paramsUsed += "Creation duration: $AzGovVizHTMLDuration minutes &#13;"
    if (-not $NoScopeInsights) {
        $html += @"
        <abbr style="text-decoration:none" title="$($paramsUsed)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr> <button id="hierarchyTreeShowHide" onclick="toggleHierarchyTree()">Hide HierarchyMap</button> <button id="summaryShowHide" onclick="togglesummprnt()">Hide TenantSummary</button> <button id="definitionInsightsShowHide" onclick="toggledefinitioninsightsprnt()">Hide DefinitionInsights</button> <button id="hierprntShowHide" onclick="togglehierprnt()">Hide ScopeInsights</button> $azGovVizNewerVersionAvailableHTML
        <hr>
"@
    }
    else {
        $html += @"
        <abbr style="text-decoration:none" title="$($paramsUsed)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr> <button id="hierarchyTreeShowHide" onclick="toggleHierarchyTree()">Hide HierarchyMap</button> <button id="summaryShowHide" onclick="togglesummprnt()">Hide TenantSummary</button> <button id="definitionInsightsShowHide" onclick="toggledefinitioninsightsprnt()">Hide DefinitionInsights</button> $azGovVizNewerVersionAvailableHTML
"@

    }
}

$html += @"
    </div>
    <script src="https://www.azadvertizer.net/azgovvizv4/js/toggle_v004_004.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv4/js/collapsetable_v004_001.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv4/js/fitty_v004_001.min.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv4/js/version_v004_004.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv4/js/autocorrectOff_v004_001.js"></script>
    <script>
        fitty('#fitme', {
            minSize: 7,
            maxSize: 10
        });
    </script>

    <script>
        `$("#getImage").on('click', function () {

            element = document.getElementById('saveAsImageArea')
            var images = element.getElementsByTagName('img');
            var l = images.length;
            for (var i = 0; i < l; i++) {
                images[0].parentNode.removeChild(images[0]);
            }

            var scale = 3;
            domtoimage.toPng(element, { quality: 0.95 , width: element.clientWidth * scale,
                height: element.clientHeight * scale,
                style: {
                    transform: 'scale('+scale+')',
                    transformOrigin: 'top left'
            }})
                .then(function (dataUrl) {
                var link = document.createElement('a');
                link.download = '$($fileName).png';
                link.href = dataUrl;
                link.click();
            });

            // domtoimage.toJpeg(element)
            //     .then(function (dataUrl) {
            //         var link = document.createElement('a');
            //         link.download = '$($fileName).jpeg';
            //         link.href = dataUrl;
            //         link.click();
            //     });

            })
    </script>
</body>
</html>
"@

$html | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force

$endBuildHTML = Get-Date
Write-Host "Building HTML total duration: $((New-TimeSpan -Start $startBuildHTML -End $endBuildHTML).TotalMinutes) minutes ($((New-TimeSpan -Start $startBuildHTML -End $endBuildHTML).TotalSeconds) seconds)"
#endregion BuildHTML

buildMD
showMemoryUsage

if (-not $azAPICallConf['htParameters'].NoJsonExport) {
    buildJSON
    showMemoryUsage
}

if (-not $HierarchyMapOnly) {
    buildPolicyAllJSON
}

#endregion createoutputs

apiCallTracking -stage 'Summary' -spacing ''

$endAzGovViz = Get-Date
$durationProduct = (New-TimeSpan -Start $startAzGovViz -End $endAzGovViz)
Write-Host "Azure Governance Visualizer duration: $($durationProduct.TotalMinutes) minutes"

#end
$endTime = Get-Date -Format 'dd-MMM-yyyy HH:mm:ss'
Write-Host "End Azure Governance Visualizer $endTime"

Write-Host 'Checking for errors'
if ($Error.Count -gt 0) {
    Write-Host "Dumping $($Error.Count) Errors (handled by Azure Governance Visualizer):"
    $Error | Out-Host
}
else {
    Write-Host 'Error count is 0'
}

stats

if ($DoTranscript) {
    Stop-Transcript
}

Write-Host ''
Write-Host '--------------------'
Write-Host 'Azure Governance Visualizer completed successful' -ForegroundColor Green

if ($Error.Count -gt 0) {
    Write-Host "Don't bother about dumped errors"
}

if ($DoPSRule) {
    $psRuleErrors = $arrayPsRule.where({ -not [string]::IsNullOrWhiteSpace($_.errorMsg) })
    if ($psRuleErrors) {
        Write-Host ''
        Write-Host "$($psRuleErrors.Count) 'PSRule for Azure' error(s) encountered"
        Write-Host 'Please review the error(s) and consider filing an issue at the PSRule.Rules.Azure GitHub repository https://github.com/Azure/PSRule.Rules.Azure - thank you'
        $psRuleErrorsGrouped = $psRuleErrors | Group-Object -Property resourceType, errorMsg
        foreach ($errorGroupedByResourceTypeAndMessage in $psRuleErrorsGrouped) {
            Write-Host "$($errorGroupedByResourceTypeAndMessage.Count) x $($errorGroupedByResourceTypeAndMessage.Name)"
            Write-Host 'Resources:'
            foreach ($resourceId in $errorGroupedByResourceTypeAndMessage.Group.resourceId) {
                Write-Host " -$resourceId"
            }
        }
    }
}

#region infoNewAzGovVizVersionAvailable
if ($azGovVizNewerVersionAvailable) {
    if ($azAPICallConf['htParameters'].onAzureDevOpsOrGitHubActions) {
        Write-Host ''
        Write-Host "This Azure Governance Visualizer version ($ProductVersion) is not up to date. Get the latest Azure Governance Visualizer version ($azGovVizVersionOnRepositoryFull)!"
        Write-Host 'Check the Azure Governance Visualizer history: https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting/blob/master/history.md'
    }
}
#endregion infoNewAzGovVizVersionAvailable

#region reportErrors
if ($htResourcePropertiesConvertfromJSONFailed.Keys.Count -gt 0) {
    Write-Host ''
    Write-Host ' * * * Please help * * *' -ForegroundColor DarkGreen
    Write-Host 'For the following resource(s) an error occurred converting from JSON (different casing). Please inspect the resource(s) for keys with different casing. Please file an issue at the Azure Governance Visualizer GitHub repository (aka.ms/AzGovViz) and provide the JSON dump for the resource(s) (scrub subscription Id and company identifyable names) - Thank you!'
    foreach ($resourceId in $htResourcePropertiesConvertfromJSONFailed.Keys) {
        Write-Host " resId: '$resourceId'"
    }
    Write-Host ' * * * * * *' -ForegroundColor DarkGreen
}
#endregion reportErrors

#region runIdentifier
if ($ShowRunIdentifier) {
    Write-Host "Azure Governance Visualizer run identifier: '$($statsIdentifier)'"
}
#endregion runIdentifier