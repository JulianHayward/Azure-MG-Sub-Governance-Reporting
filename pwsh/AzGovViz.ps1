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
    Do you want to have visibility on your Management Group hierarchy, document it in markdown? This script iterates Management Group hierarchy down to Subscription level capturing RBAC Roles, Policies and PolicySets (Initiatives).
 
.PARAMETER managementGroupId
    Define the Management Group Id for which the outputs/files shall be generated
 
.PARAMETER csvDelimiter
    The script outputs a csv file depending on your delimit defaults choose semicolon or comma

.PARAMETER outputPath
    Full- or relative path

.PARAMETER DoNotShowRoleAssignmentsUserData
    default is to capture the DisplayName and SignInName for RoleAssignments on ObjectType=User; for data protection and security reasons this may not be acceptable

.PARAMETER HierarchyTreeOnly
    default is to query all Management groups and Subscription for Governance capabilities, if you use the parameter -HierarchyTreeOnly then only the Hierarchy Tree will be created

.PARAMETER AzureDevOpsWikiAsCode
    default is to add timestamp to the MD output, use the parameter to remove the timestamp - the MD file will then only be pushed to Wiki Repo if the Management Group structure and/or Subscription linkage changed

.PARAMETER LimitCriticalPercentage
    default is 80%, this parameter indicates the warning level for approaching Limits (e.g. 80% of Role Assignment limit reached) change as per your preference

.EXAMPLE
    Define the ManagementGroup ID
    PS C:\> .\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id>

    Define how the CSV output should be delimited. Valid input is ; or , (semicolon is default)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -CsvDelimiter ","
    
    Define the outputPath (must exist)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -OutputPath 123
    
    Define if the script runs in AzureDevOps. This will not print any timestamps into the markdown output so that only true deviation will force a push to the wiki repository (default prints timestamps to the markdown output)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -AzureDevOpsWikiAsCode
    
    Define if User information shall be scrubbed (default prints Userinformation to the CSV and HTML output)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -DoNotShowRoleAssignmentsUserData
    
    Define when limits should be highlited as warning (default is 80 percent)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -LimitCriticalPercentage

    Define if only the hierarchy tree output shall be created. Will ignore the parameters 'LimitCriticalPercentage' and 'DoNotShowRoleAssignmentsUserData' (default queries for Governance capabilities such as policy-, role-, blueprints assignments and more)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -HierarchyTreeOnly

.NOTES
    AUTHOR: Julian Hayward - Premier Field Engineer - Azure Infrastucture/Automation/Devops/Governance

    Role assignments to Unknown Object happens when the graph object(User/Group/Service principal) gets deleted from the directory after the Role assignment was created. Since the graph entity is deleted, we cannot figure out the object's displayname or type from graph, due to which we show the objecType as Unknown.
    
    API permissions: If you run the script in Azure Automation or Azure DevOps hosted agent you will need to grant API permissions in Azure Active Directory (get-AzRoleAssignment cmdlet). The Automation Account App registration must be granted with: Azure Active Directory API | Application | Directory | Read.All

    The Limits might change, use the paramters to reflect changes

.LINK
    https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting

#>

[CmdletBinding()]
Param
(
    #[Parameter(Mandatory = $True)][string]$ManagementGroupId,
    [string]$ManagementGroupId,
    [string]$CsvDelimiter = ";",
    [string]$OutputPath,
    [switch]$DoNotShowRoleAssignmentsUserData,
    [switch]$HierarchyTreeOnly,
    [switch]$AzureDevOpsWikiAsCode,
    [int]$LimitCriticalPercentage = 80,

    #https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#role-based-access-control-limits
    [int]$LimitRBACCustomRoleDefinitionsTenant = 5000,
    [int]$LimitRBACRoleAssignmentsManagementGroup = 500,
    #[string]$LimitRBACRoleAssignmentsSubscription = 2000 #will be retrieved programatically

    #https://docs.microsoft.com/en-us/azure/governance/policy/overview#maximum-count-of-azure-policy-objects
    [int]$LimitPOLICYPolicyAssignmentsManagementGroup = 100,
    [int]$LimitPOLICYPolicyAssignmentsSubscription = 100,
    #[int]$LimitPOLICYPolicyDefinitionsScopedTenant = 1000,
    [int]$LimitPOLICYPolicyDefinitionsScopedManagementGroup = 500,
    [int]$LimitPOLICYPolicyDefinitionsScopedSubscription = 500,
    [int]$LimitPOLICYPolicySetAssignmentsManagementGroup = 100,
    [int]$LimitPOLICYPolicySetAssignmentsSubscription = 100,
    [int]$LimitPOLICYPolicySetDefinitionsScopedTenant = 2500,
    [int]$LimitPOLICYPolicySetDefinitionsScopedManagementGroup = 100,
    [int]$LimitPOLICYPolicySetDefinitionsScopedSubscription = 100,

    #https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#subscription-limits
    [int]$LimitResourceGroups = 980,
    [int]$LimitTagsSubscription = 50
)

function Add-IndexNumberToArray (
    [Parameter(Mandatory = $True)]
    [array]$array
) {
    for ($i = 0; $i -lt ($array | measure-object).count; $i++) { 
        Add-Member -InputObject $array[$i] -Name "#" -Value ($i + 1) -MemberType NoteProperty 
    }
    $array
}

#delimiter oppsite
if ($CsvDelimiter -eq ";") {
    $CsvDelimiterOpposite = ","
}
if ($CsvDelimiter -eq ",") {
    $CsvDelimiterOpposite = ";"
}

#check for required cmdlets
#Az.Context
$testCommands = @('Get-AzContext', 'Get-AzPolicyDefinition', 'Search-AzGraph')
foreach ($testCommand in $testCommands){
    if (-not (Get-Command $testCommand -ErrorAction Ignore)) {
        Write-Output "cmdlet $testCommand not available - make sure the modules Az.Accounts, Az.Resources and Az.ResourceGrpah are installed"
        return
    }
    else {
        Write-Output "passed: Az ps module supporting cmdlet $testCommandAzAccounts installed"
    }
}

#check if connected, verify Access Token lifetime
$tokenExirationMinimumInMinutes = 5
$checkContext = Get-AzContext

function refreshToken() {
    $checkContext = Get-AzContext
    Write-Output "Creating new Token"
    $azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile;
    $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile);
    $newAccessToken = ($profileClient.AcquireAccessToken($checkContext.Subscription.TenantId))
    if ($AzureDevOpsWikiAsCode) {
        $script:accessTokenExipresOn = ($checkContext.TokenCache.ReadItems() | Where-Object { ($_.Resource -eq "https://management.core.windows.net/") }).ExpiresOn
    }
    else {
        $script:accessTokenExipresOn = ($checkContext.TokenCache.ReadItems() | Where-Object { ($_.TenantId -eq $checkContext.Tenant.Id) -and ($_.Resource -eq "https://management.core.windows.net/") -and ($_.DisplayableId -eq $checkContext.account.id) }).ExpiresOn
    }
    #$script:accessTokenExipresOn = $newAccessToken.expiresOn
    $script:accessToken = $newAccessToken.AccessToken
}

function checkToken() {
    $tokenExirationInMinutes = ($accessTokenExipresOn - (get-date)).Minutes
    if ($tokenExirationInMinutes -lt $tokenExirationMinimumInMinutes) {
        Write-Output "Access Token for REST AUTH has has less than $tokenExirationMinimumInMinutes minutes lifetime ($tokenExirationInMinutes minutes). Creating new token"
        refreshToken
        Write-output "New Token expires: $($($script:accessTokenExipresOn).LocalDateTime) ($(($script:accessTokenExipresOn - (get-date)).Minutes) minutes)"
    }
    else {
        #Write-Output "Access Token for REST AUTH remaining lifetime ($tokenExirationInMinutes minutes) above minimum lifetime ($tokenExirationMinimumInMinutes minutes)"
    }
}

if ($checkContext) {
    if ($AzureDevOpsWikiAsCode) {
        $accessTokenExipresOn = ($checkContext.TokenCache.ReadItems() | Where-Object { ($_.Resource -eq "https://management.core.windows.net/") }).ExpiresOn
    }
    else {
        $accessTokenExipresOn = ($checkContext.TokenCache.ReadItems() | Where-Object { ($_.TenantId -eq $checkContext.Tenant.Id) -and ($_.Resource -eq "https://management.core.windows.net/") -and ($_.DisplayableId -eq $checkContext.account.id) }).ExpiresOn
    }

    if ($accessTokenExipresOn -lt $(Get-Date)) {
        Write-output "Access Token for REST AUTH has has expired"
        refreshToken
        Write-output "New Token expires: $($($script:accessTokenExipresOn).LocalDateTime) ($(($script:accessTokenExipresOn - (get-date)).Minutes) minutes)"
    }
    else {
        $tokenExirationInMinutes = ($accessTokenExipresOn - (get-date)).Minutes
        if ($tokenExirationInMinutes -lt $tokenExirationMinimumInMinutes) {
            Write-Output "Access Token for REST AUTH has has less than $tokenExirationMinimumInMinutes minutes lifetime ($tokenExirationInMinutes minutes)"
            refreshToken
            Write-output "New Token expires: $($($script:accessTokenExipresOn).LocalDateTime) ($(($script:accessTokenExipresOn - (get-date)).Minutes) minutes)"
        }
        else {
            if ($AzureDevOpsWikiAsCode) {
                $accessToken = ($checkContext.TokenCache.ReadItems() | Where-Object { ($_.Resource -eq "https://management.core.windows.net/") }).AccessToken
            }
            else {
                $accessToken = ($checkContext.TokenCache.ReadItems() | Where-Object { ($_.TenantId -eq $checkContext.Tenant.Id) -and ($_.Resource -eq "https://management.core.windows.net/") -and ($_.DisplayableId -eq $checkContext.account.id) }).AccessToken
            }
            Write-Output "Found Access Token for REST AUTH (expires in $tokenExirationInMinutes minutes; defined minimum lifetime: $tokenExirationMinimumInMinutes minutes).."
        }
    }
}
else {
    Write-Output "No context found. Please connect to Azure (run: Connect-AzAccount) and re-run script"
    return
}

#ManagementGroup helper
#thx @Jim Britt https://github.com/JimGBritt/AzurePolicy/tree/master/AzureMonitor/Scripts Create-AzDiagPolicy.ps1
if (-not $ManagementGroupId) {
    [array]$MgtGroupArray = Add-IndexNumberToArray (Get-AzManagementGroup)
    if (-not $MgtGroupArray) {
        Write-Output "Seems you do not have access to any Management Group. Please make sure you have the required RBAC role [Reader] assigned on at least one Management Group"
        return
    }
    Write-Output "Please select a Management Group from the list below"
    $MgtGroupArray | Select-Object "#", Name, DisplayName, Id | Format-Table
    try {
        Write-Output "If you don't see your ManagementGroupID try using the parameter -ManagementGroupID"
        $SelectedMG = Read-Host "Please enter a selection from 1 to $(($MgtGroupArray | measure-object).count)"
    }
    catch {
        Write-Warning -Message 'Invalid option, please try again.'
    }
    if ($($MgtGroupArray[$SelectedMG - 1].Name)) {
        $ManagementGroupID = $($MgtGroupArray[$SelectedMG - 1].Name)
        $ManagementGroupName = $($MgtGroupArray[$SelectedMG - 1].DisplayName)
    }
    Write-Output "Selected Management Group: $ManagementGroupName (Id: $ManagementGroupId)"
}

#helper file/dir
if (-not [IO.Path]::IsPathRooted($outputPath)) {
    $outputPath = Join-Path -Path (Get-Location).Path -ChildPath $outputPath
}
$outputPath = Join-Path -Path $outputPath -ChildPath '.'
$outputPath = [IO.Path]::GetFullPath($outputPath)
if (-not (test-path $outputPath)) {
    Write-Output "path $outputPath does not exist -create it!"
    return
}
else {
    Write-Output "Output/Files will be created in path $outputPath"
}
$DirectorySeparatorChar = [IO.Path]::DirectorySeparatorChar
$fileTimestamp = (get-date -format "yyyyMMddHHmmss")

if ($AzureDevOpsWikiAsCode) {
        $fileName = "AzGovViz_$($ManagementGroupId)"
}
else {
    if ($HierarchyTreeOnly){
        $fileName = "AzGovViz_$($fileTimestamp)_$($ManagementGroupId)_HierarchyOnly"
    }
    else{
        $fileName = "AzGovViz_$($fileTimestamp)_$($ManagementGroupId)"
    }
}

#helper 
$executionDateTimeInternationalReadable = get-date -format "dd-MMM-yyyy HH:mm:ss"
$currentTimeZone = (Get-TimeZone).Id

#run
Write-Output "Running AzGovViz for ManagementGroupId: '$ManagementGroupId'"
$startAzGovViz = get-date

#region Code
#region table
$table = [System.Data.DataTable]::new("AzGovViz")
$table.columns.add((New-Object system.Data.DataColumn Level, ([string])))
$table.columns.add((New-Object system.Data.DataColumn MgName, ([string])))
$table.columns.add((New-Object system.Data.DataColumn MgId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn mgParentId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn mgParentName, ([string])))
$table.columns.add((New-Object system.Data.DataColumn Subscription, ([string])))
$table.columns.add((New-Object system.Data.DataColumn SubscriptionId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn SubscriptionQuotaId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn SubscriptionState, ([string])))
$table.columns.add((New-Object system.Data.DataColumn SubscriptionASCSecureScore, ([string])))
$table.columns.add((New-Object system.Data.DataColumn SubscriptionTags, ([string])))
$table.columns.add((New-Object system.Data.DataColumn SubscriptionTagsLimit, ([int])))
$table.columns.add((New-Object system.Data.DataColumn SubscriptionTagsCount, ([int])))
$table.columns.add((New-Object system.Data.DataColumn Policy, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyVariant, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyType, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyCategory, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyDefinitionIdGuid, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyDefinitionIdFull, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyDefintionScope, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyDefinitionsScopedLimit, ([int])))
$table.columns.add((New-Object system.Data.DataColumn PolicyDefinitionsScopedCount, ([int])))
$table.columns.add((New-Object system.Data.DataColumn PolicySetDefinitionsScopedLimit, ([int])))
$table.columns.add((New-Object system.Data.DataColumn PolicySetDefinitionsScopedCount, ([int])))
$table.columns.add((New-Object system.Data.DataColumn PolicyAssignmentScope, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyAssignmentId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyAssignmentName, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyAssignmentIdentity, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyAssigmentLimit, ([int])))
$table.columns.add((New-Object system.Data.DataColumn PolicyAssigmentCount, ([int])))
$table.columns.add((New-Object system.Data.DataColumn PolicyAssigmentAtScopeCount, ([int])))
$table.columns.add((New-Object system.Data.DataColumn PolicySetAssigmentLimit, ([int])))
$table.columns.add((New-Object system.Data.DataColumn PolicySetAssigmentCount, ([int])))
$table.columns.add((New-Object system.Data.DataColumn PolicySetAssigmentAtScopeCount, ([int])))
$table.columns.add((New-Object system.Data.DataColumn PolicyAndPolicySetAssigmentAtScopeCount, ([int])))
$table.columns.add((New-Object system.Data.DataColumn RoleDefinitionName, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleDefinitionId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleIsCustom, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleActions, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleNotActions, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleDataActions, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleNotDataActions, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleAssignmentDisplayname, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleAssignmentSignInName, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleAssignmentObjectId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleAssignmentObjectType, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleAssignmentId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleAssignmentScope, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleAssignableScopes, ([string])))
$table.columns.add((New-Object system.Data.DataColumn RoleAssignmentsLimit, ([int])))
$table.columns.add((New-Object system.Data.DataColumn RoleAssignmentsCount, ([int])))
$table.columns.add((New-Object system.Data.DataColumn RoleSecurityCustomRoleOwner, ([int])))
$table.columns.add((New-Object system.Data.DataColumn RoleSecurityOwnerAssignmentSP, ([int])))
$table.columns.add((New-Object system.Data.DataColumn BlueprintName, ([string])))
$table.columns.add((New-Object system.Data.DataColumn BlueprintId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn BlueprintDisplayName, ([string])))
$table.columns.add((New-Object system.Data.DataColumn BlueprintDescription, ([string])))
$table.columns.add((New-Object system.Data.DataColumn BlueprintScoped, ([string])))
$table.columns.add((New-Object system.Data.DataColumn BlueprintAssignmentId, ([string])))
#endregion table

#region Function
function addRowToTable() {
    Param (
        $hierarchyLevel, 
        $mgName, 
        $mgId, 
        $mgParentId, 
        $mgParentName, 
        $Subscription, 
        $SubscriptionId, 
        $SubscriptionQuotaId, 
        $SubscriptionState, 
        $SubscriptionASCSecureScore, 
        $SubscriptionTags, 
        $SubscriptionTagsLimit = 0, 
        $SubscriptionTagsCount = 0, 
        $Policy, 
        $PolicyType, 
        $PolicyCategory, 
        $PolicyDefinitionIdGuid, 
        $PolicyDefinitionIdFull, 
        $PolicyDefintionScope, 
        $PolicyDefinitionsScopedLimit = 0, 
        $PolicyDefinitionsScopedCount = 0, 
        $PolicySetDefinitionsScopedLimit = 0, 
        $PolicySetDefinitionsScopedCount = 0, 
        $PolicyAssignmentScope, 
        $PolicyAssignmentId, 
        $PolicyAssignmentName, 
        $PolicyAssignmentIdentity, 
        $PolicyVariant, 
        $PolicyAssigmentLimit = 0, 
        $PolicyAssigmentCount = 0, 
        $PolicyAssigmentAtScopeCount = 0, 
        $PolicySetAssigmentLimit = 0, 
        $PolicySetAssigmentCount = 0, 
        $PolicySetAssigmentAtScopeCount = 0, 
        $PolicyAndPolicySetAssigmentAtScopeCount = 0, 
        $RoleDefinitionId, 
        $RoleDefinitionName,
        $RoleAssignmentDisplayname, 
        $RoleAssignmentSignInName, 
        $RoleAssignmentObjectId, 
        $RoleAssignmentObjectType, 
        $RoleAssignmentId, 
        $RoleAssignmentScope, 
        $RoleIsCustom, 
        $RoleAssignableScopes, 
        $RoleAssignmentsLimit = 0, 
        $RoleAssignmentsCount = 0, 
        $RoleActions, 
        $RoleNotActions, 
        $RoleDataActions, 
        $RoleNotDataActions, 
        $RoleSecurityCustomRoleOwner = 0, 
        $RoleSecurityOwnerAssignmentSP = 0, 
        $BlueprintName, 
        $BlueprintId, 
        $BlueprintDisplayName, 
        $BlueprintDescription, 
        $BlueprintScoped, 
        $BlueprintAssignmentId
    )
    $row = $table.NewRow()
    $row.Level = $hierarchyLevel
    $row.MgName = $mgName
    $row.MgId = $mgId
    $row.mgParentId = $mgParentId
    $row.mgParentName = $mgParentName
    $row.Subscription = $Subscription
    $row.SubscriptionId = $SubscriptionId
    $row.SubscriptionQuotaId = $SubscriptionQuotaId
    $row.SubscriptionState = $SubscriptionState
    $row.SubscriptionASCSecureScore = $SubscriptionASCSecureScore
    $row.SubscriptionTags = $SubscriptionTags
    $row.SubscriptionTagsLimit = $SubscriptionTagsLimit
    $row.SubscriptionTagsCount = $SubscriptionTagsCount
    $row.Policy = $Policy
    $row.PolicyType = $PolicyType
    $row.PolicyCategory = $PolicyCategory
    $row.PolicyDefinitionIdGuid = $PolicyDefinitionIdGuid
    $row.PolicyDefinitionIdFull = $PolicyDefinitionIdFull
    $row.PolicyDefintionScope = $PolicyDefintionScope
    $row.PolicyDefinitionsScopedLimit = $PolicyDefinitionsScopedLimit
    $row.PolicyDefinitionsScopedCount = $PolicyDefinitionsScopedCount 
    $row.PolicySetDefinitionsScopedLimit = $PolicySetDefinitionsScopedLimit
    $row.PolicySetDefinitionsScopedCount = $PolicySetDefinitionsScopedCount
    $row.PolicyAssignmentScope = $PolicyAssignmentScope
    $row.PolicyAssignmentId = $PolicyAssignmentId
    $row.PolicyAssignmentName = $PolicyAssignmentName
    $row.PolicyAssignmentIdentity = $PolicyAssignmentIdentity
    $row.PolicyVariant = $PolicyVariant 
    $row.PolicyAssigmentLimit = $PolicyAssigmentLimit
    $row.PolicyAssigmentCount = $PolicyAssigmentCount
    $row.PolicyAssigmentAtScopeCount = $PolicyAssigmentAtScopeCount
    $row.PolicySetAssigmentLimit = $PolicySetAssigmentLimit
    $row.PolicySetAssigmentCount = $PolicySetAssigmentCount
    $row.PolicySetAssigmentAtScopeCount = $PolicySetAssigmentAtScopeCount
    $row.PolicyAndPolicySetAssigmentAtScopeCount = $PolicyAndPolicySetAssigmentAtScopeCount
    $row.RoleDefinitionId = $RoleDefinitionId 
    $row.RoleDefinitionName = $RoleDefinitionName
    $row.RoleIsCustom = $RoleIsCustom
    $row.RoleActions = $RoleActions
    $row.RoleNotActions = $RoleNotActions
    $row.RoleDataActions = $RoleDataActions
    $row.RoleNotDataActions = $RoleNotDataActions
    $row.RoleAssignmentDisplayname = $RoleAssignmentDisplayname
    $row.RoleAssignmentSignInName = $RoleAssignmentSignInName
    $row.RoleAssignmentObjectId = $RoleAssignmentObjectId
    $row.RoleAssignmentObjectType = $RoleAssignmentObjectType
    $row.RoleAssignmentId = $RoleAssignmentId
    $row.RoleAssignmentScope = $RoleAssignmentScope
    $row.RoleAssignableScopes = $RoleAssignableScopes 
    $row.RoleAssignmentsLimit = $RoleAssignmentsLimit
    $row.RoleAssignmentsCount = $RoleAssignmentsCount
    $row.RoleSecurityCustomRoleOwner = $RoleSecurityCustomRoleOwner
    $row.RoleSecurityOwnerAssignmentSP = $RoleSecurityOwnerAssignmentSP
    $row.BlueprintName = $BlueprintName
    $row.BlueprintId = $BlueprintId
    $row.BlueprintDisplayName = $BlueprintDisplayName
    $row.BlueprintDescription = $BlueprintDescription
    $row.BlueprintScoped = $BlueprintScoped
    $row.BlueprintAssignmentId = $BlueprintAssignmentId
    $table.Rows.Add($row)
}

if (-not $HierarchyTreeOnly) {
    $startDefinitionsCaching = get-date
    Write-Output "Definitions caching"

    #helper ht / collect results /save some time
    $htCacheDefinitions = @{ }
    ($htCacheDefinitions).policy = @{ }
    ($htCacheDefinitions).policySet = @{ }
    ($htCacheDefinitions).role = @{ }
    $htPolicyUsedInPolicySet = @{ }
    $htSubscriptionTags = @{ }

    $currentContextSubscriptionQuotaId = (Search-AzGraph -Query "resourcecontainers | where type == 'microsoft.resources/subscriptions' | where subscriptionId == '$($checkContext.Subscription.Id)' | project properties.subscriptionPolicies.quotaId").properties_subscriptionPolicies_quotaId
    if (-not $currentContextSubscriptionQuotaId){
        Write-Output "Bad Subscription context for Definition Caching (SubscriptionName: $($checkContext.Subscription.Name); SubscriptionId: $($checkContext.Subscription.Id); likely an AAD_ QuotaId"
        $alternativeSubscriptionIdForDefinitionCaching = (Search-AzGraph -Query "resourcecontainers | where type == 'microsoft.resources/subscriptions' | where properties.subscriptionPolicies.quotaId !startswith 'AAD_' | project properties.subscriptionPolicies.quotaId, subscriptionId" -first 1)
        Write-Output "Using other Subscription for Definition Caching (SubscriptionId: $($alternativeSubscriptionIdForDefinitionCaching.subscriptionId); QuotaId: $($alternativeSubscriptionIdForDefinitionCaching.properties_subscriptionPolicies_quotaId))"
        $subscriptionIdForDefinitionCaching = $alternativeSubscriptionIdForDefinitionCaching.subscriptionId
    }
    else{
        Write-Output "OK Subscription context (QuotaId not 'AAD_*') for Definition Caching (SubscriptionId: $($checkContext.Subscription.Id); QuotaId: $currentContextSubscriptionQuotaId)"
        $subscriptionIdForDefinitionCaching = $checkContext.Subscription.Id
    }

    $builtinPolicyDefinitions = Get-AzPolicyDefinition -Builtin -SubscriptionId $SubscriptionIdForDefinitionCaching
    foreach ($builtinPolicyDefinition in $builtinPolicyDefinitions) {
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name) = @{ }
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).Id = $builtinPolicyDefinition.name
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).DisplayName = $builtinPolicyDefinition.Properties.displayname
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).Type = $builtinPolicyDefinition.Properties.policyType
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).Category = $builtinPolicyDefinition.Properties.metadata.category
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).PolicyDefinitionId = $builtinPolicyDefinition.PolicyDefinitionId
    }

    $builtinPolicySetDefinitions = Get-AzPolicySetDefinition -Builtin -SubscriptionId $SubscriptionIdForDefinitionCaching
    foreach ($builtinPolicySetDefinition in $builtinPolicySetDefinitions) {
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.name) = @{ }
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.name).Id = $builtinPolicySetDefinition.name
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.name).DisplayName = $builtinPolicySetDefinition.Properties.displayname
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.name).Type = $builtinPolicySetDefinition.Properties.policyType
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.name).Category = $builtinPolicySetDefinition.Properties.metadata.category
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.name).PolicyDefinitionId = $builtinPolicySetDefinition.PolicySetDefinitionId
    }

    $roleDefinitions = Get-AzRoleDefinition -Scope "/subscriptions/$SubscriptionIdForDefinitionCaching" | where-object { $_.IsCustom -eq $false }
    foreach ($roleDefinition in $roleDefinitions) {
        $($htCacheDefinitions).role.$($roleDefinition.Id) = @{ }
        $($htCacheDefinitions).role.$($roleDefinition.Id).Id = $($roleDefinition.Id)
        $($htCacheDefinitions).role.$($roleDefinition.Id).Name = $($roleDefinition.Name)
        $($htCacheDefinitions).role.$($roleDefinition.Id).IsCustom = $($roleDefinition.IsCustom)
        $($htCacheDefinitions).role.$($roleDefinition.Id).AssignableScopes = $($roleDefinition.AssignableScopes)
        $($htCacheDefinitions).role.$($roleDefinition.Id).Actions = $($roleDefinition.Actions)
        $($htCacheDefinitions).role.$($roleDefinition.Id).NotActions = $($roleDefinition.NotActions)
        $($htCacheDefinitions).role.$($roleDefinition.Id).DataActions = $($roleDefinition.DataActions)
        $($htCacheDefinitions).role.$($roleDefinition.Id).NotDataActions = $($roleDefinition.NotDataActions)
    }

    $endDefinitionsCaching = get-date
    Write-Output "Definitions caching duration: $((NEW-TIMESPAN -Start $startDefinitionsCaching -End $endDefinitionsCaching).TotalSeconds) seconds"
}

#region Function_dataCollection
function dataCollection($mgId, $hierarchyLevel, $mgParentId, $mgParentName) {
    checkToken
    $startMgLoop = get-date
    $hierarchyLevel++
    $getMg = Get-AzManagementGroup -groupname $mgId -Expand -Recurse
    Write-Output "DataCollection: Processing L$hierarchyLevel MG '$($getMg.DisplayName)' ('$($getMg.Name)')"

    if (-not $HierarchyTreeOnly) {
        $uriMgBlueprintDefinitionScoped = "https://management.azure.com//providers/Microsoft.Management/managementGroups/$($getMg.Name)/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
        $mgBlueprintDefinitionResult = Invoke-RestMethod -Uri $uriMgBlueprintDefinitionScoped -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
        if (($mgBlueprintDefinitionResult.value | measure-object).count -gt 0) {
            foreach ($blueprint in $mgBlueprintDefinitionResult.value) {
                $blueprintName = $blueprint.name
                $blueprintId = $blueprint.id
                $blueprintDisplayName = $blueprint.properties.displayName
                $blueprintDescription = $blueprint.properties.description
                $blueprintScoped = "/providers/Microsoft.Management/managementGroups/$($getMg.Name)"
                addRowToTable `
                    -hierarchyLevel $hierarchyLevel `
                    -mgName $getMg.DisplayName `
                    -mgId $getMg.Name `
                    -mgParentId $mgParentId `
                    -mgParentName $mgParentName `
                    -BlueprintName $blueprintName `
                    -BlueprintId $blueprintId `
                    -BlueprintDisplayName $blueprintDisplayName `
                    -BlueprintDescription $blueprintDescription `
                    -BlueprintScoped $blueprintScoped
            }
        }

        $mgPolicyDefinitions = Get-AzPolicyDefinition -ManagementGroupName $getMg.Name -custom
        $PolicyDefinitionsScopedCount = ((($mgPolicyDefinitions | Where-Object { $_.ResourceName -eq $getMg.Name }) | measure-object) | measure-object).count
        foreach ($mgPolicyDefinition in $mgPolicyDefinitions) {
            if (-not $($htCacheDefinitions).policy[$mgPolicyDefinition.name]) {
                #write-output "mgLoop not existing ht policy entry"
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.name) = @{ }
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.name).Id = $($mgPolicyDefinition.name)
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.name).DisplayName = $($mgPolicyDefinition.Properties.displayname)
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.name).Type = $($mgPolicyDefinition.Properties.policyType)
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.name).Category = $($mgPolicyDefinition.Properties.metadata.Category)
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.name).PolicyDefinitionId = $($mgPolicyDefinition.PolicyDefinitionId)
            }  
        }
        $mgPolicySetDefinitions = Get-AzPolicySetDefinition -ManagementGroupName $getMg.Name -custom
        $PolicySetDefinitionsScopedCount = ((($mgPolicySetDefinitions | Where-Object { $_.ResourceName -eq $getMg.Name }) | measure-object) | measure-object).count
        foreach ($mgPolicySetDefinition in $mgPolicySetDefinitions) {
            if (-not $($htCacheDefinitions).policySet[$mgPolicySetDefinition.name]) {
                #write-output "mgLoop not existing ht policySet entry"
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.name) = @{ }
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.name).Id = $($mgPolicySetDefinition.name)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.name).DisplayName = $($mgPolicySetDefinition.Properties.displayname)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.name).Type = $($mgPolicySetDefinition.Properties.policyType)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.name).Category = $($mgPolicySetDefinition.Properties.metadata.Category)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.name).PolicyDefinitionId = $($mgPolicySetDefinition.PolicySetDefinitionId)
                $policySetPoliciesArray = @()
                foreach ($policydefinitionMgPolicySetDefinition in $mgPolicySetDefinition.properties.policydefinitions){
                    $policySetPoliciesArray += $policydefinitionMgPolicySetDefinition.policyDefinitionId
                }
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.name).PolicySetPolicyIds = $policySetPoliciesArray
            }  

            foreach ($policydefinitionMgPolicySetDefinition in $mgPolicySetDefinition.properties.policydefinitions){
                if (($htPolicyUsedInPolicySet).$($policydefinitionMgPolicySetDefinition.policyDefinitionId -replace '.*/')) {
                    #write-output "existing ht policySet policy entry $($policydefinitionMgPolicySetDefinition.policyDefinitionId -replace '.*/')"
                }
                else{
                    #write-output "NOT existing ht policySet policy entry $($policydefinitionMgPolicySetDefinition.policyDefinitionId -replace '.*/')"
                    $($htPolicyUsedInPolicySet).$($policydefinitionMgPolicySetDefinition.policyDefinitionId -replace '.*/') = @{ }
                    $($htPolicyUsedInPolicySet).$($policydefinitionMgPolicySetDefinition.policyDefinitionId -replace '.*/').Id = ($policydefinitionMgPolicySetDefinition.policyDefinitionId -replace '.*/')
                }
            }
        }

        #MgPolicyAssignments
        $L0mgmtGroupPolicyAssignments = Get-AzPolicyAssignment -Scope "/providers/Microsoft.Management/managementGroups/$($getMg.Name)"
        #Write-Output "MG Policy Assignments: $($L0mgmtGroupPolicyAssignments.count)"
        $L0mgmtGroupPolicyAssignmentsPolicyCount = (($L0mgmtGroupPolicyAssignments | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" }) | measure-object).count
        $L0mgmtGroupPolicyAssignmentsPolicySetCount = (($L0mgmtGroupPolicyAssignments | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" }) | measure-object).count
        $L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount = (($L0mgmtGroupPolicyAssignments | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -and $_.PolicyAssignmentId -match "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" }) | measure-object).count
        $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount = (($L0mgmtGroupPolicyAssignments | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" -and $_.PolicyAssignmentId -match "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" }) | measure-object).count
        $L0mgmtGroupPolicyAssignmentsPolicyAndPolicySetAtScopeCount = ($L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount + $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount)

        foreach ($L0mgmtGroupPolicyAssignment in $L0mgmtGroupPolicyAssignments) {
            if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -OR $L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
                if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/") {
                    #policy
                    $PolicyVariant = "Policy"
                    $definitiontype = "policy"
                    $Id = $L0mgmtGroupPolicyAssignment.properties.policydefinitionid -replace '.*/'
                    $PolicyAssignmentScope = $L0mgmtGroupPolicyAssignment.Properties.Scope
                    $PolicyAssignmentId = $L0mgmtGroupPolicyAssignment.PolicyAssignmentId
                    $PolicyAssignmentName = $L0mgmtGroupPolicyAssignment.Name

                    if ($L0mgmtGroupPolicyAssignment.Identity) {
                        $PolicyAssignmentIdentity = $L0mgmtGroupPolicyAssignment.Identity.principalId
                    }
                    else {
                        $PolicyAssignmentIdentity = "n/a"
                    }

                    if ($htCacheDefinitions.$definitiontype.$($Id).Type -eq "Custom") {
                        $policyDefintionScope = ($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId -split "\/")[0..4] -join "/"
                    }
                    else {
                        $policyDefintionScope = "n/a"
                    }

                    addRowToTable `
                        -hierarchyLevel $hierarchyLevel `
                        -mgName $getMg.DisplayName `
                        -mgId $getMg.Name `
                        -mgParentId $mgParentId `
                        -mgParentName $mgParentName `
                        -Policy $htCacheDefinitions.$definitiontype.$($Id).DisplayName `
                        -PolicyType $htCacheDefinitions.$definitiontype.$($Id).Type `
                        -PolicyCategory $htCacheDefinitions.$definitiontype.$($Id).Category `
                        -PolicyDefinitionIdGuid $htCacheDefinitions.$definitiontype.$($Id).Id `
                        -PolicyDefinitionIdFull $htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId `
                        -PolicyDefintionScope $policyDefintionScope `
                        -PolicyDefinitionsScopedLimit $LimitPOLICYPolicyDefinitionsScopedManagementGroup `
                        -PolicyDefinitionsScopedCount $PolicyDefinitionsScopedCount `
                        -PolicySetDefinitionsScopedLimit $LimitPOLICYPolicySetDefinitionsScopedManagementGroup `
                        -PolicySetDefinitionsScopedCount $PolicySetDefinitionsScopedCount `
                        -PolicyAssignmentScope $PolicyAssignmentScope `
                        -PolicyAssignmentId $PolicyAssignmentId `
                        -PolicyAssignmentName $PolicyAssignmentName `
                        -PolicyAssignmentIdentity $PolicyAssignmentIdentity `
                        -PolicyVariant $PolicyVariant `
                        -PolicyAssigmentLimit $LimitPOLICYPolicyAssignmentsManagementGroup `
                        -PolicyAssigmentCount $L0mgmtGroupPolicyAssignmentsPolicyCount `
                        -PolicyAssigmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount `
                        -PolicySetAssigmentLimit $LimitPOLICYPolicySetAssignmentsManagementGroup `
                        -PolicySetAssigmentCount $L0mgmtGroupPolicyAssignmentsPolicySetCount `
                        -PolicySetAssigmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount `
                        -PolicyAndPolicySetAssigmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicyAndPolicySetAtScopeCount
                }

                if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
                    $PolicyVariant = "PolicySet"
                    $definitiontype = "policySet"
                    $Id = $L0mgmtGroupPolicyAssignment.properties.policydefinitionid -replace '.*/'
                    $PolicyAssignmentScope = $L0mgmtGroupPolicyAssignment.Properties.Scope
                    $PolicyAssignmentId = $L0mgmtGroupPolicyAssignment.PolicyAssignmentId
                    $PolicyAssignmentName = $L0mgmtGroupPolicyAssignment.Name

                    if ($L0mgmtGroupPolicyAssignment.Identity) {
                        $PolicyAssignmentIdentity = $L0mgmtGroupPolicyAssignment.Identity.principalId
                    }
                    else {
                        $PolicyAssignmentIdentity = "n/a"
                    }

                    if ($htCacheDefinitions.$definitiontype.$($Id).Type -eq "Custom") {
                        $policyDefintionScope = ($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId -split "\/")[0..4] -join "/"
                    }
                    else {
                        $policyDefintionScope = "n/a"
                    }

                    addRowToTable `
                        -hierarchyLevel $hierarchyLevel `
                        -mgName $getMg.DisplayName `
                        -mgId $getMg.Name `
                        -mgParentId $mgParentId `
                        -mgParentName $mgParentName `
                        -Policy $htCacheDefinitions.$definitiontype.$($Id).DisplayName `
                        -PolicyType $htCacheDefinitions.$definitiontype.$($Id).Type `
                        -PolicyCategory $htCacheDefinitions.$definitiontype.$($Id).Category `
                        -PolicyDefinitionIdGuid $htCacheDefinitions.$definitiontype.$($Id).Id `
                        -PolicyDefinitionIdFull $htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId `
                        -PolicyDefintionScope $policyDefintionScope `
                        -PolicyDefinitionsScopedLimit $LimitPOLICYPolicyDefinitionsScopedManagementGroup `
                        -PolicyDefinitionsScopedCount $PolicyDefinitionsScopedCount `
                        -PolicySetDefinitionsScopedLimit $LimitPOLICYPolicySetDefinitionsScopedManagementGroup `
                        -PolicySetDefinitionsScopedCount $PolicySetDefinitionsScopedCount `
                        -PolicyAssignmentScope $PolicyAssignmentScope `
                        -PolicyAssignmentId $PolicyAssignmentId `
                        -PolicyAssignmentName $PolicyAssignmentName `
                        -PolicyAssignmentIdentity $PolicyAssignmentIdentity `
                        -PolicyVariant $PolicyVariant `
                        -PolicyAssigmentLimit $LimitPOLICYPolicyAssignmentsManagementGroup `
                        -PolicyAssigmentCount $L0mgmtGroupPolicyAssignmentsPolicyCount `
                        -PolicyAssigmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount `
                        -PolicySetAssigmentLimit $LimitPOLICYPolicySetAssignmentsManagementGroup `
                        -PolicySetAssigmentCount $L0mgmtGroupPolicyAssignmentsPolicySetCount `
                        -PolicySetAssigmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount `
                        -PolicyAndPolicySetAssigmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicyAndPolicySetAtScopeCount
                }
            }
            else {
                #s.th unexpected
                Write-Output "DataCollection: unexpected"
                return
            }
        }
        #Write-Output "mg RoleDefinitions caching start"
        $mgCustomRoleDefinitions = Get-AzRoleDefinition -custom -Scope "/providers/Microsoft.Management/managementGroups/$($getMg.Name)"
        #$mgCustomRoleDefinitions.count
        foreach ($mgCustomRoleDefinition in $mgCustomRoleDefinitions) {
            if (-not $($htCacheDefinitions).role[$mgCustomRoleDefinition.Id]) {
                #write-output "mgLoop not existing ht role entry"
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.Id) = @{ }
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.Id).Id = $($mgCustomRoleDefinition.Id)
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.Id).Name = $($mgCustomRoleDefinition.Name)
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.Id).IsCustom = $($mgCustomRoleDefinition.IsCustom)
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.Id).AssignableScopes = $($mgCustomRoleDefinition.AssignableScopes)
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.Id).Actions = $($mgCustomRoleDefinition.Actions)
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.Id).NotActions = $($mgCustomRoleDefinition.NotActions)
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.Id).DataActions = $($mgCustomRoleDefinition.DataActions)
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.Id).NotDataActions = $($mgCustomRoleDefinition.NotDataActions)
            }  
        }
        #Write-Output "mg RoleDefinitions caching stop"
        $L0mgmtGroupRoleAssignments = Get-AzRoleAssignment -scope "/providers/Microsoft.Management/managementGroups/$($getMg.Name)"
        $L0mgmtGroupRoleAssignmentsLimitUtilization = (($L0mgmtGroupRoleAssignments | where-object { $_.Scope -eq "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" }) | measure-object).count
        #Write-Output "MG Role Assignments: $($L0mgmtGroupRoleAssignments.count)"
        foreach ($L0mgmtGroupRoleAssignment in $L0mgmtGroupRoleAssignments) {
            #$htRoles
            $Id = $L0mgmtGroupRoleAssignment.RoleDefinitionId
            $definitiontype = "role"

            if (($L0mgmtGroupRoleAssignment.RoleDefinitionName).length -eq 0) {
                $RoleDefinitionName = "'This roleDefinition was likely deleted although a roleAssignment existed'" 
            }
            else {
                $RoleDefinitionName = $L0mgmtGroupRoleAssignment.RoleDefinitionName
            }
            if (($L0mgmtGroupRoleAssignment.DisplayName).length -eq 0) {
                $RoleAssignmentDisplayname = "n/a" 
            }
            else {
                if ($L0mgmtGroupRoleAssignment.ObjectType -eq "User") {
                    if (-not $DoNotShowRoleAssignmentsUserData) {
                        $RoleAssignmentDisplayname = $L0mgmtGroupRoleAssignment.DisplayName
                    }
                    else {
                        $RoleAssignmentDisplayname = "scrubbed"
                    }
                }
                else {
                    $RoleAssignmentDisplayname = $L0mgmtGroupRoleAssignment.DisplayName
                }
            }                
            if (($L0mgmtGroupRoleAssignment.SignInName).length -eq 0) {
                $RoleAssignmentSignInName = "n/a" 
            }
            else {
                if ($L0mgmtGroupRoleAssignment.ObjectType -eq "User") {
                    if (-not $DoNotShowRoleAssignmentsUserData) {
                        $RoleAssignmentSignInName = $L0mgmtGroupRoleAssignment.SignInName
                    }
                    else {
                        $RoleAssignmentSignInName = "scrubbed"
                    }
                }
                else {
                    $RoleAssignmentSignInName = $L0mgmtGroupRoleAssignment.SignInName
                }
            }
            $RoleAssignmentObjectId = $L0mgmtGroupRoleAssignment.ObjectId
            $RoleAssignmentObjectType = $L0mgmtGroupRoleAssignment.ObjectType
            $RoleAssignmentId = $L0mgmtGroupRoleAssignment.RoleAssignmentId
            $RoleAssignmentScope = $L0mgmtGroupRoleAssignment.Scope

            $RoleSecurityCustomRoleOwner = 0
            if ($htCacheDefinitions.$definitiontype.$($Id).Actions -eq '*' -and (($htCacheDefinitions.$definitiontype.$($Id).NotActions)).length -eq 0 -and $htCacheDefinitions.$definitiontype.$($Id).IsCustom -eq $True) {
                $RoleSecurityCustomRoleOwner = 1
            }
            $RoleSecurityOwnerAssignmentSP = 0
            if (($htCacheDefinitions.$definitiontype.$($Id).Id -eq '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' -and $RoleAssignmentObjectType -eq "ServicePrincipal") -or ($htCacheDefinitions.$definitiontype.$($Id).Actions -eq '*' -and (($htCacheDefinitions.$definitiontype.$($Id).NotActions)).length -eq 0 -and $htCacheDefinitions.$definitiontype.$($Id).IsCustom -eq $True -and $RoleAssignmentObjectType -eq "ServicePrincipal")) {
                $RoleSecurityOwnerAssignmentSP = 1
            }

            addRowToTable `
                -hierarchyLevel $hierarchyLevel `
                -mgName $getMg.DisplayName `
                -mgId $getMg.Name `
                -mgParentId $mgParentId `
                -mgParentName $mgParentName `
                -RoleDefinitionId $htCacheDefinitions.$definitiontype.$($Id).Id `
                -RoleDefinitionName $RoleDefinitionName `
                -RoleIsCustom $htCacheDefinitions.$definitiontype.$($Id).IsCustom `
                -RoleAssignableScopes ($htCacheDefinitions.$definitiontype.$($Id).AssignableScopes -join "$CsvDelimiterOpposite ") `
                -RoleActions ($htCacheDefinitions.$definitiontype.$($Id).Actions -join "$CsvDelimiterOpposite ") `
                -RoleNotActions ($htCacheDefinitions.$definitiontype.$($Id).NotActions -join "$CsvDelimiterOpposite ") `
                -RoleDataActions ($htCacheDefinitions.$definitiontype.$($Id).DataActions -join "$CsvDelimiterOpposite ") `
                -RoleNotDataActions ($htCacheDefinitions.$definitiontype.$($Id).NotDataActions -join "$CsvDelimiterOpposite ") `
                -RoleAssignmentDisplayname $RoleAssignmentDisplayname `
                -RoleAssignmentSignInName $RoleAssignmentSignInName `
                -RoleAssignmentObjectId $RoleAssignmentObjectId `
                -RoleAssignmentObjectType $RoleAssignmentObjectType `
                -RoleAssignmentId $RoleAssignmentId `
                -RoleAssignmentScope $RoleAssignmentScope `
                -RoleAssignmentsLimit $LimitRBACRoleAssignmentsManagementGroup `
                -RoleAssignmentsCount $L0mgmtGroupRoleAssignmentsLimitUtilization `
                -RoleSecurityCustomRoleOwner $RoleSecurityCustomRoleOwner `
                -RoleSecurityOwnerAssignmentSP $RoleSecurityOwnerAssignmentSP
        }
    }
    else {
        addRowToTable `
            -hierarchyLevel $hierarchyLevel `
            -mgName $getMg.DisplayName `
            -mgId $getMg.Name `
            -mgParentId $mgParentId `
            -mgParentName $mgParentName
    }
    Write-Output "DataCollection: L$hierarchyLevel MG '$($getMg.DisplayName)' ('$($getMg.Name)') child items: $(($getMg.children | measure-object).count) (MG or Sub)"
    $endMgLoop = get-date
    Write-Output "DataCollection: Mg processing duration: $((NEW-TIMESPAN -Start $startMgLoop -End $endMgLoop).TotalSeconds) seconds"

    #SUBSCRIPTION
    if (($getMg.children | measure-object).count -gt 0) {
        
        foreach ($childMg in $getMg.Children | Where-Object { $_.Type -eq "/subscriptions" }) {
            checkToken
            $startSubLoop = get-date
            $childMgSubId = $childMg.Id -replace '/subscriptions/', ''
            Write-Output "DataCollection: Processing Subscription $($childMg.DisplayName) ('$childMgSubId')"

            if (-not $HierarchyTreeOnly) {
                #SubscriptionDetails
                #https://docs.microsoft.com/en-us/rest/api/resources/subscriptions/list
                $uriSubscriptionsGet = "https://management.azure.com/subscriptions/$($childMgSubId)?api-version=2020-01-01"
                $result = "letscheck"
                try {
                    $subscriptionsGetResult = Invoke-RestMethod -Uri $uriSubscriptionsGet -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
                } catch {
                    $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
                }
                if ($result -eq "letscheck"){              

                    if ($subscriptionsGetResult.subscriptionPolicies.quotaId.startswith("AAD_")) {
                        Write-Output "DataCollection: Subscription Quota Id: $($subscriptionsGetResult.subscriptionPolicies.quotaId) is out of scope for AzGovViz"
                        $subscriptionIsInScopeforAzGovViz = $False
                    }
                    else {
                        $subscriptionIsInScopeforAzGovViz = $True
                        if ($subscriptionsGetResult.tags) {
                            $SubscriptionTagsCount = ((($subscriptionsGetResult.tags).PSObject.Properties) | Measure-Object).Count
                            $subscriptionTags = @()
                            ($htSubscriptionTags).$($childMgSubId) = @{ }
                            ($subscriptionsGetResult.tags).PSObject.Properties | ForEach-Object {
                                $subscriptionTags += "$($_.Name)/$($_.Value)"
                                ($htSubscriptionTags).$($childMgSubId).$($_.Name) = $($_.Value)
                            }
                            $subscriptionTags = $subscriptionTags -join "$CsvDelimiterOpposite "
                        }
                        else {
                            $SubscriptionTagsCount = "0"
                            $subscriptionTags = "none"
                        }
                        $subscriptionQuotaId = $subscriptionsGetResult.subscriptionPolicies.quotaId
                        $subscriptionState = $subscriptionsGetResult.state
                    }

                    if ($True -eq $subscriptionIsInScopeforAzGovViz) {
                        Write-Output "DataCollection: Subscription Quota Id: $($subscriptionsGetResult.subscriptionPolicies.quotaId) is in scope for AzGovViz: $subscriptionIsInScopeforAzGovViz"
                        #ASC SecureScore
                        $uriSubASCSecureScore = "https://management.azure.com/subscriptions/$childMgSubId/providers/Microsoft.Security/securescores?api-version=2020-01-01-preview"
                        $result = "letscheck"
                        try {
                            $subASCSecureScoreResult = Invoke-RestMethod -Uri $uriSubASCSecureScore -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
                        } catch {
                            $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
                        }
                        if ($result -ne "letscheck"){
                            Write-Output "DataCollection: Subscription Id: $childMgSubId Getting ASC Secure Score error: '$result' -> skipping ASC Secure Score for this subscription"
                            $subscriptionASCSecureScore = "n/a"
                        }
                        else{
                            if (($subASCSecureScoreResult.value | measure-object).count -gt 0) {
                                $subscriptionASCSecureScore = "$($subASCSecureScoreResult.value.properties.score.current) of $($subASCSecureScoreResult.value.properties.score.max) points" 
                            }
                            else {
                                $subscriptionASCSecureScore = "n/a"
                            }
                        }

                        $uriSubBlueprintDefinitionScoped = "https://management.azure.com//subscriptions/$childMgSubId/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
                        $subBlueprintDefinitionResult = Invoke-RestMethod -Uri $uriSubBlueprintDefinitionScoped -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
                        if (($subBlueprintDefinitionResult.value | measure-object).count -gt 0) {
                            foreach ($blueprint in $subBlueprintDefinitionResult.value) {
                                $blueprintName = $blueprint.name
                                $blueprintId = $blueprint.id
                                $blueprintDisplayName = $blueprint.properties.displayName
                                $blueprintDescription = $blueprint.properties.description
                                $blueprintScoped = "/subscriptions/$childMgSubId"
                                addRowToTable `
                                    -hierarchyLevel $hierarchyLevel `
                                    -mgName $getMg.DisplayName `
                                    -mgId $getMg.Name `
                                    -mgParentId $mgParentId `
                                    -mgParentName $mgParentName `
                                    -Subscription $childMg.DisplayName `
                                    -SubscriptionId $childMgSubId `
                                    -SubscriptionQuotaId $subscriptionQuotaId `
                                    -SubscriptionState $subscriptionState `
                                    -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                                    -SubscriptionTags $subscriptionTags `
                                    -SubscriptionTagsLimit $LimitTagsSubscription `
                                    -SubscriptionTagsCount $SubscriptionTagsCount `
                                    -BlueprintName $blueprintName `
                                    -BlueprintId $blueprintId `
                                    -BlueprintDisplayName $blueprintDisplayName `
                                    -BlueprintDescription $blueprintDescription `
                                    -BlueprintScoped $blueprintScoped
                            }
                        }

                        #SubBlueprints
                        $urisubscriptionBlueprintAssignments = "https://management.azure.com/subscriptions/$childMgSubId/providers/Microsoft.Blueprint/blueprintAssignments?api-version=2018-11-01-preview"
                        $subscriptionBlueprintAssignmentsResult = Invoke-RestMethod -Uri $urisubscriptionBlueprintAssignments -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
                        if (($subscriptionBlueprintAssignmentsResult.value | measure-object).count -gt 0) {
                            #Write-Output "SUB Blueprint Assignments: $($subscriptionBlueprintAssignmentsResult.value.count)"
                            foreach ($subscriptionBlueprintAssignment in $subscriptionBlueprintAssignmentsResult.value) {
                                if (($subscriptionBlueprintAssignment.properties.blueprintId).StartsWith("/subscriptions/")) {
                                    $blueprintScope = $subscriptionBlueprintAssignment.properties.blueprintId -replace "/providers/Microsoft.Blueprint/blueprints/.*", ""
                                    $blueprintName = $subscriptionBlueprintAssignment.properties.blueprintId -replace ".*/blueprints/", "" -replace "/versions/.*", ""
                                }
                                if (($subscriptionBlueprintAssignment.properties.blueprintId).StartsWith("/providers/Microsoft.Management/managementGroups/")) {
                                    $blueprintScope = $subscriptionBlueprintAssignment.properties.blueprintId -replace "/providers/Microsoft.Blueprint/blueprints/.*", ""
                                    $blueprintName = $subscriptionBlueprintAssignment.properties.blueprintId -replace ".*/blueprints/", "" -replace "/versions/.*", ""
                                }
                                $uriSubscriptionBlueprintDefinition = "https://management.azure.com/$($blueprintScope)/providers/Microsoft.Blueprint/blueprints/$($blueprintName)?api-version=2018-11-01-preview"
                                $subscriptionBlueprintDefinitionResult = Invoke-RestMethod -Uri $uriSubscriptionBlueprintDefinition -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
                                $blueprintName = $subscriptionBlueprintDefinitionResult.name
                                $blueprintId = $subscriptionBlueprintDefinitionResult.id
                                $blueprintDisplayName = $subscriptionBlueprintDefinitionResult.properties.displayName
                                $blueprintDescription = $subscriptionBlueprintDefinitionResult.properties.description
                                $blueprintScoped = $blueprintScope
                                $blueprintAssignmentId = $subscriptionBlueprintAssignmentsResult.value.id
                                addRowToTable `
                                    -hierarchyLevel $hierarchyLevel `
                                    -mgName $getMg.DisplayName `
                                    -mgId $getMg.Name `
                                    -mgParentId $mgParentId `
                                    -mgParentName $mgParentName `
                                    -Subscription $childMg.DisplayName `
                                    -SubscriptionId $childMgSubId `
                                    -SubscriptionQuotaId $subscriptionQuotaId `
                                    -SubscriptionState $subscriptionState `
                                    -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                                    -SubscriptionTags $subscriptionTags `
                                    -SubscriptionTagsLimit $LimitTagsSubscription `
                                    -SubscriptionTagsCount $SubscriptionTagsCount `
                                    -BlueprintName $blueprintName `
                                    -BlueprintId $blueprintId `
                                    -BlueprintDisplayName $blueprintDisplayName `
                                    -BlueprintDescription $blueprintDescription `
                                    -BlueprintScoped $blueprintScoped `
                                    -BlueprintAssignmentId $blueprintAssignmentId
                            }
                        }

                        $subPolicyDefinitions = Get-AzPolicyDefinition -custom -SubscriptionId $childMgSubId
                        $PolicyDefinitionsScopedCount = (($subPolicyDefinitions | Where-Object { $_.SubscriptionId -eq $childMgSubId }) | measure-object).count
                        foreach ($subPolicyDefinition in $subPolicyDefinitions) {
                            if (-not $($htCacheDefinitions).policy[$subPolicyDefinition.name]) {
                                #write-output "subLoop not existing ht policy entry"
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.name) = @{ }
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.name).Id = $($subPolicyDefinition.name)
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.name).DisplayName = $($subPolicyDefinition.Properties.displayname)
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.name).Type = $($subPolicyDefinition.Properties.policyType)
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.name).Category = $($subPolicyDefinition.Properties.metadata.category)
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.name).PolicyDefinitionId = $($subPolicyDefinition.PolicyDefinitionId)
                            }  
                        }

                        $subPolicySetDefinitions = Get-AzPolicySetDefinition -custom -SubscriptionId $childMgSubId
                        $PolicySetDefinitionsScopedCount = (($subPolicySetDefinitions | Where-Object { $_.SubscriptionId -eq $childMgSubId }) | measure-object).count
                        foreach ($subPolicySetDefinition in $subPolicySetDefinitions) {
                            if (-not $($htCacheDefinitions).policySet[$subPolicySetDefinition.name]) {
                                #write-output "subLoop not existing ht policySet entry"
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.name) = @{ }
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.name).Id = $($subPolicySetDefinition.name)
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.name).DisplayName = $($subPolicySetDefinition.Properties.displayname)
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.name).Type = $($subPolicySetDefinition.Properties.policyType)
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.name).Category = $($subPolicySetDefinition.Properties.metadata.category)
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.name).PolicyDefinitionId = $($subPolicySetDefinition.PolicySetDefinitionId)
                                $policySetPoliciesArray = @()
                                foreach ($policydefinitionSubPolicySetDefinition in $subPolicySetDefinition.properties.policydefinitions){
                                    $policySetPoliciesArray += $policydefinitionSubPolicySetDefinition.policyDefinitionId
                                }
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.name).PolicySetPolicyIds = $policySetPoliciesArray
                            }  

                            foreach ($policydefinitionSubPolicySetDefinition in $subPolicySetDefinition.properties.policydefinitions){
                                if (($htPolicyUsedInPolicySet).$($policydefinitionSubPolicySetDefinition.policyDefinitionId -replace '.*/')) {
                                    #write-output "sub existing ht policySet policy entry $($policydefinitionSubPolicySetDefinition.policyDefinitionId -replace '.*/')"
                                }
                                else{
                                    #write-output "sub NOT existing ht policySet policy entry $($policydefinitionSubPolicySetDefinition.policyDefinitionId -replace '.*/')"
                                    $($htPolicyUsedInPolicySet).$($policydefinitionSubPolicySetDefinition.policyDefinitionId -replace '.*/') = @{ }
                                    $($htPolicyUsedInPolicySet).$($policydefinitionSubPolicySetDefinition.policyDefinitionId -replace '.*/').Id = ($policydefinitionSubPolicySetDefinition.policyDefinitionId -replace '.*/')
                                }
                            }
                        }

                        $L1mgmtGroupSubPolicyAssignments = Get-AzPolicyAssignment -Scope "$($childMg.Id)"
                        $L1mgmtGroupSubPolicyAssignmentsPolicyCount = (($L1mgmtGroupSubPolicyAssignments | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" }) | measure-object).count
                        $L1mgmtGroupSubPolicyAssignmentsPolicySetCount = (($L1mgmtGroupSubPolicyAssignments | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" }) | measure-object).count
                        $L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount = (($L1mgmtGroupSubPolicyAssignments | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -and $_.PolicyAssignmentId -match $childMg.Id }) | measure-object).count
                        $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount = (($L1mgmtGroupSubPolicyAssignments | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" -and $_.PolicyAssignmentId -match $childMg.Id }) | measure-object).count
                        $L1mgmtGroupSubPolicyAssignmentsPolicyAndPolicySetAtScopeCount = ($L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount + $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount)
                        foreach ($L1mgmtGroupSubPolicyAssignment in $L1mgmtGroupSubPolicyAssignments) {
                            #$htpolicies&htpolicySets
                            if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -OR $L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
                                if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/") {
                                    $PolicyVariant = "Policy"
                                    $definitiontype = "policy"
                                    $Id = $L1mgmtGroupSubPolicyAssignment.properties.policydefinitionid -replace '.*/'

                                    $PolicyAssignmentScope = $L1mgmtGroupSubPolicyAssignment.Properties.Scope
                                    $PolicyAssignmentId = $L1mgmtGroupSubPolicyAssignment.PolicyAssignmentId
                                    $PolicyAssignmentName = $L1mgmtGroupSubPolicyAssignment.Name

                                    if ($L1mgmtGroupSubPolicyAssignment.Identity) {
                                        $PolicyAssignmentIdentity = $L1mgmtGroupSubPolicyAssignment.Identity.principalId
                                    }
                                    else {
                                        $PolicyAssignmentIdentity = "n/a"
                                    }

                                    if ($htCacheDefinitions.$definitiontype.$($Id).Type -eq "Custom") {
                                        if (($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId).StartsWith("/subscriptions")) {
                                            $policyDefintionScope = ($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId -split "\/")[0..2] -join "/"
                                        }
                                        if (($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId).StartsWith("/providers")) {
                                            $policyDefintionScope = ($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId -split "\/")[0..4] -join "/"
                                        }
                                    }
                                    else {
                                        $policyDefintionScope = "n/a"
                                    }
                                    
                                    addRowToTable `
                                        -hierarchyLevel $hierarchyLevel `
                                        -mgName $getMg.DisplayName `
                                        -mgId $getMg.Name `
                                        -mgParentId $mgParentId `
                                        -mgParentName $mgParentName `
                                        -Subscription $childMg.DisplayName `
                                        -SubscriptionId $childMgSubId `
                                        -SubscriptionQuotaId $subscriptionQuotaId `
                                        -SubscriptionState $subscriptionState `
                                        -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                                        -SubscriptionTags $subscriptionTags `
                                        -SubscriptionTagsLimit $LimitTagsSubscription `
                                        -SubscriptionTagsCount $SubscriptionTagsCount `
                                        -Policy $htCacheDefinitions.$definitiontype.$($Id).DisplayName `
                                        -PolicyType $htCacheDefinitions.$definitiontype.$($Id).Type `
                                        -PolicyCategory $htCacheDefinitions.$definitiontype.$($Id).Category `
                                        -PolicyDefinitionIdGuid $htCacheDefinitions.$definitiontype.$($Id).Id `
                                        -PolicyDefinitionIdFull $htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId `
                                        -PolicyDefintionScope $policyDefintionScope `
                                        -PolicyDefinitionsScopedLimit $LimitPOLICYPolicyDefinitionsScopedSubscription `
                                        -PolicyDefinitionsScopedCount $PolicyDefinitionsScopedCount `
                                        -PolicySetDefinitionsScopedLimit $LimitPOLICYPolicySetDefinitionsScopedSubscription `
                                        -PolicySetDefinitionsScopedCount $PolicySetDefinitionsScopedCount `
                                        -PolicyAssignmentScope $PolicyAssignmentScope `
                                        -PolicyAssignmentId $PolicyAssignmentId `
                                        -PolicyAssignmentName $PolicyAssignmentName `
                                        -PolicyAssignmentIdentity $PolicyAssignmentIdentity `
                                        -PolicyVariant $PolicyVariant `
                                        -PolicyAssigmentLimit $LimitPOLICYPolicyAssignmentsSubscription `
                                        -PolicyAssigmentCount $L1mgmtGroupSubPolicyAssignmentsPolicyCount `
                                        -PolicyAssigmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount `
                                        -PolicySetAssigmentLimit $LimitPOLICYPolicySetAssignmentsSubscription `
                                        -PolicySetAssigmentCount $L1mgmtGroupSubPolicyAssignmentsPolicySetCount `
                                        -PolicySetAssigmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount `
                                        -PolicyAndPolicySetAssigmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicyAndPolicySetAtScopeCount
                                }
                                if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
                                    $PolicyVariant = "PolicySet"
                                    $definitiontype = "policySet"
                                    $Id = $L1mgmtGroupSubPolicyAssignment.properties.policydefinitionid -replace '.*/'

                                    $PolicyAssignmentScope = $L1mgmtGroupSubPolicyAssignment.Properties.Scope
                                    $PolicyAssignmentId = $L1mgmtGroupSubPolicyAssignment.PolicyAssignmentId
                                    $PolicyAssignmentName = $L1mgmtGroupSubPolicyAssignment.Name

                                    if ($L1mgmtGroupSubPolicyAssignment.Identity) {
                                        $PolicyAssignmentIdentity = $L1mgmtGroupSubPolicyAssignment.Identity.principalId
                                    }
                                    else {
                                        $PolicyAssignmentIdentity = "n/a"
                                    }

                                    if ($htCacheDefinitions.$definitiontype.$($Id).Type -eq "Custom") {
                                        if (($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId).StartsWith("/subscriptions")) {
                                            $policyDefintionScope = ($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId -split "\/")[0..2] -join "/"
                                        }
                                        if (($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId).StartsWith("/providers")) {
                                            $policyDefintionScope = ($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId -split "\/")[0..4] -join "/"
                                        }
                                    }
                                    else {
                                        $policyDefintionScope = "n/a"
                                    }

                                    addRowToTable `
                                        -hierarchyLevel $hierarchyLevel `
                                        -mgName $getMg.DisplayName `
                                        -mgId $getMg.Name `
                                        -mgParentId $mgParentId `
                                        -mgParentName $mgParentName `
                                        -Subscription $childMg.DisplayName `
                                        -SubscriptionId $childMgSubId `
                                        -SubscriptionQuotaId $subscriptionQuotaId `
                                        -SubscriptionState $subscriptionState `
                                        -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                                        -SubscriptionTags $subscriptionTags `
                                        -SubscriptionTagsLimit $LimitTagsSubscription `
                                        -SubscriptionTagsCount $SubscriptionTagsCount `
                                        -Policy $htCacheDefinitions.$definitiontype.$($Id).DisplayName `
                                        -PolicyType $htCacheDefinitions.$definitiontype.$($Id).Type `
                                        -PolicyCategory $htCacheDefinitions.$definitiontype.$($Id).Category `
                                        -PolicyDefinitionIdGuid $htCacheDefinitions.$definitiontype.$($Id).Id `
                                        -PolicyDefinitionIdFull $htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId `
                                        -PolicyDefintionScope $policyDefintionScope `
                                        -PolicyDefinitionsScopedLimit $LimitPOLICYPolicyDefinitionsScopedSubscription `
                                        -PolicyDefinitionsScopedCount $PolicyDefinitionsScopedCount `
                                        -PolicySetDefinitionsScopedLimit $LimitPOLICYPolicySetDefinitionsScopedSubscription `
                                        -PolicySetDefinitionsScopedCount $PolicySetDefinitionsScopedCount `
                                        -PolicyAssignmentScope $PolicyAssignmentScope `
                                        -PolicyAssignmentId $PolicyAssignmentId `
                                        -PolicyAssignmentName $PolicyAssignmentName `
                                        -PolicyAssignmentIdentity $PolicyAssignmentIdentity `
                                        -PolicyVariant $PolicyVariant `
                                        -PolicyAssigmentLimit $LimitPOLICYPolicyAssignmentsSubscription `
                                        -PolicyAssigmentCount $L1mgmtGroupSubPolicyAssignmentsPolicyCount `
                                        -PolicyAssigmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount `
                                        -PolicySetAssigmentLimit $LimitPOLICYPolicySetAssignmentsSubscription `
                                        -PolicySetAssigmentCount $L1mgmtGroupSubPolicyAssignmentsPolicySetCount `
                                        -PolicySetAssigmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount `
                                        -PolicyAndPolicySetAssigmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicyAndPolicySetAtScopeCount
                                }
                            }
                        }
                        #Write-Output "Sub RoleDefinitions caching start"
                        $subCustomRoleDefinitions = Get-AzRoleDefinition -custom -Scope "/subscriptions/$childMgSubId"
                        foreach ($subCustomRoleDefinition in $subCustomRoleDefinitions) {
                            if (-not $($htCacheDefinitions).role[$subCustomRoleDefinition.Id]) {
                                #write-output "subLoop not existing ht role entry"
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.Id) = @{ }
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.Id).Id = $($subCustomRoleDefinition.Id)
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.Id).Name = $($subCustomRoleDefinition.Name)
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.Id).IsCustom = $($subCustomRoleDefinition.IsCustom)
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.Id).AssignableScopes = $($subCustomRoleDefinition.AssignableScopes)
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.Id).Actions = $($subCustomRoleDefinition.Actions)
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.Id).NotActions = $($subCustomRoleDefinition.NotActions)
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.Id).DataActions = $($subCustomRoleDefinition.DataActions)
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.Id).NotDataActions = $($subCustomRoleDefinition.NotDataActions)
                            }  
                        }

                        $uriRoleAssignmentsUsageMetrics = "https://management.azure.com/subscriptions/$childMgSubId/providers/Microsoft.Authorization/roleAssignmentsUsageMetrics?api-version=2019-08-01-preview"
                        $roleAssignmentsUsage = Invoke-RestMethod -Uri $uriRoleAssignmentsUsageMetrics -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
                        $L1mgmtGroupSubRoleAssignments = Get-AzRoleAssignment -Scope "$($childMg.Id)" | where-object { $_.RoleAssignmentId -notmatch "$($childMg.Id)/resourcegroups/" } #exclude rg roleassignments
                        foreach ($L1mgmtGroupSubRoleAssignment in $L1mgmtGroupSubRoleAssignments) {
                            $Id = $L1mgmtGroupSubRoleAssignment.RoleDefinitionId
                            $definitiontype = "role"

                            if (($L1mgmtGroupSubRoleAssignment.RoleDefinitionName).length -eq 0) {
                                $RoleDefinitionName = "'This roleDefinition was likely deleted although a roleAssignment existed'" 
                            }
                            else {
                                $RoleDefinitionName = $L1mgmtGroupSubRoleAssignment.RoleDefinitionName
                            }
                            if (($L1mgmtGroupSubRoleAssignment.DisplayName).length -eq 0) {
                                $RoleAssignmentDisplayname = "n/a" 
                            }
                            else {
                                if ($L1mgmtGroupSubRoleAssignment.ObjectType -eq "User") {
                                    if (-not $DoNotShowRoleAssignmentsUserData) {
                                        $RoleAssignmentDisplayname = $L1mgmtGroupSubRoleAssignment.DisplayName
                                    }
                                    else {
                                        $RoleAssignmentDisplayname = "scrubbed"
                                    }
                                }
                                else {
                                    $RoleAssignmentDisplayname = $L1mgmtGroupSubRoleAssignment.DisplayName
                                }
                            }                
                            if (($L1mgmtGroupSubRoleAssignment.SignInName).length -eq 0) {
                                $RoleAssignmentSignInName = "n/a" 
                            }
                            else {
                                if ($L1mgmtGroupSubRoleAssignment.ObjectType -eq "User") {
                                    if (-not $DoNotShowRoleAssignmentsUserData) {
                                        $RoleAssignmentSignInName = $L1mgmtGroupSubRoleAssignment.SignInName
                                    }
                                    else {
                                        $RoleAssignmentSignInName = "scrubbed"
                                    }
                                }
                                else {
                                    $RoleAssignmentSignInName = $L1mgmtGroupSubRoleAssignment.SignInName
                                }
                            }
                            
                            $RoleAssignmentObjectId = $L1mgmtGroupSubRoleAssignment.ObjectId
                            $RoleAssignmentObjectType = $L1mgmtGroupSubRoleAssignment.ObjectType
                            $RoleAssignmentId = $L1mgmtGroupSubRoleAssignment.RoleAssignmentId
                            $RoleAssignmentScope = $L1mgmtGroupSubRoleAssignment.Scope

                            $RoleSecurityCustomRoleOwner = 0
                            if ($htCacheDefinitions.$definitiontype.$($Id).Actions -eq '*' -and (($htCacheDefinitions.$definitiontype.$($Id).NotActions)).length -eq 0 -and $htCacheDefinitions.$definitiontype.$($Id).IsCustom -eq $True) {
                                $RoleSecurityCustomRoleOwner = 1
                            }
                            $RoleSecurityOwnerAssignmentSP = 0
                            if (($htCacheDefinitions.$definitiontype.$($Id).Id -eq '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' -and $RoleAssignmentObjectType -eq "ServicePrincipal") -or ($htCacheDefinitions.$definitiontype.$($Id).Actions -eq '*' -and (($htCacheDefinitions.$definitiontype.$($Id).NotActions)).length -eq 0 -and $htCacheDefinitions.$definitiontype.$($Id).IsCustom -eq $True -and $RoleAssignmentObjectType -eq "ServicePrincipal")) {
                                $RoleSecurityOwnerAssignmentSP = 1
                            }

                            addRowToTable `
                                -hierarchyLevel $hierarchyLevel `
                                -mgName $getMg.DisplayName `
                                -mgId $getMg.Name `
                                -mgParentId $mgParentId `
                                -mgParentName $mgParentName `
                                -Subscription $childMg.DisplayName `
                                -SubscriptionId $childMgSubId `
                                -SubscriptionQuotaId $subscriptionQuotaId `
                                -SubscriptionState $subscriptionState `
                                -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                                -SubscriptionTags $subscriptionTags `
                                -SubscriptionTagsLimit $LimitTagsSubscription `
                                -SubscriptionTagsCount $SubscriptionTagsCount `
                                -RoleDefinitionId $htCacheDefinitions.$definitiontype.$($Id).Id `
                                -RoleDefinitionName $RoleDefinitionName `
                                -RoleIsCustom $htCacheDefinitions.$definitiontype.$($Id).IsCustom `
                                -RoleAssignableScopes ($htCacheDefinitions.$definitiontype.$($Id).AssignableScopes -join "$CsvDelimiterOpposite ") `
                                -RoleActions ($htCacheDefinitions.$definitiontype.$($Id).Actions -join "$CsvDelimiterOpposite ") `
                                -RoleNotActions ($htCacheDefinitions.$definitiontype.$($Id).NotActions -join "$CsvDelimiterOpposite ") `
                                -RoleDataActions ($htCacheDefinitions.$definitiontype.$($Id).DataActions -join "$CsvDelimiterOpposite ") `
                                -RoleNotDataActions ($htCacheDefinitions.$definitiontype.$($Id).NotDataActions -join "$CsvDelimiterOpposite ") `
                                -RoleAssignmentDisplayname $RoleAssignmentDisplayname `
                                -RoleAssignmentSignInName $RoleAssignmentSignInName `
                                -RoleAssignmentObjectId $RoleAssignmentObjectId `
                                -RoleAssignmentObjectType $RoleAssignmentObjectType `
                                -RoleAssignmentId $RoleAssignmentId `
                                -RoleAssignmentScope $RoleAssignmentScope `
                                -RoleAssignmentsLimit $roleAssignmentsUsage.roleAssignmentsLimit `
                                -RoleAssignmentsCount $roleAssignmentsUsage.roleAssignmentsCurrentCount `
                                -RoleSecurityCustomRoleOwner $RoleSecurityCustomRoleOwner `
                                -RoleSecurityOwnerAssignmentSP $RoleSecurityOwnerAssignmentSP
                        }
                    }
                    else {
                        Write-Output "DataCollection: Subscription Quota Id: $($subscriptionsGetResult.subscriptionPolicies.quotaId) is in scope for AzGovViz: $subscriptionIsInScopeforAzGovViz"
                        addRowToTable `
                            -hierarchyLevel $hierarchyLevel `
                            -mgName $getMg.DisplayName `
                            -mgId $getMg.Name `
                            -mgParentId $mgParentId `
                            -mgParentName $mgParentName `
                            -Subscription $childMg.DisplayName `
                            -SubscriptionId $childMgSubId `
                            -SubscriptionQuotaId $subscriptionQuotaId
                    }
                }
                else{
                    Write-Output "DataCollection: Subscription Id: $childMgSubId error: '$result' -> skipping this subscription"
                    addRowToTable `
                    -hierarchyLevel $hierarchyLevel `
                    -mgName $getMg.DisplayName `
                    -mgId $getMg.Name `
                    -mgParentId $mgParentId `
                    -mgParentName $mgParentName `
                    -Subscription $childMg.DisplayName `
                    -SubscriptionId $childMgSubId
                }
            }
            else {
                addRowToTable `
                    -hierarchyLevel $hierarchyLevel `
                    -mgName $getMg.DisplayName `
                    -mgId $getMg.Name `
                    -mgParentId $mgParentId `
                    -mgParentName $mgParentName `
                    -Subscription $childMg.DisplayName `
                    -SubscriptionId $childMgSubId
            }
            $endSubLoop = get-date
            Write-Output "DataCollection: Subscription processing duration: $((NEW-TIMESPAN -Start $startSubLoop -End $endSubLoop).TotalSeconds) seconds"
        }
        foreach ($childMg in $getMg.Children | Where-Object { $_.Type -eq "/providers/Microsoft.Management/managementGroups" }) {
            Write-Output "DataCollection: Trigger Management Group '$($childMg.DisplayName)' ('$($childMg.Name)')"
            dataCollection -mgId $childMg.Name -hierarchyLevel $hierarchyLevel -mgParentId $getMg.Name -mgParentName $getMg.DisplayName
        }
    }
}
#endregion Function_dataCollection

#HTML
function createMgPath($mgid) {
    $script:mgPathArray = @()
    $script:mgPathArray += "'$mgid'"
    if ($mgid -ne $mgSubPathTopMg) {
        do {
            $parentId = ($optimizedTableForPathQuery | Where-Object { $_.mgid -eq $mgid } | Sort-Object -Unique).mgParentId
            $mgid = $parentId
            $script:mgPathArray += "'$parentId'"
        }
        until($parentId -eq $mgSubPathTopMg)
    }
}

function createMgPathSub($subid) {
    $script:submgPathArray = @()
    $script:submgPathArray += "'$subid'"
    $mgid = ($optimizedTableForPathQuery | Where-Object { $_.subscriptionId -eq $subid }).mgId
    $script:submgPathArray += "'$mgid'"
    if ($mgid -ne $mgSubPathTopMg) {
        do {
            $parentId = ($optimizedTableForPathQuery | Where-Object { $_.mgid -eq $mgid } | Sort-Object -Unique).mgParentId
            $mgid = $parentId
            $script:submgPathArray += "'$parentId'"
        }
        until($parentId -eq $mgSubPathTopMg)
    }
}

function hierarchyMgHTML($mgChild){ 
    $mgDetails = ($mgAndSubBaseQuery | Where-Object {$_.MgId -eq "$mgChild"}) | Get-Unique
    $mgName = $mgDetails.mgName
    $mgId =$mgDetails.MgId

    if ($mgId -eq ($checkContext).Tenant.Id) {
        $class = "class=`"tenantRootGroup mgnonradius`""
        $liclass = "class=`"first`""
        $liId = "id=`"first`""
        $tenantDisplayNameAndDefaultDomain = $tenantDetailsDisplay
    }
    else {
        $class = "class=`"mgnonradius`""   
        $liclass = ""   
        $liId = ""
        $tenantDisplayNameAndDefaultDomain = ""
    }
    if ($mgName -eq $mgId) {
        $mgNameAndOrId = $mgName
    }
    else {
        $mgNameAndOrId = "$mgName<br><i>$mgId</i>"
    }
$script:html += @"
                    <li $liId $liclass><a $class href="#table_$mgId"><p><img id="hierarchy_$mgId" class="imgMgTree" src="https://www.azadvertizer.net/azgovviz/icon/Icon-general-11-Management-Groups.svg"></p><div class="fitme" id="fitme">$($tenantDisplayNameAndDefaultDomain)$($mgNameAndOrId)</div></a>
"@
    $childMgs = ($mgAndSubBaseQuery | Where-Object { $_.mgParentId -eq "$mgId" }).MgId | Get-Unique
    if (($childMgs | measure-object).count -gt 0){
$script:html += @"
                <ul>
"@
        foreach ($childMg in $childMgs){
            hierarchyMgHTML -mgChild $childMg
        }
        hierarchySubForMgHTML -mgChild $mgId
$script:html += @"
                </ul>
            </li>    
"@
    }
    else{
        hierarchySubForMgUlHTML -mgChild $mgId
$script:html += @"
            </li>
"@
    }
}

function hierarchySubForMgHTML($mgChild){
    $subscriptions = ($mgAndSubBaseQuery | Where-Object { "" -ne $_.Subscription -and $_.MgId -eq $mgChild }).SubscriptionId | Get-Unique
    write-output "Build HTML Hierarchy Tree for MG '$mgChild', $(($subscriptions | measure-object).count) Subscriptions"
    if (($subscriptions | measure-object).count -gt 0){
$script:html += @"
                    <li><a href="#table_$mgChild"><p><img id="hierarchySub_$mgChild" class="imgSubTree" src="https://www.azadvertizer.net/azgovviz/icon/Icon-general-2-Subscriptions.svg"> $(($subscriptions | measure-object).count)x</p></a></li>
"@
    }
}

function hierarchySubForMgUlHTML($mgChild){
    $subscriptions = ($mgAndSubBaseQuery | Where-Object { "" -ne $_.Subscription -and $_.MgId -eq $mgChild }).SubscriptionId | Get-Unique
    write-output "Build HTML Hierarchy Tree for MG '$mgChild', $(($subscriptions | measure-object).count) Subscriptions"
    if (($subscriptions | measure-object).count -gt 0){
$script:html += @"
                <ul>
                    <li><a href="#table_$mgChild"><p><img id="hierarchySub_$mgChild" class="imgSubTree" src="https://www.azadvertizer.net/azgovviz/icon/Icon-general-2-Subscriptions.svg"> $($subscriptions.Count)x</p></a></li></ul>
"@
    }
}

function tableMgHTML($mgChild, $mgChildOf){
    $mgDetails = ($mgAndSubBaseQuery | Where-Object {$_.MgId -eq "$mgChild"}) | Get-Unique
    $mgName = $mgDetails.mgName
    $mgLevel = $mgDetails.Level
    $mgId =$mgDetails.MgId

    switch ($mgLevel) {
        "0" { $levelSpacing = "|&nbsp;" }
        "1" { $levelSpacing = "|-&nbsp;" }
        "2" { $levelSpacing = "|--&nbsp;" }
        "3" { $levelSpacing = "|---&nbsp;" }
        "4" { $levelSpacing = "|----&nbsp;" }
        "5" { $levelSpacing = "|-----&nbsp;" }
        "6" { $levelSpacing = "|------&nbsp;" }
    }

    createMgPath -mgid $mgChild
    [array]::Reverse($script:mgPathArray)
    $mgPath = $script:mgPathArray -join "/"
    $mgLinkedSubsCount = ((($mgAndSubBaseQuery | Where-Object { $_.MgId -eq "$mgChild" -and "" -ne $_.SubscriptionId }).SubscriptionId | Get-Unique) | measure-object).count
    if ($mgLinkedSubsCount -gt 0) {
        $subImg = "Icon-general-2-Subscriptions"
        $subInfo = "<img class=`"imgSub`" src=`"https://www.azadvertizer.net/azgovviz/icon/$subImg.svg`">$mgLinkedSubsCount"
    }
    else {
        $subImg = "Icon-general-2-Subscriptions_grey"
        $subInfo = "<img class=`"imgSub`" src=`"https://www.azadvertizer.net/azgovviz/icon/$subImg.svg`">"
    }

    if ($mgName -eq $mgId){
        $mgNameAndOrId = "<b>$mgName</b>"
    }
    else{
        $mgNameAndOrId = "<b>$mgName</b> ($mgId)"
    }

$script:html += @"
    <button type="button" class="collapsible" id="table_$mgId">
        $levelSpacing<img class="imgMg" src="https://www.azadvertizer.net/azgovviz/icon/Icon-general-11-Management-Groups.svg"> <span class="valignMiddle">$mgNameAndOrId $subInfo</span>
    </button>
    <div class="content">

    <table class="bottomrow">
        <tr>
            <td>
                <p><a href="#hierarchy_$mgId"><i class="fa fa-eye" aria-hidden="true"></i> <i>Highlight Management Group in hierarchy tree</i></a></p>
            </td>
        </tr>
        <tr>
            <td>
                <p>Management Group Name: <b>$mgName</b></p>
            </td>
        </tr>
        <tr>
            <td>
                <p>Management Group Id: <b>$mgId</b></p>
            </td>
        </tr>
        <tr>
            <td>
                <p>Management Group Path: $mgPath</p>
            </td>
        </tr>
        <tr><!--x-->
            <td><!--x-->
"@
    tableMgSubDetailsHTML -mgOrSub "mg" -mgchild $mgId
    tableSubForMgHTML -mgChild $mgId
    $childMgs = ($mgAndSubBaseQuery | Where-Object {$_.mgParentId -eq "$mgId"}).MgId | sort-object -Unique
    if (($childMgs | measure-object).count -gt 0){
        foreach ($childMg in $childMgs){
            tableMgHTML -mgChild $childMg -mgChildOf $mgId
        }
    }
}

function tableSubForMgHTML($mgChild){ 
    $subscriptions = ($mgAndSubBaseQuery | Where-Object { "" -ne $_.SubscriptionId -and $_.MgId -eq $mgChild } | Sort-Object -Property Subscription -Unique).SubscriptionId
    write-output "Build HTML Hierarchy Table MG '$mgChild', $(($subscriptions | measure-object).count) Subscriptions"
    if (($subscriptions | measure-object).count -gt 0){
$script:html += @"
    <tr>
        <td>
            <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $(($subscriptions | measure-object).count) Subscriptions linked</p>
            </button>
            <div class="content"><!--collapsible-->
"@
        foreach ($subscriptionId in $subscriptions){
            $subscription = ($mgAndSubBaseQuery | Where-Object { $subscriptionId -eq $_.SubscriptionId -and $_.MgId -eq $mgChild }).Subscription | Get-Unique
            #write-output "Build HTML Hierarchy Details Tables for MG '$mgChild': Subscription linked: $subscription ($subscriptionId)"
            createMgPathSub -subid $subscriptionId
            [array]::Reverse($script:submgPathArray)
            $subPath = $script:submgPathArray -join "/"
            if (($subscriptions | measure-object).count -gt 1){
$script:html += @"
                <button type="button" class="collapsible"> <img class="imgSub" src="https://www.azadvertizer.net/azgovviz/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle"><b>$subscription</b> ($subscriptionId)</span>
                </button>
                <div class="contentSub"><!--collapsiblePerSub-->
"@
            }
            #exactly 1
            else{
$script:html += @"
                <img class="imgSub" src="https://www.azadvertizer.net/azgovviz/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle"><b>$subscription</b> ($subscriptionId)</span></button>
"@
            }

$script:html += @"
                <table class="subTable">
                    <tr>
                        <td>
                            <p>
                                <a href="#hierarchySub_$mgChild"><i class="fa fa-eye" aria-hidden="true"></i> <i>Highlight Subscription in hierarchy tree</i></a>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>
                                Subscription Name: <b>$subscription</b>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>
                                Subscription Id: <b>$subscriptionId</b>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>
                                Subscription Path: $subPath
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td>
"@
            tableMgSubDetailsHTML -mgOrSub "sub" -subscriptionId $subscriptionId
$script:html += @"
                </table><!--subTable-->
"@
            if (($subscriptions | measure-object).count-gt 1){
$script:html += @"
                </div><!--collapsiblePerSub-->
"@
            }
        }
$script:html += @"
            </div><!--collapsible-->
"@

    }
    else{
$script:html += @"
    <tr>
        <td>
            <p><i class="fa fa-ban" aria-hidden="true"></i> $(($subscriptions | measure-object).count) Subscriptions linked</p>
"@  
    }
$script:html += @"
                </td>
            </tr>
        </td>
    </tr>
</table>
</div>
"@
}

function tableMgSubDetailsHTML($mgOrSub, $mgChild, $subscriptionId){
    if ($mgOrSub -eq "mg"){
        #POLICY
        $policyReleatedQuery = $policyBaseQuery | Where-Object { $_.MgId -eq $mgChild -and "" -eq $_.SubscriptionId }
        $policiesCount = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" }) | measure-object).count
        $policiesCountBuiltin = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" -and $_.PolicyType -eq "BuiltIn" }) | measure-object).count
        $policiesCountCustom = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" -and $_.PolicyType -eq "Custom" }) | measure-object).count
        $policiesAssigned = $policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" }
        $policiesAssignedAtScope = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" -and $_.PolicyAssignmentScope -match "/providers/Microsoft.Management/managementGroups/$mgChild" }) | measure-object).count
        $policySetsCount = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" }) | measure-object).count
        $policySetsCountBuiltin = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyType -eq "BuiltIn" }) | measure-object).count
        $policySetsCountCustom = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyType -eq "Custom" }) | measure-object).count
        $policySetsAssigned = $policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" }
        $policySetsAssignedAtScope = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyAssignmentScope -match "/providers/Microsoft.Management/managementGroups/$mgChild" }) | measure-object).count
        $policiesInherited = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" -and $_.PolicyAssignmentId -notmatch "/providers/Microsoft.Management/managementGroups/$mgChild/" }) | measure-object).count
        $policySetsInherited = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyAssignmentId -notmatch "/providers/Microsoft.Management/managementGroups/$mgChild/" }) | measure-object).count
        $scopePoliciesCount = 0
        $scopePoliciesArray = @()
        foreach ($policy in ($htCacheDefinitions).policy.keys){
            if (($htCacheDefinitions).policy[$policy].PolicyDefinitionId -match "/providers/Microsoft.Management/managementGroups/$mgChild/"){
                $scopePoliciesCount++
                $scopePoliciesArray += ($htCacheDefinitions).policy[$policy].Id
            }
        }
        $scopePolicySetsCount = 0
        $scopePolicySetsArray = @()
        foreach ($policySet in ($htCacheDefinitions).policySet.keys){
            if (($htCacheDefinitions).policySet[$policySet].PolicyDefinitionId -match "/providers/Microsoft.Management/managementGroups/$mgChild/"){
                $scopePolicySetsCount++
                $scopePolicySetsArray += ($htCacheDefinitions).policySet[$policySet].Id
            }
        } 
        #RBAC
        $rbacReleatedQuery = $rbacBaseQuery | Where-Object { $_.MgId -eq $mgChild -and "" -eq $_.SubscriptionId }
        $rolesAssigned = $rbacReleatedQuery
        $rolesAssignedCount = ($rbacReleatedQuery | measure-object).count
        $rolesAssignedCountUser = (($rbacReleatedQuery | Where-Object { $_.RoleAssignmentObjectType -eq "User" }) | measure-object).count
        $rolesAssignedCountGroup = (($rbacReleatedQuery | Where-Object { $_.RoleAssignmentObjectType -eq "Group" }) | measure-object).count
        $rolesAssignedCountServicePrincipal = (($rbacReleatedQuery | Where-Object { $_.RoleAssignmentObjectType -eq "ServicePrincipal" }) | measure-object).count
        $rolesAssignedCountOrphaned = (($rbacReleatedQuery | Where-Object { $_.RoleAssignmentObjectType -eq "Unknown" }) | measure-object).count
        $rolesAssignedInherited = (($rbacReleatedQuery | Where-Object { $_.RoleAssignmentId -notmatch "/providers/Microsoft.Management/managementGroups/$mgChild/" }) | measure-object).count
        $rolesAssignedScope = (($rbacReleatedQuery | Where-Object { $_.RoleAssignmentId -match "/providers/Microsoft.Management/managementGroups/$mgChild/" }) | measure-object).count
        $roleSecurityFindingCustomRoleOwner = (($rbacReleatedQuery | Where-Object { $_.RoleSecurityCustomRoleOwner -eq 1 }) | measure-object).count
        $RoleSecurityFindingOwnerAssignmentSP = (($rbacReleatedQuery | Where-Object { $_.RoleSecurityOwnerAssignmentSP -eq 1 }) | measure-object).count
        $roleAssignmentsRelatedToPolicyCount = 0
        foreach ($roleAssigned in $rolesAssigned){
            $roleAssignmentsRelatedToPolicy = ($policyAssignmentIds | where-Object { $_.PolicyAssignmentName -eq $roleAssigned.RoleAssignmentDisplayname }).PolicyAssignmentId
            if ($roleAssignmentsRelatedToPolicy){
                $roleAssignmentsRelatedToPolicyCount++
            }
        }
        #BLUEPRINT
        $blueprintReleatedQuery = $blueprintBaseQuery | Where-Object { $_.MgId -eq $mgChild -and "" -eq $_.SubscriptionId -and "" -eq $_.BlueprintAssignmentId}
        $blueprintsScoped = $blueprintReleatedQuery
        $blueprintsScopedCount = ($blueprintsScoped | measure-object).count

        $cssClass = "mgDetailsTable"
    }
    if ($mgOrSub -eq "sub"){
        #POLICY
        $policyReleatedQuery = $policyBaseQuery | Where-Object { $_.SubscriptionId -eq $subscriptionId }
        $policiesCount = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" }) | measure-object).count
        $policiesCountBuiltin = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" -and $_.PolicyType -eq "BuiltIn" }) | measure-object).count
        $policiesCountCustom = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" -and $_.PolicyType -eq "Custom" }) | measure-object).count
        $policiesAssigned = $policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" }
        $policiesAssignedAtScope = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" -and $_.PolicyAssignmentScope -match "/subscriptions/$subscriptionId" }) | measure-object).count
        $policiesInherited = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "Policy" -and $_.PolicyAssignmentId -notmatch "/subscriptions/$subscriptionId/" }) | measure-object).count
        $policySetsCount = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" }) | measure-object).count
        $policySetsCountBuiltin = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyType -eq "BuiltIn" }) | measure-object).count
        $policySetsCountCustom = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyType -eq "Custom" }) | measure-object).count
        $policySetsAssigned = $policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" }
        $policySetsAssignedAtScope = (($policyReleatedQuery | where-object { $_.PolicyVariant -eq "PolicySet" -and $_.PolicyAssignmentScope -match "/subscriptions/$subscriptionId" }) | measure-object).count
        $policySetsInherited = (($policyReleatedQuery | where-object {$_.PolicyVariant -eq "PolicySet" -and $_.PolicyAssignmentId -notmatch "/subscriptions/$subscriptionId/" }) | measure-object).count
        $scopePoliciesCount = 0
        $scopePoliciesArray = @()
        foreach ($policy in ($htCacheDefinitions).policy.keys){
            if (($htCacheDefinitions).policy[$policy].PolicyDefinitionId -match "/Subscriptions/$subscriptionId/"){
                $scopePoliciesCount++
                $scopePoliciesArray += ($htCacheDefinitions).policy[$policy].Id
            }
        }
        $scopePolicySetsCount = 0
        $scopePolicySetsArray = @()
        foreach ($policySet in ($htCacheDefinitions).policySet.keys){
            if (($htCacheDefinitions).policySet[$policySet].PolicyDefinitionId -match "/Subscriptions/$subscriptionId/"){
                $scopePolicySetsCount++
                $scopePolicySetsArray += ($htCacheDefinitions).policySet[$policySet].Id
            }
        } 
        #RBAC
        $rbacReleatedQuery = $rbacBaseQuery | Where-Object { $_.SubscriptionId -eq $subscriptionId }
        $rolesAssigned = $rbacReleatedQuery
        $rolesAssignedCount = ($rbacReleatedQuery | measure-object).count
        $rolesAssignedCountUser = (($rbacReleatedQuery | Where-Object { $_.RoleAssignmentObjectType -eq "User" }) | measure-object).count
        $rolesAssignedCountGroup = (($rbacReleatedQuery | Where-Object { $_.RoleAssignmentObjectType -eq "Group" }) | measure-object).count
        $rolesAssignedCountServicePrincipal = (($rbacReleatedQuery | Where-Object { $_.RoleAssignmentObjectType -eq "ServicePrincipal" }) | measure-object).count
        $rolesAssignedCountOrphaned = (($rbacReleatedQuery | Where-Object { $_.RoleAssignmentObjectType -eq "Unknown" }) | measure-object).count
        $rolesAssignedInherited = (($rbacReleatedQuery | Where-Object { $_.RoleAssignmentId -notmatch "/subscriptions/$subscriptionId/" }) | measure-object).count
        $LimitRBACRoleAssignmentsSubscription = (($rbacReleatedQuery).RoleAssignmentsLimit | Get-Unique)
        $rolesAssignedScope = (($rbacReleatedQuery | Where-Object { $_.RoleAssignmentId -match "/subscriptions/$subscriptionId/" }) | measure-object).count
        $roleSecurityFindingCustomRoleOwner = (($rbacReleatedQuery | Where-Object { $_.RoleSecurityCustomRoleOwner -eq 1 }) | measure-object).count
        $RoleSecurityFindingOwnerAssignmentSP = (($rbacReleatedQuery | Where-Object { $_.RoleSecurityOwnerAssignmentSP -eq 1 }) | measure-object).count
        $roleAssignmentsRelatedToPolicyCount = 0
        foreach ($roleAssigned in $rolesAssigned){
            $roleAssignmentsRelatedToPolicy = ($policyAssignmentIds | where-Object { $_.PolicyAssignmentName -eq $roleAssigned.RoleAssignmentDisplayname }).PolicyAssignmentId
            if ($roleAssignmentsRelatedToPolicy){
                $roleAssignmentsRelatedToPolicyCount++
            }
        }
        #BLUEPRINT
        $blueprintReleatedQuery = $blueprintBaseQuery | Where-Object { $_.SubscriptionId -eq $subscriptionId -and "" -ne $_.BlueprintName }
        $blueprintsAssigned = $blueprintReleatedQuery | Where-Object { "" -ne $_.BlueprintAssignmentId }
        $blueprintsAssignedCount = ($blueprintsAssigned | measure-object).count
        $blueprintsScoped = $blueprintReleatedQuery | Where-Object { $_.BlueprintScoped -eq "/subscriptions/$subscriptionId" -and "" -eq $_.BlueprintAssignmentId }
        $blueprintsScopedCount = ($blueprintsScoped | measure-object).count
        #SubscriptionTAGS
        $tagsSubscriptionCount = ($subscriptionBaseQuery | where-object { $_.SubscriptionId -eq $subscriptionId } | Select-Object -Property SubscriptionTagsCount -Unique).SubscriptionTagsCount
        #SubscriptionDetails
        $subscriptionDetailsReleatedQuery = $subscriptionBaseQuery | Where-Object { $_.SubscriptionId -eq $subscriptionId }
        $subscriptionState = ($subscriptionDetailsReleatedQuery).SubscriptionState | sort-object -Unique
        $subscriptionQuotaId = ($subscriptionDetailsReleatedQuery).SubscriptionQuotaId | sort-object -Unique    
        $SubscriptionResourceGroupsCount = ($resourceGroupsAll | where-object { $_.subscriptionId -eq $subscriptionId }).count_
        if (-not $SubscriptionResourceGroupsCount){
            $SubscriptionResourceGroupsCount = 0
        }
        #SubscriptionASCPoints
        $subscriptionASCPoints = ($subscriptionDetailsReleatedQuery).SubscriptionASCSecureScore | Get-Unique

        $cssClass = "subDetailsTable"
    }

if ($mgOrSub -eq "sub"){
$script:html += @"
            <p>State: $subscriptionState</p>
        </td>
    </tr>
    <tr>
        <td>
            <p>QuotaId: $subscriptionQuotaId</p>
        </td>
    </tr>
    <tr>
        <td>
            <p><i class="fa fa-shield" aria-hidden="true"></i> ASC Secure Score: $subscriptionASCPoints</p>
        </td>
    </tr>
    <tr>
        <td>
"@

#ResourceGroups
if ($SubscriptionResourceGroupsCount -gt 0){
$script:html += @"
    <p><i class="fa fa-check-circle" aria-hidden="true"></i> $SubscriptionResourceGroupsCount Resource Groups | Limit: ($SubscriptionResourceGroupsCount/$LimitResourceGroups)</p>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> $SubscriptionResourceGroupsCount Resource Groups</p>
"@
}
$script:html += @"
        </td>
    </tr>
    <tr>
        <td>
"@
}

#Tags
if ($mgOrSub -eq "sub"){
    if ($tagsSubscriptionCount -gt 0){
$script:html += @"
    <button type="button" class="collapsible">
        <p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $tagsSubscriptionCount Subscription Tags | Limit: ($tagsSubscriptionCount/$LimitTagsSubscription)</p></button>
    <div class="content">
        <table class="$cssClass">
            <tr>
                <th class="widthCustom">
                    Tag Name
                </th>
                <th>
                    Tag Value
                </th>
            </tr>
"@
        foreach ($tag in (($htSubscriptionTags).($subscriptionId)).keys | Sort-Object){
$script:html += @"
            <tr>
                <td>
                    $tag
                </td>
                <td>
                    $($htSubscriptionTags.$subscriptionId[$tag])
                </td>
            </tr>
"@        
        }
$script:html += @"
        </table>
    </div>
"@
    }
    else{
$script:html += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> $tagsSubscriptionCount Subscription Tags</p>
"@
    }
$script:html += @"
        </td></tr>
        <tr><!--y--><td><!--y-->
"@
}

#resources
if ($mgOrSub -eq "sub"){
    $resourcesSubscription = $resourcesAll | where-object { $_.subscriptionId -eq $subscriptionId }
    $resourcesSubscriptionTotal = 0
    $resourcesSubscription.count_ | ForEach-Object { $resourcesSubscriptionTotal += $_ }
    $resourcesSubscriptionResourceTypeCount = (($resourcesSubscription | sort-object -Property type -Unique) | measure-object).count
    $resourcesSubscriptionLocationCount = (($resourcesSubscription | sort-object -Property location -Unique) | measure-object).count
    if ($resourcesSubscriptionResourceTypeCount -gt 0){
$script:html += @"
    <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $resourcesSubscriptionResourceTypeCount ResourceTypes ($resourcesSubscriptionTotal Resources) in $resourcesSubscriptionLocationCount Locations</p></button>
    <div class="content">
        <table class="$cssClass">
            <tr>
                <th class="widthCustom">
                    ResourceType
                </th>
                <th>
                    Location
                </th>
                <th>
                    Count
                </th>
            </tr>
"@
        foreach ($resourceSubscriptionResourceTypePerLocation in $resourcesSubscription){
$script:html += @"
            <tr>
                <td>
                    $($resourceSubscriptionResourceTypePerLocation.type)
                </td>
                <td>
                    $($resourceSubscriptionResourceTypePerLocation.location)
                </td>
                <td>
                    $($resourceSubscriptionResourceTypePerLocation.count_)
                </td>
            </tr>
"@        
        }
$script:html += @"
        </table>
    </div>
"@
    }
    else{
$script:html += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> $resourcesSubscriptionResourceTypeCount ResourceTypes</p>
"@
    }
$script:html += @"
            </td></tr>
            <tr><td>
"@
}

#policyAssignments
if ($policiesCount -gt 0){
$script:html += @"
    <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $policiesCount Policy Assignments ($policiesAssignedAtScope at scope, $policiesInherited inherited) (Builtin: $policiesCountBuiltin | Custom: $policiesCountCustom)</p></button>
    <div class="content">
        <table class="$cssClass">
            <tr>
                <th class="widthCustom">
                    Policy DisplayName
                </th>
                <th>
                    Type
                </th>
                <th>
                    Category
                </th>
                <th>
                    Inheritance
                </th>
                <th>
                    Policy AssignmentId
                </th>
            </tr>
"@
            foreach ($policyAssignment in $policiesAssigned){
                if ($policyAssignment.PolicyType -eq "builtin"){
                    $policyWithWithoutLinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/$($policyAssignment.policyDefinitionIdGuid).html`" target=`"_blank`">$($policyAssignment.policy)</a>"
                }
                else{
                    $policyWithWithoutLinkToAzAdvertizer = $policyAssignment.policy
                }

                if ($mgOrSub -eq "mg"){
                    if ($policyAssignment.PolicyAssignmentId -notmatch "/providers/Microsoft.Management/managementGroups/$mgChild/"){
                        $policyAssignedAtScopeOrInherted = "inherited MG"

                    }
                    else{
                        $policyAssignedAtScopeOrInherted = "this resource"
                    }
                }
        
                if ($mgOrSub -eq "sub"){
                    if ($policyAssignment.PolicyAssignmentId -notmatch "/subscriptions/$subscriptionId/"){
                        $policyAssignedAtScopeOrInherted = "inherited MG"
                    }
                    else{
                        $policyAssignedAtScopeOrInherted = "this resource"
                    }
                }  

$script:html += @"
            <tr>
                <td>
                    $policyWithWithoutLinkToAzAdvertizer
                </td>
                <td>
                    $($policyAssignment.PolicyType)
                </td>
                <td>
                    $($policyAssignment.PolicyCategory)
                </td>
                <td>
                    $policyAssignedAtScopeOrInherted
                </td>
                <td>
                    $($policyAssignment.PolicyAssignmentId)
                </td>
            </tr>
"@        
            }
$script:html += @"
        </table>
    </div>
"@
        }
        else{
$script:html += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> $policiesCount Policy Assignments ($policiesAssignedAtScope at scope, $policiesInherited inherited) (Builtin: $policiesCountBuiltin | Custom: $policiesCountCustom)</p>
"@
        }
$script:html += @"
        </td></tr>
        <tr><!--y--><td><!--y-->
"@

#PolicySetAssignments
if ($policySetsCount -gt 0){
$script:html += @"
    <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $policySetsCount PolicySet Assignments ($policySetsAssignedAtScope at scope, $policySetsInherited inherited) (Builtin: $policySetsCountBuiltin | Custom: $policySetsCountCustom)</p></button>
    <div class="content">
        <table class="$cssClass">
            <tr>
                <th class="widthCustom">
                    PolicySet DisplayName
                </th>
                <th>
                    Type
                </th>
                <th>
                    Category
                </th>
                <th>
                    Inheritance
                </th>
                <th>
                    PolicySet AssignmentId
                </th>
            </tr>
"@
    foreach ($policySetAssignment in $policySetsAssigned){
        if ($policySetAssignment.PolicyType -eq "builtin"){
            $policyWithWithoutLinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyinitiativesadvertizer/$($policySetAssignment.policyDefinitionIdGuid).html`" target=`"_blank`">$($policySetAssignment.policy)</a>"
        }
        else{
            $policyWithWithoutLinkToAzAdvertizer = $policySetAssignment.policy
        }

        if ($mgOrSub -eq "mg"){
            if ($policySetAssignment.PolicyAssignmentId -notmatch "/providers/Microsoft.Management/managementGroups/$mgChild/"){
                $policyAssignedAtScopeOrInherted = "inherited MG"

            }
            else{
                $policyAssignedAtScopeOrInherted = "this resource"
            }
        }

        if ($mgOrSub -eq "sub"){
            if ($policySetAssignment.PolicyAssignmentId -notmatch "/subscriptions/$subscriptionId/"){
                $policyAssignedAtScopeOrInherted = "inherited MG"
            }
            else{
                $policyAssignedAtScopeOrInherted = "this resource"
            }
        }  
$script:html += @"
            <tr>
                <td>
                    $policyWithWithoutLinkToAzAdvertizer
                </td>
                <td>
                    $($policySetAssignment.PolicyType)
                </td>
                <td>
                    $($policySetAssignment.PolicyCategory)
                </td>
                <td>
                    $policyAssignedAtScopeOrInherted
                </td>
                <td>
                    $($policySetAssignment.PolicyAssignmentId)
                </td>
            </tr>
"@        
    }
$script:html += @"
        </table>
    </div>
"@
}
else{
$script:html += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> $policySetsCount PolicySet Assignments ($policySetsAssignedAtScope at scope, $policySetsInherited inherited) (Builtin: $policySetsCountBuiltin | Custom: $policySetsCountCustom)</p>
"@
}
$script:html += @"
        </td></tr>
        <tr><td><!--z-->
"@

#PolicyAssigments Limit (Policy+PolicySet)
if ($policiesAssignedAtScope -eq 0 -and $policySetsAssignedAtScope -eq 0){
    if ($mgOrSub -eq "mg"){
        $limit = $LimitPOLICYPolicyAssignmentsManagementGroup
    }
    if ($mgOrSub -eq "sub"){
        $limit = $LimitPOLICYPolicyAssignmentsSubscription
    }
    $faimage = "<i class=`"fa fa-ban`" aria-hidden=`"true`"></i>"
    
$script:html += @"
            <p>$faImage Policy Assignment Limit: 0/$limit</p>
"@
}
else{
    if ($mgOrSub -eq "mg"){
        $scopePolicyAssignmentsLimit = (($policyBaseQuery | where-object { "" -eq $_.SubscriptionId -and $_.MgId -eq "$mgChild" }) | Select-Object MgId, PolicyAssigmentAtScopeCount, PolicySetAssigmentAtScopeCount, PolicyAndPolicySetAssigmentAtScopeCount, PolicyAssigmentLimit -Unique)
    }
    if ($mgOrSub -eq "sub"){
        $scopePolicyAssignmentsLimit =(($policyBaseQuery | where-object { $_.SubscriptionId -eq $subscriptionId }) | Select-Object MgId, Subscription, SubscriptionId, PolicyAssigmentAtScopeCount, PolicySetAssigmentAtScopeCount, PolicyAndPolicySetAssigmentAtScopeCount, PolicyAssigmentLimit -Unique)
    }
    
    if ($($scopePolicyAssignmentsLimit.PolicyAndPolicySetAssigmentAtScopeCount) -gt ($($scopePolicyAssignmentsLimit.PolicyAssigmentLimit) * $LimitCriticalPercentage / 100)){
        $faImage = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
    }
    else{
        $faimage = "<i class=`"fa fa-check-circle`" aria-hidden=`"true`"></i>"
    }
$script:html += @"
            <p>$faImage Policy Assignment Limit: $($scopePolicyAssignmentsLimit.PolicyAndPolicySetAssigmentAtScopeCount)/$($scopePolicyAssignmentsLimit.PolicyAssigmentLimit)</p>
"@
}


$script:html += @"
        </td>
    </tr>
    <tr>
        <td>
"@

#Scoped Policies
if ($scopePoliciesCount -gt 0){
    if ($mgOrSub -eq "mg"){
        $LimitPOLICYPolicyScoped = $LimitPOLICYPolicyDefinitionsScopedManagementGroup
        if ($scopePoliciesCount -gt (($LimitPOLICYPolicyScoped * $LimitCriticalPercentage) / 100)){
            $faIcon = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
        }
        else{
            $faIcon = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
        }
    }
    if ($mgOrSub -eq "sub"){
        $LimitPOLICYPolicyScoped = $LimitPOLICYPolicyDefinitionsScopedSubscription
        if ($scopePoliciesCount -gt (($LimitPOLICYPolicyScoped * $LimitCriticalPercentage) / 100)){
            $faIcon = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
        }
        else{
            $faIcon = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
        }
    }

$script:html += @"
        <button type="button" class="collapsible"><p>$faIcon $scopePoliciesCount Custom Policies scoped | Limit: ($scopePoliciesCount/$LimitPOLICYPolicyScoped)</p></button>
        <div class="content">
            <table class="$cssClass">
                <tr>
                    <th class="widthCustom">
                        Policy DisplayName
                    </th>
                    <th>
                        PolicyDefinitionId
                    </th>
                    <th>
                        Unique Assignments
                    </th>
                </tr>
"@
    foreach ($scopePolicyArray in $scopePoliciesArray){
        
        $scopePoliciesUniqueAssignments = (($policyPolicyBaseQuery | Where-Object { $_.PolicyDefinitionIdGuid -eq $scopePolicyArray }).PolicyAssignmentId | sort-object -Unique)
        $scopePoliciesUniqueAssignmentArray = @()
        foreach ($scopePoliciesUniqueAssignment in $scopePoliciesUniqueAssignments){
            $scopePoliciesUniqueAssignmentArray += $scopePoliciesUniqueAssignment
        }
        $scopePoliciesUniqueAssignmentsCount = ($scopePoliciesUniqueAssignments | measure-object).count  
$script:html += @"
                <tr>
                    <td>
                        $(($htCacheDefinitions).policy[$scopePolicyArray].DisplayName)
                    </td>
                    <td>
                        $(($htCacheDefinitions).policy[$scopePolicyArray].PolicyDefinitionId)
                    </td>
                    <td>
"@
        if ($scopePoliciesUniqueAssignmentsCount -gt 0){
            $scopePoliciesUniqueAssignmentsList = "($($scopePoliciesUniqueAssignmentArray -join "$CsvDelimiterOpposite "))"
$script:html += @"
            $scopePoliciesUniqueAssignmentsCount $scopePoliciesUniqueAssignmentsList
"@
        }
        else{
$script:html += @"
            $scopePoliciesUniqueAssignmentsCount
"@
        }
$script:html += @"
                    </td>
                </tr>
"@
    }
$script:html += @"
            </table>
        </div>
"@
}
else{
$script:html += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $scopePoliciesCount Custom Policies scoped</p>
"@
}
$script:html += @"
                </td></tr>
                <tr><td>
"@

#Scoped PolicySets
if ($scopePolicySetsCount -gt 0){
    if ($mgOrSub -eq "mg"){
        $LimitPOLICYPolicySetScoped = $LimitPOLICYPolicySetDefinitionsScopedManagementGroup
        if ($scopePolicySetsCount -gt (($LimitPOLICYPolicySetScoped * $LimitCriticalPercentage) / 100)){
            $faIcon = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
        }
        else{
            $faIcon = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
        }
    }
    if ($mgOrSub -eq "sub"){
        $LimitPOLICYPolicySetScoped = $LimitPOLICYPolicySetDefinitionsScopedSubscription
        if ($scopePolicySetsCount -gt (($LimitPOLICYPolicySetScoped * $LimitCriticalPercentage) / 100)){
            $faIcon = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
        }
        else{
            $faIcon = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
        }
    }
$script:html += @"
        <button type="button" class="collapsible"><p>$faIcon $scopePolicySetsCount Custom PolicySets scoped | Limit: ($scopePolicySetsCount/$LimitPOLICYPolicySetScoped)</p></button>
        <div class="content">
            <table class="$cssClass">
                <tr>
                    <th class="widthCustom">
                        PolicySet DisplayName
                    </th>
                    <th>
                        PolicySet DefinitionId
                    </th>
                    <th>
                        Unique Assignments
                    </th>
                </tr>
"@
    foreach ($scopePolicySetArray in $scopePolicySetsArray){ 
        $scopePolicySetsUniqueAssignments = (($policyPolicySetBaseQuery | Where-Object { $_.PolicyDefinitionIdGuid -eq $scopePolicySetArray }).PolicyAssignmentId | sort-object -Unique)
        $scopePolicySetsUniqueAssignmentArray = @()
        foreach ($scopePolicySetsUniqueAssignment in $scopePolicySetsUniqueAssignments){
            $scopePolicySetsUniqueAssignmentArray += $scopePolicySetsUniqueAssignment
        }
        $scopePolicySetsUniqueAssignmentsCount = ($scopePolicySetsUniqueAssignments | measure-object).count              
$script:html += @"
                <tr>
                    <td>
                        $(($htCacheDefinitions).policySet[$scopePolicySetArray].DisplayName)
                    </td>
                    <td>
                        $(($htCacheDefinitions).policySet[$scopePolicySetArray].PolicyDefinitionId)
                    </td>
                    <td>
"@
        if ($scopePolicySetsUniqueAssignmentsCount -gt 0){
            $scopePolicySetsUniqueAssignmentsList = "($($scopePolicySetsUniqueAssignmentArray -join "$CsvDelimiterOpposite "))"
$script:html += @"
            $scopePolicySetsUniqueAssignmentsCount $scopePolicySetsUniqueAssignmentsList
"@
        }
        else{
$script:html += @"
            $scopePolicySetsUniqueAssignmentsCount
"@
        }
$script:html += @"
                    </td>
                </tr>
"@        
    }
$script:html += @"
            </table>
        </div>
"@
}
else{
$script:html += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $scopePolicySetsCount Custom PolicySets scoped</p>
"@
}
$script:html += @"
                </td></tr>
                <tr><td>
"@

#Blueprint Assignment
if ($mgOrSub -eq "sub"){
    if ($blueprintsAssignedCount -gt 0){
$script:html += @"
        <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintsAssignedCount Blueprints assigned</p></button>
        <div class="content">
            <table class="$cssClass">
                <tr>
                    <th class="widthCustom">
                        Blueprint Name
                    </th>
                    <th>
                        Blueprint DisplayName
                    </th>
                    <th>
                        Blueprint Description
                    </th>
                    <th>
                        Blueprint Id
                    </th>
                    <th>
                        Blueprint AssignmentId
                    </th>
                </tr>
"@
        foreach ($blueprintAssigned in $blueprintsAssigned){
$script:html += @"
                <tr>
                    <td>
                        $($blueprintAssigned.BlueprintName)
                    </td>
                    <td>
                        $($blueprintAssigned.BlueprintDisplayName)
                    </td>
                    <td>
                        $($blueprintAssigned.BlueprintDescription)
                    </td>
                    <td>
                        $($blueprintAssigned.BlueprintId)
                    </td>
                    <td>
                        $($blueprintAssigned.BlueprintAssignmentId)
                    </td>
                </tr>
"@        
        }
$script:html += @"
            </table>
        </div>
"@
    }
    else{
$script:html += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $blueprintsAssignedCount Blueprints assigned</p>
"@
    }
$script:html += @"
                </td></tr>
                <tr><td>
"@
}

#blueprints Scoped
if ($blueprintsScopedCount -gt 0){
$script:html += @"
        <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintsScopedCount Blueprints scoped</p></button>
        <div class="content">
            <table class="$cssClass">
                <tr>
                    <th class="widthCustom">
                        Blueprint Name
                    </th>
                    <th>
                        Blueprint DisplayName
                    </th>
                    <th>
                        Blueprint Description
                    </th>
                    <th>
                        Blueprint Id
                    </th>
                </tr>
"@
    foreach ($blueprintScoped in $blueprintsScoped){
$script:html += @"
                <tr>
                    <td>
                        $($blueprintScoped.BlueprintName)
                    </td>
                    <td>
                        $($blueprintScoped.BlueprintDisplayName)
                    </td>
                    <td>
                        $($blueprintScoped.BlueprintDescription)
                    </td>
                    <td>
                        $($blueprintScoped.BlueprintId)
                    </td>
                </tr>
"@        
    }
$script:html += @"
            </table>
        </div>
"@
}
else{
$script:html += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $blueprintsScopedCount Blueprints scoped</p>
"@
}
$script:html += @"
                </td></tr>
                <tr><td>
"@

#Role Assignments
if ($rolesAssignedCount -gt 0){
    if ($mgOrSub -eq "mg"){
        $LimitRoleAssignmentsScope = $LimitRBACRoleAssignmentsManagementGroup
        if ($rolesAssignedScope -gt (($LimitRoleAssignmentsScope * $LimitCriticalPercentage) / 100)){
            $faIcon = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
        }
        else{
            $faIcon = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
        }
    }
    if ($mgOrSub -eq "sub"){
        $LimitRoleAssignmentsScope = $LimitRBACRoleAssignmentsSubscription
        if ($rolesAssignedScope -gt (($LimitRoleAssignmentsScope * $LimitCriticalPercentage) / 100)){
            $faIcon = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
        }
        else{
            $faIcon = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
        }
    }    
    if ($roleSecurityFindingCustomRoleOwner -gt 0){
        $roleSecurityFindingCustomRoleOwnerImg = "<i class=`"fa fa-exclamation-triangle yellow`" aria-hidden=`"true`"></i> "
    }
    else{
        $roleSecurityFindingCustomRoleOwnerImg = ""
    }
    if ($RoleSecurityFindingOwnerAssignmentSP -gt 0){
        $RoleSecurityFindingOwnerAssignmentSPImg = "<i class=`"fa fa-exclamation-triangle yellow`" aria-hidden=`"true`"></i> "
    }
    else{
        $RoleSecurityFindingOwnerAssignmentSPImg = ""
    }
$script:html += @"
        <button type="button" class="collapsible"><p>$faIcon $rolesAssignedCount Role Assignments ($rolesAssignedInherited inherited) (User: $rolesAssignedCountUser | Group: $rolesAssignedCountGroup | ServicePrincipal: $rolesAssignedCountServicePrincipal | Orphaned: $rolesAssignedCountOrphaned) ($($roleSecurityFindingCustomRoleOwnerImg)CustomRoleOwner: $roleSecurityFindingCustomRoleOwner, $($RoleSecurityFindingOwnerAssignmentSPImg)OwnerAssignmentSP: $RoleSecurityFindingOwnerAssignmentSP) (Policy related: $roleAssignmentsRelatedToPolicyCount) | Limit: ($rolesAssignedScope/$LimitRoleAssignmentsScope)</p></button>
        <div class="content">
            <table class="$cssClass">
                <tr>
                    <th>
                        Role DisplayName
                    </th>
                    <th>
                        Role Type
                    </th>
                    <th>
                        Obj Type
                    </th>
                    <th>
                        Obj DisplayName
                    </th>
                    <th>
                        Obj Id
                    </th>
                    <th>
                        Scope
                    </th>
                    <th>
                        Role Assignment
                    </th>
                    <th>
                        Related Policy Assignment
                    </th>
                </tr>
"@
    foreach ($roleAssigned in $rolesAssigned){
        if ($roleAssigned.RoleIsCustom -eq "FALSE"){
            $roleType = "Builtin"
            $roleWithWithoutLinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azrolesadvertizer/$($roleAssigned.RoleDefinitionId).html`" target=`"_blank`">$($roleAssigned.RoleDefinitionName)</a>"
        }
        else{
            if ($roleAssigned.RoleSecurityCustomRoleOwner -eq 1){
                $roletype = "<abbr title=`"Custom subscription owner roles should not exist`"><i class=`"fa fa-exclamation-triangle yellow`" aria-hidden=`"true`"></i></abbr> <a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/10ee2ea2-fb4d-45b8-a7e9-a2e770044cd9.html`" target=`"_blank`">Custom</a>"
            }
            else{
                $roleType = "Custom"
            }
            $roleWithWithoutLinkToAzAdvertizer = $roleAssigned.RoleDefinitionName
        }

        if (($roleAssigned.RoleAssignmentDisplayname).length -eq 1){
            $objDisplayName = "n/a"
        }
        else{
            if ($roleAssigned.RoleSecurityOwnerAssignmentSP -eq 1){

                $objectType = "<abbr title=`"Owner permissions for Service Principals should be treated exceptional`"><i class=`"fa fa-exclamation-triangle yellow`" aria-hidden=`"true`"></i></abbr> $($roleAssigned.RoleAssignmentObjectType)"
            }
            else{
                $objectType = $($roleAssigned.RoleAssignmentObjectType)
            }
            $objDisplayName = $roleAssigned.RoleAssignmentDisplayname
        }

        if ($mgOrSub -eq "mg"){
            if ($roleAssigned.RoleAssignmentId -notmatch "/providers/Microsoft.Management/managementGroups/$mgChild/"){
                if (($roleAssigned.RoleAssignmentId).StartsWith("/providers/Microsoft.Authorization/roleAssignments/")){
                    $roleAssignedAtScopeOrInherted = "inherited Root"
                }
                else{
                    $roleAssignedAtScopeOrInherted = "inherited MG"
                }
            }
            else{
                $roleAssignedAtScopeOrInherted = "this resource"
            }
        }

        if ($mgOrSub -eq "sub"){
            if ($roleAssigned.RoleAssignmentId -notmatch "/subscriptions/$subscriptionId/"){
                if (($roleAssigned.RoleAssignmentId).StartsWith("/providers/Microsoft.Authorization/roleAssignments/")){
                    $roleAssignedAtScopeOrInherted = "inherited Root"
                }
                else{
                    $roleAssignedAtScopeOrInherted = "inherited MG"
                }
            }
            else{
                $roleAssignedAtScopeOrInherted = "this resource"
            }
        }   
$script:html += @"
                <tr>
                    <td>
                        $roleWithWithoutLinkToAzAdvertizer
                    </td>
                    <td>
                        $roleType
                    </td>
                    <td>
                        $objectType
                    </td>
                    <td class="breakwordall">
                        $objDisplayName
                    </td>
                    <td class="breakwordall">
                        $($roleAssigned.RoleAssignmentObjectId)
                    </td>
                    <td>
                        $roleAssignedAtScopeOrInherted
                    </td>
                    <td class="breakwordall">
                        $($roleAssigned.RoleAssignmentId)
                    </td>
                    <td class="breakwordall">
"@
        $relatedPolicyAssignment = ($policyBaseQuery | where-Object { $_.PolicyAssignmentName -eq $roleAssigned.RoleAssignmentDisplayname }) | Get-Unique
        if ($relatedPolicyAssignment){
            if ($relatedPolicyAssignment.PolicyType -eq "BuiltIn"){
                if ($relatedPolicyAssignment.PolicyVariant -eq "Policy"){
                    $LinkOrNotLinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/$($relatedPolicyAssignment.policyDefinitionIdGuid).html`" target=`"_blank`">$($relatedPolicyAssignment.Policy)</a>"
                }
                if ($relatedPolicyAssignment.PolicyVariant -eq "PolicySet"){
                    $LinkOrNotLinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyinitiativesadvertizer/$($relatedPolicyAssignment.policyDefinitionIdGuid).html`" target=`"_blank`">$($relatedPolicyAssignment.Policy)</a>"
                }
            }
            else{
                $LinkOrNotLinkToAzAdvertizer = $relatedPolicyAssignment.Policy
            }
$script:html += @"
                        $($relatedPolicyAssignment.PolicyAssignmentId) ($LinkOrNotLinkToAzAdvertizer)
"@
        }
        else{
$script:html += @"
                        none 
"@
        }
$script:html += @"
                    </td>
                </tr>
"@        
    }
$script:html += @"
            </table>
        </div>
"@
}
else{
$script:html += @"
                <p><i class="fa fa-ban" aria-hidden="true"></i> $rolesAssignedCount Role Assignments ($rolesAssignedInherited inherited) (User: $rolesAssignedCountUser | Group: $rolesAssignedCountGroup | ServicePrincipal: $rolesAssignedCountServicePrincipal | Orhpaned: $rolesAssignedCountOrphaned) (CustomRoleOwner: $roleSecurityFindingCustomRoleOwner, OwnerAssignmentSP: $RoleSecurityFindingOwnerAssignmentSP)</p>
"@
}
$script:html += @"
    </td></tr>
"@
}

#region Summary
function summary() {
$startSummary = get-date
write-output "Build HTML Summary"


if ($getMgParentName -eq "Tenant Root"){
    $scopeNamingSummary = "Tenant wide"
}
else{
    $scopeNamingSummary = "MG '$ManagementGroupIdCaseSensitived' and descendants wide"
}

#SUMMARY tenant total custom policies
if ($getMgParentName -eq "Tenant Root"){
$customPoliciesArray = @()
foreach ($tenantCustomPolicy in $tenantCustomPolicies){
    $customPoliciesArray += ($htCacheDefinitions).policy.($tenantCustomPolicy)
}
if ($tenantCustomPoliciesCount -gt 0){
$script:html += @"
    <button type="button" class="collapsible" id="summary_customPolicies"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policies ($scopeNamingSummary)</span></button>
    <div class="content">

        <table class="summaryTable">
            <tr>
                <th>
                    Policy DisplayName
                </th>
                <th>
                    Policy DefinitionId
                </th>
                <th>
                    Unique Assignments
                </th>
                <th>
                    Used in PolicySets
                </th>
            </tr>
"@
    foreach ($customPolicy in ($customPoliciesArray | Sort-Object @{Expression={$_.DisplayName}})){
        $policyUniqueAssignments = (($policyPolicyBaseQuery | Where-Object { $_.PolicyDefinitionIdGuid -eq ($htCacheDefinitions).policy.($customPolicy.Id).Id }).PolicyAssignmentId | sort-object -Unique)
        $policyUniqueAssignmentsArray = @()
        foreach ($policyUniqueAssignment in $policyUniqueAssignments){
            $policyUniqueAssignmentsArray += $policyUniqueAssignment
        }
        $policyUniqueAssignmentsCount = ($policyUniqueAssignments | measure-object).count 

        $currentPolicy = $customPolicy.PolicyDefinitionId
        $usedInPolicySet = @()
        $customPolicySets = ($htCacheDefinitions).policySet.keys | where-object { ($htCacheDefinitions).policySet.$_.Type -eq "Custom" }
        foreach ($customPolicySet in $customPolicySets){
            if ((($htCacheDefinitions).policySet.($customPolicySet).PolicySetPolicyIds).contains($currentPolicy)){
                $usedInPolicySet += (($htCacheDefinitions).policySet.($customPolicySet).Id)                          
            }
        }

        $usedInPolicySetList = @()
        foreach ($usedPolicySet in $usedInPolicySet){
            $usedInPolicySetList += "$(($htCacheDefinitions).policySet.($usedPolicySet).DisplayName) ($(($htCacheDefinitions).policySet.($usedPolicySet).PolicyDefinitionId))"
        }
        $usedInPolicySetListCount = ($usedInPolicySetList | Measure-Object).count

$script:html += @"
            <tr>
                <td>
                    $(($htCacheDefinitions).policy.($customPolicy.Id).DisplayName)
                </td>
                <td>
                    $(($htCacheDefinitions).policy.($customPolicy.Id).PolicyDefinitionId)
                </td>
                <td>
"@
        if ($policyUniqueAssignmentsCount -gt 0){
            $policyUniqueAssignmentsList = "($($policyUniqueAssignmentsArray -join "$CsvDelimiterOpposite "))"
$script:html += @"
            $policyUniqueAssignmentsCount $policyUniqueAssignmentsList
"@
        }
        else{
$script:html += @"
            $policyUniqueAssignmentsCount
"@
        }
$script:html += @"
                </td>
                <td>
"@
        if ($usedInPolicySetListCount -gt 0){
            $usedInPolicySetListInBrackets = "($(($usedInPolicySetList | Sort-Object) -join "$CsvDelimiterOpposite "))"
$script:html += @"
            $usedInPolicySetListCount $usedInPolicySetListInBrackets
"@
        }
        else{
$script:html += @"
            $usedInPolicySetListCount
"@
        }
$script:html += @"
                </td>
            </tr>
"@ 
    }
$script:html += @"
        </table>
    </div>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policies ($scopeNamingSummary)</span></p>
"@
}
}
#SUMMARY NOT tenant total custom policies
else{
    $faimage = "<i class=`"fa fa-check-circle`" aria-hidden=`"true`"></i>"
    if ($tenantCustomPoliciesCount -gt 0){
        $customPoliciesInScopeArray = @()
        foreach ($customPolicy in $tenantCustomPolicies) {
            if (($htCacheDefinitions).policy.$customPolicy.PolicyDefinitionId.startswith("/providers/Microsoft.Management/managementGroups/","CurrentCultureIgnoreCase")) {
                $policyScopedMgSub = ($htCacheDefinitions).policy.$customPolicy.PolicyDefinitionId -replace "/providers/Microsoft.Management/managementGroups/", "" -replace '/.*'
                if ($mgsAndSubs.MgId.contains("$policyScopedMgSub")) {
                    $customPoliciesInScopeArray += ($htCacheDefinitions).policy.$customPolicy
                }
            }

            if (($htCacheDefinitions).policy.$customPolicy.PolicyDefinitionId.startswith("/subscriptions/","CurrentCultureIgnoreCase")) {
                $policyScopedMgSub = ($htCacheDefinitions).policy.$customPolicy.PolicyDefinitionId -replace "/subscriptions/", "" -replace '/.*'
                if ($mgsAndSubs.SubscriptionId.contains("$policyScopedMgSub")) {
                    $customPoliciesInScopeArray += ($htCacheDefinitions).policy.$customPolicy
                }
                else {
                    Write-Output "$policyScopedMgSub NOT in Scope"
                }
            }
        }
        $customPoliciesFromSuperiorMGs = $tenantCustomPoliciesCount - (($customPoliciesInScopeArray | measure-object).count)
    }
    else{
        $customPoliciesFromSuperiorMGs = "0"
    }
    $customPoliciesArray = @()
    foreach ($tenantCustomPolicy in $tenantCustomPolicies){
        $customPoliciesArray += ($htCacheDefinitions).policy.($tenantCustomPolicy)
    }

if ($tenantCustomPoliciesCount -gt 0){
$script:html += @"
    <button type="button" class="collapsible" id="summary_customPolicies"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policies ($customPoliciesFromSuperiorMGs from superior Management Groups) ($scopeNamingSummary)</span></button>
    <div class="content">

        <table class="summaryTable">
            <tr>
                <th>
                    Policy DisplayName
                </th>
                <th>
                    Policy DefinitionId
                </th>
                <th>
                    Unique Assignments
                </th>
                <th>
                    Used in PolicySets
                </th>
            </tr>
"@
    foreach ($customPolicy in ($customPoliciesArray | Sort-Object @{Expression={$_.DisplayName}})){
        $policyUniqueAssignments = (($policyPolicyBaseQuery | Where-Object { $_.PolicyDefinitionIdGuid -eq ($htCacheDefinitions).policy.($customPolicy.Id).Id }).PolicyAssignmentId | sort-object -Unique)
        $policyUniqueAssignmentsArray = @()
        foreach ($policyUniqueAssignment in $policyUniqueAssignments){
            $policyUniqueAssignmentsArray += $policyUniqueAssignment
        }
        $policyUniqueAssignmentsCount = ($policyUniqueAssignments | measure-object).count 

        $customPolicy.DispayName
        $currentPolicy = $customPolicy.PolicyDefinitionId
        $usedInPolicySet = @()
        $customPolicySets = ($htCacheDefinitions).policySet.keys | where-object { ($htCacheDefinitions).policySet.$_.Type -eq "Custom" }
        foreach ($customPolicySet in $customPolicySets){
            if ((($htCacheDefinitions).policySet.($customPolicySet).PolicySetPolicyIds).contains($currentPolicy)){
                $usedInPolicySet += (($htCacheDefinitions).policySet.($customPolicySet).Id)                          }
        }

        $usedInPolicySetList = @()
        foreach ($usedPolicySet in $usedInPolicySet){
            $usedInPolicySetList += "$(($htCacheDefinitions).policySet.($usedPolicySet).DisplayName) ($(($htCacheDefinitions).policySet.($usedPolicySet).PolicyDefinitionId))"
        }
        $usedInPolicySetListCount = ($usedInPolicySetList | Measure-Object).count

$script:html += @"
            <tr>
                <td>
                    $(($htCacheDefinitions).policy.($customPolicy.Id).DisplayName)
                </td>
                <td>
                    $(($htCacheDefinitions).policy.($customPolicy.Id).PolicyDefinitionId)
                </td>
                <td>
"@
        if ($policyUniqueAssignmentsCount -gt 0){
            $policyUniqueAssignmentsList = "($($policyUniqueAssignmentsArray -join "$CsvDelimiterOpposite "))"
$script:html += @"
            $policyUniqueAssignmentsCount $policyUniqueAssignmentsList
"@
        }
        else{
$script:html += @"
            $policyUniqueAssignmentsCount
"@
        }
$script:html += @"
                </td>
                <td>
"@
        if ($usedInPolicySetListCount -gt 0){
            $usedInPolicySetListInBrackets = "($(($usedInPolicySetList | Sort-Object) -join "$CsvDelimiterOpposite "))"
$script:html += @"
            $usedInPolicySetListCount $usedInPolicySetListInBrackets
"@
        }
        else{
$script:html += @"
            $usedInPolicySetListCount
"@
        }
$script:html += @"
                </td>
            </tr>
"@ 
    }
$script:html += @"
        </table>
    </div>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policies ($scopeNamingSummary)</span></p>
"@
}

}

#SUMMARY tenant total custom policySets
if ($getMgParentName -eq "Tenant Root"){
    if ($tenantCustompolicySetsCount -gt $LimitPOLICYPolicySetDefinitionsScopedTenant * ($LimitCriticalPercentage / 100)){
        $faimage = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
    }
    else{
        $faimage = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
    }

    $customPolicySetsArray = @()
    foreach ($tenantCustomPolicySet in $tenantCustomPolicySets){
        $customPolicySetsArray += ($htCacheDefinitions).policySet.($tenantCustomPolicySet)
    }

    if ($tenantCustompolicySetsCount -gt 0){
$script:html += @"
    <button type="button" class="collapsible" id="summary_customPolicySets">$faimage <span class="valignMiddle">$tenantCustompolicySetsCount Custom PolicySets ($scopeNamingSummary) (Limit: $tenantCustompolicySetsCount/$LimitPOLICYPolicySetDefinitionsScopedTenant)</span></button>
    <div class="content">

        <table class="summaryTable">
            <tr>
                <th>
                    PolicySet DisplayName
                </th>
                <th>
                    PolicySet DefinitionId
                </th>
                <th>
                    Unique Assignments
                </th>
                <th>
                    PolicySet Policies
                </th>
            </tr>
"@
        foreach ($customPolicySet in ($customPolicySetsArray | Sort-Object @{Expression={$_.DisplayName}})){
            $policySetUniqueAssignments = (($policyPolicySetBaseQuery | Where-Object { $_.PolicyDefinitionIdGuid -eq ($htCacheDefinitions).policySet.($customPolicySet.Id).Id }).PolicyAssignmentId | sort-object -Unique)
            $policySetUniqueAssignmentsArray = @()
            foreach ($policySetUniqueAssignment in $policySetUniqueAssignments){
                $policySetUniqueAssignmentsArray += $policySetUniqueAssignment
            }
            $policySetUniqueAssignmentsCount = ($policySetUniqueAssignments | measure-object).count 

            $policySetPoliciesArray = @()
            foreach ($policyPolicySet in ($htCacheDefinitions).policySet.($customPolicySet.Id).PolicySetPolicyIds){
                $policyPolicySetId = $policyPolicySet -replace '.*/'
                $policySetPoliciesArray += "$(($htCacheDefinitions).policy.($policyPolicySetId).DisplayName) ($policyPolicySet)"
            }
            $policySetPoliciesCount = ($policySetPoliciesArray | Measure-Object).count

$script:html += @"
            <tr>
                <td>
                    $(($htCacheDefinitions).policySet.($customPolicySet.Id).DisplayName)
                </td>
                <td>
                    $(($htCacheDefinitions).policySet.($customPolicySet.Id).PolicyDefinitionId)
                </td>
                <td>
"@
            if ($policySetUniqueAssignmentsCount -gt 0){
                $policySetUniqueAssignmentsList = "($($policySetUniqueAssignmentsArray -join "$CsvDelimiterOpposite "))"
$script:html += @"
            $policySetUniqueAssignmentsCount $policySetUniqueAssignmentsList
"@
            }
            else{
$script:html += @"
            $policySetUniqueAssignmentsCount
"@
            }
$script:html += @"
                </td>
                <td>
"@
$script:html += @"
            $policySetPoliciesCount ($(($policySetPoliciesArray | sort-Object) -join "$CsvDelimiterOpposite "))
                </td>
            </tr>
"@ 
        }
$script:html += @"
        </table>
    </div>
"@
    }
    else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPolicySetsCount Custom PolicySets ($scopeNamingSummary)</span></p>
"@
    }
}
#SUMMARY NOT tenant total custom policySets
else{
    $faimage = "<i class=`"fa fa-check-circle`" aria-hidden=`"true`"></i>"
    if ($tenantCustompolicySetsCount -gt $LimitPOLICYPolicySetDefinitionsScopedTenant * ($LimitCriticalPercentage / 100)){
        $faimage = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
    }
    else{
        $faimage = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
    }
    if ($tenantCustompolicySetsCount -gt 0){
        $custompolicySetsInScopeArray = @()
        foreach ($custompolicySet in $tenantCustomPolicySets) {
            if (($htCacheDefinitions).policySet.$custompolicySet.policyDefinitionId.startswith("/providers/Microsoft.Management/managementGroups/","CurrentCultureIgnoreCase")) {
                $policySetScopedMgSub = ($htCacheDefinitions).policySet.$custompolicySet.policyDefinitionId -replace "/providers/Microsoft.Management/managementGroups/", "" -replace '/.*'
                if ($mgsAndSubs.MgId.contains("$policySetScopedMgSub")) {
                    $custompolicySetsInScopeArray += ($htCacheDefinitions).policySet.$custompolicySet
                }
            }
            if (($htCacheDefinitions).policySet.$custompolicySet.policyDefinitionId.startswith("/subscriptions/","CurrentCultureIgnoreCase")) {
                $policySetScopedMgSub = ($htCacheDefinitions).policySet.$custompolicySet.policyDefinitionId -replace "/subscriptions/", "" -replace '/.*'
                if ($mgsAndSubs.SubscriptionId.contains("$policySetScopedMgSub")) {
                    $custompolicySetsInScopeArray += ($htCacheDefinitions).policySet.$custompolicySet
                }
            }
        }
        $custompolicySetsFromSuperiorMGs = $tenantCustompolicySetsCount - (($custompolicySetsInScopeArray | measure-object).count)
    }
    else{
        $custompolicySetsFromSuperiorMGs = "0"
    }
    $customPolicySetsArray = @()
    foreach ($tenantCustomPolicySet in $tenantCustomPolicySets){
        $customPolicySetsArray += ($htCacheDefinitions).policySet.($tenantCustomPolicySet)
    }

    if ($tenantCustompolicySetsCount -gt 0){
$script:html += @"
    <button type="button" class="collapsible" id="summary_customPolicySets">$faimage <span class="valignMiddle">$tenantCustomPolicySetsCount Custom PolicySets ($custompolicySetsFromSuperiorMGs from superior Management Groups) ($scopeNamingSummary) (Limit: $tenantCustompolicySetsCount/$LimitPOLICYPolicySetDefinitionsScopedTenant)</span></button>
    <div class="content">

        <table class="summaryTable">
            <tr>
                <th>
                    PolicySet DisplayName
                </th>
                <th>
                    PolicySet DefinitionId
                </th>
                <th>
                    Unique Assignments
                </th>
                <th>
                    PolicySet Policies
                </th>
            </tr>
"@
        foreach ($customPolicySet in ($customPolicySetsArray | Sort-Object @{Expression={$_.DisplayName}})){
            $policySetUniqueAssignments = (($policyPolicySetBaseQuery | Where-Object { $_.PolicyDefinitionIdGuid -eq ($htCacheDefinitions).policySet.($customPolicySet.Id).Id }).PolicyAssignmentId | sort-object -Unique)
            $policySetUniqueAssignmentsArray = @()
            foreach ($policySetUniqueAssignment in $policySetUniqueAssignments){
                $policySetUniqueAssignmentsArray += $policySetUniqueAssignment
            }
            $policySetUniqueAssignmentsCount = ($policySetUniqueAssignments | measure-object).count 

            $policySetPoliciesArray = @()
            foreach ($policyPolicySet in ($htCacheDefinitions).policySet.($customPolicySet.Id).PolicySetPolicyIds){
                $policyPolicySetId = $policyPolicySet -replace '.*/'
                $policySetPoliciesArray += "$(($htCacheDefinitions).policy.($policyPolicySetId).DisplayName) ($policyPolicySet)"
            }
            $policySetPoliciesCount = ($policySetPoliciesArray | Measure-Object).count

$script:html += @"
            <tr>
                <td>
                    $(($htCacheDefinitions).policySet.($customPolicySet.Id).DisplayName)
                </td>
                <td>
                    $(($htCacheDefinitions).policySet.($customPolicySet.Id).PolicyDefinitionId)
                </td>
                <td>
"@
            if ($policySetUniqueAssignmentsCount -gt 0){
                $policySetUniqueAssignmentsList = "($($policySetUniqueAssignmentsArray -join "$CsvDelimiterOpposite "))"
$script:html += @"
            $policySetUniqueAssignmentsCount $policySetUniqueAssignmentsList
"@
            }
            else{
$script:html += @"
            $policySetUniqueAssignmentsCount
"@
            }
$script:html += @"
                </td>
                <td>
"@
$script:html += @"
            $policySetPoliciesCount ($(($policySetPoliciesArray | sort-Object) -join "$CsvDelimiterOpposite "))
                </td>
                
            </tr>
"@ 
        }
$script:html += @"
        </table>
    </div>
"@
    }
    else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPolicySetsCount Custom PolicySets ($scopeNamingSummary)</span></p>
"@
    }
}

#SUMMARY tenant total custom roles
$tenantCustomRolesCount = ($tenantCustomRoles | measure-object).count
if ($tenantCustomRolesCount -gt $LimitRBACCustomRoleDefinitionsTenant * ($LimitCriticalPercentage / 100)){
    $faimage = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
}
else{
    $faimage = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
}
$tenantCustomRolesArray = @()
foreach ($tenantCustomRole in $tenantCustomRoles){
    $tenantCustomRolesArray += ($htCacheDefinitions).role.($tenantCustomRole)
}

if ($tenantCustomRolesCount -gt 0){
$script:html += @"
    <button type="button" class="collapsible" id="summary_customRoles">$faimage <span class="valignMiddle">$tenantCustomRolesCount Custom Roles ($scopeNamingSummary) (Limit: $tenantCustomRolesCount/$LimitRBACCustomRoleDefinitionsTenant)</span></button>
    <div class="content">

        <table class="summaryTable">
            <tr>
                <th>
                    Role Name
                </th>
                <th>
                    Role Id
                </th>
                <th>
                    Assignable Scopes
                </th>
            </tr>
"@
    foreach ($tenantCustomRole in $tenantCustomRolesArray | sort-object @{Expression={$_.Name}}){
$script:html += @"
            <tr>
                <td>
                    $(($htCacheDefinitions).role.($tenantCustomRole.Id).Name)
                </td>
                <td>
                    $(($htCacheDefinitions).role.($tenantCustomRole.Id).Id)
                </td>
                <td>
                    $((($htCacheDefinitions).role.($tenantCustomRole.Id).AssignableScopes | Measure-Object).count) ($(($htCacheDefinitions).role.($tenantCustomRole.Id).AssignableScopes -join "$CsvDelimiterOpposite "))
                </td>
            </tr>
"@ 
    }
$script:html += @"
        </table>
    </div>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomRolesCount Custom Roles ($scopeNamingSummary)</span></p>
"@
}

#SUMMARY Custom Policies Orphanded TenantRoot
if ($getMgParentName -eq "Tenant Root"){
    $customPoliciesInUse = ($policyBaseQuery | where-object {$_.PolicyType -eq "Custom" -and $_.PolicyVariant -eq "Policy"}).PolicyDefinitionIdGuid | Sort-Object -Unique
    $customPoliciesOrphaned = @()
    foreach ($customPolicyAll in ($htCacheDefinitions).policy.keys) {
        if (($customPoliciesInUse | measure-object).count -eq 0) {
            if (($htCacheDefinitions).policy.$customPolicyAll.Type -eq "Custom") {
                $customPoliciesOrphaned += ($htCacheDefinitions).policy.$customPolicyAll
            }
        }
        else {
            if ($customPoliciesInUse.contains("$customPolicyAll")) {
            }
            else {
        
                if (($htCacheDefinitions).policy.$customPolicyAll.Type -eq "Custom") {
                    $customPoliciesOrphaned += ($htCacheDefinitions).policy.$customPolicyAll
                }
            }
        }
    }

    $customPoliciesOrphanedFinal = @()
    foreach ($customPolicyOrphaned in $customPoliciesOrphaned){
        if (-not ($htPolicyUsedInPolicySet).$($customPolicyOrphaned.Id)){
            $customPoliciesOrphanedFinal += ($htCacheDefinitions).policy.$($customPolicyOrphaned.id)
        }
    }

    if (($customPoliciesOrphanedFinal | measure-object).count -gt 0){
$script:html += @"
    <button type="button" class="collapsible" id="summary_customPoliciesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($customPoliciesOrphanedFinal | measure-object).count) Orphaned Custom Policies ($scopeNamingSummary)</span> <abbr title="Policy has no assignments AND Policy is not used in a PolicySet"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
    <div class="content">

        <table class="summaryTable">
            <tr>
                <th>
                    Policy DisplayName
                </th>
                <th>
                    Policy DefinitionId
                </th>
            </tr>
"@
        foreach ($customPolicyOrphaned in $customPoliciesOrphanedFinal | sort-object @{Expression={$_.DisplayName}}){
$script:html += @"
            <tr>
                <td>
                    $($customPolicyOrphaned.DisplayName)
                </td>
                <td>
                    $($customPolicyOrphaned.PolicyDefinitionId)
                </td>
            </tr>
"@ 
        }
$script:html += @"
        </table>
    </div>
"@
    }
    else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($customPoliciesOrphaned | measure-object).count) Orphaned Custom Policies ($scopeNamingSummary)</span></p>
"@
    }
}

#SUMMARY Custom Policies Orphanded NOT TenantRoot
else{
    $customPoliciesInUse = ($policyBaseQuery | where-object {$_.PolicyType -eq "Custom" -and $_.PolicyVariant -eq "Policy"}).PolicyDefinitionIdGuid | Sort-Object -Unique
    $customPoliciesOrphaned = @()
    foreach ($customPolicyAll in ($htCacheDefinitions).policy.keys) {
        if (($customPoliciesInUse | measure-object).count -eq 0) {
            if (($htCacheDefinitions).policy.$customPolicyAll.Type -eq "Custom") {
                $customPoliciesOrphaned += ($htCacheDefinitions).policy.$customPolicyAll.Id
            }
        }
        else {
            if (-not $customPoliciesInUse.contains("$customPolicyAll")) {    
                if (($htCacheDefinitions).policy.$customPolicyAll.Type -eq "Custom") {
                    $customPoliciesOrphaned += ($htCacheDefinitions).policy.$customPolicyAll.Id
                }
            }
        }
    }
    #$customPoliciesOrphanedInScopeArrayHt = @{}
    $customPoliciesOrphanedInScopeArray = @()
    foreach ($customPolicyOrphaned in  $customPoliciesOrphaned){
        if (($htCacheDefinitions).policy.$customPolicyOrphaned.PolicyDefinitionId.startswith("/providers/Microsoft.Management/managementGroups/","CurrentCultureIgnoreCase")) {
            $policyScopedMgSub = ($htCacheDefinitions).policy.$customPolicyOrphaned.PolicyDefinitionId -replace "/providers/Microsoft.Management/managementGroups/", "" -replace '/.*'
            if ($mgsAndSubs.MgId.contains("$policyScopedMgSub")) {
                $customPoliciesOrphanedInScopeArray += ($htCacheDefinitions).policy.$customPolicyOrphaned
            }
        }
        if (($htCacheDefinitions).policy.$customPolicyOrphaned.PolicyDefinitionId.startswith("/subscriptions/","CurrentCultureIgnoreCase")) {
            $policyScopedMgSub = ($htCacheDefinitions).policy.$customPolicyOrphaned.PolicyDefinitionId -replace "/subscriptions/", "" -replace '/.*'
            if ($mgsAndSubs.SubscriptionId.contains("$policyScopedMgSub")) {
                $customPoliciesOrphanedInScopeArray += ($htCacheDefinitions).policy.$customPolicyOrphaned
            }
        }
    }
    $customPoliciesOrphanedFinal = @()
    #$htPolicyUsedInPolicySet.Keys
    foreach ($customPolicyOrphanedInScopeArray in $customPoliciesOrphanedInScopeArray){
        if (-not ($htPolicyUsedInPolicySet).($customPolicyOrphanedInScopeArray.Id)){
            $customPoliciesOrphanedFinal += $customPolicyOrphanedInScopeArray
        }
    }
    if (($customPoliciesOrphanedFinal | measure-object).count -gt 0){
$script:html += @"
    <button type="button" class="collapsible" id="summary_customPoliciesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($customPoliciesOrphanedFinal | measure-object).count) Orphaned Custom Policies ($scopeNamingSummary)</span> <abbr title="Policy has no assignments AND Policy is not used in a PolicySet (Policies from superior scopes are not evaluated)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
    <div class="content">

        <table class="summaryTable">
            <tr>
                <th>
                    Policy DisplayName
                </th>
                <th>
                    Policy DefinitionId
                </th>
            </tr>
"@
        foreach ($customPolicyOrphaned in $customPoliciesOrphanedFinal | sort-object @{Expression={$_.DisplayName}}){
$script:html += @"
            <tr>
                <td>
                    $($customPolicyOrphaned.DisplayName)
                </td>
                <td>
                    $($customPolicyOrphaned.PolicyDefinitionId)
                </td>
            </tr>
"@ 
        }
$script:html += @"
        </table>
    </div>
"@
    }
    else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$($customPoliciesOrphanedFinal.count) Orphaned Custom Policies ($scopeNamingSummary)</span></p>
"@
    }
}

#SUMMARY Custom policySet Orphanded TenantRoot
if ($getMgParentName -eq "Tenant Root"){
    $custompolicySetSetsInUse = ($policyBaseQuery | where-object {$_.policyType -eq "Custom" -and $_.policyVariant -eq "policySet"}).policyDefinitionIdGuid | Sort-Object -Unique
    $custompolicySetSetsOrphaned = @()
    foreach ($custompolicySetAll in ($htCacheDefinitions).policySet.keys) {
        if (($custompolicySetSetsInUse | measure-object).count -eq 0) {
            if (($htCacheDefinitions).policySet.$custompolicySetAll.Type -eq "Custom") {
                $custompolicySetSetsOrphaned += ($htCacheDefinitions).policySet.$custompolicySetAll
            }
        }
        else {
            if (-not $custompolicySetSetsInUse.contains("$custompolicySetAll")) {
                if (($htCacheDefinitions).policySet.$custompolicySetAll.Type -eq "Custom") {
                    $custompolicySetSetsOrphaned += ($htCacheDefinitions).policySet.$custompolicySetAll
                }
            }
        }
    }

    if (($custompolicySetSetsOrphaned | measure-object).count -gt 0){
$script:html += @"
    <button type="button" class="collapsible" id="summary_custompolicySetSetsOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($custompolicySetSetsOrphaned | measure-object).count) Orphaned Custom PolicySets ($scopeNamingSummary)</span></button>
    <div class="content">

        <table class="summaryTable">
            <tr>
                <th>
                    PolicySet DisplayName
                </th>
                <th>
                    PolicySet DefinitionId
                </th>
            </tr>
"@
        foreach ($custompolicySetOrphaned in $custompolicySetSetsOrphaned | sort-object @{Expression={$_.DisplayName}}){
$script:html += @"
            <tr>
                <td>
                    $($custompolicySetOrphaned.DisplayName)
                </td>
                <td>
                    $($custompolicySetOrphaned.policyDefinitionId)
                </td>
            </tr>
"@ 
        }
$script:html += @"
        </table>
    </div>
"@
    }
    else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($custompolicySetSetsOrphaned | measure-object).count) Orphaned Custom PolicySets ($scopeNamingSummary)</span></p>
"@
    }
}
#SUMMARY Custom policySetSets Orphanded NOT TenantRoot
else{
    $custompolicySetSetsInUse = ($policyBaseQuery | where-object {$_.policyType -eq "Custom" -and $_.policyVariant -eq "policySet"}).policyDefinitionIdGuid | Sort-Object -Unique
    $custompolicySetSetsOrphaned = @()
    foreach ($custompolicySetAll in ($htCacheDefinitions).policySet.keys) {
        if (($custompolicySetSetsInUse | measure-object).count -eq 0) {
            if (($htCacheDefinitions).policySet.$custompolicySetAll.Type -eq "Custom") {
                $custompolicySetSetsOrphaned += ($htCacheDefinitions).policySet.$custompolicySetAll.Id
            }
        }
        else {
            if (-not $custompolicySetSetsInUse.contains("$custompolicySetAll")) {    
                if (($htCacheDefinitions).policySet.$custompolicySetAll.Type -eq "Custom") {
                    $custompolicySetSetsOrphaned += ($htCacheDefinitions).policySet.$custompolicySetAll.Id
                }
            }
        }
    }
    $customPoliciesOrphanedFinal = @()
    foreach ($custompolicySetOrphaned in  $custompolicySetSetsOrphaned){
        if (($htCacheDefinitions).policySet.$custompolicySetOrphaned.policyDefinitionId.startswith("/providers/Microsoft.Management/managementGroups/","CurrentCultureIgnoreCase")) {
            $policySetScopedMgSub = ($htCacheDefinitions).policySet.$custompolicySetOrphaned.policyDefinitionId -replace "/providers/Microsoft.Management/managementGroups/", "" -replace '/.*'
            if ($mgsAndSubs.MgId.contains("$policySetScopedMgSub")) {
                $customPoliciesOrphanedFinal += ($htCacheDefinitions).policySet.$custompolicySetOrphaned
            }
        }
        if (($htCacheDefinitions).policySet.$custompolicySetOrphaned.policyDefinitionId.startswith("/subscriptions/","CurrentCultureIgnoreCase")) {
            $policySetScopedMgSub = ($htCacheDefinitions).policySet.$custompolicySetOrphaned.policyDefinitionId -replace "/subscriptions/", "" -replace '/.*'
            if ($mgsAndSubs.SubscriptionId.contains("$policySetScopedMgSub")) {
                $customPoliciesOrphanedFinal += ($htCacheDefinitions).policySet.$custompolicySetOrphaned
            }
        }
    }
    if (($customPoliciesOrphanedFinal | measure-object).count -gt 0){
$script:html += @"
    <button type="button" class="collapsible" id="summary_custompolicySetSetsOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($customPoliciesOrphanedFinal | measure-object).count) Orphaned Custom PolicySets ($scopeNamingSummary)</span></button>
    <div class="content">

        <table class="summaryTable">
            <tr>
                <th>
                    PolicySet DisplayName
                </th>
                <th>
                    PolicySet DefinitionId
                </th>
            </tr>
"@
        foreach ($custompolicySetOrphaned in $customPoliciesOrphanedFinal | sort-object @{Expression={$_.DisplayName}}){
$script:html += @"
            <tr>
                <td>
                    $($custompolicySetOrphaned.DisplayName)
                </td>
                <td>
                    $($custompolicySetOrphaned.policyDefinitionId)
                </td>
            </tr>
"@ 
        }
$script:html += @"
        </table>
    </div>
"@
    }
    else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($customPoliciesOrphanedFinal | measure-object).count) Orphaned Custom PolicySets ($scopeNamingSummary)</span></p>
"@
    }
}

#SUMMARY Orphaned Custom Roles
if ($getMgParentName -eq "Tenant Root"){
    $customRolesInUse = ($rbacBaseQuery | where-object {$_.RoleIsCustom -eq "TRUE"}).RoleDefinitionId | Sort-Object -Unique
    
    $customRolesOrphaned = @()
    if (($tenantCustomRoles | Measure-Object).count -gt 0){
        foreach ($customRoleAll in $tenantCustomRoles){
            if (-not $customRolesInUse.contains("$customRoleAll")){    
                if (($htCacheDefinitions).role.$customRoleAll.IsCustom -eq $True){
                    $customRolesOrphaned += ($htCacheDefinitions).role.$customRoleAll
                }
            }
        }
    }
    if (($customRolesOrphaned | measure-object).count -gt 0){
$script:html += @"
    <button type="button" class="collapsible" id="summary_customRolesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($customRolesOrphaned | measure-object).count) Orphaned Custom Roles ($scopeNamingSummary) <abbr title="Role has no assignments"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
    </button>
    <div class="content">
        <table class="summaryTable">
            <tr>
                <th>
                    Role Name
                </th>
                <th>
                    Role Id
                </th>
                <th>
                    Assignable Scopes
                </th>
            </tr>
"@
        foreach ($customRoleOrphaned in $customRolesOrphaned | Sort-Object @{Expression={$_.Name}}){
$script:html += @"
            <tr>
                <td>
                    $($customRoleOrphaned.Name)
                </td>
                <td>
                    $($customRoleOrphaned.Id)
                </td>
                <td>
                $(($customRoleOrphaned.AssignableScopes | Measure-Object).count) ($($customRoleOrphaned.AssignableScopes -join "$CsvDelimiterOpposite "))                    
                </td>
            </tr>
"@ 
        }
$script:html += @"
        </table>
    </div>
"@
    }
    else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($customRolesOrphaned | measure-object).count) Orphaned Custom Roles ($scopeNamingSummary)</span></p>
"@
    }
#not renant root
}
else{
    $mgs = (($mgAndSubBaseQuery | where-object {$_.mgId -ne "" -and $_.Level -ne "0"}) | select-object MgId -unique)
    $subs = (($mgAndSubBaseQuery | where-object { "" -ne $_.SubscriptionId -and $_.Level -ne "0"}) | select-object SubscriptionId -unique)
    
    $customRolesInScopeArray = @()
    if (($tenantCustomRoles | measure-object).count -gt 0){
        foreach ($customRole in $tenantCustomRoles){
            $customRoleAssignableScopes = ($htCacheDefinitions).role.$customRole.AssignableScopes
            $customRoleInScope = $false
            $customRoleIsOut = $false
            foreach ($customRoleAssignableScope in $customRoleAssignableScopes){
                if ($customRoleAssignableScope.startswith("/providers/Microsoft.Management/managementGroups/","CurrentCultureIgnoreCase")){
                    $roleAssignableScopeMgSub = $customRoleAssignableScope -replace "/providers/Microsoft.Management/managementGroups/", ""
                    foreach ($customRoleAssignableScope in $customRoleAssignableScopes) {
                        if ($customRoleAssignableScope.startswith("/providers/Microsoft.Management/managementGroups/","CurrentCultureIgnoreCase")){
                            $roleAssignableScopeMgSub = $customRoleAssignableScope -replace "/providers/Microsoft.Management/managementGroups/", ""
                            if (-not $mgs.MgId.contains("$roleAssignableScopeMgSub")){
                                $customRoleIsOut = $true
                            }
                        }
                    }
                    if (-not $customRoleIsOut -eq $true){
                        if ($mgs.MgId.contains("$roleAssignableScopeMgSub")){
                            $customRoleInScope = $true
                        }
                    }
                }
                if (-not $customRoleIsOut -eq $true){
                    if (($subs | measure-object).count -gt 0){
                        if ($customRoleAssignableScope.startswith("/subscriptions/","CurrentCultureIgnoreCase")){
                            $roleAssignableScopeMgSub = $customRoleAssignableScope -replace "/subscriptions/", ""
                            if ($subs.SubscriptionId.contains("$roleAssignableScopeMgSub")){
                                $customRoleInScope = $true
                            }
                        }
                    }
                }
            }
            if ($customRoleInScope -eq $true){
                $customRolesInScopeArray += ($htCacheDefinitions).role.($customRole)
            }
        }
    }

    if (($customRolesInScopeArray | measure-object).count -gt 0){
$script:html += @"
    <button type="button" class="collapsible" id="summary_customRolesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($customRolesInScopeArray | measure-object).count) Orphaned Custom Roles ($scopeNamingSummary) <abbr title="Role has no assignments (Roles where assignableScopes has mg from superior scopes are not evaluated)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
    </button>
    <div class="content">
        <table class="summaryTable">
            <tr>
                <th>
                    Name
                </th>
                <th>
                    Id
                </th>
                <th>
                    Assignable Scopes
                </th>
            </tr>
"@
        foreach ($inScopeCustomRole in $customRolesInScopeArray | Sort-Object @{Expression={$_.Name}}){

$script:html += @"
            <tr>
                <td>
                    $($inScopeCustomRole.Name)
                </td>
                <td>
                    $($inScopeCustomRole.Id)
                </td>
                <td>
                $(($inScopeCustomRole.AssignableScopes | Measure-Object).count) ($($inScopeCustomRole.AssignableScopes -join "$CsvDelimiterOpposite "))
                </td>
            </tr>
"@ 
        }
$script:html += @"
        </table>
    </div>
"@
    }
    else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($customRolesInScopeArray | measure-object).count) Orphaned Custom Roles ($scopeNamingSummary)</span></p>
"@
    }
}

#SUMMARY RoleAssignments Orphaned
$roleAssignmentsOrphanedAll = $rbacBaseQuery | Where-Object { $_.RoleAssignmentObjectType -eq "Unknown" } | Sort-Object -Property RoleAssignmentId
$roleAssignmentsOrphanedUnique = $roleAssignmentsOrphanedAll | Sort-Object -Property RoleAssignmentId -Unique

if (($roleAssignmentsOrphanedUnique | measure-object).count -gt 0) {
$script:html += @"
    <button type="button" class="collapsible" id="summary_roleAssignmnetsOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOrphanedUnique | measure-object).count) Orphaned Role Assignments ($scopeNamingSummary) <abbr title="Role was deleted although and assignment existed OR the target identity (Sser, Group, ServicePrincipal) was deleted"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
    </button>
    <div class="content">
        <table class="summaryTable">
            <tr>
                <th>
                    Role Assignment Id
                </th>
                <th>
                    Role Name
                </th>
                <th>
                    Role Id
                </th>
                <th>
                    Impacted Mg/Sub
                </th>
            </tr>
"@
    foreach ($roleAssignmentOrphanedUnique in $roleAssignmentsOrphanedUnique) {
        $impactedMgs = ($roleAssignmentsOrphanedAll | Where-Object { "" -eq $_.SubscriptionId -and $_.RoleAssignmentId -eq $roleAssignmentOrphanedUnique.RoleAssignmentId } | Sort-Object -Property MgId)
        $impactedSubs = $roleAssignmentsOrphanedAll | Where-Object { "" -ne $_.SubscriptionId -and $_.RoleAssignmentId -eq $roleAssignmentOrphanedUnique.RoleAssignmentId } | Sort-Object -Property SubscriptionId
$script:html += @"
            <tr>
                <td>
                    $($roleAssignmentOrphanedUnique.RoleAssignmentId)
                </td>
                <td>
                    $($roleAssignmentOrphanedUnique.RoleDefinitionName)
                </td>
                <td>
                    $($roleAssignmentOrphanedUnique.RoleDefinitionId)
                </td>
                <td>
                    Mg: $(($impactedMgs | measure-object).count); Sub: $(($impactedSubs | measure-object).count)
                </td>
            </tr>
"@ 
    }
$script:html += @"
        </table>
    </div>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOrphanedUnique | measure-object).count) Orphaned Role Assignments ($scopeNamingSummary)</span></p>
"@
}

#SUMMARY Security CustomRoles
$customRolesOwnerAll = $rbacBaseQuery | Where-Object { $_.RoleSecurityCustomRoleOwner -eq 1 } | Sort-Object -Property RoleDefinitionId
$customRolesOwnerHtAll = ($htCacheDefinitions).role.keys | where-object { ($htCacheDefinitions).role.$_.Actions -eq '*' -and (($htCacheDefinitions).role.$_.NotActions).length -eq 0 -and ($htCacheDefinitions).role.$_.IsCustom -eq $True }
if (($customRolesOwnerHtAll | measure-object).count -gt 0){

$script:html += @"
    <button type="button" class="collapsible" id="summary_customroleCustomRoleOwner"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($customRolesOwnerHtAll | measure-object).count) Custom Roles Owner permissions ($scopeNamingSummary) <abbr title="Custom subscription owner roles should not exist"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
    </button>
    <div class="content">
        <table class="summaryTable">
            <tr>
                <th>
                    Role Name
                </th>
                <th>
                    Role Id
                </th>
                <th>
                    Role Assignments
                </th>
                <th>
                    Assignable Scopes
                </th>
            </tr>
"@
    foreach ($customRole in ($customRolesOwnerHtAll)) {
        $customRoleOwnersAllAssignmentsCount = ((($customRolesOwnerAll | Where-Object { $_.RoleDefinitionId -eq $customRole }).RoleAssignmentId | Sort-Object -Unique) | measure-object).count
        if ($customRoleOwnersAllAssignmentsCount -gt 0){
            $customRoleRoleAssignmentsArray = @()
            $customRoleRoleAssignmentIds = ($customRolesOwnerAll | Where-Object { $_.RoleDefinitionId -eq $customRole }).RoleAssignmentId | Sort-Object -Unique
            foreach ($customRoleRoleAssignmentId in $customRoleRoleAssignmentIds){
                $customRoleRoleAssignmentsArray += $customRoleRoleAssignmentId
            }
            $customRoleRoleAssignmentsOutput = "$customRoleOwnersAllAssignmentsCount ($($customRoleRoleAssignmentsArray -join "$CsvDelimiterOpposite "))"
        }
        else{
            $customRoleRoleAssignmentsOutput = "$customRoleOwnersAllAssignmentsCount"
        }
$script:html += @"
            <tr>
                <td>
                    $(($htCacheDefinitions).role.($customRole).Name)
                </td>
                <td>
                    $($customRole)
                </td>
                <td>
                    $($customRoleRoleAssignmentsOutput)
                </td>
                <td>
                    $((($htCacheDefinitions).role.($customRole).AssignableScopes | Measure-Object).count) ($(($htCacheDefinitions).role.($customRole).AssignableScopes -join "$CsvDelimiterOpposite "))
                </td>
            </tr>
"@ 
    }
$script:html += @"
        </table>
    </div>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($customRolesOwnerHtAll | measure-object).count) Custom Roles Owner permissions ($scopeNamingSummary)</span></p>
"@
}

#SUMMARY Security OwnerAssignmentSP
$roleAssignmentsOwnerAssignmentSPAll = ($rbacBaseQuery | Where-Object { $_.RoleSecurityOwnerAssignmentSP -eq 1 } | Sort-Object -Property RoleAssignmentId)
$roleAssignmentsOwnerAssignmentSP = $roleAssignmentsOwnerAssignmentSPAll | sort-object -Property RoleAssignmentId -Unique
if (($roleAssignmentsOwnerAssignmentSP | measure-object).count -gt 0){
$script:html += @"
    <button type="button" class="collapsible" id="summary_roleAssignmentsOwnerAssignmentSP"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentSP | measure-object).count) Owner permission assignments to ServicePrincipal ($scopeNamingSummary) <abbr title="Owner permissions for Service Principals should be treated exceptional"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
    </button>
    <div class="content">
        <table class="summaryTable">
            <tr>
                <th>
                    Role Name
                </th>
                <th>
                    Role Id
                </th>
                <th>
                    Role Assignment
                </th>
                <th>
                    ServicePrincipal (ObjId)
                </th>
                <th>
                    Impacted Mg/Sub
                </th>
            </tr>
"@
    foreach ($roleAssignmentOwnerAssignmentSP in ($roleAssignmentsOwnerAssignmentSP)) {
        $impactedMgs = $roleAssignmentsOwnerAssignmentSPAll | Where-Object { "" -eq $_.SubscriptionId -and $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentSP.RoleAssignmentId }
        $impactedSubs = $roleAssignmentsOwnerAssignmentSPAll | Where-Object { "" -ne $_.SubscriptionId -and $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentSP.RoleAssignmentId }
        $servicePrincipal = ($roleAssignmentsOwnerAssignmentSP | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentSP.RoleAssignmentId }) | Get-Unique
$script:html += @"
            <tr>
                <td>
                    $($roleAssignmentOwnerAssignmentSP.RoleDefinitionName)
                </td>
                <td>
                    $($roleAssignmentOwnerAssignmentSP.RoleDefinitionId)
                </td>
                <td>
                    $($roleAssignmentOwnerAssignmentSP.RoleAssignmentId)
                </td>
                <td>
                    $($servicePrincipal.RoleAssignmentDisplayname) ($($servicePrincipal.RoleAssignmentObjectId))
                </td>
                <td>
                    Mg: $(($impactedMgs | measure-object).count); Sub: $(($impactedSubs | measure-object).count)
                </td>
            </tr>
"@ 
    }
$script:html += @"
        </table>
    </div>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentSP | measure-object).count) Owner permission assignments to ServicePrincipal ($scopeNamingSummary)</span></p>
"@
}

#SUMMARY Resources
if (($resourcesAll | Measure-Object).count -gt 0){
    $resourcesAllSummarized = $resourcesAll | Select-Object -Property type, location, count_ | Group-Object type, location | ForEach-Object {
        New-Object PSObject -Property @{
            type = ($_.Name -split ",")[0]
            location = $_.Group[0].location
            count_ = ($_.Group | Measure-Object -Property count_ -Sum).Sum
        }
    }

    $resourcesTotal = 0
    $resourcesAllSummarized.count_ | ForEach-Object { $resourcesTotal += $_ }
    $resourcesResourceTypeCount = (($resourcesAllSummarized | sort-object -Property type -Unique) | measure-object).count
    $resourcesLocationCount = (($resourcesAllSummarized | sort-object -Property location -Unique) | measure-object).count

    if ($resourcesResourceTypeCount -gt 0){
$script:html += @"
<button type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$resourcesResourceTypeCount ResourceTypes ($resourcesTotal Resources) in $resourcesLocationCount Locations ($scopeNamingSummary)</span>
</button>
<div class="content">
    <table class="summaryTable">
        <tr>
            <th>
                ResourceType
            </th>
            <th>
                Location
            </th>
            <th>
                Count
            </th>
        </tr>
"@
        foreach ($resourceAllSummarized in $resourcesAllSummarized){
$script:html += @"
        <tr>
            <td>
                $($resourceAllSummarized.type)
            </td>
            <td>
                $($resourceAllSummarized.location)
            </td>
            <td>
                $($resourceAllSummarized.count_)
            </td>
        </tr>
"@        
        }
$script:html += @"
    </table>
</div>
"@
    }
    else{
$script:html += @"
        <p><i class="fa fa-ban" aria-hidden="true"></i> $resourcesResourceTypeCount ResourceTypes</p>
"@
    }
$script:html += @"
        </td></tr>
        <tr><td>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> 0 ResourceTypes</p>
"@
}

#SUMMARY MGs
$mgsDetails = (($mgAndSubBaseQuery | where-object {$_.mgId -ne ""}) | Select-Object Level, MgId -Unique)
$mgDepth = ($mgsDetails.Level | Measure-Object -maximum).Maximum
$script:html += @"
    <p><i class="fa fa-check-circle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsDetails | measure-object).count) Management Groups ($mgDepth levels of depth)</span></p>
"@

#SUMMARY Mgs approaching Limits PolicyAssignments
$mgsApproachingLimitPolicyAssignments = (($policyBaseQuery | where-object { "" -eq $_.SubscriptionId -and $_.PolicyAndPolicySetAssigmentAtScopeCount -gt 0 -and  (($_.PolicyAndPolicySetAssigmentAtScopeCount -gt ($_.PolicyAssigmentLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, MgName, PolicyAssigmentAtScopeCount, PolicySetAssigmentAtScopeCount, PolicyAndPolicySetAssigmentAtScopeCount, PolicyAssigmentLimit -Unique)
if (($mgsApproachingLimitPolicyAssignments | measure-object).count -gt 0){
$script:html += @"
<button type="button" class="collapsible"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicyAssignments | measure-object).count) Management Groups approaching Limit for PolicyAssignment</span></button>
<div class="content">
    <table class="summaryTable">
        <tr>
            <th>
                ManagementGroup
            </th>
            <th>
                ManagementGroupId
            </th>
            <th>
                Limit
            </th>
        </tr>
"@
    foreach ($mgApproachingLimitPolicyAssignments in $mgsApproachingLimitPolicyAssignments){
$script:html += @"
        <tr>
            <td>
                <span class="valignMiddle">$($mgApproachingLimitPolicyAssignments.MgName)</span>
            </td>
            <td>
                <span class="valignMiddle"><a class="internallink" href="#table_$($mgApproachingLimitPolicyAssignments.MgId)">$($mgApproachingLimitPolicyAssignments.MgId)</a></span>
            </td>
            <td>
            <!--<meter min="0" max="$($mgApproachingLimitPolicyAssignments.PolicyAssigmentLimit)" low="$($mgApproachingLimitPolicyAssignments.PolicyAssigmentLimit * $LimitCriticalPercentage / 100)" high="0" value="$($mgApproachingLimitPolicyAssignments.PolicyAndPolicySetAssigmentAtScopeCount)"></meter> $($subscriptionApproachingLimitPolicyAssignments.PolicyAndPolicySetAssigmentAtScopeCount)/$($subscriptionApproachingLimitPolicyAssignments.PolicyAssigmentLimit)-->
                $($mgApproachingLimitPolicyAssignments.PolicyAndPolicySetAssigmentAtScopeCount)/$($mgApproachingLimitPolicyAssignments.PolicyAssigmentLimit) ($($mgApproachingLimitPolicyAssignments.PolicyAssigmentAtScopeCount) Policy Assignments, $($mgApproachingLimitPolicyAssignments.PolicySetAssigmentAtScopeCount) PolicySet Assignments)
            </td>
        </tr>
"@
    }
$script:html += @"
    </table>
    </div>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicyAssignments | measure-object).count) Management Groups approaching Limit for PolicyAssignment</span></p>
"@
}

#SUMMARY Mgs approaching Limits PolicyScope
$mgsApproachingLimitPolicyScope = (($policyBaseQuery | where-object { "" -eq $_.SubscriptionId -and $_.PolicyDefinitionsScopedCount -gt 0 -and (($_.PolicyDefinitionsScopedCount -gt ($_.PolicyDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, MgName, PolicyDefinitionsScopedCount, PolicyDefinitionsScopedLimit -Unique)
if (($mgsApproachingLimitPolicyScope | measure-object).count -gt 0){
$script:html += @"
<button type="button" class="collapsible"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicyScope | measure-object).count) Management Groups approaching Limit for Policy Scope</span></button>
<div class="content">
    <table class="summaryTable">
        <tr>
            <th>
                Management Group
            </th>
            <th>
                Management Group Id
            </th>
            <th>
                Limit
            </th>
        </tr>
"@
    foreach ($mgApproachingLimitPolicyScope in $mgsApproachingLimitPolicyScope){
$script:html += @"
        <tr>
            <td>
                <span class="valignMiddle">$($mgApproachingLimitPolicyScope.MgName)</span>
            </td>
            <td>
                <span class="valignMiddle"><a class="internallink" href="#table_$($mgApproachingLimitPolicyScope.MgId)">$($mgApproachingLimitPolicyScope.MgId)</a></span>
            </td>
            <td>
                $($mgApproachingLimitPolicyScope.PolicyDefinitionsScopedCount)/$($mgApproachingLimitPolicyScope.PolicyDefinitionsScopedLimit)
            </td>
        </tr>
"@
    }
$script:html += @"
    </table>
    </div>
"@
}
else{
$script:html += @"
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$($mgsApproachingLimitPolicyScope.count) Management Groups approaching Limit for Policy Scope</span></p>
"@
}

#SUMMARY Mgs approaching Limits PolicyScope
$mgsApproachingLimitPolicySetScope = (($policyBaseQuery | where-object { "" -eq $_.SubscriptionId -and $_.PolicySetDefinitionsScopedCount -gt 0 -and  (($_.PolicySetDefinitionsScopedCount -gt ($_.PolicySetDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, MgName, PolicySetDefinitionsScopedCount, PolicySetDefinitionsScopedLimit -Unique)
if ($mgsApproachingLimitPolicySetScope.count -gt 0){
$script:html += @"
<button type="button" class="collapsible"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicySetScope | measure-object).count) Management Groups approaching Limit for PolicySets Scope</span></button>
<div class="content">
    <table class="summaryTable">
        <tr>
            <th>
                Management Group
            </th>
            <th>
                Management Group Id
            </th>
            <th>
                Limit
            </th>
        </tr>
"@
    foreach ($mgApproachingLimitPolicySetScope in $mgsApproachingLimitPolicySetScope){
$script:html += @"
        <tr>
            <td>
                <span class="valignMiddle">$($mgApproachingLimitPolicySetScope.MgName)</span>
            </td>
            <td>
                <span class="valignMiddle"><a class="internallink" href="#table_$($mgApproachingLimitPolicySetScope.MgId)">$($mgApproachingLimitPolicySetScope.MgId)</a></span>
            </td>
            <td>
                $($mgApproachingLimitPolicySetScope.PolicySetDefinitionsScopedCount)/$($mgApproachingLimitPolicySetScope.PolicySetDefinitionsScopedLimit)
            </td>
        </tr>
"@
    }
$script:html += @"
    </table>
    </div>
"@
}
else{
$script:html += @"
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicySetScope | measure-object).count) Management Groups approaching Limit for PolicySets Scope</span></p>
"@
}

#SUMMARY Subs
$summarySubscriptions = $subscriptionBaseQuery | Select-Object -Property Subscription, SubscriptionId, MgId, SubscriptionQuotaId, SubscriptionState -Unique | Sort-Object -Property Subscription
#$summarySubscriptions = $table | Select-Object -Property Subscription, SubscriptionId, MgId, SubscriptionQuotaId, SubscriptionState -Unique | where-object { "" -ne $_.SubscriptionId } | Sort-Object -Property Subscription
if (($summarySubscriptions | measure-object).count -gt 0){
$script:html += @"
    <button type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($summarySubscriptions | measure-object).count) Subscriptions</span></button>
    <div class="content">
        <table class="summaryTable">
            <tr>
                <th>
                    Subscription
                </th>
                <th>
                    SubscriptionId
                </th>
                <th>
                    State
                </th>
                <th>
                    QuotaId
                </th>
                <th>
                    Path
                </th>
            </tr>
"@
    foreach ($summarySubscription in $summarySubscriptions){
        createMgPathSub -subid $summarySubscription.subscriptionId
        [array]::Reverse($script:submgPathArray)
        $subPath = $script:submgPathArray -join "/"
$script:html += @"
            <tr>
                <td>
                    $($summarySubscription.subscription)
                </td>
                <td>
                    <span class="valignMiddle"><a class="internallink" href="#table_$($summarySubscription.MgId)">$($summarySubscription.subscriptionId)</a></span>
                </td>
                <td>
                    $($summarySubscription.SubscriptionState)
                </td>
                <td>
                    $($summarySubscription.SubscriptionQuotaId)
                </td>
                <td>
                    $subPath
                </td>
            </tr>
"@
    }
$script:html += @"
        </table>
    </div>
"@
    }
    else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$subscount Subscriptions</span></p>
"@
}

#SUMMARY Subs approaching Limits ResourceGroups
$subscriptionsApproachingLimitFromResourceGroupsAll = $resourceGroupsAll | where-object { $_.count_ -gt ($LimitResourceGroups * ($LimitCriticalPercentage / 100)) }
if (($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count -gt 0){
$script:html += @"
<button type="button" class="collapsible"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count) Subscriptions approaching Limit for ResourceGroups</span></button>
<div class="content">
    <table class="summaryTable">
        <tr>
            <th>
                Subscription
            </th>
            <th>
                SubscriptionId
            </th>
            <th>
                Limit
            </th>
        </tr>
"@
    foreach ($subscriptionApproachingLimitFromResourceGroupsAll in $subscriptionsApproachingLimitFromResourceGroupsAll){
        $subscriptionData = $mgAndSubBaseQuery | Where-Object { $_.SubscriptionId -eq $subscriptionApproachingLimitFromResourceGroupsAll.subscriptionId } | Get-Unique
        #$subscriptionData
    #}
$script:html += @"
        <tr>
            <td>
                <span class="valignMiddle">$($subscriptionData.subscription)</span>
            </td>
            <td>
                <span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionData.MgId)">$($subscriptionData.subscriptionId)</a></span>
            </td>
            <td>
                $($subscriptionApproachingLimitFromResourceGroupsAll.count_)/$($LimitResourceGroups)
            </td>
        </tr>
"@
    }
$script:html += @"
    </table>
    </div>
"@
}
else{
$script:html += @"
    <p"><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count) Subscriptions approaching Limit for ResourceGroups</span></p>
"@
}

#SUMMARY Subs approaching Limits SubscriptionTags
$subscriptionsApproachingLimitTags = ($subscriptionBaseQuery | Select-Object -Property MgId, Subscription, SubscriptionId, SubscriptionTagsCount, SubscriptionTagsLimit -Unique | where-object { (($_.SubscriptionTagsCount -gt ($_.SubscriptionTagsLimit * ($LimitCriticalPercentage / 100)))) })
if (($subscriptionsApproachingLimitTags | measure-object).count -gt 0){
$script:html += @"
<button type="button" class="collapsible"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitTags | measure-object).count) Subscriptions approaching Limit for Tags</span></button>
<div class="content">
    <table class="summaryTable">
        <tr>
            <th>
                Subscription
            </th>
            <th>
                SubscriptionId
            </th>
            <th>
                Limit
            </th>
        </tr>
"@
    foreach ($subscriptionApproachingLimitTags in $subscriptionsApproachingLimitTags){
$script:html += @"
        <tr>
            <td>
                <span class="valignMiddle">$($subscriptionApproachingLimitTags.subscription)</span>
            </td>
            <td>
                <span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingLimitTags.MgId)">$($subscriptionApproachingLimitTags.subscriptionId)</a></span>
            </td>
            <td>
            <!--<meter min="0" max="$($subscriptionApproachingLimitTags.SubscriptionTagsLimit)" low="$($subscriptionApproachingLimitTags.SubscriptionTagsLimit * $LimitCriticalPercentage / 100)" high="0" value="$($subscriptionApproachingLimitTags.SubscriptionTagsCount)"></meter>-->
            $($subscriptionApproachingLimitTags.SubscriptionTagsCount)/$($subscriptionApproachingLimitTags.SubscriptionTagsLimit)
            </td>
        </tr>
"@
    }
$script:html += @"
    </table>
    </div>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$($subscriptionsApproachingLimitTags.count) Subscriptions approaching Limit for Tags</span></p>
"@
}

#SUMMARY Subs approaching Limits PolicyAssignments
$subscriptionsApproachingLimitPolicyAssignments =(($policyBaseQuery | where-object { "" -ne $_.SubscriptionId -and $_.PolicyAndPolicySetAssigmentAtScopeCount -gt 0 -and  (($_.PolicyAndPolicySetAssigmentAtScopeCount -gt ($_.PolicyAssigmentLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, Subscription, SubscriptionId, PolicyAssigmentAtScopeCount, PolicySetAssigmentAtScopeCount, PolicyAndPolicySetAssigmentAtScopeCount, PolicyAssigmentLimit -Unique)
if ($subscriptionsApproachingLimitPolicyAssignments.count -gt 0){
$script:html += @"
<button type="button" class="collapsible"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyAssignments | measure-object).count) Subscriptions approaching Limit for PolicyAssignment</span></button>
<div class="content">
    <table class="summaryTable">
        <tr>
            <th>
                Subscription
            </th>
            <th>
                SubscriptionId
            </th>
            <th>
                Limit
            </th>
        </tr>
"@
    foreach ($subscriptionApproachingLimitPolicyAssignments in $subscriptionsApproachingLimitPolicyAssignments){
$script:html += @"
        <tr>
            <td>
                <span class="valignMiddle">$($subscriptionApproachingLimitPolicyAssignments.subscription)</span>
            </td>
            <td>
                <span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingLimitPolicyAssignments.MgId)">$($subscriptionApproachingLimitPolicyAssignments.subscriptionId)</a></span>
            </td>
            <td>
                $($subscriptionApproachingLimitPolicyAssignments.PolicyAndPolicySetAssigmentAtScopeCount)/$($subscriptionApproachingLimitPolicyAssignments.PolicyAssigmentLimit) ($($subscriptionApproachingLimitPolicyAssignments.PolicyAssigmentAtScopeCount) Policy Assignments, $($subscriptionApproachingLimitPolicyAssignments.PolicySetAssigmentAtScopeCount) PolicySet Assignments)
            </td>
        </tr>
"@
    }
$script:html += @"
    </table>
    </div>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyAssignments | measure-object).count) Subscriptions approaching Limit for PolicyAssignment</span></p>
"@
}

#SUMMARY Subs approaching Limits PolicyScope
$subscriptionsApproachingLimitPolicyScope = (($policyBaseQuery | where-object { "" -ne $_.SubscriptionId -and $_.PolicyDefinitionsScopedCount -gt 0 -and  (($_.PolicyDefinitionsScopedCount -gt ($_.PolicyDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, Subscription, SubscriptionId, PolicyDefinitionsScopedCount, PolicyDefinitionsScopedLimit -Unique)
if (($subscriptionsApproachingLimitPolicyScope | measure-object).count -gt 0){
$script:html += @"
<button type="button" class="collapsible"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyScope | measure-object).count) Subscriptions approaching Limit for Policy Scope</span></button>
<div class="content">
    <table class="summaryTable">
        <tr>
            <th>
                Subscription
            </th>
            <th>
                SubscriptionId
            </th>
            <th>
                Limit
            </th>
        </tr>
"@
    foreach ($subscriptionApproachingLimitPolicyScope in $subscriptionsApproachingLimitPolicyScope){
$script:html += @"
        <tr>
            <td>
                <span class="valignMiddle">$($subscriptionApproachingLimitPolicyScope.subscription)</span>
            </td>
            <td>
                <span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingLimitPolicyScope.MgId)">$($subscriptionApproachingLimitPolicyScope.subscriptionId)</a></span>
            </td>
            <td>
                $($subscriptionApproachingLimitPolicyScope.PolicyDefinitionsScopedCount)/$($subscriptionApproachingLimitPolicyScope.PolicyDefinitionsScopedLimit)
            </td>
        </tr>
"@
    }
$script:html += @"
    </table>
    </div>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$($subscriptionsApproachingLimitPolicyScope.count) Subscriptions approaching Limit for Policy Scope</span></p>
"@
}

#SUMMARY Subs approaching Limits PolicySetScope
$subscriptionsApproachingLimitPolicySetScope = (($policyBaseQuery | where-object { "" -ne $_.SubscriptionId -and $_.PolicySetDefinitionsScopedCount -gt 0 -and  (($_.PolicySetDefinitionsScopedCount -gt ($_.PolicySetDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, Subscription, SubscriptionId, PolicySetDefinitionsScopedCount, PolicySetDefinitionsScopedLimit -Unique)
if ($subscriptionsApproachingLimitPolicySetScope.count -gt 0){
$script:html += @"
<button type="button" class="collapsible"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyScope | measure-object).count) Subscriptions approaching Limit for PolicySet Scope</span></button>
<div class="content">
    <table class="summaryTable">
        <tr>
            <th>
                Subscription
            </th>
            <th>
                SubscriptionId
            </th>
            <th>
                Limit
            </th>
        </tr>
"@
    foreach ($subscriptionApproachingLimitPolicySetScope in $subscriptionsApproachingLimitPolicySetScope){
$script:html += @"
        <tr>
            <td>
                <span class="valignMiddle">$($subscriptionApproachingLimitPolicySetScope.subscription)</span>
            </td>
            <td>
                <span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingLimitPolicySetScope.MgId)">$($subscriptionApproachingLimitPolicySetScope.subscriptionId)</a></span>
            </td>
            <td>
                $($subscriptionApproachingLimitPolicySetScope.PolicySetDefinitionsScopedCount)/$($subscriptionApproachingLimitPolicySetScope.PolicySetDefinitionsScopedLimit)
            </td>
        </tr>
"@
    }
$script:html += @"
    </table>
    </div>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyScope | measure-object).count) Subscriptions approaching Limit for PolicySet Scope</span></p>
"@
}

$endSummary = get-date
Write-Output "Build HTML Summary duration: $((NEW-TIMESPAN -Start $startSummary -End $endSummary).TotalMinutes) minutes"
}
#endregion Summary

#MD
function diagramMermaid() {
    $mgLevels = ($table | Sort-Object -Property Level -Unique).Level
    foreach ($mgLevel in $mgLevels){
        $mgsInLevel = ($table | Where-Object { $_.Level -eq $mgLevel}).MgId | Get-Unique
        foreach ($mgInLevel in $mgsInLevel){ 
            $mgName = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgName | Get-Unique
            $mgParentId = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).mgParentId | Get-Unique
            $mgParentName = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).mgParentName | Get-Unique
            if ($mgInLevel -ne $getMgParentId){
                $script:arrayMgs += $mgInLevel
            }

            if ($mgParentName -eq $mgParentId){
                $mgParentNameId = $mgParentName
            }
            else{
                $mgParentNameId = "$mgParentName<br/>$mgParentId"
            }

            if ($mgName -eq $mgInLevel){
                $mgNameId = $mgName
            }
            else{
                $mgNameId = "$mgName<br/>$mgInLevel"
            }

$script:markdownhierarchyMgs += @"
$mgParentId($mgParentNameId) --> $mgInLevel($mgNameId)`n
"@
            $subsUnderMg = ($table | Where-Object { $_.Level -eq $mgLevel -and "" -ne $_.Subscription -and $_.MgId -eq $mgInLevel }).SubscriptionId | Get-Unique
            if (($subsUnderMg | measure-object).count -gt 0){
                foreach ($subUnderMg in $subsUnderMg){
                    $script:arraySubs += "SubsOf$mgInLevel"
                    $mgName = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgName | Get-Unique
                    $mgParentId = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgParentId | Get-Unique
                    $mgParentName = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgParentName | Get-Unique
                    $subName = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel -and $_.SubscriptionId -eq $subUnderMg }).Subscription | Get-Unique
$script:markdownTable += @"
| $mgLevel | $mgName | $mgInLevel | $mgParentName | $mgParentId | $subName | $($subUnderMg -replace '.*/') |`n
"@
                }
                $mgName = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgName | Get-Unique
                if ($mgName -eq $mgInLevel){
                    $mgNameId = $mgName
                }
                else{
                    $mgNameId = "$mgName<br/>$mgInLevel"
                }
$script:markdownhierarchySubs += @"
$mgInLevel($mgNameId) --> SubsOf$mgInLevel(($(($subsUnderMg | measure-object).count)))`n
"@
            }
            else{
                $mgName = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgName | Get-Unique
                $mgParentId = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgParentId | Get-Unique
                $mgParentName = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgParentName | Get-Unique
$script:markdownTable += @"
| $mgLevel | $mgName | $mgInLevel | $mgParentName | $mgParentId | none | none |`n
"@
            }
        }
    }
}

#endregion Function

#region dataCollection
if (($checkContext).Tenant.Id -ne $ManagementGroupId) {
    #managementGroupId is not RootMgId - get the parents..
    $getMgParent = Get-AzManagementGroup -GroupName "contoso"
    $getMgParent = Get-AzManagementGroup -GroupName $ManagementGroupId
    if (!$getMgParent){
        write-output "fail - check the provided ManagementGroup Id: '$ManagementGroupId' (RBAC role: Reader; MgId correct?)"
        return
    }
    $mgSubPathTopMg = $getMgParent.ParentName
    $getMgParentId = $getMgParent.ParentName
    $getMgParentName = $getMgParent.ParentDisplayName
    $mermaidprnts = "'$(($checkContext).Tenant.Id)',$getMgParentId"
    #$scopeNamingSummary = "MG '$ManagementGroupId' and descendants wide"
    $hierarchyLevel = 0
    addRowToTable `
        -hierarchyLevel $hierarchyLevel `
        -mgName $getMgParentName `
        -mgId $getMgParentId `
        -mgParentId "'$(($checkContext).Tenant.Id)'" `
        -mgParentName "Tenant Root"
}
else{
    $hierarchyLevel = -1
    $mgSubPathTopMg = "$ManagementGroupId"
    $getMgParentId = "'$ManagementGroupId'"
    $getMgParentName = "Tenant Root"
    $mermaidprnts = "'$getMgParentId',$getMgParentId"
}

if (-not $AzureDevOpsWikiAsCode){
    $uriTenantDetails = "https://management.azure.com/tenants?api-version=2020-01-01"
    $tenantDetailsResult = Invoke-RestMethod -Uri $uriTenantDetails -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
    if (($tenantDetailsResult.value | measure-object).count -gt 0) {
        $tenantDetails = $tenantDetailsResult.value | where-object { $_.tenantId -eq ($checkContext).Tenant.Id }
        $tenantDisplayName = $tenantDetails.displayName
        $tenantDefaultDomain = $tenantDetails.defaultDomain
        $tenantDisplayName
    }
    else{
        Write-Output "something unexpected"
    }
}

Write-Output "Data Collection"
$startDataCollection = get-date
dataCollection -mgId $ManagementGroupId -hierarchyLevel $hierarchyLevel -mgParentId $getMgParentId -mgParentName $getMgParentName
$endDataCollection = get-date
Write-Output "Data Collection duration: $((NEW-TIMESPAN -Start $startDataCollection -End $endDataCollection).TotalMinutes) minutes"

if (-not $HierarchyTreeOnly){
    Write-Output "Resource caching"
    $startResourceCaching = get-date

    #Resources https://docs.microsoft.com/en-us/azure/governance/resource-graph/troubleshoot/general#toomanysubscription
    $subscriptionIds = ($table | Where-Object { "" -ne $_.SubscriptionId} | select-Object SubscriptionId | Sort-Object -Property SubscriptionId -Unique).SubscriptionId
    $queryResources = "resources | project id, subscriptionId, location, type | summarize count() by subscriptionId, location, type"
    $queryResourceGroups = "resourcecontainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups' | project id, subscriptionId | summarize count() by subscriptionId"
    #$Query = "resources | project id, subscriptionId, location, type | order by id asc | summarize count() by subscriptionId, location, type"
    $resourcesAll = @()
    $resourceGroupsAll = @()    
    foreach ($subscriptionId in $subscriptionIds){
        $resourcesAll += Search-AzGraph -Subscription $subscriptionId -Query $queryResources
        $resourceGroupsAll += Search-AzGraph -Subscription $subscriptionId -Query $queryResourceGroups
    }

    $endResourceCaching = get-date
    Write-Output "Resource caching duration: $((NEW-TIMESPAN -Start $startResourceCaching -End $endResourceCaching).TotalSeconds) seconds"
}
#endregion dataCollection

#region createoutputs

#region BuildCSV
$table | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).csv" -Delimiter "$csvDelimiter" -NoTypeInformation
#endregion BuildCSV

#region BuildHTML
$startBuildHTML = get-date
$html = $null

#testing helper
#$fileTimestamp = (get-date -format "yyyyMMddHHmmss")##############################

#preQueries
$mgAndSubBaseQuery = ($table | Select-Object -Property level, mgid, mgname, mgParentName, mgParentId, subscriptionId, subscription)
$parentMgNamex = ($mgAndSubBaseQuery | Where-Object { $_.MgParentId -eq $getMgParentId }).mgParentName | Get-Unique
$parentMgIdx = ($mgAndSubBaseQuery | Where-Object { $_.MgParentId -eq $getMgParentId }).mgParentId | Get-Unique
$ManagementGroupIdCaseSensitived = (($mgAndSubBaseQuery | Where-Object {$_.MgId -eq $ManagementGroupId}).mgId) | Get-Unique
$optimizedTableForPathQuery = ($mgAndSubBaseQuery | Select-Object -Property level, mgid, mgparentid, subscriptionId) | sort-object -Property level, mgid, mgname, mgparentId, mgparentName, subscriptionId, subscription -Unique
$subscriptionBaseQuery = $table | Where-Object { "" -ne $_.SubscriptionId }

if (-not $HierarchyTreeOnly){
    $policyBaseQuery = $table | Where-Object { "" -ne $_.Policy } | Sort-Object -Property PolicyType, Policy | Select-Object -Property Policy*, mgId, mgname, SubscriptionId, Subscription
    $policyPolicyBaseQuery = $policyBaseQuery | Where-Object { $_.PolicyVariant -eq "Policy" } | Select-Object -Property PolicyDefinitionIdGuid, PolicyAssignmentId
    $policyPolicySetBaseQuery = $policyBaseQuery | Where-Object { $_.PolicyVariant -eq "PolicySet" } | Select-Object -Property PolicyDefinitionIdGuid, PolicyAssignmentId
    $policyAssignmentIds = ($policyBaseQuery | sort-object -property PolicyAssignmentName, PolicyAssignmentId -Unique | Select-Object -Property PolicyAssignmentName, PolicyAssignmentId)

    $rbacBaseQuery = $table | Where-Object { "" -ne $_.RoleDefinitionName } | Sort-Object -Property RoleIsCustom, RoleDefinitionName | Select-Object -Property Role*, mgId, SubscriptionId

    $blueprintBaseQuery = $table | Where-Object { "" -ne $_.BlueprintName}

    $mgsAndSubs = (($mgAndSubBaseQuery | where-object {$_.mgId -ne "" -and $_.Level -ne "0"}) | select-object MgId, SubscriptionId -unique)
    $tenantCustomPolicies = ($htCacheDefinitions).policy.keys | where-object { ($htCacheDefinitions).policy.($_).Type -eq "Custom" }
    $tenantCustomPoliciesCount = ($tenantCustomPolicies | measure-object).count
    $tenantCustomPolicySets = ($htCacheDefinitions).policySet.keys | where-object { ($htCacheDefinitions).policySet.($_).Type -eq "Custom" }
    $tenantCustompolicySetsCount = ($tenantCustomPolicySets | measure-object).count
    $tenantCustomRoles = $($htCacheDefinitions).role.keys | where-object { ($htCacheDefinitions).role.($_).IsCustom -eq $True }
}

$html += @"
<!doctype html>
<html lang="en">
<html style="height: 100%">
<head>
    <meta charset="utf-8" />
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
    <meta http-equiv="Pragma" content="no-cache" />
    <meta http-equiv="Expires" content="0" />
    <title>AzGovViz</title>
    <script type="text/javascript">
        var link = document.createElement( "link" );
        rand = Math.floor(Math.random() * 99999);
        link.href = "https://www.azadvertizer.net/azgovviz/css/azgovvizversion.css?rnd=" + rand;
        link.type = "text/css";
        link.rel = "stylesheet";
        link.media = "screen,print";
        document.getElementsByTagName( "head" )[0].appendChild( link );
    </script>
    <link rel="stylesheet" type="text/css" href="https://www.azadvertizer.net/azgovviz/css/azgovvizmain_002_002.css">
    <script src="https://code.jquery.com/jquery-1.7.2.js" integrity="sha256-FxfqH96M63WENBok78hchTCDxmChGFlo+/lFIPcZPeI=" crossorigin="anonymous"></script>
    <script src="https://code.jquery.com/ui/1.8.18/jquery-ui.js" integrity="sha256-lzf/CwLt49jbVoZoFcPZOc0LlMYPFBorVSwMsTs2zsA=" crossorigin="anonymous"></script>
    <script type="text/javascript" src="https://www.azadvertizer.net/azgovviz/js/highlight.js"></script>
    <script src="https://use.fontawesome.com/0c0b5cbde8.js"></script>
</head>
<body>
    <div class="tree">
        <div class="hierarchyTree" id="hierarchyTree">
"@

if ($getMgParentName -eq "Tenant Root"){
$html += @"
            <ul>
"@
}
else{
    if ($parentMgNamex -eq $parentMgIdx){
        $mgNameAndOrId = $parentMgNamex
    }
    else{
        $mgNameAndOrId = "$parentMgNamex<br><i>$parentMgIdx</i>"
    }
    
    if (-not $AzureDevOpsWikiAsCode){
        $tenantDetailsDisplay = "$tenantDisplayName<br>$tenantDefaultDomain<br>"
    }
    else{
        $tenantDetailsDisplay = ""
    }
$html += @"
            <ul>
                <li id ="first">
                    <a class="tenant"><div class="fitme" id="fitme">$($tenantDetailsDisplay)$(($checkContext).Tenant.Id)</div></a>
                    <ul>
                        <li><a class="mgnonradius parentmgnotaccessible"><img class="imgMgTree" src="https://www.azadvertizer.net/azgovviz/icon/Icon-general-11-Management-Groups.svg"><div class="fitme" id="fitme">$mgNameAndOrId</div></a>
                        <ul>
"@
}

hierarchyMgHTML -mgChild $ManagementGroupIdCaseSensitived

if ($getMgParentName -eq "Tenant Root"){
$html += @"
                    </ul>
                </li>
            </ul>
        </div>
    </div>
"@
}
else{
$html += @"
                            </ul>
                        </li>
                    </ul>
                </li>
            </ul>
        </div>
    </div>
"@
}

if (-not $HierarchyTreeOnly){

$html += @"
    <div class="summprnt" id="summprnt">
    <div class="summary" id="summary">
"@

    summary

$html += @"
    </div>
    </div>
    <div class="hierprnt" id="hierprnt">
    <div class="hierarchyTables" id="hierarchyTables">
"@

    tableMgHTML -mgChild $ManagementGroupIdCaseSensitived -mgChildOf $getMgParentId

$html += @"
    </div>
    </div>
"@
}

$html += @"
    <div class="footer">
    <div class="VersionDiv VersionLatest"></div>
    <div class="VersionDiv VersionThis"></div>
    <div class="VersionAlert"></div>
"@

if (-not $HierarchyTreeOnly){
$html += @"
        Limit: $($LimitCriticalPercentage)% <button id="hierarchyTreeShowHide" onclick="toggleHierarchyTree()">Hide Hierarchy Tree</button> <button id="summaryShowHide" onclick="togglesummprnt()">Hide Summary</button> <button id="hierprntShowHide" onclick="togglehierprnt()">Hide Details</button>
"@
}

$html += @"
    </div>
    <script src="https://www.azadvertizer.net/azgovviz/js/toggle.js"></script>
    <script src="https://www.azadvertizer.net/azgovviz/js/collapsetable.js"></script>
    <script src="https://www.azadvertizer.net/azgovviz/js/fitty.min.js"></script>
    <script src="https://www.azadvertizer.net/azgovviz/js/version.js"></script>
    <script>
        fitty('#fitme', {
            minSize: 6,
            maxSize: 10
        });
    </script>
</body>
</html>
"@  

if ($AzureDevOpsWikiAsCode) { 
    $fileName = "AzGovViz_$($ManagementGroupIdCaseSensitived)"
}
else{
    $fileName = "AzGovViz_$($fileTimestamp)_$($ManagementGroupIdCaseSensitived)"
}
$html | Set-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force

$endBuildHTML = get-date
Write-Output "Build HTML duration: $((NEW-TIMESPAN -Start $startBuildHTML -End $endBuildHTML).TotalMinutes) minutes"
#endregion BuildHTML

#region BuildMD
$arrayMgs = @()
$arraySubs = @()
$markdown = $null
$markdownhierarchyMgs = $null
$markdownhierarchySubs = $null
$markdownTable = $null

if ($AzureDevOpsWikiAsCode) { 
$markdown += @"
# AzGovViz - Management Group Hierarchy

## Hierarchy Diagram (Mermaid)

::: mermaid
    graph TD;`n
"@
}
else{
$markdown += @"
# AzGovViz - Management Group Hierarchy

$executionDateTimeInternationalReadable ($currentTimeZone)

## Hierarchy Diagram (Mermaid)

::: mermaid
    graph TD;`n
"@
}

    diagramMermaid

$markdown += @"
$markdownhierarchyMgs
$markdownhierarchySubs
 classDef mgr fill:#D9F0FF,stroke:#56595E,stroke-width:1px;
 classDef subs fill:#EEEEEE,stroke:#56595E,stroke-width:1px;
 classDef mgrprnts fill:#FFFFFF,stroke:#56595E,stroke-width:1px;
 class $(($arrayMgs | sort-object -unique) -join ",") mgr;
 class $(($arraySubs | sort-object -unique) -join ",") subs;
 class $mermaidprnts mgrprnts;
:::

## Hierarchy Table

| **MgLevel** | **MgName** | **MgId** | **MgParentName** | **MgParentId** | **SubName** | **SubId** |
|-------------|-------------|-------------|-------------|-------------|-------------|-------------|
$markdownTable
"@

$markdown | Set-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).md" -Encoding utf8 -Force
#endregion BuildMD

#endregion createoutputs

#endregion Code

$endAzGovViz = get-date
Write-Output "AzGovViz duration: $((NEW-TIMESPAN -Start $startAzGovViz -End $endAzGovViz).TotalMinutes) minutes"