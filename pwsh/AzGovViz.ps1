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
 
.PARAMETER ManagementGroupId
    Define the Management Group Id for which the outputs/files shall be generated
 
.PARAMETER CsvDelimiter
    The script outputs a csv file depending on your delimit defaults choose semicolon or comma

.PARAMETER OutputPath
    Full- or relative path

.PARAMETER DoNotShowRoleAssignmentsUserData
    default is to capture the DisplayName and SignInName for RoleAssignments on ObjectType=User; for data protection and security reasons this may not be acceptable

.PARAMETER HierarchyTreeOnly
    default is to query all Management groups and Subscription for Governance capabilities, if you use the parameter -HierarchyTreeOnly then only the Hierarchy Tree will be created

.PARAMETER AzureDevOpsWikiAsCode
    default is to add timestamp to the MD output, use the parameter to remove the timestamp - the MD file will then only be pushed to Wiki Repo if the Management Group structure and/or Subscription linkage changed

.PARAMETER LimitCriticalPercentage
    default is 80%, this parameter defines the warning level for approaching Limits (e.g. 80% of Role Assignment limit reached) change as per your preference

.PARAMETER SubscriptionQuotaIdWhitelist
    default is 'undefined', this parameter defines the QuotaIds the subscriptions must match so that AzGovViz processes them.  

.EXAMPLE
    Define the ManagementGroup ID
    PS C:\> .\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id>

    Define how the CSV output should be delimited. Valid input is ; or , (semicolon is default)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -CsvDelimiter ","
    
    Define the outputPath (must exist)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -OutputPath 123
    
    Define if User information shall be scrubbed (default prints Userinformation to the CSV and HTML output)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -DoNotShowRoleAssignmentsUserData
    
    Define if only the hierarchy tree output shall be created. Will ignore the parameters 'LimitCriticalPercentage' and 'DoNotShowRoleAssignmentsUserData' (default queries for Governance capabilities such as policy-, role-, blueprints assignments and more)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -HierarchyTreeOnly

    Define if the script runs in AzureDevOps. This will not print any timestamps into the markdown output so that only true deviation will force a push to the wiki repository (default prints timestamps to the markdown output)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -AzureDevOpsWikiAsCode
    
    Define when limits should be highlited as warning (default is 80 percent)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -LimitCriticalPercentage

    Define the QuotaId whitelist by providing strings separated by a backslash
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -SubscriptionQuotaIdWhitelist MSDN_\EnterpriseAgreement_

.NOTES
    AUTHOR: Julian Hayward - Customer Engineer - Azure Infrastucture/Automation/Devops/Governance

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
    [string]$SubscriptionQuotaIdWhitelist = "undefined",

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
        Write-Host "cmdlet $testCommand not available - make sure the modules Az.Accounts, Az.Resources and Az.ResourceGraph are installed"
        break
    }
    else {
        Write-Host "passed: Az ps module supporting cmdlet $testCommand installed"
    }
}

#check if connected, verify Access Token lifetime
$tokenExirationMinimumInMinutes = 5
$checkContext = Get-AzContext -ErrorAction Stop
$checkAzEnvironments = Get-AzEnvironment -ErrorAction Stop

#FutureUse
#Graph Endpoints https://docs.microsoft.com/en-us/graph/deployments#microsoft-graph-and-graph-explorer-service-root-endpoints
#AzureCloud https://graph.microsoft.com
#AzureUSGovernment L4 https://graph.microsoft.us
#AzureUSGovernment L5 (DOD) https://dod-graph.microsoft.us
#AzureChinaCloud https://microsoftgraph.chinacloudapi.cn
#AzureGermanCloud https://graph.microsoft.de

#AzureEnvironmentRelatedUrls
$htAzureEnvironmentRelatedUrls = @{ }
foreach ($checkAzEnvironment in $checkAzEnvironments){
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name) = @{ }
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).ResourceManagerUrl = $checkAzEnvironment.ResourceManagerUrl
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).ServiceManagementUrl = $checkAzEnvironment.ServiceManagementUrl
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).ActiveDirectoryAuthority = $checkAzEnvironment.ActiveDirectoryAuthority
}

function refreshToken() {
    $checkContext = Get-AzContext -ErrorAction Stop
    Write-Host "Creating new Token"
    $azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile;
    $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile);
    $newAccessToken = ($profileClient.AcquireAccessToken($checkContext.Subscription.TenantId))
    if ($AzureDevOpsWikiAsCode) {
        $script:accessTokenExipresOn = ($checkContext.TokenCache.ReadItems() | Where-Object { ($_.Resource -eq ($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ServiceManagementUrl) }).ExpiresOn
    }
    else {
        $script:accessTokenExipresOn = ($checkContext.TokenCache.ReadItems() | Where-Object { ($_.TenantId -eq $checkContext.Tenant.Id) -and ($_.Resource -eq ($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ServiceManagementUrl) -and ($_.DisplayableId -eq $checkContext.account.id) }).ExpiresOn
    }
    $script:accessToken = $newAccessToken.AccessToken
}

function checkTokenLifetime() {
    $tokenExirationInMinutes = ($accessTokenExipresOn - (get-date)).Minutes
    if ($tokenExirationInMinutes -lt $tokenExirationMinimumInMinutes) {
        Write-Host "Access Token for REST AUTH has has less than $tokenExirationMinimumInMinutes minutes lifetime ($tokenExirationInMinutes minutes). Creating new token"
        refreshToken
        Write-Host "New Token expires: $($($script:accessTokenExipresOn).LocalDateTime) ($(($script:accessTokenExipresOn - (get-date)).Minutes) minutes)"
    }
    else {
        #Write-Host "Access Token for REST AUTH remaining lifetime ($tokenExirationInMinutes minutes) above minimum lifetime ($tokenExirationMinimumInMinutes minutes)"
    }
}

if ($checkContext) {
    if ($AzureDevOpsWikiAsCode) {
        $accessTokenExipresOn = ($checkContext.TokenCache.ReadItems() | Where-Object { ($_.Resource -eq ($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ServiceManagementUrl) }).ExpiresOn
    }
    else {
        $accessTokenExipresOn = ($checkContext.TokenCache.ReadItems() | Where-Object { ($_.TenantId -eq $checkContext.Tenant.Id) -and ($_.Resource -eq ($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ServiceManagementUrl) -and ($_.DisplayableId -eq $checkContext.account.id) }).ExpiresOn
    }

    if ($accessTokenExipresOn -lt $(Get-Date)) {
        Write-Host "Access Token for REST AUTH has has expired"
        refreshToken
        Write-Host "New Token expires: $($($script:accessTokenExipresOn).LocalDateTime) ($(($script:accessTokenExipresOn - (get-date)).Minutes) minutes)"
    }
    else {
        $tokenExirationInMinutes = ($accessTokenExipresOn - (get-date)).Minutes
        if ($tokenExirationInMinutes -lt $tokenExirationMinimumInMinutes) {
            Write-Host "Access Token for REST AUTH has has less than $tokenExirationMinimumInMinutes minutes lifetime ($tokenExirationInMinutes minutes)"
            refreshToken
            Write-Host "New Token expires: $($($script:accessTokenExipresOn).LocalDateTime) ($(($script:accessTokenExipresOn - (get-date)).Minutes) minutes)"
        }
        else {
            if ($AzureDevOpsWikiAsCode) {
                $accessToken = ($checkContext.TokenCache.ReadItems() | Where-Object { ($_.Resource -eq ($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ServiceManagementUrl) }).AccessToken
            }
            else {
                $accessToken = ($checkContext.TokenCache.ReadItems() | Where-Object { ($_.TenantId -eq $checkContext.Tenant.Id) -and ($_.Resource -eq ($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ServiceManagementUrl) -and ($_.DisplayableId -eq $checkContext.account.id) }).AccessToken
            }
            Write-Host "Found Access Token for REST AUTH (expires in $tokenExirationInMinutes minutes; defined minimum lifetime: $tokenExirationMinimumInMinutes minutes).."
        }
    }
}
else {
    Write-Host "No context found. Please connect to Azure (run: Connect-AzAccount) and re-run script"
    return
}

#helper file/dir
if (-not [IO.Path]::IsPathRooted($outputPath)) {
    $outputPath = Join-Path -Path (Get-Location).Path -ChildPath $outputPath
}
$outputPath = Join-Path -Path $outputPath -ChildPath '.'
$outputPath = [IO.Path]::GetFullPath($outputPath)
if (-not (test-path $outputPath)) {
    Write-Host "path $outputPath does not exist -create it!"
    return
}
else {
    Write-Host "Output/Files will be created in path $outputPath"
}
$DirectorySeparatorChar = [IO.Path]::DirectorySeparatorChar
$fileTimestamp = (get-date -format "yyyyMMddHHmmss")

#ManagementGroup helper
#thx @Jim Britt https://github.com/JimGBritt/AzurePolicy/tree/master/AzureMonitor/Scripts Create-AzDiagPolicy.ps1
if (-not $ManagementGroupId) {
    [array]$MgtGroupArray = Add-IndexNumberToArray (Get-AzManagementGroup -ErrorAction Stop)
    if (-not $MgtGroupArray) {
        Write-Host "Seems you do not have access to any Management Group. Please make sure you have the required RBAC role [Reader] assigned on at least one Management Group"
        return
    }
    function selectMg() {
        Write-Host "Please select a Management Group from the list below"
        $MgtGroupArray | Select-Object "#", Name, DisplayName, Id | Format-Table

        Write-Host "If you don't see your ManagementGroupID try using the parameter -ManagementGroupID" -ForegroundColor Yellow
        if ($msg){
            Write-Host $msg -ForegroundColor Red
        }
        
        $script:SelectedMG = Read-Host "Please enter a selection from 1 to $(($MgtGroupArray | measure-object).count)"

        function IsNumeric ($Value) {
            return $Value -match "^[\d\.]+$"
        }
        if (IsNumeric $SelectedMG){
            if ([int]$SelectedMG -lt 1 -or [int]$SelectedMG -gt ($MgtGroupArray | measure-object).count) {
                $msg = "last input '$SelectedMG' is out of range, enter a number from the selection!"
                selectMg
            }
        }
        else{
            $msg = "last input '$SelectedMG' is not numeric, enter a number from the selection!"
            selectMg
        }
    }
    selectMg
    

    if ($($MgtGroupArray[$SelectedMG - 1].Name)) {
        $ManagementGroupID = $($MgtGroupArray[$SelectedMG - 1].Name)
        $ManagementGroupName = $($MgtGroupArray[$SelectedMG - 1].DisplayName)
    }
    else{
        Write-Host "s.th. unexpected happened" -ForegroundColor Red
        return
    }
    Write-Host "Selected Management Group: $ManagementGroupName (Id: $ManagementGroupId)" -ForegroundColor Green
    Write-Host "_______________________________________"
}

#helper 
$executionDateTimeInternationalReadable = get-date -format "dd-MMM-yyyy HH:mm:ss"
$currentTimeZone = (Get-TimeZone).Id

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
$table.columns.add((New-Object system.Data.DataColumn PolicyAssignmentNotScope, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyAssignmentId, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyAssignmentName, ([string])))
$table.columns.add((New-Object system.Data.DataColumn PolicyAssignmentDisplayName, ([string])))
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
$table.columns.add((New-Object system.Data.DataColumn BlueprintAssignmentVersion, ([string])))
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
        $PolicyAssignmentNotScope, 
        $PolicyAssignmentId, 
        $PolicyAssignmentName, 
        $PolicyAssignmentDisplayName, 
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
        $BlueprintAssignmentVersion,
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
    $row.PolicyAssignmentNotScope = $PolicyAssignmentNotScope
    $row.PolicyAssignmentId = $PolicyAssignmentId
    $row.PolicyAssignmentName = $PolicyAssignmentName
    $row.PolicyAssignmentDisplayName = $PolicyAssignmentDisplayName
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
    $row.BlueprintAssignmentVersion = $BlueprintAssignmentVersion
    $row.BlueprintAssignmentId = $BlueprintAssignmentId 
    $table.Rows.Add($row)
}

#region Function_dataCollection
function dataCollection($mgId, $hierarchyLevel, $mgParentId, $mgParentName) {
    checkTokenLifetime
    $startMgLoop = get-date
    $hierarchyLevel++
    $getMg = Get-AzManagementGroup -groupname $mgId -Expand -Recurse -ErrorAction Stop
    Write-Host "CustomDataCollection: Processing L$hierarchyLevel MG '$($getMg.DisplayName)' ('$($getMg.Name)')"

    if (-not $HierarchyTreeOnly) {

        #MGPolicyCompliance
        ($htCachePolicyCompliance).mg.($getMg.Name) = @{ }
        $url = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)/providers/Microsoft.Management/managementGroups/$($getMg.Name)/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
        $result = Invoke-RestMethod -Uri $url -Method POST -Headers @{"Authorization" = "Bearer $accesstoken" }

        foreach ($policyAssignment in $result.value.policyassignments | sort-object -Property policyAssignmentId){
            ($htCachePolicyCompliance).mg.($getMg.Name).($policyAssignment.policyAssignmentId) = @{ }
            foreach ($policyComplianceState in $policyAssignment.results.policydetails){
                if ($policyComplianceState.ComplianceState -eq "compliant"){
                    ($htCachePolicyCompliance).mg.($getMg.Name).($policyAssignment.policyAssignmentId).CompliantPolicies = $policyComplianceState.count
                }
                if ($policyComplianceState.ComplianceState -eq "noncompliant"){
                    ($htCachePolicyCompliance).mg.($getMg.Name).($policyAssignment.policyAssignmentId).NonCompliantPolicies = $policyComplianceState.count
                }
            }

            foreach ($resourceComplianceState in $policyAssignment.results.resourcedetails){
                if ($resourceComplianceState.ComplianceState -eq "compliant"){
                    ($htCachePolicyCompliance).mg.($getMg.Name).($policyAssignment.policyAssignmentId).CompliantResources = $resourceComplianceState.count
                }
                if ($resourceComplianceState.ComplianceState -eq "nonCompliant"){
                    ($htCachePolicyCompliance).mg.($getMg.Name).($policyAssignment.policyAssignmentId).NonCompliantResources = $resourceComplianceState.count
                }
            }
        }

        #MGBlueprints
        $uriMgBlueprintDefinitionScoped = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)/providers/Microsoft.Management/managementGroups/$($getMg.Name)/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
        $mgBlueprintDefinitionResult = Invoke-RestMethod -Uri $uriMgBlueprintDefinitionScoped -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
        if (($mgBlueprintDefinitionResult.value | measure-object).count -gt 0) {
            foreach ($blueprint in $mgBlueprintDefinitionResult.value) {

                if (-not $($htCacheDefinitions).blueprint[$blueprint.Id]) {
                    $($htCacheDefinitions).blueprint.$($blueprint.Id) = @{ }
                    $($htCacheDefinitions).blueprint.$($blueprint.Id) = $blueprint
                }  

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

        #MGCustomPolicies
        $uriPolicyDefinitionAPI = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementgroups/$($getMg.Name)/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
        $requestPolicyDefinitionAPI = Invoke-RestMethod -Uri $uriPolicyDefinitionAPI -Headers  @{"Authorization" = "Bearer $accesstoken" }
        $mgPolicyDefinitions = $requestPolicyDefinitionAPI.value | Where-Object { $_.properties.policyType -eq "custom" }
        $PolicyDefinitionsScopedCount = (($mgPolicyDefinitions | Where-Object { ($_.Id).startswith("/providers/Microsoft.Management/managementGroups/$($getMg.Name)/") }) | measure-object).count
        foreach ($mgPolicyDefinition in $mgPolicyDefinitions) {
            if (-not $($htCacheDefinitions).policy[$mgPolicyDefinition.name]) {
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.name) = @{ }
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.name).Id = $($mgPolicyDefinition.name)
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.name).DisplayName = $($mgPolicyDefinition.Properties.displayname)
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.name).Type = $($mgPolicyDefinition.Properties.policyType)
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.name).Category = $($mgPolicyDefinition.Properties.metadata.Category)
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.name).PolicyDefinitionId = $($mgPolicyDefinition.id)
                #effects
                if ($mgPolicyDefinition.properties.parameters.effect.defaultvalue) {
                    ($htCacheDefinitions).policy.$($mgPolicyDefinition.name).effectDefaultValue = $mgPolicyDefinition.properties.parameters.effect.defaultvalue
                    if ($mgPolicyDefinition.properties.parameters.effect.allowedValues){
                        ($htCacheDefinitions).policy.$($mgPolicyDefinition.name).effectAllowedValue = $mgPolicyDefinition.properties.parameters.effect.allowedValues -join ","
                    }
                    else{
                        ($htCacheDefinitions).policy.$($mgPolicyDefinition.name).effectAllowedValue = "n/a"
                    }
                    ($htCacheDefinitions).policy.$($mgPolicyDefinition.name).effectFixedValue = "n/a"
                }
                else {
                    if ($mgPolicyDefinition.properties.parameters.policyEffect.defaultValue) {
                        ($htCacheDefinitions).policy.$($mgPolicyDefinition.name).effectDefaultValue = $mgPolicyDefinition.properties.parameters.policyEffect.defaultvalue
                        if ($mgPolicyDefinition.properties.parameters.policyEffect.allowedValues){
                            ($htCacheDefinitions).policy.$($mgPolicyDefinition.name).effectAllowedValue = $mgPolicyDefinition.properties.parameters.policyEffect.allowedValues -join ","
                        }
                        else{
                            ($htCacheDefinitions).policy.$($mgPolicyDefinition.name).effectAllowedValue = "n/a"
                        }
                        ($htCacheDefinitions).policy.$($mgPolicyDefinition.name).effectFixedValue = "n/a"
                    }
                    else {
                        ($htCacheDefinitions).policy.$($mgPolicyDefinition.name).effectFixedValue = $mgPolicyDefinition.Properties.policyRule.then.effect
                        ($htCacheDefinitions).policy.$($mgPolicyDefinition.name).effectDefaultValue = "n/a"
                        ($htCacheDefinitions).policy.$($mgPolicyDefinition.name).effectAllowedValue = "n/a"
                    }
                }
                ($htCacheDefinitions).policy.$($mgPolicyDefinition.name).json = $mgPolicyDefinition
            }
            if (-not $($htCacheDefinitionsAsIs).policy[$mgPolicyDefinition.name]) {
                ($htCacheDefinitionsAsIs).policy.$($mgPolicyDefinition.name) = @{ }
                ($htCacheDefinitionsAsIs).policy.$($mgPolicyDefinition.name) = $mgPolicyDefinition
            }  
        }

        #MGPolicySets
        $uriPolicySetDefinitionAPI = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementgroups/$($getMg.Name)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"
        $requestPolicySetDefinitionAPI = Invoke-RestMethod -Uri $uriPolicySetDefinitionAPI -Headers  @{"Authorization" = "Bearer $accesstoken" }
        $mgPolicySetDefinitions = $requestPolicySetDefinitionAPI.value | Where-Object { $_.properties.policyType -eq "custom" }
        $PolicySetDefinitionsScopedCount = (($mgPolicySetDefinitions | Where-Object { ($_.Id).startswith("/providers/Microsoft.Management/managementGroups/$($getMg.Name)/") }) | measure-object).count
        foreach ($mgPolicySetDefinition in $mgPolicySetDefinitions) {
            if (-not $($htCacheDefinitions).policySet[$mgPolicySetDefinition.name]) {
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.name) = @{ }
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.name).Id = $($mgPolicySetDefinition.name)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.name).DisplayName = $($mgPolicySetDefinition.Properties.displayname)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.name).Type = $($mgPolicySetDefinition.Properties.policyType)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.name).Category = $($mgPolicySetDefinition.Properties.metadata.Category)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.name).PolicyDefinitionId = $($mgPolicySetDefinition.id)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.name).PolicySetPolicyIds = $mgPolicySetDefinition.properties.policydefinitions.policyDefinitionId
                ($htCacheDefinitions).policySet.$($mgPolicySetDefinition.name).json = $mgPolicySetDefinition
            }  
        }

        #MgPolicyAssignments
        $L0mgmtGroupPolicyAssignments = Get-AzPolicyAssignment -Scope "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" -ErrorAction Stop
        $L0mgmtGroupPolicyAssignmentsPolicyCount = (($L0mgmtGroupPolicyAssignments | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" }) | measure-object).count
        $L0mgmtGroupPolicyAssignmentsPolicySetCount = (($L0mgmtGroupPolicyAssignments | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" }) | measure-object).count
        $L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount = (($L0mgmtGroupPolicyAssignments | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -and $_.PolicyAssignmentId -match "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" }) | measure-object).count
        $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount = (($L0mgmtGroupPolicyAssignments | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" -and $_.PolicyAssignmentId -match "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" }) | measure-object).count
        $L0mgmtGroupPolicyAssignmentsPolicyAndPolicySetAtScopeCount = ($L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount + $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount)
        foreach ($L0mgmtGroupPolicyAssignment in $L0mgmtGroupPolicyAssignments) {

            if (-not $($htCacheAssignments).policy[$L0mgmtGroupPolicyAssignment.PolicyAssignmentId]) {
                $($htCacheAssignments).policy.$($L0mgmtGroupPolicyAssignment.PolicyAssignmentId) = @{ }
                $($htCacheAssignments).policy.$($L0mgmtGroupPolicyAssignment.PolicyAssignmentId) = $L0mgmtGroupPolicyAssignment
            }  

            if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -OR $L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
                if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/") {
                    $PolicyVariant = "Policy"
                    $definitiontype = "policy"
                    $Id = $L0mgmtGroupPolicyAssignment.properties.policydefinitionid -replace '.*/'
                    $PolicyAssignmentScope = $L0mgmtGroupPolicyAssignment.Properties.Scope
                    $PolicyAssignmentNotScope = $L0mgmtGroupPolicyAssignment.Properties.NotScopes -join "$CsvDelimiterOpposite "
                    $PolicyAssignmentId = $L0mgmtGroupPolicyAssignment.PolicyAssignmentId
                    $PolicyAssignmentName = $L0mgmtGroupPolicyAssignment.Name
                    $PolicyAssignmentDisplayName = $L0mgmtGroupPolicyAssignment.Properties.DisplayName

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
                        -PolicyAssignmentNotScope $PolicyAssignmentNotScope `
                        -PolicyAssignmentId $PolicyAssignmentId `
                        -PolicyAssignmentName $PolicyAssignmentName `
                        -PolicyAssignmentDisplayName $PolicyAssignmentDisplayName `
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
                    $PolicyAssignmentNotScope = $L0mgmtGroupPolicyAssignment.Properties.NotScopes -join "$CsvDelimiterOpposite "
                    $PolicyAssignmentId = $L0mgmtGroupPolicyAssignment.PolicyAssignmentId
                    $PolicyAssignmentName = $L0mgmtGroupPolicyAssignment.Name
                    $PolicyAssignmentDisplayName = $L0mgmtGroupPolicyAssignment.Properties.DisplayName

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
                        -PolicyAssignmentNotScope $PolicyAssignmentNotScope `
                        -PolicyAssignmentId $PolicyAssignmentId `
                        -PolicyAssignmentName $PolicyAssignmentName `
                        -PolicyAssignmentDisplayName $PolicyAssignmentDisplayName `
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
                Write-Host "CustomDataCollection: unexpected"
                return
            }
        }
        #MGCustomRolesRoles
        $mgCustomRoleDefinitions = Get-AzRoleDefinition -custom -Scope "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" -ErrorAction Stop
        foreach ($mgCustomRoleDefinition in $mgCustomRoleDefinitions) {
            if (-not $($htCacheDefinitions).role[$mgCustomRoleDefinition.Id]) {
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
        $L0mgmtGroupRoleAssignments = Get-AzRoleAssignment -scope "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" -ErrorAction Stop
        $L0mgmtGroupRoleAssignmentsLimitUtilization = (($L0mgmtGroupRoleAssignments | where-object { $_.Scope -eq "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" }) | measure-object).count
        foreach ($L0mgmtGroupRoleAssignment in $L0mgmtGroupRoleAssignments) {
            
            if (-not $($htCacheAssignments).role[$L0mgmtGroupRoleAssignment.RoleAssignmentId]) {
                $($htCacheAssignments).role.$($L0mgmtGroupRoleAssignment.RoleAssignmentId) = @{ }
                $($htCacheAssignments).role.$($L0mgmtGroupRoleAssignment.RoleAssignmentId) = $L0mgmtGroupRoleAssignment
            }  

            $Id = $L0mgmtGroupRoleAssignment.RoleDefinitionId
            $definitiontype = "role"

            if (($L0mgmtGroupRoleAssignment.RoleDefinitionName).length -eq 0) {
                $RoleDefinitionName = "'This roleDefinition likely was deleted although a roleAssignment existed'" 
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
    $endMgLoop = get-date
    Write-Host "CustomDataCollection: L$hierarchyLevel MG '$($getMg.DisplayName)' ('$($getMg.Name)') processing duration: $((NEW-TIMESPAN -Start $startMgLoop -End $endMgLoop).TotalSeconds) seconds"

    #SUBSCRIPTION
    if (($getMg.children | measure-object).count -gt 0) {
        
        foreach ($childMg in $getMg.Children | Where-Object { $_.Type -eq "/subscriptions" }) {
            checkTokenLifetime
            $startSubLoop = get-date
            $childMgSubId = $childMg.Id -replace '/subscriptions/', ''
            Write-Host "CustomDataCollection: Processing Subscription $($childMg.DisplayName) ('$childMgSubId')"

            if (-not $HierarchyTreeOnly) {
                #SubscriptionDetails
                #https://docs.microsoft.com/en-us/rest/api/resources/subscriptions/list
                $uriSubscriptionsGet = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($childMgSubId)?api-version=2020-01-01"
                $result = "letscheck"
                try {
                    $subscriptionsGetResult = Invoke-RestMethod -Uri $uriSubscriptionsGet -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
                } catch {
                    $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
                }
                if ($result -eq "letscheck"){              

                    if (($subscriptionsGetResult.subscriptionPolicies.quotaId).startswith("AAD_","CurrentCultureIgnoreCase") -or $subscriptionsGetResult.state -ne "enabled") {
                        if (($subscriptionsGetResult.subscriptionPolicies.quotaId).startswith("AAD_","CurrentCultureIgnoreCase")) {
                            Write-Host "CustomDataCollection: Subscription Quota Id: $($subscriptionsGetResult.subscriptionPolicies.quotaId) is out of scope for AzGovViz"
                            $htOutOfScopeSubscriptions.($childMgSubId) = @{ }
                            $htOutOfScopeSubscriptions.($childMgSubId).subscriptionId = $childMgSubId
                            $htOutOfScopeSubscriptions.($childMgSubId).subscriptionName = $childMg.DisplayName
                            $htOutOfScopeSubscriptions.($childMgSubId).outOfScopeReason = "QuotaId: AAD_"
                            $htOutOfScopeSubscriptions.($childMgSubId).ManagementGroupId = $getMg.Name
                            $htOutOfScopeSubscriptions.($childMgSubId).ManagementGroupName = $getMg.DisplayName
                        }
                        if ($subscriptionsGetResult.state -ne "enabled") {
                            Write-Host "CustomDataCollection: Subscription State: $($subscriptionsGetResult.state) is out of scope for AzGovViz"
                            $htOutOfScopeSubscriptions.($childMgSubId) = @{ }
                            $htOutOfScopeSubscriptions.($childMgSubId).subscriptionId = $childMgSubId
                            $htOutOfScopeSubscriptions.($childMgSubId).subscriptionName = $childMg.DisplayName
                            $htOutOfScopeSubscriptions.($childMgSubId).outOfScopeReason = "State: $($subscriptionsGetResult.state)"
                            $htOutOfScopeSubscriptions.($childMgSubId).ManagementGroupId = $getMg.Name
                            $htOutOfScopeSubscriptions.($childMgSubId).ManagementGroupName = $getMg.DisplayName
                        }
                        $subscriptionIsInScopeforAzGovViz = $False
                    }
                    else {
                        if ($subscriptionQuotaIdWhitelistMode -eq $true){
                            $whitelistMatched = $false
                            foreach ($subscriptionQuotaIdWhitelistQuotaId in $subscriptionQuotaIdWhitelistArray){
                                if (($subscriptionsGetResult.subscriptionPolicies.quotaId).startswith($subscriptionQuotaIdWhitelistQuotaId,"CurrentCultureIgnoreCase")){
                                    $whitelistMatched = $true
                                }
                            }

                            if ($true -eq $whitelistMatched){
                                $subscriptionIsInScopeforAzGovViz = $True
                            }
                            else{
                                Write-Host "CustomDataCollection: Subscription Quota Id: $($subscriptionsGetResult.subscriptionPolicies.quotaId) is out of scope for AzGovViz (not in Whitelist)"
                                $htOutOfScopeSubscriptions.($childMgSubId) = @{ }
                                $htOutOfScopeSubscriptions.($childMgSubId).subscriptionId = $childMgSubId
                                $htOutOfScopeSubscriptions.($childMgSubId).subscriptionName = $childMg.DisplayName
                                $htOutOfScopeSubscriptions.($childMgSubId).outOfScopeReason = "QuotaId: '$($subscriptionsGetResult.subscriptionPolicies.quotaId)' not in Whitelist"
                                $htOutOfScopeSubscriptions.($childMgSubId).ManagementGroupId = $getMg.Name
                                $htOutOfScopeSubscriptions.($childMgSubId).ManagementGroupName = $getMg.DisplayName
                                $subscriptionIsInScopeforAzGovViz = $False
                            }
                        }
                        else{
                            $subscriptionIsInScopeforAzGovViz = $True
                        }
                    }

                    if ($True -eq $subscriptionIsInScopeforAzGovViz) {
                        #SubscriptionTags
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

                        #SubscriptionPolicyCompliance
                        ($htCachePolicyCompliance).sub.$childMgSubId = @{ }
                        $url = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
                        $result = Invoke-RestMethod -Uri $url -Method POST -Headers @{"Authorization" = "Bearer $accesstoken" }

                        foreach ($policyAssignment in $result.value.policyassignments | sort-object -Property policyAssignmentId){
                            ($htCachePolicyCompliance).sub.($childMgSubId).($policyAssignment.policyAssignmentId) = @{ }
                            foreach ($policyComplianceState in $policyAssignment.results.policydetails){
                                if ($policyComplianceState.ComplianceState -eq "compliant"){
                                    ($htCachePolicyCompliance).sub.($childMgSubId).($policyAssignment.policyAssignmentId).CompliantPolicies = $policyComplianceState.count
                                }
                                if ($policyComplianceState.ComplianceState -eq "noncompliant"){
                                    ($htCachePolicyCompliance).sub.($childMgSubId).($policyAssignment.policyAssignmentId).NonCompliantPolicies = $policyComplianceState.count
                                }
                            }
                
                            foreach ($resourceComplianceState in $policyAssignment.results.resourcedetails){
                                if ($resourceComplianceState.ComplianceState -eq "compliant"){
                                    ($htCachePolicyCompliance).sub.($childMgSubId).($policyAssignment.policyAssignmentId).CompliantResources = $resourceComplianceState.count
                                }
                                if ($resourceComplianceState.ComplianceState -eq "nonCompliant"){
                                    ($htCachePolicyCompliance).sub.($childMgSubId).($policyAssignment.policyAssignmentId).NonCompliantResources = $resourceComplianceState.count
                                }
                            }
                        }

                        #SubscriptionASCSecureScore
                        $uriSubASCSecureScore = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Security/securescores?api-version=2020-01-01-preview"
                        $result = "letscheck"
                        try {
                            $subASCSecureScoreResult = Invoke-RestMethod -Uri $uriSubASCSecureScore -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
                        } catch {
                            $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
                        }
                        if ($result -ne "letscheck"){
                            Write-Host "CustomDataCollection: Subscription Id: $childMgSubId Getting ASC Secure Score error: '$result' -> skipping ASC Secure Score for this subscription"
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

                        #SubscriptionBlueprint
                        $uriSubBlueprintDefinitionScoped = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)/subscriptions/$childMgSubId/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
                        $subBlueprintDefinitionResult = Invoke-RestMethod -Uri $uriSubBlueprintDefinitionScoped -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
                        if (($subBlueprintDefinitionResult.value | measure-object).count -gt 0) {
                            foreach ($blueprint in $subBlueprintDefinitionResult.value) {

                                if (-not $($htCacheDefinitions).blueprint[$blueprint.Id]) {
                                    $($htCacheDefinitions).blueprint.$($blueprint.Id) = @{ }
                                    $($htCacheDefinitions).blueprint.$($blueprint.Id) = $blueprint
                                }  

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

                        #SubscriptionBlueprintAssignment
                        $urisubscriptionBlueprintAssignments = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Blueprint/blueprintAssignments?api-version=2018-11-01-preview"
                        $subscriptionBlueprintAssignmentsResult = Invoke-RestMethod -Uri $urisubscriptionBlueprintAssignments -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
                        if (($subscriptionBlueprintAssignmentsResult.value | measure-object).count -gt 0) {
                            foreach ($subscriptionBlueprintAssignment in $subscriptionBlueprintAssignmentsResult.value) {

                                if (-not $($htCacheAssignments).blueprint[$subscriptionBlueprintAssignment.Id]) {
                                    $($htCacheAssignments).blueprint.$($subscriptionBlueprintAssignment.Id) = @{ }
                                    $($htCacheAssignments).blueprint.$($subscriptionBlueprintAssignment.Id) = $subscriptionBlueprintAssignment
                                }  

                                if (($subscriptionBlueprintAssignment.properties.blueprintId).StartsWith("/subscriptions/")) {
                                    $blueprintScope = $subscriptionBlueprintAssignment.properties.blueprintId -replace "/providers/Microsoft.Blueprint/blueprints/.*", ""
                                    $blueprintName = $subscriptionBlueprintAssignment.properties.blueprintId -replace ".*/blueprints/", "" -replace "/versions/.*", ""
                                }
                                if (($subscriptionBlueprintAssignment.properties.blueprintId).StartsWith("/providers/Microsoft.Management/managementGroups/")) {
                                    $blueprintScope = $subscriptionBlueprintAssignment.properties.blueprintId -replace "/providers/Microsoft.Blueprint/blueprints/.*", ""
                                    $blueprintName = $subscriptionBlueprintAssignment.properties.blueprintId -replace ".*/blueprints/", "" -replace "/versions/.*", ""
                                }
                                $uriSubscriptionBlueprintDefinition = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)$($blueprintScope)/providers/Microsoft.Blueprint/blueprints/$($blueprintName)?api-version=2018-11-01-preview"
                                $subscriptionBlueprintDefinitionResult = Invoke-RestMethod -Uri $uriSubscriptionBlueprintDefinition -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
                                $blueprintName = $subscriptionBlueprintDefinitionResult.name
                                $blueprintId = $subscriptionBlueprintDefinitionResult.id
                                $blueprintAssignmentVersion = $subscriptionBlueprintAssignment.properties.blueprintId -replace ".*/"
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
                                    -BlueprintAssignmentVersion $blueprintAssignmentVersion `
                                    -BlueprintAssignmentId $blueprintAssignmentId
                            }
                        }

                        #SubscriptionPolicies
                        $uriPolicyDefinitionAPI = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
                        $requestPolicyDefinitionAPI = Invoke-RestMethod -Uri $uriPolicyDefinitionAPI -Headers  @{"Authorization" = "Bearer $accesstoken" }
                        $subPolicyDefinitions = $requestPolicyDefinitionAPI.value | Where-Object { $_.properties.policyType -eq "custom" }
                        $PolicyDefinitionsScopedCount = (($subPolicyDefinitions | Where-Object { ($_.Id).startswith("/subscriptions/$childMgSubId/") }) | measure-object).count
                        foreach ($subPolicyDefinition in $subPolicyDefinitions) {
                            if (-not $($htCacheDefinitions).policy[$subPolicyDefinition.name]) {
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.name) = @{ }
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.name).Id = $($subPolicyDefinition.name)
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.name).DisplayName = $($subPolicyDefinition.Properties.displayname)
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.name).Type = $($subPolicyDefinition.Properties.policyType)
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.name).Category = $($subPolicyDefinition.Properties.metadata.category)
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.name).PolicyDefinitionId = $($subPolicyDefinition.id)
                                #effects
                                if ($subPolicyDefinition.properties.parameters.effect.defaultvalue) {
                                    ($htCacheDefinitions).policy.$($subPolicyDefinition.name).effectDefaultValue = $subPolicyDefinition.properties.parameters.effect.defaultvalue
                                    if ($subPolicyDefinition.properties.parameters.effect.allowedValues){
                                        ($htCacheDefinitions).policy.$($subPolicyDefinition.name).effectAllowedValue = $subPolicyDefinition.properties.parameters.effect.allowedValues -join ","
                                    }
                                    else{
                                        ($htCacheDefinitions).policy.$($subPolicyDefinition.name).effectAllowedValue = "n/a"
                                    }
                                    ($htCacheDefinitions).policy.$($subPolicyDefinition.name).effectFixedValue = "n/a"
                                }
                                else {
                                    if ($subPolicyDefinition.properties.parameters.policyEffect.defaultValue) {
                                        ($htCacheDefinitions).policy.$($subPolicyDefinition.name).effectDefaultValue = $subPolicyDefinition.properties.parameters.policyEffect.defaultvalue
                                        if ($subPolicyDefinition.properties.parameters.policyEffect.allowedValues){
                                            ($htCacheDefinitions).policy.$($subPolicyDefinition.name).effectAllowedValue = $subPolicyDefinition.properties.parameters.policyEffect.allowedValues -join ","
                                        }
                                        else{
                                            ($htCacheDefinitions).policy.$($subPolicyDefinition.name).effectAllowedValue = "n/a"
                                        }
                                        ($htCacheDefinitions).policy.$($subPolicyDefinition.name).effectFixedValue = "n/a"
                                    }
                                    else {
                                        ($htCacheDefinitions).policy.$($subPolicyDefinition.name).effectFixedValue = $subPolicyDefinition.Properties.policyRule.then.effect
                                        ($htCacheDefinitions).policy.$($subPolicyDefinition.name).effectDefaultValue = "n/a"
                                        ($htCacheDefinitions).policy.$($subPolicyDefinition.name).effectAllowedValue = "n/a"
                                    }
                                }
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.name).json = $subPolicyDefinition
                            }  
                            if (-not $($htCacheDefinitionsAsIs).policy[$subPolicyDefinition.name]) {
                                ($htCacheDefinitionsAsIs).policy.$($subPolicyDefinition.name) = @{ }
                                ($htCacheDefinitionsAsIs).policy.$($subPolicyDefinition.name) = $subPolicyDefinition
                            }  
                        }

                        #SubscriptionPolicySets
                        $uriPolicySetDefinitionAPI = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"
                        $requestPolicySetDefinitionAPI = Invoke-RestMethod -Uri $uriPolicySetDefinitionAPI -Headers  @{"Authorization" = "Bearer $accesstoken" }
                        $subPolicySetDefinitions = $requestPolicySetDefinitionAPI.value | Where-Object { $_.properties.policyType -eq "custom" }
                        $PolicySetDefinitionsScopedCount = (($subPolicySetDefinitions | Where-Object { ($_.Id).startswith("/subscriptions/$childMgSubId/") }) | measure-object).count
                        foreach ($subPolicySetDefinition in $subPolicySetDefinitions) {
                            if (-not $($htCacheDefinitions).policySet[$subPolicySetDefinition.name]) {
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.name) = @{ }
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.name).Id = $($subPolicySetDefinition.name)
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.name).DisplayName = $($subPolicySetDefinition.Properties.displayname)
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.name).Type = $($subPolicySetDefinition.Properties.policyType)
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.name).Category = $($subPolicySetDefinition.Properties.metadata.category)
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.name).PolicyDefinitionId = $($subPolicySetDefinition.id)
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.name).PolicySetPolicyIds = $subPolicySetDefinition.properties.policydefinitions.policyDefinitionId
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.name).json = $subPolicySetDefinition
                            }  
                        }

                        #SubscriptionPolicyAssignments
                        $L1mgmtGroupSubPolicyAssignments = Get-AzPolicyAssignment -Scope "$($childMg.Id)" -ErrorAction Stop
                        $L1mgmtGroupSubPolicyAssignmentsPolicyCount = (($L1mgmtGroupSubPolicyAssignments | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" }) | measure-object).count
                        $L1mgmtGroupSubPolicyAssignmentsPolicySetCount = (($L1mgmtGroupSubPolicyAssignments | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" }) | measure-object).count
                        $L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount = (($L1mgmtGroupSubPolicyAssignments | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -and $_.PolicyAssignmentId -match $childMg.Id }) | measure-object).count
                        $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount = (($L1mgmtGroupSubPolicyAssignments | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" -and $_.PolicyAssignmentId -match $childMg.Id }) | measure-object).count
                        $L1mgmtGroupSubPolicyAssignmentsPolicyAndPolicySetAtScopeCount = ($L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount + $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount)
                        foreach ($L1mgmtGroupSubPolicyAssignment in $L1mgmtGroupSubPolicyAssignments) {

                            if (-not $($htCacheAssignments).policy[$L1mgmtGroupSubPolicyAssignment.PolicyAssignmentId]) {
                                $($htCacheAssignments).policy.$($L1mgmtGroupSubPolicyAssignment.PolicyAssignmentId) = @{ }
                                $($htCacheAssignments).policy.$($L1mgmtGroupSubPolicyAssignment.PolicyAssignmentId) = $L1mgmtGroupSubPolicyAssignment
                            }  

                            if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -OR $L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
                                if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/") {
                                    $PolicyVariant = "Policy"
                                    $definitiontype = "policy"
                                    $Id = $L1mgmtGroupSubPolicyAssignment.properties.policydefinitionid -replace '.*/'

                                    $PolicyAssignmentScope = $L1mgmtGroupSubPolicyAssignment.Properties.Scope
                                    $PolicyAssignmentNotScope = $L1mgmtGroupSubPolicyAssignment.Properties.NotScopes -join "$CsvDelimiterOpposite "
                                    $PolicyAssignmentId = $L1mgmtGroupSubPolicyAssignment.PolicyAssignmentId
                                    $PolicyAssignmentName = $L1mgmtGroupSubPolicyAssignment.Name
                                    $PolicyAssignmentDisplayName = $L1mgmtGroupSubPolicyAssignment.Properties.DisplayName

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
                                        -PolicyAssignmentNotScope $PolicyAssignmentNotScope `
                                        -PolicyAssignmentId $PolicyAssignmentId `
                                        -PolicyAssignmentName $PolicyAssignmentName `
                                        -PolicyAssignmentDisplayName $PolicyAssignmentDisplayName `
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
                                    $PolicyAssignmentNotScope = $L1mgmtGroupSubPolicyAssignment.Properties.NotScopes -join "$CsvDelimiterOpposite "
                                    $PolicyAssignmentId = $L1mgmtGroupSubPolicyAssignment.PolicyAssignmentId
                                    $PolicyAssignmentName = $L1mgmtGroupSubPolicyAssignment.Name
                                    $PolicyAssignmentDisplayName = $L1mgmtGroupSubPolicyAssignment.Properties.DisplayName

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
                                        -PolicyAssignmentNotScope $PolicyAssignmentNotScope `
                                        -PolicyAssignmentId $PolicyAssignmentId `
                                        -PolicyAssignmentName $PolicyAssignmentName `
                                        -PolicyAssignmentDisplayName $PolicyAssignmentDisplayName `
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

                        #SubscriptionRoles
                        $subCustomRoleDefinitions = Get-AzRoleDefinition -custom -Scope "/subscriptions/$childMgSubId" -ErrorAction Stop
                        foreach ($subCustomRoleDefinition in $subCustomRoleDefinitions) {
                            if (-not $($htCacheDefinitions).role[$subCustomRoleDefinition.Id]) {
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

                        #SubscriptionRoleAssignments
                        $uriRoleAssignmentsUsageMetrics = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Authorization/roleAssignmentsUsageMetrics?api-version=2019-08-01-preview"
                        $roleAssignmentsUsage = Invoke-RestMethod -Uri $uriRoleAssignmentsUsageMetrics -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
                        $L1mgmtGroupSubRoleAssignments = Get-AzRoleAssignment -Scope "$($childMg.Id)" -ErrorAction Stop | where-object { $_.RoleAssignmentId -notmatch "$($childMg.Id)/resourcegroups/" } #exclude rg roleassignments
                        foreach ($L1mgmtGroupSubRoleAssignment in $L1mgmtGroupSubRoleAssignments) {

                            if (-not $($htCacheAssignments).role[$L1mgmtGroupSubRoleAssignment.RoleAssignmentId]) {
                                $($htCacheAssignments).role.$($L1mgmtGroupSubRoleAssignment.RoleAssignmentId) = @{ }
                                $($htCacheAssignments).role.$($L1mgmtGroupSubRoleAssignment.RoleAssignmentId) = $L1mgmtGroupSubRoleAssignment
                            }  

                            $Id = $L1mgmtGroupSubRoleAssignment.RoleDefinitionId
                            $definitiontype = "role"

                            if (($L1mgmtGroupSubRoleAssignment.RoleDefinitionName).length -eq 0) {
                                $RoleDefinitionName = "'This roleDefinition likely was deleted although a roleAssignment existed'" 
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
                }
                else{
                    Write-Host "CustomDataCollection: Subscription Error: '$result' -> skipping this subscription"
                    $htOutOfScopeSubscriptions.($childMgSubId) = @{ }
                    $htOutOfScopeSubscriptions.($childMgSubId).subscriptionId = $childMgSubId
                    $htOutOfScopeSubscriptions.($childMgSubId).subscriptionName = $childMg.DisplayName
                    $htOutOfScopeSubscriptions.($childMgSubId).outOfScopeReason = $result
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
            Write-Host "CustomDataCollection: Subscription processing duration: $((NEW-TIMESPAN -Start $startSubLoop -End $endSubLoop).TotalSeconds) seconds"
        }
        foreach ($childMg in $getMg.Children | Where-Object { $_.Type -eq "/providers/Microsoft.Management/managementGroups" }) {
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
                    <li $liId $liclass><a $class href="#table_$mgId" id="hierarchy_$mgId"><p><img class="imgMgTree" src="https://www.azadvertizer.net/azgovvizv3/icon/Icon-general-11-Management-Groups.svg"></p><div class="fitme" id="fitme">$($tenantDisplayNameAndDefaultDomain)$($mgNameAndOrId)</div></a>
"@
    $childMgs = ($mgAndSubBaseQuery | Where-Object { $_.mgParentId -eq "$mgId" }).MgId | Sort-Object -Unique
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
    Write-Host "Building HTML Hierarchy Tree for MG '$mgChild', $(($subscriptions | measure-object).count) Subscriptions"
    if (($subscriptions | measure-object).count -gt 0){
$script:html += @"
                    <li><a href="#table_$mgChild"><p id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv3/icon/Icon-general-2-Subscriptions.svg"> $(($subscriptions | measure-object).count)x</p></a></li>
"@
    }
}

function hierarchySubForMgUlHTML($mgChild){
    $subscriptions = ($mgAndSubBaseQuery | Where-Object { "" -ne $_.Subscription -and $_.MgId -eq $mgChild }).SubscriptionId | Get-Unique
    Write-Host "Building HTML Hierarchy Tree for MG '$mgChild', $(($subscriptions | measure-object).count) Subscriptions"
    if (($subscriptions | measure-object).count -gt 0){
$script:html += @"
                <ul>
                    <li><a href="#table_$mgChild" id="hierarchySub_$mgChild"><p><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv3/icon/Icon-general-2-Subscriptions.svg"> $($subscriptions.Count)x</p></a></li></ul>
"@
    }
}

function tableMgHTML($mgChild, $mgChildOf){
    $mgDetails = ($mgAndSubBaseQuery | Where-Object {$_.MgId -eq "$mgChild"}) | Get-Unique
    $mgName = $mgDetails.mgName
    $mgLevel = $mgDetails.Level
    $mgId =$mgDetails.MgId

    switch ($mgLevel) {
        "0" { $levelSpacing = "| &nbsp;" }
        "1" { $levelSpacing = "| -&nbsp;" }
        "2" { $levelSpacing = "| - -&nbsp;" }
        "3" { $levelSpacing = "| - - -&nbsp;" }
        "4" { $levelSpacing = "| - - - -&nbsp;" }
        "5" { $levelSpacing = "|- - - - -&nbsp;" }
        "6" { $levelSpacing = "|- - - - - -&nbsp;" }
    }

    createMgPath -mgid $mgChild
    [array]::Reverse($script:mgPathArray)
    $mgPath = $script:mgPathArray -join "/"
    $mgLinkedSubsCount = ((($mgAndSubBaseQuery | Where-Object { $_.MgId -eq "$mgChild" -and "" -ne $_.SubscriptionId }).SubscriptionId | Get-Unique) | measure-object).count
    if ($mgLinkedSubsCount -gt 0) {
        $subImg = "Icon-general-2-Subscriptions"
        $subInfo = "<img class=`"imgSub`" src=`"https://www.azadvertizer.net/azgovvizv3/icon/$subImg.svg`">$mgLinkedSubsCount"
    }
    else {
        $subImg = "Icon-general-2-Subscriptions_grey"
        $subInfo = "<img class=`"imgSub`" src=`"https://www.azadvertizer.net/azgovvizv3/icon/$subImg.svg`">"
    }

    if ($mgName -eq $mgId){
        $mgNameAndOrId = "<b>$mgName</b>"
    }
    else{
        $mgNameAndOrId = "<b>$mgName</b> ($mgId)"
    }

$script:html += @"
    <button type="button" class="collapsible" id="table_$mgId">
        $levelSpacing<img class="imgMg" src="https://www.azadvertizer.net/azgovvizv3/icon/Icon-general-11-Management-Groups.svg"> <span class="valignMiddle">$mgNameAndOrId $subInfo</span>
    </button>
    <div class="content">

    <table class="bottomrow">
        <tr>
            <td class="detailstd">
                <p><a href="#hierarchy_$mgId"><i class="fa fa-eye" aria-hidden="true"></i> <i>Highlight Management Group in hierarchy tree</i></a></p>
            </td>
        </tr>
        <tr>
            <td class="detailstd">
                <p>Management Group Name: <b>$mgName</b></p>
            </td>
        </tr>
        <tr>
            <td class="detailstd">
                <p>Management Group Id: <b>$mgId</b></p>
            </td>
        </tr>
        <tr>
            <td class="detailstd">
                <p>Management Group Path: $mgPath</p>
            </td>
        </tr>
        <tr><!--x-->
            <td class="detailstd"><!--x-->
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
    Write-Host "Building HTML Hierarchy Table MG '$mgChild', $(($subscriptions | measure-object).count) Subscriptions"
    if (($subscriptions | measure-object).count -gt 0){
$script:html += @"
    <tr>
        <td class="detailstd">
            <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $(($subscriptions | measure-object).count) Subscriptions linked</p>
            </button>
            <div class="content"><!--collapsible-->
"@
        foreach ($subscriptionId in $subscriptions){
            $subscription = ($mgAndSubBaseQuery | Where-Object { $subscriptionId -eq $_.SubscriptionId -and $_.MgId -eq $mgChild }).Subscription | Get-Unique
            createMgPathSub -subid $subscriptionId
            [array]::Reverse($script:submgPathArray)
            $subPath = $script:submgPathArray -join "/"
            if (($subscriptions | measure-object).count -gt 1){
$script:html += @"
                <button type="button" class="collapsible"> <img class="imgSub" src="https://www.azadvertizer.net/azgovvizv3/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle"><b>$subscription</b> ($subscriptionId)</span>
                </button>
                <div class="contentSub"><!--collapsiblePerSub-->
"@
            }
            #exactly 1
            else{
$script:html += @"
                <img class="imgSub" src="https://www.azadvertizer.net/azgovvizv3/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle"><b>$subscription</b> ($subscriptionId)</span></button>
"@
            }

$script:html += @"
                <table class="subTable">
                    <tr>
                        <td class="detailstd">
                            <p>
                                <a href="#hierarchySub_$mgChild"><i class="fa fa-eye" aria-hidden="true"></i> <i>Highlight Subscription in hierarchy tree</i></a>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td class="detailstd">
                            <p>
                                Subscription Name: <b>$subscription</b>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td class="detailstd">
                            <p>
                                Subscription Id: <b>$subscriptionId</b>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td class="detailstd">
                            <p>
                                Subscription Path: $subPath
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td class="detailstd">
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
        <td class="detailstd">
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
    #testtiming
    #$startdatafortable = get-date

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
        #Resources
        $resourcesSubscription = $resourcesAll | where-object { $_.subscriptionId -eq $subscriptionId } | Sort-Object -Property type, location
        $resourcesSubscriptionTotal = 0
        $resourcesSubscription.count_ | ForEach-Object { $resourcesSubscriptionTotal += $_ }
        $resourcesSubscriptionResourceTypeCount = (($resourcesSubscription | sort-object -Property type -Unique) | measure-object).count

        $cssClass = "subDetailsTable"


    }
    #testtiming
    #$enddatafortable = get-date
    #Write-Host "datafortable duration ($mgOrSub $subscriptionId): $((NEW-TIMESPAN -Start $startdatafortable -End $enddatafortable).TotalSeconds) seconds"

    #testtiming
    #$startprocesstable = get-date

if ($mgOrSub -eq "sub"){
$script:html += @"
            <p>State: $subscriptionState</p>
        </td>
    </tr>
    <tr>
        <td class="detailstd">
            <p>QuotaId: $subscriptionQuotaId</p>
        </td>
    </tr>
    <tr>
        <td class="detailstd">
            <p><i class="fa fa-shield" aria-hidden="true"></i> ASC Secure Score: $subscriptionASCPoints</p>
        </td>
    </tr>
    <tr>
        <td class="detailstd">
"@

#ResourceProvider
#region ResourceProvidersDetailed
if (($htResourceProvidersAll.Keys | Measure-Object).count -gt 0){
    $tfCount = ($arrayResourceProvidersAll | Measure-Object).Count
    $tableId = "DetailsTable_ResourceProvider_$($subscriptionId -replace '-','_')"
$script:html += @"
    <button type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Providers Detailed</span></button>
    <div class="content">

        <table id="$tableId" class="$cssClass">
            <thead>
                <tr>
                    <th>
                        Provider
                    </th>
                    <th>
                        State
                    </th>
                </tr>
            </thead>
            <tbody>
"@
    foreach ($provider in ($htResourceProvidersAll).($subscriptionId).Providers){
$script:html += @"
                <tr>
                    <td>
                        $($provider.namespace)
                    </td>
                    <td>
                        $($provider.registrationState)
                    </td>
                </tr>
"@ 
    }
    
$script:html += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
            
"@      
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            }, 
"@      
}
$script:html += @"
            btn_reset: true, 
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_1: 'select',
            col_types: [
                'string',
                'select'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($htResourceProvidersAll.Keys | Measure-Object).count) Resource Providers</span></p>
"@
}
#endregion ResourceProvidersDetailed

$script:html += @"
        </td>
    </tr>
    <tr>
        <td class="detailstd">
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
        <td class="detailstd">
"@
}

#Tags
if ($mgOrSub -eq "sub"){
    if ($tagsSubscriptionCount -gt 0){
        $tfCount = $tagsSubscriptionCount
        $tableId = "DetailsTable_Tags_$($subscriptionId -replace '-','_')"
$script:html += @"
    <button type="button" class="collapsible">
        <p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $tagsSubscriptionCount Subscription Tags | Limit: ($tagsSubscriptionCount/$LimitTagsSubscription)</p></button>
    <div class="content">
        <table id="$tableId" class="$cssClass">
            <thead>
                <tr>
                    <th class="widthCustom">
                        Tag Name
                    </th>
                    <th>
                        Tag Value
                    </th>
                </tr>
            </thead>
            <tbody>
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
            </tbody>
        </table>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
                btn_reset: true, 
                highlight_keywords: true,
                alternate_rows: true,
                auto_filter: {
                    delay: 1100 //milliseconds
                },
                no_results_message: true,
                col_types: [
                    'string',
                    'string'
                ],
                extensions: [{
                    name: 'sort'
                }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
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
        <tr><!--y--><td class="detailstd"><!--y-->
"@
}

#resources
if ($mgOrSub -eq "sub"){

    $resourcesSubscriptionLocationCount = (($resourcesSubscription | sort-object -Property location -Unique) | measure-object).count
    if ($resourcesSubscriptionResourceTypeCount -gt 0){
        $tfCount = $resourcesSubscriptionResourceTypeCount
        
        $tableId = "DetailsTable_Resources_$($subscriptionId -replace '-','_')"
$script:html += @"
    <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $resourcesSubscriptionResourceTypeCount ResourceTypes ($resourcesSubscriptionTotal Resources) in $resourcesSubscriptionLocationCount Locations</p></button>
    <div class="content">
        <table id="$tableId" class="$cssClass">
            <thead>
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
            </thead>
            <tbody>
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
            </tbody>
        </table>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
                btn_reset: true,
                highlight_keywords: true,
                alternate_rows: true,
                auto_filter: {
                    delay: 1100 //milliseconds
                },
                no_results_message: true,
                col_types: [
                    'string',
                    'string',
                    'number'
                ],
                extensions: [{
                    name: 'sort'
                }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
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
            <tr><td class="detailstd">
"@
}

#resourcesDiagnosticsCapable
if ($mgOrSub -eq "sub"){
    $resourceTypesUnique = ($resourcesSubscription | select-object type -Unique).type
    $resourceTypesSummarizedArray = @()
    foreach ($resourceTypeUnique in $resourceTypesUnique){
        $resourcesTypeCountTotal = 0
        ($resourcesSubscription | Where-Object { $_.type -eq $resourceTypeUnique }).count_ | ForEach-Object { $resourcesTypeCountTotal += $_ }
        $resourceTypesSummarizedObject = New-Object -TypeName PSObject -Property @{'ResourceType' = $resourceTypeUnique; 'ResourceCount' = $resourcesTypeCountTotal }
        $resourceTypesSummarizedArray += $resourceTypesSummarizedObject
    }

    $subscriptionResourcesDiagnosticsCapableArray = @()
    $subscriptionResourcesDiagnosticsCapableArray += foreach ($resourceSubscriptionResourceType in $resourceTypesSummarizedArray){
        $dataFromResourceTypesDiagnosticsArray = $resourceTypesDiagnosticsArray | Where-Object { $_.ResourceType -eq $resourceSubscriptionResourceType.ResourceType}
        if ($dataFromResourceTypesDiagnosticsArray.Metrics -eq $true -or $dataFromResourceTypesDiagnosticsArray.Logs -eq $true){
            $resourceDiagnosticscapable = $true
        }
        else{
            $resourceDiagnosticscapable = $false
        }
        New-Object -TypeName PSObject -Property @{'ResourceType' = $resourceSubscriptionResourceType.ResourceType; 'ResourceCount'= $resourceSubscriptionResourceType.ResourceCount; 'DiagnosticsCapable'= $resourceDiagnosticscapable; 'Metrics'= $dataFromResourceTypesDiagnosticsArray.Metrics; 'Logs' = $dataFromResourceTypesDiagnosticsArray.Logs; 'LogCategories' = ($dataFromResourceTypesDiagnosticsArray.LogCategories -join "$CsvDelimiterOpposite ") }
    }
    $subscriptionResourceTypesDiagnosticsCapableMetricsCount = ($subscriptionResourcesDiagnosticsCapableArray | Where-Object { $_.Metrics -eq $true } | Measure-Object).count
    $subscriptionResourceTypesDiagnosticsCapableLogsCount = ($subscriptionResourcesDiagnosticsCapableArray | Where-Object { $_.Logs -eq $true } | Measure-Object).count
    $subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount = ($subscriptionResourcesDiagnosticsCapableArray | Where-Object { $_.Metrics -eq $true -or $_.Logs -eq $true } | Measure-Object).count

    if ($resourcesSubscriptionResourceTypeCount -gt 0){
        $tfCount = $resourcesSubscriptionResourceTypeCount
        
        $tableId = "DetailsTable_resourcesDiagnosticsCapable_$($subscriptionId -replace '-','_')"
$script:html += @"
    <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount/$resourcesSubscriptionResourceTypeCount ResourceTypes Diagnostics capable ($subscriptionResourceTypesDiagnosticsCapableMetricsCount Metrics, $subscriptionResourceTypesDiagnosticsCapableLogsCount Logs)</p></button>
    <div class="content">
        <table id="$tableId" class="$cssClass">
            <thead>
                <tr>
                    <th class="widthCustom">
                        ResourceType
                    </th>
                    <th>
                        Resource Count
                    </th>
                    <th>
                        Diagnostics capable
                    </th>
                    <th>
                        Metrics
                    </th>
                    <th>
                        Logs
                    </th>
                    <th>
                        LogCategories
                    </th>
                </tr>
            </thead>
            <tbody>
"@
        foreach ($resourceSubscriptionResourceType in $subscriptionResourcesDiagnosticsCapableArray){
            
$script:html += @"
                <tr>
                    <td>
                        $($resourceSubscriptionResourceType.ResourceType)
                    </td>
                    <td>
                        $($resourceSubscriptionResourceType.ResourceCount)
                    </td>
                    <td>
                        $($resourceSubscriptionResourceType.DiagnosticsCapable)
                    </td>
                    <td>
                        $($resourceSubscriptionResourceType.Metrics)
                    </td>
                    <td>
                        $($resourceSubscriptionResourceType.Logs)
                    </td>
                    <td>
                        $($resourceSubscriptionResourceType.LogCategories)
                    </td>
                </tr>
"@        
        }
$script:html += @"
            </tbody>
        </table>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
                btn_reset: true,
                highlight_keywords: true,
                alternate_rows: true,
                auto_filter: {
                    delay: 1100 //milliseconds
                },
                no_results_message: true,
                col_2: 'select',
                col_types: [
                    'string',
                    'number',
                    'select',
                    'string',
                    'string',
                    'string'
                ],
                extensions: [{
                    name: 'sort'
                }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
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
            <tr><td class="detailstd">
"@
}

#testtiming
#$startPolicyAssignments = get-date

#policyAssignments
if ($policiesCount -gt 0){
    $tfCount = $policiesCount
    
    if ($mgOrSub -eq "mg"){
        $tableIdentifier = $mgChild
    }
    if ($mgOrSub -eq "sub"){
        $tableIdentifier = $subscriptionId
    }
    $tableId = "DetailsTable_PolicyAssignments_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
$script:html += @"
    <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $policiesCount Policy Assignments ($policiesAssignedAtScope at scope, $policiesInherited inherited) (Builtin: $policiesCountBuiltin | Custom: $policiesCountCustom)</p></button>
    <div class="content">
        <table id="$tableId" class="$cssClass">
            <thead>
                <tr>
                    <th>
                        Inheritance
                    </th>
                    <th>
                        Scope Excluded
                    </th>
                    <th>
                        Policy
                    </th>
                    <th>
                        Type
                    </th>
                    <th>
                        Category
                    </th>
                    <th>
                        Effect
                    </th>
                    <th>
                        Policies NonCmplnt
                    </th>
                    <th>
                        Policies Compliant
                    </th>
                    <th>
                        Resources NonCmplnt
                    </th>
                    <th>
                        Resources Compliant
                    </th>
                    <th>
                        Role/Assignment
                    </th>
                    <th>
                        Assignment DisplayName
                    </th>
                    <th>
                        Assignment Id
                    </th>
                </tr>
            </thead>
            <tbody>
"@
            foreach ($policyAssignment in $policiesAssigned){
                
                $excludedScope = "false"
                $policyAssignmentNotScopes = ($htCacheAssignments).policy.($policyAssignment.PolicyAssignmentId).Properties.NotScopes

                if (($policyAssignmentNotScopes | Measure-Object).count -gt 0){
                    foreach ($policyAssignmentNotScope in $policyAssignmentNotScopes){
        
                        if ("" -ne $policyAssignment.subscriptionId){
                            createMgPathSub -subid $policyAssignment.subscriptionId
                            [array]::Reverse($script:submgPathArray)
                            $subPath = $script:submgPathArray -join "/"
                            
                            if ($submgPathArray -contains "'$($policyAssignmentNotScope -replace "/subscriptions/" -replace "/providers/Microsoft.Management/managementGroups/")'"){
                                $excludedScope = "true"
                            }
                        }
                        else{
                            createMgPath -mgid $policyAssignment.MgId
                            [array]::Reverse($script:mgPathArray)
                            $mgPath = $script:mgPathArray -join "/"
                            
                            if ($mgPathArray -contains "'$($policyAssignmentNotScope -replace "/providers/Microsoft.Management/managementGroups/")'"){
                                $excludedScope = "true"
                            }
                        }
                    }
                }

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

                $relatedRoleAssignmentsArray = @()
                $relatedRoleAssignmentsArray += foreach ($roleassignment in ($htCacheAssignments).role.keys){
                    $tRoleAssignment = ($htCacheAssignments).role.($roleassignment)
                    if ($tRoleAssignment.DisplayName -replace '.*/' -eq ($policyAssignment.PolicyAssignmentId -replace '.*/')){
                        Write-Output "<u>$($tRoleAssignment.RoleDefinitionName)</u> ($($tRoleAssignment.RoleAssignmentId))"
                    }
                }
                if (($relatedRoleAssignmentsArray | Measure-Object).count -gt 0){
                    $relatedRoleAssignments = $relatedRoleAssignmentsArray -join "$CsvDelimiterOpposite "
                }
                else{
                    $relatedRoleAssignments = "n/a"
                }

                if (($htCacheAssignments).policy.($policyAssignment.PolicyAssignmentId).properties.parameters.effect.value){
                    $effect = ($htCacheAssignments).policy.($policyAssignment.PolicyAssignmentId).properties.parameters.effect.value
                }
                else{
                    $tPolicyDefinition = ($htCacheDefinitions).policy.(($htCacheAssignments).policy.($policyAssignment.PolicyAssignmentId).properties.PolicyDefinitionId -replace '.*/')
                    if ($tPolicyDefinition.effectDefaultValue -ne "n/a"){
                        $effect = $tPolicyDefinition.effectDefaultValue
                    }
                    if ($tPolicyDefinition.effectFixedValue -ne "n/a"){
                        $effect = $tPolicyDefinition.effectFixedValue
                    }
                }
$script:html += @"
                <tr>
                    <td>
                        $policyAssignedAtScopeOrInherted
                    </td>
                    <td>
                        $excludedScope
                    </td>
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
                        $effect
                    </td>
                    <td>
"@
if ($($policyAssignment.PolicyAssignmentId).StartsWith("/providers/Microsoft.Management/managementGroups/")){
$script:html += @"
                        $(($htCachePolicyCompliance).mg.($policyAssignment.MgId).($policyAssignment.policyAssignmentId).NonCompliantPolicies)
"@
}
if ($($policyAssignment.PolicyAssignmentId).StartsWith("/subscriptions/")){
$script:html += @"
                        $(($htCachePolicyCompliance).sub.($policyAssignment.SubscriptionId).($policyAssignment.policyAssignmentId).NonCompliantPolicies)
"@
}
$script:html += @"
                    </td>
                    <td>
"@
if ($($policyAssignment.PolicyAssignmentId).StartsWith("/providers/Microsoft.Management/managementGroups/")){
$script:html += @"
                        $(($htCachePolicyCompliance).mg.($policyAssignment.MgId).($policyAssignment.policyAssignmentId).CompliantPolicies)
"@
}
if ($($policyAssignment.PolicyAssignmentId).StartsWith("/subscriptions/")){
$script:html += @"
                        $(($htCachePolicyCompliance).sub.($policyAssignment.SubscriptionId).($policyAssignment.policyAssignmentId).CompliantPolicies)
"@
}
$script:html += @"
                    </td>
                    <td>
"@
#noncomp
if ($($policyAssignment.PolicyAssignmentId).StartsWith("/providers/Microsoft.Management/managementGroups/")){
$script:html += @"
    $(($htCachePolicyCompliance).mg.($policyAssignment.MgId).($policyAssignment.policyAssignmentId).NonCompliantResources)
"@
}
if ($($policyAssignment.PolicyAssignmentId).StartsWith("/subscriptions/")){
$script:html += @"
    $(($htCachePolicyCompliance).sub.($policyAssignment.SubscriptionId).($policyAssignment.policyAssignmentId).NonCompliantResources)
"@
}    
$script:html += @"
                    </td>
                    <td>
"@
#compl
if ($($policyAssignment.PolicyAssignmentId).StartsWith("/providers/Microsoft.Management/managementGroups/")){
$script:html += @"
    $(($htCachePolicyCompliance).mg.($policyAssignment.MgId).($policyAssignment.policyAssignmentId).CompliantResources)
"@
}
if ($($policyAssignment.PolicyAssignmentId).StartsWith("/subscriptions/")){
$script:html += @"
    $(($htCachePolicyCompliance).sub.($policyAssignment.SubscriptionId).($policyAssignment.policyAssignmentId).CompliantResources)
"@
}    
$script:html += @"
                    </td>
                    <td class="breakwordall">
                        $relatedRoleAssignments
                    </td>
                    <td>
                        $($policyAssignment.PolicyAssignmentDisplayName)
                    </td>
                    <td class="breakwordall">
                        $($policyAssignment.PolicyAssignmentId)
                    </td>
                </tr>
"@        
            }
$script:html += @"
            </tbody>
        </table>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
                btn_reset: true,
                highlight_keywords: true,
                alternate_rows: true,
                auto_filter: {
                    delay: 1100 //milliseconds
                },
                no_results_message: true,
                col_0: 'select',
                col_1: 'select',
                col_3: 'select',
                col_5: 'select',
                col_types: [
                    'select',
                    'select',
                    'string',
                    'select',
                    'string',
                    'select',
                    'number',
                    'number',
                    'number',
                    'number',
                    'string',
                    'string',
                    'string'
                ],
                extensions: [{
                    name: 'sort'
                }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
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
        <tr><!--y--><td class="detailstd"><!--y-->
"@

#PolicySetAssignments
if ($policySetsCount -gt 0){
    $tfCount = $policySetsCount
    
    if ($mgOrSub -eq "mg"){
        $tableIdentifier = $mgChild
    }
    if ($mgOrSub -eq "sub"){
        $tableIdentifier = $subscriptionId
    }
    $tableId = "DetailsTable_PolicySetAssignments_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
$script:html += @"
    <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $policySetsCount PolicySet Assignments ($policySetsAssignedAtScope at scope, $policySetsInherited inherited) (Builtin: $policySetsCountBuiltin | Custom: $policySetsCountCustom)</p></button>
    <div class="content">
        <table id="$tableId" class="$cssClass">
            <thead>
                <tr>
                    <th>
                        Inheritance
                    </th>
                    <th>
                        Scope Excluded
                    </th>
                    <th>
                        PolicySet
                    </th>
                    <th>
                        Type
                    </th>
                    <th>
                        Category
                    </th>
                    <th>
                        Policies NonCmplnt
                    </th>
                    <th>
                        Policies Compliant
                    </th>
                    <th>
                        Resources NonCmplnt
                    </th>
                    <th>
                        Resources Compliant
                    </th>
                    <th>
                        Role/Assignment
                    </th>
                    <th>
                        Assignment DisplayName
                    </th>
                    <th>
                        Assignment Id
                    </th>
                </tr>
            </thead>
            <tbody>
"@
    foreach ($policySetAssignment in $policySetsAssigned){

        $excludedScope = "false"
        $policyAssignmentNotScopes = ($htCacheAssignments).policy.($policySetAssignment.PolicyAssignmentId).Properties.NotScopes

        if (($policyAssignmentNotScopes | Measure-Object).count -gt 0){
            foreach ($policyAssignmentNotScope in $policyAssignmentNotScopes){

                if ("" -ne $policySetAssignment.subscriptionId){
                    createMgPathSub -subid $policySetAssignment.subscriptionId
                    [array]::Reverse($script:submgPathArray)
                    $subPath = $script:submgPathArray -join "/"
                    
                    if ($submgPathArray -contains "'$($policyAssignmentNotScope -replace "/subscriptions/" -replace "/providers/Microsoft.Management/managementGroups/")'"){
                        $excludedScope = "true"
                    }
                }
                else{
                    createMgPath -mgid $policySetAssignment.MgId
                    [array]::Reverse($script:mgPathArray)
                    $mgPath = $script:mgPathArray -join "/"
                    
                    if ($mgPathArray -contains "'$($policyAssignmentNotScope -replace "/providers/Microsoft.Management/managementGroups/")'"){
                        $excludedScope = "true"
                    }
                }
            }
        }

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

        $relatedRoleAssignmentsArray = @()
        $relatedRoleAssignmentsArray += foreach ($roleassignment in ($htCacheAssignments).role.keys){
            $tRoleAssignment = ($htCacheAssignments).role.($roleassignment)
            if ($tRoleAssignment.DisplayName -replace '.*/' -eq ($policySetAssignment.PolicyAssignmentId -replace '.*/')){
                Write-Output "<u>$($tRoleAssignment.RoleDefinitionName)</u> ($($tRoleAssignment.RoleAssignmentId))"
            }
        }
        if (($relatedRoleAssignmentsArray | Measure-Object).count -gt 0){
            $relatedRoleAssignments = $relatedRoleAssignmentsArray -join "$CsvDelimiterOpposite "
        }
        else{
            $relatedRoleAssignments = "n/a"
        }
$script:html += @"
                <tr>
                    <td>
                        $policyAssignedAtScopeOrInherted
                    </td>
                    <td>
                        $excludedScope
                    </td>
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
"@
if ($($policySetAssignment.PolicyAssignmentId).StartsWith("/providers/Microsoft.Management/managementGroups/")){
$script:html += @"
                        $(($htCachePolicyCompliance).mg.($policySetAssignment.MgId).($policySetAssignment.policyAssignmentId).NonCompliantPolicies)
"@
}
if ($($policySetAssignment.PolicyAssignmentId).StartsWith("/subscriptions/")){
$script:html += @"
                        $(($htCachePolicyCompliance).sub.($policySetAssignment.SubscriptionId).($policySetAssignment.policyAssignmentId).NonCompliantPolicies)
"@
}
$script:html += @"
                    </td>
                    <td>
"@
if ($($policySetAssignment.PolicyAssignmentId).StartsWith("/providers/Microsoft.Management/managementGroups/")){
$script:html += @"
                        $(($htCachePolicyCompliance).mg.($policySetAssignment.MgId).($policySetAssignment.policyAssignmentId).CompliantPolicies)
"@
}
if ($($policySetAssignment.PolicyAssignmentId).StartsWith("/subscriptions/")){
$script:html += @"
                        $(($htCachePolicyCompliance).sub.($policySetAssignment.SubscriptionId).($policySetAssignment.policyAssignmentId).CompliantPolicies)
"@
}
$script:html += @"
                    </td>
                    <td>
"@
#noncomp
if ($($policySetAssignment.PolicyAssignmentId).StartsWith("/providers/Microsoft.Management/managementGroups/")){
$script:html += @"
    $(($htCachePolicyCompliance).mg.($policySetAssignment.MgId).($policySetAssignment.policyAssignmentId).NonCompliantResources)
"@
}
if ($($policySetAssignment.PolicyAssignmentId).StartsWith("/subscriptions/")){
$script:html += @"
    $(($htCachePolicyCompliance).sub.($policySetAssignment.SubscriptionId).($policySetAssignment.policyAssignmentId).NonCompliantResources)
"@
}    
$script:html += @"
                    </td>
                    <td>
"@
#compl
if ($($policySetAssignment.PolicyAssignmentId).StartsWith("/providers/Microsoft.Management/managementGroups/")){
$script:html += @"
    $(($htCachePolicyCompliance).mg.($policySetAssignment.MgId).($policySetAssignment.policyAssignmentId).CompliantResources)
"@
}
if ($($policySetAssignment.PolicyAssignmentId).StartsWith("/subscriptions/")){
$script:html += @"
    $(($htCachePolicyCompliance).sub.($policySetAssignment.SubscriptionId).($policySetAssignment.policyAssignmentId).CompliantResources)
"@
}    
$script:html += @"
                    </td>

                    <td class="breakwordall">
                        $relatedRoleAssignments
                    </td>
                    <td>
                        $($policySetAssignment.PolicyAssignmentDisplayName)
                    </td>
                    <td class="breakwordall">
                        $($policySetAssignment.PolicyAssignmentId)
                    </td>
                </tr>
"@        
    }
$script:html += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_0: 'select',
            col_1: 'select',
            col_types: [
                'select',
                'select',
                'string',
                'string',
                'string',
                'number',
                'number',
                'number',
                'number',
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> $policySetsCount PolicySet Assignments ($policySetsAssignedAtScope at scope, $policySetsInherited inherited) (Builtin: $policySetsCountBuiltin | Custom: $policySetsCountCustom)</p>
"@
}
$script:html += @"
        </td></tr>
        <tr><td class="detailstd"><!--z-->
"@

#testtiming
#$endPolicyAssignments = get-date
#Write-Host "policyAssignments duration ($mgOrSub $subscriptionId): $((NEW-TIMESPAN -Start $startPolicyAssignments -End $endPolicyAssignments).TotalSeconds) seconds"

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
        <td class="detailstd">
"@

#Scoped Policies
if ($scopePoliciesCount -gt 0){
    $tfCount = $scopePoliciesCount
    
    if ($mgOrSub -eq "mg"){
        $tableIdentifier = $mgChild
    }
    if ($mgOrSub -eq "sub"){
        $tableIdentifier = $subscriptionId
    }
    $tableId = "DetailsTable_ScopedPolicies_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
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
            <table id="$tableId" class="$cssClass">
                <thead>
                    <tr>
                        <th class="widthCustom">
                            Policy DisplayName
                        </th>
                        <th>
                            PolicyDefinitionId
                        </th>
                        <th>
                            Policy effect
                        </th>
                        <th>
                            RoleDefinitions
                        </th>
                        <th>
                            Unique Assignments
                        </th>
                        <th>
                            Used in PolicySets
                        </th>
                    </tr>
                </thead>
                <tbody>
"@
    foreach ($scopePolicyArray in $scopePoliciesArray){
        
        $scopePoliciesUniqueAssignments = (($policyPolicyBaseQuery | Where-Object { $_.PolicyDefinitionIdGuid -eq $scopePolicyArray }).PolicyAssignmentId | sort-object -Unique)
        $scopePoliciesUniqueAssignmentArray = @()
        foreach ($scopePoliciesUniqueAssignment in $scopePoliciesUniqueAssignments){
            $scopePoliciesUniqueAssignmentArray += $scopePoliciesUniqueAssignment
        }
        $scopePoliciesUniqueAssignmentsCount = ($scopePoliciesUniqueAssignments | measure-object).count
        
        $currentPolicy = $scopePolicyArray
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

        if (($htCacheDefinitions).policy.($scopePolicyArray).effectDefaultValue -ne "n/a"){
            $effect = "Default: $(($htCacheDefinitions).policy.($scopePolicyArray).effectDefaultValue); Allowed: $(($htCacheDefinitions).policy.($scopePolicyArray).effectAllowedValue)"
        }
        else{
            $effect = "Fixed: $(($htCacheDefinitions).policy.($scopePolicyArray).effectFixedValue)"
        }

        $policyRoleDefinitionsArray = @()
        if (($htCacheDefinitionsAsIs).policy.($scopePolicyArray).properties.policyrule.then.details.roledefinitionIds){
            $policyRoleDefinitionsArray += foreach ($policyRoledefinitionId in ($htCacheDefinitionsAsIs).policy.($scopePolicyArray).properties.policyrule.then.details.roledefinitionIds){
                ($htCacheDefinitions).role.($policyRoledefinitionId -replace '.*/').Name
            }
        }
        if (($policyRoleDefinitionsArray | Measure-Object).count -gt 0){
            $policyRoleDefinitions =  $policyRoleDefinitionsArray -join "$CsvDelimiterOpposite "
        }
        else{
            $policyRoleDefinitions = "n/a"
        }
        
$script:html += @"
                    <tr>
                        <td>
                            $(($htCacheDefinitions).policy[$scopePolicyArray].DisplayName)
                        </td>
                        <td>
                            $(($htCacheDefinitions).policy[$scopePolicyArray].PolicyDefinitionId)
                        </td>
                        <td>
                            $effect
                        </td>
                        <td>
                            $policyRoleDefinitions
                        </td>
                        <td class="breakwordall">
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
                        <td class="breakwordall">
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
                </tbody>
            </table>
        </div>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
                btn_reset: true,
                highlight_keywords: true,
                alternate_rows: true,
                auto_filter: {
                    delay: 1100 //milliseconds
                },
                no_results_message: true,
                col_types: [
                    'string',
                    'string',
                    'string',
                    'string',
                    'string',
                    'string'
                ],
                extensions: [{
                    name: 'sort'
                }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
"@
}
else{
$script:html += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $scopePoliciesCount Custom Policies scoped</p>
"@
}
$script:html += @"
                </td></tr>
                <tr><td class="detailstd">
"@

#Scoped PolicySets
if ($scopePolicySetsCount -gt 0){
    $tfCount = $scopePolicySetsCount
    
    if ($mgOrSub -eq "mg"){
        $tableIdentifier = $mgChild
    }
    if ($mgOrSub -eq "sub"){
        $tableIdentifier = $subscriptionId
    }
    $tableId = "DetailsTable_ScopedPolicySets_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
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
            <table id="$tableId" class="$cssClass">
                <thead>
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
                </thead
                <tbody>
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
                </tbody>
            </table>
        </div>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
                btn_reset: true,
                highlight_keywords: true,
                alternate_rows: true,
                auto_filter: {
                    delay: 1100 //milliseconds
                },
                no_results_message: true,
                col_types: [
                    'string',
                    'string',
                    'string'
                ],
                extensions: [{
                    name: 'sort'
                }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
"@
}
else{
$script:html += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $scopePolicySetsCount Custom PolicySets scoped</p>
"@
}
$script:html += @"
                </td></tr>
                <tr><td class="detailstd">
"@

#Blueprint Assignment
if ($mgOrSub -eq "sub"){
    if ($blueprintsAssignedCount -gt 0){
        
        if ($mgOrSub -eq "mg"){
            $tableIdentifier = $mgChild
        }
        if ($mgOrSub -eq "sub"){
            $tableIdentifier = $subscriptionId
        }
        $tableId = "DetailsTable_BlueprintAssignment_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
$script:html += @"
        <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintsAssignedCount Blueprints assigned</p></button>
        <div class="content">
            <table id="$tableId" class="$cssClass">
                <thead>
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
                            Blueprint Version
                        </th>
                        <th>
                            Blueprint AssignmentId
                        </th>
                    </tr>
                </thead>
                <tbody
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
                            $($blueprintAssigned.BlueprintAssignmentVersion)
                        </td>
                        <td>
                            $($blueprintAssigned.BlueprintAssignmentId)
                        </td>
                    </tr>
"@        
        }
$script:html += @"
                </tbody>
            </table>
        </div>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
                btn_reset: true,
                highlight_keywords: true,
                alternate_rows: true,
                auto_filter: {
                    delay: 1100 //milliseconds
                },
                no_results_message: true,
                col_types: [
                    'string',
                    'string',
                    'string',
                    'string',
                    'string',
                    'string'
                ],
                extensions: [{
                    name: 'sort'
                }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
"@
    }
    else{
$script:html += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $blueprintsAssignedCount Blueprints assigned</p>
"@
    }
$script:html += @"
                </td></tr>
                <tr><td class="detailstd">
"@
}

#blueprints Scoped
if ($blueprintsScopedCount -gt 0){
    $tfCount = $blueprintsScopedCount
    
    if ($mgOrSub -eq "mg"){
        $tableIdentifier = $mgChild
    }
    if ($mgOrSub -eq "sub"){
        $tableIdentifier = $subscriptionId
    }
    $tableId = "DetailsTable_BlueprintScoped_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
$script:html += @"
        <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintsScopedCount Blueprints scoped</p></button>
        <div class="content">
            <table id="$tableId" class="$cssClass">
                <thead>
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
                </thead>
                <tbody>
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
                </tbody>
            </table>
        </div>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
                btn_reset: true,
                highlight_keywords: true,
                alternate_rows: true,
                auto_filter: {
                    delay: 1100 //milliseconds
                },
                no_results_message: true,
                col_types: [
                    'string',
                    'string',
                    'string',
                    'string'
                ],
                extensions: [{
                    name: 'sort'
                }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
"@
}
else{
$script:html += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $blueprintsScopedCount Blueprints scoped</p>
"@
}
$script:html += @"
                </td></tr>
                <tr><td class="detailstd">
"@

#RoleAssignments
if ($rolesAssignedCount -gt 0){
    $tfCount = $rolesAssignedCount
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
    
    if ($mgOrSub -eq "mg"){
        $tableIdentifier = $mgChild
    }
    if ($mgOrSub -eq "sub"){
        $tableIdentifier = $subscriptionId
    }
    $tableId = "DetailsTable_RoleAssignments_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
$script:html += @"
        <button type="button" class="collapsible"><p>$faIcon $rolesAssignedCount Role Assignments ($rolesAssignedInherited inherited) (User: $rolesAssignedCountUser | Group: $rolesAssignedCountGroup | ServicePrincipal: $rolesAssignedCountServicePrincipal | Orphaned: $rolesAssignedCountOrphaned) ($($roleSecurityFindingCustomRoleOwnerImg)CustomRoleOwner: $roleSecurityFindingCustomRoleOwner, $($RoleSecurityFindingOwnerAssignmentSPImg)OwnerAssignmentSP: $RoleSecurityFindingOwnerAssignmentSP) (Policy related: $roleAssignmentsRelatedToPolicyCount) | Limit: ($rolesAssignedScope/$LimitRoleAssignmentsScope)</p></button>
        <div class="content">
            <table id="$tableId" class="$cssClass">
                <thead>
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
                            Obj SignInName
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
                </thead>
                <tbody>
"@
    foreach ($roleAssigned in $rolesAssigned){
        if ($roleAssigned.RoleIsCustom -eq "FALSE"){
            $roleType = "Builtin"
            $roleWithWithoutLinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azrolesadvertizer/$($roleAssigned.RoleDefinitionId).html`" target=`"_blank`">$($roleAssigned.RoleDefinitionName)</a>"
        }
        else{
            if ($roleAssigned.RoleSecurityCustomRoleOwner -eq 1){
                $roletype = "<abbr title=`"Custom owner roles should not exist`"><i class=`"fa fa-exclamation-triangle yellow`" aria-hidden=`"true`"></i></abbr> <a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/10ee2ea2-fb4d-45b8-a7e9-a2e770044cd9.html`" target=`"_blank`">Custom</a>"
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
        
        if (($roleAssigned.RoleAssignmentSignInName).length -eq 1){
            $objSignInName = "n/a"
        }
        else{
            $objSignInName = $roleAssigned.RoleAssignmentSignInName
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
                            $objSignInName
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
                </tbody>
            </table>
        </div>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
                btn_reset: true,
                highlight_keywords: true,
                alternate_rows: true,
                auto_filter: {
                    delay: 1100 //milliseconds
                },
                no_results_message: true,
                col_1: 'select',
                col_2: 'select',
                col_5: 'select',
                col_types: [
                    'string',
                    'select',
                    'select',
                    'string',
                    'string',
                    'string',
                    'select',
                    'string',
                    'string'
                ],
                extensions: [{
                    name: 'sort'
                }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>

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
    #testtiming
    #$endprocesstable = get-date
    #Write-Host "processtable duration ($mgOrSub $subscriptionId ----------------): $((NEW-TIMESPAN -Start $startprocesstable -End $endprocesstable).TotalSeconds) seconds"
}

#region Summary
function summary() {
#$startSummary = get-date
Write-Host "Building HTML Summary"

if ($getMgParentName -eq "Tenant Root"){
    $scopeNamingSummary = "Tenant wide"
}
else{
    $scopeNamingSummary = "MG '$ManagementGroupIdCaseSensitived' and descendants wide"
}

#region SUMMARYcustompolicies
if ($getMgParentName -eq "Tenant Root"){
$customPoliciesArray = @()
foreach ($tenantCustomPolicy in $tenantCustomPolicies){
    $customPoliciesArray += ($htCacheDefinitions).policy.($tenantCustomPolicy)
}
if ($tenantCustomPoliciesCount -gt 0){
    $tfCount = $tenantCustomPoliciesCount

    
    $tableId = "SummaryTable_customPolicies"

$script:html += @"
    <button type="button" class="collapsible" id="summary_customPolicies"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policies ($scopeNamingSummary)</span></button>
    <div class="content">

        <table id="$tableId" class="summaryTable">
            <thead>
                <tr>
                    <th>
                        Policy DisplayName
                    </th>
                    <th>
                        Policy DefinitionId
                    </th>
                    <th>
                        Policy Effect
                    </th>
                    <th>
                        RoleDefinitions
                    </th>
                    <th>
                        Unique Assignments
                    </th>
                    <th>
                        Used in PolicySets
                    </th>
                </tr>
            </thead>
            <tbody>
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

        if (($htCacheDefinitions).policy.($customPolicy.Id).effectDefaultValue -ne "n/a"){
            $effect = "Default: $(($htCacheDefinitions).policy.($customPolicy.Id).effectDefaultValue); Allowed: $(($htCacheDefinitions).policy.($customPolicy.Id).effectAllowedValue)"
        }
        else{
            $effect = "Fixed: $(($htCacheDefinitions).policy.($customPolicy.Id).effectFixedValue)"
        }

        $policyRoleDefinitionsArray = @()
        if (($htCacheDefinitionsAsIs).policy.($customPolicy.Id).properties.policyrule.then.details.roledefinitionIds){
            $policyRoleDefinitionsArray += foreach ($policyRoledefinitionId in ($htCacheDefinitionsAsIs).policy.($customPolicy.Id).properties.policyrule.then.details.roledefinitionIds){
                ($htCacheDefinitions).role.($policyRoledefinitionId -replace '.*/').Name
            }
        }
        if (($policyRoleDefinitionsArray | Measure-Object).count -gt 0){
            $policyRoleDefinitions =  $policyRoleDefinitionsArray -join "$CsvDelimiterOpposite "
        }
        else{
            $policyRoleDefinitions = "n/a"
        }

$script:html += @"
                <tr>
                    <td>
                        $(($htCacheDefinitions).policy.($customPolicy.Id).DisplayName)
                    </td>
                    <td class="breakwordall">
                        $(($htCacheDefinitions).policy.($customPolicy.Id).PolicyDefinitionId)
                    </td>
                    <td>
                        $effect
                    </td>
                    <td>
                        $policyRoleDefinitions
                    </td>
                    <td class="breakwordall">
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
                    <td class="breakwordall">
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
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
            
"@      
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
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
        $tfCount = $tenantCustomPoliciesCount
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
                    Write-Host "$policyScopedMgSub NOT in Scope"
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
    $tfCount = $tenantCustomPoliciesCount
    
    $tableId = "SummaryTable_customPolicies"
$script:html += @"
    <button type="button" class="collapsible" id="summary_customPolicies"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policies ($customPoliciesFromSuperiorMGs from superior Management Groups) ($scopeNamingSummary)</span></button>
    <div class="content">

        <table id="$tableId" class="summaryTable">
            <thead>
                <tr>
                    <th>
                        Policy DisplayName
                    </th>
                    <th>
                        Policy DefinitionId
                    </th>
                    <th>
                        Policy Effect
                    </th>
                    <th>
                        RoleDefinitions
                    </th>
                    <th>
                        Unique Assignments
                    </th>
                    <th>
                        Used in PolicySets
                    </th>
                </tr>
            </thead>
            <tbody>
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

        if (($htCacheDefinitions).policy.($customPolicy.Id).effectDefaultValue -ne "n/a"){
            $effect = "Default: $(($htCacheDefinitions).policy.($customPolicy.Id).effectDefaultValue); Allowed: $(($htCacheDefinitions).policy.($customPolicy.Id).effectAllowedValue)"
        }
        else{
            $effect = "Fixed: $(($htCacheDefinitions).policy.($customPolicy.Id).effectFixedValue)"
        }

        $policyRoleDefinitionsArray = @()
        if (($htCacheDefinitionsAsIs).policy.($customPolicy.Id).properties.policyrule.then.details.roledefinitionIds){
            $policyRoleDefinitionsArray += foreach ($policyRoledefinitionId in ($htCacheDefinitionsAsIs).policy.($customPolicy.Id).properties.policyrule.then.details.roledefinitionIds){
                ($htCacheDefinitions).role.($policyRoledefinitionId -replace '.*/').Name
            }
        }
        if (($policyRoleDefinitionsArray | Measure-Object).count -gt 0){
            $policyRoleDefinitions =  $policyRoleDefinitionsArray -join "$CsvDelimiterOpposite "
        }
        else{
            $policyRoleDefinitions = "n/a"
        }

$script:html += @"
                <tr>
                    <td>
                        $(($htCacheDefinitions).policy.($customPolicy.Id).DisplayName)
                    </td>
                    <td class="breakwordall">
                        $(($htCacheDefinitions).policy.($customPolicy.Id).PolicyDefinitionId)
                    </td>
                    <td>
                        $effect
                    </td>
                    <td>
                        $policyRoleDefinitions
                    </td>
                    <td class="breakwordall">
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
                    <td class="breakwordall">
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
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policies ($scopeNamingSummary)</span></p>
"@
}
}
#endregion SUMMARYcustompolicies

#region SUMMARYCustomPoliciesOrphandedTenantRoot
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
        if (-not ($htCachePoliciesUsedInPolicySets).$($customPolicyOrphaned.Id)){
            $customPoliciesOrphanedFinal += ($htCacheDefinitions).policy.$($customPolicyOrphaned.id)
        }
    }

    if (($customPoliciesOrphanedFinal | measure-object).count -gt 0){
        $tfCount = ($customPoliciesOrphanedFinal | measure-object).count
        
        $tableId = "SummaryTable_customPoliciesOrphaned"
$script:html += @"
    <button type="button" class="collapsible" id="summary_customPoliciesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($customPoliciesOrphanedFinal | measure-object).count) Orphaned Custom Policies ($scopeNamingSummary)</span> <abbr title="Policy has no assignments AND Policy is not used in a PolicySet"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
    <div class="content">

        <table id="$tableId" class="summaryTable">
            <thead>
                <tr>
                    <th>
                        Policy DisplayName
                    </th>
                    <th>
                        Policy DefinitionId
                    </th>
                </tr>
            </thead>
            <tbody>
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
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
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
    foreach ($customPolicyOrphanedInScopeArray in $customPoliciesOrphanedInScopeArray){
        if (-not ($htCachePoliciesUsedInPolicySets).($customPolicyOrphanedInScopeArray.Id)){
            $customPoliciesOrphanedFinal += $customPolicyOrphanedInScopeArray
        }
    }
    if (($customPoliciesOrphanedFinal | measure-object).count -gt 0){
        $tfCount = ($customPoliciesOrphanedFinal | measure-object).count
        
        $tableId = "SummaryTable_customPoliciesOrphaned"
$script:html += @"
    <button type="button" class="collapsible" id="summary_customPoliciesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($customPoliciesOrphanedFinal | measure-object).count) Orphaned Custom Policies ($scopeNamingSummary)</span> <abbr title="Policy has no assignments AND Policy is not used in a PolicySet (Policies from superior scopes are not evaluated)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
    <div class="content">

        <table id="$tableId" class="summaryTable">
            <thead>
                <tr>
                    <th>
                        Policy DisplayName
                    </th>
                    <th>
                        Policy DefinitionId
                    </th>
                </tr>
            </thead>
            <tbody>
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
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,      
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
    }
    else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$($customPoliciesOrphanedFinal.count) Orphaned Custom Policies ($scopeNamingSummary)</span></p>
"@
    }
}
#endregion SUMMARYCustomPoliciesOrphandedTenantRoot

#region SUMMARYtenanttotalcustompolicySets
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
        $tfCount = $tenantCustompolicySetsCount
        
        $tableId = "SummaryTable_customPolicySets"
$script:html += @"
    <button type="button" class="collapsible" id="summary_customPolicySets">$faimage <span class="valignMiddle">$tenantCustompolicySetsCount Custom PolicySets ($scopeNamingSummary) (Limit: $tenantCustompolicySetsCount/$LimitPOLICYPolicySetDefinitionsScopedTenant)</span></button>
    <div class="content">

        <table id="$tableId" class="summaryTable">
            <thead>
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
            </thead>
            <tbody>
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
                    <td class="breakwordall">
                        $(($htCacheDefinitions).policySet.($customPolicySet.Id).PolicyDefinitionId)
                    </td>
                    <td class="breakwordall">
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
                    <td class="breakwordall">
"@
$script:html += @"
                        $policySetPoliciesCount ($(($policySetPoliciesArray | sort-Object) -join "$CsvDelimiterOpposite "))
                    </td>
                </tr>
"@ 
        }
$script:html += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
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
        $tfCount = $tenantCustompolicySetsCount
        
        $tableId = "SummaryTable_customPolicySets"
$script:html += @"
    <button type="button" class="collapsible" id="summary_customPolicySets">$faimage <span class="valignMiddle">$tenantCustomPolicySetsCount Custom PolicySets ($custompolicySetsFromSuperiorMGs from superior Management Groups) ($scopeNamingSummary) (Limit: $tenantCustompolicySetsCount/$LimitPOLICYPolicySetDefinitionsScopedTenant)</span></button>
    <div class="content">

        <table id="$tableId" class="summaryTable">
            <thead>
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
            </thead>
            <tbody>
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
                    <td class="breakwordall">
                        $(($htCacheDefinitions).policySet.($customPolicySet.Id).PolicyDefinitionId)
                    </td>
                    <td class="breakwordall">
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
                    <td class="breakwordall">
"@
$script:html += @"
                        $policySetPoliciesCount ($(($policySetPoliciesArray | sort-Object) -join "$CsvDelimiterOpposite "))
                    </td>
                </tr>
"@ 
        }
$script:html += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
    }
    else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPolicySetsCount Custom PolicySets ($scopeNamingSummary)</span></p>
"@
    }
}
#endregion SUMMARYtenanttotalcustompolicySets

#region SUMMARYCustompolicySetOrphandedTenantRoot
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
        $tfCount = ($custompolicySetSetsOrphaned | measure-object).count
        
        $tableId = "SummaryTable_customPolicySetsOrphaned"
$script:html += @"
    <button type="button" class="collapsible" id="summary_custompolicySetsOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($custompolicySetSetsOrphaned | measure-object).count) Orphaned Custom PolicySets ($scopeNamingSummary)</span></button>
    <div class="content">

        <table id="$tableId" class="summaryTable">
            <thead>
                <tr>
                    <th>
                        PolicySet DisplayName
                    </th>
                    <th>
                        PolicySet DefinitionId
                    </th>
                </tr>
            </thead>
            <tbody>
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
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
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
        $tfCount = ($customPoliciesOrphanedFinal | measure-object).count
        
        $tableId = "SummaryTable_customPolicySetsOrphaned"
$script:html += @"
    <button type="button" class="collapsible" id="summary_custompolicySetsOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($customPoliciesOrphanedFinal | measure-object).count) Orphaned Custom PolicySets ($scopeNamingSummary)</span></button>
    <div class="content">

        <table id="$tableId" class="summaryTable">
            <thead>
                <tr>
                    <th>
                        PolicySet DisplayName
                    </th>
                    <th>
                        PolicySet DefinitionId
                    </th>
                </tr>
            </thead>
            <tbody>
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
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
    }
    else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($customPoliciesOrphanedFinal | measure-object).count) Orphaned Custom PolicySets ($scopeNamingSummary)</span></p>
"@
    }
}
#endregion SUMMARYCustompolicySetOrphandedTenantRoot

#region SUMMARYPolicySetsDeprecatedPolicy
$policySetsDeprecated=@()
foreach ($polSetDef in $($htCacheDefinitions).policySet.keys | where-object { ($htCacheDefinitions).policySet.($_).type -eq "Custom" }){
    foreach ($polsetPolDefId in $($htCacheDefinitions).policySet.($polSetDef).PolicySetPolicyIds) {
        if ((($htCacheDefinitions).policy.(($polsetPolDefId -replace '.*/'))).type -eq "BuiltIn" -and (($htCacheDefinitions).policy.(($polsetPolDefId -replace '.*/'))).deprecated -eq $true -or (($htCacheDefinitions).policy.(($polsetPolDefId -replace '.*/'))).displayname.startswith("[Deprecated]")) {
                $object = New-Object -TypeName PSObject -Property @{'PolicySetDisplayName'= $($htCacheDefinitions).policySet.($polSetDef).DisplayName; 'PolicySetDefinitionId'= $($htCacheDefinitions).policySet.($polSetDef).PolicyDefinitionId; 'PolicyDisplayName' = (($htCacheDefinitions).policy.(($polsetPolDefId -replace '.*/'))).displayname; 'PolicyId' = (($htCacheDefinitions).policy.(($polsetPolDefId -replace '.*/'))).Id; 'DeprecatedProperty' = (($htCacheDefinitions).policy.(($polsetPolDefId -replace '.*/'))).deprecated }
                $policySetsDeprecated += $object
        }
    }
}

if (($policySetsDeprecated | measure-object).count -gt 0) {
    $tfCount = ($policySetsDeprecated | measure-object).count
    
    $tableId = "SummaryTable_policySetsDeprecated"
$script:html += @"
    <button type="button" class="collapsible" id="summary_policySetsDeprecated"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($policySetsDeprecated | measure-object).count) Custom Policy Sets / deprecated Built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] or Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
    </button>
    <div class="content">
        <table id= "$tableId" class="summaryTable">
            <thead>
                <tr>
                    <th>
                        PolicySet DisplayName
                    </th>
                    <th>
                        PolicySet DefinitionId
                    </th>
                    <th>
                        Policy DisplayName
                    </th>
                    <th>
                        Policy DefinitionId
                    </th>
                    <th>
                        Deprecated Property
                    </th>
                </tr>
            </thead>
            <tbody>
"@
    foreach ($policySetDeprecated in $policySetsDeprecated) {
        if ($policySetDeprecated.DeprecatedProperty -eq $true){
            $deprecatedProperty = "true"
        }
        else{
            $deprecatedProperty = "false"
        }
$script:html += @"
                <tr>
                    <td>
                        $($policySetDeprecated.PolicySetDisplayName)
                    </td>
                    <td>
                        $($policySetDeprecated.PolicySetDefinitionId)
                    </td>
                    <td>
                        $($policySetDeprecated.PolicyDisplayName)
                    </td>
                    <td>
                        $($policySetDeprecated.PolicyId)
                    </td>
                    <td>
                        $deprecatedProperty
                    </td>
                </tr>
"@ 
    }
$script:html += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($policySetsDeprecated | measure-object).count) Policy Sets / deprecated Built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] or Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span></p>
"@
}
#endregion SUMMARYPolicySetsDeprecatedPolicy

#region SUMMARYPolicyAssignmentsDeprecatedPolicy
$policyAssignmentsDeprecated =@()
foreach ($policyAssignmentAll in $($htCacheAssignments).policy.keys) {
    #policySet
    if ($($htCacheDefinitions).policySet.(($($htCacheAssignments).policy.($policyAssignmentAll).Properties.PolicyDefinitionId -replace '.*/')) -and -not($($htCacheAssignments).policy.($policyAssignmentAll)).Properties.PolicyDefinitionId.StartsWith("/providers/Microsoft.Authorization/policySetDefinitions/")) {
        foreach ($polsetPolDefId in $($htCacheDefinitions).policySet.(($($htCacheAssignments).policy.($policyAssignmentAll).Properties.PolicyDefinitionId -replace '.*/')).PolicySetPolicyIds) {
            if ((($htCacheDefinitions).policy.(($polsetPolDefId -replace '.*/'))).type -eq "BuiltIn" -and (($htCacheDefinitions).policy.(($polsetPolDefId -replace '.*/'))).deprecated -eq $true -or (($htCacheDefinitions).policy.(($polsetPolDefId -replace '.*/'))).displayname.startswith("[Deprecated]")) {
                    $object = New-Object -TypeName PSObject -Property @{'PolicyAssignmentId' = $policyAssignmentAll; 'PolicyDisplayName' = (($htCacheDefinitions).policy.(($polsetPolDefId -replace '.*/'))).displayname; 'PolicyId' = (($htCacheDefinitions).policy.(($polsetPolDefId -replace '.*/'))).Id; 'PolicyType' = "PolicySet"; 'DeprecatedProperty' = (($htCacheDefinitions).policy.(($polsetPolDefId -replace '.*/'))).deprecated }
                    $policyAssignmentsDeprecated += $object
            }
        }
    }
    #Policy
    if ($($htCacheDefinitions).policy.(($($htCacheAssignments).policy.($policyAssignmentAll).Properties.PolicyDefinitionId -replace '.*/')) -and ($($htCacheDefinitions).policy.(($($htCacheAssignments).policy.($policyAssignmentAll).Properties.PolicyDefinitionId -replace '.*/')).type -eq "Builtin" -and ($($htCacheDefinitions).policy.(($($htCacheAssignments).policy.($policyAssignmentAll).Properties.PolicyDefinitionId -replace '.*/')).deprecated -eq $true) -or $($htCacheDefinitions).policy.(($($htCacheAssignments).policy.($policyAssignmentAll).Properties.PolicyDefinitionId -replace '.*/')).displayname.startswith("[Deprecated]"))) {
        $object = New-Object -TypeName PSObject -Property @{'PolicyAssignmentId' = $policyAssignmentAll; 'PolicyDisplayName' = $($htCacheDefinitions).policy.(($($htCacheAssignments).policy.($policyAssignmentAll).Properties.PolicyDefinitionId -replace '.*/')).displayname; 'PolicyId' = $($htCacheDefinitions).policy.(($($htCacheAssignments).policy.($policyAssignmentAll).Properties.PolicyDefinitionId -replace '.*/')).Id; 'PolicyType' = "Policy"; 'DeprecatedProperty' = $($htCacheDefinitions).policy.(($($htCacheAssignments).policy.($policyAssignmentAll).Properties.PolicyDefinitionId -replace '.*/')).deprecated }
        $policyAssignmentsDeprecated += $object
    }
}

#$policyAssignmentsDeprecated
if (($policyAssignmentsDeprecated | measure-object).count -gt 0) {
    $tfCount = ($policyAssignmentsDeprecated | measure-object).count
    
    $tableId = "SummaryTable_policyAssignmnetsDeprecated"
$script:html += @"
    <button type="button" class="collapsible" id="summary_policyAssignmnetsDeprecated"><i class="fa fa-exclamation-triangle orange" aria-hidden="true"></i> <span class="valignMiddle">$(($policyAssignmentsDeprecated | measure-object).count) Policy Assignments / deprecated Built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] or Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
    </button>
    <div class="content">
        <table id= "$tableId" class="summaryTable">
            <thead>
                <tr>
                    <th>
                        Policy AssignmentId
                    </th>
                    <th>
                        Policy Type
                    </th>
                    <th>
                        Policy DisplayName
                    </th>
                    <th>
                        Policy DefinitionId
                    </th>
                    <th>
                        Deprecated Property
                    </th>
                </tr>
            </thead>
            <tbody>
"@
    foreach ($policyAssignmentDeprecated in $policyAssignmentsDeprecated) {
        if ($policyAssignmentDeprecated.DeprecatedProperty -eq $true){
            $deprecatedProperty = "true"
        }
        else{
            $deprecatedProperty = "false"
        }
$script:html += @"
                <tr>
                    <td>
                        $($policyAssignmentDeprecated.PolicyAssignmentId)
                    </td>
                    <td>
                        $($policyAssignmentDeprecated.PolicyType)
                    </td>
                    <td>
                        $($policyAssignmentDeprecated.PolicyDisplayName)
                    </td>
                    <td>
                        $($policyAssignmentDeprecated.PolicyId)
                    </td>
                    <td>
                        $deprecatedProperty
                    </td>
                </tr>
"@ 
    }
$script:html += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_1: 'select',
            col_types: [
                'string',
                'select',
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($policyAssignmentsDeprecated | measure-object).count) Policy Assignments / deprecated Built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] or Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span></p>
"@
}
#endregion SUMMARYPolicyAssignmentsDeprecatedPolicy

#region SUMMARYPolicyAssignmentsAll
$policyAssignmentsAllArray =@() 
foreach ($policyAssignmentAll in $policyBaseQuery){  
    $notScopesArray = @()
    $policyAssignmentNotScopes = ($htCacheAssignments).policy.($policyAssignmentAll.PolicyAssignmentId).properties.NotScopes
    if (($policyAssignmentNotScopes | Measure-Object).count -gt 0){
        $notScopesArray += foreach ($notscope in $policyAssignmentNotScopes){
            $notscope
        }
    }
    
    if ($policyAssignmentAll.PolicyAssignmentId.StartsWith("/providers/Microsoft.Management/managementGroups/")){
        if ("" -ne $policyAssignmentAll.SubscriptionId){
            $scope = "inherited $($policyAssignmentAll.PolicyAssignmentScope -replace '.*/')"
        }
        else{
            if (($policyAssignmentAll.PolicyAssignmentScope -replace '.*/') -eq $policyAssignmentAll.MgId){
                $scope = "this Mg"
            }
            else{
                $scope = "inherited $($policyAssignmentAll.PolicyAssignmentScope -replace '.*/')"
            }
        }
    }
    if ($policyAssignmentAll.PolicyAssignmentId.StartsWith("/subscriptions/")){
        $scope = "this Sub"
    }

    if (($htCacheAssignments).policy.($policyAssignmentAll.PolicyAssignmentId).properties.parameters.effect.value){
        $effect = ($htCacheAssignments).policy.($policyAssignmentAll.PolicyAssignmentId).properties.parameters.effect.value
    }
    else{
        if ((($htCacheDefinitions).policy.(($htCacheAssignments).policy.($policyAssignmentAll.PolicyAssignmentId).properties.PolicyDefinitionId -replace '.*/')).effectDefaultValue -ne "n/a"){
            $effect = (($htCacheDefinitions).policy.(($htCacheAssignments).policy.($policyAssignmentAll.PolicyAssignmentId).properties.PolicyDefinitionId -replace '.*/')).effectDefaultValue
        }
        if ((($htCacheDefinitions).policy.(($htCacheAssignments).policy.($policyAssignmentAll.PolicyAssignmentId).properties.PolicyDefinitionId -replace '.*/')).effectFixedValue -ne "n/a"){
            $effect = (($htCacheDefinitions).policy.(($htCacheAssignments).policy.($policyAssignmentAll.PolicyAssignmentId).properties.PolicyDefinitionId -replace '.*/')).effectFixedValue
        }
    }

    $object = New-Object -TypeName PSObject -Property @{'Level' = $policyAssignmentAll.Level; 'MgId'= $policyAssignmentAll.MgId; 'MgName'= $policyAssignmentAll.MgName; 'subscriptionId' = $policyAssignmentAll.SubscriptionId; 'subscriptionName' = $policyAssignmentAll.Subscription; 'PolicyAssignmentId' = $policyAssignmentAll.PolicyAssignmentId; 'PolicyAssignmentDisplayName' = $policyAssignmentAll.PolicyAssignmentDisplayName; 'Effect' = $effect; 'PolicyName' = $policyAssignmentAll.Policy; 'PolicyId' = $policyAssignmentAll.PolicyDefinitionIdGuid; 'PolicyVariant' = $policyAssignmentAll.PolicyVariant; 'PolicyType' = $policyAssignmentAll.PolicyType; 'PolicyCategory' = $policyAssignmentAll.PolicyCategory; 'Inheritance' = $scope; 'PolicyAssignmentNotScopes' = $notScopesArray }
    $policyAssignmentsAllArray += $object
}

if (($policyAssignmentsAllArray | measure-object).count -gt 0) {
    $tfCount = ($policyAssignmentsAllArray | measure-object).count
    $policyAssignmentsUniqueCount = ($policyAssignmentsAllArray | Sort-Object -Property PolicyAssignmentId -Unique | measure-object).count
    
    $tableId = "SummaryTable_policyAssignmentsAll"
$script:html += @"
    <button type="button" class="collapsible" id="summary_policyAssignmentsAll"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($policyAssignmentsAllArray | measure-object).count) Policy Assignments ($policyAssignmentsUniqueCount unique)</span>
    </button>
    <div class="content">
        <table id= "$tableId" class="summaryTable">
            <thead>
                <tr>
                    <th>
                        Mg/Sub
                    </th>
                    <th>
                        Management Group Id
                    </th>
                    <th>
                        Management Group Name
                    </th>
                    <th>
                        Subscription Id
                    </th>
                    <th>
                        Subscription Name
                    </th>
                    <th>
                        Inheritance
                    </th>
                    <th>
                        ScopeExcluded
                    </th>
                    <th>
                        Assignment DisplayName
                    </th>
                    <th>
                        Policy
                    </th>
                    <th>
                        Policy/Set
                    </th>
                    <th>
                        Type
                    </th>
                    <th>
                        Category
                    </th>
                    <th>
                        Effect
                    </th>
                    <th>
                        Policies NonCmplnt
                    </th>
                    <th>
                        Policies Compliant
                    </th>
                    <th>
                        Resources NonCmplnt
                    </th>
                    <th>
                        Resources Compliant
                    </th>
                    <th>
                        Role/Assignment
                    </th>
                    <th>
                        Assignment Id
                    </th>
                </tr>
            </thead>
            <tbody>
"@
    foreach ($policyAssignment in $policyAssignmentsAllArray | sort-object -Property Level, MgName, MgId, SubscriptionName, SubscriptionId) {
        $relatedRoleAssignmentsArray = @()
        $relatedRoleAssignmentsArray += foreach ($roleassignment in ($htCacheAssignments).role.keys){
            if ((($htCacheAssignments).role.($roleassignment).DisplayName -replace '.*/') -eq ($policyAssignment.PolicyAssignmentId -replace '.*/')){
                if (($htCacheDefinitions).role.(($htCacheAssignments).role.($roleassignment).RoleDefinitionId).IsCustom -eq $false){
                    Write-Output "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azrolesadvertizer/$(($htCacheAssignments).role.($roleassignment).RoleDefinitionId).html`" target=`"_blank`">$(($htCacheAssignments).role.($roleassignment).RoleDefinitionName)</a> ($(($htCacheAssignments).role.($roleassignment).RoleAssignmentId))"
                }
                else{
                    Write-Output "<u>$(($htCacheAssignments).role.($roleassignment).RoleDefinitionName)</u> ($(($htCacheAssignments).role.($roleassignment).RoleAssignmentId))"
                }
            }
        }
        if (($relatedRoleAssignmentsArray | Measure-Object).count -gt 0){
            $relatedRoleAssignments = $relatedRoleAssignmentsArray -join "$CsvDelimiterOpposite "
        }
        else{
            $relatedRoleAssignments = "n/a"
        }

        if ("" -eq $policyAssignment.SubscriptionId){
            $mgOrSub = "Mg"
        }
        else{
            $mgOrSub = "Sub"
        }

        $excludedScope = "false"
        if (($policyAssignment.PolicyAssignmentNotScopes | Measure-Object).count -gt 0){
            foreach ($policyAssignmentNotScope in $policyAssignment.PolicyAssignmentNotScopes){

                if ("" -ne $policyAssignment.subscriptionId){
                    createMgPathSub -subid $policyAssignment.subscriptionId
                    [array]::Reverse($script:submgPathArray)
                    $subPath = $script:submgPathArray -join "/"
                    
                    if ($submgPathArray -contains "'$($policyAssignmentNotScope -replace "/subscriptions/" -replace "/providers/Microsoft.Management/managementGroups/")'"){
                        $excludedScope = "true"
                    }
                }
                else{
                    createMgPath -mgid $policyAssignment.MgId
                    [array]::Reverse($script:mgPathArray)
                    $mgPath = $script:mgPathArray -join "/"
                    
                    if ($mgPathArray -contains "'$($policyAssignmentNotScope -replace "/providers/Microsoft.Management/managementGroups/")'"){
                        $excludedScope = "true"
                    }
                }
            }
        }

$script:html += @"
                <tr>
                    <td>
                        $mgOrSub
                    </td>
                    <td>
                        $($policyAssignment.MgId)
                    </td>
                    <td>
                        $($policyAssignment.MgName)
                    </td>
                    <td>
                        $($policyAssignment.SubscriptionId)
                    </td>
                    <td>
                        $($policyAssignment.SubscriptionName)
                    </td>
                    <td>
                        $($policyAssignment.Inheritance)
                    </td>
                    <td>
                        $excludedScope
                    </td>
                    <td>
                        $($policyAssignment.PolicyAssignmentDisplayName)
                    </td>
                    <td>
                        $($policyAssignment.PolicyName)
                    </td>
                    <td>
                        $($policyAssignment.PolicyVariant)
                    </td>
                    <td>
                        $($policyAssignment.PolicyType)
                    </td>
                    <td>
                        $($policyAssignment.PolicyCategory)
                    </td>
                    <td>
"@
                    if ($policyAssignment.PolicyVariant -eq "Policy"){
$script:html += @"
                        $($policyAssignment.Effect)
"@
                    }
                    else{
$script:html += @"
                        n/a
"@
                    }
$script:html += @"
                    </td>
                    <td>
"@
if ($($policyAssignment.PolicyAssignmentId).StartsWith("/providers/Microsoft.Management/managementGroups/")){
$script:html += @"
                        $(($htCachePolicyCompliance).mg.($policyAssignment.MgId).($policyAssignment.policyAssignmentId).NonCompliantPolicies)
"@
}
if ($($policyAssignment.PolicyAssignmentId).StartsWith("/subscriptions/")){
$script:html += @"
                        $(($htCachePolicyCompliance).sub.($policyAssignment.SubscriptionId).($policyAssignment.policyAssignmentId).NonCompliantPolicies)
"@
}
$script:html += @"
                    </td>
                    <td>
"@
if ($($policyAssignment.PolicyAssignmentId).StartsWith("/providers/Microsoft.Management/managementGroups/")){
$script:html += @"
                        $(($htCachePolicyCompliance).mg.($policyAssignment.MgId).($policyAssignment.policyAssignmentId).CompliantPolicies)
"@
}
if ($($policyAssignment.PolicyAssignmentId).StartsWith("/subscriptions/")){
$script:html += @"
                        $(($htCachePolicyCompliance).sub.($policyAssignment.SubscriptionId).($policyAssignment.policyAssignmentId).CompliantPolicies)
"@
}
$script:html += @"
                    </td>
                    <td>
"@
#noncomp
if ($($policyAssignment.PolicyAssignmentId).StartsWith("/providers/Microsoft.Management/managementGroups/")){
$script:html += @"
    $(($htCachePolicyCompliance).mg.($policyAssignment.MgId).($policyAssignment.policyAssignmentId).NonCompliantResources)
"@
}
if ($($policyAssignment.PolicyAssignmentId).StartsWith("/subscriptions/")){
$script:html += @"
    $(($htCachePolicyCompliance).sub.($policyAssignment.SubscriptionId).($policyAssignment.policyAssignmentId).NonCompliantResources)
"@
}    
$script:html += @"
                    </td>
                    <td>
"@
#compl
if ($($policyAssignment.PolicyAssignmentId).StartsWith("/providers/Microsoft.Management/managementGroups/")){
$script:html += @"
    $(($htCachePolicyCompliance).mg.($policyAssignment.MgId).($policyAssignment.policyAssignmentId).CompliantResources)
"@
}
if ($($policyAssignment.PolicyAssignmentId).StartsWith("/subscriptions/")){
$script:html += @"
    $(($htCachePolicyCompliance).sub.($policyAssignment.SubscriptionId).($policyAssignment.policyAssignmentId).CompliantResources)
"@
}    
$script:html += @"
                    </td>
                    <td class="breakwordall">
                        $relatedRoleAssignments
                    </td>
                    <td class="breakwordall">
                        $($policyAssignment.PolicyAssignmentId)
                    </td>
                </tr>
"@
    }
$script:html += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_0: 'select',
            col_6: 'select',
            col_9: 'select',
            col_10: 'select',
            col_12: 'select',
            col_types: [
                'select',
                'string',
                'string',
                'string',
                'string',
                'string',
                'select',
                'string',
                'string',
                'select',
                'select',
                'string',
                'select',
                'number',
                'number',
                'number',
                'number',
                'string',
                'string'
            ],
            watermark: ['', '', '', 'try [nonempty]', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($policyAssignmentsAllArray | measure-object).count) Policy Assignments</span></p>
"@
}
#endregion SUMMARYPolicyAssignmentsAll


#region SUMMARYtenanttotalcustomroles
$script:html += @"
    <hr>
"@
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
    $tfCount = $tenantCustomRolesCount
    
    $tableId = "SummaryTable_customRoles"
$script:html += @"
    <button type="button" class="collapsible" id="summary_customRoles">$faimage <span class="valignMiddle">$tenantCustomRolesCount Custom Roles ($scopeNamingSummary) (Limit: $tenantCustomRolesCount/$LimitRBACCustomRoleDefinitionsTenant)</span></button>
    <div class="content">

        <table id="$tableId" class="summaryTable">
            <thead>
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
            </thead>
            <tbody>
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
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomRolesCount Custom Roles ($scopeNamingSummary)</span></p>
"@
}
#endregion SUMMARYtenanttotalcustomroles

#region SUMMARYOrphanedCustomRoles
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
        $tfCount = ($customRolesOrphaned | measure-object).count
        
        $tableId = "SummaryTable_customRolesOrphaned"
$script:html += @"
    <button type="button" class="collapsible" id="summary_customRolesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($customRolesOrphaned | measure-object).count) Orphaned Custom Roles ($scopeNamingSummary) <abbr title="Role has no assignments"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
    </button>
    <div class="content">
        <table id="$tableId" class="summaryTable">
            <thead>
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
            </thead>
            <tbody>
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
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
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
        $tfCount = ($customRolesInScopeArray | measure-object).count
        
        $tableId = "SummaryTable_customRolesOrphaned"
$script:html += @"
    <button type="button" class="collapsible" id="summary_customRolesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($customRolesInScopeArray | measure-object).count) Orphaned Custom Roles ($scopeNamingSummary) <abbr title="Role has no assignments (Roles where assignableScopes has mg from superior scopes are not evaluated)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
    </button>
    <div class="content">
        <table id="$tableId" class="summaryTable">
            <thead>
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
            </thead>
            <tbody>
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
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
    }
    else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($customRolesInScopeArray | measure-object).count) Orphaned Custom Roles ($scopeNamingSummary)</span></p>
"@
    }
}
#endregion SUMMARYOrphanedCustomRoles

#region SUMMARYOrphanedRoleAssignments
$roleAssignmentsOrphanedAll = $rbacBaseQuery | Where-Object { $_.RoleAssignmentObjectType -eq "Unknown" } | Sort-Object -Property RoleAssignmentId
$roleAssignmentsOrphanedUnique = $roleAssignmentsOrphanedAll | Sort-Object -Property RoleAssignmentId -Unique

if (($roleAssignmentsOrphanedUnique | measure-object).count -gt 0) {
    $tfCount = ($roleAssignmentsOrphanedUnique | measure-object).count
    
    $tableId = "SummaryTable_roleAssignmnetsOrphaned"
$script:html += @"
    <button type="button" class="collapsible" id="summary_roleAssignmnetsOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOrphanedUnique | measure-object).count) Orphaned Role Assignments ($scopeNamingSummary) <abbr title="Role was deleted although and assignment existed OR the target identity (User, Group, ServicePrincipal) was deleted"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
    </button>
    <div class="content">
        <table id= "$tableId" class="summaryTable">
            <thead>
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
            </thead>
            <tbody>
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
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOrphanedUnique | measure-object).count) Orphaned Role Assignments ($scopeNamingSummary)</span></p>
"@
}
#endregion SUMMARYOrphanedRoleAssignments

#region SUMMARYRoleAssignmentsAll
$rbacAll = @()
foreach ($rbac in $rbacBaseQuery){
    $scope = $null
    if ($rbac.RoleAssignmentId.StartsWith("/providers/Microsoft.Management/managementGroups/")){
        if ("" -ne $rbac.SubscriptionId){
            $scope = "inherited $($rbac.RoleAssignmentScope -replace '.*/')"
        }
        else{
            if (($rbac.RoleAssignmentScope -replace '.*/') -eq $rbac.MgId){
                $scope = "this Mg"
            }
            else{
                $scope = "inherited $($rbac.RoleAssignmentScope -replace '.*/')"
            }
        }
    }
    if ($rbac.RoleAssignmentId.StartsWith("/subscriptions/")){
        $scope = "this Sub"
    }
    if ($rbac.RoleAssignmentId.StartsWith("/providers/Microsoft.Authorization/roleAssignments/")){
            $scope = "INHERITED ROOT"
    }
    $object = New-Object -TypeName PSObject -Property @{'Level' = $rbac.Level; 'RoleAssignmentId' = $rbac.RoleAssignmentId; 'MgId'= $rbac.MgId; 'MgName' = $rbac.MgName; 'SubscriptionId' = $rbac.SubscriptionId; 'SubscriptionName' = $rbac.Subscription; 'Scope' = $scope; 'Role' = $rbac.RoleDefinitionName; 'RoleIsCustom' = $rbac.RoleIsCustom; 'ObjectDisplayName' = $rbac.RoleAssignmentDisplayname; 'ObjectSignInName' = $rbac.RoleAssignmentSignInName; 'ObjectId' = $rbac.RoleAssignmentObjectId; 'ObjectType' = $rbac.RoleAssignmentObjectType }
    $rbacAll += $object
}
if (($rbacAll | measure-object).count -gt 0) {
    $uniqueRoleAssignmentsCount = ($rbacAll | sort-object -Property RoleAssignmentId -Unique | Measure-Object).count
    $tfCount = ($rbacAll | measure-object).count
    
    $tableId = "SummaryTable_roleAssignmentsAll"
$script:html += @"
    <button type="button" class="collapsible" id="summary_roleAssignmentsAll"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($rbacAll | measure-object).count) Role Assignments ($uniqueRoleAssignmentsCount unique)</span>
    </button>
    <div class="content">
        <table id= "$tableId" class="summaryTable">
            <thead>
                <tr>
                    <th>
                        Mg/Sub
                    </th>
                    <th>
                        Management Group Id
                    </th>
                    <th>
                        Management Group Name
                    </th>
                    <th>
                        Subscription Id
                    </th>
                    <th>
                        Subscription Name
                    </th>
                    <th>
                        Scope
                    </th>
                    <th>
                        Role
                    </th>
                    <th>
                        Role Custom
                    </th>
                    <th>
                        Object Displayname
                    </th>
                    <th>
                        Object SignInName
                    </th>
                    <th>
                        Object ObjectId
                    </th>
                    <th>
                        Object Type
                    </th>
                    <th>
                        RoleAssignmentId
                    </th>
                    <th>
                        Related PolicyAssignment
                    </th>
                </tr>
            </thead>
            <tbody>
"@
    foreach ($roleAssignment in $rbacAll | sort-object -Property Level, MgName, MgId, SubscriptionName, SubscriptionId) {
        if ("" -eq $roleAssignment.SubscriptionId){
            $mgOrSub = "Mg"
        }
        else{
            $mgOrSub = "Sub"
        }
$script:html += @"
                <tr>
                    <td>
                        $mgOrSub
                    </td>
                    <td>
                        $($roleAssignment.MgId)
                    </td>
                    <td>
                        $($roleAssignment.MgName)
                    </td>
                    <td>
                        $($roleAssignment.SubscriptionId)
                    </td>
                    <td>
                        $($roleAssignment.SubscriptionName)
                    </td>
                    <td>
                        $($roleAssignment.Scope)
                    </td>
                    <td>
                        $($roleAssignment.Role)
                    </td>
                    <td>
                        $($roleAssignment.RoleIsCustom)
                    </td>
                    <td class="breakwordall">
                        $($roleAssignment.ObjectDisplayName)
                    </td>
                    <td class="breakwordall">
                        $($roleAssignment.ObjectSignInName)
                    </td>
                    <td class="breakwordall">
                        $($roleAssignment.ObjectId)
                    </td>
                    <td>
                        $($roleAssignment.ObjectType)
                    </td>
                    <td class="breakwordall">
                        $($roleAssignment.RoleAssignmentId)
                    </td>
                    <td class="breakwordall">
"@
        $relatedPolicyAssignment = ($policyBaseQuery | where-Object { $_.PolicyAssignmentName -eq $roleAssignment.ObjectDisplayName }) | Get-Unique
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
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_0: 'select',
            col_7: 'select',
            col_types: [
                'select',
                'string',
                'string',
                'string',
                'string',
                'string',
                'string',
                'select',
                'string',
                'string',
                'string',
                'string',
                'string',
                'string'
            ],
            watermark: ['', '', '', 'try [nonempty]', '', '', 'try owner||reader', '', '', '', '', '', '', ''],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($rbacAll | measure-object).count) Role Assignments</span></p>
"@
}
#endregion SUMMARYRoleAssignmentsAll

#region SUMMARYSecurityCustomRoles
$customRolesOwnerAll = $rbacBaseQuery | Where-Object { $_.RoleSecurityCustomRoleOwner -eq 1 } | Sort-Object -Property RoleDefinitionId
$customRolesOwnerHtAll = ($htCacheDefinitions).role.keys | where-object { ($htCacheDefinitions).role.$_.Actions -eq '*' -and (($htCacheDefinitions).role.$_.NotActions).length -eq 0 -and ($htCacheDefinitions).role.$_.IsCustom -eq $True }
if (($customRolesOwnerHtAll | measure-object).count -gt 0){
    $tfCount = ($customRolesOwnerHtAll | measure-object).count
    
    $tableId = "SummaryTable_customroleCustomRoleOwner"
$script:html += @"
    <button type="button" class="collapsible" id="summary_customroleCustomRoleOwner"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($customRolesOwnerHtAll | measure-object).count) Custom Roles Owner permissions ($scopeNamingSummary) <abbr title="Custom owner roles should not exist"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
    </button>
    <div class="content">
        <table id="$tableId" class="summaryTable">
            <thead>
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
            </thead>
            <tbody>
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
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($customRolesOwnerHtAll | measure-object).count) Custom Roles Owner permissions ($scopeNamingSummary)</span></p>
"@
}
#endregion SUMMARYSecurityCustomRoles

#region SUMMARYSecurityOwnerAssignmentSP
$roleAssignmentsOwnerAssignmentSPAll = ($rbacBaseQuery | Where-Object { $_.RoleSecurityOwnerAssignmentSP -eq 1 } | Sort-Object -Property RoleAssignmentId)
$roleAssignmentsOwnerAssignmentSP = $roleAssignmentsOwnerAssignmentSPAll | sort-object -Property RoleAssignmentId -Unique
if (($roleAssignmentsOwnerAssignmentSP | measure-object).count -gt 0){
    $tfCount = ($roleAssignmentsOwnerAssignmentSP | measure-object).count
    
    $tableId = "SummaryTable_roleAssignmentsOwnerAssignmentSP"
$script:html += @"
    <button type="button" class="collapsible" id="summary_roleAssignmentsOwnerAssignmentSP"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentSP | measure-object).count) Owner permission assignments to ServicePrincipal ($scopeNamingSummary) <abbr title="Owner permissions for Service Principals should be treated exceptional"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
    </button>
    <div class="content">
        <table id= "$tableId" class="summaryTable">
            <thead>
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
            </thead>
            <tbody>
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
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentSP | measure-object).count) Owner permission assignments to ServicePrincipal ($scopeNamingSummary)</span></p>
"@
}
#endregion SUMMARYSecurityOwnerAssignmentSP

#region SUMMARYSecurityOwnerAssignmentNotGroup
$roleAssignmentsOwnerAssignmentNotGroupAll = ($rbacBaseQuery | Where-Object { $_.RoleDefinitionName -eq "Owner" -and $_.RoleAssignmentObjectType -ne "Group" } | Sort-Object -Property RoleAssignmentId)
$roleAssignmentsOwnerAssignmentNotGroup = $roleAssignmentsOwnerAssignmentNotGroupAll | sort-object -Property RoleAssignmentId -Unique
if (($roleAssignmentsOwnerAssignmentNotGroup | measure-object).count -gt 0){
    $tfCount = ($roleAssignmentsOwnerAssignmentNotGroup | measure-object).count
    
    $tableId = "SummaryTable_roleAssignmentsOwnerAssignmentNotGroup"
$script:html += @"
    <button type="button" class="collapsible" id="summary_roleAssignmentsOwnerAssignmentNotGroup"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentNotGroup | measure-object).count) Owner permission assignments to notGroup ($scopeNamingSummary)</span>
    </button>
    <div class="content">
        <table id= "$tableId" class="summaryTable">
            <thead>
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
                        Obj Type
                    </th>
                    <th>
                        Obj DisplayName
                    </th>
                    <th>
                        Obj SignInName
                    </th>
                    <th>
                        Obj Id
                    </th>
                    <th>
                        Impacted Mg/Sub
                    </th>
                </tr>
            </thead>
            <tbody>
"@
    foreach ($roleAssignmentOwnerAssignmentNotGroup in ($roleAssignmentsOwnerAssignmentNotGroup)) {
        $impactedMgs = $roleAssignmentsOwnerAssignmentNotGroupAll | Where-Object { "" -eq $_.SubscriptionId -and $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentId }
        $impactedSubs = $roleAssignmentsOwnerAssignmentNotGroupAll | Where-Object { "" -ne $_.SubscriptionId -and $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentId }
        $servicePrincipal = ($roleAssignmentsOwnerAssignmentNotGroup | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentId }) | Get-Unique
$script:html += @"
                <tr>
                    <td>
                        $($roleAssignmentOwnerAssignmentNotGroup.RoleDefinitionName)
                    </td>
                    <td>
                        $($roleAssignmentOwnerAssignmentNotGroup.RoleDefinitionId)
                    </td>
                    <td class="breakwordall">
                        $($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentId)
                    </td>
                    <td>
                        $($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentObjectType)
                    </td>
                    <td>
                        $($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentDisplayname)
                    </td>
                    <td class="breakwordall">
                        $($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentSignInName)
                    </td>
                    <td class="breakwordall">
                        $($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentObjectId)
                    </td>
                    <td>
                        Mg: $(($impactedMgs | measure-object).count); Sub: $(($impactedSubs | measure-object).count)
                    </td>
                </tr>
"@ 
    }
$script:html += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string',
                'string',
                'string',
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentNotGroup | measure-object).count) Owner permission assignments to notGroup ($scopeNamingSummary)</span></p>
"@
}
#endregion SUMMARYSecurityOwnerAssignmentNotGroup

#region SUMMARYSecurityUserAccessAdministratorAssignmentNotGroup
$roleAssignmentsUserAccessAdministratorAssignmentNotGroupAll = ($rbacBaseQuery | Where-Object { $_.RoleDefinitionName -eq "User Access Administrator" -and $_.RoleAssignmentObjectType -ne "Group" } | Sort-Object -Property RoleAssignmentId)
$roleAssignmentsUserAccessAdministratorAssignmentNotGroup = $roleAssignmentsUserAccessAdministratorAssignmentNotGroupAll | sort-object -Property RoleAssignmentId -Unique
if (($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | measure-object).count -gt 0){
    $tfCount = ($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | measure-object).count
    
    $tableId = "SummaryTable_roleAssignmentsUserAccessAdministratorAssignmentNotGroup"
$script:html += @"
    <button type="button" class="collapsible" id="summary_roleAssignmentsUserAccessAdministratorAssignmentNotGroup"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | measure-object).count) UserAccessAdministrator permission assignments to notGroup ($scopeNamingSummary)</span>
    </button>
    <div class="content">
        <table id= "$tableId" class="summaryTable">
            <thead>
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
                        Obj Type
                    </th>
                    <th>
                        Obj DisplayName
                    </th>
                    <th>
                        Obj SignInName
                    </th>
                    <th>
                        Obj Id
                    </th>
                    <th>
                        Impacted Mg/Sub
                    </th>
                </tr>
            </thead>
            <tbody>
"@
    foreach ($roleAssignmentUserAccessAdministratorAssignmentNotGroup in ($roleAssignmentsUserAccessAdministratorAssignmentNotGroup)) {
        $impactedMgs = $roleAssignmentsUserAccessAdministratorAssignmentNotGroupAll | Where-Object { "" -eq $_.SubscriptionId -and $_.RoleAssignmentId -eq $roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId }
        $impactedSubs = $roleAssignmentsUserAccessAdministratorAssignmentNotGroupAll | Where-Object { "" -ne $_.SubscriptionId -and $_.RoleAssignmentId -eq $roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId }
        $servicePrincipal = ($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId }) | Get-Unique
$script:html += @"
                <tr>
                    <td>
                        $($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleDefinitionName)
                    </td>
                    <td>
                        $($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleDefinitionId)
                    </td>
                    <td class="breakwordall">
                        $($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId)
                    </td>
                    <td>
                        $($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentObjectType)
                    </td>
                    <td>
                        $($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentDisplayname)
                    </td>
                    <td class="breakwordall">
                        $($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentSignInName)
                    </td>
                    <td class="breakwordall">
                        $($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentObjectId)
                    </td>
                    <td>
                        Mg: $(($impactedMgs | measure-object).count); Sub: $(($impactedSubs | measure-object).count)
                    </td>
                </tr>
"@ 
    }
$script:html += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string',
                'string',
                'string',
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | measure-object).count) UserAccessAdministrator permission assignments to notGroup ($scopeNamingSummary)</span></p>
"@
}
#endregion SUMMARYSecurityUserAccessAdministratorAssignmentNotGroup


#region SUMMARYBlueprintDefinitions
$script:html += @"
    <hr>
"@
$blueprintDefinitions = ($blueprintBaseQuery | Where-Object { "" -eq $_.BlueprintAssignmentId })

$blueprintDefinitionsCount = ($blueprintDefinitions | measure-object).count

    if ($blueprintDefinitionsCount -gt 0){
        

        $tableId = "SUMMARY_BlueprintDefinitions"
$script:html += @"
        <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintDefinitionsCount Blueprints</p></button>
        <div class="content">
            <table id="$tableId" class="summaryTable">
                <thead>
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
                </thead>
                <tbody
"@
        foreach ($blueprintDefinition in $blueprintDefinitions){
$script:html += @"
                    <tr>
                        <td>
                            $($blueprintDefinition.BlueprintName)
                        </td>
                        <td>
                            $($blueprintDefinition.BlueprintDisplayName)
                        </td>
                        <td>
                            $($blueprintDefinition.BlueprintDescription)
                        </td>
                        <td>
                            $($blueprintDefinition.BlueprintId)
                        </td>
                    </tr>
"@        
        }
$script:html += @"
                </tbody>
            </table>
        </div>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
                btn_reset: true,
                highlight_keywords: true,
                alternate_rows: true,
                auto_filter: {
                    delay: 1100 //milliseconds
                },
                no_results_message: true,
                col_types: [
                    'string',
                    'string',
                    'string',
                    'string'
                ],
                extensions: [{
                    name: 'sort'
                }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
"@
    }
    else{
$script:html += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $blueprintDefinitionsCount Blueprints</p>
"@
    }
#endregion SUMMARYBlueprintDefinitions

#region SUMMARYBlueprintAssignments
$blueprintAssignments = ($blueprintBaseQuery | Where-Object { "" -ne $_.BlueprintAssignmentId })
$blueprintAssignmentsCount = ($blueprintAssignments | measure-object).count

    if ($blueprintAssignmentsCount -gt 0){
        $tableId = "SUMMARY_BlueprintAssignments"
$script:html += @"
        <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintAssignmentsCount Blueprint Assignments</p></button>
        <div class="content">
            <table id="$tableId" class="summaryTable">
                <thead>
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
                            Blueprint Version
                        </th>
                        <th>
                            Blueprint AssignmentId
                        </th>
                    </tr>
                </thead>
                <tbody
"@
        foreach ($blueprintAssignment in $blueprintAssignments){
$script:html += @"
                    <tr>
                        <td>
                            $($blueprintAssignment.BlueprintName)
                        </td>
                        <td>
                            $($blueprintAssignment.BlueprintDisplayName)
                        </td>
                        <td>
                            $($blueprintAssignment.BlueprintDescription)
                        </td>
                        <td>
                            $($blueprintAssignment.BlueprintId)
                        </td>
                        <td>
                            $($blueprintAssignment.BlueprintAssignmentVersion)
                        </td>
                        <td>
                            $($blueprintAssignment.BlueprintAssignmentId)
                        </td>
                    </tr>
"@        
        }
$script:html += @"
                </tbody>
            </table>
        </div>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
                btn_reset: true,
                highlight_keywords: true,
                alternate_rows: true,
                auto_filter: {
                    delay: 1100 //milliseconds
                },
                no_results_message: true,
                col_types: [
                    'string',
                    'string',
                    'string',
                    'string',
                    'string',
                    'string'
                ],
                extensions: [{
                    name: 'sort'
                }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
"@
    }
    else{
$script:html += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $blueprintAssignmentsCount Blueprint Assignments</p>
"@
    }
#endregion SUMMARYBlueprintAssignments

#region SUMMARYBlueprintsOrphaned
$blueprintDefinitionsOrphanedArray =@()
if ($blueprintDefinitionsCount -gt 0){
    if ($blueprintAssignmentsCount -gt 0){
        $blueprintDefinitionsOrphanedArray = foreach ($blueprintDefinition in $blueprintDefinitions){
            if (-not($blueprintAssignments.BlueprintId).contains($blueprintDefinition.BlueprintId)){
                $blueprintDefinition
            }
        }
    }
    else{
        $blueprintDefinitionsOrphanedArray = foreach ($blueprintDefinition in $blueprintDefinitions){
            $blueprintDefinition
        }

    }
}
$blueprintDefinitionsOrphanedCount = ($blueprintDefinitionsOrphanedArray | Measure-Object).count

if ($blueprintDefinitionsOrphanedCount -gt 0){
    $tableId = "SUMMARY_BlueprintsOrphaned"
$script:html += @"
    <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintDefinitionsOrphanedCount Orphaned Blueprints</p></button>
    <div class="content">
        <table id="$tableId" class="summaryTable">
            <thead>
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
            </thead>
            <tbody
"@
    foreach ($blueprintDefinition in $blueprintDefinitionsOrphanedArray){
$script:html += @"
                <tr>
                    <td>
                        $($blueprintDefinition.BlueprintName)
                    </td>
                    <td>
                        $($blueprintDefinition.BlueprintDisplayName)
                    </td>
                    <td>
                        $($blueprintDefinition.BlueprintDescription)
                    </td>
                    <td>
                        $($blueprintDefinition.BlueprintId)
                    </td>
                </tr>
"@        
    }
$script:html += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
$spectrum = "10, $tfCount"
if ($tfCount -gt 100){
    $spectrum = "10, 30, 50, $tfCount"
}
if ($tfCount -gt 500){
    $spectrum = "10, 30, 50, 100, 250, $tfCount"
}
if ($tfCount -gt 1000){
    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
}
if ($tfCount -gt 2000){
    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
}
if ($tfCount -gt 3000){
    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
}

$script:html += @"
        paging: {
            results_per_page: ['Records: ', [$spectrum]]
        },
        state: {
            types: ['local_storage'],
            filters: true,
            page_number: true,
            page_length: true,
            sort: true
        },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
                <p><i class="fa fa-ban" aria-hidden="true"></i> $blueprintDefinitionsOrphanedCount Orphaned Blueprints</p>
"@
}
#endregion SUMMARYBlueprintsOrphaned


#region SUMMARYMGs
$script:html += @"
    <hr>
"@
$script:html += @"
    <p><i class="fa fa-check-circle" aria-hidden="true"></i> <span class="valignMiddle">$totalMgCount Management Groups ($mgDepth levels of depth)</span></p>
"@
#endregion SUMMARYMGs

#region SUMMARYMgsapproachingLimitsPolicyAssignments
$mgsApproachingLimitPolicyAssignments = (($policyBaseQuery | where-object { "" -eq $_.SubscriptionId -and $_.PolicyAndPolicySetAssigmentAtScopeCount -gt 0 -and  (($_.PolicyAndPolicySetAssigmentAtScopeCount -gt ($_.PolicyAssigmentLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, MgName, PolicyAssigmentAtScopeCount, PolicySetAssigmentAtScopeCount, PolicyAndPolicySetAssigmentAtScopeCount, PolicyAssigmentLimit -Unique)
if (($mgsApproachingLimitPolicyAssignments | measure-object).count -gt 0){
    $tfCount = ($mgsApproachingLimitPolicyAssignments | measure-object).count
    $tableId = "SummaryTable_MgsapproachingLimitsPolicyAssignments"
$script:html += @"
<button type="button" class="collapsible" id="SUMMARY_MgsapproachingLimitsPolicyAssignments"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicyAssignments | measure-object).count) Management Groups approaching Limit for PolicyAssignment</span></button>
<div class="content">
    <table id= "$tableId" class="summaryTable">
        <thead>
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
        </thead>
        <tbody
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
        </tbody>
    </table>
</div>
<script>
    var tfConfig4$tableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
        btn_reset: true,
        highlight_keywords: true,
        alternate_rows: true,
        auto_filter: {
            delay: 1100 //milliseconds
        },
        no_results_message: true,
        col_types: [
            'string',
            'string',
            'string'
        ],
        extensions: [{
            name: 'sort'
        }]
    };
    var tf = new TableFilter('$tableId', tfConfig4$tableId);
    tf.init();
</script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicyAssignments | measure-object).count) Management Groups approaching Limit for PolicyAssignment</span></p>
"@
}
#endregion SUMMARYMgsapproachingLimitsPolicyAssignments

#region SUMMARYMgsapproachingLimitsPolicyScope
$mgsApproachingLimitPolicyScope = (($policyBaseQuery | where-object { "" -eq $_.SubscriptionId -and $_.PolicyDefinitionsScopedCount -gt 0 -and (($_.PolicyDefinitionsScopedCount -gt ($_.PolicyDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, MgName, PolicyDefinitionsScopedCount, PolicyDefinitionsScopedLimit -Unique)
if (($mgsApproachingLimitPolicyScope | measure-object).count -gt 0){
    $tfCount = ($mgsApproachingLimitPolicyScope | measure-object).count
    
    $tableId = "SummaryTable_MgsapproachingLimitsPolicyScope"
$script:html += @"
<button type="button" class="collapsible" id="SUMMARY_MgsapproachingLimitsPolicyScope"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicyScope | measure-object).count) Management Groups approaching Limit for Policy Scope</span></button>
<div class="content">
    <table id="$tableId" class="summaryTable">
        <thead>
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
        </thead>
        <tbody>
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
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$($mgsApproachingLimitPolicyScope.count) Management Groups approaching Limit for Policy Scope</span></p>
"@
}
#endregion SUMMARYMgsapproachingLimitsPolicyScope

#region SUMMARYMgsapproachingLimitsPolicySetScope
$mgsApproachingLimitPolicySetScope = (($policyBaseQuery | where-object { "" -eq $_.SubscriptionId -and $_.PolicySetDefinitionsScopedCount -gt 0 -and  (($_.PolicySetDefinitionsScopedCount -gt ($_.PolicySetDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, MgName, PolicySetDefinitionsScopedCount, PolicySetDefinitionsScopedLimit -Unique)
if ($mgsApproachingLimitPolicySetScope.count -gt 0){
    $tfCount = ($mgsApproachingLimitPolicySetScope | measure-object).count
    
    $tableId = "SummaryTable_MgsapproachingLimitsPolicySetScope"
$script:html += @"
<button type="button" class="collapsible" id="SUMMARY_MgsapproachingLimitsPolicySetScope"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicySetScope | measure-object).count) Management Groups approaching Limit for PolicySet Scope</span></button>
<div class="content">
    <table id="$tableId" class="summaryTable">
        <thead>
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
        </thead>
        <tbody>
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
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicySetScope | measure-object).count) Management Groups approaching Limit for PolicySet Scope</span></p>
"@
}
#endregion SUMMARYMgsapproachingLimitsPolicySetScope

#region SUMMARYMgsapproachingLimitsRoleAssignment
$mgsApproachingRoleAssignmentLimit = $rbacBaseQuery | Where-Object { "" -eq $_.SubscriptionId -and $_.RoleAssignmentsCount -gt ($_.RoleAssignmentsLimit * $LimitCriticalPercentage / 100)} | Sort-Object -Property MgId -Unique | select-object -Property MgId, MgName, RoleAssignmentsCount, RoleAssignmentsLimit
if (($mgsApproachingRoleAssignmentLimit | measure-object).count -gt 0){
    $tfCount = ($mgsApproachingRoleAssignmentLimit | measure-object).count
    $tableId = "SummaryTable_MgsapproachingLimitsRoleAssignment"
$script:html += @"
<button type="button" class="collapsible" id="SUMMARY_MgsapproachingLimitsRoleAssignment"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingRoleAssignmentLimit | measure-object).count) Management Groups approaching Limit for RoleAssignment</span></button>
<div class="content">
    <table id= "$tableId" class="summaryTable">
        <thead>
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
        </thead>
        <tbody>
"@
    foreach ($mgApproachingRoleAssignmentLimit in $mgsApproachingRoleAssignmentLimit){
$script:html += @"
            <tr>
                <td>
                    <span class="valignMiddle">$($mgApproachingRoleAssignmentLimit.MgName)</span>
                </td>
                <td>
                    <span class="valignMiddle"><a class="internallink" href="#table_$($mgApproachingRoleAssignmentLimit.MgId)">$($mgApproachingRoleAssignmentLimit.MgId)</a></span>
                </td>
                <td>
                    $($mgApproachingRoleAssignmentLimit.RoleAssignmentsCount)/$($mgApproachingRoleAssignmentLimit.RoleAssignmentsLimit)
                </td>
            </tr>
"@
    }
$script:html += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($mgApproachingRoleAssignmentLimit | measure-object).count) Management Groups approaching Limit for RoleAssignment</span></p>
"@
}
#endregion SUMMARYMgsapproachingLimitsRoleAssignment


#region SUMMARYSubs
$script:html += @"
    <hr>
"@
$summarySubscriptions = $subscriptionBaseQuery | Select-Object -Property Subscription, SubscriptionId, MgId, SubscriptionQuotaId, SubscriptionState -Unique | Sort-Object -Property Subscription
if (($summarySubscriptions | measure-object).count -gt 0){
    $tfCount = ($summarySubscriptions | measure-object).count
    
    $tableId = "SummaryTable_subs"
$script:html += @"
    <button type="button" class="collapsible" id="SUMMARY_Subs"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($summarySubscriptions | measure-object).count) Subscriptions</span></button>
    <div class="content">
        <table id="$tableId" class="summaryTable">
            <thead>
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
                        Tags
                    </th>
                    <th>
                        Path
                    </th>
                </tr>
            </thead>
            <tbody>
"@
    foreach ($summarySubscription in $summarySubscriptions){
        createMgPathSub -subid $summarySubscription.subscriptionId
        [array]::Reverse($script:submgPathArray)
        $subPath = $script:submgPathArray -join "/"

        $subscriptionTagsArray = @()
        $subscriptionTagsArray += foreach ($tag in ($htSubscriptionTags).($summarySubscription.subscriptionId).keys) {
            write-output "'$($tag)':'$(($htSubscriptionTags).$($summarySubscription.subscriptionId).$tag)'"
        }

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
                        $(($subscriptionTagsArray | sort-object) -join "$CsvDelimiterOpposite ")
                    </td>
                    <td>
                        <a href="#hierarchySub_$($summarySubscription.MgId)"><i class="fa fa-eye" aria-hidden="true"></i></a> $subPath
                    </td>
                </tr>
"@
    }
$script:html += @"
            </tbody>
        </table>
    </div>

    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string',
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>

"@
    }
    else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$subscount Subscriptions</span></p>
"@
}
#endregion SUMMARYSubs

#region SUMMARYOutOfScopeSubscriptions
$outOfScopeSubscriptionsCount = ($htOutOfScopeSubscriptions.keys | Measure-Object).Count
if ($outOfScopeSubscriptionsCount -gt 0){
    $tfCount = $outOfScopeSubscriptionsCount
    $tableId = "SummaryTable_outOfScopeSubscriptions"
$script:html += @"
    <button type="button" class="collapsible" id="summary_outOfScopeSubscriptions"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$outOfScopeSubscriptionsCount Subscriptions out-of-scope</span></button>
    <div class="content">

        <table id="$tableId" class="summaryTable">
            <thead>
                <tr>
                    <th>
                        Subscription Name
                    </th>
                    <th>
                        Subscription Id
                    </th>
                    <th>
                        out-of-scope reason
                    </th>
                    <th>
                        ManagementGroup
                    </th>
                </tr>
            </thead>
            <tbody>
"@
    foreach ($outOfScopeSubscription in $htOutOfScopeSubscriptions.keys){
        
$script:html += @"
                <tr>
                    <td>
                        $(($htOutOfScopeSubscriptions).($outOfScopeSubscription).SubscriptionName)
                    </td>
                    <td>
                        $(($htOutOfScopeSubscriptions).($outOfScopeSubscription).SubscriptionId)
                    </td>
                    <td>
                        $(($htOutOfScopeSubscriptions).($outOfScopeSubscription).outOfScopeReason)
                    </td>
                    <td>
                        <a href="#hierarchy_$(($htOutOfScopeSubscriptions).($outOfScopeSubscription).ManagementGroupId)"><i class="fa fa-eye" aria-hidden="true"></i></a> $(($htOutOfScopeSubscriptions).($outOfScopeSubscription).ManagementGroupName) ($(($htOutOfScopeSubscriptions).($outOfScopeSubscription).ManagementGroupId))
                    </td>
                </tr>
"@ 
    }
$script:html += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
            
"@      
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$outOfScopeSubscriptionsCount Subscriptions out-of-scope</span></p>
"@
}
#endregion SUMMARYOutOfScopeSubscriptions

#region SUMMARYResources
if (($resourcesAll | Measure-Object).count -gt 0){
    $tfCount = ($resourcesAll | Measure-Object).count
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
        $tfCount = ($resourcesResourceTypeCount | measure-object).count
        
        $tableId = "SummaryTable_resources"
$script:html += @"
<button type="button" class="collapsible" id="summary_resources"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$resourcesResourceTypeCount ResourceTypes ($resourcesTotal Resources) in $resourcesLocationCount Locations ($scopeNamingSummary)</span>
</button>
<div class="content">
    <table id="$tableId" class="summaryTable">
        <thead>
            <tr>
                <th>
                    ResourceType
                </th>
                <th>
                    Location
                </th>
                <th>
                    Resource Count
                </th>
            </tr>
        </thead>
        <tbody>
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
        </tbody>
    </table>
</div>
<script>
    var tfConfig4$tableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
        btn_reset: true,
        highlight_keywords: true,
        alternate_rows: true,
        auto_filter: {
            delay: 1100 //milliseconds
        },
        no_results_message: true,
        col_types: [
            'string',
            'string',
            'number'
        ],
        extensions: [{
            name: 'sort'
        }]
    };
    var tf = new TableFilter('$tableId', tfConfig4$tableId);
    tf.init();
</script>
"@
    }
    else{
$script:html += @"
        <p><i class="fa fa-ban" aria-hidden="true"></i> $resourcesResourceTypeCount ResourceTypes</p>
"@
    }

}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> 0 ResourceTypes</p>
"@
}
#endregion SUMMARYResources

#region SUMMARYResourcesDiagnosticsCapable
$resourceTypesDiagnosticsArraySorted = $resourceTypesDiagnosticsArray | Sort-Object -Property ResourceType, ResourceCount, Metrics, Logs, LogCategories
$resourceTypesDiagnosticsArraySortedCount = ($resourceTypesDiagnosticsArraySorted | measure-object).count
$resourceTypesDiagnosticsMetricsTrueCount = ($resourceTypesDiagnosticsArray | Where-Object { $_.Metrics -eq $True } | Measure-Object).count
$resourceTypesDiagnosticsLogsTrueCount = ($resourceTypesDiagnosticsArray | Where-Object { $_.Logs -eq $True } | Measure-Object).count
$resourceTypesDiagnosticsMetricsLogsTrueCount = ($resourceTypesDiagnosticsArray | Where-Object { $_.Metrics -eq $True -or $_.Logs -eq $True } | Measure-Object).count
if ($resourceTypesDiagnosticsArraySortedCount -gt 0){
    $tfCount = $resourceTypesDiagnosticsArraySortedCount
    
    $tableId = "SummaryTable_ResourcesDiagnosticsCapable"
$script:html += @"
<button type="button" class="collapsible" id="SUMMARY_ResourcesDiagnosticsCapable"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$resourceTypesDiagnosticsMetricsLogsTrueCount/$resourceTypesDiagnosticsArraySortedCount ResourceTypes Diagnostics capable ($resourceTypesDiagnosticsMetricsTrueCount Metrics, $resourceTypesDiagnosticsLogsTrueCount Logs)</span></button>
<div class="content">
    <table id= "$tableId" class="summaryTable">
        <thead>
            <tr>
                <th>
                    ResourceType
                </th>
                <th>
                    Resource Count
                </th>
                <th>
                    Diagnostics capable
                </th>
                <th>
                    Metrics
                </th>
                <th>
                    Logs
                </th>
                <th>
                    LogCategories
                </th>
            </tr>
        </thead>
        <tbody
"@
    foreach ($resourceType in $resourceTypesDiagnosticsArraySorted){
        if ($resourceType.Metrics -eq $true -or $resourceType.Logs -eq $true){
            $diagnosticsCapable = $true
        }
        else{
            $diagnosticsCapable = $false
        }
$script:html += @"
            <tr>
                <td>
                    $($resourceType.ResourceType)
                </td>
                <td>
                    $($resourceType.ResourceCount)
                </td>
                <td>
                    $diagnosticsCapable
                </td>
                <td>
                    $($resourceType.Metrics)
                </td>
                <td>
                    $($resourceType.Logs)
                </td>
                <td>
                    $($resourceType.LogCategories -join "$CsvDelimiterOpposite ")
                </td>
            </tr>
"@
    }
$script:html += @"
        </tbody>
    </table>
</div>
<script>
    var tfConfig4$tableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
        btn_reset: true,
        highlight_keywords: true,
        alternate_rows: true,
        auto_filter: {
            delay: 1100 //milliseconds
        },
        no_results_message: true,
        col_2: 'select',
        col_types: [
            'string',
            'number',
            'select',
            'string',
            'string',
            'string'
        ],
        extensions: [{
            name: 'sort'
        }]
    };
    var tf = new TableFilter('$tableId', tfConfig4$tableId);
    tf.init();
</script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($resourceTypesDiagnosticsMetricsLogsTrueCount | measure-object).count) Management Groups approaching Limit for PolicyAssignment</span></p>
"@
}
#endregion SUMMARYResourcesDiagnosticsCapable

#region SUMMARYDiagnosticsPolicyLifecycle
if ($tenantCustomPoliciesCount -gt 0) {
    $policiesThatDefineDiagnosticsCount = (($htCacheDefinitions).policy.keys | Where-Object {
        ($htCacheDefinitions).policy.($_).Type -eq "custom" -and
        ($htCacheDefinitions).policy.($_).json.properties.policyrule.then.details.type -eq "Microsoft.Insights/diagnosticSettings" -and
        ($htCacheDefinitions).policy.($_).json.properties.policyrule.then.details.deployment.properties.template.resources.type -match "/providers/diagnosticSettings"
    } | Measure-Object).count
    if ($policiesThatDefineDiagnosticsCount -gt 0){
        $diagnosticsPolicyAnalysis = @()
        foreach ($policy in ($htCacheDefinitions).policy.keys | Where-Object {
                ($htCacheDefinitions).policy.($_).Type -eq "custom" -and
                ($htCacheDefinitions).policy.($_).json.properties.policyrule.then.details.type -eq "Microsoft.Insights/diagnosticSettings" -and
                ($htCacheDefinitions).policy.($_).json.properties.policyrule.then.details.deployment.properties.template.resources.type -match "/providers/diagnosticSettings"
            }) {
            #($htCacheDefinitions).policy.($policy).Id
            if (
                (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | where-object { $_.type -match "/providers/diagnosticSettings" }).properties.workspaceId -or
                (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | where-object { $_.type -match "/providers/diagnosticSettings" }).properties.eventHubAuthorizationRuleId -or
                (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | where-object { $_.type -match "/providers/diagnosticSettings" }).properties.storageAccountId
            ) {
                if ( (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | where-object { $_.type -match "/providers/diagnosticSettings" }).properties.workspaceId) {
                    $diagnosticsDestination = "LA"
                }
                if ( (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | where-object { $_.type -match "/providers/diagnosticSettings" }).properties.eventHubAuthorizationRuleId) {
                    $diagnosticsDestination = "EH"
                }
                if ( (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | where-object { $_.type -match "/providers/diagnosticSettings" }).properties.storageAccountId) {
                    $diagnosticsDestination = "SA"
                }

                #write-host $diagnosticsDestination
                if ( (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | where-object { $_.type -match "/providers/diagnosticSettings" }).properties.logs ) {
                    $diagnosticsLogCategoriesCoveredByPolicy = (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | where-object { $_.type -match "/providers/diagnosticSettings" }).properties.logs
                    $resourceType = ( (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | where-object { $_.type -match "/providers/diagnosticSettings" }).type -replace "/providers/diagnosticSettings")
                    $resourceTypeCountFromResourceTypesSummarizedArray = ($resourceTypesSummarizedArray | Where-Object { $_.ResourceType -eq $resourceType }).ResourceCount
                    $supportedLogs = $resourceTypesDiagnosticsArray | where-object { $_.ResourceType -eq ( (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | where-object { $_.type -match "/providers/diagnosticSettings" }).type -replace "/providers/diagnosticSettings") }
                    if (($supportedLogs | Measure-Object).count -gt 0) {
                        $status = "AzGovViz detected the resourceType"
                        $diagnosticsLogCategoriesSupported = $supportedLogs.LogCategories
                        $logsSupported = "yes"
                        $actionItems = @()
                        foreach ($supportedLogCategory in $supportedLogs.LogCategories) {
                            if (-not $diagnosticsLogCategoriesCoveredByPolicy.category.contains($supportedLogCategory)) {
                                $actionItems += $supportedLogCategory
                            }
                        }
                        if (($actionItems | Measure-Object).count -gt 0) {
                            $diagnosticsLogCategoriesNotCoveredByPolicy = $actionItems
                            $recommendation = "review the policy and add the missing categories as required"
                        }
                        else {
                            $diagnosticsLogCategoriesNotCoveredByPolicy = "all OK"
                            $recommendation = "no recommendation"
                        }
                    }
                    else {
                        $status = "AzGovViz did not detect the resourceType"
                        $diagnosticsLogCategoriesSupported = "n/a"
                        $diagnosticsLogCategoriesNotCoveredByPolicy = "n/a"
                        $recommendation = "no recommendation as this resourceType seems not existing"
                        $logsSupported = "unknown"
                    }

                    $policyHasPolicyAssignments = $policyBaseQuery | where-object { $_.PolicyDefinitionIdGuid -eq $policy } | sort-object -property PolicyDefinitionIdGuid, PolicyAssignmentId -unique
                    $policyHasPolicyAssignmentCount = ($policyHasPolicyAssignments | Measure-Object).count
                    if ($policyHasPolicyAssignmentCount -gt 0) {
                        $policyAssignmentsArray = @()
                        $policyAssignmentsArray += foreach ($policyAssignment in $policyHasPolicyAssignments) {
                            "$($policyAssignment.PolicyAssignmentId) ($($policyAssignment.PolicyAssignmentDisplayName))"
                        }
                        $policyAssignmentsCollCount = ($policyAssignmentsArray | Measure-Object).count
                        #$policyAssignments = "$policyAssignmentsCount [$($policyAssignmentsArray -join "$CsvDelimiterOpposite ")]"
                        $policyAssignmentsColl = $policyAssignmentsCollCount
                    }
                    else {
                        $policyAssignmentsColl = 0
                    }

                    #PolicyUsedinPolicySet
                    $policySetAssignmentsColl = 0
                    $policyUsedinPolicySets = "n/a"
                    if (($htCachePoliciesUsedInPolicySets).(($htCacheDefinitions).policy.($policy).Id)) {
                        $policyUsedinPolicySets = ($htCachePoliciesUsedInPolicySets).(($htCacheDefinitions).policy.($policy).Id).policySetId
                        $policyUsedinPolicySetsCount = (($htCachePoliciesUsedInPolicySets).(($htCacheDefinitions).policy.($policy).Id).policySetId | Measure-Object).count

                        if ($policyUsedinPolicySetsCount -gt 0) {
                            $policyUsedinPolicySetsArray = @()
                            $policySetAssignmentsArray = @()
                            foreach ($policySetsWherePolicyIsUsed in $policyUsedinPolicySets) {
                                $policyUsedinPolicySetsArray += "[$policySetsWherePolicyIsUsed ($(($htCacheDefinitions).policySet.($policySetsWherePolicyIsUsed).DisplayName))]"

                                #PolicySetHasAssignments
                                $policySetAssignments = ($htCacheAssignments).policy.keys | where-object { ($htCacheAssignments).policy.($_).properties.PolicyDefinitionId -eq ($htCacheDefinitions).policySet.($policySetsWherePolicyIsUsed).PolicyDefinitionId }
                                $policySetAssignmentsCount = ($policySetAssignments | measure-object).count
                                if ($policySetAssignmentsCount -gt 0) {
                                    $policySetAssignmentsArray += foreach ($policySetAssignment in $policySetAssignments) {
                                        "$(($htCacheAssignments).policy.($policySetAssignment).PolicyAssignmentId) ($(($htCacheAssignments).policy.($policySetAssignment).properties.DisplayName))"
                                    }
                                    $policySetAssignmentsCollCount = ($policySetAssignmentsArray | Measure-Object).Count
                                    #$policySetAssignmentsColl = "$policySetAssignmentsCollCount [$($policySetAssignmentsArray -join "$CsvDelimiterOpposite ")]"
                                    $policySetAssignmentsColl = $policySetAssignmentsCollCount
                                }
                            }
                            $policyUsedinPolicySetsCount = ($policyUsedinPolicySetsArray | Measure-Object).count
                            #$policyUsedinPolicySets = "$policyUsedinPolicySetsCount $($policyUsedinPolicySetsArray -join "$CsvDelimiterOpposite ")"
                            $policyUsedinPolicySets = $policyUsedinPolicySetsCount
                        }
                        else {
                            $policyUsedinPolicySets = "n/a"
                        }     
                    }

                    if ($recommendation -eq "review the policy and add the missing categories as required"){
                        if ($policyAssignmentsColl -gt 0 -or $policySetAssignmentsColl -gt 0){
                            $priority = "1-High"
                        }
                        else{
                            $priority = "3-MediumLow"
                        }
                    }
                    else{
                        $priority = "4-Low"
                    }

                    $roleDefinitionIdsArray = @()
                    $roleDefinitionIdsArray += foreach ($roleDefinitionId in ($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.roleDefinitionIds){
                        "$(($htCacheDefinitions).role.($roleDefinitionId -replace ".*/").Name) ($($roleDefinitionId -replace ".*/"))"
                    }

                    $object = New-Object -TypeName PSObject -Property @{
                        'Priority'                    = $priority;
                        'PolicyId'                    = ($htCacheDefinitions).policy.($policy).Id;
                        'PolicyCategory'              = ($htCacheDefinitions).policy.($policy).Category;
                        'PolicyName'                  = ($htCacheDefinitions).policy.($policy).DisplayName;
                        'PolicyDeploysRoles'          = $roleDefinitionIdsArray -join "$CsvDelimiterOpposite ";
                        'PolicyForResourceTypeExists' = $true;
                        'ResourceType'                = $resourceType;
                        'ResourceTypeCount'           = $resourceTypeCountFromResourceTypesSummarizedArray;
                        'Status'                      = $status;
                        'LogsSupported'               = $logsSupported;
                        'LogCategoriesInPolicy'       = ($diagnosticsLogCategoriesCoveredByPolicy.category | Sort-Object) -join "$CsvDelimiterOpposite ";
                        'LogCategoriesSupported'      = ($diagnosticsLogCategoriesSupported | Sort-Object) -join "$CsvDelimiterOpposite ";
                        'LogCategoriesDelta'          = ($diagnosticsLogCategoriesNotCoveredByPolicy | Sort-Object) -join "$CsvDelimiterOpposite ";
                        'Recommendation'              = $recommendation;
                        'DiagnosticsTargetType'       = $diagnosticsDestination;
                        'PolicyAssignments'           = $policyAssignmentsColl;
                        'PolicyUsedInPolicySet'       = $policyUsedinPolicySets;
                        'PolicySetAssignments'        = $policySetAssignmentsColl;

                    }
                    $diagnosticsPolicyAnalysis += $object
                } 
            }
            else {
                write-host "DiagnosticsLifeCycle: something unexpected - not EH, LA, SA"
            }
        }

        #where no Policy exists
        foreach ($resourceTypeDiagnosticsCapable in $resourceTypesDiagnosticsArray | Where-Object { $_.Logs -eq $true }) {
            if (-not($diagnosticsPolicyAnalysis.ResourceType).ToLower().Contains( ($resourceTypeDiagnosticsCapable.ResourceType).ToLower() )) {
                $supportedLogs = ($resourceTypesDiagnosticsArray | where-object { $_.ResourceType -eq $resourceTypeDiagnosticsCapable.ResourceType }).LogCategories
                $logsSupported = "yes"
                $resourceTypeCountFromResourceTypesSummarizedArray = ($resourceTypesSummarizedArray | Where-Object { $_.ResourceType -eq $resourceTypeDiagnosticsCapable.ResourceType }).ResourceCount
                $recommendation = "Create and assign a diagnostics policy for this ResourceType"
                $object = New-Object -TypeName PSObject -Property @{
                    'Priority'                    = "2-Medium";
                    'PolicyId'                    = "n/a";
                    'PolicyCategory'              = "n/a";
                    'PolicyName'                  = "n/a";
                    'PolicyDeploysRoles'          = "n/a";
                    'ResourceType'                = $resourceTypeDiagnosticsCapable.ResourceType;
                    'ResourceTypeCount'           = $resourceTypeCountFromResourceTypesSummarizedArray;
                    'Status'                      = "n/a";
                    'LogsSupported'               = $logsSupported;
                    'LogCategoriesInPolicy'       = "n/a";
                    'LogCategoriesSupported'      = $supportedLogs -join "$CsvDelimiterOpposite ";
                    'LogCategoriesDelta'          = "n/a";
                    'Recommendation'              = $recommendation;
                    'DiagnosticsTargetType'       = "n/a";
                    'PolicyForResourceTypeExists' = $false;
                    'PolicyAssignments'           = "n/a";
                    'PolicyUsedInPolicySet'       = "n/a";
                    'PolicySetAssignments'        = "n/a";
                }
                $diagnosticsPolicyAnalysis += $object
            }
        }
        $diagnosticsPolicyAnalysisCount = ($diagnosticsPolicyAnalysis | Measure-Object).count
    
if ($diagnosticsPolicyAnalysisCount -gt 0){
    $tfCount = $diagnosticsPolicyAnalysisCount
    
    $tableId = "SummaryTable_DiagnosticsLifecycle"
$script:html += @"
<button type="button" class="collapsible" id="Summary_DiagnosticsLifecycle"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Diagnostics Logs Findings</span></button>
<div class="content">
&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true" style="color:#FFB100;"></i> <b>Create Custom Policies for Azure ResourceTypes that support Diagnostics Logs and Metrics</b> <a class="externallink" href="https://github.com/JimGBritt/AzurePolicy/blob/master/AzureMonitor/Scripts/README.md#overview-of-create-azdiagpolicyps1" target="_blank">Create-AzDiagPolicy</a><br>
&nbsp;<i class="fa fa-windows" aria-hidden="true"></i> <b>Microsoft Docs</b> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-monitor/platform/resource-logs-categories" target="_blank">Supported categories for Azure Resource Logs</a>
<table id= "$tableId" class="summaryTable">
        <thead>
            <tr>
                <th>
                    Priority
                </th>
                <th>
                    Recommendation
                </th>
                <th>
                    ResourceType
                </th>
                <th>
                    Resource Count
                </th>
                <th>
                    Diagnostics capable
                </th>
                <th>
                    Policy Id
                </th>
                <th>
                    Policy Name
                </th>
                <th>
                    Policy deploys RoleDefinitionIds
                </th>              
                <th>
                    Target
                </th>
                <th>
                    Log Categories not covered
                </th>
                <th>
                    Policy Assignments
                </th>
                <th>
                    Policy used in PolicySet
                </th>
                <th>
                    PolicySet Assignments
                </th>
            </tr>
        </thead>
        <tbody
"@
    foreach ($diagnosticsFinding in $diagnosticsPolicyAnalysis | Sort-Object -property Priority, PolicyName){

$script:html += @"
            <tr>
                <td>
                    $($diagnosticsFinding.Priority)
                </td>
                <td>
                    $($diagnosticsFinding.Recommendation)
                </td>
                <td>
                    $($diagnosticsFinding.ResourceType)
                </td>
                <td>
                    $($diagnosticsFinding.ResourceTypeCount)
                </td>
                <td>
                    $($diagnosticsFinding.LogsSupported)
                </td>
                <td>
                    $($diagnosticsFinding.PolicyId)
                </td>
                <td>
                    $($diagnosticsFinding.PolicyName)
                </td>
                <td>
                    $($diagnosticsFinding.PolicyDeploysRoles)
                </td>
                <td>
                    $($diagnosticsFinding.DiagnosticsTargetType)
                </td>
                <td>
                    $($diagnosticsFinding.LogCategoriesDelta)
                </td>
                <td>
                    $($diagnosticsFinding.PolicyAssignments)
                </td>
                <td>
                    $($diagnosticsFinding.PolicyUsedInPolicySet)
                </td>
                <td>
                    $($diagnosticsFinding.PolicySetAssignments)
                </td>
            </tr>
"@
    }
$script:html += @"
        </tbody>
    </table>
</div>
<script>
    var tfConfig4$tableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10){
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100){
                $spectrum = "10, 30, 50, $tfCount"
            }
            if ($tfCount -gt 500){
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000){
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000){
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000){
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
        btn_reset: true,
        highlight_keywords: true,
        alternate_rows: true,
        auto_filter: {
            delay: 1100 //milliseconds
        },
        no_results_message: true,
        col_types: [
            'string',
            'string',
            'number',
            'string',
            'string',
            'string',
            'string',
            'string',
            'string',
            'number',
            'number',
            'number'
        ],
        extensions: [{
            name: 'sort'
        }]
    };
    var tf = new TableFilter('$tableId', tfConfig4$tableId);
    tf.init();
</script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No Diagnostics findings</span></p>
"@
}
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No Diagnostics Logs findings</span></p>
"@
}
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No Diagnostics Logs findings</span></p>
"@
}
#endregion SUMMARYDiagnosticsPolicyLifecycle

#region SUMMARYSubResourceProviders
if (($htResourceProvidersAll.Keys | Measure-Object).count -gt 0){
    $grped = $arrayResourceProvidersAll | sort-object -property namespace, registrationState | group-object namespace
    $htResProvSummary = @{ }
    foreach ($grp in $grped){
        $htResProvSummary.($grp.name) = @{ }
        $regstates = ($grp.group | sort-object -property registrationState -unique | select-object registrationState).registrationstate
        foreach ($regstate in $regstates){
            $htResProvSummary.($grp.name).$regstate = ($grp.group | where-object { $_.registrationstate -eq $regstate} | measure-object).count
        }
    }
    $providerSummary = @()
    foreach ($provider in $htResProvSummary.keys){
        if ($htResProvSummary.$provider.registered){
            $registered = $htResProvSummary.$provider.registered
        }
        else{
            $registered = "0"
        }

        if ($htResProvSummary.$provider.registering){
            $registering = $htResProvSummary.$provider.registering
        }
        else{
            $registering = "0"
        }

        if ($htResProvSummary.$provider.notregistered){
            $notregistered = $htResProvSummary.$provider.notregistered
        }
        else{
            $notregistered = "0"
        }

        if ($htResProvSummary.$provider.unregistering){
            $unregistering = $htResProvSummary.$provider.unregistering
        }
        else{
            $unregistering = "0"
        }

        $object = New-Object -TypeName PSObject -Property @{'Provider' = $provider; 'Registered'= $registered; 'NotRegistered'= $notregistered; 'Registering'= $registering; 'Unregistering'= $unregistering }
        $providerSummary += $object
    }

    $uniqueNamespaces = $arrayResourceProvidersAll | Sort-Object -Property namespace -Unique
    $uniqueNamespacesCount = ($uniqueNamespaces | Measure-Object).count
    $uniqueNamespaceRegistrationState = $arrayResourceProvidersAll | Sort-Object -Property namespace, registrationState -Unique
    $providersRegistered = $uniqueNamespaceRegistrationState | Where-Object { $_.registrationState -eq "registered" -or $_.registrationState -eq "registering"} | select-object -property namespace | Sort-Object namespace -Unique
    $providersRegisteredCount = ($providersRegistered | Measure-Object).count

    $providersNotRegisteredUniqueCount = 0 
    foreach ($uniqueNamespace in $uniqueNamespaces){
        if (-not $providersRegistered.namespace.contains($uniqueNamespace.namespace)){
            $providersNotRegisteredUniqueCount++
        }
    }
    $tfCount = $uniqueNamespacesCount
    
    $tableId = "SummaryTable_SubResourceProviders"
$script:html += @"
    <button type="button" class="collapsible" id="SUMMARY_SubResourceProviders"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Providers Total: $uniqueNamespacesCount Registered/Registering: $providersRegisteredCount NotRegistered/Unregistering: $providersNotRegisteredUniqueCount</span></button>
    <div class="content">

        <table id="$tableId" class="summaryTable">
            <thead>
                <tr>
                    <th>
                        Provider
                    </th>
                    <th>
                        Registered
                    </th>
                    <th>
                        Registering
                    </th>
                    <th>
                        NotRegistered
                    </th>
                    <th>
                        Unregistering
                    </th>
                </tr>
            </thead>
            <tbody>
"@
    foreach ($provider in ($providerSummary | Sort-Object -Property Provider)){
$script:html += @"
                <tr>
                    <td>
                        $($provider.Provider)
                    </td>
                    <td>
                        $($provider.Registered)
                    </td>
                    <td>
                        $($provider.Registering)
                    </td>
                    <td>
                        $($provider.NotRegistered)
                    </td>
                    <td>
                        $($provider.Unregistering)
                    </td>
                </tr>
"@ 
        
    }
$script:html += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
            
"@      
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            }, 
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'number',
                'number',
                'number',
                'number'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($htResourceProvidersAll.Keys | Measure-Object).count) Resource Providers</span></p>
"@
}
#endregion SUMMARYSubResourceProviders

#region SUMMARYSubResourceProvidersDetailed
if (($htResourceProvidersAll.Keys | Measure-Object).count -gt 0){
    $tfCount = ($arrayResourceProvidersAll | Measure-Object).Count
    $tableId = "SummaryTable_SubResourceProvidersDetailed"
$script:html += @"
    <button type="button" class="collapsible" id="SUMMARY_SubResourceProvidersDetailed"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Providers Detailed</span></button>
    <div class="content">

        <table id="$tableId" class="summaryTable">
            <thead>
                <tr>
                    <th>
                        Mg Name
                    </th>
                    <th>
                        Mg Id
                    </th>
                    <th>
                        Subscription Name
                    </th>
                    <th>
                        Subscription Id
                    </th>
                    <th>
                        Provider
                    </th>
                    <th>
                        State
                    </th>
                </tr>
            </thead>
            <tbody>
"@
    foreach ($subscriptionResProv in $htResourceProvidersAll.Keys){
        $subscriptionResProvDetails = $mgAndSubBaseQuery | Where-Object { $_.SubscriptionId -eq $subscriptionResProv} | sort-object -Property SubscriptionId -Unique
        foreach ($provider in ($htResourceProvidersAll).($subscriptionResProv).Providers){
$script:html += @"
                <tr>
                    <td>
                        $($subscriptionResProvDetails.MgId)
                    </td>
                    <td>
                        $($subscriptionResProvDetails.MgName)
                    </td>
                    <td>
                        $($subscriptionResProvDetails.Subscription)
                    </td>
                    <td>
                        $($subscriptionResProv)
                    </td>
                    <td>
                        $($provider.namespace)
                    </td>
                    <td>
                        $($provider.registrationState)
                    </td>
                </tr>
"@ 
        }
    }
$script:html += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
            
"@      
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            }, 
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_5: 'select',
            col_types: [
                'string',
                'string',
                'string',
                'string',
                'string',
                'select'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($htResourceProvidersAll.Keys | Measure-Object).count) Resource Providers</span></p>
"@
}
#endregion SUMMARYSubResourceProvidersDetailed

#region SUMMARYSubsapproachingLimitsResourceGroups
$subscriptionsApproachingLimitFromResourceGroupsAll = $resourceGroupsAll | where-object { $_.count_ -gt ($LimitResourceGroups * ($LimitCriticalPercentage / 100)) }
if (($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count -gt 0){
    $tfCount = ($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count
    
    $tableId = "SummaryTable_SubsapproachingLimitsResourceGroups"
$script:html += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsResourceGroups"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count) Subscriptions approaching Limit for ResourceGroups</span></button>
<div class="content">
    <table id= "$tableId" class="summaryTable">
        <thead>
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
        </thead>
        <tbody>
"@
    foreach ($subscriptionApproachingLimitFromResourceGroupsAll in $subscriptionsApproachingLimitFromResourceGroupsAll){
        $subscriptionData = $mgAndSubBaseQuery | Where-Object { $_.SubscriptionId -eq $subscriptionApproachingLimitFromResourceGroupsAll.subscriptionId } | Get-Unique
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
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p"><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count) Subscriptions approaching Limit for ResourceGroups</span></p>
"@
}
#endregion SUMMARYSubsapproachingLimitsResourceGroups

#region SUMMARYSubsapproachingLimitsSubscriptionTags
$subscriptionsApproachingLimitTags = ($subscriptionBaseQuery | Select-Object -Property MgId, Subscription, SubscriptionId, SubscriptionTagsCount, SubscriptionTagsLimit -Unique | where-object { (($_.SubscriptionTagsCount -gt ($_.SubscriptionTagsLimit * ($LimitCriticalPercentage / 100)))) })
if (($subscriptionsApproachingLimitTags | measure-object).count -gt 0){
    $tfCount = ($subscriptionsApproachingLimitTags | measure-object).count
    $tableId = "SummaryTable_SubsapproachingLimitsSubscriptionTags"
$script:html += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsSubscriptionTags"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitTags | measure-object).count) Subscriptions approaching Limit for Tags</span></button>
<div class="content">
    <table id="$tableId" class="summaryTable">
        <thead>
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
        </thead>
        <tbody
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
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$($subscriptionsApproachingLimitTags.count) Subscriptions approaching Limit for Tags</span></p>
"@
}
#endregion SUMMARYSubsapproachingLimitsSubscriptionTags

#region SUMMARYSubsapproachingLimitsPolicyAssignments
$subscriptionsApproachingLimitPolicyAssignments =(($policyBaseQuery | where-object { "" -ne $_.SubscriptionId -and $_.PolicyAndPolicySetAssigmentAtScopeCount -gt 0 -and  (($_.PolicyAndPolicySetAssigmentAtScopeCount -gt ($_.PolicyAssigmentLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, Subscription, SubscriptionId, PolicyAssigmentAtScopeCount, PolicySetAssigmentAtScopeCount, PolicyAndPolicySetAssigmentAtScopeCount, PolicyAssigmentLimit -Unique)
if ($subscriptionsApproachingLimitPolicyAssignments.count -gt 0){
    $tfCount = ($subscriptionsApproachingLimitPolicyAssignments | measure-object).count
    $tableId = "SummaryTable_SubsapproachingLimitsPolicyAssignments"
$script:html += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsPolicyAssignments"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyAssignments | measure-object).count) Subscriptions approaching Limit for PolicyAssignment</span></button>
<div class="content">
    <table id="$tableId" class="summaryTable">
        <thead>
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
        </thead>
        <tbody>
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
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyAssignments | measure-object).count) Subscriptions approaching Limit for PolicyAssignment</span></p>
"@
}
#endregion SUMMARYSubsapproachingLimitsPolicyAssignments

#region SUMMARYSubsapproachingLimitsPolicyScope
$subscriptionsApproachingLimitPolicyScope = (($policyBaseQuery | where-object { "" -ne $_.SubscriptionId -and $_.PolicyDefinitionsScopedCount -gt 0 -and  (($_.PolicyDefinitionsScopedCount -gt ($_.PolicyDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, Subscription, SubscriptionId, PolicyDefinitionsScopedCount, PolicyDefinitionsScopedLimit -Unique)
if (($subscriptionsApproachingLimitPolicyScope | measure-object).count -gt 0){
    $tfCount = ($subscriptionsApproachingLimitPolicyScope | measure-object).count
    $tableId = "SummaryTable_SubsapproachingLimitsPolicyScope"
$script:html += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsPolicyScope"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyScope | measure-object).count) Subscriptions approaching Limit for Policy Scope</span></button>
<div class="content">
    <table id="$tableId" class="summaryTable">
        <thead>
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
        </thead>
        <tbody>
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
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$($subscriptionsApproachingLimitPolicyScope.count) Subscriptions approaching Limit for Policy Scope</span></p>
"@
}
#endregion SUMMARYSubsapproachingLimitsPolicyScope

#region SUMMARYSubsapproachingLimitsPolicySetScope
$subscriptionsApproachingLimitPolicySetScope = (($policyBaseQuery | where-object { "" -ne $_.SubscriptionId -and $_.PolicySetDefinitionsScopedCount -gt 0 -and  (($_.PolicySetDefinitionsScopedCount -gt ($_.PolicySetDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, Subscription, SubscriptionId, PolicySetDefinitionsScopedCount, PolicySetDefinitionsScopedLimit -Unique)
if ($subscriptionsApproachingLimitPolicySetScope.count -gt 0){
    $tfCount = ($subscriptionsApproachingLimitPolicySetScope | measure-object).count
    $tableId = "SummaryTable_SubsapproachingLimitsPolicySetScope"
$script:html += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsPolicySetScope"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyScope | measure-object).count) Subscriptions approaching Limit for PolicySet Scope</span></button>
<div class="content">
    <table id="$tableId" class="summaryTable">
        <thead>
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
        </thead>
        <tbody>
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
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyScope | measure-object).count) Subscriptions approaching Limit for PolicySet Scope</span></p>
"@
}
#endregion SUMMARYSubsapproachingLimitsPolicySetScope

#region SUMMARYSubsapproachingLimitsRoleAssignment
$subscriptionsApproachingRoleAssignmentLimit = $rbacBaseQuery | Where-Object { "" -ne $_.SubscriptionId -and $_.RoleAssignmentsCount -gt ($_.RoleAssignmentsLimit * $LimitCriticalPercentage / 100)} | Sort-Object -Property SubscriptionId -Unique | select-object -Property MgId, SubscriptionId, Subscription, RoleAssignmentsCount, RoleAssignmentsLimit
if (($subscriptionsApproachingRoleAssignmentLimit | measure-object).count -gt 0){
    $tfCount = ($subscriptionsApproachingRoleAssignmentLimit | measure-object).count
    $tableId = "SummaryTable_SubsapproachingLimitsRoleAssignment"
$script:html += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsRoleAssignment"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingRoleAssignmentLimit | measure-object).count) Subscriptions approaching Limit for RoleAssignment</span></button>
<div class="content">
    <table id= "$tableId" class="summaryTable">
        <thead>
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
        </thead>
        <tbody>
"@
    foreach ($subscriptionApproachingRoleAssignmentLimit in $subscriptionsApproachingRoleAssignmentLimit){
$script:html += @"
            <tr>
                <td>
                    <span class="valignMiddle">$($subscriptionApproachingRoleAssignmentLimit.subscription)</span>
                </td>
                <td>
                    <span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingRoleAssignmentLimit.MgId)">$($subscriptionApproachingRoleAssignmentLimit.subscriptionId)</a></span>
                </td>
                <td>
                    $($subscriptionApproachingRoleAssignmentLimit.RoleAssignmentsCount)/$($subscriptionApproachingRoleAssignmentLimit.RoleAssignmentsLimit)
                </td>
            </tr>
"@
    }
$script:html += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv3/tablefilter/', rows_counter: true,
"@
if ($tfCount -gt 10){
    $spectrum = "10, $tfCount"
    if ($tfCount -gt 100){
        $spectrum = "10, 30, 50, $tfCount"
    }
    if ($tfCount -gt 500){
        $spectrum = "10, 30, 50, 100, 250, $tfCount"
    }
    if ($tfCount -gt 1000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
    }
    if ($tfCount -gt 2000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
    }
    if ($tfCount -gt 3000){
        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
    }

$script:html += @"
            paging: {
                results_per_page: ['Records: ', [$spectrum]]
            },
            state: {
                types: ['local_storage'],
                filters: true,
                page_number: true,
                page_length: true,
                sort: true
            },
"@      
}
$script:html += @"
            btn_reset: true,
            highlight_keywords: true,
            alternate_rows: true,
            auto_filter: {
                delay: 1100 //milliseconds
            },
            no_results_message: true,
            col_types: [
                'string',
                'string',
                'string'
            ],
            extensions: [{
                name: 'sort'
            }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$script:html += @"
    <p"><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingRoleAssignmentLimit | measure-object).count) Subscriptions approaching Limit for RoleAssignment</span></p>
"@
}
#endregion SUMMARYSubsapproachingLimitsRoleAssignment

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

#run
Write-Host "Running AzGovViz for ManagementGroupId: '$ManagementGroupId'"
$startAzGovViz = get-date

#validation / check ManagementGroup Access
$selectedManagementGroupId = Get-AzManagementGroup -GroupName $ManagementGroupId -ErrorAction SilentlyContinue
if (-not $selectedManagementGroupId){
    Write-Host "Access test failed: ManagementGroupId '$ManagementGroupId' is not accessible. Make sure you have required permissions (RBAC: Reader) / check typ0"
    break
}
else{
    Write-Host "Access test passed: ManagementGroupId '$($selectedManagementGroupId.Name)' is accessible" 
}

if (($checkContext).Tenant.Id -ne $ManagementGroupId) {
    $mgSubPathTopMg = $selectedManagementGroupId.ParentName
    $getMgParentId = $selectedManagementGroupId.ParentName
    $getMgParentName = $selectedManagementGroupId.ParentDisplayName
    $mermaidprnts = "'$(($checkContext).Tenant.Id)',$getMgParentId"
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
    $uriTenantDetails = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)tenants?api-version=2020-01-01"
    $tenantDetailsResult = Invoke-RestMethod -Uri $uriTenantDetails -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
    if (($tenantDetailsResult.value | measure-object).count -gt 0) {
        $tenantDetails = $tenantDetailsResult.value | where-object { $_.tenantId -eq ($checkContext).Tenant.Id }
        $tenantDisplayName = $tenantDetails.displayName
        $tenantDefaultDomain = $tenantDetails.defaultDomain
        Write-Host "Tenant DisplayName: $tenantDisplayName"
    }
    else{
        Write-Host "something unexpected"
    }
}

if (-not $HierarchyTreeOnly) {

    if ($SubscriptionQuotaIdWhitelist -ne "undefined" -and $SubscriptionQuotaIdWhitelist -ne ""){
        $subscriptionQuotaIdWhitelistArray = [Array]($SubscriptionQuotaIdWhitelist).tostring().split("\")
        if (($subscriptionQuotaIdWhitelistArray | Measure-Object).count -gt 0){
            Write-Host "Subscription Whitelist enabled. AzGovViz will only process Subscriptions where QuotaId startswith one of the following strings:"
            Write-Host "$($subscriptionQuotaIdWhitelistArray -join ", ")"
            $subscriptionQuotaIdWhitelistMode = $true
        }
        else{
            Write-Host "Error: invalid Parameter Value for 'SubscriptionQuotaIdWhitelist'"
            break
        }
    }
    else{
        Write-Host "Subscription Whitelist disabled."
        $subscriptionQuotaIdWhitelistMode = $false
    }

    $startDefinitionsCaching = get-date
    Write-Host "Caching built-in data"

    #helper ht / collect results /save some time
    $htCacheDefinitions = @{ }
    ($htCacheDefinitions).policy = @{ }
    ($htCacheDefinitions).policySet = @{ }
    ($htCacheDefinitions).role = @{ }
    ($htCacheDefinitions).blueprint = @{ }
    $htCacheDefinitionsAsIs = @{ }
    ($htCacheDefinitionsAsIs).policy = @{ }
    $htCachePoliciesUsedInPolicySets = @{ }
    $htSubscriptionTags = @{ }
    $htCacheAssignments = @{ }
    ($htCacheAssignments).policy = @{ }
    ($htCacheAssignments).role = @{ }
    ($htCacheAssignments).blueprint = @{ }
    $htCachePolicyCompliance = @{ }
    ($htCachePolicyCompliance).mg = @{ }
    ($htCachePolicyCompliance).sub = @{ }
    $htOutOfScopeSubscriptions = @{ }

    $currentContextSubscriptionQuotaId = (Search-AzGraph -Subscription $checkContext.Subscription.Id -Query "resourcecontainers | where type == 'microsoft.resources/subscriptions' | project properties.subscriptionPolicies.quotaId").properties_subscriptionPolicies_quotaId
    if (-not $currentContextSubscriptionQuotaId){
        Write-Host "Bad Subscription context for Definition Caching (SubscriptionName: $($checkContext.Subscription.Name); SubscriptionId: $($checkContext.Subscription.Id); likely an AAD_ QuotaId"
        $alternativeSubscriptionIdForDefinitionCaching = (Search-AzGraph -Query "resourcecontainers | where type == 'microsoft.resources/subscriptions' | where properties.subscriptionPolicies.quotaId !startswith 'AAD_' | project properties.subscriptionPolicies.quotaId, subscriptionId" -first 1)
        Write-Host "Using other Subscription for Definition Caching (SubscriptionId: $($alternativeSubscriptionIdForDefinitionCaching.subscriptionId); QuotaId: $($alternativeSubscriptionIdForDefinitionCaching.properties_subscriptionPolicies_quotaId))"
        $subscriptionIdForDefinitionCaching = $alternativeSubscriptionIdForDefinitionCaching.subscriptionId
        #switch subscription context
        Select-AzSubscription -SubscriptionId $subscriptionIdForDefinitionCaching -ErrorAction Stop
    }
    else{
        Write-Host "OK Subscription context (QuotaId not 'AAD_*') for Definition Caching (SubscriptionId: $($checkContext.Subscription.Id); QuotaId: $currentContextSubscriptionQuotaId)"
        $subscriptionIdForDefinitionCaching = $checkContext.Subscription.Id
    }

    $uriPolicyDefinitionAPI = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
    $requestPolicyDefinitionAPI = Invoke-RestMethod -Uri $uriPolicyDefinitionAPI -Headers  @{"Authorization" = "Bearer $accesstoken" }
    $builtinPolicyDefinitions = $requestPolicyDefinitionAPI.value | Where-Object { $_.properties.policyType -eq "builtin" }

    foreach ($builtinPolicyDefinition in $builtinPolicyDefinitions) {
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name) = @{ }
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).Id = $builtinPolicyDefinition.name
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).DisplayName = $builtinPolicyDefinition.Properties.displayname
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).Type = $builtinPolicyDefinition.Properties.policyType
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).Category = $builtinPolicyDefinition.Properties.metadata.category
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).PolicyDefinitionId = $builtinPolicyDefinition.id
        if ($builtinPolicyDefinition.Properties.metadata.deprecated -eq $true){
            ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).Deprecated = $builtinPolicyDefinition.Properties.metadata.deprecated
        }
        else{
            ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).Deprecated = $false
        }
        #effects
        if ($builtinPolicyDefinition.properties.parameters.effect.defaultvalue) {
            ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).effectDefaultValue = $builtinPolicyDefinition.properties.parameters.effect.defaultvalue
            if ($builtinPolicyDefinition.properties.parameters.effect.allowedValues){
                ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).effectAllowedValue = $builtinPolicyDefinition.properties.parameters.effect.allowedValues -join ","
            }
            else{
                ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).effectAllowedValue = "n/a"
            }
            ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).effectFixedValue = "n/a"
        }
        else {
            if ($builtinPolicyDefinition.properties.parameters.policyEffect.defaultValue) {
                ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).effectDefaultValue = $builtinPolicyDefinition.properties.parameters.policyEffect.defaultvalue
                if ($builtinPolicyDefinition.properties.parameters.policyEffect.allowedValues){
                    ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).effectAllowedValue = $builtinPolicyDefinition.properties.parameters.policyEffect.allowedValues -join ","
                }
                else{
                    ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).effectAllowedValue = "n/a"
                }
                ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).effectFixedValue = "n/a"
            }
            else {
                ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).effectFixedValue = $builtinPolicyDefinition.Properties.policyRule.then.effect
                ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).effectDefaultValue = "n/a"
                ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).effectAllowedValue = "n/a"
            }
        }
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.name).json = $builtinPolicyDefinition

        #AsIs
        ($htCacheDefinitionsAsIs).policy.$($builtinPolicyDefinition.name) = @{ }
        ($htCacheDefinitionsAsIs).policy.$($builtinPolicyDefinition.name) = $builtinPolicyDefinition
    }

    $uriPolicySetDefinitionAPI = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"
    $requestPolicySetDefinitionAPI = Invoke-RestMethod -Uri $uriPolicySetDefinitionAPI -Headers  @{"Authorization" = "Bearer $accesstoken" }
    $builtinPolicySetDefinitions = $requestPolicySetDefinitionAPI.value | Where-Object { $_.properties.policyType -eq "builtin" }
    
    foreach ($builtinPolicySetDefinition in $builtinPolicySetDefinitions) {
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.name) = @{ }
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.name).Id = $builtinPolicySetDefinition.name
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.name).DisplayName = $builtinPolicySetDefinition.Properties.displayname
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.name).Type = $builtinPolicySetDefinition.Properties.policyType
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.name).Category = $builtinPolicySetDefinition.Properties.metadata.category
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.name).PolicyDefinitionId = $builtinPolicySetDefinition.id
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.name).PolicySetPolicyIds = $builtinPolicySetDefinition.properties.policydefinitions.policyDefinitionId
        if ($builtinPolicySetDefinition.Properties.metadata.deprecated -eq $true){
            ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.name).Deprecated = $builtinPolicySetDefinition.Properties.metadata.deprecated
        }
        else{
            ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.name).Deprecated = $false
        }
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.name).json = $builtinPolicySetDefinition
    }

    $roleDefinitions = Get-AzRoleDefinition -Scope "/subscriptions/$SubscriptionIdForDefinitionCaching" -ErrorAction Stop | where-object { $_.IsCustom -eq $false }
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
    Write-Host "Caching built-in data duration: $((NEW-TIMESPAN -Start $startDefinitionsCaching -End $endDefinitionsCaching).TotalSeconds) seconds"
}

Write-Host "Collecting custom data"
$startDataCollection = get-date

dataCollection -mgId $ManagementGroupId -hierarchyLevel $hierarchyLevel -mgParentId $getMgParentId -mgParentName $getMgParentName

$endDataCollection = get-date
Write-Host "Collecting custom data duration: $((NEW-TIMESPAN -Start $startDataCollection -End $endDataCollection).TotalMinutes) minutes"

if (-not $HierarchyTreeOnly){
    checkTokenLifetime
    Write-Host "Caching Resource data"
    $startResourceCaching = get-date
    $subscriptionIds = ($table | Where-Object { "" -ne $_.SubscriptionId} | select-Object SubscriptionId | Sort-Object -Property SubscriptionId -Unique).SubscriptionId
    $queryResources = "resources | project id, subscriptionId, location, type | summarize count() by subscriptionId, location, type"
    $queryResourceGroups = "resourcecontainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups' | project id, subscriptionId | summarize count() by subscriptionId"
    $resourcesAll = @()
    $resourceGroupsAll = @()
    $htResourceProvidersAll = @{ }
    $arrayResourceProvidersAll = @()
    foreach ($subscriptionId in $subscriptionIds){
        $resourcesAll += Search-AzGraph -Subscription $subscriptionId -Query $queryResources
        $resourceGroupsAll += Search-AzGraph -Subscription $subscriptionId -Query $queryResourceGroups
        ($htResourceProvidersAll).($subscriptionId) = @{ }
        $url = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($subscriptionId)/providers?api-version=2019-10-01"
        $resProvResult = Invoke-RestMethod -Uri $url -Headers @{"Authorization" = "Bearer $accesstoken" }
        ($htResourceProvidersAll).($subscriptionId).Providers = $resProvResult.value
        $arrayResourceProvidersAll += $resProvResult.value
    }

    $resourceTypesUnique = ($resourcesAll | select-object type -Unique).type
    $resourceTypesSummarizedArray = @()
    $resourcesTypeAllCountTotal = 0
    ($resourcesAll).count_ | ForEach-Object { $resourcesTypeAllCountTotal += $_ }
    foreach ($resourceTypeUnique in $resourceTypesUnique){
        $resourcesTypeCountTotal = 0
        ($resourcesAll | Where-Object { $_.type -eq $resourceTypeUnique }).count_ | ForEach-Object { $resourcesTypeCountTotal += $_ }
        $resourceTypesSummarizedObject = New-Object -TypeName PSObject -Property @{'ResourceType' = $resourceTypeUnique; 'ResourceCount' = $resourcesTypeCountTotal }
        $resourceTypesSummarizedArray += $resourceTypesSummarizedObject
    }

    $resourceTypesDiagnosticsArray = @()
    foreach ($resourcetype in $resourceTypesSummarizedArray.ResourceType) {
        $tryCounter = 0
        do{
            if ($tryCounter -gt 0){
                Start-Sleep -Seconds 2
            }
            $tryCounter++
            #write-Host "$resourcetype getting a resourceId: try #$tryCounter"
            $resource = Search-AzGraph -Query "where type =~ '$resourcetype' | project id" -First 1
        }
        until(($resource | Measure-Object).count -gt 0)

        $resourceCount = ($resourceTypesSummarizedArray | where-object { $_.Resourcetype -eq $resourcetype}).ResourceCount

        #taken from https://github.com/JimGBritt/AzurePolicy/tree/master/AzureMonitor/Scripts
        try {
            $Invalid = $false
            $LogCategories = @()
            $metrics = $false #initialize metrics flag to $false
            $logs = $false #initialize logs flag to $false

            $URI = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)$($resource.id)/providers/microsoft.insights/diagnosticSettingsCategories/?api-version=2017-05-01-preview"
            
            Try {
                $Status = Invoke-WebRequest -uri $URI -Headers @{"Authorization" = "Bearer $accesstoken" }
            }
            catch {
                $Invalid = $True
                $Logs = $False
                $Metrics = $False
                $ResponseJSON = ''
            }
            if (!($Invalid)) {
                $ResponseJSON = $Status.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
            }
        
            # If logs are supported or metrics on each resource, set value as $True
            If ($ResponseJSON) {                
                foreach ($R in $ResponseJSON.value) {
                    if ($R.properties.categoryType -eq "Metrics") {
                        $metrics = $true
                    }
                    if ($R.properties.categoryType -eq "Logs") {
                        $Logs = $true
                        $LogCategories += $r.name
                    }
                }
            }
        }
        catch { }
        finally {
            $resourceTypesDiagnosticsObject = New-Object -TypeName PSObject -Property @{'ResourceType' = $resourcetype; 'Metrics' = $metrics; 'Logs' = $logs; 'LogCategories' = $LogCategories; 'ResourceCount' = [int]$resourceCount }
            $resourceTypesDiagnosticsArray += $resourceTypesDiagnosticsObject
        }
    }

    foreach ($policySet in ($htCacheDefinitions).policySet.keys){
        $PolicySetPolicyIds = ($htCacheDefinitions).policySet.($policySet).PolicySetPolicyIds
        foreach ($PolicySetPolicyId in $PolicySetPolicyIds){
            if (($htCachePoliciesUsedInPolicySets).($PolicySetPolicyId -replace ".*/")){
                $policySetArray = ($htCachePoliciesUsedInPolicySets).($PolicySetPolicyId -replace ".*/").policySetId
                $policySetArray += ($htCacheDefinitions).policySet.($policySet).PolicyDefinitionId -replace ".*/"
                ($htCachePoliciesUsedInPolicySets).($PolicySetPolicyId -replace ".*/").PolicySetId = $policySetArray
            }
            else{
                ($htCachePoliciesUsedInPolicySets).($PolicySetPolicyId -replace ".*/") = @{ }
                ($htCachePoliciesUsedInPolicySets).($PolicySetPolicyId -replace ".*/").PolicyId = $PolicySetPolicyId -replace ".*/"
                ($htCachePoliciesUsedInPolicySets).($PolicySetPolicyId -replace ".*/").PolicySetId = [array]($htCacheDefinitions).policySet.($policySet).PolicyDefinitionId -replace ".*/"
            }
        }
    }
    
    $endResourceCaching = get-date
    Write-Host "Caching Resource data duration: $((NEW-TIMESPAN -Start $startResourceCaching -End $endResourceCaching).TotalSeconds) seconds"
    
    #summarizeDataCollectionResults
    $mgsDetails = (($table | where-object { "" -ne $_.mgId}) | Select-Object Level, MgId -Unique)
    $mgDepth = ($mgsDetails.Level | Measure-Object -maximum).Maximum
    $totalMgCount = ($mgsDetails | Measure-Object).count
    $totalSubCount = (($table | Where-Object { "" -ne $_.subscriptionId} | Select-Object -Property subscriptionId -Unique).SubscriptionId | Measure-Object).count
    $totalPolicyDefinitionsCustomCount = ((($htCacheDefinitions).policy.keys | where-object { ($htCacheDefinitions).policy.$_.Type -eq "Custom" }) | Measure-Object).count
    $totalPolicySetDefinitionsCustomCount = ((($htCacheDefinitions).policySet.keys | where-object { ($htCacheDefinitions).policySet.$_.Type -eq "Custom" }) | Measure-Object).count
    $totalRoleDefinitionsCustomCount = ((($htCacheDefinitions).role.keys | where-object { ($htCacheDefinitions).role.$_.IsCustom -eq $True }) | Measure-Object).count
    $totalBlueprintDefinitionsCount = ((($htCacheDefinitions).blueprint.keys) | Measure-Object).count
    $totalPolicyAssignmentsCount = (($htCacheAssignments).policy.keys | Measure-Object).count
    $totalRoleAssignmentsCount = (($htCacheAssignments).role.keys | Measure-Object).count
    $totalBlueprintAssignmentsCount = (($htCacheAssignments).blueprint.keys | Measure-Object).count
    $totalResourceTypesCount = ($resourceTypesDiagnosticsArray | Measure-Object).Count
    Write-Host "Total Management Groups: $totalMgCount (depth $mgDepth)"
    Write-Host "Total Subscriptions: $totalSubCount"
    Write-Host "Total Custom Policy Definitions: $totalPolicyDefinitionsCustomCount"
    Write-Host "Total Custom PolicySet Definitions: $totalPolicySetDefinitionsCustomCount"
    Write-Host "Total Custom Roles: $totalRoleDefinitionsCustomCount"
    Write-Host "Total Blueprint Definitions: $totalBlueprintDefinitionsCount"
    Write-Host "Total Policy Assignments: $totalPolicyAssignmentsCount"
    Write-Host "Total Role Assignments: $totalRoleAssignmentsCount"
    Write-Host "Total Blueprint Assignments: $totalBlueprintAssignmentsCount"
    Write-Host "Total Resources: $resourcesTypeAllCountTotal"
    Write-Host "Total Resource Types: $totalResourceTypesCount"    
}
#endregion dataCollection

#region createoutputs

#region BuildHTML

#testhelper
#$fileTimestamp = (get-date -format "yyyyMMddHHmmss")

$startBuildHTML = get-date
$html = $null

#preQueries
$mgAndSubBaseQuery = ($table | Select-Object -Property level, mgid, mgname, mgParentName, mgParentId, subscriptionId, subscription)
$parentMgNamex = ($mgAndSubBaseQuery | Where-Object { $_.MgParentId -eq $getMgParentId }).mgParentName | Get-Unique
$parentMgIdx = ($mgAndSubBaseQuery | Where-Object { $_.MgParentId -eq $getMgParentId }).mgParentId | Get-Unique
$ManagementGroupIdCaseSensitived = (($mgAndSubBaseQuery | Where-Object { $_.MgId -eq $ManagementGroupId }).mgId) | Get-Unique
$optimizedTableForPathQuery = ($mgAndSubBaseQuery | Select-Object -Property level, mgid, mgparentid, subscriptionId) | sort-object -Property level, mgid, mgname, mgparentId, mgparentName, subscriptionId, subscription -Unique
$subscriptionBaseQuery = $table | Where-Object { "" -ne $_.SubscriptionId }

if (-not $HierarchyTreeOnly) {
    $policyBaseQuery = $table | Where-Object { "" -ne $_.Policy } | Sort-Object -Property PolicyType, Policy | Select-Object -Property Level, Policy*, mgId, mgname, SubscriptionId, Subscription
    $policyPolicyBaseQuery = $policyBaseQuery | Where-Object { $_.PolicyVariant -eq "Policy" } | Select-Object -Property PolicyDefinitionIdGuid, PolicyAssignmentId
    $policyPolicySetBaseQuery = $policyBaseQuery | Where-Object { $_.PolicyVariant -eq "PolicySet" } | Select-Object -Property PolicyDefinitionIdGuid, PolicyAssignmentId
    $policyAssignmentIds = ($policyBaseQuery | sort-object -property PolicyAssignmentName, PolicyAssignmentId -Unique | Select-Object -Property PolicyAssignmentName, PolicyAssignmentId)

    $rbacBaseQuery = $table | Where-Object { "" -ne $_.RoleDefinitionName } | Sort-Object -Property RoleIsCustom, RoleDefinitionName | Select-Object -Property Level, Role*, mgId, MgName, SubscriptionId, Subscription

    $blueprintBaseQuery = $table | Where-Object { "" -ne $_.BlueprintName }

    $mgsAndSubs = (($mgAndSubBaseQuery | where-object { $_.mgId -ne "" -and $_.Level -ne "0" }) | select-object MgId, SubscriptionId -unique)
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
        link.href = "https://www.azadvertizer.net/azgovvizv3/css/azgovvizversion.css?rnd=" + rand;
        link.type = "text/css";
        link.rel = "stylesheet";
        link.media = "screen,print";
        document.getElementsByTagName( "head" )[0].appendChild( link );
    </script>
    <link rel="stylesheet" type="text/css" href="https://www.azadvertizer.net/azgovvizv3/css/azgovvizmain_003_002.css">
    <script src="https://code.jquery.com/jquery-1.7.2.js" integrity="sha256-FxfqH96M63WENBok78hchTCDxmChGFlo+/lFIPcZPeI=" crossorigin="anonymous"></script>
    <script src="https://code.jquery.com/ui/1.8.18/jquery-ui.js" integrity="sha256-lzf/CwLt49jbVoZoFcPZOc0LlMYPFBorVSwMsTs2zsA=" crossorigin="anonymous"></script>
    <script type="text/javascript" src="https://www.azadvertizer.net/azgovvizv3/js/highlight_v3.js"></script>
    <script src="https://use.fontawesome.com/0c0b5cbde8.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv3/tablefilter/tablefilter.js"></script>
    <script>
        `$(window).load(function() {
            // Animate loader off screen
            `$(".se-pre-con").fadeOut("slow");;
        });
    </script>
</head>
<body>
    <div class="se-pre-con"></div>
    <div class="tree">
        <div class="hierarchyTree" id="hierarchyTree">
"@

if ($getMgParentName -eq "Tenant Root") {
    $html += @"
            <ul>
"@
}
else {
    if ($parentMgNamex -eq $parentMgIdx) {
        $mgNameAndOrId = $parentMgNamex
    }
    else {
        $mgNameAndOrId = "$parentMgNamex<br><i>$parentMgIdx</i>"
    }
    
    if (-not $AzureDevOpsWikiAsCode) {
        $tenantDetailsDisplay = "$tenantDisplayName<br>$tenantDefaultDomain<br>"
    }
    else {
        $tenantDetailsDisplay = ""
    }
    $html += @"
            <ul>
                <li id ="first">
                    <a class="tenant"><div class="fitme" id="fitme">$($tenantDetailsDisplay)$(($checkContext).Tenant.Id)</div></a>
                    <ul>
                        <li><a class="mgnonradius parentmgnotaccessible"><img class="imgMgTree" src="https://www.azadvertizer.net/azgovvizv3/icon/Icon-general-11-Management-Groups.svg"><div class="fitme" id="fitme">$mgNameAndOrId</div></a>
                        <ul>
"@
}

$startHierarchyTree = get-date

hierarchyMgHTML -mgChild $ManagementGroupIdCaseSensitived

$endHierarchyTree = get-date
Write-Host "Building HTML Hierarchy Tree: $((NEW-TIMESPAN -Start $startHierarchyTree -End $endHierarchyTree).TotalMinutes) minutes"

if ($getMgParentName -eq "Tenant Root") {
    $html += @"
                    </ul>
                </li>
            </ul>
        </div>
    </div>
"@
}
else {
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

if (-not $HierarchyTreeOnly) {

    $html += @"
    <div class="summprnt" id="summprnt">
    <div class="summary" id="summary">
"@

    $startSummary = get-date

    summary

    $endSummary = get-date
    Write-Host "Building HTML Summary duration: $((NEW-TIMESPAN -Start $startSummary -End $endSummary).TotalMinutes) minutes"

    $html += @"
    </div>
    </div>
    <div class="hierprnt" id="hierprnt">
    <div class="hierarchyTables" id="hierarchyTables">
"@
    #Write-Host "______________________________________"
    Write-Host "Building HTML Hierarchy Table"
    $startHierarchyTable = get-date

    tableMgHTML -mgChild $ManagementGroupIdCaseSensitived -mgChildOf $getMgParentId

    $endHierarchyTable = get-date
    Write-Host "Building HTML Hierarchy Table duration: $((NEW-TIMESPAN -Start $startHierarchyTable -End $endHierarchyTable).TotalMinutes) minutes"

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

if (-not $HierarchyTreeOnly) {
    $html += @"
        Limit: $($LimitCriticalPercentage)% <button id="hierarchyTreeShowHide" onclick="toggleHierarchyTree()">Hide Hierarchy Tree</button> <button id="summaryShowHide" onclick="togglesummprnt()">Hide Summary</button> <button id="hierprntShowHide" onclick="togglehierprnt()">Hide Details</button>
"@
}

$html += @"
    </div>
    <script src="https://www.azadvertizer.net/azgovvizv3/js/toggle.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv3/js/collapsetable.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv3/js/fitty.min.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv3/js/version_v3.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv3/js/autocorractOff.js"></script>
    <script>
        fitty('#fitme', {
            minSize: 7,
            maxSize: 10
        });
    </script>


</body>
</html>
"@  

if ($AzureDevOpsWikiAsCode) { 
    $fileName = "AzGovViz_$($ManagementGroupIdCaseSensitived)"
}
else {
    if ($HierarchyTreeOnly) {
        $fileName = "AzGovViz_$($fileTimestamp)_$($ManagementGroupIdCaseSensitived)_HierarchyOnly"
    }
    else {
        $fileName = "AzGovViz_$($fileTimestamp)_$($ManagementGroupIdCaseSensitived)"
    }
}

$html | Set-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force

$endBuildHTML = get-date
Write-Host "Building HTML total duration: $((NEW-TIMESPAN -Start $startBuildHTML -End $endBuildHTML).TotalMinutes) minutes"
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

## Summary

Total Management Groups: $totalMgCount (depth $mgDepth)\
Total Subscriptions: $totalSubCount\
Total Custom Policy Definitions: $totalPolicyDefinitionsCustomCount\
Total Custom PolicySet Definitions: $totalPolicySetDefinitionsCustomCount\
Total Custom Roles: $totalRoleDefinitionsCustomCount\
Total Blueprint Definitions: $totalBlueprintDefinitionsCount\
Total Policy Assignments: $totalPolicyAssignmentsCount\
Total Role Assignments: $totalRoleAssignmentsCount\
Total Blueprint Assignments: $totalBlueprintAssignmentsCount\
Total Resources: $resourcesTypeAllCountTotal\
Total Resource Types: $totalResourceTypesCount

## Hierarchy Table

| **MgLevel** | **MgName** | **MgId** | **MgParentName** | **MgParentId** | **SubName** | **SubId** |
|-------------|-------------|-------------|-------------|-------------|-------------|-------------|
$markdownTable
"@

$markdown | Set-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).md" -Encoding utf8 -Force
#endregion BuildMD

#region BuildCSV
$table | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).csv" -Delimiter "$csvDelimiter" -NoTypeInformation
#endregion BuildCSV

#endregion createoutputs

$endAzGovViz = get-date
Write-Host "AzGovViz duration: $((NEW-TIMESPAN -Start $startAzGovViz -End $endAzGovViz).TotalMinutes) minutes"
