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
    Do you want to get granular insights on your technical Azure Governance implementation? - document it in csv, html and markdown? AzGovViz is a PowerShell based script that iterates your Azure Tenants Management Group hierarchy down to Subscription level. It captures most relevant Azure governance capabilities such as Azure Policy, RBAC and Blueprints and a lot more. From the collected data AzGovViz provides visibility on your Hierarchy Map, creates a Tenant Summary and builds granular Scope Insights on Management Groups and Subscriptions. The technical requirements as well as the required permissions are minimal.
 
.PARAMETER ManagementGroupId
    Define the Management Group Id for which the outputs/files shall be generated
 
.PARAMETER CsvDelimiter
    The script outputs a csv file depending on your delimit defaults choose semicolon or comma

.PARAMETER OutputPath
    Full- or relative path

.PARAMETER DoNotShowRoleAssignmentsUserData
    default is to capture the DisplayName and SignInName for RoleAssignments on ObjectType=User; for data protection and security reasons this may not be acceptable

.PARAMETER HierarchyMapOnly
    default is to query all Management groups and Subscription for Governance capabilities, if you use the parameter -HierarchyMapOnly then only the Hierarchy Tree will be created

.PARAMETER NoASCSecureScore
    default is to query all Subscriptions for Azure Security Center Secure Score. As the API is in preview you may want to disable it.

.PARAMETER NoResourceProvidersDetailed
    default is to output all ResourceProvider states for all Subscriptions. In large Tenants this can become time consuming.

.PARAMETER AzureDevOpsWikiAsCode
    default is to add timestamp to the MD output, use the parameter to remove the timestamp - the MD file will then only be pushed to Wiki Repo if the Management Group structure and/or Subscription linkage changed

.PARAMETER LimitCriticalPercentage
    default is 80%, this parameter defines the warning level for approaching Limits (e.g. 80% of Role Assignment limit reached) change as per your preference

.PARAMETER SubscriptionQuotaIdWhitelist
    default is 'undefined', this parameter defines the QuotaIds the subscriptions must match so that AzGovViz processes them. The script checks if the QuotaId startswith the string that you have put in. Separate multiple strings with backslash e.g. MSDN_\EnterpriseAgreement_   

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
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -HierarchyMapOnly

    Define if ASC SecureScore should be queried for Subscriptions
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -NoASCSecureScore

    Define if a detailed summary on Resource Provider states per Subscription should be created in the TenantSummary section
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -NoResourceProvidersDetailed

    Define if the script runs in AzureDevOps. This will not print any timestamps into the markdown output so that only true deviation will force a push to the wiki repository (default prints timestamps to the markdown output)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -AzureDevOpsWikiAsCode
    
    Define when limits should be highlited as warning (default is 80 percent)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -LimitCriticalPercentage 90

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
    [switch]$HierarchyMapOnly,
    [switch]$NoASCSecureScore,
    [switch]$NoResourceProvidersDetailed,
    [switch]$AzureDevOpsWikiAsCode,
    [int]$LimitCriticalPercentage = 80,
    [string]$SubscriptionQuotaIdWhitelist = "undefined",

    #https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#role-based-access-control-limits
    [int]$LimitRBACCustomRoleDefinitionsTenant = 5000,
    [int]$LimitRBACRoleAssignmentsManagementGroup = 500,
    [int]$LimitRBACRoleAssignmentsSubscription = 2000,
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
    #mkdir $outputPath
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
$script:dataCollectionSubscriptionsCounter = 0
function dataCollection($mgId, $hierarchyLevel, $mgParentId, $mgParentName) {
    checkTokenLifetime
    $startMgLoop = get-date
    $hierarchyLevel++
    $getMg = Get-AzManagementGroup -groupname $mgId -Expand -Recurse -ErrorAction Stop
    Write-Host " CustomDataCollection: Processing L$hierarchyLevel MG '$($getMg.DisplayName)' ('$($getMg.Name)')"

    if (-not $HierarchyMapOnly) {

        #MGPolicyCompliance
        ($htCachePolicyCompliance).mg.($getMg.Name) = @{ }
        $uriMgPolicyCompliance = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)/providers/Microsoft.Management/managementGroups/$($getMg.Name)/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"

        $tryCounter = 0
        do {
            $result = "letscheck"
            $tryCounter++
            try {
                $mgPolicyComplianceResult = Invoke-RestMethod -Uri $uriMgPolicyCompliance -Method POST -Headers @{"Authorization" = "Bearer $accesstoken" }
            }
            catch {
                $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
            }
            if ($result -ne "letscheck"){
                $result
                if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                    Write-Host " CustomDataCollection: L$hierarchyLevel MG '$($getMg.DisplayName)' ('$($getMg.Name)') Getting Policy Compliance: try #$tryCounter; returned: '$result' - try again"
                    $result = "tryAgain"
                    Start-Sleep -Milliseconds 250
                }
            }
        }
        until($result -ne "tryAgain")

        foreach ($policyAssignment in $mgPolicyComplianceResult.value.policyassignments | sort-object -Property policyAssignmentId){
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
        
        $tryCounter = 0
        do {
            $result = "letscheck"
            $tryCounter++
            try {
                $mgBlueprintDefinitionResult = Invoke-RestMethod -Uri $uriMgBlueprintDefinitionScoped -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
            }
            catch {
                $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
            }
            if ($result -ne "letscheck"){
                $result
                if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                    Write-Host " CustomDataCollection: L$hierarchyLevel MG '$($getMg.DisplayName)' ('$($getMg.Name)') Getting scoped Blueprint Definitions: try #$tryCounter; returned: '$result' - try again"
                    $result = "tryAgain"
                    Start-Sleep -Milliseconds 250
                }
            }
        }
        until($result -ne "tryAgain")
        
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
        
        $tryCounter = 0
        do {
            $result = "letscheck"
            $tryCounter++
            try {
                $requestPolicyDefinitionAPI = Invoke-RestMethod -Uri $uriPolicyDefinitionAPI -Headers  @{"Authorization" = "Bearer $accesstoken" }
            }
            catch {
                $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
            }
            if ($result -ne "letscheck"){
                $result
                if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                    Write-Host " CustomDataCollection: L$hierarchyLevel MG '$($getMg.DisplayName)' ('$($getMg.Name)') Getting Policy Definitions: try #$tryCounter; returned: '$result' - try again"
                    $result = "tryAgain"
                    Start-Sleep -Milliseconds 250
                }
            }
        }
        until($result -ne "tryAgain")
        
        $mgPolicyDefinitions = $requestPolicyDefinitionAPI.value | Where-Object { $_.properties.policyType -eq "custom" }
        $PolicyDefinitionsScopedCount = (($mgPolicyDefinitions | Where-Object { ($_.Id).startswith("/providers/Microsoft.Management/managementGroups/$($getMg.Name)/","CurrentCultureIgnoreCase") }) | measure-object).count
        foreach ($mgPolicyDefinition in $mgPolicyDefinitions) {
            if (-not $($htCacheDefinitions).policy.($mgPolicyDefinition.id)) {
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.id) = @{ }
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.id).Id = $($mgPolicyDefinition.id)
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.id).DisplayName = $($mgPolicyDefinition.Properties.displayname)
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.id).Type = $($mgPolicyDefinition.Properties.policyType)
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.id).Category = $($mgPolicyDefinition.Properties.metadata.Category)
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.id).PolicyDefinitionId = $($mgPolicyDefinition.id)
                #effects
                if ($mgPolicyDefinition.properties.parameters.effect.defaultvalue) {
                    ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).effectDefaultValue = $mgPolicyDefinition.properties.parameters.effect.defaultvalue
                    if ($mgPolicyDefinition.properties.parameters.effect.allowedValues){
                        ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).effectAllowedValue = $mgPolicyDefinition.properties.parameters.effect.allowedValues -join ","
                    }
                    else{
                        ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).effectAllowedValue = "n/a"
                    }
                    ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).effectFixedValue = "n/a"
                }
                else {
                    if ($mgPolicyDefinition.properties.parameters.policyEffect.defaultValue) {
                        ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).effectDefaultValue = $mgPolicyDefinition.properties.parameters.policyEffect.defaultvalue
                        if ($mgPolicyDefinition.properties.parameters.policyEffect.allowedValues){
                            ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).effectAllowedValue = $mgPolicyDefinition.properties.parameters.policyEffect.allowedValues -join ","
                        }
                        else{
                            ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).effectAllowedValue = "n/a"
                        }
                        ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).effectFixedValue = "n/a"
                    }
                    else {
                        ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).effectFixedValue = $mgPolicyDefinition.Properties.policyRule.then.effect
                        ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).effectDefaultValue = "n/a"
                        ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).effectAllowedValue = "n/a"
                    }
                }
                ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).json = $mgPolicyDefinition
            }
            if (-not $($htCacheDefinitionsAsIs).policy[$mgPolicyDefinition.id]) {
                ($htCacheDefinitionsAsIs).policy.$($mgPolicyDefinition.id) = @{ }
                ($htCacheDefinitionsAsIs).policy.$($mgPolicyDefinition.id) = $mgPolicyDefinition
            }  
        }

        #MGPolicySets
        $uriPolicySetDefinitionAPI = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementgroups/$($getMg.Name)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"
        
        $tryCounter = 0
        do {
            $result = "letscheck"
            $tryCounter++
            try {
                $requestPolicySetDefinitionAPI = Invoke-RestMethod -Uri $uriPolicySetDefinitionAPI -Headers  @{"Authorization" = "Bearer $accesstoken" }
            }
            catch {
                $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
            }
            if ($result -ne "letscheck"){
                $result
                if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                    Write-Host " CustomDataCollection: L$hierarchyLevel MG '$($getMg.DisplayName)' ('$($getMg.Name)') Getting PolicySet Definitions: try #$tryCounter; returned: '$result' - try again"
                    $result = "tryAgain"
                    Start-Sleep -Milliseconds 250
                }
            }
        }
        until($result -ne "tryAgain")
        
        $mgPolicySetDefinitions = $requestPolicySetDefinitionAPI.value | Where-Object { $_.properties.policyType -eq "custom" }
        $PolicySetDefinitionsScopedCount = (($mgPolicySetDefinitions | Where-Object { ($_.Id).startswith("/providers/Microsoft.Management/managementGroups/$($getMg.Name)/","CurrentCultureIgnoreCase") }) | measure-object).count
        foreach ($mgPolicySetDefinition in $mgPolicySetDefinitions) {
            if (-not $($htCacheDefinitions).policySet.($mgPolicySetDefinition.id)) {
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.id) = @{ }
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.id).Id = $($mgPolicySetDefinition.id)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.id).DisplayName = $($mgPolicySetDefinition.Properties.displayname)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.id).Type = $($mgPolicySetDefinition.Properties.policyType)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.id).Category = $($mgPolicySetDefinition.Properties.metadata.Category)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.id).PolicyDefinitionId = $($mgPolicySetDefinition.id)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.id).PolicySetPolicyIds = $mgPolicySetDefinition.properties.policydefinitions.policyDefinitionId
                ($htCacheDefinitions).policySet.$($mgPolicySetDefinition.id).json = $mgPolicySetDefinition
            }  
        }

        #MgPolicyAssignments
        $uriPolicyAssignmentAPI = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementgroups/$($getMg.Name)/providers/Microsoft.Authorization/policyAssignments?`$filter=atscope()&api-version=2019-09-01"
        
        $tryCounter = 0
        do {
            $result = "letscheck"
            $tryCounter++
            try {
                $L0mgmtGroupPolicyAssignments = Invoke-RestMethod -Uri $uriPolicyAssignmentAPI -Headers  @{"Authorization" = "Bearer $accesstoken" }
            }
            catch {
                $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
            }
            if ($result -ne "letscheck"){
                $result
                if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                    Write-Host " CustomDataCollection: $($getMg.Name) Getting Policy Assignments: try #$tryCounter; returned: '$result' - try again"
                    $result = "tryAgain"
                    Start-Sleep -Milliseconds 250
                }
            }
        }
        until($result -ne "tryAgain")

        $L0mgmtGroupPolicyAssignmentsPolicyCount = (($L0mgmtGroupPolicyAssignments.value | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" }) | measure-object).count
        $L0mgmtGroupPolicyAssignmentsPolicySetCount = (($L0mgmtGroupPolicyAssignments.value | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" }) | measure-object).count
        $L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount = (($L0mgmtGroupPolicyAssignments.value | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -and $_.Id -match "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" }) | measure-object).count
        $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount = (($L0mgmtGroupPolicyAssignments.value | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" -and $_.Id -match "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" }) | measure-object).count
        $L0mgmtGroupPolicyAssignmentsPolicyAndPolicySetAtScopeCount = ($L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount + $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount)
        foreach ($L0mgmtGroupPolicyAssignment in $L0mgmtGroupPolicyAssignments.value) {

            if (-not $($htCacheAssignments).policy[$L0mgmtGroupPolicyAssignment.Id]) {
                $($htCacheAssignments).policy.$($L0mgmtGroupPolicyAssignment.Id) = @{ }
                $($htCacheAssignments).policy.$($L0mgmtGroupPolicyAssignment.Id) = $L0mgmtGroupPolicyAssignment
            }  

            if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -OR $L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
                if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/") {
                    $PolicyVariant = "Policy"
                    $definitiontype = "policy"
                    $Id = $L0mgmtGroupPolicyAssignment.properties.policydefinitionid
                    $PolicyAssignmentScope = $L0mgmtGroupPolicyAssignment.Properties.Scope
                    $PolicyAssignmentNotScope = $L0mgmtGroupPolicyAssignment.Properties.NotScopes -join "$CsvDelimiterOpposite "
                    $PolicyAssignmentId = $L0mgmtGroupPolicyAssignment.Id
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
                        -PolicyDefinitionIdGuid ((($htCacheDefinitions).($definitiontype).($Id).Id) -replace ".*/") `
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
                    $Id = $L0mgmtGroupPolicyAssignment.properties.policydefinitionid
                    $PolicyAssignmentScope = $L0mgmtGroupPolicyAssignment.Properties.Scope
                    $PolicyAssignmentNotScope = $L0mgmtGroupPolicyAssignment.Properties.NotScopes -join "$CsvDelimiterOpposite "
                    $PolicyAssignmentId = $L0mgmtGroupPolicyAssignment.Id
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
                        -PolicyDefinitionIdGuid ((($htCacheDefinitions).($definitiontype).($Id).Id) -replace ".*/") `
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
                Write-Host " CustomDataCollection: unexpected"
                return
            }
        }

        #MGCustomRolesRoles
        $uriRoleDefinitionAPI = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementGroups/$($getMg.Name)/providers/Microsoft.Authorization/roleDefinitions?api-version=2015-07-01&`$filter=type%20eq%20'CustomRole'"

        $tryCounter = 0
        do {
            $result = "letscheck"
            $tryCounter++
            try {
                $mgCustomRoleDefinitions = Invoke-RestMethod -Uri $uriRoleDefinitionAPI -Headers  @{"Authorization" = "Bearer $accesstoken" }
            }
            catch {
                $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
            }
            if ($result -ne "letscheck"){
                $result
                if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                    Write-Host " CustomDataCollection: $($getMg.Name) Getting Custom Roles: try #$tryCounter; returned: '$result' - try again"
                    $result = "tryAgain"
                    Start-Sleep -Milliseconds 250
                }
            }
        }
        until($result -ne "tryAgain")
        
        foreach ($mgCustomRoleDefinition in $mgCustomRoleDefinitions.value) {
            if (-not $($htCacheDefinitions).role[$mgCustomRoleDefinition.name]) {
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.name) = @{ }
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.name).Id = $($mgCustomRoleDefinition.name)
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.name).Name = $($mgCustomRoleDefinition.properties.roleName)
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.name).IsCustom = $true
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.name).AssignableScopes = $($mgCustomRoleDefinition.properties.AssignableScopes)
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.name).Actions = $($mgCustomRoleDefinition.properties.permissions.Actions)
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.name).NotActions = $($mgCustomRoleDefinition.properties.permissions.NotActions)
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.name).DataActions = $($mgCustomRoleDefinition.properties.permissions.DataActions)
                $($htCacheDefinitions).role.$($mgCustomRoleDefinition.name).NotDataActions = $($mgCustomRoleDefinition.properties.permissions.NotDataActions)
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
    Write-Host " CustomDataCollection: L$hierarchyLevel MG '$($getMg.DisplayName)' ('$($getMg.Name)') processing duration: $((NEW-TIMESPAN -Start $startMgLoop -End $endMgLoop).TotalSeconds) seconds"

    #SUBSCRIPTION
    if (($getMg.children | measure-object).count -gt 0) {
        
        foreach ($childMg in $getMg.Children | Where-Object { $_.Type -eq "/subscriptions" }) {
            checkTokenLifetime
            $startSubLoop = get-date
            $childMgSubId = $childMg.Id -replace '/subscriptions/', ''
            $script:dataCollectionSubscriptionsCounter++
            Write-Host " CustomDataCollection: (#$script:dataCollectionSubscriptionsCounter) Processing Subscription '$($childMg.DisplayName)' ('$childMgSubId')"

            if (-not $HierarchyMapOnly) {
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
                            Write-Host " CustomDataCollection: Subscription Quota Id: $($subscriptionsGetResult.subscriptionPolicies.quotaId) is out of scope for AzGovViz"
                            $null = $script:outOfScopeSubscriptions.Add([PSCustomObject]@{ 'subscriptionId' = $childMgSubId; 'subscriptionName'= $childMg.DisplayName; 'outOfScopeReason'= "QuotaId: AAD_ (State: $($subscriptionsGetResult.state))"; 'ManagementGroupId' = $getMg.Name; 'ManagementGroupName' = $getMg.DisplayName })
                        }
                        else{
                            if ($subscriptionsGetResult.state -ne "enabled") {
                                Write-Host " CustomDataCollection: Subscription State: '$($subscriptionsGetResult.state)'; out of scope"
                                $null = $script:outOfScopeSubscriptions.Add([PSCustomObject]@{ 'subscriptionId' = $childMgSubId; 'subscriptionName'= $childMg.DisplayName; 'outOfScopeReason'= "State: $($subscriptionsGetResult.state)"; 'ManagementGroupId' = $getMg.Name; 'ManagementGroupName' = $getMg.DisplayName })
                            }
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
                                Write-Host " CustomDataCollection: Subscription Quota Id: $($subscriptionsGetResult.subscriptionPolicies.quotaId) is out of scope for AzGovViz (not in Whitelist)"
                                $null = $script:outOfScopeSubscriptions.Add([PSCustomObject]@{ 'subscriptionId' = $childMgSubId; 'subscriptionName'= $childMg.DisplayName; 'outOfScopeReason'= "QuotaId: '$($subscriptionsGetResult.subscriptionPolicies.quotaId)' not in Whitelist"; 'ManagementGroupId' = $getMg.Name; 'ManagementGroupName' = $getMg.DisplayName })
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
                        $uriSubPolicyCompliance = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"

                        $tryCounter = 0
                        do {
                            $result = "letscheck"
                            $tryCounter++
                            try {
                                $subPolicyComplianceResult = Invoke-RestMethod -Uri $uriSubPolicyCompliance -Method POST -Headers @{"Authorization" = "Bearer $accesstoken" }
                            }
                            catch {
                                $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
                            }
                            if ($result -ne "letscheck"){
                                $result
                                if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                                    Write-Host " CustomDataCollection: Subscription Id: $childMgSubId Getting Policy Compliance: try #$tryCounter; returned: '$result' - try again"
                                    $result = "tryAgain"
                                    Start-Sleep -Milliseconds 250
                                }
                            }
                        }
                        until($result -ne "tryAgain")

                        ($htCachePolicyCompliance).sub.$childMgSubId = @{ }
                        foreach ($policyAssignment in $subPolicyComplianceResult.value.policyassignments | sort-object -Property policyAssignmentId){
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
                        if (-not $NoASCSecureScore){
                            $uriSubASCSecureScore = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Security/securescores?api-version=2020-01-01-preview"
                            
                            $tryCounter = 0
                            do {
                                $result = "letscheck"
                                $tryCounter++
                                try {
                                    $subASCSecureScoreResult = Invoke-RestMethod -Uri $uriSubASCSecureScore -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
                                }
                                catch {
                                    $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
                                }
                                if ($result -ne "letscheck"){
                                    $result
                                    if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                                        Write-Host " CustomDataCollection: Subscription Id: $childMgSubId Getting ASC Secure Score: try #$tryCounter; returned: '$result' - try again"
                                        $result = "tryAgain"
                                        Start-Sleep -Milliseconds 250
                                    }
                                }
                            }
                            until($result -ne "tryAgain")

                            if ($result -ne "letscheck"){
                                Write-Host " CustomDataCollection: Subscription Id: $childMgSubId Getting ASC Secure Score error: '$result' -> skipping ASC Secure Score for this subscription"
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
                        }
                        else{
                            $subscriptionASCSecureScore = "excluded"
                        }

                        #SubscriptionBlueprint
                        $uriSubBlueprintDefinitionScoped = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)/subscriptions/$childMgSubId/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"

                        $tryCounter = 0
                        do {
                            $result = "letscheck"
                            $tryCounter++
                            try {
                                $subBlueprintDefinitionResult = Invoke-RestMethod -Uri $uriSubBlueprintDefinitionScoped -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
                            }
                            catch {
                                $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
                            }
                            if ($result -ne "letscheck"){
                                $result
                                if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                                    Write-Host " CustomDataCollection: Subscription Id: $childMgSubId Getting scoped Blueprint Definitions: try #$tryCounter; returned: '$result' - try again"
                                    $result = "tryAgain"
                                    Start-Sleep -Milliseconds 250
                                }
                            }
                        }
                        until($result -ne "tryAgain")

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
                        
                        $tryCounter = 0
                        do {
                            $result = "letscheck"
                            $tryCounter++
                            try {
                                $subscriptionBlueprintAssignmentsResult = Invoke-RestMethod -Uri $urisubscriptionBlueprintAssignments -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
                            }
                            catch {
                                $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
                            }
                            if ($result -ne "letscheck"){
                                $result
                                if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                                    Write-Host " CustomDataCollection: Subscription Id: $childMgSubId Getting Blueprint Assignments: try #$tryCounter; returned: '$result' - try again"
                                    $result = "tryAgain"
                                    Start-Sleep -Milliseconds 250
                                }
                            }
                        }
                        until($result -ne "tryAgain")

                        if (($subscriptionBlueprintAssignmentsResult.value | measure-object).count -gt 0) {
                            foreach ($subscriptionBlueprintAssignment in $subscriptionBlueprintAssignmentsResult.value) {

                                if (-not $($htCacheAssignments).blueprint[$subscriptionBlueprintAssignment.Id]) {
                                    $($htCacheAssignments).blueprint.$($subscriptionBlueprintAssignment.Id) = @{ }
                                    $($htCacheAssignments).blueprint.$($subscriptionBlueprintAssignment.Id) = $subscriptionBlueprintAssignment
                                }  

                                if (($subscriptionBlueprintAssignment.properties.blueprintId).StartsWith("/subscriptions/","CurrentCultureIgnoreCase")) {
                                    $blueprintScope = $subscriptionBlueprintAssignment.properties.blueprintId -replace "/providers/Microsoft.Blueprint/blueprints/.*", ""
                                    $blueprintName = $subscriptionBlueprintAssignment.properties.blueprintId -replace ".*/blueprints/", "" -replace "/versions/.*", ""
                                }
                                if (($subscriptionBlueprintAssignment.properties.blueprintId).StartsWith("/providers/Microsoft.Management/managementGroups/","CurrentCultureIgnoreCase")) {
                                    $blueprintScope = $subscriptionBlueprintAssignment.properties.blueprintId -replace "/providers/Microsoft.Blueprint/blueprints/.*", ""
                                    $blueprintName = $subscriptionBlueprintAssignment.properties.blueprintId -replace ".*/blueprints/", "" -replace "/versions/.*", ""
                                }
                                
                                $uriSubscriptionBlueprintDefinition = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)$($blueprintScope)/providers/Microsoft.Blueprint/blueprints/$($blueprintName)?api-version=2018-11-01-preview"

                                $tryCounter = 0
                                do {
                                    $result = "letscheck"
                                    $tryCounter++
                                    try {
                                        $subscriptionBlueprintDefinitionResult = Invoke-RestMethod -Uri $uriSubscriptionBlueprintDefinition -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
                                    }
                                    catch {
                                        $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
                                    }
                                    if ($result -ne "letscheck"){
                                        $result
                                        if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                                            Write-Host " CustomDataCollection: Subscription Id: $childMgSubId Getting Blueprint Definitions: try #$tryCounter; returned: '$result' - try again"
                                            $result = "tryAgain"
                                            Start-Sleep -Milliseconds 250
                                        }
                                    }
                                }
                                until($result -ne "tryAgain")

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
                        
                        $tryCounter = 0
                        do {
                            $result = "letscheck"
                            $tryCounter++
                            try {
                                $requestPolicyDefinitionAPI = Invoke-RestMethod -Uri $uriPolicyDefinitionAPI -Headers  @{"Authorization" = "Bearer $accesstoken" }
                            }
                            catch {
                                $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
                            }
                            if ($result -ne "letscheck"){
                                $result
                                if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                                    Write-Host " CustomDataCollection: $childMgSubId Getting Policy Definitions: try #$tryCounter; returned: '$result' - try again"
                                    $result = "tryAgain"
                                    Start-Sleep -Milliseconds 250
                                }
                            }
                        }
                        until($result -ne "tryAgain")
                        
                        $subPolicyDefinitions = $requestPolicyDefinitionAPI.value | Where-Object { $_.properties.policyType -eq "custom" }
                        $PolicyDefinitionsScopedCount = (($subPolicyDefinitions | Where-Object { ($_.Id).startswith("/subscriptions/$childMgSubId/","CurrentCultureIgnoreCase") }) | measure-object).count
                        foreach ($subPolicyDefinition in $subPolicyDefinitions) {
                            if (-not $($htCacheDefinitions).policy.($subPolicyDefinition.id)) {
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.id) = @{ }
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.id).Id = $($subPolicyDefinition.id)
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.id).DisplayName = $($subPolicyDefinition.Properties.displayname)
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.id).Type = $($subPolicyDefinition.Properties.policyType)
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.id).Category = $($subPolicyDefinition.Properties.metadata.category)
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.id).PolicyDefinitionId = $($subPolicyDefinition.id)
                                #effects
                                if ($subPolicyDefinition.properties.parameters.effect.defaultvalue) {
                                    ($htCacheDefinitions).policy.$($subPolicyDefinition.id).effectDefaultValue = $subPolicyDefinition.properties.parameters.effect.defaultvalue
                                    if ($subPolicyDefinition.properties.parameters.effect.allowedValues){
                                        ($htCacheDefinitions).policy.$($subPolicyDefinition.id).effectAllowedValue = $subPolicyDefinition.properties.parameters.effect.allowedValues -join ","
                                    }
                                    else{
                                        ($htCacheDefinitions).policy.$($subPolicyDefinition.id).effectAllowedValue = "n/a"
                                    }
                                    ($htCacheDefinitions).policy.$($subPolicyDefinition.id).effectFixedValue = "n/a"
                                }
                                else {
                                    if ($subPolicyDefinition.properties.parameters.policyEffect.defaultValue) {
                                        ($htCacheDefinitions).policy.$($subPolicyDefinition.id).effectDefaultValue = $subPolicyDefinition.properties.parameters.policyEffect.defaultvalue
                                        if ($subPolicyDefinition.properties.parameters.policyEffect.allowedValues){
                                            ($htCacheDefinitions).policy.$($subPolicyDefinition.id).effectAllowedValue = $subPolicyDefinition.properties.parameters.policyEffect.allowedValues -join ","
                                        }
                                        else{
                                            ($htCacheDefinitions).policy.$($subPolicyDefinition.id).effectAllowedValue = "n/a"
                                        }
                                        ($htCacheDefinitions).policy.$($subPolicyDefinition.id).effectFixedValue = "n/a"
                                    }
                                    else {
                                        ($htCacheDefinitions).policy.$($subPolicyDefinition.id).effectFixedValue = $subPolicyDefinition.Properties.policyRule.then.effect
                                        ($htCacheDefinitions).policy.$($subPolicyDefinition.id).effectDefaultValue = "n/a"
                                        ($htCacheDefinitions).policy.$($subPolicyDefinition.id).effectAllowedValue = "n/a"
                                    }
                                }
                                $($htCacheDefinitions).policy.$($subPolicyDefinition.id).json = $subPolicyDefinition
                            }  
                            if (-not $($htCacheDefinitionsAsIs).policy[$subPolicyDefinition.id]) {
                                ($htCacheDefinitionsAsIs).policy.$($subPolicyDefinition.id) = @{ }
                                ($htCacheDefinitionsAsIs).policy.$($subPolicyDefinition.id) = $subPolicyDefinition
                            }  
                        }

                        #SubscriptionPolicySets
                        $uriPolicySetDefinitionAPI = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"
                        
                        $tryCounter = 0
                        do {
                            $result = "letscheck"
                            $tryCounter++
                            try {
                                $requestPolicySetDefinitionAPI = Invoke-RestMethod -Uri $uriPolicySetDefinitionAPI -Headers  @{"Authorization" = "Bearer $accesstoken" }
                            }
                            catch {
                                $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
                            }
                            if ($result -ne "letscheck"){
                                $result
                                if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                                    Write-Host " CustomDataCollection: $childMgSubId Getting PolicySet Definitions: try #$tryCounter; returned: '$result' - try again"
                                    $result = "tryAgain"
                                    Start-Sleep -Milliseconds 250
                                }
                            }
                        }
                        until($result -ne "tryAgain")
                       
                        $subPolicySetDefinitions = $requestPolicySetDefinitionAPI.value | Where-Object { $_.properties.policyType -eq "custom" }
                        $PolicySetDefinitionsScopedCount = (($subPolicySetDefinitions | Where-Object { ($_.Id).startswith("/subscriptions/$childMgSubId/","CurrentCultureIgnoreCase") }) | measure-object).count
                        foreach ($subPolicySetDefinition in $subPolicySetDefinitions) {
                            if (-not $($htCacheDefinitions).policySet.($subPolicySetDefinition.id)) {
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.id) = @{ }
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.id).Id = $($subPolicySetDefinition.id)
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.id).DisplayName = $($subPolicySetDefinition.Properties.displayname)
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.id).Type = $($subPolicySetDefinition.Properties.policyType)
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.id).Category = $($subPolicySetDefinition.Properties.metadata.category)
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.id).PolicyDefinitionId = $($subPolicySetDefinition.id)
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.id).PolicySetPolicyIds = $subPolicySetDefinition.properties.policydefinitions.policyDefinitionId
                                $($htCacheDefinitions).policySet.$($subPolicySetDefinition.id).json = $subPolicySetDefinition
                            }  
                        }

                        #SubscriptionPolicyAssignments
                        $uriPolicyAssignmentAPI = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policyAssignments?api-version=2019-09-01"
                        
                        $tryCounter = 0
                        do {
                            $result = "letscheck"
                            $tryCounter++
                            try {
                                $L1mgmtGroupSubPolicyAssignments = Invoke-RestMethod -Uri $uriPolicyAssignmentAPI -Headers  @{"Authorization" = "Bearer $accesstoken" }
                            }
                            catch {
                                $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
                            }
                            if ($result -ne "letscheck"){
                                $result
                                if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                                    Write-Host " CustomDataCollection: $childMgSubId Getting Policy Assignments: try #$tryCounter; returned: '$result' - try again"
                                    $result = "tryAgain"
                                    Start-Sleep -Milliseconds 250
                                }
                            }
                        }
                        until($result -ne "tryAgain")

                        $L1mgmtGroupSubPolicyAssignmentsPolicyCount = (($L1mgmtGroupSubPolicyAssignments.value | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -and $_.id -notmatch "$($childMg.Id)/resourceGroups" }) | measure-object).count
                        $L1mgmtGroupSubPolicyAssignmentsPolicySetCount = (($L1mgmtGroupSubPolicyAssignments.value | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" -and $_.id -notmatch "$($childMg.Id)/resourceGroups" }) | measure-object).count
                        $L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount = (($L1mgmtGroupSubPolicyAssignments.value | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -and $_.Id -match $childMg.Id -and $_.id -notmatch "$($childMg.Id)/resourceGroups" }) | measure-object).count
                        $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount = (($L1mgmtGroupSubPolicyAssignments.value | where-object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" -and $_.Id -match $childMg.Id -and $_.id -notmatch "$($childMg.Id)/resourceGroups" }) | measure-object).count

                        $L1mgmtGroupSubPolicyAssignmentsPolicyAndPolicySetAtScopeCount = ($L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount + $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount)

                        $script:arrayCachePolicyAssignmentsResourceGroups += foreach ($L1mgmtGroupSubPolicyAssignment in $L1mgmtGroupSubPolicyAssignments.value | Where-Object { $_.id -match "$($childMg.Id)/resourceGroups"} ) {
                            $L1mgmtGroupSubPolicyAssignment
                        }
                        
                        foreach ($L1mgmtGroupSubPolicyAssignment in $L1mgmtGroupSubPolicyAssignments.value | Where-Object { $_.id -notmatch "$($childMg.Id)/resourceGroups"} ) {

                            if (-not $($htCacheAssignments).policy[$L1mgmtGroupSubPolicyAssignment.id]) {
                                $($htCacheAssignments).policy.$($L1mgmtGroupSubPolicyAssignment.id) = @{ }
                                $($htCacheAssignments).policy.$($L1mgmtGroupSubPolicyAssignment.id) = $L1mgmtGroupSubPolicyAssignment
                            }  

                            if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -OR $L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
                                if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/") {
                                    $PolicyVariant = "Policy"
                                    $definitiontype = "policy"
                                    $Id = $L1mgmtGroupSubPolicyAssignment.properties.policydefinitionid

                                    $PolicyAssignmentScope = $L1mgmtGroupSubPolicyAssignment.Properties.Scope
                                    $PolicyAssignmentNotScope = $L1mgmtGroupSubPolicyAssignment.Properties.NotScopes -join "$CsvDelimiterOpposite "
                                    $PolicyAssignmentId = $L1mgmtGroupSubPolicyAssignment.id
                                    $PolicyAssignmentName = $L1mgmtGroupSubPolicyAssignment.Name
                                    $PolicyAssignmentDisplayName = $L1mgmtGroupSubPolicyAssignment.Properties.DisplayName

                                    if ($L1mgmtGroupSubPolicyAssignment.Identity) {
                                        $PolicyAssignmentIdentity = $L1mgmtGroupSubPolicyAssignment.Identity.principalId
                                    }
                                    else {
                                        $PolicyAssignmentIdentity = "n/a"
                                    }

                                    if ($htCacheDefinitions.$definitiontype.$($Id).Type -eq "Custom") {
                                        if (($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId).StartsWith("/subscriptions","CurrentCultureIgnoreCase")) {
                                            $policyDefintionScope = ($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId -split "\/")[0..2] -join "/"
                                        }
                                        if (($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId).StartsWith("/providers","CurrentCultureIgnoreCase")) {
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
                                        -PolicyDefinitionIdGuid ((($htCacheDefinitions).($definitiontype).($Id).Id) -replace ".*/") `
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
                                    $Id = $L1mgmtGroupSubPolicyAssignment.properties.policydefinitionid

                                    $PolicyAssignmentScope = $L1mgmtGroupSubPolicyAssignment.Properties.Scope
                                    $PolicyAssignmentNotScope = $L1mgmtGroupSubPolicyAssignment.Properties.NotScopes -join "$CsvDelimiterOpposite "
                                    $PolicyAssignmentId = $L1mgmtGroupSubPolicyAssignment.id
                                    $PolicyAssignmentName = $L1mgmtGroupSubPolicyAssignment.Name
                                    $PolicyAssignmentDisplayName = $L1mgmtGroupSubPolicyAssignment.Properties.DisplayName

                                    if ($L1mgmtGroupSubPolicyAssignment.Identity) {
                                        $PolicyAssignmentIdentity = $L1mgmtGroupSubPolicyAssignment.Identity.principalId
                                    }
                                    else {
                                        $PolicyAssignmentIdentity = "n/a"
                                    }

                                    if ($htCacheDefinitions.$definitiontype.$($Id).Type -eq "Custom") {
                                        if (($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId).StartsWith("/subscriptions","CurrentCultureIgnoreCase")) {
                                            $policyDefintionScope = ($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId -split "\/")[0..2] -join "/"
                                        }
                                        if (($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId).StartsWith("/providers","CurrentCultureIgnoreCase")) {
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
                                        -PolicyDefinitionIdGuid ((($htCacheDefinitions).($definitiontype).($Id).Id) -replace ".*/") `
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
                        $uriRoleDefinitionAPI = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Authorization/roleDefinitions?api-version=2015-07-01&`$filter=type%20eq%20'CustomRole'"
                
                        $tryCounter = 0
                        do {
                            $result = "letscheck"
                            $tryCounter++
                            try {
                                $subCustomRoleDefinitions = Invoke-RestMethod -Uri $uriRoleDefinitionAPI -Headers  @{"Authorization" = "Bearer $accesstoken" }
                            }
                            catch {
                                $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
                            }
                            if ($result -ne "letscheck"){
                                $result
                                if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                                    Write-Host " CustomDataCollection: $childMgSubId Getting Custom Roles: try #$tryCounter; returned: '$result' - try again"
                                    $result = "tryAgain"
                                    Start-Sleep -Milliseconds 250
                                }
                            }
                        }
                        until($result -ne "tryAgain")
                        
                        foreach ($subCustomRoleDefinition in $subCustomRoleDefinitions.value) {
                            if (-not $($htCacheDefinitions).role[$subCustomRoleDefinition.name]) {
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.name) = @{ }
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.name).Id = $($subCustomRoleDefinition.name)
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.name).Name = $($subCustomRoleDefinition.properties.roleName)
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.name).IsCustom = $true
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.name).AssignableScopes = $($subCustomRoleDefinition.properties.AssignableScopes)
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.name).Actions = $($subCustomRoleDefinition.properties.permissions.Actions)
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.name).NotActions = $($subCustomRoleDefinition.properties.permissions.NotActions)
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.name).DataActions = $($subCustomRoleDefinition.properties.permissions.DataActions)
                                $($htCacheDefinitions).role.$($subCustomRoleDefinition.name).NotDataActions = $($subCustomRoleDefinition.properties.permissions.NotDataActions)
                            }  
                        }

                        #SubscriptionRoleAssignments
                        $uriRoleAssignmentsUsageMetrics = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Authorization/roleAssignmentsUsageMetrics?api-version=2019-08-01-preview"
                        
                        $tryCounter = 0
                        do {
                            $result = "letscheck"
                            $tryCounter++
                            try {
                                $roleAssignmentsUsage = Invoke-RestMethod -Uri $uriRoleAssignmentsUsageMetrics -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
                            }
                            catch {
                                $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
                            }
                            if ($result -ne "letscheck"){
                                $result
                                if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                                    Write-Host " CustomDataCollection: $childMgSubId Getting Role Assignments Usage Metrics: try #$tryCounter; returned: '$result' - try again"
                                    $result = "tryAgain"
                                    Start-Sleep -Milliseconds 250
                                }
                            }
                        }
                        until($result -ne "tryAgain")
                        
                        $L1mgmtGroupSubRoleAssignments = Get-AzRoleAssignment -Scope "$($childMg.Id)" -ErrorAction Stop #exclude rg roleassignments
                        $script:arrayCacheRoleAssignmentsResourceGroups += foreach ($L1mgmtGroupSubRoleAssignmentOnRg in $L1mgmtGroupSubRoleAssignments | where-object { $_.RoleAssignmentId -match "$($childMg.Id)/resourcegroups/" }) {
                            $L1mgmtGroupSubRoleAssignmentOnRg
                        }

                        foreach ($L1mgmtGroupSubRoleAssignment in $L1mgmtGroupSubRoleAssignments | where-object { $_.RoleAssignmentId -notmatch "$($childMg.Id)/resourcegroups/" }) {

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
                    Write-Host " CustomDataCollection: Subscription Error: '$result' -> skipping this subscription"
                    $null = $script:outOfScopeSubscriptions.Add([PSCustomObject]@{ 'subscriptionId' = $childMgSubId; 'subscriptionName'= $childMg.DisplayName; 'outOfScopeReason'= $result; 'ManagementGroupId' = $getMg.Name; 'ManagementGroupName' = $getMg.DisplayName })
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
            Write-Host " CustomDataCollection: Subscription processing duration: $((NEW-TIMESPAN -Start $startSubLoop -End $endSubLoop).TotalSeconds) seconds"
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
                    <li $liId $liclass><a $class href="#table_$mgId" id="hierarchy_$mgId"><p><img class="imgMgTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"></p><div class="fitme" id="fitme">$($tenantDisplayNameAndDefaultDomain)$($mgNameAndOrId)</div></a>
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
    $subscriptionsCnt = ($subscriptions | measure-object).count
    $subscriptionsOutOfScopelinked = $script:outOfScopeSubscriptions | where-object { $_.ManagementGroupId -eq $mgChild }
    $subscriptionsOutOfScopelinkedCnt = ($subscriptionsOutOfScopelinked | Measure-Object).count
    Write-Host "  Building HTML Hierarchy Tree for MG '$mgChild', $(($subscriptions | measure-object).count) Subscriptions"
    if ($subscriptionsCnt -gt 0 -or $subscriptionsOutOfScopelinkedCnt -gt 0){
        if ($subscriptionsCnt -gt 0 -and $subscriptionsOutOfScopelinkedCnt -gt 0){
$script:html += @"
            <li><a href="#table_$mgChild"><p id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg">$(($subscriptions | measure-object).count)x <img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg">$(($subscriptionsOutOfScopelinked | Measure-Object).count)x</p></a></li>
"@
        }
        if ($subscriptionsCnt -gt 0 -and $subscriptionsOutOfScopelinkedCnt -eq 0){
$script:html += @"
            <li><a href="#table_$mgChild"><p id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> $(($subscriptions | measure-object).count)x</p></a></li>
"@
        }
        if ($subscriptionsCnt -eq 0 -and $subscriptionsOutOfScopelinkedCnt -gt 0){
$script:html += @"
            <li><a href="#table_$mgChild"><p id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg">$(($subscriptionsOutOfScopelinked | Measure-Object).count)x</p></a></li>
"@
        }
    }
}

function hierarchySubForMgUlHTML($mgChild){
    $subscriptions = ($mgAndSubBaseQuery | Where-Object { "" -ne $_.Subscription -and $_.MgId -eq $mgChild }).SubscriptionId | Get-Unique
    $subscriptionsCnt = ($subscriptions | measure-object).count
    $subscriptionsOutOfScopelinked = $script:outOfScopeSubscriptions | where-object { $_.ManagementGroupId -eq $mgChild }
    $subscriptionsOutOfScopelinkedCnt = ($subscriptionsOutOfScopelinked | Measure-Object).count
    Write-Host "  Building HTML Hierarchy Tree for MG '$mgChild', $(($subscriptions | measure-object).count) Subscriptions"
    if ($subscriptionsCnt -gt 0 -or $subscriptionsOutOfScopelinkedCnt -gt 0){
        if ($subscriptionsCnt -gt 0 -and $subscriptionsOutOfScopelinkedCnt -gt 0){
$script:html += @"
            <ul><li><a href="#table_$mgChild"><p id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> $(($subscriptions | measure-object).count)x <img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg">$(($subscriptionsOutOfScopelinked | Measure-Object).count)x</p></a></li></ul>
"@
        }
        if ($subscriptionsCnt -gt 0 -and $subscriptionsOutOfScopelinkedCnt -eq 0){
$script:html += @"
            <ul><li><a href="#table_$mgChild"><p id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> $(($subscriptions | measure-object).count)x</p></a></li></ul>
"@
        }
        if ($subscriptionsCnt -eq 0 -and $subscriptionsOutOfScopelinkedCnt -gt 0){
$script:html += @"
            <ul><li><a href="#table_$mgChild"><p id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg">$(($subscriptionsOutOfScopelinked | Measure-Object).count)x</p></a></li></ul>
"@
        }
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

    $mgPath = $htAllMgsPath.($mgChild).path -join "/"

    $mgLinkedSubsCount = ((($mgAndSubBaseQuery | Where-Object { $_.MgId -eq "$mgChild" -and "" -ne $_.SubscriptionId }).SubscriptionId | Get-Unique) | measure-object).count
    $subscriptionsOutOfScopelinkedCount = ($script:outOfScopeSubscriptions | where-object { $_.ManagementGroupId -eq $mgChild } | Measure-Object).count
    if ($mgLinkedSubsCount -gt 0 -and $subscriptionsOutOfScopelinkedCount -eq 0) {
        $subInfo = "<img class=`"imgSub`" src=`"https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg`">$mgLinkedSubsCount"
    }
    if ($mgLinkedSubsCount -gt 0 -and $subscriptionsOutOfScopelinkedCount -gt 0) {
        $subInfo = "<img class=`"imgSub`" src=`"https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg`">$mgLinkedSubsCount <img class=`"imgSub`" src=`"https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg`">$subscriptionsOutOfScopelinkedCount"
    }
    if ($mgLinkedSubsCount -eq 0 -and $subscriptionsOutOfScopelinkedCount -gt 0) {
        $subInfo = "<img class=`"imgSub`" src=`"https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg`">$subscriptionsOutOfScopelinkedCount"
    }
    if ($mgLinkedSubsCount -eq 0 -and $subscriptionsOutOfScopelinkedCount -eq 0) {
        $subInfo = "<img class=`"imgSub`" src=`"https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_grey.svg`">"
    }

    if ($mgName -eq $mgId){
        $mgNameAndOrId = "<b>$mgName</b>"
    }
    else{
        $mgNameAndOrId = "<b>$mgName</b> ($mgId)"
    }

$script:html += @"
<button type="button" class="collapsible" id="table_$mgId">$levelSpacing<img class="imgMg" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> <span class="valignMiddle">$mgNameAndOrId $subInfo</span></button>
<div class="content">
<table class="bottomrow">
<tr><td class="detailstd"><p><a href="#hierarchy_$mgId"><i class="fa fa-eye" aria-hidden="true"></i> <i>Highlight Management Group in hierarchy tree</i></a></p></td></tr>
<tr><td class="detailstd"><p>Management Group Name: <b>$mgName</b></p></td></tr>
<tr><td class="detailstd"><p>Management Group Id: <b>$mgId</b></p></td></tr>
<tr><td class="detailstd"><p>Management Group Path: $mgPath</p></td></tr>
<tr><!--x--><td class="detailstd"><!--x-->
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
    $subscriptions = ($mgAndSubBaseQuery | Where-Object { "" -ne $_.SubscriptionId -and $_.MgId -eq $mgChild } | Sort-Object -Property SubscriptionId -Unique) | select-object SubscriptionId, Subscription
    $subscriptionLinkedCount = ($subscriptions | measure-object).count
    $subscriptionsOutOfScopelinked = $script:outOfScopeSubscriptions | where-object { $_.ManagementGroupId -eq $mgChild }
    $subscriptionsOutOfScopelinkedCount = ($subscriptionsOutOfScopelinked | Measure-Object).count
    if ($subscriptionsOutOfScopelinkedCount -gt 0){
        $subscriptionsOutOfScopelinkedInfo = "($subscriptionsOutOfScopelinkedCount out-of-scope)"
    }
    else{
        $subscriptionsOutOfScopelinkedInfo = ""
    }
    Write-Host "  Building HTML Hierarchy Table MG '$mgChild', $subscriptionLinkedCount Subscriptions"
    if ($subscriptionLinkedCount -gt 0){
$script:html += @"
    <tr>
        <td class="detailstd">
            <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $subscriptionLinkedCount Subscriptions linked $subscriptionsOutOfScopelinkedInfo</p></button>
            <div class="content"><!--collapsible-->
"@
        foreach ($subEntry in $subscriptions | sort-object -Property subscription, subscriptionId){
            $subPath = $htAllSubsMgPath.($subEntry.subscriptionId).path -join "/"
            if ($subscriptionLinkedCount -gt 1){
$script:html += @"
                <button type="button" class="collapsible"> <img class="imgSub" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle"><b>$($subEntry.subscription)</b> ($($subEntry.subscriptionId))</span></button>
                <div class="contentSub"><!--collapsiblePerSub-->
"@
            }
            #exactly 1
            else{
$script:html += @"
                <img class="imgSub" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle"><b>$($subEntry.subscription)</b> ($($subEntry.subscriptionId))</span></button>
"@
            }

$script:html += @"
<table class="subTable">
<tr><td class="detailstd"><p><a href="#hierarchySub_$mgChild"><i class="fa fa-eye" aria-hidden="true"></i> <i>Highlight Subscription in hierarchy tree</i></a></p></td></tr>
<tr><td class="detailstd"><p>Subscription Name: <b>$($subEntry.subscription)</b></p></td></tr>
<tr><td class="detailstd"><p>Subscription Id: <b>$($subEntry.subscriptionId)</b></p></td></tr>
<tr><td class="detailstd"><p>Subscription Path: $subPath</p></td></tr>
<tr><td class="detailstd">
"@
            tableMgSubDetailsHTML -mgOrSub "sub" -subscriptionId $subEntry.subscriptionId
$script:html += @"
                </table><!--subTable-->
"@
            if ($subscriptionLinkedCount -gt 1){
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
            <p><i class="fa fa-ban" aria-hidden="true"></i> $subscriptionLinkedCount Subscriptions linked $subscriptionsOutOfScopelinkedInfo</p>
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

#rsi
function tableMgSubDetailsHTML($mgOrSub, $mgChild, $subscriptionId){
    $script:scopescnter++
    $htmlScopeInsights =$null
#region ScopeInsightsBaseCollection
if ($mgOrSub -eq "mg"){
    #BLUEPRINT
    $blueprintReleatedQuery = $blueprintBaseQuery | Where-Object { $_.MgId -eq $mgChild -and "" -eq $_.SubscriptionId -and "" -eq $_.BlueprintAssignmentId}
    $blueprintsScoped = $blueprintReleatedQuery
    $blueprintsScopedCount = ($blueprintsScoped | measure-object).count
    #Resources
    $mgAllChildSubscriptions = @()
    $mgAllChildSubscriptions += foreach ($entry in $htAllSubsMgPath.keys){
        if (($htAllSubsMgPath.($entry).path) -contains "'$mgchild'"){
            $entry
        }
    }
    $resourcesAllChildSubscriptions += foreach ($mgAllChildSubscription in $mgAllChildSubscriptions){
        $resourcesAll | where-object { $_.subscriptionId -eq $mgAllChildSubscription } | Sort-Object -Property type, location
    }
    $resourcesAllChildSubscriptionsArray = [System.Collections.ArrayList]@()
    $grp = $resourcesAllChildSubscriptions | Group-Object -Property type, location
    foreach ($resLoc in $grp){
        $cnt=0
        $ResoureTypeAndLocation = $resLoc.Name -split ","
        $resLoc.Group.count_ | ForEach-Object { $cnt += $_ }
        $null = $resourcesAllChildSubscriptionsArray.Add([PSCustomObject]@{ 'ResourceType' = $ResoureTypeAndLocation[0]; 'Location'= $ResoureTypeAndLocation[1]; 'ResourceCount'= $cnt })
    }
    $resourcesAllChildSubscriptions.count_ | ForEach-Object { $resourcesAllChildSubscriptionTotal += $_ }
    $resourcesAllChildSubscriptionResourceTypeCount = (($resourcesAllChildSubscriptions | sort-object -Property type -Unique) | measure-object).count
    $resourcesAllChildSubscriptionLocationCount = (($resourcesAllChildSubscriptions | sort-object -Property location -Unique) | measure-object).count

    #childrenMgInfo
    $mgAllChildMgs = @()
    $mgAllChildMgs += foreach ($entry in $htAllMgsPath.keys){
        if (($htAllMgsPath.($entry).path) -contains "'$mgchild'"){
            $entry
        }
    }
    
    $cssClass = "mgDetailsTable"
}
if ($mgOrSub -eq "sub"){
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
    $subscriptionASCPoints = ($subscriptionDetailsReleatedQuery).SubscriptionASCSecureScore | Get-Unique
    $resourcesSubscription = $resourcesAll | where-object { $_.subscriptionId -eq $subscriptionId } | Sort-Object -Property type, location
    $resourcesSubscriptionTotal = 0
    $resourcesSubscription.count_ | ForEach-Object { $resourcesSubscriptionTotal += $_ }
    $resourcesSubscriptionResourceTypeCount = (($resourcesSubscription | sort-object -Property type -Unique) | measure-object).count
    $resourcesSubscriptionLocationCount = (($resourcesSubscription | sort-object -Property location -Unique) | measure-object).count

    $cssClass = "subDetailsTable"
}
#endregion ScopeInsightsBaseCollection

if ($mgOrSub -eq "sub"){
$htmlScopeInsights += @"
<p>State: $subscriptionState</p>
</td></tr>
<tr><td class="detailstd"><p>QuotaId: $subscriptionQuotaId</p></td></tr>
<tr><td class="detailstd"><p><i class="fa fa-shield" aria-hidden="true"></i> ASC Secure Score: $subscriptionASCPoints</p></td></tr>
<tr><td class="detailstd">
"@

if (-not $NoResourceProvidersDetailed){
#ResourceProvider
#region ScopeInsightsResourceProvidersDetailed
if (($htResourceProvidersAll.Keys | Measure-Object).count -gt 0){
    $tfCount = ($arrayResourceProvidersAll | Measure-Object).Count
    $tableId = "DetailsTable_ResourceProvider_$($subscriptionId -replace '-','_')"
$htmlScopeInsights += @"
<button type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Providers Detailed</span></button>
<div class="content">
<table id="$tableId" class="$cssClass">
<thead>
<tr>
<th>Provider</th>
<th>State</th>
</tr>
</thead>
<tbody>
"@
    $htmlScopeInsightsResourceProvidersDetailed = $null
    foreach ($provider in ($htResourceProvidersAll).($subscriptionId).Providers){
$htmlScopeInsightsResourceProvidersDetailed += @"
<tr>
<td>$($provider.namespace)</td>
<td>$($provider.registrationState)</td>
</tr>
"@ 
    }
$htmlScopeInsights += $htmlScopeInsightsResourceProvidersDetailed
$htmlScopeInsights += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,          
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
$htmlScopeInsights += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
}
$htmlScopeInsights += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_1: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlScopeInsights += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($htResourceProvidersAll.Keys | Measure-Object).count) Resource Providers</span></p>
"@
}
$htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
#endregion ScopeInsightsResourceProvidersDetailed
}

#ResourceGroups
#region ScopeInsightsResourceGroups
if ($SubscriptionResourceGroupsCount -gt 0){
$htmlScopeInsights += @"
    <p><i class="fa fa-check-circle" aria-hidden="true"></i> $SubscriptionResourceGroupsCount Resource Groups | Limit: ($SubscriptionResourceGroupsCount/$LimitResourceGroups)</p>
"@
}
else{
$htmlScopeInsights += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> $SubscriptionResourceGroupsCount Resource Groups</p>
"@
}
$htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
}
#endregion ScopeInsightsResourceGroups

#Tags
#region ScopeInsightsTags
if ($mgOrSub -eq "sub"){
    if ($tagsSubscriptionCount -gt 0){
        $tfCount = $tagsSubscriptionCount
        $tableId = "DetailsTable_Tags_$($subscriptionId -replace '-','_')"
$htmlScopeInsights += @"
<button type="button" class="collapsible">
<p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $tagsSubscriptionCount Subscription Tags | Limit: ($tagsSubscriptionCount/$LimitTagsSubscription)</p></button>
<div class="content">
<table id="$tableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">Tag Name</th>
<th>Tag Value</th>
</tr>
</thead>
<tbody>
"@
        $htmlScopeInsightsTags = $null
        foreach ($tag in (($htSubscriptionTags).($subscriptionId)).keys | Sort-Object){
$htmlScopeInsightsTags += @"
<tr>
<td>$tag</td>
<td>$($htSubscriptionTags.$subscriptionId[$tag])</td>
</tr>
"@        
        }
$htmlScopeInsights += $htmlScopeInsightsTags 
$htmlScopeInsights += @"
            </tbody>
        </table>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlScopeInsights += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
}
$htmlScopeInsights += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
                col_types: [
                    'caseinsensitivestring',
                    'caseinsensitivestring'
                ],
extensions: [{ name: 'sort' }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
    </div>
"@
    }
    else{
$htmlScopeInsights += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> $tagsSubscriptionCount Subscription Tags</p>
"@
    }
$htmlScopeInsights += @"
        </td></tr>
        <tr><!--y--><td class="detailstd"><!--y-->
"@
}
#endregion ScopeInsightsTags

#MgChildInfo
#region ScopeInsightsManagementGroups
if ($mgOrSub -eq "mg"){
    
$htmlScopeInsights += @"
<p>$(($mgAllChildMgs | Measure-Object).count -1) ManagementGroups below this scope</p>
</td></tr>
<tr><td class="detailstd"><p>$(($mgAllChildSubscriptions | Measure-Object).count) Subscriptions below this scope</p></td></tr>
<tr><td class="detailstd">
"@
}
#endregion ScopeInsightsManagementGroups

#resources 
#region ScopeInsightsResources
if ($mgOrSub -eq "mg"){
    if ($resourcesAllChildSubscriptionLocationCount -gt 0){
        $tfCount = ($resourcesAllChildSubscriptionsArray | measure-object).count
        $tableId = "DetailsTable_Resources_$($mgChild -replace '-','_')"
$htmlScopeInsights += @"
<button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $resourcesAllChildSubscriptionResourceTypeCount ResourceTypes ($resourcesAllChildSubscriptionTotal Resources) in $resourcesAllChildSubscriptionLocationCount Locations (all Subscriptions below this scope)</p></button>
<div class="content">
<table id="$tableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">ResourceType</th>
<th>Location</th>
<th>Count</th>
</tr>
</thead>
<tbody>
"@
        $htmlScopeInsightsResources = $null
        foreach ($resourceAllChildSubscriptionResourceTypePerLocation in $resourcesAllChildSubscriptionsArray | sort-object @{Expression={$_.ResourceType}}, @{Expression={$_.location}}){
                    
$htmlScopeInsightsResources += @"
<tr>
<td>$($resourceAllChildSubscriptionResourceTypePerLocation.ResourceType)</td>
<td>$($resourceAllChildSubscriptionResourceTypePerLocation.location)</td>
<td>$($resourceAllChildSubscriptionResourceTypePerLocation.ResourceCount)</td>
</tr>
"@        
        }
$htmlScopeInsights += $htmlScopeInsightsResources
$htmlScopeInsights += @"
            </tbody>
        </table>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlScopeInsights += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@  
}
$htmlScopeInsights += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
                col_types: [
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'number'
                ],
extensions: [{ name: 'sort' }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
    </div>
"@
    }
    else{
$htmlScopeInsights += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> $resourcesAllChildSubscriptionResourceTypeCount ResourceTypes (all Subscriptions below this scope)</p>
"@
    }
$htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
}

if ($mgOrSub -eq "sub"){
    if ($resourcesSubscriptionResourceTypeCount -gt 0){
        $tfCount = ($resourcesSubscription | Measure-Object).Count
        $tableId = "DetailsTable_Resources_$($subscriptionId -replace '-','_')"
$htmlScopeInsights += @"
<button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $resourcesSubscriptionResourceTypeCount ResourceTypes ($resourcesSubscriptionTotal Resources) in $resourcesSubscriptionLocationCount Locations</p></button>
<div class="content">
<table id="$tableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">ResourceType</th>
<th>Location</th>
<th>Count</th>
</tr>
</thead>
<tbody>
"@
        $htmlScopeInsightsResources = $null
        foreach ($resourceSubscriptionResourceTypePerLocation in $resourcesSubscription | sort-object @{Expression={$_.type}}, @{Expression={$_.location}}, @{Expression={$_.count_}}){
$htmlScopeInsightsResources += @"
<tr>
<td>$($resourceSubscriptionResourceTypePerLocation.type)</td>
<td>$($resourceSubscriptionResourceTypePerLocation.location)</td>
<td>$($resourceSubscriptionResourceTypePerLocation.count_)</td>
</tr>
"@        
        }
$htmlScopeInsights += $htmlScopeInsightsResources
$htmlScopeInsights += @"
            </tbody>
        </table>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlScopeInsights += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@ 
}
$htmlScopeInsights += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
                col_types: [
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'number'
                ],
extensions: [{ name: 'sort' }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
    </div>
"@
    }
    else{
$htmlScopeInsights += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> $resourcesSubscriptionResourceTypeCount ResourceTypes</p>
"@
    }
$htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
}
#endregion ScopeInsightsManagementGroups

#resourcesDiagnosticsCapable
#region ScopeInsightsDiagnosticsCapable
if ($mgOrSub -eq "mg"){
        $resourceTypesUnique = ($resourcesAllChildSubscriptions | select-object type -Unique).type
    $resourceTypesSummarizedArray = @()
    $resourceTypesSummarizedArray += foreach ($resourceTypeUnique in $resourceTypesUnique){
        $resourcesTypeCountTotal = 0
        ($resourcesAllChildSubscriptions | Where-Object { $_.type -eq $resourceTypeUnique }).count_ | ForEach-Object { $resourcesTypeCountTotal += $_ }
        $dataFromResourceTypesDiagnosticsArray = $resourceTypesDiagnosticsArray | Where-Object { $_.ResourceType -eq $resourceTypeUnique}
        if ($dataFromResourceTypesDiagnosticsArray.Metrics -eq $true -or $dataFromResourceTypesDiagnosticsArray.Logs -eq $true){
            $resourceDiagnosticscapable = $true
        }
        else{
            $resourceDiagnosticscapable = $false
        }
        [PSCustomObject]@{'ResourceType' = $resourceTypeUnique; 'ResourceCount' = $resourcesTypeCountTotal;'DiagnosticsCapable'= $resourceDiagnosticscapable; 'Metrics'= $dataFromResourceTypesDiagnosticsArray.Metrics; 'Logs' = $dataFromResourceTypesDiagnosticsArray.Logs; 'LogCategories' = ($dataFromResourceTypesDiagnosticsArray.LogCategories -join "$CsvDelimiterOpposite ") }
    }
    $subscriptionResourceTypesDiagnosticsCapableMetricsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Metrics -eq $true } | Measure-Object).count
    $subscriptionResourceTypesDiagnosticsCapableLogsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Logs -eq $true } | Measure-Object).count
    $subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Metrics -eq $true -or $_.Logs -eq $true } | Measure-Object).count
    
    if ($resourcesAllChildSubscriptionResourceTypeCount -gt 0){
        $tfCount = $resourcesAllChildSubscriptionResourceTypeCount
        $tableId = "DetailsTable_resourcesDiagnosticsCapable_$($mgchild -replace '-','_')"
$htmlScopeInsights += @"
<button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount/$resourcesAllChildSubscriptionResourceTypeCount ResourceTypes Diagnostics capable ($subscriptionResourceTypesDiagnosticsCapableMetricsCount Metrics, $subscriptionResourceTypesDiagnosticsCapableLogsCount Logs) (all Subscriptions below this scope)</p></button>
<div class="content">
<table id="$tableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">ResourceType</th>
<th>Resource Count</th>
<th>Diagnostics capable</th>
<th>Metrics</th>
<th>Logs</th>
<th>LogCategories</th>
</tr>
</thead>
<tbody>
"@
        $htmlScopeInsightsDiagnosticsCapable = $null
        foreach ($resourceSubscriptionResourceType in $resourceTypesSummarizedArray | sort-object @{Expression={$_.ResourceType}}){
$htmlScopeInsightsDiagnosticsCapable += @"
<tr>
<td>$($resourceSubscriptionResourceType.ResourceType)</td>
<td>$($resourceSubscriptionResourceType.ResourceCount)</td>
<td>$($resourceSubscriptionResourceType.DiagnosticsCapable)</td>
<td>$($resourceSubscriptionResourceType.Metrics)</td>
<td>$($resourceSubscriptionResourceType.Logs)</td>
<td>$($resourceSubscriptionResourceType.LogCategories)</td>
</tr>
"@        
        }
$htmlScopeInsights += $htmlScopeInsightsDiagnosticsCapable
$htmlScopeInsights += @"
            </tbody>
        </table>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlScopeInsights += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@ 
}
$htmlScopeInsights += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
                col_2: 'select',
                col_3: 'select',
                col_4: 'select',
                col_types: [
                    'caseinsensitivestring',
                    'number',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring'
                ],
extensions: [{ name: 'sort' }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
    </div>
"@
    }
    else{
$htmlScopeInsights += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> $resourcesAllChildSubscriptionResourceTypeCount ResourceTypes Diagnostics capable (all Subscriptions below this scope)</p>
"@
    }
$htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
}

if ($mgOrSub -eq "sub"){
    $resourceTypesUnique = ($resourcesSubscription | select-object type -Unique).type
    $resourceTypesSummarizedArray = @()
    $resourceTypesSummarizedArray += foreach ($resourceTypeUnique in $resourceTypesUnique){
        $resourcesTypeCountTotal = 0
        ($resourcesSubscription | Where-Object { $_.type -eq $resourceTypeUnique }).count_ | ForEach-Object { $resourcesTypeCountTotal += $_ }
        $dataFromResourceTypesDiagnosticsArray = $resourceTypesDiagnosticsArray | Where-Object { $_.ResourceType -eq $resourceTypeUnique}
        if ($dataFromResourceTypesDiagnosticsArray.Metrics -eq $true -or $dataFromResourceTypesDiagnosticsArray.Logs -eq $true){
            $resourceDiagnosticscapable = $true
        }
        else{
            $resourceDiagnosticscapable = $false
        }
        [PSCustomObject]@{'ResourceType' = $resourceTypeUnique; 'ResourceCount' = $resourcesTypeCountTotal;'DiagnosticsCapable'= $resourceDiagnosticscapable; 'Metrics'= $dataFromResourceTypesDiagnosticsArray.Metrics; 'Logs' = $dataFromResourceTypesDiagnosticsArray.Logs; 'LogCategories' = ($dataFromResourceTypesDiagnosticsArray.LogCategories -join "$CsvDelimiterOpposite ") }
    }

    $subscriptionResourceTypesDiagnosticsCapableMetricsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Metrics -eq $true } | Measure-Object).count
    $subscriptionResourceTypesDiagnosticsCapableLogsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Logs -eq $true } | Measure-Object).count
    $subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Metrics -eq $true -or $_.Logs -eq $true } | Measure-Object).count

    if ($resourcesSubscriptionResourceTypeCount -gt 0){
        $tfCount = $resourcesSubscriptionResourceTypeCount
        $tableId = "DetailsTable_resourcesDiagnosticsCapable_$($subscriptionId -replace '-','_')"
$htmlScopeInsights += @"
<button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount/$resourcesSubscriptionResourceTypeCount ResourceTypes Diagnostics capable ($subscriptionResourceTypesDiagnosticsCapableMetricsCount Metrics, $subscriptionResourceTypesDiagnosticsCapableLogsCount Logs)</p></button>
<div class="content">
<table id="$tableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">ResourceType</th>
<th>Resource Count</th>
<th>Diagnostics capable</th>
<th>Metrics</th>
<th>Logs</th>
<th>LogCategories</th>
</tr>
</thead>
<tbody>
"@
        $htmlScopeInsightsDiagnosticsCapable = $null
        foreach ($resourceSubscriptionResourceType in $resourceTypesSummarizedArray | sort-object @{Expression={$_.ResourceType}}){
$htmlScopeInsightsDiagnosticsCapable += @"
<tr>
<td>$($resourceSubscriptionResourceType.ResourceType)</td>
<td>$($resourceSubscriptionResourceType.ResourceCount)</td>
<td>$($resourceSubscriptionResourceType.DiagnosticsCapable)</td>
<td>$($resourceSubscriptionResourceType.Metrics)</td>
<td>$($resourceSubscriptionResourceType.Logs)</td>
<td>$($resourceSubscriptionResourceType.LogCategories)</td>
</tr>
"@        
        }
$htmlScopeInsights += $htmlScopeInsightsDiagnosticsCapable
$htmlScopeInsights += @"
            </tbody>
        </table>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlScopeInsights += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@  
}
$htmlScopeInsights += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
                col_2: 'select',
                col_3: 'select',
                col_4: 'select',
                col_types: [
                    'caseinsensitivestring',
                    'number',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring'
                ],
extensions: [{ name: 'sort' }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
    </div>
"@
    }
    else{
$htmlScopeInsights += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> $resourcesSubscriptionResourceTypeCount ResourceTypes Diagnostics capable</p>
"@
    }
$htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
}
#endregion ScopeInsightsDiagnosticsCapable

#PolicyAssignments
#region ScopeInsightsPolicyAssignments
if ($mgOrSub -eq "mg"){
    $tableIdentifier = $mgChild
    $policiesAssigned = $script:policyAssignmentsAllArray | Where-Object { "" -eq $_.subscriptionId -and $_.MgId -eq $mgChild -and $_.PolicyVariant -eq "Policy" }
}
if ($mgOrSub -eq "sub"){
    $tableIdentifier = $subscriptionId
    $policiesAssigned = $script:policyAssignmentsAllArray | Where-Object { $_.subscriptionId -eq $subscriptionId -and $_.PolicyVariant -eq "Policy" }
}

$policiesCount = ($policiesAssigned | measure-object).count
$policiesCountBuiltin = (($policiesAssigned | where-object { $_.PolicyType -eq "BuiltIn" }) | measure-object).count
$policiesCountCustom = (($policiesAssigned | where-object { $_.PolicyType -eq "Custom" }) | measure-object).count
$policiesAssignedAtScope = (($policiesAssigned | where-object { $_.Inheritance -match "this*" }) | measure-object).count
$policiesInherited = (($policiesAssigned | where-object { $_.Inheritance -notmatch "this*" }) | measure-object).count

if (($policiesAssigned | measure-object).count -gt 0) {
    $tfCount = ($policiesAssigned | measure-object).count
    $tableId = "DetailsTable_PolicyAssignments_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
$htmlScopeInsights += @"
<button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $policiesCount Policy Assignments ($policiesAssignedAtScope at scope, $policiesInherited inherited) (Builtin: $policiesCountBuiltin | Custom: $policiesCountCustom)</p></button>
<div class="content">
<table id="$tableId" class="$cssClass">
<thead>
<tr>
<th>Inheritance</th>
<th>ScopeExcluded</th>
<th>Policy DisplayName</th>
<th>PolicyId</th>
<th>Type</th>
<th>Category</th>
<th>Effect</th>
<th>Policies NonCmplnt</th>
<th>Policies Compliant</th>
<th>Resources NonCmplnt</th>
<th>Resources Compliant</th>
<th>Role/Assignment</th>
<th>Assignment DisplayName</th>
<th>AssignmentId</th>
</tr>
</thead>
<tbody>
"@
    $htmlScopeInsightsPolicyAssignments = $null
    foreach ($policyAssignment in $policiesAssigned | sort-object @{Expression={$_.Level}}, @{Expression={$_.MgName}}, @{Expression={$_.MgId}}, @{Expression={$_.SubscriptionName}}, @{Expression={$_.SubscriptionId}}) {
$htmlScopeInsightsPolicyAssignments += @"
<tr>
<td>$($policyAssignment.Inheritance)</td>
<td>$($policyAssignment.ExcludedScope)</td>
<td class="breakwordall">$($policyAssignment.PolicyName)</td>
<td class="breakwordall">$($policyAssignment.PolicyId)</td>
<td>$($policyAssignment.PolicyType)</td>
<td>$($policyAssignment.PolicyCategory)</td>
<td>$($policyAssignment.Effect)</td>
<td>$($policyAssignment.NonCompliantPolicies)</td>
<td>$($policyAssignment.CompliantPolicies)</td>
<td>$($policyAssignment.NonCompliantResources)</td>
<td>$($policyAssignment.CompliantResources)</td>
<td class="breakwordall">$($policyAssignment.RelatedRoleAssignments)</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentDisplayName)</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentId)</td>
</tr>
"@
    }
$htmlScopeInsights += $htmlScopeInsightsPolicyAssignments
$htmlScopeInsights += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlScopeInsights += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
}
$htmlScopeInsights += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_1: 'select',
            col_4: 'select',
            col_6: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number',
                'number',
                'number',
                'number',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
            watermark: ['', '', '', '', '', '', '', '', '', '', '', '', '', ''],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlScopeInsights += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($policiesAssigned | measure-object).count) Policy Assignments</span></p>
"@
}
$htmlScopeInsights += @"
        </td></tr>
        <tr><!--y--><td class="detailstd"><!--y-->
"@
#endregion ScopeInsightsPolicyAssignments

#PolicySetAssignments
#region ScopeInsightsPolicySetAssignments
if ($mgOrSub -eq "mg"){
    $tableIdentifier = $mgChild
    $policySetsAssigned = $script:policyAssignmentsAllArray | Where-Object { "" -eq $_.subscriptionId -and $_.MgId -eq $mgChild -and $_.PolicyVariant -eq "PolicySet" }
}
if ($mgOrSub -eq "sub"){
    $tableIdentifier = $subscriptionId
    $policySetsAssigned = $script:policyAssignmentsAllArray | Where-Object { $_.subscriptionId -eq $subscriptionId -and $_.PolicyVariant -eq "PolicySet" }
}

$policySetsCount = ($policySetsAssigned | measure-object).count
$policySetsCountBuiltin = (($policySetsAssigned | where-object { $_.PolicyType -eq "BuiltIn" }) | measure-object).count
$policySetsCountCustom = (($policySetsAssigned | where-object { $_.PolicyType -eq "Custom" }) | measure-object).count
$policySetsAssignedAtScope = (($policySetsAssigned | where-object { $_.Inheritance -match "this*" }) | measure-object).count
$policySetsInherited = (($policySetsAssigned | where-object { $_.Inheritance -notmatch "this*" }) | measure-object).count

if (($policySetsAssigned | measure-object).count -gt 0) {
    $tfCount = ($policiesAssigned | measure-object).count
    $tableId = "DetailsTable_PolicySetAssignments_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
$htmlScopeInsights += @"
<button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $policySetsCount PolicySet Assignments ($policySetsAssignedAtScope at scope, $policySetsInherited inherited) (Builtin: $policySetsCountBuiltin | Custom: $policySetsCountCustom)</p></button>
<div class="content">
<table id="$tableId" class="$cssClass">
<thead>
<tr>
<th>Inheritance</th>
<th>ScopeExcluded</th>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
<th>Type</th>
<th>Category</th>
<th>Policies NonCmplnt</th>
<th>Policies Compliant</th>
<th>Resources NonCmplnt</th>
<th>Resources Compliant</th>
<th>Role/Assignment</th>
<th>Assignment DisplayName</th>
<th>AssignmentId</th>
</tr>
</thead>
<tbody>
"@
    $htmlScopeInsightsPolicySetAssignments = $null
    foreach ($policyAssignment in $policySetsAssigned | sort-object -Property Level, MgName, MgId, SubscriptionName, SubscriptionId) {
$htmlScopeInsightsPolicySetAssignments += @"
<tr>
<td>$($policyAssignment.Inheritance)</td>
<td>$($policyAssignment.ExcludedScope)</td>
<td class="breakwordall">$($policyAssignment.PolicyName)</td>
<td class="breakwordall">$($policyAssignment.PolicyId)</td>
<td>$($policyAssignment.PolicyType)</td>
<td>$($policyAssignment.PolicyCategory)</td>
<td>$($policyAssignment.NonCompliantPolicies)</td>
<td>$($policyAssignment.CompliantPolicies)</td>
<td>$($policyAssignment.NonCompliantResources)</td>
<td>$($policyAssignment.CompliantResources)</td>
<td class="breakwordall">$($policyAssignment.RelatedRoleAssignments)</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentDisplayName)</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentId)</td>
</tr>
"@
    }
$htmlScopeInsights += $htmlScopeInsightsPolicySetAssignments
$htmlScopeInsights += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlScopeInsights += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@   
}
$htmlScopeInsights += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_1: 'select',
            col_4: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number',
                'number',
                'number',
                'number',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
            watermark: ['', '', '', '', '', '', '', '', '', '', '', '', ''],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlScopeInsights += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($policySetsAssigned | measure-object).count) PolicySet Assignments</span></p>
"@
}
$htmlScopeInsights += @"
        </td></tr>
        <tr><!--y--><td class="detailstd"><!--y-->
"@
#endregion ScopeInsightsPolicySetAssignments

#PolicyAssigmentsLimit (Policy+PolicySet)
#region ScopeInsightsPolicyAssigmentsLimit
if ($policiesAssignedAtScope -eq 0 -and $policySetsAssignedAtScope -eq 0){
    if ($mgOrSub -eq "mg"){
        $limit = $LimitPOLICYPolicyAssignmentsManagementGroup
    }
    if ($mgOrSub -eq "sub"){
        $limit = $LimitPOLICYPolicyAssignmentsSubscription
    }
    $faimage = "<i class=`"fa fa-ban`" aria-hidden=`"true`"></i>"
    
$htmlScopeInsights += @"
            <p>$faImage Policy Assignment Limit: 0/$limit</p>
"@
}
else{
    if ($mgOrSub -eq "mg"){
        $scopePolicyAssignmentsLimit = (($policyBaseQuery | where-object { "" -eq $_.SubscriptionId -and $_.MgId -eq "$mgChild" }) | Select-Object MgId, PolicyAssigmentAtScopeCount, PolicySetAssigmentAtScopeCount, PolicyAndPolicySetAssigmentAtScopeCount, PolicyAssigmentLimit -Unique)
    }
    if ($mgOrSub -eq "sub"){
        $scopePolicyAssignmentsLimit = (($policyBaseQuery | where-object { $_.SubscriptionId -eq $subscriptionId }) | Select-Object MgId, Subscription, SubscriptionId, PolicyAssigmentAtScopeCount, PolicySetAssigmentAtScopeCount, PolicyAndPolicySetAssigmentAtScopeCount, PolicyAssigmentLimit -Unique)
    }
    
    if ($($scopePolicyAssignmentsLimit.PolicyAndPolicySetAssigmentAtScopeCount) -gt ($($scopePolicyAssignmentsLimit.PolicyAssigmentLimit) * $LimitCriticalPercentage / 100)){
        $faImage = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
    }
    else{
        $faimage = "<i class=`"fa fa-check-circle`" aria-hidden=`"true`"></i>"
    }
$htmlScopeInsights += @"
            <p>$faImage Policy Assignment Limit: $($scopePolicyAssignmentsLimit.PolicyAndPolicySetAssigmentAtScopeCount)/$($scopePolicyAssignmentsLimit.PolicyAssigmentLimit)</p>
"@
}
$htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
#endregion ScopeInsightsPolicyAssigmentsLimit

#ScopedPolicies
#region ScopeInsightsScopedPolicies
if ($mgOrSub -eq "mg"){
    $tableIdentifier = $mgChild
    $scopePolicies = ($script:customPoliciesDetailed | where-object { $_.PolicyDefinitionId  -match "/providers/Microsoft.Management/managementGroups/$mgChild/" })
    $scopePoliciesCount = ($scopePolicies | Measure-Object).count
}
if ($mgOrSub -eq "sub"){
    $tableIdentifier = $subscriptionId
    $scopePolicies = ($script:customPoliciesDetailed | where-object { $_.PolicyDefinitionId  -match "/subscriptions/$subscriptionId/" })
    $scopePoliciesCount = ($scopePolicies | Measure-Object).count
}

if ($scopePoliciesCount -gt 0){
    $tfCount = $scopePoliciesCount
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

$htmlScopeInsights += @"
<button type="button" class="collapsible"><p>$faIcon $scopePoliciesCount Custom Policies scoped | Limit: ($scopePoliciesCount/$LimitPOLICYPolicyScoped)</p></button>
<div class="content">
<table id="$tableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">Policy DisplayName</th>
<th>PolicyId</th>
<th>Policy effect</th>
<th>Role Definitions</th>
<th>Unique Assignments</th>
<th>Used in PolicySets</th>
</tr>
</thead>
<tbody>
"@
    $htmlScopeInsightsScopedPolicies = $null
    foreach ($custompolicy in $scopePolicies | Sort-Object @{Expression={$_.PolicyDisplayName}}, @{Expression={$_.PolicyDefinitionId}}){
$htmlScopeInsightsScopedPolicies += @"
<tr>
<td>$($customPolicy.PolicyDisplayName)</td>
<td class="breakwordall">$($customPolicy.PolicyDefinitionId)</td>
<td>$($customPolicy.PolicyEffect)</td>
<td>$($customPolicy.RoleDefinitions)</td>
<td class="breakwordall">$($customPolicy.UniqueAssignments)</td>
<td class="breakwordall">$($customPolicy.UsedInPolicySets)</td>
</tr>
"@ 
    }
$htmlScopeInsights += $htmlScopeInsightsScopedPolicies
$htmlScopeInsights += @"
                </tbody>
            </table>
        </div>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlScopeInsights += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@   
}
$htmlScopeInsights += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
                col_types: [
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring'
                ],
extensions: [{ name: 'sort' }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
"@
}
else{
$htmlScopeInsights += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $scopePoliciesCount Custom Policies scoped</p>
"@
}
$htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
#endregion ScopeInsightsScopedPolicies

#ScopedPolicySets
#region ScopeInsightsScopedPolicySets
if ($mgOrSub -eq "mg"){
    $tableIdentifier = $mgChild
    $scopePolicySets = ($script:customPolicySetsDetailed | where-object { $_.PolicySetDefinitionId  -match "/providers/Microsoft.Management/managementGroups/$mgChild/" })
    $scopePolicySetsCount = ($scopePolicySets | Measure-Object).count
}
if ($mgOrSub -eq "sub"){
    $tableIdentifier = $subscriptionId
    $scopePolicySets = ($script:customPolicySetsDetailed | where-object { $_.PolicySetDefinitionId  -match "/subscriptions/$subscriptionId/" })
    $scopePolicySetsCount = ($scopePolicySets | Measure-Object).count
}

if ($scopePolicySetsCount -gt 0){
    $tfCount = $scopePolicySetsCount
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
$htmlScopeInsights += @"
<button type="button" class="collapsible"><p>$faIcon $scopePolicySetsCount Custom PolicySets scoped | Limit: ($scopePolicySetsCount/$LimitPOLICYPolicySetScoped)</p></button>
<div class="content">
<table id="$tableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">PolicySet DisplayName</th>
<th>PolicySetId</th>
<th>Unique Assignments</th>
<th>Policies Used</th>
</tr>
</thead>
<tbody>
"@
    $htmlScopeInsightsScopedPolicySets = $null
    foreach ($custompolicySet in $scopePolicySets | Sort-Object @{Expression={$_.PolicySetDisplayName}}, @{Expression={$_.PolicySetDefinitionId}}){
$htmlScopeInsightsScopedPolicySets += @"
<tr>
<td>$($custompolicySet.PolicySetDisplayName)</td>
<td>$($custompolicySet.PolicySetDefinitionId)</td>
<td>$($custompolicySet.UniqueAssignments)</td>
<td>$($custompolicySet.PoliciesUsed)</td>
</tr>
"@        
    }
$htmlScopeInsights += $htmlScopeInsightsScopedPolicySets
$htmlScopeInsights += @"
                </tbody>
            </table>
        </div>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlScopeInsights += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@   
}
$htmlScopeInsights += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
                col_types: [
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring'
                ],
extensions: [{ name: 'sort' }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
"@
}
else{
$htmlScopeInsights += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $scopePolicySetsCount Custom PolicySets scoped</p>
"@
}
$htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
#endregion ScopeInsightsScopedPolicySets

#BlueprintAssignments
#region ScopeInsightsBlueprintAssignments
if ($mgOrSub -eq "sub"){
    if ($blueprintsAssignedCount -gt 0){
        
        if ($mgOrSub -eq "mg"){
            $tableIdentifier = $mgChild
        }
        if ($mgOrSub -eq "sub"){
            $tableIdentifier = $subscriptionId
        }
        $tableId = "DetailsTable_BlueprintAssignment_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
$htmlScopeInsights += @"
<button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintsAssignedCount Blueprints assigned</p></button>
<div class="content">
<table id="$tableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">Blueprint Name</th>
<th>Blueprint DisplayName</th>
<th>Blueprint Description</th>
<th>BlueprintId</th>
<th>Blueprint Version</th>
<th>Blueprint AssignmentId</th>
</tr>
</thead>
<tbody>
"@
        $htmlScopeInsightsBlueprintAssignments = $null
        foreach ($blueprintAssigned in $blueprintsAssigned){
$htmlScopeInsightsBlueprintAssignments += @"
<tr>
<td>$($blueprintAssigned.BlueprintName)</td>
<td>$($blueprintAssigned.BlueprintDisplayName)</td>
<td>$($blueprintAssigned.BlueprintDescription)</td>
<td>$($blueprintAssigned.BlueprintId)</td>
<td>$($blueprintAssigned.BlueprintAssignmentVersion)</td>
<td>$($blueprintAssigned.BlueprintAssignmentId)</td>
</tr>
"@        
        }
$htmlScopeInsights += $htmlScopeInsightsBlueprintAssignments
$htmlScopeInsights += @"
                </tbody>
            </table>
        </div>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlScopeInsights += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@   
}
$htmlScopeInsights += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
                col_types: [
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring'
                ],
extensions: [{ name: 'sort' }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
"@
    }
    else{
$htmlScopeInsights += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $blueprintsAssignedCount Blueprints assigned</p>
"@
    }
$htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
}
#endregion ScopeInsightsBlueprintAssignments

#BlueprintsScoped
#region ScopeInsightsBlueprintsScoped
if ($blueprintsScopedCount -gt 0){
    $tfCount = $blueprintsScopedCount
    if ($mgOrSub -eq "mg"){
        $tableIdentifier = $mgChild
    }
    if ($mgOrSub -eq "sub"){
        $tableIdentifier = $subscriptionId
    }
    $tableId = "DetailsTable_BlueprintScoped_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
$htmlScopeInsights += @"
<button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintsScopedCount Blueprints scoped</p></button>
<div class="content">
<table id="$tableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">Blueprint Name</th>
<th>Blueprint DisplayName</th>
<th>Blueprint Description</th>
<th>BlueprintId</th>
</tr>
</thead>
<tbody>
"@
    $htmlScopeInsightsBlueprintsScoped = $null
    foreach ($blueprintScoped in $blueprintsScoped){
$htmlScopeInsightsBlueprintsScoped += @"
<tr>
<td>$($blueprintScoped.BlueprintName)</td>
<td>$($blueprintScoped.BlueprintDisplayName)</td>
<td>$($blueprintScoped.BlueprintDescription)</td>
<td>$($blueprintScoped.BlueprintId)</td>
</tr>
"@        
    }
$htmlScopeInsights += $htmlScopeInsightsBlueprintsScoped
$htmlScopeInsights += @"
                </tbody>
            </table>
        </div>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlScopeInsights += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@    
}
$htmlScopeInsights += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
                col_types: [
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring'
                ],
extensions: [{ name: 'sort' }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
"@
}
else{
$htmlScopeInsights += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $blueprintsScopedCount Blueprints scoped</p>
"@
}
$htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
#endregion ScopeInsightsBlueprintsScoped

#RoleAssignments
#region ScopeInsightsRoleAssignments
if ($mgOrSub -eq "mg"){
    $tableIdentifier = $mgChild
    $LimitRoleAssignmentsScope = $LimitRBACRoleAssignmentsManagementGroup
    $rolesAssigned = $script:rbacAll | Where-Object { "" -eq $_.subscriptionId -and $_.MgId -eq $mgChild }
}
if ($mgOrSub -eq "sub"){
    $tableIdentifier = $subscriptionId
    $LimitRoleAssignmentsScope = $LimitRBACRoleAssignmentsSubscription
    $rolesAssigned = $script:rbacAll | Where-Object { $_.subscriptionId -eq $subscriptionId }
}

$rolesAssignedCount = ($rolesAssigned | Measure-Object).count

$rolesAssignedInheritedCount = ($rolesAssigned | Where-Object { $_.Scope -notlike "this*" } | Measure-Object).count
$rolesAssignedAtScopeCount = $rolesAssignedCount - $rolesAssignedInheritedCount

$rolesAssignedUser = ($rolesAssigned | Where-Object { $_.ObjectType -eq "User"} | Measure-Object).count
$rolesAssignedGroup = ($rolesAssigned | Where-Object { $_.ObjectType -eq "Group"} | Measure-Object).count
$rolesAssignedServicePrincipal = ($rolesAssigned | Where-Object { $_.ObjectType -eq "ServicePrincipal"} | Measure-Object).count
$rolesAssignedUnknown = ($rolesAssigned | Where-Object { $_.ObjectType -eq "Unknown"} | Measure-Object).count
$roleAssignmentsRelatedToPolicyCount = ($rolesAssigned | Where-Object {$_.RbacRelatedPolicyAssignment -ne "none"} | Measure-Object).count

$roleSecurityFindingCustomRoleOwner = ($rolesAssigned | Where-Object { $_.RoleSecurityCustomRoleOwner -eq 1} | Measure-Object).count
$roleSecurityFindingOwnerAssignmentSP = ($rolesAssigned | Where-Object { $_.RoleSecurityOwnerAssignmentSP -eq 1} | Measure-Object).count

if (($rolesAssigned | measure-object).count -gt 0) {
    $tfCount = ($rolesAssigned | measure-object).count
    $tableId = "DetailsTable_RoleAssignments_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
$htmlScopeInsights += @"
<button type="button" class="collapsible"><p>$faIcon $rolesAssignedCount Role Assignments ($rolesAssignedInheritedCount inherited) (User: $rolesAssignedUser | Group: $rolesAssignedGroup | ServicePrincipal: $rolesAssignedServicePrincipal | Orphaned: $rolesAssignedUnknown) ($($roleSecurityFindingCustomRoleOwnerImg)CustomRoleOwner: $roleSecurityFindingCustomRoleOwner, $($RoleSecurityFindingOwnerAssignmentSPImg)OwnerAssignmentSP: $roleSecurityFindingOwnerAssignmentSP) (Policy related: $roleAssignmentsRelatedToPolicyCount) | Limit: ($rolesAssignedAtScopeCount/$LimitRoleAssignmentsScope)</p></button>
<div class="content">
<table id="$tableId" class="$cssClass">
<thead>
<tr>
<th>Scope</th>
<th>Role</th>
<th>Role Type</th>
<th>Object Displayname</th>
<th>Object SignInName</th>
<th>Object ObjectId</th>
<th>Object Type</th>
<th>Role AssignmentId</th>
<th>Related PolicyAssignment</th>
</tr>
</thead>
<tbody>
"@
    $htmlScopeInsightsRoleAssignments = $null
    foreach ($roleAssignment in $rolesAssigned | sort-object @{Expression={$_.Level}}, @{Expression={$_.MgName}}, @{Expression={$_.MgId}}, @{Expression={$_.SubscriptionName}}, @{Expression={$_.SubscriptionId}}) {
$htmlScopeInsightsRoleAssignments += @"
<tr>
<td>$($roleAssignment.Scope)</td>
<td>$($roleAssignment.Role)</td>
<td>$($roleAssignment.RoleType)</td>
<td class="breakwordall">$($roleAssignment.ObjectDisplayName)</td>
<td class="breakwordall">$($roleAssignment.ObjectSignInName)</td>
<td class="breakwordall">$($roleAssignment.ObjectId)</td>
<td>$($roleAssignment.ObjectType)</td>
<td class="breakwordall">$($roleAssignment.RoleAssignmentId)</td>
<td class="breakwordall">$($roleAssignment.rbacRelatedPolicyAssignment)</td>
</tr>
"@
    }
$htmlScopeInsights += $htmlScopeInsightsRoleAssignments
$htmlScopeInsights += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlScopeInsights += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
}
$htmlScopeInsights += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_2: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
            watermark: ['', 'try owner||reader', '', '', '', '', '', '', ''],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlScopeInsights += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($script:rbacAll | measure-object).count) Role Assignments</span></p>
    </td></tr>
"@
}
#endregion ScopeInsightsRoleAssignments

$script:html += $htmlScopeInsights

if ($script:scopescnter % 30  -eq 0){
    $script:scopescnter = 0
    write-host "   append file duration: " (Measure-Command { $script:html | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force }).TotalSeconds "seconds"
$script:html = $null 
}

}

#rsu
#region Summary
function summary() {
#$startSummary = get-date
Write-Host " Building HTML Summary"

if ($getMgParentName -eq "Tenant Root"){
    $scopeNamingSummary = "Tenant wide"
}
else{
    $scopeNamingSummary = "ManagementGroup '$ManagementGroupIdCaseSensitived' and descendants wide"
}

#tenantSummaryPolicy
$htmlTenantSummary += @"
    <hr class="hr-text" data-content="Policy" />
"@

#region SUMMARYcustompolicies
$startCustPolLoop = get-date
Write-Host "  processing Summary Custom Policies"

$customPoliciesArray = @()
$customPoliciesArray += foreach ($tenantCustomPolicy in $tenantCustomPolicies){
     ($htCacheDefinitions).policy.($tenantCustomPolicy)
}

$script:customPoliciesDetailed = @()
$script:customPoliciesDetailed += foreach ($customPolicy in ($customPoliciesArray | Sort-Object @{Expression={$_.DisplayName}}, @{Expression={$_.PolicyDefinitionId}})){
    
    #uniqueAssignments
    $policyUniqueAssignments = (($policyPolicyBaseQuery | Where-Object { $_.PolicyDefinitionIdFull -eq ($htCacheDefinitions).policy.($customPolicy.Id).Id }).PolicyAssignmentId | sort-object -Unique)
    $policyUniqueAssignmentsArray = @()
    $policyUniqueAssignmentsArray += foreach ($policyUniqueAssignment in $policyUniqueAssignments){
        $policyUniqueAssignment
    }
    $policyUniqueAssignmentsCount = ($policyUniqueAssignments | measure-object).count 
    #
    $uniqueAssignments = $null
    if ($policyUniqueAssignmentsCount -gt 0){
        $policyUniqueAssignmentsList = "($($policyUniqueAssignmentsArray -join "$CsvDelimiterOpposite "))"
        $uniqueAssignments = "$policyUniqueAssignmentsCount $policyUniqueAssignmentsList"
    }
    else{
        $uniqueAssignments = $policyUniqueAssignmentsCount
    }

    #usedInPolicySet
    $usedInPolicySetArray = @()
    $customPolicySets = $tenantCustomPolicySets | where-object { ($htCacheDefinitions).policySet.$_.Type -eq "Custom" }
    $usedInPolicySetArray += foreach ($customPolicySet in $customPolicySets){
        $hlpCustomPolicySet = ($htCacheDefinitions).policySet.($customPolicySet)
        if (($hlpCustomPolicySet.PolicySetPolicyIds).contains($customPolicy.PolicyDefinitionId)){
            ($hlpCustomPolicySet.Id)                          
        }
    }
    $usedInPolicySetList = @()
    $usedInPolicySetList += foreach ($usedPolicySet in $usedInPolicySetArray){
        $hlpPolicySetUsed = ($htCacheDefinitions).policySet.($usedPolicySet)
        "$($hlpPolicySetUsed.DisplayName) ($($hlpPolicySetUsed.PolicyDefinitionId))"
    }
    $usedInPolicySetListCount = ($usedInPolicySetList | Measure-Object).count
    $usedInPolicySet = $null
    if ($usedInPolicySetListCount -gt 0){
        $usedInPolicySetListInBrackets = "($(($usedInPolicySetList | Sort-Object) -join "$CsvDelimiterOpposite "))"
        $usedInPolicySet = "$usedInPolicySetListCount $usedInPolicySetListInBrackets"
    }
    else{
        $usedInPolicySet = $usedInPolicySetListCount
    }

    #policyEffect
    $temp0000000 = ($htCacheDefinitions).policy.($customPolicy.Id)
    if ($temp0000000.effectDefaultValue -ne "n/a"){
        $effect = "Default: $($temp0000000.effectDefaultValue); Allowed: $($temp0000000.effectAllowedValue)"
    }
    else{
        $effect = "Fixed: $($temp0000000.effectFixedValue)"
    }

    #policyRoledefinitions
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
    [PSCustomObject]@{ 
        'PolicyDisplayName' = $temp0000000.DisplayName; 
        'PolicyDefinitionId'= $temp0000000.PolicyDefinitionId; 
        'PolicyEffect'= $effect; 
        'RoleDefinitions' = $policyRoleDefinitions; 
        'UniqueAssignments' = $uniqueAssignments; 
        'UsedInPolicySets' = $usedInPolicySet
    }
}

if ($getMgParentName -eq "Tenant Root"){

$customPoliciesArray = @()
$customPoliciesArray += foreach ($tenantCustomPolicy in $tenantCustomPolicies){
     ($htCacheDefinitions).policy.($tenantCustomPolicy)
}

if ($tenantCustomPoliciesCount -gt 0){
    $tfCount = $tenantCustomPoliciesCount
    $tableId = "SummaryTable_customPolicies"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customPolicies"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policies ($scopeNamingSummary)</span></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Policy DisplayName</th>
<th>PolicyId</th>
<th>Policy Effect</th>
<th>Role Definitions</th>
<th>Unique Assignments</th>
<th>Used in PolicySets</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYcustompolicies = $null
    foreach ($customPolicy in ($script:customPoliciesDetailed | Sort-Object @{Expression={$_.PolicyDisplayName}}, @{Expression={$_.PolicyDefinitionId}})){
$htmlSUMMARYcustompolicies += @"
<tr>
<td>$($customPolicy.PolicyDisplayName)</td>
<td class="breakwordall">$($customPolicy.PolicyDefinitionId)</td>
<td>$($customPolicy.PolicyEffect)</td>
<td>$($customPolicy.RoleDefinitions)</td>
<td class="breakwordall">$($customPolicy.UniqueAssignments)</td>
<td class="breakwordall">$($customPolicy.UsedInPolicySets)</td>
</tr>
"@ 
    }
$htmlTenantSummary += $htmlSUMMARYcustompolicies
$htmlTenantSummary | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
$htmlTenantSummary = $null
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,       
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policies ($scopeNamingSummary)</span></p>
"@
}
}
#SUMMARY NOT tenant total custom policies
else{
    $faimage = "<i class=`"fa fa-check-circle`" aria-hidden=`"true`"></i>"
    if ($tenantCustomPoliciesCount -gt 0){
        $tfCount = $tenantCustomPoliciesCount
        $customPoliciesInScopeArray = [System.Collections.ArrayList]@()
        foreach ($customPolicy in ($customPoliciesArray | Sort-Object @{Expression={$_.DisplayName}}, @{Expression={$_.PolicyDefinitionId}})) {
            $currentpolicy = ($htCacheDefinitions).policy.($customPolicy.PolicyDefinitionId)
            if (($currentpolicy.PolicyDefinitionId).startswith("/providers/Microsoft.Management/managementGroups/","CurrentCultureIgnoreCase")) {
                $policyScopedMgSub = $currentpolicy.PolicyDefinitionId -replace "/providers/Microsoft.Management/managementGroups/", "" -replace '/.*'
                if ($mgsAndSubs.MgId.contains("$policyScopedMgSub")) {
                    $null = $customPoliciesInScopeArray.Add($currentpolicy)
                }
            }

            if (($currentpolicy.PolicyDefinitionId).startswith("/subscriptions/","CurrentCultureIgnoreCase")) {
                $policyScopedMgSub = $currentpolicy.PolicyDefinitionId -replace "/subscriptions/", "" -replace '/.*'
                if ($mgsAndSubs.SubscriptionId.contains("$policyScopedMgSub")) {
                    $null = $customPoliciesInScopeArray.Add($currentpolicy)
                }
                else {
                    #Write-Host "$policyScopedMgSub NOT in Scope"
                }
            }
            
        }
        $customPoliciesFromSuperiorMGs = $tenantCustomPoliciesCount - (($customPoliciesInScopeArray | measure-object).count)
    }
    else{
        $customPoliciesFromSuperiorMGs = "0"
    }

if ($tenantCustomPoliciesCount -gt 0){
    $tfCount = $tenantCustomPoliciesCount
    $tableId = "SummaryTable_customPolicies"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customPolicies"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policies $scopeNamingSummary ($customPoliciesFromSuperiorMGs from superior scopes)</span></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Policy DisplayName</th>
<th>PolicyId</th>
<th>Policy Effect</th>
<th>Role Definitions</th>
<th>Unique Assignments</th>
<th>Used in PolicySets</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYcustompolicies = $null
    foreach ($customPolicy in ($script:customPoliciesDetailed | Sort-Object @{Expression={$_.PolicyDisplayName}}, @{Expression={$_.PolicyDefinitionId}})){
$htmlSUMMARYcustompolicies += @"
<tr>
<td>$($customPolicy.PolicyDisplayName)</td>
<td class="breakwordall">$($customPolicy.PolicyDefinitionId)</td>
<td>$($customPolicy.PolicyEffect)</td>
<td>$($customPolicy.RoleDefinitions)</td>
<td class="breakwordall">$($customPolicy.UniqueAssignments)</td>
<td class="breakwordall">$($customPolicy.UsedInPolicySets)</td>
</tr>
"@ 
    }
$htmlTenantSummary += $htmlSUMMARYcustompolicies
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policies ($scopeNamingSummary)</span></p>
"@
}
}
$endCustPolLoop = get-date
Write-Host "   Custom Policy processing duration: $((NEW-TIMESPAN -Start $startCustPolLoop -End $endCustPolLoop).TotalSeconds) seconds"
#endregion SUMMARYcustompolicies

#region SUMMARYCustomPoliciesOrphandedTenantRoot
Write-Host "  processing Summary Custom Policies orphaned"
if ($getMgParentName -eq "Tenant Root"){
    $customPoliciesInUse = ($policyBaseQuery | where-object {$_.PolicyType -eq "Custom" -and $_.PolicyVariant -eq "Policy"}).PolicyDefinitionIdFull | Sort-Object -Unique
    $customPoliciesOrphaned = @()
    $customPoliciesOrphaned += foreach ($customPolicyAll in $tenantCustomPolicies) {
        if (($customPoliciesInUse | measure-object).count -eq 0) {
            $hlpCustomPolicy = ($htCacheDefinitions).policy.$customPolicyAll
            if ($hlpCustomPolicy.Type -eq "Custom") {
                $hlpCustomPolicy
            }
        }
        else {
            if ($customPoliciesInUse.contains("$customPolicyAll")) {
            }
            else {
                $hlpCustomPolicy = ($htCacheDefinitions).policy.$customPolicyAll
                if ($hlpCustomPolicy.Type -eq "Custom") {
                    $hlpCustomPolicy
                }
            }
        }
    }

    $arrayCustomPoliciesOrphanedFinal = @()
    $arrayCustomPoliciesOrphanedFinal += foreach ($customPolicyOrphaned in $customPoliciesOrphaned){
        if ($arrayPoliciesUsedInPolicySets -notcontains $customPolicyOrphaned.id){
            ($htCacheDefinitions).policy.$($customPolicyOrphaned.id)
        }
    }

    $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups = @()
    $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups += foreach ($customPolicyOrphanedFinal in $arrayCustomPoliciesOrphanedFinal){
        if ($script:arrayCachePolicyAssignmentsResourceGroups.properties.policydefinitionId -notcontains $customPolicyOrphanedFinal.policydefinitionId){
            $customPolicyOrphanedFinal
        }
    }

    if (($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0){
        $tfCount = ($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count
        $tableId = "SummaryTable_customPoliciesOrphaned"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customPoliciesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom Policies ($scopeNamingSummary)</span> <abbr title="Policy is not used in a PolicySet AND Policy has no Assignments (including ResourceGroups)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Policy DisplayName</th>
<th>PolicyId</th>
</tr>
</thead>
<tbody>
"@
        $htmlSUMMARYCustomPoliciesOrphandedTenantRoot = $null
        foreach ($customPolicyOrphaned in $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | sort-object @{Expression={$_.DisplayName}}){
$htmlSUMMARYCustomPoliciesOrphandedTenantRoot += @"
<tr>
<td>$($customPolicyOrphaned.DisplayName)</td>
<td>$($customPolicyOrphaned.PolicyDefinitionId)</td>
</tr>
"@ 
        }
$htmlTenantSummary += $htmlSUMMARYCustomPoliciesOrphandedTenantRoot
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
    }
    else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($customPoliciesOrphaned | measure-object).count) Orphaned Custom Policies ($scopeNamingSummary)</span></p>
"@
    }
}
#SUMMARY Custom Policies Orphanded NOT TenantRoot
else{
    $customPoliciesInUse = ($policyBaseQuery | where-object {$_.PolicyType -eq "Custom" -and $_.PolicyVariant -eq "Policy"}).PolicyDefinitionIdFull | Sort-Object -Unique
    $customPoliciesOrphaned = @()
    $customPoliciesOrphaned += foreach ($customPolicyAll in $tenantCustomPolicies) {
        if (($customPoliciesInUse | measure-object).count -eq 0) {
            if (($htCacheDefinitions).policy.$customPolicyAll.Type -eq "Custom") {
                ($htCacheDefinitions).policy.$customPolicyAll.Id
            }
        }
        else {
            if (-not $customPoliciesInUse.contains("$customPolicyAll")) {    
                if (($htCacheDefinitions).policy.$customPolicyAll.Type -eq "Custom") {
                    ($htCacheDefinitions).policy.$customPolicyAll.Id
                }
            }
        }
    }
    $customPoliciesOrphanedInScopeArray = @()
    $customPoliciesOrphanedInScopeArray += foreach ($customPolicyOrphaned in  $customPoliciesOrphaned){
        $hlpOrphanedInScope = ($htCacheDefinitions).policy.$customPolicyOrphaned
        if (($hlpOrphanedInScope.PolicyDefinitionId).startswith("/providers/Microsoft.Management/managementGroups/","CurrentCultureIgnoreCase")) {
            $policyScopedMgSub = $hlpOrphanedInScope.PolicyDefinitionId -replace "/providers/Microsoft.Management/managementGroups/", "" -replace '/.*'
            if ($mgsAndSubs.MgId.contains("$policyScopedMgSub")) {
                $hlpOrphanedInScope
            }
        }
        if (($hlpOrphanedInScope.PolicyDefinitionId).startswith("/subscriptions/","CurrentCultureIgnoreCase")) {
            $policyScopedMgSub = $hlpOrphanedInScope.PolicyDefinitionId -replace "/subscriptions/", "" -replace '/.*'
            if ($mgsAndSubs.SubscriptionId.contains("$policyScopedMgSub")) {
                $hlpOrphanedInScope
            }
        }
    }
    $arrayCustomPoliciesOrphanedFinal = @()
    $arrayCustomPoliciesOrphanedFinal += foreach ($customPolicyOrphanedInScopeArray in $customPoliciesOrphanedInScopeArray){
        if ($arrayPoliciesUsedInPolicySets -notcontains $customPolicyOrphanedInScopeArray.id){
            $customPolicyOrphanedInScopeArray
        }
    }

    $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups = @()
    $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups += foreach ($customPolicyOrphanedFinal in $arrayCustomPoliciesOrphanedFinal){
        if ($script:arrayCachePolicyAssignmentsResourceGroups.properties.policydefinitionId -notcontains $customPolicyOrphanedFinal.policydefinitionId){
            $customPolicyOrphanedFinal
        }

    }

    if (($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0){
        $tfCount = ($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count
        $tableId = "SummaryTable_customPoliciesOrphaned"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customPoliciesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom Policies ($scopeNamingSummary)</span> <abbr title="Policy is not used in a PolicySet AND Policy has no Assignments (including ResourceGroups) (Policies from superior scopes are not evaluated)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Policy DisplayName</th>
<th>PolicyId</th>
</tr>
</thead>
<tbody>
"@
        $htmlSUMMARYCustomPoliciesOrphandedTenantRoot = $null
        foreach ($customPolicyOrphaned in $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | sort-object @{Expression={$_.DisplayName}}){
$htmlSUMMARYCustomPoliciesOrphandedTenantRoot += @"
<tr>
<td>$($customPolicyOrphaned.DisplayName)</td>
<td>$($customPolicyOrphaned.PolicyDefinitionId)</td>
</tr>
"@ 
        }
$htmlTenantSummary += $htmlSUMMARYCustomPoliciesOrphandedTenantRoot
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
    }
    else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups.count) Orphaned Custom Policies ($scopeNamingSummary)</span></p>
"@
    }
}
#endregion SUMMARYCustomPoliciesOrphandedTenantRoot

#region SUMMARYtenanttotalcustompolicySets
Write-Host "  processing Summary Custom PolicySets"
$customPolicySetsArray = @()
$customPolicySetsArray += foreach ($tenantCustomPolicySet in $tenantCustomPolicySets){
    ($htCacheDefinitions).policySet.($tenantCustomPolicySet)
}
$script:customPolicySetsDetailed = @()
$script:customPolicySetsDetailed += foreach ($customPolicySet in ($customPolicySetsArray | Sort-Object)){
    
    $policySetUniqueAssignments = (($policyPolicySetBaseQuery | Where-Object { $_.PolicyDefinitionIdFull -eq ($htCacheDefinitions).policySet.($customPolicySet.Id).Id }).PolicyAssignmentId | sort-object -Unique)
    $policySetUniqueAssignmentsArray = @()
    $policySetUniqueAssignmentsArray += foreach ($policySetUniqueAssignment in $policySetUniqueAssignments){
        $policySetUniqueAssignment
    }
    $policySetUniqueAssignmentsCount = ($policySetUniqueAssignments | measure-object).count 
    if ($policySetUniqueAssignmentsCount -gt 0){
        $policySetUniqueAssignmentsList = "($($policySetUniqueAssignmentsArray -join "$CsvDelimiterOpposite "))"
        $policySetUniqueAssignment = "$policySetUniqueAssignmentsCount $policySetUniqueAssignmentsList"
    }
    else{
        $policySetUniqueAssignment = $policySetUniqueAssignmentsCount
    }

    #<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/10ee2ea2-fb4d-45b8-a7e9-a2e770044cd9.html`" target=`"_blank`">

    $policySetPoliciesArray = @()
    $policySetPoliciesArray += foreach ($policyPolicySet in ($htCacheDefinitions).policySet.($customPolicySet.Id).PolicySetPolicyIds){
        #$policyPolicySetId = $policyPolicySet
        $hlpPolicyDef = ($htCacheDefinitions).policy.($policyPolicySet)
        #https://www.azadvertizer.net/azpolicyadvertizer//providers/Microsoft.Authorization/policyDefinitions/e1e5fd5d-3e4c-4ce1-8661-7d1873ae6b15.html
        #($htCacheDefinitions).policy."/providers/Microsoft.Authorization/policyDefinitions/e1e5fd5d-3e4c-4ce1-8661-7d1873ae6b15"
        if ($hlpPolicyDef.Type -eq "Builtin"){
            "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/$($hlpPolicyDef.Id -replace '.*/').html`" target=`"_blank`">$($hlpPolicyDef.DisplayName)</a> ($policyPolicySet)"
        }
        else{
            "$($hlpPolicyDef.DisplayName) ($policyPolicySet)"
        }
    }
    $policySetPoliciesCount = ($policySetPoliciesArray | Measure-Object).count
    if ($policySetPoliciesCount -gt 0){
        $policiesUsed = "$policySetPoliciesCount ($(($policySetPoliciesArray | sort-Object) -join "$CsvDelimiterOpposite "))"
    }
    else{
        $policiesUsed = "0 really?"
    }

    [PSCustomObject]@{ 
        'PolicySetDisplayName' = $customPolicySet.DisplayName; 
        'PolicySetDefinitionId'= $customPolicySet.PolicyDefinitionId; 
        'UniqueAssignments' = $policySetUniqueAssignment; 
        'PoliciesUsed' = $policiesUsed
    }
}

if ($getMgParentName -eq "Tenant Root"){
    if ($tenantCustompolicySetsCount -gt $LimitPOLICYPolicySetDefinitionsScopedTenant * ($LimitCriticalPercentage / 100)){
        $faimage = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
    }
    else{
        $faimage = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
    }

    if ($tenantCustompolicySetsCount -gt 0){
        $tfCount = $tenantCustompolicySetsCount
        $tableId = "SummaryTable_customPolicySets"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customPolicySets">$faimage <span class="valignMiddle">$tenantCustompolicySetsCount Custom PolicySets ($scopeNamingSummary) (Limit: $tenantCustompolicySetsCount/$LimitPOLICYPolicySetDefinitionsScopedTenant)</span></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
<th>Unique Assignments</th>
<th>Policies used in PolicySet</th>
</tr>
</thead>
<tbody>
"@
        $htmlSUMMARYtenanttotalcustompolicySets = $null
        foreach ($customPolicySet in $script:customPolicySetsDetailed | Sort-Object @{Expression={$_.PolicySetDisplayName}}, @{Expression={$_.PolicySetDefinitionId}}){
$htmlSUMMARYtenanttotalcustompolicySets += @"
<tr>
<td>$($customPolicySet.PolicySetDisplayName)</td>
<td class="breakwordall">$($customPolicySet.PolicySetDefinitionId)</td>
<td class="breakwordall">$($customPolicySet.UniqueAssignments)</td>
<td class="breakwordall">$($customPolicySet.PoliciesUsed)</td>
</tr>
"@ 
        }
$htmlTenantSummary += $htmlSUMMARYtenanttotalcustompolicySets
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@   
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
    }
    else{
$htmlTenantSummary += @"
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
        $custompolicySetsInScopeArray += foreach ($custompolicySet in $tenantCustomPolicySets) {
            $currentpolicyset = ($htCacheDefinitions).policySet.$custompolicySet
            if (($currentpolicyset.policyDefinitionId).startswith("/providers/Microsoft.Management/managementGroups/","CurrentCultureIgnoreCase")) {
                $policySetScopedMgSub = $currentpolicyset.policyDefinitionId -replace "/providers/Microsoft.Management/managementGroups/", "" -replace '/.*'
                if ($mgsAndSubs.MgId.contains("$policySetScopedMgSub")) {
                    $currentpolicyset
                }
            }
            if (($currentpolicyset.policyDefinitionId).startswith("/subscriptions/","CurrentCultureIgnoreCase")) {
                $policySetScopedMgSub = $currentpolicyset.policyDefinitionId -replace "/subscriptions/", "" -replace '/.*'
                if ($mgsAndSubs.SubscriptionId.contains("$policySetScopedMgSub")) {
                    $currentpolicyset
                }
            }
        }
        $custompolicySetsFromSuperiorMGs = $tenantCustompolicySetsCount - (($custompolicySetsInScopeArray | measure-object).count)
    }
    else{
        $custompolicySetsFromSuperiorMGs = "0"
    }

    if ($tenantCustompolicySetsCount -gt 0){
        $tfCount = $tenantCustompolicySetsCount
        $tableId = "SummaryTable_customPolicySets"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customPolicySets">$faimage <span class="valignMiddle">$tenantCustomPolicySetsCount Custom PolicySets $scopeNamingSummary ($custompolicySetsFromSuperiorMGs from superior scopes) (Limit: $tenantCustompolicySetsCount/$LimitPOLICYPolicySetDefinitionsScopedTenant)</span></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
<th>Unique Assignments</th>
<th>Policies used in PolicySet</th>
</tr>
</thead>
<tbody>
"@
        $htmlSUMMARYtenanttotalcustompolicySets = $null
        foreach ($customPolicySet in $script:customPolicySetsDetailed){
$htmlSUMMARYtenanttotalcustompolicySets += @"
<tr>
<td>$($customPolicySet.PolicySetDisplayName)</td>
<td class="breakwordall">$($customPolicySet.PolicySetDefinitionId)</td>
<td class="breakwordall">$($customPolicySet.UniqueAssignments)</td>
<td class="breakwordall">$($customPolicySet.PoliciesUsed)</td>
</tr>
"@ 
        }
$htmlTenantSummary += $htmlSUMMARYtenanttotalcustompolicySets
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@    
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
    }
    else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPolicySetsCount Custom PolicySets ($scopeNamingSummary)</span></p>
"@
    }
}
#endregion SUMMARYtenanttotalcustompolicySets

#region SUMMARYCustompolicySetOrphandedTenantRoot
Write-Host "  processing Summary Custom PolicySets orphaned"
if ($getMgParentName -eq "Tenant Root"){
    $custompolicySetSetsInUse = ($policyBaseQuery | where-object {$_.policyType -eq "Custom" -and $_.policyVariant -eq "policySet"}).PolicyDefinitionIdFull | Sort-Object -Unique
    $custompolicySetSetsOrphaned = @()
    $custompolicySetSetsOrphaned += foreach ($custompolicySetAll in $tenantCustomPolicySets) {
        if (($custompolicySetSetsInUse | measure-object).count -eq 0) {
            ($htCacheDefinitions).policySet.$custompolicySetAll
        }
        else {
            if (-not $custompolicySetSetsInUse.contains($custompolicySetAll)) {
                ($htCacheDefinitions).policySet.$custompolicySetAll
            }
        }
    }

    $arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups = @()
    $arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups += foreach ($customPolicySetOrphaned in $custompolicySetSetsOrphaned){
        if ($script:arrayCachePolicyAssignmentsResourceGroups.properties.policydefinitionId -notcontains $customPolicySetOrphaned.policydefinitionId){
            $customPolicySetOrphaned
        }
    }

    if (($arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0){
        $tfCount = ($arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups | measure-object).count
        $tableId = "SummaryTable_customPolicySetsOrphaned"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_custompolicySetsOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom PolicySets ($scopeNamingSummary)</span> <abbr title="PolicySet has no Assignments (including ResourceGroups)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
</tr>
</thead>
<tbody>
"@
        $htmlSUMMARYCustompolicySetOrphandedTenantRoot = $null
        foreach ($custompolicySetOrphaned in $arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups | sort-object @{Expression={$_.DisplayName}}, @{Expression={$_.policyDefinitionId}}){
$htmlSUMMARYCustompolicySetOrphandedTenantRoot += @"
<tr>
<td>$($custompolicySetOrphaned.DisplayName)</td>
<td>$($custompolicySetOrphaned.policyDefinitionId)</td>
</tr>
"@ 
        }
$htmlTenantSummary += $htmlSUMMARYCustompolicySetOrphandedTenantRoot
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@     
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
    }
    else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom PolicySets ($scopeNamingSummary)</span></p>
"@
    }
}
#SUMMARY Custom policySetSets Orphanded NOT TenantRoot
else{
    $custompolicySetSetsInUse = ($policyBaseQuery | where-object {$_.policyType -eq "Custom" -and $_.policyVariant -eq "policySet"}).PolicyDefinitionIdFull | Sort-Object -Unique
    $custompolicySetSetsOrphaned = @()
    $custompolicySetSetsOrphaned += foreach ($custompolicySetAll in $tenantCustomPolicySets) {
        if (($custompolicySetSetsInUse | measure-object).count -eq 0) {
            ($htCacheDefinitions).policySet.$custompolicySetAll.Id
        }
        else {
            if (-not $custompolicySetSetsInUse.contains("$custompolicySetAll")) {    
                ($htCacheDefinitions).policySet.$custompolicySetAll.Id
            }
        }
    }
    $arrayCustomPolicySetsOrphanedFinal = @()
    $arrayCustomPolicySetsOrphanedFinal += foreach ($custompolicySetOrphaned in  $custompolicySetSetsOrphaned){
        if ((($htCacheDefinitions).policySet.$custompolicySetOrphaned.policyDefinitionId).startswith("/providers/Microsoft.Management/managementGroups/","CurrentCultureIgnoreCase")) {
            $policySetScopedMgSub = ($htCacheDefinitions).policySet.$custompolicySetOrphaned.policyDefinitionId -replace "/providers/Microsoft.Management/managementGroups/", "" -replace '/.*'
            if ($mgsAndSubs.MgId.contains("$policySetScopedMgSub")) {
                ($htCacheDefinitions).policySet.$custompolicySetOrphaned
            }
        }
        if ((($htCacheDefinitions).policySet.$custompolicySetOrphaned.policyDefinitionId).startswith("/subscriptions/","CurrentCultureIgnoreCase")) {
            $policySetScopedMgSub = ($htCacheDefinitions).policySet.$custompolicySetOrphaned.policyDefinitionId -replace "/subscriptions/", "" -replace '/.*'
            if ($mgsAndSubs.SubscriptionId.contains("$policySetScopedMgSub")) {
                ($htCacheDefinitions).policySet.$custompolicySetOrphaned
            }
        }
    }

    $arraycustompolicySetsOrphanedFinalIncludingResourceGroups = @()
    $arraycustompolicySetsOrphanedFinalIncludingResourceGroups += foreach ($customPolicySetOrphaned in $arrayCustomPolicySetsOrphanedFinal){
        if ($script:arrayCachePolicyAssignmentsResourceGroups.properties.policydefinitionId -notcontains $customPolicySetOrphaned.policydefinitionId){
            $customPolicySetOrphaned
        }
    }

    if (($arraycustompolicySetsOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0){
        $tfCount = ($arraycustompolicySetsOrphanedFinalIncludingResourceGroups | measure-object).count
        $tableId = "SummaryTable_customPolicySetsOrphaned"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_custompolicySetsOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arraycustompolicySetsOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom PolicySets ($scopeNamingSummary)</span> <abbr title="PolicySet has no Assignments (including ResourceGroups) (PolicySets from superior scopes are not evaluated)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
</tr>
</thead>
<tbody>
"@
        $htmlSUMMARYCustompolicySetOrphandedTenantRoot = $null
        foreach ($custompolicySetOrphaned in $arraycustompolicySetsOrphanedFinalIncludingResourceGroups | sort-object @{Expression={$_.DisplayName}}, @{Expression={$_.policyDefinitionId}}){
$htmlSUMMARYCustompolicySetOrphandedTenantRoot += @"
<tr>
<td>$($custompolicySetOrphaned.DisplayName)</td>
<td>$($custompolicySetOrphaned.policyDefinitionId)</td>
</tr>
"@ 
        }
$htmlTenantSummary += $htmlSUMMARYCustompolicySetOrphandedTenantRoot
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@   
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
    }
    else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($arraycustompolicySetsOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom PolicySets ($scopeNamingSummary)</span></p>
"@
    }
}
#endregion SUMMARYCustompolicySetOrphandedTenantRoot


#region SUMMARYPolicySetsDeprecatedPolicy
Write-Host "  processing Summary Custom PolicySets using depracted Policy"
$policySetsDeprecated=@()
$customPolicySets = $tenantCustomPolicySets | where-object { ($htCacheDefinitions).policySet.($_).type -eq "Custom" } 
$customPolicySetsCount = ($customPolicySets | Measure-Object).count
if ($customPolicySetsCount -gt 0){
    $policySetsDeprecated += foreach ($polSetDef in $tenantCustomPolicySets | where-object { ($htCacheDefinitions).policySet.($_).type -eq "Custom" }){
        foreach ($polsetPolDefId in $($htCacheDefinitions).policySet.($polSetDef).PolicySetPolicyIds) {
            $hlpDeprecatedPolicySet = (($htCacheDefinitions).policy.$polsetPolDefId)
            if ($hlpDeprecatedPolicySet.type -eq "BuiltIn") {
                if ($hlpDeprecatedPolicySet.deprecated -eq $true -or ($hlpDeprecatedPolicySet.displayname).startswith("[Deprecated]","CurrentCultureIgnoreCase")) {
                    [PSCustomObject]@{'PolicySetDisplayName'= $($htCacheDefinitions).policySet.($polSetDef).DisplayName; 'PolicySetDefinitionId'= $($htCacheDefinitions).policySet.($polSetDef).PolicyDefinitionId; 'PolicyDisplayName' = $hlpDeprecatedPolicySet.displayname; 'PolicyId' = $hlpDeprecatedPolicySet.Id; 'DeprecatedProperty' = $hlpDeprecatedPolicySet.deprecated }
                }
            }
        }
    }
}

if (($policySetsDeprecated | measure-object).count -gt 0) {
    $tfCount = ($policySetsDeprecated | measure-object).count
    $tableId = "SummaryTable_policySetsDeprecated"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_policySetsDeprecated"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($policySetsDeprecated | measure-object).count) Custom PolicySets / deprecated Built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] or Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
<table id= "$tableId" class="summaryTable">
<thead>
<tr>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
<th>Policy DisplayName</th>
<th>PolicyId</th>
<th>Deprecated Property</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYPolicySetsDeprecatedPolicy = $null
    foreach ($policySetDeprecated in $policySetsDeprecated | sort-object @{Expression={$_.PolicySetDisplayName}}, @{Expression={$_.PolicySetDefinitionId}}) {
        if ($policySetDeprecated.DeprecatedProperty -eq $true){
            $deprecatedProperty = "true"
        }
        else{
            $deprecatedProperty = "false"
        }
$htmlSUMMARYPolicySetsDeprecatedPolicy += @"
<tr>
<td>$($policySetDeprecated.PolicySetDisplayName)</td>
<td>$($policySetDeprecated.PolicySetDefinitionId)</td>
<td>$($policySetDeprecated.PolicyDisplayName)</td>
<td>$($policySetDeprecated.PolicyId)</td>
<td>$deprecatedProperty</td>
</tr>
"@ 
    }
$htmlTenantSummary += $htmlSUMMARYPolicySetsDeprecatedPolicy
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@    
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($policySetsDeprecated | measure-object).count) PolicySets / deprecated Built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] or Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span></p>
"@
}
#endregion SUMMARYPolicySetsDeprecatedPolicy

#region SUMMARYPolicyAssignmentsDeprecatedPolicy
Write-Host "  processing Summary PolicyAssignments using deprecated Policy"
$policyAssignmentsDeprecated =@()
$policyAssignmentsDeprecated += foreach ($policyAssignmentAll in $($htCacheAssignments).policy.keys) {
    
    $hlpAssignmentDeprecatedPolicy = ($htCacheAssignments).policy.($policyAssignmentAll).Properties
    #policySet
    if ($($htCacheDefinitions).policySet.(($hlpAssignmentDeprecatedPolicy.PolicyDefinitionId))) {
        foreach ($polsetPolDefId in $($htCacheDefinitions).policySet.(($hlpAssignmentDeprecatedPolicy.PolicyDefinitionId)).PolicySetPolicyIds) {
            $hlpDeprecatedAssignment = (($htCacheDefinitions).policy.(($polsetPolDefId)))
            if ($hlpDeprecatedAssignment.type -eq "BuiltIn") {
                if ($hlpDeprecatedAssignment.deprecated -eq $true -or ($hlpDeprecatedAssignment.displayname).startswith("[Deprecated]","CurrentCultureIgnoreCase")) {
                    [PSCustomObject]@{'PolicyAssignmentDisplayName' = $hlpAssignmentDeprecatedPolicy.DisplayName; 'PolicyAssignmentId' = $policyAssignmentAll; 'PolicyDisplayName' = $hlpDeprecatedAssignment.displayname; 'PolicyId' = $hlpDeprecatedAssignment.Id; 'PolicySetDisplayName' = ($htCacheDefinitions).policySet.(($hlpAssignmentDeprecatedPolicy.PolicyDefinitionId)).displayname; 'PolicySetId' = ($htCacheDefinitions).policySet.(($hlpAssignmentDeprecatedPolicy.PolicyDefinitionId)).policydefinitionId; 'PolicyType' = "PolicySet"; 'DeprecatedProperty' = $hlpDeprecatedAssignment.deprecated }
                    
                }
            }
        }
    }
    #Policy
    $hlpDeprecatedAssignmentPol = ($htCacheDefinitions).policy.(($hlpAssignmentDeprecatedPolicy.PolicyDefinitionId))
    if ($hlpDeprecatedAssignmentPol -and ($hlpDeprecatedAssignmentPol.type -eq "Builtin" -and ($hlpDeprecatedAssignmentPol.deprecated -eq $true) -or ($hlpDeprecatedAssignmentPol.displayname).startswith("[Deprecated]","CurrentCultureIgnoreCase"))) {
        [PSCustomObject]@{'PolicyAssignmentDisplayName' = $hlpAssignmentDeprecatedPolicy.DisplayName; 'PolicyAssignmentId' = $policyAssignmentAll; 'PolicyDisplayName' = $hlpDeprecatedAssignmentPol.displayname; 'PolicyId' = $hlpDeprecatedAssignmentPol.Id; 'PolicyType' = "Policy"; 'DeprecatedProperty' = $hlpDeprecatedAssignmentPol.deprecated; 'PolicySetDisplayName' = "n/a"; 'PolicySetId' = "n/a"; }
    }
}


if (($policyAssignmentsDeprecated | measure-object).count -gt 0) {
    $tfCount = ($policyAssignmentsDeprecated | measure-object).count
    $tableId = "SummaryTable_policyAssignmnetsDeprecated"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_policyAssignmnetsDeprecated"><i class="fa fa-exclamation-triangle orange" aria-hidden="true"></i> <span class="valignMiddle">$(($policyAssignmentsDeprecated | measure-object).count) Policy Assignments / deprecated Built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] or Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
<table id= "$tableId" class="summaryTable">
<thead>
<tr>
<th>Policy Assignment DisplayName</th>
<th>Policy AssignmentId</th>
<th>Policy/PolicySet</th>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
<th>Policy DisplayName</th>
<th>PolicyId</th>
<th>Deprecated Property</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYPolicyAssignmentsDeprecatedPolicy = $null
    foreach ($policyAssignmentDeprecated in $policyAssignmentsDeprecated | sort-object @{Expression={$_.PolicyAssignmentDisplayName}}, @{Expression={$_.PolicyAssignmentId}}) {
        if ($policyAssignmentDeprecated.DeprecatedProperty -eq $true){
            $deprecatedProperty = "true"
        }
        else{
            $deprecatedProperty = "false"
        }
$htmlSUMMARYPolicyAssignmentsDeprecatedPolicy += @"
<tr>
<td>$($policyAssignmentDeprecated.PolicyAssignmentDisplayName)</td>
<td class="breakwordall">$($policyAssignmentDeprecated.PolicyAssignmentId)</td>
<td>$($policyAssignmentDeprecated.PolicyType)</td>
<td>$($policyAssignmentDeprecated.PolicySetDisplayName)</td>
<td class="breakwordall">$($policyAssignmentDeprecated.PolicySetId)</td>
<td>$($policyAssignmentDeprecated.PolicyDisplayName)</td>
<td class="breakwordall">$($policyAssignmentDeprecated.PolicyId)</td>
<td>$deprecatedProperty</td>
</tr>
"@ 
    }
$htmlTenantSummary += $htmlSUMMARYPolicyAssignmentsDeprecatedPolicy
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@ 
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_2: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($policyAssignmentsDeprecated | measure-object).count) Policy Assignments / deprecated Built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] or Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span></p>
"@
}
#endregion SUMMARYPolicyAssignmentsDeprecatedPolicy

#region SUMMARYPolicyAssignmentsAll
$startSummaryPolicyAssignmentsAll = get-date
$allPolicyAssignments = ($policyBaseQuery | Measure-Object).count
Write-Host "  processing Summary PolicyAssignments (all $allPolicyAssignments)"

$script:policyAssignmentsAllArray =[System.Collections.ArrayList]@() 
$cnter = 0

$RoleAssignmentsArray += foreach ($roleassignment in ($htCacheAssignments).role.keys | Sort-Object){
    ($htCacheAssignments).role.($roleassignment)
}

#
$starttest = get-date
#
$htPolicyAssignmentRelatedRoleAssignments = @{ }
$htPolicyAssignmentEffect = @{ }
#$policyAssignmentIdsUnique = $policyBaseQuery | select-object PolicyAssignmentId, Policy, PolicyDefinitionIdGuid, PolicyDefinitionIdFull, PolicyVariant, PolicyType, PolicyAssignmentName | sort-object -Property PolicyAssignmentId -Unique
$policyAssignmentIdsUnique = $policyBaseQuery | sort-object -Property PolicyAssignmentId -Unique
foreach ($policyAssignmentIdUnique in $policyAssignmentIdsUnique) {

    $assignment = ($htCacheAssignments).policy.($policyAssignmentIdUnique.PolicyAssignmentId)
    if ($assignment.properties.policyDefinitionId -match "/Microsoft.Authorization/policyDefinitions/"){
        $test0 = $assignment.properties.parameters.effect.value
        if ($test0){
            $effect = $test0
        }
        else{
            $definition = ($htCacheDefinitions).policy.($assignment.properties.PolicyDefinitionId)
            $test1 = $definition.effectDefaultValue
            if ($test1 -ne "n/a"){
                $effect = $test1
            }
            $test2 = $definition.effectFixedValue
            if ($test2 -ne "n/a"){
                $effect = $test2
            }
        }
        #$effect
        $htPolicyAssignmentEffect.($policyAssignmentIdUnique.PolicyAssignmentId) = @{ }
        $htPolicyAssignmentEffect.($policyAssignmentIdUnique.PolicyAssignmentId).effect = $effect
    }

    $relatedRoleAssignmentsArray = @()
    $relatedRoleAssignments = $RoleAssignmentsArray | where-object { $_.DisplayName -eq ($policyAssignmentIdUnique.PolicyAssignmentId -replace '.*/') }
    if (($relatedRoleAssignments | Measure-Object).count -gt 0) {
        $relatedRoleAssignmentsArray += foreach ($relatedRoleAssignment in $relatedRoleAssignments) {
            if (($htCacheDefinitions).role.($relatedRoleAssignment.RoleDefinitionId).IsCustom -eq $false) {
                Write-Output "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azrolesadvertizer/$($relatedRoleAssignment.RoleDefinitionId).html`" target=`"_blank`">$($relatedRoleAssignment.RoleDefinitionName)</a> ($($relatedRoleAssignment.RoleAssignmentId))"
            }
            else {
                Write-Output "<u>$($relatedRoleAssignment.RoleDefinitionName)</u> ($($relatedRoleAssignment.RoleAssignmentId))"
            }
        }
    }
    $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId) = @{ }
    if (($relatedRoleAssignmentsArray | Measure-Object).count -gt 0) {
        $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId).relatedRoleAssignments = ($relatedRoleAssignmentsArray | sort-object) -join "$CsvDelimiterOpposite "
    }
    else {
        $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId).relatedRoleAssignments = "n/a"
    }

    if ($policyAssignmentIdUnique.PolicyType -eq "builtin"){
        if ($policyAssignmentIdUnique.PolicyVariant -eq "Policy"){
            $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId).policyWithWithoutLinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/$($policyAssignmentIdUnique.policyDefinitionIdGuid).html`" target=`"_blank`">$($policyAssignmentIdUnique.policy)</a>"
        }
        else{
            $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId).policyWithWithoutLinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyinitiativesadvertizer/$($policyAssignmentIdUnique.policyDefinitionIdGuid).html`" target=`"_blank`">$($policyAssignmentIdUnique.policy)</a>"
        }
    }
    else{
        $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId).policyWithWithoutLinkToAzAdvertizer = $policyAssignmentIdUnique.policy
    }
}
$endtest = get-date
Write-Host " processing duration: $((NEW-TIMESPAN -Start $starttest -End $endtest).TotalSeconds) seconds"

$starttest2 = get-date
foreach ($policyAssignmentAll in $policyBaseQuery){  
    $cnter++
    if ($cnter % 500  -eq 0){
        $etappeSummaryPolicyAssignmentsAll = get-date
        write-host "   $cnter of $allPolicyAssignments PolicyAssignments processed: $((NEW-TIMESPAN -Start $startSummaryPolicyAssignmentsAll -End $etappeSummaryPolicyAssignmentsAll).TotalSeconds) seconds"
        
    }
   
    $assignment = ($htCacheAssignments).policy.($policyAssignmentAll.PolicyAssignmentId)

    $excludedScope = "false"
    if (($assignment.properties.NotScopes | Measure-Object).count -gt 0){
        foreach ($policyAssignmentNotScope in $assignment.properties.NotScopes){
            if ("" -ne $policyAssignmentAll.subscriptionId){
                if ($htAllSubsMgPath.($policyAssignmentAll.subscriptionId).path -contains "'$($policyAssignmentNotScope -replace "/subscriptions/" -replace "/providers/Microsoft.Management/managementGroups/")'"){
                    $excludedScope = "true"
                }
            }
            else{
                if ($htAllMgsPath.($policyAssignmentAll.MgId).path -contains "'$($policyAssignmentNotScope -replace "/providers/Microsoft.Management/managementGroups/")'"){
                    $excludedScope = "true"
                }
            }
        }
    }

    if (($policyAssignmentAll.PolicyAssignmentId).StartsWith("/providers/Microsoft.Management/managementGroups/","CurrentCultureIgnoreCase")){
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
    if (($policyAssignmentAll.PolicyAssignmentId).StartsWith("/subscriptions/","CurrentCultureIgnoreCase")){
        $scope = "this Sub"
    }

    if ($policyAssignmentAll.PolicyVariant -eq "Policy"){
        $effect = $htPolicyAssignmentEffect.($policyAssignmentAll.PolicyAssignmentId).effect
    }
    else{
        $effect = "n/a"
    }

    if ("" -eq $policyAssignmentAll.SubscriptionId){
        $mgOrSub = "Mg"
    }
    else{
        $mgOrSub = "Sub"
    }

    #compliance
    if ("" -eq $policyAssignmentAll.subscriptionId){
        $compliance = ($htCachePolicyCompliance).mg.($policyAssignmentAll.MgId).($policyAssignmentAll.policyAssignmentId)
        $NonCompliantPolicies = $compliance.NonCompliantPolicies
        $CompliantPolicies = $compliance.CompliantPolicies
        $NonCompliantResources = $compliance.NonCompliantResources
        $CompliantResources = $compliance.CompliantResources
    }
    else{
        $compliance = ($htCachePolicyCompliance).sub.($policyAssignmentAll.SubscriptionId).($policyAssignmentAll.policyAssignmentId)
        $NonCompliantPolicies = $compliance.NonCompliantPolicies
        $CompliantPolicies = $compliance.CompliantPolicies
        $NonCompliantResources = $compliance.NonCompliantResources
        $CompliantResources = $compliance.CompliantResources
    }

    if (!$NonCompliantPolicies){
        $NonCompliantPolicies = 0
    }
    if (!$CompliantPolicies){
        $CompliantPolicies = 0
    }
    if (!$NonCompliantResources){
        $NonCompliantResources = 0
    }
    if (!$CompliantResources){
        $CompliantResources = 0
    }

    $null = $script:policyAssignmentsAllArray.Add([PSCustomObject]@{ 'Level' = $policyAssignmentAll.Level; 'MgId'= $policyAssignmentAll.MgId; 'MgName'= $policyAssignmentAll.MgName; 'subscriptionId' = $policyAssignmentAll.SubscriptionId; 'subscriptionName' = $policyAssignmentAll.Subscription; 'PolicyAssignmentId' = $policyAssignmentAll.PolicyAssignmentId; 'PolicyAssignmentDisplayName' = $policyAssignmentAll.PolicyAssignmentDisplayName; 'Effect' = $effect; 'PolicyName' = $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentAll.PolicyAssignmentId).policyWithWithoutLinkToAzAdvertizer; 'PolicyId' = $policyAssignmentAll.PolicyDefinitionIdFull; 'PolicyVariant' = $policyAssignmentAll.PolicyVariant; 'PolicyType' = $policyAssignmentAll.PolicyType; 'PolicyCategory' = $policyAssignmentAll.PolicyCategory; 'Inheritance' = $scope; 'ExcludedScope' = $excludedScope; 'RelatedRoleAssignments' = $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentAll.PolicyAssignmentId).relatedRoleAssignments; 'MgOrSub' = $mgOrSub; 'NonCompliantPolicies' = [int]$NonCompliantPolicies; 'CompliantPolicies' = $CompliantPolicies; 'NonCompliantResources' = $NonCompliantResources; 'CompliantResources' = $CompliantResources })
}
$endtest2 = get-date
Write-Host " processing duration: $((NEW-TIMESPAN -Start $starttest2 -End $endtest2).TotalSeconds) seconds"

if (($script:policyAssignmentsAllArray | measure-object).count -gt 0) {
    $tfCount = ($script:policyAssignmentsAllArray | measure-object).count
    $policyAssignmentsUniqueCount = ($script:policyAssignmentsAllArray | Sort-Object -Property PolicyAssignmentId -Unique | measure-object).count
    $tableId = "SummaryTable_policyAssignmentsAll"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_policyAssignmentsAll"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($script:policyAssignmentsAllArray | measure-object).count) Policy Assignments ($policyAssignmentsUniqueCount unique)</span>
</button>
<div class="content">
<table id= "$tableId" class="summaryTable">
<thead>
<tr>
<th>Mg/Sub</th>
<th>Management Group Id</th>
<th>Management Group Name</th>
<th>SubscriptionId</th>
<th>Subscription Name</th>
<th>Inheritance</th>
<th>ScopeExcluded</th>
<th>Policy/Set DisplayName</th>
<th>Policy/SetId</th>
<th>Policy/Set</th>
<th>Type</th>
<th>Category</th>
<th>Effect</th>
<th>Policies NonCmplnt</th>
<th>Policies Compliant</th>
<th>Resources NonCmplnt</th>
<th>Resources Compliant</th>
<th>Role/Assignment</th>
<th>Assignment DisplayName</th>
<th>AssignmentId</th>
</tr>
</thead>
<tbody>
"@
    $htmlSummaryPolicyAssignmentsAll = $null
    foreach ($policyAssignment in $script:policyAssignmentsAllArray | sort-object -Property Level, MgName, MgId, SubscriptionName, SubscriptionId) {
$htmlSummaryPolicyAssignmentsAll += @"
<tr>
<td>$($policyAssignment.MgOrSub)</td>
<td>$($policyAssignment.MgId)</td>
<td>$($policyAssignment.MgName)</td>
<td>$($policyAssignment.SubscriptionId)</td>
<td>$($policyAssignment.SubscriptionName)</td>
<td>$($policyAssignment.Inheritance)</td>
<td>$($policyAssignment.ExcludedScope)</td>
<td>$($policyAssignment.PolicyName)</td>
<td class="breakwordall">$($policyAssignment.PolicyId)</td>
<td>$($policyAssignment.PolicyVariant)</td>
<td>$($policyAssignment.PolicyType)</td>
<td>$($policyAssignment.PolicyCategory)</td>
<td>$($policyAssignment.Effect)</td>
<td>$($policyAssignment.NonCompliantPolicies)</td>
<td>$($policyAssignment.CompliantPolicies)</td>
<td>$($policyAssignment.NonCompliantResources)</td>
<td>$($policyAssignment.CompliantResources)</td>
<td class="breakwordall">$($policyAssignment.RelatedRoleAssignments)</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentDisplayName)</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentId)</td>
</tr>
"@
    }
$start = get-date 
$htmlTenantSummary += $htmlSummaryPolicyAssignmentsAll 
$htmlTenantSummary | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
$htmlTenantSummary = $null
$end = get-date
Write-Host "   append file duration: $((NEW-TIMESPAN -Start $start -End $end).TotalSeconds) seconds"
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@ 
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
            col_6: 'select',
            col_9: 'select',
            col_10: 'select',
            col_12: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number',
                'number',
                'number',
                'number',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
            watermark: ['', '', '', 'try [nonempty]', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($script:policyAssignmentsAllArray | measure-object).count) Policy Assignments</span></p>
"@
}
$endSummaryPolicyAssignmentsAll = get-date
Write-Host "   SummaryPolicyAssignmentsAll duration: $((NEW-TIMESPAN -Start $startSummaryPolicyAssignmentsAll -End $endSummaryPolicyAssignmentsAll).TotalMinutes) minutes"
#endregion SUMMARYPolicyAssignmentsAll

#tenantSummaryRBAC
$htmlTenantSummary += @"
    <hr class="hr-text" data-content="RBAC" />
"@

#region SUMMARYtenanttotalcustomroles
Write-Host "  processing Summary Custom Roles"
$tenantCustomRolesCount = ($tenantCustomRoles | measure-object).count
if ($tenantCustomRolesCount -gt $LimitRBACCustomRoleDefinitionsTenant * ($LimitCriticalPercentage / 100)){
    $faimage = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
}
else{
    $faimage = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
}
$tenantCustomRolesArray = @()
$tenantCustomRolesArray += foreach ($tenantCustomRole in $tenantCustomRoles){
    ($htCacheDefinitions).role.($tenantCustomRole)
}

if ($tenantCustomRolesCount -gt 0){
    $tfCount = $tenantCustomRolesCount
    $tableId = "SummaryTable_customRoles"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customRoles">$faimage <span class="valignMiddle">$tenantCustomRolesCount Custom Roles ($scopeNamingSummary) (Limit: $tenantCustomRolesCount/$LimitRBACCustomRoleDefinitionsTenant)</span></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Assignable Scopes</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYtenanttotalcustomroles = $null
    foreach ($tenantCustomRole in $tenantCustomRolesArray | sort-object @{Expression={$_.Name}}, @{Expression={$_.Id}}){
        $cachedTenantCustomRole = ($htCacheDefinitions).role.($tenantCustomRole.Id)
$htmlSUMMARYtenanttotalcustomroles += @"
<tr>
<td>$($cachedTenantCustomRole.Name)
</td>
<td>$($cachedTenantCustomRole.Id)
</td>
<td>$(($cachedTenantCustomRole.AssignableScopes | Measure-Object).count) ($($cachedTenantCustomRole.AssignableScopes -join "$CsvDelimiterOpposite "))
</td>
</tr>
"@ 
    }
$htmlTenantSummary += $htmlSUMMARYtenanttotalcustomroles
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@ 
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomRolesCount Custom Roles ($scopeNamingSummary)</span></p>
"@
}
#endregion SUMMARYtenanttotalcustomroles

#region SUMMARYOrphanedCustomRoles
Write-Host "  processing Summary Custom Roles orphaned"
if ($getMgParentName -eq "Tenant Root"){
    $customRolesInUse = ($rbacBaseQuery | where-object {$_.RoleIsCustom -eq "TRUE"}).RoleDefinitionId | Sort-Object -Unique
    
    $customRolesOrphaned = @()
    if (($tenantCustomRoles | Measure-Object).count -gt 0){
        $customRolesOrphaned += foreach ($customRoleAll in $tenantCustomRoles){
            if (-not $customRolesInUse.contains("$customRoleAll")){    
                $hlpCustomRole = ($htCacheDefinitions).role.$customRoleAll
                if ($hlpCustomRole.IsCustom -eq $True){
                    $hlpCustomRole
                }
            }
        }
    }

    $arrayCustomRolesOrphanedFinalIncludingResourceGroups = @()
    $arrayCustomRolesOrphanedFinalIncludingResourceGroups += foreach ($customRoleOrphaned in $customRolesOrphaned){
        if ($script:arrayCacheRoleAssignmentsResourceGroups.RoleDefinitionId -notcontains $customRoleOrphaned.Id ){
            $customRoleOrphaned
        }
    }

    if (($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0){
        $tfCount = ($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count
        $tableId = "SummaryTable_customRolesOrphaned"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customRolesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom Roles ($scopeNamingSummary) <abbr title="Role has no Assignments (including ResourceGroups and Resources)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Assignable Scopes</th>
</tr>
</thead>
<tbody>
"@
        $htmlSUMMARYOrphanedCustomRoles = $null
        foreach ($customRoleOrphaned in $arrayCustomRolesOrphanedFinalIncludingResourceGroups | Sort-Object @{Expression={$_.Name}}){
$htmlSUMMARYOrphanedCustomRoles += @"
<tr>
<td>$($customRoleOrphaned.Name)</td>
<td>$($customRoleOrphaned.Id)</td>
<td>$(($customRoleOrphaned.AssignableScopes | Measure-Object).count) ($($customRoleOrphaned.AssignableScopes -join "$CsvDelimiterOpposite "))</td>
</tr>
"@ 
        }
$htmlTenantSummary += $htmlSUMMARYOrphanedCustomRoles
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@    
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
    }
    else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom Roles ($scopeNamingSummary)</span></p>
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
                if (($customRoleAssignableScope).startswith("/providers/Microsoft.Management/managementGroups/","CurrentCultureIgnoreCase")){
                    $roleAssignableScopeMgSub = $customRoleAssignableScope -replace "/providers/Microsoft.Management/managementGroups/", ""
                    foreach ($customRoleAssignableScope in $customRoleAssignableScopes) {
                        if (($customRoleAssignableScope).startswith("/providers/Microsoft.Management/managementGroups/","CurrentCultureIgnoreCase")){
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
                        if (($customRoleAssignableScope).startswith("/subscriptions/","CurrentCultureIgnoreCase")){
                            $roleAssignableScopeMgSub = $customRoleAssignableScope -replace "/subscriptions/", "" -replace "/.*", ""
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

    $arrayCustomRolesOrphanedFinalIncludingResourceGroups = @()
    $arrayCustomRolesOrphanedFinalIncludingResourceGroups += foreach ($customRoleOrphaned in $customRolesInScopeArray){
        if ($script:arrayCacheRoleAssignmentsResourceGroups.RoleDefinitionId -notcontains $customRoleOrphaned.Id ){
            $customRoleOrphaned
        }
    }

    if (($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0){
        $tfCount = ($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count
        $tableId = "SummaryTable_customRolesOrphaned"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customRolesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom Roles ($scopeNamingSummary) <abbr title="Role has no Assignments (including ResourceGroups and Resources). Roles where assignableScopes has mg from superior scopes are not evaluated"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Role Assignable Scopes</th>
</tr>
</thead>
<tbody>
"@
        $htmlSUMMARYOrphanedCustomRoles = $null
        foreach ($inScopeCustomRole in $arrayCustomRolesOrphanedFinalIncludingResourceGroups | Sort-Object @{Expression={$_.Name}}){
$htmlSUMMARYOrphanedCustomRoles += @"
<tr>
<td>$($inScopeCustomRole.Name)</td>
<td>$($inScopeCustomRole.Id)</td>
<td>$(($inScopeCustomRole.AssignableScopes | Measure-Object).count) ($($inScopeCustomRole.AssignableScopes -join "$CsvDelimiterOpposite "))</td>
</tr>
"@ 
        }
$htmlTenantSummary += $htmlSUMMARYOrphanedCustomRoles
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@    
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
    }
    else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom Roles ($scopeNamingSummary)</span></p>
"@
    }
}
#endregion SUMMARYOrphanedCustomRoles

#region SUMMARYOrphanedRoleAssignments
Write-Host "  processing Summary RoleAssignments orphaned"
$roleAssignmentsOrphanedAll = $rbacBaseQuery | Where-Object { $_.RoleAssignmentObjectType -eq "Unknown" } | Sort-Object -Property RoleAssignmentId
$roleAssignmentsOrphanedUnique = $roleAssignmentsOrphanedAll | Sort-Object -Property RoleAssignmentId -Unique

if (($roleAssignmentsOrphanedUnique | measure-object).count -gt 0) {
    $tfCount = ($roleAssignmentsOrphanedUnique | measure-object).count
    $tableId = "SummaryTable_roleAssignmnetsOrphaned"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_roleAssignmnetsOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOrphanedUnique | measure-object).count) Orphaned Role Assignments ($scopeNamingSummary) <abbr title="Role was deleted although and assignment existed OR the target identity (User, Group, ServicePrincipal) was deleted"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
<table id= "$tableId" class="summaryTable">
<thead>
<tr>
<th>Role AssignmentId</th>
<th>Role Name</th>
<th>RoleId</th>
<th>Impacted Mg/Sub</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYOrphanedRoleAssignments = $null
    foreach ($roleAssignmentOrphanedUnique in $roleAssignmentsOrphanedUnique) {
        $impactedMgs = ($roleAssignmentsOrphanedAll | Where-Object { "" -eq $_.SubscriptionId -and $_.RoleAssignmentId -eq $roleAssignmentOrphanedUnique.RoleAssignmentId } | Sort-Object -Property MgId)
        $impactedSubs = $roleAssignmentsOrphanedAll | Where-Object { "" -ne $_.SubscriptionId -and $_.RoleAssignmentId -eq $roleAssignmentOrphanedUnique.RoleAssignmentId } | Sort-Object -Property SubscriptionId
$htmlSUMMARYOrphanedRoleAssignments += @"
<tr>
<td>$($roleAssignmentOrphanedUnique.RoleAssignmentId)</td>
<td>$($roleAssignmentOrphanedUnique.RoleDefinitionName)</td>
<td>$($roleAssignmentOrphanedUnique.RoleDefinitionId)</td>
<td>Mg: $(($impactedMgs | measure-object).count); Sub: $(($impactedSubs | measure-object).count)</td>
</tr>
"@ 
    }
$htmlTenantSummary += $htmlSUMMARYOrphanedRoleAssignments
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@   
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOrphanedUnique | measure-object).count) Orphaned Role Assignments ($scopeNamingSummary)</span></p>
"@
}
#endregion SUMMARYOrphanedRoleAssignments

#region SUMMARYRoleAssignmentsAll
$roleAssignmentsallCount = ($rbacBaseQuery | Measure-Object).count
$policyAssignmentIdsUnique = $policyBaseQuery | select-object PolicyAssignmentId, Policy, PolicyDefinitionIdGuid, PolicyVariant, PolicyType, PolicyAssignmentName | sort-object -Property PolicyAssignmentId -Unique
$roleAssignmentIdsUnique = $rbacBaseQuery | sort-object -Property RoleAssignmentId -Unique

$htRoleAssignmentRelatedPolicyAssignments = @{ }
foreach ($roleAssignmentIdUnique in $roleAssignmentIdsUnique){
    $relatedPolicyAssignment = $policyAssignmentIdsUnique | where-Object { $_.PolicyAssignmentName -eq $roleAssignmentIdUnique.RoleAssignmentDisplayname }
    $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId) = @{ }
    if ($relatedPolicyAssignment) {
        if ($relatedPolicyAssignment.PolicyType -eq "BuiltIn") {
            if ($relatedPolicyAssignment.PolicyVariant -eq "Policy") {
                $LinkOrNotLinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/$($relatedPolicyAssignment.policyDefinitionIdGuid).html`" target=`"_blank`">$($relatedPolicyAssignment.Policy)</a>"
            }
            if ($relatedPolicyAssignment.PolicyVariant -eq "PolicySet") {
                $LinkOrNotLinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyinitiativesadvertizer/$($relatedPolicyAssignment.policyDefinitionIdGuid).html`" target=`"_blank`">$($relatedPolicyAssignment.Policy)</a>"
            }
        }
        else {
            $LinkOrNotLinkToAzAdvertizer = $relatedPolicyAssignment.Policy
        }
        $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).relatedPolicyAssignment = "$($relatedPolicyAssignment.PolicyAssignmentId) ($LinkOrNotLinkToAzAdvertizer)"
    }
    else {
        $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).relatedPolicyAssignment = "none" 
    }

    if ($roleAssignmentIdUnique.RoleIsCustom -eq "FALSE"){
        $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).roleType = "Builtin"
        $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azrolesadvertizer/$($roleAssignmentIdUnique.RoleDefinitionId).html`" target=`"_blank`">$($roleAssignmentIdUnique.RoleDefinitionName)</a>"
    }
    else{
        if ($roleAssigned.RoleSecurityCustomRoleOwner -eq 1){
            $roletype = "<abbr title=`"Custom owner roles should not exist`"><i class=`"fa fa-exclamation-triangle yellow`" aria-hidden=`"true`"></i></abbr> <a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/10ee2ea2-fb4d-45b8-a7e9-a2e770044cd9.html`" target=`"_blank`">Custom</a>"
        }
        else{
            $roleType = "Custom"
        }
        $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).roleType = $roleType
        $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer = $roleAssignmentIdUnique.RoleDefinitionName
    }
}

Write-Host "  processing Summary RoleAssignments (all $roleAssignmentsallCount)"
$cnter = 0
$script:rbacAll = [System.Collections.ArrayList]@()
$startRoleAssignmentsAll = get-date
foreach ($rbac in $rbacBaseQuery){
    $cnter++
    if ($cnter % 500  -eq 0){
        $etappeRoleAssignmentsAll = get-date
        write-host "   $cnter of $roleAssignmentsallCount RoleAssignments processed; $((NEW-TIMESPAN -Start $startRoleAssignmentsAll -End $etappeRoleAssignmentsAll).TotalSeconds) seconds"
    }
    $scope = $null
    if (($rbac.RoleAssignmentId).StartsWith("/providers/Microsoft.Management/managementGroups/","CurrentCultureIgnoreCase")){
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
    if (($rbac.RoleAssignmentId).StartsWith("/subscriptions/","CurrentCultureIgnoreCase")){
        $scope = "this Sub"
    }
    if (($rbac.RoleAssignmentId).StartsWith("/providers/Microsoft.Authorization/roleAssignments/","CurrentCultureIgnoreCase")){
            $scope = "inherited ROOT"
    }

    if ("" -eq $rbac.SubscriptionId){
        $mgOrSub = "Mg"
    }
    else{
        $mgOrSub = "Sub"
    }

    $null = $script:rbacAll.Add([PSCustomObject]@{ 'Level' = $rbac.Level; 'RoleAssignmentId' = $rbac.RoleAssignmentId; 'MgId'= $rbac.MgId; 'MgName' = $rbac.MgName; 'SubscriptionId' = $rbac.SubscriptionId; 'SubscriptionName' = $rbac.Subscription; 'Scope' = $scope; 'Role' = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer; 'RoleType' = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleType; 'ObjectDisplayName' = $rbac.RoleAssignmentDisplayname; 'ObjectSignInName' = $rbac.RoleAssignmentSignInName; 'ObjectId' = $rbac.RoleAssignmentObjectId; 'ObjectType' = $rbac.RoleAssignmentObjectType; 'MgOrSub' = $mgOrSub; 'RbacRelatedPolicyAssignment' = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).relatedPolicyAssignment; 'RoleSecurityCustomRoleOwner' = $rbac.RoleSecurityCustomRoleOwner; 'RoleSecurityOwnerAssignmentSP' = $rbac.RoleSecurityOwnerAssignmentSP })
}
Write-Host "   RoleAssignments Array created $(get-date)"

if (($script:rbacAll | measure-object).count -gt 0) {
    $uniqueRoleAssignmentsCount = ($script:rbacAll | sort-object -Property RoleAssignmentId -Unique | Measure-Object).count
    $tfCount = ($script:rbacAll | measure-object).count
    $tableId = "SummaryTable_roleAssignmentsAll"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_roleAssignmentsAll"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($script:rbacAll | measure-object).count) Role Assignments ($uniqueRoleAssignmentsCount unique)</span>
</button>
<div class="content">
<table id= "$tableId" class="summaryTable">
<thead>
<tr>
<th>Mg/Sub</th>
<th>Management Group Id</th>
<th>Management Group Name</th>
<th>SubscriptionId</th>
<th>Subscription Name</th>
<th>Scope</th>
<th>Role</th>
<th>Role Type</th>
<th>Object Displayname</th>
<th>Object SignInName</th>
<th>Object ObjectId</th>
<th>Object Type</th>
<th>Role AssignmentId</th>
<th>Related PolicyAssignment</th>
</tr>
</thead>
<tbody>
"@
    $cnter = 0
    $roleAssignmentsAllCount = ($script:rbacAll | Measure-Object).count
    $startWriteRoleAssignmentsAll = get-date
    $htmlSummaryRoleAssignmentsAll = $null
    foreach ($roleAssignment in $script:rbacAll | sort-object -Property Level, MgName, MgId, SubscriptionName, SubscriptionId) {
        $cnter++
        if ($cnter % 500  -eq 0){
            $etappeWriteRoleAssignmentsAll = get-date
            write-host "   $cnter of $roleAssignmentsAllCount RoleAssignments processed; $((NEW-TIMESPAN -Start $startWriteRoleAssignmentsAll -End $etappeWriteRoleAssignmentsAll).TotalSeconds) seconds"
        }
$htmlSummaryRoleAssignmentsAll += @"
<tr>
<td>$($roleAssignment.MgOrSub)</td>
<td>$($roleAssignment.MgId)</td>
<td>$($roleAssignment.MgName)</td>
<td>$($roleAssignment.SubscriptionId)</td>
<td>$($roleAssignment.SubscriptionName)</td>
<td>$($roleAssignment.Scope)</td>
<td>$($roleAssignment.Role)</td>
<td>$($roleAssignment.RoleType)</td>
<td class="breakwordall">$($roleAssignment.ObjectDisplayName)</td>
<td class="breakwordall">$($roleAssignment.ObjectSignInName)</td>
<td class="breakwordall">$($roleAssignment.ObjectId)</td>
<td>$($roleAssignment.ObjectType)</td>
<td class="breakwordall">$($roleAssignment.RoleAssignmentId)</td>
<td class="breakwordall">$($roleAssignment.rbacRelatedPolicyAssignment)</td>
</tr>
"@
    }
$start = get-date
$htmlTenantSummary += $htmlSummaryRoleAssignmentsAll
$htmlTenantSummary | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
$htmlTenantSummary = $null
$end = get-date
Write-Host "   append file duration: $((NEW-TIMESPAN -Start $start -End $end).TotalSeconds) seconds"
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@    
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
            col_7: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
            watermark: ['', '', '', 'try [nonempty]', '', '', 'try owner||reader', '', '', '', '', '', '', ''],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($script:rbacAll | measure-object).count) Role Assignments</span></p>
"@
}
$endRoleAssignmentsAll = get-date
Write-Host "   SummaryRoleAssignmentsAll duration: $((NEW-TIMESPAN -Start $startRoleAssignmentsAll -End $endRoleAssignmentsAll).TotalMinutes) minutes"
#endregion SUMMARYRoleAssignmentsAll

#region SUMMARYSecurityCustomRoles
Write-Host "  processing Summary Custom Roles security (owner permissions)"
$customRolesOwnerAll = $rbacBaseQuery | Where-Object { $_.RoleSecurityCustomRoleOwner -eq 1 } | Sort-Object -Property RoleDefinitionId
$customRolesOwnerHtAll = $tenantCustomRoles | where-object { ($htCacheDefinitions).role.$_.Actions -eq '*' -and (($htCacheDefinitions).role.$_.NotActions).length -eq 0 }
if (($customRolesOwnerHtAll | measure-object).count -gt 0){
    $tfCount = ($customRolesOwnerHtAll | measure-object).count
    $tableId = "SummaryTable_customroleCustomRoleOwner"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customroleCustomRoleOwner"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($customRolesOwnerHtAll | measure-object).count) Custom Roles Owner permissions ($scopeNamingSummary) <abbr title="Custom owner roles should not exist"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Role Assignments</th>
<th>Assignable Scopes</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYSecurityCustomRoles = $null
    foreach ($customRole in ($customRolesOwnerHtAll | sort-object)) {
        $customRoleOwnersAllAssignmentsCount = ((($customRolesOwnerAll | Where-Object { $_.RoleDefinitionId -eq $customRole }).RoleAssignmentId | Sort-Object -Unique) | measure-object).count
        if ($customRoleOwnersAllAssignmentsCount -gt 0){
            $customRoleRoleAssignmentsArray = @()
            $customRoleRoleAssignmentIds = ($customRolesOwnerAll | Where-Object { $_.RoleDefinitionId -eq $customRole }).RoleAssignmentId | Sort-Object -Unique
            $customRoleRoleAssignmentsArray += foreach ($customRoleRoleAssignmentId in $customRoleRoleAssignmentIds){
                $customRoleRoleAssignmentId
            }
            $customRoleRoleAssignmentsOutput = "$customRoleOwnersAllAssignmentsCount ($($customRoleRoleAssignmentsArray -join "$CsvDelimiterOpposite "))"
        }
        else{
            $customRoleRoleAssignmentsOutput = "$customRoleOwnersAllAssignmentsCount"
        }
        $hlpCustomRole = ($htCacheDefinitions).role.($customRole)
$htmlSUMMARYSecurityCustomRoles += @"
<tr>
<td>$($hlpCustomRole.Name)</td>
<td>$($customRole)</td>
<td>$($customRoleRoleAssignmentsOutput)</td>
<td>$(($hlpCustomRole.AssignableScopes | Measure-Object).count) ($($hlpCustomRole.AssignableScopes -join "$CsvDelimiterOpposite "))</td>
</tr>
"@ 
    }
$htmlTenantSummary += $htmlSUMMARYSecurityCustomRoles
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($customRolesOwnerHtAll | measure-object).count) Custom Roles Owner permissions ($scopeNamingSummary)</span></p>
"@
}
#endregion SUMMARYSecurityCustomRoles

#region SUMMARYSecurityOwnerAssignmentSP
Write-Host "  processing Summary RoleAssignments security (owner SP)"
$roleAssignmentsOwnerAssignmentSPAll = ($rbacBaseQuery | Where-Object { $_.RoleSecurityOwnerAssignmentSP -eq 1 } | Sort-Object -Property RoleAssignmentId)
$roleAssignmentsOwnerAssignmentSP = $roleAssignmentsOwnerAssignmentSPAll | sort-object -Property RoleAssignmentId -Unique
if (($roleAssignmentsOwnerAssignmentSP | measure-object).count -gt 0){
    $tfCount = ($roleAssignmentsOwnerAssignmentSP | measure-object).count
    $tableId = "SummaryTable_roleAssignmentsOwnerAssignmentSP"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_roleAssignmentsOwnerAssignmentSP"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentSP | measure-object).count) Owner permission assignments to ServicePrincipal ($scopeNamingSummary) <abbr title="Owner permissions for Service Principals should be treated exceptional"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
<table id= "$tableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Role Assignment</th>
<th>ServicePrincipal (ObjId)</th>
<th>Impacted Mg/Sub</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYSecurityOwnerAssignmentSP = $null
    foreach ($roleAssignmentOwnerAssignmentSP in ($roleAssignmentsOwnerAssignmentSP)) {
        $impactedMgs = $roleAssignmentsOwnerAssignmentSPAll | Where-Object { "" -eq $_.SubscriptionId -and $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentSP.RoleAssignmentId }
        $impactedSubs = $roleAssignmentsOwnerAssignmentSPAll | Where-Object { "" -ne $_.SubscriptionId -and $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentSP.RoleAssignmentId }
        $servicePrincipal = ($roleAssignmentsOwnerAssignmentSP | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentSP.RoleAssignmentId }) | Get-Unique
$htmlSUMMARYSecurityOwnerAssignmentSP += @"
<tr>
<td>$($roleAssignmentOwnerAssignmentSP.RoleDefinitionName)</td>
<td>$($roleAssignmentOwnerAssignmentSP.RoleDefinitionId)</td>
<td>$($roleAssignmentOwnerAssignmentSP.RoleAssignmentId)</td>
<td>$($servicePrincipal.RoleAssignmentDisplayname) ($($servicePrincipal.RoleAssignmentObjectId))</td>
<td>Mg: $(($impactedMgs | measure-object).count); Sub: $(($impactedSubs | measure-object).count)</td>
</tr>
"@ 
    }
$htmlTenantSummary += $htmlSUMMARYSecurityOwnerAssignmentSP
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentSP | measure-object).count) Owner permission assignments to ServicePrincipal ($scopeNamingSummary)</span></p>
"@
}
#endregion SUMMARYSecurityOwnerAssignmentSP

#region SUMMARYSecurityOwnerAssignmentNotGroup
Write-Host "  processing Summary RoleAssignments security (owner notGroup)"
$roleAssignmentsOwnerAssignmentNotGroupAll = ($rbacBaseQuery | Where-Object { $_.RoleDefinitionName -eq "Owner" -and $_.RoleAssignmentObjectType -ne "Group" } | Sort-Object -Property RoleAssignmentId)
$roleAssignmentsOwnerAssignmentNotGroup = $roleAssignmentsOwnerAssignmentNotGroupAll | sort-object -Property RoleAssignmentId -Unique
if (($roleAssignmentsOwnerAssignmentNotGroup | measure-object).count -gt 0){
    $tfCount = ($roleAssignmentsOwnerAssignmentNotGroup | measure-object).count
    $tableId = "SummaryTable_roleAssignmentsOwnerAssignmentNotGroup"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_roleAssignmentsOwnerAssignmentNotGroup"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentNotGroup | measure-object).count) Owner permission assignments to notGroup ($scopeNamingSummary)</span>
</button>
<div class="content">
<table id= "$tableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Role Assignment</th>
<th>Obj Type</th>
<th>Obj DisplayName</th>
<th>Obj SignInName</th>
<th>ObjId</th>
<th>Impacted Mg/Sub</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYSecurityOwnerAssignmentNotGroup = $null
    foreach ($roleAssignmentOwnerAssignmentNotGroup in ($roleAssignmentsOwnerAssignmentNotGroup)) {
        $impactedMgSubBaseQuery = $roleAssignmentsOwnerAssignmentNotGroupAll | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentId }
        $impactedMgs = $impactedMgSubBaseQuery | Where-Object { "" -eq $_.SubscriptionId }
        $impactedSubs = $impactedMgSubBaseQuery | Where-Object { "" -ne $_.SubscriptionId }
        $servicePrincipal = ($roleAssignmentsOwnerAssignmentNotGroup | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentId }) | Get-Unique
$htmlSUMMARYSecurityOwnerAssignmentNotGroup += @"
<tr>
<td>$($roleAssignmentOwnerAssignmentNotGroup.RoleDefinitionName)</td>
<td>$($roleAssignmentOwnerAssignmentNotGroup.RoleDefinitionId)</td>
<td class="breakwordall">$($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentId)</td>
<td>$($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentObjectType)</td>
<td>$($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentDisplayname)</td>
<td class="breakwordall">$($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentSignInName)</td>
<td class="breakwordall">$($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentObjectId)</td>
<td>Mg: $(($impactedMgs | measure-object).count); Sub: $(($impactedSubs | measure-object).count)</td>
</tr>
"@ 
    }
$htmlTenantSummary += $htmlSUMMARYSecurityOwnerAssignmentNotGroup
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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

$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@   
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentNotGroup | measure-object).count) Owner permission assignments to notGroup ($scopeNamingSummary)</span></p>
"@
}
#endregion SUMMARYSecurityOwnerAssignmentNotGroup

#region SUMMARYSecurityUserAccessAdministratorAssignmentNotGroup
Write-Host "  processing Summary RoleAssignments security (userAccessAdministrator notGroup)"
$roleAssignmentsUserAccessAdministratorAssignmentNotGroupAll = ($rbacBaseQuery | Where-Object { $_.RoleDefinitionName -eq "User Access Administrator" -and $_.RoleAssignmentObjectType -ne "Group" } | Sort-Object -Property RoleAssignmentId)
$roleAssignmentsUserAccessAdministratorAssignmentNotGroup = $roleAssignmentsUserAccessAdministratorAssignmentNotGroupAll | sort-object -Property RoleAssignmentId -Unique
if (($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | measure-object).count -gt 0){
    $tfCount = ($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | measure-object).count
    $tableId = "SummaryTable_roleAssignmentsUserAccessAdministratorAssignmentNotGroup"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_roleAssignmentsUserAccessAdministratorAssignmentNotGroup"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | measure-object).count) UserAccessAdministrator permission assignments to notGroup ($scopeNamingSummary)</span>
</button>
<div class="content">
<table id= "$tableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Role Assignment</th>
<th>Obj Type</th>
<th>Obj DisplayName</th>
<th>Obj SignInName</th>
<th>ObjId</th>
<th>Impacted Mg/Sub</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup = $null
    foreach ($roleAssignmentUserAccessAdministratorAssignmentNotGroup in ($roleAssignmentsUserAccessAdministratorAssignmentNotGroup)) {
        $impactedMgSubBaseQuery = $roleAssignmentsUserAccessAdministratorAssignmentNotGroupAll | Where-Object { $roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId }
        $impactedMgs = $impactedMgSubBaseQuery | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId }
        $impactedSubs = $impactedMgSubBaseQuery | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId }
        $servicePrincipal = ($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId }) | Get-Unique
$htmlSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup += @"
<tr>
<td>$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleDefinitionName)</td>
<td>$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleDefinitionId)</td>
<td class="breakwordall">$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId)</td>
<td>$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentObjectType)</td>
<td>$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentDisplayname)</td>
<td class="breakwordall">$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentSignInName)</td>
<td class="breakwordall">$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentObjectId)</td>
<td>Mg: $(($impactedMgs | measure-object).count); Sub: $(($impactedSubs | measure-object).count)</td>
</tr>
"@ 
    }
$htmlTenantSummary += $htmlSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@    
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | measure-object).count) UserAccessAdministrator permission assignments to notGroup ($scopeNamingSummary)</span></p>
"@
}
#endregion SUMMARYSecurityUserAccessAdministratorAssignmentNotGroup

#tenantSummaryBlueprints
$htmlTenantSummary += @"
    <hr class="hr-text" data-content="Blueprints" />
"@

#region SUMMARYBlueprintDefinitions
Write-Host "  processing Summary Blueprints"
$blueprintDefinitions = ($blueprintBaseQuery | Where-Object { "" -eq $_.BlueprintAssignmentId })
$blueprintDefinitionsCount = ($blueprintDefinitions | measure-object).count
    if ($blueprintDefinitionsCount -gt 0){
        $tableId = "SUMMARY_BlueprintDefinitions"
$htmlTenantSummary += @"
<button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintDefinitionsCount Blueprints</p></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th class="widthCustom">Blueprint Name</th>
<th>Blueprint DisplayName</th>
<th>Blueprint Description</th>
<th>BlueprintId</th>
</tr>
</thead>
<tbody>
"@
        $htmlSUMMARYBlueprintDefinitions = $null
        foreach ($blueprintDefinition in $blueprintDefinitions){
$htmlSUMMARYBlueprintDefinitions += @"
<tr>
<td>$($blueprintDefinition.BlueprintName)</td>
<td>$($blueprintDefinition.BlueprintDisplayName)</td>
<td>$($blueprintDefinition.BlueprintDescription)</td>
<td>$($blueprintDefinition.BlueprintId)</td>
</tr>
"@        
        }
$htmlTenantSummary += $htmlSUMMARYBlueprintDefinitions
$htmlTenantSummary += @"
                </tbody>
            </table>
        </div>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
                col_types: [
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring'
                ],
extensions: [{ name: 'sort' }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
"@
    }
    else{
$htmlTenantSummary += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $blueprintDefinitionsCount Blueprints</p>
"@
    }
#endregion SUMMARYBlueprintDefinitions

#region SUMMARYBlueprintAssignments
Write-Host "  processing Summary BlueprintAssignments"
$blueprintAssignments = ($blueprintBaseQuery | Where-Object { "" -ne $_.BlueprintAssignmentId })
$blueprintAssignmentsCount = ($blueprintAssignments | measure-object).count

    if ($blueprintAssignmentsCount -gt 0){
        $tableId = "SUMMARY_BlueprintAssignments"
$htmlTenantSummary += @"
<button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintAssignmentsCount Blueprint Assignments</p></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th class="widthCustom">Blueprint Name</th>
<th>Blueprint DisplayName</th>
<th>Blueprint Description</th>
<th>BlueprintId</th>
<th>Blueprint Version</th>
<th>Blueprint AssignmentId</th>
</tr>
</thead>
<tbody>
"@
        $htmlSUMMARYBlueprintAssignments = $null
        foreach ($blueprintAssignment in $blueprintAssignments){
$htmlSUMMARYBlueprintAssignments += @"
<tr>
<td>$($blueprintAssignment.BlueprintName)</td>
<td>$($blueprintAssignment.BlueprintDisplayName)</td>
<td>$($blueprintAssignment.BlueprintDescription)</td>
<td>$($blueprintAssignment.BlueprintId)</td>
<td>$($blueprintAssignment.BlueprintAssignmentVersion)</td>
<td>$($blueprintAssignment.BlueprintAssignmentId)</td>
</tr>
"@        
        }
$htmlTenantSummary += $htmlSUMMARYBlueprintAssignments
$htmlTenantSummary += @"
                </tbody>
            </table>
        </div>
        <script>
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
                col_types: [
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring',
                    'caseinsensitivestring'
                ],
extensions: [{ name: 'sort' }]
            };
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
            tf.init();
        </script>
"@
    }
    else{
$htmlTenantSummary += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $blueprintAssignmentsCount Blueprint Assignments</p>
"@
    }
#endregion SUMMARYBlueprintAssignments

#region SUMMARYBlueprintsOrphaned
Write-Host "  processing Summary Blueprints orphaned"
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
$htmlTenantSummary += @"
<button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintDefinitionsOrphanedCount Orphaned Blueprints</p></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th class="widthCustom">Blueprint Name</th>
<th>Blueprint DisplayName</th>
<th>Blueprint Description</th>
<th>BlueprintId</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYBlueprintsOrphaned = $null
    foreach ($blueprintDefinition in $blueprintDefinitionsOrphanedArray){
$htmlSUMMARYBlueprintsOrphaned += @"
<tr>
<td>$($blueprintDefinition.BlueprintName)</td>
<td>$($blueprintDefinition.BlueprintDisplayName)</td>
<td>$($blueprintDefinition.BlueprintDescription)</td>
<td>$($blueprintDefinition.BlueprintId)</td>
</tr>
"@        
    }
$htmlTenantSummary += $htmlSUMMARYBlueprintsOrphaned
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@     
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
                <p><i class="fa fa-ban" aria-hidden="true"></i> $blueprintDefinitionsOrphanedCount Orphaned Blueprints</p>
"@
}
#endregion SUMMARYBlueprintsOrphaned

#tenantSummaryManagementGroups
$htmlTenantSummary += @"
    <hr class="hr-text" data-content="Management Groups & Limits" />
"@

#region SUMMARYMGs
Write-Host "  processing Summary ManagementGroups"
$htmlTenantSummary += @"
    <p><img class="imgMgTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> <span class="valignMiddle">$totalMgCount Management Groups ($mgDepth levels of depth)</span></p>
"@
#endregion SUMMARYMGs

#region SUMMARYMgsapproachingLimitsPolicyAssignments
Write-Host "  processing Summary ManagementGroups Limit PolicyAssignments"
$mgsApproachingLimitPolicyAssignments = (($policyBaseQuery | where-object { "" -eq $_.SubscriptionId -and $_.PolicyAndPolicySetAssigmentAtScopeCount -gt 0 -and  (($_.PolicyAndPolicySetAssigmentAtScopeCount -gt ($_.PolicyAssigmentLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, MgName, PolicyAssigmentAtScopeCount, PolicySetAssigmentAtScopeCount, PolicyAndPolicySetAssigmentAtScopeCount, PolicyAssigmentLimit -Unique)
if (($mgsApproachingLimitPolicyAssignments | measure-object).count -gt 0){
    $tfCount = ($mgsApproachingLimitPolicyAssignments | measure-object).count
    $tableId = "SummaryTable_MgsapproachingLimitsPolicyAssignments"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_MgsapproachingLimitsPolicyAssignments"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicyAssignments | measure-object).count) Management Groups approaching Limit for PolicyAssignment</span></button>
<div class="content">
<table id= "$tableId" class="summaryTable">
<thead>
<tr>
<th>Management Group Name</th>
<th>Management Group Id</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYMgsapproachingLimitsPolicyAssignments = $null
    foreach ($mgApproachingLimitPolicyAssignments in $mgsApproachingLimitPolicyAssignments){
$htmlSUMMARYMgsapproachingLimitsPolicyAssignments += @"
<tr>
<td><span class="valignMiddle">$($mgApproachingLimitPolicyAssignments.MgName)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($mgApproachingLimitPolicyAssignments.MgId)">$($mgApproachingLimitPolicyAssignments.MgId)</a></span></td>
<td>$($mgApproachingLimitPolicyAssignments.PolicyAndPolicySetAssigmentAtScopeCount)/$($mgApproachingLimitPolicyAssignments.PolicyAssigmentLimit) ($($mgApproachingLimitPolicyAssignments.PolicyAssigmentAtScopeCount) Policy Assignments, $($mgApproachingLimitPolicyAssignments.PolicySetAssigmentAtScopeCount) PolicySet Assignments)</td>
</tr>
"@
    }
$htmlTenantSummary += $htmlSUMMARYMgsapproachingLimitsPolicyAssignments
$htmlTenantSummary += @"
        </tbody>
    </table>
</div>
<script>
    var tfConfig4$tableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@      
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$tableId', tfConfig4$tableId);
    tf.init();
</script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicyAssignments | measure-object).count) Management Groups approaching Limit for PolicyAssignment</span></p>
"@
}
#endregion SUMMARYMgsapproachingLimitsPolicyAssignments

#region SUMMARYMgsapproachingLimitsPolicyScope
Write-Host "  processing Summary ManagementGroups Limit PolicyScope"
$mgsApproachingLimitPolicyScope = (($policyBaseQuery | where-object { "" -eq $_.SubscriptionId -and $_.PolicyDefinitionsScopedCount -gt 0 -and (($_.PolicyDefinitionsScopedCount -gt ($_.PolicyDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, MgName, PolicyDefinitionsScopedCount, PolicyDefinitionsScopedLimit -Unique)
if (($mgsApproachingLimitPolicyScope | measure-object).count -gt 0){
    $tfCount = ($mgsApproachingLimitPolicyScope | measure-object).count
    $tableId = "SummaryTable_MgsapproachingLimitsPolicyScope"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_MgsapproachingLimitsPolicyScope"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicyScope | measure-object).count) Management Groups approaching Limit for Policy Scope</span></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Management Group Name</th>
<th>Management Group Id</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYMgsapproachingLimitsPolicyScope = $null
    foreach ($mgApproachingLimitPolicyScope in $mgsApproachingLimitPolicyScope){
$htmlSUMMARYMgsapproachingLimitsPolicyScope += @"
<tr>
<td><span class="valignMiddle">$($mgApproachingLimitPolicyScope.MgName)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($mgApproachingLimitPolicyScope.MgId)">$($mgApproachingLimitPolicyScope.MgId)</a></span></td>
<td>$($mgApproachingLimitPolicyScope.PolicyDefinitionsScopedCount)/$($mgApproachingLimitPolicyScope.PolicyDefinitionsScopedLimit)</td>
</tr>
"@
    }
$htmlTenantSummary += $htmlSUMMARYMgsapproachingLimitsPolicyScope
$htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@    
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$($mgsApproachingLimitPolicyScope.count) Management Groups approaching Limit for Policy Scope</span></p>
"@
}
#endregion SUMMARYMgsapproachingLimitsPolicyScope

#region SUMMARYMgsapproachingLimitsPolicySetScope
Write-Host "  processing Summary ManagementGroups Limit PolicySetScope"
$mgsApproachingLimitPolicySetScope = (($policyBaseQuery | where-object { "" -eq $_.SubscriptionId -and $_.PolicySetDefinitionsScopedCount -gt 0 -and  (($_.PolicySetDefinitionsScopedCount -gt ($_.PolicySetDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, MgName, PolicySetDefinitionsScopedCount, PolicySetDefinitionsScopedLimit -Unique)
if ($mgsApproachingLimitPolicySetScope.count -gt 0){
    $tfCount = ($mgsApproachingLimitPolicySetScope | measure-object).count 
    $tableId = "SummaryTable_MgsapproachingLimitsPolicySetScope"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_MgsapproachingLimitsPolicySetScope"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicySetScope | measure-object).count) Management Groups approaching Limit for PolicySet Scope</span></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Management Group Name</th>
<th>Management Group Id</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYMgsapproachingLimitsPolicySetScope = $null
    foreach ($mgApproachingLimitPolicySetScope in $mgsApproachingLimitPolicySetScope){
$htmlSUMMARYMgsapproachingLimitsPolicySetScope += @"
<tr>
<td><span class="valignMiddle">$($mgApproachingLimitPolicySetScope.MgName)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($mgApproachingLimitPolicySetScope.MgId)">$($mgApproachingLimitPolicySetScope.MgId)</a></span></td>
<td>$($mgApproachingLimitPolicySetScope.PolicySetDefinitionsScopedCount)/$($mgApproachingLimitPolicySetScope.PolicySetDefinitionsScopedLimit)</td>
</tr>
"@
    }
$htmlTenantSummary += $htmlSUMMARYMgsapproachingLimitsPolicySetScope
$htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@     
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicySetScope | measure-object).count) Management Groups approaching Limit for PolicySet Scope</span></p>
"@
}
#endregion SUMMARYMgsapproachingLimitsPolicySetScope

#region SUMMARYMgsapproachingLimitsRoleAssignment
Write-Host "  processing Summary ManagementGroups Limit RoleAssignments"
$mgsApproachingRoleAssignmentLimit = $rbacBaseQuery | Where-Object { "" -eq $_.SubscriptionId -and $_.RoleAssignmentsCount -gt ($_.RoleAssignmentsLimit * $LimitCriticalPercentage / 100)} | Sort-Object -Property MgId -Unique | select-object -Property MgId, MgName, RoleAssignmentsCount, RoleAssignmentsLimit
if (($mgsApproachingRoleAssignmentLimit | measure-object).count -gt 0){
    $tfCount = ($mgsApproachingRoleAssignmentLimit | measure-object).count
    $tableId = "SummaryTable_MgsapproachingLimitsRoleAssignment"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_MgsapproachingLimitsRoleAssignment"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingRoleAssignmentLimit | measure-object).count) Management Groups approaching Limit for RoleAssignment</span></button>
<div class="content">
<table id= "$tableId" class="summaryTable">
<thead>
<tr>
<th>Management Group Name</th>
<th>Management Group Id</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYMgsapproachingLimitsRoleAssignment = $null
    foreach ($mgApproachingRoleAssignmentLimit in $mgsApproachingRoleAssignmentLimit){
$htmlSUMMARYMgsapproachingLimitsRoleAssignment += @"
<tr>
<td><span class="valignMiddle">$($mgApproachingRoleAssignmentLimit.MgName)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($mgApproachingRoleAssignmentLimit.MgId)">$($mgApproachingRoleAssignmentLimit.MgId)</a></span></td>
<td>$($mgApproachingRoleAssignmentLimit.RoleAssignmentsCount)/$($mgApproachingRoleAssignmentLimit.RoleAssignmentsLimit)</td>
</tr>
"@
    }
$htmlTenantSummary += $htmlSUMMARYMgsapproachingLimitsRoleAssignment
$htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@   
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($mgApproachingRoleAssignmentLimit | measure-object).count) Management Groups approaching Limit for RoleAssignment</span></p>
"@
}
#endregion SUMMARYMgsapproachingLimitsRoleAssignment

#tenantSummarySubscriptions
$htmlTenantSummary += @"
    <hr class="hr-text" data-content="Subscriptions, Resources & Limits" />
"@

#region SUMMARYSubs
Write-Host "  processing Summary Subscriptions"
$summarySubscriptions = $subscriptionBaseQuery | Select-Object -Property Subscription, SubscriptionId, MgId, SubscriptionQuotaId, SubscriptionState -Unique | Sort-Object -Property Subscription
if (($summarySubscriptions | measure-object).count -gt 0){
    $tfCount = ($summarySubscriptions | measure-object).count
    $tableId = "SummaryTable_subs"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_Subs"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle">$(($summarySubscriptions | measure-object).count) Subscriptions</span></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>State</th>
<th>QuotaId</th>
<th>Tags</th>
<th>Path</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYSubs = $null
    foreach ($summarySubscription in $summarySubscriptions){
        $subPath = $htAllSubsMgPath.($summarySubscription.subscriptionId).path -join "/"
        $subscriptionTagsArray = @()
        $subscriptionTagsArray += foreach ($tag in ($htSubscriptionTags).($summarySubscription.subscriptionId).keys) {
            write-output "'$($tag)':'$(($htSubscriptionTags).$($summarySubscription.subscriptionId).$tag)'"
        }

$htmlSUMMARYSubs += @"
<tr>
<td>$($summarySubscription.subscription)</td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($summarySubscription.MgId)">$($summarySubscription.subscriptionId)</a></span></td>
<td>$($summarySubscription.SubscriptionState)</td>
<td>$($summarySubscription.SubscriptionQuotaId)</td>
<td>$(($subscriptionTagsArray | sort-object) -join "$CsvDelimiterOpposite ")</td>
<td><a href="#hierarchySub_$($summarySubscription.MgId)"><i class="fa fa-eye" aria-hidden="true"></i></a> $subPath</td>
</tr>
"@
    }
$htmlTenantSummary += $htmlSUMMARYSubs
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>

    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@   
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>

"@
    }
    else{
$htmlTenantSummary += @"
    <p><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle">$subscount Subscriptions</span></p>
"@
}
#endregion SUMMARYSubs

#region SUMMARYOutOfScopeSubscriptions
Write-Host "  processing Summary Subscriptions (out-of-scope)"
#$script:outOfScopeSubscriptions
#$outOfScopeSubscriptionsCount = ($htOutOfScopeSubscriptions.keys | Measure-Object).Count
$outOfScopeSubscriptionsCount = ($script:outOfScopeSubscriptions | Measure-Object).Count
if ($outOfScopeSubscriptionsCount -gt 0){
    $tfCount = $outOfScopeSubscriptionsCount
    $tableId = "SummaryTable_outOfScopeSubscriptions"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_outOfScopeSubscriptions"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg"> <span class="valignMiddle">$outOfScopeSubscriptionsCount Subscriptions out-of-scope</span></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Subscription Name</th>
<th>SubscriptionId</th>
<th>out-of-scope reason</th>
<th>Management Group</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYOutOfScopeSubscriptions = $null
    foreach ($outOfScopeSubscription in $script:outOfScopeSubscriptions){
$htmlSUMMARYOutOfScopeSubscriptions += @"
<tr>
<td>$($outOfScopeSubscription.SubscriptionName)</td>
<td>$($outOfScopeSubscription.SubscriptionId)</td>
<td>$($outOfScopeSubscription.outOfScopeReason)</td>
<td><a href="#hierarchy_$($outOfScopeSubscription.ManagementGroupId)"><i class="fa fa-eye" aria-hidden="true"></i></a> $($outOfScopeSubscription.ManagementGroupName) ($($outOfScopeSubscription.ManagementGroupId))</td>
</tr>
"@ 
    }
$htmlTenantSummary += $htmlSUMMARYOutOfScopeSubscriptions
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
            
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@  
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg"> <span class="valignMiddle">$outOfScopeSubscriptionsCount Subscriptions out-of-scope</span></p>
"@
}
#endregion SUMMARYOutOfScopeSubscriptions


#region SUMMARYResources
Write-Host "  processing Summary Subscriptions Resources"
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
        $tfCount = ($resourcesAllSummarized | measure-object).count
        $tableId = "SummaryTable_resources"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_resources"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$resourcesResourceTypeCount ResourceTypes ($resourcesTotal Resources) in $resourcesLocationCount Locations ($scopeNamingSummary)</span>
</button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>ResourceType</th>
<th>Location</th>
<th>Resource Count</th>
</tr>
</thead>
<tbody>
"@
        $htmlSUMMARYResources = $null
        foreach ($resourceAllSummarized in $resourcesAllSummarized){
$htmlSUMMARYResources += @"
<tr>
<td>$($resourceAllSummarized.type)</td>
<td>$($resourceAllSummarized.location)</td>
<td>$($resourceAllSummarized.count_)</td>
</tr>
"@        
        }
$htmlTenantSummary += $htmlSUMMARYResources
$htmlTenantSummary += @"
        </tbody>
    </table>
</div>
<script>
    var tfConfig4$tableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@  
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'number'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$tableId', tfConfig4$tableId);
    tf.init();
</script>
"@
    }
    else{
$htmlTenantSummary += @"
        <p><i class="fa fa-ban" aria-hidden="true"></i> $resourcesResourceTypeCount ResourceTypes</p>
"@
    }

}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> 0 ResourceTypes</p>
"@
}
#endregion SUMMARYResources

#region SUMMARYResourcesDiagnosticsCapable
Write-Host "  processing Summary Subscriptions Resources Diagnostics Capable"
$resourceTypesDiagnosticsArraySorted = $resourceTypesDiagnosticsArray | Sort-Object -Property ResourceType, ResourceCount, Metrics, Logs, LogCategories
$resourceTypesDiagnosticsArraySortedCount = ($resourceTypesDiagnosticsArraySorted | measure-object).count
$resourceTypesDiagnosticsMetricsTrueCount = ($resourceTypesDiagnosticsArray | Where-Object { $_.Metrics -eq $True } | Measure-Object).count
$resourceTypesDiagnosticsLogsTrueCount = ($resourceTypesDiagnosticsArray | Where-Object { $_.Logs -eq $True } | Measure-Object).count
$resourceTypesDiagnosticsMetricsLogsTrueCount = ($resourceTypesDiagnosticsArray | Where-Object { $_.Metrics -eq $True -or $_.Logs -eq $True } | Measure-Object).count
if ($resourceTypesDiagnosticsArraySortedCount -gt 0){
    $tfCount = $resourceTypesDiagnosticsArraySortedCount
    $tableId = "SummaryTable_ResourcesDiagnosticsCapable"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_ResourcesDiagnosticsCapable"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$resourceTypesDiagnosticsMetricsLogsTrueCount/$resourceTypesDiagnosticsArraySortedCount ResourceTypes Diagnostics capable ($resourceTypesDiagnosticsMetricsTrueCount Metrics, $resourceTypesDiagnosticsLogsTrueCount Logs)</span></button>
<div class="content">
&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true" style="color:#FFB100;"></i> <b>Create Custom Policies for Azure ResourceTypes that support Diagnostics Logs and Metrics</b> <a class="externallink" href="https://github.com/JimGBritt/AzurePolicy/blob/master/AzureMonitor/Scripts/README.md#overview-of-create-azdiagpolicyps1" target="_blank">Create-AzDiagPolicy</a><br>
&nbsp;<i class="fa fa-windows" aria-hidden="true" style="color:#00a2ed;"></i> <b>Supported categories for Azure Resource Logs</b> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-monitor/platform/resource-logs-categories" target="_blank">Microsoft Docs</a>
<table id= "$tableId" class="summaryTable">
<thead>
<tr>
<th>ResourceType</th>
<th>Resource Count</th>
<th>Diagnostics capable</th>
<th>Metrics</th>
<th>Logs</th>
<th>LogCategories</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYResourcesDiagnosticsCapable = $null
    foreach ($resourceType in $resourceTypesDiagnosticsArraySorted){
        if ($resourceType.Metrics -eq $true -or $resourceType.Logs -eq $true){
            $diagnosticsCapable = $true
        }
        else{
            $diagnosticsCapable = $false
        }
$htmlSUMMARYResourcesDiagnosticsCapable += @"
<tr>
<td>$($resourceType.ResourceType)</td>
<td>$($resourceType.ResourceCount)</td>
<td>$diagnosticsCapable</td>
<td>$($resourceType.Metrics)</td>
<td>$($resourceType.Logs)</td>
<td>$($resourceType.LogCategories -join "$CsvDelimiterOpposite ")</td>
</tr>
"@
    }
$htmlTenantSummary += $htmlSUMMARYResourcesDiagnosticsCapable
$htmlTenantSummary += @"
        </tbody>
    </table>
</div>
<script>
    var tfConfig4$tableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@  
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_2: 'select',
        col_3: 'select',
        col_4: 'select',
        col_types: [
            'caseinsensitivestring',
            'number',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$tableId', tfConfig4$tableId);
    tf.init();
</script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($resourceTypesDiagnosticsMetricsLogsTrueCount | measure-object).count) Management Groups approaching Limit for PolicyAssignment</span></p>
"@
}
#endregion SUMMARYResourcesDiagnosticsCapable

<#EXPERIMENTAL
#region SUMMARYDiagnosticsPolicyLifecycle

Write-Host "  processing Summary Subscriptions Diagnostics Policy Lifecycle"
$startsumDiagLifecycle = get-date

if ($tenantCustomPoliciesCount -gt 0) {
    $policiesThatDefineDiagnosticsCount = ($tenantCustomPolicies | Where-Object {
        ($htCacheDefinitions).policy.($_).Type -eq "custom" -and
        ($htCacheDefinitions).policy.($_).json.properties.policyrule.then.details.type -eq "Microsoft.Insights/diagnosticSettings" -and
        ($htCacheDefinitions).policy.($_).json.properties.policyrule.then.details.deployment.properties.template.resources.type -match "/providers/diagnosticSettings"
    } | Measure-Object).count
    if ($policiesThatDefineDiagnosticsCount -gt 0){
        $diagnosticsPolicyAnalysis = @()
        $diagnosticsPolicyAnalysis += foreach ($policy in $tenantCustomPolicies | Where-Object {
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
                        $actionItems += foreach ($supportedLogCategory in $supportedLogs.LogCategories) {
                            if (-not $diagnosticsLogCategoriesCoveredByPolicy.category.contains($supportedLogCategory)) {
                                $supportedLogCategory
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
                            $policyUsedinPolicySetsArray += foreach ($policySetsWherePolicyIsUsed in $policyUsedinPolicySets) {
                                "[$policySetsWherePolicyIsUsed ($(($htCacheDefinitions).policySet.($policySetsWherePolicyIsUsed).DisplayName))]"

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

                    [PSCustomObject]@{
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
                    #$diagnosticsPolicyAnalysis += $object
                } 
            }
            else {
                write-host "DiagnosticsLifeCycle: something unexpected - not EH, LA, SA"
            }
        }

        #where no Policy exists
        $diagnosticsPolicyAnalysis += foreach ($resourceTypeDiagnosticsCapable in $resourceTypesDiagnosticsArray | Where-Object { $_.Logs -eq $true }) {
            if (-not($diagnosticsPolicyAnalysis.ResourceType).ToLower().Contains( ($resourceTypeDiagnosticsCapable.ResourceType).ToLower() )) {
                $supportedLogs = ($resourceTypesDiagnosticsArray | where-object { $_.ResourceType -eq $resourceTypeDiagnosticsCapable.ResourceType }).LogCategories
                $logsSupported = "yes"
                $resourceTypeCountFromResourceTypesSummarizedArray = ($resourceTypesSummarizedArray | Where-Object { $_.ResourceType -eq $resourceTypeDiagnosticsCapable.ResourceType }).ResourceCount
                $recommendation = "Create and assign a diagnostics policy for this ResourceType"
                [PSCustomObject]@{
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
                #$diagnosticsPolicyAnalysis += $object
            }
        }
        $diagnosticsPolicyAnalysisCount = ($diagnosticsPolicyAnalysis | Measure-Object).count
    
if ($diagnosticsPolicyAnalysisCount -gt 0){
    $tfCount = $diagnosticsPolicyAnalysisCount
    
    $tableId = "SummaryTable_DiagnosticsLifecycle"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="Summary_DiagnosticsLifecycle"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">ResourceDiagnostics Policy Lifecycle recommendations</span></button>
<div class="content">
&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true" style="color:#FFB100;"></i> <b>Create Custom Policies for Azure ResourceTypes that support Diagnostics Logs and Metrics</b> <a class="externallink" href="https://github.com/JimGBritt/AzurePolicy/blob/master/AzureMonitor/Scripts/README.md#overview-of-create-azdiagpolicyps1" target="_blank">Create-AzDiagPolicy</a>
<table id= "$tableId" class="summaryTable">
<thead>
<tr>
<th>Priority</th>
<th>Recommendation</th>
<th>ResourceType</th>
<th>Resource Count</th>
<th>Diagnostics capable</th>
<th>PolicyId</th>
<th>Policy Name</th>
<th>Policy deploys RoleDefinitionIds</th>              
<th>Target</th>
<th>Log Categories not covered by Policy</th>
<th>Policy Assignments</th>
<th>Policy used in PolicySet</th>
<th>PolicySet Assignments</th>
</tr>
</thead>
<tbody>
"@
    foreach ($diagnosticsFinding in $diagnosticsPolicyAnalysis | Sort-Object -property Priority, Recommendation, ResourceType, PolicyName){

$htmlTenantSummary += @"
            <tr>
                <td>
                    $($diagnosticsFinding.Priority)
                </td>
                <td>
                    $($diagnosticsFinding.Recommendation)
                </td>
                <td>
                    <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-monitor/platform/resource-logs-categories#$(($diagnosticsFinding.ResourceType -replace '\.','' -replace '/','').ToLower())" target="_blank">$($diagnosticsFinding.ResourceType)</a>
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
$htmlTenantSummary += @"
        </tbody>
    </table>
</div>
<script>
    var tfConfig4$tableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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

$htmlTenantSummary += @"
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
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
        col_types: [
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'number',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'caseinsensitivestring',
            'number',
            'number',
            'number'
        ],
extensions: [{ name: 'sort' }]
    };
    var tf = new TableFilter('$tableId', tfConfig4$tableId);
    tf.init();
</script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No ResourceDiagnostics Policy Lifecycle recommendations</span></p>
"@
}
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No ResourceDiagnostics Policy Lifecycle recommendations</span></p>
"@
}
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No ResourceDiagnostics Policy Lifecycle recommendations</span></p>
"@
}
$endsumDiagLifecycle = get-date
Write-Host "   LifeCycle processing duration: $((NEW-TIMESPAN -Start $startsumDiagLifecycle -End $endsumDiagLifecycle).TotalSeconds) seconds"
#endregion SUMMARYDiagnosticsPolicyLifecycle
#>


#region SUMMARYSubResourceProviders
Write-Host "  processing Summary Subscriptions Resource Providers"
$resourceProvidersAllCount = ($htResourceProvidersAll.Keys | Measure-Object).count
if ($resourceProvidersAllCount  -gt 0){
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
    $providerSummary += foreach ($provider in $htResProvSummary.keys){
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

        [PSCustomObject]@{'Provider' = $provider; 'Registered'= $registered; 'NotRegistered'= $notregistered; 'Registering'= $registering; 'Unregistering'= $unregistering }
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
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_SubResourceProviders"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Providers Total: $uniqueNamespacesCount Registered/Registering: $providersRegisteredCount NotRegistered/Unregistering: $providersNotRegisteredUniqueCount</span></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Provider</th>
<th>Registered</th>
<th>Registering</th>
<th>NotRegistered</th>
<th>Unregistering</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYSubResourceProviders = $null
    foreach ($provider in ($providerSummary | Sort-Object -Property Provider)){
$htmlSUMMARYSubResourceProviders += @"
<tr>
<td>$($provider.Provider)</td>
<td>$($provider.Registered)</td>
<td>$($provider.Registering)</td>
<td>$($provider.NotRegistered)</td>
<td>$($provider.Unregistering)</td>
</tr>
"@ 
    }
$htmlTenantSummary += $htmlSUMMARYSubResourceProviders
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,      
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'number',
                'number',
                'number',
                'number'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$resourceProvidersAllCount Resource Providers</span></p>
"@
}
#endregion SUMMARYSubResourceProviders

#region SUMMARYSubResourceProvidersDetailed
if (-not $NoResourceProvidersDetailed){

Write-Host "  processing Summary Subscriptions Resource Providers detailed"
$startsumRPDetailed = get-date
$resourceProvidersAllCount = ($htResourceProvidersAll.Keys | Measure-Object).count
if ($resourceProvidersAllCount -gt 0){
    $tfCount = ($arrayResourceProvidersAll | Measure-Object).Count
    $tableId = "SummaryTable_SubResourceProvidersDetailed"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_SubResourceProvidersDetailed"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Providers Detailed</span></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Mg Name</th>
<th>MgId</th>
<th>Subscription Name</th>
<th>SubscriptionId</th>
<th>Provider</th>
<th>State</th>
</tr>
</thead>
<tbody>
"@
    $cnter = 0
    $startResProvDetailed = get-date
    $htmlSUMMARYSubResourceProvidersDetailed = $null
    foreach ($subscriptionResProv in ($htResourceProvidersAll.Keys | sort-object)){
        $subscriptionResProvDetails = $mgAndSubBaseQuery | Where-Object { $_.SubscriptionId -eq $subscriptionResProv} | sort-object -Property SubscriptionId -Unique
        foreach ($provider in ($htResourceProvidersAll).($subscriptionResProv).Providers | sort-object @{Expression={$_.namespace}}){
            $cnter++
            if ($cnter % 500  -eq 0){
                $etappeResProvDetailed = get-date
                write-host "   $cnter ResProv processed; $((NEW-TIMESPAN -Start $startResProvDetailed -End $etappeResProvDetailed).TotalSeconds) seconds"  
            }
$htmlSUMMARYSubResourceProvidersDetailed += @"
<tr>
<td>$($subscriptionResProvDetails.MgId)</td>
<td>$($subscriptionResProvDetails.MgName)</td>
<td>$($subscriptionResProvDetails.Subscription)</td>
<td>$($subscriptionResProv)</td>
<td>$($provider.namespace)</td>
<td>$($provider.registrationState)</td>
</tr>
"@ 
        }
    }
$htmlTenantSummary += $htmlSUMMARYSubResourceProvidersDetailed
$htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
            
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@ 
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_5: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$resourceProvidersAllCount Resource Providers</span></p>
"@
}
$endsumRPDetailed = get-date
Write-Host "   RP detailed processing duration: $((NEW-TIMESPAN -Start $startsumRPDetailed -End $endsumRPDetailed).TotalMinutes) minutes"
#endregion SUMMARYSubResourceProvidersDetailed
}

#region SUMMARYSubsapproachingLimitsResourceGroups
Write-Host "  processing Summary Subscriptions Limit Resource Groups"
$subscriptionsApproachingLimitFromResourceGroupsAll = $resourceGroupsAll | where-object { $_.count_ -gt ($LimitResourceGroups * ($LimitCriticalPercentage / 100)) }
if (($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count -gt 0){
    $tfCount = ($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count
    $tableId = "SummaryTable_SubsapproachingLimitsResourceGroups"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsResourceGroups"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count) Subscriptions approaching Limit for ResourceGroups</span></button>
<div class="content">
<table id= "$tableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYSubsapproachingLimitsResourceGroups = $null
    foreach ($subscriptionApproachingLimitFromResourceGroupsAll in $subscriptionsApproachingLimitFromResourceGroupsAll){
        $subscriptionData = $mgAndSubBaseQuery | Where-Object { $_.SubscriptionId -eq $subscriptionApproachingLimitFromResourceGroupsAll.subscriptionId } | Get-Unique
$htmlSUMMARYSubsapproachingLimitsResourceGroups += @"
<tr>
<td><span class="valignMiddle">$($subscriptionData.subscription)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionData.MgId)">$($subscriptionData.subscriptionId)</a></span></td>
<td>$($subscriptionApproachingLimitFromResourceGroupsAll.count_)/$($LimitResourceGroups)</td>
</tr>
"@
    }
$htmlTenantSummary += $htmlSUMMARYSubsapproachingLimitsResourceGroups
$htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@  
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p"><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count) Subscriptions approaching Limit for ResourceGroups</span></p>
"@
}
#endregion SUMMARYSubsapproachingLimitsResourceGroups

#region SUMMARYSubsapproachingLimitsSubscriptionTags
Write-Host "  processing Summary Subscriptions Limit Subscription Tags"
$subscriptionsApproachingLimitTags = ($subscriptionBaseQuery | Select-Object -Property MgId, Subscription, SubscriptionId, SubscriptionTagsCount, SubscriptionTagsLimit -Unique | where-object { (($_.SubscriptionTagsCount -gt ($_.SubscriptionTagsLimit * ($LimitCriticalPercentage / 100)))) })
if (($subscriptionsApproachingLimitTags | measure-object).count -gt 0){
    $tfCount = ($subscriptionsApproachingLimitTags | measure-object).count
    $tableId = "SummaryTable_SubsapproachingLimitsSubscriptionTags"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsSubscriptionTags"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitTags | measure-object).count) Subscriptions approaching Limit for Tags</span></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYSubsapproachingLimitsSubscriptionTags = $null
    foreach ($subscriptionApproachingLimitTags in $subscriptionsApproachingLimitTags){
$htmlSUMMARYSubsapproachingLimitsSubscriptionTags += @"
<tr>
<td><span class="valignMiddle">$($subscriptionApproachingLimitTags.subscription)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingLimitTags.MgId)">$($subscriptionApproachingLimitTags.subscriptionId)</a></span></td>
<td>$($subscriptionApproachingLimitTags.SubscriptionTagsCount)/$($subscriptionApproachingLimitTags.SubscriptionTagsLimit)</td>
</tr>
"@
    }
$htmlTenantSummary += $htmlSUMMARYSubsapproachingLimitsSubscriptionTags
$htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@   
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$($subscriptionsApproachingLimitTags.count) Subscriptions approaching Limit for Tags</span></p>
"@
}
#endregion SUMMARYSubsapproachingLimitsSubscriptionTags

#region SUMMARYSubsapproachingLimitsPolicyAssignments
Write-Host "  processing Summary Subscriptions Limit PolicyAssignments"
$subscriptionsApproachingLimitPolicyAssignments =(($policyBaseQuery | where-object { "" -ne $_.SubscriptionId -and $_.PolicyAndPolicySetAssigmentAtScopeCount -gt 0 -and  (($_.PolicyAndPolicySetAssigmentAtScopeCount -gt ($_.PolicyAssigmentLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, Subscription, SubscriptionId, PolicyAssigmentAtScopeCount, PolicySetAssigmentAtScopeCount, PolicyAndPolicySetAssigmentAtScopeCount, PolicyAssigmentLimit -Unique)
if ($subscriptionsApproachingLimitPolicyAssignments.count -gt 0){
    $tfCount = ($subscriptionsApproachingLimitPolicyAssignments | measure-object).count
    $tableId = "SummaryTable_SubsapproachingLimitsPolicyAssignments"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsPolicyAssignments"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyAssignments | measure-object).count) Subscriptions approaching Limit for PolicyAssignment</span></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYSubsapproachingLimitsPolicyAssignments = $null
    foreach ($subscriptionApproachingLimitPolicyAssignments in $subscriptionsApproachingLimitPolicyAssignments){
$htmlSUMMARYSubsapproachingLimitsPolicyAssignments += @"
<tr>
<td><span class="valignMiddle">$($subscriptionApproachingLimitPolicyAssignments.subscription)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingLimitPolicyAssignments.MgId)">$($subscriptionApproachingLimitPolicyAssignments.subscriptionId)</a></span></td>
<td>$($subscriptionApproachingLimitPolicyAssignments.PolicyAndPolicySetAssigmentAtScopeCount)/$($subscriptionApproachingLimitPolicyAssignments.PolicyAssigmentLimit) ($($subscriptionApproachingLimitPolicyAssignments.PolicyAssigmentAtScopeCount) Policy Assignments, $($subscriptionApproachingLimitPolicyAssignments.PolicySetAssigmentAtScopeCount) PolicySet Assignments)</td>
</tr>
"@
    }
$htmlTenantSummary += $htmlSUMMARYSubsapproachingLimitsPolicyAssignments
$htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@    
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyAssignments | measure-object).count) Subscriptions approaching Limit for PolicyAssignment</span></p>
"@
}
#endregion SUMMARYSubsapproachingLimitsPolicyAssignments

#region SUMMARYSubsapproachingLimitsPolicyScope
Write-Host "  processing Summary Subscriptions Limit PolicyScope"
$subscriptionsApproachingLimitPolicyScope = (($policyBaseQuery | where-object { "" -ne $_.SubscriptionId -and $_.PolicyDefinitionsScopedCount -gt 0 -and  (($_.PolicyDefinitionsScopedCount -gt ($_.PolicyDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, Subscription, SubscriptionId, PolicyDefinitionsScopedCount, PolicyDefinitionsScopedLimit -Unique)
if (($subscriptionsApproachingLimitPolicyScope | measure-object).count -gt 0){
    $tfCount = ($subscriptionsApproachingLimitPolicyScope | measure-object).count
    $tableId = "SummaryTable_SubsapproachingLimitsPolicyScope"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsPolicyScope"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyScope | measure-object).count) Subscriptions approaching Limit for Policy Scope</span></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYSubsapproachingLimitsPolicyScope = $null
    foreach ($subscriptionApproachingLimitPolicyScope in $subscriptionsApproachingLimitPolicyScope){
$htmlSUMMARYSubsapproachingLimitsPolicyScope += @"
<tr>
<td><span class="valignMiddle">$($subscriptionApproachingLimitPolicyScope.subscription)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingLimitPolicyScope.MgId)">$($subscriptionApproachingLimitPolicyScope.subscriptionId)</a></span></td>
<td>$($subscriptionApproachingLimitPolicyScope.PolicyDefinitionsScopedCount)/$($subscriptionApproachingLimitPolicyScope.PolicyDefinitionsScopedLimit)</td>
</tr>
"@
    }
$htmlTenantSummary += $htmlSUMMARYSubsapproachingLimitsPolicyScope
$htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$($subscriptionsApproachingLimitPolicyScope.count) Subscriptions approaching Limit for Policy Scope</span></p>
"@
}
#endregion SUMMARYSubsapproachingLimitsPolicyScope

#region SUMMARYSubsapproachingLimitsPolicySetScope
Write-Host "  processing Summary Subscriptions Limit PolicySetScope"
$subscriptionsApproachingLimitPolicySetScope = (($policyBaseQuery | where-object { "" -ne $_.SubscriptionId -and $_.PolicySetDefinitionsScopedCount -gt 0 -and  (($_.PolicySetDefinitionsScopedCount -gt ($_.PolicySetDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, Subscription, SubscriptionId, PolicySetDefinitionsScopedCount, PolicySetDefinitionsScopedLimit -Unique)
if ($subscriptionsApproachingLimitPolicySetScope.count -gt 0){
    $tfCount = ($subscriptionsApproachingLimitPolicySetScope | measure-object).count
    $tableId = "SummaryTable_SubsapproachingLimitsPolicySetScope"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsPolicySetScope"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyScope | measure-object).count) Subscriptions approaching Limit for PolicySet Scope</span></button>
<div class="content">
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYSubsapproachingLimitsPolicySetScope = $null
    foreach ($subscriptionApproachingLimitPolicySetScope in $subscriptionsApproachingLimitPolicySetScope){
$htmlSUMMARYSubsapproachingLimitsPolicySetScope += @"
<tr>
<td><span class="valignMiddle">$($subscriptionApproachingLimitPolicySetScope.subscription)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingLimitPolicySetScope.MgId)">$($subscriptionApproachingLimitPolicySetScope.subscriptionId)</a></span></td>
<td>$($subscriptionApproachingLimitPolicySetScope.PolicySetDefinitionsScopedCount)/$($subscriptionApproachingLimitPolicySetScope.PolicySetDefinitionsScopedLimit)</td>
</tr>
"@
    }
$htmlTenantSummary += $htmlSUMMARYSubsapproachingLimitsPolicySetScope
$htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@      
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
$htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyScope | measure-object).count) Subscriptions approaching Limit for PolicySet Scope</span></p>
"@
}
#endregion SUMMARYSubsapproachingLimitsPolicySetScope

#region SUMMARYSubsapproachingLimitsRoleAssignment
Write-Host "  processing Summary Subscriptions Limit RoleAssignments"
$subscriptionsApproachingRoleAssignmentLimit = $rbacBaseQuery | Where-Object { "" -ne $_.SubscriptionId -and $_.RoleAssignmentsCount -gt ($_.RoleAssignmentsLimit * $LimitCriticalPercentage / 100)} | Sort-Object -Property SubscriptionId -Unique | select-object -Property MgId, SubscriptionId, Subscription, RoleAssignmentsCount, RoleAssignmentsLimit
if (($subscriptionsApproachingRoleAssignmentLimit | measure-object).count -gt 0){
    $tfCount = ($subscriptionsApproachingRoleAssignmentLimit | measure-object).count
    $tableId = "SummaryTable_SubsapproachingLimitsRoleAssignment"
$htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsRoleAssignment"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingRoleAssignmentLimit | measure-object).count) Subscriptions approaching Limit for RoleAssignment</span></button>
<div class="content">
<table id= "$tableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>Limit</th>
</tr>
</thead>
<tbody>
"@
    $htmlSUMMARYSubsapproachingLimitsRoleAssignment = $null
    foreach ($subscriptionApproachingRoleAssignmentLimit in $subscriptionsApproachingRoleAssignmentLimit){
$htmlSUMMARYSubsapproachingLimitsRoleAssignment += @"
<tr>
<td><span class="valignMiddle">$($subscriptionApproachingRoleAssignmentLimit.subscription)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingRoleAssignmentLimit.MgId)">$($subscriptionApproachingRoleAssignmentLimit.subscriptionId)</a></span></td>
<td>$($subscriptionApproachingRoleAssignmentLimit.RoleAssignmentsCount)/$($subscriptionApproachingRoleAssignmentLimit.RoleAssignmentsLimit)</td>
</tr>
"@
    }
$htmlTenantSummary += $htmlSUMMARYSubsapproachingLimitsRoleAssignment
$htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
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
$htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@  
}
$htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
}
else{
    $htmlTenantSummary += @"
    <p"><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingRoleAssignmentLimit | measure-object).count) Subscriptions approaching Limit for RoleAssignment</span></p>
"@
}
#endregion SUMMARYSubsapproachingLimitsRoleAssignment

$script:html += $htmlTenantSummary
$htmlTenantSummary = $null
$script:html | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
$script:html = $null

}
#endregion Summary

#MD
function diagramMermaid() {
    $mgLevels = ($mgAndSubBaseQuery | Sort-Object -Property Level -Unique).Level
    foreach ($mgLevel in $mgLevels){
        $mgsInLevel = ($mgAndSubBaseQuery | Where-Object { $_.Level -eq $mgLevel}).MgId | Get-Unique
        $script:arrayMgs += foreach ($mgInLevel in $mgsInLevel){ 
            $mgDetails = ($mgAndSubBaseQuery | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel })
            $mgName = $mgDetails.MgName | Get-Unique
            $mgParentId = $mgDetails.mgParentId | Get-Unique
            $mgParentName = $mgDetails.mgParentName | Get-Unique
            if ($mgInLevel -ne $getMgParentId){
                $mgInLevel
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
            $subsUnderMg = ($mgAndSubBaseQuery | Where-Object { $_.Level -eq $mgLevel -and "" -ne $_.Subscription -and $_.MgId -eq $mgInLevel }).SubscriptionId | Get-Unique
            if (($subsUnderMg | measure-object).count -gt 0){
                $script:arraySubs += foreach ($subUnderMg in $subsUnderMg){
                    "SubsOf$mgInLevel"
                    $mgDetalsN = ($mgAndSubBaseQuery | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel })
                    $mgName = $mgDetalsN.MgName | Get-Unique
                    $mgParentId = $mgDetalsN.MgParentId | Get-Unique
                    $mgParentName = $mgDetalsN.MgParentName | Get-Unique
                    $subName = ($mgAndSubBaseQuery | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel -and $_.SubscriptionId -eq $subUnderMg }).Subscription | Get-Unique
$script:markdownTable += @"
| $mgLevel | $mgName | $mgInLevel | $mgParentName | $mgParentId | $subName | $($subUnderMg -replace '.*/') |`n
"@
                }
                $mgName = ($mgAndSubBaseQuery | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgName | Get-Unique
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
                $mgDetailsM = ($table | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel })
                $mgName = $mgDetailsM.MgName | Get-Unique
                $mgParentId = $mgDetailsM.MgParentId | Get-Unique
                $mgParentName = $mgDetailsM.MgParentName | Get-Unique
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
    
    $tryCounter = 0
    do {
        $result = "letscheck"
        $tryCounter++
        try {
            $tenantDetailsResult = Invoke-RestMethod -Uri $uriTenantDetails -Method Get -Headers @{"Authorization" = "Bearer $accesstoken" }
        }
        catch {
            $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
        }
        if ($result -ne "letscheck"){
            $result
            if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                Write-Host "Getting Tenant Details: try #$tryCounter; returned: '$result' - try again"
                $result = "tryAgain"
                Start-Sleep -Milliseconds 250
            }
        }
    }
    until($result -ne "tryAgain")

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

if (-not $HierarchyMapOnly) {
    Write-Host "Run Info:"
    Write-Host " Creating HierarchyMap, TenantSummary and ScopeInsights - use parameter -HierarchyMapOnly to only create the HierarchyMap"

    if ($SubscriptionQuotaIdWhitelist -ne "undefined" -and $SubscriptionQuotaIdWhitelist -ne ""){
        $subscriptionQuotaIdWhitelistArray = [Array]($SubscriptionQuotaIdWhitelist).tostring().split("\")
        if (($subscriptionQuotaIdWhitelistArray | Measure-Object).count -gt 0){
            Write-Host " Subscription Whitelist enabled. AzGovViz will only process Subscriptions where QuotaId startswith one of the following strings:"
            Write-Host "$($subscriptionQuotaIdWhitelistArray -join ", ")"
            $subscriptionQuotaIdWhitelistMode = $true
        }
        else{
            Write-Host " Subscription Whitelist enabled. Error: invalid Parameter Value for 'SubscriptionQuotaIdWhitelist'"
            break
        }
    }
    else{
        Write-Host " Subscription Whitelist disabled - use parameter -SubscriptionQuotaIdWhitelist to whitelist QuotaIds"
        $subscriptionQuotaIdWhitelistMode = $false
    }

    if ($NoASCSecureScore){
        Write-Host " ASC Secure Score for Subscriptions disabled"
    }
    else{
        Write-Host " ASC Secure Score for Subscriptions enabled - use parameter -NoASCSecureScore to disable"
    }

    if ($NoResourceProvidersDetailed){
        Write-Host " ResourceProvider Detailed for TenantSummary disabled"
    }
    else{
        Write-Host " ResourceProvider Detailed for TenantSummary enabled - use parameter -NoResourceProvidersDetailed to disable"
    }

    if ($DoNotShowRoleAssignmentsUserData){
        Write-Host " Scrub Identity information for identityType='User' enabled"
    }
    else{
        Write-Host " Scrub Identity information for identityType='User' disabled - use parameter -DoNotShowRoleAssignmentsUserData to scrub information such as displayName and signInName (email) for identityType='User'"
    }

    if ($LimitCriticalPercentage -eq 80){
        Write-Host " ARM Limits warning set to 80% (default) - use parameter -LimitCriticalPercentage to set warning level accordingly"
    }
    else{
        Write-Host " ARM Limits warning set to $($LimitCriticalPercentage)% (custom)"
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
    $arrayPoliciesUsedInPolicySets = @()
    $htSubscriptionTags = @{ }
    $htCacheAssignments = @{ }
    ($htCacheAssignments).policy = @{ }
    $htCacheAssignmentsResourceGroups = @{ }
    ($htCacheAssignmentsResourceGroups).policy = @{ }
    $script:arrayCachePolicyAssignmentsResourceGroups = @()
    $script:arrayCacheRoleAssignmentsResourceGroups = @()
    ($htCacheAssignments).role = @{ }
    ($htCacheAssignments).blueprint = @{ }
    $htCachePolicyCompliance = @{ }
    ($htCachePolicyCompliance).mg = @{ }
    ($htCachePolicyCompliance).sub = @{ }
    $script:outOfScopeSubscriptions = [System.Collections.ArrayList]@()

    $currentContextSubscriptionQuotaId = (Search-AzGraph -ErrorAction SilentlyContinue -Subscription $checkContext.Subscription.Id -Query "resourcecontainers | where type == 'microsoft.resources/subscriptions' | project properties.subscriptionPolicies.quotaId").properties_subscriptionPolicies_quotaId
    if (-not $currentContextSubscriptionQuotaId){
        Write-Host "Bad Subscription context for Definition Caching (SubscriptionName: $($checkContext.Subscription.Name); SubscriptionId: $($checkContext.Subscription.Id); likely an AAD_ QuotaId"
        $alternativeSubscriptionIdForDefinitionCaching = (Search-AzGraph -Query "resourcecontainers | where type == 'microsoft.resources/subscriptions' | where properties.subscriptionPolicies.quotaId !startswith 'AAD_' | project properties.subscriptionPolicies.quotaId, subscriptionId" -first 1)
        Write-Host "Using other Subscription for Definition Caching (SubscriptionId: $($alternativeSubscriptionIdForDefinitionCaching.subscriptionId); QuotaId: $($alternativeSubscriptionIdForDefinitionCaching.properties_subscriptionPolicies_quotaId))"
        $subscriptionIdForDefinitionCaching = $alternativeSubscriptionIdForDefinitionCaching.subscriptionId
        Select-AzSubscription -SubscriptionId $subscriptionIdForDefinitionCaching -ErrorAction Stop
    }
    else{
        Write-Host "OK Subscription context (QuotaId not 'AAD_*') for Definition Caching (SubscriptionId: $($checkContext.Subscription.Id); QuotaId: $currentContextSubscriptionQuotaId)"
        $subscriptionIdForDefinitionCaching = $checkContext.Subscription.Id
    }

    $uriPolicyDefinitionAPI = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"

    $tryCounter = 0
    do {
        $result = "letscheck"
        $tryCounter++
        try {
            $requestPolicyDefinitionAPI = Invoke-RestMethod -Uri $uriPolicyDefinitionAPI -Headers  @{"Authorization" = "Bearer $accesstoken" }
        }
        catch {
            $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
        }
        if ($result -ne "letscheck"){
            $result
            if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                Write-Host "Getting BuiltIn Policy Definitions: try #$tryCounter; returned: '$result' - try again"
                $result = "tryAgain"
                Start-Sleep -Milliseconds 250
            }
        }
    }
    until($result -ne "tryAgain")

    $builtinPolicyDefinitions = $requestPolicyDefinitionAPI.value | Where-Object { $_.properties.policyType -eq "builtin" }

    foreach ($builtinPolicyDefinition in $builtinPolicyDefinitions) {
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id) = @{ }
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).Id = $builtinPolicyDefinition.id
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).DisplayName = $builtinPolicyDefinition.Properties.displayname
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).Type = $builtinPolicyDefinition.Properties.policyType
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).Category = $builtinPolicyDefinition.Properties.metadata.category
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).PolicyDefinitionId = $builtinPolicyDefinition.id
        if ($builtinPolicyDefinition.Properties.metadata.deprecated -eq $true){
            ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).Deprecated = $builtinPolicyDefinition.Properties.metadata.deprecated
        }
        else{
            ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).Deprecated = $false
        }
        #effects
        if ($builtinPolicyDefinition.properties.parameters.effect.defaultvalue) {
            ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).effectDefaultValue = $builtinPolicyDefinition.properties.parameters.effect.defaultvalue
            if ($builtinPolicyDefinition.properties.parameters.effect.allowedValues){
                ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).effectAllowedValue = $builtinPolicyDefinition.properties.parameters.effect.allowedValues -join ","
            }
            else{
                ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).effectAllowedValue = "n/a"
            }
            ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).effectFixedValue = "n/a"
        }
        else {
            if ($builtinPolicyDefinition.properties.parameters.policyEffect.defaultValue) {
                ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).effectDefaultValue = $builtinPolicyDefinition.properties.parameters.policyEffect.defaultvalue
                if ($builtinPolicyDefinition.properties.parameters.policyEffect.allowedValues){
                    ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).effectAllowedValue = $builtinPolicyDefinition.properties.parameters.policyEffect.allowedValues -join ","
                }
                else{
                    ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).effectAllowedValue = "n/a"
                }
                ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).effectFixedValue = "n/a"
            }
            else {
                ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).effectFixedValue = $builtinPolicyDefinition.Properties.policyRule.then.effect
                ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).effectDefaultValue = "n/a"
                ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).effectAllowedValue = "n/a"
            }
        }
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).json = $builtinPolicyDefinition

        #AsIs
        ($htCacheDefinitionsAsIs).policy.$($builtinPolicyDefinition.id) = @{ }
        ($htCacheDefinitionsAsIs).policy.$($builtinPolicyDefinition.id) = $builtinPolicyDefinition
    }

    $uriPolicySetDefinitionAPI = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"

    $tryCounter = 0
    do {
        $result = "letscheck"
        $tryCounter++
        try {
            $requestPolicySetDefinitionAPI = Invoke-RestMethod -Uri $uriPolicySetDefinitionAPI -Headers  @{"Authorization" = "Bearer $accesstoken" }
        }
        catch {
            $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
        }
        if ($result -ne "letscheck"){
            $result
            if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                Write-Host "Getting BuiltIn PolicySet Definitions: try #$tryCounter; returned: '$result' - try again"
                $result = "tryAgain"
                Start-Sleep -Milliseconds 250
            }
        }
    }
    until($result -ne "tryAgain")

    $builtinPolicySetDefinitions = $requestPolicySetDefinitionAPI.value | Where-Object { $_.properties.policyType -eq "builtin" }
    
    foreach ($builtinPolicySetDefinition in $builtinPolicySetDefinitions) {
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id) = @{ }
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).Id = $builtinPolicySetDefinition.id
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).DisplayName = $builtinPolicySetDefinition.Properties.displayname
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).Type = $builtinPolicySetDefinition.Properties.policyType
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).Category = $builtinPolicySetDefinition.Properties.metadata.category
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).PolicyDefinitionId = $builtinPolicySetDefinition.id
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).PolicySetPolicyIds = $builtinPolicySetDefinition.properties.policydefinitions.policyDefinitionId
        if ($builtinPolicySetDefinition.Properties.metadata.deprecated -eq $true){
            ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).Deprecated = $builtinPolicySetDefinition.Properties.metadata.deprecated
        }
        else{
            ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).Deprecated = $false
        }
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).json = $builtinPolicySetDefinition
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
    Write-Host "Caching built-in data duration: $((NEW-TIMESPAN -Start $startDefinitionsCaching -End $endDefinitionsCaching).TotalMinutes) minutes"
}

Write-Host "Collecting custom data"
$startDataCollection = get-date

dataCollection -mgId $ManagementGroupId -hierarchyLevel $hierarchyLevel -mgParentId $getMgParentId -mgParentName $getMgParentName

$endDataCollection = get-date
Write-Host "Collecting custom data duration: $((NEW-TIMESPAN -Start $startDataCollection -End $endDataCollection).TotalMinutes) minutes"

if (-not $HierarchyMapOnly){
    checkTokenLifetime
    Write-Host "Caching Resource data"
    $startResourceCaching = get-date
    $subscriptionIds = ($table | Where-Object { "" -ne $_.SubscriptionId} | select-Object SubscriptionId | Sort-Object -Property SubscriptionId -Unique).SubscriptionId
    $counter = [PSCustomObject] @{ Value = 0 }
    $batchSize = 1000
    $subscriptionsBatch = $subscriptionIds | Group-Object -Property { [math]::Floor($counter.Value++ / $batchSize) }
    #ARG queries
    #$queryResources = "resources | project id, subscriptionId, location, type | summarize count() by subscriptionId, location, type"
    #$queryResourceGroups = "resourcecontainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups' | project id, subscriptionId | summarize count() by subscriptionId"
    $resourcesAll = @()
    $resourceGroupsAll = @()
    $htResourceProvidersAll = @{ }
    $arrayResourceProvidersAll = @()
    Write-Host " Getting RescourceTypes and ResourceGroups and RescourceProviders"
    $startResourceProviders = get-date
    
    foreach ($subscriptionId in $subscriptionIds){
        checkTokenLifetime

        #alternative to ARG
        $uriResourcesPerSubscription = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($subscriptionId)/resources?api-version=2020-06-01"
        
        $tryCounter = 0
        do {
            $result = "letscheck"
            $tryCounter++
            try {
                $resourcesSubscriptionResult = Invoke-RestMethod -Uri $uriResourcesPerSubscription -Headers @{"Authorization" = "Bearer $accesstoken" }
            }
            catch {
                $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
            }
            if ($result -ne "letscheck"){
                $result
                if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                    Write-Host "  Getting ResourceTypes: try #$tryCounter; returned: '$result' - try again"
                    $result = "tryAgain"
                    Start-Sleep -Milliseconds 250
                }
            }
        }
        until($result -ne "tryAgain")
        
        $resourcesAll += foreach ($resourceTypeLocation in ($resourcesSubscriptionResult.value | Group-Object -Property type, location)){
            [PSCustomObject]@{'subscriptionId' = $subscriptionId; 'type' = ($resourceTypeLocation.values[0]).ToLower(); 'location' = ($resourceTypeLocation.values[1]).ToLower(); 'count_' = $resourceTypeLocation.Count }
        }

        #alternative to ARG
        #https://management.azure.com/subscriptions/{subscriptionId}/resourcegroups?api-version=2020-06-01
        $uriResourceGroupsPerSubscription = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($subscriptionId)/resourcegroups?api-version=2020-06-01"
        
        $tryCounter = 0
        do {
            $result = "letscheck"
            $tryCounter++
            try {
                $resourceGroupsSubscriptionResult = Invoke-RestMethod -Uri $uriResourceGroupsPerSubscription -Headers @{"Authorization" = "Bearer $accesstoken" }
            }
            catch {
                $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
            }
            if ($result -ne "letscheck"){
                $result
                if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                    Write-Host "  Getting ResourceGroups: try #$tryCounter; returned: '$result' - try again"
                    $result = "tryAgain"
                    Start-Sleep -Milliseconds 250
                }
            }
        }
        until($result -ne "tryAgain")
        
        $resourceGroupsAllSubscriptionObject = [PSCustomObject]@{'subscriptionId' = $subscriptionId; 'count_' = ($resourceGroupsSubscriptionResult.value | Measure-Object).count}
        $resourceGroupsAll += $resourceGroupsAllSubscriptionObject

        ($htResourceProvidersAll).($subscriptionId) = @{ }
        $uriResourceProviderSubscription = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($subscriptionId)/providers?api-version=2019-10-01"

        $tryCounter = 0
        do {
            $result = "letscheck"
            $tryCounter++
            try {
                $resProvResult = Invoke-RestMethod -Uri $uriResourceProviderSubscription -Headers @{"Authorization" = "Bearer $accesstoken" }
            }
            catch {
                $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
            }
            if ($result -ne "letscheck"){
                $result
                if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                    Write-Host "  Getting RescourceProviders: try #$tryCounter; returned: '$result' - try again"
                    $result = "tryAgain"
                    Start-Sleep -Milliseconds 250
                }
            }
        }
        until($result -ne "tryAgain")

        ($htResourceProvidersAll).($subscriptionId).Providers = $resProvResult.value
        $arrayResourceProvidersAll += $resProvResult.value
    }
    $endResourceProviders = get-date
    Write-Host " Getting Getting RescourceTypes and ResourceGroups and RescourceProviders duration: $((NEW-TIMESPAN -Start $startResourceProviders -End $endResourceProviders).TotalMinutes) minutes"
    
    <#
    Write-Host " Getting RescourceTypes and ResourceGroups"
    $startResourceTypesResourceGroups = get-date
    foreach ($batch in $subscriptionsBatch) {
        $resourcesAll += Search-AzGraph -Subscription $batch.Group -Query $queryResources -First 5000
        $resourceGroupsAll += Search-AzGraph -Subscription $batch.Group -Query $queryResourceGroups
    }
    #>

    <# ARG OLD
    $resourcesRetryCount = 0
    $resourcesRetrySeconds = 2
    $resourcesMoreThanZero = $false
    do {
        $resourcesRetryCount++
        
        #$gettingResourcesAll = Search-AzGraph -Subscription $subscriptionId -Query $queryResources -First 5000
        
        foreach ($batch in $subscriptionsBatch) {
            $gettingResourcesAll = Search-AzGraph -Subscription $batch.Group -Query $queryResources -First 5000
            
        }
        
        if (($gettingResourcesAll | Measure-Object).count -eq 0){
            Write-Host "really??! $(($gettingResourcesAll | Measure-Object).count) Resources, let´s check again (try: #$($resourcesRetryCount))"
            start-sleep -seconds $resourcesRetrySeconds
            $resourcesRetrySeconds++
        }
        else{
            Write-Host "$(($gettingResourcesAll | Measure-Object).count) Resources detected (try: #$($resourcesRetryCount))"
            $resourcesMoreThanZero = $true
        }
    }
    until($resourcesRetryCount -eq 2 -or $resourcesMoreThanZero -eq $true)
    $resourcesAll += $gettingResourcesAll
    #$resourcesAll += Search-AzGraph -Subscription $subscriptionId -Query $queryResources -First 5000
    #

    # ARG OLD
    $resourceGroupsRetryCount = 0
    $resourceGroupsRetrySeconds = 2
    $resourceGroupsMoreThanZero = $false
    do {
        $resourceGroupsRetryCount++
        $gettingresourceGroupsAll = Search-AzGraph -Subscription $subscriptionId -Query $queryResourceGroups
        if (($gettingresourceGroupsAll | Measure-Object).count -eq 0){
            Write-Host "really??! None ResourceGroups, let´s check again (try: #$($resourceGroupsRetryCount))"
            start-sleep -seconds $resourceGroupsRetrySeconds
            $resourceGroupsRetrySeconds++
        }
        else{
            Write-Host "$($gettingresourceGroupsAll.count_) ResourceGroups detected (try: #$($resourceGroupsRetryCount))"
            $resourceGroupsMoreThanZero = $true
        }
    }
    until($resourceGroupsRetryCount -eq 2 -or $resourceGroupsMoreThanZero -eq $true)
    $resourceGroupsAll += $gettingresourceGroupsAll
    #$resourceGroupsAll += Search-AzGraph -Subscription $subscriptionId -Query $queryResourceGroups
    #>

    #$endResourceTypesResourceGroups = get-date
    #Write-Host " Getting RescourceTypes and ResourceGroups duration: $((NEW-TIMESPAN -Start $startResourceTypesResourceGroups -End $endResourceTypesResourceGroups).TotalMinutes) minutes"

    Write-Host " Checking Rescource Types Diagnostics capability"
    $startResourceDiagnosticsCheck = get-date

    $resourceTypesUnique = ($resourcesAll | select-object type).type.tolower() | sort-object -Unique  
    $resourceTypesSummarizedArray = @()
    $resourcesTypeAllCountTotal = 0
    ($resourcesAll).count_ | ForEach-Object { $resourcesTypeAllCountTotal += $_ }
    $resourceTypesSummarizedArray += foreach ($resourceTypeUnique in $resourceTypesUnique){
        $resourcesTypeCountTotal = 0
        ($resourcesAll | Where-Object { $_.type -eq $resourceTypeUnique }).count_ | ForEach-Object { $resourcesTypeCountTotal += $_ }
        [PSCustomObject]@{'ResourceType' = $resourceTypeUnique; 'ResourceCount' = $resourcesTypeCountTotal }
    }

    $resourceTypesDiagnosticsArray = @()
    foreach ($resourcetype in $resourceTypesSummarizedArray.ResourceType) {
        checkTokenLifetime
        $tryCounter = 0
        do{
            if ($tryCounter -gt 0){
                Start-Sleep -Milliseconds 250
            }
            $tryCounter++
            $dedicatedResourceArray = @()
            $dedicatedResourceArray += foreach ($batch in $subscriptionsBatch) {
                Search-AzGraph -Query "resources | where type =~ '$resourcetype' | project id" -Subscription $batch.Group -First 1
            }
        }
        until(($dedicatedResourceArray | Measure-Object).count -gt 0)

        $resource = $dedicatedResourceArray[0]
        $resourceCount = ($resourceTypesSummarizedArray | where-object { $_.Resourcetype -eq $resourcetype}).ResourceCount

        #thx @Jim Britt https://github.com/JimGBritt/AzurePolicy/tree/master/AzureMonitor/Scripts Create-AzDiagPolicy.ps1
        try {
            $Invalid = $false
            $LogCategories = @()
            $metrics = $false #initialize metrics flag to $false
            $logs = $false #initialize logs flag to $false

            $uriDiagnosticsSettingsCategories = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)$($resource.id)/providers/microsoft.insights/diagnosticSettingsCategories/?api-version=2017-05-01-preview"
            do {
                $result = "letscheck"
                $tryCounter++
                Try {
                    $Status = Invoke-WebRequest -uri $uriDiagnosticsSettingsCategories -Headers @{"Authorization" = "Bearer $accesstoken" }
                }
                catch {
                    $Invalid = $True
                    $Logs = $False
                    $Metrics = $False
                    $ResponseJSON = ''
                    $result = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code
                }
                if ($result -ne "letscheck"){
                    #$result
                    if ($result -eq "GatewayTimeout" -or $result -eq "BadGatewayConnection" -or $result -eq "InvalidGatewayHost") {
                        Write-Host " Checking Rescource Types Diagnostics capability for $($resourcetype): try #$tryCounter; returned: '$result' - try again"
                        $result = "tryAgain"
                        Start-Sleep -Milliseconds 250
                    }
                }
                if (!($Invalid)) {
                    $ResponseJSON = $Status.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
                }
            }
            until($result -ne "tryAgain")
        
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
            $resourceTypesDiagnosticsObject = [PSCustomObject]@{'ResourceType' = $resourcetype; 'Metrics' = $metrics; 'Logs' = $logs; 'LogCategories' = $LogCategories; 'ResourceCount' = [int]$resourceCount }
            $resourceTypesDiagnosticsArray += $resourceTypesDiagnosticsObject
        }
    }
    $endResourceDiagnosticsCheck = get-date
    Write-Host " Checking Rescource Types Diagnostics capability duration: $((NEW-TIMESPAN -Start $startResourceDiagnosticsCheck -End $endResourceDiagnosticsCheck).TotalMinutes) minutes"
    
    Write-Host "Create helper ht Policies used in PolicySets"
    foreach ($policySet in ($htCacheDefinitions).policySet.keys){
        $PolicySetPolicyIds = ($htCacheDefinitions).policySet.($policySet).PolicySetPolicyIds
        $arrayPoliciesUsedInPolicySets += foreach ($PolicySetPolicyId in $PolicySetPolicyIds){
            if ($arrayPoliciesUsedInPolicySets -notcontains $PolicySetPolicyId){
                $PolicySetPolicyId
            }
        }
    }
    
    $endResourceCaching = get-date
    Write-Host "Caching Resource data duration: $((NEW-TIMESPAN -Start $startResourceCaching -End $endResourceCaching).TotalMinutes) minutes"
    
    #summarizeDataCollectionResults
    Write-Host "Summary data collection"
    $mgsDetails = (($table | where-object { "" -ne $_.mgId}) | Select-Object Level, MgId -Unique)
    $mgDepth = ($mgsDetails.Level | Measure-Object -maximum).Maximum
    $totalMgCount = ($mgsDetails | Measure-Object).count
    $totalSubCount = (($table | Where-Object { "" -ne $_.subscriptionId} | Select-Object -Property subscriptionId -Unique).SubscriptionId | Measure-Object).count
    $totalSubOutOfScopeCount =($script:outOfScopeSubscriptions | Measure-Object).count
    $totalSubIncludedAndExcludedCount = $totalSubCount + $totalSubOutOfScopeCount
    $totalPolicyDefinitionsCustomCount = ((($htCacheDefinitions).policy.keys | where-object { ($htCacheDefinitions).policy.$_.Type -eq "Custom" }) | Measure-Object).count
    $totalPolicySetDefinitionsCustomCount = ((($htCacheDefinitions).policySet.keys | where-object { ($htCacheDefinitions).policySet.$_.Type -eq "Custom" }) | Measure-Object).count
    $totalPolicyAssignmentsCount = (($htCacheAssignments).policy.keys | Measure-Object).count
    $totalPolicyAssignmentsResourceGroupsAndResourcesCount =($script:arrayCachePolicyAssignmentsResourceGroups | Measure-Object).count
    $totalRoleDefinitionsCustomCount = ((($htCacheDefinitions).role.keys | where-object { ($htCacheDefinitions).role.$_.IsCustom -eq $True }) | Measure-Object).count
    $totalRoleAssignmentsCount = (($htCacheAssignments).role.keys | Measure-Object).count
    $totalRoleAssignmentsResourceGroupsAndResourcesCount =($script:arrayCacheRoleAssignmentsResourceGroups | Measure-Object).count
    $totalBlueprintDefinitionsCount = ((($htCacheDefinitions).blueprint.keys) | Measure-Object).count
    $totalBlueprintAssignmentsCount = (($htCacheAssignments).blueprint.keys | Measure-Object).count
    $totalResourceTypesCount = ($resourceTypesDiagnosticsArray | Measure-Object).Count
    Write-Host " Total Management Groups: $totalMgCount (depth $mgDepth)"
    Write-Host " Total Subscriptions: $totalSubIncludedAndExcludedCount ($totalSubCount included; $totalSubOutOfScopeCount out-of-scope)"
    Write-Host " Total Custom Policy Definitions: $totalPolicyDefinitionsCustomCount"
    Write-Host " Total Custom PolicySet Definitions: $totalPolicySetDefinitionsCustomCount"
    Write-Host " Total Policy Assignments: $($totalPolicyAssignmentsCount + $totalPolicyAssignmentsResourceGroupsAndResourcesCount)"
    Write-Host " Total Policy Assignments (ManagementGroups and Subscriptions): $totalPolicyAssignmentsCount"
    Write-Host " Total Policy Assignments (ResourceGroups): $totalPolicyAssignmentsResourceGroupsAndResourcesCount"
    Write-Host " Total Custom Roles: $totalRoleDefinitionsCustomCount"
    Write-Host " Total Role Assignments: $($totalRoleAssignmentsCount + $totalRoleAssignmentsResourceGroupsAndResourcesCount)"
    Write-Host " Total Role Assignments (ManagementGroups and Subscriptions): $totalRoleAssignmentsCount"
    Write-Host " Total Role Assignments (ResourceGroups and Resources): $totalRoleAssignmentsResourceGroupsAndResourcesCount"
    Write-Host " Total Blueprint Definitions: $totalBlueprintDefinitionsCount"
    Write-Host " Total Blueprint Assignments: $totalBlueprintAssignmentsCount"
    Write-Host " Total Resources: $resourcesTypeAllCountTotal"
    Write-Host " Total Resource Types: $totalResourceTypesCount"    
}
#endregion dataCollection

#region createoutputs

#region BuildHTML

#testhelper
#$fileTimestamp = (get-date -format "yyyyMMddHHmmss")

$startBuildHTML = get-date
Write-Host "Building HTML"
$html = $null

#preQueries
Write-Host "processing Helper Queries"
$startHelperQueries = get-date
$mgAndSubBaseQuery = ($table | Select-Object -Property level, mgid, mgname, mgParentName, mgParentId, subscriptionId, subscription)
$parentMgBaseQuery = ($mgAndSubBaseQuery | Where-Object { $_.MgParentId -eq $getMgParentId })
$parentMgNamex = $parentMgBaseQuery.mgParentName | Get-Unique
$parentMgIdx = $parentMgBaseQuery.mgParentId | Get-Unique
$ManagementGroupIdCaseSensitived = (($mgAndSubBaseQuery | Where-Object { $_.MgId -eq $ManagementGroupId }).mgId) | Get-Unique
$optimizedTableForPathQuery = ($mgAndSubBaseQuery | Select-Object -Property level, mgid, mgparentid, subscriptionId) | sort-object -Property level, mgid, mgname, mgparentId, mgparentName, subscriptionId, subscription -Unique
$subscriptionBaseQuery = $table | Where-Object { "" -ne $_.SubscriptionId }

if (-not $HierarchyMapOnly) {
    write-host " Build preQueries"
    $policyBaseQuery = $table | Where-Object { "" -ne $_.PolicyVariant } | Sort-Object -Property PolicyType, Policy | Select-Object -Property Level, Policy*, mgId, mgname, SubscriptionId, Subscription
    $policyPolicyBaseQuery = $policyBaseQuery | Where-Object { $_.PolicyVariant -eq "Policy" } | Select-Object -Property PolicyDefinitionIdGuid, PolicyDefinitionIdFull, PolicyAssignmentId
    $policyPolicySetBaseQuery = $policyBaseQuery | Where-Object { $_.PolicyVariant -eq "PolicySet" } | Select-Object -Property PolicyDefinitionIdGuid, PolicyDefinitionIdFull, PolicyAssignmentId
    $rbacBaseQuery = $table | Where-Object { "" -ne $_.RoleDefinitionName } | Sort-Object -Property RoleIsCustom, RoleDefinitionName | Select-Object -Property Level, Role*, mgId, MgName, SubscriptionId, Subscription
    $blueprintBaseQuery = $table | Where-Object { "" -ne $_.BlueprintName }
    $mgsAndSubs = (($mgAndSubBaseQuery | where-object { $_.mgId -ne "" -and $_.Level -ne "0" }) | select-object MgId, SubscriptionId -unique)
    $tenantCustomPolicies = ($htCacheDefinitions).policy.keys | where-object { ($htCacheDefinitions).policy.($_).Type -eq "Custom" }
    $tenantCustomPoliciesCount = ($tenantCustomPolicies | measure-object).count
    $tenantCustomPolicySets = ($htCacheDefinitions).policySet.keys | where-object { ($htCacheDefinitions).policySet.($_).Type -eq "Custom" }
    $tenantCustompolicySetsCount = ($tenantCustomPolicySets | measure-object).count
    $tenantCustomRoles = $($htCacheDefinitions).role.keys | where-object { ($htCacheDefinitions).role.($_).IsCustom -eq $True }

    write-host " Build SubscriptionsMgPath"
    $htAllSubsMgPath = @{ }
    foreach ($subscriptionId in $subscriptionIds){
        $htAllSubsMgPath.($subscriptionId) = @{ }
        createMgPathSub -subid $subscriptionId
        [array]::Reverse($script:submgPathArray)
        $htAllSubsMgPath.($subscriptionId).path = $script:submgPathArray
    }

    write-host " Build MgPaths"
    $htAllMgsPath = @{ }
    foreach ($mgid in (($optimizedTableForPathQuery | Where-Object { "" -eq $_.SubscriptionId} ).mgid)){
        $htAllMgsPath.($mgid) = @{ }
        createMgPath -mgid $mgid
        [array]::Reverse($script:mgPathArray)
        $htAllMgsPath.($mgid).path = $script:mgPathArray
    }
}
$endHelperQueries = get-date
Write-Host "Helper Queries duration: $((NEW-TIMESPAN -Start $startHelperQueries -End $endHelperQueries).TotalSeconds) seconds"

#filename
if ($AzureDevOpsWikiAsCode) { 
    $fileName = "AzGovViz_$($ManagementGroupIdCaseSensitived)"
}
else {
    if ($HierarchyMapOnly) {
        $fileName = "AzGovViz_$($fileTimestamp)_$($ManagementGroupIdCaseSensitived)_HierarchyMapOnly"
    }
    else {
        $fileName = "AzGovViz_$($fileTimestamp)_$($ManagementGroupIdCaseSensitived)"
    }
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
        link.href = "https://www.azadvertizer.net/azgovvizv4/css/azgovvizversion.css?rnd=" + rand;
        link.type = "text/css";
        link.rel = "stylesheet";
        link.media = "screen,print";
        document.getElementsByTagName( "head" )[0].appendChild( link );
    </script>
    <link rel="stylesheet" type="text/css" href="https://www.azadvertizer.net/azgovvizv4/css/azgovvizmain_004_002.css">
    <script src="https://code.jquery.com/jquery-1.7.2.js" integrity="sha256-FxfqH96M63WENBok78hchTCDxmChGFlo+/lFIPcZPeI=" crossorigin="anonymous"></script>
    <script src="https://code.jquery.com/ui/1.8.18/jquery-ui.js" integrity="sha256-lzf/CwLt49jbVoZoFcPZOc0LlMYPFBorVSwMsTs2zsA=" crossorigin="anonymous"></script>
    <script type="text/javascript" src="https://www.azadvertizer.net/azgovvizv4/js/highlight_v004_001.js"></script>
    <script src="https://use.fontawesome.com/0c0b5cbde8.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv4/tablefilter/tablefilter.js"></script>
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
                        <li><a class="mgnonradius parentmgnotaccessible"><img class="imgMgTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"><div class="fitme" id="fitme">$mgNameAndOrId</div></a>
                        <ul>
"@
}

$startHierarchyTree = get-date
Write-Host " Building HTML Hierarchy Tree"

hierarchyMgHTML -mgChild $ManagementGroupIdCaseSensitived

$endHierarchyTree = get-date
Write-Host " Building HTML Hierarchy Tree duration: $((NEW-TIMESPAN -Start $startHierarchyTree -End $endHierarchyTree).TotalMinutes) minutes"

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

if (-not $HierarchyMapOnly) {

$html += @"
    <div class="summprnt" id="summprnt">
    <div class="summary" id="summary">
"@

$html | Set-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
$html = $null

    $startSummary = get-date

    summary

    $endSummary = get-date
    Write-Host " Building HTML Summary duration: $((NEW-TIMESPAN -Start $startSummary -End $endSummary).TotalMinutes) minutes"

$html += @"
    </div>
    </div>
    <div class="hierprnt" id="hierprnt">
    <div class="hierarchyTables" id="hierarchyTables">
"@
$html | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
$html = $null
    Write-Host " Building HTML Hierarchy Table"
    $startHierarchyTable = get-date

    $script:scopescnter = 0
    tableMgHTML -mgChild $ManagementGroupIdCaseSensitived -mgChildOf $getMgParentId

    $endHierarchyTable = get-date
    Write-Host " Building HTML Hierarchy Table duration: $((NEW-TIMESPAN -Start $startHierarchyTable -End $endHierarchyTable).TotalMinutes) minutes"
    
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

if (-not $HierarchyMapOnly) {
$html += @"
        Limit Warning: $($LimitCriticalPercentage)% <button id="hierarchyTreeShowHide" onclick="toggleHierarchyTree()">Hide HierarchyMap</button> <button id="summaryShowHide" onclick="togglesummprnt()">Hide TenantSummary</button> <button id="hierprntShowHide" onclick="togglehierprnt()">Hide ScopeInsights</button>
"@
}

$html += @"
    </div>
    <script src="https://www.azadvertizer.net/azgovvizv4/js/toggle_v004_001.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv4/js/collapsetable_v004_001.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv4/js/fitty_v004_001.min.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv4/js/version_v004_001.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv4/js/autocorrectOff_v004_001.js"></script>
    <script>
        fitty('#fitme', {
            minSize: 7,
            maxSize: 10
        });
    </script>


</body>
</html>
"@  

$html | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force

$endBuildHTML = get-date
Write-Host "Building HTML total duration: $((NEW-TIMESPAN -Start $startBuildHTML -End $endBuildHTML).TotalMinutes) minutes"
#endregion BuildHTML

#region BuildMD
Write-Host "Building Markdown"
$startBuildMD = get-date
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
Total Subscriptions: $totalSubIncludedAndExcludedCount ($totalSubCount included; $totalSubOutOfScopeCount out-of-scope)\
Total Custom Policy Definitions: $totalPolicyDefinitionsCustomCount\
Total Custom PolicySet Definitions: $totalPolicySetDefinitionsCustomCount\
Total Policy Assignments: $($totalPolicyAssignmentsCount + $totalPolicyAssignmentsResourceGroupsAndResourcesCount)\
Total Policy Assignments (ManagementGroups and Subscriptions): $totalPolicyAssignmentsCount\
Total Policy Assignments (ResourceGroups): $totalPolicyAssignmentsResourceGroupsAndResourcesCount\
Total Custom Roles: $totalRoleDefinitionsCustomCount\
Total Role Assignments: $($totalRoleAssignmentsCount + $totalRoleAssignmentsResourceGroupsAndResourcesCount)\
Total Role Assignments (ManagementGroups and Subscriptions): $totalRoleAssignmentsCount\
Total Role Assignments (ResourceGroups and Resources): $totalRoleAssignmentsResourceGroupsAndResourcesCount\
Total Blueprint Definitions: $totalBlueprintDefinitionsCount\
Total Blueprint Assignments: $totalBlueprintAssignmentsCount\
Total Resources: $resourcesTypeAllCountTotal\
Total Resource Types: $totalResourceTypesCount

## Hierarchy Table

| **MgLevel** | **MgName** | **MgId** | **MgParentName** | **MgParentId** | **SubName** | **SubId** |
|-------------|-------------|-------------|-------------|-------------|-------------|-------------|
$markdownTable
"@

$markdown | Set-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).md" -Encoding utf8 -Force
$endBuildMD = get-date
Write-Host "Building Markdown total duration: $((NEW-TIMESPAN -Start $startBuildMD -End $endBuildMD).TotalMinutes) minutes"
#endregion BuildMD

#region BuildCSV
Write-Host "Building CSV"
$startBuildCSV = get-date
$table | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).csv" -Delimiter "$csvDelimiter" -NoTypeInformation
$endBuildCSV = get-date
Write-Host "Building CSV total duration: $((NEW-TIMESPAN -Start $startBuildCSV -End $endBuildCSV).TotalMinutes) minutes"
#endregion BuildCSV

#endregion createoutputs

$endAzGovViz = get-date
Write-Host "AzGovViz duration: $((NEW-TIMESPAN -Start $startAzGovViz -End $endAzGovViz).TotalMinutes) minutes"