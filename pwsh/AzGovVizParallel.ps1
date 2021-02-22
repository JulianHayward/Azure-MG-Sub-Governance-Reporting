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
    Define the Management Group Id for which the outputs/files should be generated
 
.PARAMETER CsvDelimiter
    The script outputs a csv file depending on your delimit defaults choose semicolon or comma

.PARAMETER OutputPath
    Full- or relative path

.PARAMETER DoNotShowRoleAssignmentsUserData
    default is to capture the DisplayName and SignInName for RoleAssignments on ObjectType=User; for data protection and security reasons this may not be acceptable

.PARAMETER HierarchyMapOnly
    default is to query all Management groups and Subscription for Governance capabilities, if you use the parameter -HierarchyMapOnly then only the HierarchyMap will be created

.PARAMETER NoASCSecureScore
    default is to query all Subscriptions for Azure Security Center Secure Score. As the API is in preview you may want to disable it.

.PARAMETER NoResourceProvidersDetailed
    default is to output all ResourceProvider states for all Subscriptions. In large Tenants this can become time consuming.

.PARAMETER AzureDevOpsWikiAsCode
    use this parameter when running AzGovViz in Azure DevOps (AzDO) pipeline
    default is to Throw at error, whilst in AzDO we will Write-Error "Error"
    default is to add timestamp to the outputs filename, in AzDO the outputs filenames will not have a filestamp added as we have a GIT history (the files will only be pushed to Wiki Repo in case the files differ)

.PARAMETER LimitCriticalPercentage
    default is 80%, this parameter defines the warning level for approaching Limits (e.g. 80% of Role Assignment limit reached) change as per your preference

.PARAMETER SubscriptionQuotaIdWhitelist
    default is 'undefined', this parameter defines the QuotaIds the subscriptions must match so that AzGovViz processes them. The script checks if the QuotaId startswith the string that you have put in. Separate multiple strings with backslash e.g. MSDN_\EnterpriseAgreement_   

.PARAMETER NoPolicyComplianceStates
    use this parameter if policy compliance states should not be queried

.PARAMETER NoResourceDiagnosticsPolicyLifecycle
    use this parameter if Resource Diagnostics Policy Lifecycle recommendations should not be created

.PARAMETER NoAADGroupsResolveMembers
    use this parameter if Azure Active Directory Group memberships should not be resolved for Role assignments where identity type is 'Group'

.PARAMETER NoAADGuestUsers
    use this parameter if Azure Active Directory User type (Guest or Member) should not be resolved for Role assignments where identity type is 'User'

.PARAMETER NoAADServicePrincipalResolve
    use this parameter if Azure Active Directory Service Principals should not be resolved for Role assignments where identity type is 'ServicePrincipal'

.PARAMETER AADServicePrincipalExpiryWarningDays
    use this parameter if not using parameter -NoAADServicePrincipalResolve. Secret and Certificate expiry warning for lifetime below AADServicePrincipalExpiryWarningDays (days); default is 14 days

.PARAMETER NoAzureConsumption
    use this parameter if Azure Consumption data should not be reported

.PARAMETER AzureConsumptionPeriod
    use this parameter to define for which time period Azure Consumption data should be gathered; default is 1 day

.PARAMETER NoAzureConsumptionReportExportToCSV
    use this parameter if Azure Consumption data should not be exported (CSV)

.PARAMETER NoScopeInsights
    Q: Why would you want to do this? A: In larger tenants the ScopeInsights section blows up the html file (up to unusable due to html file size)

.PARAMETER ThrottleLimit
    Leveraging PowerShell Core´s parallel capability you can define the ThrottleLimit (default=5)

.PARAMETER DoTranscript
    Log the console output

.PARAMETER AzureDevOpsWikiHierarchyDirection
    Define the direction the Hierarchy should be built in Azure DevOps TD (default) = TopDown (Horizontal), LR = LeftRight (Vertical)

.EXAMPLE
    Define the ManagementGroup ID
    PS C:\> .\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id>

    Define how the CSV output should be delimited. Valid input is ; or , (semicolon is default)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -CsvDelimiter ","
    
    Define the outputPath (must exist)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -OutputPath 123
    
    Define if User information should be scrubbed (default prints Userinformation to the CSV and HTML output)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -DoNotShowRoleAssignmentsUserData
    
    Define if only the HierarchyMap output should be created. Will ignore the parameters 'LimitCriticalPercentage' and 'DoNotShowRoleAssignmentsUserData' (default queries for Governance capabilities such as policy-, role-, blueprints assignments and more)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -HierarchyMapOnly

    Define if ASC SecureScore should be queried for Subscriptions
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -NoASCSecureScore

    Define if a detailed summary on Resource Provider states per Subscription should be created in the TenantSummary section
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -NoResourceProvidersDetailed

    Define if the script runs in AzureDevOps.
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -AzureDevOpsWikiAsCode
    
    Define when limits should be highlighted as warning (default is 80 percent)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -LimitCriticalPercentage 90

    Define the QuotaId whitelist by providing strings separated by a backslash
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -SubscriptionQuotaIdWhitelist MSDN_\EnterpriseAgreement_

    Define if policy compliance states should be queried
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -NoPolicyComplianceStates

    Define if Resource Diagnostics Policy Lifecycle recommendations should not be created
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -NoResourceDiagnosticsPolicyLifecycle

    Define if Azure Active Directory Group memberships should not be resolved for Role assignments where identity type is 'Group'
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -NoAADGroupsResolveMembers

    Define if Azure Active Directory User type (Guest or Member) should not be resolved for Role assignments where identity type is 'User'
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -NoAADGuestUsers

    Define if Azure Active Directory Service Principals should not be resolved for Role assignments where identity type is 'ServicePrincipal'
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -NoAADServicePrincipalResolve

    Define Service Principal Secret and Certificate grace period (lifetime below the defined will be marked for warning / default is 14 days)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -AADServicePrincipalExpiryWarningDays 30

    Define if Azure Consumption data should not be reported
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -NoAzureConsumption

    Define for which time period (days) Azure Consumption data should be gathered; e.g. 14 days; default is 1 day
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -AzureConsumptionPeriod 14

    Define if ScopeInsights should be created or not. Q: Why would you want to do this? A: In larger tenants the ScopeInsights section blows up the html file (up to unusable due to html file size)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -NoScopeInsights

    Define the number of script blocks running in parallel. Leveraging PowerShell Core´s parallel capability you can define the ThrottleLimit (default=5)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -ThrottleLimit 10

    Define if you want to log the console output
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -DoTranscript

    Define the direction the Hierarchy should be built in Azure DevOps WokiAsCode (Markdown) TD = TopDown (Horizontal), LR = LeftRight (Vertical)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -AzureDevOpsWikiHierarchyDirection "LR"

.NOTES
    AUTHOR: Julian Hayward - Customer Engineer - Customer Success Unit | Azure Infrastucture/Automation/Devops/Governance | Microsoft

.LINK
    https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting
    Please note that while being developed by a Microsoft employee, AzGovViz is not a Microsoft service or product. AzGovViz is a personal/community driven project, there are none implicit or explicit obligations related to this project, it is provided 'as is' with no warranties and confer no rights.
#>

[CmdletBinding()]
Param
(
    [string]$AzGovVizVersion = "v5_major_20210222_1",
    [string]$ManagementGroupId,
    [switch]$AzureDevOpsWikiAsCode,
    [switch]$DebugAzAPICall,
    [switch]$CsvExport,
    [string]$CsvDelimiter = ";",
    [switch]$CsvExportUseQuotesAsNeeded,
    [string]$OutputPath,
    [switch]$DoNotShowRoleAssignmentsUserData,
    [switch]$HierarchyMapOnly,
    [switch]$NoASCSecureScore,
    [switch]$NoResourceProvidersDetailed,
    [int]$LimitCriticalPercentage = 80,
    [array]$SubscriptionQuotaIdWhitelist = @("undefined"),
    [switch]$NoPolicyComplianceStates,
    [switch]$NoResourceDiagnosticsPolicyLifecycle,
    [switch]$NoAADGroupsResolveMembers,
    [switch]$NoAADGuestUsers,
    [switch]$NoAADServicePrincipalResolve,
    [int]$AADServicePrincipalExpiryWarningDays = 14,
    [switch]$NoAzureConsumption,
    [int]$AzureConsumptionPeriod = 1,
    [switch]$NoAzureConsumptionReportExportToCSV,
    [switch]$NoScopeInsights,
    [switch]$DoTranscript,
    [int]$TFCriticalRowsCount = 40000, #HTML ScopeInsights Role Assignments -> becomes unresponsive depending on client device performance. A recommendation will be shown to download the CSV instead of opening the TF table
    [int]$ThrottleLimit = 5, 
    [array]$ExludedResourceTypesDiagnosticsCapable = @("microsoft.web/certificates"),
    [switch]$IncludeResourceGroupsAndResources,
    #[string]$AzureDevOpsWikiHierarchyDirection = "TD",
    [parameter(ValueFromPipeline)][ValidateSet("TD","LR")][string[]]$AzureDevOpsWikiHierarchyDirection = "TD",

    #https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#role-based-access-control-limits
    [int]$LimitRBACCustomRoleDefinitionsTenant = 5000,
    [int]$LimitRBACRoleAssignmentsManagementGroup = 500,
    [int]$LimitRBACRoleAssignmentsSubscription = 2000,
    #[string]$LimitRBACRoleAssignmentsSubscription = 2000 #will be retrieved programatically

    #https://docs.microsoft.com/en-us/azure/governance/policy/overview#maximum-count-of-azure-policy-objects
    [int]$LimitPOLICYPolicyAssignmentsManagementGroup = 200,
    [int]$LimitPOLICYPolicyAssignmentsSubscription = 200,
    #[int]$LimitPOLICYPolicyDefinitionsScopedTenant = 1000,
    [int]$LimitPOLICYPolicyDefinitionsScopedManagementGroup = 500,
    [int]$LimitPOLICYPolicyDefinitionsScopedSubscription = 500,
    [int]$LimitPOLICYPolicySetAssignmentsManagementGroup = 200,
    [int]$LimitPOLICYPolicySetAssignmentsSubscription = 200,
    [int]$LimitPOLICYPolicySetDefinitionsScopedTenant = 2500,
    [int]$LimitPOLICYPolicySetDefinitionsScopedManagementGroup = 200,
    [int]$LimitPOLICYPolicySetDefinitionsScopedSubscription = 200,

    #https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#subscription-limits
    [int]$LimitResourceGroups = 980,
    [int]$LimitTagsSubscription = 50
)
$ErrorActionPreference = "Stop"

#filedir
if (-not [IO.Path]::IsPathRooted($outputPath)) {
    $outputPath = Join-Path -Path (Get-Location).Path -ChildPath $outputPath
}
$outputPath = Join-Path -Path $outputPath -ChildPath '.'
$outputPath = [IO.Path]::GetFullPath($outputPath)
if (-not (test-path $outputPath)) {
    Write-Host "path $outputPath does not exist -create it!" -ForegroundColor Red
    Throw "Error - check the last console output for details"
}
else {
    Write-Host "Output/Files will be created in path $outputPath"
}
$DirectorySeparatorChar = [IO.Path]::DirectorySeparatorChar
$fileTimestamp = (get-date -format "yyyyMMddHHmmss")

if ($DoTranscript){
    $fileNameTranscript = "AzGovViz_$($AzGovVizVersion)_$($fileTimestamp)_Log.txt"
    Start-Transcript -Path "$($outputPath)$($DirectorySeparatorChar)$($fileNameTranscript)" -NoClobber
}

#time
$executionDateTimeInternationalReadable = get-date -format "dd-MMM-yyyy HH:mm:ss"
$currentTimeZone = (Get-TimeZone).id


#start
$startAzGovViz = get-date
$startTime = get-date -format "dd-MMM-yyyy HH:mm:ss"
$startTimeUTC = ((Get-Date).ToUniversalTime()).ToString("dd-MMM-yyyy HH:mm:ss")
Write-Host "Start AzGovViz $($startTime) (#$($AzGovVizVersion))"

#region htParameters (all switch params used in foreach-object -parallel)
$htParameters = @{ }
if ($AzureDevOpsWikiAsCode) {
    $htParameters.AzureDevOpsWikiAsCode = $true
}
else {
    $htParameters.AzureDevOpsWikiAsCode = $false
}

if ($DebugAzAPICall) {
    $htParameters.DebugAzAPICall = $true
}
else {
    $htParameters.DebugAzAPICall = $false
}

if ($DoNotShowRoleAssignmentsUserData) {
    $htParameters.DoNotShowRoleAssignmentsUserData = $true
}
else {
    $htParameters.DoNotShowRoleAssignmentsUserData = $false
}

if ($HierarchyMapOnly) {
    $htParameters.HierarchyMapOnly = $true
}
else {
    $htParameters.HierarchyMapOnly = $false
}

if ($NoASCSecureScore) {
    $htParameters.NoASCSecureScore = $true
}
else {
    $htParameters.NoASCSecureScore = $false
}

if ($NoResourceProvidersDetailed) {
    $htParameters.NoResourceProvidersDetailed = $true
}
else {
    $htParameters.NoResourceProvidersDetailed = $false
}

if ($NoPolicyComplianceStates) {
    $htParameters.NoPolicyComplianceStates = $true
}
else {
    $htParameters.NoPolicyComplianceStates = $false
}

if ($NoAzureConsumption) {
    $htParameters.NoAzureConsumption = $true
}
else {
    $htParameters.NoAzureConsumption = $false
}

if ($IncludeResourceGroupsAndResources) {
    $htParameters.IncludeResourceGroupsAndResources = $true
}
else {
    $htParameters.IncludeResourceGroupsAndResources = $false
}
#endregion htParameters

#region PowerShellEditionAnVersionCheck
Write-Host "Checking powershell edition and version"
$requiredPSVersion = "7.0.3"
if ($PSVersionTable.PSEdition -eq "Core" -and ( [version]('{0}.{1}.{2}' -f (($PSVersionTable.PSVersion).tostring()).split('.')) -ge [version]('{0}.{1}.{2}' -f ($requiredPSVersion).split('.')) ) ) {
    Write-Host " PS check passed"
    Write-Host " PS Edition: $($PSVersionTable.PSEdition)"
    Write-Host " PS Version: $($PSVersionTable.PSVersion)"
}
else {
    Write-Host " PS Edition: $($PSVersionTable.PSEdition)"
    Write-Host " PS Version: $($PSVersionTable.PSVersion)"
    Write-Host " This AzGovViz version only supports Powershell 'Core' version '7.0.3' or higher"
    if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
        Write-Error "Error"
    }
    else {
        Throw "Error - check the last console output for details"
    }
}
#endregion PowerShellEditionAnVersionCheck

if ($htParameters.DebugAzAPICall -eq $false) {
    write-host "no AzAPICall debug"
}
else {
    write-host "AzAPICall debug"
}

#shutuppoluters
$ProgressPreference = 'SilentlyContinue'
Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings "true"

function Add-IndexNumberToArray (
    [Parameter(Mandatory = $True)]
    [array]$array
) {
    for ($i = 0; $i -lt ($array | measure-object).count; $i++) { 
        Add-Member -InputObject $array[$i] -Name "#" -Value ($i + 1) -MemberType NoteProperty 
    }
    $array
}

#JWTDetails https://www.powershellgallery.com/packages/JWTDetails/1.0.2
#region jwtdetails
function getJWTDetails {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string]$token
    )

    if (!$token -contains (".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }

    #Token
    foreach ($i in 0..1) {
        $data = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
        switch ($data.Length % 4) {
            0 { break }
            2 { $data += '==' }
            3 { $data += '=' }
        }
    }

    $decodedToken = [System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String($data)) | ConvertFrom-Json 
    Write-Verbose "JWT Token:"
    Write-Verbose $decodedToken

    #Signature
    foreach ($i in 0..2) {
        $sig = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
        switch ($sig.Length % 4) {
            0 { break }
            2 { $sig += '==' }
            3 { $sig += '=' }
        }
    }
    Write-Verbose "JWT Signature:"
    Write-Verbose $sig
    $decodedToken | Add-Member -Type NoteProperty -Name "sig" -Value $sig

    #Convert Expiry time to PowerShell DateTime
    $orig = (Get-Date -Year 1970 -Month 1 -Day 1 -hour 0 -Minute 0 -Second 0 -Millisecond 0)
    $timeZone = Get-TimeZone
    $utcTime = $orig.AddSeconds($decodedToken.exp)
    $offset = $timeZone.GetUtcOffset($(Get-Date)).TotalMinutes #Daylight saving needs to be calculated
    $localTime = $utcTime.AddMinutes($offset)     # Return local time,
    
    $decodedToken | Add-Member -Type NoteProperty -Name "expiryDateTime" -Value $localTime
    
    #Time to Expiry
    $timeToExpiry = ($localTime - (get-date))
    $decodedToken | Add-Member -Type NoteProperty -Name "timeToExpiry" -Value $timeToExpiry

    return $decodedToken
}
$funcGetJWTDetails = $function:getJWTDetails.ToString()
#endregion jwtdetails

#Bearer Token
#region createbearertoken
function createBearerToken($targetEndPoint) {
    $checkContext = Get-AzContext -ErrorAction Stop
    Write-Host "+Processing new bearer token request ($targetEndPoint)"
    if ($targetEndPoint -eq "ManagementAPI") {
        $azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile;
        $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile);
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = ($profileClient.AcquireAccessToken($checkContext.Subscription.TenantId))
        }
        catch {
            $catchResult = $_
        }
    }
    if ($targetEndPoint -eq "GraphAPI") {
        $contextForGraphToken = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForGraphToken.Account, $contextForGraphToken.Environment, $contextForGraphToken.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).GraphUrl)")
        }
        catch {
            $catchResult = $_
        }
    }
    if ($catchResult -ne "letscheck") {
        Write-Host "-ERROR processing new bearer token request ($targetEndPoint): $catchResult" -ForegroundColor Red
        Write-Host "Likely your Azure credentials have not been set up or have expired, please run 'Connect-AzAccount' to set up your Azure credentials."
        Write-Host "It could also well be that there are multiple context in cache, please run 'Clear-AzContext' and then run 'Connect-AzAccount'."
        Throw "Error - check the last console output for details"
    }
    $dateTimeTokenCreated = (get-date -format "MM/dd/yyyy HH:mm:ss")
    if ($targetEndPoint -eq "ManagementAPI") {
        $script:htBearerAccessToken.AccessTokenManagement = $newBearerAccessTokenRequest.AccessToken
    }
    if ($targetEndPoint -eq "GraphAPI") {
        $script:htBearerAccessToken.AccessTokenGraph = $newBearerAccessTokenRequest.AccessToken
    }
    $bearerDetails = GetJWTDetails -token $newBearerAccessTokenRequest.AccessToken
    $bearerAccessTokenExpiryDateTime = $bearerDetails.expiryDateTime
    $bearerAccessTokenTimeToExpiry = $bearerDetails.timeToExpiry
    Write-Host "+Bearer token ($targetEndPoint): [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']"
}
$funcCreateBearerToken = $function:createBearerToken.ToString()
$htBearerAccessToken = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
#endregion createbearertoken

#API
#region azapicall
function AzAPICall($uri, $method, $currentTask, $body, $listenOn, $getConsumption, $getApp, $getSp, $getGuests, $caller) {
    #$debugAzAPICall = $true
    $tryCounter = 0
    $tryCounterUnexpectedError = 0
    $retryAuthorizationFailed = 5
    $retryAuthorizationFailedCounter = 0
    $apiCallResultsCollection = [System.Collections.ArrayList]@()
    $initialUri = $uri
    $restartDueToDuplicateNextlinkCounter = 0

    do {
        if ($arrayAzureManagementEndPointUrls | Where-Object { $uri -match $_ }) {
            $targetEndpoint = "ManagementAPI"
            $bearerToUse = $htBearerAccessToken.AccessTokenManagement
        }
        else {
            $targetEndpoint = "GraphAPI"
            $bearerToUse = $htBearerAccessToken.AccessTokenGraph
        }

        #API Call Tracking
        $tstmp = (Get-Date -format "yyyyMMddHHmmssms")
        $null = $script:arrayAPICallTracking.Add([PSCustomObject]@{ 
                CurrentTask    = $currentTask
                TargetEndpoint = $targetEndpoint
                Uri            = $uri
                Method         = $method
                TryCounter = $tryCounter
                TryCounterUnexpectedError = $tryCounterUnexpectedError
                RetryAuthorizationFailedCounter = $retryAuthorizationFailedCounter
                RestartDueToDuplicateNextlinkCounter = $restartDueToDuplicateNextlinkCounter
                TimeStamp = $tstmp
            })
        
        if ($caller -eq "CustomDataCollection"){
            $null = $script:arrayAPICallTrackingCustomDataCollection.Add([PSCustomObject]@{ 
                    CurrentTask    = $currentTask
                    TargetEndpoint = $targetEndpoint
                    Uri            = $uri
                    Method         = $method
                    TryCounter = $tryCounter
                    TryCounterUnexpectedError = $tryCounterUnexpectedError
                    RetryAuthorizationFailedCounter = $retryAuthorizationFailedCounter
                    RestartDueToDuplicateNextlinkCounter = $restartDueToDuplicateNextlinkCounter
                    TimeStamp = $tstmp
                })
        }

        $unexpectedError = $false
        $tryCounter++
        if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "  DEBUGTASK: attempt#$($tryCounter) processing: $($currenttask)" }
        try {
            if ($body) {
                #write-host "has BODY"
                $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -body $body -Headers @{"Content-Type" = "application/json"; "Authorization" = "Bearer $bearerToUse" } -ContentType "application/json" -UseBasicParsing
            }
            else {
                $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -Headers @{"Content-Type" = "application/json"; "Authorization" = "Bearer $bearerToUse" } -UseBasicParsing
            }
        }
        catch {
            try {
                $catchResultPlain = $_.ErrorDetails.Message
                $catchResult = ($catchResultPlain | ConvertFrom-Json -ErrorAction SilentlyContinue) 
            }
            catch {
                $catchResult = $catchResultPlain
                $tryCounterUnexpectedError++
                $unexpectedError = $true
            }
        }
        
        if ($unexpectedError -eq $false) {
            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: unexpectedError: false" }
            if ($azAPIRequest.StatusCode -ne 200) {
                if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: apiStatusCode: $($azAPIRequest.StatusCode)" }
                if ($catchResult.error.code -like "*GatewayTimeout*" -or $catchResult.error.code -like "*BadGatewayConnection*" -or 
                    $catchResult.error.code -like "*InvalidGatewayHost*" -or $catchResult.error.code -like "*ServerTimeout*" -or 
                    $catchResult.error.code -like "*ServiceUnavailable*" -or $catchResult.code -like "*ServiceUnavailable*" -or 
                    $catchResult.error.code -like "*MultipleErrorsOccurred*" -or $catchResult.error.code -like "*InternalServerError*" -or 
                    $catchResult.error.code -like "*RequestTimeout*" -or $catchResult.error.code -like "*AuthorizationFailed*" -or 
                    $catchResult.error.code -like "*ExpiredAuthenticationToken*" -or $catchResult.error.code -like "*ResponseTooLarge*" -or 
                    $catchResult.error.code -like "*InvalidAuthenticationToken*" -or ($getConsumption -and $catchResult.error.code -eq 404) -or 
                    ($getSp -and $catchResult.error.code -like "*Request_ResourceNotFound*") -or 
                    ($getSp -and $catchResult.error.code -like "*Authorization_RequestDenied*") -or
                    ($getApp -and $catchResult.error.code -like "*Request_ResourceNotFound*") -or 
                    ($getApp -and $catchResult.error.code -like "*Authorization_RequestDenied*") -or 
                    ($getGuests -and $catchResult.error.code -like "*Authorization_RequestDenied*") -or 
                    $catchResult.error.message -like "*The offer MS-AZR-0110P is not supported*") {
                    if ($catchResult.error.code -like "*ResponseTooLarge*") {
                        Write-Host "###### LIMIT #################################"
                        Write-Host "Hitting LIMIT getting Policy Compliance States!"
                        Write-Host "ErrorCode: $($catchResult.error.code)"
                        Write-Host "ErrorMessage: $($catchResult.error.message)"
                        Write-Host "There is nothing we can do about this right now. Please run AzGovViz with the following parameter: '-NoPolicyComplianceStates'." -ForegroundColor Yellow
                        Write-Host "Impact using parameter '-NoPolicyComplianceStates': only policy compliance states will not be available in the various AzGovViz outputs - all other output remains." -ForegroundColor Yellow
                        if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
                            Write-Error "Error"
                        }
                        else {
                            break # Break Script
                        }
                    }
                    if ($catchResult.error.message -like "*The offer MS-AZR-0110P is not supported*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - seems we´re hitting a malicious endpoint .. try again in $tryCounter second(s)"
                        Start-Sleep -Seconds $tryCounter
                    }
                    if ($catchResult.error.code -like "*GatewayTimeout*" -or $catchResult.error.code -like "*BadGatewayConnection*" -or $catchResult.error.code -like "*InvalidGatewayHost*" -or $catchResult.error.code -like "*ServerTimeout*" -or $catchResult.error.code -like "*ServiceUnavailable*" -or $catchResult.code -like "*ServiceUnavailable*" -or $catchResult.error.code -like "*MultipleErrorsOccurred*" -or $catchResult.error.code -like "*InternalServerError*" -or $catchResult.error.code -like "*RequestTimeout*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again"
                        Start-Sleep -Milliseconds 250
                    }
                    if ($catchResult.error.code -like "*AuthorizationFailed*") {
                        if ($retryAuthorizationFailedCounter -gt $retryAuthorizationFailed) {
                            Write-Host " $currentTask - try #$tryCounter; returned: '$($catchResult.error.code)' | '$($catchResult.error.message)' - $retryAuthorizationFailed retries failed - investigate that error!/exit"
                            if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
                                Write-Error "Error"
                            }
                            else {
                                Throw "Error - check the last console output for details"
                            }
                        }
                        else {
                            if ($retryAuthorizationFailedCounter -gt 2) {
                                Start-Sleep -Seconds 5
                            }
                            if ($retryAuthorizationFailedCounter -gt 3) {
                                Start-Sleep -Seconds 10
                            }
                            Write-Host " $currentTask - try #$tryCounter; returned: '$($catchResult.error.code)' | '$($catchResult.error.message)' - not reasonable, retry #$retryAuthorizationFailedCounter of $retryAuthorizationFailed"
                            $retryAuthorizationFailedCounter ++
                        }
                    }
                    if ($catchResult.error.code -like "*ExpiredAuthenticationToken*" -or $catchResult.error.code -like "*InvalidAuthenticationToken*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: '$($catchResult.error.code)' | '$($catchResult.error.message)' - requesting new bearer token ($targetEndpoint)"
                        createBearerToken -targetEndPoint $targetEndpoint
                    }
                    if ($getConsumption -and $catchResult.error.code -eq 404) {
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Subscriptions was created only recently - skipping"
                        return $apiCallResultsCollection
                    }
                    if (($getApp -or $getSp) -and $catchResult.error.code -like "*Request_ResourceNotFound*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) uncertain ServicePrincipal status - skipping for now :)"
                        return "Request_ResourceNotFound"
                    }
                    if ((($getApp -or $getSp) -and $catchResult.error.code -like "*Authorization_RequestDenied*") -or ($getGuests -and $catchResult.error.code -like "*Authorization_RequestDenied*")) {
                        if ($userType -eq "Guest") {
                            Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult)"
                            Write-Host " AzGovViz says: You are a 'Guest' User in the tenant therefore not enough permissions. You have the following options: [1. request membership to AAD Role 'Directory readers'.] [2. Use parameters '-NoAADGuestUsers' and '-NoAADServicePrincipalResolve'.] [3. Grant explicit Microsoft Graph API permission. Permissions reference Users: https://docs.microsoft.com/en-us/graph/api/user-list | Applications: https://docs.microsoft.com/en-us/graph/api/application-list]" -ForegroundColor Yellow
                            if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
                                Write-Error "Error"
                            }
                            else {
                                Throw "Authorization_RequestDenied"
                            }
                        }
                        else {
                            Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) investigate that error!/exit"
                            if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
                                Write-Error "Error"
                            }
                            else {
                                Throw "Authorization_RequestDenied"
                            }
                        }
                    }                    
                }
                else {
                    Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) investigate that error!/exit"
                    if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
                        Write-Error "Error"
                    }
                    else {
                        Throw "Error - check the last console output for details"
                    }
                }
            }
            else {
                if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: apiStatusCode: $($azAPIRequest.StatusCode)" }
                $azAPIRequestConvertedFromJson = ($azAPIRequest.Content | ConvertFrom-Json)
                if ($listenOn -eq "Content") {       
                    if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: listenOn=content ($((($azAPIRequestConvertedFromJson) | Measure-Object).count))" }      
                    $null = $apiCallResultsCollection.Add($azAPIRequestConvertedFromJson)
                }
                elseif ($listenOn -eq "ContentProperties") {
                    if (($azAPIRequestConvertedFromJson.properties.rows | Measure-Object).Count -gt 0) {
                        foreach ($consumptionline in $azAPIRequestConvertedFromJson.properties.rows) {
                            $null = $apiCallResultsCollection.Add([PSCustomObject]@{ 
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[0])" = $consumptionline[0]
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[1])" = $consumptionline[1]
                                    SubscriptionMgPath                                             = $htSubscriptionsMgPath.($consumptionline[1]).ParentNameChain
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[2])" = $consumptionline[2]
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[3])" = $consumptionline[3]
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[4])" = $consumptionline[4]
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[5])" = $consumptionline[5]
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[6])" = $consumptionline[6]
                                })
                        }
                    }
                }
                else {       
                    if (($azAPIRequestConvertedFromJson).value) {
                        if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: listenOn=default(value) value exists ($((($azAPIRequestConvertedFromJson).value | Measure-Object).count))" }
                        $null = $apiCallResultsCollection.AddRange($azAPIRequestConvertedFromJson.value)
                    }
                    else {
                        if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: listenOn=default(value) value not exists; return empty array" }
                    }
                }

                $isMore = $false
                if ($azAPIRequestConvertedFromJson.nextLink) {
                    $isMore = $true
                    if ($uri -eq $azAPIRequestConvertedFromJson.nextLink) {
                        if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                            Write-Host " $currentTask restartDueToDuplicateNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                            if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
                                Write-Error "Error"
                            }
                            else {
                                Throw "Error - check the last console output for details"
                            }
                        }
                        else {
                            $restartDueToDuplicateNextlinkCounter++
                            Write-Host "nextLinkLog: uri is equal to nextLinkUri"
                            Write-Host "nextLinkLog: uri: $uri"
                            Write-Host "nextLinkLog: nextLinkUri: $($azAPIRequestConvertedFromJson.nextLink)"
                            Write-Host "nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
                            $apiCallResultsCollection = [System.Collections.ArrayList]@()
                            $uri = $initialUri
                            Start-Sleep -Seconds 1
                            createBearerToken -targetEndPoint $targetEndpoint
                            Start-Sleep -Seconds 1
                        }
                    }
                    else {
                        $uri = $azAPIRequestConvertedFromJson.nextLink
                    }
                    if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: nextLink: $Uri" }
                }
                elseIf ($azAPIRequestConvertedFromJson."@oData.nextLink") {
                    $isMore = $true
                    if ($uri -eq $azAPIRequestConvertedFromJson."@odata.nextLink") {
                        if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                            Write-Host " $currentTask restartDueToDuplicate@odataNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                            if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
                                Write-Error "Error"
                            }
                            else {
                                Throw "Error - check the last console output for details"
                            }
                        }
                        else {
                            $restartDueToDuplicateNextlinkCounter++
                            Write-Host "nextLinkLog: uri is equal to @odata.nextLinkUri"
                            Write-Host "nextLinkLog: uri: $uri"
                            Write-Host "nextLinkLog: @odata.nextLinkUri: $($azAPIRequestConvertedFromJson."@odata.nextLink")"
                            Write-Host "nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
                            $apiCallResultsCollection = [System.Collections.ArrayList]@()
                            $uri = $initialUri
                            Start-Sleep -Seconds 1
                            createBearerToken -targetEndPoint $targetEndpoint
                            Start-Sleep -Seconds 1
                        }
                    }
                    else {
                        $uri = $azAPIRequestConvertedFromJson."@odata.nextLink"
                    }
                    if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: @oData.nextLink: $Uri" }
                }
                elseif ($azAPIRequestConvertedFromJson.properties.nextLink) {              
                    $isMore = $true
                    if ($uri -eq $azAPIRequestConvertedFromJson.properties.nextLink) {
                        if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                            Write-Host " $currentTask restartDueToDuplicateNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                            if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
                                Write-Error "Error"
                            }
                            else {
                                Throw "Error - check the last console output for details"
                            }
                        }
                        else {
                            $restartDueToDuplicateNextlinkCounter++
                            Write-Host "nextLinkLog: uri is equal to nextLinkUri"
                            Write-Host "nextLinkLog: uri: $uri"
                            Write-Host "nextLinkLog: nextLinkUri: $($azAPIRequestConvertedFromJson.properties.nextLink)"
                            Write-Host "nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
                            $apiCallResultsCollection = [System.Collections.ArrayList]@()
                            $uri = $initialUri
                            Start-Sleep -Seconds 1
                            createBearerToken -targetEndPoint $targetEndpoint
                            Start-Sleep -Seconds 1
                        }
                    }
                    else {
                        $uri = $azAPIRequestConvertedFromJson.properties.nextLink
                    }
                    if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: nextLink: $Uri" }
                }
                else {
                    if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: NextLink: none" }
                }
            }
        }
        else {
            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: unexpectedError: notFalse" }
            if ($tryCounterUnexpectedError -lt 10) {
                $sleepSec = @(1,2,3,5,10,20,30,40,50,60)[$tryCounterUnexpectedError]
                Write-Host " $currentTask #$tryCounterUnexpectedError 'Unexpected Error' occurred (trying 10 times); sleep $sleepSec seconds"
                Write-Host $catchResult
                Start-Sleep -Seconds $sleepSec
            }
            else {
                Write-Host " $currentTask #$tryCounterUnexpectedError 'Unexpected Error' occurred (tried 5 times)/exit"
                if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
                    Write-Error "Error"
                }
                else {
                    Throw "Error - check the last console output for details"
                }
            }
        }
    }
    until($azAPIRequest.StatusCode -eq 200 -and -not $isMore)
    return $apiCallResultsCollection
}
$funcAzAPICall = $function:AzAPICall.ToString()
#endregion azapicall

#region azapicalldiag
function AzAPICallDiag($uri, $method, $currentTask, $resourceType) {
    $tryCounter = 0
    $tryCounterUnexpectedError = 0
    
    do {
        if ($arrayAzureManagementEndPointUrls | Where-Object { $uri -match $_ }) {
            $targetEndpoint = "ManagementAPI"
            $bearerToUse = $htBearerAccessToken.AccessTokenManagement
        }
        else {
            $targetEndpoint = "GraphAPI"
            $bearerToUse = $htBearerAccessToken.AccessTokenGraph
        }

        #API Call Tracking
        $tstmp = (Get-Date -format "yyyyMMddHHmmssms")
        $null = $script:arrayAPICallTracking.Add([PSCustomObject]@{ 
                CurrentTask    = $currentTask
                TargetEndpoint = $targetEndpoint
                Uri            = $uri
                Method         = $method
                TryCounter = $tryCounter
                TryCounterUnexpectedError = 0
                RetryAuthorizationFailedCounter = 0
                RestartDueToDuplicateNextlinkCounter = 0
                TimeStamp = $tstmp
            })

        $tryCounter++
        $retryAuthorizationFailed = 5
        $retryAuthorizationFailedCounter = 0
        $unexpectedError = $false
        try {
            $azAPIRequest = $null
            $azAPIRequest = Invoke-WebRequest -uri $uri -Method $method -Headers @{"Content-Type" = "application/json"; "Authorization" = "Bearer $bearerToUse" } -UseBasicParsing
        }
        catch {
            try {
                $catchResultPlain = $_.ErrorDetails.Message
                $catchResult = ($catchResultPlain | ConvertFrom-Json -ErrorAction SilentlyContinue)
            }
            catch {
                $catchResult = $catchResultPlain
                $tryCounterUnexpectedError++
                $unexpectedError = $true
            }
        }
        if ($unexpectedError -eq $false) {
            if ($azAPIRequest.StatusCode -ne 200) {
                if ($catchResult.error.code -like "*GatewayTimeout*" -or $catchResult.error.code -like "*BadGatewayConnection*" -or $catchResult.error.code -like "*InvalidGatewayHost*" -or $catchResult.error.code -like "*ServerTimeout*" -or $catchResult.error.code -like "*ServiceUnavailable*" -or $catchResult.code -like "*ServiceUnavailable*" -or $catchResult.error.code -like "*MultipleErrorsOccurred*" -or $catchResult.error.code -like "*InternalServerError*" -or $catchResult.code -like "*RequestTimeout*" -or $catchResult.error.code -like "*RequestTimeout*" -or $catchResult.error.code -like "*AuthorizationFailed*" -or $catchResult.code -like "*NotSupported*" -or $catchResult.error.code -like "*ExpiredAuthenticationToken*") {
                    if ($catchResult.error.code -like "*GatewayTimeout*" -or $catchResult.error.code -like "*BadGatewayConnection*" -or $catchResult.error.code -like "*InvalidGatewayHost*" -or $catchResult.error.code -like "*ServerTimeout*" -or $catchResult.error.code -like "*ServiceUnavailable*" -or $catchResult.code -like "*ServiceUnavailable*" -or $catchResult.error.code -like "*MultipleErrorsOccurred*" -or $catchResult.error.code -like "*InternalServerError*" -or $catchResult.code -like "*RequestTimeout*" -or $catchResult.error.code -like "*RequestTimeout*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again"
                        Start-Sleep -Milliseconds 250
                    }
                    if ($catchResult.code -like "*NotSupported*") {
                        Write-Host "  $($catchResult.code) | $($catchResult.message)"
                    }
                    if ($catchResult.error.code -like "*AuthorizationFailed*") {
                        if ($retryAuthorizationFailedCounter -gt $retryAuthorizationFailed) {
                            Write-Host " $currentTask - try #$tryCounter; returned: '$($catchResult.error.code)' | '$($catchResult.error.message)' - $retryAuthorizationFailed retries failed - investigate that error!"
                            if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
                                Write-Error "Error"
                            }
                            else {
                                Throw "Error - check the last console output for details"
                            }
                        }
                        else {
                            if ($retryAuthorizationFailedCounter -gt 2) {
                                Start-Sleep -Seconds 5
                            }
                            if ($retryAuthorizationFailedCounter -gt 3) {
                                Start-Sleep -Seconds 10
                            }
                            Write-Host " $currentTask - try #$tryCounter; returned: '$($catchResult.error.code)' | '$($catchResult.error.message)' - not reasonable, retry #$retryAuthorizationFailedCounter of $retryAuthorizationFailed"
                            $retryAuthorizationFailedCounter ++
                        }
                    }
                    if ($catchResult.error.code -like "*ExpiredAuthenticationToken*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: '$($catchResult.error.code)' | '$($catchResult.error.message)' - requesting new bearer token"
                        createBearerToken -targetEndPoint $targetEndpoint
                    }
                }
                else {
                    Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - investigate that error!"
                    if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
                        Write-Error "Error"
                    }
                    else {
                        Throw "Error - check the last console output for details"
                    }
                }
            }
            else {
                Write-Host "  ResourceTypeSupported | The resource type '$($resourcetype)' supports diagnostic settings."
                $Script:responseJSON = $azAPIRequest.Content | ConvertFrom-Json
            }
        }
        else {
            if ($tryCounterUnexpectedError -lt 6) {
                Write-Host " $currentTask #$tryCounterUnexpectedError 'Unexpected Error' occurred (trying 5 times)"
                Write-Host $catchResult
                Start-Sleep -Seconds $tryCounterUnexpectedError
            }
            else {
                if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
                    Write-Error "Error"
                }
                else {
                    Throw "Error - check the last console output for details"
                }
            }
        }
    }
    until($azAPIRequest.StatusCode -eq 200 -or $catchResult.code -like "*NotSupported*")
}
$funcAzAPICallDiag = $function:AzAPICallDiag.ToString()
#endregion azapicalldiag

#test required Az modules cmdlets
#region testAzModules
$testCommands = @('Get-AzContext', 'Get-AzPolicyDefinition', 'Search-AzGraph')
$azModules = @('Az.Accounts', 'Az.Resources', 'Az.ResourceGraph')

Write-Host "Testing required Az modules cmdlets"
foreach ($testCommand in $testCommands) {
    if (-not (Get-Command $testCommand -ErrorAction Ignore)) {
        if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
            Write-Error "AzModule test failed: cmdlet $testCommand not available - make sure the modules $($azModules -join ", ") are installed"
            Write-Error "Error"
        }
        else {
            Write-Host " AzModule test failed: cmdlet $testCommand not available - make sure the modules $($azModules -join ", ") are installed" -ForegroundColor Red
            Throw "Error - check the last console output for details"
        }
    }
    else {
        Write-Host " AzModule test passed: Az ps module supporting cmdlet $testCommand installed" -ForegroundColor Green
    }
}

Write-Host "Collecting Az modules versions"
foreach ($azModule in $azModules) {
    $azModuleVersion = (Get-InstalledModule -name "$azModule" -ErrorAction Ignore).Version
    if ($azModuleVersion) {
        Write-Host " Az Module $azModule Version: $azModuleVersion"
    }
    else {
        Write-Host " Az Module $azModule Version: could not be assessed"
    }
}
#endregion testAzModules

#check AzContext
#region checkAzContext
$checkContext = Get-AzContext -ErrorAction Stop
Write-Host "Checking Az Context"
if (-not $checkContext) {
    Write-Host " Context test failed: No context found. Please connect to Azure (run: Connect-AzAccount) and re-run AzGovViz" -ForegroundColor Red
    if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
        Write-Error "Error"
    }
    else {
        Throw "Error - check the last console output for details"
    }
}
else {
    $accountType = $checkContext.Account.Type
    $accountId = $checkContext.Account.id
    Write-Host " Context AccountId: '$($accountId)'" -ForegroundColor Yellow
    Write-Host " Context AccountType: '$($accountType)'" -ForegroundColor Yellow

    if (-not $checkContext.Subscription) {
        $checkContext
        Write-Host " Context test failed: Context is not set to any Subscription. Set your context to a subscription by running: Set-AzContext -subscription <subscriptionId> (run Get-AzSubscription to get the list of available Subscriptions). When done re-run AzGovViz" -ForegroundColor Red
        if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
            Write-Error "Error"
        }
        else {
            Throw "Error - check the last console output for details"
        }
    }
    else {
        Write-Host " Context test passed: Context OK" -ForegroundColor Green
    }
}
#endregion checkAzContext

#environment check
#region environmentcheck
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
$arrayAzureManagementEndPointUrls = @()
foreach ($checkAzEnvironment in $checkAzEnvironments) {
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name) = @{ }
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).ResourceManagerUrl = $checkAzEnvironment.ResourceManagerUrl
    $arrayAzureManagementEndPointUrls += $checkAzEnvironment.ResourceManagerUrl
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).ServiceManagementUrl = $checkAzEnvironment.ServiceManagementUrl
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).ActiveDirectoryAuthority = $checkAzEnvironment.ActiveDirectoryAuthority
    if ($checkAzEnvironment.Name -eq "AzureCloud") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).GraphUrl = "https://graph.microsoft.com"
    }
    if ($checkAzEnvironment.Name -eq "AzureChinaCloud") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).GraphUrl = "https://microsoftgraph.chinacloudapi.cn"
    }
    if ($checkAzEnvironment.Name -eq "AzureUSGovernment") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).GraphUrl = "https://graph.microsoft.us"
    }
    if ($checkAzEnvironment.Name -eq "AzureGermanCloud") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).GraphUrl = "https://graph.microsoft.de"
    }
}
#endregion environmentcheck

#create bearer token
createBearerToken -targetEndPoint "ManagementAPI"
#graphToken only required for certain scenarios
if (-not $NoAADGroupsResolveMembers -or -not $NoAADServicePrincipalResolve) {
    createBearerToken -targetEndPoint "GraphAPI"
}

#helper file/dir, delimiter, time
#region helper
#delimiter
if ($CsvDelimiter -eq ";") {
    $CsvDelimiterOpposite = ","
}
if ($CsvDelimiter -eq ",") {
    $CsvDelimiterOpposite = ";"
}
#endregion helper

#ManagementGroup helper
#region managementGroupHelper
#thx @Jim Britt https://github.com/JimGBritt/AzurePolicy/tree/master/AzureMonitor/Scripts Create-AzDiagPolicy.ps1
if (-not $ManagementGroupId) {
    $catchResult = "letscheck"
    try {
        $getAzManagementGroups = Get-AzManagementGroup -ErrorAction Stop
    }
    catch {
        $catchResult = $_.Exception.Message
    }
    if ($catchResult -ne "letscheck") {
        Write-Host "$catchResult"
        Throw "Error - check the last console output for details"
    }

    [array]$MgtGroupArray = Add-IndexNumberToArray ($getAzManagementGroups)
    if (-not $MgtGroupArray) {
        Write-Host "Seems you do not have access to any Management Group. Please make sure you have the required RBAC role [Reader] assigned on at least one Management Group" -ForegroundColor Red
        Throw "Error - check the last console output for details"
    }
    function selectMg() {
        Write-Host "Please select a Management Group from the list below:"
        $MgtGroupArray | Select-Object "#", Name, DisplayName, Id | Format-Table
        Write-Host "If you don't see your ManagementGroupID try using the parameter -ManagementGroupID" -ForegroundColor Yellow
        if ($msg) {
            Write-Host $msg -ForegroundColor Red
        }
        
        $script:SelectedMG = Read-Host "Please enter a selection from 1 to $(($MgtGroupArray | measure-object).count)"

        function IsNumeric ($Value) {
            return $Value -match "^[\d\.]+$"
        }
        if (IsNumeric $SelectedMG) {
            if ([int]$SelectedMG -lt 1 -or [int]$SelectedMG -gt ($MgtGroupArray | measure-object).count) {
                $msg = "last input '$SelectedMG' is out of range, enter a number from the selection!"
                selectMg
            }
        }
        else {
            $msg = "last input '$SelectedMG' is not numeric, enter a number from the selection!"
            selectMg
        }
    }
    selectMg

    if ($($MgtGroupArray[$SelectedMG - 1].Name)) {
        $ManagementGroupID = $($MgtGroupArray[$SelectedMG - 1].Name)
        $ManagementGroupName = $($MgtGroupArray[$SelectedMG - 1].DisplayName)
    }
    else {
        Write-Host "s.th. unexpected happened" -ForegroundColor Red
        return
    }
    Write-Host "Selected Management Group: $ManagementGroupName (Id: $ManagementGroupId)" -ForegroundColor Green
    Write-Host "_______________________________________"
}
#endregion managementGroupHelper

#region Function
function addRowToTable() {
    Param (
        [string]$level = 0, 
        [string]$mgName = "", 
        [string]$mgId = "", 
        [string]$mgParentId = "", 
        [string]$mgParentName = "", 
        [string]$Subscription = "", 
        [string]$SubscriptionId = "", 
        [string]$SubscriptionQuotaId = "", 
        [string]$SubscriptionState = "", 
        [string]$SubscriptionASCSecureScore = "", 
        [string]$SubscriptionTags = "", 
        [int]$SubscriptionTagsCount = 0, 
        [string]$Policy = "", 
        [string]$PolicyDescription = "",
        [string]$PolicyVariant = "", 
        [string]$PolicyType = "", 
        [string]$PolicyCategory = "", 
        [string]$PolicyDefinitionIdGuid = "", 
        [string]$PolicyDefinitionId = "", 
        [string]$PolicyDefintionScope = "", 
        [string]$PolicyDefintionScopeMgSub = "", 
        [string]$PolicyDefintionScopeId = "", 
        [int]$PolicyDefinitionsScopedLimit = 0, 
        [int]$PolicyDefinitionsScopedCount = 0, 
        [int]$PolicySetDefinitionsScopedLimit = 0, 
        [int]$PolicySetDefinitionsScopedCount = 0, 
        [string]$PolicyAssignmentScope = "", 
        [string]$PolicyAssignmentScopeMgSubRgRes = "",
        [string]$PolicyAssignmentScopeName = "",
        $PolicyAssignmentNotScopes = "", 
        [string]$PolicyAssignmentId = "", 
        [string]$PolicyAssignmentName = "", 
        [string]$PolicyAssignmentDisplayName = "", 
        [string]$PolicyAssignmentDescription = "",
        [string]$PolicyAssignmentIdentity = "", 
        [int]$PolicyAssigmentLimit = 0, 
        [int]$PolicyAssigmentCount = 0, 
        [int]$PolicyAssigmentAtScopeCount = 0,
        $PolicyAssigmentParameters,
        [int]$PolicySetAssigmentLimit = 0, 
        [int]$PolicySetAssigmentCount = 0, 
        [int]$PolicySetAssigmentAtScopeCount = 0, 
        [int]$PolicyAndPolicySetAssigmentAtScopeCount = 0, 
        [string]$RoleDefinitionId = "", 
        [string]$RoleDefinitionName = "",
        [string]$RoleAssignmentIdentityDisplayname = "", 
        [string]$RoleAssignmentIdentitySignInName = "", 
        [string]$RoleAssignmentIdentityObjectId = "", 
        [string]$RoleAssignmentIdentityObjectType = "", 
        [string]$RoleAssignmentId = "", 
        [string]$RoleAssignmentScope = "",
        [string]$RoleAssignmentScopeName = "", 
        [string]$RoleIsCustom = "", 
        [string]$RoleAssignableScopes = "", 
        [int]$RoleAssignmentsLimit = 0, 
        [int]$RoleAssignmentsCount = 0, 
        [string]$RoleActions = "", 
        [string]$RoleNotActions = "", 
        [string]$RoleDataActions = "", 
        [string]$RoleNotDataActions = "", 
        [int]$RoleSecurityCustomRoleOwner = 0, 
        [int]$RoleSecurityOwnerAssignmentSP = 0, 
        [string]$BlueprintName = "", 
        [string]$BlueprintId = "", 
        [string]$BlueprintDisplayName = "", 
        [string]$BlueprintDescription = "", 
        [string]$BlueprintScoped = "", 
        [string]$BlueprintAssignmentVersion = "",
        [string]$BlueprintAssignmentId = ""
    )
    
    $null = $script:newTable.Add([PSCustomObject]@{ 
            level                                   = $level 
            mgName                                  = $mgName 
            mgId                                    = $mgId 
            mgParentId                              = $mgParentId 
            mgParentName                            = $mgParentName 
            Subscription                            = $Subscription 
            SubscriptionId                          = $SubscriptionId 
            SubscriptionQuotaId                     = $SubscriptionQuotaId 
            SubscriptionState                       = $SubscriptionState 
            SubscriptionASCSecureScore              = $SubscriptionASCSecureScore 
            SubscriptionTags                        = $SubscriptionTags 
            SubscriptionTagsCount                   = $SubscriptionTagsCount
            Policy                                  = $Policy 
            PolicyDescription                       = $PolicyDescription
            PolicyVariant                           = $PolicyVariant
            PolicyType                              = $PolicyType 
            PolicyCategory                          = $PolicyCategory 
            PolicyDefinitionIdGuid                  = $PolicyDefinitionIdGuid 
            PolicyDefinitionId                      = $PolicyDefinitionId 
            PolicyDefintionScope                    = $PolicyDefintionScope 
            PolicyDefintionScopeMgSub               = $PolicyDefintionScopeMgSub 
            PolicyDefintionScopeId                  = $PolicyDefintionScopeId 
            PolicyDefinitionsScopedLimit            = $PolicyDefinitionsScopedLimit
            PolicyDefinitionsScopedCount            = $PolicyDefinitionsScopedCount
            PolicySetDefinitionsScopedLimit         = $PolicySetDefinitionsScopedLimit
            PolicySetDefinitionsScopedCount         = $PolicySetDefinitionsScopedCount
            PolicyAssignmentScope                   = $PolicyAssignmentScope 
            PolicyAssignmentScopeMgSubRgRes         = $PolicyAssignmentScopeMgSubRgRes
            PolicyAssignmentScopeName               = $PolicyAssignmentScopeName
            PolicyAssignmentNotScopes               = $PolicyAssignmentNotScopes 
            PolicyAssignmentId                      = $PolicyAssignmentId 
            PolicyAssignmentName                    = $PolicyAssignmentName 
            PolicyAssignmentDisplayName             = $PolicyAssignmentDisplayName 
            PolicyAssignmentDescription             = $PolicyAssignmentDescription
            PolicyAssignmentIdentity                = $PolicyAssignmentIdentity  
            PolicyAssigmentLimit                    = $PolicyAssigmentLimit
            PolicyAssigmentCount                    = $PolicyAssigmentCount
            PolicyAssigmentAtScopeCount             = $PolicyAssigmentAtScopeCount
            PolicyAssigmentParameters               = $PolicyAssigmentParameters
            PolicySetAssigmentLimit                 = $PolicySetAssigmentLimit
            PolicySetAssigmentCount                 = $PolicySetAssigmentCount
            PolicySetAssigmentAtScopeCount          = $PolicySetAssigmentAtScopeCount
            PolicyAndPolicySetAssigmentAtScopeCount = $PolicyAndPolicySetAssigmentAtScopeCount
            RoleDefinitionId                        = $RoleDefinitionId 
            RoleDefinitionName                      = $RoleDefinitionName
            RoleAssignmentIdentityDisplayname       = $RoleAssignmentIdentityDisplayname 
            RoleAssignmentIdentitySignInName        = $RoleAssignmentIdentitySignInName 
            RoleAssignmentIdentityObjectId          = $RoleAssignmentIdentityObjectId 
            RoleAssignmentIdentityObjectType        = $RoleAssignmentIdentityObjectType 
            RoleAssignmentId                        = $RoleAssignmentId 
            RoleAssignmentScope                     = $RoleAssignmentScope 
            RoleAssignmentScopeName                 = $RoleAssignmentScopeName
            RoleIsCustom                            = $RoleIsCustom 
            RoleAssignableScopes                    = $RoleAssignableScopes 
            RoleAssignmentsLimit                    = $RoleAssignmentsLimit
            RoleAssignmentsCount                    = $RoleAssignmentsCount
            RoleActions                             = $RoleActions 
            RoleNotActions                          = $RoleNotActions 
            RoleDataActions                         = $RoleDataActions 
            RoleNotDataActions                      = $RoleNotDataActions 
            RoleSecurityCustomRoleOwner             = $RoleSecurityCustomRoleOwner
            RoleSecurityOwnerAssignmentSP           = $RoleSecurityOwnerAssignmentSP
            BlueprintName                           = $BlueprintName 
            BlueprintId                             = $BlueprintId 
            BlueprintDisplayName                    = $BlueprintDisplayName 
            BlueprintDescription                    = $BlueprintDescription 
            BlueprintScoped                         = $BlueprintScoped 
            BlueprintAssignmentVersion              = $BlueprintAssignmentVersion
            BlueprintAssignmentId                   = $BlueprintAssignmentId
        })
}
$funcAddRowToTable = $function:addRowToTable.ToString()

#region Function_dataCollection

function dataCollection($mgId) {
    Write-Host " CustomDataCollection ManagementGroups"
    $startMgLoop = get-date
    
    $allManagementGroupsFromEntitiesChildOfRequestedMg = $arrayEntitiesFromAPI | Where-Object { $_.type -eq "Microsoft.Management/managementGroups" -and ($_.Name -eq $mgId -or $_.properties.parentNameChain -contains $mgId) }
    $allManagementGroupsFromEntitiesChildOfRequestedMgCount = ($allManagementGroupsFromEntitiesChildOfRequestedMg | Measure-Object).Count

    <#
    Write-Host "Management Groups to be processed:"
    foreach ($mg in $allManagementGroupsFromEntitiesChildOfRequestedMg){
        Write-Host " $($mg.name)"
    }
    #>

    $allManagementGroupsFromEntitiesChildOfRequestedMg | ForEach-Object -Parallel {
        $mgdetail = $_
        #region UsingVARs
        #Parameters MG&Sub related
        $CsvDelimiter = $using:CsvDelimiter
        #fromOtherFunctions
        $arrayAzureManagementEndPointUrls = $using:arrayAzureManagementEndPointUrls
        $checkContext = $using:checkContext
        $htAzureEnvironmentRelatedUrls = $using:htAzureEnvironmentRelatedUrls
        $htBearerAccessToken = $using:htBearerAccessToken
        #Array&HTs
        $htParameters = $using:htParameters
        $newTable = $using:newTable
        #$outOfScopeSubscriptions = $using:outOfScopeSubscriptions
        $resourcesAll = $using:resourcesAll
        $resourceGroupsAll = $using:resourceGroupsAll
        $arrayCachePolicyAssignmentsResourceGroupsAndResources = $using:arrayCachePolicyAssignmentsResourceGroupsAndResources
        $arrayCacheRoleAssignmentsResourceGroups = $using:arrayCacheRoleAssignmentsResourceGroups
        $customDataCollectionDuration = $using:customDataCollectionDuration
        $htResourceProvidersAll = $using:htResourceProvidersAll
        $htSubscriptionTagList = $using:htSubscriptionTagList
        $htResourceTypesUniqueResource = $using:htResourceTypesUniqueResource
        $htAllTagList = $using:htAllTagList
        $htSubscriptionTags = $using:htSubscriptionTags
        $htCacheDefinitions = $using:htCacheDefinitions
        $htCachePolicyCompliance = $using:htCachePolicyCompliance
        $htCacheDefinitionsAsIs = $using:htCacheDefinitionsAsIs
        $htCacheAssignments = $using:htCacheAssignments
        $htPolicyAssignmentExemptions = $using:htPolicyAssignmentExemptions
        $htResourceLocks = $using:htResourceLocks
        $LimitPOLICYPolicyDefinitionsScopedManagementGroup = $using:LimitPOLICYPolicyDefinitionsScopedManagementGroup
        $LimitPOLICYPolicySetDefinitionsScopedManagementGroup = $using:LimitPOLICYPolicySetDefinitionsScopedManagementGroup
        $LimitPOLICYPolicyAssignmentsManagementGroup = $using:LimitPOLICYPolicyAssignmentsManagementGroup
        $LimitPOLICYPolicySetAssignmentsManagementGroup = $using:LimitPOLICYPolicySetAssignmentsManagementGroup
        $LimitRBACRoleAssignmentsManagementGroup = $using:LimitRBACRoleAssignmentsManagementGroup
        $arrayEntitiesFromAPI = $using:arrayEntitiesFromAPI
        $allManagementGroupsFromEntitiesChildOfRequestedMg = $using:allManagementGroupsFromEntitiesChildOfRequestedMg
        $allManagementGroupsFromEntitiesChildOfRequestedMgCount = $using:allManagementGroupsFromEntitiesChildOfRequestedMgCount
        $arrayDataCollectionProgressMg = $using:arrayDataCollectionProgressMg
        $arrayAPICallTracking = $using:arrayAPICallTracking
        $arrayAPICallTrackingCustomDataCollection = $using:arrayAPICallTrackingCustomDataCollection
        #Functions
        $function:AzAPICall = $using:funcAzAPICall
        $function:createBearerToken = $using:funcCreateBearerToken
        $function:addRowToTable = $using:funcAddRowToTable
        $function:GetJWTDetails = $using:funcGetJWTDetails
        #endregion usingVARS

        $MgParentId = ($allManagementGroupsFromEntitiesChildOfRequestedMg | Where-Object { $_.Name -eq $mgdetail.Name }).properties.parent.id -replace ".*/"
        if ([string]::IsNullOrEmpty($MgParentId)) {
            $MgParentId = "TenantRoot"
            $MgParentName = "TenantRoot"
        }
        else {
            $MgParentName = ($arrayEntitiesFromAPI | Where-Object { $_.Name -eq $MgParentId }).Name
        }
        
        $hierarchyLevel = (($allManagementGroupsFromEntitiesChildOfRequestedMg | Where-Object { $_.Name -eq $mgdetail.Name }).properties.parentNameChain | Measure-Object).Count

        #Write-Host "processing $($mgdetail.Name)/$($mgdetail.properties.displayName); MgParentId $($MgParentId); MgParentName $($MgParentName); level $($hierarchyLevel)"

        $rndom = Get-Random -Minimum 10 -Maximum 750
        start-sleep -Millisecond $rndom
        $startMgLoopThis = get-date

        if ($htParameters.HierarchyMapOnly -eq $false) {         

            if ($htParameters.NoPolicyComplianceStates -eq $false) {
                #MGPolicyCompliance
                $currentTask = "Policy Compliance '$($mgdetail.properties.displayName)' ('$($mgdetail.Name)')"
                ($script:htCachePolicyCompliance).mg.($mgdetail.Name) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementGroups/$($mgdetail.Name)/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
                #$path = "/providers/Microsoft.Management/managementGroups/$($mgdetail.Name)/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
                $method = "POST"
    
                foreach ($policyAssignment in (((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))).policyassignments | sort-object -Property policyAssignmentId) {
                    #$policyAssignment
                    $policyAssignmentIdToLower = ($policyAssignment.policyAssignmentId).ToLower()
                    ($script:htCachePolicyCompliance).mg.($mgdetail.Name).($policyAssignmentIdToLower) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                    foreach ($policyComplianceState in $policyAssignment.results.policydetails) {
                        if ($policyComplianceState.ComplianceState -eq "compliant") {
                            ($script:htCachePolicyCompliance).mg.($mgdetail.Name).($policyAssignmentIdToLower).CompliantPolicies = $policyComplianceState.count
                        }
                        if ($policyComplianceState.ComplianceState -eq "noncompliant") {
                            ($script:htCachePolicyCompliance).mg.($mgdetail.Name).($policyAssignmentIdToLower).NonCompliantPolicies = $policyComplianceState.count
                        }
                    }
    
                    foreach ($resourceComplianceState in $policyAssignment.results.resourcedetails) {
                        if ($resourceComplianceState.ComplianceState -eq "compliant") {
                            ($script:htCachePolicyCompliance).mg.($mgdetail.Name).($policyAssignmentIdToLower).CompliantResources = $resourceComplianceState.count
                        }
                        if ($resourceComplianceState.ComplianceState -eq "nonCompliant") {
                            ($script:htCachePolicyCompliance).mg.($mgdetail.Name).($policyAssignmentIdToLower).NonCompliantResources = $resourceComplianceState.count
                        }
                    }
                }
            }
    
            #MGBlueprints
            $currentTask = "Blueprint definitions '$($mgdetail.properties.displayName)' ('$($mgdetail.Name)')"
            $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementGroups/$($mgdetail.Name)/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
            #$path = "/providers/Microsoft.Management/managementGroups/$($mgdetail.Name)/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
            $method = "GET"
    
            $mgBlueprintDefinitionResult = ""
            $mgBlueprintDefinitionResult = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
    
            if (($mgBlueprintDefinitionResult | measure-object).count -gt 0) {
                foreach ($blueprint in $mgBlueprintDefinitionResult) {
    
                    if (-not ($htCacheDefinitions).blueprint.($blueprint.id)) {
                        ($script:htCacheDefinitions).blueprint.($blueprint.id) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                        ($script:htCacheDefinitions).blueprint.($blueprint.id) = $blueprint
                    }  
    
                    $blueprintName = $blueprint.name
                    $blueprintId = $blueprint.id
                    $blueprintDisplayName = $blueprint.properties.displayName
                    $blueprintDescription = $blueprint.properties.description
                    $blueprintScoped = "/providers/Microsoft.Management/managementGroups/$($mgdetail.Name)"
                    addRowToTable `
                        -level $hierarchyLevel `
                        -mgName $mgdetail.properties.displayName `
                        -mgId $mgdetail.Name `
                        -mgParentId $mgParentId `
                        -mgParentName $mgParentName `
                        -BlueprintName $blueprintName `
                        -BlueprintId $blueprintId `
                        -BlueprintDisplayName $blueprintDisplayName `
                        -BlueprintDescription $blueprintDescription `
                        -BlueprintScoped $blueprintScoped
                }
            }
    
            $currentTask = "Policy exemptions '$($mgdetail.properties.displayName)' ('$($mgdetail.Name)')"
            $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementGroups/$($mgdetail.Name)/providers/Microsoft.Authorization/policyExemptions?api-version=2020-07-01-preview&`$filter=atScope()"
            #$path = "/subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
            $method = "GET"
    
            $requestPolicyExemptionAPI = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
            $requestPolicyExemptionAPICount = ($requestPolicyExemptionAPI | Measure-Object).Count
            if ($requestPolicyExemptionAPICount -gt 0) {
                foreach ($exemption in $requestPolicyExemptionAPI) {
                    if (-not $htPolicyAssignmentExemptions.($exemption.id)) {
                        $script:htPolicyAssignmentExemptions.($exemption.id) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                        $script:htPolicyAssignmentExemptions.($exemption.id).exemption = $exemption
                    }
                }
            }
    
            #MGCustomPolicies
            $currentTask = "Custom Policy definitions '$($mgdetail.properties.displayName)' ('$($mgdetail.Name)')"
            $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementgroups/$($mgdetail.Name)/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
            #$path = "/providers/Microsoft.Management/managementgroups/$($mgdetail.Name)/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
            $method = "GET"
    
            $requestPolicyDefinitionAPI = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
            $mgPolicyDefinitions = $requestPolicyDefinitionAPI | Where-Object { $_.properties.policyType -eq "custom" }
            $PolicyDefinitionsScopedCount = (($mgPolicyDefinitions | Where-Object { ($_.id) -like "/providers/Microsoft.Management/managementGroups/$($mgdetail.Name)/*" }) | measure-object).count
            foreach ($mgPolicyDefinition in $mgPolicyDefinitions) {
                if (-not $($htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower())) {
                    if (($mgPolicyDefinition.Properties.description).length -eq 0) {
                        $policyDefinitionDescription = "no description given"
                    }
                    else {
                        $policyDefinitionDescription = $mgPolicyDefinition.Properties.description
                    }
                    ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                    ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).id = ($mgPolicyDefinition.id).ToLower()
                    ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).Scope = (($mgPolicyDefinition.id) -split "\/")[0..4] -join "/"
                    ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).ScopeMgSub = "Mg"
                    ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).ScopeId = (($mgPolicyDefinition.id) -split "\/")[4]
                    ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).DisplayName = $($mgPolicyDefinition.Properties.displayname)
                    ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).Description = $($policyDefinitionDescription)
                    ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).Type = $($mgPolicyDefinition.Properties.policyType)
                    ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).Category = $($mgPolicyDefinition.Properties.metadata.Category)
                    ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).PolicyDefinitionId = ($mgPolicyDefinition.id).ToLower()
                    
                    if ($mgPolicyDefinition.Properties.metadata.deprecated -eq $true -or $mgPolicyDefinition.Properties.displayname -like "``[Deprecated``]*") {
                        ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).Deprecated = $mgPolicyDefinition.Properties.metadata.deprecated
                    }
                    else {
                        ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).Deprecated = $false
                    }
                    if ($mgPolicyDefinition.Properties.metadata.preview -eq $true -or $mgPolicyDefinition.Properties.displayname -like "``[*Preview``]*") {
                        ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).Preview = $mgPolicyDefinition.Properties.metadata.preview
                    }
                    else {
                        ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).Preview = $false
                    }

                    #effects
                    if ($mgPolicyDefinition.properties.parameters.effect.defaultvalue) {
                        ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).effectDefaultValue = $mgPolicyDefinition.properties.parameters.effect.defaultvalue
                        if ($mgPolicyDefinition.properties.parameters.effect.allowedValues) {
                            ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).effectAllowedValue = $mgPolicyDefinition.properties.parameters.effect.allowedValues -join ","
                        }
                        else {
                            ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).effectAllowedValue = "n/a"
                        }
                        ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).effectFixedValue = "n/a"
                    }
                    else {
                        if ($mgPolicyDefinition.properties.parameters.policyEffect.defaultValue) {
                            ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).effectDefaultValue = $mgPolicyDefinition.properties.parameters.policyEffect.defaultvalue
                            if ($mgPolicyDefinition.properties.parameters.policyEffect.allowedValues) {
                                ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).effectAllowedValue = $mgPolicyDefinition.properties.parameters.policyEffect.allowedValues -join ","
                            }
                            else {
                                ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).effectAllowedValue = "n/a"
                            }
                            ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).effectFixedValue = "n/a"
                        }
                        else {
                            ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).effectFixedValue = $mgPolicyDefinition.Properties.policyRule.then.effect
                            ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).effectDefaultValue = "n/a"
                            ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).effectAllowedValue = "n/a"
                        }
                    }
                    ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).json = $mgPolicyDefinition

                    if ($mgPolicyDefinition.properties.policyRule.then.details.roleDefinitionIds) {
                        ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).RoleDefinitionIds = $mgPolicyDefinition.properties.policyRule.then.details.roleDefinitionIds
                    }
                    else {
                        ($script:htCacheDefinitions).policy.(($mgPolicyDefinition.id).ToLower()).RoleDefinitionIds  = "n/a"
                    }
                }
                if (-not $($htCacheDefinitionsAsIs).policy[$mgPolicyDefinition.id]) {
                    ($script:htCacheDefinitionsAsIs).policy.(($mgPolicyDefinition.id).ToLower()) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                    ($script:htCacheDefinitionsAsIs).policy.(($mgPolicyDefinition.id).ToLower()) = $mgPolicyDefinition
                }  
            }
    
            #MGPolicySets
            $currentTask = "Custom PolicySet definitions '$($mgdetail.properties.displayName)' ('$($mgdetail.Name)')"
            $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementgroups/$($mgdetail.Name)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"
            #$path = "/providers/Microsoft.Management/managementgroups/$($mgdetail.Name)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"
            $method = "GET"
            
            $requestPolicySetDefinitionAPI = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
            $mgPolicySetDefinitions = $requestPolicySetDefinitionAPI | Where-Object { $_.properties.policyType -eq "custom" }
            $PolicySetDefinitionsScopedCount = (($mgPolicySetDefinitions | Where-Object { ($_.id) -like "/providers/Microsoft.Management/managementGroups/$($mgdetail.Name)/*" }) | measure-object).count
            foreach ($mgPolicySetDefinition in $mgPolicySetDefinitions) {
                if (-not $($htCacheDefinitions).policySet.(($mgPolicySetDefinition.id).ToLower())) {
                    if (($mgPolicySetDefinition.Properties.description).length -eq 0) {
                        $policySetDefinitionDescription = "no description given"
                    }
                    else {
                        $policySetDefinitionDescription = $mgPolicySetDefinition.Properties.description
                    }
                    ($script:htCacheDefinitions).policySet.(($mgPolicySetDefinition.id).ToLower()) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                    ($script:htCacheDefinitions).policySet.(($mgPolicySetDefinition.id).ToLower()).id = ($mgPolicySetDefinition.id).ToLower()
                    ($script:htCacheDefinitions).policySet.(($mgPolicySetDefinition.id).ToLower()).Scope = (($mgPolicySetDefinition.id) -split "\/")[0..4] -join "/"
                    ($script:htCacheDefinitions).policySet.(($mgPolicySetDefinition.id).ToLower()).ScopeMgSub = "Mg"
                    ($script:htCacheDefinitions).policySet.(($mgPolicySetDefinition.id).ToLower()).ScopeId = (($mgPolicySetDefinition.id) -split "\/")[4]
                    ($script:htCacheDefinitions).policySet.(($mgPolicySetDefinition.id).ToLower()).DisplayName = $($mgPolicySetDefinition.Properties.displayname)
                    ($script:htCacheDefinitions).policySet.(($mgPolicySetDefinition.id).ToLower()).Description = $($policySetDefinitionDescription)
                    ($script:htCacheDefinitions).policySet.(($mgPolicySetDefinition.id).ToLower()).Type = $($mgPolicySetDefinition.Properties.policyType)
                    ($script:htCacheDefinitions).policySet.(($mgPolicySetDefinition.id).ToLower()).Category = $($mgPolicySetDefinition.Properties.metadata.Category)
                    ($script:htCacheDefinitions).policySet.(($mgPolicySetDefinition.id).ToLower()).PolicyDefinitionId = ($mgPolicySetDefinition.id).ToLower()
                    $arrayPolicySetPolicyIdsToLower = @()
                    $arrayPolicySetPolicyIdsToLower = foreach ($policySetPolicy in $mgPolicySetDefinition.properties.policydefinitions.policyDefinitionId) {
                        ($policySetPolicy).ToLower()
                    }
                    ($script:htCacheDefinitions).policySet.(($mgPolicySetDefinition.id).ToLower()).PolicySetPolicyIds = $arrayPolicySetPolicyIdsToLower
                    ($script:htCacheDefinitions).policySet.(($mgPolicySetDefinition.id).ToLower()).json = $mgPolicySetDefinition
                    if ($mgPolicySetDefinition.Properties.metadata.deprecated -eq $true -or $mgPolicySetDefinition.Properties.displayname -like "``[Deprecated``]*") {
                        ($script:htCacheDefinitions).policySet.(($mgPolicySetDefinition.id).ToLower()).Deprecated = $mgPolicySetDefinition.Properties.metadata.deprecated
                    }
                    else {
                        ($script:htCacheDefinitions).policySet.(($mgPolicySetDefinition.id).ToLower()).Deprecated = $false
                    }
                    if ($mgPolicySetDefinition.Properties.metadata.preview -eq $true -or $mgPolicySetDefinition.Properties.displayname -like "``[*Preview``]*") {
                        ($script:htCacheDefinitions).policySet.(($mgPolicySetDefinition.id).ToLower()).Preview = $mgPolicySetDefinition.Properties.metadata.preview
                    }
                    else {
                        ($script:htCacheDefinitions).policySet.(($mgPolicySetDefinition.id).ToLower()).Preview = $false
                    }
                    
                }  
            }
    
            #MgPolicyAssignments
            $currentTask = "Policy assignments '$($mgdetail.properties.displayName)' ('$($mgdetail.Name)')"
            $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementgroups/$($mgdetail.Name)/providers/Microsoft.Authorization/policyAssignments?`$filter=atscope()&api-version=2019-09-01"
            #$path = "/providers/Microsoft.Management/managementgroups/$($mgdetail.Name)/providers/Microsoft.Authorization/policyAssignments?`$filter=atscope()&api-version=2019-09-01"
            $method = "GET"
           
            $L0mgmtGroupPolicyAssignments = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
            $L0mgmtGroupPolicyAssignmentsPolicyCount = (($L0mgmtGroupPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" }) | measure-object).count
            $L0mgmtGroupPolicyAssignmentsPolicySetCount = (($L0mgmtGroupPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" }) | measure-object).count
            $L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount = (($L0mgmtGroupPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -and $_.id -match "/providers/Microsoft.Management/managementGroups/$($mgdetail.Name)" }) | measure-object).count
            $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount = (($L0mgmtGroupPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" -and $_.id -match "/providers/Microsoft.Management/managementGroups/$($mgdetail.Name)" }) | measure-object).count
            $L0mgmtGroupPolicyAssignmentsPolicyAndPolicySetAtScopeCount = ($L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount + $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount)
            foreach ($L0mgmtGroupPolicyAssignment in $L0mgmtGroupPolicyAssignments) {
                
                if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -OR $L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
                    if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/") {
                        $PolicyVariant = "Policy"
                        $definitiontype = "policy"
                        $Id = ($L0mgmtGroupPolicyAssignment.properties.policydefinitionid).ToLower()
                        $Def = ($htCacheDefinitions).($definitiontype).($Id)
                        $PolicyAssignmentScope = $L0mgmtGroupPolicyAssignment.Properties.Scope
                        $PolicyAssignmentNotScopes = $L0mgmtGroupPolicyAssignment.Properties.NotScopes -join "$CsvDelimiterOpposite "
                        $PolicyAssignmentId = $L0mgmtGroupPolicyAssignment.id
                        $PolicyAssignmentName = $L0mgmtGroupPolicyAssignment.Name
                        $PolicyAssignmentDisplayName = $L0mgmtGroupPolicyAssignment.Properties.DisplayName
                        if (($L0mgmtGroupPolicyAssignment.Properties.Description).length -eq 0) {
                            $PolicyAssignmentDescription = "no description given"
                        }
                        else {
                            $PolicyAssignmentDescription = $L0mgmtGroupPolicyAssignment.Properties.Description
                        }
    
                        if ($L0mgmtGroupPolicyAssignment.identity) {
                            $PolicyAssignmentIdentity = $L0mgmtGroupPolicyAssignment.identity.principalId
                        }
                        else {
                            $PolicyAssignmentIdentity = "n/a"
                        }
    
                        if ($Def.Type -eq "Custom") {
                            $policyDefintionScope = $Def.Scope
                            $policyDefintionScopeMgSub = $Def.ScopeMgSub
                            $policyDefintionScopeId = $Def.ScopeId
                        }
                        else {
                            $policyDefintionScope = "n/a"
                            $policyDefintionScopeMgSub = "n/a"
                            $policyDefintionScopeId = "n/a"
                        }
    
                        addRowToTable `
                            -level $hierarchyLevel `
                            -mgName $mgdetail.properties.displayName `
                            -mgId $mgdetail.Name `
                            -mgParentId $mgParentId `
                            -mgParentName $mgParentName `
                            -Policy $Def.DisplayName `
                            -PolicyDescription $Def.Description `
                            -PolicyVariant $PolicyVariant `
                            -PolicyType $Def.Type `
                            -PolicyCategory $Def.Category `
                            -PolicyDefinitionIdGuid (($Def.id) -replace ".*/") `
                            -PolicyDefinitionId $Def.PolicyDefinitionId `
                            -PolicyDefintionScope $policyDefintionScope `
                            -PolicyDefintionScopeMgSub $policyDefintionScopeMgSub `
                            -PolicyDefintionScopeId $policyDefintionScopeId `
                            -PolicyDefinitionsScopedLimit $LimitPOLICYPolicyDefinitionsScopedManagementGroup `
                            -PolicyDefinitionsScopedCount $PolicyDefinitionsScopedCount `
                            -PolicySetDefinitionsScopedLimit $LimitPOLICYPolicySetDefinitionsScopedManagementGroup `
                            -PolicySetDefinitionsScopedCount $PolicySetDefinitionsScopedCount `
                            -PolicyAssignmentScope $PolicyAssignmentScope `
                            -PolicyAssignmentScopeMgSubRgRes "Mg" `
                            -PolicyAssignmentScopeName ($PolicyAssignmentScope -replace ".*/", "") `
                            -PolicyAssignmentNotScopes $L0mgmtGroupPolicyAssignment.Properties.NotScopes `
                            -PolicyAssignmentId $PolicyAssignmentId `
                            -PolicyAssignmentName $PolicyAssignmentName `
                            -PolicyAssignmentDisplayName $PolicyAssignmentDisplayName `
                            -PolicyAssignmentDescription $PolicyAssignmentDescription `
                            -PolicyAssignmentIdentity $PolicyAssignmentIdentity `
                            -PolicyAssigmentLimit $LimitPOLICYPolicyAssignmentsManagementGroup `
                            -PolicyAssigmentCount $L0mgmtGroupPolicyAssignmentsPolicyCount `
                            -PolicyAssigmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount `
                            -PolicyAssigmentParameters $L0mgmtGroupPolicyAssignment.Properties.Parameters `
                            -PolicySetAssigmentLimit $LimitPOLICYPolicySetAssignmentsManagementGroup `
                            -PolicySetAssigmentCount $L0mgmtGroupPolicyAssignmentsPolicySetCount `
                            -PolicySetAssigmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount `
                            -PolicyAndPolicySetAssigmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicyAndPolicySetAtScopeCount
                    }
    
                    if ($L0mgmtGroupPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
                        $PolicyVariant = "PolicySet"
                        $definitiontype = "policySet"
                        $Id = ($L0mgmtGroupPolicyAssignment.properties.policydefinitionid).ToLower()
                        $Def = ($htCacheDefinitions).($definitiontype).($Id)
                        $PolicyAssignmentScope = $L0mgmtGroupPolicyAssignment.Properties.Scope
                        $PolicyAssignmentNotScopes = $L0mgmtGroupPolicyAssignment.Properties.NotScopes -join "$CsvDelimiterOpposite "
                        $PolicyAssignmentId = $L0mgmtGroupPolicyAssignment.id
                        $PolicyAssignmentName = $L0mgmtGroupPolicyAssignment.Name
                        $PolicyAssignmentDisplayName = $L0mgmtGroupPolicyAssignment.Properties.DisplayName
                        if (($L0mgmtGroupPolicyAssignment.Properties.Description).length -eq 0) {
                            $PolicyAssignmentDescription = "no description given"
                        }
                        else {
                            $PolicyAssignmentDescription = $L0mgmtGroupPolicyAssignment.Properties.Description
                        }
    
                        if ($L0mgmtGroupPolicyAssignment.identity) {
                            $PolicyAssignmentIdentity = $L0mgmtGroupPolicyAssignment.identity.principalId
                        }
                        else {
                            $PolicyAssignmentIdentity = "n/a"
                        }
    
                        if ($Def.Type -eq "Custom") {
                            $policyDefintionScope = $Def.Scope
                            $policyDefintionScopeMgSub = $Def.ScopeMgSub
                            $policyDefintionScopeId = $Def.ScopeId
                        }
                        else {
                            $policyDefintionScope = "n/a"
                            $policyDefintionScopeMgSub = "n/a"
                            $policyDefintionScopeId = "n/a"
                        }
    
                        addRowToTable `
                            -level $hierarchyLevel `
                            -mgName $mgdetail.properties.displayName `
                            -mgId $mgdetail.Name `
                            -mgParentId $mgParentId `
                            -mgParentName $mgParentName `
                            -Policy $Def.DisplayName `
                            -PolicyDescription $Def.Description `
                            -PolicyVariant $PolicyVariant `
                            -PolicyType $Def.Type `
                            -PolicyCategory $Def.Category `
                            -PolicyDefinitionIdGuid (($Def.id) -replace ".*/") `
                            -PolicyDefinitionId $Def.PolicyDefinitionId `
                            -PolicyDefintionScope $policyDefintionScope `
                            -PolicyDefintionScopeMgSub $policyDefintionScopeMgSub `
                            -PolicyDefintionScopeId $policyDefintionScopeId `
                            -PolicyDefinitionsScopedLimit $LimitPOLICYPolicyDefinitionsScopedManagementGroup `
                            -PolicyDefinitionsScopedCount $PolicyDefinitionsScopedCount `
                            -PolicySetDefinitionsScopedLimit $LimitPOLICYPolicySetDefinitionsScopedManagementGroup `
                            -PolicySetDefinitionsScopedCount $PolicySetDefinitionsScopedCount `
                            -PolicyAssignmentScope $PolicyAssignmentScope `
                            -PolicyAssignmentScopeMgSubRgRes "Mg" `
                            -PolicyAssignmentScopeName ($PolicyAssignmentScope -replace ".*/", "") `
                            -PolicyAssignmentNotScopes $L0mgmtGroupPolicyAssignment.Properties.NotScopes `
                            -PolicyAssignmentId $PolicyAssignmentId `
                            -PolicyAssignmentName $PolicyAssignmentName `
                            -PolicyAssignmentDisplayName $PolicyAssignmentDisplayName `
                            -PolicyAssignmentDescription $PolicyAssignmentDescription `
                            -PolicyAssignmentIdentity $PolicyAssignmentIdentity `
                            -PolicyAssigmentLimit $LimitPOLICYPolicyAssignmentsManagementGroup `
                            -PolicyAssigmentCount $L0mgmtGroupPolicyAssignmentsPolicyCount `
                            -PolicyAssigmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount `
                            -PolicyAssigmentParameters $L0mgmtGroupPolicyAssignment.Properties.Parameters `
                            -PolicySetAssigmentLimit $LimitPOLICYPolicySetAssignmentsManagementGroup `
                            -PolicySetAssigmentCount $L0mgmtGroupPolicyAssignmentsPolicySetCount `
                            -PolicySetAssigmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount `
                            -PolicyAndPolicySetAssigmentAtScopeCount $L0mgmtGroupPolicyAssignmentsPolicyAndPolicySetAtScopeCount
                    }
                }
                else {
                    #s.th unexpected
                    Write-Host "  CustomDataCollection ManagementGroups: unexpected"
                    return
                } 
            }
    
            #MGCustomRolesRoles
            $currentTask = "Custom Role definitions '$($mgdetail.properties.displayName)' ('$($mgdetail.Name)')"
            $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementGroups/$($mgdetail.Name)/providers/Microsoft.Authorization/roleDefinitions?api-version=2015-07-01&`$filter=type%20eq%20'CustomRole'"
            #$path = "/providers/Microsoft.Management/managementGroups/$($mgdetail.Name)/providers/Microsoft.Authorization/roleDefinitions?api-version=2015-07-01&`$filter=type%20eq%20'CustomRole'"
            $method = "GET"
            
            $mgCustomRoleDefinitions = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
            foreach ($mgCustomRoleDefinition in $mgCustomRoleDefinitions) {
                if (-not $($htCacheDefinitions).role[$mgCustomRoleDefinition.name]) {
                    ($script:htCacheDefinitions).role.$($mgCustomRoleDefinition.name) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                    ($script:htCacheDefinitions).role.$($mgCustomRoleDefinition.name).id = $($mgCustomRoleDefinition.name)
                    ($script:htCacheDefinitions).role.$($mgCustomRoleDefinition.name).Name = $($mgCustomRoleDefinition.properties.roleName)
                    ($script:htCacheDefinitions).role.$($mgCustomRoleDefinition.name).IsCustom = $true
                    ($script:htCacheDefinitions).role.$($mgCustomRoleDefinition.name).AssignableScopes = $($mgCustomRoleDefinition.properties.AssignableScopes)
                    ($script:htCacheDefinitions).role.$($mgCustomRoleDefinition.name).Actions = $($mgCustomRoleDefinition.properties.permissions.Actions)
                    ($script:htCacheDefinitions).role.$($mgCustomRoleDefinition.name).NotActions = $($mgCustomRoleDefinition.properties.permissions.NotActions)
                    ($script:htCacheDefinitions).role.$($mgCustomRoleDefinition.name).DataActions = $($mgCustomRoleDefinition.properties.permissions.DataActions)
                    ($script:htCacheDefinitions).role.$($mgCustomRoleDefinition.name).NotDataActions = $($mgCustomRoleDefinition.properties.permissions.NotDataActions)
                    ($script:htCacheDefinitions).role.$($mgCustomRoleDefinition.name).json = $mgCustomRoleDefinition
                }  
            }
    
            #cmdletgetazroleassignment
            $retryCmletCount = 0
            do {
                $errorOccurred = "no"
                $retryCmletCount++
                try {
                    $L0mgmtGroupRoleAssignments = Get-AzRoleAssignment -scope "/providers/Microsoft.Management/managementGroups/$($mgdetail.Name)" -ErrorAction SilentlyContinue
                }
                catch {
                    $errorOccurred = "yes"
                }
                if ($errorOccurred -ne "no") {
                    Write-Host "try#$($retryCmletCount) cmdlet Get-AzRoleAssignment ManagementGroup '$($mgdetail.Name)' failed, retry in $($retryCmletCount) seconds"
                    start-sleep -Seconds $retryCmletCount
                }
            }
            until($errorOccurred -eq "no")
    
            $L0mgmtGroupRoleAssignmentsLimitUtilization = (($L0mgmtGroupRoleAssignments | Where-Object { $_.Scope -eq "/providers/Microsoft.Management/managementGroups/$($mgdetail.Name)" }) | measure-object).count
            foreach ($L0mgmtGroupRoleAssignment in $L0mgmtGroupRoleAssignments) {
                
                if (-not $($htCacheAssignments).role[$L0mgmtGroupRoleAssignment.RoleAssignmentId]) {
                    $($script:htCacheAssignments).role.$($L0mgmtGroupRoleAssignment.RoleAssignmentId) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                    $($script:htCacheAssignments).role.$($L0mgmtGroupRoleAssignment.RoleAssignmentId) = $L0mgmtGroupRoleAssignment
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
                    $RoleAssignmentIdentityDisplayname = "n/a" 
                }
                else {
                    if ($L0mgmtGroupRoleAssignment.ObjectType -eq "User") {
                        if ($htParameters.DoNotShowRoleAssignmentsUserData -eq $false) {
                            $RoleAssignmentIdentityDisplayname = $L0mgmtGroupRoleAssignment.DisplayName
                        }
                        else {
                            $RoleAssignmentIdentityDisplayname = "scrubbed"
                        }
                    }
                    else {
                        $RoleAssignmentIdentityDisplayname = $L0mgmtGroupRoleAssignment.DisplayName
                    }
                }                
                if (($L0mgmtGroupRoleAssignment.SignInName).length -eq 0) {
                    $RoleAssignmentIdentitySignInName = "n/a" 
                }
                else {
                    if ($L0mgmtGroupRoleAssignment.ObjectType -eq "User") {
                        if ($htParameters.DoNotShowRoleAssignmentsUserData -eq $false) {
                            $RoleAssignmentIdentitySignInName = $L0mgmtGroupRoleAssignment.SignInName
                        }
                        else {
                            $RoleAssignmentIdentitySignInName = "scrubbed"
                        }
                    }
                    else {
                        $RoleAssignmentIdentitySignInName = $L0mgmtGroupRoleAssignment.SignInName
                    }
                }
                $RoleAssignmentIdentityObjectId = $L0mgmtGroupRoleAssignment.ObjectId
                $RoleAssignmentIdentityObjectType = $L0mgmtGroupRoleAssignment.ObjectType
                $RoleAssignmentId = $L0mgmtGroupRoleAssignment.RoleAssignmentId
                $RoleAssignmentScope = $L0mgmtGroupRoleAssignment.Scope
                $RoleAssignmentScopeName = $RoleAssignmentScope -replace '.*/'
    
                $RoleSecurityCustomRoleOwner = 0
                if (($htCacheDefinitions).$definitiontype.$($Id).Actions -eq '*' -and ((($htCacheDefinitions).$definitiontype.$($Id).NotActions)).length -eq 0 -and ($htCacheDefinitions).$definitiontype.$($Id).IsCustom -eq $True) {
                    $RoleSecurityCustomRoleOwner = 1
                }
                $RoleSecurityOwnerAssignmentSP = 0
                if ((($htCacheDefinitions).$definitiontype.$($Id).id -eq '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' -and $RoleAssignmentIdentityObjectType -eq "ServicePrincipal") -or (($htCacheDefinitions).$definitiontype.$($Id).Actions -eq '*' -and ((($htCacheDefinitions).$definitiontype.$($Id).NotActions)).length -eq 0 -and ($htCacheDefinitions).$definitiontype.$($Id).IsCustom -eq $True -and $RoleAssignmentIdentityObjectType -eq "ServicePrincipal")) {
                    $RoleSecurityOwnerAssignmentSP = 1
                }
    
                addRowToTable `
                    -level $hierarchyLevel `
                    -mgName $mgdetail.properties.displayName `
                    -mgId $mgdetail.Name `
                    -mgParentId $mgParentId `
                    -mgParentName $mgParentName `
                    -RoleDefinitionId ($htCacheDefinitions).$definitiontype.$($Id).id `
                    -RoleDefinitionName $RoleDefinitionName `
                    -RoleIsCustom ($htCacheDefinitions).$definitiontype.$($Id).IsCustom `
                    -RoleAssignableScopes (($htCacheDefinitions).$definitiontype.$($Id).AssignableScopes -join "$CsvDelimiterOpposite ") `
                    -RoleActions (($htCacheDefinitions).$definitiontype.$($Id).Actions -join "$CsvDelimiterOpposite ") `
                    -RoleNotActions (($htCacheDefinitions).$definitiontype.$($Id).NotActions -join "$CsvDelimiterOpposite ") `
                    -RoleDataActions (($htCacheDefinitions).$definitiontype.$($Id).DataActions -join "$CsvDelimiterOpposite ") `
                    -RoleNotDataActions (($htCacheDefinitions).$definitiontype.$($Id).NotDataActions -join "$CsvDelimiterOpposite ") `
                    -RoleAssignmentIdentityDisplayname $RoleAssignmentIdentityDisplayname `
                    -RoleAssignmentIdentitySignInName $RoleAssignmentIdentitySignInName `
                    -RoleAssignmentIdentityObjectId $RoleAssignmentIdentityObjectId `
                    -RoleAssignmentIdentityObjectType $RoleAssignmentIdentityObjectType `
                    -RoleAssignmentId $RoleAssignmentId `
                    -RoleAssignmentScope $RoleAssignmentScope `
                    -RoleAssignmentScopeName $RoleAssignmentScopeName `
                    -RoleAssignmentsLimit $LimitRBACRoleAssignmentsManagementGroup `
                    -RoleAssignmentsCount $L0mgmtGroupRoleAssignmentsLimitUtilization `
                    -RoleSecurityCustomRoleOwner $RoleSecurityCustomRoleOwner `
                    -RoleSecurityOwnerAssignmentSP $RoleSecurityOwnerAssignmentSP
            }
        }
        else {
            addRowToTable `
                -level $hierarchyLevel `
                -mgName $mgdetail.properties.displayName `
                -mgId $mgdetail.Name `
                -mgParentId $mgParentId `
                -mgParentName $mgParentName
        }


        $endMgLoopThis = get-date
        $null = $script:customDataCollectionDuration.Add([PSCustomObject]@{ 
                Type        = "Mg"
                Id          = $mgdetail.Name
                DurationSec = (NEW-TIMESPAN -Start $startMgLoopThis -End $endMgLoopThis).TotalSeconds
            })

        $null = $script:arrayDataCollectionProgressMg.Add($mgdetail.Name)
        $progressCount = ($arrayDataCollectionProgressMg).Count
        Write-Host "  $($progressCount)/$($allManagementGroupsFromEntitiesChildOfRequestedMgCount) ManagementGroups processed"

    } -ThrottleLimit $ThrottleLimit

    $endMgLoop = get-date
    Write-Host " CustomDataCollection ManagementGroups processing duration: $((NEW-TIMESPAN -Start $startMgLoop -End $endMgLoop).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startMgLoop -End $endMgLoop).TotalSeconds) seconds)"


    #SUBSCRIPTION
    Write-Host " CustomDataCollection Subscriptions"
    $childrenSubscriptions = $arrayEntitiesFromAPI | Where-Object { $_.properties.parentNameChain -contains $mgid -and $_.type -eq "/subscriptions" }
    $childrenSubscriptionsCount = ($childrenSubscriptions | Measure-Object).Count
    $startSubLoop = get-date
    if ($childrenSubscriptionsCount -gt 0) {

        $childrenSubscriptions | ForEach-Object -Parallel {
            $startSubLoopThis = get-date
            $childMgSubDetail = $_
            #region UsingVARs
            #Parameters MG&Sub related
            $CsvDelimiter = $using:CsvDelimiter
            #Parameters Sub related
            $SubscriptionQuotaIdWhitelist = $using:SubscriptionQuotaIdWhitelist
            #fromOtherFunctions
            $arrayAzureManagementEndPointUrls = $using:arrayAzureManagementEndPointUrls
            $checkContext = $using:checkContext
            $htAzureEnvironmentRelatedUrls = $using:htAzureEnvironmentRelatedUrls
            $htBearerAccessToken = $using:htBearerAccessToken
            #Array&HTs
            $htParameters = $using:htParameters
            $newTable = $using:newTable
            $outOfScopeSubscriptions = $using:outOfScopeSubscriptions
            $resourcesAll = $using:resourcesAll
            $resourceGroupsAll = $using:resourceGroupsAll
            $arrayCachePolicyAssignmentsResourceGroupsAndResources = $using:arrayCachePolicyAssignmentsResourceGroupsAndResources
            $arrayCacheRoleAssignmentsResourceGroups = $using:arrayCacheRoleAssignmentsResourceGroups
            $customDataCollectionDuration = $using:customDataCollectionDuration
            $htResourceProvidersAll = $using:htResourceProvidersAll
            $htSubscriptionTagList = $using:htSubscriptionTagList
            $htResourceTypesUniqueResource = $using:htResourceTypesUniqueResource
            $htAllTagList = $using:htAllTagList
            $htSubscriptionTags = $using:htSubscriptionTags
            $htCacheDefinitions = $using:htCacheDefinitions
            $htCachePolicyCompliance = $using:htCachePolicyCompliance
            $htCacheDefinitionsAsIs = $using:htCacheDefinitionsAsIs
            $htCacheAssignments = $using:htCacheAssignments
            $htPolicyAssignmentExemptions = $using:htPolicyAssignmentExemptions
            $htResourceLocks = $using:htResourceLocks
            $LimitPOLICYPolicyDefinitionsScopedSubscription = $using:LimitPOLICYPolicyDefinitionsScopedSubscription
            $LimitPOLICYPolicySetDefinitionsScopedSubscription = $using:LimitPOLICYPolicySetDefinitionsScopedSubscription
            $LimitPOLICYPolicyAssignmentsSubscription = $using:LimitPOLICYPolicyAssignmentsSubscription
            $LimitPOLICYPolicySetAssignmentsSubscription = $using:LimitPOLICYPolicySetAssignmentsSubscription
            $childrenSubscriptionsCount = $using:childrenSubscriptionsCount
            $arrayDataCollectionProgressSub = $using:arrayDataCollectionProgressSub
            $htAllSubscriptionsFromAPI = $using:htAllSubscriptionsFromAPI
            $arrayEntitiesFromAPI = $using:arrayEntitiesFromAPI
            $arrayAPICallTracking = $using:arrayAPICallTracking
            $arrayAPICallTrackingCustomDataCollection = $using:arrayAPICallTrackingCustomDataCollection
            #Functions
            $function:AzAPICall = $using:funcAzAPICall
            $function:createBearerToken = $using:funcCreateBearerToken
            $function:addRowToTable = $using:funcAddRowToTable
            $function:GetJWTDetails = $using:funcGetJWTDetails
            #endregion UsingVARs
            
            $childMgSubId = $childMgSubDetail.name
            $childMgSubDisplayName = $childMgSubDetail.properties.displayName
            $mgDetail = ($arrayEntitiesFromAPI | Where-Object { $_.type -eq "/subscriptions" -and $_.Name -eq $childMgSubId })
            $hierarchyLevel = ($mgDetail.properties.parentNameChain | Measure-Object).count - 1
            $childMgId = $mgDetail.properties.parent.id -replace ".*/"
            $childMgDetail = ($arrayEntitiesFromAPI | Where-Object { $_.Name -eq $childMgId })
            $childMgDisplayName = $childMgDetail.properties.displayName
            $mgParentDetail = ($arrayEntitiesFromAPI | Where-Object { $_.type -eq "Microsoft.Management/managementGroups" -and $_.Name -eq $childMgId })
            $childMgParentId = $mgParentDetail.properties.parent.id -replace ".*/"
            $childMgParentName = ($arrayEntitiesFromAPI | Where-Object { $_.Name -eq $childMgParentId }).properties.displayName
            
           
            $rndom = Get-Random -Minimum 10 -Maximum 750
            start-sleep -Millisecond $rndom
            if ($htParameters.HierarchyMapOnly -eq $false) {
                
                $currentSubscription = $htAllSubscriptionsFromAPI.($childMgSubId).subDetails

                if (($currentSubscription.subscriptionPolicies.quotaId).startswith("AAD_", "CurrentCultureIgnoreCase") -or $currentSubscription.state -ne "enabled") {
                    if (($currentSubscription.subscriptionPolicies.quotaId).startswith("AAD_", "CurrentCultureIgnoreCase")) {
                        Write-Host " CustomDataCollection: Subscription Quota Id: $($currentSubscription.subscriptionPolicies.quotaId) is out of scope for AzGovViz"
                        $null = $script:outOfScopeSubscriptions.Add([PSCustomObject]@{ 
                                subscriptionId      = $childMgSubId
                                subscriptionName    = $childMgSubDisplayName
                                outOfScopeReason    = "QuotaId: AAD_ (State: $($currentSubscription.state))"
                                ManagementGroupId   = $childMgId
                                ManagementGroupName = $childMgDisplayName 
                                Level               = $hierarchyLevel
                            })
                    }
                    else {
                        if ($currentSubscription.state -ne "enabled") {
                            Write-Host " CustomDataCollection: Subscription State: '$($currentSubscription.state)'; out of scope"
                            $null = $script:outOfScopeSubscriptions.Add([PSCustomObject]@{ 
                                    subscriptionId      = $childMgSubId
                                    subscriptionName    = $childMgSubDisplayName
                                    outOfScopeReason    = "State: $($currentSubscription.state)"
                                    ManagementGroupId   = $childMgId
                                    ManagementGroupName = $childMgDisplayName
                                    Level               = $hierarchyLevel 
                                })
                        }
                    }
                    $subscriptionIsInScopeforAzGovViz = $False
                }
                else {
                    if ($SubscriptionQuotaIdWhitelist[0] -ne "undefined") {
                        $whitelistMatched = "unknown"
                        foreach ($subscriptionQuotaIdWhitelistQuotaId in $SubscriptionQuotaIdWhitelist) {
                            if (($currentSubscription.subscriptionPolicies.quotaId).startswith($subscriptionQuotaIdWhitelistQuotaId, "CurrentCultureIgnoreCase")) {
                                $whitelistMatched = "inWhitelist"
                            }
                        }

                        if ($whitelistMatched -eq "inWhitelist") {
                            $subscriptionIsInScopeforAzGovViz = $True
                        }
                        else {
                            Write-Host " CustomDataCollection: Subscription Quota Id: $($currentSubscription.subscriptionPolicies.quotaId) is out of scope for AzGovViz (not in Whitelist)"
                            $null = $script:outOfScopeSubscriptions.Add([PSCustomObject]@{ 
                                    subscriptionId      = $childMgSubId
                                    subscriptionName    = $childMgSubDisplayName 
                                    outOfScopeReason    = "QuotaId: '$($currentSubscription.subscriptionPolicies.quotaId)' not in Whitelist"
                                    ManagementGroupId   = $childMgId
                                    ManagementGroupName = $childMgDisplayName 
                                    Level               = $hierarchyLevel
                                })
                            $subscriptionIsInScopeforAzGovViz = $False
                        }
                    }
                    else {
                        $subscriptionIsInScopeforAzGovViz = $True
                    }
                }

                if ($True -eq $subscriptionIsInScopeforAzGovViz) {
                    $subscriptionQuotaId = $currentSubscription.subscriptionPolicies.quotaId
                    $subscriptionState = $currentSubscription.state

                    $currentTask = "Getting ResourceTypes for SubscriptionId: '$($childMgSubId)'"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($childMgSubId)/resources?api-version=2020-06-01"
                    #$path = "/subscriptions/$($childMgSubId)/resources?api-version=2020-06-01"
                    $method = "GET"

                    $resourcesSubscriptionResult = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))    
                    foreach ($resourceTypeLocation in ($resourcesSubscriptionResult | Group-Object -Property type, location)) {
                        $null = $script:resourcesAll.Add([PSCustomObject]@{
                                subscriptionId = $childMgSubId
                                type           = ($resourceTypeLocation.values[0]).ToLower()
                                location       = ($resourceTypeLocation.values[1]).ToLower()
                                count_         = $resourceTypeLocation.Count 
                            })
                    }

                    foreach ($resourceType in ($resourcesSubscriptionResult | Group-Object -Property type)) {
                        if (-not $htResourceTypesUniqueResource.(($resourceType.name).ToLower())) {
                            $script:htResourceTypesUniqueResource.(($resourceType.name).ToLower()) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                            $script:htResourceTypesUniqueResource.(($resourceType.name).ToLower()).resourceId = $resourceType.Group.id | Select-Object -first 1
                        }
                    }
                    
                    #resourceTags
                    $script:htSubscriptionTagList.($childMgSubId) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                    $script:htSubscriptionTagList.($childMgSubId).Resource = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                    ForEach ($tags in ($resourcesSubscriptionResult | Where-Object { $_.Tags -and -not [String]::IsNullOrWhiteSpace($_.Tags) }).Tags) {
                        ForEach ($tagName in $tags.PSObject.Properties.Name) {
                            #resource
                            If ($htSubscriptionTagList.($childMgSubId).Resource.ContainsKey($tagName)) {
                                $script:htSubscriptionTagList.($childMgSubId).Resource."$tagName" += 1
                            }
                            Else {
                                $script:htSubscriptionTagList.($childMgSubId).Resource."$tagName" = 1
                            }

                            #resourceAll
                            If ($htAllTagList.Resource.ContainsKey($tagName)) {
                                $script:htAllTagList.Resource."$tagName" += 1
                            }
                            Else {
                                $script:htAllTagList.Resource."$tagName" = 1
                            }

                            #all
                            If ($htAllTagList.AllScopes.ContainsKey($tagName)) {
                                $script:htAllTagList.AllScopes."$tagName" += 1
                            }
                            Else {
                                $script:htAllTagList.AllScopes."$tagName" = 1
                            }
                        }
                    }

                    #https://management.azure.com/subscriptions/{subscriptionId}/resourcegroups?api-version=2020-06-01
                    $currentTask = "Getting ResourceGroups for SubscriptionId: '$($childMgSubId)'"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($childMgSubId)/resourcegroups?api-version=2020-06-01"
                    #$path = "/subscriptions/$($childMgSubId)/resourcegroups?api-version=2020-06-01"
                    $method = "GET"
                    
                    $resourceGroupsSubscriptionResult = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
                    $null = $script:resourceGroupsAll.Add([PSCustomObject]@{
                            subscriptionId = $childMgSubId
                            count_         = ($resourceGroupsSubscriptionResult | Measure-Object).count
                        })

                    #resourceGroupTags
                    $script:htSubscriptionTagList.($childMgSubId).ResourceGroup = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                    ForEach ($tags in ($resourceGroupsSubscriptionResult | Where-Object { $_.Tags -and -not [String]::IsNullOrWhiteSpace($_.Tags) }).Tags) {
                        ForEach ($tagName in $tags.PSObject.Properties.Name) {
                            
                            #resource
                            If ($htSubscriptionTagList.($childMgSubId).ResourceGroup.ContainsKey($tagName)) {
                                $script:htSubscriptionTagList.($childMgSubId).ResourceGroup."$tagName" += 1
                            }
                            Else {
                                $script:htSubscriptionTagList.($childMgSubId).ResourceGroup."$tagName" = 1
                            }

                            #resourceAll
                            If ($htAllTagList.ResourceGroup.ContainsKey($tagName)) {
                                $script:htAllTagList.ResourceGroup."$tagName" += 1
                            }
                            Else {
                                $script:htAllTagList.ResourceGroup."$tagName" = 1
                            }

                            #all
                            If ($htAllTagList.AllScopes.ContainsKey($tagName)) {
                                $script:htAllTagList.AllScopes."$tagName" += 1
                            }
                            Else {
                                $script:htAllTagList.AllScopes."$tagName" = 1
                            }
                        }
                    }

                    #resourceProviders
                    ($script:htResourceProvidersAll).($childMgSubId) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                    $currentTask = "Getting ResourceProviders for SubscriptionId: '$($childMgSubId)'"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($childMgSubId)/providers?api-version=2019-10-01"
                    #$path = "/subscriptions/$($childMgSubId)/providers?api-version=2019-10-01"
                    $method = "GET"

                    $resProvResult = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
                    ($script:htResourceProvidersAll).($childMgSubId).Providers = $resProvResult

                    #resourceLocks
                    $currentTask = "Subscription ResourceLocks '$($childMgSubDisplayName)' ('$childMgSubId')"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Authorization/locks?api-version=2016-09-01"
                    #$path = "/subscriptions/$childMgSubId/providers/Microsoft.Authorization/locks?api-version=2016-09-01"
                    $method = "GET"

                    $requestSubscriptionResourceLocks = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
                    $requestSubscriptionResourceLocksCount = ($requestSubscriptionResourceLocks | Measure-Object).Count
                    if ($requestSubscriptionResourceLocksCount -gt 0) {
                        $script:htResourceLocks.($childMgSubId) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                        $locksAnyLockSubscriptionCount = 0
                        $locksCannotDeleteSubscriptionCount = 0
                        $locksReadOnlySubscriptionCount = 0
                        $arrayResourceGroupsAnyLock = [System.Collections.ArrayList]@()
                        $arrayResourceGroupsCannotDeleteLock = [System.Collections.ArrayList]@()
                        $arrayResourceGroupsReadOnlyLock = [System.Collections.ArrayList]@()
                        $arrayResourcesAnyLock = [System.Collections.ArrayList]@()
                        $arrayResourcesCannotDeleteLock = [System.Collections.ArrayList]@()
                        $arrayResourcesReadOnlyLock = [System.Collections.ArrayList]@()
                        foreach ($requestSubscriptionResourceLock in $requestSubscriptionResourceLocks) {
                            
                            $splitRequestSubscriptionResourceLockId = ($requestSubscriptionResourceLock.id).Split('/')
                            switch (($splitRequestSubscriptionResourceLockId | Measure-Object).Count - 1) {
                                #subLock
                                6 {
                                    $locksAnyLockSubscriptionCount++
                                    if ($requestSubscriptionResourceLock.properties.level -eq "CanNotDelete") {
                                        $locksCannotDeleteSubscriptionCount++
                                    }
                                    if ($requestSubscriptionResourceLock.properties.level -eq "ReadOnly") {
                                        $locksReadOnlySubscriptionCount++
                                    }
                                }
                                #rgLock
                                8 {
                                    $resourceGroupName = $splitRequestSubscriptionResourceLockId[0..4] -join "/"
                                    $null = $arrayResourceGroupsAnyLock.Add([PSCustomObject]@{ 
                                            rg = $resourceGroupName
                                        })
                                    if ($requestSubscriptionResourceLock.properties.level -eq "CanNotDelete") {
                                        $null = $arrayResourceGroupsCannotDeleteLock.Add([PSCustomObject]@{ 
                                                rg = $resourceGroupName
                                            })
                                    }
                                    if ($requestSubscriptionResourceLock.properties.level -eq "ReadOnly") {
                                        $null = $arrayResourceGroupsReadOnlyLock.Add([PSCustomObject]@{ 
                                                rg = $resourceGroupName
                                            })
                                    }
                                }
                                #resLock
                                12 {
                                    $resourceId = $splitRequestSubscriptionResourceLockId[0..8] -join "/"
                                    $null = $arrayResourcesAnyLock.Add([PSCustomObject]@{ 
                                            res = $resourceId
                                        })
                                    if ($requestSubscriptionResourceLock.properties.level -eq "CanNotDelete") {
                                        $null = $arrayResourcesCannotDeleteLock.Add([PSCustomObject]@{ 
                                                res = $resourceId
                                            })
                                    }
                                    if ($requestSubscriptionResourceLock.properties.level -eq "ReadOnly") {
                                        $null = $arrayResourcesReadOnlyLock.Add([PSCustomObject]@{ 
                                                res = $resourceId
                                            })
                                    }
                                }
                            }
                        }

                        $script:htResourceLocks.($childMgSubId).SubscriptionLocksCannotDeleteCount = $locksCannotDeleteSubscriptionCount
                        $script:htResourceLocks.($childMgSubId).SubscriptionLocksReadOnlyCount = $locksReadOnlySubscriptionCount

                        #resourceGroups
                        $resourceGroupsLocksCannotDeleteCount = ($arrayResourceGroupsCannotDeleteLock | Measure-Object).Count
                        $script:htResourceLocks.($childMgSubId).ResourceGroupsLocksCannotDeleteCount = $resourceGroupsLocksCannotDeleteCount
                        $script:resourceGroupsLocksCannotDeleteCountTotal = $resourceGroupsLocksCannotDeleteCountTotal + $resourceGroupsLocksCannotDeleteCount
                        
                        $resourceGroupsLocksReadOnlyCount = ($arrayResourceGroupsReadOnlyLock | Measure-Object).Count
                        $script:htResourceLocks.($childMgSubId).resourceGroupsLocksReadOnlyCount = $resourceGroupsLocksReadOnlyCount
                        $script:resourceGroupsLocksReadOnlyCountTotal = $resourceGroupsLocksReadOnlyCountTotal + $resourceGroupsLocksReadOnlyCount

                        $script:htResourceLocks.($childMgSubId).ResourceGroupsLocksCannotDelete = $arrayResourceGroupsCannotDeleteLock
                        $script:htResourceLocks.($childMgSubId).ResourceGroupsLocksReadOnly = $arrayResourceGroupsReadOnlyLock

                        #resources
                        $resourcesLocksCannotDeleteCount = ($arrayResourcesCannotDeleteLock | Measure-Object).Count
                        $script:htResourceLocks.($childMgSubId).ResourcesLocksCannotDeleteCount = $resourcesLocksCannotDeleteCount
                        $script:resourcesLocksCannotDeleteCountTotal = $resourcesLocksCannotDeleteCountTotal + $resourcesLocksCannotDeleteCount

                        $resourcesLocksReadOnlyCount = ($arrayResourcesReadOnlyLock | Measure-Object).Count
                        $script:htResourceLocks.($childMgSubId).ResourcesLocksReadOnlyCount = $resourcesLocksReadOnlyCount
                        $script:resourcesLocksReadOnlyCountTotal = $resourcesLocksReadOnlyCountTotal + $resourcesLocksReadOnlyCount

                        $script:htResourceLocks.($childMgSubId).ResourcesLocksCannotDelete = $arrayResourcesCannotDeleteLock
                        $script:htResourceLocks.($childMgSubId).ResourcesLocksReadOnly = $arrayResourcesReadOnlyLock
                    }

                    #tags
                    $currentTask = "Subscription Tags '$($childMgSubDisplayName)' ('$childMgSubId')"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Resources/tags/default?api-version=2020-06-01"
                    #$path = "/subscriptions/$childMgSubId/providers/Microsoft.Resources/tags/default?api-version=2020-06-01"
                    $method = "GET"

                    $requestSubscriptionTags = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -listenOn "Content" -caller "CustomDataCollection"))
                    
                    $script:htSubscriptionTagList.($childMgSubId).Subscription = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                    if ($requestSubscriptionTags.properties.tags) {
                        $subscriptionTags = @()
                        ($script:htSubscriptionTags).($childMgSubId) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                        foreach ($tag in ($requestSubscriptionTags.properties.tags).PSObject.Properties) {
                            $subscriptionTags += "$($tag.Name)/$($tag.Value)"
                            
                            ($script:htSubscriptionTags).($childMgSubId).($tag.Name) = $tag.Value
                            $tagName = $tag.Name

                            #subscription
                            If ($htSubscriptionTagList.($childMgSubId).Subscription.ContainsKey($tagName)) {
                                $script:htSubscriptionTagList.($childMgSubId).Subscription."$tagName" += 1
                            }
                            Else {
                                $script:htSubscriptionTagList.($childMgSubId).Subscription."$tagName" = 1
                            }

                            #subscriptionAll
                            If ($htAllTagList.Subscription.ContainsKey($tagName)) {
                                $script:htAllTagList.Subscription."$tagName" += 1
                            }
                            Else {
                                $script:htAllTagList.Subscription."$tagName" = 1
                            }
                    
                            #all
                            If ($htAllTagList.AllScopes.ContainsKey($tagName)) {
                                $script:htAllTagList.AllScopes."$tagName" += 1
                            }
                            Else {
                                $script:htAllTagList.AllScopes."$tagName" = 1
                            }

                        }
                        $subscriptionTagsCount = ($subscriptionTags | Measure-Object).Count
                        $subscriptionTags = $subscriptionTags -join "$CsvDelimiterOpposite "
                    }
                    else {
                        $SubscriptionTagsCount = 0
                        $subscriptionTags = "none"
                    }

                    if ($htParameters.NoPolicyComplianceStates -eq $false) {
                        #SubscriptionPolicyCompliance

                        $currentTask = "Policy Compliance '$($childMgSubDisplayName)' ('$childMgSubId')"
                        $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
                        #$path = "/subscriptions/$childMgSubId/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
                        $method = "POST"
                        
                        $subPolicyComplianceResult = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
                        ($script:htCachePolicyCompliance).sub.($childMgSubId) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                        foreach ($policyAssignment in $subPolicyComplianceResult.policyassignments | sort-object -Property policyAssignmentId) {
                            $policyAssignmentIdToLower = ($policyAssignment.policyAssignmentId).ToLower()
                            ($script:htCachePolicyCompliance).sub.($childMgSubId).($policyAssignmentIdToLower) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                            foreach ($policyComplianceState in $policyAssignment.results.policydetails) {
                                if ($policyComplianceState.ComplianceState -eq "compliant") {
                                    ($script:htCachePolicyCompliance).sub.($childMgSubId).($policyAssignmentIdToLower).CompliantPolicies = $policyComplianceState.count
                                }
                                if ($policyComplianceState.ComplianceState -eq "noncompliant") {
                                    ($script:htCachePolicyCompliance).sub.($childMgSubId).($policyAssignmentIdToLower).NonCompliantPolicies = $policyComplianceState.count
                                }
                            }

                            foreach ($resourceComplianceState in $policyAssignment.results.resourcedetails) {
                                if ($resourceComplianceState.ComplianceState -eq "compliant") {
                                    ($script:htCachePolicyCompliance).sub.($childMgSubId).($policyAssignmentIdToLower).CompliantResources = $resourceComplianceState.count
                                }
                                if ($resourceComplianceState.ComplianceState -eq "nonCompliant") {
                                    ($script:htCachePolicyCompliance).sub.($childMgSubId).($policyAssignmentIdToLower).NonCompliantResources = $resourceComplianceState.count
                                }
                            }
                        }
                    }

                    #SubscriptionASCSecureScore
                    if ($htParameters.NoASCSecureScore -eq $false) {
                        $currentTask = "ASC Secure Score '$($childMgSubDisplayName)' ('$childMgSubId')"
                        $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Security/securescores?api-version=2020-01-01-preview"
                        #$path = "/subscriptions/$childMgSubId/providers/Microsoft.Security/securescores?api-version=2020-01-01-preview"
                        $method = "GET"

                        $subASCSecureScoreResult = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
                        if (($subASCSecureScoreResult | measure-object).count -gt 0) {
                            $subscriptionASCSecureScore = "$($subASCSecureScoreResult.properties.score.current) of $($subASCSecureScoreResult.properties.score.max) points" 
                        }
                        else {
                            $subscriptionASCSecureScore = "n/a"
                        }
                    }
                    else {
                        $subscriptionASCSecureScore = "excluded"
                    }

                    #SubscriptionBlueprint
                    $currentTask = "Blueprint definitions '$($childMgSubDisplayName)' ('$childMgSubId')"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
                    #$path = "/subscriptions/$childMgSubId/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
                    $method = "GET"

                    $subBlueprintDefinitionResult = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
                    if (($subBlueprintDefinitionResult | measure-object).count -gt 0) {
                        foreach ($blueprint in $subBlueprintDefinitionResult) {

                            if (-not $($htCacheDefinitions).blueprint[$blueprint.id]) {
                                $($script:htCacheDefinitions).blueprint.$($blueprint.id) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                                $($script:htCacheDefinitions).blueprint.$($blueprint.id) = $blueprint
                            }  

                            $blueprintName = $blueprint.name
                            $blueprintId = $blueprint.id
                            $blueprintDisplayName = $blueprint.properties.displayName
                            $blueprintDescription = $blueprint.properties.description
                            $blueprintScoped = "/subscriptions/$childMgSubId"
                            addRowToTable `
                                -level $hierarchyLevel `
                                -mgName $childMgDisplayName `
                                -mgId $childMgId `
                                -mgParentId $childMgParentId `
                                -mgParentName $childMgParentName `
                                -Subscription $childMgSubDisplayName `
                                -SubscriptionId $childMgSubId `
                                -SubscriptionQuotaId $subscriptionQuotaId `
                                -SubscriptionState $subscriptionState `
                                -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                                -SubscriptionTags $subscriptionTags `
                                -SubscriptionTagsCount $subscriptionTagsCount `
                                -BlueprintName $blueprintName `
                                -BlueprintId $blueprintId `
                                -BlueprintDisplayName $blueprintDisplayName `
                                -BlueprintDescription $blueprintDescription `
                                -BlueprintScoped $blueprintScoped
                        }
                    }

                    #SubscriptionBlueprintAssignment
                    $currentTask = "Blueprint assignments '$($childMgSubDisplayName)' ('$childMgSubId')"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Blueprint/blueprintAssignments?api-version=2018-11-01-preview"
                    #$path = "/subscriptions/$childMgSubId/providers/Microsoft.Blueprint/blueprintAssignments?api-version=2018-11-01-preview"
                    $method = "GET"
                    
                    $subscriptionBlueprintAssignmentsResult = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
                    
                    if (($subscriptionBlueprintAssignmentsResult | measure-object).count -gt 0) {
                        foreach ($subscriptionBlueprintAssignment in $subscriptionBlueprintAssignmentsResult) {

                            if (-not ($htCacheAssignments).blueprint.($subscriptionBlueprintAssignment.id)) {
                                ($script:htCacheAssignments).blueprint.($subscriptionBlueprintAssignment.id) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                                ($script:htCacheAssignments).blueprint.($subscriptionBlueprintAssignment.id) = $subscriptionBlueprintAssignment
                            }  

                            if (($subscriptionBlueprintAssignment.properties.blueprintId) -like "/subscriptions/*") {
                                $blueprintScope = $subscriptionBlueprintAssignment.properties.blueprintId -replace "/providers/Microsoft.Blueprint/blueprints/.*", ""
                                $blueprintName = $subscriptionBlueprintAssignment.properties.blueprintId -replace ".*/blueprints/", "" -replace "/versions/.*", ""
                            }
                            if (($subscriptionBlueprintAssignment.properties.blueprintId) -like "/providers/Microsoft.Management/managementGroups/*") {
                                $blueprintScope = $subscriptionBlueprintAssignment.properties.blueprintId -replace "/providers/Microsoft.Blueprint/blueprints/.*", ""
                                $blueprintName = $subscriptionBlueprintAssignment.properties.blueprintId -replace ".*/blueprints/", "" -replace "/versions/.*", ""
                            }
                            
                            $currentTask = "Blueprint definitions related to Blueprint assignments '$($childMgSubDisplayName)' ('$childMgSubId')"
                            $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)$($blueprintScope)/providers/Microsoft.Blueprint/blueprints/$($blueprintName)?api-version=2018-11-01-preview"
                            #$path = "$($blueprintScope)/providers/Microsoft.Blueprint/blueprints/$($blueprintName)?api-version=2018-11-01-preview"
                            $method = "GET"
                            
                            $subscriptionBlueprintDefinitionResult = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -listenOn "Content" -caller "CustomDataCollection"))
                            $blueprintName = $subscriptionBlueprintDefinitionResult.name
                            $blueprintId = $subscriptionBlueprintDefinitionResult.id
                            $blueprintAssignmentVersion = $subscriptionBlueprintAssignment.properties.blueprintId -replace ".*/"
                            $blueprintDisplayName = $subscriptionBlueprintDefinitionResult.properties.displayName
                            $blueprintDescription = $subscriptionBlueprintDefinitionResult.properties.description
                            $blueprintScoped = $blueprintScope
                            $blueprintAssignmentId = $subscriptionBlueprintAssignmentsResult.id
                            addRowToTable `
                                -level $hierarchyLevel `
                                -mgName $childMgDisplayName `
                                -mgId $childMgId `
                                -mgParentId $childMgParentId `
                                -mgParentName $childMgParentName `
                                -Subscription $childMgSubDisplayName `
                                -SubscriptionId $childMgSubId `
                                -SubscriptionQuotaId $subscriptionQuotaId `
                                -SubscriptionState $subscriptionState `
                                -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                                -SubscriptionTags $subscriptionTags `
                                -SubscriptionTagsCount $subscriptionTagsCount `
                                -BlueprintName $blueprintName `
                                -BlueprintId $blueprintId `
                                -BlueprintDisplayName $blueprintDisplayName `
                                -BlueprintDescription $blueprintDescription `
                                -BlueprintScoped $blueprintScoped `
                                -BlueprintAssignmentVersion $blueprintAssignmentVersion `
                                -BlueprintAssignmentId $blueprintAssignmentId
                        }
                    }

                    #SubscriptionPolicyExemptions
                    #https://management.azure.com/subscriptions/b2ac7057-8edf-4617-a1f7-5ed6b44ef2c8/providers/Microsoft.Authorization/policyExemptions?api-version=2020-07-01-preview
                    $currentTask = "Policy exemptions '$($childMgSubDisplayName)' ('$childMgSubId')"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policyExemptions?api-version=2020-07-01-preview"
                    #$path = "/subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
                    $method = "GET"

                    $requestPolicyExemptionAPI = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
                    $requestPolicyExemptionAPICount = ($requestPolicyExemptionAPI | Measure-Object).Count
                    if ($requestPolicyExemptionAPICount -gt 0) {
                        foreach ($exemption in $requestPolicyExemptionAPI) {
                            if (-not $htPolicyAssignmentExemptions.($exemption.id)) {
                                $script:htPolicyAssignmentExemptions.($exemption.id) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                                $script:htPolicyAssignmentExemptions.($exemption.id).exemption = $exemption
                            }
                        }
                    }

                    #SubscriptionPolicies
                    $currentTask = "Policy definitions '$($childMgSubDisplayName)' ('$childMgSubId')"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
                    #$path = "/subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
                    $method = "GET"
                    
                    $requestPolicyDefinitionAPI = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
                    $subPolicyDefinitions = $requestPolicyDefinitionAPI | Where-Object { $_.properties.policyType -eq "custom" }
                    $PolicyDefinitionsScopedCount = (($subPolicyDefinitions | Where-Object { ($_.id) -like "/subscriptions/$childMgSubId/*" }) | measure-object).count
                    foreach ($subPolicyDefinition in $subPolicyDefinitions) {
                        if (-not $($htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower())) {
                            if (($subPolicyDefinition.Properties.description).length -eq 0) {
                                $policyDefinitionDescription = "no description given"
                            }
                            else {
                                $policyDefinitionDescription = $subPolicyDefinition.Properties.description
                            }
                            ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                            ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).id = ($subPolicyDefinition.id).ToLower()
                            if ($subPolicyDefinition.id -like "/providers/Microsoft.Management/managementGroups/*") {
                                ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).Scope = (($subPolicyDefinition.id) -split "\/")[0..4] -join "/"
                                ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).ScopeMgSub = "Mg"
                                ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).ScopeId = (($subPolicyDefinition.id) -split "\/")[4]
                            }
                            if ($subPolicyDefinition.id -like "/subscriptions/*") {
                                ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).Scope = (($subPolicyDefinition.id) -split "\/")[0..2] -join "/"
                                ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).ScopeMgSub = "Sub"
                                ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).ScopeId = (($subPolicyDefinition.id) -split "\/")[2]
                            }
                            ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).DisplayName = $($subPolicyDefinition.Properties.displayname)
                            ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).Description = $($policyDefinitionDescription)
                            ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).Type = $($subPolicyDefinition.Properties.policyType)
                            ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).Category = $($subPolicyDefinition.Properties.metadata.category)
                            ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).PolicyDefinitionId = ($subPolicyDefinition.id).ToLower()
                            if ($subPolicyDefinition.Properties.metadata.deprecated -eq $true -or $subPolicyDefinition.Properties.displayname -like "``[Deprecated``]*") {
                                ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).Deprecated = $subPolicyDefinition.Properties.metadata.deprecated
                            }
                            else {
                                ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).Deprecated = $false
                            }
                            if ($subPolicyDefinition.Properties.metadata.preview -eq $true -or $subPolicyDefinition.Properties.displayname -like "``[*Preview``]*") {
                                ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).Preview = $subPolicyDefinition.Properties.metadata.preview
                            }
                            else {
                                ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).Preview = $false
                            }
                            #effects
                            if ($subPolicyDefinition.properties.parameters.effect.defaultvalue) {
                                ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).effectDefaultValue = $subPolicyDefinition.properties.parameters.effect.defaultvalue
                                if ($subPolicyDefinition.properties.parameters.effect.allowedValues) {
                                    ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).effectAllowedValue = $subPolicyDefinition.properties.parameters.effect.allowedValues -join ","
                                }
                                else {
                                    ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).effectAllowedValue = "n/a"
                                }
                                ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).effectFixedValue = "n/a"
                            }
                            else {
                                if ($subPolicyDefinition.properties.parameters.policyEffect.defaultValue) {
                                    ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).effectDefaultValue = $subPolicyDefinition.properties.parameters.policyEffect.defaultvalue
                                    if ($subPolicyDefinition.properties.parameters.policyEffect.allowedValues) {
                                        ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).effectAllowedValue = $subPolicyDefinition.properties.parameters.policyEffect.allowedValues -join ","
                                    }
                                    else {
                                        ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).effectAllowedValue = "n/a"
                                    }
                                    ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).effectFixedValue = "n/a"
                                }
                                else {
                                    ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).effectFixedValue = $subPolicyDefinition.Properties.policyRule.then.effect
                                    ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).effectDefaultValue = "n/a"
                                    ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).effectAllowedValue = "n/a"
                                }
                            }
                            $($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).json = $subPolicyDefinition

                            if ($subPolicyDefinition.properties.policyRule.then.details.roleDefinitionIds) {
                                ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).RoleDefinitionIds  = $subPolicyDefinition.properties.policyRule.then.details.roleDefinitionIds
                            }
                            else {
                                ($script:htCacheDefinitions).policy.(($subPolicyDefinition.id).ToLower()).RoleDefinitionIds  = "n/a"
                            }
                        }  
                        if (-not $($htCacheDefinitionsAsIs).policy[$subPolicyDefinition.id]) {
                            ($script:htCacheDefinitionsAsIs).policy.(($subPolicyDefinition.id).ToLower()) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                            ($script:htCacheDefinitionsAsIs).policy.(($subPolicyDefinition.id).ToLower()) = $subPolicyDefinition
                        }  
                    }

                    #SubscriptionPolicySets
                    $currentTask = "PolicySet definitions '$($childMgSubDisplayName)' ('$childMgSubId')"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"
                    #$path = "/subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"
                    $method = "GET"
                
                    $requestPolicySetDefinitionAPI = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
                    $subPolicySetDefinitions = $requestPolicySetDefinitionAPI | Where-Object { $_.properties.policyType -eq "custom" }
                    $PolicySetDefinitionsScopedCount = (($subPolicySetDefinitions | Where-Object { ($_.id) -like "/subscriptions/$childMgSubId/*" }) | measure-object).count
                    foreach ($subPolicySetDefinition in $subPolicySetDefinitions) {
                        if (-not $($htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower())) {
                            if (($subPolicySetDefinition.Properties.description).length -eq 0) {
                                $policySetDefinitionDescription = "no description given"
                            }
                            else {
                                $policySetDefinitionDescription = $subPolicySetDefinition.Properties.description
                            }
                            $($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                            $($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).id = ($subPolicySetDefinition.id).ToLower()
                            if ($subPolicySetDefinition.id -like "/providers/Microsoft.Management/managementGroups/*") {
                                ($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).Scope = (($subPolicySetDefinition.id) -split "\/")[0..4] -join "/"
                                ($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).ScopeMgSub = "Mg"
                                ($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).ScopeId = (($subPolicySetDefinition.id) -split "\/")[4]
                            }
                            if ($subPolicySetDefinition.id -like "/subscriptions/*") {
                                ($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).Scope = (($subPolicySetDefinition.id) -split "\/")[0..2] -join "/"
                                ($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).ScopeMgSub = "Sub"
                                ($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).ScopeId = (($subPolicySetDefinition.id) -split "\/")[2]
                            }
                            $($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).DisplayName = $($subPolicySetDefinition.Properties.displayname)
                            $($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).Description = $($policySetDefinitionDescription)
                            $($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).Type = $($subPolicySetDefinition.Properties.policyType)
                            $($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).Category = $($subPolicySetDefinition.Properties.metadata.category)
                            $($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).PolicyDefinitionId = ($subPolicySetDefinition.id).ToLower()
                            $arrayPolicySetPolicyIdsToLower = @()
                            $arrayPolicySetPolicyIdsToLower = foreach ($policySetPolicy in $subPolicySetDefinition.properties.policydefinitions.policyDefinitionId) {
                                ($policySetPolicy).ToLower()
                            }
                            $($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).PolicySetPolicyIds = $arrayPolicySetPolicyIdsToLower
                            $($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).json = $subPolicySetDefinition
                            if ($subPolicySetDefinition.Properties.metadata.deprecated -eq $true -or $subPolicySetDefinition.Properties.displayname -like "``[Deprecated``]*") {
                                ($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).Deprecated = $subPolicySetDefinition.Properties.metadata.deprecated
                            }
                            else {
                                ($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).Deprecated = $false
                            }
                            if ($subPolicySetDefinition.Properties.metadata.preview -eq $true -or $subPolicySetDefinition.Properties.displayname -like "``[*Preview``]*") {
                                ($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).Preview = $subPolicySetDefinition.Properties.metadata.preview
                            }
                            else {
                                ($script:htCacheDefinitions).policySet.(($subPolicySetDefinition.id).ToLower()).Preview = $false
                            }
                        }  
                    }

                    #SubscriptionPolicyAssignments
                    $currentTask = "Policy assignments '$($childMgSubDisplayName)' ('$childMgSubId')"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policyAssignments?api-version=2019-09-01"
                    #$path = "/subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policyAssignments?api-version=2019-09-01"
                    $method = "GET"
                 
                    if ($htParameters.IncludeResourceGroupsAndResources -eq $true) {
                        $L1mgmtGroupSubPolicyAssignments = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
                        $L1mgmtGroupSubPolicyAssignmentsPolicyCount = (($L1mgmtGroupSubPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" }) | measure-object).count
                        $L1mgmtGroupSubPolicyAssignmentsPolicySetCount = (($L1mgmtGroupSubPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" }) | measure-object).count
                        $L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount = (($L1mgmtGroupSubPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -and $_.id -match "/subscriptions/$($childMgSubId)" }) | measure-object).count
                        $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount = (($L1mgmtGroupSubPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" -and $_.id -match "/subscriptions/$($childMgSubId)" }) | measure-object).count
                    }
                    else {
                        $L1mgmtGroupSubPolicyAssignments = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
                        $L1mgmtGroupSubPolicyAssignmentsPolicyCount = (($L1mgmtGroupSubPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -and $_.id -notmatch "/subscriptions/$($childMgSubId)/resourceGroups" }) | measure-object).count
                        $L1mgmtGroupSubPolicyAssignmentsPolicySetCount = (($L1mgmtGroupSubPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" -and $_.id -notmatch "/subscriptions/$($childMgSubId)/resourceGroups" }) | measure-object).count
                        $L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount = (($L1mgmtGroupSubPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -and $_.id -match "/subscriptions/$($childMgSubId)" -and $_.id -notmatch "/subscriptions/$($childMgSubId)/resourceGroups" }) | measure-object).count
                        $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount = (($L1mgmtGroupSubPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" -and $_.id -match "/subscriptions/$($childMgSubId)" -and $_.id -notmatch "/subscriptions/$($childMgSubId)/resourceGroups" }) | measure-object).count
                    }

                    $L1mgmtGroupSubPolicyAssignmentsPolicyAndPolicySetAtScopeCount = ($L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount + $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount)

                    foreach ($L1mgmtGroupSubPolicyAssignment in $L1mgmtGroupSubPolicyAssignments | Where-Object { $_.id -match "/subscriptions/$($childMgSubId)/resourceGroups" } ) {
                        $null = $script:arrayCachePolicyAssignmentsResourceGroupsAndResources.Add($L1mgmtGroupSubPolicyAssignment)
                        ($script:htCacheAssignments).policyOnResourceGroupsAndResources.($L1mgmtGroupSubPolicyAssignment.id) = $L1mgmtGroupSubPolicyAssignment
                    }
                    
                    if ($htParameters.IncludeResourceGroupsAndResources -eq $true) {
                        $L1mgmtGroupSubPolicyAssignmentsQuery = $L1mgmtGroupSubPolicyAssignments
                    }
                    else {
                        $L1mgmtGroupSubPolicyAssignmentsQuery = $L1mgmtGroupSubPolicyAssignments | Where-Object { $_.id -notmatch "/subscriptions/$($childMgSubId)/resourceGroups" }
                    }

                    foreach ($L1mgmtGroupSubPolicyAssignment in $L1mgmtGroupSubPolicyAssignmentsQuery ) {

                        if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -OR $L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
                            if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/") {
                                $PolicyVariant = "Policy"
                                $definitiontype = "policy"
                                $Id = ($L1mgmtGroupSubPolicyAssignment.properties.policydefinitionid).ToLower()
                                $Def = ($htCacheDefinitions).($definitiontype).($Id)
                                $PolicyAssignmentScope = $L1mgmtGroupSubPolicyAssignment.Properties.Scope

                                if ($PolicyAssignmentScope -like "/providers/Microsoft.Management/managementGroups/*") {
                                    $PolicyAssignmentScopeMgSubRgRes = "Mg"
                                }
                                else {
                                    $splitPolicyAssignmentScope = ($PolicyAssignmentScope).Split('/')
                                    switch (($splitPolicyAssignmentScope | Measure-Object).Count - 1) {
                                        #sub
                                        2 {
                                            $PolicyAssignmentScopeMgSubRgRes = "Sub"
                                        }
                                        4 {
                                            $PolicyAssignmentScopeMgSubRgRes = "Rg"
                                        }
                                        Default {
                                            $PolicyAssignmentScopeMgSubRgRes = "Res"
                                        }
                                    }
                                }

                                $PolicyAssignmentNotScopes = $L1mgmtGroupSubPolicyAssignment.Properties.NotScopes -join "$CsvDelimiterOpposite "
                                $PolicyAssignmentId = $L1mgmtGroupSubPolicyAssignment.id
                                $PolicyAssignmentName = $L1mgmtGroupSubPolicyAssignment.Name
                                $PolicyAssignmentDisplayName = $L1mgmtGroupSubPolicyAssignment.Properties.DisplayName
                                if (($L1mgmtGroupSubPolicyAssignment.Properties.Description).length -eq 0) {
                                    $PolicyAssignmentDescription = "no description given"
                                }
                                else {
                                    $PolicyAssignmentDescription = $L1mgmtGroupSubPolicyAssignment.Properties.Description
                                }

                                if ($L1mgmtGroupSubPolicyAssignment.identity) {
                                    $PolicyAssignmentIdentity = $L1mgmtGroupSubPolicyAssignment.identity.principalId
                                }
                                else {
                                    $PolicyAssignmentIdentity = "n/a"
                                }

                                if (($htCacheDefinitions).$definitiontype.$($Id).Type -eq "Custom") {
                                    $policyDefintionScope = $Def.Scope
                                    $policyDefintionScopeMgSub = $Def.ScopeMgSub
                                    $policyDefintionScopeId = $Def.ScopeId
                                }
                                else {
                                    $policyDefintionScope = "n/a"
                                    $policyDefintionScopeMgSub = "n/a"
                                    $policyDefintionScopeId = "n/a"
                                }
                                
                                addRowToTable `
                                    -level $hierarchyLevel `
                                    -mgName $childMgDisplayName `
                                    -mgId $childMgId `
                                    -mgParentId $childMgParentId `
                                    -mgParentName $childMgParentName `
                                    -Subscription $childMgSubDisplayName `
                                    -SubscriptionId $childMgSubId `
                                    -SubscriptionQuotaId $subscriptionQuotaId `
                                    -SubscriptionState $subscriptionState `
                                    -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                                    -SubscriptionTags $subscriptionTags `
                                    -SubscriptionTagsCount $subscriptionTagsCount `
                                    -Policy $Def.DisplayName `
                                    -PolicyDescription $Def.Description `
                                    -PolicyVariant $PolicyVariant `
                                    -PolicyType $Def.Type `
                                    -PolicyCategory $Def.Category `
                                    -PolicyDefinitionIdGuid (($Def.id) -replace ".*/") `
                                    -PolicyDefinitionId $Def.PolicyDefinitionId `
                                    -PolicyDefintionScope $policyDefintionScope `
                                    -PolicyDefintionScopeMgSub $policyDefintionScope `
                                    -PolicyDefintionScopeId $policyDefintionScopeId `
                                    -PolicyDefinitionsScopedLimit $LimitPOLICYPolicyDefinitionsScopedSubscription `
                                    -PolicyDefinitionsScopedCount $PolicyDefinitionsScopedCount `
                                    -PolicySetDefinitionsScopedLimit $LimitPOLICYPolicySetDefinitionsScopedSubscription `
                                    -PolicySetDefinitionsScopedCount $PolicySetDefinitionsScopedCount `
                                    -PolicyAssignmentScope $PolicyAssignmentScope `
                                    -PolicyAssignmentScopeMgSubRgRes $PolicyAssignmentScopeMgSubRgRes `
                                    -PolicyAssignmentScopeName ($PolicyAssignmentScope -replace '.*/', '') `
                                    -PolicyAssignmentNotScopes $L1mgmtGroupSubPolicyAssignment.Properties.NotScopes `
                                    -PolicyAssignmentId $PolicyAssignmentId `
                                    -PolicyAssignmentName $PolicyAssignmentName `
                                    -PolicyAssignmentDisplayName $PolicyAssignmentDisplayName `
                                    -PolicyAssignmentDescription $PolicyAssignmentDescription `
                                    -PolicyAssignmentIdentity $PolicyAssignmentIdentity `
                                    -PolicyAssigmentLimit $LimitPOLICYPolicyAssignmentsSubscription `
                                    -PolicyAssigmentCount $L1mgmtGroupSubPolicyAssignmentsPolicyCount `
                                    -PolicyAssigmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount `
                                    -PolicyAssigmentParameters $L1mgmtGroupSubPolicyAssignment.Properties.Parameters `
                                    -PolicySetAssigmentLimit $LimitPOLICYPolicySetAssignmentsSubscription `
                                    -PolicySetAssigmentCount $L1mgmtGroupSubPolicyAssignmentsPolicySetCount `
                                    -PolicySetAssigmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount `
                                    -PolicyAndPolicySetAssigmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicyAndPolicySetAtScopeCount
                            }
                            if ($L1mgmtGroupSubPolicyAssignment.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/") {
                                $PolicyVariant = "PolicySet"
                                $definitiontype = "policySet"
                                $Id = ($L1mgmtGroupSubPolicyAssignment.properties.policydefinitionid).ToLower()
                                $Def = ($htCacheDefinitions).($definitiontype).($Id)
                                $PolicyAssignmentScope = $L1mgmtGroupSubPolicyAssignment.Properties.Scope
                                if ($PolicyAssignmentScope -like "/providers/Microsoft.Management/managementGroups/*") {
                                    $PolicyAssignmentScopeMgSubRgRes = "Mg"
                                }
                                else {
                                    $splitPolicyAssignmentScope = ($PolicyAssignmentScope).Split('/')
                                    switch (($splitPolicyAssignmentScope | Measure-Object).Count - 1) {
                                        #sub
                                        2 {
                                            $PolicyAssignmentScopeMgSubRgRes = "Sub"
                                        }
                                        4 {
                                            $PolicyAssignmentScopeMgSubRgRes = "Rg"
                                        }
                                        Default {
                                            $PolicyAssignmentScopeMgSubRgRes = "Res"
                                        }
                                    }
                                }
                                $PolicyAssignmentNotScopes = $L1mgmtGroupSubPolicyAssignment.Properties.NotScopes -join "$CsvDelimiterOpposite "
                                $PolicyAssignmentId = $L1mgmtGroupSubPolicyAssignment.id
                                $PolicyAssignmentName = $L1mgmtGroupSubPolicyAssignment.Name
                                $PolicyAssignmentDisplayName = $L1mgmtGroupSubPolicyAssignment.Properties.DisplayName
                                if (($L1mgmtGroupSubPolicyAssignment.Properties.Description).length -eq 0) {
                                    $PolicyAssignmentDescription = "no description given"
                                }
                                else {
                                    $PolicyAssignmentDescription = $L1mgmtGroupSubPolicyAssignment.Properties.Description
                                }

                                if ($L1mgmtGroupSubPolicyAssignment.identity) {
                                    $PolicyAssignmentIdentity = $L1mgmtGroupSubPolicyAssignment.identity.principalId
                                }
                                else {
                                    $PolicyAssignmentIdentity = "n/a"
                                }

                                if (($htCacheDefinitions).$definitiontype.$($Id).Type -eq "Custom") {
                                    $policyDefintionScope = $Def.Scope
                                    $policyDefintionScopeMgSub = $Def.ScopeMgSub
                                    $policyDefintionScopeId = $Def.ScopeId
                                }
                                else {
                                    $policyDefintionScope = "n/a"
                                    $policyDefintionScopeMgSub = "n/a"
                                    $policyDefintionScopeId = "n/a"
                                }

                                addRowToTable `
                                    -level $hierarchyLevel `
                                    -mgName $childMgDisplayName `
                                    -mgId $childMgId `
                                    -mgParentId $childMgParentId `
                                    -mgParentName $childMgParentName `
                                    -Subscription $childMgSubDisplayName `
                                    -SubscriptionId $childMgSubId `
                                    -SubscriptionQuotaId $subscriptionQuotaId `
                                    -SubscriptionState $subscriptionState `
                                    -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                                    -SubscriptionTags $subscriptionTags `
                                    -SubscriptionTagsCount $subscriptionTagsCount `
                                    -Policy $Def.DisplayName `
                                    -PolicyDescription $Def.Description `
                                    -PolicyVariant $PolicyVariant `
                                    -PolicyType $Def.Type `
                                    -PolicyCategory $Def.Category `
                                    -PolicyDefinitionIdGuid (($Def.id) -replace ".*/") `
                                    -PolicyDefinitionId $Def.PolicyDefinitionId `
                                    -PolicyDefintionScope $policyDefintionScope `
                                    -PolicyDefintionScopeMgSub $policyDefintionScopeMgSub `
                                    -PolicyDefintionScopeId $policyDefintionScopeId `
                                    -PolicyDefinitionsScopedLimit $LimitPOLICYPolicyDefinitionsScopedSubscription `
                                    -PolicyDefinitionsScopedCount $PolicyDefinitionsScopedCount `
                                    -PolicySetDefinitionsScopedLimit $LimitPOLICYPolicySetDefinitionsScopedSubscription `
                                    -PolicySetDefinitionsScopedCount $PolicySetDefinitionsScopedCount `
                                    -PolicyAssignmentScope $PolicyAssignmentScope `
                                    -PolicyAssignmentScopeMgSubRgRes $PolicyAssignmentScopeMgSubRgRes `
                                    -PolicyAssignmentScopeName ($PolicyAssignmentScope -replace '.*/', '') `
                                    -PolicyAssignmentNotScopes $L1mgmtGroupSubPolicyAssignment.Properties.NotScopes `
                                    -PolicyAssignmentId $PolicyAssignmentId `
                                    -PolicyAssignmentName $PolicyAssignmentName `
                                    -PolicyAssignmentDisplayName $PolicyAssignmentDisplayName `
                                    -PolicyAssignmentDescription $PolicyAssignmentDescription `
                                    -PolicyAssignmentIdentity $PolicyAssignmentIdentity `
                                    -PolicyAssigmentLimit $LimitPOLICYPolicyAssignmentsSubscription `
                                    -PolicyAssigmentCount $L1mgmtGroupSubPolicyAssignmentsPolicyCount `
                                    -PolicyAssigmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount `
                                    -PolicyAssigmentParameters $L1mgmtGroupSubPolicyAssignment.Properties.Parameters `
                                    -PolicySetAssigmentLimit $LimitPOLICYPolicySetAssignmentsSubscription `
                                    -PolicySetAssigmentCount $L1mgmtGroupSubPolicyAssignmentsPolicySetCount `
                                    -PolicySetAssigmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount `
                                    -PolicyAndPolicySetAssigmentAtScopeCount $L1mgmtGroupSubPolicyAssignmentsPolicyAndPolicySetAtScopeCount
                            }
                        }
                    }

                    #SubscriptionRoles
                    $currentTask = "Custom Role definitions '$($childMgSubDisplayName)' ('$childMgSubId')"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Authorization/roleDefinitions?api-version=2015-07-01&`$filter=type%20eq%20'CustomRole'"
                    #$path = "/subscriptions/$childMgSubId/providers/Microsoft.Authorization/roleDefinitions?api-version=2015-07-01&`$filter=type%20eq%20'CustomRole'"
                    $method = "GET"
                    
                    $subCustomRoleDefinitions = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -caller "CustomDataCollection"))
                    foreach ($subCustomRoleDefinition in $subCustomRoleDefinitions) {
                        if (-not $($htCacheDefinitions).role[$subCustomRoleDefinition.name]) {
                            ($script:htCacheDefinitions).role.$($subCustomRoleDefinition.name) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                            ($script:htCacheDefinitions).role.$($subCustomRoleDefinition.name).id = $($subCustomRoleDefinition.name)
                            ($script:htCacheDefinitions).role.$($subCustomRoleDefinition.name).Name = $($subCustomRoleDefinition.properties.roleName)
                            ($script:htCacheDefinitions).role.$($subCustomRoleDefinition.name).IsCustom = $true
                            ($script:htCacheDefinitions).role.$($subCustomRoleDefinition.name).AssignableScopes = $($subCustomRoleDefinition.properties.AssignableScopes)
                            ($script:htCacheDefinitions).role.$($subCustomRoleDefinition.name).Actions = $($subCustomRoleDefinition.properties.permissions.Actions)
                            ($script:htCacheDefinitions).role.$($subCustomRoleDefinition.name).NotActions = $($subCustomRoleDefinition.properties.permissions.NotActions)
                            ($script:htCacheDefinitions).role.$($subCustomRoleDefinition.name).DataActions = $($subCustomRoleDefinition.properties.permissions.DataActions)
                            ($script:htCacheDefinitions).role.$($subCustomRoleDefinition.name).NotDataActions = $($subCustomRoleDefinition.properties.permissions.NotDataActions)
                            ($script:htCacheDefinitions).role.$($subCustomRoleDefinition.name).json = $subCustomRoleDefinition
                        }  
                    }

                    #SubscriptionRoleAssignments
                    $currentTask = "Role assignments usage metrics '$($childMgSubDisplayName)' ('$childMgSubId')"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Authorization/roleAssignmentsUsageMetrics?api-version=2019-08-01-preview"
                    #$path = "/subscriptions/$childMgSubId/providers/Microsoft.Authorization/roleAssignmentsUsageMetrics?api-version=2019-08-01-preview"
                    $method = "GET"
                    $roleAssignmentsUsage = ((AzAPICall -uri $uri -method $method -currentTask $currentTask -listenOn "Content" -caller "CustomDataCollection"))

                    #cmdletgetazroleassignment
                    $retryCmletCount = 0
                    do {
                        $errorOccurred = "no"
                        $retryCmletCount++
                        try {
                            $L1mgmtGroupSubRoleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$($childMgSubId)" -ErrorAction SilentlyContinue
                        }
                        catch {
                            $errorOccurred = "yes"
                        }
                        if ($errorOccurred -ne "no") {
                            Write-Host "try#$($retryCmletCount) cmdlet Get-AzRoleAssignment Subscription '$($childMgSubId)' failed, retry in $($retryCmletCount) seconds"
                            start-sleep -Seconds $retryCmletCount
                        }
                    }
                    until($errorOccurred -eq "no")
                    
                    foreach ($L1mgmtGroupSubRoleAssignmentOnRg in $L1mgmtGroupSubRoleAssignments | Where-Object { $_.RoleAssignmentId -match "/subscriptions/$($childMgSubId)/resourcegroups/" }) {
                        $null = $script:arrayCacheRoleAssignmentsResourceGroups.Add($L1mgmtGroupSubRoleAssignmentOnRg)
                        if (-not ($htCacheAssignments).rbacOnResourceGroupsAndResources.($L1mgmtGroupSubRoleAssignmentOnRg.RoleAssignmentId)) {
                            ($script:htCacheAssignments).rbacOnResourceGroupsAndResources.($L1mgmtGroupSubRoleAssignmentOnRg.RoleAssignmentId) = $L1mgmtGroupSubRoleAssignmentOnRg
                        }
                    }

                    foreach ($L1mgmtGroupSubRoleAssignment in $L1mgmtGroupSubRoleAssignments | Where-Object { $_.RoleAssignmentId -notmatch "/subscriptions/$($childMgSubId)/resourcegroups/" }) {

                        if (-not $($htCacheAssignments).role[$L1mgmtGroupSubRoleAssignment.RoleAssignmentId]) {
                            $($script:htCacheAssignments).role.$($L1mgmtGroupSubRoleAssignment.RoleAssignmentId) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                            $($script:htCacheAssignments).role.$($L1mgmtGroupSubRoleAssignment.RoleAssignmentId) = $L1mgmtGroupSubRoleAssignment
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
                            $RoleAssignmentIdentityDisplayname = "n/a" 
                        }
                        else {
                            if ($L1mgmtGroupSubRoleAssignment.ObjectType -eq "User") {
                                if ($htParameters.DoNotShowRoleAssignmentsUserData -eq $false) {
                                    $RoleAssignmentIdentityDisplayname = $L1mgmtGroupSubRoleAssignment.DisplayName
                                }
                                else {
                                    $RoleAssignmentIdentityDisplayname = "scrubbed"
                                }
                            }
                            else {
                                $RoleAssignmentIdentityDisplayname = $L1mgmtGroupSubRoleAssignment.DisplayName
                            }
                        }                
                        if (($L1mgmtGroupSubRoleAssignment.SignInName).length -eq 0) {
                            $RoleAssignmentIdentitySignInName = "n/a" 
                        }
                        else {
                            if ($L1mgmtGroupSubRoleAssignment.ObjectType -eq "User") {
                                if ($htParameters.DoNotShowRoleAssignmentsUserData -eq $false) {
                                    $RoleAssignmentIdentitySignInName = $L1mgmtGroupSubRoleAssignment.SignInName
                                }
                                else {
                                    $RoleAssignmentIdentitySignInName = "scrubbed"
                                }
                            }
                            else {
                                $RoleAssignmentIdentitySignInName = $L1mgmtGroupSubRoleAssignment.SignInName
                            }
                        }
                        
                        $RoleAssignmentIdentityObjectId = $L1mgmtGroupSubRoleAssignment.ObjectId
                        $RoleAssignmentIdentityObjectType = $L1mgmtGroupSubRoleAssignment.ObjectType
                        $RoleAssignmentId = $L1mgmtGroupSubRoleAssignment.RoleAssignmentId
                        $RoleAssignmentScope = $L1mgmtGroupSubRoleAssignment.Scope
                        $RoleAssignmentScopeName = $RoleAssignmentScope -replace '.*/'

                        $RoleSecurityCustomRoleOwner = 0
                        if (($htCacheDefinitions).$definitiontype.$($Id).Actions -eq '*' -and ((($htCacheDefinitions).$definitiontype.$($Id).NotActions)).length -eq 0 -and ($htCacheDefinitions).$definitiontype.$($Id).IsCustom -eq $True) {
                            $RoleSecurityCustomRoleOwner = 1
                        }
                        $RoleSecurityOwnerAssignmentSP = 0
                        if ((($htCacheDefinitions).$definitiontype.$($Id).id -eq '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' -and $RoleAssignmentIdentityObjectType -eq "ServicePrincipal") -or (($htCacheDefinitions).$definitiontype.$($Id).Actions -eq '*' -and ((($htCacheDefinitions).$definitiontype.$($Id).NotActions)).length -eq 0 -and ($htCacheDefinitions).$definitiontype.$($Id).IsCustom -eq $True -and $RoleAssignmentIdentityObjectType -eq "ServicePrincipal")) {
                            $RoleSecurityOwnerAssignmentSP = 1
                        }

                        addRowToTable `
                            -level $hierarchyLevel `
                            -mgName $childMgDisplayName `
                            -mgId $childMgId `
                            -mgParentId $childMgParentId `
                            -mgParentName $childMgParentName `
                            -Subscription $childMgSubDisplayName `
                            -SubscriptionId $childMgSubId `
                            -SubscriptionQuotaId $subscriptionQuotaId `
                            -SubscriptionState $subscriptionState `
                            -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                            -SubscriptionTags $subscriptionTags `
                            -SubscriptionTagsCount $subscriptionTagsCount `
                            -RoleDefinitionId ($htCacheDefinitions).$definitiontype.$($Id).id `
                            -RoleDefinitionName $RoleDefinitionName `
                            -RoleIsCustom ($htCacheDefinitions).$definitiontype.$($Id).IsCustom `
                            -RoleAssignableScopes (($htCacheDefinitions).$definitiontype.$($Id).AssignableScopes -join "$CsvDelimiterOpposite ") `
                            -RoleActions (($htCacheDefinitions).$definitiontype.$($Id).Actions -join "$CsvDelimiterOpposite ") `
                            -RoleNotActions (($htCacheDefinitions).$definitiontype.$($Id).NotActions -join "$CsvDelimiterOpposite ") `
                            -RoleDataActions (($htCacheDefinitions).$definitiontype.$($Id).DataActions -join "$CsvDelimiterOpposite ") `
                            -RoleNotDataActions (($htCacheDefinitions).$definitiontype.$($Id).NotDataActions -join "$CsvDelimiterOpposite ") `
                            -RoleAssignmentIdentityDisplayname $RoleAssignmentIdentityDisplayname `
                            -RoleAssignmentIdentitySignInName $RoleAssignmentIdentitySignInName `
                            -RoleAssignmentIdentityObjectId $RoleAssignmentIdentityObjectId `
                            -RoleAssignmentIdentityObjectType $RoleAssignmentIdentityObjectType `
                            -RoleAssignmentId $RoleAssignmentId `
                            -RoleAssignmentScope $RoleAssignmentScope `
                            -RoleAssignmentScopeName $RoleAssignmentScopeName `
                            -RoleAssignmentsLimit $roleAssignmentsUsage.roleAssignmentsLimit `
                            -RoleAssignmentsCount $roleAssignmentsUsage.roleAssignmentsCurrentCount `
                            -RoleSecurityCustomRoleOwner $RoleSecurityCustomRoleOwner `
                            -RoleSecurityOwnerAssignmentSP $RoleSecurityOwnerAssignmentSP
                    }
                }
            }
            else {
                addRowToTable `
                    -level $hierarchyLevel `
                    -mgName $childMgDisplayName `
                    -mgId $childMgId `
                    -mgParentId $childMgParentId `
                    -mgParentName $childMgParentName `
                    -Subscription $childMgSubDisplayName `
                    -SubscriptionId $childMgSubId
            }
            $endSubLoopThis = get-date
            $null = $script:customDataCollectionDuration.Add([PSCustomObject]@{ 
                    Type        = "SUB"
                    Id          = $childMgSubId
                    DurationSec = (NEW-TIMESPAN -Start $startSubLoopThis -End $endSubLoopThis).TotalSeconds
                })

            $null = $script:arrayDataCollectionProgressSub.Add($childMgSubId)
            $progressCount = ($arrayDataCollectionProgressSub).Count
            Write-Host "  $($progressCount)/$($childrenSubscriptionsCount) Subscriptions processed"
    
        } -ThrottleLimit $ThrottleLimit

        $endSubLoop = get-date
        Write-Host " CustomDataCollection Subscriptions processing duration: $((NEW-TIMESPAN -Start $startSubLoop -End $endSubLoop).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startSubLoop -End $endSubLoop).TotalSeconds) seconds)"
    }

}

#endregion Function_dataCollection

#HTML
#
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
            $parentId = ($optimizedTableForPathQueryMg | Where-Object { $_.mgid -eq $mgid } | Sort-Object -Unique).mgParentId
            $mgid = $parentId
            $script:submgPathArray += "'$parentId'"
        }
        until($parentId -eq $mgSubPathTopMg)
    }
}

function hierarchyMgHTML($mgChild) { 
    $mgDetails = ($optimizedTableForPathQueryMg | Where-Object { $_.MgId -eq "$mgChild" }) | Get-Unique
    $mgName = $mgDetails.mgName
    $mgId = $mgDetails.MgId

    if ($mgId -eq ($checkContext).Tenant.id) {
        if ($mgId -eq $defaultManagementGroupId) {
            $class = "class=`"tenantRootGroup mgnonradius defaultMG`""
        }
        else {
            $class = "class=`"tenantRootGroup mgnonradius`""
        }
        
        $liclass = "class=`"first`""
        $liId = "id=`"first`""
        $tenantDisplayNameAndDefaultDomain = $tenantDetailsDisplay
    }
    else {
        if ($mgId -eq $defaultManagementGroupId) {
            $class = "class=`"mgnonradius defaultMG`""
        }
        else {
            $class = "class=`"mgnonradius`""
        }
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
    $childMgs = ($optimizedTableForPathQueryMg | Where-Object { $_.mgParentId -eq "$mgId" }).MgId | Sort-Object -Unique
    if (($childMgs | measure-object).count -gt 0) {
        $script:html += @"
                <ul>
"@
        foreach ($childMg in $childMgs) {
            hierarchyMgHTML -mgChild $childMg
        }
        hierarchySubForMgHTML -mgChild $mgId
        $script:html += @"
                </ul>
            </li>    
"@
    }
    else {
        hierarchySubForMgUlHTML -mgChild $mgId
        $script:html += @"
            </li>
"@
    }
}

function hierarchySubForMgHTML($mgChild) {
    $subscriptions = ($optimizedTableForPathQueryMgAndSub | Where-Object { $_.MgId -eq $mgChild }).SubscriptionId | Get-Unique
    $subscriptionsCnt = ($subscriptions | measure-object).count
    $subscriptionsOutOfScopelinked = $outOfScopeSubscriptions | Where-Object { $_.ManagementGroupId -eq $mgChild }
    $subscriptionsOutOfScopelinkedCnt = ($subscriptionsOutOfScopelinked | Measure-Object).count
    Write-Host "  Building HierarchyMap for MG '$mgChild', $(($subscriptions | measure-object).count) Subscriptions"
    if ($subscriptionsCnt -gt 0 -or $subscriptionsOutOfScopelinkedCnt -gt 0) {
        if ($subscriptionsCnt -gt 0 -and $subscriptionsOutOfScopelinkedCnt -gt 0) {
            $script:html += @"
            <li><a href="#table_$mgChild"><p id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg">$(($subscriptions | measure-object).count)x <img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg">$(($subscriptionsOutOfScopelinked | Measure-Object).count)x</p></a></li>
"@
        }
        if ($subscriptionsCnt -gt 0 -and $subscriptionsOutOfScopelinkedCnt -eq 0) {
            $script:html += @"
            <li><a href="#table_$mgChild"><p id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> $(($subscriptions | measure-object).count)x</p></a></li>
"@
        }
        if ($subscriptionsCnt -eq 0 -and $subscriptionsOutOfScopelinkedCnt -gt 0) {
            $script:html += @"
            <li><a href="#table_$mgChild"><p id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg">$(($subscriptionsOutOfScopelinked | Measure-Object).count)x</p></a></li>
"@
        }
    }
}

function hierarchySubForMgUlHTML($mgChild) {
    $subscriptions = ($optimizedTableForPathQueryMgAndSub | Where-Object { $_.MgId -eq $mgChild }).SubscriptionId | Get-Unique
    $subscriptionsCnt = ($subscriptions | measure-object).count
    $subscriptionsOutOfScopelinked = $outOfScopeSubscriptions | Where-Object { $_.ManagementGroupId -eq $mgChild }
    $subscriptionsOutOfScopelinkedCnt = ($subscriptionsOutOfScopelinked | Measure-Object).count
    Write-Host "  Building HierarchyMap for MG '$mgChild', $(($subscriptions | measure-object).count) Subscriptions"
    if ($subscriptionsCnt -gt 0 -or $subscriptionsOutOfScopelinkedCnt -gt 0) {
        if ($subscriptionsCnt -gt 0 -and $subscriptionsOutOfScopelinkedCnt -gt 0) {
            $script:html += @"
            <ul><li><a href="#table_$mgChild"><p id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> $(($subscriptions | measure-object).count)x <img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg">$(($subscriptionsOutOfScopelinked | Measure-Object).count)x</p></a></li></ul>
"@
        }
        if ($subscriptionsCnt -gt 0 -and $subscriptionsOutOfScopelinkedCnt -eq 0) {
            $script:html += @"
            <ul><li><a href="#table_$mgChild"><p id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> $(($subscriptions | measure-object).count)x</p></a></li></ul>
"@
        }
        if ($subscriptionsCnt -eq 0 -and $subscriptionsOutOfScopelinkedCnt -gt 0) {
            $script:html += @"
            <ul><li><a href="#table_$mgChild"><p id="hierarchySub_$mgChild"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg">$(($subscriptionsOutOfScopelinked | Measure-Object).count)x</p></a></li></ul>
"@
        }
    }
}

function tableMgHTML($mgChild, $mgChildOf) {
    $mgDetails = ($optimizedTableForPathQueryMg | Where-Object { $_.MgId -eq "$mgChild" }) | Get-Unique
    $mgName = $mgDetails.mgName
    $mgLevel = $mgDetails.Level
    $mgId = $mgDetails.MgId

    if ($mgId -eq $defaultManagementGroupId) {
        $classDefaultMG = "defaultMG"
    }
    else {
        $classDefaultMG = ""
    }

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

    $mgLinkedSubsCount = ((($optimizedTableForPathQuery | Where-Object { $_.MgId -eq $mgChild -and -not [String]::IsNullOrEmpty($_.SubscriptionId) }).SubscriptionId | Get-Unique) | measure-object).count
    $subscriptionsOutOfScopelinkedCount = ($outOfScopeSubscriptions | Where-Object { $_.ManagementGroupId -eq $mgChild } | Measure-Object).count
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

    if ($mgName -eq $mgId) {
        $mgNameAndOrId = "<b>$mgName</b>"
    }
    else {
        $mgNameAndOrId = "<b>$mgName</b> ($mgId)"
    }

    $script:html += @"
<button type="button" class="collapsible" id="table_$mgId">$levelSpacing<img class="imgMg $($classDefaultMG)" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> <span class="valignMiddle">$mgNameAndOrId $subInfo</span></button>
<div class="content">
<table class="bottomrow">
<tr><td class="detailstd"><p><a href="#hierarchy_$mgId"><i class="fa fa-eye" aria-hidden="true"></i> <i>Highlight Management Group in HierarchyMap</i></a></p></td></tr>
"@
    if ($mgId -eq $defaultManagementGroupId) {
        $script:html += @"
        <tr><td class="detailstd"><p><i class="fa fa-circle" aria-hidden="true" style="color:#FFCBC7"></i> <b>Default</b> Management Group <a class="externallink" href="https://docs.microsoft.com/en-us/azure/governance/management-groups/how-to/protect-resource-hierarchy#setting---default-management-group" target="_blank">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p></td></tr>
"@
    }
    $script:html += @"
<tr><td class="detailstd"><p>Management Group Name: <b>$mgName</b></p></td></tr>
<tr><td class="detailstd"><p>Management Group Id: <b>$mgId</b></p></td></tr>
<tr><td class="detailstd"><p>Management Group Path: $mgPath</p></td></tr>
<tr><!--x--><td class="detailstd"><!--x-->
"@
    tableMgSubDetailsHTML -mgOrSub "mg" -mgchild $mgId
    tableSubForMgHTML -mgChild $mgId
    $childMgs = ($optimizedTableForPathQueryMg | Where-Object { $_.mgParentId -eq "$mgId" }).MgId | sort-object -Unique
    if (($childMgs | measure-object).count -gt 0) {
        foreach ($childMg in $childMgs) {
            tableMgHTML -mgChild $childMg -mgChildOf $mgId
        }
    }
}

function tableSubForMgHTML($mgChild) { 
    $subscriptions = ($optimizedTableForPathQueryMgAndSub | Where-Object { $_.MgId -eq $mgChild })
    $subscriptionLinkedCount = ($subscriptions | measure-object).count
    $subscriptionsOutOfScopelinked = $outOfScopeSubscriptions | Where-Object { $_.ManagementGroupId -eq $mgChild }
    $subscriptionsOutOfScopelinkedCount = ($subscriptionsOutOfScopelinked | Measure-Object).count
    if ($subscriptionsOutOfScopelinkedCount -gt 0) {
        $subscriptionsOutOfScopelinkedInfo = "($subscriptionsOutOfScopelinkedCount out-of-scope)"
    }
    else {
        $subscriptionsOutOfScopelinkedInfo = ""
    }
    Write-Host "  Building ScopeInsights MG '$mgChild', $subscriptionLinkedCount Subscriptions"
    if ($subscriptionLinkedCount -gt 0) {
        $script:html += @"
    <tr>
        <td class="detailstd">
            <button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $subscriptionLinkedCount Subscriptions linked $subscriptionsOutOfScopelinkedInfo</p></button>
            <div class="content"><!--collapsible-->
"@
        foreach ($subEntry in $subscriptions | sort-object -Property subscription, subscriptionId) {
            $subPath = $htAllSubsMgPath.($subEntry.subscriptionId).path -join "/"
            if ($subscriptionLinkedCount -gt 1) {
                $script:html += @"
                <button type="button" class="collapsible"> <img class="imgSub" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle"><b>$($subEntry.subscription)</b> ($($subEntry.subscriptionId))</span></button>
                <div class="contentSub"><!--collapsiblePerSub-->
"@
            }
            #exactly 1
            else {
                $script:html += @"
                <img class="imgSub" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle"><b>$($subEntry.subscription)</b> ($($subEntry.subscriptionId))</span></button>
"@
            }

            $script:html += @"
<table class="subTable">
<tr><td class="detailstd"><p><a href="#hierarchySub_$mgChild"><i class="fa fa-eye" aria-hidden="true"></i> <i>Highlight Subscription in HierarchyMap</i></a></p></td></tr>
<tr><td class="detailstd"><p>Subscription Name: <b>$($subEntry.subscription)</b></p></td></tr>
<tr><td class="detailstd"><p>Subscription Id: <b>$($subEntry.subscriptionId)</b></p></td></tr>
<tr><td class="detailstd"><p>Subscription Path: $subPath</p></td></tr>
<tr><td class="detailstd">
"@
            tableMgSubDetailsHTML -mgOrSub "sub" -subscriptionId $subEntry.subscriptionId
            $script:html += @"
                </table><!--subTable-->
"@
            if ($subscriptionLinkedCount -gt 1) {
                $script:html += @"
                </div><!--collapsiblePerSub-->
"@
            }
        }
        $script:html += @"
            </div><!--collapsible-->
"@

    }
    else {
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
#region ScopeInsights
function tableMgSubDetailsHTML($mgOrSub, $mgChild, $subscriptionId) {
    $script:scopescnter++
    $htmlScopeInsights = $null
    #region ScopeInsightsBaseCollection
    if ($mgOrSub -eq "mg") {
        #$startScopeInsightsPreQueryMg = get-date
        #BLUEPRINT
        $blueprintReleatedQuery = $blueprintBaseQuery | Where-Object { $_.MgId -eq $mgChild -and [String]::IsNullOrEmpty($_.SubscriptionId) -and [String]::IsNullOrEmpty($_.BlueprintAssignmentId) }
        $blueprintsScoped = $blueprintReleatedQuery
        $blueprintsScopedCount = ($blueprintsScoped | measure-object).count
        #Resources
        $mgAllChildSubscriptions = [System.Collections.ArrayList]@()
        $mgAllChildSubscriptions = foreach ($entry in $htAllSubsMgPath.keys) {
            if (($htAllSubsMgPath.($entry).path) -contains "'$mgchild'") {
                $entry
            }
        }
        $resourcesAllChildSubscriptions = [System.Collections.ArrayList]@()
        foreach ($mgAllChildSubscription in $mgAllChildSubscriptions) {
            foreach ($resource in ($resourcesAllGroupedBySubcriptionId | where-object { $_.name -eq $mgAllChildSubscription }).group | Sort-Object -Property type, location) {
                $null = $resourcesAllChildSubscriptions.Add($resource)
            }

        }
        $resourcesAllChildSubscriptionsArray = [System.Collections.ArrayList]@()
        $grp = $resourcesAllChildSubscriptions | Group-Object -Property type, location
        foreach ($resLoc in $grp) {
            $cnt = 0
            $ResoureTypeAndLocation = $resLoc.Name -split ","
            $resLoc.Group.count_ | ForEach-Object { $cnt += $_ }
            $null = $resourcesAllChildSubscriptionsArray.Add([PSCustomObject]@{ 
                    ResourceType  = $ResoureTypeAndLocation[0]
                    Location      = $ResoureTypeAndLocation[1]
                    ResourceCount = $cnt 
                })
        }
        $resourcesAllChildSubscriptions.count_ | ForEach-Object { $resourcesAllChildSubscriptionTotal += $_ }
        $resourcesAllChildSubscriptionResourceTypeCount = (($resourcesAllChildSubscriptions | sort-object -Property type -Unique) | measure-object).count
        $resourcesAllChildSubscriptionLocationCount = (($resourcesAllChildSubscriptions | sort-object -Property location -Unique) | measure-object).count

        #childrenMgInfo
        $mgAllChildMgs = [System.Collections.ArrayList]@()
        $mgAllChildMgs = foreach ($entry in $htAllMgsPath.keys) {
            if (($htAllMgsPath.($entry).path) -contains "'$mgchild'") {
                $entry
            }
        }
    
        $policyAssignmentsAllArrayForThisManagementGroup = ($policyAssignmentsAllArrayGroupedByManagementGroup | where-Object { $_.name -eq $mgChild }).group
        $policyAssignmentsAllArrayForThisManagementGroupGroupedByPolicyVariant = $policyAssignmentsAllArrayForThisManagementGroup | Group-Object -Property PolicyVariant
        $policyAssignmentsAllArrayForThisManagementGroupVariantPolicy = ($policyAssignmentsAllArrayForThisManagementGroupGroupedByPolicyVariant | where-Object { $_.name -eq "Policy" }).group
        $policyAssignmentsAllArrayForThisManagementGroupVariantPolicySet = ($policyAssignmentsAllArrayForThisManagementGroupGroupedByPolicyVariant | where-Object { $_.name -eq "PolicySet" }).group
        
        $cssClass = "mgDetailsTable"

        #$endScopeInsightsPreQueryMg = get-date
        #Write-Host "   ScopeInsights MG PreQuery processing duration: $((NEW-TIMESPAN -Start $startScopeInsightsPreQueryMg -End $endScopeInsightsPreQueryMg).TotalSeconds) seconds"
    }
    if ($mgOrSub -eq "sub") {
        #$startScopeInsightsPreQuerySub = get-date
        #BLUEPRINT
        $blueprintReleatedQuery = $blueprintBaseQuery | Where-Object { $_.SubscriptionId -eq $subscriptionId -and -not [String]::IsNullOrEmpty($_.BlueprintName) }
        $blueprintsAssigned = $blueprintReleatedQuery | Where-Object { -not [String]::IsNullOrEmpty($_.BlueprintAssignmentId) }
        $blueprintsAssignedCount = ($blueprintsAssigned | measure-object).count
        $blueprintsScoped = $blueprintReleatedQuery | Where-Object { $_.BlueprintScoped -eq "/subscriptions/$subscriptionId" -and [String]::IsNullOrEmpty($_.BlueprintAssignmentId) }
        $blueprintsScopedCount = ($blueprintsScoped | measure-object).count
        #SubscriptionDetails
        $subscriptionDetailsReleatedQuery = $optimizedTableForPathQuerySub | Where-Object { $_.SubscriptionId -eq $subscriptionId }
        $subscriptionState = ($subscriptionDetailsReleatedQuery).SubscriptionState
        $subscriptionQuotaId = ($subscriptionDetailsReleatedQuery).SubscriptionQuotaId    
        $subscriptionResourceGroupsCount = ($resourceGroupsAll | Where-Object { $_.subscriptionId -eq $subscriptionId }).count_
        if (-not $subscriptionResourceGroupsCount) {
            $subscriptionResourceGroupsCount = 0
        }
        $subscriptionASCPoints = ($subscriptionDetailsReleatedQuery).SubscriptionASCSecureScore
        #Resources
        $resourcesSubscription = [System.Collections.ArrayList]@()      
        foreach ($resource in ($resourcesAllGroupedBySubcriptionId | where-object { $_.name -eq $subscriptionId }).group | Sort-Object -Property type, location) {
            $null = $resourcesSubscription.Add($resource)
        }
        
        $resourcesSubscriptionTotal = 0
        $resourcesSubscription.count_ | ForEach-Object { $resourcesSubscriptionTotal += $_ }
        $resourcesSubscriptionResourceTypeCount = (($resourcesSubscription | sort-object -Property type -Unique) | measure-object).count
        $resourcesSubscriptionLocationCount = (($resourcesSubscription | sort-object -Property location -Unique) | measure-object).count


        $policyAssignmentsAllArrayForThisSubscription = ($policyAssignmentsAllArrayGroupedBySubscription | where-Object { $_.name -eq $subscriptionId }).group
        $policyAssignmentsAllArrayForThisSubscriptionGroupedByPolicyVariant = $policyAssignmentsAllArrayForThisSubscription | Group-Object -Property PolicyVariant
        $policyAssignmentsAllArrayForThisSubscriptionVariantPolicy = ($policyAssignmentsAllArrayForThisSubscriptionGroupedByPolicyVariant | where-Object { $_.name -eq "Policy" }).group
        $policyAssignmentsAllArrayForThisSubscriptionVariantPolicySet = ($policyAssignmentsAllArrayForThisSubscriptionGroupedByPolicyVariant | where-Object { $_.name -eq "PolicySet" }).group

        $cssClass = "subDetailsTable"

        #$endScopeInsightsPreQuerySub = get-date
        #Write-Host "   ScopeInsights SUB PreQuery processing duration: $((NEW-TIMESPAN -Start $startScopeInsightsPreQuerySub -End $endScopeInsightsPreQuerySub).TotalSeconds) seconds"
    }
    #endregion ScopeInsightsBaseCollection

    if ($mgOrSub -eq "sub") {

        $htmlScopeInsights += @"
<p>State: $subscriptionState</p>
</td></tr>
<tr><td class="detailstd"><p>QuotaId: $subscriptionQuotaId</p></td></tr>
<tr><td class="detailstd"><p><i class="fa fa-shield" aria-hidden="true"></i> ASC Secure Score: $subscriptionASCPoints <a class="externallink" href="https://www.youtube.com/watch?v=2EMnzxdqDhA" target="_blank">Video <i class="fa fa-external-link" aria-hidden="true"></i></a>, <a class="externallink" href="https://techcommunity.microsoft.com/t5/azure-security-center/security-controls-in-azure-security-center-enable-endpoint/ba-p/1624653" target="_blank">Blog <i class="fa fa-external-link" aria-hidden="true"></i></a></p></td></tr>
<tr><td class="detailstd">
"@
        #Tags
        #region ScopeInsightsTags
        $tagsSubscriptionCount = ($htSubscriptionTags.$subscriptionId.Keys | Measure-Object).count
        if ($tagsSubscriptionCount -gt 0) {
            $tfCount = $tagsSubscriptionCount
            $htmlTableId = "ScopeInsights_Tags_$($subscriptionId -replace '-','_')"
            $randomFunctionName = "func_$htmlTableId"
            $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible">
<p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $tagsSubscriptionCount Subscription Tags | Limit: ($tagsSubscriptionCount/$LimitTagsSubscription)</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">Tag Name</th>
<th>Tag Value</th>
</tr>
</thead>
<tbody>
"@
            $htmlScopeInsightsTags = $null
            $htmlScopeInsightsTags = foreach ($tag in (($htSubscriptionTags).($subscriptionId)).keys | Sort-Object) {
                @"
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$htmlTableId !== 1) { 
   window.helpertfConfig4$htmlTableId =1;
   var tfConfig4$htmlTableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
            var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
            tf.init();}}
        </script>
    </div>
"@
        }
        else {
            $htmlScopeInsights += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> $tagsSubscriptionCount Subscription Tags</p>
"@
        }
        $htmlScopeInsights += @"
        </td></tr>
        <tr><!--y--><td class="detailstd"><!--y-->
"@
        #endregion ScopeInsightsTags

        #TagNameUsage
        #region ScopeInsightsTagNameUsage
        $arrayTagListSubscription = [System.Collections.ArrayList]@()
        foreach ($tagScope in $htSubscriptionTagList.($subscriptionId).keys) {
            foreach ($tagScopeTagName in $htSubscriptionTagList.($subscriptionId).$tagScope.Keys) {
                $null = $arrayTagListSubscription.Add([PSCustomObject]@{ 
                        Scope    = $tagScope
                        TagName  = ($tagScopeTagName)
                        TagCount = $htAllTagList.($tagScope).($tagScopeTagName)
                    })
            }
        }
        $tagsUsageCount = ($arrayTagListSubscription | Measure-Object).Count

        if ($tagsUsageCount -gt 0) {
            $tagNamesUniqueCount = ($arrayTagListSubscription | Sort-Object -Property TagName -Unique | Measure-Object).Count
            $tagNamesUsedInScopes = ($arrayTagListSubscription | Sort-Object -Property Scope -Unique).scope -join "$($CsvDelimiterOpposite) "
            $tfCount = $arrayTagListSubscriptionUniqueTagsCount
            $htmlTableId = "ScopeInsights_TagNameUsage_$($subscriptionId -replace '-','_')"
            $randomFunctionName = "func_$htmlTableId"
            $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible">
<p><i class="fa fa-check-circle blue" aria-hidden="true"></i> Tag Name Usage ($tagNamesUniqueCount unique Tag Names applied at $($tagNamesUsedInScopes)</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Scope</th>
<th>TagName</th>
<th>Count</th>
</tr>
</thead>
<tbody>
"@
            $htmlScopeInsightsTagsUsage = $null
            $htmlScopeInsightsTagsUsage = foreach ($tagEntry in $arrayTagListSubscription | Sort-Object Scope, TagName) {
                @"
<tr>
<td>$($tagEntry.Scope)</td>
<td>$($tagEntry.TagName)</td>
<td>$($tagEntry.TagCount)</td>
</tr>
"@        
            }
            $htmlScopeInsights += $htmlScopeInsightsTagsUsage 
            $htmlScopeInsights += @"
            </tbody>
        </table>
        <script>
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$htmlTableId !== 1) { 
            window.helpertfConfig4$htmlTableId =1;
            var tfConfig4$htmlTableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                $htmlScopeInsights += @"
            paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
            }
            $htmlScopeInsights += @"
            btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'multiple',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number'
                ],
            extensions: [{ name: 'sort' }]
            };
            var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
            tf.init();}}
        </script>
    </div>
"@
        }
        else {
            $htmlScopeInsights += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> Tag Name Usage ($tagsUsageCount Tags)</p>
"@
        }
        $htmlScopeInsights += @"
        </td></tr>
        <tr><!--y--><td class="detailstd"><!--y-->
"@
        #endregion ScopeInsightsTagNameUsage

        #Consumption
        #region ScopeInsightsConsumptionSub
        if ($htParameters.NoAzureConsumption -eq $false) {
            $consumptionData = ($groupAllConsumptionDataBySubscriptionId | Where-Object { $_.name -eq $subscriptionId }).group
            
            if (($consumptionData | Measure-Object).Count -gt 0) {
                $arrayTotalCostSummary = @()
                $arrayConsumptionData = [System.Collections.ArrayList]@()
                $consumptionDataGroupedByCurrency = $consumptionData | group-object -property Currency

                foreach ($currency in $consumptionDataGroupedByCurrency) {
                    $totalCost = 0
                    $tenantSummaryConsumptionDataGrouped = $currency.group | group-object -property ConsumedService, ChargeType, MeterCategory
                    $subsCount = ($tenantSummaryConsumptionDataGrouped.group.subscriptionId | Sort-Object -Unique | Measure-Object).Count
                    $consumedServiceCount = ($tenantSummaryConsumptionDataGrouped.group.consumedService | Sort-Object -Unique | Measure-Object).Count
                    $resourceCount = ($tenantSummaryConsumptionDataGrouped.group.ResourceId | Sort-Object -Unique | Measure-Object).Count
                    foreach ($consumptionline in $tenantSummaryConsumptionDataGrouped) {
        
                        $costConsumptionLine = ($consumptionline.group.PreTaxCost | Measure-Object -Sum).Sum
                        if ([math]::Round($costConsumptionLine, 4) -eq 0) {
                            $cost = $costConsumptionLine
                        }
                        else {
                            $cost = [math]::Round($costConsumptionLine, 4)
                        }
                        
                        $null = $arrayConsumptionData.Add([PSCustomObject]@{ 
                                ConsumedService              = ($consumptionline.name).split(", ")[0]
                                ConsumedServiceChargeType    = ($consumptionline.name).split(", ")[1]
                                ConsumedServiceCategory      = ($consumptionline.name).split(", ")[2]
                                ConsumedServiceInstanceCount = $consumptionline.Count
                                ConsumedServiceCost          = [decimal]$cost
                                ConsumedServiceCurrency      = $currency.Name
                            })
                        
                        $totalCost = $totalCost + $costConsumptionLine
        
                    }
                    if ([math]::Round($totalCost, 4) -eq 0) {
                        $totalCost = $totalCost
                    }
                    else {
                        $totalCost = [math]::Round($totalCost, 4)
                    }
                    $arrayTotalCostSummary += "$([decimal]$totalCost) $($currency.Name) generated by $($resourceCount) Resources ($($consumedServiceCount) ResourceTypes)"
                }

                $tfCount = ($arrayConsumptionData | Measure-Object).Count
                $htmlTableId = "ScopeInsights_Consumption_$($subscriptionId -replace '-','_')"
                $randomFunctionName = "func_$htmlTableId"
                $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><i class="fa fa-credit-card" aria-hidden="true" style="color: #0078df"></i> Total cost $($arrayTotalCostSummary -join ", ") last $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>ChargeType</th>
<th>ResourceType</th>
<th>Category</th>
<th>ResourceCount</th>
<th>Cost ($($AzureConsumptionPeriod)d)</th>
<th>Currency</th>
</tr>
</thead>
<tbody>
"@
                $htmlScopeInsightsConsumptionSub = $null
                $htmlScopeInsightsConsumptionSub = foreach ($consumptionLine in $arrayConsumptionData) {
                    @"
<tr>
<td>$($consumptionLine.ConsumedServiceChargeType)</td>
<td>$($consumptionLine.ConsumedService)</td>
<td>$($consumptionLine.ConsumedServiceCategory)</td>
<td>$($consumptionLine.ConsumedServiceInstanceCount)</td>
<td>$($consumptionLine.ConsumedServiceCost)</td>
<td>$($consumptionLine.ConsumedServiceCurrency)</td>
</tr>
"@ 
                }
                $htmlScopeInsights += $htmlScopeInsightsConsumptionSub
                $htmlScopeInsights += @"
</tbody>
</table>
</div>
<script>
function loadtf$randomFunctionName() { if (window.helpertfConfig4$htmlTableId !== 1) { 
window.helpertfConfig4$htmlTableId=1;
var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,          
"@      
                if ($tfCount -gt 10) {
                    $spectrum = "10, $tfCount"
                    if ($tfCount -gt 50) {
                        $spectrum = "10, 25, 50, $tfCount"
                    }        
                    if ($tfCount -gt 100) {
                        $spectrum = "10, 30, 50, 100, $tfCount"
                    }
                    if ($tfCount -gt 500) {
                        $spectrum = "10, 30, 50, 100, 250, $tfCount"
                    }
                    if ($tfCount -gt 1000) {
                        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                    }
                    if ($tfCount -gt 2000) {
                        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                    }
                    if ($tfCount -gt 3000) {
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
        'number',
        'number',
        'caseinsensitivestring'
    ],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
"@
            }
            else {
                $htmlScopeInsights += @"
<p><i class="fa fa-credit-card" aria-hidden="true"></i> <span class="valignMiddle">No Consumption data available</span></p>
"@
            }
    
            $htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
        }   
        else {
            $htmlScopeInsights += @"
<p><i class="fa fa-credit-card" aria-hidden="true"></i> <span class="valignMiddle">No Consumption data available as parameter -NoAzureConsumption was applied</span></p>
"@
        }
        #endregion ScopeInsightsConsumptionSub

        #ResourceGroups
        #region ScopeInsightsResourceGroups
        if ($subscriptionResourceGroupsCount -gt 0) {
            $htmlScopeInsights += @"
    <p><i class="fa fa-check-circle" aria-hidden="true"></i> $subscriptionResourceGroupsCount Resource Groups | Limit: ($subscriptionResourceGroupsCount/$LimitResourceGroups)</p>
"@
        }
        else {
            $htmlScopeInsights += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> $subscriptionResourceGroupsCount Resource Groups</p>
"@
        }
        $htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
        #endregion ScopeInsightsResourceGroups

        #ResourceProvider
        #region ScopeInsightsResourceProvidersDetailed
        if ($htParameters.NoResourceProvidersDetailed -eq $false) {
            if (($htResourceProvidersAll.Keys | Measure-Object).count -gt 0) {
                $tfCount = ($arrayResourceProvidersAll | Measure-Object).Count
                $htmlTableId = "ScopeInsights_ResourceProvider_$($subscriptionId -replace '-','_')"
                $randomFunctionName = "func_$htmlTableId"
                $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Providers Detailed</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Provider</th>
<th>State</th>
</tr>
</thead>
<tbody>
"@
                $htmlScopeInsightsResourceProvidersDetailed = $null
                $htmlScopeInsightsResourceProvidersDetailed = foreach ($provider in ($htResourceProvidersAll).($subscriptionId).Providers) {
                    @"
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
        function loadtf$randomFunctionName() { if (window.helpertfConfig4$htmlTableId !== 1) { 
   window.helpertfConfig4$htmlTableId=1;
   var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,          
"@      
                if ($tfCount -gt 10) {
                    $spectrum = "10, $tfCount"
                    if ($tfCount -gt 50) {
                        $spectrum = "10, 25, 50, $tfCount"
                    }        
                    if ($tfCount -gt 100) {
                        $spectrum = "10, 30, 50, 100, $tfCount"
                    }
                    if ($tfCount -gt 500) {
                        $spectrum = "10, 30, 50, 100, 250, $tfCount"
                    }
                    if ($tfCount -gt 1000) {
                        $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                    }
                    if ($tfCount -gt 2000) {
                        $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                    }
                    if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@
            }
            else {
                $htmlScopeInsights += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($htResourceProvidersAll.Keys | Measure-Object).count) Resource Providers</span></p>
"@
            }
            $htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
        }    
        #endregion ScopeInsightsResourceProvidersDetailed
        
        #ResourceLocks
        #region ScopeInsightsResourceLocks
        if ($htResourceLocks.($subscriptionId)) {
            $tfCount = 6
            $htmlTableId = "ScopeInsights_ResourceLocks_$($subscriptionId -replace '-','_')"
            $randomFunctionName = "func_$htmlTableId"

            $subscriptionLocksCannotDeleteCount = $htResourceLocks.($subscriptionId).SubscriptionLocksCannotDeleteCount
            $subscriptionLocksReadOnlyCount = $htResourceLocks.($subscriptionId).SubscriptionLocksReadOnlyCount
            $resourceGroupsLocksCannotDeleteCount = $htResourceLocks.($subscriptionId).ResourceGroupsLocksCannotDeleteCount
            $resourceGroupsLocksReadOnlyCount = $htResourceLocks.($subscriptionId).ResourceGroupsLocksReadOnlyCount
            $resourcesLocksCannotDeleteCount = $htResourceLocks.($subscriptionId).ResourcesLocksCannotDeleteCount
            $resourcesLocksReadOnlyCount = $htResourceLocks.($subscriptionId).ResourcesLocksReadOnlyCount

            $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible">
<p><i class="fa fa-check-circle blue" aria-hidden="true"></i> Resource Locks</p></button>
<div class="content">
&nbsp;&nbsp;<b>Considerations before applying locks</b> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources#considerations-before-applying-locks" target="_blank">docs <i class="fa fa-external-link" aria-hidden="true"></i></a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Lock scope</th>
<th>Lock type</th>
<th>presence</th>
</tr>
</thead>
<tbody>
<tr><td>Subscription</td><td>CannotDelete</td><td>$($subscriptionLocksCannotDeleteCount)</td></tr>
<tr><td>Subscription</td><td>ReadOnly</td><td>$($subscriptionLocksReadOnlyCount)</td></tr>
<tr><td>ResourceGroup</td><td>CannotDelete</td><td>$($resourceGroupsLocksCannotDeleteCount)</td></tr>
<tr><td>ResourceGroup</td><td>ReadOnly</td><td>$($resourceGroupsLocksReadOnlyCount)</td></tr>
<tr><td>Resource</td><td>CannotDelete</td><td>$($resourcesLocksCannotDeleteCount)</td></tr>
<tr><td>Resource</td><td>ReadOnly</td><td>$($resourcesLocksReadOnlyCount)</td></tr>
</tbody>
</table>
<script>
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$htmlTableId !== 1) { 
   window.helpertfConfig4$htmlTableId =1;
   var tfConfig4$htmlTableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                $htmlScopeInsights += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
            }
            $htmlScopeInsights += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
            col_1: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number'
            ],
extensions: [{ name: 'sort' }]
            };
            var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
            tf.init();}}
        </script>
</div>
"@
        }
        else {
            $htmlScopeInsights += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> 0 Resource Locks <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources#considerations-before-applying-locks" target="_blank">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></p>
"@
        }
        $htmlScopeInsights += @"
        </td></tr>
        <tr><!--y--><td class="detailstd"><!--y-->
"@
        #endregion ScopeInsightsResourceLocks
        
    }
        
    #MgChildInfo
    #region ScopeInsightsManagementGroups
    if ($mgOrSub -eq "mg") {
    
        $htmlScopeInsights += @"
<p>$(($mgAllChildMgs | Measure-Object).count -1) ManagementGroups below this scope</p>
</td></tr>
<tr><td class="detailstd"><p>$(($mgAllChildSubscriptions | Measure-Object).count) Subscriptions below this scope</p></td></tr>
<tr><td class="detailstd">
"@

        #region ScopeInsightsConsumptionMg
        if ($htParameters.NoAzureConsumption -eq $false) {
            if ($allConsumptionDataCount -gt 0) {

                $consumptionData = $allConsumptionData | Where-Object { $_.SubscriptionMgPath -contains $mgChild }
                if (($consumptionData | Measure-Object).Count -gt 0) {
                    $arrayTotalCostSummary = @()
                    $arrayConsumptionData = [System.Collections.ArrayList]@()
                    $consumptionDataGroupedByCurrency = $consumptionData | group-object -property Currency
                    foreach ($currency in $consumptionDataGroupedByCurrency) {
                        $totalCost = 0
                        $tenantSummaryConsumptionDataGrouped = $currency.group | group-object -property ConsumedService, ChargeType, MeterCategory
                        $subsCount = ($tenantSummaryConsumptionDataGrouped.group.subscriptionId | Sort-Object -Unique | Measure-Object).Count
                        $consumedServiceCount = ($tenantSummaryConsumptionDataGrouped.group.consumedService | Sort-Object -Unique | Measure-Object).Count
                        $resourceCount = ($tenantSummaryConsumptionDataGrouped.group.ResourceId | Sort-Object -Unique | Measure-Object).Count
                        foreach ($consumptionline in $tenantSummaryConsumptionDataGrouped) {
            
                            $costConsumptionLine = ($consumptionline.group.PreTaxCost | Measure-Object -Sum).Sum
                            if ([math]::Round($costConsumptionLine, 4) -eq 0) {
                                $cost = $costConsumptionLine
                            }
                            else {
                                $cost = [math]::Round($costConsumptionLine, 4)
                            }
                            
                            $null = $arrayConsumptionData.Add([PSCustomObject]@{ 
                                    ConsumedService              = ($consumptionline.name).split(", ")[0]
                                    ConsumedServiceChargeType    = ($consumptionline.name).split(", ")[1]
                                    ConsumedServiceCategory      = ($consumptionline.name).split(", ")[2]
                                    ConsumedServiceInstanceCount = $consumptionline.Count
                                    ConsumedServiceCost          = [decimal]$cost
                                    ConsumedServiceSubscriptions = ($consumptionline.group.SubscriptionId | Sort-Object -Unique).Count
                                    ConsumedServiceCurrency      = $currency.Name
                                })
                            
                            $totalCost = $totalCost + $costConsumptionLine
                        }
                        if ([math]::Round($totalCost, 4) -eq 0) {
                            $totalCost = $totalCost
                        }
                        else {
                            $totalCost = [math]::Round($totalCost, 4)
                        }
                        $arrayTotalCostSummary += "$([decimal]$totalCost) $($currency.Name) generated by $($resourceCount) Resources ($($consumedServiceCount) ResourceTypes) in $($subsCount) Subscriptions"
                    }

                    $tfCount = ($arrayConsumptionData | Measure-Object).Count
                    $htmlTableId = "ScopeInsights_Consumption_$($mgChild -replace '-','_')"
                    $randomFunctionName = "func_$htmlTableId"
                    $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><i class="fa fa-credit-card" aria-hidden="true" style="color: #0078df"></i> Total cost $($arrayTotalCostSummary -join "$CsvDelimiterOpposite ") last $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>ChargeType</th>
<th>ResourceType</th>
<th>Category</th>
<th>ResourceCount</th>
<th>Cost ($($AzureConsumptionPeriod)d)</th>
<th>Currency</th>
<th>Subscriptions</th>
</tr>
</thead>
<tbody>
"@
                    $htmlScopeInsightsConsumptionMg = $null
                    $htmlScopeInsightsConsumptionMg = foreach ($consumptionLine in $arrayConsumptionData) {
                        @"
<tr>
<td>$($consumptionLine.ConsumedServiceChargeType)</td>
<td>$($consumptionLine.ConsumedService)</td>
<td>$($consumptionLine.ConsumedServiceCategory)</td>
<td>$($consumptionLine.ConsumedServiceInstanceCount)</td>
<td>$($consumptionLine.ConsumedServiceCost)</td>
<td>$($consumptionLine.ConsumedServiceCurrency)</td>
<td>$($consumptionLine.ConsumedServiceSubscriptions)</td>
</tr>
"@ 
                    }
                    $htmlScopeInsights += $htmlScopeInsightsConsumptionMg
                    $htmlScopeInsights += @"
</tbody>
</table>
</div>
<script>
function loadtf$randomFunctionName() { if (window.helpertfConfig4$htmlTableId !== 1) { 
window.helpertfConfig4$htmlTableId=1;
var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,          
"@      
                    if ($tfCount -gt 10) {
                        $spectrum = "10, $tfCount"
                        if ($tfCount -gt 50) {
                            $spectrum = "10, 25, 50, $tfCount"
                        }        
                        if ($tfCount -gt 100) {
                            $spectrum = "10, 30, 50, 100, $tfCount"
                        }
                        if ($tfCount -gt 500) {
                            $spectrum = "10, 30, 50, 100, 250, $tfCount"
                        }
                        if ($tfCount -gt 1000) {
                            $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                        }
                        if ($tfCount -gt 2000) {
                            $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                        }
                        if ($tfCount -gt 3000) {
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
        'number',
        'number',
        'caseinsensitivestring',
        'number'
    ],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
"@
                }
                else {
                    $htmlScopeInsights += @"
<p><i class="fa fa-credit-card" aria-hidden="true"></i> <span class="valignMiddle">No Consumption data available for Subscriptions under this ManagementGroup</span></p>
"@
                }
            }
            else {
                $htmlScopeInsights += @"
<p><i class="fa fa-credit-card" aria-hidden="true"></i> <span class="valignMiddle">No Consumption data available</span></p>
"@
            }
    
            $htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
        }   
        else {
            $htmlScopeInsights += @"
<p><i class="fa fa-credit-card" aria-hidden="true"></i> <span class="valignMiddle">No Consumption data available as parameter -NoAzureConsumption was applied</span></p>
"@
        }
        #endregion ScopeInsightsConsumptionMg

    }
    #endregion ScopeInsightsManagementGroups

    #resources 
    #region ScopeInsightsResources
    if ($mgOrSub -eq "mg") {
        if ($resourcesAllChildSubscriptionLocationCount -gt 0) {
            $tfCount = ($resourcesAllChildSubscriptionsArray | measure-object).count
            $htmlTableId = "ScopeInsights_Resources_$($mgChild -replace '-','_')"
            $randomFunctionName = "func_$htmlTableId"
            $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $resourcesAllChildSubscriptionResourceTypeCount ResourceTypes ($resourcesAllChildSubscriptionTotal Resources) in $resourcesAllChildSubscriptionLocationCount Locations (all Subscriptions below this scope)</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
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
            $htmlScopeInsightsResources = foreach ($resourceAllChildSubscriptionResourceTypePerLocation in $resourcesAllChildSubscriptionsArray | sort-object @{Expression = { $_.ResourceType } }, @{Expression = { $_.location } }) {
                @"
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$htmlTableId !== 1) { 
   window.helpertfConfig4$htmlTableId =1;
   var tfConfig4$htmlTableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
            var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
            tf.init();}}
        </script>
    </div>
"@
        }
        else {
            $htmlScopeInsights += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> $resourcesAllChildSubscriptionResourceTypeCount ResourceTypes (all Subscriptions below this scope)</p>
"@
        }
        $htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
    }

    if ($mgOrSub -eq "sub") {
        if ($resourcesSubscriptionResourceTypeCount -gt 0) {
            $tfCount = ($resourcesSubscription | Measure-Object).Count
            $htmlTableId = "ScopeInsights_Resources_$($subscriptionId -replace '-','_')"
            $randomFunctionName = "func_$htmlTableId"
            $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $resourcesSubscriptionResourceTypeCount ResourceTypes ($resourcesSubscriptionTotal Resources) in $resourcesSubscriptionLocationCount Locations</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
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
            $htmlScopeInsightsResources = foreach ($resourceSubscriptionResourceTypePerLocation in $resourcesSubscription | sort-object @{Expression = { $_.type } }, @{Expression = { $_.location } }, @{Expression = { $_.count_ } }) {
                @"
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$htmlTableId !== 1) { 
   window.helpertfConfig4$htmlTableId =1;
   var tfConfig4$htmlTableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
            var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
            tf.init();}}
        </script>
    </div>
"@
        }
        else {
            $htmlScopeInsights += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> $resourcesSubscriptionResourceTypeCount ResourceTypes</p>
"@
        }
        $htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
    }
    #endregion ScopeInsightsResources

    #resourcesDiagnosticsCapable
    #region ScopeInsightsDiagnosticsCapable
    if ($mgOrSub -eq "mg") {
        $resourceTypesUnique = ($resourcesAllChildSubscriptions | select-object type -Unique).type
        $resourceTypesSummarizedArray = [System.Collections.ArrayList]@()
        foreach ($resourceTypeUnique in $resourceTypesUnique) {
            $resourcesTypeCountTotal = 0
            ($resourcesAllChildSubscriptions | Where-Object { $_.type -eq $resourceTypeUnique }).count_ | ForEach-Object { $resourcesTypeCountTotal += $_ }
            $dataFromResourceTypesDiagnosticsArray = $resourceTypesDiagnosticsArray | Where-Object { $_.ResourceType -eq $resourceTypeUnique }
            if ($dataFromResourceTypesDiagnosticsArray.Metrics -eq $true -or $dataFromResourceTypesDiagnosticsArray.Logs -eq $true) {
                $resourceDiagnosticscapable = $true
            }
            else {
                $resourceDiagnosticscapable = $false
            }
            $null = $resourceTypesSummarizedArray.Add([PSCustomObject]@{
                    ResourceType       = $resourceTypeUnique
                    ResourceCount      = $resourcesTypeCountTotal
                    DiagnosticsCapable = $resourceDiagnosticscapable
                    Metrics            = $dataFromResourceTypesDiagnosticsArray.Metrics
                    Logs               = $dataFromResourceTypesDiagnosticsArray.Logs
                    LogCategories      = ($dataFromResourceTypesDiagnosticsArray.LogCategories -join "$CsvDelimiterOpposite ") 
                })
        }
        $subscriptionResourceTypesDiagnosticsCapableMetricsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Metrics -eq $true } | Measure-Object).count
        $subscriptionResourceTypesDiagnosticsCapableLogsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Logs -eq $true } | Measure-Object).count
        $subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Metrics -eq $true -or $_.Logs -eq $true } | Measure-Object).count
    
        if ($resourcesAllChildSubscriptionResourceTypeCount -gt 0) {
            $tfCount = $resourcesAllChildSubscriptionResourceTypeCount
            $htmlTableId = "ScopeInsights_resourcesDiagnosticsCapable_$($mgchild -replace '-','_')"
            $randomFunctionName = "func_$htmlTableId"
            $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount/$resourcesAllChildSubscriptionResourceTypeCount ResourceTypes Diagnostics capable ($subscriptionResourceTypesDiagnosticsCapableMetricsCount Metrics, $subscriptionResourceTypesDiagnosticsCapableLogsCount Logs) (all Subscriptions below this scope)</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
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
            $htmlScopeInsightsDiagnosticsCapable = foreach ($resourceSubscriptionResourceType in $resourceTypesSummarizedArray | sort-object @{Expression = { $_.ResourceType } }) {
                @"
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$htmlTableId !== 1) { 
   window.helpertfConfig4$htmlTableId =1;
   var tfConfig4$htmlTableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
            var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
            tf.init();}}
        </script>
    </div>
"@
        }
        else {
            $htmlScopeInsights += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> $resourcesAllChildSubscriptionResourceTypeCount ResourceTypes Diagnostics capable (all Subscriptions below this scope)</p>
"@
        }
        $htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
    }

    if ($mgOrSub -eq "sub") {
        $resourceTypesUnique = ($resourcesSubscription | select-object type -Unique).type
        $resourceTypesSummarizedArray = [System.Collections.ArrayList]@()
        foreach ($resourceTypeUnique in $resourceTypesUnique) {
            $resourcesTypeCountTotal = 0
            ($resourcesSubscription | Where-Object { $_.type -eq $resourceTypeUnique }).count_ | ForEach-Object { $resourcesTypeCountTotal += $_ }
            $dataFromResourceTypesDiagnosticsArray = $resourceTypesDiagnosticsArray | Where-Object { $_.ResourceType -eq $resourceTypeUnique }
            if ($dataFromResourceTypesDiagnosticsArray.Metrics -eq $true -or $dataFromResourceTypesDiagnosticsArray.Logs -eq $true) {
                $resourceDiagnosticscapable = $true
            }
            else {
                $resourceDiagnosticscapable = $false
            }
            $null = $resourceTypesSummarizedArray.Add([PSCustomObject]@{
                    ResourceType       = $resourceTypeUnique
                    ResourceCount      = $resourcesTypeCountTotal
                    DiagnosticsCapable = $resourceDiagnosticscapable
                    Metrics            = $dataFromResourceTypesDiagnosticsArray.Metrics
                    Logs               = $dataFromResourceTypesDiagnosticsArray.Logs
                    LogCategories      = ($dataFromResourceTypesDiagnosticsArray.LogCategories -join "$CsvDelimiterOpposite ") 
                })
        }

        $subscriptionResourceTypesDiagnosticsCapableMetricsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Metrics -eq $true } | Measure-Object).count
        $subscriptionResourceTypesDiagnosticsCapableLogsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Logs -eq $true } | Measure-Object).count
        $subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Metrics -eq $true -or $_.Logs -eq $true } | Measure-Object).count

        if ($resourcesSubscriptionResourceTypeCount -gt 0) {
            $tfCount = $resourcesSubscriptionResourceTypeCount
            $htmlTableId = "ScopeInsights_resourcesDiagnosticsCapable_$($subscriptionId -replace '-','_')"
            $randomFunctionName = "func_$htmlTableId"
            $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount/$resourcesSubscriptionResourceTypeCount ResourceTypes Diagnostics capable ($subscriptionResourceTypesDiagnosticsCapableMetricsCount Metrics, $subscriptionResourceTypesDiagnosticsCapableLogsCount Logs)</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
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
            $htmlScopeInsightsDiagnosticsCapable = foreach ($resourceSubscriptionResourceType in $resourceTypesSummarizedArray | sort-object @{Expression = { $_.ResourceType } }) {
                @"
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$htmlTableId !== 1) { 
   window.helpertfConfig4$htmlTableId =1;
   var tfConfig4$htmlTableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
            var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
            tf.init();}}
        </script>
    </div>
"@
        }
        else {
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
    if ($mgOrSub -eq "mg") {
        $htmlTableIdentifier = $mgChild

        $policiesAssigned = [System.Collections.ArrayList]@()
        $policiesCount = 0
        $policiesCountBuiltin = 0
        $policiesCountCustom = 0
        $policiesAssignedAtScope = 0
        $policiesInherited = 0
        foreach ($policyAssignment in $policyAssignmentsAllArrayForThisManagementGroupVariantPolicy) {
            if ([String]::IsNullOrEmpty($policyAssignment.subscriptionId)) {
                $null = $policiesAssigned.Add($policyAssignment)
                $policiesCount++
                if ($policyAssignment.PolicyType -eq "BuiltIn") {
                    $policiesCountBuiltin++
                }
                if ($policyAssignment.PolicyType -eq "Custom") {
                    $policiesCountCustom++
                }
                if ($policyAssignment.Inheritance -like "this*") {
                    $policiesAssignedAtScope++
                }
                if ($policyAssignment.Inheritance -notlike "this*") {
                    $policiesInherited++
                }
            }
        }
    }
    if ($mgOrSub -eq "sub") {
        $htmlTableIdentifier = $subscriptionId

        $policiesAssigned = [System.Collections.ArrayList]@()
        $policiesCount = 0
        $policiesCountBuiltin = 0
        $policiesCountCustom = 0
        $policiesAssignedAtScope = 0
        $policiesInherited = 0
        foreach ($policyAssignment in $policyAssignmentsAllArrayForThisSubscriptionVariantPolicy) {
            $null = $policiesAssigned.Add($policyAssignment)
            $policiesCount++
            if ($policyAssignment.PolicyType -eq "BuiltIn") {
                $policiesCountBuiltin++
            }
            if ($policyAssignment.PolicyType -eq "Custom") {
                $policiesCountCustom++
            }
            if ($policyAssignment.Inheritance -like "this*") {
                $policiesAssignedAtScope++
            }
            if ($policyAssignment.Inheritance -notlike "this*") {
                $policiesInherited++
            }
        }
    }

    if (($policiesAssigned | measure-object).count -gt 0) {
        $tfCount = ($policiesAssigned | measure-object).count
        $htmlTableId = "ScopeInsights_PolicyAssignments_$($htmlTableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
        $randomFunctionName = "func_$htmlTableId"
        if (-not $NoAADServicePrincipalResolve) {
            $noteOrNot = ""
        }
        else {
            $noteOrNot = "<abbr title=`"Note: will show 'n/a' if parameter -NoAADServicePrincipalResolve was used`"><i class=`"fa fa-question-circle`" aria-hidden=`"true`"></i></abbr>"
        }
        $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $policiesCount Policy Assignments ($policiesAssignedAtScope at scope, $policiesInherited inherited) (Builtin: $policiesCountBuiltin | Custom: $policiesCountCustom)</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a><br>
&nbsp;&nbsp;<span style="color:#FF5733">*Depending on the number of rows and your computer´s performance the table may respond with delay, download the csv for better filtering experience</span>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Inheritance</th>
<th>ScopeExcluded</th>
<th>Exemption applies</th>
<th>Policy DisplayName</th>
<th>PolicyId</th>
<th>Type</th>
<th>Category</th>
<th>Effect</th>
"@

        if ($htParameters.NoPolicyComplianceStates -eq $false) {

            $htmlScopeInsights += @"
<th>Policies NonCmplnt</th>
<th>Policies Compliant</th>
<th>Resources NonCmplnt</th>
<th>Resources Compliant</th>
"@
        }

        $htmlScopeInsights += @"
<th>Role/Assignment $noteOrNot</th>
<th>Assignment DisplayName</th>
<th>AssignmentId</th>
</tr>
</thead>
<tbody>
"@
        $htmlScopeInsightsPolicyAssignments = $null
        $htmlScopeInsightsPolicyAssignments = foreach ($policyAssignment in $policiesAssigned | sort-object @{Expression = { $_.Level } }, @{Expression = { $_.MgName } }, @{Expression = { $_.MgId } }, @{Expression = { $_.SubscriptionName } }, @{Expression = { $_.SubscriptionId } }, @{Expression = { $_.PolicyAssignmentId } }) {
            @"
<tr>
<td>$($policyAssignment.Inheritance)</td>
<td>$($policyAssignment.ExcludedScope)</td>
<td>$($policyAssignment.ExemptionScope)</td>
<td class="breakwordall">$($policyAssignment.PolicyName)</td>
<td class="breakwordall">$($policyAssignment.PolicyId)</td>
<td>$($policyAssignment.PolicyType)</td>
<td>$($policyAssignment.PolicyCategory)</td>
<td>$($policyAssignment.Effect)</td>
"@

            if ($htParameters.NoPolicyComplianceStates -eq $false) {
                @"
<td>$($policyAssignment.NonCompliantPolicies)</td>
<td>$($policyAssignment.CompliantPolicies)</td>
<td>$($policyAssignment.NonCompliantResources)</td>
<td>$($policyAssignment.CompliantResources)</td>
"@
            }

            @"
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
        function loadtf$randomFunctionName() { if (window.helpertfConfig4$htmlTableId !== 1) { 
   window.helpertfConfig4$htmlTableId =1;
   var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            $htmlScopeInsights += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
        }
        $htmlScopeInsights += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_1: 'select',
            col_2: 'select',
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
                'caseinsensitivestring',
"@

        if ($htParameters.NoPolicyComplianceStates -eq $false) {
            
            $htmlScopeInsights += @"

                'number',
                'number',
                'number',
                'number',
"@
        }
        $htmlScopeInsights += @"
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
            watermark: ['', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@
    }
    else {
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
    if ($mgOrSub -eq "mg") {
        $htmlTableIdentifier = $mgChild

        $policySetsAssigned = [System.Collections.ArrayList]@()
        $policySetsCount = 0
        $policySetsCountBuiltin = 0
        $policySetsCountCustom = 0
        $policySetsAssignedAtScope = 0
        $policySetsInherited = 0
        foreach ($policySetAssignment in $policyAssignmentsAllArrayForThisManagementGroupVariantPolicySet) {
            if ([String]::IsNullOrEmpty($policySetAssignment.subscriptionId)) {
                $null = $policySetsAssigned.Add($policySetAssignment)
                $policySetsCount++
                if ($policySetAssignment.PolicyType -eq "BuiltIn") {
                    $policySetsCountBuiltin++
                }
                if ($policySetAssignment.PolicyType -eq "Custom") {
                    $policySetsCountCustom++
                }
                if ($policySetAssignment.Inheritance -like "this*") {
                    $policySetsAssignedAtScope++
                }
                if ($policySetAssignment.Inheritance -notlike "this*") {
                    $policySetsInherited++
                }
            }
        }
    }
    if ($mgOrSub -eq "sub") {
        $htmlTableIdentifier = $subscriptionId

        $policySetsAssigned = [System.Collections.ArrayList]@()
        $policySetsCount = 0
        $policySetsCountBuiltin = 0
        $policySetsCountCustom = 0
        $policySetsAssignedAtScope = 0
        $policySetsInherited = 0
        foreach ($policySetAssignment in $policyAssignmentsAllArrayForThisSubscriptionVariantPolicySet) {
            $null = $policySetsAssigned.Add($policySetAssignment)
            $policySetsCount++
            if ($policySetAssignment.PolicyType -eq "BuiltIn") {
                $policySetsCountBuiltin++
            }
            if ($policySetAssignment.PolicyType -eq "Custom") {
                $policySetsCountCustom++
            }
            if ($policySetAssignment.Inheritance -like "this*") {
                $policySetsAssignedAtScope++
            }
            if ($policySetAssignment.Inheritance -notlike "this*") {
                $policySetsInherited++
            }
        }
    }

    if (($policySetsAssigned | measure-object).count -gt 0) {
        $tfCount = ($policiesAssigned | measure-object).count
        $htmlTableId = "ScopeInsights_PolicySetAssignments_$($htmlTableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
        $randomFunctionName = "func_$htmlTableId"
        if (-not $NoAADServicePrincipalResolve) {
            $noteOrNot = ""
        }
        else {
            $noteOrNot = "<abbr title=`"Note: will show 'n/a' if parameter -NoAADServicePrincipalResolve was used`"><i class=`"fa fa-question-circle`" aria-hidden=`"true`"></i></abbr>"
        }
        $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $policySetsCount PolicySet Assignments ($policySetsAssignedAtScope at scope, $policySetsInherited inherited) (Builtin: $policySetsCountBuiltin | Custom: $policySetsCountCustom)</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Inheritance</th>
<th>ScopeExcluded</th>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
<th>Type</th>
<th>Category</th>
"@

        if ($htParameters.NoPolicyComplianceStates -eq $false) {
        
            $htmlScopeInsights += @"
<th>Policies NonCmplnt</th>
<th>Policies Compliant</th>
<th>Resources NonCmplnt</th>
<th>Resources Compliant</th>
"@
        }

        $htmlScopeInsights += @"
<th>Role/Assignment $noteOrNot</th>
<th>Assignment DisplayName</th>
<th>AssignmentId</th>
</tr>
</thead>
<tbody>
"@
        $htmlScopeInsightsPolicySetAssignments = $null
        $htmlScopeInsightsPolicySetAssignments = foreach ($policyAssignment in $policySetsAssigned | sort-object -Property Level, MgName, MgId, SubscriptionName, SubscriptionId) {
            @"
<tr>
<td>$($policyAssignment.Inheritance)</td>
<td>$($policyAssignment.ExcludedScope)</td>
<td class="breakwordall">$($policyAssignment.PolicyName)</td>
<td class="breakwordall">$($policyAssignment.PolicyId)</td>
<td>$($policyAssignment.PolicyType)</td>
<td>$($policyAssignment.PolicyCategory)</td>
"@
            if ($htParameters.NoPolicyComplianceStates -eq $false) {
                @"
<td>$($policyAssignment.NonCompliantPolicies)</td>
<td>$($policyAssignment.CompliantPolicies)</td>
<td>$($policyAssignment.NonCompliantResources)</td>
<td>$($policyAssignment.CompliantResources)</td>
"@
            }
            @"
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
        function loadtf$randomFunctionName() { if (window.helpertfConfig4$htmlTableId !== 1) { 
   window.helpertfConfig4$htmlTableId =1;
   var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
"@

        if ($htParameters.NoPolicyComplianceStates -eq $false) {
            $htmlScopeInsights += @"
                'number',
                'number',
                'number',
                'number',
"@
        }
        $htmlScopeInsights += @"
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
            watermark: ['', '', '', '', '', '', '', '', '', '', '', '', ''],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@
    }
    else {
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
    if ($mgOrSub -eq "mg") {
        $limit = $LimitPOLICYPolicyAssignmentsManagementGroup
    }
    if ($mgOrSub -eq "sub") {
        $limit = $LimitPOLICYPolicyAssignmentsSubscription
    }

    if ($policiesAssignedAtScope -eq 0 -and $policySetsAssignedAtScope -eq 0) {
        $faimage = "<i class=`"fa fa-ban`" aria-hidden=`"true`"></i>"
    
        $htmlScopeInsights += @"
            <p>$faImage Policy Assignment Limit: 0/$limit</p>
"@
    }
    else {
        if ($mgOrSub -eq "mg") {
            $scopePolicyAssignmentsLimit = $policyPolicyBaseQueryScopeInsights | Where-Object { [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.MgId -eq $mgChild }
        }
        if ($mgOrSub -eq "sub") {
            $scopePolicyAssignmentsLimit = $policyPolicyBaseQueryScopeInsights | Where-Object { $_.SubscriptionId -eq $subscriptionId }
        }

        if ($scopePolicyAssignmentsLimit.PolicyAndPolicySetAssigmentAtScopeCount -gt (($limit) * $LimitCriticalPercentage / 100)) {
            $faImage = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
        }
        else {
            $faimage = "<i class=`"fa fa-check-circle`" aria-hidden=`"true`"></i>"
        }
        $htmlScopeInsights += @"
            <p>$faImage Policy Assignment Limit: $($scopePolicyAssignmentsLimit.PolicyAndPolicySetAssigmentAtScopeCount)/$($limit)</p>
"@
    }
    $htmlScopeInsights += @"
</td></tr>
<tr><td class="detailstd">
"@
    #endregion ScopeInsightsPolicyAssigmentsLimit

    #ScopedPolicies
    #region ScopeInsightsScopedPolicies
    if ($mgOrSub -eq "mg") {
        $htmlTableIdentifier = $mgChild
        $scopePolicies = $customPoliciesDetailed.Where( { $_.PolicyDefinitionId -like "*/providers/Microsoft.Management/managementGroups/$mgChild/*" } )
        $scopePoliciesCount = ($scopePolicies | Measure-Object).count
    }
    if ($mgOrSub -eq "sub") {
        $htmlTableIdentifier = $subscriptionId
        $scopePolicies = $customPoliciesDetailed.Where( { $_.PolicyDefinitionId -like "*/subscriptions/$subscriptionId/*" } )
        $scopePoliciesCount = ($scopePolicies | Measure-Object).count
    }

    if ($scopePoliciesCount -gt 0) {
        $tfCount = $scopePoliciesCount
        $htmlTableId = "ScopeInsights_ScopedPolicies_$($htmlTableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
        $randomFunctionName = "func_$htmlTableId"
        if ($mgOrSub -eq "mg") {
            $LimitPOLICYPolicyScoped = $LimitPOLICYPolicyDefinitionsScopedManagementGroup
            if ($scopePoliciesCount -gt (($LimitPOLICYPolicyScoped * $LimitCriticalPercentage) / 100)) {
                $faIcon = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
            }
            else {
                $faIcon = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
            }
        }
        if ($mgOrSub -eq "sub") {
            $LimitPOLICYPolicyScoped = $LimitPOLICYPolicyDefinitionsScopedSubscription
            if ($scopePoliciesCount -gt (($LimitPOLICYPolicyScoped * $LimitCriticalPercentage) / 100)) {
                $faIcon = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
            }
            else {
                $faIcon = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
            }
        }

        $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p>$faIcon $scopePoliciesCount Custom Policies scoped | Limit: ($scopePoliciesCount/$LimitPOLICYPolicyScoped)</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">Policy DisplayName</th>
<th>PolicyId</th>
<th>Category</th>
<th>Policy effect</th>
<th>Role Definitions</th>
<th>Unique Assignments</th>
<th>Used in PolicySets</th>
</tr>
</thead>
<tbody>
"@
        $htmlScopeInsightsScopedPolicies = $null
        $htmlScopeInsightsScopedPolicies = foreach ($custompolicy in $scopePolicies | Sort-Object @{Expression = { $_.PolicyDisplayName } }, @{Expression = { $_.PolicyDefinitionId } }) {
            @"
<tr>
<td>$($customPolicy.PolicyDisplayName)</td>
<td class="breakwordall">$($customPolicy.PolicyDefinitionId)</td>
<td>$($customPolicy.PolicyCategory)</td>
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$htmlTableId !== 1) { 
   window.helpertfConfig4$htmlTableId =1;
   var tfConfig4$htmlTableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
                    'caseinsensitivestring',
                    'caseinsensitivestring'
                ],
extensions: [{ name: 'sort' }]
            };
            var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
            tf.init();}}
        </script>
"@
    }
    else {
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
    if ($mgOrSub -eq "mg") {
        $htmlTableIdentifier = $mgChild
        $scopePolicySets = $customPolicySetsDetailed.Where( { $_.PolicySetDefinitionId -like "*/providers/Microsoft.Management/managementGroups/$mgChild/*" } )
        $scopePolicySetsCount = ($scopePolicySets | Measure-Object).count
    }
    if ($mgOrSub -eq "sub") {
        $htmlTableIdentifier = $subscriptionId
        $scopePolicySets = $customPolicySetsDetailed.Where( { $_.PolicySetDefinitionId -like "*/subscriptions/$subscriptionId/*" } )
        $scopePolicySetsCount = ($scopePolicySets | Measure-Object).count
    }

    if ($scopePolicySetsCount -gt 0) {
        $tfCount = $scopePolicySetsCount
        $htmlTableId = "ScopeInsights_ScopedPolicySets_$($htmlTableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
        $randomFunctionName = "func_$htmlTableId"
        if ($mgOrSub -eq "mg") {
            $LimitPOLICYPolicySetScoped = $LimitPOLICYPolicySetDefinitionsScopedManagementGroup
            if ($scopePolicySetsCount -gt (($LimitPOLICYPolicySetScoped * $LimitCriticalPercentage) / 100)) {
                $faIcon = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
            }
            else {
                $faIcon = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
            }
        }
        if ($mgOrSub -eq "sub") {
            $LimitPOLICYPolicySetScoped = $LimitPOLICYPolicySetDefinitionsScopedSubscription
            if ($scopePolicySetsCount -gt (($LimitPOLICYPolicySetScoped * $LimitCriticalPercentage) / 100)) {
                $faIcon = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
            }
            else {
                $faIcon = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
            }
        }
        $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p>$faIcon $scopePolicySetsCount Custom PolicySets scoped | Limit: ($scopePolicySetsCount/$LimitPOLICYPolicySetScoped)</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th class="widthCustom">PolicySet DisplayName</th>
<th>PolicySetId</th>
<th>Category</th>
<th>Unique Assignments</th>
<th>Policies Used</th>
</tr>
</thead>
<tbody>
"@
        $htmlScopeInsightsScopedPolicySets = $null
        foreach ($custompolicySet in $scopePolicySets | Sort-Object @{Expression = { $_.PolicySetDisplayName } }, @{Expression = { $_.PolicySetDefinitionId } }) {
            $htmlScopeInsightsScopedPolicySets += @"
<tr>
<td>$($custompolicySet.PolicySetDisplayName)</td>
<td>$($custompolicySet.PolicySetDefinitionId)</td>
<td>$($custompolicySet.PolicySetCategory)</td>
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$htmlTableId !== 1) { 
   window.helpertfConfig4$htmlTableId =1;
   var tfConfig4$htmlTableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
            var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
            tf.init();}}
        </script>
"@
    }
    else {
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
    if ($mgOrSub -eq "sub") {
        if ($blueprintsAssignedCount -gt 0) {
        
            if ($mgOrSub -eq "mg") {
                $htmlTableIdentifier = $mgChild
            }
            if ($mgOrSub -eq "sub") {
                $htmlTableIdentifier = $subscriptionId
            }
            $htmlTableId = "ScopeInsights_BlueprintAssignment_$($htmlTableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
            $randomFunctionName = "func_$htmlTableId"
            $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintsAssignedCount Blueprints assigned</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
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
            $htmlScopeInsightsBlueprintAssignments = foreach ($blueprintAssigned in $blueprintsAssigned) {
                @"
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$htmlTableId !== 1) { 
   window.helpertfConfig4$htmlTableId =1;
   var tfConfig4$htmlTableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
            var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
            tf.init();}}
        </script>
"@
        }
        else {
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
    if ($blueprintsScopedCount -gt 0) {
        $tfCount = $blueprintsScopedCount
        if ($mgOrSub -eq "mg") {
            $htmlTableIdentifier = $mgChild
        }
        if ($mgOrSub -eq "sub") {
            $htmlTableIdentifier = $subscriptionId
        }
        $htmlTableId = "ScopeInsights_BlueprintScoped_$($htmlTableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
        $randomFunctionName = "func_$htmlTableId"
        $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintsScopedCount Blueprints scoped</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="$cssClass">
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
        $htmlScopeInsightsBlueprintsScoped = foreach ($blueprintScoped in $blueprintsScoped) {
            @"
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$htmlTableId !== 1) { 
   window.helpertfConfig4$htmlTableId =1;
   var tfConfig4$htmlTableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
            var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
            tf.init();}}
        </script>
"@
    }
    else {
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
    if ($mgOrSub -eq "mg") {
        $htmlTableIdentifier = $mgChild
        $LimitRoleAssignmentsScope = $LimitRBACRoleAssignmentsManagementGroup

        $rolesAssigned = [System.Collections.ArrayList]@()
        $rolesAssignedCount = 0
        $rolesAssignedInheritedCount = 0
        $rolesAssignedUser = 0
        $rolesAssignedGroup = 0
        $rolesAssignedServicePrincipal = 0
        $rolesAssignedUnknown = 0
        $roleAssignmentsRelatedToPolicyCount = 0
        $roleSecurityFindingCustomRoleOwner = 0
        $roleSecurityFindingOwnerAssignmentSP = 0
        $rbacForThisManagementGroup = ($rbacAllGroupedByManagementGroup | Where-Object { $_.name -eq $mgChild }).group
        foreach ($roleAssignment in $rbacForThisManagementGroup) {
            if ([String]::IsNullOrEmpty($roleAssignment.subscriptionId)) {
                $null = $rolesAssigned.Add($roleAssignment)
                $rolesAssignedCount++
                if ($roleAssignment.Scope -notlike "this*") {
                    $rolesAssignedInheritedCount++
                }
                if ($roleAssignment.ObjectType -eq "User") {
                    $rolesAssignedUser++
                }
                if ($roleAssignment.ObjectType -eq "Group") {
                    $rolesAssignedGroup++
                }
                if ($roleAssignment.ObjectType -eq "ServicePrincipal") {
                    $rolesAssignedServicePrincipal++
                }
                if ($roleAssignment.ObjectType -eq "Unknown") {
                    $rolesAssignedUnknown++
                }
                if ($roleAssignment.RbacRelatedPolicyAssignment -ne "none") {
                    $roleAssignmentsRelatedToPolicyCount++
                }
                if ($roleAssignment.RoleSecurityCustomRoleOwner -eq 1) {
                    $roleSecurityFindingCustomRoleOwner++
                }
                if ($roleAssignment.RoleSecurityOwnerAssignmentSP -eq 1) {
                    $roleSecurityFindingOwnerAssignmentSP++
                }
            }
        }
    }
    if ($mgOrSub -eq "sub") {
        $htmlTableIdentifier = $subscriptionId
        $LimitRoleAssignmentsScope = $LimitRBACRoleAssignmentsSubscription

        $rolesAssigned = [System.Collections.ArrayList]@()
        $rolesAssignedCount = 0
        $rolesAssignedInheritedCount = 0
        $rolesAssignedUser = 0
        $rolesAssignedGroup = 0
        $rolesAssignedServicePrincipal = 0
        $rolesAssignedUnknown = 0
        $roleAssignmentsRelatedToPolicyCount = 0
        $roleSecurityFindingCustomRoleOwner = 0
        $roleSecurityFindingOwnerAssignmentSP = 0
        $rbacForThisSubscription = ($rbacAllGroupedBySubscription | Where-Object { $_.name -eq $subscriptionId }).group
        $rolesAssigned = foreach ($roleAssignment in $rbacForThisSubscription) {

            $roleAssignment
            $rolesAssignedCount++
            if ($roleAssignment.Scope -notlike "this*") {
                $rolesAssignedInheritedCount++
            }
            if ($roleAssignment.ObjectType -eq "User") {
                $rolesAssignedUser++
            }
            if ($roleAssignment.ObjectType -eq "Group") {
                $rolesAssignedGroup++
            }
            if ($roleAssignment.ObjectType -eq "ServicePrincipal") {
                $rolesAssignedServicePrincipal++
            }
            if ($roleAssignment.ObjectType -eq "Unknown") {
                $rolesAssignedUnknown++
            }
            if ($roleAssignment.RbacRelatedPolicyAssignment -ne "none") {
                $roleAssignmentsRelatedToPolicyCount++
            }
            if ($roleAssignment.RoleSecurityCustomRoleOwner -eq 1) {
                $roleSecurityFindingCustomRoleOwner++
            }
            if ($roleAssignment.RoleSecurityOwnerAssignmentSP -eq 1) {
                $roleSecurityFindingOwnerAssignmentSP++
            }
        }
    }

    $rolesAssignedAtScopeCount = $rolesAssignedCount - $rolesAssignedInheritedCount

    if (($rolesAssigned | measure-object).count -gt 0) {
        $tfCount = ($rolesAssigned | measure-object).count
        $htmlTableId = "ScopeInsights_RoleAssignments_$($htmlTableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
        $randomFunctionName = "func_$htmlTableId"
        if (-not $NoAADServicePrincipalResolve) {
            $noteOrNot = ""
        }
        else {
            $noteOrNot = "<abbr title=`"Note: will show 'n/a' if parameter -NoAADServicePrincipalResolve was used`"><i class=`"fa fa-question-circle`" aria-hidden=`"true`"></i></abbr>"
        }
        
        $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p>$faIcon $rolesAssignedCount Role Assignments ($rolesAssignedInheritedCount inherited) (User: $rolesAssignedUser | Group: $rolesAssignedGroup | ServicePrincipal: $rolesAssignedServicePrincipal | Orphaned: $rolesAssignedUnknown) ($($roleSecurityFindingCustomRoleOwnerImg)CustomRoleOwner: $roleSecurityFindingCustomRoleOwner, $($RoleSecurityFindingOwnerAssignmentSPImg)OwnerAssignmentSP: $roleSecurityFindingOwnerAssignmentSP) (Policy related: $roleAssignmentsRelatedToPolicyCount) | Limit: ($rolesAssignedAtScopeCount/$LimitRoleAssignmentsScope)</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a><br>
&nbsp;&nbsp;<span style="color:#FF5733">*Depending on the number of rows and your computer´s performance the table may respond with delay, download the csv for better filtering experience</span>
<table id="$htmlTableId" class="$cssClass">
<thead>
<tr>
<th>Scope</th>
<th>Role</th>
<th>RoleId</th>
<th>Role Type</th>
<th>Data</th>
<th>Identity Displayname</th>
<th>Identity SignInName</th>
<th>Identity ObjectId</th>
<th>Identity Type</th>
<th>Applicability</th>
<th>Applies through membership <abbr title="Note: the identity might not be a direct member of the group it could also be member of a nested group"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></th>
"@
        $htmlScopeInsights += @"
<th>Role AssignmentId</th>
<th>Related Policy Assignment $noteOrNot</th>
</tr>
</thead>
<tbody>
"@
        $htmlScopeInsightsRoleAssignments = $null
        $htmlScopeInsightsRoleAssignments = foreach ($roleAssignment in ($rolesAssigned | Sort-Object -Property Level, MgName, MgId, SubscriptionName, SubscriptionId, Scope, Role, ObjectDisplayName, RoleAssignmentId)) {
            @"
<tr>
<td>$($roleAssignment.Scope)</td>
<td>$($roleAssignment.Role)</td>
<td>$($roleAssignment.RoleId)</td>
<td>$($roleAssignment.RoleType)</td>
<td>$($roleAssignment.RoleDataRelated)</td>
<td class="breakwordall">$($roleAssignment.ObjectDisplayName)</td>
<td class="breakwordall">$($roleAssignment.ObjectSignInName)</td>
<td class="breakwordall">$($roleAssignment.ObjectId)</td>
<td>$($roleAssignment.ObjectType)</td>
<td>$($roleAssignment.AssignmentType)</td>
<td>$($roleAssignment.AssignmentInheritFrom)</td>
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
        function loadtf$randomFunctionName() { if (window.helpertfConfig4$htmlTableId !== 1) { 
   window.helpertfConfig4$htmlTableId =1;
   var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            $htmlScopeInsights += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
        }
        $htmlScopeInsights += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_3: 'select',
            col_4: 'select',
            col_8: 'multiple',
            col_9: 'select',
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
                'caseinsensitivestring'
            ],
            watermark: ['', 'try owner||reader', '', '', '', '', '', '', '', '', '', ''],          
            extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@
    }
    else {
        $htmlScopeInsights += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($rbacAll | measure-object).count) Role Assignments</span></p>
    </td></tr>
"@
    }
    #endregion ScopeInsightsRoleAssignments

    $script:html += $htmlScopeInsights

    if ($scopescnter % 50 -eq 0) {
        $script:scopescnter = 0
        Write-Host "   append file duration: " (Measure-Command { $script:html | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force }).TotalSeconds "seconds"
        $script:html = $null 
    }

}
#endregion ScopeInsights

#rsu
#region TenantSummary
function summary() {
    Write-Host " Building TenantSummary"

    if ($getMgParentName -eq "Tenant Root") {
        $scopeNamingSummary = "Tenant wide"
    }
    else {
        $scopeNamingSummary = "ManagementGroup '$ManagementGroupIdCaseSensitived' and descendants wide"
    }
 
    #region tenantSummaryPolicy
    $htmlTenantSummary += @"
<button type="button" class="collapsible" id="tenantSummaryPolicy"><hr class="hr-text" data-content="Policy" /></button>
<div class="content">
"@

    #region SUMMARYcustompolicies
    $startCustPolLoop = get-date
    Write-Host "  processing TenantSummary Custom Policies"

    $script:customPoliciesDetailed = [System.Collections.ArrayList]@()
    foreach ($customPolicy in ($customPoliciesArray | Sort-Object @{Expression = { $_.DisplayName } }, @{Expression = { $_.PolicyDefinitionId } })) {
    #foreach ($customPolicy in ($customPoliciesArray | Sort-Object -Property DisplayName, PolicyDefinitionId)) {
        #uniqueAssignments
        $policyUniqueAssignments = ($policyPolicyBaseQueryUniqueAssignmentsArrayList.where( { $_.PolicyDefinitionId -eq $customPolicy.PolicyDefinitionId })).PolicyAssignmentId
        $policyUniqueAssignmentsCount = ($policyUniqueAssignments | measure-object).count 

        $uniqueAssignments = $null
        if ($policyUniqueAssignmentsCount -gt 0) {
            $policyUniqueAssignmentsList = "($($policyUniqueAssignments -join "$CsvDelimiterOpposite "))"
            $uniqueAssignments = "$policyUniqueAssignmentsCount $policyUniqueAssignmentsList"
        }
        else {
            $uniqueAssignments = $policyUniqueAssignmentsCount
        }

        #PolicyUsedInPolicySet
        $usedInPolicySet = "0"
        if (($htPoliciesUsedInPolicySets).($customPolicy.PolicyDefinitionId)){
            $hlpPolicySetUsed = ($htPoliciesUsedInPolicySets).($customPolicy.PolicyDefinitionId)
            $usedInPolicySet = "$(($hlpPolicySetUsed.PolicySet | Measure-Object).Count) ($($hlpPolicySetUsed.PolicySet -join "$CsvDelimiterOpposite ")"
        }

        #policyEffect
        if ($customPolicy.effectDefaultValue -ne "n/a") {
            $effect = "Default: $($customPolicy.effectDefaultValue); Allowed: $($customPolicy.effectAllowedValue)"
        }
        else {
            $effect = "Fixed: $($customPolicy.effectFixedValue)"
        }

        <#policyRoledefinitions
        $policyRoleDefinitionsArray = [System.Collections.ArrayList]@()
        if (($htCacheDefinitionsAsIs).policy.($customPolicy.id).properties.policyrule.then.details.roledefinitionIds) {
            foreach ($policyRoledefinitionId in ($htCacheDefinitionsAsIs).policy.($customPolicy.id).properties.policyrule.then.details.roledefinitionIds) {
                $null = $policyRoleDefinitionsArray.Add((($htCacheDefinitions).role.($policyRoledefinitionId -replace '.*/').Name))
            }
        }
        if (($policyRoleDefinitionsArray | Measure-Object).count -gt 0) {
            $policyRoleDefinitions = $policyRoleDefinitionsArray -join "$CsvDelimiterOpposite "
        }
        else {
            $policyRoleDefinitions = "n/a"
        }
        #>

        if (($customPolicy.RoleDefinitionIds) -ne "n/a"){
            $policyRoleDefinitionsArray = @()
            $policyRoleDefinitionsArray = foreach ($roleDefinitionId in $customPolicy.RoleDefinitionIds | Sort-Object){
                ($htCacheDefinitions).role.($roleDefinitionId -replace ".*/").Name
                #write-host ($htCacheDefinitions).role.($roleDefinitionId -replace ".*/").Name
            }
            $policyRoleDefinitions = $policyRoleDefinitionsArray -join "$CsvDelimiterOpposite "
        }
        else{
            $policyRoleDefinitions = "n/a"
        }
        #$policyRoleDefinitions
        #Write-host "_____"

        $null = $script:customPoliciesDetailed.Add([PSCustomObject]@{ 
                Scope              = $customPolicy.ScopeMgSub
                ScopeId            = $customPolicy.ScopeId
                PolicyDisplayName  = $customPolicy.DisplayName 
                PolicyDefinitionId = $customPolicy.PolicyDefinitionId 
                PolicyEffect       = $effect
                PolicyCategory     = $customPolicy.Category
                RoleDefinitions    = $policyRoleDefinitions 
                UniqueAssignments  = $uniqueAssignments 
                UsedInPolicySets   = $usedInPolicySet
            })
    }

    if ($getMgParentName -eq "Tenant Root") {

        if ($tenantCustomPoliciesCount -gt 0) {
            $tfCount = $tenantCustomPoliciesCount
            $htmlTableId = "TenantSummary_customPolicies"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_customPolicies"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policies ($scopeNamingSummary)</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>Scope Id</th>
<th>Policy DisplayName</th>
<th>PolicyId</th>
<th>Category</th>
<th>Effect</th>
<th>Role Definitions</th>
<th>Unique Assignments</th>
<th>Used in PolicySets</th>
</tr>
</thead>
<tbody>
"@
            $htmlSUMMARYcustompolicies = $null
            $htmlSUMMARYcustompolicies = foreach ($customPolicy in ($customPoliciesDetailed | Sort-Object @{Expression = { $_.PolicyDisplayName } }, @{Expression = { $_.PolicyDefinitionId } })) {
                @"
<tr>
<td>$($customPolicy.Scope)</td>
<td>$($customPolicy.ScopeId)</td>
<td>$($customPolicy.PolicyDisplayName)</td>
<td class="breakwordall">$($customPolicy.PolicyDefinitionId)</td>
<td>$($customPolicy.PolicyCategory)</td>
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,       
"@      
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                $htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
            }
            $htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
        }
        else {
            $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policies ($scopeNamingSummary)</span></p>
"@
        }
    }
    #SUMMARY NOT tenant total custom policies
    else {
        $faimage = "<i class=`"fa fa-check-circle`" aria-hidden=`"true`"></i>"


        if ($tenantCustomPoliciesCount -gt 0) {
            $tfCount = $tenantCustomPoliciesCount
            $customPoliciesInScopeArray = [System.Collections.ArrayList]@()
            foreach ($customPolicy in ($customPoliciesArray | Sort-Object @{Expression = { $_.DisplayName } }, @{Expression = { $_.PolicyDefinitionId } })) {
                if (($customPolicy.PolicyDefinitionId) -like "/providers/Microsoft.Management/managementGroups/*") {
                    $policyScopedMgSub = $customPolicy.PolicyDefinitionId -replace "/providers/Microsoft.Management/managementGroups/", "" -replace '/.*'
                    if ($mgsAndSubs.MgId -contains ($policyScopedMgSub)) {
                        $null = $customPoliciesInScopeArray.Add($customPolicy)
                    }
                }

                if (($customPolicy.PolicyDefinitionId) -like "/subscriptions/*") {
                    $policyScopedMgSub = $customPolicy.PolicyDefinitionId -replace "/subscriptions/", "" -replace '/.*'
                    if ($mgsAndSubs.SubscriptionId -contains ($policyScopedMgSub)) {
                        $null = $customPoliciesInScopeArray.Add($customPolicy)
                    }
                    else {
                        #Write-Host "$policyScopedMgSub NOT in Scope"
                    }
                }
            }
            $customPoliciesFromSuperiorMGs = $tenantCustomPoliciesCount - (($customPoliciesInScopeArray | measure-object).count)
        }
        else {
            $customPoliciesFromSuperiorMGs = "0"
        }

        if ($tenantCustomPoliciesCount -gt 0) {
            $tfCount = $tenantCustomPoliciesCount
            $htmlTableId = "TenantSummary_customPolicies"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_customPolicies"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policies $scopeNamingSummary ($customPoliciesFromSuperiorMGs from superior scopes)</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>Scope Id</th>
<th>Policy DisplayName</th>
<th>PolicyId</th>
<th>Category</th>
<th>Policy Effect</th>
<th>Role Definitions</th>
<th>Unique Assignments</th>
<th>Used in PolicySets</th>
</tr>
</thead>
<tbody>
"@
            $htmlSUMMARYcustompolicies = $null
            $htmlSUMMARYcustompolicies = foreach ($customPolicy in ($customPoliciesDetailed | Sort-Object @{Expression = { $_.PolicyDisplayName } }, @{Expression = { $_.PolicyDefinitionId } })) {
                @"
<tr>
<td>$($customPolicy.Scope)</td>
<td>$($customPolicy.ScopeId)</td>
<td>$($customPolicy.PolicyDisplayName)</td>
<td class="breakwordall">$($customPolicy.PolicyDefinitionId)</td>
<td>$($customPolicy.PolicyCategory)</td>
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                $htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
            }
            $htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
        }
        else {
            $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policies ($scopeNamingSummary)</span></p>
"@
        }
    }
    $endCustPolLoop = get-date
    Write-Host "   Custom Policy processing duration: $((NEW-TIMESPAN -Start $startCustPolLoop -End $endCustPolLoop).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startCustPolLoop -End $endCustPolLoop).TotalSeconds) seconds)"
    #endregion SUMMARYcustompolicies

    $startcustpolorph = get-date
    #region SUMMARYCustomPoliciesOrphandedTenantRoot
    Write-Host "  processing TenantSummary Custom Policies orphaned"
    if ($getMgParentName -eq "Tenant Root") {
        $customPoliciesOrphaned = [System.Collections.ArrayList]@()
        foreach ($customPolicyAll in $customPoliciesArray) {
            if (($policyPolicyBaseQueryUniqueCustomDefinitions | measure-object).count -eq 0) {
                #$hlpCustomPolicy = $customPolicyAll
                #if ($customPolicyAll.Type -eq "Custom") {
                    $null = $customPoliciesOrphaned.Add($customPolicyAll)
                #}
            }
            else {
                if ($policyPolicyBaseQueryUniqueCustomDefinitions -notcontains ($customPolicyAll.PolicyDefinitionId)) {
                #}
                #else {
                    #$hlpCustomPolicy = $customPolicyAll
                    #if ($customPolicyAll.Type -eq "Custom") {
                        $null = $customPoliciesOrphaned.Add($customPolicyAll)
                    #}
                }
            }
        }

        $arrayCustomPoliciesOrphanedFinal = [System.Collections.ArrayList]@()
        foreach ($customPolicyOrphaned in $customPoliciesOrphaned) {
            if (-not $htPoliciesUsedInPolicySets.($customPolicyOrphaned.id)) {
                $null = $arrayCustomPoliciesOrphanedFinal.Add($customPolicyOrphaned)
            }
        }

        #rgchange
        $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()
        foreach ($customPolicyOrphanedFinal in $arrayCustomPoliciesOrphanedFinal) {
            if ($arrayCachePolicyAssignmentsResourceGroupsAndResources.properties.PolicyDefinitionId -notcontains $customPolicyOrphanedFinal.PolicyDefinitionId) {
                $null = $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups.Add($customPolicyOrphanedFinal)
            }
        }

        if (($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0) {
            $tfCount = ($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count
            $htmlTableId = "TenantSummary_customPoliciesOrphaned"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_customPoliciesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom Policies ($scopeNamingSummary)</span> <abbr title="Policy is not used in a PolicySet &#13;AND &#13;Policy has no Assignments (including ResourceGroups)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Policy DisplayName</th>
<th>PolicyId</th>
</tr>
</thead>
<tbody>
"@
            $htmlSUMMARYCustomPoliciesOrphandedTenantRoot = $null
            $htmlSUMMARYCustomPoliciesOrphandedTenantRoot = foreach ($customPolicyOrphaned in $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | sort-object @{Expression = { $_.DisplayName } }, @{Expression = { $_.PolicyDefinitionId } }) {
                @"
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
        }
        else {
            $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($customPoliciesOrphaned | measure-object).count) Orphaned Custom Policies ($scopeNamingSummary)</span></p>
"@
        }
    }
    #SUMMARY Custom Policies Orphanded NOT TenantRoot
    else {
        $customPoliciesOrphaned = [System.Collections.ArrayList]@()
        foreach ($customPolicyAll in $customPoliciesArray) {
            if (($policyPolicyBaseQueryUniqueCustomDefinitions | measure-object).count -eq 0) {
                $null = $customPoliciesOrphaned.Add($customPolicyAll)
            }
            else {
                if ($policyPolicyBaseQueryUniqueCustomDefinitions -notcontains ($customPolicyAll.PolicyDefinitionId)) {    
                    $null = $customPoliciesOrphaned.Add($customPolicyAll)
                }
            }
        }

        $customPoliciesOrphanedInScopeArray = [System.Collections.ArrayList]@()
        foreach ($customPolicyOrphaned in  $customPoliciesOrphaned) {
            $hlpOrphanedInScope = $customPolicyOrphaned
            if (($hlpOrphanedInScope.PolicyDefinitionId) -like "/providers/Microsoft.Management/managementGroups/*") {
                $policyScopedMgSub = $hlpOrphanedInScope.PolicyDefinitionId -replace "/providers/Microsoft.Management/managementGroups/" -replace "/.*"
                if ($mgsAndSubs.MgId -contains ($policyScopedMgSub)) {
                    $null = $customPoliciesOrphanedInScopeArray.Add($hlpOrphanedInScope)
                }
            }
            if (($hlpOrphanedInScope.PolicyDefinitionId) -like "/subscriptions/*") {
                $policyScopedMgSub = $hlpOrphanedInScope.PolicyDefinitionId -replace "/subscriptions/" -replace "/.*"
                if ($mgsAndSubs.SubscriptionId -contains ($policyScopedMgSub)) {
                    $null = $customPoliciesOrphanedInScopeArray.Add($hlpOrphanedInScope)
                }
            }
        }

        $arrayCustomPoliciesOrphanedFinal = [System.Collections.ArrayList]@()
        foreach ($customPolicyOrphanedInScopeArray in $customPoliciesOrphanedInScopeArray) {
            if (-not $htPoliciesUsedInPolicySets.($customPolicyOrphanedInScopeArray.id)) {
                $null = $arrayCustomPoliciesOrphanedFinal.Add($customPolicyOrphanedInScopeArray)
            }
        }

        $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()
        foreach ($customPolicyOrphanedFinal in $arrayCustomPoliciesOrphanedFinal) {
            if ($arrayCachePolicyAssignmentsResourceGroupsAndResources.properties.PolicyDefinitionId -notcontains $customPolicyOrphanedFinal.PolicyDefinitionId) {
                $null = $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups.Add($customPolicyOrphanedFinal)
            }
        }

        if (($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0) {
            $tfCount = ($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count
            $htmlTableId = "TenantSummary_customPoliciesOrphaned"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_customPoliciesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom Policies ($scopeNamingSummary)</span> <abbr title="Policy is not used in a PolicySet &#13;AND &#13;Policy has no Assignments (including ResourceGroups) &#13;Note: Policies from superior scopes are not evaluated"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Policy DisplayName</th>
<th>PolicyId</th>
</tr>
</thead>
<tbody>
"@
            $htmlSUMMARYCustomPoliciesOrphandedTenantRoot = $null
            $htmlSUMMARYCustomPoliciesOrphandedTenantRoot = foreach ($customPolicyOrphaned in $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | sort-object @{Expression = { $_.DisplayName } }, @{Expression = { $_.PolicyDefinitionId } }) {
                @"
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
        }
        else {
            $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups.count) Orphaned Custom Policies ($scopeNamingSummary)</span></p>
"@
        }
    }
    #endregion SUMMARYCustomPoliciesOrphandedTenantRoot
    $endcustpolorph = get-date
    Write-Host "   processing TenantSummary Custom Policies orphaned duration: $((NEW-TIMESPAN -Start $startcustpolorph -End $endcustpolorph).TotalSeconds) seconds"

    #region SUMMARYtenanttotalcustompolicySets
    Write-Host "  processing TenantSummary Custom PolicySets"
    $script:customPolicySetsDetailed = [System.Collections.ArrayList]@()
    $custompolicySetsInScopeArray = [System.Collections.ArrayList]@()
    if ($tenantCustompolicySetsCount -gt 0) {
        foreach ($customPolicySet in ($customPolicySetsArray)) {
    
            $customPolicySet = $customPolicySet
            $policySetUniqueAssignments = (($policyPolicySetBaseQueryUniqueAssignments | Where-Object { $_.PolicyDefinitionId -eq $customPolicySet.id }).PolicyAssignmentId)
            $policySetUniqueAssignmentsArray = [System.Collections.ArrayList]@()
            foreach ($policySetUniqueAssignment in $policySetUniqueAssignments) {
                $null = $policySetUniqueAssignmentsArray.Add($policySetUniqueAssignment)
            }
            $policySetUniqueAssignmentsCount = ($policySetUniqueAssignments | measure-object).count 
            if ($policySetUniqueAssignmentsCount -gt 0) {
                $policySetUniqueAssignmentsList = "($($policySetUniqueAssignmentsArray -join "$CsvDelimiterOpposite "))"
                $policySetUniqueAssignment = "$policySetUniqueAssignmentsCount $policySetUniqueAssignmentsList"
            }
            else {
                $policySetUniqueAssignment = $policySetUniqueAssignmentsCount
            }

            $policySetPoliciesArray = [System.Collections.ArrayList]@()
            foreach ($policyPolicySet in $customPolicySet.PolicySetPolicyIds) {
                $hlpPolicyDef = ($htCacheDefinitions).policy.($policyPolicySet)

                if ($hlpPolicyDef.Type -eq "Builtin") {
                    $null = $policySetPoliciesArray.Add("$($hlpPolicyDef.LinkToAzAdvertizer) ($policyPolicySet)")
                }
                else {
                    $null = $policySetPoliciesArray.Add("<b>$($hlpPolicyDef.DisplayName)</b> ($policyPolicySet)")
                }
            }
            $policySetPoliciesCount = ($policySetPoliciesArray | Measure-Object).count
            if ($policySetPoliciesCount -gt 0) {
                $policiesUsed = "$policySetPoliciesCount ($(($policySetPoliciesArray | sort-Object) -join "$CsvDelimiterOpposite "))"
            }
            else {
                $policiesUsed = "0 really?"
            }

            #inscopeOrNot
            if ($getMgParentName -ne "Tenant Root") {
                if ($mgsAndSubs.MgId -contains ($customPolicySet.ScopeId)) {
                    $null = $custompolicySetsInScopeArray.Add($customPolicySet)
                }
                if ($mgsAndSubs.SubscriptionId -contains ($customPolicySet.ScopeId)) {
                    $null = $custompolicySetsInScopeArray.Add($customPolicySet)
                }
            }

            $null = $script:customPolicySetsDetailed.Add([PSCustomObject]@{ 
                    Scope                 = $customPolicySet.ScopeMgSub
                    ScopeId               = $customPolicySet.ScopeId
                    PolicySetDisplayName  = $customPolicySet.DisplayName
                    PolicySetDefinitionId = $customPolicySet.PolicyDefinitionId 
                    PolicySetCategory     = $customPolicySet.Category
                    UniqueAssignments     = $policySetUniqueAssignment 
                    PoliciesUsed          = $policiesUsed
                })
        }
    }

    if ($getMgParentName -eq "Tenant Root") {
        if ($tenantCustompolicySetsCount -gt $LimitPOLICYPolicySetDefinitionsScopedTenant * ($LimitCriticalPercentage / 100)) {
            $faimage = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
        }
        else {
            $faimage = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
        }

        if ($tenantCustompolicySetsCount -gt 0) {
            $tfCount = $tenantCustompolicySetsCount
            $htmlTableId = "TenantSummary_customPolicySets"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_customPolicySets">$faimage <span class="valignMiddle">$tenantCustompolicySetsCount Custom PolicySets ($scopeNamingSummary) (Limit: $tenantCustompolicySetsCount/$LimitPOLICYPolicySetDefinitionsScopedTenant)</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>ScopeId</th>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
<th>Category</th>
<th>Unique Assignments</th>
<th>Policies used in PolicySet</th>
</tr>
</thead>
<tbody>
"@
            $htmlSUMMARYtenanttotalcustompolicySets = $null
            $htmlSUMMARYtenanttotalcustompolicySets = foreach ($customPolicySet in $customPolicySetsDetailed | Sort-Object @{Expression = { $_.Scope } }, @{Expression = { $_.PolicySetDisplayName } }, @{Expression = { $_.PolicySetDefinitionId } }) {
                @"
<tr>
<td>$($customPolicySet.Scope)</td>
<td>$($customPolicySet.ScopeId)</td>
<td>$($customPolicySet.PolicySetDisplayName)</td>
<td class="breakwordall">$($customPolicySet.PolicySetDefinitionId)</td>
<td class="breakwordall">$($customPolicySet.PolicySetCategory)</td>
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                $htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@   
            }
            $htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
            col_types: [
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
        }
        else {
            $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPolicySetsCount Custom PolicySets ($scopeNamingSummary)</span></p>
"@
        }
    }
    #SUMMARY NOT tenant total custom policySets
    else {
        $faimage = "<i class=`"fa fa-check-circle`" aria-hidden=`"true`"></i>"
        if ($tenantCustompolicySetsCount -gt $LimitPOLICYPolicySetDefinitionsScopedTenant * ($LimitCriticalPercentage / 100)) {
            $faimage = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
        }
        else {
            $faimage = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
        }

        if ($tenantCustompolicySetsCount -gt 0) {
            $custompolicySetsFromSuperiorMGs = $tenantCustompolicySetsCount - (($custompolicySetsInScopeArray | measure-object).count)
        }
        else {
            $custompolicySetsFromSuperiorMGs = "0"
        }

        if ($tenantCustompolicySetsCount -gt 0) {
            $tfCount = $tenantCustompolicySetsCount
            $htmlTableId = "TenantSummary_customPolicySets"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_customPolicySets">$faimage <span class="valignMiddle">$tenantCustomPolicySetsCount Custom PolicySets $scopeNamingSummary ($custompolicySetsFromSuperiorMGs from superior scopes) (Limit: $tenantCustompolicySetsCount/$LimitPOLICYPolicySetDefinitionsScopedTenant)</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>Scope Id</th>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
<th>Category</th>
<th>Unique Assignments</th>
<th>Policies used in PolicySet</th>
</tr>
</thead>
<tbody>
"@
            $htmlSUMMARYtenanttotalcustompolicySets = $null
            $htmlSUMMARYtenanttotalcustompolicySets = foreach ($customPolicySet in $customPolicySetsDetailed | Sort-Object @{Expression = { $_.Scope } }, @{Expression = { $_.PolicySetDisplayName } }, @{Expression = { $_.PolicySetDefinitionId } }) {
                @"
<tr>
<td class="breakwordall">$($customPolicySet.Scope)</td>
<td class="breakwordall">$($customPolicySet.ScopeId)</td>
<td>$($customPolicySet.PolicySetDisplayName)</td>
<td class="breakwordall">$($customPolicySet.PolicySetDefinitionId)</td>
<td class="breakwordall">$($customPolicySet.PolicySetCategory)</td>
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                $htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@    
            }
            $htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
            col_types: [
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
        }
        else {
            $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPolicySetsCount Custom PolicySets ($scopeNamingSummary)</span></p>
"@
        }
    }
    #endregion SUMMARYtenanttotalcustompolicySets

    #region SUMMARYCustompolicySetOrphandedTenantRoot
    Write-Host "  processing TenantSummary Custom PolicySets orphaned"
    if ($getMgParentName -eq "Tenant Root") {
        $custompolicySetSetsOrphaned = [System.Collections.ArrayList]@()
        foreach ($custompolicySetAll in $customPolicySetsArray) {
            if (($policyPolicySetBaseQueryUniqueCustomDefinitions | measure-object).count -eq 0) {
                $null = $custompolicySetSetsOrphaned.Add($custompolicySetAll)
            }
            else {
                if ($policyPolicySetBaseQueryUniqueCustomDefinitions -notcontains ($custompolicySetAll.id)) {
                    $null = $custompolicySetSetsOrphaned.Add($custompolicySetAll)
                }
            }
        }

        $arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()
        foreach ($customPolicySetOrphaned in $custompolicySetSetsOrphaned) {
            if ($arrayCachePolicyAssignmentsResourceGroupsAndResources.properties.PolicyDefinitionId -notcontains $customPolicySetOrphaned.PolicyDefinitionId) {
                $null = $arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups.Add($customPolicySetOrphaned)
            }
        }

        if (($arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0) {
            $tfCount = ($arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups | measure-object).count
            $htmlTableId = "TenantSummary_customPolicySetsOrphaned"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_custompolicySetsOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom PolicySets ($scopeNamingSummary)</span> <abbr title="PolicySet has no Assignments (including ResourceGroups)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
</tr>
</thead>
<tbody>
"@
            $htmlSUMMARYCustompolicySetOrphandedTenantRoot = $null
            $htmlSUMMARYCustompolicySetOrphandedTenantRoot = foreach ($custompolicySetOrphaned in $arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups | sort-object @{Expression = { $_.DisplayName } }, @{Expression = { $_.policyDefinitionId } }) {
                @"
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
        }
        else {
            $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom PolicySets ($scopeNamingSummary)</span></p>
"@
        }
    }
    #SUMMARY Custom policySetSets Orphanded NOT TenantRoot
    else {
        $arraycustompolicySetsOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()
        foreach ($custompolicySetAll in $customPolicySetsArray) {
            $isOrphaned = "unknown"
            if (($policyPolicySetBaseQueryUniqueCustomDefinitions | measure-object).count -eq 0) {
                $isOrphaned = "potentially"
            }
            else {
                if ($policyPolicySetBaseQueryUniqueCustomDefinitions -notcontains $custompolicySetAll.id) {    
                    $isOrphaned = "potentially"
                }
            }
            #$isOrphaned
            if ($isOrphaned -eq "potentially") {
                $isInScope = "unknown"
                if ($custompolicySetAll.PolicyDefinitionId -like "/providers/Microsoft.Management/managementGroups/*") {
                    $policySetScopedMgSub = $custompolicySetAll.PolicyDefinitionId -replace "/providers/Microsoft.Management/managementGroups/", "" -replace '/.*'
                    if ($mgsAndSubs.MgId -contains ($policySetScopedMgSub)) {
                        $isInScope = "inScope"
                    }
                }
                elseif ($custompolicySetAll.PolicyDefinitionId -like "/subscriptions/*") {
                    $policySetScopedMgSub = $custompolicySetAll.PolicyDefinitionId -replace "/subscriptions/", "" -replace '/.*'
                    if ($mgsAndSubs.SubscriptionId -contains ($policySetScopedMgSub)) {
                        $isInScope = "inScope"
                    }
                }
                else {
                    write-host "unexpected"
                }

                if ($isInScope -eq "inScope") {
                    if ($arrayCachePolicyAssignmentsResourceGroupsAndResources.properties.PolicyDefinitionId -notcontains $custompolicySetAll.PolicyDefinitionId) {
                        $null = $arraycustompolicySetsOrphanedFinalIncludingResourceGroups.Add($custompolicySetAll)
                    }
                }
            }
        }

        if (($arraycustompolicySetsOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0) {
            $tfCount = ($arraycustompolicySetsOrphanedFinalIncludingResourceGroups | measure-object).count
            $htmlTableId = "TenantSummary_customPolicySetsOrphaned"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_custompolicySetsOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arraycustompolicySetsOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom PolicySets ($scopeNamingSummary)</span> <abbr title="PolicySet has no Assignments (including ResourceGroups) &#13;Note: PolicySets from superior scopes are not evaluated"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
</tr>
</thead>
<tbody>
"@
            $htmlSUMMARYCustompolicySetOrphandedTenantRoot = $null
            $htmlSUMMARYCustompolicySetOrphandedTenantRoot = foreach ($custompolicySetOrphaned in $arraycustompolicySetsOrphanedFinalIncludingResourceGroups | sort-object @{Expression = { $_.DisplayName } }, @{Expression = { $_.policyDefinitionId } }) {
                @"
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
        }
        else {
            $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($arraycustompolicySetsOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom PolicySets ($scopeNamingSummary)</span></p>
"@
        }
    }
    #endregion SUMMARYCustompolicySetOrphandedTenantRoot

    $startcustpolsetdeprpol = get-date
    #region SUMMARYPolicySetsDeprecatedPolicy
    Write-Host "  processing TenantSummary Custom PolicySets using depracted Policy"
    $policySetsDeprecated = [System.Collections.ArrayList]@()
    $customPolicySetsCount = ($customPolicySetsArray | Measure-Object).count
    if ($customPolicySetsCount -gt 0) {
        foreach ($polSetDef in $customPolicySetsArray) {
            foreach ($polsetPolDefId in $polSetDef.PolicySetPolicyIds) {
                $hlpDeprecatedPolicySet = (($htCacheDefinitions).policy.$polsetPolDefId)
                if ($hlpDeprecatedPolicySet.Type -eq "BuiltIn") {
                    if ($hlpDeprecatedPolicySet.Deprecated -eq $true -or ($hlpDeprecatedPolicySet.DisplayName).StartsWith("[Deprecated]", "CurrentCultureIgnoreCase")) {
                        $null = $policySetsDeprecated.Add([PSCustomObject]@{
                                PolicySetDisplayName  = $polSetDef.DisplayName
                                PolicySetDefinitionId = $polSetDef.PolicyDefinitionId
                                PolicyDisplayName     = $hlpDeprecatedPolicySet.DisplayName
                                PolicyId              = $hlpDeprecatedPolicySet.id
                                DeprecatedProperty    = $hlpDeprecatedPolicySet.Deprecated 
                            })
                    }
                }
            }
        }
    }

    if (($policySetsDeprecated | measure-object).count -gt 0) {
        $tfCount = ($policySetsDeprecated | measure-object).count
        $htmlTableId = "TenantSummary_policySetsDeprecated"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_policySetsDeprecated"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($policySetsDeprecated | measure-object).count) Custom PolicySets / deprecated Built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] &#13;OR &#13;Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYPolicySetsDeprecatedPolicy = foreach ($policySetDeprecated in $policySetsDeprecated | sort-object @{Expression = { $_.PolicySetDisplayName } }, @{Expression = { $_.PolicySetDefinitionId } }) {
            if ($policySetDeprecated.DeprecatedProperty -eq $true) {
                $deprecatedProperty = "true"
            }
            else {
                $deprecatedProperty = "false"
            }
            @"
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($policySetsDeprecated | measure-object).count) PolicySets / deprecated Built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] &#13;OR &#13;Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span></p>
"@
    }
    #endregion SUMMARYPolicySetsDeprecatedPolicy
    $endcustpolsetdeprpol = get-date
    Write-Host "   processing PolicySetsDeprecatedPolicy duration: $((NEW-TIMESPAN -Start $startcustpolsetdeprpol -End $endcustpolsetdeprpol).TotalSeconds) seconds"


    #region SUMMARYPolicyAssignmentsDeprecatedPolicy
    Write-Host "  processing TenantSummary PolicyAssignments using deprecated Policy"
    $policyAssignmentsDeprecated = [System.Collections.ArrayList]@()
    foreach ($policyAssignmentAll in $($htCacheAssignments2).policy.keys) {
    
        $hlpAssignmentDeprecatedPolicy = ($htCacheAssignments2).policy.($policyAssignmentAll)
        
        #policySet
        if ($($htCacheDefinitions).policySet.(($hlpAssignmentDeprecatedPolicy.PolicyDefinitionId))) {
            foreach ($polsetPolDefId in $($htCacheDefinitions).policySet.(($hlpAssignmentDeprecatedPolicy.PolicyDefinitionId)).PolicySetPolicyIds) {
                $hlpDeprecatedAssignment = (($htCacheDefinitions).policy.(($polsetPolDefId)))
                if ($hlpDeprecatedAssignment.type -eq "BuiltIn") {
                    if ($hlpDeprecatedAssignment.Deprecated -eq $true -or ($hlpDeprecatedAssignment.displayname).StartsWith("[Deprecated]", "CurrentCultureIgnoreCase")) {                        
                        $null = $policyAssignmentsDeprecated.Add([PSCustomObject]@{
                                PolicyAssignmentDisplayName = $hlpAssignmentDeprecatedPolicy.PolicyAssignmentDisplayName
                                PolicyAssignmentId          = $policyAssignmentAll
                                PolicyDisplayName           = $hlpDeprecatedAssignment.DisplayName
                                PolicyId                    = $hlpDeprecatedAssignment.id
                                PolicySetDisplayName        = ($htCacheDefinitions).policySet.(($hlpAssignmentDeprecatedPolicy.PolicyDefinitionId)).DisplayName
                                PolicySetId                 = ($htCacheDefinitions).policySet.(($hlpAssignmentDeprecatedPolicy.PolicyDefinitionId)).PolicyDefinitionId
                                PolicyType                  = "PolicySet"
                                DeprecatedProperty          = $hlpDeprecatedAssignment.Deprecated 
                            })
                    }
                }
            }
        }

        #Policy
        $hlpDeprecatedAssignmentPol = ($htCacheDefinitions).policy.(($hlpAssignmentDeprecatedPolicy.PolicyDefinitionId))
        if ($hlpDeprecatedAssignmentPol) {
            if ($hlpDeprecatedAssignmentPol.type -eq "BuiltIn") {
                if ($hlpDeprecatedAssignmentPol.Deprecated -eq $true -or ($hlpDeprecatedAssignmentPol.DisplayName).StartsWith("[Deprecated]", "CurrentCultureIgnoreCase")) {
                    $null = $policyAssignmentsDeprecated.Add([PSCustomObject]@{
                            PolicyAssignmentDisplayName = $hlpAssignmentDeprecatedPolicy.PolicyAssignmentDisplayName
                            PolicyAssignmentId          = $policyAssignmentAll
                            PolicyDisplayName           = $hlpDeprecatedAssignmentPol.DisplayName
                            PolicyId                    = $hlpDeprecatedAssignmentPol.id
                            PolicyType                  = "Policy"
                            DeprecatedProperty          = $hlpDeprecatedAssignmentPol.Deprecated
                            PolicySetDisplayName        = "n/a"
                            PolicySetId                 = "n/a"
                        })
                }
            }
        }
    }

    if (($policyAssignmentsDeprecated | measure-object).count -gt 0) {
        $tfCount = ($policyAssignmentsDeprecated | measure-object).count
        $htmlTableId = "TenantSummary_policyAssignmentsDeprecated"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_policyAssignmentsDeprecated"><i class="fa fa-exclamation-triangle orange" aria-hidden="true"></i> <span class="valignMiddle">$(($policyAssignmentsDeprecated | measure-object).count) Policy Assignments / deprecated Built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] &#13;OR &#13;Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYPolicyAssignmentsDeprecatedPolicy = foreach ($policyAssignmentDeprecated in $policyAssignmentsDeprecated | sort-object @{Expression = { $_.PolicyAssignmentDisplayName } }, @{Expression = { $_.PolicyAssignmentId } }) {
            if ($policyAssignmentDeprecated.DeprecatedProperty -eq $true) {
                $deprecatedProperty = "true"
            }
            else {
                $deprecatedProperty = "false"
            }
            @"
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($policyAssignmentsDeprecated | measure-object).count) Policy Assignments / deprecated Built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] &#13;OR &#13;Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span></p>
"@
    }
    #endregion SUMMARYPolicyAssignmentsDeprecatedPolicy

    #region SUMMARYPolicyExemptions
    Write-Host "  processing TenantSummary Policy Exemptions"
    $policyExemptionsCount = ($htPolicyAssignmentExemptions.Keys | Measure-Object).Count

    if ($policyExemptionsCount -gt 0) {
        $tfCount = $policyExemptionsCount
        $htmlTableId = "TenantSummary_policyExemptions"

        $expiredExemptionsCount = ($htPolicyAssignmentExemptions.Keys | where-object { $htPolicyAssignmentExemptions.($_).exemption.properties.expiresOn -and $htPolicyAssignmentExemptions.($_).exemption.properties.expiresOn -lt (Get-Date).ToUniversalTime() } | Measure-Object).count

        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_policyExemptions"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$($policyExemptionsCount) Policy Exemptions | Expired: $($expiredExemptionsCount)</span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Mg/Sub</th>
<th>Management Group Id</th>
<th>Management Group Name</th>
<th>SubscriptionId</th>
<th>Subscription Name</th>
<th>ResourceGroup</th>
<th>ResourceName / ResourceType</th>
<th>DisplayName</th>
<th>Category</th>
<th>ExpiresOn (UTC)</th>
<th>Id</th>
<th>Policy AssignmentId</th>
</tr>
</thead>
<tbody>
"@

        $htmlSUMMARYPolicyExemptions = $null
        $htmlSUMMARYPolicyExemptions = foreach ($policyExemption in $htPolicyAssignmentExemptions.Keys | Sort-Object) {
            $exemption = $htPolicyAssignmentExemptions.$policyExemption.exemption
            if ($exemption.properties.expiresOn) {
                $exemptionExpiresOnFormated = (($exemption.properties.expiresOn).ToString("yyyy-MM-dd HH:mm:ss"))
                if ($exemption.properties.expiresOn -gt (Get-Date).ToUniversalTime()) {
                    $exemptionExpiresOn = $exemptionExpiresOnFormated
                }
                else {
                    $exemptionExpiresOn = "expired $($exemptionExpiresOnFormated)"
                }
            }
            else {
                $exemptionExpiresOn = "n/a"
            }

            $splitExemptionId = ($exemption.id).Split('/')
            if (($exemption.id) -like "/subscriptions/*") {
                
                switch (($splitExemptionId | Measure-Object).Count - 1) {
                    #sub
                    6 {
                        $exemptionScope = "Sub"
                        $subId = $splitExemptionId[2]
                        $subdetails = ($optimizedTableForPathQueryMgAndSub | Where-Object { $_.SubscriptionId -eq $subId })
                        $mgId = $subdetails.MgId
                        $mgName = $subdetails.MgName
                        $subName = $subdetails.Subscription
                        $rgName = ""
                        $resName = ""
                    }

                    #rg
                    8 {
                        $exemptionScope = "RG"
                        $subId = $splitExemptionId[2]
                        $subdetails = ($optimizedTableForPathQueryMgAndSub | Where-Object { $_.SubscriptionId -eq $subId })
                        $mgId = $subdetails.MgId
                        $mgName = $subdetails.MgName
                        $subName = $subdetails.Subscription
                        $rgName = $splitExemptionId[4]
                        $resName = ""
                    }

                    #res
                    12 {
                        $exemptionScope = "Res"
                        $subId = $splitExemptionId[2]
                        $subdetails = ($optimizedTableForPathQueryMgAndSub | Where-Object { $_.SubscriptionId -eq $subId })
                        $mgId = $subdetails.MgId
                        $mgName = $subdetails.MgName
                        $subName = $subdetails.Subscription
                        $rgName = $splitExemptionId[4]
                        $resName = "$($splitExemptionId[8]) / $($splitExemptionId[6..7] -join "/")"
                    }
                }
            }
            else {
                $exemptionScope = "MG"
                $mgId = $splitExemptionId[4]
                $mgdetails = ($optimizedTableForPathQueryMg | Where-Object { $_.MgId -eq $mgId })
                $mgName = $mgdetails.MgName
                $subId = ""
                $subName = ""
                $rgName = ""
                $resName = ""
            }

            @"
<tr>
<td>$($exemptionScope)</td>
<td>$($mgId)</td>
<td>$($mgName)</td>
<td>$($subId)</td>
<td>$($subName)</td>
<td>$($rgName)</td>
<td>$($resName)</td>
<td>$($exemption.properties.DisplayName)</td>
<td>$($exemption.properties.exemptionCategory)</td>
<td>$($exemptionExpiresOn)</td>
<td class="breakwordall">$($exemption.id)</td>
<td class="breakwordall">$($exemption.properties.policyAssignmentId)</td>
</tr>
"@ 
        }
        $htmlTenantSummary += $htmlSUMMARYPolicyExemptions
        $htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            $htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@ 
        }
        $htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
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
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$($policyExemptionsCount) Policy Exemptions</span></p>
"@
    }
    #endregion SUMMARYPolicyExemptions

    #region SUMMARYPolicyAssignmentsAll
    $startSummaryPolicyAssignmentsAll = get-date
    $allPolicyAssignments = ($policyBaseQuery | Measure-Object).count
    Write-Host "  processing TenantSummary PolicyAssignments (all $allPolicyAssignments)"

    $script:policyAssignmentsAllArray = [System.Collections.ArrayList]@() 
    $cnter = 0

    $script:htPolicyAssignmentRoleAssignmentMapping = @{ }
    $script:htPolicyAssignmentMiRoleAssignmentMappingAll = @{ }
    if (-not $NoAADServicePrincipalResolve) {
        $script:htPolicyAssignmentRoleAssignmentMapping = @{ }
        foreach ($roleassignmentId in ($htCacheAssignments).role.keys | Sort-Object) {
            $roleAssignment = ($htCacheAssignments).role.($roleassignmentId)

            if ($htManagedIdentityForPolicyAssignment.($roleAssignment.ObjectId)) {
                $mi = $htManagedIdentityForPolicyAssignment.($roleAssignment.ObjectId)

                #allPerMi
                if (-not $htPolicyAssignmentMiRoleAssignmentMappingAll.($roleAssignment.ObjectId)) {
                    $script:htPolicyAssignmentMiRoleAssignmentMappingAll.($roleAssignment.ObjectId) = @{ }
                }
                #this
                if (-not $htPolicyAssignmentRoleAssignmentMapping.($mi.policyAssignmentId)) {
                    $script:htPolicyAssignmentRoleAssignmentMapping.($mi.policyAssignmentId) = @{ }
                }

                if (($htCacheDefinitions).role.($roleAssignment.RoleDefinitionId).IsCustom) {
                    $roleDefinitionType = "custom"
                }
                else {
                    $roleDefinitionType = "builtin"
                }

                $array = [System.Collections.ArrayList]@() 
                $null = $array.Add([PSCustomObject]@{
                        roleassignmentId   = $roleassignmentId
                        roleDefinitionId   = $roleAssignment.RoleDefinitionId
                        roleDefinitionName = $roleAssignment.RoleDefinitionName
                        roleDefinitionType = $roleDefinitionType
                    })
                
                #allPerMi
                if ($htPolicyAssignmentMiRoleAssignmentMappingAll.($roleAssignment.ObjectId).roleassignments) {
                    $script:htPolicyAssignmentMiRoleAssignmentMappingAll.($roleAssignment.ObjectId).roleassignments += $array
                }
                else {
                    $script:htPolicyAssignmentMiRoleAssignmentMappingAll.($roleAssignment.ObjectId).roleassignments = $array
                }    
                #this
                if ($htPolicyAssignmentRoleAssignmentMapping.($mi.policyAssignmentId).roleassignments) {
                    $script:htPolicyAssignmentRoleAssignmentMapping.($mi.policyAssignmentId).roleassignments += $array
                }
                else {
                    $script:htPolicyAssignmentRoleAssignmentMapping.($mi.policyAssignmentId).roleassignments = $array
                }
            }
        }
        foreach ($roleassignmentId in ($htCacheAssignments).rbacOnResourceGroupsAndResources.keys | Sort-Object) {
            $roleAssignment = ($htCacheAssignments).rbacOnResourceGroupsAndResources.($roleassignmentId)

            if ($htManagedIdentityForPolicyAssignment.($roleAssignment.ObjectId)) {
                $mi = $htManagedIdentityForPolicyAssignment.($roleAssignment.ObjectId)

                #allPerMi
                if (-not $htPolicyAssignmentMiRoleAssignmentMappingAll.($roleAssignment.ObjectId)) {
                    $script:htPolicyAssignmentMiRoleAssignmentMappingAll.($roleAssignment.ObjectId) = @{ }
                }
                #this
                if (-not $htPolicyAssignmentRoleAssignmentMapping.($mi.policyAssignmentId)) {
                    $script:htPolicyAssignmentRoleAssignmentMapping.($mi.policyAssignmentId) = @{ }
                }

                if (($htCacheDefinitions).role.($roleAssignment.RoleDefinitionId).IsCustom) {
                    $roleDefinitionType = "custom"
                }
                else {
                    $roleDefinitionType = "builtin"
                }

                $array = [System.Collections.ArrayList]@() 
                $null = $array.Add([PSCustomObject]@{
                        roleassignmentId   = $roleassignmentId
                        roleDefinitionId   = $roleAssignment.RoleDefinitionId
                        roleDefinitionName = $roleAssignment.RoleDefinitionName
                        roleDefinitionType = $roleDefinitionType
                    })
                
                #allPerMi
                if ($htPolicyAssignmentMiRoleAssignmentMappingAll.($roleAssignment.ObjectId).roleassignments) {
                    $script:htPolicyAssignmentMiRoleAssignmentMappingAll.($roleAssignment.ObjectId).roleassignments += $array
                }
                else {
                    $script:htPolicyAssignmentMiRoleAssignmentMappingAll.($roleAssignment.ObjectId).roleassignments = $array
                }    
                #this
                if ($htPolicyAssignmentRoleAssignmentMapping.($mi.policyAssignmentId).roleassignments) {
                    $script:htPolicyAssignmentRoleAssignmentMapping.($mi.policyAssignmentId).roleassignments += $array
                }
                else {
                    $script:htPolicyAssignmentRoleAssignmentMapping.($mi.policyAssignmentId).roleassignments = $array
                }
            }
        }
        $htPolicyAssignmentRoleAssignmentMappingCount = ($htPolicyAssignmentRoleAssignmentMapping.keys | Measure-Object).Count
    }

    $starttest = get-date

    $htPolicyAssignmentRelatedRoleAssignments = @{ }
    $htPolicyAssignmentEffect = @{ }
    $htPolicyAssignmentRelatedExemptions = @{ }
    $htPolicyAzAdvertizerOrNot = @{ }

    foreach ($policyAssignmentIdUnique in $policyBaseQueryUniqueAssignments) {
        
        $hlpDefinitionPolicy = ($htCacheDefinitions).policy.($policyAssignmentIdUnique.PolicyDefinitionId)

        #if ($policyAssignmentIdUnique.PolicyDefinitionId -like "*/Microsoft.Authorization/policyDefinitions/*") {
        if ($policyAssignmentIdUnique.PolicyVariant -eq "Policy") {
            $test0 = $policyAssignmentIdUnique.PolicyAssigmentParameters.effect.value
            if ($test0) {
                $effect = $test0
            }
            else {
                $test1 = $hlpDefinitionPolicy.effectDefaultValue
                if ($test1 -ne "n/a") {
                    $effect = $test1
                }
                $test2 = $hlpDefinitionPolicy.effectFixedValue
                if ($test2 -ne "n/a") {
                    $effect = $test2
                }
            }
            #$effect
            $htPolicyAssignmentEffect.($policyAssignmentIdUnique.PolicyAssignmentId) = @{ }
            $htPolicyAssignmentEffect.($policyAssignmentIdUnique.PolicyAssignmentId).effect = $effect
        }

        $relatedRoleAssignmentsArray = @() 
        if ($htPolicyAssignmentRoleAssignmentMappingCount -gt 0) {
            if ($htPolicyAssignmentRoleAssignmentMapping.($policyAssignmentIdUnique.PolicyAssignmentId)) {
                $relatedRoleAssignmentsArray += foreach ($entry in $htPolicyAssignmentRoleAssignmentMapping.($policyAssignmentIdUnique.PolicyAssignmentId).roleassignments) {
                    if ($entry.roleDefinitionType -eq "builtin") {
                        Write-Output "$(($htCacheDefinitions).role.($entry.roleDefinitionId).LinkToAzAdvertizer) ($($entry.roleAssignmentId))"
                    }
                    else {
                        Write-Output "<u>$($entry.roleDefinitionName)</u> ($($entry.roleAssignmentId))"
                    }
                }
            }
        }
        
        $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId) = @{ }
        if (-not $NoAADServicePrincipalResolve) {
            if (($relatedRoleAssignmentsArray | Measure-Object).count -gt 0) {
                $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId).relatedRoleAssignments = ($relatedRoleAssignmentsArray | sort-object) -join "$CsvDelimiterOpposite "
            }
            else {
                $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId).relatedRoleAssignments = "none"
            }
        }
        else {
            $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId).relatedRoleAssignments = "n/a"
        }

        $htPolicyAzAdvertizerOrNot.($policyAssignmentIdUnique.PolicyAssignmentId) = @{ }
        if ($policyAssignmentIdUnique.PolicyType -eq "builtin") {
            if ($policyAssignmentIdUnique.PolicyVariant -eq "Policy") {
                $htPolicyAzAdvertizerOrNot.($policyAssignmentIdUnique.PolicyAssignmentId).policyWithWithoutLinkToAzAdvertizer = $hlpDefinitionPolicy.LinkToAzAdvertizer
            }
            else {
                $htPolicyAzAdvertizerOrNot.($policyAssignmentIdUnique.PolicyAssignmentId).policyWithWithoutLinkToAzAdvertizer = ($htCacheDefinitions).policySet.($policyAssignmentIdUnique.PolicyDefinitionId).LinkToAzAdvertizer
            }
        }
        else {
            $htPolicyAzAdvertizerOrNot.($policyAssignmentIdUnique.PolicyAssignmentId).policyWithWithoutLinkToAzAdvertizer = $policyAssignmentIdUnique.policy
        }

        #region exemptions
        $arrayExemptions = @()
        foreach ($exemptionId in $htPolicyAssignmentExemptions.keys) {
            if ($htPolicyAssignmentExemptions.($exemptionId).exemption.properties.policyAssignmentId -eq $policyAssignmentIdUnique.PolicyAssignmentId) {
                $arrayExemptions += $htPolicyAssignmentExemptions.($exemptionId).exemption
                if (-not $htPolicyAssignmentRelatedExemptions.($policyAssignmentIdUnique.PolicyAssignmentId)) {
                    $htPolicyAssignmentRelatedExemptions.($policyAssignmentIdUnique.PolicyAssignmentId) = @{ }
                    $htPolicyAssignmentRelatedExemptions.($policyAssignmentIdUnique.PolicyAssignmentId).exemptionsCount = 1
                    $htPolicyAssignmentRelatedExemptions.($policyAssignmentIdUnique.PolicyAssignmentId).exemptions = $arrayExemptions
                }
                else {
                    $htPolicyAssignmentRelatedExemptions.($policyAssignmentIdUnique.PolicyAssignmentId).exemptionsCount += 1
                    $htPolicyAssignmentRelatedExemptions.($policyAssignmentIdUnique.PolicyAssignmentId).exemptions = $arrayExemptions
                }
            }
        }
        #endregion exemptions
    }

    $endtest = get-date
    Write-Host "   processing duration: $((NEW-TIMESPAN -Start $starttest -End $endtest).TotalSeconds) seconds"

    $starttest2 = get-date
    foreach ($policyAssignmentAll in $policyBaseQuery) {  
        $cnter++
        if ($cnter % 500 -eq 0) {
            $etappeSummaryPolicyAssignmentsAll = get-date
            Write-Host "   $cnter of $allPolicyAssignments PolicyAssignments processed: $((NEW-TIMESPAN -Start $startSummaryPolicyAssignmentsAll -End $etappeSummaryPolicyAssignmentsAll).TotalSeconds) seconds"
        }

        $excludedScope = "false"
        if (($policyAssignmentAll.PolicyAssignmentNotScopes | Measure-Object).count -gt 0) {
            foreach ($policyAssignmentNotScope in $policyAssignmentAll.PolicyAssignmentNotScopes) {
                if (-not [String]::IsNullOrEmpty($policyAssignmentAll.subscriptionId)) {
                    if ($htAllSubsMgPath.($policyAssignmentAll.subscriptionId).path -contains "'$($policyAssignmentNotScope -replace "/subscriptions/" -replace "/providers/Microsoft.Management/managementGroups/")'") {
                        $excludedScope = "true"
                    }
                }
                else {
                    if ($htAllMgsPath.($policyAssignmentAll.MgId).path -contains "'$($policyAssignmentNotScope -replace "/providers/Microsoft.Management/managementGroups/")'") {
                        $excludedScope = "true"
                    }
                }
            }
        }

        #region exemptions
        $exemptionScope = "false"
        if ($htPolicyAssignmentRelatedExemptions.($policyAssignmentAll.PolicyAssignmentId)) {
            foreach ($exemption in $htPolicyAssignmentRelatedExemptions.($policyAssignmentAll.PolicyAssignmentId).exemptions) {
                if ($exemption.properties.expiresOn) {
                    if ($exemption.properties.expiresOn -gt (Get-Date).ToUniversalTime()) {
                        if (-not [String]::IsNullOrEmpty($policyAssignmentAll.subscriptionId)) {
                            if ($htAllSubsMgPath.($policyAssignmentAll.subscriptionId).path -contains "'$(($exemption.id -split "/providers/Microsoft.Authorization/policyExemptions/")[0] -replace "/subscriptions/" -replace "/providers/Microsoft.Management/managementGroups/")'") {
                                $exemptionScope = "true"
                            }
                        }
                        else {
                            if ($htAllMgsPath.($policyAssignmentAll.MgId).path -contains "'$(($exemption.id -split "/providers/Microsoft.Authorization/policyExemptions/")[0] -replace "/subscriptions/" -replace "/providers/Microsoft.Management/managementGroups/")'") {
                                $exemptionScope = "true"
                            }
                        }
                    }
                    else {
                        #Write-Host "$($exemption.id) $($exemption.properties.expiresOn) $((Get-Date).ToUniversalTime()) expired"
                    }
                }
                else {
                    #same code as above / function?
                    if (-not [String]::IsNullOrEmpty($policyAssignmentAll.subscriptionId)) {
                        if ($htAllSubsMgPath.($policyAssignmentAll.subscriptionId).path -contains "'$(($exemption.id -split "/providers/Microsoft.Authorization/policyExemptions/")[0] -replace "/subscriptions/" -replace "/providers/Microsoft.Management/managementGroups/")'") {
                            $exemptionScope = "true"
                        }
                    }
                    else {
                        if ($htAllMgsPath.($policyAssignmentAll.MgId).path -contains "'$(($exemption.id -split "/providers/Microsoft.Authorization/policyExemptions/")[0] -replace "/subscriptions/" -replace "/providers/Microsoft.Management/managementGroups/")'") {
                            $exemptionScope = "true"
                        }
                    }
                }
            }
        }
        #endregion exemptions

        if ($policyAssignmentAll.PolicyAssignmentId -like "/providers/Microsoft.Management/managementGroups/*") {
            if (-not [String]::IsNullOrEmpty($policyAssignmentAll.SubscriptionId)) {
                $scope = "inherited $($policyAssignmentAll.PolicyAssignmentScope -replace '.*/')"
            }
            else {
                if (($policyAssignmentAll.PolicyAssignmentScope -replace '.*/') -eq $policyAssignmentAll.MgId) {
                    $scope = "thisScope Mg"
                }
                else {
                    $scope = "inherited $($policyAssignmentAll.PolicyAssignmentScope -replace '.*/')"
                }
            }
        }

        if ($policyAssignmentAll.PolicyAssignmentId -like "/subscriptions/*") {
            $scope = "thisScope Sub"
        }

        if ($policyAssignmentAll.PolicyVariant -eq "Policy") {
            $effect = $htPolicyAssignmentEffect.($policyAssignmentAll.PolicyAssignmentId).effect
        }
        else {
            $effect = "n/a"
        }

        if ([String]::IsNullOrEmpty($policyAssignmentAll.SubscriptionId)) {
            $mgOrSub = "Mg"
        }
        else {
            $mgOrSub = "Sub"
        }

        if ($htParameters.NoPolicyComplianceStates -eq $false) {
            #compliance
            $policyAssignmentIdToLower = ($policyAssignmentAll.policyAssignmentId).ToLower()
            if ([String]::IsNullOrEmpty($policyAssignmentAll.subscriptionId)) {
                $compliance = ($htCachePolicyCompliance).mg.($policyAssignmentAll.MgId).($policyAssignmentIdToLower)
                $NonCompliantPolicies = $compliance.NonCompliantPolicies
                $CompliantPolicies = $compliance.CompliantPolicies
                $NonCompliantResources = $compliance.NonCompliantResources
                $CompliantResources = $compliance.CompliantResources
            }
            else {
                $compliance = ($htCachePolicyCompliance).sub.($policyAssignmentAll.SubscriptionId).($policyAssignmentIdToLower)
                $NonCompliantPolicies = $compliance.NonCompliantPolicies
                $CompliantPolicies = $compliance.CompliantPolicies
                $NonCompliantResources = $compliance.NonCompliantResources
                $CompliantResources = $compliance.CompliantResources
            }

            if (!$NonCompliantPolicies) {
                $NonCompliantPolicies = 0
            }
            if (!$CompliantPolicies) {
                $CompliantPolicies = 0
            }
            if (!$NonCompliantResources) {
                $NonCompliantResources = 0
            }
            if (!$CompliantResources) {
                $CompliantResources = 0
            }

            $null = $script:policyAssignmentsAllArray.Add([PSCustomObject]@{ 
                    Level                       = $policyAssignmentAll.Level
                    MgId                        = $policyAssignmentAll.MgId
                    MgName                      = $policyAssignmentAll.MgName
                    subscriptionId              = $policyAssignmentAll.SubscriptionId
                    subscriptionName            = $policyAssignmentAll.Subscription
                    PolicyAssignmentId          = (($policyAssignmentAll.PolicyAssignmentId).Tolower())
                    PolicyAssignmentDisplayName = $policyAssignmentAll.PolicyAssignmentDisplayName
                    PolicyAssignmentDescription = $policyAssignmentAll.PolicyAssignmentDescription
                    Effect                      = $effect
                    PolicyName                  = $htPolicyAzAdvertizerOrNot.($policyAssignmentAll.PolicyAssignmentId).policyWithWithoutLinkToAzAdvertizer
                    PolicyDescription           = $policyAssignmentAll.PolicyDescription
                    PolicyId                    = $policyAssignmentAll.PolicyDefinitionId
                    PolicyVariant               = $policyAssignmentAll.PolicyVariant
                    PolicyType                  = $policyAssignmentAll.PolicyType
                    PolicyCategory              = $policyAssignmentAll.PolicyCategory
                    Inheritance                 = $scope
                    ExcludedScope               = $excludedScope
                    RelatedRoleAssignments      = $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentAll.PolicyAssignmentId).relatedRoleAssignments
                    MgOrSub                     = $mgOrSub
                    NonCompliantPolicies        = [int]$NonCompliantPolicies
                    CompliantPolicies           = $CompliantPolicies
                    NonCompliantResources       = $NonCompliantResources
                    CompliantResources          = $CompliantResources 
                    ExemptionScope              = $exemptionScope
                })
        }
        else {
            $null = $script:policyAssignmentsAllArray.Add([PSCustomObject]@{ 
                    Level                       = $policyAssignmentAll.Level
                    MgId                        = $policyAssignmentAll.MgId
                    MgName                      = $policyAssignmentAll.MgName
                    subscriptionId              = $policyAssignmentAll.SubscriptionId
                    subscriptionName            = $policyAssignmentAll.Subscription
                    PolicyAssignmentId          = (($policyAssignmentAll.PolicyAssignmentId).Tolower())
                    PolicyAssignmentDisplayName = $policyAssignmentAll.PolicyAssignmentDisplayName
                    PolicyAssignmentDescription = $policyAssignmentAll.PolicyAssignmentDescription
                    Effect                      = $effect
                    PolicyName                  = $htPolicyAzAdvertizerOrNot.($policyAssignmentAll.PolicyAssignmentId).policyWithWithoutLinkToAzAdvertizer
                    PolicyDescription           = $policyAssignmentAll.PolicyDescription
                    PolicyId                    = $policyAssignmentAll.PolicyDefinitionId
                    PolicyVariant               = $policyAssignmentAll.PolicyVariant
                    PolicyType                  = $policyAssignmentAll.PolicyType
                    PolicyCategory              = $policyAssignmentAll.PolicyCategory
                    Inheritance                 = $scope
                    ExcludedScope               = $excludedScope
                    RelatedRoleAssignments      = $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentAll.PolicyAssignmentId).relatedRoleAssignments
                    MgOrSub                     = $mgOrSub
                    ExemptionScope              = $exemptionScope
                })
        }
    }


    $script:policyAssignmentsAllArrayGroupedBySubscription = $policyAssignmentsAllArray | Group-Object -Property subscriptionId
    $script:policyAssignmentsAllArrayGroupedByManagementGroup = $policyAssignmentsAllArray | Group-Object -Property MgId

    $endtest2 = get-date
    Write-Host "   processing duration: $((NEW-TIMESPAN -Start $starttest2 -End $endtest2).TotalSeconds) seconds"

    if (($policyAssignmentsAllArray | measure-object).count -gt 0) {
        $tfCount = ($policyAssignmentsAllArray | measure-object).count
        $policyAssignmentsUniqueCount = ($policyAssignmentsAllArray | Sort-Object -Property PolicyAssignmentId -Unique | measure-object).count
        $htmlTableId = "TenantSummary_policyAssignmentsAll"
        if (-not $NoAADServicePrincipalResolve) {
            $noteOrNot = ""
        }
        else {
            $noteOrNot = "<abbr title=`"Note: will show 'n/a' if parameter -NoAADServicePrincipalResolve was used`"><i class=`"fa fa-question-circle`" aria-hidden=`"true`"></i></abbr>"
        }
        $htmlTenantSummary += @"
<button onclick="loadtf$htmlTableId()" type="button" class="collapsible" id="buttonTenantSummary_policyAssignmentsAll"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($policyAssignmentsAllArray | measure-object).count) Policy Assignments ($policyAssignmentsUniqueCount unique)</span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a><br>
&nbsp;&nbsp;<span style="color:#FF5733">*Depending on the number of rows and your computer´s performance the table may respond with delay, download the csv for better filtering experience</span>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Mg/Sub</th>
<th>Management Group Id</th>
<th>Management Group Name</th>
<th>SubscriptionId</th>
<th>Subscription Name</th>
<th>Inheritance</th>
<th>ScopeExcluded</th>
<th>Exemption applies</th>
<th>Policy/Set DisplayName</th>
<th>Policy/Set Description</th>
<th>Policy/SetId</th>
<th>Policy/Set</th>
<th>Type</th>
<th>Category</th>
<th>Effect</th>
"@

        if ($htParameters.NoPolicyComplianceStates -eq $false) {
            $htmlTenantSummary += @"
<th>Policies NonCmplnt</th>
<th>Policies Compliant</th>
<th>Resources NonCmplnt</th>
<th>Resources Compliant</th>
"@
        }

        $htmlTenantSummary += @"
<th>Role/Assignment $noteOrNot</th>
<th>Assignment DisplayName</th>
<th>Assignment Description</th>
<th>AssignmentId</th>
</tr>
</thead>
<tbody>
"@

        $htmlTenantSummary | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
        $htmlTenantSummary = $null
        $htmlSummaryPolicyAssignmentsAll = $null
        $startloop = get-date 

        if ($CsvExport) {
            if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
                $csvFilename = "AzGovViz_$($ManagementGroupIdCaseSensitived)_$($htmlTableId)"
            }
            else {
                $csvFilename = "AzGovViz_$($fileTimestamp)_$($ManagementGroupIdCaseSensitived)_$($htmlTableId)"
            }
            if ($CsvExportUseQuotesAsNeeded) {
                $policyAssignmentsAllArray | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter "$csvDelimiter" -NoTypeInformation -UseQuotes AsNeeded
            }
            else {
                $policyAssignmentsAllArray | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter "$csvDelimiter" -NoTypeInformation
            }
        }

        $htmlSummaryPolicyAssignmentsAll = foreach ($policyAssignment in $policyAssignmentsAllArray | sort-object -Property Level, MgName, MgId, SubscriptionName, SubscriptionId, PolicyAssignmentId) {
            @"
<tr>
<td>$($policyAssignment.MgOrSub)</td>
<td>$($policyAssignment.MgId)</td>
<td>$($policyAssignment.MgName)</td>
<td>$($policyAssignment.SubscriptionId)</td>
<td>$($policyAssignment.SubscriptionName)</td>
<td>$($policyAssignment.Inheritance)</td>
<td>$($policyAssignment.ExcludedScope)</td>
<td>$($policyAssignment.ExemptionScope)</td>
<td>$($policyAssignment.PolicyName)</td>
<td>$($policyAssignment.PolicyDescription)</td>
<td class="breakwordall">$($policyAssignment.PolicyId)</td>
<td>$($policyAssignment.PolicyVariant)</td>
<td>$($policyAssignment.PolicyType)</td>
<td>$($policyAssignment.PolicyCategory)</td>
<td>$($policyAssignment.Effect)</td>
"@

            if ($htParameters.NoPolicyComplianceStates -eq $false) {
                @"
<td>$($policyAssignment.NonCompliantPolicies)</td>
<td>$($policyAssignment.CompliantPolicies)</td>
<td>$($policyAssignment.NonCompliantResources)</td>
<td>$($policyAssignment.CompliantResources)</td>
"@
            }

            @"
<td class="breakwordall">$($policyAssignment.RelatedRoleAssignments)</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentDisplayName)</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentDescription)</td>
<td class="breakwordall">$($policyAssignment.PolicyAssignmentId)</td>
</tr>
"@
        }

        $endloop = get-date
        Write-Host "   loop duration: $((NEW-TIMESPAN -Start $startloop -End $endloop).TotalSeconds) seconds"

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
        function loadtf$htmlTableId() { if (window.helpertfConfig4$htmlTableId !== 1) { 
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            $htmlTenantSummary += @"
        paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@ 
        }
        $htmlTenantSummary += @"
            btn_reset: true, 
            highlight_keywords: true, 
            alternate_rows: true, 
            auto_filter: { 
                delay: 1100 
            }, 
            no_results_message: true,
            col_0: 'select',
            col_6: 'select',
            col_7: 'select',
            col_11: 'select',
            col_12: 'select',
            col_13: 'select',
            col_14: 'select',
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
                'caseinsensitivestring',
                'caseinsensitivestring',
"@

        if ($htParameters.NoPolicyComplianceStates -eq $false) {
            $htmlTenantSummary += @"
                'number',
                'number',
                'number',
                'number',
"@
        }

        $htmlTenantSummary += @"
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
"@

        if ($htParameters.NoPolicyComplianceStates -eq $false) {
            $htmlTenantSummary += @"
            watermark: ['', '', '', 'try [nonempty]', '', 'thisScope', '', '', '', '', '', '','', '', '', '', '', '', ''],
"@
        }
        else {
            $htmlTenantSummary += @"
            watermark: ['', '', '', 'try [nonempty]', '', 'thisScope', '', '', '', '', '', '','', '', '', '', '', '', '', '', '', '', ''],
"@ 
        }

        $htmlTenantSummary += @"
            extensions: [
                {
                    name: 'colsVisibility',
"@

        if ($htParameters.NoPolicyComplianceStates -eq $false) {
            $htmlTenantSummary += @"
                    at_start: [9, 21],
"@
        }
        else {
            $htmlTenantSummary += @"
                    at_start: [9, 17],
"@        
        }

        $htmlTenantSummary += @"
                    text: 'Columns: ',
                    enable_tick_all: true
                },    
                { name: 'sort' 
                }
            ]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($policyAssignmentsAllArray | measure-object).count) Policy Assignments</span></p>
"@
    }
    $endSummaryPolicyAssignmentsAll = get-date
    Write-Host "   SummaryPolicyAssignmentsAll duration: $((NEW-TIMESPAN -Start $startSummaryPolicyAssignmentsAll -End $endSummaryPolicyAssignmentsAll).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startSummaryPolicyAssignmentsAll -End $endSummaryPolicyAssignmentsAll).TotalSeconds) seconds)"
    #endregion SUMMARYPolicyAssignmentsAll

    $htmlTenantSummary += @"
    </div>
"@
    #endregion tenantSummaryPolicy

    #region tenantSummaryRBAC
    $htmlTenantSummary += @"
<button type="button" class="collapsible" id="tenantSummaryRBAC"><hr class="hr-text" data-content="RBAC" /></button>
<div class="content">
"@

    #region SUMMARYtenanttotalcustomroles
    Write-Host "  processing TenantSummary Custom Roles"
    if ($tenantCustomRolesCount -gt $LimitRBACCustomRoleDefinitionsTenant * ($LimitCriticalPercentage / 100)) {
        $faimage = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
    }
    else {
        $faimage = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
    }

    if ($tenantCustomRolesCount -gt 0) {
        $tfCount = $tenantCustomRolesCount
        $htmlTableId = "TenantSummary_customRoles"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_customRoles">$faimage <span class="valignMiddle">$tenantCustomRolesCount Custom Roles ($scopeNamingSummary) (Limit: $tenantCustomRolesCount/$LimitRBACCustomRoleDefinitionsTenant)</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Role Name</th>
<th>RoleId</th>
<th>Assignable Scopes</th>
<th>Data related</th>
</tr>
</thead>
<tbody>
"@
        $htmlSUMMARYtenanttotalcustomroles = $null
        $htmlSUMMARYtenanttotalcustomroles = foreach ($tenantCustomRole in $tenantCustomRolesArray | sort-object @{Expression = { $_.Name } }, @{Expression = { $_.id } }) {
            $cachedTenantCustomRole = ($htCacheDefinitions).role.($tenantCustomRole.id)
            if (-not [string]::IsNullOrEmpty($cachedTenantCustomRole.DataActions) -or -not [string]::IsNullOrEmpty($cachedTenantCustomRole.NotDataActions)) {
                $roleManageData = "true"
            }
            else {
                $roleManageData = "false"
            }
            @"
<tr>
<td>$($cachedTenantCustomRole.Name)
</td>
<td>$($cachedTenantCustomRole.id)
</td>
<td>$(($cachedTenantCustomRole.AssignableScopes | Measure-Object).count) ($($cachedTenantCustomRole.AssignableScopes -join "$CsvDelimiterOpposite "))
</td>
<td>$($roleManageData)
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            $htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@ 
        }
        $htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_3: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'select'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomRolesCount Custom Roles ($scopeNamingSummary)</span></p>
"@
    }
    #endregion SUMMARYtenanttotalcustomroles

    #region SUMMARYOrphanedCustomRoles
    $startSUMMARYOrphanedCustomRoles = get-date
    Write-Host "  processing TenantSummary Custom Roles orphaned"
    if ($getMgParentName -eq "Tenant Root") {
        
        $arrayCustomRolesOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()
        
        if (($tenantCustomRolesArray | Measure-Object).count -gt 0) {
            $mgSubRoleAssignmentsArrayRoleDefinitionIdUnique = $mgSubRoleAssignmentsArray.RoleDefinitionId | sort-object -Unique
            $rgResRoleAssignmentsArrayRoleDefinitionIdUnique = $rgResRoleAssignmentsArray.RoleDefinitionId | sort-object -Unique
            foreach ($customRoleAll in $tenantCustomRolesArray) {
                $roleIsUsed = $false
                if (($mgSubRoleAssignmentsArrayRoleDefinitionIdUnique) -contains ($customRoleAll.id)) {
                    $roleIsUsed = $true
                }

                if ($roleIsUsed -eq $false) {
                    if (($rgResRoleAssignmentsArrayRoleDefinitionIdUnique) -contains ($customRoleAll.id)) {
                        $roleIsUsed = $true
                    }
                }

                if ($roleIsUsed -eq $false) {
                    $null = $arrayCustomRolesOrphanedFinalIncludingResourceGroups.Add($customRoleAll)
                }
                
            }
        }

        if (($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0) {
            $tfCount = ($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count
            $htmlTableId = "TenantSummary_customRolesOrphaned"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_customRolesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom Roles ($scopeNamingSummary) <abbr title="Role has no Assignments (including ResourceGroups and Resources)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
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
            $htmlSUMMARYOrphanedCustomRoles = foreach ($customRoleOrphaned in $arrayCustomRolesOrphanedFinalIncludingResourceGroups | Sort-Object @{Expression = { $_.Name } }) {
                @"
<tr>
<td>$($customRoleOrphaned.Name)</td>
<td>$($customRoleOrphaned.id)</td>
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
        }
        else {
            $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom Roles ($scopeNamingSummary)</span></p>
"@
        }
        #not renant root
    }
    else {
        $mgs = (($optimizedTableForPathQueryMg | Where-Object { $_.mgId -ne "" -and $_.Level -ne "0" }) | select-object MgId -unique)
        $arrayCustomRolesOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()
        
        $mgSubRoleAssignmentsArrayRoleDefinitionIdUnique = $mgSubRoleAssignmentsArray.RoleDefinitionId | sort-object -Unique
        $rgResRoleAssignmentsArrayRoleDefinitionIdUnique = $rgResRoleAssignmentsArray.RoleDefinitionId | sort-object -Unique

        if (($tenantCustomRolesArray | Measure-Object).count -gt 0) {
            foreach ($customRoleAll in $tenantCustomRolesArray) {
                $roleIsUsed = $false
                $customRoleAssignableScopes = $customRoleAll.AssignableScopes
                foreach ($customRoleAssignableScope in $customRoleAssignableScopes) {
                    if (($customRoleAssignableScope) -like "/providers/Microsoft.Management/managementGroups/*") {
                        $roleAssignableScopeMg = $customRoleAssignableScope -replace "/providers/Microsoft.Management/managementGroups/", ""
                        if ($mgs.MgId -notcontains ($roleAssignableScopeMg)) {
                            #assignableScope outside of the ManagementGroupId Scope
                            $roleIsUsed = $true
                            Continue
                        }
                    }

                }
                if ($roleIsUsed -eq $false) {
                    if (($mgSubRoleAssignmentsArrayRoleDefinitionIdUnique) -contains ($customRoleAll.id)) {
                        $roleIsUsed = $true
                    }
                }
                if ($roleIsUsed -eq $false) {
                    if (($rgResRoleAssignmentsArrayRoleDefinitionIdUnique) -contains ($customRoleAll.id)) {
                        $roleIsUsed = $true
                    }
                }

                if ($roleIsUsed -eq $false) {
                    $null = $arrayCustomRolesOrphanedFinalIncludingResourceGroups.Add($customRoleAll)
                }
                
            }
        }

        if (($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0) {
            $tfCount = ($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count
            $htmlTableId = "TenantSummary_customRolesOrphaned"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_customRolesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom Roles ($scopeNamingSummary) <abbr title="Role has no Assignments (including ResourceGroups and Resources) &#13;Roles where assignableScopes contains MG Id from superior scopes are not evaluated"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
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
            $htmlSUMMARYOrphanedCustomRoles = foreach ($inScopeCustomRole in $arrayCustomRolesOrphanedFinalIncludingResourceGroups | Sort-Object @{Expression = { $_.Name } }) {
                @"
<tr>
<td>$($inScopeCustomRole.Name)</td>
<td>$($inScopeCustomRole.id)</td>
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
        }
        else {
            $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom Roles ($scopeNamingSummary)</span></p>
"@
        }
    }
    $endSUMMARYOrphanedCustomRoles = get-date
    Write-Host "   SUMMARYOrphanedCustomRoles duration: $((NEW-TIMESPAN -Start $startSUMMARYOrphanedCustomRoles -End $endSUMMARYOrphanedCustomRoles).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startSUMMARYOrphanedCustomRoles -End $endSUMMARYOrphanedCustomRoles).TotalSeconds) seconds)"

    #endregion SUMMARYOrphanedCustomRoles

    #region SUMMARYOrphanedRoleAssignments
    Write-Host "  processing TenantSummary RoleAssignments orphaned"
    $roleAssignmentsOrphanedAll = ($rbacBaseQueryArrayList.Where( { $_.RoleAssignmentIdentityObjectType -eq "Unknown" })) | Sort-Object -Property RoleAssignmentId
    $roleAssignmentsOrphanedUnique = $roleAssignmentsOrphanedAll | Sort-Object -Property RoleAssignmentId -Unique

    if (($roleAssignmentsOrphanedUnique | measure-object).count -gt 0) {
        $tfCount = ($roleAssignmentsOrphanedUnique | measure-object).count
        $htmlTableId = "TenantSummary_roleAssignmnetsOrphaned"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_roleAssignmnetsOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOrphanedUnique | measure-object).count) Orphaned Role Assignments ($scopeNamingSummary) <abbr title="Role definition was deleted although and assignment existed &#13;OR &#13;Target identity (User, Group, ServicePrincipal) was deleted &#13;OR &#13;Target Resource was moved"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
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
            $impactedMgs = ($roleAssignmentsOrphanedAll | Where-Object { [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.RoleAssignmentId -eq $roleAssignmentOrphanedUnique.RoleAssignmentId } | Sort-Object -Property MgId)
            $impactedSubs = $roleAssignmentsOrphanedAll | Where-Object { -not [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.RoleAssignmentId -eq $roleAssignmentOrphanedUnique.RoleAssignmentId } | Sort-Object -Property SubscriptionId
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOrphanedUnique | measure-object).count) Orphaned Role Assignments ($scopeNamingSummary)</span></p>
"@
    }
    #endregion SUMMARYOrphanedRoleAssignments

    #region SUMMARYRoleAssignmentsAll
    $startRoleAssignmentsAll = get-date
    $roleAssignmentsallCount = ($rbacBaseQuery | Measure-Object).count
    Write-Host "  processing TenantSummary RoleAssignments (all $roleAssignmentsallCount)"
    $roleAssignmentIdsUnique = $rbacBaseQuery | sort-object -Property RoleAssignmentId -Unique

    $startRelatedPolicyAssignmentsAll = get-date
    $htRoleAssignmentRelatedPolicyAssignments = @{ }
    foreach ($roleAssignmentIdUnique in $roleAssignmentIdsUnique) {

        $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId) = @{ }

        if (-not $NoAADServicePrincipalResolve) {
            if ($htManagedIdentityForPolicyAssignment.($roleAssignmentIdUnique.RoleAssignmentIdentityObjectId)) {
                $policyAssignment = $htManagedIdentityForPolicyAssignment.($roleAssignmentIdUnique.RoleAssignmentIdentityObjectId).policyAssignmentId
                $temp0000000000 = ($htCacheAssignments2).policy.($policyAssignment)
                $policyAssignmentId = $temp0000000000.PolicyAssignmentId
                $policyDefinitionId = $temp0000000000.PolicyDefinitionId
                $policyDefinitionIdOnly = $policyDefinitionId -replace '.*/'
                        
                #builtin
                if ($policyDefinitionId -like "/providers/Microsoft.Authorization/policy*") {
                    #policy
                    if ($policyDefinitionId -like "/providers/Microsoft.Authorization/policyDefinitions/*") {
                        #$policyDisplayName = ($htCacheDefinitions).policy.$policyDefinitionId.DisplayName
                        #$LinkOrNotLinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/$($policyDefinitionIdOnly).html`" target=`"_blank`">$($policyDisplayName)</a>"
                        $LinkOrNotLinkToAzAdvertizer = ($htCacheDefinitions).policy.($policyDefinitionId).LinkToAzAdvertizer
                    }
                    #policySet
                    if ($policyDefinitionId -like "/providers/Microsoft.Authorization/policySetDefinitions/*") {
                        #$policyDisplayName = ($htCacheDefinitions).policySet.$policyDefinitionId.DisplayName
                        #$LinkOrNotLinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyinitiativesadvertizer/$($policyDefinitionIdOnly).html`" target=`"_blank`">$($policyDisplayName)</a>"
                        $LinkOrNotLinkToAzAdvertizer = ($htCacheDefinitions).policySet.($policyDefinitionId).LinkToAzAdvertizer
                    }
                }
                else {
                    #policy
                    if ($policyDefinitionId -like "*/providers/Microsoft.Authorization/policyDefinitions/*") {
                        $policyDisplayName = ($htCacheDefinitions).policy.$policyDefinitionId.DisplayName
                                
                    }
                    #policySet
                    if ($policyDefinitionId -like "*/providers/Microsoft.Authorization/policySetDefinitions/*") {
                        $policyDisplayName = ($htCacheDefinitions).policySet.$policyDefinitionId.DisplayName
                                
                    }
                    
                    $LinkOrNotLinkToAzAdvertizer = "<b>$($policyDisplayName)</b>"
                }
                $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).relatedPolicyAssignment = "$($policyAssignmentId) ($LinkOrNotLinkToAzAdvertizer)"
            }
            else {
                $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).relatedPolicyAssignment = "none"
            }
        }
        else {
            $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).relatedPolicyAssignment = "n/a"
        }

        if ($roleAssignmentIdUnique.RoleIsCustom -eq "FALSE") {
            $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).roleType = "Builtin"
            #$htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azrolesadvertizer/$($roleAssignmentIdUnique.RoleDefinitionId).html`" target=`"_blank`">$($roleAssignmentIdUnique.RoleDefinitionName)</a>"
            $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer = ($htCacheDefinitions).role.($roleAssignmentIdUnique.RoleDefinitionId).LinkToAzAdvertizer
        }
        else {
            
            if ($roleAssigned.RoleSecurityCustomRoleOwner -eq 1) {
                $roletype = "<abbr title=`"Custom 'Owner' Role definitions should not exist`"><i class=`"fa fa-exclamation-triangle yellow`" aria-hidden=`"true`"></i></abbr> <a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/10ee2ea2-fb4d-45b8-a7e9-a2e770044cd9.html`" target=`"_blank`">Custom</a>"
            }
            else {
                $roleType = "Custom"
            }
            
            $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).roleType = $roleType
            $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer = $roleAssignmentIdUnique.RoleDefinitionName
        }
    }
    $endRelatedPolicyAssignmentsAll = get-date
    Write-Host "   RelatedPolicyAssignmentsAll duration: $((NEW-TIMESPAN -Start $startRelatedPolicyAssignmentsAll -End $endRelatedPolicyAssignmentsAll).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startRelatedPolicyAssignmentsAll -End $endRelatedPolicyAssignmentsAll).TotalSeconds) seconds)"


    $cnter = 0
    $script:rbacAll = [System.Collections.ArrayList]@()
    $startCreateRBACAll = get-date
    foreach ($rbac in $rbacBaseQuery) {
        $cnter++
        if ($cnter % 500 -eq 0) {
            $etappeRoleAssignmentsAll = get-date
            Write-Host "   $cnter of $roleAssignmentsallCount RoleAssignments processed; $((NEW-TIMESPAN -Start $startRoleAssignmentsAll -End $etappeRoleAssignmentsAll).TotalSeconds) seconds"
        }
        $scope = $null

        if ($rbac.RoleAssignmentId -like "/providers/Microsoft.Management/managementGroups/*") {
            if (-not [String]::IsNullOrEmpty($rbac.SubscriptionId)) {
                $scope = "inherited $($rbac.RoleAssignmentScopeName)"
            }
            else {
                if (($rbac.RoleAssignmentScopeName) -eq $rbac.MgId) {
                    $scope = "thisScope MG"
                }
                else {
                    $scope = "inherited $($rbac.RoleAssignmentScopeName)"
                }
            }
        }

        if ($rbac.RoleAssignmentId -like "/subscriptions/*") {
            $scope = "thisScope Sub"
        }

        if ($rbac.RoleAssignmentId -like "/providers/Microsoft.Authorization/roleAssignments/*") {
            $scope = "inherited ROOT"
        }

        if ([String]::IsNullOrEmpty($rbac.SubscriptionId)) {
            $mgOrSub = "Mg"
        }
        else {
            $mgOrSub = "Sub"
        }

        $objectTypeUserType = ""
        if (-not $NoAADGuestUsers) {
            if ($rbac.RoleAssignmentIdentityObjectType -eq "User") {
                if ($htUserTypes.($rbac.RoleAssignmentIdentityObjectId)) {
                    $objectTypeUserType = "(Guest)"
                }
                else {
                    $objectTypeUserType = "(Member)"
                }
            }
        }

        $hlpRoleDataRelated = ($htCacheDefinitions).role.($rbac.RoleDefinitionId)
        if (-not [string]::IsNullOrEmpty($hlpRoleDataRelated.DataActions) -or -not [string]::IsNullOrEmpty($hlpRoleDataRelated.NotDataActions)) {
            $roleManageData = "true"
        }
        else {
            $roleManageData = "false"
        }

        if (-not $NoAADGroupsResolveMembers) {
            if ($rbac.RoleAssignmentIdentityObjectType -eq "Group") {
                if ($htAADGroupsDetails.($rbac.RoleAssignmentIdentityObjectId).MembersAllCount -gt 0) {
                    
                    $null = $script:rbacAll.Add([PSCustomObject]@{ 
                            Level                         = $rbac.Level
                            RoleAssignmentId              = $rbac.RoleAssignmentId
                            MgId                          = $rbac.MgId
                            MgName                        = $rbac.MgName
                            SubscriptionId                = $rbac.SubscriptionId
                            SubscriptionName              = $rbac.Subscription
                            Scope                         = $scope
                            Role                          = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer 
                            RoleId                        = $rbac.RoleDefinitionId
                            RoleType                      = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleType
                            RoleDataRelated               = $roleManageData
                            AssignmentType                = "direct"
                            AssignmentInheritFrom         = "n/a"
                            ObjectDisplayName             = $rbac.RoleAssignmentIdentityDisplayname
                            ObjectSignInName              = $rbac.RoleAssignmentIdentitySignInName
                            ObjectId                      = $rbac.RoleAssignmentIdentityObjectId
                            ObjectType                    = "$($rbac.RoleAssignmentIdentityObjectType) $objectTypeUserType"
                            MgOrSub                       = $mgOrSub
                            RbacRelatedPolicyAssignment   = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).relatedPolicyAssignment
                            RoleSecurityCustomRoleOwner   = $rbac.RoleSecurityCustomRoleOwner
                            RoleSecurityOwnerAssignmentSP = $rbac.RoleSecurityOwnerAssignmentSP 
                        })

                    foreach ($groupmember in $htAADGroupsDetails.($rbac.RoleAssignmentIdentityObjectId).MembersAll) {
                        if ($groupmember.'@odata.type' -eq "#microsoft.graph.user") {
                            if ($htParameters.DoNotShowRoleAssignmentsUserData -eq $true) {
                                $grpMemberDisplayName = "scrubbed"
                                $grpMemberSignInName = "scrubbed"
                            }
                            else {
                                $grpMemberDisplayName = $groupmember.displayName
                                $grpMemberSignInName = $groupmember.userPrincipalName
                            }
                            $grpMemberId = $groupmember.id
                            $grpMemberType = "User"
                            $grpMemberUserType = ""
                            if (-not $NoAADGuestUsers) {
                                if ($htUserTypes.($grpMemberId)) {
                                    $grpMemberUserType = "(Guest)"
                                }
                                else {
                                    $grpMemberUserType = "(Member)"
                                }
                            }
                        }
                        if ($groupmember.'@odata.type' -eq "#microsoft.graph.group") {
                            $grpMemberDisplayName = $groupmember.displayName
                            $grpMemberSignInName = "n/a"
                            $grpMemberId = $groupmember.id
                            $grpMemberType = "Group"
                            $grpMemberUserType = ""
                        }
                        if ($groupmember.'@odata.type' -eq "#microsoft.graph.servicePrincipal") {
                            $grpMemberDisplayName = $groupmember.appDisplayName
                            $grpMemberSignInName = "n/a"
                            $grpMemberId = $groupmember.id
                            $grpMemberType = "ServicePrincipal"
                            $grpMemberUserType = ""
                        }

                        if (-not $NoAADServicePrincipalResolve) {
                            if ($grpMemberType -eq "ServicePrincipal") {
                                $identityType = "$($grpMemberType) ($($htServicePrincipalsDetails.($grpMemberId).servicePrincipalType))"
                            }
                            else {
                                $identityType = $grpMemberType
                            }
                        }
                        else {
                            $identityType = $grpMemberType
                        }

                        $null = $script:rbacAll.Add([PSCustomObject]@{ 
                                Level                         = $rbac.Level
                                RoleAssignmentId              = $rbac.RoleAssignmentId
                                MgId                          = $rbac.MgId
                                MgName                        = $rbac.MgName
                                SubscriptionId                = $rbac.SubscriptionId
                                SubscriptionName              = $rbac.Subscription
                                Scope                         = $scope
                                Role                          = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer 
                                RoleId                        = $rbac.RoleDefinitionId
                                RoleType                      = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleType
                                RoleDataRelated               = $roleManageData
                                AssignmentType                = "indirect"
                                AssignmentInheritFrom         = "$($rbac.RoleAssignmentIdentityDisplayname) ($($rbac.RoleAssignmentIdentityObjectId))"
                                ObjectDisplayName             = $grpMemberDisplayName
                                ObjectSignInName              = $grpMemberSignInName
                                ObjectId                      = $grpMemberId
                                ObjectType                    = "$identityType $grpMemberUserType"
                                MgOrSub                       = $mgOrSub
                                RbacRelatedPolicyAssignment   = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).relatedPolicyAssignment
                                RoleSecurityCustomRoleOwner   = $rbac.RoleSecurityCustomRoleOwner
                                RoleSecurityOwnerAssignmentSP = $rbac.RoleSecurityOwnerAssignmentSP 
                            })
                    }
                }
                else {

                    if (-not $NoAADServicePrincipalResolve) {
                        if ($rbac.RoleAssignmentIdentityObjectType -eq "ServicePrincipal") {
                            $identityType = "$($rbac.RoleAssignmentIdentityObjectType) ($($htServicePrincipalsDetails.($rbac.RoleAssignmentIdentityObjectId).servicePrincipalType))"
                        }
                        else {
                            $identityType = $rbac.RoleAssignmentIdentityObjectType
                        }
                    }
                    else {
                        $identityType = $rbac.RoleAssignmentIdentityObjectType
                    }

                    $null = $script:rbacAll.Add([PSCustomObject]@{ 
                            Level                         = $rbac.Level
                            RoleAssignmentId              = $rbac.RoleAssignmentId
                            MgId                          = $rbac.MgId
                            MgName                        = $rbac.MgName
                            SubscriptionId                = $rbac.SubscriptionId
                            SubscriptionName              = $rbac.Subscription
                            Scope                         = $scope
                            Role                          = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer 
                            RoleId                        = $rbac.RoleDefinitionId
                            RoleType                      = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleType
                            RoleDataRelated               = $roleManageData
                            AssignmentType                = "direct"
                            AssignmentInheritFrom         = "n/a"
                            ObjectDisplayName             = $rbac.RoleAssignmentIdentityDisplayname
                            ObjectSignInName              = $rbac.RoleAssignmentIdentitySignInName
                            ObjectId                      = $rbac.RoleAssignmentIdentityObjectId
                            ObjectType                    = "$identityType $objectTypeUserType"
                            MgOrSub                       = $mgOrSub
                            RbacRelatedPolicyAssignment   = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).relatedPolicyAssignment
                            RoleSecurityCustomRoleOwner   = $rbac.RoleSecurityCustomRoleOwner
                            RoleSecurityOwnerAssignmentSP = $rbac.RoleSecurityOwnerAssignmentSP 
                        })
                }
            }
            else {

                if (-not $NoAADServicePrincipalResolve) {
                    if ($rbac.RoleAssignmentIdentityObjectType -eq "ServicePrincipal") {
                        $identityType = "$($rbac.RoleAssignmentIdentityObjectType) ($($htServicePrincipalsDetails.($rbac.RoleAssignmentIdentityObjectId).servicePrincipalType))"
                    }
                    else {
                        $identityType = $rbac.RoleAssignmentIdentityObjectType
                    }
                }
                else {
                    $identityType = $rbac.RoleAssignmentIdentityObjectType
                }
                
                $null = $script:rbacAll.Add([PSCustomObject]@{ 
                        Level                         = $rbac.Level
                        RoleAssignmentId              = $rbac.RoleAssignmentId
                        MgId                          = $rbac.MgId
                        MgName                        = $rbac.MgName
                        SubscriptionId                = $rbac.SubscriptionId
                        SubscriptionName              = $rbac.Subscription
                        Scope                         = $scope
                        Role                          = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer 
                        RoleId                        = $rbac.RoleDefinitionId
                        RoleType                      = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleType
                        RoleDataRelated               = $roleManageData
                        AssignmentType                = "direct"
                        AssignmentInheritFrom         = "n/a"
                        ObjectDisplayName             = $rbac.RoleAssignmentIdentityDisplayname
                        ObjectSignInName              = $rbac.RoleAssignmentIdentitySignInName
                        ObjectId                      = $rbac.RoleAssignmentIdentityObjectId
                        ObjectType                    = "$identityType $objectTypeUserType"
                        MgOrSub                       = $mgOrSub
                        RbacRelatedPolicyAssignment   = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).relatedPolicyAssignment
                        RoleSecurityCustomRoleOwner   = $rbac.RoleSecurityCustomRoleOwner
                        RoleSecurityOwnerAssignmentSP = $rbac.RoleSecurityOwnerAssignmentSP 
                    })
            }
        }
        else {
            if (-not $NoAADServicePrincipalResolve) {
                if ($rbac.RoleAssignmentIdentityObjectType -eq "ServicePrincipal") {
                    $identityType = "$($rbac.RoleAssignmentIdentityObjectType) ($($htServicePrincipalsDetails.($rbac.RoleAssignmentIdentityObjectId).servicePrincipalType))"
                }
                else {
                    $identityType = $rbac.RoleAssignmentIdentityObjectType
                }
            }
            else {
                $identityType = $rbac.RoleAssignmentIdentityObjectType
            }

            #noaadgroupmemberresolve
            $null = $script:rbacAll.Add([PSCustomObject]@{ 
                    Level                         = $rbac.Level
                    RoleAssignmentId              = $rbac.RoleAssignmentId
                    MgId                          = $rbac.MgId
                    MgName                        = $rbac.MgName
                    SubscriptionId                = $rbac.SubscriptionId
                    SubscriptionName              = $rbac.Subscription
                    Scope                         = $scope
                    Role                          = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer 
                    RoleId                        = $rbac.RoleDefinitionId
                    RoleType                      = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleType
                    RoleDataRelated               = $roleManageData
                    AssignmentType                = "direct"
                    AssignmentInheritFrom         = "n/a"
                    ObjectDisplayName             = $rbac.RoleAssignmentIdentityDisplayname
                    ObjectSignInName              = $rbac.RoleAssignmentIdentitySignInName
                    ObjectId                      = $rbac.RoleAssignmentIdentityObjectId
                    ObjectType                    = "$identityType $objectTypeUserType"
                    MgOrSub                       = $mgOrSub
                    RbacRelatedPolicyAssignment   = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).relatedPolicyAssignment
                    RoleSecurityCustomRoleOwner   = $rbac.RoleSecurityCustomRoleOwner
                    RoleSecurityOwnerAssignmentSP = $rbac.RoleSecurityOwnerAssignmentSP 
                })
        }
    }

    $script:rbacAllGroupedBySubscription = $rbacAll | Group-Object -Property SubscriptionId
    $script:rbacAllGroupedByManagementGroup = $rbacAll | Group-Object -Property MgId

    $endCreateRBACAll = get-date
    Write-Host "   CreateRBACAll duration: $((NEW-TIMESPAN -Start $startCreateRBACAll -End $endCreateRBACAll).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startCreateRBACAll -End $endCreateRBACAll).TotalSeconds) seconds)"


    if (($rbacAll | measure-object).count -gt 0) {
        $uniqueRoleAssignmentsCount = ($rbacAll | sort-object -Property RoleAssignmentId -Unique | Measure-Object).count
        $tfCount = ($rbacAll | measure-object).count
        $htmlTableId = "TenantSummary_roleAssignmentsAll"
        if (-not $NoAADServicePrincipalResolve) {
            $noteOrNot = ""
        }
        else {
            $noteOrNot = "<abbr title=`"Note: will show 'n/a' if parameter -NoAADServicePrincipalResolve was used`"><i class=`"fa fa-question-circle`" aria-hidden=`"true`"></i></abbr>"
        }

        if ($tfCount -gt $TFCriticalRowsCount) {
            $htmlTenantSummary += @"
            <button type="button" class="collapsible" id="buttonTenantSummary_roleAssignmentsAll_largeDataSet"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($rbacAll | measure-object).count) Role Assignments ($uniqueRoleAssignmentsCount unique)</span>
            </button>
            <div class="content">
            <i  class="fa fa-exclamation-triangle orange paddingleft10" aria-hidden="true"></i><span style="color:#ff0000"> Lots of data here!</span> <span>You might be better off downloading the CSV..</span><br>
            <i  class="fa fa-table paddingleft10" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a><br>
            <button onclick="loadtf$htmlTableId()" type="button" class="collapsible paddingleft10" id="buttonTenantSummary_roleAssignmentsAll"><i class="fa fa-check" aria-hidden="true" style="color: #67C409"></i> <span class="valignMiddle"><b>Understood!</b> Go for it anyway..</span>
            </button>
            <div class="content">
"@            
        }

        if ($tfCount -le $TFCriticalRowsCount) {
            $htmlTenantSummary += @"
<button onclick="loadtf$htmlTableId()" type="button" class="collapsible" id="buttonTenantSummary_roleAssignmentsAll"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($rbacAll | measure-object).count) Role Assignments ($uniqueRoleAssignmentsCount unique)</span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a><br>
&nbsp;&nbsp;<span style="color:#FF5733">*Depending on the number of rows and your computer´s performance the table may respond with delay, download the csv for better filtering experience</span> 
"@
        }
        $htmlTenantSummary += @"
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Mg/Sub</th>
<th>Management Group Id</th>
<th>Management Group Name</th>
<th>SubscriptionId</th>
<th>Subscription Name</th>
<th>Assignment Scope</th>
<th>Role</th>
<th>Role Id</th>
<th>Role Type</th>
<th>Data</th>
<th>Identity Displayname</th>
<th>Identity SignInName</th>
<th>Identity ObjectId</th>
<th>Identity Type</th>
<th>Applicability</th>
<th>Applies through membership <abbr title="Note: the identity might not be a direct member of the group it could also be member of a nested group"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></th>
<th>Role AssignmentId</th>
<th>Related Policy Assignment $noteOrNot</th>
</tr>
</thead>
<tbody>
"@
        $cnter = 0
        $roleAssignmentsAllCount = ($rbacAll | Measure-Object).count
        $htmlSummaryRoleAssignmentsAll = ""
        $htmlTenantSummary | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
        $htmlTenantSummary = ""

        if ($CsvExport) {
            if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
                $csvFilename = "AzGovViz_$($ManagementGroupIdCaseSensitived)_$($htmlTableId)"
            }
            else {
                $csvFilename = "AzGovViz_$($fileTimestamp)_$($ManagementGroupIdCaseSensitived)_$($htmlTableId)"
            }
            if ($CsvExportUseQuotesAsNeeded) {
                $rbacAll | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter "$csvDelimiter" -NoTypeInformation -UseQuotes AsNeeded
            }
            else {
                $rbacAll | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($csvFilename).csv" -Delimiter "$csvDelimiter" -NoTypeInformation
            }
        }

        $htmlSummaryRoleAssignmentsAll = foreach ($roleAssignment in $rbacAll | sort-object -Property Level, MgName, MgId, SubscriptionName, SubscriptionId, Scope, Role, ObjectDisplayName, RoleAssignmentId) {
            $cnter++
            @"
<tr>
<td>$($roleAssignment.MgOrSub)</td>
<td>$($roleAssignment.MgId)</td>
<td>$($roleAssignment.MgName)</td>
<td>$($roleAssignment.SubscriptionId)</td>
<td>$($roleAssignment.SubscriptionName)</td>
<td>$($roleAssignment.Scope)</td>
<td>$($roleAssignment.Role)</td>
<td>$($roleAssignment.RoleId)</td>
<td>$($roleAssignment.RoleType)</td>
<td>$($roleAssignment.RoleDataRelated)</td>
<td class="breakwordall">$($roleAssignment.ObjectDisplayName)</td>
<td class="breakwordall">$($roleAssignment.ObjectSignInName)</td>
<td class="breakwordall">$($roleAssignment.ObjectId)</td>
<td>$($roleAssignment.ObjectType)</td>
<td>$($roleAssignment.AssignmentType)</td>
<td>$($roleAssignment.AssignmentInheritFrom)</td>
<td class="breakwordall">$($roleAssignment.RoleAssignmentId)</td>
<td class="breakwordall">$($roleAssignment.rbacRelatedPolicyAssignment)</td>
</tr>
"@

        }
        $start = get-date
        $htmlTenantSummary += $htmlSummaryRoleAssignmentsAll
        $htmlTenantSummary | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
        $htmlTenantSummary = ""
        $end = get-date
        Write-Host "   append file duration: $((NEW-TIMESPAN -Start $start -End $end).TotalSeconds) seconds"
        $htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
"@
        if ($tfCount -gt $TFCriticalRowsCount) {
            $htmlTenantSummary += @"
</div>
"@            
        }
        $htmlTenantSummary += @"
    <script>
        function loadtf$htmlTableId() { if (window.helpertfConfig4$htmlTableId !== 1) { 
        window.helpertfConfig4$htmlTableId =1;
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            $htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@    
        }
        $htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
            col_8: 'select',
            col_9: 'select',
            col_13: 'multiple',
            col_14: 'select',
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
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
            watermark: ['', '', '', 'try [nonempty]', '', 'thisScope', 'try owner||reader', '', '', '', '', '', '', '', '', ''],
            extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();}}
    </script>
"@
        
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($rbacAll | measure-object).count) Role Assignments</span></p>
"@
    }
    $endRoleAssignmentsAll = get-date
    Write-Host "   SummaryRoleAssignmentsAll duration: $((NEW-TIMESPAN -Start $startRoleAssignmentsAll -End $endRoleAssignmentsAll).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startRoleAssignmentsAll -End $endRoleAssignmentsAll).TotalSeconds) seconds)"
    #endregion SUMMARYRoleAssignmentsAll

    #region SUMMARYSecurityCustomRoles
    Write-Host "  processing TenantSummary Custom Roles security (owner permissions)"
    $customRolesOwnerAll = ($rbacBaseQueryArrayList.Where( { $_.RoleSecurityCustomRoleOwner -eq 1 })) | Sort-Object -Property RoleDefinitionId
    $customRolesOwnerHtAll = $tenantCustomRolesArray.Where( { $_.Actions -eq '*' -and ($_.NotActions).length -eq 0 })
    if (($customRolesOwnerHtAll | measure-object).count -gt 0) {
        $tfCount = ($customRolesOwnerHtAll | measure-object).count
        $htmlTableId = "TenantSummary_CustomRoleOwner"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_CustomRoleOwner"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($customRolesOwnerHtAll | measure-object).count) Custom Roles Owner permissions ($scopeNamingSummary) <abbr title="Custom 'Owner' Role definitions should not exist"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
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
            $customRoleOwnersAllAssignmentsCount = ((($customRolesOwnerAll | Where-Object { $_.RoleDefinitionId -eq $customRole.id }).RoleAssignmentId | Sort-Object -Unique) | measure-object).count
            if ($customRoleOwnersAllAssignmentsCount -gt 0) {
                $customRoleRoleAssignmentsArray = [System.Collections.ArrayList]@()
                $customRoleRoleAssignmentIds = ($customRolesOwnerAll | Where-Object { $_.RoleDefinitionId -eq $customRole.id }).RoleAssignmentId | Sort-Object -Unique
                foreach ($customRoleRoleAssignmentId in $customRoleRoleAssignmentIds) {
                    $null = $customRoleRoleAssignmentsArray.Add($customRoleRoleAssignmentId)
                }
                $customRoleRoleAssignmentsOutput = "$customRoleOwnersAllAssignmentsCount ($($customRoleRoleAssignmentsArray -join "$CsvDelimiterOpposite "))"
            }
            else {
                $customRoleRoleAssignmentsOutput = "$customRoleOwnersAllAssignmentsCount"
            }
            $htmlSUMMARYSecurityCustomRoles += @"
<tr>
<td>$($customRole.Name)</td>
<td>$($customRole.id)</td>
<td>$($customRoleRoleAssignmentsOutput)</td>
<td>$(($customRole.AssignableScopes | Measure-Object).count) ($($customRole.AssignableScopes -join "$CsvDelimiterOpposite "))</td>
</tr>
"@ 
        }
        $htmlTenantSummary += $htmlSUMMARYSecurityCustomRoles
        $htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($customRolesOwnerHtAll | measure-object).count) Custom Roles Owner permissions ($scopeNamingSummary)</span></p>
"@
    }
    #endregion SUMMARYSecurityCustomRoles

    #region SUMMARYSecurityOwnerAssignmentSP
    Write-Host "  processing TenantSummary RoleAssignments security (owner SP)"
    $roleAssignmentsOwnerAssignmentSPAll = ($rbacBaseQueryArrayList.Where( { $_.RoleSecurityOwnerAssignmentSP -eq 1 })) | Sort-Object -Property RoleAssignmentId
    $roleAssignmentsOwnerAssignmentSP = $roleAssignmentsOwnerAssignmentSPAll | sort-object -Property RoleAssignmentId -Unique
    if (($roleAssignmentsOwnerAssignmentSP | measure-object).count -gt 0) {
        $tfCount = ($roleAssignmentsOwnerAssignmentSP | measure-object).count
        $htmlTableId = "TenantSummary_roleAssignmentsOwnerAssignmentSP"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_roleAssignmentsOwnerAssignmentSP"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentSP | measure-object).count) Owner permission assignments to ServicePrincipal ($scopeNamingSummary) <abbr title="Owner permissions on Service Principals should be treated exceptional"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYSecurityOwnerAssignmentSP = foreach ($roleAssignmentOwnerAssignmentSP in ($roleAssignmentsOwnerAssignmentSP)) {
            $impactedMgs = $roleAssignmentsOwnerAssignmentSPAll | Where-Object { [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentSP.RoleAssignmentId }
            $impactedSubs = $roleAssignmentsOwnerAssignmentSPAll | Where-Object { -not [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentSP.RoleAssignmentId }
            $servicePrincipal = ($roleAssignmentsOwnerAssignmentSP | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentSP.RoleAssignmentId }) | Get-Unique
            @"
<tr>
<td>$($roleAssignmentOwnerAssignmentSP.RoleDefinitionName)</td>
<td>$($roleAssignmentOwnerAssignmentSP.RoleDefinitionId)</td>
<td>$($roleAssignmentOwnerAssignmentSP.RoleAssignmentId)</td>
<td>$($servicePrincipal.RoleAssignmentIdentityDisplayname) ($($servicePrincipal.RoleAssignmentIdentityObjectId))</td>
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentSP | measure-object).count) Owner permission assignments to ServicePrincipal ($scopeNamingSummary)</span></p>
"@
    }
    #endregion SUMMARYSecurityOwnerAssignmentSP

    #region SUMMARYSecurityOwnerAssignmentNotGroup
    Write-Host "  processing TenantSummary RoleAssignments security (owner notGroup)"
    $startSUMMARYSecurityOwnerAssignmentNotGroup = get-date
    #$roleAssignmentsOwnerAssignmentNotGroupAll = ($rbacBaseQueryArrayList.Where( { $_.RoleDefinitionName -eq "Owner" -and $_.RoleAssignmentIdentityObjectType -ne "Group" }) | Sort-Object -Property RoleAssignmentId)
    $roleAssignmentsOwnerAssignmentNotGroup = $rbacBaseQueryArrayListNotGroupOwner | sort-object -Property RoleAssignmentId -Unique

    if (($roleAssignmentsOwnerAssignmentNotGroup | measure-object).count -gt 0) {
        $tfCount = ($roleAssignmentsOwnerAssignmentNotGroup | measure-object).count
        $htmlTableId = "TenantSummary_roleAssignmentsOwnerAssignmentNotGroup"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_roleAssignmentsOwnerAssignmentNotGroup"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentNotGroup | measure-object).count) Owner permission assignments to notGroup ($scopeNamingSummary)</span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYSecurityOwnerAssignmentNotGroup = foreach ($roleAssignmentOwnerAssignmentNotGroup in ($roleAssignmentsOwnerAssignmentNotGroup)) {
            $impactedMgSubBaseQuery = $rbacBaseQueryArrayListNotGroupOwner | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentId }
            $impactedMgs = $impactedMgSubBaseQuery | Where-Object { [String]::IsNullOrEmpty($_.SubscriptionId) }
            $impactedSubs = $impactedMgSubBaseQuery | Where-Object { -not [String]::IsNullOrEmpty($_.SubscriptionId) }
            #$servicePrincipal = ($roleAssignmentsOwnerAssignmentNotGroup | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentId }) | Get-Unique
            @"
<tr>
<td>$($roleAssignmentOwnerAssignmentNotGroup.RoleDefinitionName)</td>
<td>$($roleAssignmentOwnerAssignmentNotGroup.RoleDefinitionId)</td>
<td class="breakwordall">$($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentId)</td>
<td>$($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentIdentityObjectType)</td>
<td>$($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentIdentityDisplayname)</td>
<td class="breakwordall">$($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentIdentitySignInName)</td>
<td class="breakwordall">$($roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentIdentityObjectId)</td>
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }

            $htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@   
        }
        $htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_3: 'multiple',
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentNotGroup | measure-object).count) Owner permission assignments to notGroup ($scopeNamingSummary)</span></p>
"@
    }
    $endSUMMARYSecurityOwnerAssignmentNotGroup = get-date
    Write-Host "   TenantSummary RoleAssignments security (owner notGroup) duration: $((NEW-TIMESPAN -Start $startSUMMARYSecurityOwnerAssignmentNotGroup -End $endSUMMARYSecurityOwnerAssignmentNotGroup).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startSUMMARYSecurityOwnerAssignmentNotGroup -End $endSUMMARYSecurityOwnerAssignmentNotGroup).TotalSeconds) seconds)"
    #endregion SUMMARYSecurityOwnerAssignmentNotGroup

    #region SUMMARYSecurityUserAccessAdministratorAssignmentNotGroup
    $startSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup = get-date
    Write-Host "  processing TenantSummary RoleAssignments security (userAccessAdministrator notGroup)"
    #$roleAssignmentsUserAccessAdministratorAssignmentNotGroupAll = ($rbacBaseQueryArrayList.Where( { $_.RoleDefinitionName -eq "User Access Administrator" -and $_.RoleAssignmentIdentityObjectType -ne "Group" }) | Sort-Object -Property RoleAssignmentId)
    $roleAssignmentsUserAccessAdministratorAssignmentNotGroup = $rbacBaseQueryArrayListNotGroupUserAccessAdministrator | sort-object -Property RoleAssignmentId -Unique

    if (($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | measure-object).count -gt 0) {
        $tfCount = ($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | measure-object).count
        $htmlTableId = "TenantSummary_roleAssignmentsUserAccessAdministratorAssignmentNotGroup"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_roleAssignmentsUserAccessAdministratorAssignmentNotGroup"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | measure-object).count) UserAccessAdministrator permission assignments to notGroup ($scopeNamingSummary)</span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup = foreach ($roleAssignmentUserAccessAdministratorAssignmentNotGroup in ($roleAssignmentsUserAccessAdministratorAssignmentNotGroup)) {
            $impactedMgSubBaseQuery = $rbacBaseQueryArrayListNotGroupUserAccessAdministrator | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId }
            #$impactedMgs = $impactedMgSubBaseQuery | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId }
            #$impactedSubs = $impactedMgSubBaseQuery | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId }
            $impactedMgs = $impactedMgSubBaseQuery | Where-Object { [String]::IsNullOrEmpty($_.SubscriptionId) }
            $impactedSubs = $impactedMgSubBaseQuery | Where-Object { -not [String]::IsNullOrEmpty($_.SubscriptionId) }
            #$servicePrincipal = ($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId }) | Get-Unique
            @"
<tr>
<td>$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleDefinitionName)</td>
<td>$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleDefinitionId)</td>
<td class="breakwordall">$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId)</td>
<td>$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentIdentityObjectType)</td>
<td>$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentIdentityDisplayname)</td>
<td class="breakwordall">$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentIdentitySignInName)</td>
<td class="breakwordall">$($roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentIdentityObjectId)</td>
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            $htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@    
        }
        $htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_3: 'multiple',
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | measure-object).count) UserAccessAdministrator permission assignments to notGroup ($scopeNamingSummary)</span></p>
"@
    }
    $endSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup = get-date
    Write-Host "   TenantSummary RoleAssignments security (userAccessAdministrator notGroup) duration: $((NEW-TIMESPAN -Start $startSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup -End $endSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup -End $endSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup).TotalSeconds) seconds)"
    #endregion SUMMARYSecurityUserAccessAdministratorAssignmentNotGroup

    $htmlTenantSummary += @"
    </div>
"@
    #endregion tenantSummaryRBAC

    #region tenantSummaryBlueprints
    $htmlTenantSummary += @"
<button type="button" class="collapsible" id="tenantSummaryBlueprints"><hr class="hr-text" data-content="Blueprints" /></button>
<div class="content">
"@

    #region SUMMARYBlueprintDefinitions
    Write-Host "  processing TenantSummary Blueprints"
    $blueprintDefinitions = ($blueprintBaseQuery | Where-Object { [String]::IsNullOrEmpty($_.BlueprintAssignmentId) })
    $blueprintDefinitionsCount = ($blueprintDefinitions | measure-object).count
    if ($blueprintDefinitionsCount -gt 0) {
        $htmlTableId = "TenantSummary_BlueprintDefinitions"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_BlueprintDefinitions"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintDefinitionsCount Blueprints</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYBlueprintDefinitions = foreach ($blueprintDefinition in $blueprintDefinitions) {
            @"
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
            var tfConfig4$htmlTableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
            var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
            tf.init();
        </script>
"@
    }
    else {
        $htmlTenantSummary += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $blueprintDefinitionsCount Blueprints</p>
"@
    }
    #endregion SUMMARYBlueprintDefinitions

    #region SUMMARYBlueprintAssignments
    Write-Host "  processing TenantSummary BlueprintAssignments"
    $blueprintAssignments = ($blueprintBaseQuery | Where-Object { -not [String]::IsNullOrEmpty($_.BlueprintAssignmentId) })
    $blueprintAssignmentsCount = ($blueprintAssignments | measure-object).count

    if ($blueprintAssignmentsCount -gt 0) {
        $htmlTableId = "TenantSummary_BlueprintAssignments"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_BlueprintAssignments"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintAssignmentsCount Blueprint Assignments</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYBlueprintAssignments = foreach ($blueprintAssignment in $blueprintAssignments) {
            @"
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
            var tfConfig4$htmlTableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
            var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
            tf.init();
        </script>
"@
    }
    else {
        $htmlTenantSummary += @"
                    <p><i class="fa fa-ban" aria-hidden="true"></i> $blueprintAssignmentsCount Blueprint Assignments</p>
"@
    }
    #endregion SUMMARYBlueprintAssignments

    #region SUMMARYBlueprintsOrphaned
    Write-Host "  processing TenantSummary Blueprints orphaned"
    $blueprintDefinitionsOrphanedArray = @()
    if ($blueprintDefinitionsCount -gt 0) {
        if ($blueprintAssignmentsCount -gt 0) {
            $blueprintDefinitionsOrphanedArray += foreach ($blueprintDefinition in $blueprintDefinitions) {
                if (($blueprintAssignments.BlueprintId) -notcontains ($blueprintDefinition.BlueprintId)) {
                    $blueprintDefinition
                }
            }
        }
        else {
            $blueprintDefinitionsOrphanedArray += foreach ($blueprintDefinition in $blueprintDefinitions) {
                $blueprintDefinition
            }
        }
    }
    $blueprintDefinitionsOrphanedCount = ($blueprintDefinitionsOrphanedArray | Measure-Object).count

    if ($blueprintDefinitionsOrphanedCount -gt 0) {

        $htmlTableId = "TenantSummary_BlueprintsOrphaned"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_BlueprintsOrphaned"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintDefinitionsOrphanedCount Orphaned Blueprints</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYBlueprintsOrphaned = foreach ($blueprintDefinition in $blueprintDefinitionsOrphanedArray) {
            @"
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
                <p><i class="fa fa-ban" aria-hidden="true"></i> $blueprintDefinitionsOrphanedCount Orphaned Blueprints</p>
"@
    }
    #endregion SUMMARYBlueprintsOrphaned

    $htmlTenantSummary += @"
    </div>
"@
    #endregion tenantSummaryBlueprints

    #region tenantSummaryManagementGroups
    $htmlTenantSummary += @"
<button type="button" class="collapsible" id="tenantSummaryManagementGroups"><hr class="hr-text" data-content="Management Groups & Limits" /></button>
<div class="content">
"@

    #region SUMMARYMGs
    Write-Host "  processing TenantSummary ManagementGroups"
        
    $summaryManagementGroups = $optimizedTableForPathQueryMg | Sort-Object -Property Level, mgid, mgParentId
    $summaryManagementGroupsCount = ($summaryManagementGroups | Measure-Object).Count
    if ($summaryManagementGroupsCount -gt 0) {
        $tfCount = $summaryManagementGroupsCount
        $htmlTableId = "TenantSummary_ManagementGroups"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_Subs"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> <span class="valignMiddle">$($summaryManagementGroupsCount) Management Groups</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Level</th>
<th>ManagementGroup</th>
<th>ManagementGroup Id</th>
<th>Mg children (total)</th>
<th>Mg children (direct)</th>
<th>Sub children (total)</th>
<th>Sub children (direct)</th>
"@
        if ($htParameters.NoAzureConsumption -eq $false) {
            $htmlTenantSummary += @"
<th>Cost ($($AzureConsumptionPeriod)d)</th>
"@
        }
        $htmlTenantSummary += @"
<th>Path</th>
</tr>
</thead>
<tbody>
"@
        $htmlSUMMARYManagementGroups = $null
        $htmlSUMMARYManagementGroups = foreach ($summaryManagementGroup in $summaryManagementGroups) {
            $mgPath = $htAllMgsPath.($summaryManagementGroup.mgId).path -join "/"

            if ($summaryManagementGroup.mgid -eq $mgSubPathTopMg -and ($checkContext).Tenant.id -ne $ManagementGroupId) {
                $pathhlper = "$($mgPath)"
                $arrayTotalCostSummary = "n/a"
                $mgAllChildMgsCountTotal = "n/a"
                $mgAllChildMgsCountDirect = "n/a"
                $mgAllChildSubscriptionsCountTotal = "n/a"
                $mgAllChildSubscriptionsCountDirect = "n/a"
            }
            else {
                if ($htParameters.NoAzureConsumption -eq $false) {
                    if ($allConsumptionDataCount -gt 0) {
            
                        $consumptionData = $allConsumptionData | Where-Object { $_.SubscriptionMgPath -contains $summaryManagementGroup.mgid }
                        if (($consumptionData | Measure-Object).Count -gt 0) {
                            $arrayTotalCostSummary = @()
                            $arrayConsumptionData = [System.Collections.ArrayList]@()
                            $consumptionDataGroupedByCurrency = $consumptionData | group-object -property Currency
                            foreach ($currency in $consumptionDataGroupedByCurrency) {
                                $totalCost = 0
                                $tenantSummaryConsumptionDataGrouped = $currency.group | group-object -property ConsumedService, ChargeType, MeterCategory
                                $subsCount = ($tenantSummaryConsumptionDataGrouped.group.subscriptionId | Sort-Object -Unique | Measure-Object).Count
                                $consumedServiceCount = ($tenantSummaryConsumptionDataGrouped.group.consumedService | Sort-Object -Unique | Measure-Object).Count
                                $resourceCount = ($tenantSummaryConsumptionDataGrouped.group.ResourceId | Sort-Object -Unique | Measure-Object).Count
                                foreach ($consumptionline in $tenantSummaryConsumptionDataGrouped) {
                        
                                    $costConsumptionLine = ($consumptionline.group.PreTaxCost | Measure-Object -Sum).Sum                            
                                    $totalCost = $totalCost + $costConsumptionLine
                                }
                                if ([math]::Round($totalCost, 4) -eq 0) {
                                    $totalCost = $totalCost
                                }
                                else {
                                    $totalCost = [math]::Round($totalCost, 4)
                                }
                                $arrayTotalCostSummary += "$([decimal]$totalCost) $($currency.Name) generated by $($resourceCount) Resources ($($consumedServiceCount) ResourceTypes) in $($subsCount) Subscriptions"
                            }
                        }
                        else {
                            $arrayTotalCostSummary = "no consumption data available"
                        }
                    }
                    else {
                        $arrayTotalCostSummary = "no consumption data available"
                    }
                }
                $pathhlper = "<a href=`"#hierarchy_$($summaryManagementGroup.mgId)`"><i class=`"fa fa-eye`" aria-hidden=`"true`"></i></a> $($mgPath)"
                    
                #childrenMgInfo
                #
                $mgAllChildMgs = [System.Collections.ArrayList]@()
                $mgAllChildMgs = foreach ($entry in $htAllMgsPath.keys) {
                    if (($htAllMgsPath.($entry).path) -contains "'$($summaryManagementGroup.mgid)'") {
                        $entry
                    }
                }
                $mgAllChildMgsCountTotal = (($mgAllChildMgs | Measure-Object).Count - 1)
                $mgAllChildMgsCountDirect = ($optimizedTableForPathQueryMg | Where-Object { $_.mgParentId -eq $summaryManagementGroup.mgid } | Measure-Object).Count
                    
                    
                #
                $mgAllChildSubscriptions = [System.Collections.ArrayList]@()
                $mgAllChildSubscriptions = foreach ($entry in $htAllSubsMgPath.keys) {
                    if (($htAllSubsMgPath.($entry).path) -contains "'$($summaryManagementGroup.mgid)'") {
                        $entry
                    }
                }
                $mgAllChildSubscriptionsCountTotal = (($mgAllChildSubscriptions | Measure-Object).Count)
                $mgAllChildSubscriptionsCountDirect = ($optimizedTableForPathQueryMgAndSub | Where-Object { $_.mgId -eq $summaryManagementGroup.mgid } | Measure-Object).Count
                    
            }

            @"
<tr>
<td>$($summaryManagementGroup.level)</td>
<td>$($summaryManagementGroup.mgName)</td>
<td>$($summaryManagementGroup.mgId)</td>
<td>$($mgAllChildMgsCountTotal)</td>
<td>$($mgAllChildMgsCountDirect)</td>
<td>$($mgAllChildSubscriptionsCountTotal)</td>
<td>$($mgAllChildSubscriptionsCountDirect)</td>
"@
            if ($htParameters.NoAzureConsumption -eq $false) {
                @"
<td>$arrayTotalCostSummary</td>
"@
            }
            @"
<td>$($pathhlper)</td>
</tr>
"@
        }
        $htmlTenantSummary += $htmlSUMMARYManagementGroups
        $htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            $htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@   
        }
        $htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',            
            col_types: [
                'number',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number',
                'number',
                'number',
                'number',
"@
        if ($htParameters.NoAzureConsumption -eq $false) {
            $htmlTenantSummary += @"
                'caseinsensitivestring',
"@
        }
        $htmlTenantSummary += @"
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>

"@
    }
    else {
        $htmlTenantSummary += @"
    <p><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> <span class="valignMiddle">$($summaryManagementGroupsCount) Management Groups</span></p>
"@
    }
    #endregion SUMMARYMGs

    #region SUMMARYMGdefault
    Write-Host "  processing TenantSummary ManagementGroups - default Management Group"
    $htmlTenantSummary += @"
    <p><img class="imgMgTree defaultMG" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> <span class="valignMiddle">Hierarchy Settings | Default Management Group Id: '<b>$($defaultManagementGroupId)</b>' <a class="externallink" href="https://docs.microsoft.com/en-us/azure/governance/management-groups/how-to/protect-resource-hierarchy#setting---default-management-group" target="_blank">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></span></p>
"@
    #endregion SUMMARYMGdefault

    #region SUMMARYMGRequireAuthorizationForGroupCreation
    Write-Host "  processing TenantSummary ManagementGroups - requireAuthorizationForGroupCreation Management Group"
    $htmlTenantSummary += @"
    <p><img class="imgMgTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> <span class="valignMiddle">Hierarchy Settings | Require authorization for Management Group creation: '<b>$($requireAuthorizationForGroupCreation)</b>' <a class="externallink" href="https://docs.microsoft.com/en-us/azure/governance/management-groups/how-to/protect-resource-hierarchy#setting---require-authorization" target="_blank">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></span></p>
"@
    #endregion SUMMARYMGRequireAuthorizationForGroupCreation

    #region SUMMARYMgsapproachingLimitsPolicyAssignments
    Write-Host "  processing TenantSummary ManagementGroups Limit PolicyAssignments"
    $mgsApproachingLimitPolicyAssignments = (($policyBaseQueryManagementGroups | Where-Object { [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.PolicyAndPolicySetAssigmentAtScopeCount -gt 0 -and (($_.PolicyAndPolicySetAssigmentAtScopeCount -gt ($LimitPOLICYPolicyAssignmentsManagementGroup * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, MgName, PolicyAssigmentAtScopeCount, PolicySetAssigmentAtScopeCount, PolicyAndPolicySetAssigmentAtScopeCount, PolicyAssigmentLimit -Unique)
    if (($mgsApproachingLimitPolicyAssignments | measure-object).count -gt 0) {
        $tfCount = ($mgsApproachingLimitPolicyAssignments | measure-object).count
        $htmlTableId = "TenantSummary_MgsapproachingLimitsPolicyAssignments"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_MgsapproachingLimitsPolicyAssignments"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicyAssignments | measure-object).count) Management Groups approaching Limit ($LimitPOLICYPolicyAssignmentsManagementGroup) for PolicyAssignment</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYMgsapproachingLimitsPolicyAssignments = foreach ($mgApproachingLimitPolicyAssignments in $mgsApproachingLimitPolicyAssignments) {
            @"
<tr>
<td><span class="valignMiddle">$($mgApproachingLimitPolicyAssignments.MgName)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($mgApproachingLimitPolicyAssignments.MgId)">$($mgApproachingLimitPolicyAssignments.MgId)</a></span></td>
<td>$(($mgApproachingLimitPolicyAssignments.PolicyAndPolicySetAssigmentAtScopeCount/$LimitPOLICYPolicyAssignmentsManagementGroup).tostring("P")) ($($mgApproachingLimitPolicyAssignments.PolicyAndPolicySetAssigmentAtScopeCount)/$($LimitPOLICYPolicyAssignmentsManagementGroup)) ($($mgApproachingLimitPolicyAssignments.PolicyAssigmentAtScopeCount) Policy Assignments, $($mgApproachingLimitPolicyAssignments.PolicySetAssigmentAtScopeCount) PolicySet Assignments)</td>
</tr>
"@
        }
        $htmlTenantSummary += $htmlSUMMARYMgsapproachingLimitsPolicyAssignments
        $htmlTenantSummary += @"
        </tbody>
    </table>
</div>
<script>
    var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();
</script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicyAssignments | measure-object).count) Management Groups approaching Limit ($LimitPOLICYPolicyAssignmentsManagementGroup) for PolicyAssignment</span></p>
"@
    }
    #endregion SUMMARYMgsapproachingLimitsPolicyAssignments

    #region SUMMARYMgsapproachingLimitsPolicyScope
    Write-Host "  processing TenantSummary ManagementGroups Limit PolicyScope"
    $mgsApproachingLimitPolicyScope = (($policyBaseQueryManagementGroups | Where-Object { [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.PolicyDefinitionsScopedCount -gt 0 -and (($_.PolicyDefinitionsScopedCount -gt ($LimitPOLICYPolicyDefinitionsScopedManagementGroup * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, MgName, PolicyDefinitionsScopedCount, PolicyDefinitionsScopedLimit -Unique)
    if (($mgsApproachingLimitPolicyScope | measure-object).count -gt 0) {
        $tfCount = ($mgsApproachingLimitPolicyScope | measure-object).count
        $htmlTableId = "TenantSummary_MgsapproachingLimitsPolicyScope"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_MgsapproachingLimitsPolicyScope"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicyScope | measure-object).count) Management Groups approaching Limit ($LimitPOLICYPolicyDefinitionsScopedManagementGroup) for Policy Scope</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYMgsapproachingLimitsPolicyScope = foreach ($mgApproachingLimitPolicyScope in $mgsApproachingLimitPolicyScope) {
            @"
<tr>
<td><span class="valignMiddle">$($mgApproachingLimitPolicyScope.MgName)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($mgApproachingLimitPolicyScope.MgId)">$($mgApproachingLimitPolicyScope.MgId)</a></span></td>
<td>$(($mgApproachingLimitPolicyScope.PolicyDefinitionsScopedCount/$LimitPOLICYPolicyDefinitionsScopedManagementGroup).tostring("P")) $($mgApproachingLimitPolicyScope.PolicyDefinitionsScopedCount)/$($LimitPOLICYPolicyDefinitionsScopedManagementGroup)</td>
</tr>
"@
        }
        $htmlTenantSummary += $htmlSUMMARYMgsapproachingLimitsPolicyScope
        $htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$($mgsApproachingLimitPolicyScope.count) Management Groups approaching Limit ($LimitPOLICYPolicyDefinitionsScopedManagementGroup) for Policy Scope</span></p>
"@
    }
    #endregion SUMMARYMgsapproachingLimitsPolicyScope

    #region SUMMARYMgsapproachingLimitsPolicySetScope
    Write-Host "  processing TenantSummary ManagementGroups Limit PolicySetScope"
    $mgsApproachingLimitPolicySetScope = (($policyBaseQueryManagementGroups | Where-Object { [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.PolicySetDefinitionsScopedCount -gt 0 -and (($_.PolicySetDefinitionsScopedCount -gt ($LimitPOLICYPolicySetDefinitionsScopedManagementGroup * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, MgName, PolicySetDefinitionsScopedCount, PolicySetDefinitionsScopedLimit -Unique)
    if ($mgsApproachingLimitPolicySetScope.count -gt 0) {
        $tfCount = ($mgsApproachingLimitPolicySetScope | measure-object).count 
        $htmlTableId = "TenantSummary_MgsapproachingLimitsPolicySetScope"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_MgsapproachingLimitsPolicySetScope"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicySetScope | measure-object).count) Management Groups approaching Limit ($LimitPOLICYPolicySetDefinitionsScopedManagementGroup) for PolicySet Scope</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYMgsapproachingLimitsPolicySetScope = foreach ($mgApproachingLimitPolicySetScope in $mgsApproachingLimitPolicySetScope) {
            @"
<tr>
<td><span class="valignMiddle">$($mgApproachingLimitPolicySetScope.MgName)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($mgApproachingLimitPolicySetScope.MgId)">$($mgApproachingLimitPolicySetScope.MgId)</a></span></td>
<td>$(($mgApproachingLimitPolicySetScope.PolicySetDefinitionsScopedCount/$LimitPOLICYPolicySetDefinitionsScopedManagementGroup).tostring("P")) ($($mgApproachingLimitPolicySetScope.PolicySetDefinitionsScopedCount)/$($LimitPOLICYPolicySetDefinitionsScopedManagementGroup))</td>
</tr>
"@
        }
        $htmlTenantSummary += $htmlSUMMARYMgsapproachingLimitsPolicySetScope
        $htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicySetScope | measure-object).count) Management Groups approaching Limit ($LimitPOLICYPolicySetDefinitionsScopedManagementGroup) for PolicySet Scope</span></p>
"@
    }
    #endregion SUMMARYMgsapproachingLimitsPolicySetScope

    #region SUMMARYMgsapproachingLimitsRoleAssignment
    Write-Host "  processing TenantSummary ManagementGroups Limit RoleAssignments"
    $mgsApproachingRoleAssignmentLimit = $rbacBaseQueryArrayList.Where( { [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.RoleAssignmentsCount -gt ($LimitRBACRoleAssignmentsManagementGroup * $LimitCriticalPercentage / 100) }) | Sort-Object -Property MgId -Unique | select-object -Property MgId, MgName, RoleAssignmentsCount, RoleAssignmentsLimit
    
    if (($mgsApproachingRoleAssignmentLimit | measure-object).count -gt 0) {
        $tfCount = ($mgsApproachingRoleAssignmentLimit | measure-object).count
        $htmlTableId = "TenantSummary_MgsapproachingLimitsRoleAssignment"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_MgsapproachingLimitsRoleAssignment"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingRoleAssignmentLimit | measure-object).count) Management Groups approaching Limit ($LimitRBACRoleAssignmentsManagementGroup) for RoleAssignment</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYMgsapproachingLimitsRoleAssignment = foreach ($mgApproachingRoleAssignmentLimit in $mgsApproachingRoleAssignmentLimit) {
            @"
<tr>
<td><span class="valignMiddle">$($mgApproachingRoleAssignmentLimit.MgName)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($mgApproachingRoleAssignmentLimit.MgId)">$($mgApproachingRoleAssignmentLimit.MgId)</a></span></td>
<td>$(($mgApproachingRoleAssignmentLimit.RoleAssignmentsCount/$LimitRBACRoleAssignmentsManagementGroup).tostring("P")) ($($mgApproachingRoleAssignmentLimit.RoleAssignmentsCount)/$($LimitRBACRoleAssignmentsManagementGroup))</td>
</tr>
"@
        }
        $htmlTenantSummary += $htmlSUMMARYMgsapproachingLimitsRoleAssignment
        $htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($mgApproachingRoleAssignmentLimit | measure-object).count) Management Groups approaching Limit ($LimitRBACRoleAssignmentsManagementGroup) for RoleAssignment</span></p>
"@
    }
    #endregion SUMMARYMgsapproachingLimitsRoleAssignment

    $htmlTenantSummary += @"
    </div>
"@
    #endregion tenantSummaryManagementGroups

    #region tenantSummarySubscriptions
    $htmlTenantSummary += @"
<button type="button" class="collapsible" id="tenantSummarySubscriptions"><hr class="hr-text" data-content="Subscriptions, Resources & Limits" /></button>
<div class="content">
"@

    #region SUMMARYSubs
    Write-Host "  processing TenantSummary Subscriptions"
    $summarySubscriptions = $optimizedTableForPathQueryMgAndSub | Sort-Object -Property Subscription
    $summarySubscriptionsCount = ($summarySubscriptions | Measure-Object).Count
    if ($summarySubscriptionsCount -gt 0) {
        $tfCount = $summarySubscriptionsCount
        $htmlTableId = "TenantSummary_subs"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_Subs"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle">$($summarySubscriptionsCount) Subscriptions (state: enabled)</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true" style="color:#FFB100;"></i> <b>Understand ASC Secure Score</b> <a class="externallink" href="https://www.youtube.com/watch?v=2EMnzxdqDhA" target="_blank">Video <i class="fa fa-external-link" aria-hidden="true"></i></a>, <a class="externallink" href="https://techcommunity.microsoft.com/t5/azure-security-center/security-controls-in-azure-security-center-enable-endpoint/ba-p/1624653" target="_blank">Blog <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>QuotaId</th>
<th>Tags</th>
<th>ASC Score</th>
"@
        if ($htParameters.NoAzureConsumption -eq $false) {
            $htmlTenantSummary += @"
<th>Cost ($($AzureConsumptionPeriod)d)</th>
<th>Currency</th>
"@
        }
        $htmlTenantSummary += @"
<th>Path</th>
</tr>
</thead>
<tbody>
"@
        $htmlSUMMARYSubs = $null
        $htmlSUMMARYSubs = foreach ($summarySubscription in $summarySubscriptions) {
            $subPath = $htAllSubsMgPath.($summarySubscription.subscriptionId).path -join "/"
            $subscriptionTagsArray = [System.Collections.ArrayList]@()
            foreach ($tag in ($htSubscriptionTags).($summarySubscription.subscriptionId).keys) {
                $null = $subscriptionTagsArray.Add("'$($tag)':'$(($htSubscriptionTags).$($summarySubscription.subscriptionId).$tag)'")
            }    

            if ($htParameters.NoAzureConsumption -eq $false) {
                if ($htAzureConsumptionSubscriptions.($summarySubscription.subscriptionId)) {
                    if ([math]::Round($htAzureConsumptionSubscriptions.($summarySubscription.subscriptionId).TotalCost, 4) -eq 0) {
                        $totalCost = [decimal]$htAzureConsumptionSubscriptions.($summarySubscription.subscriptionId).TotalCost
                    }
                    else {
                        $totalCost = [decimal]([math]::Round($htAzureConsumptionSubscriptions.($summarySubscription.subscriptionId).TotalCost, 4))
                    }
                    $currency = $htAzureConsumptionSubscriptions.($summarySubscription.subscriptionId).Currency
                }
                else {
                    $totalCost = "0"
                    $currency = "n/a"
                }
            }
            else {
                $totalCost = "n/a"
                $currency = "n/a"
            }
            @"
<tr>
<td>$($summarySubscription.subscription)</td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($summarySubscription.MgId)">$($summarySubscription.subscriptionId)</a></span></td>
<td>$($summarySubscription.SubscriptionQuotaId)</td>
<td>$(($subscriptionTagsArray | sort-object) -join "$CsvDelimiterOpposite ")</td>
<td>$($summarySubscription.SubscriptionASCSecureScore)</td>
"@
            if ($htParameters.NoAzureConsumption -eq $false) {
                @"
<td>$totalCost</td>
<td>$currency</td>
"@
            }
            @"
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
                'number',
"@
        if ($htParameters.NoAzureConsumption -eq $false) {
            $htmlTenantSummary += @"
                'number',
                'caseinsensitivestring',
"@
        }
        $htmlTenantSummary += @"
                'caseinsensitivestring'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>

"@
    }
    else {
        $htmlTenantSummary += @"
    <p><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle">$($summarySubscriptionsCount) Subscriptions</span></p>
"@
    }
    #endregion SUMMARYSubs

    #region SUMMARYOutOfScopeSubscriptions
    Write-Host "  processing TenantSummary Subscriptions (out-of-scope)"
    $outOfScopeSubscriptionsCount = ($outOfScopeSubscriptions | Measure-Object).Count
    if ($outOfScopeSubscriptionsCount -gt 0) {
        $tfCount = $outOfScopeSubscriptionsCount
        $htmlTableId = "TenantSummary_outOfScopeSubscriptions"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_outOfScopeSubscriptions"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg"> <span class="valignMiddle">$outOfScopeSubscriptionsCount Subscriptions out-of-scope</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYOutOfScopeSubscriptions = foreach ($outOfScopeSubscription in $outOfScopeSubscriptions) {
            @"
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
            
"@      
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg"> <span class="valignMiddle">$outOfScopeSubscriptionsCount Subscriptions out-of-scope</span></p>
"@
    }
    #endregion SUMMARYOutOfScopeSubscriptions

    #region SUMMARYTagNameUsage
    Write-Host "  processing TenantSummary TagsUsage"
    $tagsUsageCount = ($arrayTagList | Measure-Object).Count
    if ($tagsUsageCount -gt 0) {
        $tagNamesUniqueCount = ($arrayTagList | Sort-Object -Property TagName -Unique | Measure-Object).Count
        $tagNamesUsedInScopes = ($arrayTagList | Where-Object { $_.Scope -ne "AllScopes" } | Sort-Object -Property Scope -Unique).scope -join "$($CsvDelimiterOpposite) "
        $tfCount = $tagsUsageCount
        $htmlTableId = "TenantSummary_tagsUsage"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_tagsUsage"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Tag Name Usage ($tagNamesUniqueCount unique Tag Names applied at $($tagNamesUsedInScopes))</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Scope</th>
<th>TagName</th>
<th>Count</th>
</tr>
</thead>
<tbody>
"@
        $htmlSUMMARYtagsUsage = $null
        $htmlSUMMARYtagsUsage = foreach ($tagEntry in $arrayTagList | Sort-Object -Property Scope, TagName -CaseSensitive) {
            @"
<tr>
<td>$($tagEntry.Scope)</td>
<td>$($tagEntry.TagName)</td>
<td>$($tagEntry.TagCount)</td>
</tr>
"@ 
        }
        $htmlTenantSummary += $htmlSUMMARYtagsUsage
        $htmlTenantSummary += @"
            </tbody>
        </table>
    </div>
    <script>
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
            
"@      
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            $htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@  
        }
        $htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'multiple',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> Tag Name Usage ($tagsUsageCount Tags)</p>
"@
    }
    #endregion SUMMARYTagNameUsage

    #region SUMMARYResources
    Write-Host "  processing TenantSummary Subscriptions Resources"
    if (($resourcesAll | Measure-Object).count -gt 0) {
        $tfCount = ($resourcesAll | Measure-Object).count
        $resourcesAllSummarized = $resourcesAll | Select-Object -Property type, location, count_ | Group-Object type, location | ForEach-Object {
            New-Object PSObject -Property @{
                type     = ($_.Name -split ",")[0]
                location = $_.Group[0].location
                count_   = ($_.Group | Measure-Object -Property count_ -Sum).Sum
            }
        }

        $resourcesTotal = 0
        $resourcesAllSummarized.count_ | ForEach-Object { $resourcesTotal += $_ }
        $resourcesResourceTypeCount = (($resourcesAllSummarized | sort-object -Property type -Unique) | measure-object).count
        $resourcesLocationCount = (($resourcesAllSummarized | sort-object -Property location -Unique) | measure-object).count

        if ($resourcesResourceTypeCount -gt 0) {
            $tfCount = ($resourcesAllSummarized | measure-object).count
            $htmlTableId = "TenantSummary_resources"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_resources"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$resourcesResourceTypeCount ResourceTypes ($resourcesTotal Resources) in $resourcesLocationCount Locations ($scopeNamingSummary)</span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
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
            $htmlSUMMARYResources = foreach ($resourceAllSummarized in $resourcesAllSummarized) {
                @"
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
    var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();
</script>
"@
        }
        else {
            $htmlTenantSummary += @"
        <p><i class="fa fa-ban" aria-hidden="true"></i> $resourcesResourceTypeCount ResourceTypes</p>
"@
        }

    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> 0 ResourceTypes</p>
"@
    }
    #endregion SUMMARYResources

    #region SUMMARYResourcesDiagnosticsCapable
    Write-Host "  processing TenantSummary Subscriptions Resources Diagnostics Capable"
    $resourceTypesDiagnosticsArraySorted = $resourceTypesDiagnosticsArray | Sort-Object -Property ResourceType, ResourceCount, Metrics, Logs, LogCategories
    $resourceTypesDiagnosticsArraySortedCount = ($resourceTypesDiagnosticsArraySorted | measure-object).count
    $resourceTypesDiagnosticsMetricsTrueCount = ($resourceTypesDiagnosticsArray | Where-Object { $_.Metrics -eq $True } | Measure-Object).count
    $resourceTypesDiagnosticsLogsTrueCount = ($resourceTypesDiagnosticsArray | Where-Object { $_.Logs -eq $True } | Measure-Object).count
    $resourceTypesDiagnosticsMetricsLogsTrueCount = ($resourceTypesDiagnosticsArray | Where-Object { $_.Metrics -eq $True -or $_.Logs -eq $True } | Measure-Object).count
    if ($resourceTypesDiagnosticsArraySortedCount -gt 0) {
        $tfCount = $resourceTypesDiagnosticsArraySortedCount
        $htmlTableId = "TenantSummary_ResourcesDiagnosticsCapable"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_ResourcesDiagnosticsCapable"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$resourceTypesDiagnosticsMetricsLogsTrueCount/$resourceTypesDiagnosticsArraySortedCount ResourceTypes Diagnostics capable ($resourceTypesDiagnosticsMetricsTrueCount Metrics, $resourceTypesDiagnosticsLogsTrueCount Logs)</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true" style="color:#FFB100;"></i> <b>Create Custom Policies for Azure ResourceTypes that support Diagnostics Logs and Metrics</b> <a class="externallink" href="https://github.com/JimGBritt/AzurePolicy/blob/master/AzureMonitor/Scripts/README.md#overview-of-create-azdiagpolicyps1" target="_blank">Create-AzDiagPolicy <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
&nbsp;&nbsp; <b>Supported categories for Azure Resource Logs</b> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-monitor/platform/resource-logs-categories" target="_blank">docs <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYResourcesDiagnosticsCapable = foreach ($resourceType in $resourceTypesDiagnosticsArraySorted) {
            if ($resourceType.Metrics -eq $true -or $resourceType.Logs -eq $true) {
                $diagnosticsCapable = $true
            }
            else {
                $diagnosticsCapable = $false
            }
            @"
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
    var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();
</script>
"@
    }
    else {

        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($resourceTypesDiagnosticsMetricsLogsTrueCount | measure-object).count) Management Groups approaching Limit ($LimitPOLICYPolicyAssignmentsManagementGroup) for PolicyAssignment</span></p>
"@
    }
    #endregion SUMMARYResourcesDiagnosticsCapable

    #region SUMMARYDiagnosticsPolicyLifecycle
    if (-not $NoResourceDiagnosticsPolicyLifecycle) {
        Write-Host "  processing TenantSummary Resource Diagnostics Policy Lifecycle"
        $startsumDiagLifecycle = get-date

        if ($tenantCustomPoliciesCount -gt 0) {

            $policiesThatDefineDiagnostics = $tenantCustomPolicies | Where-Object {
                ($htCacheDefinitions).policy.($_).Type -eq "custom" -and
                ($htCacheDefinitions).policy.($_).json.properties.policyrule.then.details.type -eq "Microsoft.Insights/diagnosticSettings" -and
                ($htCacheDefinitions).policy.($_).json.properties.policyrule.then.details.deployment.properties.template.resources.type -match "/providers/diagnosticSettings"
            }

            $policiesThatDefineDiagnosticsCount = ($policiesThatDefineDiagnostics | Measure-Object).count
            if ($policiesThatDefineDiagnosticsCount -gt 0) {

                $diagnosticsPolicyAnalysis = @()
                $diagnosticsPolicyAnalysis = [System.Collections.ArrayList]@()
                foreach ($policy in $policiesThatDefineDiagnostics) {

                    if (
                        (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match "/providers/diagnosticSettings" }).properties.workspaceId -or
                        (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match "/providers/diagnosticSettings" }).properties.eventHubAuthorizationRuleId -or
                        (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match "/providers/diagnosticSettings" }).properties.storageAccountId
                    ) {
                        if ( (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match "/providers/diagnosticSettings" }).properties.workspaceId) {
                            $diagnosticsDestination = "LA"
                        }
                        if ( (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match "/providers/diagnosticSettings" }).properties.eventHubAuthorizationRuleId) {
                            $diagnosticsDestination = "EH"
                        }
                        if ( (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match "/providers/diagnosticSettings" }).properties.storageAccountId) {
                            $diagnosticsDestination = "SA"
                        }

                        if ( (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match "/providers/diagnosticSettings" }).properties.logs ) {

                            $resourceType = ( (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match "/providers/diagnosticSettings" }).type -replace "/providers/diagnosticSettings")

                            $resourceTypeCountFromResourceTypesSummarizedArray = ($resourceTypesSummarizedArray | Where-Object { $_.ResourceType -eq $resourceType }).ResourceCount
                            if ($resourceTypeCountFromResourceTypesSummarizedArray) {
                                $resourceCount = $resourceTypeCountFromResourceTypesSummarizedArray
                            }
                            else {
                                $resourceCount = "0"
                            }
                            $supportedLogs = $resourceTypesDiagnosticsArray | Where-Object { $_.ResourceType -eq ( (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match "/providers/diagnosticSettings" }).type -replace "/providers/diagnosticSettings") }
                            
                            $diagnosticsLogCategoriesSupported = $supportedLogs.LogCategories
                            if (($supportedLogs | Measure-Object).count -gt 0) {
                                $logsSupported = "yes"
                            }
                            else {
                                $logsSupported = "no"
                            }

                            $roleDefinitionIdsArray = [System.Collections.ArrayList]@()
                            foreach ($roleDefinitionId in ($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.roleDefinitionIds) {
                                if (($htCacheDefinitions).role.($roleDefinitionId -replace ".*/")) {
                                    $null = $roleDefinitionIdsArray.Add("<b>$(($htCacheDefinitions).role.($roleDefinitionId -replace ".*/").Name)</b> ($($roleDefinitionId -replace ".*/"))")
                                }
                                else {
                                    Write-Host "  DiagnosticsLifeCycle: unknown RoleDefinition '$roleDefinitionId'"
                                    $null = $roleDefinitionIdsArray.Add("unknown RoleDefinition: '$roleDefinitionId'")
                                }
                            }

                            

                            $policyHasPolicyAssignments = $policyBaseQuery | Where-Object { $_.PolicyDefinitionId -eq $policy } | sort-object -property PolicyDefinitionId, PolicyAssignmentId -unique
                            $policyHasPolicyAssignmentCount = ($policyHasPolicyAssignments | Measure-Object).count
                            if ($policyHasPolicyAssignmentCount -gt 0) {
                                $policyAssignmentsArray = @()
                                $policyAssignmentsArray += foreach ($policyAssignment in $policyHasPolicyAssignments) {
                                    "$($policyAssignment.PolicyAssignmentId) (<b>$($policyAssignment.PolicyAssignmentDisplayName)</b>)"
                                }
                                $policyAssignmentsCollCount = ($policyAssignmentsArray | Measure-Object).count
                                $policyAssignmentsColl = $policyAssignmentsCollCount
                            }
                            else {
                                $policyAssignmentsColl = 0
                            }

                            #PolicyUsedinPolicySet
                            $policySetAssignmentsColl = 0
                            $policySetAssignmentsArray = @()
                            $policyUsedinPolicySets = "n/a"
                                
                            $usedInPolicySetArray = [System.Collections.ArrayList]@()
                            $usedInPolicySetArray = foreach ($customPolicySet in $tenantCustomPolicySets) {
                                if (($htCacheDefinitions).policySet.$customPolicySet.Type -eq "Custom") {
                                    $hlpCustomPolicySet = ($htCacheDefinitions).policySet.($customPolicySet)
                                    if (($hlpCustomPolicySet.PolicySetPolicyIds) -contains ($policy)) {
                                        "$($hlpCustomPolicySet.id) (<b>$($hlpCustomPolicySet.DisplayName)</b>)"
                                            
                                        #PolicySetHasAssignments
                                        $policySetAssignments = ($htCacheAssignments2).policy.keys | Where-Object { ($htCacheAssignments2).policy.($_).PolicyDefinitionId -eq ($hlpCustomPolicySet.id) }
                                        $policySetAssignmentsCount = ($policySetAssignments | measure-object).count
                                        if ($policySetAssignmentsCount -gt 0) {
                                            $policySetAssignmentsArray += foreach ($policySetAssignment in $policySetAssignments) {
                                                "$(($htCacheAssignments2).policy.($policySetAssignment).PolicyAssignmentId) (<b>$(($htCacheAssignments2).policy.($policySetAssignment).PolicyAssignmentDisplayName)</b>)"
                                            }
                                            $policySetAssignmentsCollCount = ($policySetAssignmentsArray | Measure-Object).Count
                                            $policySetAssignmentsColl = "$policySetAssignmentsCollCount [$($policySetAssignmentsArray -join "$CsvDelimiterOpposite ")]"
                                        }

                                    }
                                }
                            }

                            if (($usedInPolicySetArray | Measure-Object).count -gt 0) {
                                $policyUsedinPolicySets = "$(($usedInPolicySetArray | Measure-Object).count) [$($usedInPolicySetArray -join "$CsvDelimiterOpposite ")]"
                            }
                            else {
                                $policyUsedinPolicySets = "$(($usedInPolicySetArray | Measure-Object).count)"
                            }

                            if ($recommendation -eq "review the policy and add the missing categories as required") {
                                if ($policyAssignmentsColl -gt 0 -or $policySetAssignmentsColl -gt 0) {
                                    $priority = "1-High"
                                }
                                else {
                                    $priority = "3-MediumLow"
                                }
                            }
                            else {
                                $priority = "4-Low"
                            }

                            $diagnosticsLogCategoriesCoveredByPolicy = (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match "/providers/diagnosticSettings" }).properties.logs
                            if (($diagnosticsLogCategoriesCoveredByPolicy.category | Measure-Object).count -gt 0) {

                                if (($supportedLogs | Measure-Object).count -gt 0) {
                                    $actionItems = @()
                                    $actionItems += foreach ($supportedLogCategory in $supportedLogs.LogCategories) {
                                        if ($diagnosticsLogCategoriesCoveredByPolicy.category -notcontains ($supportedLogCategory)) {
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

                                $null = $diagnosticsPolicyAnalysis.Add([PSCustomObject]@{
                                        Priority                    = $priority
                                        PolicyId                    = ($htCacheDefinitions).policy.($policy).id
                                        PolicyCategory              = ($htCacheDefinitions).policy.($policy).Category
                                        PolicyName                  = ($htCacheDefinitions).policy.($policy).DisplayName
                                        PolicyDeploysRoles          = $roleDefinitionIdsArray -join "$CsvDelimiterOpposite "
                                        PolicyForResourceTypeExists = $true
                                        ResourceType                = $resourceType
                                        ResourceTypeCount           = $resourceCount
                                        Status                      = $status
                                        LogsSupported               = $logsSupported
                                        LogCategoriesInPolicy       = ($diagnosticsLogCategoriesCoveredByPolicy.category | Sort-Object) -join "$CsvDelimiterOpposite "
                                        LogCategoriesSupported      = ($diagnosticsLogCategoriesSupported | Sort-Object) -join "$CsvDelimiterOpposite "
                                        LogCategoriesDelta          = ($diagnosticsLogCategoriesNotCoveredByPolicy | Sort-Object) -join "$CsvDelimiterOpposite "
                                        Recommendation              = $recommendation
                                        DiagnosticsTargetType       = $diagnosticsDestination
                                        PolicyAssignments           = $policyAssignmentsColl
                                        PolicyUsedInPolicySet       = $policyUsedinPolicySets
                                        PolicySetAssignments        = $policySetAssignmentsColl
                                    })

                            }
                            else {
                                $status = "no categories defined"
                                $priority = "5-Low"
                                $recommendation = "Review the policy - the definition has key for categories, but there are none categories defined"
                                $null = $diagnosticsPolicyAnalysis.Add([PSCustomObject]@{
                                        Priority                    = $priority
                                        PolicyId                    = ($htCacheDefinitions).policy.($policy).id
                                        PolicyCategory              = ($htCacheDefinitions).policy.($policy).Category
                                        PolicyName                  = ($htCacheDefinitions).policy.($policy).DisplayName
                                        PolicyDeploysRoles          = $roleDefinitionIdsArray -join "$CsvDelimiterOpposite "
                                        PolicyForResourceTypeExists = $true
                                        ResourceType                = $resourceType
                                        ResourceTypeCount           = $resourceCount
                                        Status                      = $status
                                        LogsSupported               = $logsSupported
                                        LogCategoriesInPolicy       = "none"
                                        LogCategoriesSupported      = ($diagnosticsLogCategoriesSupported | Sort-Object) -join "$CsvDelimiterOpposite "
                                        LogCategoriesDelta          = ($diagnosticsLogCategoriesSupported | Sort-Object) -join "$CsvDelimiterOpposite "
                                        Recommendation              = $recommendation
                                        DiagnosticsTargetType       = $diagnosticsDestination
                                        PolicyAssignments           = $policyAssignmentsColl
                                        PolicyUsedInPolicySet       = $policyUsedinPolicySets
                                        PolicySetAssignments        = $policySetAssignmentsColl
                                    })
                            }
                        } 
                        else {
                            if (-not (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match "/providers/diagnosticSettings" }).properties.metrics ) {
                                Write-Host "  DiagnosticsLifeCycle check?!: $($policy) - something unexpected, no Logs and no Metrics defined"
                            } 
                        }
                    }
                    else {
                        Write-Host "   DiagnosticsLifeCycle check?!: $($policy) - something unexpected - not EH, LA, SA"
                    }
                }
                #where no Policy exists
                foreach ($resourceTypeDiagnosticsCapable in $resourceTypesDiagnosticsArray | Where-Object { $_.Logs -eq $true }) {
                    if (($diagnosticsPolicyAnalysis.ResourceType).ToLower() -notcontains ( ($resourceTypeDiagnosticsCapable.ResourceType).ToLower() )) {
                        $supportedLogs = ($resourceTypesDiagnosticsArray | Where-Object { $_.ResourceType -eq $resourceTypeDiagnosticsCapable.ResourceType }).LogCategories
                        $logsSupported = "yes"
                        $resourceTypeCountFromResourceTypesSummarizedArray = ($resourceTypesSummarizedArray | Where-Object { $_.ResourceType -eq $resourceTypeDiagnosticsCapable.ResourceType }).ResourceCount
                        if ($resourceTypeCountFromResourceTypesSummarizedArray) {
                            $resourceCount = $resourceTypeCountFromResourceTypesSummarizedArray
                        }
                        else {
                            $resourceCount = "0"
                        }
                        $recommendation = "Create diagnostics policy for this ResourceType. To verify GA check <a class=`"externallink`" href=`"https://docs.microsoft.com/en-us/azure/azure-monitor/platform/resource-logs-categories`" target=`"_blank`">docs <i class=`"fa fa-external-link`" aria-hidden=`"true`"></i></a>"
                        $null = $diagnosticsPolicyAnalysis.Add([PSCustomObject]@{
                                Priority                    = "2-Medium"
                                PolicyId                    = "n/a"
                                PolicyCategory              = "n/a"
                                PolicyName                  = "n/a"
                                PolicyDeploysRoles          = "n/a"
                                ResourceType                = $resourceTypeDiagnosticsCapable.ResourceType
                                ResourceTypeCount           = $resourceCount
                                Status                      = "n/a"
                                LogsSupported               = $logsSupported
                                LogCategoriesInPolicy       = "n/a"
                                LogCategoriesSupported      = $supportedLogs -join "$CsvDelimiterOpposite "
                                LogCategoriesDelta          = "n/a"
                                Recommendation              = $recommendation
                                DiagnosticsTargetType       = "n/a"
                                PolicyForResourceTypeExists = $false
                                PolicyAssignments           = "n/a"
                                PolicyUsedInPolicySet       = "n/a"
                                PolicySetAssignments        = "n/a"
                            })
                    }
                }
                $diagnosticsPolicyAnalysisCount = ($diagnosticsPolicyAnalysis | Measure-Object).count

                if ($diagnosticsPolicyAnalysisCount -gt 0) {
                    $tfCount = $diagnosticsPolicyAnalysisCount
    
                    $htmlTableId = "TenantSummary_DiagnosticsLifecycle"
                    $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_DiagnosticsLifecycle"><i class="fa fa-check" aria-hidden="true" style="color: #67C409"></i> <span class="valignMiddle">ResourceDiagnostics for Logs - Policy Lifecycle recommendations</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true" style="color:#FFB100;"></i> <b>Create Custom Policies for Azure ResourceTypes that support Diagnostics Logs and Metrics</b> <a class="externallink" href="https://github.com/JimGBritt/AzurePolicy/blob/master/AzureMonitor/Scripts/README.md#overview-of-create-azdiagpolicyps1" target="_blank">Create-AzDiagPolicy <i class="fa fa-external-link" aria-hidden="true"></i></a><br>
&nbsp;&nbsp; <b>Supported categories for Azure Resource Logs</b> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-monitor/platform/resource-logs-categories" target="_blank">docs <i class="fa fa-external-link" aria-hidden="true"></i></a>
<table id= "$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Priority</th>
<th>Recommendation</th>
<th>ResourceType</th>
<th>Resource Count</th>
<th>Diagnostics capable (logs)</th>
<th>Policy Id</th>
<th>Policy DisplayName</th>
<th>Role Definitions</th>              
<th>Target</th>
<th>Log Categories not covered by Policy</th>
<th>Policy Assignments</th>
<th>Policy used in PolicySet</th>
<th>PolicySet Assignments</th>
</tr>
</thead>
<tbody>
"@

                    foreach ($diagnosticsFinding in $diagnosticsPolicyAnalysis | Sort-Object -property @{Expression = { $_.Priority } }, @{Expression = { $_.Recommendation } }, @{Expression = { $_.ResourceType } }, @{Expression = { $_.PolicyName } }, @{Expression = { $_.PolicyId } }) {
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
                <td class="breakwordall">
                    $($diagnosticsFinding.PolicyId)
                </td>
                <td class="breakwordall">
                    $($diagnosticsFinding.PolicyName)
                </td>
                <td class="breakwordall">
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
                <td class="breakwordall">
                    $($diagnosticsFinding.PolicyUsedInPolicySet)
                </td>
                <td class="breakwordall">
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
    var tfConfig4$htmlTableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
                    if ($tfCount -gt 10) {
                        $spectrum = "10, $tfCount"
                        if ($tfCount -gt 50) {
                            $spectrum = "10, 25, 50, $tfCount"
                        }        
                        if ($tfCount -gt 100) {
                            $spectrum = "10, 30, 50, 100, $tfCount"
                        }
                        if ($tfCount -gt 500) {
                            $spectrum = "10, 30, 50, 100, 250, $tfCount"
                        }
                        if ($tfCount -gt 1000) {
                            $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                        }
                        if ($tfCount -gt 2000) {
                            $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                        }
                        if ($tfCount -gt 3000) {
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
        col_0: 'select',
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
    var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
    tf.init();
</script>
"@
                }
                else {
                    $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No ResourceDiagnostics Policy Lifecycle recommendations</span></p>
"@
                }
            }
            else {
                $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No ResourceDiagnostics Policy Lifecycle recommendations</span></p>
"@
            }
        }
        else {
            $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No ResourceDiagnostics Policy Lifecycle recommendations</span></p>
"@
        }
        $endsumDiagLifecycle = get-date
        Write-Host "   Resource Diagnostics Policy Lifecycle processing duration: $((NEW-TIMESPAN -Start $startsumDiagLifecycle -End $endsumDiagLifecycle).TotalSeconds) seconds"
    }
    #endregion SUMMARYDiagnosticsPolicyLifecycle

    #region SUMMARYSubResourceProviders
    Write-Host "  processing TenantSummary Subscriptions Resource Providers"
    $resourceProvidersAllCount = (($htResourceProvidersAll).Keys | Measure-Object).count
    if ($resourceProvidersAllCount -gt 0) {
        $grped = ($arrayResourceProvidersAll) | sort-object -property namespace, registrationState | group-object namespace
        $htResProvSummary = @{ }
        foreach ($grp in $grped) {
            $htResProvSummary.($grp.name) = @{ }
            $regstates = ($grp.group | sort-object -property registrationState -unique | select-object registrationState).registrationstate
            foreach ($regstate in $regstates) {
                $htResProvSummary.($grp.name).$regstate = ($grp.group | Where-Object { $_.registrationstate -eq $regstate } | measure-object).count
            }
        }
        $providerSummary = [System.Collections.ArrayList]@()
        foreach ($provider in $htResProvSummary.keys) {
            if ($htResProvSummary.$provider.registered) {
                $registered = $htResProvSummary.$provider.registered
            }
            else {
                $registered = "0"
            }

            if ($htResProvSummary.$provider.registering) {
                $registering = $htResProvSummary.$provider.registering
            }
            else {
                $registering = "0"
            }

            if ($htResProvSummary.$provider.notregistered) {
                $notregistered = $htResProvSummary.$provider.notregistered
            }
            else {
                $notregistered = "0"
            }

            if ($htResProvSummary.$provider.unregistering) {
                $unregistering = $htResProvSummary.$provider.unregistering
            }
            else {
                $unregistering = "0"
            }

            $null = $providerSummary.Add([PSCustomObject]@{
                    Provider      = $provider
                    Registered    = $registered
                    NotRegistered = $notregistered
                    Registering   = $registering
                    Unregistering = $unregistering 
                })
        }

        $uniqueNamespaces = ($arrayResourceProvidersAll) | Sort-Object -Property namespace -Unique
        $uniqueNamespacesCount = ($uniqueNamespaces | Measure-Object).count
        $uniqueNamespaceRegistrationState = ($arrayResourceProvidersAll) | Sort-Object -Property namespace, registrationState -Unique
        $providersRegistered = $uniqueNamespaceRegistrationState | Where-Object { $_.registrationState -eq "registered" -or $_.registrationState -eq "registering" } | select-object -property namespace | Sort-Object namespace -Unique
        $providersRegisteredCount = ($providersRegistered | Measure-Object).count

        $providersNotRegisteredUniqueCount = 0 
        foreach ($uniqueNamespace in $uniqueNamespaces) {
            if ($providersRegistered.namespace -notcontains ($uniqueNamespace.namespace)) {
                $providersNotRegisteredUniqueCount++
            }
        }
        $tfCount = $uniqueNamespacesCount
        $htmlTableId = "TenantSummary_SubResourceProviders"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_SubResourceProviders"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Providers Total: $uniqueNamespacesCount Registered/Registering: $providersRegisteredCount NotRegistered/Unregistering: $providersNotRegisteredUniqueCount</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYSubResourceProviders = foreach ($provider in ($providerSummary | Sort-Object -Property Provider)) {
            @"
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,      
"@      
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$resourceProvidersAllCount Resource Providers</span></p>
"@
    }
    #endregion SUMMARYSubResourceProviders

    #region SUMMARYSubResourceProvidersDetailed
    if ($htParameters.NoResourceProvidersDetailed -eq $false) {

        Write-Host "  processing TenantSummary Subscriptions Resource Providers detailed"
        $startsumRPDetailed = get-date
        $resourceProvidersAllCount = (($htResourceProvidersAll).Keys | Measure-Object).count
        if ($resourceProvidersAllCount -gt 0) {
            $tfCount = (($arrayResourceProvidersAll) | Measure-Object).Count
            $htmlTableId = "TenantSummary_SubResourceProvidersDetailed"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_SubResourceProvidersDetailed"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Providers Detailed</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
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
            $htmlSUMMARYSubResourceProvidersDetailed = foreach ($subscriptionResProv in (($htResourceProvidersAll).Keys | sort-object)) {
                $subscriptionResProvDetails = $optimizedTableForPathQueryMgAndSub | Where-Object { $_.SubscriptionId -eq $subscriptionResProv } | sort-object -Property SubscriptionId -Unique
                foreach ($provider in ($htResourceProvidersAll).($subscriptionResProv).Providers | sort-object @{Expression = { $_.namespace } }) {
                    $cnter++
                    if ($cnter % 500 -eq 0) {
                        $etappeResProvDetailed = get-date
                        Write-Host "   $cnter ResProv processed; $((NEW-TIMESPAN -Start $startResProvDetailed -End $etappeResProvDetailed).TotalSeconds) seconds"  
                    }
                    @"
<tr>
<td>$($subscriptionResProvDetails.MgName)</td>
<td>$($subscriptionResProvDetails.MgId)</td>
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
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
            
"@      
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
        }
        else {
            $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$resourceProvidersAllCount Resource Providers</span></p>
"@
        }
        $endsumRPDetailed = get-date
        Write-Host "   RP detailed processing duration: $((NEW-TIMESPAN -Start $startsumRPDetailed -End $endsumRPDetailed).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startsumRPDetailed -End $endsumRPDetailed).TotalSeconds) seconds)"
    }
    #endregion SUMMARYSubResourceProvidersDetailed

    #region SUMMARYSubResourceLocks
    Write-Host "  processing TenantSummary Subscriptions Resource Locks"
    $tfCount = 6
    $startResourceLocks = get-date

    if (($htResourceLocks.keys | Measure-Object).Count -gt 0) {
        $htmlTableId = "TenantSummary_ResourceLocks"
        
        $subscriptionLocksCannotDeleteCount = ($htResourceLocks.Keys | Where-Object { $htResourceLocks.($_).SubscriptionLocksCannotDeleteCount -gt 0 } | Measure-Object).Count
        $subscriptionLocksReadOnlyCount = ($htResourceLocks.Keys | Where-Object { $htResourceLocks.($_).SubscriptionLocksReadOnlyCount -gt 0 } | Measure-Object).Count

        $resourceGroupsLocksCannotDeleteCount = ($htResourceLocks.Keys | Where-Object { $htResourceLocks.($_).ResourceGroupsLocksCannotDeleteCount -gt 0 } | Measure-Object).Count
        $resourceGroupsLocksReadOnlyCount = ($htResourceLocks.Keys | Where-Object { $htResourceLocks.($_).ResourceGroupsLocksReadOnlyCount -gt 0 } | Measure-Object).Count

        $resourcesLocksCannotDeleteCount = ($htResourceLocks.Keys | Where-Object { $htResourceLocks.($_).ResourcesLocksCannotDeleteCount -gt 0 } | Measure-Object).Count
        $resourcesLocksReadOnlyCount = ($htResourceLocks.Keys | Where-Object { $htResourceLocks.($_).ResourcesLocksReadOnlyCount -gt 0 } | Measure-Object).Count
        
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_ResourceLocks"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Locks</span></button>
<div class="content">
&nbsp;&nbsp;<b>Considerations before applying locks</b> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources#considerations-before-applying-locks" target="_blank">docs <i class="fa fa-external-link" aria-hidden="true"></i></a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Lock scope</th>
<th>Lock type</th>
<th>presence</th>
</tr>
</thead>
<tbody>
<tr><td>Subscription</td><td>CannotDelete</td><td>$($subscriptionLocksCannotDeleteCount) of $totalSubCount Subscriptions</td></tr>
<tr><td>Subscription</td><td>ReadOnly</td><td>$($subscriptionLocksReadOnlyCount) of $totalSubCount Subscriptions</td></tr>
<tr><td>ResourceGroup</td><td>CannotDelete</td><td>$($resourceGroupsLocksCannotDeleteCount) of $totalSubCount Subscriptions (total: $($resourceGroupsLocksCannotDeleteCountTotal))</td></tr>
<tr><td>ResourceGroup</td><td>ReadOnly</td><td>$($resourceGroupsLocksReadOnlyCount) of $totalSubCount Subscriptions (total: $($resourceGroupsLocksReadOnlyCountTotal))</td></tr>
<tr><td>Resource</td><td>CannotDelete</td><td>$($resourcesLocksCannotDeleteCount) of $totalSubCount Subscriptions (total: $($resourcesLocksCannotDeleteCountTotal))</td></tr>
<tr><td>Resource</td><td>ReadOnly</td><td>$($resourcesLocksReadOnlyCount) of $totalSubCount Subscriptions (total: $($resourcesLocksReadOnlyCountTotal))</td></tr>
</tbody>
</table>
<script>
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@      
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
            }
            $htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@ 
        }
        $htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
            col_0: 'select',
            col_1: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'number'
            ],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
</div>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No Resource Locks at all <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources#considerations-before-applying-locks" target="_blank">docs <i class="fa fa-external-link" aria-hidden="true"></i></a></span></p>
"@
    }
    $endResourceLocks = get-date
    Write-Host "   ResourceLocks processing duration: $((NEW-TIMESPAN -Start $startResourceLocks -End $endResourceLocks).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startResourceLocks -End $endResourceLocks).TotalSeconds) seconds)"
    #endregion SUMMARYSubResourceLocks

    #region SUMMARYSubsapproachingLimitsResourceGroups
    Write-Host "  processing TenantSummary Subscriptions Limit Resource Groups"
    $subscriptionsApproachingLimitFromResourceGroupsAll = $resourceGroupsAll | Where-Object { $_.count_ -gt ($LimitResourceGroups * ($LimitCriticalPercentage / 100)) }
    if (($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count -gt 0) {
        $tfCount = ($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count
        $htmlTableId = "TenantSummary_SubsapproachingLimitsResourceGroups"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_SubsapproachingLimitsResourceGroups"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count) Subscriptions approaching Limit ($LimitResourceGroups) for ResourceGroups</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYSubsapproachingLimitsResourceGroups = foreach ($subscriptionApproachingLimitFromResourceGroupsAll in $subscriptionsApproachingLimitFromResourceGroupsAll) {
            $subscriptionData = $optimizedTableForPathQueryMgAndSub | Where-Object { $_.SubscriptionId -eq $subscriptionApproachingLimitFromResourceGroupsAll.subscriptionId } | Get-Unique
            @"
<tr>
<td><span class="valignMiddle">$($subscriptionData.subscription)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionData.MgId)">$($subscriptionData.subscriptionId)</a></span></td>
<td>$(($subscriptionApproachingLimitFromResourceGroupsAll.count_/$LimitResourceGroups).tostring("P")) ($($subscriptionApproachingLimitFromResourceGroupsAll.count_)/$($LimitResourceGroups))</td>
</tr>
"@
        }
        $htmlTenantSummary += $htmlSUMMARYSubsapproachingLimitsResourceGroups
        $htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p"><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count) Subscriptions approaching Limit ($LimitResourceGroups) for ResourceGroups</span></p>
"@
    }
    #endregion SUMMARYSubsapproachingLimitsResourceGroups

    #region SUMMARYSubsapproachingLimitsSubscriptionTags
    Write-Host "  processing TenantSummary Subscriptions Limit Subscription Tags"
    $subscriptionsApproachingLimitTags = ($optimizedTableForPathQueryMgAndSub | Where-Object { (($_.SubscriptionTagsCount -gt ($LimitTagsSubscription * ($LimitCriticalPercentage / 100)))) })
    if (($subscriptionsApproachingLimitTags | measure-object).count -gt 0) {
        $tfCount = ($subscriptionsApproachingLimitTags | measure-object).count
        $htmlTableId = "TenantSummary_SubsapproachingLimitsSubscriptionTags"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_SubsapproachingLimitsSubscriptionTags"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitTags | measure-object).count) Subscriptions approaching Limit ($LimitTagsSubscription) for Tags</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYSubsapproachingLimitsSubscriptionTags = foreach ($subscriptionApproachingLimitTags in $subscriptionsApproachingLimitTags) {
            @"
<tr>
<td><span class="valignMiddle">$($subscriptionApproachingLimitTags.subscription)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingLimitTags.MgId)">$($subscriptionApproachingLimitTags.subscriptionId)</a></span></td>
<td>$(($subscriptionApproachingLimitTags.SubscriptionTagsCount/$LimitTagsSubscription).tostring("P")) ($($subscriptionApproachingLimitTags.SubscriptionTagsCount)/$($LimitTagsSubscription))</td>
</tr>
"@
        }
        $htmlTenantSummary += $htmlSUMMARYSubsapproachingLimitsSubscriptionTags
        $htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$($subscriptionsApproachingLimitTags.count) Subscriptions approaching Limit ($LimitTagsSubscription) for Tags</span></p>
"@
    }
    #endregion SUMMARYSubsapproachingLimitsSubscriptionTags

    #region SUMMARYSubsapproachingLimitsPolicyAssignments
    Write-Host "  processing TenantSummary Subscriptions Limit PolicyAssignments"
    $subscriptionsApproachingLimitPolicyAssignments = (($policyBaseQuerySubscriptions | Where-Object { -not [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.PolicyAndPolicySetAssigmentAtScopeCount -gt 0 -and (($_.PolicyAndPolicySetAssigmentAtScopeCount -gt ($_.PolicyAssigmentLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, Subscription, SubscriptionId, PolicyAssigmentAtScopeCount, PolicySetAssigmentAtScopeCount, PolicyAndPolicySetAssigmentAtScopeCount, PolicyAssigmentLimit -Unique)
    if ($subscriptionsApproachingLimitPolicyAssignments.count -gt 0) {
        $tfCount = ($subscriptionsApproachingLimitPolicyAssignments | measure-object).count
        $htmlTableId = "TenantSummary_SubsapproachingLimitsPolicyAssignments"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_SubsapproachingLimitsPolicyAssignments"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyAssignments | measure-object).count) Subscriptions approaching Limit ($LimitPOLICYPolicyAssignmentsSubscription) for PolicyAssignment</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYSubsapproachingLimitsPolicyAssignments = foreach ($subscriptionApproachingLimitPolicyAssignments in $subscriptionsApproachingLimitPolicyAssignments) {
            @"
<tr>
<td><span class="valignMiddle">$($subscriptionApproachingLimitPolicyAssignments.subscription)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingLimitPolicyAssignments.MgId)">$($subscriptionApproachingLimitPolicyAssignments.subscriptionId)</a></span></td>
<td>$(($subscriptionApproachingLimitPolicyAssignments.PolicyAndPolicySetAssigmentAtScopeCount/$subscriptionApproachingLimitPolicyAssignments.PolicyAssigmentLimit).tostring("P")) ($($subscriptionApproachingLimitPolicyAssignments.PolicyAndPolicySetAssigmentAtScopeCount)/$($subscriptionApproachingLimitPolicyAssignments.PolicyAssigmentLimit)) ($($subscriptionApproachingLimitPolicyAssignments.PolicyAssigmentAtScopeCount) Policy Assignments, $($subscriptionApproachingLimitPolicyAssignments.PolicySetAssigmentAtScopeCount) PolicySet Assignments)</td>
</tr>
"@
        }
        $htmlTenantSummary += $htmlSUMMARYSubsapproachingLimitsPolicyAssignments
        $htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyAssignments | measure-object).count) Subscriptions ($LimitPOLICYPolicyAssignmentsSubscription) for PolicyAssignment</span></p>
"@
    }
    #endregion SUMMARYSubsapproachingLimitsPolicyAssignments

    #region SUMMARYSubsapproachingLimitsPolicyScope
    Write-Host "  processing TenantSummary Subscriptions Limit PolicyScope"
    $subscriptionsApproachingLimitPolicyScope = (($policyBaseQuerySubscriptions | Where-Object { -not [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.PolicyDefinitionsScopedCount -gt 0 -and (($_.PolicyDefinitionsScopedCount -gt ($_.PolicyDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, Subscription, SubscriptionId, PolicyDefinitionsScopedCount, PolicyDefinitionsScopedLimit -Unique)
    if (($subscriptionsApproachingLimitPolicyScope | measure-object).count -gt 0) {
        $tfCount = ($subscriptionsApproachingLimitPolicyScope | measure-object).count
        $htmlTableId = "TenantSummary_SubsapproachingLimitsPolicyScope"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_SubsapproachingLimitsPolicyScope"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyScope | measure-object).count) Subscriptions approaching Limit ($LimitPOLICYPolicyDefinitionsScopedSubscription) for Policy Scope</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYSubsapproachingLimitsPolicyScope = foreach ($subscriptionApproachingLimitPolicyScope in $subscriptionsApproachingLimitPolicyScope) {
            @"
<tr>
<td><span class="valignMiddle">$($subscriptionApproachingLimitPolicyScope.subscription)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingLimitPolicyScope.MgId)">$($subscriptionApproachingLimitPolicyScope.subscriptionId)</a></span></td>
<td>$(($subscriptionApproachingLimitPolicyScope.PolicyDefinitionsScopedCount/$subscriptionApproachingLimitPolicyScope.PolicyDefinitionsScopedLimit).tostring("P")) ($($subscriptionApproachingLimitPolicyScope.PolicyDefinitionsScopedCount)/$($subscriptionApproachingLimitPolicyScope.PolicyDefinitionsScopedLimit))</td>
</tr>
"@
        }
        $htmlTenantSummary += $htmlSUMMARYSubsapproachingLimitsPolicyScope
        $htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$($subscriptionsApproachingLimitPolicyScope.count) Subscriptions approaching Limit ($LimitPOLICYPolicyDefinitionsScopedSubscription) for Policy Scope</span></p>
"@
    }
    #endregion SUMMARYSubsapproachingLimitsPolicyScope

    #region SUMMARYSubsapproachingLimitsPolicySetScope
    Write-Host "  processing TenantSummary Subscriptions Limit PolicySetScope"
    $subscriptionsApproachingLimitPolicySetScope = (($policyBaseQuerySubscriptions | Where-Object { -not [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.PolicySetDefinitionsScopedCount -gt 0 -and (($_.PolicySetDefinitionsScopedCount -gt ($_.PolicySetDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, Subscription, SubscriptionId, PolicySetDefinitionsScopedCount, PolicySetDefinitionsScopedLimit -Unique)
    if ($subscriptionsApproachingLimitPolicySetScope.count -gt 0) {
        $tfCount = ($subscriptionsApproachingLimitPolicySetScope | measure-object).count
        $htmlTableId = "TenantSummary_SubsapproachingLimitsPolicySetScope"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_SubsapproachingLimitsPolicySetScope"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyScope | measure-object).count) Subscriptions approaching Limit ($LimitPOLICYPolicySetDefinitionsScopedSubscription) for PolicySet Scope</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYSubsapproachingLimitsPolicySetScope = foreach ($subscriptionApproachingLimitPolicySetScope in $subscriptionsApproachingLimitPolicySetScope) {
            @"
<tr>
<td><span class="valignMiddle">$($subscriptionApproachingLimitPolicySetScope.subscription)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingLimitPolicySetScope.MgId)">$($subscriptionApproachingLimitPolicySetScope.subscriptionId)</a></span></td>
<td>$(($subscriptionApproachingLimitPolicySetScope.PolicySetDefinitionsScopedCount/$subscriptionApproachingLimitPolicySetScope.PolicySetDefinitionsScopedLimit).tostring("P")) ($($subscriptionApproachingLimitPolicySetScope.PolicySetDefinitionsScopedCount)/$($subscriptionApproachingLimitPolicySetScope.PolicySetDefinitionsScopedLimit))</td>
</tr>
"@
        }
        $htmlTenantSummary += $htmlSUMMARYSubsapproachingLimitsPolicySetScope
        $htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyScope | measure-object).count) Subscriptions approaching Limit ($LimitPOLICYPolicySetDefinitionsScopedSubscription) for PolicySet Scope</span></p>
"@
    }
    #endregion SUMMARYSubsapproachingLimitsPolicySetScope

    #region SUMMARYSubsapproachingLimitsRoleAssignment
    Write-Host "  processing TenantSummary Subscriptions Limit RoleAssignments"
    $subscriptionsApproachingRoleAssignmentLimit = $rbacBaseQueryArrayList.Where( { -not [String]::IsNullOrEmpty($_.SubscriptionId) -and $_.RoleAssignmentsCount -gt ($_.RoleAssignmentsLimit * $LimitCriticalPercentage / 100) }) | Sort-Object -Property SubscriptionId -Unique | select-object -Property MgId, SubscriptionId, Subscription, RoleAssignmentsCount, RoleAssignmentsLimit
    
    if (($subscriptionsApproachingRoleAssignmentLimit | measure-object).count -gt 0) {
        $tfCount = ($subscriptionsApproachingRoleAssignmentLimit | measure-object).count
        $htmlTableId = "TenantSummary_SubsapproachingLimitsRoleAssignment"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_SubsapproachingLimitsRoleAssignment"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingRoleAssignmentLimit | measure-object).count) Subscriptions approaching Limit ($LimitRBACRoleAssignmentsSubscription) for RoleAssignment</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id= "$htmlTableId" class="summaryTable">
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
        $htmlSUMMARYSubsapproachingLimitsRoleAssignment = foreach ($subscriptionApproachingRoleAssignmentLimit in $subscriptionsApproachingRoleAssignmentLimit) {
            @"
<tr>
<td><span class="valignMiddle">$($subscriptionApproachingRoleAssignmentLimit.subscription)</span></td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($subscriptionApproachingRoleAssignmentLimit.MgId)">$($subscriptionApproachingRoleAssignmentLimit.subscriptionId)</a></span></td>
<td>$(($subscriptionApproachingRoleAssignmentLimit.RoleAssignmentsCount/$subscriptionApproachingRoleAssignmentLimit.RoleAssignmentsLimit).tostring("P")) ($($subscriptionApproachingRoleAssignmentLimit.RoleAssignmentsCount)/$($subscriptionApproachingRoleAssignmentLimit.RoleAssignmentsLimit))</td>
</tr>
"@
        }
        $htmlTenantSummary += $htmlSUMMARYSubsapproachingLimitsRoleAssignment
        $htmlTenantSummary += @"
        </tbody>
    </table>
    </div>
    <script>
        var tfConfig4$htmlTableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 50) {
                $spectrum = "10, 25, 50, $tfCount"
            }        
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, 100, $tfCount"
            }
            if ($tfCount -gt 500) {
                $spectrum = "10, 30, 50, 100, 250, $tfCount"
            }
            if ($tfCount -gt 1000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
            }
            if ($tfCount -gt 2000) {
                $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
            }
            if ($tfCount -gt 3000) {
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
        var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p"><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingRoleAssignmentLimit | measure-object).count) Subscriptions approaching Limit ($LimitRBACRoleAssignmentsSubscription) for RoleAssignment</span></p>
"@
    }
    #endregion SUMMARYSubsapproachingLimitsRoleAssignment

    $htmlTenantSummary += @"
    </div>
"@
    #endregion tenantSummarySubscriptions

    #region tenantSummaryAAD
    $htmlTenantSummary += @"
<button type="button" class="collapsible" id="tenantSummaryAAD"><hr class="hr-text" data-content="Azure Active Directory" /></button>
<div class="content">
"@   

    #region AADSPNotFound
    if (-not $NoAADServicePrincipalResolve) {
        Write-Host "  processing TenantSummary AAD ServicePrincipals - not found"

        if ($servicePrincipalRequestResourceNotFoundCount -gt 0){
            $tfCount = $servicePrincipalRequestResourceNotFoundCount
            $htmlTableId = "TenantSummary_AADSPNotFound"

            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_AADSPNotFound"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$($servicePrincipalRequestResourceNotFoundCount) AAD ServicePrincipals 'Request_ResourceNotFound'</span> <abbr title="API return: Request_ResourceNotFound"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Service Principal Object Id</th>
</tr>
</thead>
<tbody>
"@
            $htmlSUMMARYAADSPNotFound = $null
            $htmlSUMMARYAADSPNotFound = foreach ($serviceprincipal in $arrayServicePrincipalRequestResourceNotFound | Sort-Object) {
                
                @"
<tr>
<td>$($serviceprincipal)</td>
</tr>
"@
            }
            $htmlTenantSummary += $htmlSUMMARYAADSPNotFound
            $htmlTenantSummary += @"
    </tbody>
</table>
</div>
<script>
var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                $htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
            }
            $htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
    col_types: [
        'caseinsensitivestring'
    ],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();
</script>
"@
        }
        else{
            $htmlTenantSummary += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No ServicePrincipals where the API returned 'Request_ResourceNotFound'</span></p>
"@
        }
    }
    #endregion AADSPNotFound

    #region AADAppNotFound
    if (-not $NoAADServicePrincipalResolve) {
        Write-Host "  processing TenantSummary AAD Applications - not found"

        if ($applicationRequestResourceNotFoundCount -gt 0){
            $tfCount = $applicationRequestResourceNotFoundCount
            $htmlTableId = "TenantSummary_AADAppNotFound"

            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_AADAppNotFound"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$($applicationRequestResourceNotFoundCount) AAD Applications 'Request_ResourceNotFound'</span> <abbr title="API return: Request_ResourceNotFound"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>Application (Client) Id</th>
</tr>
</thead>
<tbody>
"@
            $htmlSUMMARYAADAppNotFound = $null
            $htmlSUMMARYAADAppNotFound = foreach ($app in $arrayApplicationRequestResourceNotFound | Sort-Object) {
                
                @"
<tr>
<td>$($app)</td>
</tr>
"@
            }
            $htmlTenantSummary += $htmlSUMMARYAADAppNotFound
            $htmlTenantSummary += @"
    </tbody>
</table>
</div>
<script>
var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
                }
                $htmlTenantSummary += @"
paging: {results_per_page: ['Records: ', [$spectrum]]},state: {types: ['local_storage'], filters: true, page_number: true, page_length: true, sort: true},
"@
            }
            $htmlTenantSummary += @"
btn_reset: true, highlight_keywords: true, alternate_rows: true, auto_filter: { delay: 1100 }, no_results_message: true,
    col_types: [
        'caseinsensitivestring'
    ],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();
</script>
"@
        }
        else{
            $htmlTenantSummary += @"
            <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No Applications where the API returned 'Request_ResourceNotFound'</span></p>
"@
        }
    }
    #endregion AADAppNotFound
    
    #region AADSPManagedIdentity
    if (-not $NoAADServicePrincipalResolve) {
        $startAADSPManagedIdentityLoop = get-date
        Write-Host "  processing TenantSummary AAD SP Managed Identities"   

        if ($servicePrincipalsOfTypeManagedIdentityCount -gt 0) {        
            $tfCount = $servicePrincipalsOfTypeManagedIdentityCount
            $htmlTableId = "TenantSummary_AADSPManagedIdentities"

            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_AADSPManagedIdentities"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$($servicePrincipalsOfTypeManagedIdentityCount) AAD ServicePrincipals type=ManagedIdentity</span> <abbr title="ServicePrincipals where a Role assignment exists &#13;(including ResourceGroups and Resources)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>ApplicationId</th>
<th>DisplayName</th>
<th>SP ObjectId</th>
<th>Usage</th>
<th>Usage info</th>
<th>Policy assigment details</th>
<th>Role Assignments</th>
</tr>
</thead>
<tbody>
"@
            $htmlSUMMARYAADSPManagedIdentities = $null
            $htmlSUMMARYAADSPManagedIdentities = foreach ($serviceprincipalApp in $servicePrincipalsOfTypeManagedIdentity | Sort-Object) {
                
                $miRoleAssignments = "n/a"
                $spAlternativeNames = $htServicePrincipalsDetails.($serviceprincipalApp).spGraphDetails.alternativeNames
                if ($spAlternativeNames -like "*/providers/Microsoft.Authorization/policyAssignments/*") {
                    $usage = "Policy Assignments"
                    $policyAssignmentId = $spAlternativeNames | Where-Object { $_ -like "*/providers/Microsoft.Authorization/policyAssignments/*" }

                    if ($policyAssignmentId -like "/providers/Microsoft.Management/managementGroups/*") {
                        if (-not ($htCacheAssignments2).policy.($policyAssignmentId)) {
                            $assignmentInfo = "n/a"
                        }
                        else {
                            $assignmentInfo = ($htCacheAssignments2).policy.($policyAssignmentId)
                        }
                    }
                    else {
                        #sub
                        if (((($policyAssignmentId).Split('/') | Measure-Object).Count - 1) -eq 6) {
                            if (-not ($htCacheAssignments2).policy.($policyAssignmentId)) {
                                $assignmentInfo = "n/a"
                            }
                            else {
                                $assignmentInfo = ($htCacheAssignments2).policy.($policyAssignmentId)
                            }
                        }
                        else {
                            #rg or res
                            if (-not ($htCacheAssignments).policyOnResourceGroupsAndResources.($policyAssignmentId)) {
                                $assignmentInfo = "n/a"
                            }
                            else {
                                $assignmentInfo = ($htCacheAssignments).policyOnResourceGroupsAndResources.($policyAssignmentId)
                            }
                        }
                    }

                    if ($assignmentinfo -ne "n/a") {
                        if ($assignmentInfo.PolicyDefinitionId -like "*/providers/Microsoft.Authorization/policyDefinitions/*") {
                            $policyAssignmentsPolicyVariant = "Policy"
                            $policyAssignmentsPolicyVariant4ht = "policy"
                            $linkHelper = "azpolicyadvertizer"
                        }
                        if ($assignmentInfo.PolicyDefinitionId -like "*/providers/Microsoft.Authorization/policySetDefinitions/*") {
                            $policyAssignmentsPolicyVariant = "PolicySet"
                            $policyAssignmentsPolicyVariant4ht = "policySet"
                            $linkHelper = "azpolicyinitiativesadvertizer"
                        }
                        $policyAssignmentspolicyDefinitionIdGuid = $assignmentInfo.PolicyDefinitionIdGuid
                        $policyAssignmentsPolicyDefinitionId = $assignmentInfo.PolicyDefinitionId
                        $definitionInfo = ($htCacheDefinitions).($policyAssignmentsPolicyVariant4ht).($assignmentInfo.PolicyDefinitionId)
                        if ($definitionInfo.type -eq "BuiltIn") {
                            #$policyAssignmentMoreInfo = "$($definitionInfo.Type) $($policyAssignmentsPolicyVariant): <a class=`"externallink`" href=`"https://www.azadvertizer.net/$($linkHelper)/$($policyAssignmentspolicyDefinitionIdGuid).html`" target=`"_blank`">$($definitionInfo.displayname)</a> ($policyAssignmentspolicyDefinitionIdGuid)"
                            $policyAssignmentMoreInfo = "$($definitionInfo.Type) $($policyAssignmentsPolicyVariant): $($definitionInfo.LinkToAzAdvertizer) ($policyAssignmentspolicyDefinitionIdGuid)"
                        }
                        else {
                            $policyAssignmentMoreInfo = "$($definitionInfo.Type) $($policyAssignmentsPolicyVariant): <b>$($definitionInfo.DisplayName)</b> ($($policyAssignmentsPolicyDefinitionId))"
                        }
                    }
                    else {
                        $policyAssignmentMoreInfo = "n/a"
                    }
                }
                else {
                    $usage = "Unknown"
                    $policyAssignmentMoreInfo = "n/a"
                    $miRoleAssignments = "not evaluated if 'Usage info' is 'unknown'"
                }

                if ($htPolicyAssignmentMiRoleAssignmentMappingAll.($serviceprincipalApp)) {
                    $arrayMiRoleAssignments = @()
                    $helperMiRoleAssignments = $htPolicyAssignmentMiRoleAssignmentMappingAll.($serviceprincipalApp).roleassignments
                    foreach ($roleAssignment in $helperMiRoleAssignments) {
                        if ($roleAssignment.roleDefinitionType -eq "builtin") {
                            #$arrayMiRoleAssignments += "$($roleAssignment.roleassignmentId) (<a class=`"externallink`" href=`"https://www.azadvertizer.net/azrolesadvertizer/$($roleAssignment.roleDefinitionId).html`" target=`"_blank`">$($roleAssignment.roleDefinitionName)</a>)"  
                            $arrayMiRoleAssignments += "$($roleAssignment.roleassignmentId) ($(($htCacheDefinitions).role.($roleAssignment.roleDefinitionId).LinkToAzAdvertizer))"
                        }
                        else {
                            $arrayMiRoleAssignments += "$($roleAssignment.roleassignmentId) (<b>$roleAssignment.roleDefinitionName</b>; $roleAssignment.roleDefinitionId)"
                        }
                    }
                    $miRoleAssignments = "$(($arrayMiRoleAssignments | Measure-Object).Count) ($($arrayMiRoleAssignments -join ", "))"
                }
                
                @"
<tr>
<td>$($htServicePrincipalsDetails.($serviceprincipalApp).spGraphDetails.appId)</td>
<td>$($htServicePrincipalsDetails.($serviceprincipalApp).spGraphDetails.displayName)</td>
<td class="breakwordall">$($htServicePrincipalsDetails.($serviceprincipalApp).spGraphDetails.id)</td>
<td>$usage</td>
<td class="breakwordall">$($htServicePrincipalsDetails.($serviceprincipalApp).spGraphDetails.alternativeNames -join ", ")</td>
<td class="breakwordall">$policyAssignmentMoreInfo</td>
<td class="breakwordall">$($miRoleAssignments)</td>
</tr>
"@
            }
            $htmlTenantSummary += $htmlSUMMARYAADSPManagedIdentities
            $htmlTenantSummary += @"
    </tbody>
</table>
</div>
<script>
var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
        'caseinsensitivestring'
    ],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();
</script>
"@
        }
        else {
            $htmlTenantSummary += @"
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$servicePrincipalsOfTypeManagedIdentityCount AAD ServicePrincipals type=ManagedIdentity</span></p>
"@
        }

        $endAADSPManagedIdentityLoop = get-date
        Write-Host "   TenantSummary AAD SP Managed Identities processing duration: $((NEW-TIMESPAN -Start $startAADSPManagedIdentityLoop -End $endAADSPManagedIdentityLoop).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startAADSPManagedIdentityLoop -End $endAADSPManagedIdentityLoop).TotalSeconds) seconds)"

    }
    else {
        $htmlTenantSummary += @"
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No information on AAD ServicePrincipals type=ManagedIdentity as parameter -NoAADServicePrincipalResolve was applied</span></p>
"@
    }
    #endregion AADSPManagedIdentity

    #region AADSPCredExpiry
    if (-not $NoAADServicePrincipalResolve) {
        $startAADSPCredExpiryLoop = get-date
        Write-Host "  processing TenantSummary AAD SP Apps CredExpiry"

        $servicePrincipalsOfTypeApplication = $htServicePrincipalsDetails.Keys | Where-Object { $htServicePrincipalsDetails.($_).servicePrincipalType -eq "Application" -and $htServicePrincipalsDetails.($_).appOwnerOrganizationId -eq $checkContext.Subscription.TenantId }
        $servicePrincipalsOfTypeApplicationCount = ($servicePrincipalsOfTypeApplication | Measure-Object).Count

        if ($servicePrincipalsOfTypeApplicationCount -gt 0) {
            $tfCount = $servicePrincipalsOfTypeApplicationCount
            $htmlTableId = "TenantSummary_AADSPCredExpiry"

            $servicePrincipalsOfTypeApplicationSecretsExpiring = $servicePrincipalsOfTypeApplication | Where-Object { $htServicePrincipalsDetails.($_).appPasswordCredentialsGracePeriodExpiryCount -gt 0 }
            $servicePrincipalsOfTypeApplicationSecretsExpiringCount = ($servicePrincipalsOfTypeApplicationSecretsExpiring | Measure-Object).Count
            $servicePrincipalsOfTypeApplicationCertificatesExpiring = $servicePrincipalsOfTypeApplication | Where-Object { $htServicePrincipalsDetails.($_).appKeyCredentialsGracePeriodExpiryCount -gt 0 }
            $servicePrincipalsOfTypeApplicationCertificatesExpiringCount = ($servicePrincipalsOfTypeApplicationCertificatesExpiring | Measure-Object).Count
            if ($servicePrincipalsOfTypeApplicationSecretsExpiringCount -gt 0 -or $servicePrincipalsOfTypeApplicationCertificatesExpiringCount -gt 0) {
                $warningOrNot = "<i class=`"fa fa-exclamation-triangle yellow`" aria-hidden=`"true`"></i>"
            }
            else {
                $warningOrNot = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
            }
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_AADSPCredExpiry">$warningOrNot <span class="valignMiddle">$($servicePrincipalsOfTypeApplicationCount) AAD ServicePrincipals type=Application | $servicePrincipalsOfTypeApplicationSecretsExpiringCount Secrets expire < $($AADServicePrincipalExpiryWarningDays)d | $servicePrincipalsOfTypeApplicationCertificatesExpiringCount Certificates expire < $($AADServicePrincipalExpiryWarningDays)d</span> <abbr title="ServicePrincipals where a Role assignment exists &#13;(including ResourceGroups and Resources)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>ApplicationId</th>
<th>DisplayName</th>
<th>Notes</th>
<th>SP ObjectId</th>
<th>App ObjectId</th>
<th>Secrets</th>
<th>Secrets expired</th>
<th>Secrets expiry<br><$($AADServicePrincipalExpiryWarningDays)d</th>
<th>Secrets expiry<br>>$($AADServicePrincipalExpiryWarningDays)d & <2y</th>
<th>Secrets expiry<br>>2y</th>
<th>Certs</th>
<th>Certs expired</th>
<th>Certs expiry<br><$($AADServicePrincipalExpiryWarningDays)d</th>
<th>Certs expiry<br>>$($AADServicePrincipalExpiryWarningDays)d & <2y</th>
<th>Certs expiry<br>>2y</th>
</tr>
</thead>
<tbody>
"@
            $htmlSUMMARYAADSPCredExpiry = $null
            $htmlSUMMARYAADSPCredExpiry = foreach ($serviceprincipalApp in $servicePrincipalsOfTypeApplication | Sort-Object) {
                @"
<tr>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.spGraphDetails.appId)</td>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.spGraphDetails.displayName)</td>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.spGraphDetails.notes)</td>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.spGraphDetails.id)</td>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.appGraphDetails.id)</td>
"@
                if ($htServicePrincipalsDetails.$serviceprincipalApp.appPasswordCredentialsCount) {
                    @"
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.appPasswordCredentialsCount)</td>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.appPasswordCredentialsExpiredCount)</td>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.appPasswordCredentialsGracePeriodExpiryCount)</td>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.appPasswordCredentialsExpiryOKCount)</td>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.appPasswordCredentialsExpiryOKMoreThan2YearsCount)</td>
"@ 
                }
                else {
                    @"
<td>0</td>
<td>0</td>
<td>0</td>
<td>0</td>
<td>0</td>
"@ 
                }

                if ($htServicePrincipalsDetails.$serviceprincipalApp.appKeyCredentialsCount) {
                    @"
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.appKeyCredentialsCount)</td>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.appKeyCredentialsExpiredCount)</td>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.appKeyCredentialsGracePeriodExpiryCount)</td>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.appKeyCredentialsExpiryOKCount)</td>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.appKeyCredentialsExpiryOKMoreThan2YearsCount)</td>
"@ 
                }
                else {
                    @"
<td>0</td>
<td>0</td>
<td>0</td>
<td>0</td>
<td>0</td>
"@ 
                }

                @"
</tr>
"@
            }
            $htmlTenantSummary += $htmlSUMMARYAADSPCredExpiry
            $htmlTenantSummary += @"
    </tbody>
</table>
</div>
<script>
var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number',
        'number'
    ],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();
</script>
"@
        }
        else {
            $htmlTenantSummary += @"
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$servicePrincipalsOfTypeApplicationCount AAD ServicePrincipals type=Application</span></p>
"@
        }

        $endAADSPCredExpiryLoop = get-date
        Write-Host "   TenantSummary AAD SP Apps CredExpiry processing duration: $((NEW-TIMESPAN -Start $startAADSPCredExpiryLoop -End $endAADSPCredExpiryLoop).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startAADSPCredExpiryLoop -End $endAADSPCredExpiryLoop).TotalSeconds) seconds)"

    }
    else {
        $htmlTenantSummary += @"
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No information on AAD ServicePrincipals type=Application as parameter -NoAADServicePrincipalResolve was applied</span></p>
"@
    }
    #endregion AADSPCredExpiry

    #region AADSPExternalSP
    if (-not $NoAADServicePrincipalResolve) {
        Write-Host "  processing TenantSummary AAD External ServicePrincipals"
        $startAADSPExternalSP = get-date
  
        $htRoleAssignmentsForServicePrincipals = @{ }
        $roleAssignmentsForServicePrincipals = (($newTable | Where-Object { $_.RoleAssignmentIdentityObjectType -eq "ServicePrincipal" } ) | sort-object -Property RoleAssignmentId -Unique)
        foreach ($spWithRoleAssignment in $roleAssignmentsForServicePrincipals | Group-Object -Property RoleAssignmentIdentityObjectId) {
            if (-not $htRoleAssignmentsForServicePrincipals.($spWithRoleAssignment.Name)) {
                $htRoleAssignmentsForServicePrincipals.($spWithRoleAssignment.Name) = @{ }
                $htRoleAssignmentsForServicePrincipals.($spWithRoleAssignment.Name).RoleAssignments = $spWithRoleAssignment.group
            }
        }

        $htRoleAssignmentsForServicePrincipalsRgRes = @{ }
        $roleAssignmentsForServicePrincipalsRgRes = (($arrayCacheRoleAssignmentsResourceGroups | Where-Object { $_.ObjectType -eq "ServicePrincipal" } ) | sort-object -Property RoleAssignmentId -Unique)
        foreach ($spWithRoleAssignment in $roleAssignmentsForServicePrincipalsRgRes | Group-Object -Property ObjectId) {
            if (-not $htRoleAssignmentsForServicePrincipalsRgRes.($spWithRoleAssignment.Name)) {
                $htRoleAssignmentsForServicePrincipalsRgRes.($spWithRoleAssignment.Name) = @{ }
                $htRoleAssignmentsForServicePrincipalsRgRes.($spWithRoleAssignment.Name).RoleAssignments = $spWithRoleAssignment.group
            }
        }

        $appsWithOtherOrgId = $htServicePrincipalsDetails.Keys | Where-Object { $htServicePrincipalsDetails.($_).servicePrincipalType -eq "Application" -and $htServicePrincipalsDetails.($_).appOwnerOrganizationId -ne $checkContext.Subscription.TenantId }
        $appsWithOtherOrgIdCount = ($appsWithOtherOrgId | Measure-Object).Count

        if ($appsWithOtherOrgIdCount -gt 0) {     
            $tfCount = $appsWithOtherOrgIdCount
            $htmlTableId = "TenantSummary_AADSPExternal"

            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_AADSPExternal"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$($appsWithOtherOrgIdCount) External (appOwnerOrganizationId) AAD ServicePrincipals type=Application</span> <abbr title="External (appOwnerOrganizationId != $($checkContext.Subscription.TenantId)) ServicePrincipals where a Role assignment exists &#13;(including ResourceGroups and Resources)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>ApplicationId</th>
<th>DisplayName</th>
<th>SP ObjectId</th>
<th>OrganizationId</th>
<th>Role Assignments <abbr title="Lists only RoleAssignmentIds for scope RG/Resource &#13;Check TenantSummary/RBAC to find the RoleAssignmentIds for MG/Sub scopes"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></th>
</tr>
</thead>
<tbody>
"@
            $htmlSUMMARYAADSPExternal = $null
            $htmlSUMMARYAADSPExternal = foreach ($serviceprincipalApp in $appsWithOtherOrgId | Sort-Object) {
                $arrayRoleAssignments4ExternalApp = [System.Collections.ArrayList]@()
                $roleAssignmentsMgSub = $htRoleAssignmentsForServicePrincipals.($serviceprincipalApp).RoleAssignments
                $roleAssignmentsMgSubCount = ($roleAssignmentsMgSub | Measure-Object).Count
                $roleAssignments4ExternalApp = "n/a"
                if ($roleAssignmentsMgSubCount -gt 0) {
                    $roleAssignments4ExternalApp = $roleAssignmentsMgSubCount
                }
                $roleAssignmentsRgRes = $roleAssignmentsForServicePrincipalsRgRes | where-object { $_.ObjectId -eq $serviceprincipalApp }
                $roleAssignmentsRgRes = $htRoleAssignmentsForServicePrincipalsRgRes.($serviceprincipalApp).RoleAssignments
                $roleAssignmentsRgResCount = ($roleAssignmentsRgRes | Measure-Object).Count
                if ($roleAssignmentsRgResCount -gt 0) {
                    foreach ($roleAssignmentRgRes in $roleAssignmentsRgRes) {
                        $null = $arrayRoleAssignments4ExternalApp.Add([PSCustomObject]@{
                                roleAssignmentId = $roleAssignmentRgRes.RoleAssignmentId
                            })
                    }
                    $roleAssignments4ExternalApp = "$roleAssignmentsRgResCount ($($arrayRoleAssignments4ExternalApp.roleAssignmentId -join ", "))"
                }
                
                @"
<tr>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.spGraphDetails.appId)</td>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.spGraphDetails.displayName)</td>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.spGraphDetails.id)</td>
<td>$($htServicePrincipalsDetails.($serviceprincipalApp).spGraphDetails.appOwnerOrganizationId)</td>
<td>$roleAssignments4ExternalApp</td>
</tr>
"@
            }
            $htmlTenantSummary += $htmlSUMMARYAADSPExternal
            $htmlTenantSummary += @"
    </tbody>
</table>
</div>
<script>
var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();
</script>
"@
        }
        else {
            $htmlTenantSummary += @"
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$appsWithOtherOrgIdCount External (appOwnerOrganizationId) AAD ServicePrincipals type=Application</span></p>
"@
        }

        $endAADSPExternalSP = get-date
        Write-Host "   TenantSummary AAD External ServicePrincipals processing duration: $((NEW-TIMESPAN -Start $startAADSPExternalSP -End $endAADSPExternalSP).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startAADSPExternalSP -End $endAADSPExternalSP).TotalSeconds) seconds)"

    }
    else {
        $htmlTenantSummary += @"
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No information on External (appOwnerOrganizationId) AAD ServicePrincipals type=Application as parameter -NoAADServicePrincipalResolve was applied</span></p>
"@
    }

    #endregion AADSPExternalSP

    $htmlTenantSummary += @"
</div>
"@
    #endregion tenantSummaryAAD

    #region tenantSummary Consumption
    $htmlTenantSummary += @"
    <button type="button" class="collapsible" id="tenantSummaryAAD"><hr class="hr-text" data-content="Consumption" /></button>
    <div class="content">
    <i class="fa fa-lightbulb-o" aria-hidden="true" style="color:#FFB100;"></i> <b>Customize your Azure environment optimizations (Cost, Reliability & more) with</b> <a class="externallink" href="https://github.com/helderpinto/AzureOptimizationEngine" target="_blank">Azure Optimization Engine (AOE) <i class="fa fa-external-link" aria-hidden="true"></i></a>
"@  

    if ($htParameters.NoAzureConsumption -eq $false) {
        $startConsumption = get-date
        Write-Host "  processing TenantSummary Consumption"

        if (($arrayConsumptionData | Measure-Object).Count -gt 0) {
            $tfCount = ($arrayConsumptionData | Measure-Object).Count
            $htmlTableId = "TenantSummary_Consumption"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="buttonTenantSummary_Consumption"><i class="fa fa-credit-card" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">Total cost $($arrayTotalCostSummary -join "$CsvDelimiterOpposite ") last $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$htmlTableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$htmlTableId');">comma</a>
<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>ChargeType</th>
<th>ResourceType</th>
<th>Category</th>
<th>ResourceCount</th>
<th>Cost ($($AzureConsumptionPeriod)d)</th>
<th>Currency</th>
<th>Subscriptions</th>
</tr>
</thead>
<tbody>
"@
            $htmlSUMMARYConsumption = $null
            $htmlSUMMARYConsumption = foreach ($consumptionLine in $arrayConsumptionData) {
                @"
<tr>
<td>$($consumptionLine.ConsumedServiceChargeType)</td>
<td>$($consumptionLine.ConsumedService)</td>
<td>$($consumptionLine.ConsumedServiceCategory)</td>
<td>$($consumptionLine.ConsumedServiceInstanceCount)</td>
<td>$($consumptionLine.ConsumedServiceCost)</td>
<td>$($consumptionLine.ConsumedServiceCurrency)</td>
<td>$($consumptionLine.ConsumedServiceSubscriptions)</td>
</tr>
"@
            }
            $htmlTenantSummary += $htmlSUMMARYConsumption
            $htmlTenantSummary += @"
</tbody>
</table>
</div>
<script>
var tfConfig4$htmlTableId = {
base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 50) {
                    $spectrum = "10, 25, 50, $tfCount"
                }        
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, 100, $tfCount"
                }
                if ($tfCount -gt 500) {
                    $spectrum = "10, 30, 50, 100, 250, $tfCount"
                }
                if ($tfCount -gt 1000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
                }
                if ($tfCount -gt 2000) {
                    $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
                }
                if ($tfCount -gt 3000) {
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
    'number',
    'number',
    'caseinsensitivestring',
    'number'
],
extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();
</script>
"@
        }
        else {
            $htmlTenantSummary += @"
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No information on Consumption</span></p>
"@
        }

        $endConsumption = get-date
        Write-Host "   TenantSummary Consumption processing duration: $((NEW-TIMESPAN -Start $startConsumption -End $endConsumption).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startConsumption -End $endConsumption).TotalSeconds) seconds)"

    }
    else {
        $htmlTenantSummary += @"
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No information on Consumption as parameter -NoAzureConsumption was applied</span></p>
"@
    }

    $htmlTenantSummary += @"
</div>
"@
    #endregion tenantSummary Consumption

    $script:html += $htmlTenantSummary
    $htmlTenantSummary = $null
    $script:html | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
    $script:html = $null

}
#endregion TenantSummary

#region DefinitionInsights
function definitionInsights() {
    $startDefinitionInsights = get-date
    Write-Host " Building DefinitionInsights"

    #region definitionInsightsAzurePolicy
    $htmlDefinitionInsights += @"
    <button type="button" class="collapsible" id="definitionInsights_AzurePolicy"><hr class="hr-text-definitionInsights" data-content="Policy" /></button>
    <div class="content contentDefinitionInsights">
"@

    #policy/policySet preQuery
    $htPolicyWithAssignments = @{ }
    $htPolicyWithAssignments.policy = @{ }
    $htPolicyWithAssignments.policySet = @{ }

    foreach ($policyOrPolicySet in $policyAssignmentsAllArray | sort-object -Property PolicyAssignmentId -Unique | group-object -property PolicyId, PolicyVariant) {
        $policyOrPolicySetNameSplit = $policyOrPolicySet.name -split ', '
        if ($policyOrPolicySetNameSplit[1] -eq "Policy") {
            #policy
            if (-not ($htPolicyWithAssignments).policy.($policyOrPolicySetNameSplit[0])) {
                $pscustomObj = [System.Collections.ArrayList]@()
                $null = $pscustomObj.Add([PSCustomObject]@{ 
                    PolicyAssignmentId             = $policyOrPolicySet.group.PolicyAssignmentId
                    PolicyAssignmentDisplayName    = $policyOrPolicySet.group.PolicyAssignmentDisplayName
                })
                ($htPolicyWithAssignments).policy.($policyOrPolicySetNameSplit[0]) = @{ }
                ($htPolicyWithAssignments).policy.($policyOrPolicySetNameSplit[0]).Assignments = [array]($pscustomObj)
            }
        }
        else {
            #policySet
            if (-not ($htPolicyWithAssignments).policySet.($policyOrPolicySetNameSplit[0])) {
                $pscustomObj = [System.Collections.ArrayList]@()
                $null = $pscustomObj.Add([PSCustomObject]@{ 
                    PolicyAssignmentId             = $policyOrPolicySet.group.PolicyAssignmentId
                    PolicyAssignmentDisplayName    = $policyOrPolicySet.group.PolicyAssignmentDisplayName
                })
                ($htPolicyWithAssignments).policySet.($policyOrPolicySetNameSplit[0]) = @{ }
                ($htPolicyWithAssignments).policySet.($policyOrPolicySetNameSplit[0]).Assignments = [array]($pscustomObj)
            }
        }
    }

    foreach ($customPolicy in $customPoliciesArray){
        if ($htPoliciesWithAssignmentOnRgRes.($customPolicy.PolicyDefinitionId)) {
            if (-not ($htPolicyWithAssignments).policy.($customPolicy.PolicyDefinitionId)) {
                ($htPolicyWithAssignments).policy.($customPolicy.PolicyDefinitionId) = @{ }
                ($htPolicyWithAssignments).policy.($customPolicy.PolicyDefinitionId).Assignments = [array]($htPoliciesWithAssignmentOnRgRes.($customPolicy.PolicyDefinitionId).Assignments)
            }
            else{
                $array = @()
                $array += ($htPolicyWithAssignments).policy.($customPolicy.PolicyDefinitionId).Assignments
                $array += $htPoliciesWithAssignmentOnRgRes.($customPolicy.PolicyDefinitionId).Assignments
                ($htPolicyWithAssignments).policy.($customPolicy.PolicyDefinitionId).Assignments = $array
            }
        }
    }

    foreach ($customPolicySet in $customPolicySetsArray){
        if ($htPoliciesWithAssignmentOnRgRes.($customPolicySet.PolicyDefinitionId)) {
            if (-not ($htPolicyWithAssignments).policySet.($customPolicySet.PolicyDefinitionId)) {
                ($htPolicyWithAssignments).policySet.($customPolicySet.PolicyDefinitionId) = @{ }
                ($htPolicyWithAssignments).policySet.($customPolicySet.PolicyDefinitionId).Assignments = [array]($htPoliciesWithAssignmentOnRgRes.($customPolicySet.PolicyDefinitionId).Assignments)
            }
            else{
                $array = @()
                $array += ($htPolicyWithAssignments).policySet.($customPolicySet.PolicyDefinitionId).Assignments
                $array += $htPoliciesWithAssignmentOnRgRes.($customPolicySet.PolicyDefinitionId).Assignments
                ($htPolicyWithAssignments).policySet.($customPolicySet.PolicyDefinitionId).Assignments = $array
            }
        }
    }

    #region definitionInsightsPolicyDefinitions
    $tfCount = $tenantAllPoliciesCount
    $htmlTableId = "definitionInsights_Policy"
    $htmlDefinitionInsights += @"
<button onclick="loadtf$htmlTableId()" type="button" class="collapsible" id="button_definitionInsights_Policy"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantAllPoliciesCount Policy definitions</span></button>
<div class="content contentDefinitionInsights">

<div id="extGridPolicy" class="panel panel-info pull-left" >
    <div class="panel-body bg-info">
        <div class="me">
            <label>Search JSON</label>
            <span id="polJson"></span>
        </div>

        <div class="me">
            <label>Builtin/Custom</label>
            <span id="polType"></span>
        </div>

        <div class="me">
            <label>Category</label>
            <span id="polCategory"></span>
        </div>

        <div class="me">
            <label>Deprecated</label>
            <span id="polDeprecated"></span>
        </div>

        <div class="me">
            <label>Preview</label>
            <span id="polPreview"></span>
        </div>

        <div class="me">
            <label>Scope Mg/Sub</label>
            <span id="polScope"></span>
        </div>

        <div class="me">
            <label>Scope Name/Id</label>
            <span id="polScopeNameId"></span>
        </div>

        <div class="me">
            <label>Effect default</label>
            <span id="polEffectDefaultValue"></span>
        </div>

        <div class="me">
            <label>hasAssignment</label>
            <span id="polHasAssignment"></span>
        </div>

        <div class="me" style="display: none;">
            <label>polPolAssignments</label>
            <span id="polPolAssignments"></span>
        </div>

        <div class="me" style="display: none;">
            <label>polhid1</label>
            <span id="polhid1"></span>
        </div>

        <div class="me">
            <label>usedInPolicySet</label>
            <span id="polUsedInPolicySet"></span>
        </div>

        <div class="me" style="display: none;">
            <label>polUsedInPolicySetCount</label>
            <span id="polUsedInPolicySetCount"></span>
        </div>

        <div class="me" style="display: none;">
            <label>polUsedInPolicySets</label>
            <span id="polUsedInPolicySets"></span>
        </div>

        <div class="me">
            <label>Roles</label>
            <span id="polRoledefs"></span>
        </div>

    </div>
</div>
  
<div class="pull-left" style="margin-left: 0.5em;">

<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>JSON</th>
<th>PolicyType</th>
<th>Category</th>
<th>Deprecated</th>
<th>Preview</th>
<th>Scope Mg/Sub</th>
<th>Scope Name/Id</th>
<th>effectDefaultValue</th>
<th>hasAssignments</th>
<th>Assignments Count</th>
<th>Assignments</th>
<th>UsedInPolicySet</th>
<th>PolicySetsCount</th>
<th>PolicySets</th>
<th>Roles</th>
</tr>
</thead>
<tbody>
"@
    $htmlDefinitionInsightshlp = $null
    $htmlDefinitionInsightshlp = foreach ($policy in ($allPoliciesArray | Sort-Object @{Expression = { $_.DisplayName } }, @{Expression = { $_.PolicyDefinitionId } })) {
        $hasAssignments = "false"
        $assignmentsCount = 0
        $assignmentsDetailed = "n/a"
        
        if (($htPolicyWithAssignments).policy.($policy.PolicyDefinitionId)) {
            $hasAssignments = "true"
            $assignments = ($htPolicyWithAssignments).policy.($policy.PolicyDefinitionId).Assignments
            $assignmentsCount = ($assignments | Measure-Object).Count
            
            if ($assignmentsCount -gt 0) {
                $arrayAssignmentDetails = @()
                $arrayAssignmentDetails = foreach ($assignment in $assignments) {
                    if ($assignment.PolicyAssignmentDisplayName -eq ""){
                        $polAssDisplayName = "<i>#no AssignmentName given</i>"
                    }
                    else{
                        $polAssDisplayName = $assignment.PolicyAssignmentDisplayName
                    }
                    "$($assignment.PolicyAssignmentId) (<b>$($polAssDisplayName)</b>)"
                }
                $assignmentsDetailed = $arrayAssignmentDetails -join "$CsvDelimiterOpposite "
            }
            
        }

        $roleDefinitionIds = "n/a"
        if ($policy.RoleDefinitionIds -ne "n/a") {
            $arrayRoleDefDetails = @()
            $arrayRoleDefDetails = foreach ($roleDef in $policy.RoleDefinitionIds) {
                $roleDefIdOnly = $roleDef -replace ".*/"
                if (($roleDefIdOnly).Length -ne 36){
                    "'INVALID RoleDefId!' ($($roleDefIdOnly))"
                }
                else{
                    $roleDefHlp = ($htCacheDefinitions).role.($roleDefIdOnly)
                    "'$($roleDefHlp.Name)' ($($roleDefHlp.id))"
                }
            }
            $roleDefinitionIds = $arrayRoleDefDetails -join "$CsvDelimiterOpposite "
        }

        $scopeDetails = "n/a"
        if ($policy.ScopeId -ne "n/a") {
            $scopeDetails = "$($policy.ScopeId) ($($htEntities.($policy.ScopeId).DisplayName))"
        }

        $usedInPolicySet = "false"
        $usedInPolicySetCount = 0
        $usedInPolicySets = "n/a"
    
        if ($htPoliciesUsedInPolicySets.($policy.PolicyDefinitionId)){
            $usedInPolicySet = "true"
            $usedInPolicySetCount = ($htPoliciesUsedInPolicySets.($policy.PolicyDefinitionId).policySet).Count
            $usedInPolicySets = ($htPoliciesUsedInPolicySets.($policy.PolicyDefinitionId).policySet) -join "$CsvDelimiterOpposite "
        }

        @"
<tr>
<td><pre class="precode"><code class="language-json hljs">$($policy.json | convertto-json -depth 99)</code></pre></td>
<td>$($policy.Type)</td>
<td>$($policy.Category)</td>
<td>$($policy.Deprecated)</td>
<td>$($policy.Preview)</td>
<td>$($policy.ScopeMgSub)</td>
<td>$scopeDetails</td>
<td>$($policy.effectDefaultValue)</td>
<td>$hasAssignments</td>
<td>$assignmentsCount</td>
<td class="breakwordall">$assignmentsDetailed</td>
<td class="breakwordall">$usedInPolicySet</td>
<td class="breakwordall">$usedInPolicySetCount</td>
<td class="breakwordall">$usedInPolicySets</td>
<td class="breakwordall">$roleDefinitionIds</td>
</tr>
"@ 
    }
    $htmlDefinitionInsights += $htmlDefinitionInsightshlp
    $htmlDefinitionInsights | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
    $htmlDefinitionInsights = $null
    $htmlDefinitionInsights += @"
    </tbody>
</table>
</div>
<script>
function loadtf$htmlTableId() { if (window.helpertfConfig4$htmlTableId !== 1) { 
    window.helpertfConfig4$htmlTableId =1;
    var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,       
"@      
    if ($tfCount -gt 10) {
        $spectrum = "10, $tfCount"
        if ($tfCount -gt 50) {
            $spectrum = "10, 25, 50, $tfCount"
        }        
        if ($tfCount -gt 100) {
            $spectrum = "10, 30, 50, 100, $tfCount"
        }
        if ($tfCount -gt 500) {
            $spectrum = "10, 30, 50, 100, 250, $tfCount"
        }
        if ($tfCount -gt 1000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
        }
        if ($tfCount -gt 2000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
        }
        if ($tfCount -gt 3000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
        }
        $htmlDefinitionInsights += @"
        paging: {
            results_per_page: [
                'Records: ', 
                [$spectrum]
            ]
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
    $htmlDefinitionInsights += @"
    btn_reset: true, 
    highlight_keywords: true, 
    alternate_rows: true, 
    auto_filter: { 
        delay: 1100 
    },
    linked_filters: true,
    no_results_message: true,
    rows_counter: {
        text: 'results: '
    },
    col_1: 'select',
    col_2: 'select',
    col_3: 'select',
    col_4: 'select',
    col_5: 'select',
    col_7: 'select',
    col_8: 'select',
    col_11: 'select',
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
        'number',
        'caseinsensitivestring',
        'number',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring'
    ],
    external_flt_ids: [
        'polJson',
        'polType',
        'polCategory',
        'polDeprecated',
        'polPreview',
        'polScope',
        'polScopeNameId',
        'polEffectDefaultValue',
        'polHasAssignment',
        'polPolAssignments',
        'polhid1',
        'polUsedInPolicySet',
        'polUsedInPolicySetCount',
        'polUsedInPolicySets',
        'polRoledefs'
    ],
    watermark: ['', '','', '', '', '', '', '', '', '','','','','', 'try: \'Contributor\''],
    extensions: [
        { 
            name: 'sort' 
        },
        {
            name: 'colsVisibility',
            at_start: [1,2,3,4,5,6,7,8,9,10,11,12,13,14],
            text: 'Columns: ',
            enable_tick_all: true
        }
    ]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
</div>
"@
    #endregion definitionInsightsPolicyDefinitions

    #region definitionInsightsPolicySetDefinitions
    $tfCount = $tenantAllPolicySetsCount
    $htmlTableId = "definitionInsights_PolicySet"
    $htmlDefinitionInsights += @"
<button type="button" onclick="loadtf$htmlTableId()" class="collapsible" id="button_definitionInsights_PolicySet"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantAllPolicySetsCount PolicySet definitions</span></button>
<div class="content contentDefinitionInsights">

<div id="extGridPolicySet" class="panel panel-info pull-left" >
    <div class="panel-body bg-info">
        <div class="me">
            <label>Search JSON</label>
            <span id="polsetJson"></span>
        </div>

        <div class="me">
            <label>Builtin/Custom</label>
            <span id="polsetType"></span>
        </div>

        <div class="me">
            <label>Category</label>
            <span id="polsetCategory"></span>
        </div>

        <div class="me">
            <label>Deprecated</label>
            <span id="polsetDeprecated"></span>
        </div>

        <div class="me">
            <label>Preview</label>
            <span id="polsetPreview"></span>
        </div>

        <div class="me">
            <label>Scope Mg/Sub</label>
            <span id="polSetScope"></span>
        </div>

        <div class="me">
            <label>Scope Name/Id</label>
            <span id="polSetScopeNameId"></span>
        </div>

        <div class="me">
            <label>hasAssignment</label>
            <span id="polSetHasAssignment"></span>
        </div>

    </div>
</div>

  
<div class="pull-left" style="margin-left: 0.5em;">

<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>JSON</th>
<th>PolicySet Type</th>
<th>Category</th>
<th>Deprecated</th>
<th>Preview</th>
<th>Scope Mg/Sub</th>
<th>Scope Name/Id</th>
<th>hasAssignments</th>
<th>Assignments Count</th>
<th>Assignments</th>
</tr>
</thead>
<tbody>
"@
    $htmlDefinitionInsightshlp = $null
    $htmlDefinitionInsightshlp = foreach ($policySet in ($allPolicySetsArray | Sort-Object @{Expression = { $_.DisplayName } }, @{Expression = { $_.PolicyDefinitionId } })) {
        $hasAssignments = "false"
        $assignmentsCount = 0
        $assignmentsDetailed = "n/a"
        
        if (($htPolicyWithAssignments).policySet.($policySet.PolicyDefinitionId)) {
            $hasAssignments = "true"
            $assignments = ($htPolicyWithAssignments).policySet.($policySet.PolicyDefinitionId).Assignments
            $assignmentsCount = ($assignments | Measure-Object).Count
            
            if ($assignmentsCount -gt 0) {
                $arrayAssignmentDetails = @()
                $arrayAssignmentDetails = foreach ($assignment in $assignments) {
                    if ($assignment.PolicyAssignmentDisplayName -eq ""){
                        $polAssDisplayName = "<i>#no AssignmentName given</i>"
                    }
                    else{
                        $polAssDisplayName = $assignment.PolicyAssignmentDisplayName
                    }
                    "$($assignment.PolicyAssignmentId) (<b>$($polAssDisplayName)</b>)"
                }
                $assignmentsDetailed = $arrayAssignmentDetails -join "$CsvDelimiterOpposite "
            }
            
        }

        $scopeDetails = "n/a"
        if ($policySet.ScopeId -ne "n/a") {
            $scopeDetails = "$($policySet.ScopeId) ($($htEntities.($policySet.ScopeId).DisplayName))"
        }
        @"
<tr>
<td><pre class="precode"><code class="language-json hljs">$($policySet.json | convertto-json -depth 99)</code></pre></td>
<td>$($policySet.Type)</td>
<td>$($policySet.Category)</td>
<td>$($policySet.Deprecated)</td>
<td>$($policySet.Preview)</td>
<td>$($policySet.ScopeMgSub)</td>
<td>$scopeDetails</td>
<td>$hasAssignments</td>
<td>$assignmentsCount</td>
<td class="breakwordall">$assignmentsDetailed</td>
</tr>
"@ 
    }
    $htmlDefinitionInsights += $htmlDefinitionInsightshlp
    $htmlDefinitionInsights | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
    $htmlDefinitionInsights = $null
    $htmlDefinitionInsights += @"
    </tbody>
</table>
</div>
<script>
function loadtf$htmlTableId() { if (window.helpertfConfig4$htmlTableId !== 1) { 
    window.helpertfConfig4$htmlTableId =1;
    var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,       
"@      
    if ($tfCount -gt 10) {
        $spectrum = "10, $tfCount"
        if ($tfCount -gt 50) {
            $spectrum = "10, 25, 50, $tfCount"
        }        
        if ($tfCount -gt 100) {
            $spectrum = "10, 30, 50, 100, $tfCount"
        }
        if ($tfCount -gt 500) {
            $spectrum = "10, 30, 50, 100, 250, $tfCount"
        }
        if ($tfCount -gt 1000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
        }
        if ($tfCount -gt 2000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
        }
        if ($tfCount -gt 3000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
        }
        $htmlDefinitionInsights += @"
        paging: {
            results_per_page: [
                'Records: ', 
                [$spectrum]
            ]
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
    $htmlDefinitionInsights += @"
    btn_reset: true, 
    highlight_keywords: true, 
    alternate_rows: true, 
    auto_filter: { 
        delay: 1100 
    },
    linked_filters: true,
    no_results_message: true,
    rows_counter: {
        text: 'results: '
    },
    col_1: 'select',
    col_2: 'select',
    col_3: 'select',
    col_4: 'select',
    col_5: 'select',
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
        'number',
        'caseinsensitivestring'

    ],
    external_flt_ids: [
        'polsetJson',
        'polsetType',
        'polsetCategory',
        'polsetDeprecated',
        'polsetPreview',
        'polSetScope',
        'polSetScopeNameId',
        'polSetHasAssignment'
    ],
    extensions: [
        { 
            name: 'sort' 
        },
        {
            name: 'colsVisibility',
            at_start: [1,2,3,4,5,6,7,8,9],
            text: 'Columns: ',
            enable_tick_all: true
        }
    ]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
</div>
"@
    #endregion definitionInsightsPolicySetDefinitions

    $htmlDefinitionInsights += @"
    </div>
"@
    #endregion definitionInsightsAzurePolicy

    #region definitionInsightsAzureRBAC
    $htmlDefinitionInsights += @"
    <button type="button" class="collapsible" id="definitionInsights_AzureRBAC"><hr class="hr-text-definitionInsights" data-content="RBAC" /></button>
    <div class="content contentDefinitionInsights">
"@

    #RBAC preQuery
    $htRoleWithAssignments = @{ }
    foreach ($roleDef in $rbacAll | sort-object -Property RoleAssignmentId -Unique | group-object -property RoleId) {   
        if (-not ($htRoleWithAssignments).($roleDef.Name)) {
            ($htRoleWithAssignments).($roleDef.Name) = @{ }
            ($htRoleWithAssignments).($roleDef.Name).Assignments = $roleDef.group
        }
    }

    #region definitionInsightsRoleDefinitions
    $tfCount = $tenantAllRolesCount
    $htmlTableId = "definitionInsights_Roles"
    $htmlDefinitionInsights += @"
<button type="button" onclick="loadtf$htmlTableId()" class="collapsible" id="button_definitionInsights_Roles"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantAllRolesCount Role definitions</span></button>
<div class="content contentDefinitionInsights">

<div id="extGridRole" class="panel panel-info pull-left" >
    <div class="panel-body bg-info">
        <div class="me">
            <label>Search JSON</label>
            <span id="roleJson"></span>
        </div>

        <div class="me">
            <label>Builtin/Custom</label>
            <span id="roleType"></span>
        </div>

        <div class="me">
            <label>Data</label>
            <span id="roleDataRelated"></span>
        </div>

        <div class="me">
            <label>hasAssignment</label>
            <span id="roleHasAssignment"></span>
        </div>


    </div>
</div>

  
<div class="pull-left" style="margin-left: 0.5em;">

<table id="$htmlTableId" class="summaryTable">
<thead>
<tr>
<th>JSON</th>
<th>Role Type</th>
<th>Data related</th>
<th>hasAssignments</th>
<th>Assignments Count</th>
<th>Assignments</th>
</tr>
</thead>
<tbody>
"@
    $htmlDefinitionInsightshlp = $null
    $htmlDefinitionInsightshlp = foreach ($role in ($tenantAllRolesArray | Sort-Object @{Expression = { $_.Name } })) {
        if ($role.IsCustom -eq $true) {
            $roleType = "Custom"
        }
        else {
            $roleType = "Builtin"
        }
        if (-not [string]::IsNullOrEmpty($role.DataActions) -or -not [string]::IsNullOrEmpty($role.NotDataActions)) {
            $roleManageData = "true"
        }
        else {
            $roleManageData = "false"
        }

        $hasAssignments = "false"
        $assignmentsCount = 0
        $assignmentsDetailed = "n/a"
        if (($htRoleWithAssignments).($role.id)) {
            $hasAssignments = "true"
            $assignments = ($htRoleWithAssignments).($role.id).Assignments
            $assignmentsCount = ($assignments | Measure-Object).Count            
            if ($assignmentsCount -gt 0) {
                $arrayAssignmentDetails = @()
                $arrayAssignmentDetails = foreach ($assignment in $assignments) {
                    "$($assignment.RoleAssignmentId)"
                }
                $assignmentsDetailed = $arrayAssignmentDetails -join "$CsvDelimiterOpposite "
            }
            
        }

        @"
<tr>
<td><pre class="precode"><code class="language-json hljs">$($role.json | convertto-json -depth 99)</code></pre></td>
<td>$($roleType)</td>
<td>$($roleManageData)</td>
<td>$hasAssignments</td>
<td>$assignmentsCount</td>
<td class="breakwordall">$assignmentsDetailed</td>
</tr>
"@ 
    }
    $htmlDefinitionInsights += $htmlDefinitionInsightshlp
    $htmlDefinitionInsights | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
    $htmlDefinitionInsights = $null
    $htmlDefinitionInsights += @"
    </tbody>
</table>
</div>
<script>
function loadtf$htmlTableId() { if (window.helpertfConfig4$htmlTableId !== 1) { 
    window.helpertfConfig4$htmlTableId =1;
    var tfConfig4$htmlTableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,       
"@      
    if ($tfCount -gt 10) {
        $spectrum = "10, $tfCount"
        if ($tfCount -gt 50) {
            $spectrum = "10, 25, 50, $tfCount"
        }        
        if ($tfCount -gt 100) {
            $spectrum = "10, 30, 50, 100, $tfCount"
        }
        if ($tfCount -gt 500) {
            $spectrum = "10, 30, 50, 100, 250, $tfCount"
        }
        if ($tfCount -gt 1000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, $tfCount"
        }
        if ($tfCount -gt 2000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, $tfCount"
        }
        if ($tfCount -gt 3000) {
            $spectrum = "10, 30, 50, 100, 250, 500, 750, 1000, 1500, 3000, $tfCount"
        }
        $htmlDefinitionInsights += @"
        paging: {
            results_per_page: [
                'Records: ', 
                [$spectrum]
            ]
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
    $htmlDefinitionInsights += @"
    btn_reset: true, 
    highlight_keywords: true, 
    alternate_rows: true, 
    auto_filter: { 
        delay: 1100 
    },
    linked_filters: true,
    no_results_message: true,
    rows_counter: {
        text: 'results: '
    },
    col_1: 'select',
    col_2: 'select',
    col_3: 'select',
    col_types: [
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'caseinsensitivestring',
        'number',
        'caseinsensitivestring'
    ],
    external_flt_ids: [
        'roleJson',
        'roleType',
        'roleDataRelated',
        'roleHasAssignment'
    ],
    extensions: [
        { 
            name: 'sort' 
        },
        {
            name: 'colsVisibility',
            at_start: [1,2,3,4,5],
            text: 'Columns: ',
            enable_tick_all: true
        }
    ]
};
var tf = new TableFilter('$htmlTableId', tfConfig4$htmlTableId);
tf.init();}}
</script>
</div>
"@
    #endregion definitionInsightsRoleDefinitions

    $htmlDefinitionInsights += @"
    </div>
"@
    #endregion definitionInsightsAzureRBAC

    $script:html += $htmlDefinitionInsights
    $htmlDefinitionInsights = $null
    $script:html | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
    $script:html = $null

    $endDefinitionInsights = get-date
    Write-Host "  DefinitionInsights processing duration: $((NEW-TIMESPAN -Start $startDefinitionInsights -End $endDefinitionInsights).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startDefinitionInsights -End $endDefinitionInsights).TotalSeconds) seconds)"
}
#endregion DefinitionInsights

#region markdown4wiki
function diagramMermaid() {
    $mgLevels = ($optimizedTableForPathQueryMg | Sort-Object -Property Level -Unique).Level
    foreach ($mgLevel in $mgLevels) {
        $mgsInLevel = ($optimizedTableForPathQueryMg | Where-Object { $_.Level -eq $mgLevel }).MgId | Get-Unique
        $script:arrayMgs += foreach ($mgInLevel in $mgsInLevel) { 
            $mgDetails = ($optimizedTableForPathQueryMg | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel })
            $mgName = $mgDetails.MgName | Get-Unique
            $mgParentId = $mgDetails.mgParentId | Get-Unique
            $mgParentName = $mgDetails.mgParentName | Get-Unique
            if ($mgInLevel -ne $getMgParentId) {
                $mgInLevel
            }

            if ($mgParentName -eq $mgParentId) {
                $mgParentNameId = $mgParentName
            }
            else {
                $mgParentNameId = "$mgParentName<br/>$mgParentId"
            }

            if ($mgName -eq $mgInLevel) {
                $mgNameId = $mgName
            }
            else {
                $mgNameId = "$mgName<br/>$mgInLevel"
            }
            $script:markdownhierarchyMgs += @"
$mgParentId(`"$mgParentNameId`") --> $mgInLevel(`"$mgNameId`")`n
"@
            $subsUnderMg = ($optimizedTableForPathQueryMgAndSub | Where-Object { -not [string]::IsNullOrEmpty($_.SubscriptionId) -and $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).SubscriptionId
            if (($subsUnderMg | measure-object).count -gt 0) {
                $script:arraySubs += foreach ($subUnderMg in $subsUnderMg) {
                    "SubsOf$mgInLevel"
                    $mgDetalsN = ($optimizedTableForPathQueryMg | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel })
                    $mgName = $mgDetalsN.MgName | Get-Unique
                    $mgParentId = $mgDetalsN.MgParentId | Get-Unique
                    $mgParentName = $mgDetalsN.MgParentName | Get-Unique
                    $subName = ($optimizedTableForPathQuery | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel -and $_.SubscriptionId -eq $subUnderMg }).Subscription | Get-Unique
                    $script:markdownTable += @"
| $mgLevel | $mgName | $mgInLevel | $mgParentName | $mgParentId | $subName | $($subUnderMg -replace '.*/') |`n
"@
                }
                $mgName = ($optimizedTableForPathQueryMg | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).MgName | Get-Unique
                if ($mgName -eq $mgInLevel) {
                    $mgNameId = $mgName
                }
                else {
                    $mgNameId = "$mgName<br/>$mgInLevel"
                }
                $script:markdownhierarchySubs += @"
$mgInLevel(`"$mgNameId`") --> SubsOf$mgInLevel(`"$(($subsUnderMg | measure-object).count)`")`n
"@
            }
            else {
                $mgDetailsM = ($optimizedTableForPathQueryMg | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel })
                $mgName = $mgDetailsM.MgName | Get-Unique
                $mgParentId = $mgDetailsM.MgParentId | Get-Unique
                $mgParentName = $mgDetailsM.MgParentName | Get-Unique
                $script:markdownTable += @"
| $mgLevel | $mgName | $mgInLevel | $mgParentName | $mgParentId | none | none |`n
"@
            }

            if (($script:outOfScopeSubscriptions | Measure-Object).count -gt 0) {
                $subsoosUnderMg = ($outOfScopeSubscriptions | Where-Object { $_.Level -eq $mgLevel -and $_.ManagementGroupId -eq $mgInLevel }).SubscriptionId | Get-Unique
                if (($subsoosUnderMg | measure-object).count -gt 0) {
                    $script:arraySubsOos += foreach ($subUnderMg in $subsoosUnderMg) {
                        "SubsoosOf$mgInLevel"                   
                        $mgDetalsN = ($optimizedTableForPathQueryMg | Where-Object { $_.Level -eq $mgLevel -and $_.ManagementGroupId -eq $mgInLevel })
                        $mgName = $mgDetalsN.MgName | Get-Unique
                    }
                    $mgName = ($outOfScopeSubscriptions | Where-Object { $_.Level -eq $mgLevel -and $_.ManagementGroupId -eq $mgInLevel }).ManagementGroupName | Get-Unique
                    if ($mgName -eq $mgInLevel) {
                        $mgNameId = $mgName
                    }
                    else {
                        $mgNameId = "$mgName<br/>$mgInLevel"
                    }
                    $script:markdownhierarchySubs += @"
$mgInLevel(`"$mgNameId`") --> SubsoosOf$mgInLevel(`"$(($subsoosUnderMg | measure-object).count)`")`n
"@
                }
            }
        }
    }
}
#endregion markdown4wikiF

#endregion Function

#region dataCollection

#run
Write-Host "Running AzGovViz for ManagementGroupId: '$ManagementGroupId'"

#validation / check ManagementGroup Access
Write-Host "Checking permissions on ManagementGroup '$ManagementGroupId'"
$testMGReadAccessResult = "letscheck"
try {
    $selectedManagementGroupId = Get-AzManagementGroup -GroupName $ManagementGroupId -ErrorAction Stop
}
catch {
    $testMGReadAccessResult = $_.Exception.Message
}
if ($testMGReadAccessResult -ne "letscheck") {
    if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
        Write-Error "Permissions test failed: Your AzDO ServiceConnection seems to lack ManagementGroup Read permissions or the ManagementGroupId '$ManagementGroupId' does not exist. Please check the documentation: https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting#required-permissions-in-azure | Error: $testMGReadAccessResult"
        Write-Error "Error"
    }
    else {
        Write-Host " Error: $testMGReadAccessResult" -ForegroundColor Red
        Write-Host " Permissions test failed: Your Account '$($checkContext.Account.id)' seems to lack ManagementGroup Read permissions (RBAC Role: Reader) or the ManagementGroupId '$ManagementGroupId' does not exist. Please check the documentation: https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting#required-permissions-in-azure"
        Throw "Error - check the last console output for details"
    }
}
else {
    Write-Host " Permissions test passed: ManagementGroup permissions OK"
}

#validation / check 'Azure Active Directory API' Access
if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
    Write-Host "Checking AzDO ServiceConnection permissions"
    $testSCSPAPIReadAccessResult = "letscheck"
    try {
        $testSCSPAPIReadAccess = Get-AzRoleAssignment -scope "/providers/Microsoft.Management/managementGroups/$($selectedManagementGroupId.Name)"
    }
    catch {
        $testSCSPAPIReadAccessResult = $_.Exception.Message
    }
    if ($testSCSPAPIReadAccessResult -ne "letscheck") {
        Write-Error "Permissions test failed: Your AzDO ServiceConnection seems to lack 'Azure Active Directory API' Read permissions. Please check the documentation: https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting#required-permissions-in-azure Error: $testSCSPAPIReadAccessResult"
        Write-Error "Error"
    }
    else {
        Write-Host " Permissions test passed: 'Azure Active Directory API' permissions OK"
    }
}

$arrayAPICallTracking = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$arrayAPICallTrackingCustomDataCollection = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

$userType = "n/a"
if ($accountType -eq "User") {
    $currentTask = "Checking AAD UserType"
    Write-Host $currentTask
    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).GraphUrl)/v1.0/me?`$select=userType"
    $method = "GET"
    $checkUserType = AzAPICall -uri $uri -method $method -listenOn "Content" -currentTask $currentTask
    $userType = $checkUserType.userType
    Write-Host "AAD UserType: $($userType)" -ForegroundColor Yellow
}

$newTable = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

#region GettingEntities
$startEntities = get-date
$currentTask = "Getting Entities"
Write-Host "$currentTask"
#https://management.azure.com/providers/Microsoft.Management/getEntities?api-version=2020-02-01
$uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/getEntities?api-version=2020-02-01"
#$path = "/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
$method = "POST"

$arrayEntitiesFromAPI = ((AzAPICall -uri $uri -method $method -currentTask $currentTask))

$htSubscriptionsMgPath = @{ }
$htManagementGroupsMgPath = @{ }
$htEntities = @{ }
$htEntitiesPlain = @{ }

foreach ($entity in $arrayEntitiesFromAPI) {
    $htEntitiesPlain.($entity.Name) = @{ }
    $htEntitiesPlain.($entity.Name) = $entity
}

foreach ($entity in $arrayEntitiesFromAPI) {
    if ($entity.Type -eq "/subscriptions") {
        $htSubscriptionsMgPath.($entity.name) = @{ }
        $htSubscriptionsMgPath.($entity.name).ParentNameChain = $entity.properties.parentNameChain
        $htSubscriptionsMgPath.($entity.name).Parent = $entity.properties.parent.id -replace ".*/"
        $htSubscriptionsMgPath.($entity.name).DisplayName = $entity.properties.displayName
    }
    if ($entity.Type -eq "Microsoft.Management/managementGroups") {
        if ([string]::IsNullOrEmpty($entity.properties.parent.id)) {
            $parent = "_TenantRoot_"
        }
        else {
            $parent = $entity.properties.parent.id -replace ".*/"
        }
        $htManagementGroupsMgPath.($entity.name) = @{ }
        $htManagementGroupsMgPath.($entity.name).ParentNameChain = $entity.properties.parentNameChain
        $htManagementGroupsMgPath.($entity.name).Parent = $parent
        $htManagementGroupsMgPath.($entity.name).DisplayName = $entity.properties.displayName
    }
    
    $htEntities.($entity.name) = @{ }
    $htEntities.($entity.name).ParentNameChain = $entity.properties.parentNameChain
    $htEntities.($entity.name).Parent = $parent
    if ($parent -eq "_TenantRoot_"){
        $parentDisplayName = "_TenantRoot_"
    }
    else{
        $parentDisplayName = $htEntitiesPlain.($htEntities.($entity.name).Parent).properties.displayName
    }
    $htEntities.($entity.name).ParentDisplayName = $parentDisplayName
    $htEntities.($entity.name).DisplayName = $entity.properties.displayName
    $htEntities.($entity.name).Id = $entity.Name
}

$endEntities = get-date
Write-Host "Getting Entities duration: $((NEW-TIMESPAN -Start $startEntities -End $endEntities).TotalSeconds) seconds"
#endregion GettingEntities


if (($checkContext).Tenant.id -ne $ManagementGroupId) {
    $mgSubPathTopMg = $selectedManagementGroupId.ParentName
    $getMgParentId = $selectedManagementGroupId.ParentName
    $getMgParentName = $selectedManagementGroupId.ParentDisplayName
    $mermaidprnts = "'$(($checkContext).Tenant.id)',$getMgParentId"
    #$hierarchyLevel = 0
    addRowToTable `
        -level (($htManagementGroupsMgPath.($ManagementGroupId).ParentNameChain | Measure-Object).Count -1) `
        -mgName $getMgParentName `
        -mgId $getMgParentId `
        -mgParentId "'$(($checkContext).Tenant.id)'" `
        -mgParentName "Tenant Root"
}
else {
    $hierarchyLevel = -1
    $mgSubPathTopMg = "$ManagementGroupId"
    $getMgParentId = "'$ManagementGroupId'"
    $getMgParentName = "Tenant Root"
    $mermaidprnts = "'$getMgParentId',$getMgParentId"
}

if ($htParameters.AzureDevOpsWikiAsCode -eq $false) {
    $currentTask = "Get Tenant details"
    Write-Host $currentTask
    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)tenants?api-version=2020-01-01"
    #$path = "/tenants?api-version=2020-01-01"
    $method = "GET"

    $tenantDetailsResult = ((AzAPICall -uri $uri -method $method -currentTask $currentTask))
    if (($tenantDetailsResult | measure-object).count -gt 0) {
        $tenantDetails = $tenantDetailsResult | Where-Object { $_.tenantId -eq ($checkContext).Tenant.id }
        $tenantDisplayName = $tenantDetails.displayName
        $tenantDefaultDomain = $tenantDetails.defaultDomain
        Write-Host " Tenant DisplayName: $tenantDisplayName"
    }
    else {
        Write-Host " something unexpected"
    }
}

Write-Host "Get Default Management Group"
$currentTask = "Get Default Management Group"
$uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementGroups/$(($checkContext).Tenant.id)/settings?api-version=2020-02-01"
#$path = "providers/Microsoft.Management/managementGroups/($checkContext).Tenant.id/settings?api-version=2020-02-01"
$method = "GET"

#default Management Group
#https://docs.microsoft.com/en-us/azure/governance/management-groups/how-to/protect-resource-hierarchy#setting---default-management-group
$settingsMG = ((AzAPICall -uri $uri -method $method -currentTask $currentTask))
if (($settingsMG | Measure-Object).count -gt 0) {
    write-host " default ManagementGroup Id: $($settingsMG.properties.defaultManagementGroup)"
    $defaultManagementGroupId = $settingsMG.properties.defaultManagementGroup
    write-host " requireAuthorizationForGroupCreation: $($settingsMG.properties.requireAuthorizationForGroupCreation)"
    $requireAuthorizationForGroupCreation = $settingsMG.properties.requireAuthorizationForGroupCreation
}
else {
    write-host " default ManagementGroup: $(($checkContext).Tenant.id) (Tenant Root)"
    $defaultManagementGroupId = ($checkContext).Tenant.id
    $requireAuthorizationForGroupCreation = $false
}



if ($htParameters.HierarchyMapOnly -eq $false) {
    
    #region RunInfo
    $paramsUsed = $Null
    $paramsUsed += "RunInfo &#13;"
    $paramsUsed += "Date: $startTimeUTC (UTC) &#13;"
    $paramsUsed += "Version: $AzGovVizVersion &#13;"

    if ($accountType -eq "ServicePrincipal") {
        $paramsUsed += "ExecutedBy: $($accountId) (App/ClientId) ($($accountType)) &#13;"
    }
    else {
        $paramsUsed += "ExecutedBy: $($accountId) ($($accountType), $($userType)) &#13;"
    }
    $paramsUsed += "ManagementGroupId: $($ManagementGroupId) &#13;"
    $paramsUsed += "HierarchyMapOnly: false &#13;"
    Write-Host "Run Info:"
    Write-Host " Creating HierarchyMap, TenantSummary and ScopeInsights - use parameter: '-HierarchyMapOnly' to only create the HierarchyMap" -ForegroundColor Yellow

    if (($SubscriptionQuotaIdWhitelist | Measure-Object).count -eq 1 -and $SubscriptionQuotaIdWhitelist[0] -eq "undefined") {
        Write-Host " Subscription Whitelist disabled - use parameter: '-SubscriptionQuotaIdWhitelist' to whitelist QuotaIds" -ForegroundColor Yellow
        $paramsUsed += "SubscriptionQuotaIdWhitelist: false &#13;"
    }
    else {
        Write-Host " Subscription Whitelist enabled. AzGovViz will only process Subscriptions where QuotaId startswith one of the following strings:" -ForegroundColor Green
        Write-Host "  $($SubscriptionQuotaIdWhitelist -join ", ")"
        foreach ($whiteListEntry in $SubscriptionQuotaIdWhitelist) {
            if ($whiteListEntry -eq "undefined") {
                Write-Host "When defining the 'SubscriptionQuotaIdWhitelist' make sure to remove the 'undefined' entry from the array :)" -ForegroundColor Red
                if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
                    Write-Error "Error"
                }
                else {
                    Throw "Error - check the last console output for details"
                }
            }
        }
        $paramsUsed += "SubscriptionQuotaIdWhitelist: $($SubscriptionQuotaIdWhitelist -join ", ") &#13;"
    }


    if ($htParameters.NoASCSecureScore -eq $true) {
        Write-Host " ASC Secure Score for Subscriptions disabled (-NoASCSecureScore = $($htParameters.NoASCSecureScore))" -ForegroundColor Green
        $paramsUsed += "NoASCSecureScore: true &#13;"
    }
    else {
        Write-Host " ASC Secure Score for Subscriptions enabled - use parameter: '-NoASCSecureScore' to disable" -ForegroundColor Yellow
        $paramsUsed += "NoASCSecureScore: false &#13;"
    }

    if ($htParameters.NoResourceProvidersDetailed -eq $true) {
        Write-Host " ResourceProvider Detailed for TenantSummary disabled (-NoResourceProvidersDetailed = $($htParameters.NoResourceProvidersDetailed))" -ForegroundColor Green
        $paramsUsed += "NoResourceProvidersDetailed: true &#13;"
    }
    else {
        Write-Host " ResourceProvider Detailed for TenantSummary enabled - use parameter: '-NoResourceProvidersDetailed' to disable" -ForegroundColor Yellow
        $paramsUsed += "NoResourceProvidersDetailed: false &#13;"
    }

    if ($htParameters.DoNotShowRoleAssignmentsUserData -eq $true) {
        Write-Host " Scrub Identity information for identityType='User' enabled (-DoNotShowRoleAssignmentsUserData = $($htParameters.DoNotShowRoleAssignmentsUserData))" -ForegroundColor Green
        $paramsUsed += "DoNotShowRoleAssignmentsUserData: true &#13;"
    }
    else {
        Write-Host " Scrub Identity information for identityType='User' disabled - use parameter: '-DoNotShowRoleAssignmentsUserData' to scrub information such as displayName and signInName (email) for identityType='User'" -ForegroundColor Yellow
        $paramsUsed += "DoNotShowRoleAssignmentsUserData: false &#13;"
    }

    if ($LimitCriticalPercentage -eq 80) {
        Write-Host " ARM Limits warning set to 80% (default) - use parameter: '-LimitCriticalPercentage' to set warning level accordingly" -ForegroundColor Yellow
        $paramsUsed += "LimitCriticalPercentage: 80% (default) &#13;"
    }
    else {
        Write-Host " ARM Limits warning set to $($LimitCriticalPercentage)% (custom)" -ForegroundColor Green
        $paramsUsed += "LimitCriticalPercentage: $($LimitCriticalPercentage)% &#13;"
    }

    if ($htParameters.NoPolicyComplianceStates -eq $false) {
        Write-Host " Policy States enabled - use parameter: '-NoPolicyComplianceStates' to disable Policy States" -ForegroundColor Yellow
        $paramsUsed += "NoPolicyComplianceStates: false &#13;"
    }
    else {
        Write-Host " Policy States disabled (-NoPolicyComplianceStates = $($htParameters.NoPolicyComplianceStates))" -ForegroundColor Green
        $paramsUsed += "NoPolicyComplianceStates: true &#13;"
    }

    if (-not $NoResourceDiagnosticsPolicyLifecycle) {
        Write-Host " Resource Diagnostics Policy Lifecycle recommendations enabled - use parameter: '-NoResourceDiagnosticsPolicyLifecycle' to disable Resource Diagnostics Policy Lifecycle recommendations" -ForegroundColor Yellow
        $paramsUsed += "NoResourceDiagnosticsPolicyLifecycle: false &#13;"
    }
    else {
        Write-Host " Resource Diagnostics Policy Lifecycle disabled (-NoResourceDiagnosticsPolicyLifecycle = $($NoResourceDiagnosticsPolicyLifecycle))" -ForegroundColor Green
        $paramsUsed += "NoResourceDiagnosticsPolicyLifecycle: true &#13;"
    }

    if (-not $NoAADGroupsResolveMembers) {
        Write-Host " AAD Groups resolve members enabled (honors parameter -DoNotShowRoleAssignmentsUserData) - use parameter: '-NoAADGroupsResolveMembers' to disable resolving AAD Group memberships" -ForegroundColor Yellow
        $paramsUsed += "NoAADGroupsResolveMembers: false &#13;"
    }
    else {
        Write-Host " AAD Groups resolve members disabled (-NoAADGroupsResolveMembers = $($NoAADGroupsResolveMembers))" -ForegroundColor Green
        $paramsUsed += "NoAADGroupsResolveMembers: true &#13;"
    }

    if (-not $NoAADGuestUsers) {
        Write-Host " AAD resolve User type (Guest or Member) enabled - use parameter: '-NoAADGuestUsers' to disable" -ForegroundColor Yellow
        $paramsUsed += "NoAADGuestUsers: false &#13;"
    }
    else {
        Write-Host " AAD resolve User type (Guest or Member) (-NoAADGuestUsers = $($NoAADGuestUsers))" -ForegroundColor Green
        $paramsUsed += "NoAADGuestUsers: true &#13;"
    }

    if (-not $NoAADServicePrincipalResolve) {
        Write-Host " AAD ServicePrincipal resolve enabled (Expiry warning: $AADServicePrincipalExpiryWarningDays days) - use parameter: '-AADServicePrincipalExpiryWarningDays' to define minimum lifetime in days for SP passwords/keys expiry warning (use parameter: '-NoAADServicePrincipalResolve' to disable resolving ServicePrincipals)" -ForegroundColor Yellow
        $paramsUsed += "NoAADServicePrincipalResolve: false &#13;"
        $paramsUsed += "AADServicePrincipalExpiryWarningDays: $AADServicePrincipalExpiryWarningDays &#13;"
    }
    else {
        Write-Host " AAD ServicePrincipal resolve disabled (-NoAADServicePrincipalResolve = $($NoAADServicePrincipalResolve))" -ForegroundColor Green
        $paramsUsed += "NoAADServicePrincipalResolve: true &#13;"
    }

    if ($htParameters.NoAzureConsumption -eq $false) {
        if (-not $AzureConsumptionPeriod -is [int]) {
            Write-Host "parameter -AzureConsumptionPeriod must be an integer"
            if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
                Write-Error "Error"
            }
            else {
                Throw "Error - check the last console output for details"
            }
        }
        elseif ($AzureConsumptionPeriod -eq 0) {
            Write-Host "parameter -AzureConsumptionPeriod must be gt 0"
            if ($htParameters.AzureDevOpsWikiAsCode -eq $true) {
                Write-Error "Error"
            }
            else {
                Throw "Error - check the last console output for details"
            }
        }
        else {
            $azureConsumptionStartDate = ((get-date).AddDays( - ($($AzureConsumptionPeriod)))).ToString("yyyy-MM-dd")
            $azureConsumptionEndDate = ((get-date).AddDays(-1)).ToString("yyyy-MM-dd")

            if ($AzureConsumptionPeriod -eq 1) {
                Write-Host " Azure Consumption reporting enabled: $AzureConsumptionPeriod days (default) ($azureConsumptionStartDate - $azureConsumptionEndDate) - use parameter: '-NoAzureConsumption' to disable; use parameter: '-AzureConsumptionPeriod' to define the period (days)" -ForegroundColor Yellow
            }
            else {
                Write-Host " Azure Consumption reporting enabled: $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate) - use parameter: '-NoAzureConsumption' to disable" -ForegroundColor Green
            }
            
            if (-not $NoAzureConsumptionReportExportToCSV) {
                Write-Host " Azure Consumption report export to CSV enabled - use parameter: '-NoAzureConsumptionReportExportToCSV' to disable" -ForegroundColor Yellow
            }
            else {
                Write-Host " Azure Consumption report export to CSV disabled (-NoAzureConsumptionReportExportToCSV = $($NoAzureConsumptionReportExportToCSV))" -ForegroundColor Green
            }
            $paramsUsed += "NoAzureConsumption: false &#13;" 
            $paramsUsed += "AzureConsumptionPeriod: $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate) &#13;"
            $paramsUsed += "NoAzureConsumptionReportExportToCSV: $NoAzureConsumptionReportExportToCSV &#13;"
        }
    }
    else {
        Write-Host " Azure Consumption reporting disabled (-NoAzureConsumption = $($htParameters.NoAzureConsumption))" -ForegroundColor Green
        $paramsUsed += "NoAzureConsumption: true &#13;"
    }

    if ($NoScopeInsights) {
        Write-Host " ScopeInsights disabled (-NoScopeInsights = $($NoScopeInsights))" -ForegroundColor Green
        $paramsUsed += "NoScopeInsights: true &#13;"
    }
    else {
        Write-Host " ScopeInsights enabled - use parameter: '-NoScopeInsights' to disable. Q: Why would you want to do this? A: In larger tenants the ScopeInsights section blows up the html file (up to unusable due to html file size)" -ForegroundColor Yellow
        $paramsUsed += "NoScopeInsights: false &#13;"
    }

    if ($ThrottleLimit -eq 5){
        Write-Host " ThrottleLimit = $ThrottleLimit" -ForegroundColor Yellow
        $paramsUsed += "ThrottleLimit: $ThrottleLimit &#13;"
    }
    else{
        Write-Host " ThrottleLimit = $ThrottleLimit" -ForegroundColor Green
        $paramsUsed += "ThrottleLimit: $ThrottleLimit &#13;"
    }


    #endregion RunInfo

    #helper ht / collect results /save some time
    $htCacheDefinitions = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    ($htCacheDefinitions).policy = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    ($htCacheDefinitions).policySet = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    ($htCacheDefinitions).role = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    ($htCacheDefinitions).blueprint = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $htCacheDefinitionsAsIs = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    ($htCacheDefinitionsAsIs).policy = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $htPoliciesUsedInPolicySets = @{ }
    $htSubscriptionTags = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $htCacheAssignments = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $arrayCachePolicyAssignmentsResourceGroupsAndResources = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    ($htCacheAssignments).policyOnResourceGroupsAndResources = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    ($htCacheAssignments).role = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $arrayCacheRoleAssignmentsResourceGroups = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    ($htCacheAssignments).rbacOnResourceGroupsAndResources = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    ($htCacheAssignments).blueprint = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $htCachePolicyCompliance = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    ($htCachePolicyCompliance).mg = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    ($htCachePolicyCompliance).sub = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $outOfScopeSubscriptions = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $htAllSubscriptionsFromAPI = @{ }
    if ($htParameters.NoAzureConsumption -eq $false) {
        $htAzureConsumptionSubscriptions = @{ }
    }
    $customDataCollectionDuration = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))   
    $htResourceLocks = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $resourceGroupsLocksCannotDeleteCountTotal = 0
    $resourceGroupsLocksReadOnlyCountTotal = 0
    $resourcesLocksCannotDeleteCountTotal = 0
    $resourcesLocksReadOnlyCountTotal = 0
    $htAllTagList = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $htAllTagList.AllScopes = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $htAllTagList.Subscription = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $htAllTagList.ResourceGroup = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $htAllTagList.Resource = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $arrayTagList = [System.Collections.ArrayList]@()
    $htSubscriptionTagList = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $htPolicyAssignmentExemptions = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    if (-not $NoAADGuestUsers) {
        $htUserTypes = @{ }
    }
    $resourcesAll = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $resourceGroupsAll = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $htResourceProvidersAll = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $arrayResourceProvidersAll = @()
    $htResourceTypesUniqueResource = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $arrayDataCollectionProgressMg = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $arrayDataCollectionProgressSub = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

    #current context sub not AAD*
    do {
        $result = "letscheck"
        try {
            $currentContextSubscriptionQuotaId = (Search-AzGraph -ErrorAction SilentlyContinue -Subscription $checkContext.Subscription.id -Query "resourcecontainers | where type == 'microsoft.resources/subscriptions' | project properties.subscriptionPolicies.quotaId").properties_subscriptionPolicies_quotaId
        }
        catch {
            $result = "letscheck"
        }
    }
    until ($result -eq "letscheck")

    if (-not $currentContextSubscriptionQuotaId) {
        Write-Host " Bad Subscription context for Definition Caching (SubscriptionName: $($checkContext.Subscription.Name); SubscriptionId: $($checkContext.Subscription.id); likely an AAD_ QuotaId" -ForegroundColor Yellow
        
        do {
            $result = "letscheck"
            try {
                $alternativeSubscriptionIdForDefinitionCaching = (Search-AzGraph -Query "resourcecontainers | where type == 'microsoft.resources/subscriptions' | where properties.subscriptionPolicies.quotaId !startswith 'AAD_' | project properties.subscriptionPolicies.quotaId, subscriptionId" -first 1)
            }
            catch {
                $result = "letscheck"
            }
        }
        until ($result -eq "letscheck")

        Write-Host "Using other Subscription for Definition Caching (SubscriptionId: $($alternativeSubscriptionIdForDefinitionCaching.subscriptionId); QuotaId: $($alternativeSubscriptionIdForDefinitionCaching.properties_subscriptionPolicies_quotaId))" -ForegroundColor Yellow
        $subscriptionIdForDefinitionCaching = $alternativeSubscriptionIdForDefinitionCaching.subscriptionId
        Select-AzSubscription -SubscriptionId $subscriptionIdForDefinitionCaching -ErrorAction Stop
    }
    else {
        Write-Host "Subscription context valid (QuotaId not 'AAD_*') for Definition Caching (SubscriptionId: $($checkContext.Subscription.id); QuotaId: $currentContextSubscriptionQuotaId)"
        $subscriptionIdForDefinitionCaching = $checkContext.Subscription.id
    }

    $startGetSubscriptions = get-date
    $currentTask = "Getting all Subscriptions"
    Write-Host "$currentTask"
    #https://management.azure.com/subscriptions?api-version=2020-01-01
    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions?api-version=2019-10-01"
    #$path = "/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
    $method = "GET"

    $requestAllSubscriptionsAPI = ((AzAPICall -uri $uri -method $method -currentTask $currentTask))
    foreach ($subscription in $requestAllSubscriptionsAPI) {   
        $htAllSubscriptionsFromAPI.($subscription.subscriptionId) = @{ }
        $htAllSubscriptionsFromAPI.($subscription.subscriptionId).subDetails = $subscription
    }
    $endGetSubscriptions = get-date
    Write-Host "Getting all Subscriptions duration: $((NEW-TIMESPAN -Start $startGetSubscriptions -End $endGetSubscriptions).TotalSeconds) seconds"  

    if ($htParameters.NoAzureConsumption -eq $false) {
        
        #region dataprocessingConsumption
        $startConsumptionData = Get-Date
        
        $currenttask = "Getting Consumption data for scope: '$($ManagementGroupId)' for period $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)"
        Write-Host "$currentTask"
        $uri = "https://management.azure.com/providers/Microsoft.Management/managementGroups/$($ManagementGroupId)/providers/Microsoft.CostManagement/query?api-version=2019-11-01&`$top=5000"
        $method = "POST"
        $body = @"
{
    "type": "ActualCost",
    "dataset": {
        "granularity": "none",
        "aggregation": {
            "totalCost": {
                "name": "PreTaxCost",
                "function": "Sum"
            }
        },
        "grouping": [
            {
                "type": "Dimension",
                "name": "SubscriptionId"
            },
            {
                "type": "Dimension",
                "name": "ResourceId"
            },
            {
                "type": "Dimension",
                "name": "ConsumedService"
            },
            {
                "type": "Dimension",
                "name": "MeterCategory"
            },
            {
                "type": "Dimension",
                "name": "ChargeType"
            }
        ]
    },
    "timeframe": "Custom",
    "timeperiod": {
        "from": "$($azureConsumptionStartDate)",
        "to": "$($azureConsumptionEndDate)"
    }
}
"@

        $allConsumptionData = AzAPICall -uri $uri -method $method -body $body -currentTask $currentTask -listenOn "ContentProperties" -getConsumption $true
        $allConsumptionDataCount = ($allConsumptionData | Measure-Object).Count

        if ($allConsumptionDataCount -gt 0) {
            Write-Host " $allConsumptionDataCount consumption data entries"

            $allConsumptionData = $allConsumptionData | where-Object { $_.PreTaxCost -ne 0 }
            $groupAllConsumptionDataBySubscriptionId = $allConsumptionData | Group-Object -Property SubscriptionId


            $arrayTotalCostSummary = @()
            $arrayConsumptionData = [System.Collections.ArrayList]@()
            $consumptionData = $allConsumptionData
            $consumptionDataGroupedByCurrency = $consumptionData | group-object -property Currency

            foreach ($currency in $consumptionDataGroupedByCurrency) {

                #subscriptions
                $groupAllConsumptionDataPerCurrencyBySubscriptionId = $currency.group | Group-Object -Property SubscriptionId
                foreach ($subscriptionId in $groupAllConsumptionDataPerCurrencyBySubscriptionId) {
                    $htAzureConsumptionSubscriptions.($subscriptionId.Name) = @{ }
                    $htAzureConsumptionSubscriptions.($subscriptionId.Name).ConsumptionData = $subscriptionId.group
                    $htAzureConsumptionSubscriptions.($subscriptionId.Name).TotalCost = ($subscriptionId.Group.PreTaxCost | Measure-Object -Sum).Sum
                    $htAzureConsumptionSubscriptions.($subscriptionId.Name).Currency = $currency.Name
                }

                $totalCost = 0
                $tenantSummaryConsumptionDataGrouped = $currency.group | group-object -property ConsumedService, ChargeType, MeterCategory
                $subsCount = ($tenantSummaryConsumptionDataGrouped.group.subscriptionId | Sort-Object -Unique | Measure-Object).Count
                $consumedServiceCount = ($tenantSummaryConsumptionDataGrouped.group.consumedService | Sort-Object -Unique | Measure-Object).Count
                $resourceCount = ($tenantSummaryConsumptionDataGrouped.group.ResourceId | Sort-Object -Unique | Measure-Object).Count
                foreach ($consumptionline in $tenantSummaryConsumptionDataGrouped) {

                    $costConsumptionLine = ($consumptionline.group.PreTaxCost | Measure-Object -Sum).Sum
                    if ([math]::Round($costConsumptionLine, 4) -eq 0) {
                        $cost = $costConsumptionLine
                    }
                    else {
                        $cost = [math]::Round($costConsumptionLine, 4)
                    }
                
                    $null = $arrayConsumptionData.Add([PSCustomObject]@{ 
                            ConsumedService              = ($consumptionline.name).split(", ")[0]
                            ConsumedServiceChargeType    = ($consumptionline.name).split(", ")[1]
                            ConsumedServiceCategory      = ($consumptionline.name).split(", ")[2]
                            ConsumedServiceInstanceCount = $consumptionline.Count
                            ConsumedServiceCost          = [decimal]$cost
                            ConsumedServiceSubscriptions = ($consumptionline.group.SubscriptionId | Sort-Object -Unique).Count
                            ConsumedServiceCurrency      = $currency.Name
                        })
                
                    $totalCost = $totalCost + $costConsumptionLine

                }
                if ([math]::Round($totalCost, 4) -eq 0) {
                    $totalCost = $totalCost
                }
                else {
                    $totalCost = [math]::Round($totalCost, 4)
                }
                $arrayTotalCostSummary += "$([decimal]$totalCost) $($currency.Name) generated by $($resourceCount) Resources ($($consumedServiceCount) ResourceTypes) in $($subsCount) Subscriptions"
            }
        }
        $endConsumptionData = get-date
        Write-Host "Getting Consumption data duration: $((NEW-TIMESPAN -Start $startConsumptionData -End $endConsumptionData).TotalSeconds) seconds"
        #endregion dataprocessingConsumption
    }
    

    #region dataprocessingDefinitionCaching
    $startDefinitionsCaching = get-date
    Write-Host "Caching built-in Policy and RBAC Role definitions"
    $currentTask = "Caching built-in Policy definitions"
    Write-Host " $currentTask"
    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
    #$path = "/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
    $method = "GET"

    $requestPolicyDefinitionAPI = ((AzAPICall -uri $uri -method $method -currentTask $currentTask))
    $builtinPolicyDefinitions = $requestPolicyDefinitionAPI | Where-Object { $_.properties.policyType -eq "builtin" }
    foreach ($builtinPolicyDefinition in $builtinPolicyDefinitions) {
        ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()) = @{ }
        ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).id = ($builtinPolicyDefinition.id).ToLower()
        ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).Scope = "n/a"
        ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).ScopeMgSub = "n/a"
        ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).ScopeId = "n/a"
        ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).DisplayName = $builtinPolicyDefinition.Properties.displayname
        ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).Description = $builtinPolicyDefinition.Properties.description
        ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).Type = $builtinPolicyDefinition.Properties.policyType
        ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).Category = $builtinPolicyDefinition.Properties.metadata.category
        ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).PolicyDefinitionId = ($builtinPolicyDefinition.id).ToLower()
        ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).LinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/$(($builtinPolicyDefinition.id -replace ".*/")).html`" target=`"_blank`">$($builtinPolicyDefinition.Properties.displayname)</a>"
        if ($builtinPolicyDefinition.Properties.metadata.deprecated -eq $true -or $builtinPolicyDefinition.Properties.displayname -like "``[Deprecated``]*") {
            ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).Deprecated = $builtinPolicyDefinition.Properties.metadata.deprecated
        }
        else {
            ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).Deprecated = $false
        }
        if ($builtinPolicyDefinition.Properties.metadata.preview -eq $true -or $builtinPolicyDefinition.Properties.displayname -like "``[*Preview``]*") {
            ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).Preview = $builtinPolicyDefinition.Properties.metadata.preview
        }
        else {
            ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).Preview = $false
        }
        #effects
        if ($builtinPolicyDefinition.properties.parameters.effect.defaultvalue) {
            ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).effectDefaultValue = $builtinPolicyDefinition.properties.parameters.effect.defaultvalue
            if ($builtinPolicyDefinition.properties.parameters.effect.allowedValues) {
                ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).effectAllowedValue = $builtinPolicyDefinition.properties.parameters.effect.allowedValues -join ","
            }
            else {
                ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).effectAllowedValue = "n/a"
            }
            ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).effectFixedValue = "n/a"
        }
        else {
            if ($builtinPolicyDefinition.properties.parameters.policyEffect.defaultValue) {
                ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).effectDefaultValue = $builtinPolicyDefinition.properties.parameters.policyEffect.defaultvalue
                if ($builtinPolicyDefinition.properties.parameters.policyEffect.allowedValues) {
                    ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).effectAllowedValue = $builtinPolicyDefinition.properties.parameters.policyEffect.allowedValues -join ","
                }
                else {
                    ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).effectAllowedValue = "n/a"
                }
                ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).effectFixedValue = "n/a"
            }
            else {
                ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).effectFixedValue = $builtinPolicyDefinition.Properties.policyRule.then.effect
                ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).effectDefaultValue = "n/a"
                ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).effectAllowedValue = "n/a"
            }
        }
        ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).json = $builtinPolicyDefinition

        
        if ($builtinPolicyDefinition.properties.policyRule.then.details.roleDefinitionIds) {
            ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).RoleDefinitionIds  = $builtinPolicyDefinition.properties.policyRule.then.details.roleDefinitionIds
        }
        else {
            ($htCacheDefinitions).policy.(($builtinPolicyDefinition.id).ToLower()).RoleDefinitionIds  = "n/a"
        }

        #AsIs
        ($htCacheDefinitionsAsIs).policy.(($builtinPolicyDefinition.id).ToLower()) = @{ }
        ($htCacheDefinitionsAsIs).policy.(($builtinPolicyDefinition.id).ToLower()) = $builtinPolicyDefinition
    }

    $currentTask = "Caching built-in PolicySet definitions"
    Write-Host " $currentTask"
    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"
    #$path = "/providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"
    $method = "GET"

    $requestPolicySetDefinitionAPI = ((AzAPICall -uri $uri -method $method -currentTask $currentTask))
    $builtinPolicySetDefinitions = $requestPolicySetDefinitionAPI | Where-Object { $_.properties.policyType -eq "builtin" }
    foreach ($builtinPolicySetDefinition in $builtinPolicySetDefinitions) {
        ($htCacheDefinitions).policySet.(($builtinPolicySetDefinition.id).ToLower()) = @{ }
        ($htCacheDefinitions).policySet.(($builtinPolicySetDefinition.id).ToLower()).id = ($builtinPolicySetDefinition.id).ToLower()
        ($htCacheDefinitions).policySet.(($builtinPolicySetDefinition.id).ToLower()).Scope = "n/a"
        ($htCacheDefinitions).policySet.(($builtinPolicySetDefinition.id).ToLower()).ScopeMgSub = "n/a"
        ($htCacheDefinitions).policySet.(($builtinPolicySetDefinition.id).ToLower()).ScopeId = "n/a"
        ($htCacheDefinitions).policySet.(($builtinPolicySetDefinition.id).ToLower()).DisplayName = $builtinPolicySetDefinition.Properties.displayname
        ($htCacheDefinitions).policySet.(($builtinPolicySetDefinition.id).ToLower()).Description = $builtinPolicySetDefinition.Properties.description
        ($htCacheDefinitions).policySet.(($builtinPolicySetDefinition.id).ToLower()).Type = $builtinPolicySetDefinition.Properties.policyType
        ($htCacheDefinitions).policySet.(($builtinPolicySetDefinition.id).ToLower()).Category = $builtinPolicySetDefinition.Properties.metadata.category
        ($htCacheDefinitions).policySet.(($builtinPolicySetDefinition.id).ToLower()).PolicyDefinitionId = ($builtinPolicySetDefinition.id).ToLower()
        ($htCacheDefinitions).policySet.(($builtinPolicySetDefinition.id).ToLower()).LinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyinitiativesadvertizer/$(($builtinPolicySetDefinition.id -replace ".*/")).html`" target=`"_blank`">$($builtinPolicySetDefinition.Properties.displayname)</a>"
        $arrayPolicySetPolicyIdsToLower = @()
        $arrayPolicySetPolicyIdsToLower = foreach ($policySetPolicy in $builtinPolicySetDefinition.properties.policydefinitions.policyDefinitionId) {
            ($policySetPolicy).ToLower()
        }
        ($htCacheDefinitions).policySet.(($builtinPolicySetDefinition.id).ToLower()).PolicySetPolicyIds = $arrayPolicySetPolicyIdsToLower
        if ($builtinPolicySetDefinition.Properties.metadata.deprecated -eq $true -or $builtinPolicySetDefinition.Properties.displayname -like "``[Deprecated``]*") {
            ($htCacheDefinitions).policySet.(($builtinPolicySetDefinition.id).ToLower()).Deprecated = $builtinPolicySetDefinition.Properties.metadata.deprecated
        }
        else {
            ($htCacheDefinitions).policySet.(($builtinPolicySetDefinition.id).ToLower()).Deprecated = $false
        }
        if ($builtinPolicySetDefinition.Properties.metadata.preview -eq $true -or $builtinPolicySetDefinition.Properties.displayname -like "``[*Preview``]*") {
            ($htCacheDefinitions).policySet.(($builtinPolicySetDefinition.id).ToLower()).Preview = $builtinPolicySetDefinition.Properties.metadata.preview
        }
        else {
            ($htCacheDefinitions).policySet.(($builtinPolicySetDefinition.id).ToLower()).Preview = $false
        }
        ($htCacheDefinitions).policySet.(($builtinPolicySetDefinition.id).ToLower()).json = $builtinPolicySetDefinition
    }

    Write-Host " Caching built-in Role definitions"
    $roleDefinitions = Get-AzRoleDefinition -Scope "/subscriptions/$SubscriptionIdForDefinitionCaching" -ErrorAction Stop | Where-Object { $_.IsCustom -eq $false }
    foreach ($roleDefinition in $roleDefinitions) {
        ($htCacheDefinitions).role.($roleDefinition.id) = @{ }
        ($htCacheDefinitions).role.($roleDefinition.id).id = ($roleDefinition.id)
        ($htCacheDefinitions).role.($roleDefinition.id).Name = ($roleDefinition.Name)
        ($htCacheDefinitions).role.($roleDefinition.id).IsCustom = ($roleDefinition.IsCustom)
        ($htCacheDefinitions).role.($roleDefinition.id).AssignableScopes = ($roleDefinition.AssignableScopes)
        ($htCacheDefinitions).role.($roleDefinition.id).Actions = ($roleDefinition.Actions)
        ($htCacheDefinitions).role.($roleDefinition.id).NotActions = ($roleDefinition.NotActions)
        ($htCacheDefinitions).role.($roleDefinition.id).DataActions = ($roleDefinition.DataActions)
        ($htCacheDefinitions).role.($roleDefinition.id).NotDataActions = ($roleDefinition.NotDataActions)
        ($htCacheDefinitions).role.($roleDefinition.id).json = $roleDefinition
        ($htCacheDefinitions).role.($roleDefinition.id).LinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azrolesadvertizer/$($roleDefinition.id).html`" target=`"_blank`">$($roleDefinition.Name)</a>"
    }

    $endDefinitionsCaching = get-date
    Write-Host "Caching built-in definitions duration: $((NEW-TIMESPAN -Start $startDefinitionsCaching -End $endDefinitionsCaching).TotalSeconds) seconds"
    #endregion dataprocessingDefinitionCaching
}
else {
    Write-Host "Run Info:"
    Write-Host " Creating HierarchyMap only" -ForegroundColor Green
}

$arrayEntitiesFromAPISubscriptionsCount = ($arrayEntitiesFromAPI | Where-Object { $_.type -eq "/subscriptions" -and $_.properties.parentNameChain -contains $ManagementGroupId } | Measure-Object).count
$arrayEntitiesFromAPIManagementGroupsCount = ($arrayEntitiesFromAPI | Where-Object { $_.type -eq "Microsoft.Management/managementGroups" -and $_.properties.parentNameChain -contains $ManagementGroupId } | Measure-Object).count + 1

if ($htParameters.HierarchyMapOnly -eq $false) {
    Write-Host "Collecting custom data"
    $startDataCollection = get-date

    dataCollection -mgId $ManagementGroupId

    $endDataCollection = get-date
    Write-Host "Collecting custom data duration: $((NEW-TIMESPAN -Start $startDataCollection -End $endDataCollection).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startDataCollection -End $endDataCollection).TotalSeconds) seconds)"
}
else {
    foreach ($entity in $arrayEntitiesFromAPI) {
        if ($entity.properties.parentNameChain -contains $ManagementGroupID -or $entity.Name -eq $ManagementGroupId) {
            if ($entity.type -eq "/subscriptions") {             
                addRowToTable `
                    -level (($htEntities.($entity.name).ParentNameChain | Measure-Object).Count -1) `
                    -mgName $htEntities.(($entity.properties.parent.id) -replace '.*/').displayName `
                    -mgId (($entity.properties.parent.id) -replace '.*/') `
                    -mgParentId $htEntities.(($entity.properties.parent.id) -replace '.*/').Parent `
                    -mgParentName $htEntities.(($entity.properties.parent.id) -replace '.*/').ParentDisplayName `
                    -Subscription $htEntities.($entity.name).DisplayName `
                    -SubscriptionId $htEntities.($entity.name).Id
            }
            if ($entity.type -eq "Microsoft.Management/managementGroups") {
                addRowToTable `
                    -level ($htEntities.($entity.name).ParentNameChain | Measure-Object).Count `
                    -mgName $entity.properties.displayname `
                    -mgId $entity.Name `
                    -mgParentId $htEntities.($entity.name).Parent `
                    -mgParentName $htEntities.($entity.name).ParentDisplayName
            }
        }
    }
}

$durationDataMG = ($customDataCollectionDuration | Where-Object { $_.Type -eq "MG" })
$durationDataSUB = ($customDataCollectionDuration | Where-Object { $_.Type -eq "SUB" })
$durationMGAverageMaxMin = ($durationDataMG.DurationSec | Measure-Object -Average -Maximum -Minimum)
$durationSUBAverageMaxMin = ($durationDataSUB.DurationSec | Measure-Object -Average -Maximum -Minimum)
Write-Host "Collecting custom data for $($arrayEntitiesFromAPIManagementGroupsCount) ManagementGroups Avg/Max/Min duration in seconds: Average: $([math]::Round($durationMGAverageMaxMin.Average,4)); Maximum: $([math]::Round($durationMGAverageMaxMin.Maximum,4)); Minimum: $([math]::Round($durationMGAverageMaxMin.Minimum,4))"
Write-Host "Collecting custom data for $($arrayEntitiesFromAPISubscriptionsCount) Subscriptions Avg/Max/Min duration in seconds: Average: $([math]::Round($durationSUBAverageMaxMin.Average,4)); Maximum: $([math]::Round($durationSUBAverageMaxMin.Maximum,4)); Minimum: $([math]::Round($durationSUBAverageMaxMin.Minimum,4))"

#APITracking
$APICallTrackingCount = ($arrayAPICallTrackingCustomDataCollection | Measure-Object).Count
$APICallTrackingRetriesCount = ($arrayAPICallTrackingCustomDataCollection | Where-Object { $_.TryCounter -gt 0 } | Measure-Object).Count
$APICallTrackingRestartDueToDuplicateNextlinkCounterCount = ($arrayAPICallTrackingCustomDataCollection | Where-Object { $_.RestartDueToDuplicateNextlinkCounter -gt 0 } | Measure-Object).Count
Write-Host "Collecting custom data APICalls (Management) total count: $APICallTrackingCount ($APICallTrackingRetriesCount retries; $APICallTrackingRestartDueToDuplicateNextlinkCounterCount nextLinkReset)"

$optimizedTableForPathQuery = ($newTable | Select-Object -Property level, mg*, subscription*) | sort-object -Property level, mgid, subscriptionId -Unique
$optimizedTableForPathQueryMgAndSub = ($optimizedTableForPathQuery  | Where-Object { -not [String]::IsNullOrEmpty($_.SubscriptionId) } | Select-Object -Property level, mg*, subscription*) | sort-object -Property level, mgid, mgname, mgparentId, mgparentName, subscriptionId, subscription -Unique
$optimizedTableForPathQueryMg = ($optimizedTableForPathQuery | Where-Object { [String]::IsNullOrEmpty($_.SubscriptionId) } | Select-Object -Property level, mgid, mgName, mgparentid, mgparentName) | sort-object -Property level, mgid, mgname, mgparentId, mgparentName -Unique
$optimizedTableForPathQuerySub = ($optimizedTableForPathQuery | Where-Object { -not [String]::IsNullOrEmpty($_.SubscriptionId) } | Select-Object -Property subscription*) | sort-object -Property subscriptionId -Unique

if ($htParameters.HierarchyMapOnly -eq $false) {
    #region dataprocessingAADGuests
    if (-not $NoAADGuestUsers) {
        Write-Host "Getting AAD Guest Users"
        $startAADGuestUsers = get-date

        $currenttask = "Get AAD Guest Users"
        $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).GraphUrl)/v1.0/users?`$filter=userType eq 'Guest'"
        $method = "GET"
        $aadGuestUsers = AzAPICall -uri $uri -method $method -currentTask $currenttask -getGuests $true

        $aadGuestUsersCount = ($aadGuestUsers | Measure-Object).Count
        Write-Host " Found $aadGuestUsersCount AAD Guest Users"
        if ($aadGuestUsersCount -gt 0) {
            foreach ($aadGuestUser in $aadGuestUsers) {
                $htUserTypes.($aadGuestUser.id) = @{ }
                $htUserTypes.($aadGuestUser.id).userType = "Guest"
            }
        }

        $endAADGuestUsers = Get-Date
        Write-Host "Getting AAD Guest Users duration: $((NEW-TIMESPAN -Start $startAADGuestUsers -End $endAADGuestUsers).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startAADGuestUsers -End $endAADGuestUsers).TotalSeconds) seconds)"
    }
    #endregion dataprocessingAADGuests

    #region dataprocessingAADGroups
    if (-not $NoAADGroupsResolveMembers) {
        $htAADGroupsDetails = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
        $arrayGroupRoleAssignmentsOnServicePrincipals = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        $arrayProgressedAADGroups = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        Write-Host "Resolving AAD Groups"
        $startAADGroupsResolveMembers = get-date
        function GetGroupmembers($aadGroupId, $aadGroupDisplayName) {
            if (-not $htAADGroupsDetails.$aadGroupId) {
                $script:htAADGroupsDetails.$aadGroupId = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                $script:htAADGroupsDetails.($aadGroupId).id = $aadGroupId
                $script:htAADGroupsDetails.($aadGroupId).displayname = $aadGroupDisplayName
                $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).GraphUrl)/beta/groups/$($aadGroupId)/transitiveMembers"
                $method = "GET"
                $aadGroupMembers = AzAPICall -uri $uri -method $method -currentTask "getGroupMembers $($aadGroupId)"

                $aadGroupMembersAll = ($aadGroupMembers)
                $aadGroupMembersUsers = ($aadGroupMembers | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.user" })
                $aadGroupMembersGroups = ($aadGroupMembers | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.group" })
                $aadGroupMembersServicePrincipals = ($aadGroupMembers | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.servicePrincipal" })

                $aadGroupMembersAllCount = ($aadGroupMembersAll | Measure-Object).count
                $aadGroupMembersUsersCount = ($aadGroupMembersUsers | Measure-Object).count
                $aadGroupMembersGroupsCount = ($aadGroupMembersGroups | Measure-Object).count
                $aadGroupMembersServicePrincipalsCount = ($aadGroupMembersServicePrincipals | Measure-Object).count
                #for SP stuff
                if ($aadGroupMembersServicePrincipalsCount -gt 0) {
                    foreach ($aadGroupMembersServicePrincipal in $aadGroupMembersServicePrincipals) {
                        if ($arrayGroupRoleAssignmentsOnServicePrincipals -notcontains $aadGroupMembersServicePrincipal.id) {
                            $null = $arrayGroupRoleAssignmentsOnServicePrincipals.Add($aadGroupMembersServicePrincipal.id)
                        }
                    }
                }

                $script:htAADGroupsDetails.($aadGroupId).MembersAllCount = $aadGroupMembersAllCount
                $script:htAADGroupsDetails.($aadGroupId).MembersUsersCount = $aadGroupMembersUsersCount
                $script:htAADGroupsDetails.($aadGroupId).MembersGroupsCount = $aadGroupMembersGroupsCount
                $script:htAADGroupsDetails.($aadGroupId).MembersServicePrincipalsCount = $aadGroupMembersServicePrincipalsCount

                if ($aadGroupMembersAllCount -gt 0) {
                    $script:htAADGroupsDetails.($aadGroupId).MembersAll = $aadGroupMembersAll
                    
                    if ($aadGroupMembersUsersCount -gt 0) {
                        $script:htAADGroupsDetails.($aadGroupId).MembersUsers = $aadGroupMembersUsers
                    }    
                    if ($aadGroupMembersGroupsCount -gt 0) {
                        $script:htAADGroupsDetails.($aadGroupId).MembersGroups = $aadGroupMembersGroups
                    }   
                    if ($aadGroupMembersServicePrincipalsCount -gt 0) {
                        $script:htAADGroupsDetails.($aadGroupId).MembersServicePrincipals = $aadGroupMembersServicePrincipals
                    }   
                }
            }
        }
        $funcGetGroupmembers = $function:GetGroupmembers.ToString()

        $optimizedTableForAADGroupsQuery = ($newTable | Where-Object { $_.RoleAssignmentIdentityObjectType -eq "Group" } | Select-Object -Property RoleAssignmentIdentityObjectId, RoleAssignmentIdentityDisplayname) | sort-object -Property RoleAssignmentIdentityObjectId -Unique
        $aadGroupsCount = ($optimizedTableForAADGroupsQuery | Measure-Object).Count

        if ($aadGroupsCount -gt 0) {
            Write-Host " processing $($aadGroupsCount) AAD Groups with Role assignments"

            #foreach ($aadGroupIdWithRoleAssignment in $optimizedTableForAADGroupsQuery) {
            $optimizedTableForAADGroupsQuery | ForEach-Object -Parallel {
                $aadGroupIdWithRoleAssignment = $_
                #region UsingVARs
                #fromOtherFunctions
                $arrayAzureManagementEndPointUrls = $using:arrayAzureManagementEndPointUrls
                $checkContext = $using:checkContext
                $htAzureEnvironmentRelatedUrls = $using:htAzureEnvironmentRelatedUrls
                $htBearerAccessToken = $using:htBearerAccessToken
                #Array&HTs
                $htAADGroupsDetails = $using:htAADGroupsDetails
                $arrayGroupRoleAssignmentsOnServicePrincipals = $using:arrayGroupRoleAssignmentsOnServicePrincipals
                $arrayProgressedAADGroups = $using:arrayProgressedAADGroups
                $arrayAPICallTracking = $using:arrayAPICallTracking
                #Functions
                $function:AzAPICall = $using:funcAzAPICall
                $function:createBearerToken = $using:funcCreateBearerToken
                $function:GetJWTDetails = $using:funcGetJWTDetails
                $function:GetGroupmembers = $using:funcGetGroupmembers
                #endregion UsingVARs

                $rndom = Get-Random -Minimum 10 -Maximum 750
                start-sleep -Millisecond $rndom
                
                GetGroupmembers -aadGroupId $aadGroupIdWithRoleAssignment.RoleAssignmentIdentityObjectId -aadGroupDisplayName $aadGroupIdWithRoleAssignment.RoleAssignmentIdentityDisplayname
            
                $null = $script:arrayProgressedAADGroups.Add($aadGroupIdWithRoleAssignment.RoleAssignmentIdentityObjectId)
                $processedAADGroupsCount = $null
                $processedAADGroupsCount = ($arrayProgressedAADGroups).Count
                if ($processedAADGroupsCount) {
                    if ($processedAADGroupsCount % 10 -eq 0) {
                        Write-Host " $processedAADGroupsCount AAD Groups processed"
                    }
                }
            } -ThrottleLimit $ThrottleLimit
        }
        else {
            Write-Host " processing $($aadGroupsCount) AAD Groups with Role assignments"
        }

        $endAADGroupsResolveMembers = Get-Date
        Write-Host "Resolving AAD Groups duration: $((NEW-TIMESPAN -Start $startAADGroupsResolveMembers -End $endAADGroupsResolveMembers).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startAADGroupsResolveMembers -End $endAADGroupsResolveMembers).TotalSeconds) seconds)"
    }
    #endregion dataprocessingAADGroups

    #region dataprocessingAADSP
    if (-not $NoAADServicePrincipalResolve) {
        Write-Host "Getting ServicePrincipals"
        $startAADGetServicePrincipals = get-date
        $arrayAllServicePrincipalsWithRoleAssignment = @()
        $servicePrincipalsWithDirectRoleAssignment = (($newTable | Where-Object { $_.RoleAssignmentIdentityObjectType -eq "ServicePrincipal" } ) | sort-object -Property RoleAssignmentIdentityObjectId -Unique).RoleAssignmentIdentityObjectId
        $servicePrincipalsWithDirectRoleAssignmentCount = ($servicePrincipalsWithDirectRoleAssignment | Measure-Object).Count

        $servicePrincipalsWithDirectRoleAssignmentResourceGroupsAndResources = (($arrayCacheRoleAssignmentsResourceGroups | Where-Object { $_.ObjectType -eq "ServicePrincipal" } ) | sort-object -Property ObjectId -Unique).ObjectId
        $servicePrincipalsWithDirectRoleAssignmentResourceGroupsAndResourcesCount = ($servicePrincipalsWithDirectRoleAssignmentResourceGroupsAndResources | Measure-Object).Count

        write-host " $servicePrincipalsWithDirectRoleAssignmentCount ServicePrincipals with Role assignment on MG/Sub"
        if ($servicePrincipalsWithDirectRoleAssignmentCount -gt 0) {
            foreach ($servicePrincipalWithDirectRoleAssignment in $servicePrincipalsWithDirectRoleAssignment) {
                if ($arrayAllServicePrincipalsWithRoleAssignment -notcontains $servicePrincipalWithDirectRoleAssignment) {
                    $arrayAllServicePrincipalsWithRoleAssignment += $servicePrincipalWithDirectRoleAssignment
                }
            }
        }

        write-host " $servicePrincipalsWithDirectRoleAssignmentResourceGroupsAndResourcesCount ServicePrincipals with Role assignment on RG/Resource"
        if ($servicePrincipalsWithDirectRoleAssignmentResourceGroupsAndResourcesCount -gt 0) {
            foreach ($servicePrincipalWithDirectRoleAssignmentResourceGroupsAndResources in $servicePrincipalsWithDirectRoleAssignmentResourceGroupsAndResources) {
                if ($arrayAllServicePrincipalsWithRoleAssignment -notcontains $servicePrincipalWithDirectRoleAssignmentResourceGroupsAndResources) {
                    $arrayAllServicePrincipalsWithRoleAssignment += $servicePrincipalWithDirectRoleAssignmentResourceGroupsAndResources
                }
            }
        }

        if (-not $NoAADGroupsResolveMembers) {
            if (($arrayGroupRoleAssignmentsOnServicePrincipals | Measure-Object).Count -gt 0) {
                $servicePrincipalsWithInheritedAssignmentFromGroupCount = (($arrayGroupRoleAssignmentsOnServicePrincipals | sort-Object -Unique) | Measure-Object).count
                Write-Host " $($servicePrincipalsWithInheritedAssignmentFromGroupCount) ServicePrincipals with Role Assignment inherited through AAD Group membership"
                foreach ($aadGroupMembersServicePrincipal in $arrayGroupRoleAssignmentsOnServicePrincipals) {
                    if ($arrayAllServicePrincipalsWithRoleAssignment -notcontains $aadGroupMembersServicePrincipal) {
                        $arrayAllServicePrincipalsWithRoleAssignment += $aadGroupMembersServicePrincipal
                    }
                }
            }
        }
        $arrayAllServicePrincipalsWithRoleAssignmentCount = ($arrayAllServicePrincipalsWithRoleAssignment | Measure-Object).count

        if ($arrayAllServicePrincipalsWithRoleAssignmentCount -gt 0) {
            $arrayServicePrincipalRequestResourceNotFound = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
            $arrayApplicationRequestResourceNotFound = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
            Write-Host " processing $($arrayAllServicePrincipalsWithRoleAssignmentCount) unique ServicePrincipals"
            $htServicePrincipalsDetails = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
            $arrayProgressedServicePrincipals = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
            $currentDateUTC = (Get-Date).ToUniversalTime()
            
            $arrayAllServicePrincipalsWithRoleAssignment | ForEach-Object -Parallel {
                $servicePrincipalWithRoleAssignment = $_
                #region UsingVARs
                $currentDateUTC = $using:currentDateUTC
                #fromOtherFunctions
                $arrayAzureManagementEndPointUrls = $using:arrayAzureManagementEndPointUrls
                $checkContext = $using:checkContext
                $htAzureEnvironmentRelatedUrls = $using:htAzureEnvironmentRelatedUrls
                $htBearerAccessToken = $using:htBearerAccessToken
                #Array&HTs
                $userType = $using:userType
                $arrayServicePrincipalRequestResourceNotFound = $using:arrayServicePrincipalRequestResourceNotFound
                $arrayApplicationRequestResourceNotFound = $using:arrayApplicationRequestResourceNotFound
                $htServicePrincipalsDetails = $using:htServicePrincipalsDetails
                $arrayProgressedServicePrincipals = $using:arrayProgressedServicePrincipals
                $arrayAPICallTracking = $using:arrayAPICallTracking
                #Functions
                $function:AzAPICall = $using:funcAzAPICall
                $function:createBearerToken = $using:funcCreateBearerToken
                $function:GetJWTDetails = $using:funcGetJWTDetails
                #endregion UsingVARs

                $rndom = Get-Random -Minimum 10 -Maximum 750
                start-sleep -Millisecond $rndom
                
                if (-not $htServicePrincipalsDetails.($ServicePrincipalWithRoleAssignment)) {
                    $currentTask = "getSP $($servicePrincipalWithRoleAssignment)"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).GraphUrl)/v1.0/servicePrincipals/$($servicePrincipalWithRoleAssignment)"
                    $method = "GET"
                    $getServicePrincipal = AzAPICall -uri $uri -method $method -currentTask $currentTask -listenOn "Content" -getSp $true
                    if ($getServicePrincipal -eq "Request_ResourceNotFound") {
                        $null = $arrayServicePrincipalRequestResourceNotFound.Add([PSCustomObject]@{ 
                                spId = $servicePrincipalWithRoleAssignment
                            })
                    }
                    else {
                        $script:htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment) = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
                        $script:htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).servicePrincipalType = $getServicePrincipal.servicePrincipalType
                        $script:htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).spGraphDetails = $getServicePrincipal
                        $script:htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appOwnerOrganizationId = $getServicePrincipal.appOwnerOrganizationId
                        if ($getServicePrincipal.servicePrincipalType -eq "Application") {

                            if ($getServicePrincipal.appOwnerOrganizationId -eq $checkContext.Subscription.TenantId) {
                                $currentTask = "getApp $($getServicePrincipal.appId)"
                                $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).GraphUrl)/v1.0/applications?`$filter=appId eq '$($getServicePrincipal.appId)'"
                                $method = "GET"
                                $getApplication = AzAPICall -uri $uri -method $method -currentTask $currentTask -getApp $true
                                
                                if ($getApplication -eq "Request_ResourceNotFound") {
                                    $null = $arrayApplicationRequestResourceNotFound.Add([PSCustomObject]@{ 
                                            appId = $getServicePrincipal.appId
                                        })
                                }
                                else {
                                    if (($getApplication | Measure-Object).Count -eq 0) {
                                        Write-Host "$($getServicePrincipal.appId) no data returned / seems non existent?"
                                    }
                                    else {
                                        $script:htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appGraphDetails = $getApplication
                                        $appPasswordCredentialsCount = ($getApplication.passwordCredentials | Measure-Object).count
                                        if ($appPasswordCredentialsCount -gt 0) {
                                            $script:htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appPasswordCredentialsCount = $appPasswordCredentialsCount
                                            $appPasswordCredentialsExpiredCount = 0
                                            $appPasswordCredentialsGracePeriodExpiryCount = 0
                                            $appPasswordCredentialsExpiryOKCount = 0
                                            $appPasswordCredentialsExpiryOKMoreThan2YearsCount = 0
                                            foreach ($appPasswordCredential in $getApplication.passwordCredentials) {
                                                $passwordExpiryTotalDays = (NEW-TIMESPAN -Start $currentDateUTC -End $appPasswordCredential.endDateTime).TotalDays
                                                if ($passwordExpiryTotalDays -lt 0) {
                                                    $appPasswordCredentialsExpiredCount++
                                                }
                                                elseif ($passwordExpiryTotalDays -lt $AADServicePrincipalExpiryWarningDays) {
                                                    $appPasswordCredentialsGracePeriodExpiryCount++
                                                }
                                                else {
                                                    if ($passwordExpiryTotalDays -gt 730) {
                                                        $appPasswordCredentialsExpiryOKMoreThan2YearsCount++
                                                    }
                                                    else {
                                                        $appPasswordCredentialsExpiryOKCount++
                                                    }
                                                }
                                            }
                                            $script:htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appPasswordCredentialsExpiredCount = $appPasswordCredentialsExpiredCount
                                            $script:htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appPasswordCredentialsGracePeriodExpiryCount = $appPasswordCredentialsGracePeriodExpiryCount
                                            $script:htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appPasswordCredentialsExpiryOKCount = $appPasswordCredentialsExpiryOKCount
                                            $script:htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appPasswordCredentialsExpiryOKMoreThan2YearsCount = $appPasswordCredentialsExpiryOKMoreThan2YearsCount
                                        }

                                        $appKeyCredentialsCount = ($getApplication.keyCredentials | Measure-Object).count
                                        if ($appKeyCredentialsCount -gt 0) {
                                            $script:htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appKeyCredentialsCount = $appKeyCredentialsCount
                                            $appKeyCredentialsExpiredCount = 0
                                            $appKeyCredentialsGracePeriodExpiryCount = 0
                                            $appKeyCredentialsExpiryOKCount = 0
                                            $appKeyCredentialsExpiryOKMoreThan2YearsCount = 0
                                            foreach ($appKeyCredential in $getApplication.keyCredentials) {
                                                $keyCredentialExpiryTotalDays = (NEW-TIMESPAN -Start $currentDateUTC -End $appKeyCredential.endDateTime).TotalDays
                                                if ($keyCredentialExpiryTotalDays -lt 0) {
                                                    $appKeyCredentialsExpiredCount++
                                                }
                                                elseif ($keyCredentialExpiryTotalDays -lt $AADServicePrincipalExpiryWarningDays) {
                                                    $appKeyCredentialsGracePeriodExpiryCount++
                                                }
                                                else {
                                                    if ($keyCredentialExpiryTotalDays -gt 730) {
                                                        $appKeyCredentialsExpiryOKMoreThan2YearsCount++
                                                    }
                                                    else {
                                                        $appKeyCredentialsExpiryOKCount++
                                                    }
                                                }
                                            }
                                            $script:htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appKeyCredentialsExpiredCount = $appKeyCredentialsExpiredCount
                                            $script:htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appKeyCredentialsGracePeriodExpiryCount = $appKeyCredentialsGracePeriodExpiryCount
                                            $script:htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appKeyCredentialsExpiryOKCount = $appKeyCredentialsExpiryOKCount
                                            $script:htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appKeyCredentialsExpiryOKMoreThan2YearsCount = $appKeyCredentialsExpiryOKMoreThan2YearsCount
                                        }
                                    }
                                }
                            }
                            else {
                                #Write-Host "----- non matching appOwnerOrg: $($getServicePrincipal.appOwnerOrganizationId)"
                            }
                        }
                        else {
                            #Write-Host "--> $($getServicePrincipal.servicePrincipalType)"
                        }
                    }
                }

                $null = $script:arrayProgressedServicePrincipals.Add($servicePrincipalWithRoleAssignment)
                $processedServicePrincipalsCount = $null
                $processedServicePrincipalsCount = ($arrayProgressedServicePrincipals).Count
                if ($processedServicePrincipalsCount) {
                    if ($processedServicePrincipalsCount % 10 -eq 0) {
                        Write-Host " $processedServicePrincipalsCount ServicePrincipals processed"
                    }
                }

            } -ThrottleLimit $ThrottleLimit
            $servicePrincipalRequestResourceNotFoundCount = ($arrayServicePrincipalRequestResourceNotFound | Measure-Object).Count
            if ($servicePrincipalRequestResourceNotFoundCount -gt 0) {
                Write-Host "$servicePrincipalRequestResourceNotFoundCount ServicePrincipals could not be checked"
            }
            $applicationRequestResourceNotFoundCount = ($arrayApplicationRequestResourceNotFound | Measure-Object).Count
            if ($applicationRequestResourceNotFoundCount -gt 0) {
                Write-Host "$applicationRequestResourceNotFoundCount Applications could not be checked for Secret/certificate expiry"
            }
        }
        else {
            #Write-Host "no roleAssignments on ServicePrincipals ($($arrayAllServicePrincipalsWithRoleAssignmentCount))"
        }

        $htManagedIdentityForPolicyAssignment = @{ }
        $htPolicyAssignmentManagedIdentity = @{ }
        $servicePrincipalsOfTypeManagedIdentity = $htServicePrincipalsDetails.Keys | Where-Object { $htServicePrincipalsDetails.($_).servicePrincipalType -eq "ManagedIdentity" }
        $servicePrincipalsOfTypeManagedIdentityCount = ($servicePrincipalsOfTypeManagedIdentity | Measure-Object).Count
        if ($servicePrincipalsOfTypeManagedIdentityCount -gt 0) {
            foreach ($servicePrincipalOfTypeManagedIdentity in $servicePrincipalsOfTypeManagedIdentity) {
                $miObjectId = $htServicePrincipalsDetails.($servicePrincipalOfTypeManagedIdentity).spGraphDetails.id
                $usageentries = $htServicePrincipalsDetails.($servicePrincipalOfTypeManagedIdentity).spGraphDetails.alternativeNames
                $usageentriesCount = ($usageentries | Measure-Object).Count
                if ($usageentriesCount -gt 0) {
                    foreach ($usageentry in $usageentries) {
                        if ($usageentry -like "*/providers/Microsoft.Authorization/policyAssignments/*") {
                            $htManagedIdentityForPolicyAssignment.($miObjectId) = @{ }
                            $htManagedIdentityForPolicyAssignment.($miObjectId).policyAssignmentId = $usageentry
                            $htPolicyAssignmentManagedIdentity.($usageentry) = @{ }
                            $htPolicyAssignmentManagedIdentity.($usageentry).miObjectId = $miObjectId
                        }
                    }
                }
            }
        }

        $endAADGetServicePrincipals = Get-Date
        Write-Host "Getting ServicePrincipals duration: $((NEW-TIMESPAN -Start $startAADGetServicePrincipals -End $endAADGetServicePrincipals).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startAADGetServicePrincipals -End $endAADGetServicePrincipals).TotalSeconds) seconds)"
    }
    #endregion dataprocessingAADSP

    #resourcesAll
    $resourcesAllGroupedBySubcriptionId = $resourcesAll | group-object -property subscriptionId

    #region dataprocessingCreateTagListArray
    $startTagListArray = Get-Date
    Write-Host "Creating TagList array"

    $tagsSubRgResCount = ($htAllTagList."AllScopes".Keys | Measure-Object).Count
    $tagsSubsriptionCount = ($htAllTagList."Subscription".Keys | Measure-Object).Count
    $tagsResourceGroupCount = ($htAllTagList."ResourceGroup".Keys | Measure-Object).Count
    $tagsResourceCount = ($htAllTagList."Resource".Keys | Measure-Object).Count
    Write-Host " Total Number of ALL unique Tag Names: $tagsSubRgResCount"
    Write-Host " Total Number of Subscription unique Tag Names: $tagsSubsriptionCount"
    Write-Host " Total Number of ResourceGroup unique Tag Names: $tagsResourceGroupCount"
    Write-Host " Total Number of Resource unique Tag Names: $tagsResourceCount"

    foreach ($tagScope in $htAllTagList.keys) {
        foreach ($tagScopeTagName in $htAllTagList.($tagScope).keys) {
            $null = $arrayTagList.Add([PSCustomObject]@{ 
                    Scope    = $tagScope
                    TagName  = ($tagScopeTagName)
                    TagCount = $htAllTagList.($tagScope).($tagScopeTagName)
                })
        }
    }
    $endTagListArray = get-date
    Write-Host "Creating TagList array duration: $((NEW-TIMESPAN -Start $startTagListArray -End $endTagListArray).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startTagListArray -End $endTagListArray).TotalSeconds) seconds)"
    #endregion dataprocessingCreateTagListArray
   
    #region dataprocessingDiagnosticsCapable
    Write-Host "Checking Resource Types Diagnostics capability"
    $startResourceDiagnosticsCheck = get-date
    if (($resourcesAll | Measure-Object).count -gt 0) {

        $resourceTypesUnique = ($resourcesAll | select-object type).type.ToLower() | sort-object -Unique  
        $resourceTypesUniqueCount = ($resourceTypesUnique | Measure-Object).count
        Write-Host " $($resourceTypesUniqueCount) unique Resource Types to process"
        $resourceTypesSummarizedArray = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        $resourcesTypeAllCountTotal = 0
        ($resourcesAll).count_ | ForEach-Object { $resourcesTypeAllCountTotal += $_ }
        foreach ($resourceTypeUnique in $resourceTypesUnique) {
            $resourcesTypeCountTotal = 0
            ($resourcesAll | Where-Object { $_.type -eq $resourceTypeUnique }).count_ | ForEach-Object { $resourcesTypeCountTotal += $_ }
            $null = $resourceTypesSummarizedArray.Add([PSCustomObject]@{
                    ResourceType  = $resourceTypeUnique
                    ResourceCount = $resourcesTypeCountTotal 
                })
        }

        $resourceTypesDiagnosticsArray = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        $resourceTypesSummarizedArray.ResourceType | ForEach-Object -Parallel {
            $resourcetype = $_
            #region UsingVARs
            #fromOtherFunctions
            $arrayAzureManagementEndPointUrls = $using:arrayAzureManagementEndPointUrls
            $checkContext = $using:checkContext
            $htAzureEnvironmentRelatedUrls = $using:htAzureEnvironmentRelatedUrls
            $htBearerAccessToken = $using:htBearerAccessToken
            #Array&HTs
            $ExludedResourceTypesDiagnosticsCapable = $using:ExludedResourceTypesDiagnosticsCapable
            $resourceTypesDiagnosticsArray = $using:resourceTypesDiagnosticsArray
            $htResourceTypesUniqueResource = $using:htResourceTypesUniqueResource
            $resourceTypesSummarizedArray = $using:resourceTypesSummarizedArray
            $arrayAPICallTracking = $using:arrayAPICallTracking
            #Functions
            $function:AzAPICallDiag = $using:funcAzAPICallDiag
            $function:createBearerToken = $using:funcCreateBearerToken
            $function:GetJWTDetails = $using:funcGetJWTDetails
            #endregion UsingVARs

            $skipThisResourceType = $false
            if (($ExludedResourceTypesDiagnosticsCapable | Measure-Object).Count -gt 0) {
                foreach ($excludedResourceType in $ExludedResourceTypesDiagnosticsCapable) {
                    if ($excludedResourceType -eq $resourcetype) {
                        $skipThisResourceType = $true
                    }
                }
            }
            
            if ($skipThisResourceType -eq $false) {
                $resourceCount = ($resourceTypesSummarizedArray | Where-Object { $_.Resourcetype -eq $resourcetype }).ResourceCount

                $resourceCheck = "undone"
                $tryCounter = 0
                do{
                    $tryCounter++
                    $getResource = Search-AzGraph -Query "resources | where type =~ '$($resourcetype)'" -First 1
                    if (($getResource | Measure-Object).Count -ne 1){
                        $sleepSec = @(1,2,3,5,10,20,30,40,50,60,60)[$tryCounter]
                        Write-Host "Getting a resourceId for resourceType $($resourcetype) #try: $($tryCounter) (count (based on CustomDataCollection): $($resourceCount)) not successful. The resource(s) might meanwhile have been deleted - better check.. try again; sleep $sleepSec seconds"
                        Start-Sleep -Seconds $sleepSec
                    }
                    else{
                        $resourceCheck = "done"
                        $resourceId = $getResource.id
                    }
                }
                until($resourceCheck -eq "done" -or $tryCounter -gt 10)
                
                if ($resourceCheck -eq "undone"){
                    Write-Host "Getting a resourceId for resourceType $($resourcetype) skipped"
                    $null = $script:resourceTypesDiagnosticsArray.Add([PSCustomObject]@{
                        ResourceType  = $resourcetype
                        Metrics       = "skipped"
                        Logs          = "skipped"
                        LogCategories = "skipped"
                        ResourceCount = [int]$resourceCount 
                    })
                }
                else{
                    #thx @Jim Britt (Microsoft) https://github.com/JimGBritt/AzurePolicy/tree/master/AzureMonitor/Scripts Create-AzDiagPolicy.ps1
                    $responseJSON = ''
                    $logCategories = @()
                    $metrics = $false
                    $logs = $false
        
                    $currentTask = "Checking if ResourceType '$resourceType' is capable for Resource Diagnostics using ResourceId: '$($resourceId)'"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)$($resourceId)/providers/microsoft.insights/diagnosticSettingsCategories/?api-version=2017-05-01-preview"
                    #$path = "$($resourceId)/providers/microsoft.insights/diagnosticSettingsCategories/?api-version=2017-05-01-preview"
                    $method = "GET"
                            
                    ((AzAPICallDiag -uri $uri -method $method -currentTask $currentTask -resourceType $resourcetype))
                    if ($responseJSON) {                
                        foreach ($response in $responseJSON.value) {
                            if ($response.properties.categoryType -eq "Metrics") {
                                $metrics = $true
                            }
                            if ($response.properties.categoryType -eq "Logs") {
                                $logs = $true
                                $logCategories += $response.name
                            }
                        }
                    }

                    $null = $script:resourceTypesDiagnosticsArray.Add([PSCustomObject]@{
                            ResourceType  = $resourcetype
                            Metrics       = $metrics
                            Logs          = $logs
                            LogCategories = $logCategories
                            ResourceCount = [int]$resourceCount 
                        })
                }    

                
            }
            else {
                Write-Host "Skipping ResourceType $($resourcetype) as per '`$ExludedResourceTypesDiagnosticsCapable'"
            }

            
        } -ThrottleLimit $ThrottleLimit
    }
    else {
        Write-Host " No Resources at all"
    }
    $endResourceDiagnosticsCheck = get-date
    Write-Host "Checking Resource Types Diagnostics capability duration: $((NEW-TIMESPAN -Start $startResourceDiagnosticsCheck -End $endResourceDiagnosticsCheck).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startResourceDiagnosticsCheck -End $endResourceDiagnosticsCheck).TotalSeconds) seconds)"
    #endregion dataprocessingDiagnosticsCapable


    Write-Host "Create helper hash table"
    $startHelperHt = get-date
    $htPoliciesUsedInPolicySets = @{ }
    $policySetshlpr = ($htCacheDefinitions).policySet.keys
    $customPolicySetshlprCount = ( $policySetshlpr | Measure-Object).Count
    if ($customPolicySetshlprCount -gt 0) {
        foreach ($policySet in $policySetshlpr) {
            $PolicySetPolicyIds = ($htCacheDefinitions).policySet.($policySet).PolicySetPolicyIds
            foreach ($PolicySetPolicyId in $PolicySetPolicyIds) {
                $hlper = ($htCacheDefinitions).policySet.($policySet)
                if ($hlper.LinkToAzAdvertizer){
                    $hlperDisplayNameWithOrWithoutLinkToAzAdvertizer = "$($hlper.LinkToAzAdvertizer) ($($hlper.PolicyDefinitionId))"
                }
                else{
                    $hlperDisplayNameWithOrWithoutLinkToAzAdvertizer = "<b>$($hlper.DisplayName)</b> ($($hlper.PolicyDefinitionId))"
                }
                if (-not $htPoliciesUsedInPolicySets.($PolicySetPolicyId)) {
                    $htPoliciesUsedInPolicySets.($PolicySetPolicyId) = @{ }
                    $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySet = [array]$hlperDisplayNameWithOrWithoutLinkToAzAdvertizer
                }
                else{
                    $array = @()
                    $array = $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySet
                    $array += $hlperDisplayNameWithOrWithoutLinkToAzAdvertizer
                    $htPoliciesUsedInPolicySets.($PolicySetPolicyId).policySet = $array
                }
            }
        }
    }
   
    $endHelperHt = get-date
    Write-Host "Create helper hash table duration: $((NEW-TIMESPAN -Start $startHelperHt -End $endHelperHt).TotalSeconds) seconds"
        
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

$parentMgBaseQuery = ($optimizedTableForPathQueryMg | Where-Object { $_.MgParentId -eq $getMgParentId })
$parentMgNamex = $parentMgBaseQuery.mgParentName | Get-Unique
$parentMgIdx = $parentMgBaseQuery.mgParentId | Get-Unique
$ManagementGroupIdCaseSensitived = (($optimizedTableForPathQueryMg | Where-Object { $_.MgId -eq $ManagementGroupId }).mgId) | Get-Unique

if ($htParameters.HierarchyMapOnly -eq $false) {
    #region preQueries
    Write-Host " Building preQueries"
    
    if ($htParameters.IncludeResourceGroupsAndResources -eq $true) {
        $policyBaseQuery = $newTable | Where-Object { -not [String]::IsNullOrEmpty($_.PolicyVariant) } | Sort-Object -Property PolicyType, Policy | Select-Object -Property Level, Policy*, mgId, mgname, SubscriptionId, Subscription
    }
    else {
        $policyBaseQuery = $newTable | Where-Object { -not [String]::IsNullOrEmpty($_.PolicyVariant) -and ($_.PolicyAssignmentScopeMgSubRgRes -eq "Mg" -or $_.PolicyAssignmentScopeMgSubRgRes -eq "Sub") } | Sort-Object -Property PolicyType, Policy | Select-Object -Property Level, Policy*, mgId, mgname, SubscriptionId, Subscription
    }

    $policyBaseQuerySubscriptions = $policyBaseQuery | Where-Object { -not [String]::IsNullOrEmpty($_.SubscriptionId) }
    $policyBaseQueryManagementGroups = $policyBaseQuery | Where-Object { [String]::IsNullOrEmpty($_.SubscriptionId) }
    $policyPolicyBaseQueryScopeInsights = ($policyBaseQuery | Select-Object Mg*, Subscription*, PolicyAssigmentAtScopeCount, PolicySetAssigmentAtScopeCount, PolicyAndPolicySetAssigmentAtScopeCount, PolicyAssigmentLimit -Unique)
    $policyBaseQueryUniqueAssignments = $policyBaseQuery | Select-Object -Property Policy* | sort-object -Property PolicyAssignmentId -Unique
    $policyPolicyBaseQueryUniqueAssignmentsArrayList = [System.Collections.ArrayList]@()
    foreach ($policyBaseQueryUniqueAssignment in $policyBaseQueryUniqueAssignments) {
        if ($policyBaseQueryUniqueAssignment.PolicyVariant -eq "Policy") {
            $null = $policyPolicyBaseQueryUniqueAssignmentsArrayList.Add($policyBaseQueryUniqueAssignment)
        }
    }
    
    $policyPolicySetBaseQueryUniqueAssignments = $policyBaseQueryUniqueAssignments | Where-Object { $_.PolicyVariant -eq "PolicySet" } 
    $policyBaseQueryUniqueCustomDefinitions = ($policyBaseQuery | Where-Object { $_.PolicyType -eq "Custom" }) | select-object PolicyVariant, PolicyDefinitionId -Unique
    $policyPolicyBaseQueryUniqueCustomDefinitions = ($policyBaseQueryUniqueCustomDefinitions | Where-Object { $_.PolicyVariant -eq "Policy" }).PolicyDefinitionId
    $policyPolicySetBaseQueryUniqueCustomDefinitions = ($policyBaseQueryUniqueCustomDefinitions | Where-Object { $_.PolicyVariant -eq "PolicySet" }).PolicyDefinitionId

    $rbacBaseQuery = $newTable | Where-Object { -not [String]::IsNullOrEmpty($_.RoleDefinitionName) } | Sort-Object -Property RoleIsCustom, RoleDefinitionName | Select-Object -Property Level, Role*, mgId, MgName, SubscriptionId, Subscription

    #rbacArrayList
    $startcreateArrayListRBAC = get-date
    $rbacBaseQueryArrayList = [System.Collections.ArrayList]@()
    $rbacBaseQueryArrayListNotGroupOwner = [System.Collections.ArrayList]@()
    $rbacBaseQueryArrayListNotGroupUserAccessAdministrator = [System.Collections.ArrayList]@()
    foreach ($rbac in $rbacBaseQuery) {
        $null = $rbacBaseQueryArrayList.Add($rbac)
        if ($rbac.RoleAssignmentIdentityObjectType -ne "Group"){
            if ($rbac.RoleDefinitionName -eq "Owner"){
                $null = $rbacBaseQueryArrayListNotGroupOwner.Add($rbac)
            }
            if ($rbac.RoleDefinitionName -eq "User Access Administrator"){
                $null = $rbacBaseQueryArrayListNotGroupUserAccessAdministrator.Add($rbac)
            }
        }
    }
    $endcreateArrayListRBAC = get-date
    Write-Host "  Create ArrayListsRBAC duration: $((NEW-TIMESPAN -Start $startcreateArrayListRBAC -End $endcreateArrayListRBAC).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startcreateArrayListRBAC -End $endcreateArrayListRBAC).TotalSeconds) seconds)"
    
    
    
    $blueprintBaseQuery = $newTable | Where-Object { -not [String]::IsNullOrEmpty($_.BlueprintName) }
    $mgsAndSubs = (($optimizedTableForPathQuery | Where-Object { $_.mgId -ne "" -and $_.Level -ne "0" }) | select-object MgId, SubscriptionId -unique)

    $tenantAllPolicies = ($htCacheDefinitions).policy.keys
    $tenantAllPoliciesCount = ($tenantAllPolicies | measure-object).count
    $tenantCustomPolicies = ($htCacheDefinitions).policy.keys | Where-Object { ($htCacheDefinitions).policy.($_).Type -eq "Custom" }
    $tenantCustomPoliciesCount = ($tenantCustomPolicies | measure-object).count
    $customPoliciesArray = [System.Collections.ArrayList]@()
    $allPoliciesArray = [System.Collections.ArrayList]@()
    if ($tenantAllPoliciesCount -gt 0) {
        foreach ($tenantPolicy in $tenantAllPolicies) {
            
            if (($htCacheDefinitions).policy.($tenantPolicy).Type -eq "Custom") {
                $null = $customPoliciesArray.Add([PSCustomObject]@{ 
                        Description        = ($htCacheDefinitions).policy.($tenantPolicy).Description
                        effectFixedValue   = ($htCacheDefinitions).policy.($tenantPolicy).effectFixedValue
                        PolicyDefinitionId = ($htCacheDefinitions).policy.($tenantPolicy).PolicyDefinitionId
                        effectDefaultValue = ($htCacheDefinitions).policy.($tenantPolicy).effectDefaultValue
                        Type               = ($htCacheDefinitions).policy.($tenantPolicy).Type
                        DisplayName        = ($htCacheDefinitions).policy.($tenantPolicy).DisplayName
                        id                 = ($htCacheDefinitions).policy.($tenantPolicy).id
                        json               = ($htCacheDefinitions).policy.($tenantPolicy).json
                        Deprecated         = ($htCacheDefinitions).policy.($tenantPolicy).Deprecated
                        Preview            = ($htCacheDefinitions).policy.($tenantPolicy).Preview
                        effectAllowedValue = ($htCacheDefinitions).policy.($tenantPolicy).effectAllowedValue
                        Category           = ($htCacheDefinitions).policy.($tenantPolicy).Category
                        Scope              = ($htCacheDefinitions).policy.($tenantPolicy).Scope   
                        ScopeMgSub         = ($htCacheDefinitions).policy.($tenantPolicy).ScopeMgSub  
                        ScopeId            = ($htCacheDefinitions).policy.($tenantPolicy).ScopeId 
                        RoleDefinitionIds  = ($htCacheDefinitions).policy.($tenantPolicy).RoleDefinitionIds 
                    })
            }
            $null = $allPoliciesArray.Add([PSCustomObject]@{ 
                    Description        = ($htCacheDefinitions).policy.($tenantPolicy).Description
                    effectFixedValue   = ($htCacheDefinitions).policy.($tenantPolicy).effectFixedValue
                    PolicyDefinitionId = ($htCacheDefinitions).policy.($tenantPolicy).PolicyDefinitionId
                    effectDefaultValue = ($htCacheDefinitions).policy.($tenantPolicy).effectDefaultValue
                    Type               = ($htCacheDefinitions).policy.($tenantPolicy).Type
                    DisplayName        = ($htCacheDefinitions).policy.($tenantPolicy).DisplayName
                    id                 = ($htCacheDefinitions).policy.($tenantPolicy).id
                    json               = ($htCacheDefinitions).policy.($tenantPolicy).json
                    Deprecated         = ($htCacheDefinitions).policy.($tenantPolicy).Deprecated
                    Preview            = ($htCacheDefinitions).policy.($tenantPolicy).Preview
                    effectAllowedValue = ($htCacheDefinitions).policy.($tenantPolicy).effectAllowedValue
                    Category           = ($htCacheDefinitions).policy.($tenantPolicy).Category
                    Scope              = ($htCacheDefinitions).policy.($tenantPolicy).Scope   
                    ScopeMgSub         = ($htCacheDefinitions).policy.($tenantPolicy).ScopeMgSub  
                    ScopeId            = ($htCacheDefinitions).policy.($tenantPolicy).ScopeId 
                    RoleDefinitionIds  = ($htCacheDefinitions).policy.($tenantPolicy).RoleDefinitionIds
                })
        }
    }

    $tenantAllPolicySets = ($htCacheDefinitions).policySet.keys
    $tenantAllPolicySetsCount = ($tenantAllPolicySets | measure-object).count
    $tenantCustomPolicySets = ($htCacheDefinitions).policySet.keys | Where-Object { ($htCacheDefinitions).policySet.($_).Type -eq "Custom" }
    $tenantCustompolicySetsCount = ($tenantCustomPolicySets | measure-object).count
    $customPolicySetsArray = [System.Collections.ArrayList]@()
    $allPolicySetsArray = [System.Collections.ArrayList]@()
    if ($tenantAllPolicySetsCount -gt 0) {
        foreach ($tenantPolicySet in $tenantAllPolicySets) {
            if (($htCacheDefinitions).policySet.($tenantPolicySet).Type -eq "Custom") {
                $null = $customPolicySetsArray.Add([PSCustomObject]@{ 
                        Description        = ($htCacheDefinitions).policySet.($tenantPolicySet).Description
                        PolicySetPolicyIds = ($htCacheDefinitions).policySet.($tenantPolicySet).PolicySetPolicyIds
                        PolicyDefinitionId = ($htCacheDefinitions).policySet.($tenantPolicySet).PolicyDefinitionId
                        Type               = ($htCacheDefinitions).policySet.($tenantPolicySet).Type
                        DisplayName        = ($htCacheDefinitions).policySet.($tenantPolicySet).DisplayName
                        id                 = ($htCacheDefinitions).policySet.($tenantPolicySet).id
                        Deprecated         = ($htCacheDefinitions).policySet.($tenantPolicySet).Deprecated
                        Preview            = ($htCacheDefinitions).policySet.($tenantPolicySet).Preview
                        json               = ($htCacheDefinitions).policySet.($tenantPolicySet).json
                        Category           = ($htCacheDefinitions).policySet.($tenantPolicySet).Category
                        Scope              = ($htCacheDefinitions).policySet.($tenantPolicySet).Scope   
                        ScopeMgSub         = ($htCacheDefinitions).policySet.($tenantPolicySet).ScopeMgSub  
                        ScopeId            = ($htCacheDefinitions).policySet.($tenantPolicySet).ScopeId       
                    })
            }
            $null = $allPolicySetsArray.Add([PSCustomObject]@{ 
                    Description        = ($htCacheDefinitions).policySet.($tenantPolicySet).Description
                    PolicySetPolicyIds = ($htCacheDefinitions).policySet.($tenantPolicySet).PolicySetPolicyIds
                    PolicyDefinitionId = ($htCacheDefinitions).policySet.($tenantPolicySet).PolicyDefinitionId
                    Type               = ($htCacheDefinitions).policySet.($tenantPolicySet).Type
                    DisplayName        = ($htCacheDefinitions).policySet.($tenantPolicySet).DisplayName
                    id                 = ($htCacheDefinitions).policySet.($tenantPolicySet).id
                    Deprecated         = ($htCacheDefinitions).policySet.($tenantPolicySet).Deprecated
                    Preview            = ($htCacheDefinitions).policySet.($tenantPolicySet).Preview
                    json               = ($htCacheDefinitions).policySet.($tenantPolicySet).json
                    Category           = ($htCacheDefinitions).policySet.($tenantPolicySet).Category
                    Scope              = ($htCacheDefinitions).policySet.($tenantPolicySet).Scope   
                    ScopeMgSub         = ($htCacheDefinitions).policySet.($tenantPolicySet).ScopeMgSub  
                    ScopeId            = ($htCacheDefinitions).policySet.($tenantPolicySet).ScopeId  
                })
        }
    }
    

    #region assignments    
    $htCacheAssignments2 = @{ }
    ($htCacheAssignments2).policy = @{ }
    foreach ($policyAssignment in $policyBaseQueryUniqueAssignments) {
        if (-not ($htCacheAssignments2).policy.($policyAssignment.PolicyAssignmentId)) {
            ($htCacheAssignments2).policy.($policyAssignment.PolicyAssignmentId) = $policyAssignment
        }
    }
    #endregion assignments

    #region assignmentRgRes
    $htPoliciesWithAssignmentOnRgRes = @{ }
    foreach ($policyAssignmentRgRes in $arrayCachePolicyAssignmentsResourceGroupsAndResources | Sort-Object -Property id -Unique){
        $hlperPolDefId = (($policyAssignmentRgRes.properties.policyDefinitionId).Tolower())
        if (-not $htPoliciesWithAssignmentOnRgRes.($hlperPolDefId)){
            $pscustomObj = [System.Collections.ArrayList]@()
            $null = $pscustomObj.Add([PSCustomObject]@{ 
                PolicyAssignmentId             = ($policyAssignmentRgRes.id).tolower()
                PolicyAssignmentDisplayName    = $policyAssignmentRgRes.properties.displayName
            })
            $htPoliciesWithAssignmentOnRgRes.($hlperPolDefId) = @{ }
            $htPoliciesWithAssignmentOnRgRes.($hlperPolDefId).Assignments = [array](($pscustomObj))
        }
        else{
            $pscustomObj = [System.Collections.ArrayList]@()
            $null = $pscustomObj.Add([PSCustomObject]@{ 
                PolicyAssignmentId             = ($policyAssignmentRgRes.id).tolower()
                PolicyAssignmentDisplayName    = $policyAssignmentRgRes.properties.displayName
            })
            $array = @()
            $array += $htPoliciesWithAssignmentOnRgRes.($hlperPolDefId).Assignments
            $array += (($pscustomObj))
            $htPoliciesWithAssignmentOnRgRes.($hlperPolDefId).Assignments = $array
        }
    }

    #$htPoliciesWithAssignmentOnRgRes.Keys
    #$arrayCachePolicyAssignmentsResourceGroupsAndResources.properties.policyDefinitionId | Sort-Object -Unique
    #endregion assignmentRgRes


    $tenantAllRoles = $($htCacheDefinitions).role.keys
    $tenantAllRolesCount = ($tenantAllRoles | Measure-Object).Count
    $tenantCustomRoles = $($htCacheDefinitions).role.keys | Where-Object { ($htCacheDefinitions).role.($_).IsCustom -eq $True }
    $tenantCustomRolesCount = ($tenantCustomRoles | Measure-Object).Count
    $tenantCustomRolesArray = [System.Collections.ArrayList]@()
    $tenantAllRolesArray = [System.Collections.ArrayList]@()
    foreach ($tenantRole in $tenantAllRoles) {
        if (($htCacheDefinitions).role.($tenantRole).IsCustom -eq $true) {
            $null = $tenantCustomRolesArray.Add(($htCacheDefinitions).role.($tenantRole))
        }
        $null = $tenantAllRolesArray.Add(($htCacheDefinitions).role.($tenantRole))
    }

    $mgSubRoleAssignmentsArray = [System.Collections.ArrayList]@()
    foreach ($roleAssignment in ($htCacheAssignments).role.Keys) {
        $null = $mgSubRoleAssignmentsArray.Add(($htCacheAssignments).role.$roleAssignment)
    }

    $rgResRoleAssignmentsArray = [System.Collections.ArrayList]@()
    foreach ($roleAssignment in ($htCacheAssignments).rbacOnResourceGroupsAndResources.Keys) {
        $null = $rgResRoleAssignmentsArray.Add(($htCacheAssignments).rbacOnResourceGroupsAndResources.$roleAssignment)
    }

    if ((($htResourceProvidersAll).Keys | Measure-Object).Count -gt 0) {
        $arrayResourceProvidersAll = foreach ($subscription in ($htResourceProvidersAll).Keys) {
            ($htResourceProvidersAll).($subscription).Providers
        }
    }

    Write-Host " Build SubscriptionsMgPath"
    $subscriptionIds = ($optimizedTableForPathQuerySub).SubscriptionId
    $htAllSubsMgPath = @{ }
    foreach ($subscriptionId in $subscriptionIds) {
        $htAllSubsMgPath.($subscriptionId) = @{ }
        createMgPathSub -subid $subscriptionId
        [array]::Reverse($submgPathArray)
        $htAllSubsMgPath.($subscriptionId).path = $submgPathArray
    }

    Write-Host " Build MgPaths"
    $htAllMgsPath = @{ }
    foreach ($mgid in (($optimizedTableForPathQuery | Where-Object { [String]::IsNullOrEmpty($_.SubscriptionId) } ).mgid)) {
        $htAllMgsPath.($mgid) = @{ }
        createMgPath -mgid $mgid
        [array]::Reverse($mgPathArray)
        $htAllMgsPath.($mgid).path = $mgPathArray
    }
    $endHelperQueries = get-date
    Write-Host "Helper Queries duration: $((NEW-TIMESPAN -Start $startHelperQueries -End $endHelperQueries).TotalSeconds) seconds"
    #endregion preQueries

    #region summarizeDataCollectionResults
    Write-Host "Summary data collection"
    $mgsDetails = ($optimizedTableForPathQueryMg | Select-Object Level, MgId -Unique)
    $mgDepth = ($mgsDetails.Level | Measure-Object -maximum).Maximum
    $totalMgCount = ($mgsDetails | Measure-Object).count
    $totalSubCount = ($optimizedTableForPathQuerySub | Measure-Object).count
    $totalSubOutOfScopeCount = ($outOfScopeSubscriptions | Measure-Object).count
    $totalSubIncludedAndExcludedCount = $totalSubCount + $totalSubOutOfScopeCount
    $totalPolicyDefinitionsCustomCount = ((($htCacheDefinitions).policy.keys | Where-Object { ($htCacheDefinitions).policy.($_).Type -eq "Custom" }) | Measure-Object).count
    $totalPolicySetDefinitionsCustomCount = ((($htCacheDefinitions).policySet.keys | Where-Object { ($htCacheDefinitions).policySet.($_).Type -eq "Custom" }) | Measure-Object).count

    if ($htParameters.IncludeResourceGroupsAndResources -eq $true) {
        $totalPolicyAssignmentsCount = (($htCacheAssignments2).policy.keys | Measure-Object).count
        $totalPolicyAssignmentsCountMg = (($htCacheAssignments2).policy.keys | Where-Object { ($htCacheAssignments2).policy.($_).PolicyAssignmentScopeMgSubRgRes -eq "Mg" } | Measure-Object).count
        $totalPolicyAssignmentsCountSub = (($htCacheAssignments2).policy.keys | Where-Object { ($htCacheAssignments2).policy.($_).PolicyAssignmentScopeMgSubRgRes -eq "Sub" } | Measure-Object).count
        $totalPolicyAssignmentsCountRgRes = (($htCacheAssignments2).policy.keys | Where-Object { ($htCacheAssignments2).policy.($_).PolicyAssignmentScopeMgSubRgRes -eq "Rg" -or ($htCacheAssignments2).policy.($_).PolicyAssignmentScopeMgSubRgRes -eq "Res" } | Measure-Object).count
    }
    else {
        $totalPolicyAssignmentsCount = (($htCacheAssignments2).policy.keys | Measure-Object).count
        $totalPolicyAssignmentsCountMg = (($htCacheAssignments2).policy.keys | Where-Object { ($htCacheAssignments2).policy.($_).PolicyAssignmentScopeMgSubRgRes -eq "Mg" } | Measure-Object).count
        $totalPolicyAssignmentsCountSub = (($htCacheAssignments2).policy.keys | Where-Object { ($htCacheAssignments2).policy.($_).PolicyAssignmentScopeMgSubRgRes -eq "Sub" } | Measure-Object).count
        $totalPolicyAssignmentsCountRgRes = ($arrayCachePolicyAssignmentsResourceGroupsAndResources | Measure-Object).count
        $totalPolicyAssignmentsCount = $totalPolicyAssignmentsCount + $totalPolicyAssignmentsCountRgRes
    }

    $totalRoleDefinitionsCustomCount = ((($htCacheDefinitions).role.keys | Where-Object { ($htCacheDefinitions).role.($_).IsCustom -eq $True }) | Measure-Object).count
    $totalRoleAssignmentsCount = (($htCacheAssignments).role.keys | Measure-Object).count
    $totalRoleAssignmentsResourceGroupsAndResourcesCount = ($arrayCacheRoleAssignmentsResourceGroups | Measure-Object).count
    $totalBlueprintDefinitionsCount = ((($htCacheDefinitions).blueprint.keys) | Measure-Object).count
    $totalBlueprintAssignmentsCount = (($htCacheAssignments).blueprint.keys | Measure-Object).count
    $totalResourceTypesCount = ($resourceTypesDiagnosticsArray | Measure-Object).Count

    Write-Host " Total Management Groups: $totalMgCount (depth $mgDepth)"
    Write-Host " Total Subscriptions: $totalSubIncludedAndExcludedCount ($totalSubCount included; $totalSubOutOfScopeCount out-of-scope)"
    Write-Host " Total Custom Policy Definitions: $totalPolicyDefinitionsCustomCount"
    Write-Host " Total Custom PolicySet Definitions: $totalPolicySetDefinitionsCustomCount"
    Write-Host " Total Policy Assignments: $($totalPolicyAssignmentsCount)"
    Write-Host " Total Policy Assignments ManagementGroups $($totalPolicyAssignmentsCountMg)"
    Write-Host " Total Policy Assignments Subscriptions $($totalPolicyAssignmentsCountSub)"
    Write-Host " Total Policy Assignments ResourceGroups & Resources: $($totalPolicyAssignmentsCountRgRes)"
    Write-Host " Total Custom Roles: $totalRoleDefinitionsCustomCount"
    Write-Host " Total Role Assignments: $($totalRoleAssignmentsCount + $totalRoleAssignmentsResourceGroupsAndResourcesCount)"
    Write-Host " Total Role Assignments (ManagementGroups and Subscriptions): $totalRoleAssignmentsCount"
    Write-Host " Total Role Assignments (ResourceGroups and Resources): $totalRoleAssignmentsResourceGroupsAndResourcesCount"
    Write-Host " Total Blueprint Definitions: $totalBlueprintDefinitionsCount"
    Write-Host " Total Blueprint Assignments: $totalBlueprintAssignmentsCount"
    Write-Host " Total Resources: $resourcesTypeAllCountTotal"
    Write-Host " Total Resource Types: $totalResourceTypesCount"
    #endregion summarizeDataCollectionResults
}

#filename
if ($htParameters.AzureDevOpsWikiAsCode -eq $true) { 
    $fileName = "AzGovViz_$($ManagementGroupIdCaseSensitived)"
    if ($htParameters.HierarchyMapOnly -eq $true) {
        $fileName = "AzGovViz_$($ManagementGroupIdCaseSensitived)_HierarchyMapOnly"
    }
    else {
        $fileName = "AzGovViz_$($ManagementGroupIdCaseSensitived)"
    }
}
else {
    if ($htParameters.HierarchyMapOnly -eq $true) {
        $fileName = "AzGovViz_$($AzGovVizVersion)_$($fileTimestamp)_$($ManagementGroupIdCaseSensitived)_HierarchyMapOnly"
    }
    else {
        $fileName = "AzGovViz_$($AzGovVizVersion)_$($fileTimestamp)_$($ManagementGroupIdCaseSensitived)"
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
    <link rel="stylesheet" type="text/css" href="https://www.azadvertizer.net/azgovvizv4/css/azgovvizmain_004_027.css">
    <script src="https://code.jquery.com/jquery-1.7.2.js" integrity="sha256-FxfqH96M63WENBok78hchTCDxmChGFlo+/lFIPcZPeI=" crossorigin="anonymous"></script>
    <script src="https://code.jquery.com/ui/1.8.18/jquery-ui.js" integrity="sha256-lzf/CwLt49jbVoZoFcPZOc0LlMYPFBorVSwMsTs2zsA=" crossorigin="anonymous"></script>
    <script type="text/javascript" src="https://www.azadvertizer.net/azgovvizv4/js/highlight_v004_001.js"></script>
    <script src="https://use.fontawesome.com/0c0b5cbde8.js"></script>
    <script src="https://www.azadvertizer.net/azgovvizv4/tablefilter/tablefilter.js"></script>

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/10.5.0/styles/github.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/10.5.0/highlight.min.js"></script>
    <script>hljs.initHighlightingOnLoad();</script>

    <script>
        `$(window).load(function() {
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
        var filename = 'export_' + table_id + '_' + new Date().toLocaleDateString() + '.csv';
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
        var filename = 'export_' + table_id + '_' + new Date().toLocaleDateString() + '.csv';
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
<body>
    <div class="se-pre-con"></div>
    <div class="tree">
        <div class="hierarchyTree" id="hierarchyTree">
            <p class="pbordered pborderedspecial">HierarchyMap</p>
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
    
    if ($htParameters.AzureDevOpsWikiAsCode -eq $false) {
        $tenantDetailsDisplay = "$tenantDisplayName<br>$tenantDefaultDomain<br>"
    }
    else {
        $tenantDetailsDisplay = ""
    }
    if ($parentMgIdx -eq $defaultManagementGroupId) {
        $classdefaultMG = "defaultMG"
    }
    else {
        $classdefaultMG = ""
    }
    $html += @"
            <ul>
                <li id ="first">
                    <a class="tenant"><div class="fitme" id="fitme">$($tenantDetailsDisplay)$(($checkContext).Tenant.id)</div></a>
                    <ul>
                        <li><a class="mgnonradius parentmgnotaccessible $($classdefaultMG)"><img class="imgMgTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"><div class="fitme" id="fitme">$mgNameAndOrId</div></a>
                        <ul>
"@
}

$starthierarchyMap = get-date
Write-Host " Building HierarchyMap"

hierarchyMgHTML -mgChild $ManagementGroupIdCaseSensitived

$endhierarchyMap = get-date
Write-Host " Building HierarchyMap duration: $((NEW-TIMESPAN -Start $starthierarchyMap -End $endhierarchyMap).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $starthierarchyMap -End $endhierarchyMap).TotalSeconds) seconds)"

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

if ($htParameters.HierarchyMapOnly -eq $false) {

    $html += @"
    <div class="summprnt" id="summprnt">
    <div class="summary" id="summary"><p class="pbordered">TenantSummary</p>
"@

    $html | Set-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
    $html = $null

    $startSummary = get-date

    summary

    $endSummary = get-date
    Write-Host " Building TenantSummary duration: $((NEW-TIMESPAN -Start $startSummary -End $endSummary).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startSummary -End $endSummary).TotalSeconds) seconds)"

    $html += @"
    </div><!--summary-->
    </div><!--summprnt-->

    <div class="definitioninsightsprnt" id="definitioninsightsprnt">
    <div class="definitioninsights" id="definitioninsights"><p class="pbordered">DefinitionInsights</p>
"@
    $html | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
    $html = $null

    definitionInsights

    $html += @"
    </div><!--definitionInsights-->
    </div><!--definitionInsightsprnt-->
"@

    if (-not $NoScopeInsights) {

        $html += @"
    <div class="hierprnt" id="hierprnt">
    <div class="hierarchyTables" id="hierarchyTables"><p class="pbordered">ScopeInsights</p>
"@

    
        $html | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
        $html = $null
        Write-Host " Building ScopeInsights"
        $startHierarchyTable = get-date

        $script:scopescnter = 0
        tableMgHTML -mgChild $ManagementGroupIdCaseSensitived -mgChildOf $getMgParentId

        $endHierarchyTable = get-date
        Write-Host " Building ScopeInsights duration: $((NEW-TIMESPAN -Start $startHierarchyTable -End $endHierarchyTable).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startHierarchyTable -End $endHierarchyTable).TotalSeconds) seconds)"
        
    
        $html += @"
    </div>
    </div>
"@
    }
}

$html += @"
    <div class="footer">
    <div class="VersionDiv VersionLatest"></div>
    <div class="VersionDiv VersionThis"></div>
    <div class="VersionAlert"></div>
"@

if ($htParameters.HierarchyMapOnly -eq $false) {
    $endAzGovVizHTML = get-date
    $AzGovVizHTMLDuration = (NEW-TIMESPAN -Start $startAzGovViz -End $endAzGovVizHTML).TotalMinutes
    $paramsUsed += "Creation duration: $AzGovVizHTMLDuration minutes &#13;"
    if (-not $NoScopeInsights) {
        $html += @"
        <abbr style="text-decoration:none" title="$($paramsUsed)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr> <button id="hierarchyTreeShowHide" onclick="toggleHierarchyTree()">Hide HierarchyMap</button> <button id="summaryShowHide" onclick="togglesummprnt()">Hide TenantSummary</button> <button id="definitionInsightsShowHide" onclick="toggledefinitioninsightsprnt()">Hide DefinitionInsights</button> <button id="hierprntShowHide" onclick="togglehierprnt()">Hide ScopeInsights</button>
        <hr>
"@
    }
    else {
        $html += @"
        <abbr style="text-decoration:none" title="$($paramsUsed)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr> <button id="hierarchyTreeShowHide" onclick="toggleHierarchyTree()">Hide HierarchyMap</button> <button id="summaryShowHide" onclick="togglesummprnt()">Hide TenantSummary</button> <button id="definitionInsightsShowHide" onclick="toggledefinitioninsightsprnt()">Hide DefinitionInsights</button>
"@

    }
}

$html += @"
    </div>
    <script src="https://www.azadvertizer.net/azgovvizv4/js/toggle_v004_003.js"></script>
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
Write-Host "Building HTML total duration: $((NEW-TIMESPAN -Start $startBuildHTML -End $endBuildHTML).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startBuildHTML -End $endBuildHTML).TotalSeconds) seconds)"
#endregion BuildHTML

#region BuildMD
Write-Host "Building Markdown"
$startBuildMD = get-date
$arrayMgs = [System.Collections.ArrayList]@()
$arraySubs = [System.Collections.ArrayList]@()
$arraySubsOos = [System.Collections.ArrayList]@()
$markdown = $null
$markdownhierarchyMgs = $null
$markdownhierarchySubs = $null
$markdownTable = $null

if ($htParameters.AzureDevOpsWikiAsCode -eq $true) { 
    $markdown += @"
# AzGovViz - Management Group Hierarchy

## Hierarchy Diagram (Mermaid)

::: mermaid
    graph $($AzureDevOpsWikiHierarchyDirection.ToUpper());`n
"@
}
else {
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
"@

if (($arraySubsOos | Measure-Object).count -gt 0) {
    $markdown += @"
 classDef subsoos fill:#FFCBC7,stroke:#56595E,stroke-width:1px;
"@
}

$markdown += @"
 classDef mgrprnts fill:#FFFFFF,stroke:#56595E,stroke-width:1px;
 class $(($arrayMgs | sort-object -unique) -join ",") mgr;
 class $(($arraySubs | sort-object -unique) -join ",") subs;
"@

if (($arraySubsOos | Measure-Object).count -gt 0) {
    $markdown += @"
 class $(($arraySubsOos | sort-object -unique) -join ",") subsoos;
"@
}

$markdown += @"
 class $mermaidprnts mgrprnts;
:::

## Summary
`n
"@
if ($htParameters.HierarchyMapOnly -eq $false) {
    $markdown += @"
Total Management Groups: $totalMgCount (depth $mgDepth)\`n
"@

if (($arraySubsOos | Measure-Object).count -gt 0) {
    $markdown += @"
Total Subscriptions: $totalSubIncludedAndExcludedCount (<font color="#FF0000">$totalSubOutOfScopeCount</font> out-of-scope)\`n
"@
}
else {
    $markdown += @"
Total Subscriptions: $totalSubIncludedAndExcludedCount\`n
"@  
}

    $markdown += @"
Total Custom Policy Definitions: $totalPolicyDefinitionsCustomCount\
Total Custom PolicySet Definitions: $totalPolicySetDefinitionsCustomCount\
Total Policy Assignments: $($totalPolicyAssignmentsCount)\
Total Policy Assignments ManagementGroups $($totalPolicyAssignmentsCountMg)\
Total Policy Assignments Subscriptions $($totalPolicyAssignmentsCountSub)\
Total Policy Assignments ResourceGroups & Resources: $($totalPolicyAssignmentsCountRgRes)\
Total Custom Roles: $totalRoleDefinitionsCustomCount\
Total Role Assignments: $($totalRoleAssignmentsCount + $totalRoleAssignmentsResourceGroupsAndResourcesCount)\
Total Role Assignments (ManagementGroups and Subscriptions): $totalRoleAssignmentsCount\
Total Role Assignments (ResourceGroups and Resources): $totalRoleAssignmentsResourceGroupsAndResourcesCount\
Total Blueprint Definitions: $totalBlueprintDefinitionsCount\
Total Blueprint Assignments: $totalBlueprintAssignmentsCount\
Total Resources: $resourcesTypeAllCountTotal\
Total Resource Types: $totalResourceTypesCount
"@

}
if ($htParameters.HierarchyMapOnly -eq $true) {
    $mgsDetails = ($optimizedTableForPathQueryMg | Select-Object Level, MgId -Unique)
    $mgDepth = ($mgsDetails.Level | Measure-Object -maximum).Maximum
    $totalMgCount = ($mgsDetails | Measure-Object).count
    $totalSubCount = ($optimizedTableForPathQuerySub | Measure-Object).count

    $markdown += @"
Total Management Groups: $totalMgCount (depth $mgDepth)\
Total Subscriptions: $totalSubCount
"@

}

$markdown += @"
`n
## Hierarchy Table

| **MgLevel** | **MgName** | **MgId** | **MgParentName** | **MgParentId** | **SubName** | **SubId** |
|-------------|-------------|-------------|-------------|-------------|-------------|-------------|
$markdownTable
"@

$markdown | Set-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).md" -Encoding utf8 -Force
$endBuildMD = get-date
Write-Host "Building Markdown total duration: $((NEW-TIMESPAN -Start $startBuildMD -End $endBuildMD).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startBuildMD -End $endBuildMD).TotalMinutes) seconds)"
#endregion BuildMD

#region BuildCSV
Write-Host "Exporting CSV"
$startBuildCSV = get-date
if ($CsvExportUseQuotesAsNeeded) {
    $newTable | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).csv" -Delimiter "$csvDelimiter" -NoTypeInformation -UseQuotes AsNeeded
}
else {
    $newTable | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).csv" -Delimiter "$csvDelimiter" -NoTypeInformation
}

$endBuildCSV = get-date
Write-Host "Exporting CSV total duration: $((NEW-TIMESPAN -Start $startBuildCSV -End $endBuildCSV).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startBuildCSV -End $endBuildCSV).TotalSeconds) seconds)"
#endregion BuildCSV


#region BuildConsumptionCSV
if ($htParameters.HierarchyMapOnly -eq $false) {
    if ($htParameters.NoAzureConsumption -eq $false) {
        if (-not $NoAzureConsumptionReportExportToCSV) {
            Write-Host "Exporting Consumption CSV"
            $startBuildConsumptionCSV = get-date
            if ($CsvExportUseQuotesAsNeeded) {
                $allConsumptionData | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_Consumption.csv" -Delimiter "$csvDelimiter" -NoTypeInformation -UseQuotes AsNeeded
            }
            else {
                $allConsumptionData | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_Consumption.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
            }
            $endBuildConsumptionCSV = get-date
            Write-Host "Exporting Consumption CSV total duration: $((NEW-TIMESPAN -Start $startBuildConsumptionCSV -End $endBuildConsumptionCSV).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startBuildCSV -End $endBuildCSV).TotalSeconds) seconds)"
        }
    }
}
#endregion BuildConsumptionCSV

#endregion createoutputs

#APITracking
$APICallTrackingCount = ($arrayAPICallTracking | Measure-Object).Count
$APICallTrackingManagementCount = ($arrayAPICallTracking | Where-Object { $_.TargetEndpoint -eq "ManagementAPI" } | Measure-Object).Count
$APICallTrackingGraphCount = ($arrayAPICallTracking | Where-Object { $_.TargetEndpoint -eq "GraphAPI" } | Measure-Object).Count
$APICallTrackingRetriesCount = ($arrayAPICallTracking | Where-Object { $_.TryCounter -gt 0 } | Measure-Object).Count
$APICallTrackingRestartDueToDuplicateNextlinkCounterCount = ($arrayAPICallTracking | Where-Object { $_.RestartDueToDuplicateNextlinkCounter -gt 0 } | Measure-Object).Count
Write-Host "AzGovViz APICalls total count: $APICallTrackingCount ($APICallTrackingManagementCount ManagementAPI; $APICallTrackingGraphCount GraphAPI; $APICallTrackingRetriesCount retries; $APICallTrackingRestartDueToDuplicateNextlinkCounterCount nextLinkReset)"

$endAzGovViz = get-date
Write-Host "AzGovViz duration: $((NEW-TIMESPAN -Start $startAzGovViz -End $endAzGovViz).TotalMinutes) minutes"

#end
$endTime = get-date -format "dd-MMM-yyyy HH:mm:ss"
Write-Host "End AzGovViz $endTime"
if ($DoTranscript){
    Stop-Transcript
}
