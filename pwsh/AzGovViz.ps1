<#v4_fix_20210109_0
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
    default is to break script at error, whilst in AzDO we will Write-Error "Error"
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

.PARAMETER NoServicePrincipalResolve
    use this parameter if Azure Active Directory Service Principals should not be resolved for Role assignments where identity type is 'ServicePrincipal'

.PARAMETER ServicePrincipalExpiryWarningDays
    use this parameter if not using parameter -NoServicePrincipalResolve. Secret and Certificate expiry warning for lifetime below ServicePrincipalExpiryWarningDays (days); default is 14 days

.PARAMETER NoAzureConsumption
    use this parameter if Azure Consumption data should not be reported

.PARAMETER AzureConsumptionPeriod
    use this parameter to define for which time period Azure Consumption data should be gathered; default is 1 day

.PARAMETER NoAzureConsumptionReportExportToCSV
    use this parameter if Azure Consumption data should not be exported (CSV)


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

    Define if Azure Active Directory Service Principals should not be resolved for Role assignments where identity type is 'ServicePrincipal'
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -NoServicePrincipalResolve

    Define Service Principal Secret and Certificate grace period (lifetime below the defined will be marked for warning / default is 14 days)
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -ServicePrincipalExpiryWarningDays 30

    Define if Azure Consumption data should not be reported
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -NoAzureConsumption

    Define for which time period (days) Azure Consumption data should be gathered; e.g. 14 days; default is 1 day
    PS C:\>.\AzGovViz.ps1 -ManagementGroupId <your-Management-Group-Id> -AzureConsumptionPeriod 14

.NOTES
    AUTHOR: Julian Hayward - Customer Engineer - Customer Success Unit | Azure Infrastucture/Automation/Devops/Governance | Microsoft

.LINK
    https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting
    Please note that while being developed by a Microsoft employee, AzAdvertizer is not a Microsoft service or product. AzAdvertizer is a personal driven project, there are none implicit or explicit obligations related to this project, it is provided 'as is' with no warranties and confer no rights.
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
    [switch]$DebugAzAPICall,
    [switch]$NoPolicyComplianceStates,
    [switch]$NoResourceDiagnosticsPolicyLifecycle,
    [switch]$NoAADGroupsResolveMembers,
    [switch]$NoServicePrincipalResolve,
    [int]$ServicePrincipalExpiryWarningDays = 14,
    [switch]$NoAzureConsumption,
    [int]$AzureConsumptionPeriod = 1,
    [switch]$NoAzureConsumptionReportExportToCSV,

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
if ($DebugAzAPICall -eq $false) {
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
function Get-JWTDetails {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string]$token
    )

    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }

    # Token
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

    # Signature
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

    # Convert Expiry time to PowerShell DateTime
    $orig = (Get-Date -Year 1970 -Month 1 -Day 1 -hour 0 -Minute 0 -Second 0 -Millisecond 0)
    $timeZone = Get-TimeZone
    $utcTime = $orig.AddSeconds($decodedToken.exp)
    $offset = $timeZone.GetUtcOffset($(Get-Date)).TotalMinutes #Daylight saving needs to be calculated
    $localTime = $utcTime.AddMinutes($offset)     # Return local time,
    
    $decodedToken | Add-Member -Type NoteProperty -Name "expiryDateTime" -Value $localTime
    
    # Time to Expiry
    $timeToExpiry = ($localTime - (get-date))
    $decodedToken | Add-Member -Type NoteProperty -Name "timeToExpiry" -Value $timeToExpiry

    return $decodedToken
}
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
        #$azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile;
        #$profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile);
        $contextForGraphToken = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        #$graphSession = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForGraphToken.Account, $contextForGraphToken.Environment, $contextForGraphToken.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "https://graph.microsoft.com")
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForGraphToken.Account, $contextForGraphToken.Environment, $contextForGraphToken.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "https://graph.microsoft.com")
        }
        catch {
            $catchResult = $_
        }
    }
    if ($catchResult -ne "letscheck") {
        Write-Host "-ERROR processing new bearer token request ($targetEndPoint): $catchResult" -ForegroundColor Red
        Write-Host "Likely your Azure credentials have not been set up or have expired, please run 'Connect-AzAccount' to set up your Azure credentials."
        Write-Host "It could also well be that there are multiple context in cache, please run 'Clear-AzContext' and then run 'Connect-AzAccount'."
        break script
    }
    $dateTimeTokenCreated = (get-date -format "MM/dd/yyyy HH:mm:ss")
    if ($targetEndPoint -eq "ManagementAPI") {
        $script:bearerAccessTokenManagement = $newBearerAccessTokenRequest.AccessToken
    }
    if ($targetEndPoint -eq "GraphAPI") {
        $script:bearerAccessTokenGraph = $newBearerAccessTokenRequest.AccessToken
    }
    $bearerDetails = Get-JWTDetails -token $newBearerAccessTokenRequest.AccessToken
    $bearerAccessTokenExpiryDateTime = $bearerDetails.expiryDateTime
    $bearerAccessTokenTimeToExpiry = $bearerDetails.timeToExpiry
    Write-Host "+Bearer token details ($targetEndPoint): [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']"
}
#endregion createbearertoken

#API
#region azapicall
function AzAPICall($uri, $method, $currentTask, $body, $listenOn, $getConsumption, $getApp) {
    $tryCounter = 0
    $tryCounterUnexpectedError = 0
    $retryAuthorizationFailed = 5
    $retryAuthorizationFailedCounter = 0
    $apiCallResultsCollection = @()
    $initialUri = $uri
    $restartDueToDuplicateNextlinkCounter = 0

    do {
        if ($arrayAzureManagementEndPointUrls | Where-Object { $uri -match $_ }) {
            $targetEndpoint = "ManagementAPI"
            $bearerToUse = $bearerAccessTokenManagement
        }
        else {
            $targetEndpoint = "GraphAPI"
            $bearerToUse = $bearerAccessTokenGraph
        }

        $unexpectedError = $false
        $tryCounter++
        if ($Script:debugAzAPICall -eq $true) { Write-Host "  DEBUGTASK: attempt#$($tryCounter) processing: $($currenttask)" }
        try {
            if ($body) {
                write-host "has BODY"
                $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -body $body -Headers @{"Content-Type" = "application/json"; "Authorization" = "Bearer $bearerToUse" } -ContentType "application/json" -UseBasicParsing
            }
            else {
                $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -Headers @{"Content-Type" = "application/json"; "Authorization" = "Bearer $bearerToUse" } -UseBasicParsing
            }
        }
        catch {
            try {
                $catchResultPlain = $_.ErrorDetails.Message
                $catchResult = ($catchResultPlain | ConvertFrom-Json)
            }
            catch {
                $catchResult = $catchResultPlain
                $tryCounterUnexpectedError++
                $unexpectedError = $true
            }
        }
        
        if ($unexpectedError -eq $false) {
            if ($Script:debugAzAPICall -eq $true) { Write-Host "   DEBUG: unexpectedError: false" }
            if ($azAPIRequest.StatusCode -ne 200) {
                if ($Script:debugAzAPICall -eq $true) { Write-Host "   DEBUG: apiStatusCode: $($azAPIRequest.StatusCode)" }
                if ($catchResult.error.code -like "*GatewayTimeout*" -or $catchResult.error.code -like "*BadGatewayConnection*" -or $catchResult.error.code -like "*InvalidGatewayHost*" -or $catchResult.error.code -like "*ServerTimeout*" -or $catchResult.error.code -like "*ServiceUnavailable*" -or $catchResult.code -like "*ServiceUnavailable*" -or $catchResult.error.code -like "*MultipleErrorsOccurred*" -or $catchResult.error.code -like "*InternalServerError*" -or $catchResult.error.code -like "*RequestTimeout*" -or $catchResult.error.code -like "*AuthorizationFailed*" -or $catchResult.error.code -like "*ExpiredAuthenticationToken*" -or $catchResult.error.code -like "*ResponseTooLarge*" -or $catchResult.error.code -like "*InvalidAuthenticationToken*" -or ($getConsumption -and $catchResult.error.code -eq 404) -or ($getApp -and $catchResult.error.code -like "*Request_ResourceNotFound*")) {
                    if ($catchResult.error.code -like "*ResponseTooLarge*") {
                        Write-Host "###### LIMIT #################################"
                        Write-Host "Hitting LIMIT getting Policy Compliance States!"
                        Write-Host "ErrorCode: $($catchResult.error.code)"
                        Write-Host "ErrorMessage: $($catchResult.error.message)"
                        Write-Host "There is nothing we can do about this right now. Please run AzGovViz with the following parameter: '-NoPolicyComplianceStates'." -ForegroundColor Yellow
                        Write-Host "Impact using parameter '-NoPolicyComplianceStates': only policy compliance states will not be available in the various AzGovViz outputs - all other output remains." -ForegroundColor Yellow
                        if ($AzureDevOpsWikiAsCode) {
                            Write-Error "Error"
                        }
                        else {
                            break script
                        }
                    }
                    if ($catchResult.error.code -like "*GatewayTimeout*" -or $catchResult.error.code -like "*BadGatewayConnection*" -or $catchResult.error.code -like "*InvalidGatewayHost*" -or $catchResult.error.code -like "*ServerTimeout*" -or $catchResult.error.code -like "*ServiceUnavailable*" -or $catchResult.code -like "*ServiceUnavailable*" -or $catchResult.error.code -like "*MultipleErrorsOccurred*" -or $catchResult.error.code -like "*InternalServerError*" -or $catchResult.error.code -like "*RequestTimeout*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again"
                        Start-Sleep -Milliseconds 250
                    }
                    if ($catchResult.error.code -like "*AuthorizationFailed*") {
                        if ($retryAuthorizationFailedCounter -gt $retryAuthorizationFailed) {
                            Write-Host " $currentTask - try #$tryCounter; returned: '$($catchResult.error.code)' | '$($catchResult.error.message)' - $retryAuthorizationFailed retries failed - investigate that error!/exit"
                            if ($AzureDevOpsWikiAsCode) {
                                Write-Error "Error"
                            }
                            else {
                                break script
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
                    if ($getConsumption -and $catchResult.error.code -eq 404){
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Subscriptions was created only recently - skipping"
                        return $apiCallResultsCollection
                    }
                    if ($getApp -and $catchResult.error.code -like "*Request_ResourceNotFound*"){
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) uncertain ServicePrincipal status - skipping for now :)"
                        return "Request_ResourceNotFound"
                    }
                }
                else {
                    Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) investigate that error!/exit"
                    if ($AzureDevOpsWikiAsCode) {
                        Write-Error "Error"
                    }
                    else {
                        break script
                    }
                }
            }
            else {
                if ($Script:debugAzAPICall -eq $true) { Write-Host "   DEBUG: apiStatusCode: $($azAPIRequest.StatusCode)" }
                $azAPIRequestConvertedFromJson = ($azAPIRequest.Content | ConvertFrom-Json)
                if ($listenOn -eq "Content") {       
                    if ($Script:debugAzAPICall -eq $true) { Write-Host "   DEBUG: listenOn=content ($((($azAPIRequestConvertedFromJson) | Measure-Object).count))" }      
                    $apiCallResultsCollection += $azAPIRequestConvertedFromJson
                }
                else {       
                    if (($azAPIRequestConvertedFromJson).value) {
                        if ($Script:debugAzAPICall -eq $true) { Write-Host "   DEBUG: listenOn=default(value) value exists ($((($azAPIRequestConvertedFromJson).value | Measure-Object).count))" }
                        $apiCallResultsCollection += ($azAPIRequestConvertedFromJson).value
                    }
                    else {
                        if ($Script:debugAzAPICall -eq $true) { Write-Host "   DEBUG: listenOn=default(value) value not exists; return empty array" }
                    }
                }

                $isMore = $false
                if ($azAPIRequestConvertedFromJson.nextLink) {
                    $isMore = $true
                    if ($uri -eq $azAPIRequestConvertedFromJson.nextLink){
                        if ($restartDueToDuplicateNextlinkCounter -gt 3){
                            Write-Host " $currentTask restartDueToDuplicateNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                            if ($AzureDevOpsWikiAsCode) {
                                Write-Error "Error"
                            }
                            else {
                                break script
                            }
                        }
                        else{
                            $restartDueToDuplicateNextlinkCounter++
                            Write-Host "nextLinkLog: uri is equal to nextLinkUri"
                            Write-Host "nextLinkLog: uri: $uri"
                            Write-Host "nextLinkLog: nextLinkUri: $($azAPIRequestConvertedFromJson.nextLink)"
                            Write-Host "nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
                            $apiCallResultsCollection = @()
                            $uri = $initialUri
                            Start-Sleep -Seconds 1
                            createBearerToken -targetEndPoint $targetEndpoint
                            Start-Sleep -Seconds 1
                        }
                    }
                    else{
                        $uri = $azAPIRequestConvertedFromJson.nextLink
                    }
                    if ($Script:debugAzAPICall -eq $true) { Write-Host "   DEBUG: nextLink: $Uri" }
                }
                elseIf ($azAPIRequestConvertedFromJson."@oData.nextLink") {
                    $isMore = $true
                    if ($uri -eq $azAPIRequestConvertedFromJson."@odata.nextLink"){
                        if ($restartDueToDuplicateNextlinkCounter -gt 3){
                            Write-Host " $currentTask restartDueToDuplicate@odataNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                            if ($AzureDevOpsWikiAsCode) {
                                Write-Error "Error"
                            }
                            else {
                                break script
                            }
                        }
                        else{
                            $restartDueToDuplicateNextlinkCounter++
                            Write-Host "nextLinkLog: uri is equal to @odata.nextLinkUri"
                            Write-Host "nextLinkLog: uri is equal to @odata.nextLinkUri"
                            Write-Host "nextLinkLog: uri: $uri"
                            Write-Host "nextLinkLog: @odata.nextLinkUri: $($azAPIRequestConvertedFromJson."@odata.nextLink")"
                            Write-Host "nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
                            $apiCallResultsCollection = @()
                            $uri = $initialUri
                            Start-Sleep -Seconds 1
                            createBearerToken -targetEndPoint $targetEndpoint
                            Start-Sleep -Seconds 1
                        }
                    }
                    else{
                        $uri = $azAPIRequestConvertedFromJson."@odata.nextLink"
                    }
                    if ($Script:debugAzAPICall -eq $true) { Write-Host "   DEBUG: @oData.nextLink: $Uri" }
                }
                else {
                    if ($Script:debugAzAPICall -eq $true) { Write-Host "   DEBUG: NextLink: none" }
                }
            }
        }
        else {
            if ($Script:debugAzAPICall -eq $true) { Write-Host "   DEBUG: unexpectedError: notFalse" }
            if ($tryCounterUnexpectedError -lt 6) {
                Write-Host " $currentTask #$tryCounterUnexpectedError 'Unexpected Error' occurred (trying 5 times)"
                Write-Host $catchResult
                Start-Sleep -Seconds 2
            }
            else {
                Write-Host " $currentTask #$tryCounterUnexpectedError 'Unexpected Error' occurred (tried 5 times)/exit"
                if ($AzureDevOpsWikiAsCode) {
                    Write-Error "Error"
                }
                else {
                    break script
                }
            }
        }
    }
    until($azAPIRequest.StatusCode -eq 200 -and -not $isMore)
    return $apiCallResultsCollection
}
#endregion azapicall

#region azapicalldiag
function AzAPICallDiag($uri, $method, $currentTask, $resourceType) {
    $tryCounter = 0
    $tryCounterUnexpectedError = 0
    


    do {
        if ($arrayAzureManagementEndPointUrls | Where-Object { $uri -match $_ }) {
            $targetEndpoint = "ManagementAPI"
            $bearerToUse = $bearerAccessTokenManagement
        }
        else {
            $targetEndpoint = "GraphAPI"
            $bearerToUse = $bearerAccessTokenGraph
        }

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
                $catchResult = ($catchResultPlain | ConvertFrom-Json)
                #$catchResult = ($_.ErrorDetails.Message | ConvertFrom-Json)
            }
            catch {
                $catchResult = $catchResultPlain
                $tryCounterUnexpectedError++
                $unexpectedError = $true
            }
        }
        if ($unexpectedError -eq $false) {
            if ($azAPIRequest.StatusCode -ne 200) {
                if ($catchResult.error.code -like "*GatewayTimeout*" -or $catchResult.error.code -like "*BadGatewayConnection*" -or $catchResult.error.code -like "*InvalidGatewayHost*" -or $catchResult.error.code -like "*ServerTimeout*" -or $catchResult.error.code -like "*ServiceUnavailable*" -or $catchResult.code -like "*ServiceUnavailable*" -or $catchResult.error.code -like "*MultipleErrorsOccurred*" -or $catchResult.error.code -like "*InternalServerError*" -or $catchResult.error.code -like "*RequestTimeout*" -or $catchResult.error.code -like "*AuthorizationFailed*" -or $catchResult.code -like "*NotSupported*" -or $catchResult.error.code -like "*ExpiredAuthenticationToken*") {
                    if ($catchResult.error.code -like "*GatewayTimeout*" -or $catchResult.error.code -like "*BadGatewayConnection*" -or $catchResult.error.code -like "*InvalidGatewayHost*" -or $catchResult.error.code -like "*ServerTimeout*" -or $catchResult.error.code -like "*ServiceUnavailable*" -or $catchResult.code -like "*ServiceUnavailable*" -or $catchResult.error.code -like "*MultipleErrorsOccurred*" -or $catchResult.error.code -like "*InternalServerError*" -or $catchResult.error.code -like "*RequestTimeout*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again"
                        Start-Sleep -Milliseconds 250
                    }
                    if ($catchResult.code -like "*NotSupported*") {
                        Write-Host "  $($catchResult.code) | $($catchResult.message)"
                    }
                    if ($catchResult.error.code -like "*AuthorizationFailed*") {
                        if ($retryAuthorizationFailedCounter -gt $retryAuthorizationFailed) {
                            Write-Host " $currentTask - try #$tryCounter; returned: '$($catchResult.error.code)' | '$($catchResult.error.message)' - $retryAuthorizationFailed retries failed - investigate that error!"
                            if ($AzureDevOpsWikiAsCode) {
                                Write-Error "Error"
                            }
                            else {
                                break script
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
                    if ($AzureDevOpsWikiAsCode) {
                        Write-Error "Error"
                    }
                    else {
                        break script
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
                Start-Sleep -Seconds 2
            }
            else {
                if ($AzureDevOpsWikiAsCode) {
                    Write-Error "Error"
                }
                else {
                    break script
                }
            }
        }
    }
    until($azAPIRequest.StatusCode -eq 200 -or $catchResult.code -like "*NotSupported*")
}
#endregion azapicalldiag

#start
$startTime = get-date -format "dd-MMM-yyyy HH:mm:ss"
Write-Host "Start AzGovViz $startTime"

#test required Az modules cmdlets
#region testAzModules
$testCommands = @('Get-AzContext', 'Get-AzPolicyDefinition', 'Search-AzGraph')
$azModules = @('Az.Accounts', 'Az.Resources', 'Az.ResourceGraph')

Write-Host "Testing required Az modules cmdlets"
foreach ($testCommand in $testCommands) {
    if (-not (Get-Command $testCommand -ErrorAction Ignore)) {
        if ($AzureDevOpsWikiAsCode) {
            Write-Error "AzModule test failed: cmdlet $testCommand not available - make sure the modules $($azModules -join ", ") are installed"
            Write-Error "Error"
        }
        else {
            Write-Host " AzModule test failed: cmdlet $testCommand not available - make sure the modules $($azModules -join ", ") are installed" -ForegroundColor Red
            break script
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
    if ($AzureDevOpsWikiAsCode) {
        Write-Error "Error"
    }
    else {
        break script
    }
}
else {
    $accountType = $checkContext.Account.Type
    $accountId = $checkContext.Account.Id
    Write-Host " Context AccountId: '$($accountId)'" -ForegroundColor Yellow
    Write-Host " Context AccountType: '$($accountType)'" -ForegroundColor Yellow

    if (-not $checkContext.Subscription) {
        $checkContext
        Write-Host " Context test failed: Context is not set to any Subscription. Set your context to a subscription by running: Set-AzContext -subscription <subscriptionId> (run Get-AzSubscription to get the list of available Subscriptions). When done re-run AzGovViz" -ForegroundColor Red
        if ($AzureDevOpsWikiAsCode) {
            Write-Error "Error"
        }
        else {
            break script
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
}
#endregion environmentcheck

#create bearer token
createBearerToken -targetEndPoint "ManagementAPI"
#graphToken only required for certain scenarios
if (-not $NoAADGroupsResolveMembers -or -not $NoServicePrincipalResolve) {
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

#filedir
if (-not [IO.Path]::IsPathRooted($outputPath)) {
    $outputPath = Join-Path -Path (Get-Location).Path -ChildPath $outputPath
}
$outputPath = Join-Path -Path $outputPath -ChildPath '.'
$outputPath = [IO.Path]::GetFullPath($outputPath)
if (-not (test-path $outputPath)) {
    Write-Host "path $outputPath does not exist -create it!" -ForegroundColor Red
    break script
}
else {
    Write-Host "Output/Files will be created in path $outputPath"
}
$DirectorySeparatorChar = [IO.Path]::DirectorySeparatorChar
$fileTimestamp = (get-date -format "yyyyMMddHHmmss")

#time
$executionDateTimeInternationalReadable = get-date -format "dd-MMM-yyyy HH:mm:ss"
$currentTimeZone = (Get-TimeZone).Id
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
        break script
    }

    [array]$MgtGroupArray = Add-IndexNumberToArray ($getAzManagementGroups)
    if (-not $MgtGroupArray) {
        Write-Host "Seems you do not have access to any Management Group. Please make sure you have the required RBAC role [Reader] assigned on at least one Management Group" -ForegroundColor Red
        break script
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
$table.columns.add((New-Object system.Data.DataColumn PolicyDescription, ([string])))
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
$table.columns.add((New-Object system.Data.DataColumn PolicyAssignmentDescription, ([string])))
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
        $PolicyDescription,
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
        $PolicyAssignmentDescription,
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
    $row.PolicyDescription = $PolicyDescription
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
    $row.PolicyAssignmentDescription = $PolicyAssignmentDescription
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
$script:dataCollectionManagementGroupsCounter = 0
$script:dataCollectionSubscriptionsCounter = 0

function dataCollection($mgId, $hierarchyLevel, $mgParentId, $mgParentName) {
    $startMgLoop = get-date
    $script:dataCollectionManagementGroupsCounter++
    $hierarchyLevel++
    $getMg = $arrayEntitiesFromAPI | Where-Object { $_.type -eq "Microsoft.Management/managementGroups" -and $_.name -eq $mgId }
    Write-Host " CustomDataCollection: Processing MG ($($script:dataCollectionManagementGroupsCounter)/$($arrayEntitiesFromAPIManagementGroupsCount)) L$($hierarchyLevel) '$($getMg.properties.displayName)' ('$($getMg.Name)')"

    if (-not $HierarchyMapOnly) {

        if (-not $NoPolicyComplianceStates) {
            #MGPolicyCompliance
            $currentTask = "Policy Compliance '$($getMg.properties.displayName)' ('$($getMg.Name)')"
            ($htCachePolicyCompliance).mg.($getMg.Name) = @{ }
            $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementGroups/$($getMg.Name)/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
            #$path = "/providers/Microsoft.Management/managementGroups/$($getMg.Name)/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
            $method = "POST"

            foreach ($policyAssignment in (((AzAPICall -uri $uri -method $method -currenttask $currentTask))).policyassignments | sort-object -Property policyAssignmentId) {
                #$policyAssignment
                ($htCachePolicyCompliance).mg.($getMg.Name).($policyAssignment.policyAssignmentId) = @{ }
                foreach ($policyComplianceState in $policyAssignment.results.policydetails) {
                    if ($policyComplianceState.ComplianceState -eq "compliant") {
                        ($htCachePolicyCompliance).mg.($getMg.Name).($policyAssignment.policyAssignmentId).CompliantPolicies = $policyComplianceState.count
                    }
                    if ($policyComplianceState.ComplianceState -eq "noncompliant") {
                        ($htCachePolicyCompliance).mg.($getMg.Name).($policyAssignment.policyAssignmentId).NonCompliantPolicies = $policyComplianceState.count
                    }
                }

                foreach ($resourceComplianceState in $policyAssignment.results.resourcedetails) {
                    if ($resourceComplianceState.ComplianceState -eq "compliant") {
                        ($htCachePolicyCompliance).mg.($getMg.Name).($policyAssignment.policyAssignmentId).CompliantResources = $resourceComplianceState.count
                    }
                    if ($resourceComplianceState.ComplianceState -eq "nonCompliant") {
                        ($htCachePolicyCompliance).mg.($getMg.Name).($policyAssignment.policyAssignmentId).NonCompliantResources = $resourceComplianceState.count
                    }
                }
            }
        }

        #MGBlueprints
        $currentTask = "Blueprint definitions '$($getMg.properties.displayName)' ('$($getMg.Name)')"
        $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementGroups/$($getMg.Name)/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
        #$path = "/providers/Microsoft.Management/managementGroups/$($getMg.Name)/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
        $method = "GET"

        $mgBlueprintDefinitionResult = ""
        $mgBlueprintDefinitionResult = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))

        if (($mgBlueprintDefinitionResult | measure-object).count -gt 0) {
            foreach ($blueprint in $mgBlueprintDefinitionResult) {

                if (-not ($htCacheDefinitions).blueprint.($blueprint.id)) {
                    ($htCacheDefinitions).blueprint.($blueprint.id) = @{ }
                    ($htCacheDefinitions).blueprint.($blueprint.id) = $blueprint
                }  

                $blueprintName = $blueprint.name
                $blueprintId = $blueprint.id
                $blueprintDisplayName = $blueprint.properties.displayName
                $blueprintDescription = $blueprint.properties.description
                $blueprintScoped = "/providers/Microsoft.Management/managementGroups/$($getMg.Name)"
                addRowToTable `
                    -hierarchyLevel $hierarchyLevel `
                    -mgName $getMg.properties.displayName `
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
        $currentTask = "Custom Policy definitions '$($getMg.properties.displayName)' ('$($getMg.Name)')"
        $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementgroups/$($getMg.Name)/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
        #$path = "/providers/Microsoft.Management/managementgroups/$($getMg.Name)/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
        $method = "GET"

        $requestPolicyDefinitionAPI = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
        $mgPolicyDefinitions = $requestPolicyDefinitionAPI | Where-Object { $_.properties.policyType -eq "custom" }
        $PolicyDefinitionsScopedCount = (($mgPolicyDefinitions | Where-Object { ($_.Id) -like "/providers/Microsoft.Management/managementGroups/$($getMg.Name)/*" }) | measure-object).count
        foreach ($mgPolicyDefinition in $mgPolicyDefinitions) {
            if (-not $($htCacheDefinitions).policy.($mgPolicyDefinition.id)) {
                if (($mgPolicyDefinition.Properties.description).length -eq 0) {
                    $policyDefinitionDescription = "no description given"
                }
                else {
                    $policyDefinitionDescription = $mgPolicyDefinition.Properties.description
                }
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.id) = @{ }
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.id).Id = $($mgPolicyDefinition.id)
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.id).DisplayName = $($mgPolicyDefinition.Properties.displayname)
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.id).Description = $($policyDefinitionDescription)
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.id).Type = $($mgPolicyDefinition.Properties.policyType)
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.id).Category = $($mgPolicyDefinition.Properties.metadata.Category)
                $($htCacheDefinitions).policy.$($mgPolicyDefinition.id).PolicyDefinitionId = $($mgPolicyDefinition.id)
                #effects
                if ($mgPolicyDefinition.properties.parameters.effect.defaultvalue) {
                    ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).effectDefaultValue = $mgPolicyDefinition.properties.parameters.effect.defaultvalue
                    if ($mgPolicyDefinition.properties.parameters.effect.allowedValues) {
                        ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).effectAllowedValue = $mgPolicyDefinition.properties.parameters.effect.allowedValues -join ","
                    }
                    else {
                        ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).effectAllowedValue = "n/a"
                    }
                    ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).effectFixedValue = "n/a"
                }
                else {
                    if ($mgPolicyDefinition.properties.parameters.policyEffect.defaultValue) {
                        ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).effectDefaultValue = $mgPolicyDefinition.properties.parameters.policyEffect.defaultvalue
                        if ($mgPolicyDefinition.properties.parameters.policyEffect.allowedValues) {
                            ($htCacheDefinitions).policy.$($mgPolicyDefinition.id).effectAllowedValue = $mgPolicyDefinition.properties.parameters.policyEffect.allowedValues -join ","
                        }
                        else {
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
        $currentTask = "Custom PolicySet definitions '$($getMg.properties.displayName)' ('$($getMg.Name)')"
        $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementgroups/$($getMg.Name)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"
        #$path = "/providers/Microsoft.Management/managementgroups/$($getMg.Name)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"
        $method = "GET"
        
        $requestPolicySetDefinitionAPI = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
        $mgPolicySetDefinitions = $requestPolicySetDefinitionAPI | Where-Object { $_.properties.policyType -eq "custom" }
        $PolicySetDefinitionsScopedCount = (($mgPolicySetDefinitions | Where-Object { ($_.Id) -like "/providers/Microsoft.Management/managementGroups/$($getMg.Name)/*" }) | measure-object).count
        foreach ($mgPolicySetDefinition in $mgPolicySetDefinitions) {
            if (-not $($htCacheDefinitions).policySet.($mgPolicySetDefinition.id)) {
                if (($mgPolicySetDefinition.Properties.description).length -eq 0) {
                    $policySetDefinitionDescription = "no description given"
                }
                else {
                    $policySetDefinitionDescription = $mgPolicySetDefinition.Properties.description
                }
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.id) = @{ }
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.id).Id = $($mgPolicySetDefinition.id)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.id).DisplayName = $($mgPolicySetDefinition.Properties.displayname)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.id).Description = $($policySetDefinitionDescription)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.id).Type = $($mgPolicySetDefinition.Properties.policyType)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.id).Category = $($mgPolicySetDefinition.Properties.metadata.Category)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.id).PolicyDefinitionId = $($mgPolicySetDefinition.id)
                $($htCacheDefinitions).policySet.$($mgPolicySetDefinition.id).PolicySetPolicyIds = $mgPolicySetDefinition.properties.policydefinitions.policyDefinitionId
                ($htCacheDefinitions).policySet.$($mgPolicySetDefinition.id).json = $mgPolicySetDefinition
            }  
        }

        #MgPolicyAssignments
        $currentTask = "Policy assignments '$($getMg.properties.displayName)' ('$($getMg.Name)')"
        $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementgroups/$($getMg.Name)/providers/Microsoft.Authorization/policyAssignments?`$filter=atscope()&api-version=2019-09-01"
        #$path = "/providers/Microsoft.Management/managementgroups/$($getMg.Name)/providers/Microsoft.Authorization/policyAssignments?`$filter=atscope()&api-version=2019-09-01"
        $method = "GET"
       
        $L0mgmtGroupPolicyAssignments = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
        $L0mgmtGroupPolicyAssignmentsPolicyCount = (($L0mgmtGroupPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" }) | measure-object).count
        $L0mgmtGroupPolicyAssignmentsPolicySetCount = (($L0mgmtGroupPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" }) | measure-object).count
        $L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount = (($L0mgmtGroupPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -and $_.Id -match "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" }) | measure-object).count
        $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount = (($L0mgmtGroupPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" -and $_.Id -match "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" }) | measure-object).count
        $L0mgmtGroupPolicyAssignmentsPolicyAndPolicySetAtScopeCount = ($L0mgmtGroupPolicyAssignmentsPolicyAtScopeCount + $L0mgmtGroupPolicyAssignmentsPolicySetAtScopeCount)
        foreach ($L0mgmtGroupPolicyAssignment in $L0mgmtGroupPolicyAssignments) {

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
                    if (($L0mgmtGroupPolicyAssignment.Properties.Description).length -eq 0) {
                        $PolicyAssignmentDescription = "no description given"
                    }
                    else {
                        $PolicyAssignmentDescription = $L0mgmtGroupPolicyAssignment.Properties.Description
                    }

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
                        -mgName $getMg.properties.displayName `
                        -mgId $getMg.Name `
                        -mgParentId $mgParentId `
                        -mgParentName $mgParentName `
                        -Policy $htCacheDefinitions.$definitiontype.$($Id).DisplayName `
                        -PolicyDescription $htCacheDefinitions.$definitiontype.$($Id).Description `
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
                        -PolicyAssignmentDescription $PolicyAssignmentDescription `
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
                    if (($L0mgmtGroupPolicyAssignment.Properties.Description).length -eq 0) {
                        $PolicyAssignmentDescription = "no description given"
                    }
                    else {
                        $PolicyAssignmentDescription = $L0mgmtGroupPolicyAssignment.Properties.Description
                    }

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
                        -mgName $getMg.properties.displayName `
                        -mgId $getMg.Name `
                        -mgParentId $mgParentId `
                        -mgParentName $mgParentName `
                        -Policy $htCacheDefinitions.$definitiontype.$($Id).DisplayName `
                        -PolicyDescription $htCacheDefinitions.$definitiontype.$($Id).Description `
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
                        -PolicyAssignmentDescription $PolicyAssignmentDescription `
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
        $currentTask = "Custom Role definitions '$($getMg.properties.displayName)' ('$($getMg.Name)')"
        $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementGroups/$($getMg.Name)/providers/Microsoft.Authorization/roleDefinitions?api-version=2015-07-01&`$filter=type%20eq%20'CustomRole'"
        #$path = "/providers/Microsoft.Management/managementGroups/$($getMg.Name)/providers/Microsoft.Authorization/roleDefinitions?api-version=2015-07-01&`$filter=type%20eq%20'CustomRole'"
        $method = "GET"
        
        $mgCustomRoleDefinitions = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
        foreach ($mgCustomRoleDefinition in $mgCustomRoleDefinitions) {
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

        #cmdletgetazroleassignment
        $retryCmletCount = 0
        do{
            $errorOccurred = "no"
            $retryCmletCount++
            try{
                $L0mgmtGroupRoleAssignments = Get-AzRoleAssignment -scope "/providers/Microsoft.Management/managementGroups/$($getMg.Name)"
            }
            catch{
                $errorOccurred = "yes"
            }
            if ($errorOccurred -ne "no"){
                Write-Host "try#$($retryCmletCount) cmdlet Get-AzRoleAssignment ManagementGroup $($getMg.Name) failed, retry in 1 second"
                start-sleep -Seconds 1
            }
        }
        until($errorOccurred -eq "no")

        $L0mgmtGroupRoleAssignmentsLimitUtilization = (($L0mgmtGroupRoleAssignments | Where-Object { $_.Scope -eq "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" }) | measure-object).count
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
                -mgName $getMg.properties.displayName `
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
            -mgName $getMg.properties.displayName `
            -mgId $getMg.Name `
            -mgParentId $mgParentId `
            -mgParentName $mgParentName
    }
    $endMgLoop = get-date
    Write-Host " CustomDataCollection: L$hierarchyLevel MG '$($getMg.properties.displayName)' ('$($getMg.Name)') processing duration: $((NEW-TIMESPAN -Start $startMgLoop -End $endMgLoop).TotalSeconds) seconds"
    $null = $script:CustomDataCollectionDuration.Add([PSCustomObject]@{ 
        Type      = "MG"
        Id        = $getMg.Name
        DurationSec = (NEW-TIMESPAN -Start $startMgLoop -End $endMgLoop).TotalSeconds
    })

    #SUBSCRIPTION
    
    $childrenCount = ($arrayEntitiesFromAPI | Where-Object { $_.properties.parent.id -eq "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" } | Measure-Object).count
    $childrenSubscriptions = $arrayEntitiesFromAPI | Where-Object { $_.type -eq "/subscriptions" -and $_.properties.parent.id -eq "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" }

    if ($childrenCount -gt 0) {
        foreach ($childMg in $childrenSubscriptions) {
            $startSubLoop = get-date
            $childMgSubId = $childMg.name
            $childMgSubDisplayName = $childMg.properties.displayName
            $script:dataCollectionSubscriptionsCounter++
            Write-Host " CustomDataCollection: Processing Subscription ($($script:dataCollectionSubscriptionsCounter)/$($arrayEntitiesFromAPISubscriptionsCount)) '$($childMgSubDisplayName)' ('$childMgSubId')"
        
            if (-not $HierarchyMapOnly) {
                $currentSubscription = $htAllSubscriptionsFromAPI.($childMgSubId).subDetails

                if (($currentSubscription.subscriptionPolicies.quotaId).startswith("AAD_", "CurrentCultureIgnoreCase") -or $currentSubscription.state -ne "enabled") {
                    if (($currentSubscription.subscriptionPolicies.quotaId).startswith("AAD_", "CurrentCultureIgnoreCase")) {
                        Write-Host " CustomDataCollection: Subscription Quota Id: $($currentSubscription.subscriptionPolicies.quotaId) is out of scope for AzGovViz"
                        $null = $script:outOfScopeSubscriptions.Add([PSCustomObject]@{ 
                                subscriptionId      = $childMgSubId
                                subscriptionName    = $childMgSubDisplayName
                                outOfScopeReason    = "QuotaId: AAD_ (State: $($currentSubscription.state))"
                                ManagementGroupId   = $getMg.Name
                                ManagementGroupName = $getMg.properties.displayName 
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
                                    ManagementGroupId   = $getMg.Name
                                    ManagementGroupName = $getMg.properties.displayName
                                    Level               = $hierarchyLevel 
                                })
                        }
                    }
                    $subscriptionIsInScopeforAzGovViz = $False
                }
                else {
                    if ($subscriptionQuotaIdWhitelistMode -eq $true) {
                        $whitelistMatched = $false
                        foreach ($subscriptionQuotaIdWhitelistQuotaId in $subscriptionQuotaIdWhitelistArray) {
                            if (($currentSubscription.subscriptionPolicies.quotaId).startswith($subscriptionQuotaIdWhitelistQuotaId, "CurrentCultureIgnoreCase")) {
                                $whitelistMatched = $true
                            }
                        }

                        if ($true -eq $whitelistMatched) {
                            $subscriptionIsInScopeforAzGovViz = $True
                        }
                        else {
                            Write-Host " CustomDataCollection: Subscription Quota Id: $($currentSubscription.subscriptionPolicies.quotaId) is out of scope for AzGovViz (not in Whitelist)"
                            $null = $script:outOfScopeSubscriptions.Add([PSCustomObject]@{ 
                                    subscriptionId      = $childMgSubId
                                    subscriptionName    = $childMgSubDisplayName 
                                    outOfScopeReason    = "QuotaId: '$($currentSubscription.subscriptionPolicies.quotaId)' not in Whitelist"
                                    ManagementGroupId   = $getMg.Name
                                    ManagementGroupName = $getMg.properties.displayName 
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

                    if (-not $NoAzureConsumption) {
                        $currenttask = "GetConsumption $childMgSubId $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)"
                        $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Consumption/usageDetails?api-version=2019-10-01&`$expand=properties/meterDetails&`$filter=properties/usageStart ge '$($azureConsumptionStartDate)' and properties/usageEnd le '$($azureConsumptionEndDate)'"
                        $method = "GET"
                        $subscriptionConsumptionData = AzAPICall -uri $uri -method $method -currenttask $currentTask -getConsumption $true
                        $utcTimeDataRetrieved = $([System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((Get-Date), [System.TimeZoneInfo]::Local.Id, 'UTC')).ToString("yyyy-MM-dd HH:mm:ss")
                        
                        if (($subscriptionConsumptionData | Measure-Object).Count -gt 0){
                            $arrayAzureConsumptionDetailedThisSubscription = [System.Collections.ArrayList]@()

                            foreach ($consumptionLine in $subscriptionConsumptionData) {
                                $resourceId = "n/a"
                                if ($null -ne $consumptionLine.properties.resourceId) {
                                    $resourceId = $consumptionLine.properties.resourceId.ToLower()
                                }
                                $resourceName = "n/a"
                                if ($null -ne $consumptionLine.properties.resourceName) {
                                    $resourceName = $consumptionLine.properties.resourceName.ToLower()
                                }
                                $resourceGroupName = "n/a"
                                if ($null -ne $consumptionLine.properties.resourceGroup) {
                                    $resourceGroupName = $consumptionLine.properties.resourceGroup.ToLower()
                                }
                                $consumedService = "n/a"
                                if ($null -ne $consumptionLine.properties.consumedService) {
                                    $consumedService = $consumptionLine.properties.consumedService.ToLower()
                                }
                                
                                #thisSub
                                $null = $arrayAzureConsumptionDetailedThisSubscription.Add([PSCustomObject]@{ 
                                    UTCTimeDataRetrieved = $utcTimeDataRetrieved
                                    SubscriptionId       = $consumptionLine.properties.subscriptionId
                                    SubscriptionName     = $childMgSubDisplayName
                                    SubscriptionMgPath   = $consumptionSubscriptionMgPath -join "$CsvDelimiterOpposite "
                                    ResourceGroupName    = $resourceGroupName
                                    ResourceName         = $resourceName
                                    ResourceId           = $resourceId
                                    UsageDate            = $consumptionLine.properties.date
                                    Tags                 = $consumptionLine.tags
                                    BillingCurrency      = $consumptionLine.properties.billingCurrency
                                    ChargeType           = $consumptionLine.properties.chargeType
                                    ConsumedService      = $consumedService
                                    Cost                 = [decimal]$consumptionLine.properties.cost
                                    EffectivePrice       = $consumptionLine.properties.effectivePrice
                                    Frequency            = $consumptionLine.properties.frequency
                                    MeterCategory        = $consumptionLine.properties.meterDetails.meterCategory
                                    MeterId              = $consumptionLine.properties.meterId
                                    MeterName            = $consumptionLine.properties.meterDetails.meterName
                                    MeterSubCategory     = $consumptionLine.properties.meterDetails.meterSubCategory
                                    ServiceFamily        = $consumptionLine.properties.meterDetails.serviceFamily
                                    PartNumber           = $consumptionLine.properties.partNumber
                                    Product              = $consumptionLine.properties.product
                                    Quantity             = $consumptionLine.properties.quantity
                                    UnitOfMeasure        = $consumptionLine.properties.meterDetails.unitOfMeasure
                                    UnitPrice            = $consumptionLine.properties.unitPrice
                                    Location             = $consumptionLine.properties.resourceLocation
                                    ReservationId        = $consumptionLine.properties.reservationId
                                    ReservationName      = $consumptionLine.properties.reservationName
                                    UsageId              = $consumptionLine.id
                                    UsageName            = $consumptionLine.name
                                })
                                
                                #allSubs
                                $null = $arrayAzureConsumptionDetailedAllSubscriptions.Add([PSCustomObject]@{ 
                                        UTCTimeDataRetrieved = $utcTimeDataRetrieved
                                        SubscriptionId       = $consumptionLine.properties.subscriptionId
                                        SubscriptionName     = $childMgSubDisplayName
                                        SubscriptionMgPath   = $consumptionSubscriptionMgPath -join "$CsvDelimiterOpposite "
                                        ResourceGroupName    = $resourceGroupName
                                        ResourceName         = $resourceName
                                        ResourceId           = $resourceId
                                        UsageDate            = $consumptionLine.properties.date
                                        Tags                 = $consumptionLine.tags
                                        BillingCurrency      = $consumptionLine.properties.billingCurrency
                                        ChargeType           = $consumptionLine.properties.chargeType
                                        ConsumedService      = $consumedService
                                        Cost                 = [decimal]$consumptionLine.properties.cost
                                        EffectivePrice       = $consumptionLine.properties.effectivePrice
                                        Frequency            = $consumptionLine.properties.frequency
                                        MeterCategory        = $consumptionLine.properties.meterDetails.meterCategory
                                        MeterId              = $consumptionLine.properties.meterId
                                        MeterName            = $consumptionLine.properties.meterDetails.meterName
                                        MeterSubCategory     = $consumptionLine.properties.meterDetails.meterSubCategory
                                        ServiceFamily        = $consumptionLine.properties.meterDetails.serviceFamily
                                        PartNumber           = $consumptionLine.properties.partNumber
                                        Product              = $consumptionLine.properties.product
                                        Quantity             = $consumptionLine.properties.quantity
                                        UnitOfMeasure        = $consumptionLine.properties.meterDetails.unitOfMeasure
                                        UnitPrice            = $consumptionLine.properties.unitPrice
                                        Location             = $consumptionLine.properties.resourceLocation
                                        ReservationId        = $consumptionLine.properties.reservationId
                                        ReservationName      = $consumptionLine.properties.reservationName
                                        UsageId              = $consumptionLine.id
                                        UsageName            = $consumptionLine.name
                                    })
                            }

                            $subscriptionConsumptionCurrency = $arrayAzureConsumptionDetailedThisSubscription.billingCurrency | sort-object -Unique
                            $groupSubscriptionConsumptionData = $arrayAzureConsumptionDetailedThisSubscription | where-object { $_.cost -gt 0 } | group-object -property ConsumedService, ChargeType, MeterCategory
                            $groupSubscriptionConsumptionDataCount = ($groupSubscriptionConsumptionData | Measure-Object).Count
                            if ($groupSubscriptionConsumptionDataCount -gt 0) {
                                $htAzureConsumption.($childMgSubId) = @{ }
                                $arraySubscriptionAzureConsumption = [System.Collections.ArrayList]@()
                                $consumptionSubscriptionMgPath = ($arrayEntitiesFromAPI | Where-Object { $_.id -eq "/subscriptions/$($childMgSubId)" }).Properties.parentNameChain
                                $htAzureConsumption.($childMgSubId).mgPath = $consumptionSubscriptionMgPath

                                foreach ($consumptionLine in $groupSubscriptionConsumptionData) {
                                    $consumedService = ($consumptionLine.Name).split(", ")[0]
                                    $consumedServiceChargeType = ($consumptionLine.Name).split(", ")[1]
                                    $consumedServiceCategory = ($consumptionLine.Name).split(", ")[2]
                                    $consumedServiceInstanceCount = ($consumptionLine.group | group-object -property resourceid | measure-object).count
                                    $consumedServiceCost = ($consumptionLine.group.cost | Measure-Object -Sum).Sum

                                    $null = $arraySubscriptionAzureConsumption.Add([PSCustomObject]@{ 
                                            ConsumedService                 = $consumedService
                                            ConsumedServiceChargeType       = $consumedServiceChargeType
                                            ConsumedServiceCategory         = $consumedServiceCategory
                                            ConsumedServiceInstanceCount    = $consumedServiceInstanceCount
                                            ConsumedServiceCost             = [decimal]$consumedServiceCost
                                        })
                                    #write-host ($consumptionLine.group | group-object -property resourceid | measure-object).count "x $($consumptionLine.Name) created cost:" ($consumptionLine.group.cost | Measure-Object -Sum).Sum

                                    $null = $arrayAzureConsumptionSummarizedByResourceType.Add([PSCustomObject]@{ 
                                            ConsumedService                 = $consumedService
                                            ConsumedServiceChargeType       = $consumedServiceChargeType
                                            ConsumedServiceCategory         = $consumedServiceCategory
                                            ConsumedServiceInstanceCount    = $consumedServiceInstanceCount
                                            ConsumedServiceCost             = [decimal]$consumedServiceCost
                                            SubscriptionId                  = $childMgSubId
                                            SubscriptionName                = $childMgSubDisplayName
                                            SubscriptionMgPath              = $consumptionSubscriptionMgPath
                                            SubscriptionConsumptionCurrency = $subscriptionConsumptionCurrency
                                        })
                                }
                                $htAzureConsumption.($childMgSubId).ConsumptionData = $arraySubscriptionAzureConsumption
                                $htAzureConsumption.($childMgSubId).ConsumptionTotal = [decimal]($arraySubscriptionAzureConsumption.ConsumedServiceCost | measure-object -Sum).Sum
                                $htAzureConsumption.($childMgSubId).Currency = $subscriptionConsumptionCurrency
                            }
                        }
                    }

                    #tags
                    $currentTask = "Subscription Tags '$($childMgSubDisplayName)' ('$childMgSubId')"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Resources/tags/default?api-version=2020-06-01"
                    #$path = "/subscriptions/$childMgSubId/providers/Microsoft.Resources/tags/default?api-version=2020-06-01"
                    $method = "GET"
    
                    $requestSubscriptionTags = ((AzAPICall -uri $uri -method $method -currenttask $currentTask -listenOn "Content"))
                    if ($requestSubscriptionTags.properties.tags) {
                        $subscriptionTags = @()
                        ($htSubscriptionTags).($childMgSubId) = @{ }
                        ($requestSubscriptionTags.properties.tags).PSObject.Properties | ForEach-Object {
                            $subscriptionTags += "$($_.Name)/$($_.Value)"
                            ($htSubscriptionTags).($childMgSubId).($_.Name) = $_.Value
                        }
                        $subscriptionTagsCount = ($subscriptionTags | Measure-Object).Count
                        $subscriptionTags = $subscriptionTags -join "$CsvDelimiterOpposite "
                    }
                    else {
                        $SubscriptionTagsCount = 0
                        $subscriptionTags = "none"
                    }

                    if (-not $NoPolicyComplianceStates) {
                        #SubscriptionPolicyCompliance
                        $currentTask = "Policy Compliance '$($childMgSubDisplayName)' ('$childMgSubId')"
                        $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
                        #$path = "/subscriptions/$childMgSubId/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
                        $method = "POST"
                        
                        $subPolicyComplianceResult = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
                        ($htCachePolicyCompliance).sub.$childMgSubId = @{ }
                        foreach ($policyAssignment in $subPolicyComplianceResult.policyassignments | sort-object -Property policyAssignmentId) {
                            ($htCachePolicyCompliance).sub.($childMgSubId).($policyAssignment.policyAssignmentId) = @{ }
                            foreach ($policyComplianceState in $policyAssignment.results.policydetails) {
                                if ($policyComplianceState.ComplianceState -eq "compliant") {
                                    ($htCachePolicyCompliance).sub.($childMgSubId).($policyAssignment.policyAssignmentId).CompliantPolicies = $policyComplianceState.count
                                }
                                if ($policyComplianceState.ComplianceState -eq "noncompliant") {
                                    ($htCachePolicyCompliance).sub.($childMgSubId).($policyAssignment.policyAssignmentId).NonCompliantPolicies = $policyComplianceState.count
                                }
                            }
                
                            foreach ($resourceComplianceState in $policyAssignment.results.resourcedetails) {
                                if ($resourceComplianceState.ComplianceState -eq "compliant") {
                                    ($htCachePolicyCompliance).sub.($childMgSubId).($policyAssignment.policyAssignmentId).CompliantResources = $resourceComplianceState.count
                                }
                                if ($resourceComplianceState.ComplianceState -eq "nonCompliant") {
                                    ($htCachePolicyCompliance).sub.($childMgSubId).($policyAssignment.policyAssignmentId).NonCompliantResources = $resourceComplianceState.count
                                }
                            }
                        }
                    }

                    #SubscriptionASCSecureScore
                    if (-not $NoASCSecureScore) {
                        $currentTask = "ASC Secure Score '$($childMgSubDisplayName)' ('$childMgSubId')"
                        $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Security/securescores?api-version=2020-01-01-preview"
                        #$path = "/subscriptions/$childMgSubId/providers/Microsoft.Security/securescores?api-version=2020-01-01-preview"
                        $method = "GET"

                        $subASCSecureScoreResult = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
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
                    #$uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)/subscriptions/$childMgSubId/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
                    #$path = "/subscriptions/$childMgSubId/providers/Microsoft.Blueprint/blueprints?api-version=2018-11-01-preview"
                    $method = "GET"

                    $subBlueprintDefinitionResult = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
                    if (($subBlueprintDefinitionResult | measure-object).count -gt 0) {
                        foreach ($blueprint in $subBlueprintDefinitionResult) {

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
                                -mgName $getMg.properties.displayName `
                                -mgId $getMg.Name `
                                -mgParentId $mgParentId `
                                -mgParentName $mgParentName `
                                -Subscription $childMgSubDisplayName `
                                -SubscriptionId $childMgSubId `
                                -SubscriptionQuotaId $subscriptionQuotaId `
                                -SubscriptionState $subscriptionState `
                                -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                                -SubscriptionTags $subscriptionTags `
                                -SubscriptionTagsLimit $LimitTagsSubscription `
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
                    
                    $subscriptionBlueprintAssignmentsResult = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
                    #($subscriptionBlueprintAssignmentsResult | measure-object).count
                    
                    if (($subscriptionBlueprintAssignmentsResult | measure-object).count -gt 0) {
                        foreach ($subscriptionBlueprintAssignment in $subscriptionBlueprintAssignmentsResult) {

                            if (-not ($htCacheAssignments).blueprint.($subscriptionBlueprintAssignment.Id)) {
                                ($htCacheAssignments).blueprint.($subscriptionBlueprintAssignment.Id) = @{ }
                                ($htCacheAssignments).blueprint.($subscriptionBlueprintAssignment.Id) = $subscriptionBlueprintAssignment
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
                            
                            $subscriptionBlueprintDefinitionResult = ((AzAPICall -uri $uri -method $method -currenttask $currentTask -listenOn "Content"))
                            $blueprintName = $subscriptionBlueprintDefinitionResult.name
                            $blueprintId = $subscriptionBlueprintDefinitionResult.id
                            $blueprintAssignmentVersion = $subscriptionBlueprintAssignment.properties.blueprintId -replace ".*/"
                            $blueprintDisplayName = $subscriptionBlueprintDefinitionResult.properties.displayName
                            $blueprintDescription = $subscriptionBlueprintDefinitionResult.properties.description
                            $blueprintScoped = $blueprintScope
                            $blueprintAssignmentId = $subscriptionBlueprintAssignmentsResult.id
                            addRowToTable `
                                -hierarchyLevel $hierarchyLevel `
                                -mgName $getMg.properties.displayName `
                                -mgId $getMg.Name `
                                -mgParentId $mgParentId `
                                -mgParentName $mgParentName `
                                -Subscription $childMgSubDisplayName `
                                -SubscriptionId $childMgSubId `
                                -SubscriptionQuotaId $subscriptionQuotaId `
                                -SubscriptionState $subscriptionState `
                                -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                                -SubscriptionTags $subscriptionTags `
                                -SubscriptionTagsLimit $LimitTagsSubscription `
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

                    #SubscriptionPolicies
                    $currentTask = "Policy definitions '$($childMgSubDisplayName)' ('$childMgSubId')"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
                    #$path = "/subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
                    $method = "GET"
                    
                    $requestPolicyDefinitionAPI = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
                    $subPolicyDefinitions = $requestPolicyDefinitionAPI | Where-Object { $_.properties.policyType -eq "custom" }
                    $PolicyDefinitionsScopedCount = (($subPolicyDefinitions | Where-Object { ($_.Id) -like "/subscriptions/$childMgSubId/*" }) | measure-object).count
                    foreach ($subPolicyDefinition in $subPolicyDefinitions) {
                        if (-not $($htCacheDefinitions).policy.($subPolicyDefinition.id)) {
                            if (($subPolicyDefinition.Properties.description).length -eq 0) {
                                $policyDefinitionDescription = "no description given"
                            }
                            else {
                                $policyDefinitionDescription = $subPolicyDefinition.Properties.description
                            }
                            $($htCacheDefinitions).policy.$($subPolicyDefinition.id) = @{ }
                            $($htCacheDefinitions).policy.$($subPolicyDefinition.id).Id = $($subPolicyDefinition.id)
                            $($htCacheDefinitions).policy.$($subPolicyDefinition.id).DisplayName = $($subPolicyDefinition.Properties.displayname)
                            $($htCacheDefinitions).policy.$($subPolicyDefinition.id).Description = $($policyDefinitionDescription)
                            $($htCacheDefinitions).policy.$($subPolicyDefinition.id).Type = $($subPolicyDefinition.Properties.policyType)
                            $($htCacheDefinitions).policy.$($subPolicyDefinition.id).Category = $($subPolicyDefinition.Properties.metadata.category)
                            $($htCacheDefinitions).policy.$($subPolicyDefinition.id).PolicyDefinitionId = $($subPolicyDefinition.id)
                            #effects
                            if ($subPolicyDefinition.properties.parameters.effect.defaultvalue) {
                                ($htCacheDefinitions).policy.$($subPolicyDefinition.id).effectDefaultValue = $subPolicyDefinition.properties.parameters.effect.defaultvalue
                                if ($subPolicyDefinition.properties.parameters.effect.allowedValues) {
                                    ($htCacheDefinitions).policy.$($subPolicyDefinition.id).effectAllowedValue = $subPolicyDefinition.properties.parameters.effect.allowedValues -join ","
                                }
                                else {
                                    ($htCacheDefinitions).policy.$($subPolicyDefinition.id).effectAllowedValue = "n/a"
                                }
                                ($htCacheDefinitions).policy.$($subPolicyDefinition.id).effectFixedValue = "n/a"
                            }
                            else {
                                if ($subPolicyDefinition.properties.parameters.policyEffect.defaultValue) {
                                    ($htCacheDefinitions).policy.$($subPolicyDefinition.id).effectDefaultValue = $subPolicyDefinition.properties.parameters.policyEffect.defaultvalue
                                    if ($subPolicyDefinition.properties.parameters.policyEffect.allowedValues) {
                                        ($htCacheDefinitions).policy.$($subPolicyDefinition.id).effectAllowedValue = $subPolicyDefinition.properties.parameters.policyEffect.allowedValues -join ","
                                    }
                                    else {
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
                    $currentTask = "PolicySet definitions '$($childMgSubDisplayName)' ('$childMgSubId')"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"
                    #$path = "/subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"
                    $method = "GET"
                
                    $requestPolicySetDefinitionAPI = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
                    $subPolicySetDefinitions = $requestPolicySetDefinitionAPI | Where-Object { $_.properties.policyType -eq "custom" }
                    $PolicySetDefinitionsScopedCount = (($subPolicySetDefinitions | Where-Object { ($_.Id) -like "/subscriptions/$childMgSubId/*" }) | measure-object).count
                    foreach ($subPolicySetDefinition in $subPolicySetDefinitions) {
                        if (-not $($htCacheDefinitions).policySet.($subPolicySetDefinition.id)) {
                            if (($subPolicySetDefinition.Properties.description).length -eq 0) {
                                $policySetDefinitionDescription = "no description given"
                            }
                            else {
                                $policySetDefinitionDescription = $subPolicySetDefinition.Properties.description
                            }
                            $($htCacheDefinitions).policySet.$($subPolicySetDefinition.id) = @{ }
                            $($htCacheDefinitions).policySet.$($subPolicySetDefinition.id).Id = $($subPolicySetDefinition.id)
                            $($htCacheDefinitions).policySet.$($subPolicySetDefinition.id).DisplayName = $($subPolicySetDefinition.Properties.displayname)
                            $($htCacheDefinitions).policySet.$($subPolicySetDefinition.id).Description = $($policySetDefinitionDescription)
                            $($htCacheDefinitions).policySet.$($subPolicySetDefinition.id).Type = $($subPolicySetDefinition.Properties.policyType)
                            $($htCacheDefinitions).policySet.$($subPolicySetDefinition.id).Category = $($subPolicySetDefinition.Properties.metadata.category)
                            $($htCacheDefinitions).policySet.$($subPolicySetDefinition.id).PolicyDefinitionId = $($subPolicySetDefinition.id)
                            $($htCacheDefinitions).policySet.$($subPolicySetDefinition.id).PolicySetPolicyIds = $subPolicySetDefinition.properties.policydefinitions.policyDefinitionId
                            $($htCacheDefinitions).policySet.$($subPolicySetDefinition.id).json = $subPolicySetDefinition
                        }  
                    }

                    #SubscriptionPolicyAssignments
                    $currentTask = "Policy assignments '$($childMgSubDisplayName)' ('$childMgSubId')"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policyAssignments?api-version=2019-09-01"
                    #$path = "/subscriptions/$($childMgSubId)/providers/Microsoft.Authorization/policyAssignments?api-version=2019-09-01"
                    $method = "GET"
                    
                    $L1mgmtGroupSubPolicyAssignments = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
                    $L1mgmtGroupSubPolicyAssignmentsPolicyCount = (($L1mgmtGroupSubPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -and $_.id -notmatch "$($childMg.Id)/resourceGroups" }) | measure-object).count
                    $L1mgmtGroupSubPolicyAssignmentsPolicySetCount = (($L1mgmtGroupSubPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" -and $_.id -notmatch "$($childMg.Id)/resourceGroups" }) | measure-object).count
                    $L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount = (($L1mgmtGroupSubPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policyDefinitions/" -and $_.Id -match $childMg.Id -and $_.id -notmatch "$($childMg.Id)/resourceGroups" }) | measure-object).count
                    $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount = (($L1mgmtGroupSubPolicyAssignments | Where-Object { $_.properties.policyDefinitionId -match "/providers/Microsoft.Authorization/policySetDefinitions/" -and $_.Id -match $childMg.Id -and $_.id -notmatch "$($childMg.Id)/resourceGroups" }) | measure-object).count

                    $L1mgmtGroupSubPolicyAssignmentsPolicyAndPolicySetAtScopeCount = ($L1mgmtGroupSubPolicyAssignmentsPolicyAtScopeCount + $L1mgmtGroupSubPolicyAssignmentsPolicySetAtScopeCount)

                    $script:arrayCachePolicyAssignmentsResourceGroups += foreach ($L1mgmtGroupSubPolicyAssignment in $L1mgmtGroupSubPolicyAssignments | Where-Object { $_.id -match "$($childMg.Id)/resourceGroups" } ) {
                        $L1mgmtGroupSubPolicyAssignment
                    }
                    
                    foreach ($L1mgmtGroupSubPolicyAssignment in $L1mgmtGroupSubPolicyAssignments | Where-Object { $_.id -notmatch "$($childMg.Id)/resourceGroups" } ) {

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
                                if (($L1mgmtGroupSubPolicyAssignment.Properties.Description).length -eq 0) {
                                    $PolicyAssignmentDescription = "no description given"
                                }
                                else {
                                    $PolicyAssignmentDescription = $L1mgmtGroupSubPolicyAssignment.Properties.Description
                                }

                                if ($L1mgmtGroupSubPolicyAssignment.Identity) {
                                    $PolicyAssignmentIdentity = $L1mgmtGroupSubPolicyAssignment.Identity.principalId
                                }
                                else {
                                    $PolicyAssignmentIdentity = "n/a"
                                }

                                if ($htCacheDefinitions.$definitiontype.$($Id).Type -eq "Custom") {
                                    if (($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId) -like "/subscriptions/*") {
                                        $policyDefintionScope = ($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId -split "\/")[0..2] -join "/"
                                    }
                                    if (($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId) -like "/providers/Microsoft.Management/managementGroups/*") {
                                        $policyDefintionScope = ($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId -split "\/")[0..4] -join "/"
                                    }
                                }
                                else {
                                    $policyDefintionScope = "n/a"
                                }
                                
                                addRowToTable `
                                    -hierarchyLevel $hierarchyLevel `
                                    -mgName $getMg.properties.displayName `
                                    -mgId $getMg.Name `
                                    -mgParentId $mgParentId `
                                    -mgParentName $mgParentName `
                                    -Subscription $childMgSubDisplayName `
                                    -SubscriptionId $childMgSubId `
                                    -SubscriptionQuotaId $subscriptionQuotaId `
                                    -SubscriptionState $subscriptionState `
                                    -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                                    -SubscriptionTags $subscriptionTags `
                                    -SubscriptionTagsLimit $LimitTagsSubscription `
                                    -SubscriptionTagsCount $subscriptionTagsCount `
                                    -Policy $htCacheDefinitions.$definitiontype.$($Id).DisplayName `
                                    -PolicyDescription $htCacheDefinitions.$definitiontype.$($Id).Description `
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
                                    -PolicyAssignmentDescription $PolicyAssignmentDescription `
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
                                if (($L1mgmtGroupSubPolicyAssignment.Properties.Description).length -eq 0) {
                                    $PolicyAssignmentDescription = "no description given"
                                }
                                else {
                                    $PolicyAssignmentDescription = $L1mgmtGroupSubPolicyAssignment.Properties.Description
                                }

                                if ($L1mgmtGroupSubPolicyAssignment.Identity) {
                                    $PolicyAssignmentIdentity = $L1mgmtGroupSubPolicyAssignment.Identity.principalId
                                }
                                else {
                                    $PolicyAssignmentIdentity = "n/a"
                                }

                                if ($htCacheDefinitions.$definitiontype.$($Id).Type -eq "Custom") {
                                    if (($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId) -like "/subscriptions/*") {
                                        $policyDefintionScope = ($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId -split "\/")[0..2] -join "/"
                                    }
                                    if (($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId) -like "/providers/Microsoft.Management/managementGroups/*") {
                                        $policyDefintionScope = ($htCacheDefinitions.$definitiontype.$($Id).PolicyDefinitionId -split "\/")[0..4] -join "/"
                                    }
                                }
                                else {
                                    $policyDefintionScope = "n/a"
                                }

                                addRowToTable `
                                    -hierarchyLevel $hierarchyLevel `
                                    -mgName $getMg.properties.displayName `
                                    -mgId $getMg.Name `
                                    -mgParentId $mgParentId `
                                    -mgParentName $mgParentName `
                                    -Subscription $childMgSubDisplayName `
                                    -SubscriptionId $childMgSubId `
                                    -SubscriptionQuotaId $subscriptionQuotaId `
                                    -SubscriptionState $subscriptionState `
                                    -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                                    -SubscriptionTags $subscriptionTags `
                                    -SubscriptionTagsLimit $LimitTagsSubscription `
                                    -SubscriptionTagsCount $subscriptionTagsCount `
                                    -Policy $htCacheDefinitions.$definitiontype.$($Id).DisplayName `
                                    -PolicyDescription $htCacheDefinitions.$definitiontype.$($Id).Description `
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
                                    -PolicyAssignmentDescription $PolicyAssignmentDescription `
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
                    $currentTask = "Custom Role definitions '$($childMgSubDisplayName)' ('$childMgSubId')"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Authorization/roleDefinitions?api-version=2015-07-01&`$filter=type%20eq%20'CustomRole'"
                    #$path = "/subscriptions/$childMgSubId/providers/Microsoft.Authorization/roleDefinitions?api-version=2015-07-01&`$filter=type%20eq%20'CustomRole'"
                    $method = "GET"
                    
                    $subCustomRoleDefinitions = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
                    foreach ($subCustomRoleDefinition in $subCustomRoleDefinitions) {
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
                    $currentTask = "Role assignments usage metrics '$($childMgSubDisplayName)' ('$childMgSubId')"
                    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$childMgSubId/providers/Microsoft.Authorization/roleAssignmentsUsageMetrics?api-version=2019-08-01-preview"
                    #$path = "/subscriptions/$childMgSubId/providers/Microsoft.Authorization/roleAssignmentsUsageMetrics?api-version=2019-08-01-preview"
                    $method = "GET"
                    $roleAssignmentsUsage = ((AzAPICall -uri $uri -method $method -currenttask $currentTask -listenOn "Content"))

                    #cmdletgetazroleassignment
                    $retryCmletCount = 0
                    do{
                        $errorOccurred = "no"
                        $retryCmletCount++
                        try{
                            $L1mgmtGroupSubRoleAssignments = Get-AzRoleAssignment -Scope "$($childMg.Id)" -ErrorAction Stop #exclude rg roleassignments
                        }
                        catch{
                            $errorOccurred = "yes"
                        }
                        if ($errorOccurred -ne "no"){
                            Write-Host "try#$($retryCmletCount) cmdlet Get-AzRoleAssignment $($childMg.Id) failed, retry in 1 second"
                            start-sleep -Seconds 1
                        }
                    }
                    until($errorOccurred -eq "no")
                    
                    $script:arrayCacheRoleAssignmentsResourceGroups += foreach ($L1mgmtGroupSubRoleAssignmentOnRg in $L1mgmtGroupSubRoleAssignments | Where-Object { $_.RoleAssignmentId -match "$($childMg.Id)/resourcegroups/" }) {
                        $L1mgmtGroupSubRoleAssignmentOnRg
                    }

                    foreach ($L1mgmtGroupSubRoleAssignment in $L1mgmtGroupSubRoleAssignments | Where-Object { $_.RoleAssignmentId -notmatch "$($childMg.Id)/resourcegroups/" }) {

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
                            -mgName $getMg.properties.displayName `
                            -mgId $getMg.Name `
                            -mgParentId $mgParentId `
                            -mgParentName $mgParentName `
                            -Subscription $childMgSubDisplayName `
                            -SubscriptionId $childMgSubId `
                            -SubscriptionQuotaId $subscriptionQuotaId `
                            -SubscriptionState $subscriptionState `
                            -SubscriptionASCSecureScore $subscriptionASCSecureScore `
                            -SubscriptionTags $subscriptionTags `
                            -SubscriptionTagsLimit $LimitTagsSubscription `
                            -SubscriptionTagsCount $subscriptionTagsCount `
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
            else {
                addRowToTable `
                    -hierarchyLevel $hierarchyLevel `
                    -mgName $getMg.properties.displayName `
                    -mgId $getMg.Name `
                    -mgParentId $mgParentId `
                    -mgParentName $mgParentName `
                    -Subscription $childMgSubDisplayName `
                    -SubscriptionId $childMgSubId
            }
            $endSubLoop = get-date
            Write-Host " CustomDataCollection: Subscription processing duration: $((NEW-TIMESPAN -Start $startSubLoop -End $endSubLoop).TotalSeconds) seconds"
            $null = $script:CustomDataCollectionDuration.Add([PSCustomObject]@{ 
                Type      = "SUB"
                Id        = $childMgSubId
                DurationSec = (NEW-TIMESPAN -Start $startSubLoop -End $endSubLoop).TotalSeconds
            })
        }
        $childrenManagementGroups = $arrayEntitiesFromAPI | Where-Object { $_.type -eq "Microsoft.Management/managementGroups" -and $_.properties.parent.id -eq "/providers/Microsoft.Management/managementGroups/$($getMg.Name)" }
        foreach ($childMg in $childrenManagementGroups) {
            dataCollection -mgId $childMg.Name -hierarchyLevel $hierarchyLevel -mgParentId $getMg.Name -mgParentName $getMg.properties.displayName
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

    if ($mgId -eq ($checkContext).Tenant.Id) {
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
    $subscriptionsOutOfScopelinked = $script:outOfScopeSubscriptions | Where-Object { $_.ManagementGroupId -eq $mgChild }
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
    $subscriptionsOutOfScopelinked = $script:outOfScopeSubscriptions | Where-Object { $_.ManagementGroupId -eq $mgChild }
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

    $mgLinkedSubsCount = ((($optimizedTableForPathQuery | Where-Object { $_.MgId -eq $mgChild -and "" -ne $_.SubscriptionId }).SubscriptionId | Get-Unique) | measure-object).count
    $subscriptionsOutOfScopelinkedCount = ($script:outOfScopeSubscriptions | Where-Object { $_.ManagementGroupId -eq $mgChild } | Measure-Object).count
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
        <tr><td class="detailstd"><p><i class="fa fa-circle" aria-hidden="true" style="color:#FFCBC7"></i> <b>Default</b> Management Group <a class="externallink" href="https://docs.microsoft.com/en-us/azure/governance/management-groups/how-to/protect-resource-hierarchy#setting---default-management-group" target="_blank">Microsoft Docs</a></p></td></tr>
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
    $subscriptionsOutOfScopelinked = $script:outOfScopeSubscriptions | Where-Object { $_.ManagementGroupId -eq $mgChild }
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
        $blueprintReleatedQuery = $blueprintBaseQuery | Where-Object { $_.MgId -eq $mgChild -and "" -eq $_.SubscriptionId -and "" -eq $_.BlueprintAssignmentId }
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
        $resourcesAllChildSubscriptions = foreach ($mgAllChildSubscription in $mgAllChildSubscriptions) {
            foreach ($resource in $resourcesAll | Sort-Object -Property type, location) {
                if ($resource.subscriptionId -eq $mgAllChildSubscription ) {
                    $resource
                }
            }
        }
        $resourcesAllChildSubscriptionsArray = [System.Collections.ArrayList]@()
        $grp = $resourcesAllChildSubscriptions | Group-Object -Property type, location
        $resourcesAllChildSubscriptionsArray = foreach ($resLoc in $grp) {
            $cnt = 0
            $ResoureTypeAndLocation = $resLoc.Name -split ","
            $resLoc.Group.count_ | ForEach-Object { $cnt += $_ }
            [PSCustomObject]@{ 
                ResourceType  = $ResoureTypeAndLocation[0]
                Location      = $ResoureTypeAndLocation[1]
                ResourceCount = $cnt 
            }
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
    
        $cssClass = "mgDetailsTable"

        #$endScopeInsightsPreQueryMg = get-date
        #Write-Host "   ScopeInsights MG PreQuery processing duration: $((NEW-TIMESPAN -Start $startScopeInsightsPreQueryMg -End $endScopeInsightsPreQueryMg).TotalSeconds) seconds"
    }
    if ($mgOrSub -eq "sub") {
        #$startScopeInsightsPreQuerySub = get-date
        #BLUEPRINT
        $blueprintReleatedQuery = $blueprintBaseQuery | Where-Object { $_.SubscriptionId -eq $subscriptionId -and "" -ne $_.BlueprintName }
        $blueprintsAssigned = $blueprintReleatedQuery | Where-Object { "" -ne $_.BlueprintAssignmentId }
        $blueprintsAssignedCount = ($blueprintsAssigned | measure-object).count
        $blueprintsScoped = $blueprintReleatedQuery | Where-Object { $_.BlueprintScoped -eq "/subscriptions/$subscriptionId" -and "" -eq $_.BlueprintAssignmentId }
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
        $resourcesSubscription = foreach ($resource in $resourcesAll | Sort-Object -Property type, location) {
            if ($resource.subscriptionId -eq $subscriptionId ) {
                $resource
            }
        }
        $resourcesSubscriptionTotal = 0
        $resourcesSubscription.count_ | ForEach-Object { $resourcesSubscriptionTotal += $_ }
        $resourcesSubscriptionResourceTypeCount = (($resourcesSubscription | sort-object -Property type -Unique) | measure-object).count
        $resourcesSubscriptionLocationCount = (($resourcesSubscription | sort-object -Property location -Unique) | measure-object).count

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
<tr><td class="detailstd"><p><i class="fa fa-shield" aria-hidden="true"></i> ASC Secure Score: $subscriptionASCPoints</p></td></tr>
<tr><td class="detailstd">
"@

        #region ScopeInsightsConsumptionSub
        if (-not $NoAzureConsumption) {

            if ($htAzureConsumption.($subscriptionId)) {
                $currency = $htAzureConsumption.($subscriptionId).Currency
                if ([math]::Round($htAzureConsumption.($subscriptionId).ConsumptionTotal,4) -eq 0){
                    $cost = $htAzureConsumption.($subscriptionId).ConsumptionTotal
                }
                else{
                    $cost = [math]::Round($htAzureConsumption.($subscriptionId).ConsumptionTotal,4)
                }
                $totalCost = "$($cost) $($htAzureConsumption.($subscriptionId).Currency)"
                $groupedArrayAzureConsumptionSummarizedByResourceType = $htAzureConsumption.($subscriptionId).Consumptiondata | group-object -property ConsumedService, ConsumedServiceCategory
                $groupedArrayAzureConsumptionSummarizedByResourceTypeCount = ($groupedArrayAzureConsumptionSummarizedByResourceType | Measure-Object).count
        
                $tfCount = $groupedArrayAzureConsumptionSummarizedByResourceTypeCount
                $tableId = "DetailsTable_Consumption_$($subscriptionId -replace '-','_')"
                $randomFunctionName = "func_$tableId"
                $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><i class="fa fa-credit-card" aria-hidden="true" style="color: #0078df"></i> Total cost $($totalCost) generated by $groupedArrayAzureConsumptionSummarizedByResourceTypeCount ResourceTypes last $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
<table id="$tableId" class="$cssClass">
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
                $htmlScopeInsightsConsumptionSub = foreach ($consumptionData in $htAzureConsumption.($subscriptionId).Consumptiondata) {
                    if ([math]::Round(($consumptionData.ConsumedServiceCost),4) -eq 0){
                        $cost = [decimal]($consumptionData.ConsumedServiceCost)
                    }
                    else{
                        $cost = [decimal]([math]::Round(($consumptionData.ConsumedServiceCost),4))
                    }
                    @"
<tr>
<td>$($consumptionData.ConsumedServiceChargeType)</td>
<td>$($consumptionData.ConsumedService)</td>
<td>$($consumptionData.ConsumedServiceCategory)</td>
<td>$($consumptionData.ConsumedServiceInstanceCount)</td>
<td>$($cost)</td>
<td>$currency</td>
</tr>
"@ 
                }
                $htmlScopeInsights += $htmlScopeInsightsConsumptionSub
                $htmlScopeInsights += @"
</tbody>
</table>
</div>
<script>
function loadtf$randomFunctionName() { if (window.helpertfConfig4$tableId !== 1) { 
window.helpertfConfig4$tableId=1;
var tfConfig4$tableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,          
"@      
                if ($tfCount -gt 10) {
                    $spectrum = "10, $tfCount"
                    if ($tfCount -gt 100) {
                        $spectrum = "10, 30, 50, $tfCount"
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
var tf = new TableFilter('$tableId', tfConfig4$tableId);
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

        #ResourceProvider
        #region ScopeInsightsResourceProvidersDetailed
        if (-not $NoResourceProvidersDetailed) {
            if (($htResourceProvidersAll.Keys | Measure-Object).count -gt 0) {
                $tfCount = ($arrayResourceProvidersAll | Measure-Object).Count
                $tableId = "DetailsTable_ResourceProvider_$($subscriptionId -replace '-','_')"
                $randomFunctionName = "func_$tableId"
                $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Providers Detailed</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        function loadtf$randomFunctionName() { if (window.helpertfConfig4$tableId !== 1) { 
   window.helpertfConfig4$tableId=1;
   var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,          
"@      
                if ($tfCount -gt 10) {
                    $spectrum = "10, $tfCount"
                    if ($tfCount -gt 100) {
                        $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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

        #Tags
        #region ScopeInsightsTags
        $tagsSubscriptionCount = ($htSubscriptionTags.$subscriptionId.Keys | Measure-Object).count
        if ($tagsSubscriptionCount -gt 0) {
            $tfCount = $tagsSubscriptionCount
            $tableId = "DetailsTable_Tags_$($subscriptionId -replace '-','_')"
            $randomFunctionName = "func_$tableId"
            $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible">
<p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $tagsSubscriptionCount Subscription Tags | Limit: ($tagsSubscriptionCount/$LimitTagsSubscription)</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$tableId !== 1) { 
   window.helpertfConfig4$tableId =1;
   var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
        if (-not $NoAzureConsumption) {
            if (($arrayAzureConsumptionSummarizedByResourceType | Measure-Object).Count -gt 0) {
                $arrayAzureConsumptionSummarizedByResourceTypeWhereMgIsInParentchain = $arrayAzureConsumptionSummarizedByResourceType | Where-Object { $_.SubscriptionMgPath -contains $mgChild }
                $arrayAzureConsumptionSummarizedByResourceTypeWhereMgIsInParentchainCount = ($arrayAzureConsumptionSummarizedByResourceTypeWhereMgIsInParentchain | Measure-Object).Count
                
                if ($arrayAzureConsumptionSummarizedByResourceTypeWhereMgIsInParentchainCount -gt 0) {

                    $groupedByCurrency = $arrayAzureConsumptionSummarizedByResourceTypeWhereMgIsInParentchain | Group-Object -Property SubscriptionConsumptionCurrency
                    $arrayTotalCostSummary = @()
                    foreach ($currency in $groupedByCurrency){
                        $totalCostTenant = ($currency.group.ConsumedServiceCost | Measure-Object -Sum).Sum
                        if ([math]::Round($totalCostTenant, 4) -eq 0){
                            $totalCostTenantRounded = $totalCostTenant
                        }
                        else{
                            $totalCostTenantRounded = [math]::Round($totalCostTenant, 4)
                        }
                        $totalCostTenantSubscriptionsCount = ($currency.group.SubscriptionId | Sort-Object -Unique | Measure-Object).Count
                        $totalCostTenantResourceTypesCount = ($currency.group.ConsumedService | Sort-Object -Unique | Measure-Object).Count
                        $totalCostTenantCurrency = $currency.Name
                        $arrayTotalCostSummary += "$($totalCostTenantRounded) $($totalCostTenantCurrency) generated by $($totalCostTenantResourceTypesCount) ResourceTypes in $($totalCostTenantSubscriptionsCount) Subscriptions"
                    }
                    $groupedArrayAzureConsumptionSummarizedByResourceTypeAndCurrency = $arrayAzureConsumptionSummarizedByResourceTypeWhereMgIsInParentchain | group-object -property ConsumedService, SubscriptionConsumptionCurrency, ConsumedServiceChargeType, ConsumedServiceCategory
                    $groupedArrayAzureConsumptionSummarizedByResourceTypeAndCurrencyCount = ($groupedArrayAzureConsumptionSummarizedByResourceTypeAndCurrency | Measure-Object).count
                
                    $tfCount = $groupedArrayAzureConsumptionSummarizedByResourceTypeAndCurrencyCount
                    $tableId = "DetailsTable_Consumption_$($mgChild -replace '-','_')"
                    $randomFunctionName = "func_$tableId"
                    $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><i class="fa fa-credit-card" aria-hidden="true" style="color: #0078df"></i> Total cost $($arrayTotalCostSummary -join "$CsvDelimiterOpposite ") last $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
<table id="$tableId" class="$cssClass">
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
                    $htmlScopeInsightsConsumptionMg = foreach ($consumedService in $groupedArrayAzureConsumptionSummarizedByResourceTypeAndCurrency) {
                        if ([math]::Round(($consumedService.group.ConsumedServiceCost | Measure-Object -Sum).Sum,4) -eq 0){
                            $cost = [decimal]($consumedService.group.ConsumedServiceCost | Measure-Object -Sum).Sum
                        }
                        else{
                            $cost = [decimal]([math]::Round(($consumedService.group.ConsumedServiceCost | Measure-Object -Sum).Sum,4))
                        }
                        @"
<tr>
<td>$((($ConsumedService.Name).split(", "))[2])</td>
<td>$((($ConsumedService.Name).split(", "))[0])</td>
<td>$((($ConsumedService.Name).split(", "))[3])</td>
<td>$(($consumedService.group.ConsumedServiceInstanceCount | Measure-Object -Sum).Sum)</td>
<td>$($cost)</td>
<td>$((($ConsumedService.Name).split(", "))[1])</td>
<td>$((($consumedService.group.SubscriptionId | sort-object -Unique) | Measure-Object).count)</td>
</tr>
"@ 
                    }
                    $htmlScopeInsights += $htmlScopeInsightsConsumptionMg
                    $htmlScopeInsights += @"
</tbody>
</table>
</div>
<script>
function loadtf$randomFunctionName() { if (window.helpertfConfig4$tableId !== 1) { 
window.helpertfConfig4$tableId=1;
var tfConfig4$tableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,          
"@      
                    if ($tfCount -gt 10) {
                        $spectrum = "10, $tfCount"
                        if ($tfCount -gt 100) {
                            $spectrum = "10, 30, 50, $tfCount"
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
var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
            $tableId = "DetailsTable_Resources_$($mgChild -replace '-','_')"
            $randomFunctionName = "func_$tableId"
            $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $resourcesAllChildSubscriptionResourceTypeCount ResourceTypes ($resourcesAllChildSubscriptionTotal Resources) in $resourcesAllChildSubscriptionLocationCount Locations (all Subscriptions below this scope)</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$tableId !== 1) { 
   window.helpertfConfig4$tableId =1;
   var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
            $tableId = "DetailsTable_Resources_$($subscriptionId -replace '-','_')"
            $randomFunctionName = "func_$tableId"
            $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $resourcesSubscriptionResourceTypeCount ResourceTypes ($resourcesSubscriptionTotal Resources) in $resourcesSubscriptionLocationCount Locations</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$tableId !== 1) { 
   window.helpertfConfig4$tableId =1;
   var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
        $resourceTypesSummarizedArray = foreach ($resourceTypeUnique in $resourceTypesUnique) {
            $resourcesTypeCountTotal = 0
            ($resourcesAllChildSubscriptions | Where-Object { $_.type -eq $resourceTypeUnique }).count_ | ForEach-Object { $resourcesTypeCountTotal += $_ }
            $dataFromResourceTypesDiagnosticsArray = $resourceTypesDiagnosticsArray | Where-Object { $_.ResourceType -eq $resourceTypeUnique }
            if ($dataFromResourceTypesDiagnosticsArray.Metrics -eq $true -or $dataFromResourceTypesDiagnosticsArray.Logs -eq $true) {
                $resourceDiagnosticscapable = $true
            }
            else {
                $resourceDiagnosticscapable = $false
            }
            [PSCustomObject]@{
                ResourceType       = $resourceTypeUnique
                ResourceCount      = $resourcesTypeCountTotal
                DiagnosticsCapable = $resourceDiagnosticscapable
                Metrics            = $dataFromResourceTypesDiagnosticsArray.Metrics
                Logs               = $dataFromResourceTypesDiagnosticsArray.Logs
                LogCategories      = ($dataFromResourceTypesDiagnosticsArray.LogCategories -join "$CsvDelimiterOpposite ") 
            }
        }
        $subscriptionResourceTypesDiagnosticsCapableMetricsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Metrics -eq $true } | Measure-Object).count
        $subscriptionResourceTypesDiagnosticsCapableLogsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Logs -eq $true } | Measure-Object).count
        $subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Metrics -eq $true -or $_.Logs -eq $true } | Measure-Object).count
    
        if ($resourcesAllChildSubscriptionResourceTypeCount -gt 0) {
            $tfCount = $resourcesAllChildSubscriptionResourceTypeCount
            $tableId = "DetailsTable_resourcesDiagnosticsCapable_$($mgchild -replace '-','_')"
            $randomFunctionName = "func_$tableId"
            $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount/$resourcesAllChildSubscriptionResourceTypeCount ResourceTypes Diagnostics capable ($subscriptionResourceTypesDiagnosticsCapableMetricsCount Metrics, $subscriptionResourceTypesDiagnosticsCapableLogsCount Logs) (all Subscriptions below this scope)</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$tableId !== 1) { 
   window.helpertfConfig4$tableId =1;
   var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
        $resourceTypesSummarizedArray = foreach ($resourceTypeUnique in $resourceTypesUnique) {
            $resourcesTypeCountTotal = 0
            ($resourcesSubscription | Where-Object { $_.type -eq $resourceTypeUnique }).count_ | ForEach-Object { $resourcesTypeCountTotal += $_ }
            $dataFromResourceTypesDiagnosticsArray = $resourceTypesDiagnosticsArray | Where-Object { $_.ResourceType -eq $resourceTypeUnique }
            if ($dataFromResourceTypesDiagnosticsArray.Metrics -eq $true -or $dataFromResourceTypesDiagnosticsArray.Logs -eq $true) {
                $resourceDiagnosticscapable = $true
            }
            else {
                $resourceDiagnosticscapable = $false
            }
            [PSCustomObject]@{
                ResourceType       = $resourceTypeUnique
                ResourceCount      = $resourcesTypeCountTotal
                DiagnosticsCapable = $resourceDiagnosticscapable
                Metrics            = $dataFromResourceTypesDiagnosticsArray.Metrics
                Logs               = $dataFromResourceTypesDiagnosticsArray.Logs
                LogCategories      = ($dataFromResourceTypesDiagnosticsArray.LogCategories -join "$CsvDelimiterOpposite ") 
            }
        }

        $subscriptionResourceTypesDiagnosticsCapableMetricsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Metrics -eq $true } | Measure-Object).count
        $subscriptionResourceTypesDiagnosticsCapableLogsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Logs -eq $true } | Measure-Object).count
        $subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount = ($resourceTypesSummarizedArray | Where-Object { $_.Metrics -eq $true -or $_.Logs -eq $true } | Measure-Object).count

        if ($resourcesSubscriptionResourceTypeCount -gt 0) {
            $tfCount = $resourcesSubscriptionResourceTypeCount
            $tableId = "DetailsTable_resourcesDiagnosticsCapable_$($subscriptionId -replace '-','_')"
            $randomFunctionName = "func_$tableId"
            $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $subscriptionResourceTypesDiagnosticsCapableMetricsLogsCount/$resourcesSubscriptionResourceTypeCount ResourceTypes Diagnostics capable ($subscriptionResourceTypesDiagnosticsCapableMetricsCount Metrics, $subscriptionResourceTypesDiagnosticsCapableLogsCount Logs)</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$tableId !== 1) { 
   window.helpertfConfig4$tableId =1;
   var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
        $tableIdentifier = $mgChild

        $policiesAssigned = [System.Collections.ArrayList]@()
        $policiesCount = 0
        $policiesCountBuiltin = 0
        $policiesCountCustom = 0
        $policiesAssignedAtScope = 0
        $policiesInherited = 0
        $policiesAssigned = foreach ($policyAssignment in $script:policyAssignmentsAllArray) {
            if ("" -eq $policyAssignment.subscriptionId -and $policyAssignment.MgId -eq $mgChild -and $policyAssignment.PolicyVariant -eq "Policy") {
                $policyAssignment
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
        $tableIdentifier = $subscriptionId

        $policiesAssigned = [System.Collections.ArrayList]@()
        $policiesCount = 0
        $policiesCountBuiltin = 0
        $policiesCountCustom = 0
        $policiesAssignedAtScope = 0
        $policiesInherited = 0
        $policiesAssigned = foreach ($policyAssignment in $script:policyAssignmentsAllArray) {
            if ($policyAssignment.subscriptionId -eq $subscriptionId -and $policyAssignment.PolicyVariant -eq "Policy") {
                $policyAssignment
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

    if (($policiesAssigned | measure-object).count -gt 0) {
        $tfCount = ($policiesAssigned | measure-object).count
        $tableId = "DetailsTable_PolicyAssignments_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
        $randomFunctionName = "func_$tableId"
        $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $policiesCount Policy Assignments ($policiesAssignedAtScope at scope, $policiesInherited inherited) (Builtin: $policiesCountBuiltin | Custom: $policiesCountCustom)</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a><br>
&nbsp;&nbsp;<span style="color:#FF5733">*Depending on the number of entries and your computer´s performance the table may respond with delay, download the csv for better filtering experience</span>
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
"@

        if (-not $NoPolicyComplianceStates) {

            $htmlScopeInsights += @"
<th>Policies NonCmplnt</th>
<th>Policies Compliant</th>
<th>Resources NonCmplnt</th>
<th>Resources Compliant</th>
"@
        }

        $htmlScopeInsights += @"
<th>Role/Assignment</th>
<th>Assignment DisplayName</th>
<th>AssignmentId</th>
</tr>
</thead>
<tbody>
"@
        $htmlScopeInsightsPolicyAssignments = $null
        $htmlScopeInsightsPolicyAssignments = foreach ($policyAssignment in $policiesAssigned | sort-object @{Expression = { $_.Level } }, @{Expression = { $_.MgName } }, @{Expression = { $_.MgId } }, @{Expression = { $_.SubscriptionName } }, @{Expression = { $_.SubscriptionId } }) {
            @"
<tr>
<td>$($policyAssignment.Inheritance)</td>
<td>$($policyAssignment.ExcludedScope)</td>
<td class="breakwordall">$($policyAssignment.PolicyName)</td>
<td class="breakwordall">$($policyAssignment.PolicyId)</td>
<td>$($policyAssignment.PolicyType)</td>
<td>$($policyAssignment.PolicyCategory)</td>
<td>$($policyAssignment.Effect)</td>
"@

            if (-not $NoPolicyComplianceStates) {
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
        function loadtf$randomFunctionName() { if (window.helpertfConfig4$tableId !== 1) { 
   window.helpertfConfig4$tableId =1;
   var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
            col_6: 'select',
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
"@

        if (-not $NoPolicyComplianceStates) {
            
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
            watermark: ['', '', '', '', '', '', '', '', '', '', '', '', '', ''],
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
        $tableIdentifier = $mgChild

        $policySetsAssigned = [System.Collections.ArrayList]@()
        $policySetsCount = 0
        $policySetsCountBuiltin = 0
        $policySetsCountCustom = 0
        $policySetsAssignedAtScope = 0
        $policySetsInherited = 0
        $policySetsAssigned = foreach ($policySetAssignment in $script:policyAssignmentsAllArray) {
            if ("" -eq $policySetAssignment.subscriptionId -and $policySetAssignment.MgId -eq $mgChild -and $policySetAssignment.PolicyVariant -eq "PolicySet") {
                $policySetAssignment
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
        $tableIdentifier = $subscriptionId

        $policySetsAssigned = [System.Collections.ArrayList]@()
        $policySetsCount = 0
        $policySetsCountBuiltin = 0
        $policySetsCountCustom = 0
        $policySetsAssignedAtScope = 0
        $policySetsInherited = 0
        $policySetsAssigned = foreach ($policySetAssignment in $script:policyAssignmentsAllArray) {
            if ($policySetAssignment.subscriptionId -eq $subscriptionId -and $policySetAssignment.PolicyVariant -eq "PolicySet") {
                $policySetAssignment
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

    if (($policySetsAssigned | measure-object).count -gt 0) {
        $tfCount = ($policiesAssigned | measure-object).count
        $tableId = "DetailsTable_PolicySetAssignments_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
        $randomFunctionName = "func_$tableId"
        $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $policySetsCount PolicySet Assignments ($policySetsAssignedAtScope at scope, $policySetsInherited inherited) (Builtin: $policySetsCountBuiltin | Custom: $policySetsCountCustom)</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
<table id="$tableId" class="$cssClass">
<thead>
<tr>
<th>Inheritance</th>
<th>ScopeExcluded</th>
<th>PolicySet DisplayName</th>
<th>PolicySetId</th>
<th>Type</th>
<th>Category</th>
"@

        if (-not $NoPolicyComplianceStates) {
        
            $htmlScopeInsights += @"
<th>Policies NonCmplnt</th>
<th>Policies Compliant</th>
<th>Resources NonCmplnt</th>
<th>Resources Compliant</th>
"@
        }

        $htmlScopeInsights += @"        
<th>Role/Assignment</th>
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
            if (-not $NoPolicyComplianceStates) {
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
        function loadtf$randomFunctionName() { if (window.helpertfConfig4$tableId !== 1) { 
   window.helpertfConfig4$tableId =1;
   var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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

        if (-not $NoPolicyComplianceStates) {
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    if ($policiesAssignedAtScope -eq 0 -and $policySetsAssignedAtScope -eq 0) {
        if ($mgOrSub -eq "mg") {
            $limit = $LimitPOLICYPolicyAssignmentsManagementGroup
        }
        if ($mgOrSub -eq "sub") {
            $limit = $LimitPOLICYPolicyAssignmentsSubscription
        }
        $faimage = "<i class=`"fa fa-ban`" aria-hidden=`"true`"></i>"
    
        $htmlScopeInsights += @"
            <p>$faImage Policy Assignment Limit: 0/$limit</p>
"@
    }
    else {
        if ($mgOrSub -eq "mg") {
            $scopePolicyAssignmentsLimit = $policyPolicyBaseQueryScopeInsights | Where-Object { "" -eq $_.SubscriptionId -and $_.MgId -eq $mgChild }
        }
        if ($mgOrSub -eq "sub") {
            $scopePolicyAssignmentsLimit = $policyPolicyBaseQueryScopeInsights | Where-Object { $_.SubscriptionId -eq $subscriptionId }
        }

        if ($scopePolicyAssignmentsLimit.PolicyAndPolicySetAssigmentAtScopeCount -gt (($scopePolicyAssignmentsLimit.PolicyAssigmentLimit) * $LimitCriticalPercentage / 100)) {
            $faImage = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
        }
        else {
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
    if ($mgOrSub -eq "mg") {
        $tableIdentifier = $mgChild
        $scopePolicies = ($script:customPoliciesDetailed | Where-Object { $_.PolicyDefinitionId -like "*/providers/Microsoft.Management/managementGroups/$mgChild/*" })
        $scopePoliciesCount = ($scopePolicies | Measure-Object).count
    }
    if ($mgOrSub -eq "sub") {
        $tableIdentifier = $subscriptionId
        $scopePolicies = ($script:customPoliciesDetailed | Where-Object { $_.PolicyDefinitionId -like "*/subscriptions/$subscriptionId/*" })
        $scopePoliciesCount = ($scopePolicies | Measure-Object).count
    }

    if ($scopePoliciesCount -gt 0) {
        $tfCount = $scopePoliciesCount
        $tableId = "DetailsTable_ScopedPolicies_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
        $randomFunctionName = "func_$tableId"
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
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
<table id="$tableId" class="$cssClass">
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$tableId !== 1) { 
   window.helpertfConfig4$tableId =1;
   var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
        $tableIdentifier = $mgChild
        $scopePolicySets = ($script:customPolicySetsDetailed | Where-Object { $_.PolicySetDefinitionId -like "*/providers/Microsoft.Management/managementGroups/$mgChild/*" })
        $scopePolicySetsCount = ($scopePolicySets | Measure-Object).count
    }
    if ($mgOrSub -eq "sub") {
        $tableIdentifier = $subscriptionId
        $scopePolicySets = ($script:customPolicySetsDetailed | Where-Object { $_.PolicySetDefinitionId -like "*/subscriptions/$subscriptionId/*" })
        $scopePolicySetsCount = ($scopePolicySets | Measure-Object).count
    }

    if ($scopePolicySetsCount -gt 0) {
        $tfCount = $scopePolicySetsCount
        $tableId = "DetailsTable_ScopedPolicySets_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
        $randomFunctionName = "func_$tableId"
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
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
<table id="$tableId" class="$cssClass">
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$tableId !== 1) { 
   window.helpertfConfig4$tableId =1;
   var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
                $tableIdentifier = $mgChild
            }
            if ($mgOrSub -eq "sub") {
                $tableIdentifier = $subscriptionId
            }
            $tableId = "DetailsTable_BlueprintAssignment_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
            $randomFunctionName = "func_$tableId"
            $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintsAssignedCount Blueprints assigned</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$tableId !== 1) { 
   window.helpertfConfig4$tableId =1;
   var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
            $tableIdentifier = $mgChild
        }
        if ($mgOrSub -eq "sub") {
            $tableIdentifier = $subscriptionId
        }
        $tableId = "DetailsTable_BlueprintScoped_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
        $randomFunctionName = "func_$tableId"
        $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintsScopedCount Blueprints scoped</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
            function loadtf$randomFunctionName() { if (window.helpertfConfig4$tableId !== 1) { 
   window.helpertfConfig4$tableId =1;
   var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
        $tableIdentifier = $mgChild
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
        $rolesAssigned = foreach ($roleAssignment in $script:rbacAll) {
            if ("" -eq $roleAssignment.subscriptionId -and $roleAssignment.MgId -eq $mgChild) {
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
    }
    if ($mgOrSub -eq "sub") {
        $tableIdentifier = $subscriptionId
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
        $rolesAssigned = foreach ($roleAssignment in $script:rbacAll) {
            if ($roleAssignment.subscriptionId -eq $subscriptionId) {
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
    }

    $rolesAssignedAtScopeCount = $rolesAssignedCount - $rolesAssignedInheritedCount

    if (($rolesAssigned | measure-object).count -gt 0) {
        $tfCount = ($rolesAssigned | measure-object).count
        $tableId = "DetailsTable_RoleAssignments_$($tableIdentifier -replace "\(","_" -replace "\)","_" -replace "-","_" -replace "\.","_")"
        $randomFunctionName = "func_$tableId"
        $htmlScopeInsights += @"
<button onclick="loadtf$randomFunctionName()" type="button" class="collapsible"><p>$faIcon $rolesAssignedCount Role Assignments ($rolesAssignedInheritedCount inherited) (User: $rolesAssignedUser | Group: $rolesAssignedGroup | ServicePrincipal: $rolesAssignedServicePrincipal | Orphaned: $rolesAssignedUnknown) ($($roleSecurityFindingCustomRoleOwnerImg)CustomRoleOwner: $roleSecurityFindingCustomRoleOwner, $($RoleSecurityFindingOwnerAssignmentSPImg)OwnerAssignmentSP: $roleSecurityFindingOwnerAssignmentSP) (Policy related: $roleAssignmentsRelatedToPolicyCount) | Limit: ($rolesAssignedAtScopeCount/$LimitRoleAssignmentsScope)</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a><br>
&nbsp;&nbsp;<span style="color:#FF5733">*Depending on the number of entries and your computer´s performance the table may respond with delay, download the csv for better filtering experience</span>
<table id="$tableId" class="$cssClass">
<thead>
<tr>
<th>Scope</th>
<th>Role</th>
<th>Role Type</th>
<th>Identity Displayname</th>
<th>Identity SignInName</th>
<th>Identity ObjectId</th>
<th>Identity Type</th>
"@

        if (-not $NoAADGroupsResolveMembers) {
            $htmlScopeInsights += @"
<th>GroupMember DisplayName</th>
<th>GroupMember SignInName</th>
<th>GroupMember ObjectId</th>
<th>GroupMember Type</th>
"@
        }

        $htmlScopeInsights += @"
<th>Role AssignmentId</th>
<th>Related PolicyAssignment</th>
</tr>
</thead>
<tbody>
"@
        $htmlScopeInsightsRoleAssignments = $null
        $htmlScopeInsightsRoleAssignments = foreach ($roleAssignment in $rolesAssigned | sort-object @{Expression = { $_.Level } }, @{Expression = { $_.MgName } }, @{Expression = { $_.MgId } }, @{Expression = { $_.SubscriptionName } }, @{Expression = { $_.SubscriptionId } }) {
            @"
<tr>
<td>$($roleAssignment.Scope)</td>
<td>$($roleAssignment.Role)</td>
<td>$($roleAssignment.RoleType)</td>
<td class="breakwordall">$($roleAssignment.ObjectDisplayName)</td>
<td class="breakwordall">$($roleAssignment.ObjectSignInName)</td>
<td class="breakwordall">$($roleAssignment.ObjectId)</td>
<td>$($roleAssignment.ObjectType)</td>
"@

            if (-not $NoAADGroupsResolveMembers) {
                @"
<td class="breakwordall">$($roleAssignment.GrpMemberDisplayName)</td>
<td class="breakwordall">$($roleAssignment.GrpMemberSignInName)</td>
<td class="breakwordall">$($roleAssignment.GrpMemberId)</td>
<td>$($roleAssignment.GrpMemberType)</td>
"@
            }

            @"
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
        function loadtf$randomFunctionName() { if (window.helpertfConfig4$tableId !== 1) { 
   window.helpertfConfig4$tableId =1;
   var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
            col_6: 'multiple',
"@
        if (-not $NoAADGroupsResolveMembers) {
            $htmlScopeInsights += @"
                col_10: 'multiple',
"@
        }
        $htmlScopeInsights += @"
            col_types: [
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
"@
        if (-not $NoAADGroupsResolveMembers) {
            $htmlScopeInsights += @"
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
"@
        }
        $htmlScopeInsights += @"
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
"@
        if (-not $NoAADGroupsResolveMembers) {
            $htmlScopeInsights += @"
                watermark: ['', 'try owner||reader', '', '', '', '', '', '', '', '', '', '', ''],
"@
        }
        else {
            $htmlScopeInsights += @"
                watermark: ['', 'try owner||reader', '', '', '', '', '', '', ''],
"@    
        }
        $htmlScopeInsights += @"
            
extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();}}
    </script>
"@
    }
    else {
        $htmlScopeInsights += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($script:rbacAll | measure-object).count) Role Assignments</span></p>
    </td></tr>
"@
    }
    #endregion ScopeInsightsRoleAssignments

    $script:html += $htmlScopeInsights

    if ($script:scopescnter % 30 -eq 0) {
        $script:scopescnter = 0
        Write-Host "   append file duration: " (Measure-Command { $script:html | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force }).TotalSeconds "seconds"
        $script:html = $null 
    }

}
#endregion ScopeInsights

#rsu
#region TenantSummary
function summary() {
    #$startSummary = get-date
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

    $customPoliciesArray = [System.Collections.ArrayList]@()
    $customPoliciesArray = foreach ($tenantCustomPolicy in $tenantCustomPolicies) {
        ($htCacheDefinitions).policy.($tenantCustomPolicy)
    }

    $script:customPoliciesDetailed = [System.Collections.ArrayList]@()
    $script:customPoliciesDetailed = foreach ($customPolicy in ($customPoliciesArray | Sort-Object @{Expression = { $_.DisplayName } }, @{Expression = { $_.PolicyDefinitionId } })) {
    
        $temp0000000 = ($htCacheDefinitions).policy.($customPolicy.Id)

        #uniqueAssignments
        $policyUniqueAssignments = (($policyPolicyBaseQueryUniqueAssignments | Where-Object { $_.PolicyDefinitionIdFull -eq $temp0000000.Id }).PolicyAssignmentId)
        $policyUniqueAssignmentsArray = [System.Collections.ArrayList]@()
        $policyUniqueAssignmentsArray = foreach ($policyUniqueAssignment in $policyUniqueAssignments) {
            $policyUniqueAssignment
        }
        $policyUniqueAssignmentsCount = ($policyUniqueAssignments | measure-object).count 

        $uniqueAssignments = $null
        if ($policyUniqueAssignmentsCount -gt 0) {
            $policyUniqueAssignmentsList = "($($policyUniqueAssignmentsArray -join "$CsvDelimiterOpposite "))"
            $uniqueAssignments = "$policyUniqueAssignmentsCount $policyUniqueAssignmentsList"
        }
        else {
            $uniqueAssignments = $policyUniqueAssignmentsCount
        }

        #usedInPolicySet
        $usedInPolicySetArray = [System.Collections.ArrayList]@()
        $usedInPolicySetArray = foreach ($customPolicySet in $tenantCustomPolicySets) {
            if (($htCacheDefinitions).policySet.$customPolicySet.Type -eq "Custom") {
                $hlpCustomPolicySet = ($htCacheDefinitions).policySet.($customPolicySet)
                if (($hlpCustomPolicySet.PolicySetPolicyIds).contains($customPolicy.PolicyDefinitionId)) {
                    ($hlpCustomPolicySet.Id)                          
                }
            }
        }
        $usedInPolicySetList = [System.Collections.ArrayList]@()
        $usedInPolicySetList = foreach ($usedPolicySet in $usedInPolicySetArray) {
            $hlpPolicySetUsed = ($htCacheDefinitions).policySet.($usedPolicySet)
            "$($hlpPolicySetUsed.DisplayName) ($($hlpPolicySetUsed.PolicyDefinitionId))"
        }
        $usedInPolicySetListCount = ($usedInPolicySetList | Measure-Object).count
        $usedInPolicySet = $null
        if ($usedInPolicySetListCount -gt 0) {
            $usedInPolicySetListInBrackets = "($(($usedInPolicySetList | Sort-Object) -join "$CsvDelimiterOpposite "))"
            $usedInPolicySet = "$usedInPolicySetListCount $usedInPolicySetListInBrackets"
        }
        else {
            $usedInPolicySet = $usedInPolicySetListCount
        }

        #policyEffect
        if ($temp0000000.effectDefaultValue -ne "n/a") {
            $effect = "Default: $($temp0000000.effectDefaultValue); Allowed: $($temp0000000.effectAllowedValue)"
        }
        else {
            $effect = "Fixed: $($temp0000000.effectFixedValue)"
        }

        #policyRoledefinitions
        $policyRoleDefinitionsArray = [System.Collections.ArrayList]@()
        if (($htCacheDefinitionsAsIs).policy.($customPolicy.Id).properties.policyrule.then.details.roledefinitionIds) {
            $policyRoleDefinitionsArray = foreach ($policyRoledefinitionId in ($htCacheDefinitionsAsIs).policy.($customPolicy.Id).properties.policyrule.then.details.roledefinitionIds) {
                ($htCacheDefinitions).role.($policyRoledefinitionId -replace '.*/').Name
            }
        }
        if (($policyRoleDefinitionsArray | Measure-Object).count -gt 0) {
            $policyRoleDefinitions = $policyRoleDefinitionsArray -join "$CsvDelimiterOpposite "
        }
        else {
            $policyRoleDefinitions = "n/a"
        }

        #scope
        if (($temp0000000.Id).startswith("/subscriptions/", "CurrentCultureIgnoreCase")) {
            $scope = "Sub"
            $scopeId = $temp0000000.Id -replace "/subscriptions/", "" -replace '/.*'
        }
        if (($temp0000000.Id).startswith("/providers/Microsoft.Management/managementGroups/", "CurrentCultureIgnoreCase")) {
            $scope = "Mg"
            $scopeId = $temp0000000.Id -replace "/providers/Microsoft.Management/managementGroups/", "" -replace '/.*'
        }

        [PSCustomObject]@{ 
            Scope              = $scope
            ScopeId            = $scopeId
            PolicyDisplayName  = $temp0000000.DisplayName 
            PolicyDefinitionId = $temp0000000.PolicyDefinitionId 
            PolicyEffect       = $effect
            PolicyCategory     = $temp0000000.Category
            RoleDefinitions    = $policyRoleDefinitions 
            UniqueAssignments  = $uniqueAssignments 
            UsedInPolicySets   = $usedInPolicySet
        }
    }

    if ($getMgParentName -eq "Tenant Root") {

        if ($tenantCustomPoliciesCount -gt 0) {
            $tfCount = $tenantCustomPoliciesCount
            $tableId = "SummaryTable_customPolicies"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customPolicies"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policies ($scopeNamingSummary)</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
<table id="$tableId" class="summaryTable">
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
            $htmlSUMMARYcustompolicies = foreach ($customPolicy in ($script:customPoliciesDetailed | Sort-Object @{Expression = { $_.PolicyDisplayName } }, @{Expression = { $_.PolicyDefinitionId } })) {
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
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,       
"@      
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
            $customPoliciesInScopeArray = foreach ($customPolicy in ($customPoliciesArray | Sort-Object @{Expression = { $_.DisplayName } }, @{Expression = { $_.PolicyDefinitionId } })) {
                $currentpolicy = ($htCacheDefinitions).policy.($customPolicy.PolicyDefinitionId)
                if (($currentpolicy.PolicyDefinitionId) -like "/providers/Microsoft.Management/managementGroups/*") {
                    $policyScopedMgSub = $currentpolicy.PolicyDefinitionId -replace "/providers/Microsoft.Management/managementGroups/", "" -replace '/.*'
                    if ($mgsAndSubs.MgId.contains("$policyScopedMgSub")) {
                        $currentpolicy
                    }
                }

                if (($currentpolicy.PolicyDefinitionId) -like "/subscriptions/*") {
                    $policyScopedMgSub = $currentpolicy.PolicyDefinitionId -replace "/subscriptions/", "" -replace '/.*'
                    if ($mgsAndSubs.SubscriptionId.contains("$policyScopedMgSub")) {
                        $currentpolicy
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
            $tableId = "SummaryTable_customPolicies"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customPolicies"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$tenantCustomPoliciesCount Custom Policies $scopeNamingSummary ($customPoliciesFromSuperiorMGs from superior scopes)</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
<table id="$tableId" class="summaryTable">
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
            $htmlSUMMARYcustompolicies = foreach ($customPolicy in ($script:customPoliciesDetailed | Sort-Object @{Expression = { $_.PolicyDisplayName } }, @{Expression = { $_.PolicyDefinitionId } })) {
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
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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

    #region SUMMARYCustomPoliciesOrphandedTenantRoot
    Write-Host "  processing TenantSummary Custom Policies orphaned"
    if ($getMgParentName -eq "Tenant Root") {
        $customPoliciesOrphaned = [System.Collections.ArrayList]@()
        $customPoliciesOrphaned = foreach ($customPolicyAll in $tenantCustomPolicies) {
            if (($policyPolicyBaseQueryUniqueCustomDefinitions | measure-object).count -eq 0) {
                $hlpCustomPolicy = ($htCacheDefinitions).policy.$customPolicyAll
                if ($hlpCustomPolicy.Type -eq "Custom") {
                    $hlpCustomPolicy
                }
            }
            else {
                if ($policyPolicyBaseQueryUniqueCustomDefinitions.contains("$customPolicyAll")) {
                }
                else {
                    $hlpCustomPolicy = ($htCacheDefinitions).policy.$customPolicyAll
                    if ($hlpCustomPolicy.Type -eq "Custom") {
                        $hlpCustomPolicy
                    }
                }
            }
        }

        $arrayCustomPoliciesOrphanedFinal = [System.Collections.ArrayList]@()
        $arrayCustomPoliciesOrphanedFinal = foreach ($customPolicyOrphaned in $customPoliciesOrphaned) {
            if ($arrayPoliciesUsedInPolicySets -notcontains $customPolicyOrphaned.id) {
                ($htCacheDefinitions).policy.$($customPolicyOrphaned.id)
            }
        }

        $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()
        $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups = foreach ($customPolicyOrphanedFinal in $arrayCustomPoliciesOrphanedFinal) {
            if ($script:arrayCachePolicyAssignmentsResourceGroups.properties.policydefinitionId -notcontains $customPolicyOrphanedFinal.policydefinitionId) {
                $customPolicyOrphanedFinal
            }
        }

        if (($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0) {
            $tfCount = ($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count
            $tableId = "SummaryTable_customPoliciesOrphaned"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customPoliciesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom Policies ($scopeNamingSummary)</span> <abbr title="Policy is not used in a PolicySet &#13;AND &#13;Policy has no Assignments (including ResourceGroups)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
        $customPoliciesOrphaned = foreach ($customPolicyAll in $tenantCustomPolicies) {
            if (($policyPolicyBaseQueryUniqueCustomDefinitions | measure-object).count -eq 0) {
                if (($htCacheDefinitions).policy.$customPolicyAll.Type -eq "Custom") {
                    ($htCacheDefinitions).policy.$customPolicyAll.Id
                }
            }
            else {
                if (-not $policyPolicyBaseQueryUniqueCustomDefinitions.contains("$customPolicyAll")) {    
                    if (($htCacheDefinitions).policy.$customPolicyAll.Type -eq "Custom") {
                        ($htCacheDefinitions).policy.$customPolicyAll.Id
                    }
                }
            }
        }
        $customPoliciesOrphanedInScopeArray = [System.Collections.ArrayList]@()
        $customPoliciesOrphanedInScopeArray = foreach ($customPolicyOrphaned in  $customPoliciesOrphaned) {
            $hlpOrphanedInScope = ($htCacheDefinitions).policy.$customPolicyOrphaned
            if (($hlpOrphanedInScope.PolicyDefinitionId) -like "/providers/Microsoft.Management/managementGroups/*") {
                $policyScopedMgSub = $hlpOrphanedInScope.PolicyDefinitionId -replace "/providers/Microsoft.Management/managementGroups/", "" -replace '/.*'
                if ($mgsAndSubs.MgId.contains("$policyScopedMgSub")) {
                    $hlpOrphanedInScope
                }
            }
            if (($hlpOrphanedInScope.PolicyDefinitionId) -like "/subscriptions/*") {
                $policyScopedMgSub = $hlpOrphanedInScope.PolicyDefinitionId -replace "/subscriptions/", "" -replace '/.*'
                if ($mgsAndSubs.SubscriptionId.contains("$policyScopedMgSub")) {
                    $hlpOrphanedInScope
                }
            }
        }
        $arrayCustomPoliciesOrphanedFinal = [System.Collections.ArrayList]@()
        $arrayCustomPoliciesOrphanedFinal = foreach ($customPolicyOrphanedInScopeArray in $customPoliciesOrphanedInScopeArray) {
            if ($arrayPoliciesUsedInPolicySets -notcontains $customPolicyOrphanedInScopeArray.id) {
                $customPolicyOrphanedInScopeArray
            }
        }

        $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()
        $arrayCustomPoliciesOrphanedFinalIncludingResourceGroups = foreach ($customPolicyOrphanedFinal in $arrayCustomPoliciesOrphanedFinal) {
            if ($script:arrayCachePolicyAssignmentsResourceGroups.properties.policydefinitionId -notcontains $customPolicyOrphanedFinal.policydefinitionId) {
                $customPolicyOrphanedFinal
            }

        }

        if (($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0) {
            $tfCount = ($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count
            $tableId = "SummaryTable_customPoliciesOrphaned"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customPoliciesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomPoliciesOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom Policies ($scopeNamingSummary)</span> <abbr title="Policy is not used in a PolicySet &#13;AND &#13;Policy has no Assignments (including ResourceGroups) &#13;Note: Policies from superior scopes are not evaluated"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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

    #region SUMMARYtenanttotalcustompolicySets
    Write-Host "  processing TenantSummary Custom PolicySets"
    $customPolicySetsArray = [System.Collections.ArrayList]@()
    $customPolicySetsArray = foreach ($tenantCustomPolicySet in $tenantCustomPolicySets) {
        ($htCacheDefinitions).policySet.($tenantCustomPolicySet)
    }
    $script:customPolicySetsDetailed = [System.Collections.ArrayList]@()
    $script:customPolicySetsDetailed = foreach ($customPolicySet in ($customPolicySetsArray)) {
    
        $temp00000000 = ($htCacheDefinitions).policySet.($customPolicySet.Id)
        $policySetUniqueAssignments = (($policyPolicySetBaseQueryUniqueAssignments | Where-Object { $_.PolicyDefinitionIdFull -eq $temp00000000.Id }).PolicyAssignmentId)
        $policySetUniqueAssignmentsArray = [System.Collections.ArrayList]@()
        $policySetUniqueAssignmentsArray = foreach ($policySetUniqueAssignment in $policySetUniqueAssignments) {
            $policySetUniqueAssignment
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
        $policySetPoliciesArray = foreach ($policyPolicySet in $temp00000000.PolicySetPolicyIds) {
            $hlpPolicyDef = ($htCacheDefinitions).policy.($policyPolicySet)

            if ($hlpPolicyDef.Type -eq "Builtin") {
                "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/$($hlpPolicyDef.Id -replace '.*/').html`" target=`"_blank`">$($hlpPolicyDef.DisplayName)</a> ($policyPolicySet)"
            }
            else {
                "$($hlpPolicyDef.DisplayName) ($policyPolicySet)"
            }
        }
        $policySetPoliciesCount = ($policySetPoliciesArray | Measure-Object).count
        if ($policySetPoliciesCount -gt 0) {
            $policiesUsed = "$policySetPoliciesCount ($(($policySetPoliciesArray | sort-Object) -join "$CsvDelimiterOpposite "))"
        }
        else {
            $policiesUsed = "0 really?"
        }

        #scope
        if (($temp00000000.Id).startswith("/subscriptions/", "CurrentCultureIgnoreCase")) {
            $scope = "Sub"
            $scopeId = $temp00000000.Id -replace "/subscriptions/", "" -replace '/.*'
        }
        if (($temp00000000.Id).startswith("/providers/Microsoft.Management/managementGroups/", "CurrentCultureIgnoreCase")) {
            $scope = "Mg"
            $scopeId = $temp00000000.Id -replace "/providers/Microsoft.Management/managementGroups/", "" -replace '/.*'
        }

        [PSCustomObject]@{ 
            Scope                 = $scope
            ScopeId               = $scopeId
            PolicySetDisplayName  = $customPolicySet.DisplayName
            PolicySetDefinitionId = $customPolicySet.PolicyDefinitionId 
            PolicySetCategory     = $customPolicySet.Category
            UniqueAssignments     = $policySetUniqueAssignment 
            PoliciesUsed          = $policiesUsed
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
            $tableId = "SummaryTable_customPolicySets"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customPolicySets">$faimage <span class="valignMiddle">$tenantCustompolicySetsCount Custom PolicySets ($scopeNamingSummary) (Limit: $tenantCustompolicySetsCount/$LimitPOLICYPolicySetDefinitionsScopedTenant)</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
<table id="$tableId" class="summaryTable">
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
            $htmlSUMMARYtenanttotalcustompolicySets = foreach ($customPolicySet in $script:customPolicySetsDetailed | Sort-Object @{Expression = { $_.PolicySetDisplayName } }, @{Expression = { $_.PolicySetDefinitionId } }) {
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
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
            $custompolicySetsInScopeArray = [System.Collections.ArrayList]@()
            $custompolicySetsInScopeArray = foreach ($custompolicySet in $tenantCustomPolicySets) {
                $currentpolicyset = ($htCacheDefinitions).policySet.$custompolicySet
                if (($currentpolicyset.policyDefinitionId) -like "/providers/Microsoft.Management/managementGroups/*") {
                    $policySetScopedMgSub = $currentpolicyset.policyDefinitionId -replace "/providers/Microsoft.Management/managementGroups/", "" -replace '/.*'
                    if ($mgsAndSubs.MgId.contains("$policySetScopedMgSub")) {
                        $currentpolicyset
                    }
                }
                if (($currentpolicyset.policyDefinitionId) -like "/subscriptions/*") {
                    $policySetScopedMgSub = $currentpolicyset.policyDefinitionId -replace "/subscriptions/", "" -replace '/.*'
                    if ($mgsAndSubs.SubscriptionId.contains("$policySetScopedMgSub")) {
                        $currentpolicyset
                    }
                }
            }
            $custompolicySetsFromSuperiorMGs = $tenantCustompolicySetsCount - (($custompolicySetsInScopeArray | measure-object).count)
        }
        else {
            $custompolicySetsFromSuperiorMGs = "0"
        }

        if ($tenantCustompolicySetsCount -gt 0) {
            $tfCount = $tenantCustompolicySetsCount
            $tableId = "SummaryTable_customPolicySets"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customPolicySets">$faimage <span class="valignMiddle">$tenantCustomPolicySetsCount Custom PolicySets $scopeNamingSummary ($custompolicySetsFromSuperiorMGs from superior scopes) (Limit: $tenantCustompolicySetsCount/$LimitPOLICYPolicySetDefinitionsScopedTenant)</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
<table id="$tableId" class="summaryTable">
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
            $htmlSUMMARYtenanttotalcustompolicySets = foreach ($customPolicySet in $script:customPolicySetsDetailed) {
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
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
        $custompolicySetSetsOrphaned = foreach ($custompolicySetAll in $tenantCustomPolicySets) {
            if (($policyPolicySetBaseQueryUniqueCustomDefinitions | measure-object).count -eq 0) {
                ($htCacheDefinitions).policySet.$custompolicySetAll
            }
            else {
                if (-not $policyPolicySetBaseQueryUniqueCustomDefinitions.contains($custompolicySetAll)) {
                    ($htCacheDefinitions).policySet.$custompolicySetAll
                }
            }
        }

        $arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()
        $arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups = foreach ($customPolicySetOrphaned in $custompolicySetSetsOrphaned) {
            if ($script:arrayCachePolicyAssignmentsResourceGroups.properties.policydefinitionId -notcontains $customPolicySetOrphaned.policydefinitionId) {
                $customPolicySetOrphaned
            }
        }

        if (($arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0) {
            $tfCount = ($arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups | measure-object).count
            $tableId = "SummaryTable_customPolicySetsOrphaned"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_custompolicySetsOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arraycustompolicySetSetsOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom PolicySets ($scopeNamingSummary)</span> <abbr title="PolicySet has no Assignments (including ResourceGroups)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
        $custompolicySetSetsOrphaned = [System.Collections.ArrayList]@()
        $custompolicySetSetsOrphaned = foreach ($custompolicySetAll in $tenantCustomPolicySets) {
            if (($policyPolicySetBaseQueryUniqueCustomDefinitions | measure-object).count -eq 0) {
                ($htCacheDefinitions).policySet.$custompolicySetAll.Id
            }
            else {
                if (-not $policyPolicySetBaseQueryUniqueCustomDefinitions.contains("$custompolicySetAll")) {    
                    ($htCacheDefinitions).policySet.$custompolicySetAll.Id
                }
            }
        }
        $arrayCustomPolicySetsOrphanedFinal = [System.Collections.ArrayList]@()
        $arrayCustomPolicySetsOrphanedFinal = foreach ($custompolicySetOrphaned in  $custompolicySetSetsOrphaned) {
            if ((($htCacheDefinitions).policySet.$custompolicySetOrphaned.policyDefinitionId) -like "/providers/Microsoft.Management/managementGroups/*") {
                $policySetScopedMgSub = ($htCacheDefinitions).policySet.$custompolicySetOrphaned.policyDefinitionId -replace "/providers/Microsoft.Management/managementGroups/", "" -replace '/.*'
                if ($mgsAndSubs.MgId.contains("$policySetScopedMgSub")) {
                    ($htCacheDefinitions).policySet.$custompolicySetOrphaned
                }
            }
            if ((($htCacheDefinitions).policySet.$custompolicySetOrphaned.policyDefinitionId) -like "/subscriptions/*") {
                $policySetScopedMgSub = ($htCacheDefinitions).policySet.$custompolicySetOrphaned.policyDefinitionId -replace "/subscriptions/", "" -replace '/.*'
                if ($mgsAndSubs.SubscriptionId.contains("$policySetScopedMgSub")) {
                    ($htCacheDefinitions).policySet.$custompolicySetOrphaned
                }
            }
        }

        $arraycustompolicySetsOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()
        $arraycustompolicySetsOrphanedFinalIncludingResourceGroups = foreach ($customPolicySetOrphaned in $arrayCustomPolicySetsOrphanedFinal) {
            if ($script:arrayCachePolicyAssignmentsResourceGroups.properties.policydefinitionId -notcontains $customPolicySetOrphaned.policydefinitionId) {
                $customPolicySetOrphaned
            }
        }

        if (($arraycustompolicySetsOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0) {
            $tfCount = ($arraycustompolicySetsOrphanedFinalIncludingResourceGroups | measure-object).count
            $tableId = "SummaryTable_customPolicySetsOrphaned"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_custompolicySetsOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arraycustompolicySetsOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom PolicySets ($scopeNamingSummary)</span> <abbr title="PolicySet has no Assignments (including ResourceGroups) &#13;Note: PolicySets from superior scopes are not evaluated"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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

    #region SUMMARYPolicySetsDeprecatedPolicy
    Write-Host "  processing TenantSummary Custom PolicySets using depracted Policy"
    $policySetsDeprecated = [System.Collections.ArrayList]@()
    $customPolicySets = $tenantCustomPolicySets | Where-Object { ($htCacheDefinitions).policySet.($_).type -eq "Custom" } 
    $customPolicySetsCount = ($customPolicySets | Measure-Object).count
    if ($customPolicySetsCount -gt 0) {
        $policySetsDeprecated = foreach ($polSetDef in $customPolicySets) {
            foreach ($polsetPolDefId in $($htCacheDefinitions).policySet.($polSetDef).PolicySetPolicyIds) {
                $hlpDeprecatedPolicySet = (($htCacheDefinitions).policy.$polsetPolDefId)
                if ($hlpDeprecatedPolicySet.type -eq "BuiltIn") {
                    if ($hlpDeprecatedPolicySet.deprecated -eq $true -or ($hlpDeprecatedPolicySet.displayname).StartsWith("[Deprecated]", "CurrentCultureIgnoreCase")) {
                        [PSCustomObject]@{
                            PolicySetDisplayName  = $($htCacheDefinitions).policySet.($polSetDef).DisplayName
                            PolicySetDefinitionId = $($htCacheDefinitions).policySet.($polSetDef).PolicyDefinitionId
                            PolicyDisplayName     = $hlpDeprecatedPolicySet.displayname
                            PolicyId              = $hlpDeprecatedPolicySet.Id
                            DeprecatedProperty    = $hlpDeprecatedPolicySet.deprecated 
                        }
                    }
                }
            }
        }
    }

    if (($policySetsDeprecated | measure-object).count -gt 0) {
        $tfCount = ($policySetsDeprecated | measure-object).count
        $tableId = "SummaryTable_policySetsDeprecated"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_policySetsDeprecated"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($policySetsDeprecated | measure-object).count) Custom PolicySets / deprecated Built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] &#13;OR &#13;Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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

    #region SUMMARYPolicyAssignmentsDeprecatedPolicy
    Write-Host "  processing TenantSummary PolicyAssignments using deprecated Policy"
    $policyAssignmentsDeprecated = [System.Collections.ArrayList]@()
    $policyAssignmentsDeprecated = foreach ($policyAssignmentAll in $($htCacheAssignments).policy.keys) {
    
        $hlpAssignmentDeprecatedPolicy = ($htCacheAssignments).policy.($policyAssignmentAll).Properties
        #policySet
        if ($($htCacheDefinitions).policySet.(($hlpAssignmentDeprecatedPolicy.PolicyDefinitionId))) {
            foreach ($polsetPolDefId in $($htCacheDefinitions).policySet.(($hlpAssignmentDeprecatedPolicy.PolicyDefinitionId)).PolicySetPolicyIds) {
                $hlpDeprecatedAssignment = (($htCacheDefinitions).policy.(($polsetPolDefId)))
                if ($hlpDeprecatedAssignment.type -eq "BuiltIn") {
                    if ($hlpDeprecatedAssignment.deprecated -eq $true -or ($hlpDeprecatedAssignment.displayname).StartsWith("[Deprecated]", "CurrentCultureIgnoreCase")) {
                        [PSCustomObject]@{
                            PolicyAssignmentDisplayName = $hlpAssignmentDeprecatedPolicy.DisplayName
                            PolicyAssignmentId          = $policyAssignmentAll
                            PolicyDisplayName           = $hlpDeprecatedAssignment.displayname
                            PolicyId                    = $hlpDeprecatedAssignment.Id
                            PolicySetDisplayName        = ($htCacheDefinitions).policySet.(($hlpAssignmentDeprecatedPolicy.PolicyDefinitionId)).displayname
                            PolicySetId                 = ($htCacheDefinitions).policySet.(($hlpAssignmentDeprecatedPolicy.PolicyDefinitionId)).policydefinitionId
                            PolicyType                  = "PolicySet"
                            DeprecatedProperty          = $hlpDeprecatedAssignment.deprecated 
                        }
                    }
                }
            }
        }
        #Policy
        $hlpDeprecatedAssignmentPol = ($htCacheDefinitions).policy.(($hlpAssignmentDeprecatedPolicy.PolicyDefinitionId))
        if ($hlpDeprecatedAssignmentPol) {
            if ($hlpDeprecatedAssignmentPol.type -eq "BuiltIn") {
                if ($hlpDeprecatedAssignmentPol.deprecated -eq $true -or ($hlpDeprecatedAssignmentPol.displayname).StartsWith("[Deprecated]", "CurrentCultureIgnoreCase")) {
                    [PSCustomObject]@{
                        PolicyAssignmentDisplayName = $hlpAssignmentDeprecatedPolicy.DisplayName
                        PolicyAssignmentId          = $policyAssignmentAll
                        PolicyDisplayName           = $hlpDeprecatedAssignmentPol.displayname
                        PolicyId                    = $hlpDeprecatedAssignmentPol.Id
                        PolicyType                  = "Policy"
                        DeprecatedProperty          = $hlpDeprecatedAssignmentPol.deprecated
                        PolicySetDisplayName        = "n/a"
                        PolicySetId                 = "n/a"
                    }
                }
            }
        }
    }

    if (($policyAssignmentsDeprecated | measure-object).count -gt 0) {
        $tfCount = ($policyAssignmentsDeprecated | measure-object).count
        $tableId = "SummaryTable_policyAssignmnetsDeprecated"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_policyAssignmnetsDeprecated"><i class="fa fa-exclamation-triangle orange" aria-hidden="true"></i> <span class="valignMiddle">$(($policyAssignmentsDeprecated | measure-object).count) Policy Assignments / deprecated Built-in Policy <abbr title="PolicyDisplayName startswith [Deprecated] &#13;OR &#13;Metadata property Deprecated=true"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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

    #region SUMMARYPolicyAssignmentsAll
    $startSummaryPolicyAssignmentsAll = get-date
    $allPolicyAssignments = ($policyBaseQuery | Measure-Object).count
    Write-Host "  processing TenantSummary PolicyAssignments (all $allPolicyAssignments)"

    $script:policyAssignmentsAllArray = [System.Collections.ArrayList]@() 
    $cnter = 0

    $roleAssignmentsArray = [System.Collections.ArrayList]@() 
    $roleAssignmentsArray = foreach ($roleassignment in ($htCacheAssignments).role.keys | Sort-Object) {
        ($htCacheAssignments).role.($roleassignment)
    }

    $starttest = get-date

    $htPolicyAssignmentRelatedRoleAssignments = @{ }
    $htPolicyAssignmentEffect = @{ }

    foreach ($policyAssignmentIdUnique in $policyBaseQueryUniqueAssignments) {
        $assignment = ($htCacheAssignments).policy.($policyAssignmentIdUnique.PolicyAssignmentId)
        if ($assignment.properties.policyDefinitionId -like "*/Microsoft.Authorization/policyDefinitions/*") {
            $test0 = $assignment.properties.parameters.effect.value
            if ($test0) {
                $effect = $test0
            }
            else {
                $definition = ($htCacheDefinitions).policy.($assignment.properties.PolicyDefinitionId)
                $test1 = $definition.effectDefaultValue
                if ($test1 -ne "n/a") {
                    $effect = $test1
                }
                $test2 = $definition.effectFixedValue
                if ($test2 -ne "n/a") {
                    $effect = $test2
                }
            }
            #$effect
            $htPolicyAssignmentEffect.($policyAssignmentIdUnique.PolicyAssignmentId) = @{ }
            $htPolicyAssignmentEffect.($policyAssignmentIdUnique.PolicyAssignmentId).effect = $effect
        }

        $relatedRoleAssignmentsArray = [System.Collections.ArrayList]@() 
        $relatedRoleAssignmentsArray = foreach ($relatedRoleAssignment in $roleAssignmentsArray) {
            if ($relatedRoleAssignment.DisplayName -eq ($policyAssignmentIdUnique.PolicyAssignmentId -replace '.*/')) {
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

        if ($policyAssignmentIdUnique.PolicyType -eq "builtin") {
            if ($policyAssignmentIdUnique.PolicyVariant -eq "Policy") {
                $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId).policyWithWithoutLinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyadvertizer/$($policyAssignmentIdUnique.policyDefinitionIdGuid).html`" target=`"_blank`">$($policyAssignmentIdUnique.policy)</a>"
            }
            else {
                $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId).policyWithWithoutLinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azpolicyinitiativesadvertizer/$($policyAssignmentIdUnique.policyDefinitionIdGuid).html`" target=`"_blank`">$($policyAssignmentIdUnique.policy)</a>"
            }
        }
        else {
            $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentIdUnique.PolicyAssignmentId).policyWithWithoutLinkToAzAdvertizer = $policyAssignmentIdUnique.policy
        }
    }
    $endtest = get-date
    Write-Host "   processing duration: $((NEW-TIMESPAN -Start $starttest -End $endtest).TotalSeconds) seconds"

    $starttest2 = get-date
    $script:policyAssignmentsAllArray = foreach ($policyAssignmentAll in $policyBaseQuery) {  
        $cnter++
        if ($cnter % 500 -eq 0) {
            $etappeSummaryPolicyAssignmentsAll = get-date
            Write-Host "   $cnter of $allPolicyAssignments PolicyAssignments processed: $((NEW-TIMESPAN -Start $startSummaryPolicyAssignmentsAll -End $etappeSummaryPolicyAssignmentsAll).TotalSeconds) seconds"
        }
   
        $assignment = ($htCacheAssignments).policy.($policyAssignmentAll.PolicyAssignmentId)

        $excludedScope = "false"
        if (($assignment.properties.NotScopes | Measure-Object).count -gt 0) {
            foreach ($policyAssignmentNotScope in $assignment.properties.NotScopes) {
                if ("" -ne $policyAssignmentAll.subscriptionId) {
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

        if ($policyAssignmentAll.PolicyAssignmentId -like "/providers/Microsoft.Management/managementGroups/*") {
            if ("" -ne $policyAssignmentAll.SubscriptionId) {
                $scope = "inherited $($policyAssignmentAll.PolicyAssignmentScope -replace '.*/')"
            }
            else {
                if (($policyAssignmentAll.PolicyAssignmentScope -replace '.*/') -eq $policyAssignmentAll.MgId) {
                    $scope = "this Mg"
                }
                else {
                    $scope = "inherited $($policyAssignmentAll.PolicyAssignmentScope -replace '.*/')"
                }
            }
        }

        if ($policyAssignmentAll.PolicyAssignmentId -like "/subscriptions/*") {
            $scope = "this Sub"
        }

        if ($policyAssignmentAll.PolicyVariant -eq "Policy") {
            $effect = $htPolicyAssignmentEffect.($policyAssignmentAll.PolicyAssignmentId).effect
        }
        else {
            $effect = "n/a"
        }

        if ("" -eq $policyAssignmentAll.SubscriptionId) {
            $mgOrSub = "Mg"
        }
        else {
            $mgOrSub = "Sub"
        }

        if (-not $NoPolicyComplianceStates) {
            #compliance
            if ("" -eq $policyAssignmentAll.subscriptionId) {
                $compliance = ($htCachePolicyCompliance).mg.($policyAssignmentAll.MgId).($policyAssignmentAll.policyAssignmentId)
                $NonCompliantPolicies = $compliance.NonCompliantPolicies
                $CompliantPolicies = $compliance.CompliantPolicies
                $NonCompliantResources = $compliance.NonCompliantResources
                $CompliantResources = $compliance.CompliantResources
            }
            else {
                $compliance = ($htCachePolicyCompliance).sub.($policyAssignmentAll.SubscriptionId).($policyAssignmentAll.policyAssignmentId)
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

            [PSCustomObject]@{ 
                Level                       = $policyAssignmentAll.Level
                MgId                        = $policyAssignmentAll.MgId
                MgName                      = $policyAssignmentAll.MgName
                subscriptionId              = $policyAssignmentAll.SubscriptionId
                subscriptionName            = $policyAssignmentAll.Subscription
                PolicyAssignmentId          = $policyAssignmentAll.PolicyAssignmentId
                PolicyAssignmentDisplayName = $policyAssignmentAll.PolicyAssignmentDisplayName
                PolicyAssignmentDescription = $policyAssignmentAll.PolicyAssignmentDescription
                Effect                      = $effect
                PolicyName                  = $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentAll.PolicyAssignmentId).policyWithWithoutLinkToAzAdvertizer
                PolicyDescription           = $policyAssignmentAll.PolicyDescription
                PolicyId                    = $policyAssignmentAll.PolicyDefinitionIdFull
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
            }
        }
        else {
            [PSCustomObject]@{ 
                Level                       = $policyAssignmentAll.Level
                MgId                        = $policyAssignmentAll.MgId
                MgName                      = $policyAssignmentAll.MgName
                subscriptionId              = $policyAssignmentAll.SubscriptionId
                subscriptionName            = $policyAssignmentAll.Subscription
                PolicyAssignmentId          = $policyAssignmentAll.PolicyAssignmentId
                PolicyAssignmentDisplayName = $policyAssignmentAll.PolicyAssignmentDisplayName
                PolicyAssignmentDescription = $policyAssignmentAll.PolicyAssignmentDescription
                Effect                      = $effect
                PolicyName                  = $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentAll.PolicyAssignmentId).policyWithWithoutLinkToAzAdvertizer
                PolicyDescription           = $policyAssignmentAll.PolicyDescription
                PolicyId                    = $policyAssignmentAll.PolicyDefinitionIdFull
                PolicyVariant               = $policyAssignmentAll.PolicyVariant
                PolicyType                  = $policyAssignmentAll.PolicyType
                PolicyCategory              = $policyAssignmentAll.PolicyCategory
                Inheritance                 = $scope
                ExcludedScope               = $excludedScope
                RelatedRoleAssignments      = $htPolicyAssignmentRelatedRoleAssignments.($policyAssignmentAll.PolicyAssignmentId).relatedRoleAssignments
                MgOrSub                     = $mgOrSub
            }
        }
    }
    $endtest2 = get-date
    Write-Host "   processing duration: $((NEW-TIMESPAN -Start $starttest2 -End $endtest2).TotalSeconds) seconds"

    if (($script:policyAssignmentsAllArray | measure-object).count -gt 0) {
        $tfCount = ($script:policyAssignmentsAllArray | measure-object).count
        $policyAssignmentsUniqueCount = ($script:policyAssignmentsAllArray | Sort-Object -Property PolicyAssignmentId -Unique | measure-object).count
        $tableId = "SummaryTable_policyAssignmentsAll"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_policyAssignmentsAll"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($script:policyAssignmentsAllArray | measure-object).count) Policy Assignments ($policyAssignmentsUniqueCount unique)</span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a><br>
&nbsp;&nbsp;<span style="color:#FF5733">*Depending on the number of entries and your computer´s performance the table may respond with delay, download the csv for better filtering experience</span>
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
<th>Policy/Set Description</th>
<th>Policy/SetId</th>
<th>Policy/Set</th>
<th>Type</th>
<th>Category</th>
<th>Effect</th>
"@

        if (-not $NoPolicyComplianceStates) {
            $htmlTenantSummary += @"
<th>Policies NonCmplnt</th>
<th>Policies Compliant</th>
<th>Resources NonCmplnt</th>
<th>Resources Compliant</th>
"@
        }

        $htmlTenantSummary += @"
<th>Role/Assignment</th>
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
        $htmlSummaryPolicyAssignmentsAll = foreach ($policyAssignment in $script:policyAssignmentsAllArray | sort-object -Property Level, MgName, MgId, SubscriptionName, SubscriptionId) {
            @"
<tr>
<td>$($policyAssignment.MgOrSub)</td>
<td>$($policyAssignment.MgId)</td>
<td>$($policyAssignment.MgName)</td>
<td>$($policyAssignment.SubscriptionId)</td>
<td>$($policyAssignment.SubscriptionName)</td>
<td>$($policyAssignment.Inheritance)</td>
<td>$($policyAssignment.ExcludedScope)</td>
<td>$($policyAssignment.PolicyName)</td>
<td>$($policyAssignment.PolicyDescription)</td>
<td class="breakwordall">$($policyAssignment.PolicyId)</td>
<td>$($policyAssignment.PolicyVariant)</td>
<td>$($policyAssignment.PolicyType)</td>
<td>$($policyAssignment.PolicyCategory)</td>
<td>$($policyAssignment.Effect)</td>
"@

            if (-not $NoPolicyComplianceStates) {
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
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
            col_6: 'select',
            col_10: 'select',
            col_11: 'select',
            col_13: 'select',
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
"@

        if (-not $NoPolicyComplianceStates) {
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

        if (-not $NoPolicyComplianceStates) {
            $htmlTenantSummary += @"
            watermark: ['', '', '', 'try [nonempty]', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
"@
        }
        else {
            $htmlTenantSummary += @"
            watermark: ['', '', '', 'try [nonempty]', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''],
"@ 
        }

        $htmlTenantSummary += @"
extensions: [
    {
        name: 'colsVisibility',
"@

        if (-not $NoPolicyComplianceStates) {
            $htmlTenantSummary += @"
        at_start: [8, 20],
"@
        }
        else {
            $htmlTenantSummary += @"
            at_start: [8, 16],
"@        
        }

        $htmlTenantSummary += @"
        text: 'Columns: ',
        enable_tick_all: true
    },    
    { name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($script:policyAssignmentsAllArray | measure-object).count) Policy Assignments</span></p>
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
    $tenantCustomRolesCount = ($tenantCustomRoles | measure-object).count
    if ($tenantCustomRolesCount -gt $LimitRBACCustomRoleDefinitionsTenant * ($LimitCriticalPercentage / 100)) {
        $faimage = "<i class=`"fa fa-exclamation-triangle`" aria-hidden=`"true`"></i>"
    }
    else {
        $faimage = "<i class=`"fa fa-check-circle blue`" aria-hidden=`"true`"></i>"
    }
    $tenantCustomRolesArray = [System.Collections.ArrayList]@()
    $tenantCustomRolesArray = foreach ($tenantCustomRole in $tenantCustomRoles) {
        ($htCacheDefinitions).role.($tenantCustomRole)
    }

    if ($tenantCustomRolesCount -gt 0) {
        $tfCount = $tenantCustomRolesCount
        $tableId = "SummaryTable_customRoles"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customRoles">$faimage <span class="valignMiddle">$tenantCustomRolesCount Custom Roles ($scopeNamingSummary) (Limit: $tenantCustomRolesCount/$LimitRBACCustomRoleDefinitionsTenant)</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        $htmlSUMMARYtenanttotalcustomroles = foreach ($tenantCustomRole in $tenantCustomRolesArray | sort-object @{Expression = { $_.Name } }, @{Expression = { $_.Id } }) {
            $cachedTenantCustomRole = ($htCacheDefinitions).role.($tenantCustomRole.Id)
            @"
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
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    Write-Host "  processing TenantSummary Custom Roles orphaned"
    if ($getMgParentName -eq "Tenant Root") {
        
        $arrayCustomRolesOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()
        
        if (($tenantCustomRoles | Measure-Object).count -gt 0) {
            $customRolesInUse = ($rbacBaseQuery | Where-Object { $_.RoleIsCustom -eq "TRUE" }).RoleDefinitionId | Sort-Object -Unique
        
            $customRolesOrphaned = [System.Collections.ArrayList]@()
                
            if ($customRolesInUse -gt 0) {
                $customRolesOrphaned = foreach ($customRoleAll in $tenantCustomRoles) {
                    if (-not $customRolesInUse.contains("$customRoleAll")) {    
                        $hlpCustomRole = ($htCacheDefinitions).role.$customRoleAll
                        if ($hlpCustomRole.IsCustom -eq $True) {
                            $hlpCustomRole
                        }
                    }
                }
            }
            else {
                $customRolesOrphaned = foreach ($customRoleAll in $tenantCustomRoles) { 
                    $hlpCustomRole = ($htCacheDefinitions).role.$customRoleAll
                    if ($hlpCustomRole.IsCustom -eq $True) {
                        $hlpCustomRole
                    }
                }
            }

            $arrayCustomRolesOrphanedFinalIncludingResourceGroups = foreach ($customRoleOrphaned in $customRolesOrphaned) {
                if ($script:arrayCacheRoleAssignmentsResourceGroups.RoleDefinitionId -notcontains $customRoleOrphaned.Id ) {
                    $customRoleOrphaned
                }
            }
        }

        if (($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0) {
            $tfCount = ($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count
            $tableId = "SummaryTable_customRolesOrphaned"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customRolesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom Roles ($scopeNamingSummary) <abbr title="Role has no Assignments (including ResourceGroups and Resources)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
            $htmlSUMMARYOrphanedCustomRoles = foreach ($customRoleOrphaned in $arrayCustomRolesOrphanedFinalIncludingResourceGroups | Sort-Object @{Expression = { $_.Name } }) {
                @"
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
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
        $subs = (($optimizedTableForPathQueryMgAndSub | Where-Object { $_.Level -ne "0" }))
        $customRolesInScopeArray = @()
        if (($tenantCustomRoles | measure-object).count -gt 0) {
            foreach ($customRole in $tenantCustomRoles) {       
                $customRoleAssignableScopes = ($htCacheDefinitions).role.$customRole.AssignableScopes
                $customRoleInScope = $false
                $customRoleIsOut = $false
                foreach ($customRoleAssignableScope in $customRoleAssignableScopes) {
                    if (($customRoleAssignableScope) -like "/providers/Microsoft.Management/managementGroups/*") {
                        $roleAssignableScopeMgSub = $customRoleAssignableScope -replace "/providers/Microsoft.Management/managementGroups/", ""
                        foreach ($customRoleAssignableScope in $customRoleAssignableScopes) {
                            if (($customRoleAssignableScope) -like "/providers/Microsoft.Management/managementGroups/*") {
                                $roleAssignableScopeMgSub = $customRoleAssignableScope -replace "/providers/Microsoft.Management/managementGroups/", ""
                                if (-not $mgs.MgId.contains("$roleAssignableScopeMgSub")) {
                                    $customRoleIsOut = $true
                                }
                            }
                        }
                        if (-not $customRoleIsOut -eq $true) {
                            if ($mgs.MgId.contains("$roleAssignableScopeMgSub")) {
                                $customRoleInScope = $true
                            }
                        }
                    }
                    if (-not $customRoleIsOut -eq $true) {
                        if (($subs | measure-object).count -gt 0) {
                            if (($customRoleAssignableScope) -like "/subscriptions/*") {
                                $roleAssignableScopeMgSub = $customRoleAssignableScope -replace "/subscriptions/", "" -replace "/.*", ""
                                if ($subs.SubscriptionId.contains("$roleAssignableScopeMgSub")) {
                                    $customRoleInScope = $true
                                }
                            }
                        }
                    }
                }
                if ($customRoleInScope -eq $true) {
                    $customRolesInScopeArray += ($htCacheDefinitions).role.($customRole)
                }
            }
        }

        $arrayCustomRolesOrphanedFinalIncludingResourceGroups = [System.Collections.ArrayList]@()
        $arrayCustomRolesOrphanedFinalIncludingResourceGroups = foreach ($customRoleOrphaned in $customRolesInScopeArray) {
            if ($script:arrayCacheRoleAssignmentsResourceGroups.RoleDefinitionId -notcontains $customRoleOrphaned.Id ) {
                $customRoleOrphaned
            }
        }

        if (($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count -gt 0) {
            $tfCount = ($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count
            $tableId = "SummaryTable_customRolesOrphaned"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customRolesOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($arrayCustomRolesOrphanedFinalIncludingResourceGroups | measure-object).count) Orphaned Custom Roles ($scopeNamingSummary) <abbr title="Role has no Assignments (including ResourceGroups and Resources) &#13;Roles where assignableScopes contins MG Id from superior scopes are not evaluated"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
            $htmlSUMMARYOrphanedCustomRoles = foreach ($inScopeCustomRole in $arrayCustomRolesOrphanedFinalIncludingResourceGroups | Sort-Object @{Expression = { $_.Name } }) {
                @"
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
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    #endregion SUMMARYOrphanedCustomRoles

    #region SUMMARYOrphanedRoleAssignments
    Write-Host "  processing TenantSummary RoleAssignments orphaned"
    $roleAssignmentsOrphanedAll = $rbacBaseQuery | Where-Object { $_.RoleAssignmentObjectType -eq "Unknown" } | Sort-Object -Property RoleAssignmentId
    $roleAssignmentsOrphanedUnique = $roleAssignmentsOrphanedAll | Sort-Object -Property RoleAssignmentId -Unique

    if (($roleAssignmentsOrphanedUnique | measure-object).count -gt 0) {
        $tfCount = ($roleAssignmentsOrphanedUnique | measure-object).count
        $tableId = "SummaryTable_roleAssignmnetsOrphaned"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_roleAssignmnetsOrphaned"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOrphanedUnique | measure-object).count) Orphaned Role Assignments ($scopeNamingSummary) <abbr title="Role was deleted although and assignment existed &#13;OR &#13;Target identity (User, Group, ServicePrincipal) was deleted"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    $roleAssignmentsallCount = ($rbacBaseQuery | Measure-Object).count
    $roleAssignmentIdsUnique = $rbacBaseQuery | sort-object -Property RoleAssignmentId -Unique

    $htRoleAssignmentRelatedPolicyAssignments = @{ }
    foreach ($roleAssignmentIdUnique in $roleAssignmentIdsUnique) {
        $relatedPolicyAssignment = $policyBaseQueryUniqueAssignments | Where-Object { $_.PolicyAssignmentName -eq $roleAssignmentIdUnique.RoleAssignmentDisplayname }

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

        if ($roleAssignmentIdUnique.RoleIsCustom -eq "FALSE") {
            $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).roleType = "Builtin"
            $htRoleAssignmentRelatedPolicyAssignments.($roleAssignmentIdUnique.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer = "<a class=`"externallink`" href=`"https://www.azadvertizer.net/azrolesadvertizer/$($roleAssignmentIdUnique.RoleDefinitionId).html`" target=`"_blank`">$($roleAssignmentIdUnique.RoleDefinitionName)</a>"
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

    Write-Host "  processing TenantSummary RoleAssignments (all $roleAssignmentsallCount)"
    $cnter = 0
    $script:rbacAll = [System.Collections.ArrayList]@()
    $startRoleAssignmentsAll = get-date
    $script:rbacAll = foreach ($rbac in $rbacBaseQuery) {
        $cnter++
        if ($cnter % 500 -eq 0) {
            $etappeRoleAssignmentsAll = get-date
            Write-Host "   $cnter of $roleAssignmentsallCount RoleAssignments processed; $((NEW-TIMESPAN -Start $startRoleAssignmentsAll -End $etappeRoleAssignmentsAll).TotalSeconds) seconds"
        }
        $scope = $null

        if ($rbac.RoleAssignmentId -like "/providers/Microsoft.Management/managementGroups/*") {
            if ("" -ne $rbac.SubscriptionId) {
                $scope = "inherited $($rbac.RoleAssignmentScope -replace '.*/')"
            }
            else {
                if (($rbac.RoleAssignmentScope -replace '.*/') -eq $rbac.MgId) {
                    $scope = "at this MG"
                }
                else {
                    $scope = "inherited $($rbac.RoleAssignmentScope -replace '.*/')"
                }
            }
        }

        if ($rbac.RoleAssignmentId -like "/subscriptions/*") {
            $scope = "at this Sub"
        }

        if ($rbac.RoleAssignmentId -like "/providers/Microsoft.Authorization/roleAssignments/*") {
            $scope = "inherited ROOT"
        }

        if ("" -eq $rbac.SubscriptionId) {
            $mgOrSub = "Mg"
        }
        else {
            $mgOrSub = "Sub"
        }

        if (-not $NoAADGroupsResolveMembers) {
            if ($rbac.RoleAssignmentObjectType -eq "Group") {
                if ($htAADGroupsDetails.($rbac.RoleAssignmentObjectId).MembersAllCount -gt 0) {
                    foreach ($groupmember in $htAADGroupsDetails.($rbac.RoleAssignmentObjectId).MembersAll) {
                        if ($groupmember.'@odata.type' -eq "#microsoft.graph.user") {
                            if ($DoNotShowRoleAssignmentsUserData) {
                                $grpMemberDisplayName = "scrubbed"
                                $grpMemberSignInName = "scrubbed"
                            }
                            else {
                                $grpMemberDisplayName = $groupmember.displayName
                                $grpMemberSignInName = $groupmember.userPrincipalName
                            }
                            $grpMemberId = $groupmember.id
                            $grpMemberType = "User"
                        }
                        if ($groupmember.'@odata.type' -eq "#microsoft.graph.group") {
                            $grpMemberDisplayName = $groupmember.displayName
                            $grpMemberSignInName = "n/a"
                            $grpMemberId = $groupmember.id
                            $grpMemberType = "Group"
                        }
                        if ($groupmember.'@odata.type' -eq "#microsoft.graph.servicePrincipal") {
                            $grpMemberDisplayName = $groupmember.appDisplayName
                            $grpMemberSignInName = "n/a"
                            $grpMemberId = $groupmember.id
                            $grpMemberType = "ServicePrincipal"
                            
                        }

                        if (-not $NoServicePrincipalResolve) {
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

                        [PSCustomObject]@{ 
                            Level                         = $rbac.Level
                            RoleAssignmentId              = $rbac.RoleAssignmentId
                            MgId                          = $rbac.MgId
                            MgName                        = $rbac.MgName
                            SubscriptionId                = $rbac.SubscriptionId
                            SubscriptionName              = $rbac.Subscription
                            Scope                         = $scope
                            Role                          = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer 
                            RoleType                      = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleType
                            ObjectDisplayName             = $rbac.RoleAssignmentDisplayname
                            ObjectSignInName              = $rbac.RoleAssignmentSignInName
                            ObjectId                      = $rbac.RoleAssignmentObjectId
                            ObjectType                    = $rbac.RoleAssignmentObjectType
                            GrpMemberDisplayName          = $grpMemberDisplayName
                            GrpMemberSignInName           = $grpMemberSignInName
                            GrpMemberId                   = $grpMemberId
                            GrpMemberType                 = $identityType
                            MgOrSub                       = $mgOrSub
                            RbacRelatedPolicyAssignment   = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).relatedPolicyAssignment
                            RoleSecurityCustomRoleOwner   = $rbac.RoleSecurityCustomRoleOwner
                            RoleSecurityOwnerAssignmentSP = $rbac.RoleSecurityOwnerAssignmentSP 
                        }
                    }
                }
                else {

                    if (-not $NoServicePrincipalResolve) {
                        if ($rbac.RoleAssignmentObjectType -eq "ServicePrincipal") {
                            $identityType = "$($rbac.RoleAssignmentObjectType) ($($htServicePrincipalsDetails.($rbac.RoleAssignmentObjectId).servicePrincipalType))"
                        }
                        else {
                            $identityType = $rbac.RoleAssignmentObjectType
                        }
                    }
                    else {
                        $identityType = $rbac.RoleAssignmentObjectType
                    }

                    [PSCustomObject]@{ 
                        Level                         = $rbac.Level
                        RoleAssignmentId              = $rbac.RoleAssignmentId
                        MgId                          = $rbac.MgId
                        MgName                        = $rbac.MgName
                        SubscriptionId                = $rbac.SubscriptionId
                        SubscriptionName              = $rbac.Subscription
                        Scope                         = $scope
                        Role                          = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer 
                        RoleType                      = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleType
                        ObjectDisplayName             = $rbac.RoleAssignmentDisplayname
                        ObjectSignInName              = $rbac.RoleAssignmentSignInName
                        ObjectId                      = $rbac.RoleAssignmentObjectId
                        ObjectType                    = $identityType
                        GrpMemberDisplayName          = ""
                        GrpMemberSignInName           = ""
                        GrpMemberId                   = ""
                        GrpMemberType                 = ""
                        MgOrSub                       = $mgOrSub
                        RbacRelatedPolicyAssignment   = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).relatedPolicyAssignment
                        RoleSecurityCustomRoleOwner   = $rbac.RoleSecurityCustomRoleOwner
                        RoleSecurityOwnerAssignmentSP = $rbac.RoleSecurityOwnerAssignmentSP 
                    }
                }
            }
            else {

                if (-not $NoServicePrincipalResolve) {
                    if ($rbac.RoleAssignmentObjectType -eq "ServicePrincipal") {
                        $identityType = "$($rbac.RoleAssignmentObjectType) ($($htServicePrincipalsDetails.($rbac.RoleAssignmentObjectId).servicePrincipalType))"
                    }
                    else {
                        $identityType = $rbac.RoleAssignmentObjectType
                    }
                }
                else {
                    $identityType = $rbac.RoleAssignmentObjectType
                }
                
                [PSCustomObject]@{ 
                    Level                         = $rbac.Level
                    RoleAssignmentId              = $rbac.RoleAssignmentId
                    MgId                          = $rbac.MgId
                    MgName                        = $rbac.MgName
                    SubscriptionId                = $rbac.SubscriptionId
                    SubscriptionName              = $rbac.Subscription
                    Scope                         = $scope
                    Role                          = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer 
                    RoleType                      = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleType
                    ObjectDisplayName             = $rbac.RoleAssignmentDisplayname
                    ObjectSignInName              = $rbac.RoleAssignmentSignInName
                    ObjectId                      = $rbac.RoleAssignmentObjectId
                    ObjectType                    = $identityType
                    GrpMemberDisplayName          = ""
                    GrpMemberSignInName           = ""
                    GrpMemberId                   = ""
                    GrpMemberType                 = ""
                    MgOrSub                       = $mgOrSub
                    RbacRelatedPolicyAssignment   = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).relatedPolicyAssignment
                    RoleSecurityCustomRoleOwner   = $rbac.RoleSecurityCustomRoleOwner
                    RoleSecurityOwnerAssignmentSP = $rbac.RoleSecurityOwnerAssignmentSP 
                }
            }
        }
        else {
            if (-not $NoServicePrincipalResolve) {
                if ($rbac.RoleAssignmentObjectType -eq "ServicePrincipal") {
                    $identityType = "$($rbac.RoleAssignmentObjectType) ($($htServicePrincipalsDetails.($rbac.RoleAssignmentObjectId).servicePrincipalType))"
                }
                else {
                    $identityType = $rbac.RoleAssignmentObjectType
                }
            }
            else {
                $identityType = $rbac.RoleAssignmentObjectType
            }

            #noaadgroupmemberresolve
            [PSCustomObject]@{ 
                Level                         = $rbac.Level
                RoleAssignmentId              = $rbac.RoleAssignmentId
                MgId                          = $rbac.MgId
                MgName                        = $rbac.MgName
                SubscriptionId                = $rbac.SubscriptionId
                SubscriptionName              = $rbac.Subscription
                Scope                         = $scope
                Role                          = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleWithWithoutLinkToAzAdvertizer 
                RoleType                      = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).roleType
                ObjectDisplayName             = $rbac.RoleAssignmentDisplayname
                ObjectSignInName              = $rbac.RoleAssignmentSignInName
                ObjectId                      = $rbac.RoleAssignmentObjectId
                ObjectType                    = $identityType
                MgOrSub                       = $mgOrSub
                RbacRelatedPolicyAssignment   = $htRoleAssignmentRelatedPolicyAssignments.($rbac.RoleAssignmentId).relatedPolicyAssignment
                RoleSecurityCustomRoleOwner   = $rbac.RoleSecurityCustomRoleOwner
                RoleSecurityOwnerAssignmentSP = $rbac.RoleSecurityOwnerAssignmentSP 
            }
        }
    }

    if (($script:rbacAll | measure-object).count -gt 0) {
        $uniqueRoleAssignmentsCount = ($script:rbacAll | sort-object -Property RoleAssignmentId -Unique | Measure-Object).count
        $tfCount = ($script:rbacAll | measure-object).count
        $tableId = "SummaryTable_roleAssignmentsAll"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_roleAssignmentsAll"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$(($script:rbacAll | measure-object).count) Role Assignments ($uniqueRoleAssignmentsCount unique)</span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a><br>
&nbsp;&nbsp;<span style="color:#FF5733">*Depending on the number of entries and your computer´s performance the table may respond with delay, download the csv for better filtering experience</span> 
<table id= "$tableId" class="summaryTable">
<thead>
<tr>
<th>Mg/Sub</th>
<th>Management Group Id</th>
<th>Management Group Name</th>
<th>SubscriptionId</th>
<th>Subscription Name</th>
<th>Assignment Scope</th>
<th>Role</th>
<th>Role Type</th>
<th>Identity Displayname</th>
<th>Identity SignInName</th>
<th>Identity ObjectId</th>
<th>Identity Type</th>
"@

        if (-not $NoAADGroupsResolveMembers) {
            $htmlTenantSummary += @"
<th>GroupMember DisplayName</th>
<th>GroupMember SignInName</th>
<th>GroupMember ObjectId</th>
<th>GroupMember Type</th>
"@
        }

        $htmlTenantSummary += @"
<th>Role AssignmentId</th>
<th>Related PolicyAssignment</th>
</tr>
</thead>
<tbody>
"@
        $cnter = 0
        $roleAssignmentsAllCount = ($script:rbacAll | Measure-Object).count
        $startWriteRoleAssignmentsAll = get-date
        $htmlSummaryRoleAssignmentsAll = ""
        $htmlTenantSummary | Add-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).html" -Encoding utf8 -Force
        $htmlTenantSummary = ""
        $htmlSummaryRoleAssignmentsAll = foreach ($roleAssignment in $script:rbacAll | sort-object -Property Level, MgName, MgId, SubscriptionName, SubscriptionId, Scope, ObjectDisplayName) {
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
<td>$($roleAssignment.RoleType)</td>
<td class="breakwordall">$($roleAssignment.ObjectDisplayName)</td>
<td class="breakwordall">$($roleAssignment.ObjectSignInName)</td>
<td class="breakwordall">$($roleAssignment.ObjectId)</td>
<td>$($roleAssignment.ObjectType)</td>
"@

            if (-not $NoAADGroupsResolveMembers) {
                @"
<td class="breakwordall">$($roleAssignment.GrpMemberDisplayName)</td>
<td class="breakwordall">$($roleAssignment.GrpMemberSignInName)</td>
<td class="breakwordall">$($roleAssignment.GrpMemberId)</td>
<td>$($roleAssignment.GrpMemberType)</td>
"@
            }

            @"
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
    <script>
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
            col_7: 'select',
            col_11: 'multiple',
"@
        if (-not $NoAADGroupsResolveMembers) {
            $htmlTenantSummary += @"
            col_15: 'multiple',
"@
        }
        $htmlTenantSummary += @"
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
"@
        if (-not $NoAADGroupsResolveMembers) {
            $htmlTenantSummary += @"
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
                'caseinsensitivestring',
"@
        }
        $htmlTenantSummary += @"
                'caseinsensitivestring',
                'caseinsensitivestring'
            ],
"@
        if (-not $NoAADGroupsResolveMembers) {
            $htmlTenantSummary += @"
                watermark: ['', '', '', 'try [nonempty]', '', '', 'try owner||reader', '', '', '', '', '', '', '', '', '', '', ''],
"@
        }
        else {
            $htmlTenantSummary += @"
                watermark: ['', '', '', 'try [nonempty]', '', '', 'try owner||reader', '', '', '', '', '', '', ''],
"@    
        }
        $htmlTenantSummary += @"
            extensions: [{ name: 'sort' }]
        };
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($script:rbacAll | measure-object).count) Role Assignments</span></p>
"@
    }
    $endRoleAssignmentsAll = get-date
    Write-Host "   SummaryRoleAssignmentsAll duration: $((NEW-TIMESPAN -Start $startRoleAssignmentsAll -End $endRoleAssignmentsAll).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startRoleAssignmentsAll -End $endRoleAssignmentsAll).TotalSeconds) seconds)"
    #endregion SUMMARYRoleAssignmentsAll

    #region SUMMARYSecurityCustomRoles
    Write-Host "  processing TenantSummary Custom Roles security (owner permissions)"
    $customRolesOwnerAll = $rbacBaseQuery | Where-Object { $_.RoleSecurityCustomRoleOwner -eq 1 } | Sort-Object -Property RoleDefinitionId
    $customRolesOwnerHtAll = $tenantCustomRoles | Where-Object { ($htCacheDefinitions).role.$_.Actions -eq '*' -and (($htCacheDefinitions).role.$_.NotActions).length -eq 0 }
    if (($customRolesOwnerHtAll | measure-object).count -gt 0) {
        $tfCount = ($customRolesOwnerHtAll | measure-object).count
        $tableId = "SummaryTable_customroleCustomRoleOwner"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_customroleCustomRoleOwner"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($customRolesOwnerHtAll | measure-object).count) Custom Roles Owner permissions ($scopeNamingSummary) <abbr title="Custom 'Owner' Role definitions should not exist"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
            if ($customRoleOwnersAllAssignmentsCount -gt 0) {
                $customRoleRoleAssignmentsArray = [System.Collections.ArrayList]@()
                $customRoleRoleAssignmentIds = ($customRolesOwnerAll | Where-Object { $_.RoleDefinitionId -eq $customRole }).RoleAssignmentId | Sort-Object -Unique
                $customRoleRoleAssignmentsArray = foreach ($customRoleRoleAssignmentId in $customRoleRoleAssignmentIds) {
                    $customRoleRoleAssignmentId
                }
                $customRoleRoleAssignmentsOutput = "$customRoleOwnersAllAssignmentsCount ($($customRoleRoleAssignmentsArray -join "$CsvDelimiterOpposite "))"
            }
            else {
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
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    $roleAssignmentsOwnerAssignmentSPAll = ($rbacBaseQuery | Where-Object { $_.RoleSecurityOwnerAssignmentSP -eq 1 } | Sort-Object -Property RoleAssignmentId)
    $roleAssignmentsOwnerAssignmentSP = $roleAssignmentsOwnerAssignmentSPAll | sort-object -Property RoleAssignmentId -Unique
    if (($roleAssignmentsOwnerAssignmentSP | measure-object).count -gt 0) {
        $tfCount = ($roleAssignmentsOwnerAssignmentSP | measure-object).count
        $tableId = "SummaryTable_roleAssignmentsOwnerAssignmentSP"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_roleAssignmentsOwnerAssignmentSP"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentSP | measure-object).count) Owner permission assignments to ServicePrincipal ($scopeNamingSummary) <abbr title="Owner permissions on Service Principals should be treated exceptional"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        $htmlSUMMARYSecurityOwnerAssignmentSP = foreach ($roleAssignmentOwnerAssignmentSP in ($roleAssignmentsOwnerAssignmentSP)) {
            $impactedMgs = $roleAssignmentsOwnerAssignmentSPAll | Where-Object { "" -eq $_.SubscriptionId -and $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentSP.RoleAssignmentId }
            $impactedSubs = $roleAssignmentsOwnerAssignmentSPAll | Where-Object { "" -ne $_.SubscriptionId -and $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentSP.RoleAssignmentId }
            $servicePrincipal = ($roleAssignmentsOwnerAssignmentSP | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentSP.RoleAssignmentId }) | Get-Unique
            @"
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
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    $roleAssignmentsOwnerAssignmentNotGroupAll = ($rbacBaseQuery | Where-Object { $_.RoleDefinitionName -eq "Owner" -and $_.RoleAssignmentObjectType -ne "Group" } | Sort-Object -Property RoleAssignmentId)
    $roleAssignmentsOwnerAssignmentNotGroup = $roleAssignmentsOwnerAssignmentNotGroupAll | sort-object -Property RoleAssignmentId -Unique
    if (($roleAssignmentsOwnerAssignmentNotGroup | measure-object).count -gt 0) {
        $tfCount = ($roleAssignmentsOwnerAssignmentNotGroup | measure-object).count
        $tableId = "SummaryTable_roleAssignmentsOwnerAssignmentNotGroup"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_roleAssignmentsOwnerAssignmentNotGroup"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentNotGroup | measure-object).count) Owner permission assignments to notGroup ($scopeNamingSummary)</span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        $htmlSUMMARYSecurityOwnerAssignmentNotGroup = foreach ($roleAssignmentOwnerAssignmentNotGroup in ($roleAssignmentsOwnerAssignmentNotGroup)) {
            $impactedMgSubBaseQuery = $roleAssignmentsOwnerAssignmentNotGroupAll | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentId }
            $impactedMgs = $impactedMgSubBaseQuery | Where-Object { "" -eq $_.SubscriptionId }
            $impactedSubs = $impactedMgSubBaseQuery | Where-Object { "" -ne $_.SubscriptionId }
            $servicePrincipal = ($roleAssignmentsOwnerAssignmentNotGroup | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentOwnerAssignmentNotGroup.RoleAssignmentId }) | Get-Unique
            @"
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
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsOwnerAssignmentNotGroup | measure-object).count) Owner permission assignments to notGroup ($scopeNamingSummary)</span></p>
"@
    }
    #endregion SUMMARYSecurityOwnerAssignmentNotGroup

    #region SUMMARYSecurityUserAccessAdministratorAssignmentNotGroup
    Write-Host "  processing TenantSummary RoleAssignments security (userAccessAdministrator notGroup)"
    $roleAssignmentsUserAccessAdministratorAssignmentNotGroupAll = ($rbacBaseQuery | Where-Object { $_.RoleDefinitionName -eq "User Access Administrator" -and $_.RoleAssignmentObjectType -ne "Group" } | Sort-Object -Property RoleAssignmentId)
    $roleAssignmentsUserAccessAdministratorAssignmentNotGroup = $roleAssignmentsUserAccessAdministratorAssignmentNotGroupAll | sort-object -Property RoleAssignmentId -Unique
    if (($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | measure-object).count -gt 0) {
        $tfCount = ($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | measure-object).count
        $tableId = "SummaryTable_roleAssignmentsUserAccessAdministratorAssignmentNotGroup"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_roleAssignmentsUserAccessAdministratorAssignmentNotGroup"><i class="fa fa-exclamation-triangle yellow" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | measure-object).count) UserAccessAdministrator permission assignments to notGroup ($scopeNamingSummary)</span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        $htmlSUMMARYSecurityUserAccessAdministratorAssignmentNotGroup = foreach ($roleAssignmentUserAccessAdministratorAssignmentNotGroup in ($roleAssignmentsUserAccessAdministratorAssignmentNotGroup)) {
            $impactedMgSubBaseQuery = $roleAssignmentsUserAccessAdministratorAssignmentNotGroupAll | Where-Object { $roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId }
            $impactedMgs = $impactedMgSubBaseQuery | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId }
            $impactedSubs = $impactedMgSubBaseQuery | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId }
            $servicePrincipal = ($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | Where-Object { $_.RoleAssignmentId -eq $roleAssignmentUserAccessAdministratorAssignmentNotGroup.RoleAssignmentId }) | Get-Unique
            @"
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
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>
"@
    }
    else {
        $htmlTenantSummary += @"
    <p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">$(($roleAssignmentsUserAccessAdministratorAssignmentNotGroup | measure-object).count) UserAccessAdministrator permission assignments to notGroup ($scopeNamingSummary)</span></p>
"@
    }
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
    $blueprintDefinitions = ($blueprintBaseQuery | Where-Object { "" -eq $_.BlueprintAssignmentId })
    $blueprintDefinitionsCount = ($blueprintDefinitions | measure-object).count
    if ($blueprintDefinitionsCount -gt 0) {
        $tableId = "SUMMARY_BlueprintDefinitions"
        $htmlTenantSummary += @"
<button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintDefinitionsCount Blueprints</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    $blueprintAssignments = ($blueprintBaseQuery | Where-Object { "" -ne $_.BlueprintAssignmentId })
    $blueprintAssignmentsCount = ($blueprintAssignments | measure-object).count

    if ($blueprintAssignmentsCount -gt 0) {
        $tableId = "SUMMARY_BlueprintAssignments"
        $htmlTenantSummary += @"
<button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintAssignmentsCount Blueprint Assignments</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
            var tfConfig4$tableId = {
                base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
            var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
                if (-not($blueprintAssignments.BlueprintId).contains($blueprintDefinition.BlueprintId)) {
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

        $tableId = "SUMMARY_BlueprintsOrphaned"
        $htmlTenantSummary += @"
<button type="button" class="collapsible"><p><i class="fa fa-check-circle blue" aria-hidden="true"></i> $blueprintDefinitionsOrphanedCount Orphaned Blueprints</p></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    $htmlTenantSummary += @"
    <p><img class="imgMgTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> <span class="valignMiddle">$totalMgCount Management Groups ($mgDepth levels of depth)</span></p>
"@
    #endregion SUMMARYMGs

    #region SUMMARYMGdefault
    Write-Host "  processing default Management Group"
    $htmlTenantSummary += @"
    <p><img class="imgMgTree defaultMG" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-11-Management-Groups.svg"> <span class="valignMiddle">Default Management Group Id: $defaultManagementGroupId <a class="externallink" href="https://docs.microsoft.com/en-us/azure/governance/management-groups/how-to/protect-resource-hierarchy#setting---default-management-group" target="_blank">Microsoft Docs</a></span></p>
"@
    #endregion SUMMARYMGdefault

    #region SUMMARYMgsapproachingLimitsPolicyAssignments
    Write-Host "  processing TenantSummary ManagementGroups Limit PolicyAssignments"
    $mgsApproachingLimitPolicyAssignments = (($policyBaseQueryManagementGroups | Where-Object { "" -eq $_.SubscriptionId -and $_.PolicyAndPolicySetAssigmentAtScopeCount -gt 0 -and (($_.PolicyAndPolicySetAssigmentAtScopeCount -gt ($_.PolicyAssigmentLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, MgName, PolicyAssigmentAtScopeCount, PolicySetAssigmentAtScopeCount, PolicyAndPolicySetAssigmentAtScopeCount, PolicyAssigmentLimit -Unique)
    if (($mgsApproachingLimitPolicyAssignments | measure-object).count -gt 0) {
        $tfCount = ($mgsApproachingLimitPolicyAssignments | measure-object).count
        $tableId = "SummaryTable_MgsapproachingLimitsPolicyAssignments"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_MgsapproachingLimitsPolicyAssignments"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicyAssignments | measure-object).count) Management Groups approaching Limit ($LimitPOLICYPolicyAssignmentsManagementGroup) for PolicyAssignment</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        $htmlSUMMARYMgsapproachingLimitsPolicyAssignments = foreach ($mgApproachingLimitPolicyAssignments in $mgsApproachingLimitPolicyAssignments) {
            @"
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
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
    var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    $mgsApproachingLimitPolicyScope = (($policyBaseQueryManagementGroups | Where-Object { "" -eq $_.SubscriptionId -and $_.PolicyDefinitionsScopedCount -gt 0 -and (($_.PolicyDefinitionsScopedCount -gt ($_.PolicyDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, MgName, PolicyDefinitionsScopedCount, PolicyDefinitionsScopedLimit -Unique)
    if (($mgsApproachingLimitPolicyScope | measure-object).count -gt 0) {
        $tfCount = ($mgsApproachingLimitPolicyScope | measure-object).count
        $tableId = "SummaryTable_MgsapproachingLimitsPolicyScope"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_MgsapproachingLimitsPolicyScope"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicyScope | measure-object).count) Management Groups approaching Limit ($LimitPOLICYPolicyDefinitionsScopedManagementGroup) for Policy Scope</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        $htmlSUMMARYMgsapproachingLimitsPolicyScope = foreach ($mgApproachingLimitPolicyScope in $mgsApproachingLimitPolicyScope) {
            @"
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
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    $mgsApproachingLimitPolicySetScope = (($policyBaseQueryManagementGroups | Where-Object { "" -eq $_.SubscriptionId -and $_.PolicySetDefinitionsScopedCount -gt 0 -and (($_.PolicySetDefinitionsScopedCount -gt ($_.PolicySetDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, MgName, PolicySetDefinitionsScopedCount, PolicySetDefinitionsScopedLimit -Unique)
    if ($mgsApproachingLimitPolicySetScope.count -gt 0) {
        $tfCount = ($mgsApproachingLimitPolicySetScope | measure-object).count 
        $tableId = "SummaryTable_MgsapproachingLimitsPolicySetScope"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_MgsapproachingLimitsPolicySetScope"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingLimitPolicySetScope | measure-object).count) Management Groups approaching Limit ($LimitPOLICYPolicySetDefinitionsScopedManagementGroup) for PolicySet Scope</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        $htmlSUMMARYMgsapproachingLimitsPolicySetScope = foreach ($mgApproachingLimitPolicySetScope in $mgsApproachingLimitPolicySetScope) {
            @"
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
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    $mgsApproachingRoleAssignmentLimit = $rbacBaseQuery | Where-Object { "" -eq $_.SubscriptionId -and $_.RoleAssignmentsCount -gt ($_.RoleAssignmentsLimit * $LimitCriticalPercentage / 100) } | Sort-Object -Property MgId -Unique | select-object -Property MgId, MgName, RoleAssignmentsCount, RoleAssignmentsLimit
    if (($mgsApproachingRoleAssignmentLimit | measure-object).count -gt 0) {
        $tfCount = ($mgsApproachingRoleAssignmentLimit | measure-object).count
        $tableId = "SummaryTable_MgsapproachingLimitsRoleAssignment"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_MgsapproachingLimitsRoleAssignment"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($mgsApproachingRoleAssignmentLimit | measure-object).count) Management Groups approaching Limit ($LimitRBACRoleAssignmentsManagementGroup) for RoleAssignment</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        $htmlSUMMARYMgsapproachingLimitsRoleAssignment = foreach ($mgApproachingRoleAssignmentLimit in $mgsApproachingRoleAssignmentLimit) {
            @"
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
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    if (($summarySubscriptions | measure-object).count -gt 0) {
        $tfCount = ($summarySubscriptions | measure-object).count
        $tableId = "SummaryTable_subs"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_Subs"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle">$(($summarySubscriptions | measure-object).count) Subscriptions (state: enabled)</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>Subscription</th>
<th>SubscriptionId</th>
<th>QuotaId</th>
<th>Tags</th>
<th>ASC Score</th>
"@
        if (-not $NoAzureConsumption) {
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
            $subscriptionTagsArray = foreach ($tag in ($htSubscriptionTags).($summarySubscription.subscriptionId).keys) {
                "'$($tag)':'$(($htSubscriptionTags).$($summarySubscription.subscriptionId).$tag)'"
            }    

            if (-not $NoAzureConsumption) {
                $subCurrency = $htAzureConsumption.($summarySubscription.subscriptionId).Currency
                if ($htAzureConsumption.($summarySubscription.subscriptionId)) {
                    #$totalCost = "$([math]::Round($htAzureConsumption.($summarySubscription.subscriptionId).ConsumptionTotal,4))"
                    if ([math]::Round($htAzureConsumption.($summarySubscription.subscriptionId).ConsumptionTotal,4) -eq 0){
                        $totalCost = [decimal]$htAzureConsumption.($summarySubscription.subscriptionId).ConsumptionTotal
                    }
                    else{
                        $totalCost = [decimal]([math]::Round($htAzureConsumption.($summarySubscription.subscriptionId).ConsumptionTotal,4))
                    }
                }
                else {
                    $totalCost = "0"
                }
            }
            else {
                $totalCost = "n/a"
            }
            @"
<tr>
<td>$($summarySubscription.subscription)</td>
<td><span class="valignMiddle"><a class="internallink" href="#table_$($summarySubscription.MgId)">$($summarySubscription.subscriptionId)</a></span></td>
<td>$($summarySubscription.SubscriptionQuotaId)</td>
<td>$(($subscriptionTagsArray | sort-object) -join "$CsvDelimiterOpposite ")</td>
<td>$($summarySubscription.SubscriptionASCSecureScore)</td>
"@
            if (-not $NoAzureConsumption) {
                @"
<td>$totalCost</td>
<td>$subCurrency</td>
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
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        if (-not $NoAzureConsumption) {
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
        tf.init();
    </script>

"@
    }
    else {
        $htmlTenantSummary += @"
    <p><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions.svg"> <span class="valignMiddle">$subscount Subscriptions</span></p>
"@
    }
    #endregion SUMMARYSubs

    #region SUMMARYOutOfScopeSubscriptions
    Write-Host "  processing TenantSummary Subscriptions (out-of-scope)"
    $outOfScopeSubscriptionsCount = ($script:outOfScopeSubscriptions | Measure-Object).Count
    if ($outOfScopeSubscriptionsCount -gt 0) {
        $tfCount = $outOfScopeSubscriptionsCount
        $tableId = "SummaryTable_outOfScopeSubscriptions"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_outOfScopeSubscriptions"><img class="imgSubTree" src="https://www.azadvertizer.net/azgovvizv4/icon/Icon-general-2-Subscriptions_excluded_r.svg"> <span class="valignMiddle">$outOfScopeSubscriptionsCount Subscriptions out-of-scope</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        $htmlSUMMARYOutOfScopeSubscriptions = foreach ($outOfScopeSubscription in $script:outOfScopeSubscriptions) {
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
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
            
"@      
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
            $tableId = "SummaryTable_resources"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_resources"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$resourcesResourceTypeCount ResourceTypes ($resourcesTotal Resources) in $resourcesLocationCount Locations ($scopeNamingSummary)</span>
</button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
    var tfConfig4$tableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
    var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
        $tableId = "SummaryTable_ResourcesDiagnosticsCapable"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_ResourcesDiagnosticsCapable"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$resourceTypesDiagnosticsMetricsLogsTrueCount/$resourceTypesDiagnosticsArraySortedCount ResourceTypes Diagnostics capable ($resourceTypesDiagnosticsMetricsTrueCount Metrics, $resourceTypesDiagnosticsLogsTrueCount Logs)</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true" style="color:#FFB100;"></i> <b>Create Custom Policies for Azure ResourceTypes that support Diagnostics Logs and Metrics</b> <a class="externallink" href="https://github.com/JimGBritt/AzurePolicy/blob/master/AzureMonitor/Scripts/README.md#overview-of-create-azdiagpolicyps1" target="_blank">Create-AzDiagPolicy</a><br>
&nbsp;&nbsp;<i class="fa fa-windows" aria-hidden="true" style="color:#00a2ed;"></i> <b>Supported categories for Azure Resource Logs</b> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-monitor/platform/resource-logs-categories" target="_blank">Microsoft Docs</a><br>
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
    var tfConfig4$tableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
    var tf = new TableFilter('$tableId', tfConfig4$tableId);
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

                            $roleDefinitionIdsArray = @()
                            $roleDefinitionIdsArray += foreach ($roleDefinitionId in ($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.roleDefinitionIds) {
                                if (($htCacheDefinitions).role.($roleDefinitionId -replace ".*/")) {
                                    "$(($htCacheDefinitions).role.($roleDefinitionId -replace ".*/").Name) ($($roleDefinitionId -replace ".*/"))"
                                }
                                else {
                                    Write-Host "  DiagnosticsLifeCycle: unknown RoleDefinition '$roleDefinitionId'"
                                    "unknown RoleDefinition: '$roleDefinitionId'"
                                }
                            }

                            $diagnosticsLogCategoriesCoveredByPolicy = (($htCacheDefinitions).policy.($policy).json.properties.policyrule.then.details.deployment.properties.template.resources | Where-Object { $_.type -match "/providers/diagnosticSettings" }).properties.logs
                            if (($diagnosticsLogCategoriesCoveredByPolicy.category | Measure-Object).count -gt 0) {

                                if (($supportedLogs | Measure-Object).count -gt 0) {
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

                                $policyHasPolicyAssignments = $policyBaseQuery | Where-Object { $_.PolicyDefinitionIdFull -eq $policy } | sort-object -property PolicyDefinitionIdFull, PolicyAssignmentId -unique
                                $policyHasPolicyAssignmentCount = ($policyHasPolicyAssignments | Measure-Object).count
                                if ($policyHasPolicyAssignmentCount -gt 0) {
                                    $policyAssignmentsArray = @()
                                    $policyAssignmentsArray += foreach ($policyAssignment in $policyHasPolicyAssignments) {
                                        "$($policyAssignment.PolicyAssignmentId) ($($policyAssignment.PolicyAssignmentDisplayName))"
                                    }
                                    $policyAssignmentsCollCount = ($policyAssignmentsArray | Measure-Object).count
                                    $policyAssignmentsColl = $policyAssignmentsCollCount
                                }
                                else {
                                    $policyAssignmentsColl = 0
                                }

                                #PolicyUsedinPolicySet
                                $policySetAssignmentsColl = 0
                                $policyUsedinPolicySets = "n/a"
                                
                                $usedInPolicySetArray = [System.Collections.ArrayList]@()
                                $usedInPolicySetArray = foreach ($customPolicySet in $tenantCustomPolicySets) {
                                    if (($htCacheDefinitions).policySet.$customPolicySet.Type -eq "Custom") {
                                        $hlpCustomPolicySet = ($htCacheDefinitions).policySet.($customPolicySet)
                                        if (($hlpCustomPolicySet.PolicySetPolicyIds).contains($policy)) {
                                            ($hlpCustomPolicySet.Id)
                                            
                                            #PolicySetHasAssignments
                                            $policySetAssignments = ($htCacheAssignments).policy.keys | Where-Object { ($htCacheAssignments).policy.($_).properties.PolicyDefinitionId -eq ($hlpCustomPolicySet.Id) }
                                            $policySetAssignmentsCount = ($policySetAssignments | measure-object).count
                                            if ($policySetAssignmentsCount -gt 0) {
                                                $policySetAssignmentsArray += foreach ($policySetAssignment in $policySetAssignments) {
                                                    "$(($htCacheAssignments).policy.($policySetAssignment).Id) ($(($htCacheAssignments).policy.($policySetAssignment).properties.DisplayName))"
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

                                $null = $diagnosticsPolicyAnalysis.Add([PSCustomObject]@{
                                        Priority                    = $priority
                                        PolicyId                    = ($htCacheDefinitions).policy.($policy).Id
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
                                        PolicyId                    = ($htCacheDefinitions).policy.($policy).Id
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
                            Write-Host "  DiagnosticsLifeCycle: something unexpected - no Logs defined"
                        }
                    }
                    else {
                        Write-Host "   DiagnosticsLifeCycle: something unexpected - not EH, LA, SA"
                    }
                }
                #where no Policy exists
                foreach ($resourceTypeDiagnosticsCapable in $resourceTypesDiagnosticsArray | Where-Object { $_.Logs -eq $true }) {
                    if (-not($diagnosticsPolicyAnalysis.ResourceType).ToLower().Contains( ($resourceTypeDiagnosticsCapable.ResourceType).ToLower() )) {
                        $supportedLogs = ($resourceTypesDiagnosticsArray | Where-Object { $_.ResourceType -eq $resourceTypeDiagnosticsCapable.ResourceType }).LogCategories
                        $logsSupported = "yes"
                        $resourceTypeCountFromResourceTypesSummarizedArray = ($resourceTypesSummarizedArray | Where-Object { $_.ResourceType -eq $resourceTypeDiagnosticsCapable.ResourceType }).ResourceCount
                        if ($resourceTypeCountFromResourceTypesSummarizedArray) {
                            $resourceCount = $resourceTypeCountFromResourceTypesSummarizedArray
                        }
                        else {
                            $resourceCount = "0"
                        }
                        $recommendation = "Create and assign a diagnostics policy for this ResourceType"
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
    
                    $tableId = "SummaryTable_DiagnosticsLifecycle"
                    $htmlTenantSummary += @"
<button type="button" class="collapsible" id="Summary_DiagnosticsLifecycle"><i class="fa fa-check" aria-hidden="true" style="color: #67C409"></i> <span class="valignMiddle">ResourceDiagnostics Policy Lifecycle recommendations</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-lightbulb-o" aria-hidden="true" style="color:#FFB100;"></i> <b>Create Custom Policies for Azure ResourceTypes that support Diagnostics Logs and Metrics</b> <a class="externallink" href="https://github.com/JimGBritt/AzurePolicy/blob/master/AzureMonitor/Scripts/README.md#overview-of-create-azdiagpolicyps1" target="_blank">Create-AzDiagPolicy</a><br>
&nbsp;&nbsp;<i class="fa fa-windows" aria-hidden="true" style="color:#00a2ed;"></i> <b>Supported categories for Azure Resource Logs</b> <a class="externallink" href="https://docs.microsoft.com/en-us/azure/azure-monitor/platform/resource-logs-categories" target="_blank">Microsoft Docs</a>
<table id= "$tableId" class="summaryTable">
<thead>
<tr>
<th>Priority</th>
<th>Recommendation</th>
<th>ResourceType</th>
<th>Resource Count</th>
<th>Diagnostics capable</th>
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
                    foreach ($diagnosticsFinding in $diagnosticsPolicyAnalysis | Sort-Object -property Priority, Recommendation, ResourceType, PolicyName) {
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
    var tfConfig4$tableId = {
        base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
                    if ($tfCount -gt 10) {
                        $spectrum = "10, $tfCount"
                        if ($tfCount -gt 100) {
                            $spectrum = "10, 30, 50, $tfCount"
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
    var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    $resourceProvidersAllCount = ($htResourceProvidersAll.Keys | Measure-Object).count
    if ($resourceProvidersAllCount -gt 0) {
        $grped = $arrayResourceProvidersAll | sort-object -property namespace, registrationState | group-object namespace
        $htResProvSummary = @{ }
        foreach ($grp in $grped) {
            $htResProvSummary.($grp.name) = @{ }
            $regstates = ($grp.group | sort-object -property registrationState -unique | select-object registrationState).registrationstate
            foreach ($regstate in $regstates) {
                $htResProvSummary.($grp.name).$regstate = ($grp.group | Where-Object { $_.registrationstate -eq $regstate } | measure-object).count
            }
        }
        $providerSummary = [System.Collections.ArrayList]@()
        $providerSummary = foreach ($provider in $htResProvSummary.keys) {
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

            [PSCustomObject]@{
                Provider      = $provider
                Registered    = $registered
                NotRegistered = $notregistered
                Registering   = $registering
                Unregistering = $unregistering 
            }
        }

        $uniqueNamespaces = $arrayResourceProvidersAll | Sort-Object -Property namespace -Unique
        $uniqueNamespacesCount = ($uniqueNamespaces | Measure-Object).count
        $uniqueNamespaceRegistrationState = $arrayResourceProvidersAll | Sort-Object -Property namespace, registrationState -Unique
        $providersRegistered = $uniqueNamespaceRegistrationState | Where-Object { $_.registrationState -eq "registered" -or $_.registrationState -eq "registering" } | select-object -property namespace | Sort-Object namespace -Unique
        $providersRegisteredCount = ($providersRegistered | Measure-Object).count

        $providersNotRegisteredUniqueCount = 0 
        foreach ($uniqueNamespace in $uniqueNamespaces) {
            if (-not $providersRegistered.namespace.contains($uniqueNamespace.namespace)) {
                $providersNotRegisteredUniqueCount++
            }
        }
        $tfCount = $uniqueNamespacesCount
        $tableId = "SummaryTable_SubResourceProviders"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_SubResourceProviders"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Providers Total: $uniqueNamespacesCount Registered/Registering: $providersRegisteredCount NotRegistered/Unregistering: $providersNotRegisteredUniqueCount</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        var tfConfig4$tableId = {
            base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,      
"@      
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    if (-not $NoResourceProvidersDetailed) {

        Write-Host "  processing TenantSummary Subscriptions Resource Providers detailed"
        $startsumRPDetailed = get-date
        $resourceProvidersAllCount = ($htResourceProvidersAll.Keys | Measure-Object).count
        if ($resourceProvidersAllCount -gt 0) {
            $tfCount = ($arrayResourceProvidersAll | Measure-Object).Count
            $tableId = "SummaryTable_SubResourceProvidersDetailed"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_SubResourceProvidersDetailed"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">Resource Providers Detailed</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
            $htmlSUMMARYSubResourceProvidersDetailed = foreach ($subscriptionResProv in ($htResourceProvidersAll.Keys | sort-object)) {
                $subscriptionResProvDetails = $optimizedTableForPathQuerySub | Where-Object { $_.SubscriptionId -eq $subscriptionResProv } | sort-object -Property SubscriptionId -Unique
                foreach ($provider in ($htResourceProvidersAll).($subscriptionResProv).Providers | sort-object @{Expression = { $_.namespace } }) {
                    $cnter++
                    if ($cnter % 500 -eq 0) {
                        $etappeResProvDetailed = get-date
                        Write-Host "   $cnter ResProv processed; $((NEW-TIMESPAN -Start $startResProvDetailed -End $etappeResProvDetailed).TotalSeconds) seconds"  
                    }
                    @"
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
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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

    #region SUMMARYSubsapproachingLimitsResourceGroups
    Write-Host "  processing TenantSummary Subscriptions Limit Resource Groups"
    $subscriptionsApproachingLimitFromResourceGroupsAll = $resourceGroupsAll | Where-Object { $_.count_ -gt ($LimitResourceGroups * ($LimitCriticalPercentage / 100)) }
    if (($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count -gt 0) {
        $tfCount = ($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count
        $tableId = "SummaryTable_SubsapproachingLimitsResourceGroups"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsResourceGroups"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitFromResourceGroupsAll | measure-object).count) Subscriptions approaching Limit ($LimitResourceGroups) for ResourceGroups</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        $htmlSUMMARYSubsapproachingLimitsResourceGroups = foreach ($subscriptionApproachingLimitFromResourceGroupsAll in $subscriptionsApproachingLimitFromResourceGroupsAll) {
            $subscriptionData = $optimizedTableForPathQueryMgAndSub | Where-Object { $_.SubscriptionId -eq $subscriptionApproachingLimitFromResourceGroupsAll.subscriptionId } | Get-Unique
            @"
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
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    $subscriptionsApproachingLimitTags = ($optimizedTableForPathQueryMgAndSub | Where-Object { (($_.SubscriptionTagsCount -gt ($_.SubscriptionTagsLimit * ($LimitCriticalPercentage / 100)))) })
    if (($subscriptionsApproachingLimitTags | measure-object).count -gt 0) {
        $tfCount = ($subscriptionsApproachingLimitTags | measure-object).count
        $tableId = "SummaryTable_SubsapproachingLimitsSubscriptionTags"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsSubscriptionTags"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitTags | measure-object).count) Subscriptions approaching Limit ($LimitTagsSubscription) for Tags</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        $htmlSUMMARYSubsapproachingLimitsSubscriptionTags = foreach ($subscriptionApproachingLimitTags in $subscriptionsApproachingLimitTags) {
            @"
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
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    $subscriptionsApproachingLimitPolicyAssignments = (($policyBaseQuerySubscriptions | Where-Object { "" -ne $_.SubscriptionId -and $_.PolicyAndPolicySetAssigmentAtScopeCount -gt 0 -and (($_.PolicyAndPolicySetAssigmentAtScopeCount -gt ($_.PolicyAssigmentLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, Subscription, SubscriptionId, PolicyAssigmentAtScopeCount, PolicySetAssigmentAtScopeCount, PolicyAndPolicySetAssigmentAtScopeCount, PolicyAssigmentLimit -Unique)
    if ($subscriptionsApproachingLimitPolicyAssignments.count -gt 0) {
        $tfCount = ($subscriptionsApproachingLimitPolicyAssignments | measure-object).count
        $tableId = "SummaryTable_SubsapproachingLimitsPolicyAssignments"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsPolicyAssignments"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyAssignments | measure-object).count) Subscriptions approaching Limit ($LimitPOLICYPolicyAssignmentsSubscription) for PolicyAssignment</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        $htmlSUMMARYSubsapproachingLimitsPolicyAssignments = foreach ($subscriptionApproachingLimitPolicyAssignments in $subscriptionsApproachingLimitPolicyAssignments) {
            @"
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
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    $subscriptionsApproachingLimitPolicyScope = (($policyBaseQuerySubscriptions | Where-Object { "" -ne $_.SubscriptionId -and $_.PolicyDefinitionsScopedCount -gt 0 -and (($_.PolicyDefinitionsScopedCount -gt ($_.PolicyDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, Subscription, SubscriptionId, PolicyDefinitionsScopedCount, PolicyDefinitionsScopedLimit -Unique)
    if (($subscriptionsApproachingLimitPolicyScope | measure-object).count -gt 0) {
        $tfCount = ($subscriptionsApproachingLimitPolicyScope | measure-object).count
        $tableId = "SummaryTable_SubsapproachingLimitsPolicyScope"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsPolicyScope"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyScope | measure-object).count) Subscriptions approaching Limit ($LimitPOLICYPolicyDefinitionsScopedSubscription) for Policy Scope</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        $htmlSUMMARYSubsapproachingLimitsPolicyScope = foreach ($subscriptionApproachingLimitPolicyScope in $subscriptionsApproachingLimitPolicyScope) {
            @"
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
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    $subscriptionsApproachingLimitPolicySetScope = (($policyBaseQuerySubscriptions | Where-Object { "" -ne $_.SubscriptionId -and $_.PolicySetDefinitionsScopedCount -gt 0 -and (($_.PolicySetDefinitionsScopedCount -gt ($_.PolicySetDefinitionsScopedLimit * ($LimitCriticalPercentage / 100)))) }) | Select-Object MgId, Subscription, SubscriptionId, PolicySetDefinitionsScopedCount, PolicySetDefinitionsScopedLimit -Unique)
    if ($subscriptionsApproachingLimitPolicySetScope.count -gt 0) {
        $tfCount = ($subscriptionsApproachingLimitPolicySetScope | measure-object).count
        $tableId = "SummaryTable_SubsapproachingLimitsPolicySetScope"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsPolicySetScope"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingLimitPolicyScope | measure-object).count) Subscriptions approaching Limit ($LimitPOLICYPolicySetDefinitionsScopedSubscription) for PolicySet Scope</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        $htmlSUMMARYSubsapproachingLimitsPolicySetScope = foreach ($subscriptionApproachingLimitPolicySetScope in $subscriptionsApproachingLimitPolicySetScope) {
            @"
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
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    $subscriptionsApproachingRoleAssignmentLimit = $rbacBaseQuery | Where-Object { "" -ne $_.SubscriptionId -and $_.RoleAssignmentsCount -gt ($_.RoleAssignmentsLimit * $LimitCriticalPercentage / 100) } | Sort-Object -Property SubscriptionId -Unique | select-object -Property MgId, SubscriptionId, Subscription, RoleAssignmentsCount, RoleAssignmentsLimit
    if (($subscriptionsApproachingRoleAssignmentLimit | measure-object).count -gt 0) {
        $tfCount = ($subscriptionsApproachingRoleAssignmentLimit | measure-object).count
        $tableId = "SummaryTable_SubsapproachingLimitsRoleAssignment"
        $htmlTenantSummary += @"
<button type="button" class="collapsible" id="SUMMARY_SubsapproachingLimitsRoleAssignment"><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> <span class="valignMiddle">$(($subscriptionsApproachingRoleAssignmentLimit | measure-object).count) Subscriptions approaching Limit ($LimitRBACRoleAssignmentsSubscription) for RoleAssignment</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
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
        $htmlSUMMARYSubsapproachingLimitsRoleAssignment = foreach ($subscriptionApproachingRoleAssignmentLimit in $subscriptionsApproachingRoleAssignmentLimit) {
            @"
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
        if ($tfCount -gt 10) {
            $spectrum = "10, $tfCount"
            if ($tfCount -gt 100) {
                $spectrum = "10, 30, 50, $tfCount"
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
        var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
    #region AADSPManagedIdentity
    if (-not $NoServicePrincipalResolve) {
        $startAADSPManagedIdentityLoop = get-date
        Write-Host "  processing TenantSummary AAD SP Managed Identities"   

        $servicePrincipalsOfTypeManagedIdentity = $htServicePrincipalsDetails.Keys | Where-Object { $htServicePrincipalsDetails.($_).servicePrincipalType -eq "ManagedIdentity" <#-and $htServicePrincipalsDetails.($_).appOwnerOrganizationId -eq $checkContext.Subscription.TenantId#> }
        $servicePrincipalsOfTypeManagedIdentityCount = ($servicePrincipalsOfTypeManagedIdentity | Measure-Object).Count

        if ($servicePrincipalsOfTypeManagedIdentityCount -gt 0) {        
            $tfCount = $servicePrincipalsOfTypeManagedIdentityCount
            $tableId = "SummaryTable_AADSPManagedIdentities"

            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_AADSPManagedIdentities"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$($servicePrincipalsOfTypeManagedIdentityCount) AAD ServicePrincipals type=ManagedIdentity</span> <abbr title="ServicePrincipals where a Role assignment exists &#13;(including ResourceGroups and Resources)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>ApplicationId</th>
<th>DisplayName</th>
<th>SP ObjectId</th>
<th>Usage</th>
<th>Usage info</th>
</tr>
</thead>
<tbody>
"@
            $htmlSUMMARYAADSPManagedIdentities = $null
            $htmlSUMMARYAADSPManagedIdentities = foreach ($serviceprincipalApp in $servicePrincipalsOfTypeManagedIdentity) {
                if ($htServicePrincipalsDetails.($serviceprincipalApp).spGraphDetails.alternativeNames -like "*/providers/Microsoft.Authorization/policyAssignments/*") {
                    $usage = "Policy Assignments"
                }
                else {
                    $usage = "Unknown"
                }
                @"
<tr>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.spGraphDetails.appId)</td>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.spGraphDetails.displayName)</td>
<td>$($htServicePrincipalsDetails.$serviceprincipalApp.spGraphDetails.id)</td>
<td>$usage</td>
<td>$($htServicePrincipalsDetails.($serviceprincipalApp).spGraphDetails.alternativeNames)</td>
</tr>
"@
            }
            $htmlTenantSummary += $htmlSUMMARYAADSPManagedIdentities
            $htmlTenantSummary += @"
    </tbody>
</table>
</div>
<script>
var tfConfig4$tableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No information on AAD ServicePrincipals type=ManagedIdentity as parameter -NoServicePrincipalResolve was applied</span></p>
"@
    }
    #endregion AADSPManagedIdentity

    #region AADSPCredExpiry
    if (-not $NoServicePrincipalResolve) {
        $startAADSPCredExpiryLoop = get-date
        Write-Host "  processing TenantSummary AAD SP Apps CredExpiry"

        $servicePrincipalsOfTypeApplication = $htServicePrincipalsDetails.Keys | Where-Object { $htServicePrincipalsDetails.($_).servicePrincipalType -eq "Application" -and $htServicePrincipalsDetails.($_).appOwnerOrganizationId -eq $checkContext.Subscription.TenantId }
        $servicePrincipalsOfTypeApplicationCount = ($servicePrincipalsOfTypeApplication | Measure-Object).Count

        if ($servicePrincipalsOfTypeApplicationCount -gt 0) {
            $tfCount = $servicePrincipalsOfTypeApplicationCount
            $tableId = "SummaryTable_AADSPCredExpiry"

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
<button type="button" class="collapsible" id="summary_AADSPCredExpiry">$warningOrNot <span class="valignMiddle">$($servicePrincipalsOfTypeApplicationCount) AAD ServicePrincipals type=Application | $servicePrincipalsOfTypeApplicationSecretsExpiringCount Secrets expire < $($ServicePrincipalExpiryWarningDays)d | $servicePrincipalsOfTypeApplicationCertificatesExpiringCount Certificates expire < $($ServicePrincipalExpiryWarningDays)d</span> <abbr title="ServicePrincipals where a Role assignment exists &#13;(including ResourceGroups and Resources)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>ApplicationId</th>
<th>DisplayName</th>
<th>Notes</th>
<th>SP ObjectId</th>
<th>App ObjectId</th>
<th>Secrets</th>
<th>Secrets expired</th>
<th>Secrets expiry<br><$($ServicePrincipalExpiryWarningDays)d</th>
<th>Secrets expiry<br>>$($ServicePrincipalExpiryWarningDays)d & <2y</th>
<th>Secrets expiry<br>>2y</th>
<th>Certs</th>
<th>Certs expired</th>
<th>Certs expiry<br><$($ServicePrincipalExpiryWarningDays)d</th>
<th>Certs expiry<br>>$($ServicePrincipalExpiryWarningDays)d & <2y</th>
<th>Certs expiry<br>>2y</th>
</tr>
</thead>
<tbody>
"@
            $htmlSUMMARYAADSPCredExpiry = $null
            $htmlSUMMARYAADSPCredExpiry = foreach ($serviceprincipalApp in $servicePrincipalsOfTypeApplication) {
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
var tfConfig4$tableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No information on AAD ServicePrincipals type=Application as parameter -NoServicePrincipalResolve was applied</span></p>
"@
    }
    #endregion AADSPCredExpiry

    #region AADSPExternalSP
    if (-not $NoServicePrincipalResolve) {
        $startAADSPExternalSP = get-date
        Write-Host "  processing TenantSummary AAD External ServicePrincipals"
        $appsWithOtherOrgId = $htServicePrincipalsDetails.Keys | Where-Object { $htServicePrincipalsDetails.($_).servicePrincipalType -eq "Application" -and $htServicePrincipalsDetails.($_).appOwnerOrganizationId -ne $checkContext.Subscription.TenantId }
        $appsWithOtherOrgIdCount = ($appsWithOtherOrgId | Measure-Object).Count

        if ($appsWithOtherOrgIdCount -gt 0) {     
            $tfCount = $appsWithOtherOrgIdCount
            $tableId = "SummaryTable_AADSPExternal"

            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_AADSPExternal"><i class="fa fa-check-circle blue" aria-hidden="true"></i> <span class="valignMiddle">$($appsWithOtherOrgIdCount) External (appOwnerOrganizationId) AAD ServicePrincipals type=Application</span> <abbr title="External (appOwnerOrganizationId != $($checkContext.Subscription.TenantId)) ServicePrincipals where a Role assignment exists &#13;(including ResourceGroups and Resources)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
<table id="$tableId" class="summaryTable">
<thead>
<tr>
<th>ApplicationId</th>
<th>DisplayName</th>
<th>SP ObjectId</th>
<th>OrganizationId</th>
<th>Role assignments <abbr title="Lists only RoleAssignmentIds for scope RG/Resource &#13;Check TenantSummary/RBAC to find the RoleAssignmentIds for MG/Sub scopes"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr></th>
</tr>
</thead>
<tbody>
"@
            $htmlSUMMARYAADSPExternal = $null
            $htmlSUMMARYAADSPExternal = foreach ($serviceprincipalApp in $appsWithOtherOrgId) {
                $arrayRoleAssignments4ExternalApp = [System.Collections.ArrayList]@()
                $roleAssignmentsMgSub = $script:rbacAll | sort-Object -property RoleAssignmentId -unique | where-object { $_.ObjectId -eq $serviceprincipalApp }
                $roleAssignmentsMgSubCount = ($roleAssignmentsMgSub | Measure-Object).Count
                $roleAssignments4ExternalApp = "n/a"
                if ($roleAssignmentsMgSubCount -gt 0) {
                    $roleAssignments4ExternalApp = $roleAssignmentsMgSubCount
                }
                $roleAssignmentsRgRes = $script:arrayCacheRoleAssignmentsResourceGroups | sort-Object -property RoleAssignmentId -unique | where-object { $_.ObjectId -eq $serviceprincipalApp }
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
var tfConfig4$tableId = {
    base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
<p><i class="fa fa-ban" aria-hidden="true"></i> <span class="valignMiddle">No information on External (appOwnerOrganizationId) AAD ServicePrincipals type=Application as parameter -NoServicePrincipalResolve was applied</span></p>
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
    <i class="fa fa-lightbulb-o" aria-hidden="true" style="color:#FFB100;"></i> <b>Customize your Azure environment optimizations (Cost, Reliability & more) with</b> <a class="externallink" href="https://github.com/helderpinto/AzureOptimizationEngine" target="_blank">Azure Optimization Engine (AOE)</a>
"@  

    if (-not $NoAzureConsumption) {
        $startConsumption = get-date
        Write-Host "  processing TenantSummary Consumption"

        if (($arrayAzureConsumptionSummarizedByResourceType | Measure-Object).Count -gt 0) {
            $groupedByCurrency = $arrayAzureConsumptionSummarizedByResourceType | Group-Object -Property SubscriptionConsumptionCurrency
            $arrayTotalCostSummary = @()
            foreach ($currency in $groupedByCurrency){
                $totalCostTenant = ($currency.group.ConsumedServiceCost | Measure-Object -Sum).Sum
                #$totalCostTenantRounded = [math]::Round($totalCostTenant, 4)
                if ([math]::Round($totalCostTenant,4) -eq 0){
                    $totalCostTenantRounded = $totalCostTenant
                }
                else{
                    $totalCostTenantRounded = [math]::Round($totalCostTenant,4)
                }
                $totalCostTenantSubscriptionsCount = ($currency.group.SubscriptionId | Sort-Object -Unique | Measure-Object).Count
                $totalCostTenantResourceTypesCount = ($currency.group.ConsumedService | Sort-Object -Unique | Measure-Object).Count
                $totalCostTenantCurrency = $currency.Name
                $arrayTotalCostSummary += "$($totalCostTenantRounded) $($totalCostTenantCurrency) generated by $($totalCostTenantResourceTypesCount) ResourceTypes in $($totalCostTenantSubscriptionsCount) Subscriptions"
            }
            $groupedArrayAzureConsumptionSummarizedByResourceTypeAndCurrency = $arrayAzureConsumptionSummarizedByResourceType | group-object -property ConsumedService, SubscriptionConsumptionCurrency, ConsumedServiceChargeType, ConsumedServiceCategory
            $groupedArrayAzureConsumptionSummarizedByResourceTypeAndCurrencyCount = ($groupedArrayAzureConsumptionSummarizedByResourceTypeAndCurrency | Measure-Object).count
            $tfCount = $groupedArrayAzureConsumptionSummarizedByResourceTypeAndCurrencyCount
            $tableId = "SummaryTable_Consumption"
            $htmlTenantSummary += @"
<button type="button" class="collapsible" id="summary_Consumption"><i class="fa fa-credit-card" aria-hidden="true" style="color: #0078df"></i> <span class="valignMiddle">Total cost $($arrayTotalCostSummary -join "$CsvDelimiterOpposite ") last $AzureConsumptionPeriod days ($azureConsumptionStartDate - $azureConsumptionEndDate)</span></button>
<div class="content">
&nbsp;&nbsp;<i class="fa fa-table" aria-hidden="true"></i> Download CSV <a class="externallink" href="#" onclick="download_table_as_csv_semicolon('$tableId');">semicolon</a> | <a class="externallink" href="#" onclick="download_table_as_csv_comma('$tableId');">comma</a>
<table id="$tableId" class="summaryTable">
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
            $htmlSUMMARYConsumption = foreach ($ConsumedService in $groupedArrayAzureConsumptionSummarizedByResourceTypeAndCurrency) {
                if ([math]::Round(($consumedService.group.ConsumedServiceCost | Measure-Object -Sum).Sum,4) -eq 0){
                    $cost = [decimal]($consumedService.group.ConsumedServiceCost | Measure-Object -Sum).Sum
                }
                else{
                    $cost = [decimal]([math]::Round(($consumedService.group.ConsumedServiceCost | Measure-Object -Sum).Sum,4))
                }
                @"
<tr>
<td>$((($ConsumedService.Name).split(", "))[2])</td>
<td>$((($ConsumedService.Name).split(", "))[0])</td>
<td>$((($ConsumedService.Name).split(", "))[3])</td>
<td>$(($consumedService.group.ConsumedServiceInstanceCount | Measure-Object -Sum).Sum)</td>
<td>$($cost)</td>
<td>$((($ConsumedService.Name).split(", "))[1])</td>
<td>$((($consumedService.group.SubscriptionId | sort-object -Unique) | Measure-Object).count)</td>
</tr>
"@
            }
            $htmlTenantSummary += $htmlSUMMARYConsumption
            $htmlTenantSummary += @"
</tbody>
</table>
</div>
<script>
var tfConfig4$tableId = {
base_path: 'https://www.azadvertizer.net/azgovvizv4/tablefilter/', rows_counter: true,
"@
            if ($tfCount -gt 10) {
                $spectrum = "10, $tfCount"
                if ($tfCount -gt 100) {
                    $spectrum = "10, 30, 50, $tfCount"
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
var tf = new TableFilter('$tableId', tfConfig4$tableId);
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
$mgParentId($mgParentNameId) --> $mgInLevel($mgNameId)`n
"@
            $subsUnderMg = ($optimizedTableForPathQueryMgAndSub | Where-Object { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel }).SubscriptionId
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
$mgInLevel($mgNameId) --> SubsOf$mgInLevel(($(($subsUnderMg | measure-object).count)))`n
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

            #
            if (($script:outOfScopeSubscriptions | Measure-Object).count -gt 0) {
                $subsoosUnderMg = ($script:outOfScopeSubscriptions | Where-Object { $_.Level -eq $mgLevel -and $_.ManagementGroupId -eq $mgInLevel }).SubscriptionId | Get-Unique
                if (($subsoosUnderMg | measure-object).count -gt 0) {
                    $script:arraySubsOos += foreach ($subUnderMg in $subsoosUnderMg) {
                        "SubsoosOf$mgInLevel"                   
                        $mgDetalsN = ($optimizedTableForPathQueryMg | Where-Object { $_.Level -eq $mgLevel -and $_.ManagementGroupId -eq $mgInLevel })
                        $mgName = $mgDetalsN.MgName | Get-Unique
                    }
                    $mgName = ($script:outOfScopeSubscriptions | Where-Object { $_.Level -eq $mgLevel -and $_.ManagementGroupId -eq $mgInLevel }).ManagementGroupName | Get-Unique
                    if ($mgName -eq $mgInLevel) {
                        $mgNameId = $mgName
                    }
                    else {
                        $mgNameId = "$mgName<br/>$mgInLevel"
                    }
                    $script:markdownhierarchySubs += @"
$mgInLevel($mgNameId) --> SubsoosOf$mgInLevel(($(($subsoosUnderMg | measure-object).count)))`n
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
$startAzGovViz = get-date

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
    if ($AzureDevOpsWikiAsCode) {
        Write-Error "Permissions test failed: Your AzDO ServiceConnection seems to lack ManagementGroup Read permissions or the ManagementGroupId '$ManagementGroupId' does not exist. Please check the documentation: https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting#required-permissions-in-azure | Error: $testMGReadAccessResult"
        Write-Error "Error"
    }
    else {
        Write-Host " Error: $testMGReadAccessResult" -ForegroundColor Red
        Write-Host " Permissions test failed: Your Account '$($checkContext.Account.Id)' seems to lack ManagementGroup Read permissions (RBAC Role: Reader) or the ManagementGroupId '$ManagementGroupId' does not exist. Please check the documentation: https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting#required-permissions-in-azure"
        break script
    }
}
else {
    Write-Host " Permissions test passed: ManagementGroup permissions OK"
}

#validation / check 'Azure Active Directory API' Access
if ($AzureDevOpsWikiAsCode) {
    Write-Host "Checking AzDO ServiceConnection permissions"
    $testSCSPAPIReadAccessResult = "letscheck"
    try {
        $testSCSPAPIReadAccess = Get-AzRoleAssignment -scope "/providers/Microsoft.Management/managementGroups/$($selectedManagementGroupId.Name)" -ErrorAction Stop
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
else {
    $hierarchyLevel = -1
    $mgSubPathTopMg = "$ManagementGroupId"
    $getMgParentId = "'$ManagementGroupId'"
    $getMgParentName = "Tenant Root"
    $mermaidprnts = "'$getMgParentId',$getMgParentId"
}

if (-not $AzureDevOpsWikiAsCode) {
    Write-Host "Get Tenant details"
    $currentTask = "Get Tenant details"
    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)tenants?api-version=2020-01-01"
    #$path = "/tenants?api-version=2020-01-01"
    $method = "GET"

    $tenantDetailsResult = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
    if (($tenantDetailsResult | measure-object).count -gt 0) {
        $tenantDetails = $tenantDetailsResult | Where-Object { $_.tenantId -eq ($checkContext).Tenant.Id }
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
$uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/managementGroups/$(($checkContext).Tenant.Id)/settings?api-version=2020-02-01"
#$path = "providers/Microsoft.Management/managementGroups/($checkContext).Tenant.Id/settings?api-version=2020-02-01"
$method = "GET"

#default Management Group
#https://docs.microsoft.com/en-us/azure/governance/management-groups/how-to/protect-resource-hierarchy#setting---default-management-group
$defaultMG = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
if (($defaultMG | Measure-Object).count -gt 0) {
    write-host " default ManagementGroup Id: $($defaultMG.properties.defaultManagementGroup)"
    $defaultManagementGroupId = $defaultMG.properties.defaultManagementGroup
}
else {
    write-host " default ManagementGroup: $(($checkContext).Tenant.Id) (Tenant Root)"
    $defaultManagementGroupId = ($checkContext).Tenant.Id
}

if (-not $HierarchyMapOnly) {
    $paramsUsed = $Null
    $paramsUsed += "RunInfo &#13;"
    if ($accountType -eq "ServicePrincipal"){
        $paramsUsed += "ExecutedBy: $($accountId) (App/ClientId) ($($accountType)) &#13;"
    }
    else{
        $paramsUsed += "ExecutedBy: $($accountId) ($($accountType)) &#13;"
    }
    $paramsUsed += "HierarchyMapOnly: false &#13;"
    Write-Host "Run Info:"
    Write-Host " Creating HierarchyMap, TenantSummary and ScopeInsights - use parameter: '-HierarchyMapOnly' to only create the HierarchyMap" -ForegroundColor Yellow

    if ($SubscriptionQuotaIdWhitelist -ne "undefined" -and $SubscriptionQuotaIdWhitelist -ne "") {
        $subscriptionQuotaIdWhitelistArray = [Array]($SubscriptionQuotaIdWhitelist).tostring().split("\")
        if (($subscriptionQuotaIdWhitelistArray | Measure-Object).count -gt 0) {
            Write-Host " Subscription Whitelist enabled. AzGovViz will only process Subscriptions where QuotaId startswith one of the following strings:" -ForegroundColor Green
            Write-Host "  $($subscriptionQuotaIdWhitelistArray -join ", ")"
            $paramsUsed += "SubscriptionQuotaIdWhitelist: $($subscriptionQuotaIdWhitelistArray -join ", ") &#13;"
            $subscriptionQuotaIdWhitelistMode = $true
        }
        else {
            Write-Host " Subscription Whitelist enabled. Error: invalid Parameter Value for 'SubscriptionQuotaIdWhitelist'" -ForegroundColor Red
            if ($AzureDevOpsWikiAsCode) {
                Write-Error "Error"
            }
            else {
                break script
            }
        }
    }
    else {
        Write-Host " Subscription Whitelist disabled - use parameter: '-SubscriptionQuotaIdWhitelist' to whitelist QuotaIds" -ForegroundColor Yellow
        $paramsUsed += "SubscriptionQuotaIdWhitelist: false &#13;"
        $subscriptionQuotaIdWhitelistMode = $false
    }

    if ($NoASCSecureScore) {
        Write-Host " ASC Secure Score for Subscriptions disabled (-NoASCSecureScore = $($NoASCSecureScore))" -ForegroundColor Green
        $paramsUsed += "NoASCSecureScore: true &#13;"
    }
    else {
        Write-Host " ASC Secure Score for Subscriptions enabled - use parameter: '-NoASCSecureScore' to disable" -ForegroundColor Yellow
        $paramsUsed += "NoASCSecureScore: false &#13;"
    }

    if ($NoResourceProvidersDetailed) {
        Write-Host " ResourceProvider Detailed for TenantSummary disabled (-NoResourceProvidersDetailed = $($NoResourceProvidersDetailed))" -ForegroundColor Green
        $paramsUsed += "NoResourceProvidersDetailed: true &#13;"
    }
    else {
        Write-Host " ResourceProvider Detailed for TenantSummary enabled - use parameter: '-NoResourceProvidersDetailed' to disable" -ForegroundColor Yellow
        $paramsUsed += "NoResourceProvidersDetailed: false &#13;"
    }

    if ($DoNotShowRoleAssignmentsUserData) {
        Write-Host " Scrub Identity information for identityType='User' enabled (-DoNotShowRoleAssignmentsUserData = $($DoNotShowRoleAssignmentsUserData))" -ForegroundColor Green
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

    if (-not $NoPolicyComplianceStates) {
        Write-Host " Policy States enabled - use parameter: '-NoPolicyComplianceStates' to disable Policy States" -ForegroundColor Yellow
        $paramsUsed += "NoPolicyComplianceStates: false &#13;"
    }
    else {
        Write-Host " Policy States disabled (-NoPolicyComplianceStates = $($NoPolicyComplianceStates))" -ForegroundColor Green
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

    if (-not $NoServicePrincipalResolve) {
        Write-Host " ServicePrincipal resolve enabled (Expiry warning: $ServicePrincipalExpiryWarningDays days) - use parameter: '-ServicePrincipalExpiryWarningDays' to define minimum lifetime in days for SP passwords/keys expiry warning (use parameter: '-NoServicePrincipalResolve' to disable resolving ServicePrincipals)" -ForegroundColor Yellow
        $paramsUsed += "NoServicePrincipalResolve: false &#13;"
        $paramsUsed += "ServicePrincipalExpiryWarningDays: $ServicePrincipalExpiryWarningDays &#13;"
    }
    else {
        Write-Host " ServicePrincipal resolve disabled (-NoServicePrincipalResolve = $($NoServicePrincipalResolve))" -ForegroundColor Green
        $paramsUsed += "NoServicePrincipalResolve: true &#13;"
    }

    if (-not $NoAzureConsumption) {
        if (-not $AzureConsumptionPeriod -is [int]) {
            Write-Host "parameter -AzureConsumptionPeriod must be an integer"
            if ($AzureDevOpsWikiAsCode) {
                Write-Error "Error"
            }
            else {
                break script
            }
        }
        elseif ($AzureConsumptionPeriod -eq 0) {
            Write-Host "parameter -AzureConsumptionPeriod must be gt 0"
            if ($AzureDevOpsWikiAsCode) {
                Write-Error "Error"
            }
            else {
                break script
            }
        }
        else {
            $azureConsumptionStartDate = ((get-date).AddDays(-($($AzureConsumptionPeriod)))).ToString("yyyy-MM-dd")
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
        Write-Host " Azure Consumption reporting disabled (-NoAzureConsumption = $($NoAzureConsumption))" -ForegroundColor Green
        $paramsUsed += "NoAzureConsumption: true &#13;"
    }


    $startDefinitionsCaching = get-date
    Write-Host "Caching built-in Policy and RBAC Role definitions"

    #helper ht / collect results /save some time
    $htCacheDefinitions = @{ }
    ($htCacheDefinitions).policy = @{ }
    ($htCacheDefinitions).policySet = @{ }
    ($htCacheDefinitions).role = @{ }
    ($htCacheDefinitions).blueprint = @{ }
    $htCacheDefinitionsAsIs = @{ }
    ($htCacheDefinitionsAsIs).policy = @{ }
    $arrayPoliciesUsedInPolicySets = [System.Collections.ArrayList]@()
    $htSubscriptionTags = @{ }
    $htCacheAssignments = @{ }
    ($htCacheAssignments).policy = @{ }
    $htCacheAssignmentsResourceGroups = @{ }
    ($htCacheAssignmentsResourceGroups).policy = @{ }
    $script:arrayCachePolicyAssignmentsResourceGroups = [System.Collections.ArrayList]@()
    $script:arrayCacheRoleAssignmentsResourceGroups = [System.Collections.ArrayList]@()
    ($htCacheAssignments).role = @{ }
    ($htCacheAssignments).blueprint = @{ }
    if (-not $NoPolicyComplianceStates) {
        $htCachePolicyCompliance = @{ }
        ($htCachePolicyCompliance).mg = @{ }
        ($htCachePolicyCompliance).sub = @{ }
    }
    $script:outOfScopeSubscriptions = [System.Collections.ArrayList]@()
    $htAllSubscriptionsFromAPI = @{ }
    if (-not $NoAzureConsumption) {
        $arrayAzureConsumptionDetailedAllSubscriptions = [System.Collections.ArrayList]@()
        $htAzureConsumption = @{ } 
        $arrayAzureConsumptionSummarizedByResourceType = [System.Collections.ArrayList]@()
    }
    $script:CustomDataCollectionDuration = [System.Collections.ArrayList]@()    

    #current context sub not AAD*
    do {
        $result = "letscheck"
        try {
            $currentContextSubscriptionQuotaId = (Search-AzGraph -ErrorAction SilentlyContinue -Subscription $checkContext.Subscription.Id -Query "resourcecontainers | where type == 'microsoft.resources/subscriptions' | project properties.subscriptionPolicies.quotaId").properties_subscriptionPolicies_quotaId
        }
        catch {
            $result = "letscheck"
        }
    }
    until ($result -eq "letscheck")

    if (-not $currentContextSubscriptionQuotaId) {
        Write-Host " Bad Subscription context for Definition Caching (SubscriptionName: $($checkContext.Subscription.Name); SubscriptionId: $($checkContext.Subscription.Id); likely an AAD_ QuotaId" -ForegroundColor Yellow
        
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

        Write-Host " Using other Subscription for Definition Caching (SubscriptionId: $($alternativeSubscriptionIdForDefinitionCaching.subscriptionId); QuotaId: $($alternativeSubscriptionIdForDefinitionCaching.properties_subscriptionPolicies_quotaId))" -ForegroundColor Yellow
        $subscriptionIdForDefinitionCaching = $alternativeSubscriptionIdForDefinitionCaching.subscriptionId
        Select-AzSubscription -SubscriptionId $subscriptionIdForDefinitionCaching -ErrorAction Stop
    }
    else {
        Write-Host " Subscription context valid (QuotaId not 'AAD_*') for Definition Caching (SubscriptionId: $($checkContext.Subscription.Id); QuotaId: $currentContextSubscriptionQuotaId)"
        $subscriptionIdForDefinitionCaching = $checkContext.Subscription.Id
    }

    $currentTask = "Getting all Subscriptions"
    Write-Host " $currentTask"
    #https://management.azure.com/subscriptions?api-version=2020-01-01
    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions?api-version=2019-10-01"
    #$path = "/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
    $method = "GET"

    $requestAllSubscriptionsAPI = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
    foreach ($subscription in $requestAllSubscriptionsAPI) {   
        $htAllSubscriptionsFromAPI.($subscription.subscriptionId) = @{ }
        $htAllSubscriptionsFromAPI.($subscription.subscriptionId).subDetails = $subscription
    }

    $currentTask = "Getting Entities"
    Write-Host " $currentTask"
    #https://management.azure.com/providers/Microsoft.Management/getEntities?api-version=2020-02-01
    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/getEntities?api-version=2020-02-01"
    #$path = "/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
    $method = "POST"

    $arrayEntitiesFromAPI = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))

    $currentTask = "Caching built-in Policy definitions"
    Write-Host " $currentTask"
    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
    #$path = "/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
    $method = "GET"

    $requestPolicyDefinitionAPI = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
    $builtinPolicyDefinitions = $requestPolicyDefinitionAPI | Where-Object { $_.properties.policyType -eq "builtin" }
    foreach ($builtinPolicyDefinition in $builtinPolicyDefinitions) {
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id) = @{ }
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).Id = $builtinPolicyDefinition.id
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).DisplayName = $builtinPolicyDefinition.Properties.displayname
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).Description = $builtinPolicyDefinition.Properties.description
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).Type = $builtinPolicyDefinition.Properties.policyType
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).Category = $builtinPolicyDefinition.Properties.metadata.category
        ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).PolicyDefinitionId = $builtinPolicyDefinition.id
        if ($builtinPolicyDefinition.Properties.metadata.deprecated -eq $true) {
            ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).Deprecated = $builtinPolicyDefinition.Properties.metadata.deprecated
        }
        else {
            ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).Deprecated = $false
        }
        #effects
        if ($builtinPolicyDefinition.properties.parameters.effect.defaultvalue) {
            ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).effectDefaultValue = $builtinPolicyDefinition.properties.parameters.effect.defaultvalue
            if ($builtinPolicyDefinition.properties.parameters.effect.allowedValues) {
                ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).effectAllowedValue = $builtinPolicyDefinition.properties.parameters.effect.allowedValues -join ","
            }
            else {
                ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).effectAllowedValue = "n/a"
            }
            ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).effectFixedValue = "n/a"
        }
        else {
            if ($builtinPolicyDefinition.properties.parameters.policyEffect.defaultValue) {
                ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).effectDefaultValue = $builtinPolicyDefinition.properties.parameters.policyEffect.defaultvalue
                if ($builtinPolicyDefinition.properties.parameters.policyEffect.allowedValues) {
                    ($htCacheDefinitions).policy.$($builtinPolicyDefinition.id).effectAllowedValue = $builtinPolicyDefinition.properties.parameters.policyEffect.allowedValues -join ","
                }
                else {
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

    $currentTask = "Caching built-in PolicySet definitions"
    Write-Host " $currentTask"
    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"
    #$path = "/providers/Microsoft.Authorization/policySetDefinitions?api-version=2019-09-01"
    $method = "GET"

    $requestPolicySetDefinitionAPI = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
    $builtinPolicySetDefinitions = $requestPolicySetDefinitionAPI | Where-Object { $_.properties.policyType -eq "builtin" }
    foreach ($builtinPolicySetDefinition in $builtinPolicySetDefinitions) {
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id) = @{ }
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).Id = $builtinPolicySetDefinition.id
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).DisplayName = $builtinPolicySetDefinition.Properties.displayname
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).Description = $builtinPolicySetDefinition.Properties.description
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).Type = $builtinPolicySetDefinition.Properties.policyType
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).Category = $builtinPolicySetDefinition.Properties.metadata.category
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).PolicyDefinitionId = $builtinPolicySetDefinition.id
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).PolicySetPolicyIds = $builtinPolicySetDefinition.properties.policydefinitions.policyDefinitionId
        if ($builtinPolicySetDefinition.Properties.metadata.deprecated -eq $true) {
            ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).Deprecated = $builtinPolicySetDefinition.Properties.metadata.deprecated
        }
        else {
            ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).Deprecated = $false
        }
        ($htCacheDefinitions).policySet.$($builtinPolicySetDefinition.id).json = $builtinPolicySetDefinition
    }

    Write-Host " Caching built-in Role definitions"
    $roleDefinitions = Get-AzRoleDefinition -Scope "/subscriptions/$SubscriptionIdForDefinitionCaching" -ErrorAction Stop | Where-Object { $_.IsCustom -eq $false }
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
    Write-Host "Caching built-in definitions duration: $((NEW-TIMESPAN -Start $startDefinitionsCaching -End $endDefinitionsCaching).TotalSeconds) seconds"
}
else {
    Write-Host "Run Info:"
    Write-Host " Creating HierarchyMap only" -ForegroundColor Green

    $currentTask = "Getting Entities"
    Write-Host " $currentTask"
    #https://management.azure.com/providers/Microsoft.Management/getEntities?api-version=2020-02-01
    $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)providers/Microsoft.Management/getEntities?api-version=2020-02-01"
    #$path = "/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
    $method = "POST"

    $arrayEntitiesFromAPI = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
}

$arrayEntitiesFromAPISubscriptionsCount = ($arrayEntitiesFromAPI | Where-Object { $_.type -eq "/subscriptions" -and $_.properties.parentNameChain -contains $ManagementGroupId } | Measure-Object).count
$arrayEntitiesFromAPIManagementGroupsCount = ($arrayEntitiesFromAPI | Where-Object { $_.type -eq "Microsoft.Management/managementGroups" -and $_.properties.parentNameChain -contains $ManagementGroupId } | Measure-Object).count + 1

Write-Host "Collecting custom data"
$startDataCollection = get-date

dataCollection -mgId $ManagementGroupId -hierarchyLevel $hierarchyLevel -mgParentId $getMgParentId -mgParentName $getMgParentName

$endDataCollection = get-date
Write-Host "Collecting custom data duration: $((NEW-TIMESPAN -Start $startDataCollection -End $endDataCollection).TotalMinutes) minutes"

$durationDataMG = ($script:CustomDataCollectionDuration | Where-Object { $_.Type -eq "MG"})
$durationDataSUB = ($script:CustomDataCollectionDuration | Where-Object { $_.Type -eq "SUB"})
$durationMGAverageMaxMin = ($durationDataMG.DurationSec | Measure-Object -Average -Maximum -Minimum)
$durationSUBAverageMaxMin = ($durationDataSUB.DurationSec | Measure-Object -Average -Maximum -Minimum)
Write-Host "Collecting custom data for $($arrayEntitiesFromAPIManagementGroupsCount) ManagementGroups Avg/Max/Min duration in seconds: Average: $([math]::Round($durationMGAverageMaxMin.Average,4)); Maximum: $([math]::Round($durationMGAverageMaxMin.Maximum,4)); Minimum: $([math]::Round($durationMGAverageMaxMin.Minimum,4))"
Write-Host "Collecting custom data for $($arrayEntitiesFromAPISubscriptionsCount) Subscriptions Avg/Max/Min duration in seconds: Average: $([math]::Round($durationSUBAverageMaxMin.Average,4)); Maximum: $([math]::Round($durationSUBAverageMaxMin.Maximum,4)); Minimum: $([math]::Round($durationSUBAverageMaxMin.Minimum,4))"

$optimizedTableForPathQuery = ($table | Select-Object -Property level, mg*, subscription*) | sort-object -Property level, mgid, subscriptionId -Unique
$optimizedTableForPathQueryMgAndSub = ($optimizedTableForPathQuery  | Where-Object { "" -ne $_.SubscriptionId } | Select-Object -Property level, mg*, subscription*) | sort-object -Property level, mgid, mgname, mgparentId, mgparentName, subscriptionId, subscription -Unique
$optimizedTableForPathQueryMg = ($optimizedTableForPathQuery | Select-Object -Property level, mgid, mgName, mgparentid, mgparentName) | sort-object -Property level, mgid, mgname, mgparentId, mgparentName -Unique
$optimizedTableForPathQuerySub = ($optimizedTableForPathQuery | Where-Object { "" -ne $_.SubscriptionId } | Select-Object -Property subscription*) | sort-object -Property subscriptionId -Unique

if (-not $HierarchyMapOnly) {
    #AADGroups
    if (-not $NoAADGroupsResolveMembers) {
        $htAADGroupsDetails = @{ }
        $arrayGroupRoleAssignmentsOnServicePrincipals = @()
        Write-Host "Resolving AAD Groups"
        $startAADGroupsResolveMembers = get-date
        function GetGroupmembers($aadGroupId, $aadGroupDisplayName) {
            if (-not $htAADGroupsDetails.$aadGroupId) {
                #write-host "no ht for '$aadGroupId' ($aadGroupDisplayName)"
                $htAADGroupsDetails.$aadGroupId = @{ }
                $htAADGroupsDetails.$aadGroupId.Id = $aadGroupId
                $htAADGroupsDetails.$aadGroupId.displayname = $aadGroupDisplayName
                $uri = "https://graph.microsoft.com/beta/groups/$($aadGroupId)/transitiveMembers"
                $method = "GET"
                $aadGroupMembers = AzAPICall -uri $uri -method $method -currenttask "getGroupMembers $($aadGroupId)"

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
                        #$aadGroupMembersServicePrincipal.displayName
                        if ($script:arrayGroupRoleAssignmentsOnServicePrincipals -notcontains $aadGroupMembersServicePrincipal.id) {
                            #Write-Host "$($aadGroupMembersServicePrincipal.displayName) - not contained"
                            $script:arrayGroupRoleAssignmentsOnServicePrincipals += $aadGroupMembersServicePrincipal.id
                        }
                    }
                }

                $htAADGroupsDetails.$aadGroupId.MembersAllCount = $aadGroupMembersAllCount
                $htAADGroupsDetails.$aadGroupId.MembersUsersCount = $aadGroupMembersUsersCount
                $htAADGroupsDetails.$aadGroupId.MembersGroupsCount = $aadGroupMembersGroupsCount
                $htAADGroupsDetails.$aadGroupId.MembersServicePrincipalsCount = $aadGroupMembersServicePrincipalsCount

                if ($aadGroupMembersAllCount -gt 0) {
                    $htAADGroupsDetails.$aadGroupId.MembersAll = $aadGroupMembersAll
                    
                    if ($aadGroupMembersUsersCount -gt 0) {
                        $htAADGroupsDetails.$aadGroupId.MembersUsers = $aadGroupMembersUsers
                    }    
                    if ($aadGroupMembersGroupsCount -gt 0) {
                        $htAADGroupsDetails.$aadGroupId.MembersGroups = $aadGroupMembersGroups
                    }   
                    if ($aadGroupMembersServicePrincipalsCount -gt 0) {
                        $htAADGroupsDetails.$aadGroupId.MembersServicePrincipals = $aadGroupMembersServicePrincipals
                    }   
                }
            }
        }

        $optimizedTableForAADGroupsQuery = ($table | Where-Object { $_.RoleAssignmentObjectType -eq "Group" } | Select-Object -Property RoleAssignmentObjectId, RoleAssignmentDisplayname) | sort-object -Property RoleAssignmentObjectId -Unique
        $aadGroupsCount = ($optimizedTableForAADGroupsQuery | Measure-Object).Count

        if ($aadGroupsCount -gt 0) {
            Write-Host " processing $($aadGroupsCount) AAD Groups with Role assignments"
            foreach ($aadGroupIdWithRoleAssignment in $optimizedTableForAADGroupsQuery) {
                GetGroupmembers -aadGroupId $aadGroupIdWithRoleAssignment.RoleAssignmentObjectId -aadGroupDisplayName $aadGroupIdWithRoleAssignment.RoleAssignmentDisplayname
            }
        }
        else {
            Write-Host " processing $($aadGroupsCount) AAD Groups with Role assignments"
        }

        $endAADGroupsResolveMembers = Get-Date
        Write-Host "Resolving AAD Groups duration: $((NEW-TIMESPAN -Start $startAADGroupsResolveMembers -End $endAADGroupsResolveMembers).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startAADGroupsResolveMembers -End $endAADGroupsResolveMembers).TotalSeconds) seconds)"
    }

    #AADSP
    if (-not $NoServicePrincipalResolve) {
        Write-Host "Getting ServicePrincipals"
        $startAADGetServicePrincipals = get-date
        $arrayAllServicePrincipalsWithRoleAssignment = @()
        $servicePrincipalsWithDirectRoleAssignment = (($table | Where-Object { $_.RoleAssignmentObjectType -eq "ServicePrincipal" } ) | sort-object -Property RoleAssignmentObjectId -Unique).RoleAssignmentObjectId
        $servicePrincipalsWithDirectRoleAssignmentCount = ($servicePrincipalsWithDirectRoleAssignment | Measure-Object).Count

        $servicePrincipalsWithDirectRoleAssignmentResourceGroupsAndResources = (($script:arrayCacheRoleAssignmentsResourceGroups | Where-Object { $_.ObjectType -eq "ServicePrincipal" } ) | sort-object -Property ObjectId -Unique).ObjectId
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
                Write-Host " $($servicePrincipalsWithInheritedAssignmentFromGroupCount) ServicePrincipals with Role Assignment inherited though AAD Group membership"
                foreach ($aadGroupMembersServicePrincipal in $arrayGroupRoleAssignmentsOnServicePrincipals) {
                    if ($arrayAllServicePrincipalsWithRoleAssignment -notcontains $aadGroupMembersServicePrincipal) {
                        $arrayAllServicePrincipalsWithRoleAssignment += $aadGroupMembersServicePrincipal
                    }
                }
            }
        }
        $arrayAllServicePrincipalsWithRoleAssignmentCount = ($arrayAllServicePrincipalsWithRoleAssignment | Measure-Object).count

        if ($arrayAllServicePrincipalsWithRoleAssignmentCount -gt 0) {
            $arrayApplicationRequestResourceNotFound = [System.Collections.ArrayList]@()
            Write-Host " processing $($arrayAllServicePrincipalsWithRoleAssignmentCount) unique ServicePrincipals"
            $htServicePrincipalsDetails = @{ }
            $currentDateUTC = (Get-Date).ToUniversalTime()
            foreach ($servicePrincipalWithRoleAssignment in $arrayAllServicePrincipalsWithRoleAssignment) {
                if (-not $htServicePrincipalsDetails.($ServicePrincipalWithRoleAssignment)) {
                    #Write-Host "processing $($servicePrincipalWithRoleAssignment)"

                    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$($servicePrincipalWithRoleAssignment)"
                    $method = "GET"
                    $getServicePrincipal = AzAPICall -uri $uri -method $method -currenttask "getSP $($servicePrincipalWithRoleAssignment)" -listenOn "Content"
                    $htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment) = @{ }
                    $htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).servicePrincipalType = $getServicePrincipal.servicePrincipalType
                    $htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).spGraphDetails = $getServicePrincipal
                    $htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appOwnerOrganizationId = $getServicePrincipal.appOwnerOrganizationId
                    if ($getServicePrincipal.servicePrincipalType -eq "Application") {

                        #Write-Host "--> APPLICATION"
                        #Write-Host "processing $($getServicePrincipal.displayName)"
                        if ($getServicePrincipal.appOwnerOrganizationId -eq $checkContext.Subscription.TenantId) {
                            #Write-Host "matching appOwnerOrg: $($getServicePrincipal.appOwnerOrganizationId)"
                            #Write-Host "getting app for sp appid '$($getServicePrincipal.appId)'"
                            $uri = "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$($getServicePrincipal.appId)'"
                            $method = "GET"
                            $getApplication = AzAPICall -uri $uri -method $method -currenttask "getApp $($getServicePrincipal.appId)" -getApp $true
                            
                            if ($getApplication -eq "Request_ResourceNotFound"){
                                $null = $arrayApplicationRequestResourceNotFound.Add([PSCustomObject]@{ 
                                    appId = $getServicePrincipal.appId
                                })
                            }
                            else{
                                if (($getApplication | Measure-Object).Count -eq 0){
                                    Write-Host "$($getServicePrincipal.appId) no data returned / seems non existent?"
                                }
                                else{
                                    $htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appGraphDetails = $getApplication
                                    $appPasswordCredentialsCount = ($getApplication.passwordCredentials | Measure-Object).count
                                    if ($appPasswordCredentialsCount -gt 0) {
                                        $htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appPasswordCredentialsCount = $appPasswordCredentialsCount
                                        $appPasswordCredentialsExpiredCount = 0
                                        $appPasswordCredentialsGracePeriodExpiryCount = 0
                                        $appPasswordCredentialsExpiryOKCount = 0
                                        $appPasswordCredentialsExpiryOKMoreThan2YearsCount = 0
                                        foreach ($appPasswordCredential in $getApplication.passwordCredentials) {
                                            $passwordExpiryTotalDays = (NEW-TIMESPAN -Start $currentDateUTC -End $appPasswordCredential.endDateTime).TotalDays
                                            if ($passwordExpiryTotalDays -lt 0) {
                                                #Write-Host "pw expired! ($passwordExpiryTotalDays)"
                                                $appPasswordCredentialsExpiredCount++
                                            }
                                            elseif ($passwordExpiryTotalDays -lt $ServicePrincipalExpiryWarningDays) {
                                                #Write-Host "pw will expire! in less than $ServicePrincipalExpiryWarningDays days ($passwordExpiryTotalDays)"
                                                $appPasswordCredentialsGracePeriodExpiryCount++
                                            }
                                            else {
                                                if ($passwordExpiryTotalDays -gt 730) {
                                                    #Write-Host "info: PW expires in $($passwordExpiryTotalDays) days"
                                                    $appPasswordCredentialsExpiryOKMoreThan2YearsCount++
                                                }
                                                else {
                                                    #Write-Host "info: PW expires in $($passwordExpiryTotalDays) days"
                                                    $appPasswordCredentialsExpiryOKCount++
                                                }
                                            }
                                        }
                                        $htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appPasswordCredentialsExpiredCount = $appPasswordCredentialsExpiredCount
                                        $htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appPasswordCredentialsGracePeriodExpiryCount = $appPasswordCredentialsGracePeriodExpiryCount
                                        $htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appPasswordCredentialsExpiryOKCount = $appPasswordCredentialsExpiryOKCount
                                        $htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appPasswordCredentialsExpiryOKMoreThan2YearsCount = $appPasswordCredentialsExpiryOKMoreThan2YearsCount
                                    }

                                    $appKeyCredentialsCount = ($getApplication.keyCredentials | Measure-Object).count
                                    if ($appKeyCredentialsCount -gt 0) {
                                        $htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appKeyCredentialsCount = $appKeyCredentialsCount
                                        $appKeyCredentialsExpiredCount = 0
                                        $appKeyCredentialsGracePeriodExpiryCount = 0
                                        $appKeyCredentialsExpiryOKCount = 0
                                        $appKeyCredentialsExpiryOKMoreThan2YearsCount = 0
                                        foreach ($appKeyCredential in $getApplication.keyCredentials) {
                                            $keyCredentialExpiryTotalDays = (NEW-TIMESPAN -Start $currentDateUTC -End $appKeyCredential.endDateTime).TotalDays
                                            if ($keyCredentialExpiryTotalDays -lt 0) {
                                                #Write-Host "keycred expired! ($keyCredentialExpiryTotalDays)"
                                                $appKeyCredentialsExpiredCount++
                                            }
                                            elseif ($keyCredentialExpiryTotalDays -lt $ServicePrincipalExpiryWarningDays) {
                                                #Write-Host "keycred will expire! in less than $ServicePrincipalExpiryWarningDays days ($keyCredentialExpiryTotalDays)"
                                                $appKeyCredentialsGracePeriodExpiryCount++
                                            }
                                            else {
                                                if ($keyCredentialExpiryTotalDays -gt 730) {
                                                    #Write-Host "info: keycred expires in $($keyCredentialExpiryTotalDays) days"
                                                    $appKeyCredentialsExpiryOKMoreThan2YearsCount++
                                                }
                                                else {
                                                    #Write-Host "info: keycred expires in $($keyCredentialExpiryTotalDays) days"
                                                    $appKeyCredentialsExpiryOKCount++
                                                }
                                            }
                                        }
                                        $htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appKeyCredentialsExpiredCount = $appKeyCredentialsExpiredCount
                                        $htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appKeyCredentialsGracePeriodExpiryCount = $appKeyCredentialsGracePeriodExpiryCount
                                        $htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appKeyCredentialsExpiryOKCount = $appKeyCredentialsExpiryOKCount
                                        $htServicePrincipalsDetails.($servicePrincipalWithRoleAssignment).appKeyCredentialsExpiryOKMoreThan2YearsCount = $appKeyCredentialsExpiryOKMoreThan2YearsCount
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
            $applicationRequestResourceNotFoundCount = ($arrayApplicationRequestResourceNotFound | Measure-Object).Count
            if ($applicationRequestResourceNotFoundCount -gt 0){
                Write-Host "$applicationRequestResourceNotFoundCount ServicePrincipals could not be checked for Secret/certificate expiry"
            }
        }
        else {
            #Write-Host "no roleAssignments on ServicePrincipals ($($arrayAllServicePrincipalsWithRoleAssignmentCount))"
        }
        $endAADGetServicePrincipals = Get-Date
        Write-Host "Getting ServicePrincipals duration: $((NEW-TIMESPAN -Start $startAADGetServicePrincipals -End $endAADGetServicePrincipals).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startAADGetServicePrincipals -End $endAADGetServicePrincipals).TotalSeconds) seconds)"
    }

    #Caching Resource data
    Write-Host "Caching Resource data"
    $startResourceCaching = get-date
    $subscriptionIds = ($optimizedTableForPathQuerySub).SubscriptionId
    
    $counter = [PSCustomObject] @{
        Value = 0 
    }
    $batchSize = 1000
    $subscriptionsBatch = $subscriptionIds | Group-Object -Property { [math]::Floor($counter.Value++ / $batchSize) }
    #ARG queries
    #$queryResources = "resources | project id, subscriptionId, location, type | summarize count() by subscriptionId, location, type"
    #$queryResourceGroups = "resourcecontainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups' | project id, subscriptionId | summarize count() by subscriptionId"
    $resourcesAll = [System.Collections.ArrayList]@()
    $resourceGroupsAll = [System.Collections.ArrayList]@()
    $htResourceProvidersAll = @{ }
    $arrayResourceProvidersAll = [System.Collections.ArrayList]@()
    Write-Host " Getting ResourceTypes, ResourceGroups and ResourceProviders for Subscriptions"
    $startResourceProviders = get-date
    
    $lastSubsCnter = 0
    $subsCnter = 0
    foreach ($subscriptionId in $subscriptionIds) {
        $subsCnter++
        #alternative to ARG
        $currentTask = "Getting ResourceTypes for SubscriptionId: '$($subscriptionId)'"
        $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($subscriptionId)/resources?api-version=2020-06-01"
        #$path = "/subscriptions/$($subscriptionId)/resources?api-version=2020-06-01"
        $method = "GET"

        $resourcesSubscriptionResult = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
        $resourcesAll += foreach ($resourceTypeLocation in ($resourcesSubscriptionResult | Group-Object -Property type, location)) {
            [PSCustomObject]@{
                subscriptionId = $subscriptionId
                type           = ($resourceTypeLocation.values[0]).ToLower()
                location       = ($resourceTypeLocation.values[1]).ToLower()
                count_         = $resourceTypeLocation.Count 
            }
        }

        #alternative to ARG
        #https://management.azure.com/subscriptions/{subscriptionId}/resourcegroups?api-version=2020-06-01
        $currentTask = "Getting ResourceGroups for SubscriptionId: '$($subscriptionId)'"
        $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($subscriptionId)/resourcegroups?api-version=2020-06-01"
        #$path = "/subscriptions/$($subscriptionId)/resourcegroups?api-version=2020-06-01"
        $method = "GET"
        
        $resourceGroupsSubscriptionResult = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
        $resourceGroupsAllSubscriptionObject = [PSCustomObject]@{
            subscriptionId = $subscriptionId
            count_         = ($resourceGroupsSubscriptionResult | Measure-Object).count
        }
        $resourceGroupsAll += $resourceGroupsAllSubscriptionObject

        ($htResourceProvidersAll).($subscriptionId) = @{ }
        $currentTask = "Getting ResourceProviders for SubscriptionId: '$($subscriptionId)'"
        $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions/$($subscriptionId)/providers?api-version=2019-10-01"
        #$path = "/subscriptions/$($subscriptionId)/providers?api-version=2019-10-01"
        $method = "GET"

        $resProvResult = ((AzAPICall -uri $uri -method $method -currenttask $currentTask))
        ($htResourceProvidersAll).($subscriptionId).Providers = $resProvResult
        $arrayResourceProvidersAll += $resProvResult

        if ($subsCnter % 25 -eq 0) {
            $lastSubsCnter = $subsCnter + $lastSubsCnter
            Write-Host "  $('{0:d4}' -f $lastSubsCnter) subscriptions processed"
            $subsCnter = 0
        }
    }
    Write-Host "  $($subsCnter + $lastSubsCnter) Subscriptions processed total"
    $endResourceProviders = get-date
    Write-Host " Getting ResourceTypes, ResourceGroups and ResourceProviders duration: $((NEW-TIMESPAN -Start $startResourceProviders -End $endResourceProviders).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startResourceProviders -End $endResourceProviders).TotalSeconds) seconds)"
    
    <#
    Write-Host " Getting ResourceTypes and ResourceGroups"
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
    #Write-Host " Getting ResourceTypes and ResourceGroups duration: $((NEW-TIMESPAN -Start $startResourceTypesResourceGroups -End $endResourceTypesResourceGroups).TotalMinutes) minutes"

    Write-Host " Checking Resource Types Diagnostics capability"
    $startResourceDiagnosticsCheck = get-date
    if (($resourcesAll | Measure-Object).count -gt 0) {

        $resourceTypesUnique = ($resourcesAll | select-object type).type.tolower() | sort-object -Unique  
        $resourceTypesUniqueCount = ($resourceTypesUnique | Measure-Object).count
        Write-Host "  $($resourceTypesUniqueCount) unique Resource Types to process"
        $resourceTypesSummarizedArray = [System.Collections.ArrayList]@()
        $resourcesTypeAllCountTotal = 0
        ($resourcesAll).count_ | ForEach-Object { $resourcesTypeAllCountTotal += $_ }
        $resourceTypesSummarizedArray = foreach ($resourceTypeUnique in $resourceTypesUnique) {
            $resourcesTypeCountTotal = 0
            ($resourcesAll | Where-Object { $_.type -eq $resourceTypeUnique }).count_ | ForEach-Object { $resourcesTypeCountTotal += $_ }
            [PSCustomObject]@{
                ResourceType  = $resourceTypeUnique
                ResourceCount = $resourcesTypeCountTotal 
            }
        }

        $resourceTypesDiagnosticsArray = @()
        $delayValues = @(0, 1, 2, 4, 8)
        foreach ($resourcetype in $resourceTypesSummarizedArray.ResourceType) {
            $tryCounter = 0
            do {
                Start-Sleep -Seconds $delayValues[$tryCounter]
                $tryCounter++
                $errorResult = $Null
                $dedicatedResourceArray = @()
                foreach ($batch in $subscriptionsBatch | sort-object -Property Name -Descending) {
                    #write-host "processing $($batch.group)"
                    try {
                        $dedicatedResourceArray = Search-AzGraph -Query "resources | where type =~ '$resourcetype' | project id, type" -Subscription $batch.Group -First 1
                        if ($dedicatedResourceArray -and $dedicatedResourceArray.count -gt 0) {
                            Break
                        }
                    }
                    catch {
                        $errorResult = "letscheck"
                    }
                }
            }
            until($tryCounter -ge 4 -or -not $errorResult -or ($dedicatedResourceArray | Measure-Object).count -gt 0)

            # How to handle when no resources were found for this resource type
            if (-not $dedicatedResourceArray -or $dedicatedResourceArray.Count -eq 0) {
                Write-Host "No resources of type ($resourcetype) were found"
                Continue
            }

            $resource = $dedicatedResourceArray[0]
            $resourceCount = ($resourceTypesSummarizedArray | Where-Object { $_.Resourcetype -eq $resourcetype }).ResourceCount

            #thx @Jim Britt (Microsoft) https://github.com/JimGBritt/AzurePolicy/tree/master/AzureMonitor/Scripts Create-AzDiagPolicy.ps1
            $responseJSON = ''
            $logCategories = @()
            $metrics = $false
            $logs = $false

            $currentTask = "Checking if ResourceType '$resourceType' is capable for Resource Diagnostics using ResourceId: '$($resource.id)'"
            $uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)$($resource.id)/providers/microsoft.insights/diagnosticSettingsCategories/?api-version=2017-05-01-preview"
            #$path = "$($resource.id)/providers/microsoft.insights/diagnosticSettingsCategories/?api-version=2017-05-01-preview"
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
            $resourceTypesDiagnosticsObject = [PSCustomObject]@{
                ResourceType  = $resourcetype
                Metrics       = $metrics
                Logs          = $logs
                LogCategories = $logCategories
                ResourceCount = [int]$resourceCount 
            }
            $resourceTypesDiagnosticsArray += $resourceTypesDiagnosticsObject
        }

    }
    else {
        Write-Host "  No Resources at all"
    }
    $endResourceDiagnosticsCheck = get-date
    Write-Host " Checking Resource Types Diagnostics capability duration: $((NEW-TIMESPAN -Start $startResourceDiagnosticsCheck -End $endResourceDiagnosticsCheck).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startResourceDiagnosticsCheck -End $endResourceDiagnosticsCheck).TotalSeconds) seconds)"
    
    $endResourceCaching = get-date
    Write-Host "Caching Resource data duration: $((NEW-TIMESPAN -Start $startResourceCaching -End $endResourceCaching).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startResourceCaching -End $endResourceCaching).TotalSeconds) seconds)"

    Write-Host "Create helper hash table"
    $startHelperHt = get-date
    foreach ($policySet in ($htCacheDefinitions).policySet.keys) {
        $PolicySetPolicyIds = ($htCacheDefinitions).policySet.($policySet).PolicySetPolicyIds
        $arrayPoliciesUsedInPolicySets += foreach ($PolicySetPolicyId in $PolicySetPolicyIds) {
            if ($arrayPoliciesUsedInPolicySets -notcontains $PolicySetPolicyId) {
                $PolicySetPolicyId
            }
        }
    }
    $endHelperHt = get-date
    Write-Host "Create helper hash table duration: $((NEW-TIMESPAN -Start $startHelperHt -End $endHelperHt).TotalSeconds) seconds"
    
    #summarizeDataCollectionResults
    Write-Host "Summary data collection"
    $mgsDetails = ($optimizedTableForPathQueryMg | Select-Object Level, MgId -Unique)
    $mgDepth = ($mgsDetails.Level | Measure-Object -maximum).Maximum
    $totalMgCount = ($mgsDetails | Measure-Object).count
    $totalSubCount = ($optimizedTableForPathQuerySub | Measure-Object).count
    $totalSubOutOfScopeCount = ($script:outOfScopeSubscriptions | Measure-Object).count
    $totalSubIncludedAndExcludedCount = $totalSubCount + $totalSubOutOfScopeCount
    $totalPolicyDefinitionsCustomCount = ((($htCacheDefinitions).policy.keys | Where-Object { ($htCacheDefinitions).policy.$_.Type -eq "Custom" }) | Measure-Object).count
    $totalPolicySetDefinitionsCustomCount = ((($htCacheDefinitions).policySet.keys | Where-Object { ($htCacheDefinitions).policySet.$_.Type -eq "Custom" }) | Measure-Object).count
    $totalPolicyAssignmentsCount = (($htCacheAssignments).policy.keys | Measure-Object).count
    $totalPolicyAssignmentsResourceGroupsAndResourcesCount = ($script:arrayCachePolicyAssignmentsResourceGroups | Measure-Object).count
    $totalRoleDefinitionsCustomCount = ((($htCacheDefinitions).role.keys | Where-Object { ($htCacheDefinitions).role.$_.IsCustom -eq $True }) | Measure-Object).count
    $totalRoleAssignmentsCount = (($htCacheAssignments).role.keys | Measure-Object).count
    $totalRoleAssignmentsResourceGroupsAndResourcesCount = ($script:arrayCacheRoleAssignmentsResourceGroups | Measure-Object).count
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

$parentMgBaseQuery = ($optimizedTableForPathQueryMg | Where-Object { $_.MgParentId -eq $getMgParentId })
$parentMgNamex = $parentMgBaseQuery.mgParentName | Get-Unique
$parentMgIdx = $parentMgBaseQuery.mgParentId | Get-Unique
$ManagementGroupIdCaseSensitived = (($optimizedTableForPathQueryMg | Where-Object { $_.MgId -eq $ManagementGroupId }).mgId) | Get-Unique

if (-not $HierarchyMapOnly) {
    Write-Host " Build preQueries"
    $policyBaseQuery = $table | Where-Object { "" -ne $_.PolicyVariant } | Sort-Object -Property PolicyType, Policy | Select-Object -Property Level, Policy*, mgId, mgname, SubscriptionId, Subscription
    $policyBaseQuerySubscriptions = $policyBaseQuery | Where-Object { "" -ne $_.SubscriptionId }
    $policyBaseQueryManagementGroups = $policyBaseQuery | Where-Object { "" -eq $_.SubscriptionId }
    $policyPolicyBaseQueryScopeInsights = ($policyBaseQuery | Select-Object Mg*, Subscription*, PolicyAssigmentAtScopeCount, PolicySetAssigmentAtScopeCount, PolicyAndPolicySetAssigmentAtScopeCount, PolicyAssigmentLimit -Unique)
    $policyBaseQueryUniqueAssignments = $policyBaseQuery | Select-Object -Property PolicyDefinitionIdGuid, PolicyDefinitionIdFull, PolicyAssignmentId, PolicyVariant, Policy, PolicyType, PolicyAssignmentName -Unique | sort-object -Property PolicyAssignmentId 
    $policyPolicyBaseQueryUniqueAssignments = $policyBaseQueryUniqueAssignments | Where-Object { $_.PolicyVariant -eq "Policy" }
    $policyPolicySetBaseQueryUniqueAssignments = $policyBaseQueryUniqueAssignments | Where-Object { $_.PolicyVariant -eq "PolicySet" } 
    $policyBaseQueryUniqueCustomDefinitions = ($policyBaseQuery | Where-Object { $_.PolicyType -eq "Custom" }) | select-object PolicyVariant, PolicyDefinitionIdFull -Unique
    $policyPolicyBaseQueryUniqueCustomDefinitions = ($policyBaseQueryUniqueCustomDefinitions | Where-Object { $_.PolicyVariant -eq "Policy" }).PolicyDefinitionIdFull
    $policyPolicySetBaseQueryUniqueCustomDefinitions = ($policyBaseQueryUniqueCustomDefinitions | Where-Object { $_.PolicyVariant -eq "PolicySet" }).PolicyDefinitionIdFull

    $rbacBaseQuery = $table | Where-Object { "" -ne $_.RoleDefinitionName } | Sort-Object -Property RoleIsCustom, RoleDefinitionName | Select-Object -Property Level, Role*, mgId, MgName, SubscriptionId, Subscription
    $blueprintBaseQuery = $table | Where-Object { "" -ne $_.BlueprintName }
    $mgsAndSubs = (($optimizedTableForPathQuery | Where-Object { $_.mgId -ne "" -and $_.Level -ne "0" }) | select-object MgId, SubscriptionId -unique)
    $tenantCustomPolicies = ($htCacheDefinitions).policy.keys | Where-Object { ($htCacheDefinitions).policy.($_).Type -eq "Custom" }
    $tenantCustomPoliciesCount = ($tenantCustomPolicies | measure-object).count
    $tenantCustomPolicySets = ($htCacheDefinitions).policySet.keys | Where-Object { ($htCacheDefinitions).policySet.($_).Type -eq "Custom" }
    $tenantCustompolicySetsCount = ($tenantCustomPolicySets | measure-object).count
    $tenantCustomRoles = $($htCacheDefinitions).role.keys | Where-Object { ($htCacheDefinitions).role.($_).IsCustom -eq $True }

    Write-Host " Build SubscriptionsMgPath"
    $htAllSubsMgPath = @{ }
    foreach ($subscriptionId in $subscriptionIds) {
        $htAllSubsMgPath.($subscriptionId) = @{ }
        createMgPathSub -subid $subscriptionId
        [array]::Reverse($script:submgPathArray)
        $htAllSubsMgPath.($subscriptionId).path = $script:submgPathArray
    }

    Write-Host " Build MgPaths"
    $htAllMgsPath = @{ }
    foreach ($mgid in (($optimizedTableForPathQuery | Where-Object { "" -eq $_.SubscriptionId } ).mgid)) {
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
    <link rel="stylesheet" type="text/css" href="https://www.azadvertizer.net/azgovvizv4/css/azgovvizmain_004_019.css">
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

    <script>
    // Quick and simple export target #table_id into a csv
    function download_table_as_csv_semicolon(table_id) {
        // Select rows from table_id
        var rows = document.querySelectorAll('table#' + table_id + ' tr');
        // Construct csv
        var csv = [];
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
    
    if (-not $AzureDevOpsWikiAsCode) {
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
                    <a class="tenant"><div class="fitme" id="fitme">$($tenantDetailsDisplay)$(($checkContext).Tenant.Id)</div></a>
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

if (-not $HierarchyMapOnly) {

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
    </div>
    </div>
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

$html += @"
    <div class="footer">
    <div class="VersionDiv VersionLatest"></div>
    <div class="VersionDiv VersionThis"></div>
    <div class="VersionAlert"></div>
"@

if (-not $HierarchyMapOnly) {
    $html += @"
        <abbr style="text-decoration:none" title="$($paramsUsed)"><i class="fa fa-question-circle" aria-hidden="true"></i></abbr> <button id="hierarchyTreeShowHide" onclick="toggleHierarchyTree()">Hide HierarchyMap</button> <button id="summaryShowHide" onclick="togglesummprnt()">Hide TenantSummary</button> <button id="hierprntShowHide" onclick="togglehierprnt()">Hide ScopeInsights</button>
"@
}

$html += @"
    <hr>
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

if ($AzureDevOpsWikiAsCode) { 
    $markdown += @"
# AzGovViz - Management Group Hierarchy

## Hierarchy Diagram (Mermaid)

::: mermaid
    graph TD;`n
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
Write-Host "Building Markdown total duration: $((NEW-TIMESPAN -Start $startBuildMD -End $endBuildMD).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startBuildMD -End $endBuildMD).TotalMinutes) seconds)"
#endregion BuildMD

#region BuildCSV
Write-Host "Exporting CSV"
$startBuildCSV = get-date
$table | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).csv" -Delimiter "$csvDelimiter" -NoTypeInformation
$endBuildCSV = get-date
Write-Host "Exporting CSV total duration: $((NEW-TIMESPAN -Start $startBuildCSV -End $endBuildCSV).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startBuildCSV -End $endBuildCSV).TotalSeconds) seconds)"
#endregion BuildCSV


#region BuildConsumptionCSV
if (-not $NoAzureConsumption) {
    if (-not $NoAzureConsumptionReportExportToCSV) {
        Write-Host "Exporting Consumption CSV"
        $startBuildConsumptionCSV = get-date
        $arrayAzureConsumptionDetailedAllSubscriptions | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_Consumption.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
        $endBuildConsumptionCSV = get-date
        Write-Host "Exporting Consumption CSV total duration: $((NEW-TIMESPAN -Start $startBuildConsumptionCSV -End $endBuildConsumptionCSV).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startBuildCSV -End $endBuildCSV).TotalSeconds) seconds)"
    }
}
#endregion BuildConsumptionCSV

#endregion createoutputs

$endAzGovViz = get-date
Write-Host "AzGovViz duration: $((NEW-TIMESPAN -Start $startAzGovViz -End $endAzGovViz).TotalMinutes) minutes"

#end
$endTime = get-date -format "dd-MMM-yyyy HH:mm:ss"
Write-Host "End AzGovViz $endTime"
