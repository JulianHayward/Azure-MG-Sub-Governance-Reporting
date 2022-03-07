# https://github.com/JulianHayward/AzAPICall

[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $False)][bool]$DebugAzAPICall = $true,
    [Parameter(Mandatory = $False)][bool]$NoPsParallelization = $true,
    [Parameter(Mandatory = $False)][string]$SubscriptionId4AzContext = 'undefined',
    [Parameter(Mandatory = $False)][string]$GithubRepository = 'aka.ms/AzAPICall',
    [Parameter(Mandatory = $False)][int]$ThrottleLimitMicrosoftGraph = 20,
    [Parameter(Mandatory = $False)][int]$ThrottleLimitARM = 10
)

#Region preferences
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-7.2#erroractionpreference
$ErrorActionPreference = 'Stop'
# https://docs.microsoft.com/de-de/powershell/azure/faq?view=azps-7.1.0#how-do-i-disable-breaking-change-warning-messages-in-azure-powershell-
$ProgressPreference = 'SilentlyContinue'
Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings 'true'
#EndRegion preferences

#Connect
#connect-azaccount -identity

#Region initAZAPICall
Write-Host "Initialize 'AzAPICall'"
Write-Host " Import PS module 'AzAPICall'"
Import-Module .\pwsh\module\AzAPICall\AzAPICall.psd1 -Force -ErrorAction Stop
Write-Host "  Import PS module 'AzAPICall' succeeded" -ForegroundColor Green
$parameters4AzAPICallModule = @{
    DebugAzAPICall           = $DebugAzAPICall
    NoPsParallelization      = $NoPsParallelization
    SubscriptionId4AzContext = $SubscriptionId4AzContext
    GithubRepository         = $GithubRepository
}
$Configuration = initAzAPICall @parameters4AzAPICallModule
Write-Host "Initialize 'AzAPICall' succeeded" -ForegroundColor Green
#EndRegion initAZAPICall

#Region Main
# Example calls

#Region ValidateAccess
$apiEndPoint = $Configuration['htAzureEnvironmentRelatedUrls'].MicrosoftGraph
$apiEndPointVersion = '/v1.0'
$api = '/groups'
$optionalQueryParameters = '?$count=true&$top=1'

#$uri = 'https://graph.microsoft.com/v1.0/groups?$count=true&$top=1'
$uri = $apiEndPoint + $apiEndPointVersion + $api + $optionalQueryParameters

$azAPICallPayload = @{
    uri              = $uri
    method           = 'GET'
    currentTask      = "$($Configuration['htAzureEnvironmentRelatedTargetEndpoints'].($apiEndPoint.split('/')[2])) API: Validate Access for Groups Read permission"
    consistencyLevel = 'eventual'
    validateAccess   = $true
    noPaging         = $true
    AzApiCallConfiguration = $Configuration
}
Write-Host $azAPICallPayload.currentTask

$res = AzAPICall @azAPICallPayload

if ($res -eq 'failed') {
    Write-Host " $($azAPICallPayload.currentTask) - check FAILED"
    throw
}
else {
    Write-Host " $($azAPICallPayload.currentTask) - check PASSED"
}
#Endregion ValidateAccess

# #Region MicrosoftGraphGroupList
# # https://docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http
# # GET /groups
# Write-Host '----------------------------------------------------------'
# Write-Host 'Processing example call: Microsoft Graph API: Get - Groups'

# $apiEndPoint = $Configuration['htAzureEnvironmentRelatedUrls'].MicrosoftGraph
# $apiEndPointVersion = '/v1.0'
# $api = '/groups'
# $optionalQueryParameters = '?$top=50&$filter=(mailEnabled eq false and securityEnabled eq true)&$select=id,createdDateTime,displayName,description&$orderby=displayName asc&$count=true'

# #$uri = 'https://graph.microsoft.com/v1.0/groups?$top=888&$filter=(mailEnabled eq false and securityEnabled eq true)&$select=id,createdDateTime,displayName,description&$orderby=displayName asc&$count=true'
# $uri = $apiEndPoint + $apiEndPointVersion + $api + $optionalQueryParameters

# $azAPICallPayload = @{
#     uri              = $uri
#     method           = 'GET'
#     currentTask      = "'$($htAzureEnvironmentRelatedTargetEndpoints.($apiEndPoint.split('/')[2])) API: Get - Groups'"
#     consistencyLevel = 'eventual'
#     noPaging         = $true #$top in $uri + parameter 'noPaging=$false' (not using 'noPaging' in the splat) will iterate further https://docs.microsoft.com/en-us/graph/paging
# }
# Write-Host $azAPICallPayload.currentTask

# $aadgroups = AzAPICall @azAPICallPayload

# Write-Host " $($azAPICallPayload.currentTask) returned results:" $aadgroups.Count
# #EndRegion MicrosoftGraphGroupList

# #Region MicrosoftGraphGroupMemberList
# Write-Host '----------------------------------------------------------'
# Write-Host "Processing example call: Getting all members for $($aadgroups.Count) AAD Groups (NoPsParallelization:$($NoPsParallelization))"
# if (-not $NoPsParallelization) {
#     $htAzureAdGroupDetails = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
#     $arrayGroupMembers = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
#     $startTime = get-date

#     $aadgroups | ForEach-Object -Parallel {
#         #general hashTables and arrays
#         $checkContext = $using:checkContext
#         $Configuration['htAzureEnvironmentRelatedUrls'] = $using:htAzureEnvironmentRelatedUrls
#         $htAzureEnvironmentRelatedTargetEndpoints = $using:htAzureEnvironmentRelatedTargetEndpoints
#         $htParameters = $using:htParameters
#         $htBearerAccessToken = $using:htBearerAccessToken
#         $arrayAPICallTracking = $using:arrayAPICallTracking
#         #general functions
#         $function:AzAPICall = $using:funcAzAPICall
#         $function:createBearerToken = $using:funcCreateBearerToken
#         $function:GetJWTDetails = $using:funcGetJWTDetails
#         #specific for this operation
#         $htAzureAdGroupDetails = $using:htAzureAdGroupDetails
#         $arrayGroupMembers = $using:arrayGroupMembers

#         $group = $_

#         # https://docs.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0&tabs=http
#         # GET /groups/{id}/members
#         $apiEndPoint = $Configuration['htAzureEnvironmentRelatedUrls'].MicrosoftGraph
#         $apiEndPointVersion = '/v1.0'
#         $api = "/groups/$($group.id)/members"
#         $optionalQueryParameters = ''

#         #$uri = 'https://graph.microsoft.com/v1.0/groups/<GUID>/members'
#         $uri = $apiEndPoint + $apiEndPointVersion + $api + $optionalQueryParameters

#         $azAPICallPayload = @{
#             uri         = $uri
#             method      = 'GET'
#             currentTask = " '$($htAzureEnvironmentRelatedTargetEndpoints.($apiEndPoint.split('/')[2])) API: Get - Group List Members (id: $($group.id))'"
#         }
#         Write-Host $azAPICallPayload.currentTask

#         $AzApiCallResult = AzAPICall @azAPICallPayload

#         #collect results in synchronized hashTable
#         $script:htAzureAdGroupDetails.($group.id) = $AzApiCallResult

#         #collect results in syncronized arrayList
#         foreach ($result in $AzApiCallResult) {
#             $null = $script:arrayGroupMembers.Add($result)
#         }

#     } -ThrottleLimit $ThrottleLimitMicrosoftGraph

#     $parallelElapsedTime = "elapsed time (foreach-parallel loop with ThrottleLimit:$($ThrottleLimitMicrosoftGraph)): " + ((get-date) - $startTime).TotalSeconds + ' seconds'
#     Write-Host $parallelElapsedTime
#     Write-Host 'returned members hashTable:' $htAzureAdGroupDetails.Values.Id.Count
#     Write-Host 'returned members arrayList:' $arrayGroupMembers.Count

#     Write-Host 'statistics:'
#     ($arrayAPICallTracking.Duration | Measure-Object -Average -Maximum -Minimum)
# }
# else {
#     $htAzureAdGroupDetails = @{}
#     $arrayGroupMembers = [System.Collections.ArrayList]@()
#     $startTime = get-date

#     $aadgroups | ForEach-Object {
#         $group = $_

#         # https://docs.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0&tabs=http
#         # GET /groups/{id}/members
#         $apiEndPoint = $Configuration['htAzureEnvironmentRelatedUrls'].MicrosoftGraph
#         $apiEndPointVersion = '/v1.0'
#         $api = "/groups/$($group.id)/members"
#         $optionalQueryParameters = ''

#         #$uri = 'https://graph.microsoft.com/v1.0/groups/<GUID>/members'
#         $uri = $apiEndPoint + $apiEndPointVersion + $api + $optionalQueryParameters

#         $azAPICallPayload = @{
#             uri         = $uri
#             method      = 'GET'
#             currentTask = "'$($htAzureEnvironmentRelatedTargetEndpoints.($apiEndPoint.split('/')[2])) API: Get - Group List Members (id: $($group.id))'"
#         }
#         Write-Host $azAPICallPayload.currentTask

#         $AzApiCallResult = AzAPICall @azAPICallPayload

#         #collect results in hashTable
#         $htAzureAdGroupDetails.($group.id) = $AzApiCallResult

#         #collect results in arrayList
#         foreach ($result in $AzApiCallResult) {
#             $null = $arrayGroupMembers.Add($result)
#         }
#     }

#     $elapsedTime = 'elapsed time: ' + ((get-date) - $startTime).TotalSeconds + ' seconds'
#     Write-Host $elapsedTime
#     Write-Host 'returned members:' $htAzureAdGroupDetails.Values.Id.Count
#     Write-Host 'returned members arrayList:' $arrayGroupMembers.Count

#     Write-Host 'API call statistics:'
#     ($arrayAPICallTracking.Duration | Measure-Object -Average -Maximum -Minimum)
# }
# #EndRegion MicrosoftGraphGroupMemberList

#Region MicrosoftResourceManagerSubscriptions
# https://docs.microsoft.com/en-us/rest/api/resources/subscriptions/list
# GET https://management.azure.com/subscriptions?api-version=2020-01-01
Write-Host '----------------------------------------------------------'
Write-Host 'Processing example call: Microsoft Resource Manager (ARM) API: List - Subscriptions'

$apiEndPoint = $Configuration['htAzureEnvironmentRelatedUrls'].ARM
$apiVersion = '?api-version=2020-01-01'
$api = '/subscriptions'
$uriParameter = ''

#$uri = https://management.azure.com/subscriptions?api-version=2020-01-01
$uri = $apiEndPoint + $api + $apiVersion + $uriParameter

$azAPICallPayload = @{
    uri         = $uri
    method      = 'GET'
    currentTask = " '$($Configuration['htAzureEnvironmentRelatedTargetEndpoints'].($apiEndPoint.split('/')[2])) API: List - Subscriptions'"
    AzAPICallConfiguration = $Configuration
}
Write-Host $azAPICallPayload.currentTask

$subscriptions = AzAPICall @azAPICallPayload

Write-Host " 'Subscriptions' returned results:" $subscriptions.Count
Write-Host " 'List - Subscriptions' first result:" $subscriptions[0].displayName $subscriptions[0].subscriptionId
#EndRegion MicrosoftResourceManagerSubscriptions

#Region MicrosoftResourceManagerResources
$subsToProcess = 20
Write-Host '----------------------------------------------------------'
Write-Host "Processing example call: Getting resources (VNets and VMs) for the first $($subsToProcess) Subscriptions (NoPsParallelization:$($NoPsParallelization))"
if (-not $NoPsParallelization) {
    $htAzureResources = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $arrayAzureResources = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $startTime = get-date

    $subscriptions.where( { $_.state -eq 'enabled' -and $_.subscriptionPolicies.quotaId -notlike 'AAD*' } )[0..($subsToProcess - 1)] | ForEach-Object -Parallel {
        #general hashTables and arrays
        $Configuration = $using:Configuration
        #general functions
        # $function:AzAPICall = $using:funcAzAPICall
        # $function:createBearerToken = $using:funcCreateBearerToken
        # $function:GetJWTDetails = $using:funcGetJWTDetails
        Import-Module .\pwsh\module\AzAPICall\AzAPICall.psd1 -Force -ErrorAction Stop
        #specific for this operation
        $htAzureResources = $using:htAzureResources
        $arrayAzureResources = $using:arrayAzureResources

        $subscription = $_

        # https://docs.microsoft.com/en-us/rest/api/resources/resources/list
        # GET https://management.azure.com/subscriptions/{subscriptionId}/resources?$filter={$filter}&$expand={$expand}&$top={$top}&api-version=2021-04-01
        $apiEndPoint = $Configuration['htAzureEnvironmentRelatedUrls'].ARM
        $apiVersion = '?api-version=2021-04-01'
        $api = "/subscriptions/$($subscription.subscriptionId)/resources"
        $uriParameter = '' #"&`$filter=resourceType eq 'Microsoft.Network/virtualNetworks' or resourceType eq 'Microsoft.Compute/virtualMachines'"

        #$uri = 'https://graph.microsoft.com/v1.0/groups/<GUID>/members'
        $uri = $apiEndPoint + $api + $apiVersion + $uriParameter

        $azAPICallPayload = @{
            uri         = $uri
            method      = 'GET'
            currentTask = " '$($Configuration['htAzureEnvironmentRelatedTargetEndpoints'].($apiEndPoint.split('/')[2])) API: Get - Resources for Subscription (name: $($subscription.displayName); id: $($subscription.subscriptionId))'"
            AzAPICallConfiguration = $Configuration
        }
        Write-Host $azAPICallPayload.currentTask

        $AzApiCallResult = AzAPICall @azAPICallPayload

        #collect results in synchronized hashTable
        $script:htAzureResources.($subscription.subscriptionId) = $AzApiCallResult

        #collect results in syncronized arrayList
        foreach ($result in $AzApiCallResult) {
            $null = $script:arrayAzureResources.Add($result)
        }

    } -ThrottleLimit $ThrottleLimitMicrosoftGraph

    $parallelElapsedTime = "elapsed time (foreach-parallel loop with ThrottleLimit:$($ThrottleLimitMicrosoftGraph)): " + ((get-date) - $startTime).TotalSeconds + ' seconds'
    Write-Host $parallelElapsedTime
    Write-Host 'returned resources hashTable:' $htAzureResources.Values.Id.Count
    Write-Host 'returned resources arrayList:' $arrayAzureResources.Count

    Write-Host 'statistics:'
    ($arrayAPICallTracking.Duration | Measure-Object -Average -Maximum -Minimum)
}
else {
    $htAzureResources = @{}
    $arrayAzureResources = [System.Collections.ArrayList]@()
    $startTime = get-date

    ($subscriptions.where( { $_.state -eq 'enabled' -and $_.subscriptionPolicies.quotaId -notlike 'AAD*' } ))[0..($subsToProcess - 1)] | ForEach-Object {
        $subscription = $_

        # https://docs.microsoft.com/en-us/rest/api/resources/resources/list
        # GET https://management.azure.com/subscriptions/{subscriptionId}/resources?$filter={$filter}&$expand={$expand}&$top={$top}&api-version=2021-04-01
        $apiEndPoint = $Configuration['htAzureEnvironmentRelatedUrls'].ARM
        $apiVersion = '?api-version=2021-04-01'
        $api = "/subscriptions/$($subscription.subscriptionId)/resources"
        $uriParameter = '' #"&`$filter=resourceType eq 'Microsoft.Network/virtualNetworks' or resourceType eq 'Microsoft.Compute/virtualMachines'"

        #$uri = 'https://graph.microsoft.com/v1.0/groups/<GUID>/members'
        $uri = $apiEndPoint + $api + $apiVersion + $uriParameter

        $azAPICallPayload = @{
            uri         = $uri
            method      = 'GET'
            currentTask = " '$($htAzureEnvironmentRelatedTargetEndpoints.($apiEndPoint.split('/')[2])) API: Get - Resources for Subscription (name: $($subscription.displayName); id: $($subscription.subscriptionId))'"
            AzAPICallConfiguration = $Configuration
        }
        Write-Host $azAPICallPayload.currentTask

        $AzApiCallResult = AzAPICall @azAPICallPayload

        #collect results in hashTable
        $htAzureResources.($subscription.subscriptionId) = $AzApiCallResult

        #collect results in arrayList
        foreach ($result in $AzApiCallResult) {
            $null = $script:arrayAzureResources.Add($result)
        }
    }

    $elapsedTime = 'elapsed time: ' + ((get-date) - $startTime).TotalSeconds + ' seconds'
    Write-Host $elapsedTime
    Write-Host 'returned resources hashTable:' $htAzureResources.Values.Id.Count
    Write-Host 'returned resources arrayList:' $arrayAzureResources.Count

    Write-Host 'API call statistics:'
    ($arrayAPICallTracking.Duration | Measure-Object -Average -Maximum -Minimum)
}
#EndRegion MicrosoftResourceManagerResources
#EndRegion Main