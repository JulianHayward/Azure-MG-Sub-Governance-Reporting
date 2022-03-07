function AzAPICall {
    <#
    .SYNOPSIS
    Short description

    .DESCRIPTION
    Long description

    .PARAMETER uri
    Parameter description

    .PARAMETER method
    Parameter description

    .PARAMETER currentTask
    Parameter description

    .PARAMETER body
    Parameter description

    .PARAMETER listenOn
    Parameter description

    .PARAMETER caller
    Parameter description

    .PARAMETER consistencyLevel
    Parameter description

    .PARAMETER getARMARGMgMDfCSecureScore
    Parameter description

    .PARAMETER validateAccess
    Parameter description

    .PARAMETER noPaging
    Parameter description

    .EXAMPLE
    PS C:\> $aadgroups = AzAPICall -uri "https://graph.microsoft.com/v1.0/groups?`$top=999&`$filter=(mailEnabled eq false and securityEnabled eq true)&`$select=id,createdDateTime,displayName,description&`$orderby=displayName asc" -method "GET" -currentTask "Microsoft Graph API: Get - Groups" -listenOn "Value" -consistencyLevel "eventual" -noPaging $true

    .NOTES
    General notes
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)][string]$uri,
        [Parameter(Mandatory = $True)][string]$method,
        [Parameter(Mandatory = $True)][string]$currentTask,
        [Parameter(Mandatory = $False)][string]$body,
        [Parameter(Mandatory = $False)][string]$listenOn,
        [Parameter(Mandatory = $False)][string]$caller,
        [Parameter(Mandatory = $False)][string]$consistencyLevel,
        [Parameter(Mandatory = $False)][switch]$noPaging,
        [Parameter(Mandatory = $False)][switch]$validateAccess,
        [Parameter(Mandatory = $False)][switch]$getARMARGMgMDfCSecureScore
    )

    $tryCounter = 0
    $tryCounterUnexpectedError = 0
    $retryAuthorizationFailed = 5
    $retryAuthorizationFailedCounter = 0
    $apiCallResultsCollection = [System.Collections.ArrayList]@()
    $initialUri = $uri
    $restartDueToDuplicateNextlinkCounter = 0
    if ($htParameters.DebugAzAPICall -eq $true) {
        if ($caller -like 'CustomDataCollection*') {
            $debugForeGroundColors = @('DarkBlue', 'DarkGreen', 'DarkCyan', 'Cyan', 'DarkMagenta', 'DarkYellow', 'Blue', 'Magenta', 'Yellow', 'Green')
            $debugForeGroundColorsCount = $debugForeGroundColors.Count
            $randomNumber = Get-Random -Minimum 0 -Maximum ($debugForeGroundColorsCount - 1)
            $debugForeGroundColor = $debugForeGroundColors[$randomNumber]
        }
        else {
            $debugForeGroundColor = 'Cyan'
        }
    }

    do {
        $uriSplitted = $uri.split('/')
        if (-not ($htAzureEnvironmentRelatedTargetEndpoints).($uriSplitted[2])) {
            Throw "Error - Unknown targetEndpoint: '$($uriSplitted[2])'; `$uri: '$uri'"
        }
        $targetEndpoint = ($htAzureEnvironmentRelatedTargetEndpoints).($uriSplitted[2])
        if (-not ($htBearerAccessToken).$targetEndpoint) {
            createBearerToken -targetEndPoint $targetEndpoint
        }

        $unexpectedError = $false

        $Header = @{
            'Content-Type'  = 'application/json';
            'Authorization' = "Bearer $($htBearerAccessToken.$targetEndpoint)"
        }
        if ($consistencyLevel) {
            $Header = @{
                'Content-Type'     = 'application/json';
                'Authorization'    = "Bearer $($htBearerAccessToken.$targetEndpoint)";
                'ConsistencyLevel' = "$consistencyLevel"
            }
        }

        #needs special handling
        switch ($uri) {
            #ARM
            { $_ -like "$($htAzureEnvironmentRelatedUrls.ARM)*/providers/Microsoft.PolicyInsights/policyStates/latest/summarize*" } { $getARMPolicyComplianceStates = $true }
            { $_ -like "$($htAzureEnvironmentRelatedUrls.ARM)*/providers/Microsoft.Authorization/roleAssignmentSchedules*" } { $getARMRoleAssignmentSchedules = $true }
            { $_ -like "$($htAzureEnvironmentRelatedUrls.ARM)/providers/Microsoft.Management/managementGroups/*/providers/microsoft.insights/diagnosticSettings*" } { $getARMDiagnosticSettingsMg = $true }
            { $_ -like "$($htAzureEnvironmentRelatedUrls.ARM)*/providers/microsoft.insights/diagnosticSettingsCategories*" } { $getARMDiagnosticSettingsResource = $true }
            { $_ -like "$($htAzureEnvironmentRelatedUrls.ARM)*/providers/Microsoft.CostManagement/query*" } { $getARMCostManagement = $true }
            { $_ -like "$($htAzureEnvironmentRelatedUrls.ARM)/subscriptions/*/providers/Microsoft.Security/pricings*" } { $getARMMDfC = $true }
            #MicrosoftGraph
            #{ $_ -like "$($htAzureEnvironmentRelatedUrls.MicrosoftGraph)/*/groups/*/transitiveMembers" } { $getMicrosoftGraphGroupMembersTransitive = $true }
            { $_ -like "$($htAzureEnvironmentRelatedUrls.MicrosoftGraph)/v1.0/applications*" } { $getMicrosoftGraphApplication = $true }
            #{ $_ -like "$($htAzureEnvironmentRelatedUrls.MicrosoftGraph)/v1.0/servicePrincipals*" } { $getMicrosoftGraphServicePrincipal = $true }
            { $_ -like "$($htAzureEnvironmentRelatedUrls.MicrosoftGraph)/*/roleManagement/directory/roleAssignmentScheduleInstances*" } { $getMicrosoftGraphRoleAssignmentScheduleInstances = $true }
            { $_ -like "$($htAzureEnvironmentRelatedUrls.MicrosoftGraph)/*/groups/*/transitiveMembers/`$count" } { $getMicrosoftGraphGroupMembersTransitiveCount = $true }
            { $_ -like "$($htAzureEnvironmentRelatedUrls.MicrosoftGraph)/v1.0/servicePrincipals/*/getMemberGroups" } { $getMicrosoftGraphServicePrincipalGetMemberGroups = $true }
        }

        $startAPICall = Get-Date
        try {
            if ($body) {
                if ($htParameters.CodeRunPlatform -eq 'AzureAutomation') {
                    $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -body $body -Headers $Header -UseBasicParsing
                }
                else {
                    $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -body $body -Headers $Header
                }
            }
            else {
                if ($htParameters.CodeRunPlatform -eq 'AzureAutomation') {
                    $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -Headers $Header -UseBasicParsing
                }
                else {
                    $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -Headers $Header
                }
            }
        }
        catch {
            try {
                $catchResultPlain = $_.ErrorDetails.Message
                if ($catchResultPlain) {
                    $catchResult = $catchResultPlain | ConvertFrom-Json -ErrorAction Stop
                }
            }
            catch {
                $catchResult = $catchResultPlain
                $tryCounterUnexpectedError++
                $unexpectedError = $true
            }
        }
        $endAPICall = Get-Date
        $durationAPICall = NEW-TIMESPAN -Start $startAPICall -End $endAPICall

        if (-not $notTryCounter) {
            $tryCounter++
        }
        $notTryCounter = $false

        #API Call Tracking
        $tstmp = (Get-Date -Format 'yyyyMMddHHmmssms')
        $null = $arrayAPICallTracking.Add([PSCustomObject]@{
                CurrentTask                          = $currentTask
                TargetEndpoint                       = $targetEndpoint
                Uri                                  = $uri
                Method                               = $method
                TryCounter                           = $tryCounter
                TryCounterUnexpectedError            = $tryCounterUnexpectedError
                RetryAuthorizationFailedCounter      = $retryAuthorizationFailedCounter
                RestartDueToDuplicateNextlinkCounter = $restartDueToDuplicateNextlinkCounter
                TimeStamp                            = $tstmp
                Duration                             = $durationAPICall.TotalSeconds
            })

        if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "  DEBUGTASK: attempt#$($tryCounter) processing: $($currenttask) uri: '$($uri)'" -ForegroundColor $debugForeGroundColor }
            if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "  Forced DEBUG: attempt#$($tryCounter) processing: $($currenttask) uri: '$($uri)'" }
        }

        if ($unexpectedError -eq $false) {
            if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                if ($htParameters.DebugAzAPICall -eq $true) { Write-Host '   DEBUG: unexpectedError: false' -ForegroundColor $debugForeGroundColor }
                if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host '   Forced DEBUG: unexpectedError: false' }
            }
            if ($azAPIRequest.StatusCode -ne 200) {
                if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                    if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: apiStatusCode: $($azAPIRequest.StatusCode)" -ForegroundColor $debugForeGroundColor }
                    if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: apiStatusCode: $($azAPIRequest.StatusCode)" }
                }
                if (
                    $catchResult.error.code -like '*GatewayTimeout*' -or
                    $catchResult.error.code -like '*BadGatewayConnection*' -or
                    $catchResult.error.code -like '*InvalidGatewayHost*' -or
                    $catchResult.error.code -like '*ServerTimeout*' -or
                    $catchResult.error.code -like '*ServiceUnavailable*' -or
                    $catchResult.code -like '*ServiceUnavailable*' -or
                    $catchResult.error.code -like '*MultipleErrorsOccurred*' -or
                    $catchResult.code -like '*InternalServerError*' -or
                    $catchResult.error.code -like '*InternalServerError*' -or
                    $catchResult.error.code -like '*RequestTimeout*' -or
                    $catchResult.error.code -like '*AuthorizationFailed*' -or
                    $catchResult.error.code -like '*ExpiredAuthenticationToken*' -or
                    $catchResult.error.code -like '*Authentication_ExpiredToken*' -or
                    $catchResult.error.code -like '*UnknownError*' -or
                    $catchResult.error.code -like '*BlueprintNotFound*' -or
                    $catchResult.error.code -eq '500' -or
                    $catchResult.error.code -eq 'ResourceRequestsThrottled' -or
                    $catchResult.error.code -eq '429' -or
                    $catchResult.error.code -eq 'InsufficientPermissions' -or
                    $catchResult.error.code -eq 'ClientCertificateValidationFailure' -or
                    $catchResult.error.code -eq 'GatewayAuthenticationFailed' -or
                    $catchResult.message -eq 'An error has occurred.' -or
                    $catchResult.error.code -eq 'Request_UnsupportedQuery' -or
                    $catchResult.error.code -eq 'GeneralError' -or
                    $catchResult.error.code -like '*InvalidAuthenticationToken*' -or
                    (
                        $getARMPolicyComplianceStates -and (
                            ($catchResult.error.code -like '*ResponseTooLarge*') -or
                            (-not $catchResult.error.code)
                        )
                    ) -or
                    (
                        $getARMCostManagement -and (
                            ($catchResult.error.code -eq 404) -or
                            ($catchResult.error.code -eq 'AccountCostDisabled') -or
                            ($catchResult.error.message -like '*does not have any valid subscriptions*') -or
                            ($catchResult.error.code -eq 'Unauthorized') -or
                            ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like '*The offer*is not supported*' -and $catchResult.error.message -notlike '*The offer MS-AZR-0110P is not supported*') -or
                            ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like 'Invalid query definition*') -or
                            ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like '*have valid WebDirect/AIRS offer type*') -or
                            ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like 'Cost management data is not supported for subscription(s)*') -or
                            ($catchResult.error.code -eq 'IndirectCostDisabled')
                        )
                    ) -or
                    $catchResult.error.message -like '*The offer MS-AZR-0110P is not supported*' -or
                    #(($getMicrosoftGraphApplication -or $getMicrosoftGraphServicePrincipal -or $getMicrosoftGraphGroupMembersTransitive -or $getMicrosoftGraphGroupMembersTransitiveCount) -and $catchResult.error.code -like "*Request_ResourceNotFound*") -or
                    ($targetEndpoint -eq 'MicrosoftGraph' -and $catchResult.error.code -like '*Request_ResourceNotFound*') -or
                    (($getMicrosoftGraphApplication) -and $catchResult.error.code -like '*Authorization_RequestDenied*') -or
                    ($getMicrosoftGraphGroupMembersTransitiveCount -and $catchResult.error.message -like '*count is not currently supported*') -or
                    ($getARMARGMgMDfCSecureScore -and $catchResult.error.code -eq 'BadRequest') -or
                    (
                        $getARMRoleAssignmentSchedules -and (
                            ($catchResult.error.code -eq 'ResourceNotOnboarded') -or
                            ($catchResult.error.code -eq 'TenantNotOnboarded') -or
                            ($catchResult.error.code -eq 'InvalidResourceType') -or
                            ($catchResult.error.code -eq 'InvalidResource')
                        )
                    ) -or
                    ($getMicrosoftGraphRoleAssignmentScheduleInstances -and $catchResult.error.code -eq 'InvalidResource') -or
                    ($getARMDiagnosticSettingsMg -and $catchResult.error.code -eq 'InvalidResourceType') -or
                    (
                        $validateAccess -and (
                            $catchResult.error.code -eq 'Authorization_RequestDenied'
                        )
                    ) -or
                    (
                        $getARMMDfC -and (
                            $catchResult.error.code -eq 'Subscription Not Registered'
                        )
                    ) -or
                    (
                        $getARMDiagnosticSettingsResource -and (
                            ($catchResult.error.code -like '*ResourceNotFound*') -or
                            ($catchResult.code -like '*ResourceNotFound*') -or
                            ($catchResult.error.code -like '*ResourceGroupNotFound*') -or
                            ($catchResult.code -like '*ResourceGroupNotFound*') -or
                            ($catchResult.code -eq 'ResourceTypeNotSupported')
                        )
                    ) -or
                    ($getMicrosoftGraphServicePrincipalGetMemberGroups -and $catchResult.error.code -like '*Directory_ResultSizeLimitExceeded*')

                ) {
                    if (
                        ($getARMPolicyComplianceStates -and (
                            ($catchResult.error.code -like '*ResponseTooLarge*') -or
                            (-not $catchResult.error.code))
                        )
                    ) {
                        if ($catchResult.error.code -like '*ResponseTooLarge*') {
                            Write-Host "Info: $currentTask - (StatusCode: '$($azAPIRequest.StatusCode)') Response too large, skipping this scope."
                            return [string]'ResponseTooLarge'
                        }
                        if (-not $catchResult.error.code) {
                            #seems API now returns null instead of 'ResponseTooLarge'
                            Write-Host "Info: $currentTask - (StatusCode: '$($azAPIRequest.StatusCode)') Response empty - handle like 'Response too large', skipping this scope."
                            return [string]'ResponseTooLarge'
                        }
                    }

                    if ($catchResult.error.message -like '*The offer MS-AZR-0110P is not supported*') {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - seems we´re hitting a malicious endpoint .. try again in $tryCounter second(s)"
                        Start-Sleep -Seconds $tryCounter
                    }

                    if ($catchResult.error.code -like '*GatewayTimeout*' -or $catchResult.error.code -like '*BadGatewayConnection*' -or $catchResult.error.code -like '*InvalidGatewayHost*' -or $catchResult.error.code -like '*ServerTimeout*' -or $catchResult.error.code -like '*ServiceUnavailable*' -or $catchResult.code -like '*ServiceUnavailable*' -or $catchResult.error.code -like '*MultipleErrorsOccurred*' -or $catchResult.code -like '*InternalServerError*' -or $catchResult.error.code -like '*InternalServerError*' -or $catchResult.error.code -like '*RequestTimeout*' -or $catchResult.error.code -like '*UnknownError*' -or $catchResult.error.code -eq '500') {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again in $tryCounter second(s)"
                        Start-Sleep -Seconds $tryCounter
                    }

                    if ($catchResult.error.code -like '*AuthorizationFailed*') {
                        if ($validateAccess) {
                            #Write-Host "$currentTask failed ('$($catchResult.error.code)' | '$($catchResult.error.message)')" -ForegroundColor DarkRed
                            return [string]'failed'
                        }
                        else {
                            if ($retryAuthorizationFailedCounter -gt $retryAuthorizationFailed) {
                                Write-Host '- - - - - - - - - - - - - - - - - - - - '
                                Write-Host "!Please report at $($htParameters.GithubRepository) and provide the following dump" -ForegroundColor Yellow
                                Write-Host "$currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - $retryAuthorizationFailed retries failed - EXIT"
                                Write-Host ''
                                Write-Host 'Parameters:'
                                foreach ($htParameter in ($htParameters.Keys | Sort-Object)) {
                                    Write-Host "$($htParameter):$($htParameters.($htParameter))"
                                }
                                Throw 'Error: check the last console output for details'
                            }
                            else {
                                if ($retryAuthorizationFailedCounter -gt 2) {
                                    Start-Sleep -Seconds 5
                                }
                                if ($retryAuthorizationFailedCounter -gt 3) {
                                    Start-Sleep -Seconds 10
                                }
                                Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - not reasonable, retry #$retryAuthorizationFailedCounter of $retryAuthorizationFailed"
                                $retryAuthorizationFailedCounter ++
                            }
                        }
                    }

                    if ($catchResult.error.code -like '*ExpiredAuthenticationToken*' -or $catchResult.error.code -like '*Authentication_ExpiredToken*' -or $catchResult.error.code -like '*InvalidAuthenticationToken*') {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - requesting new bearer token ($targetEndpoint)"
                        createBearerToken -targetEndPoint $targetEndpoint
                    }

                    if (
                        $getARMCostManagement -and (
                            ($catchResult.error.code -eq 404) -or
                            ($catchResult.error.code -eq 'AccountCostDisabled') -or
                            ($catchResult.error.message -like '*does not have any valid subscriptions*') -or
                            ($catchResult.error.code -eq 'Unauthorized') -or
                            ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like '*The offer*is not supported*' -and $catchResult.error.message -notlike '*The offer MS-AZR-0110P is not supported*') -or
                            ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like 'Invalid query definition*')
                        )

                    ) {
                        if ($catchResult.error.code -eq 404) {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Subscriptions was created only recently - skipping"
                            return [PSCustomObject]$apiCallResultsCollection
                        }

                        if ($catchResult.error.code -eq 'AccountCostDisabled') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Access to cost data has been disabled for this Account - skipping CostManagement"
                            return [string]'AccountCostDisabled'
                        }

                        if ($catchResult.error.message -like '*does not have any valid subscriptions*') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems there are no valid Subscriptions present - skipping CostManagement"
                            return [string]'NoValidSubscriptions'
                        }

                        if ($catchResult.error.code -eq 'Unauthorized') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
                            return [string]'Unauthorized'
                        }

                        if ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like '*The offer*is not supported*' -and $catchResult.error.message -notlike '*The offer MS-AZR-0110P is not supported*') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
                            return [string]'OfferNotSupported'
                        }

                        if ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like 'Invalid query definition*') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
                            return [string]'InvalidQueryDefinition'
                        }

                        if ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like '*have valid WebDirect/AIRS offer type*') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
                            return [string]'NonValidWebDirectAIRSOfferType'
                        }

                        if ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like 'Cost management data is not supported for subscription(s)*') {
                            return [string]'NotFoundNotSupported'
                        }

                        if ($catchResult.error.code -eq 'IndirectCostDisabled') {
                            return [string]'IndirectCostDisabled'
                        }
                    }

                    #if (($getMicrosoftGraphApplication -or $getMicrosoftGraphServicePrincipal -or $getMicrosoftGraphGroupMembersTransitive -or $getMicrosoftGraphGroupMembersTransitiveCount) -and $catchResult.error.code -like "*Request_ResourceNotFound*") {
                    #    Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) uncertain object status - skipping for now :)"
                    #    return [string]"Request_ResourceNotFound"
                    #}

                    if ($targetEndpoint -eq 'MicrosoftGraph' -and $catchResult.error.code -like '*Request_ResourceNotFound*') {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) uncertain object status - skipping for now :)"
                        return [string]'Request_ResourceNotFound'
                    }

                    if ($getMicrosoftGraphGroupMembersTransitiveCount -and $catchResult.error.message -like '*count is not currently supported*') {
                        $maxTries = 7
                        $sleepSec = @(1, 3, 5, 7, 10, 12, 20, 30, 40, 45)[$tryCounter]
                        if ($tryCounter -gt $maxTries) {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - exit"
                            Throw 'Error - check the last console output for details'
                        }
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' sleeping $($sleepSec) seconds"
                        start-sleep -Seconds $sleepSec
                    }

                    if ($currentTask -eq 'Checking AAD UserType' -and $catchResult.error.code -like '*Authorization_RequestDenied*') {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) cannot get the executing user´s userType information (member/guest) - proceeding as 'unknown'"
                        return [string]'unknown'
                    }

                    if ($getMicrosoftGraphApplication -and $catchResult.error.code -like '*Authorization_RequestDenied*') {
                        if ($htParameters.userType -eq 'Guest') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) - skip Application (Secrets & Certificates)"
                            return [string]'skipApplications'
                        }
                        if ($userType -eq 'Guest' -or $userType -eq 'unknown') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult)"
                            if ($userType -eq 'Guest') {
                                Write-Host " Your UserType is 'Guest' (member/guest/unknown) in the tenant therefore not enough permissions. You have the following options: [1. request membership to AAD Role 'Directory readers'.] Grant explicit Microsoft Graph API permission." -ForegroundColor Yellow
                            }
                            if ($userType -eq 'unknown') {
                                Write-Host " Your UserType is 'unknown' (member/guest/unknown) in the tenant. Seems you do not have enough permissions geeting AAD related data. You have the following options: [1. request membership to AAD Role 'Directory readers'.]" -ForegroundColor Yellow
                            }
                            Throw 'Authorization_RequestDenied'
                        }
                        else {
                            Write-Host '- - - - - - - - - - - - - - - - - - - - '
                            Write-Host "!Please report at $($htParameters.GithubRepository) and provide the following dump" -ForegroundColor Yellow
                            Write-Host "$currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) - EXIT"
                            Write-Host ''
                            Write-Host 'Parameters:'
                            foreach ($htParameter in ($htParameters.Keys | Sort-Object)) {
                                Write-Host "$($htParameter):$($htParameters.($htParameter))"
                            }
                            Throw 'Authorization_RequestDenied'
                        }
                    }

                    if ($catchResult.error.code -like '*BlueprintNotFound*') {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Blueprint definition is gone - skipping for now :)"
                        return [string]'BlueprintNotFound'
                    }

                    if ($catchResult.error.code -eq 'ResourceRequestsThrottled' -or $catchResult.error.code -eq '429') {
                        $sleepSeconds = 11
                        if ($catchResult.error.code -eq 'ResourceRequestsThrottled') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - throttled! sleeping $sleepSeconds seconds"
                            start-sleep -Seconds $sleepSeconds
                        }
                        if ($catchResult.error.code -eq '429') {
                            if ($catchResult.error.message -like '*60 seconds*') {
                                $sleepSeconds = 60
                            }
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - throttled! sleeping $sleepSeconds seconds"
                            start-sleep -Seconds $sleepSeconds
                        }

                    }

                    if ($getARMARGMgMDfCSecureScore -and $catchResult.error.code -eq 'BadRequest') {
                        $sleepSec = @(1, 1, 2, 3, 5, 7, 9, 10, 13, 15, 20, 25, 30, 45, 60, 60, 60, 60)[$tryCounter]
                        $maxTries = 15
                        if ($tryCounter -gt $maxTries) {
                            Write-Host " $currentTask - capitulation after $maxTries attempts"
                            return [string]'capitulation'
                        }
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again (trying $maxTries times) in $sleepSec second(s)"
                        Start-Sleep -Seconds $sleepSec
                    }

                    if (
                        ($getARMRoleAssignmentSchedules -and (
                        ($catchResult.error.code -eq 'ResourceNotOnboarded') -or
                        ($catchResult.error.code -eq 'TenantNotOnboarded') -or
                        ($catchResult.error.code -eq 'InvalidResourceType') -or
                        ($catchResult.error.code -eq 'InvalidResource')
                        ) -or ($getMicrosoftGraphRoleAssignmentScheduleInstances -and $catchResult.error.code -eq 'InvalidResource')
                        )
                    ) {
                        if ($catchResult.error.code -eq 'ResourceNotOnboarded') {
                            return [string]'ResourceNotOnboarded'
                        }
                        if ($catchResult.error.code -eq 'TenantNotOnboarded') {
                            return [string]'TenantNotOnboarded'
                        }
                        if ($catchResult.error.code -eq 'InvalidResourceType') {
                            return [string]'InvalidResourceType'
                        }
                        if ($catchResult.error.code -eq 'InvalidResource') {
                            return [string]'InvalidResource'
                        }
                        if ($getMicrosoftGraphRoleAssignmentScheduleInstances -and $catchResult.error.code -eq 'InvalidResource') {
                            return [string]'InvalidResource'
                        }
                    }

                    if ($getARMDiagnosticSettingsMg -and $catchResult.error.code -eq 'InvalidResourceType') {
                        return [string]'InvalidResourceType'
                    }

                    if ($catchResult.error.code -eq 'InsufficientPermissions' -or $catchResult.error.code -eq 'ClientCertificateValidationFailure' -or $catchResult.error.code -eq 'GatewayAuthenticationFailed' -or $catchResult.message -eq 'An error has occurred.' -or $catchResult.error.code -eq 'GeneralError') {
                        $maxTries = 7
                        $sleepSec = @(1, 3, 5, 7, 10, 12, 20, 30, 40, 45)[$tryCounter]
                        if ($tryCounter -gt $maxTries) {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - exit"
                            Throw 'Error - check the last console output for details'
                        }
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' sleeping $($sleepSec) seconds"
                        start-sleep -Seconds $sleepSec
                    }

                    if ($validateAccess -and $catchResult.error.code -eq 'Authorization_RequestDenied') {
                        #Write-Host "$currentTask failed ('$($catchResult.error.code)' | '$($catchResult.error.message)')" -ForegroundColor DarkRed
                        return [string]'failed'
                    }

                    if ($htParameters.userType -eq 'Guest' -and $catchResult.error.code -eq 'Authorization_RequestDenied') {
                        #https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - exit"
                        Write-Host 'Tenant seems hardened (AAD External Identities / Guest user access = most restrictive) -> https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions'
                        Write-Host "AAD Role 'Directory readers' is required for your Guest User Account!"
                        Throw 'Error - check the last console output for details'
                    }

                    if ($getARMMDfC -and $catchResult.error.code -eq 'Subscription Not Registered') {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' skipping Subscription"
                        return [string]'SubScriptionNotRegistered'
                    }

                    if ($catchResult.error.code -eq 'Request_UnsupportedQuery') {
                        $sleepSec = @(1, 3, 7, 10, 15, 20, 30)[$tryCounter]
                        $maxTries = 5
                        if ($tryCounter -gt $maxTries) {
                            Write-Host " $currentTask - capitulation after $maxTries attempts"
                            return [string]'Request_UnsupportedQuery'
                        }
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again (trying $maxTries times) in $sleepSec second(s)"
                        Start-Sleep -Seconds $sleepSec
                    }

                    if ($getARMDiagnosticSettingsResource -and (
                        ($catchResult.error.code -like '*ResourceNotFound*') -or
                        ($catchResult.code -like '*ResourceNotFound*') -or
                        ($catchResult.error.code -like '*ResourceGroupNotFound*') -or
                        ($catchResult.code -like '*ResourceGroupNotFound*') -or
                        ($catchResult.code -eq 'ResourceTypeNotSupported')
                        )
                    ) {
                        if ($catchResult.error.code -like '*ResourceNotFound*' -or $catchResult.code -like '*ResourceNotFound*') {
                            Write-Host "  ResourceGone | The resourceId '$($resourceId)' seems meanwhile deleted."
                            return [string]'meanwhile_deleted_ResourceNotFound'
                        }
                        if ($catchResult.error.code -like '*ResourceGroupNotFound*' -or $catchResult.code -like '*ResourceGroupNotFound*') {
                            Write-Host "  ResourceGone | ResourceGroup not found - the resourceId '$($resourceId)' seems meanwhile deleted."
                            return [string]'meanwhile_deleted_ResourceGroupNotFound'
                        }
                        if ($catchResult.code -eq 'ResourceTypeNotSupported') {
                            return [string]'ResourceTypeNotSupported'
                        }
                    }

                    if ($getMicrosoftGraphServicePrincipalGetMemberGroups -and $catchResult.error.code -like '*Directory_ResultSizeLimitExceeded*') {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) maximum number of groups exceeded, skipping; docs: https://docs.microsoft.com/pt-br/previous-versions/azure/ad/graph/api/functions-and-actions#getmembergroups-get-group-memberships-transitive--"
                        return 'Directory_ResultSizeLimitExceeded'
                    }
                }
                else {
                    if (-not $catchResult.code -and -not $catchResult.error.code -and -not $catchResult.message -and -not $catchResult.error.message -and -not $catchResult -and $tryCounter -lt 6) {
                        if ($azAPIRequest.StatusCode -eq 204 -and $getARMCostManagement) {
                            return [PSCustomObject]$apiCallResultsCollection
                        }
                        else {
                            $sleepSec = @(3, 7, 12, 20, 30, 45, 60)[$tryCounter]
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) try again in $sleepSec second(s)"
                            Start-Sleep -Seconds $sleepSec
                        }
                    }
                    elseif (-not $catchResult.code -and -not $catchResult.error.code -and -not $catchResult.message -and -not $catchResult.error.message -and $catchResult -and $tryCounter -lt 6) {
                        $sleepSec = @(3, 7, 12, 20, 30, 45, 60)[$tryCounter]
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) try again in $sleepSec second(s)"
                        Start-Sleep -Seconds $sleepSec
                    }
                    else {
                        Write-Host '- - - - - - - - - - - - - - - - - - - - '
                        Write-Host "!Please report at $($htParameters.GithubRepository) and provide the following dump" -ForegroundColor Yellow
                        Write-Host "$currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) - EXIT"
                        Write-Host ''
                        Write-Host 'Parameters:'
                        foreach ($htParameter in ($htParameters.Keys | Sort-Object)) {
                            Write-Host "$($htParameter):$($htParameters.($htParameter))"
                        }
                        if ($getARMCostManagement) {
                            Write-Host 'If Consumption data is not that important for you, do not use parameter: -DoAzureConsumption (however, please still report the issue - thank you)'
                        }
                        Throw 'Error - check the last console output for details'
                    }
                }
            }
            else {
                if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                    if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: apiStatusCode: $($azAPIRequest.StatusCode)" -ForegroundColor $debugForeGroundColor }
                    if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: apiStatusCode: $($azAPIRequest.StatusCode)" }
                }
                $azAPIRequestConvertedFromJson = ($azAPIRequest.Content | ConvertFrom-Json)
                if ($listenOn -eq 'Content') {
                    if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                        if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: listenOn=content ($((($azAPIRequestConvertedFromJson)).count))" -ForegroundColor $debugForeGroundColor }
                        if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: listenOn=content ($((($azAPIRequestConvertedFromJson)).count))" }
                    }
                    $null = $apiCallResultsCollection.Add($azAPIRequestConvertedFromJson)
                }
                elseif ($listenOn -eq 'ContentProperties') {
                    if (($azAPIRequestConvertedFromJson.properties.rows).Count -gt 0) {
                        foreach ($consumptionline in $azAPIRequestConvertedFromJson.properties.rows) {
                            $hlper = $htSubscriptionsMgPath.($consumptionline[1])
                            $null = $apiCallResultsCollection.Add([PSCustomObject]@{
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[0])" = $consumptionline[0]
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[1])" = $consumptionline[1]
                                    SubscriptionName                                               = $hlper.DisplayName
                                    SubscriptionMgPath                                             = $hlper.ParentNameChainDelimited
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
                        if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: listenOn=default(value) value exists ($((($azAPIRequestConvertedFromJson).value).count))" -ForegroundColor $debugForeGroundColor }
                            if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: listenOn=default(value) value exists ($((($azAPIRequestConvertedFromJson).value).count))" }
                        }
                        foreach ($entry in $azAPIRequestConvertedFromJson.value) {
                            $null = $apiCallResultsCollection.Add($entry)
                        }
                    }
                    else {
                        if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host '   DEBUG: listenOn=default(value) value not exists; return empty array' -ForegroundColor $debugForeGroundColor }
                            if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host '   Forced DEBUG: listenOn=default(value) value not exists; return empty array' }
                        }
                    }
                }

                $isMore = $false
                if (-not $noPaging) {
                    if ($azAPIRequestConvertedFromJson.nextLink) {
                        $isMore = $true
                        if ($uri -eq $azAPIRequestConvertedFromJson.nextLink) {
                            if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                                Write-Host " $currentTask restartDueToDuplicateNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Write-Host 'nextLinkLog: uri is equal to nextLinkUri'
                                Write-Host "nextLinkLog: uri: $uri"
                                Write-Host "nextLinkLog: nextLinkUri: $($azAPIRequestConvertedFromJson.nextLink)"
                                Write-Host "nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
                                $apiCallResultsCollection = [System.Collections.ArrayList]@()
                                $uri = $initialUri
                                Start-Sleep -Seconds 10
                            }
                        }
                        else {
                            $uri = $azAPIRequestConvertedFromJson.nextLink
                            $notTryCounter = $true
                        }
                        if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: nextLink: $Uri" -ForegroundColor $debugForeGroundColor }
                            if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: nextLink: $Uri" }
                        }
                    }
                    elseif ($azAPIRequestConvertedFromJson.'@oData.nextLink') {
                        $isMore = $true
                        if ($uri -eq $azAPIRequestConvertedFromJson.'@odata.nextLink') {
                            if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                                Write-Host " $currentTask restartDueToDuplicate@odataNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Write-Host 'nextLinkLog: uri is equal to @odata.nextLinkUri'
                                Write-Host "nextLinkLog: uri: $uri"
                                Write-Host "nextLinkLog: @odata.nextLinkUri: $($azAPIRequestConvertedFromJson.'@odata.nextLink')"
                                Write-Host "nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
                                $apiCallResultsCollection = [System.Collections.ArrayList]@()
                                $uri = $initialUri
                                Start-Sleep -Seconds 10
                            }
                        }
                        else {
                            $uri = $azAPIRequestConvertedFromJson.'@odata.nextLink'
                            $notTryCounter = $true
                        }
                        if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: @oData.nextLink: $Uri" -ForegroundColor $debugForeGroundColor }
                            if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: @oData.nextLink: $Uri" }
                        }
                    }
                    elseif ($azAPIRequestConvertedFromJson.properties.nextLink) {
                        $isMore = $true
                        if ($uri -eq $azAPIRequestConvertedFromJson.properties.nextLink) {
                            if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                                Write-Host " $currentTask restartDueToDuplicateNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Write-Host 'nextLinkLog: uri is equal to nextLinkUri'
                                Write-Host "nextLinkLog: uri: $uri"
                                Write-Host "nextLinkLog: nextLinkUri: $($azAPIRequestConvertedFromJson.properties.nextLink)"
                                Write-Host "nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
                                $apiCallResultsCollection = [System.Collections.ArrayList]@()
                                $uri = $initialUri
                                Start-Sleep -Seconds 10
                            }
                        }
                        else {
                            $uri = $azAPIRequestConvertedFromJson.properties.nextLink
                            $notTryCounter = $true
                        }
                        if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: nextLink: $Uri" -ForegroundColor $debugForeGroundColor }
                            if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: nextLink: $Uri" }
                        }
                    }
                    else {
                        if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host '   DEBUG: NextLink: none' -ForegroundColor $debugForeGroundColor }
                            if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host '   Forced DEBUG: NextLink: none' }
                        }
                    }
                }
            }
        }
        else {
            if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                if ($htParameters.DebugAzAPICall -eq $true) { Write-Host '   DEBUG: unexpectedError: notFalse' -ForegroundColor $debugForeGroundColor }
                if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host '   Forced DEBUG: unexpectedError: notFalse' }
            }
            if ($tryCounterUnexpectedError -lt 13) {
                $sleepSec = @(1, 2, 3, 5, 7, 10, 13, 17, 20, 30, 40, 50, , 55, 60)[$tryCounterUnexpectedError]
                Write-Host " $currentTask #$tryCounterUnexpectedError 'Unexpected Error' occurred (trying 10 times); sleep $sleepSec seconds"
                Write-Host $catchResult
                Start-Sleep -Seconds $sleepSec
            }
            else {
                Write-Host " $currentTask #$tryCounterUnexpectedError 'Unexpected Error' occurred (tried 5 times)/exit"
                Throw 'Error - check the last console output for details'
            }
        }
    }
    until(($azAPIRequest.StatusCode -in 200..204 -and -not $isMore ) -or ($Method -eq 'HEAD' -and $azAPIRequest.StatusCode -eq 404))
    return [PSCustomObject]$apiCallResultsCollection
}