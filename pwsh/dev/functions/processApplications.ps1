function processApplications {
    Write-Host 'Processing Service Principals - Applications'
    $script:servicePrincipalsOfTypeApplication = $htServicePrincipals.Keys.where( { $htServicePrincipals.($_).servicePrincipalType -eq 'Application' -and $htServicePrincipals.($_).appOwnerOrganizationId -eq $azAPICallConf['checkContext'].Subscription.TenantId } )
    if ($azAPICallConf['htParameters'].userType -eq 'Guest') {
        #checking if Guest has enough permissions
        $app4Test = $htServicePrincipals.($servicePrincipalsOfTypeApplication[0])
        $currentTask = "getApp Test $($app4Test.appId)"
        $uri = "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/applications?`$filter=appId eq '$($app4Test.appId)'"
        $method = 'GET'
        $testGetApplication = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask
        if ($testGetApplication -eq 'skipApplications') {
            $skipApplications = $true
            Write-Host ' Guest account does not have enough permissions, skipping Applications (Secrets & Certificates)'
        }
    }
    if (-not $skipApplications) {
        $startSPApp = Get-Date
        $currentDateUTC = (Get-Date).ToUniversalTime()
        $script:arrayApplicationRequestResourceNotFound = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        $servicePrincipalsOfTypeApplication | ForEach-Object -Parallel {

            #region UsingVARs
            $currentDateUTC = $using:currentDateUTC
            #fromOtherFunctions
            $azAPICallConf = $using:azAPICallConf
            $scriptPath = $using:ScriptPath
            #Array&HTs
            $arrayApplicationRequestResourceNotFound = $using:arrayApplicationRequestResourceNotFound
            $htAppDetails = $using:htAppDetails
            $htServicePrincipals = $using:htServicePrincipals
            #endregion UsingVARs

            $sp = $htServicePrincipals.($_)

            $currentTask = "getApp $($sp.appId)"
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/applications?`$filter=appId eq '$($sp.appId)'"
            $method = 'GET'
            $getApplication = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask

            if ($getApplication -eq 'Request_ResourceNotFound') {
                $null = $script:arrayApplicationRequestResourceNotFound.Add([PSCustomObject]@{
                        appId = $sp.appId
                    })
            }
            else {
                if (($getApplication).Count -eq 0) {
                    Write-Host "$($sp.appId) no data returned / seems non existent?"
                }
                else {
                    $script:htAppDetails.($sp.id) = @{}
                    $script:htAppDetails.($sp.id).servicePrincipalType = $sp.servicePrincipalType
                    $script:htAppDetails.($sp.id).spGraphDetails = $sp
                    $script:htAppDetails.($sp.id).appGraphDetails = $getApplication

                    $appPasswordCredentialsCount = ($getApplication.passwordCredentials).count
                    if ($appPasswordCredentialsCount -gt 0) {
                        $script:htAppDetails.($sp.id).appPasswordCredentialsCount = $appPasswordCredentialsCount
                        $appPasswordCredentialsExpiredCount = 0
                        $appPasswordCredentialsGracePeriodExpiryCount = 0
                        $appPasswordCredentialsExpiryOKCount = 0
                        $appPasswordCredentialsExpiryOKMoreThan2YearsCount = 0
                        foreach ($appPasswordCredential in $getApplication.passwordCredentials) {
                            $passwordExpiryTotalDays = (New-TimeSpan -Start $currentDateUTC -End $appPasswordCredential.endDateTime).TotalDays
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
                        $script:htAppDetails.($sp.id).appPasswordCredentialsExpiredCount = $appPasswordCredentialsExpiredCount
                        $script:htAppDetails.($sp.id).appPasswordCredentialsGracePeriodExpiryCount = $appPasswordCredentialsGracePeriodExpiryCount
                        $script:htAppDetails.($sp.id).appPasswordCredentialsExpiryOKCount = $appPasswordCredentialsExpiryOKCount
                        $script:htAppDetails.($sp.id).appPasswordCredentialsExpiryOKMoreThan2YearsCount = $appPasswordCredentialsExpiryOKMoreThan2YearsCount
                    }

                    $appKeyCredentialsCount = ($getApplication.keyCredentials).count
                    if ($appKeyCredentialsCount -gt 0) {
                        $script:htAppDetails.($sp.id).appKeyCredentialsCount = $appKeyCredentialsCount
                        $appKeyCredentialsExpiredCount = 0
                        $appKeyCredentialsGracePeriodExpiryCount = 0
                        $appKeyCredentialsExpiryOKCount = 0
                        $appKeyCredentialsExpiryOKMoreThan2YearsCount = 0
                        foreach ($appKeyCredential in $getApplication.keyCredentials) {
                            $keyCredentialExpiryTotalDays = (New-TimeSpan -Start $currentDateUTC -End $appKeyCredential.endDateTime).TotalDays
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
                        $script:htAppDetails.($sp.id).appKeyCredentialsExpiredCount = $appKeyCredentialsExpiredCount
                        $script:htAppDetails.($sp.id).appKeyCredentialsGracePeriodExpiryCount = $appKeyCredentialsGracePeriodExpiryCount
                        $script:htAppDetails.($sp.id).appKeyCredentialsExpiryOKCount = $appKeyCredentialsExpiryOKCount
                        $script:htAppDetails.($sp.id).appKeyCredentialsExpiryOKMoreThan2YearsCount = $appKeyCredentialsExpiryOKMoreThan2YearsCount
                    }
                }
            }

        } -ThrottleLimit ($ThrottleLimit * 2)

        $endSPApp = Get-Date
        Write-Host "Processing Service Principals - Applications duration: $((New-TimeSpan -Start $startSPApp -End $endSPApp).TotalMinutes) minutes ($((New-TimeSpan -Start $startSPApp -End $endSPApp).TotalSeconds) seconds)"
    }
}