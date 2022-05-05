function getResourceDiagnosticsCapability {
    Write-Host 'Checking Resource Types Diagnostics capability (1st party only)'
    $startResourceDiagnosticsCheck = Get-Date
    if (($resourcesAll).count -gt 0) {

        $startGroupResourceIdsByType = Get-Date
        $script:resourceTypesUnique = ($resourcesIdsAll | Group-Object -property type)
        $endGroupResourceIdsByType = Get-Date
        Write-Host " GroupResourceIdsByType processing duration: $((NEW-TIMESPAN -Start $startGroupResourceIdsByType -End $endGroupResourceIdsByType).TotalSeconds) seconds)"
        $resourceTypesUniqueCount = ($resourceTypesUnique | Measure-Object).count
        Write-Host " $($resourceTypesUniqueCount) unique Resource Types to process"
        $script:resourceTypesSummarizedArray = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

        $script:resourceTypesDiagnosticsArray = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        $resourceTypesUnique.where( { $_.Name -like 'microsoft.*' }) | ForEach-Object -Parallel {
            $resourceTypesUniqueGroup = $_
            $resourcetype = $resourceTypesUniqueGroup.Name
            #region UsingVARs
            #fromOtherFunctions
            $azAPICallConf = $using:azAPICallConf
            $scriptPath = $using:ScriptPath
            #Array&HTs
            $ExcludedResourceTypesDiagnosticsCapable = $using:ExcludedResourceTypesDiagnosticsCapable
            $resourceTypesDiagnosticsArray = $using:resourceTypesDiagnosticsArray
            $htResourceTypesUniqueResource = $using:htResourceTypesUniqueResource
            $resourceTypesSummarizedArray = $using:resourceTypesSummarizedArray
            #Functions
            #AzAPICall
            if ($azAPICallConf['htParameters'].onAzureDevOpsOrGitHubActions) {
                Import-Module ".\$($scriptPath)\AzAPICallModule\AzAPICall\$($azAPICallConf['htParameters'].azAPICallModuleVersion)\AzAPICall.psd1" -Force -ErrorAction Stop
            }
            else {
                Import-Module -Name AzAPICall -RequiredVersion $azAPICallConf['htParameters'].azAPICallModuleVersion -Force -ErrorAction Stop
            }
            #endregion UsingVARs

            $skipThisResourceType = $false
            if (($ExcludedResourceTypesDiagnosticsCapable).Count -gt 0) {
                foreach ($excludedResourceType in $ExcludedResourceTypesDiagnosticsCapable) {
                    if ($excludedResourceType -eq $resourcetype) {
                        $skipThisResourceType = $true
                    }
                }
            }

            if ($skipThisResourceType -eq $false) {
                $resourceCount = $resourceTypesUniqueGroup.Count

                #thx @Jim Britt (Microsoft) https://github.com/JimGBritt/AzurePolicy/tree/master/AzureMonitor/Scripts Create-AzDiagPolicy.ps1
                $responseJSON = ''
                $logCategories = @()
                $metrics = $false
                $logs = $false

                $resourceAvailability = ($resourceCount - 1)
                $counterTryForResourceType = 0
                do {
                    $counterTryForResourceType++
                    if ($resourceCount -gt 1) {
                        $resourceId = $resourceTypesUniqueGroup.Group.Id[$resourceAvailability]
                    }
                    else {
                        $resourceId = $resourceTypesUniqueGroup.Group.Id
                    }

                    $resourceAvailability = $resourceAvailability - 1
                    $currentTask = "Checking if ResourceType '$resourceType' is capable for Resource Diagnostics using $counterTryForResourceType ResourceId: '$($resourceId)'"
                    $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/$($resourceId)/providers/microsoft.insights/diagnosticSettingsCategories?api-version=2021-05-01-preview"
                    $method = 'GET'

                    $responseJSON = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method $method -currentTask $currentTask
                    if ($responseJSON -notlike 'meanwhile_deleted*') {
                        if ($responseJSON -eq 'ResourceTypeOrResourceProviderNotSupported') {
                            Write-Host "  ResourceTypeOrResourceProviderNotSupported | The resource type '$($resourcetype)' does not support diagnostic settings."

                        }
                        else {
                            Write-Host "  ResourceTypeSupported | The resource type '$($resourcetype)' supports diagnostic settings."
                        }
                    }
                    else {
                        Write-Host "resId '$resourceId' meanwhile deleted"
                    }
                }
                until ($resourceAvailability -lt 0 -or $responseJSON -notlike 'meanwhile_deleted*')

                if ($resourceAvailability -lt 0 -and $responseJSON -like 'meanwhile_deleted*') {
                    Write-Host "tried for all available resourceIds ($($resourceCount)) for resourceType $resourceType, but seems all resources meanwhile have been deleted"
                    $null = $script:resourceTypesDiagnosticsArray.Add([PSCustomObject]@{
                            ResourceType  = $resourcetype
                            Metrics       = "n/a - $responseJSON"
                            Logs          = "n/a - $responseJSON"
                            LogCategories = 'n/a'
                            ResourceCount = $resourceCount
                        })
                }
                else {
                    if ($responseJSON) {
                        foreach ($response in $responseJSON) {
                            if ($response.properties.categoryType -eq 'Metrics') {
                                $metrics = $true
                            }
                            if ($response.properties.categoryType -eq 'Logs') {
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
                            ResourceCount = $resourceCount
                        })
                }
            }
            else {
                Write-Host "Skipping ResourceType $($resourcetype) as per parameter '-ExcludedResourceTypesDiagnosticsCapable'"
            }
        } -ThrottleLimit $ThrottleLimit
        #[System.GC]::Collect()
    }
    else {
        Write-Host ' No Resources at all'
    }
    $endResourceDiagnosticsCheck = Get-Date
    Write-Host "Checking Resource Types Diagnostics capability duration: $((NEW-TIMESPAN -Start $startResourceDiagnosticsCheck -End $endResourceDiagnosticsCheck).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $startResourceDiagnosticsCheck -End $endResourceDiagnosticsCheck).TotalSeconds) seconds)"
}