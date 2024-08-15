function getResourceDiagnosticsCapability {
    Write-Host 'Checking Resource Types Diagnostics capability (1st party only)'
    $startResourceDiagnosticsCheck = Get-Date
    if (($resourcesAll).count -gt 0) {

        $startGroupResourceIdsByType = Get-Date
        $script:resourceTypesUnique = ($resourcesIdsAll | Group-Object -Property type)
        $endGroupResourceIdsByType = Get-Date
        Write-Host " GroupResourceIdsByType processing duration: $((New-TimeSpan -Start $startGroupResourceIdsByType -End $endGroupResourceIdsByType).TotalSeconds) seconds)"
        $resourceTypesUniqueCount = ($resourceTypesUnique | Measure-Object).count
        Write-Host " $($resourceTypesUniqueCount) unique Resource Types"
        $script:resourceTypesSummarizedArray = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

        $script:resourceTypesDiagnosticsArray = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        $microsoftResourceTypes = $resourceTypesUnique.where({ $_.Name.StartsWith('microsoft') })
        if ($microsoftResourceTypes.Count -gt 0) {
            $microsoftResourceTypes | ForEach-Object -Parallel {
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
                    $logCategories = [System.Collections.ArrayList]@()
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
                        if ($resourceId -like '*+*') {
                            Write-Host "resourceId '$resourceId' contains bad character '+'; skipping resourceId"
                            $responseJSON = 'skipResource'
                        }
                        else {
                            $currentTask = "Checking if ResourceType '$resourceType' is capable for Resource Diagnostics using $counterTryForResourceType ResourceId: '$($resourceId)'"
                            $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)/$($resourceId)/providers/microsoft.insights/diagnosticSettingsCategories?api-version=2021-05-01-preview"
                            $method = 'GET'
                            $responseJSON = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri ([uri]::EscapeUriString($uri)) -method $method -currentTask $currentTask
                        }

                        if ($responseJSON -ne 'skipResource') {
                            if ($responseJSON -eq 'ResourceTypeOrResourceProviderNotSupported') {
                                Write-Host "  ResourceTypeOrResourceProviderNotSupported | The resource type '$($resourcetype)' does not support diagnostic settings."

                            }
                            else {
                                Write-Host "  ResourceTypeSupported | The resource type '$($resourcetype)' supports diagnostic settings."
                            }
                        }
                        else {
                            Write-Host "resId '$resourceId' skipped"
                        }
                    }
                    until ($resourceAvailability -lt 0 -or $responseJSON -ne 'skipResource')

                    if ($resourceAvailability -lt 0 -and $responseJSON -eq 'skipResource') {
                        Write-Host "tried for all available resourceIds ($($resourceCount)) for resourceType $resourceType, but seems all resourceIds needed to be skipped"
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
                                    $null = $logCategories.Add($response.name)
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
        }
        else {
            Write-Host ' No 1st party Resource Types at all'
        }

    }
    else {
        Write-Host ' No Resources at all'
    }
    $endResourceDiagnosticsCheck = Get-Date
    Write-Host "Checking Resource Types Diagnostics capability duration: $((New-TimeSpan -Start $startResourceDiagnosticsCheck -End $endResourceDiagnosticsCheck).TotalMinutes) minutes ($((New-TimeSpan -Start $startResourceDiagnosticsCheck -End $endResourceDiagnosticsCheck).TotalSeconds) seconds)"
}