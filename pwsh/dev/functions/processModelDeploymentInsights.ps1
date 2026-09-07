function processModelDeploymentInsights {
    $start = Get-Date
    $deploymentCount = $arrayModelDeployments.Count
    Write-Host "Processing Model Deployment Insights for $deploymentCount deployments"

    if ($deploymentCount -eq 0) {
        return
    }

    $metricsEnd = (Get-Date).ToUniversalTime()
    $metricsStart = $metricsEnd.AddDays(-$FoundryModelDeploymentsDays)
    $timespan = '{0}/{1}' -f $metricsStart.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'"), $metricsEnd.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
    $batchSize = [math]::Ceiling($deploymentCount / $ThrottleLimit)
    $counterBatch = [PSCustomObject]@{ Value = 0 }
    $deploymentBatches = $arrayModelDeployments | Group-Object -Property { [math]::Floor($counterBatch.Value++ / $batchSize) }

    $deploymentBatches | ForEach-Object -Parallel {
        $azAPICallConf = $using:azAPICallConf
        $arrayModelDeploymentInsights = $using:arrayModelDeploymentInsights
        $timespan = $using:timespan
        $metricsStart = $using:metricsStart
        $metricsEnd = $using:metricsEnd

        foreach ($deployment in $_.Group) {
            $encodedDeploymentName = [uri]::EscapeDataString($deployment.DeploymentName)
            $filter = "ModelDeploymentName%20eq%20%27$encodedDeploymentName%27%20and%20StatusCode%20eq%20%27*%27"
            $metricNames = 'AzureOpenAIRequests,ProcessedPromptTokens,GeneratedTokens,cacheReadInputTokens'
            $uri = "$($azAPICallConf['azAPIEndpointUrls'].ARM)$($deployment.AccountId)/providers/microsoft.Insights/metrics?api-version=2024-02-01&interval=FULL&aggregation=total&validatedimensions=false&metricNamespace=microsoft.cognitiveservices%2Faccounts&timespan=$timespan&`$filter=$filter&metricnames=$metricNames"
            $currentTask = "Getting metrics for model deployment '$($deployment.DeploymentName)' in account '$($deployment.AccountName)'"
            $metricResponse = AzAPICall -AzAPICallConfiguration $azAPICallConf -uri $uri -method 'GET' -currentTask $currentTask -caller 'ModelDeploymentInsights' -unhandledErrorAction Continue

            $metricStatus = 'Succeeded'
            $totals = @{}
            $statusCodeTotals = @{}
            if ($metricResponse -is [string]) {
                $metricStatus = $metricResponse
            }
            elseif (@($metricResponse).Count -eq 0) {
                $metricStatus = 'NoData'
            }
            else {
                foreach ($metric in @($metricResponse)) {
                    $metricName = [string]$metric.name.value
                    $metricTotal = 0.0
                    foreach ($series in @($metric.timeseries)) {
                        $seriesTotal = 0.0
                        foreach ($dataPoint in @($series.data)) {
                            if ($null -ne $dataPoint.total) {
                                $seriesTotal += [double]$dataPoint.total
                            }
                        }
                        $metricTotal += $seriesTotal

                        if ($metricName -eq 'AzureOpenAIRequests') {
                            $statusMetadata = $series.metadatavalues | Where-Object { $_.name.value -ieq 'StatusCode' } | Select-Object -First 1
                            if ($null -ne $statusMetadata) {
                                $statusCode = [string]$statusMetadata.value
                                if (-not $statusCodeTotals.ContainsKey($statusCode)) {
                                    $statusCodeTotals[$statusCode] = 0.0
                                }
                                $statusCodeTotals[$statusCode] += $seriesTotal
                            }
                        }
                    }
                    $totals[$metricName] = $metricTotal
                }
            }

            $requests2xx = ($statusCodeTotals.GetEnumerator() | Where-Object { $_.Key -match '^2\d\d$' } | Measure-Object -Property Value -Sum).Sum
            $requests4xx = ($statusCodeTotals.GetEnumerator() | Where-Object { $_.Key -match '^4\d\d$' } | Measure-Object -Property Value -Sum).Sum
            $requests5xx = ($statusCodeTotals.GetEnumerator() | Where-Object { $_.Key -match '^5\d\d$' } | Measure-Object -Property Value -Sum).Sum

            $null = $arrayModelDeploymentInsights.Add([PSCustomObject]@{
                    MgPath                = $deployment.MgPath
                    SubscriptionId        = $deployment.SubscriptionId
                    SubscriptionName      = $deployment.SubscriptionName
                    ResourceGroup         = $deployment.ResourceGroup
                    AccountId             = $deployment.AccountId
                    AccountName           = $deployment.AccountName
                    AccountKind           = $deployment.AccountKind
                    AccountSku            = $deployment.AccountSku
                    AccountSkuTier        = $deployment.AccountSkuTier
                    AccountCreatedTime    = $deployment.AccountCreatedTime
                    Location              = $deployment.Location
                    PublicNetworkAccess   = $deployment.PublicNetworkAccess
                    DeploymentId          = $deployment.DeploymentId
                    DeploymentName        = $deployment.DeploymentName
                    DeploymentState       = $deployment.DeploymentState
                    DeploymentSku         = $deployment.DeploymentSku
                    DeploymentSkuTier     = $deployment.DeploymentSkuTier
                    DeploymentCapacity    = $deployment.DeploymentCapacity
                    DeploymentCapabilities = $deployment.DeploymentCapabilities
                    DeploymentRateLimits   = $deployment.DeploymentRateLimits
                    VersionUpgradeOption  = $deployment.VersionUpgradeOption
                    ModelFormat           = $deployment.ModelFormat
                    ModelName             = $deployment.ModelName
                    ModelVersion          = $deployment.ModelVersion
                    MetricsStartUtc        = $metricsStart
                    MetricsEndUtc          = $metricsEnd
                    MetricsStatus          = $metricStatus
                    Requests               = $totals.AzureOpenAIRequests
                    ProcessedPromptTokens  = $totals.ProcessedPromptTokens
                    GeneratedTokens        = $totals.GeneratedTokens
                    CacheReadInputTokens   = $totals.cacheReadInputTokens
                    Requests2xx            = if ($null -eq $requests2xx) { 0 } else { $requests2xx }
                    Requests200            = if ($statusCodeTotals.ContainsKey('200')) { $statusCodeTotals['200'] } else { 0 }
                    Requests4xx            = if ($null -eq $requests4xx) { 0 } else { $requests4xx }
                    Requests400            = if ($statusCodeTotals.ContainsKey('400')) { $statusCodeTotals['400'] } else { 0 }
                    Requests429            = if ($statusCodeTotals.ContainsKey('429')) { $statusCodeTotals['429'] } else { 0 }
                    Requests5xx            = if ($null -eq $requests5xx) { 0 } else { $requests5xx }
                    StatusCodes            = $statusCodeTotals | ConvertTo-Json -Compress
                })
        }
    } -ThrottleLimit $ThrottleLimit

    if (-not $NoCsvExport -and $arrayModelDeploymentInsights.Count -gt 0) {
        $modelDeploymentInsightsCsvPath = "$($outputPath)$($DirectorySeparatorChar)$($fileName)_ModelDeploymentInsights.csv"
        Write-Host "Exporting Model Deployment Insights CSV '$modelDeploymentInsightsCsvPath'"
        $arrayModelDeploymentInsights |
            Sort-Object -Property ModelName, ModelVersion, SubscriptionName, AccountName, DeploymentName |
            Export-Csv -Path $modelDeploymentInsightsCsvPath -Delimiter $csvDelimiter -NoTypeInformation
    }

    apiCallTracking -stage 'Model Deployment Insights' -spacing ' '
    Write-Host "Processing Model Deployment Insights duration: $((New-TimeSpan -Start $start -End (Get-Date)).TotalSeconds) seconds"
}