function apiCallTracking {
    [CmdletBinding()]Param(
        [string]$stage,
        [string]$spacing
    )
    #APITracking
    $APICallTrackingCount = ($azAPICallConf['arrayAPICallTracking']).Count
    $APICallTrackingRetriesCount = ($azAPICallConf['arrayAPICallTracking'].where({ $_.TryCounter -gt 1 } )).Count
    $APICallTrackingGroupedByTargetEndpoint = $azAPICallConf['arrayAPICallTracking'] | Group-Object -Property TargetEndpoint
    $APICallTrackingRestartDueToDuplicateNextlinkCounterCount = ($azAPICallConf['arrayAPICallTracking'].where({ $_.RestartDueToDuplicateNextlinkCounter -gt 0 } )).Count
    Write-Host "$($spacing)$($stage) API call stats:"
    $duarationStats = ($azAPICallConf['arrayAPICallTracking'].Duration | Measure-Object -Average -Maximum -Minimum)
    Write-Host "$($spacing) API calls total count: $APICallTrackingCount ($APICallTrackingRetriesCount retries; $APICallTrackingRestartDueToDuplicateNextlinkCounterCount nextLinkReset) | average: $($duarationStats.Average) sec, maximum: $($duarationStats.Maximum) sec, minimum: $($duarationStats.Minimum) sec"
    foreach ($targetEndpoint in $APICallTrackingGroupedByTargetEndpoint | Sort-Object -Property Name) {
        $APICallTrackingRetriesCount = ($targetEndpoint.Group.where({ $_.TryCounter -gt 1 } )).Count
        $APICallTrackingRestartDueToDuplicateNextlinkCounterCount = ($targetEndpoint.Group.where({ $_.RestartDueToDuplicateNextlinkCounter -gt 0 } )).Count
        $duarationStats = ($targetEndpoint.Group.Duration | Measure-Object -Average -Maximum -Minimum)
        Write-Host "$($spacing) API calls endpoint '$($targetEndpoint.Name) ($($azAPICallConf['azAPIEndpointUrls'].($targetEndpoint.Name)))' count: $($targetEndpoint.Count) ($APICallTrackingRetriesCount retries; $APICallTrackingRestartDueToDuplicateNextlinkCounterCount nextLinkReset) | average: $($duarationStats.Average) sec, maximum: $($duarationStats.Maximum) sec, minimum: $($duarationStats.Minimum) sec"
    }
}