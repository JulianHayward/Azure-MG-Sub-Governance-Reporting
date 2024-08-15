function exportBaseCSV {
    if (-not $NoCsvExport) {
        Write-Host "Exporting CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName).csv'"
        $startBuildCSV = Get-Date

        $outprops = $newtable[0].PSObject.Properties.Name
        if (-not $HierarchyMapOnly -and -not $HierarchyMapOnlyCustomDataJSON) {
            $outprops.Set($outprops.IndexOf('PolicyAssignmentNotScopes'), @{L = 'PolicyAssignmentNotScopes'; E = { ($_.PolicyAssignmentNotScopes -join "$CsvDelimiterOpposite ") } })
        }
        if ($CsvExportUseQuotesAsNeeded) {
            $newTable | Sort-Object -Property level, mgId, SubscriptionId, PolicyAssignmentId, RoleAssignmentId, BlueprintId, BlueprintAssignmentId | Select-Object -Property $outprops -ExcludeProperty PolicyAssignmentParameters | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).csv" -Delimiter "$csvDelimiter" -NoTypeInformation -UseQuotes AsNeeded
        }
        else {
            $newTable | Sort-Object -Property level, mgId, SubscriptionId, PolicyAssignmentId, RoleAssignmentId, BlueprintId, BlueprintAssignmentId | Select-Object -Property $outprops -ExcludeProperty PolicyAssignmentParameters | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).csv" -Delimiter "$csvDelimiter" -NoTypeInformation
        }

        $endBuildCSV = Get-Date
        Write-Host "Exporting CSV total duration: $((New-TimeSpan -Start $startBuildCSV -End $endBuildCSV).TotalMinutes) minutes ($((New-TimeSpan -Start $startBuildCSV -End $endBuildCSV).TotalSeconds) seconds)"
    }
}