function handlePSRuleData {
    $start = Get-Date

    $script:psRuleDataSelection = $arrayPsRule | select-object `
    @{label = "resourceType"; Expression = { $_.TargetType } }, `
    @{label = "subscriptionId"; Expression = { ($_.TargetObject.id.split('/')[2]) } }, `
    @{label = "mgPath"; Expression = { ($htSubscriptionsMgPath.($_.TargetObject.id.split('/')[2])).ParentNameChainDelimited } }, `
    @{label = "resourceId"; Expression = { ($_.TargetObject.id) } }, `
    @{label = "pillar"; Expression = { $_.Info.Annotations.pillar } }, `
    @{label = "category"; Expression = { $_.Info.Annotations.category } }, `
    @{label = "severity"; Expression = { $_.Info.Annotations.severity } }, `
    @{label = "rule"; Expression = { $_.Info.DisplayName } }, `
    @{label = "description"; Expression = { $_.Info.Description } }, `
    @{label = "recommendation"; Expression = { $_.Info.Recommendation } }, `
    @{label = "link"; Expression = { $_.Info.Annotations.'online version' } }, `
    @{label = "ruleId"; Expression = { $_.RuleId } }, `
    @{label = "result"; Expression = { $_.Outcome } }, `
    @{label = "errorMsg"; Expression = { $_.Error.Message } }

    if (-not $NoCsvExport) {
        Write-Host "Exporting 'PSRule for Azure' CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_PSRule.csv'"
        $psRuleDataSelection | Sort-Object -Property resourceId, pillar, category, severity, rule | Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_PSRule.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
    }

    $end = Get-Date
    Write-Host "   handlePSRuleData processing duration: $((NEW-TIMESPAN -Start $start -End $end).TotalMinutes) minutes ($((NEW-TIMESPAN -Start $start -End $end).TotalSeconds) seconds)"
}