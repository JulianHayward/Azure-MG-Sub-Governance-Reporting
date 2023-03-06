function buildMD {
    Write-Host 'Building Markdown'
    $startBuildMD = Get-Date
    $script:arrayMgs = [System.Collections.ArrayList]@()
    $script:arraySubs = [System.Collections.ArrayList]@()
    $script:arraySubsOos = [System.Collections.ArrayList]@()
    $markdown = $null
    $script:markdownhierarchyMgs = $null
    $script:markdownhierarchySubs = $null
    $script:markdownTable = $null

    if ($azAPICallConf['htParameters'].onAzureDevOpsOrGitHubActions -eq $true) {
        if ($azAPICallConf['htParameters'].onAzureDevOps -eq $true) {
            $markdown += @"
# Azure Governance Visualizer - Management Group Hierarchy

## HierarchyMap (Mermaid)

::: mermaid
    graph $($MermaidDirection.ToUpper());`n
"@
        }
        if ($azAPICallConf['htParameters'].onGitHubActions -eq $true) {
            $marks = '```'
            $markdown += @"
# Azure Governance Visualizer - Management Group Hierarchy

## HierarchyMap (Mermaid)

$($marks)mermaid
    graph $($MermaidDirection.ToUpper());`n
"@
        }

    }
    else {
        $markdown += @"
# Azure Governance Visualizer - Management Group Hierarchy

$executionDateTimeInternationalReadable ($currentTimeZone)

## HierarchyMap (Mermaid)

::: mermaid
    graph $($MermaidDirection.ToUpper());`n
"@
    }

    processDiagramMermaid

    $markdown += @"
$markdownhierarchyMgs
$markdownhierarchySubs
 classDef mgr fill:#D9F0FF,stroke:#56595E,color:#000000,stroke-width:1px;
 classDef subs fill:#EEEEEE,stroke:#56595E,color:#000000,stroke-width:1px;
"@

    if (($arraySubsOos).count -gt 0) {
        $markdown += @'
 classDef subsoos fill:#FFCBC7,stroke:#56595E,color:#000000,stroke-width:1px;
'@
    }

    $markdown += @"
 classDef mgrprnts fill:#FFFFFF,stroke:#56595E,color:#000000,stroke-width:1px;
 class $(($arrayMgs | Sort-Object -Unique) -join ',') mgr;
 class $(($arraySubs | Sort-Object -Unique) -join ',') subs;
"@

    if (($arraySubsOos).count -gt 0) {
        $markdown += @"
 class $(($arraySubsOos | Sort-Object -Unique) -join ',') subsoos;
"@
    }

    if ($azAPICallConf['htParameters'].onAzureDevOpsOrGitHubActions -eq $true) {
        if ($azAPICallConf['htParameters'].onAzureDevOps -eq $true) {
            $markdown += @"
class $mermaidprnts mgrprnts;
:::

"@
        }
        if ($azAPICallConf['htParameters'].onGitHubActions -eq $true) {
`
                $marks = '```'
            $markdown += @"
class $mermaidprnts mgrprnts;
$marks

"@
        }
    }
    else {
        $markdown += @"
class $mermaidprnts mgrprnts;
:::

"@
    }

    $markdown += @"
## Summary
`n
"@
    if (-not $HierarchyMapOnly) {
        $markdown += @"
Total Management Groups: $totalMgCount (depth $mgDepth)\`n
"@

        if (($arraySubsOos).count -gt 0) {
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
Total Custom Policy definitions: $tenantCustomPoliciesCount\
Total Custom PolicySet definitions: $tenantCustompolicySetsCount\
Total Policy assignments: $($totalPolicyAssignmentsCount)\
Total Policy assignments ManagementGroups $($totalPolicyAssignmentsCountMg)\
Total Policy assignments Subscriptions $($totalPolicyAssignmentsCountSub)\
Total Policy assignments ResourceGroups: $($totalPolicyAssignmentsCountRg)\
Total Custom Role definitions: $totalRoleDefinitionsCustomCount\
Total Role assignments: $totalRoleAssignmentsCount\
Total Role assignments (Tenant): $totalRoleAssignmentsCountTen\
Total Role assignments (ManagementGroups): $totalRoleAssignmentsCountMG\
Total Role assignments (Subscriptions): $totalRoleAssignmentsCountSub\
Total Role assignments (ResourceGroups and Resources): $totalRoleAssignmentsResourceGroupsAndResourcesCount\
Total Blueprint definitions: $totalBlueprintDefinitionsCount\
Total Blueprint assignments: $totalBlueprintAssignmentsCount\
Total Resources: $totalResourceCount\
Total Resource Types: $totalResourceTypesCount
"@

    }
    if ($HierarchyMapOnly) {
        $mgsDetails = ($optimizedTableForPathQueryMg | Select-Object Level, MgId -Unique)
        $mgDepth = ($mgsDetails.Level | Measure-Object -Maximum).Maximum
        $totalMgCount = ($mgsDetails).count
        $totalSubCount = ($optimizedTableForPathQuerySub).count

        $markdown += @"
Total Management Groups: $totalMgCount (depth $mgDepth)\
Total Subscriptions: $totalSubCount
"@

    }

    $markdown += @"
`n
## Hierarchy Table

| **MgLevel** | **MgName** | **MgId** | **MgParentName** | **MgParentId** | **SubName** | **SubId** |
|-------------|-------------|-------------|-------------|-------------|-------------|-------------|
$markdownTable
"@

    $markdown | Set-Content -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName).md" -Encoding utf8 -Force
    $endBuildMD = Get-Date
    Write-Host "Building Markdown total duration: $((New-TimeSpan -Start $startBuildMD -End $endBuildMD).TotalMinutes) minutes ($((New-TimeSpan -Start $startBuildMD -End $endBuildMD).TotalSeconds) seconds)"
}