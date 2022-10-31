function processDiagramMermaid() {
    if ($ManagementGroupId -ne $azAPICallConf['checkContext'].Tenant.Id) {
        $optimizedTableForPathQueryMg = $optimizedTableForPathQueryMg.where({ $_.mgParentId -ne "'upperScopes'" })
    }
    $mgLevels = ($optimizedTableForPathQueryMg | Sort-Object -Property Level -Unique).Level

    foreach ($mgLevel in $mgLevels) {
        $mgsInLevel = ($optimizedTableForPathQueryMg.where( { $_.Level -eq $mgLevel } )).MgId | Get-Unique
        foreach ($mgInLevel in $mgsInLevel) {
            $mgDetails = ($optimizedTableForPathQueryMg.where( { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel } ))
            $mgName = $mgDetails.MgName | Get-Unique
            $mgParentId = $mgDetails.mgParentId | Get-Unique
            $mgParentName = $mgDetails.mgParentName | Get-Unique
            if ($mgInLevel -ne $getMgParentId) {
                $null = $script:arrayMgs.Add($mgInLevel)
            }

            if ($mgParentName -eq $mgParentId) {
                $mgParentNameId = $mgParentName
            }
            else {
                $mgParentNameId = "$mgParentName<br/>$mgParentId"
            }

            if ($mgName -eq $mgInLevel) {
                $mgNameId = $mgName
            }
            else {
                $mgNameId = "$mgName<br/>$mgInLevel"
            }
            $script:markdownhierarchyMgs += @"
$mgParentId(`"$mgParentNameId`") --> $mgInLevel(`"$mgNameId`")`n
"@
            $subsUnderMg = ($optimizedTableForPathQueryMgAndSub.where( { -not [string]::IsNullOrEmpty($_.SubscriptionId) -and $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel } )).SubscriptionId
            if (($subsUnderMg | Measure-Object).count -gt 0) {
                foreach ($subUnderMg in $subsUnderMg) {
                    $null = $script:arraySubs.Add("SubsOf$mgInLevel")
                    $mgDetalsN = ($optimizedTableForPathQueryMg.where( { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel } ))
                    $mgName = $mgDetalsN.MgName | Get-Unique
                    $mgParentId = $mgDetalsN.MgParentId | Get-Unique
                    $mgParentName = $mgDetalsN.MgParentName | Get-Unique
                    $subName = ($optimizedTableForPathQuery.where( { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel -and $_.SubscriptionId -eq $subUnderMg } )).Subscription | Get-Unique
                    $script:markdownTable += @"
| $mgLevel | $mgName | $mgInLevel | $mgParentName | $mgParentId | $subName | $($subUnderMg -replace '.*/') |`n
"@
                }
                $mgName = ($optimizedTableForPathQueryMg.where( { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel } )).MgName | Get-Unique
                if ($mgName -eq $mgInLevel) {
                    $mgNameId = $mgName
                }
                else {
                    $mgNameId = "$mgName<br/>$mgInLevel"
                }
                $script:markdownhierarchySubs += @"
$mgInLevel(`"$mgNameId`") --> SubsOf$mgInLevel(`"$(($subsUnderMg | Measure-Object).count)`")`n
"@
            }
            else {
                $mgDetailsM = ($optimizedTableForPathQueryMg.where( { $_.Level -eq $mgLevel -and $_.MgId -eq $mgInLevel } ))
                $mgName = $mgDetailsM.MgName | Get-Unique
                $mgParentId = $mgDetailsM.MgParentId | Get-Unique
                $mgParentName = $mgDetailsM.MgParentName | Get-Unique
                $script:markdownTable += @"
| $mgLevel | $mgName | $mgInLevel | $mgParentName | $mgParentId | none | none |`n
"@
            }

            if (($script:outOfScopeSubscriptions | Measure-Object).count -gt 0) {
                $subsoosUnderMg = ($outOfScopeSubscriptions | Where-Object { $_.Level -eq $mgLevel -and $_.ManagementGroupId -eq $mgInLevel }).SubscriptionId | Get-Unique
                if (($subsoosUnderMg | Measure-Object).count -gt 0) {
                    foreach ($subUnderMg in $subsoosUnderMg) {
                        $null = $script:arraySubsOos.Add("SubsoosOf$mgInLevel")
                        $mgDetalsN = ($optimizedTableForPathQueryMg.where( { $_.Level -eq $mgLevel -and $_.ManagementGroupId -eq $mgInLevel } ))
                        $mgName = $mgDetalsN.MgName | Get-Unique
                    }
                    $mgName = ($outOfScopeSubscriptions | Where-Object { $_.Level -eq $mgLevel -and $_.ManagementGroupId -eq $mgInLevel }).ManagementGroupName | Get-Unique
                    if ($mgName -eq $mgInLevel) {
                        $mgNameId = $mgName
                    }
                    else {
                        $mgNameId = "$mgName<br/>$mgInLevel"
                    }
                    $script:markdownhierarchySubs += @"
$mgInLevel(`"$mgNameId`") --> SubsoosOf$mgInLevel(`"$(($subsoosUnderMg | Measure-Object).count)`")`n
"@
                }
            }
        }
    }
}